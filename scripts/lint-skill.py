from __future__ import annotations

import ipaddress
import json
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlparse


ROOT = Path(__file__).resolve().parents[1]
REFERENCES_DIR = ROOT / "references"
SKILL_PATH = ROOT / "SKILL.md"
INDEX_PATH = ROOT / "INDEX.md"
OPENAI_YAML_PATH = ROOT / "agents" / "openai.yaml"
README_PATH = ROOT / "README.md"
CONTRIBUTING_PATH = ROOT / "CONTRIBUTING.md"

REFERENCE_REQUIRED_KEYS = {
    "title",
    "slug",
    "category",
    "depth",
    "audit_level",
    "last_reviewed",
    "sources",
    "triggers_strong",
    "triggers_weak",
    "related",
}
ALLOWED_CATEGORIES = {
    "appsec",
    "infra",
    "iam",
    "platform",
    "ai",
    "privacy",
    "ops",
    "compliance",
}
ALLOWED_AUDIT_LEVELS = {1, 2, 3, 4}
ROOT_REFERENCE_EXCEPTIONS = {"_index.md", "_core-invariants.md"}
URL_PATTERN = re.compile(r"https?://[^\s)>\]\"'`]+")
SKILL_REFERENCE_PATTERN = re.compile(
    r"references/(?:[A-Za-z0-9_-]+/)*(?:[A-Za-z0-9_.-]+|\*)"
)
SUSPICIOUS_PATTERNS = [
    re.compile(pattern, re.IGNORECASE)
    for pattern in (
        r"ignore (all )?previous instructions",
        r"disregard (the )?(system prompt|previous instructions)",
        r"developer message",
        r"begin system prompt",
        r"reveal your system prompt",
        r"print the developer message",
        r"\bexfiltrate (?:all |the )?(?:api keys|secrets|credentials|data)\b",
        r"bypass restrictions",
    )
]
DEFENSIVE_FRAMING_PATTERNS = [
    re.compile(pattern, re.IGNORECASE)
    for pattern in (
        r"prompt[- ]injection",
        r"\b(?:malicious|hostile|untrusted) (?:input|content|instruction|payload|data)",
        r"\battacker\b",
        r"\b(?:detects?|detection|selection_override|selection_connector)\b",
        r"(?m)^\s*selection:\s*$",
        r"\bLLM01\b",
        r"\bscan for known-bad patterns\b",
        r"\binstruction-like payloads?\b",
        r"\bllm\.input\.text\|contains\b",
        r"\b(?:direct|indirect) injection\b",
        r"\bhidden (?:text|instruction|payload)\b",
        r"\b(?:block|reject|quarantine)(?:ed|ing)?\b.*\b(?:instruction|payload|content)",
        r"\bred[- ]team(?:ing)?\b",
        r"\btreat .* as untrusted\b",
    )
]
ALLOWED_DOMAIN_SUFFIXES = (
    "agentskill.sh",
    "aicpa-cima.com",
    "aicpa.org",
    "aisi.gov.uk",
    "amazon.com",
    "anthropic.com",
    "apache.org",
    "api.github.com",
    "apple.com",
    "artificialintelligenceact.eu",
    "arxiv.org",
    "blog.google",
    "chatgpt.com",
    "cisecurity.org",
    "claude.ai",
    "cmu.edu",
    "cnil.fr",
    "cncf.io",
    "csp-evaluator.withgoogle.com",
    "cyclonedx.org",
    "dataprivacyframework.gov",
    "defense.gov",
    "developers.cloudflare.com",
    "developers.openai.com",
    "doi.org",
    "docs.anthropic.com",
    "docs.cursor.com",
    "docs.sigstore.dev",
    "dora.dev",
    "edpb.europa.eu",
    "electronjs.org",
    "enisa.europa.eu",
    "envoyproxy.io",
    "eur-lex.europa.eu",
    "europa.eu",
    "falco.org",
    "fidoalliance.org",
    "first.org",
    "github.io",
    "github.com",
    "google",
    "google.com",
    "graphql.org",
    "hashicorp.com",
    "hhs.gov",
    "iec.ch",
    "ietf.org",
    "in-toto.io",
    "incidentdatabase.ai",
    "iso.org",
    "kubernetes.io",
    "llvm.org",
    "mandiant.com",
    "microsoft.com",
    "mitre.org",
    "modelcontextprotocol.io",
    "netflix.com",
    "nextjs.org",
    "nist.gov",
    "nginx.com",
    "observatory.mozilla.org",
    "openai.com",
    "openid.net",
    "openpolicyagent.org",
    "opentofu.org",
    "owasp.org",
    "owaspsamm.org",
    "pcisecuritystandards.org",
    "postgresql.org",
    "promptarmor.com",
    "raw.githubusercontent.com",
    "redhat.com",
    "rfc-editor.org",
    "scorecard.dev",
    "semgrep.dev",
    "securityheaders.com",
    "securityscorecards.dev",
    "sigmahq.io",
    "slsa.dev",
    "spdx.dev",
    "spiffe.io",
    "sqlalchemy.org",
    "stepsecurity.io",
    "stripe.com",
    "token.actions.githubusercontent.com",
    "usenix.org",
    "vault.azure.net",
    "verizon.com",
    "vuejs.org",
    "w3.org",
    "xml.org",
    "www.anthropic.com",
    "www.cisa.gov",
    "www.cisecurity.org",
    "www.first.org",
)
ALLOWED_EXAMPLE_HOSTS = {
    "app.com",
    "app",
    "attacker",
    "attacker.com",
    "backend",
    "localhost",
    "opa",
}


@dataclass
class Failure:
    path: str
    message: str


def parse_frontmatter(path: Path) -> tuple[dict[str, object], str]:
    lines = path.read_text(encoding="utf-8").splitlines()
    if not lines or lines[0].strip() != "---":
        raise ValueError("missing YAML frontmatter opening delimiter")

    data: dict[str, object] = {}
    body_start = None
    i = 1
    while i < len(lines):
        line = lines[i]
        if line.strip() == "---":
            body_start = i + 1
            break

        if not line.strip():
            i += 1
            continue

        if ":" not in line:
            raise ValueError(f"unsupported frontmatter line: {line}")

        key, raw_value = line.split(":", 1)
        key = key.strip()
        raw_value = raw_value.strip()

        if raw_value == "":
            items: list[str] = []
            i += 1
            while i < len(lines):
                nested = lines[i]
                if nested.strip() == "---":
                    i -= 1
                    break
                if not nested.startswith("  - "):
                    i -= 1
                    break
                item = nested[4:].strip()
                if item.startswith('"') and item.endswith('"'):
                    item = json.loads(item)
                items.append(item)
                i += 1
            data[key] = items
        elif raw_value == "null":
            data[key] = None
        elif raw_value.startswith("["):
            data[key] = json.loads(raw_value)
        elif raw_value.startswith('"') and raw_value.endswith('"'):
            data[key] = json.loads(raw_value)
        elif raw_value.isdigit():
            data[key] = int(raw_value)
        else:
            data[key] = raw_value

        i += 1

    if body_start is None:
        raise ValueError("missing YAML frontmatter closing delimiter")

    return data, "\n".join(lines[body_start:])


def validate_skill_manifest(text: str) -> list[str]:
    errors: list[str] = []
    lines = text.splitlines()
    if not lines or lines[0].strip() != "---":
        return ["missing YAML frontmatter opening delimiter"]
    try:
        closing = next(i for i, line in enumerate(lines[1:], start=1) if line.strip() == "---")
    except StopIteration:
        return ["missing YAML frontmatter closing delimiter"]

    fields: dict[str, str] = {}
    current_key: str | None = None
    for line in lines[1:closing]:
        if not line.strip():
            continue
        if line[:1].isspace():
            if current_key != "description":
                errors.append(f"unexpected indented manifest line: {line.strip()}")
                continue
            fields[current_key] = f"{fields[current_key]} {line.strip()}".strip()
            continue
        if ":" not in line:
            errors.append(f"unsupported manifest line: {line}")
            current_key = None
            continue
        key, raw_value = line.split(":", 1)
        key = key.strip()
        if key in fields:
            errors.append(f"duplicate manifest key: {key}")
        current_key = key
        value = raw_value.strip()
        fields[key] = "" if value in {">", ">-", "|", "|-"} else value.strip('"')

    missing = {"name", "description"} - fields.keys()
    if missing:
        errors.append(f"missing manifest keys: {', '.join(sorted(missing))}")
    extra = fields.keys() - {"name", "description"}
    if extra:
        errors.append(f"unexpected manifest keys: {', '.join(sorted(extra))}")

    name = fields.get("name", "")
    if not re.fullmatch(r"[a-z0-9]+(?:-[a-z0-9]+)*", name) or len(name) > 64:
        errors.append("name must be a lowercase hyphenated identifier of at most 64 characters")
    elif name != ROOT.name:
        errors.append(f"name `{name}` must match skill directory `{ROOT.name}`")

    description = fields.get("description", "").strip()
    if not description:
        errors.append("description must be non-empty")
    elif len(description) > 1024:
        errors.append("description must contain at most 1024 characters")
    if "<" in description or ">" in description:
        errors.append("description must not contain angle brackets")
    if not any(line.strip() for line in lines[closing + 1 :]):
        errors.append("skill body must be non-empty")
    return errors


def validate_reference_frontmatter(path: Path, meta: dict[str, object]) -> list[str]:
    errors: list[str] = []
    missing = REFERENCE_REQUIRED_KEYS - meta.keys()
    if missing:
        errors.append(f"missing frontmatter keys: {', '.join(sorted(missing))}")

    extra = set(meta.keys()) - REFERENCE_REQUIRED_KEYS
    if extra:
        errors.append(f"unexpected frontmatter keys: {', '.join(sorted(extra))}")

    title = meta.get("title")
    if not isinstance(title, str) or not title.strip():
        errors.append("title must be a non-empty string")

    slug = meta.get("slug")
    if not isinstance(slug, str) or not re.fullmatch(r"[a-z0-9-]+", slug):
        errors.append("slug must match [a-z0-9-]+")

    category = meta.get("category")
    if category not in ALLOWED_CATEGORIES:
        errors.append(f"category must be one of {sorted(ALLOWED_CATEGORIES)}")

    depth = meta.get("depth")
    if not isinstance(depth, int) or depth not in {1, 2, 3}:
        errors.append("depth must be one of 1, 2, 3")

    audit_level = meta.get("audit_level")
    if not isinstance(audit_level, list) or not audit_level:
        errors.append("audit_level must be a non-empty list")
    elif any(not isinstance(level, int) or level not in ALLOWED_AUDIT_LEVELS for level in audit_level):
        errors.append("audit_level must only contain integers from 1 to 4")

    last_reviewed = meta.get("last_reviewed")
    if last_reviewed is not None and not re.fullmatch(r"\d{4}-\d{2}-\d{2}", str(last_reviewed)):
        errors.append("last_reviewed must be null or YYYY-MM-DD")

    for key in ("sources", "triggers_strong", "triggers_weak", "related"):
        value = meta.get(key)
        if not isinstance(value, list):
            errors.append(f"{key} must be a list")
            continue
        if key == "sources" and not value:
            errors.append("sources must not be empty")
        if any(not isinstance(item, str) or not item.strip() for item in value):
            errors.append(f"{key} must only contain non-empty strings")

    expected_slug = path.stem.lstrip("_")
    if isinstance(slug, str) and slug != expected_slug:
        errors.append(f"slug `{slug}` does not match file stem `{expected_slug}`")

    if path.parent == REFERENCES_DIR and path.name not in ROOT_REFERENCE_EXCEPTIONS:
        errors.append("only `_index.md` and `_core-invariants.md` may live at the references root")

    return errors


def domain_is_allowed(host: str, *, allow_examples: bool = True) -> bool:
    if not host:
        return False

    host = host.rstrip(".").lower()
    if allow_examples and host in ALLOWED_EXAMPLE_HOSTS:
        return True

    try:
        address = ipaddress.ip_address(host)
        return allow_examples and not address.is_global
    except ValueError:
        pass

    if "." not in host:
        return False

    if allow_examples and (
        host.endswith(".example") or ".example." in host or host.startswith("example.")
    ):
        return True

    if allow_examples and any(
        token in host
        for token in ("yourapp", "yourdomain", "mycompany", "myapp", ".internal", ".corp")
    ):
        return True

    return any(host == suffix or host.endswith(f".{suffix}") for suffix in ALLOWED_DOMAIN_SUFFIXES)


def lint_urls(path: Path, text: str, *, allow_examples: bool = True) -> list[str]:
    errors: list[str] = []
    for raw_url in URL_PATTERN.findall(text):
        raw_url = raw_url.rstrip(".,;:)]}>")
        try:
            parsed = urlparse(raw_url)
            host = (parsed.hostname or "").strip().lower()
            port = parsed.port
        except ValueError as exc:
            errors.append(f"malformed URL `{raw_url}`: {exc}")
            continue
        if parsed.scheme not in {"http", "https"} or not host:
            errors.append(f"unsupported URL: {raw_url}")
        elif parsed.username is not None or parsed.password is not None:
            errors.append(f"URL must not contain credentials: {raw_url}")
        elif port is not None and port not in {80, 443} and not allow_examples:
            errors.append(f"source URL uses non-standard port {port}: {raw_url}")
        elif not domain_is_allowed(host, allow_examples=allow_examples):
            errors.append(f"external domain not allowlisted: {host}")
    return errors


def validate_source_urls(meta: dict[str, object]) -> list[str]:
    errors: list[str] = []
    sources = meta.get("sources")
    if not isinstance(sources, list):
        return errors
    for source in sources:
        if not isinstance(source, str):
            continue
        for error in lint_urls(Path("<frontmatter>"), source, allow_examples=False):
            errors.append(f"unsafe source URL: {error}")
    return errors


def lint_hidden_instructions(path: Path, text: str) -> list[str]:
    errors: list[str] = []
    lines = text.splitlines()
    fence_marker: str | None = None
    in_comment = False

    for idx, line in enumerate(lines, start=1):
        stripped = line.strip()
        fence_match = re.match(r"^(`{3,}|~{3,})", stripped)
        if fence_match:
            marker = fence_match.group(1)
            if fence_marker is None:
                fence_marker = marker[0]
            elif marker[0] == fence_marker:
                fence_marker = None

        if "<!--" in line:
            in_comment = True

        if any(pattern.search(line) for pattern in SUSPICIOUS_PATTERNS):
            # Defensive framing must be explicit and adjacent. Generic labels such
            # as "Example" or "review" are intentionally insufficient.
            context_start = max(0, idx - 6)
            context = "\n".join(lines[context_start:idx])
            if not any(pattern.search(context) for pattern in DEFENSIVE_FRAMING_PATTERNS):
                container = "comment" if in_comment else "fence" if fence_marker else "text"
                errors.append(
                    f"line {idx}: suspicious instruction in {container} without explicit defensive framing"
                )

        if "-->" in line:
            in_comment = False

    return errors


def validate_skill_routes(
    skill_text: str,
    references_by_path: dict[str, dict[str, object]],
    *,
    document_name: str = "SKILL.md",
) -> list[str]:
    errors: list[str] = []
    seen = set(SKILL_REFERENCE_PATTERN.findall(skill_text))
    references_root = REFERENCES_DIR.resolve()

    for token in sorted(seen):
        relative_token = token.removesuffix("/*")
        candidate = (ROOT / relative_token).resolve()
        try:
            candidate.relative_to(references_root)
        except ValueError:
            errors.append(f"{document_name} route escapes references/: {token}")
            continue

        if token.endswith("/*"):
            category = token.removeprefix("references/").removesuffix("/*")
            category_dir = REFERENCES_DIR / category
            if not category_dir.is_dir():
                errors.append(f"{document_name} references missing category directory: {token}")
            continue

        ref_path = ROOT / token
        if not ref_path.exists():
            errors.append(f"{document_name} references missing file: {token}")
            continue

        if token.endswith("_index.md"):
            continue

        rel = ref_path.relative_to(ROOT).as_posix()
        meta = references_by_path.get(rel)
        if meta is None:
            errors.append(f"{document_name} references file without registered frontmatter: {token}")
            continue

        expected_slug = ref_path.stem.lstrip("_")
        if meta.get("slug") != expected_slug:
            errors.append(
                f"{document_name} route `{token}` points to slug `{meta.get('slug')}` but expected `{expected_slug}`"
            )

    return errors


def collect_markdown_targets(reference_paths: list[Path]) -> list[Path]:
    targets = [SKILL_PATH, INDEX_PATH, README_PATH]
    if CONTRIBUTING_PATH.exists():
        targets.append(CONTRIBUTING_PATH)
    targets.extend(reference_paths)
    return list(dict.fromkeys(targets))


def validate_openai_yaml(path: Path) -> list[str]:
    if not path.exists():
        return ["missing agents/openai.yaml"]

    errors: list[str] = []
    lines = path.read_text(encoding="utf-8").splitlines()
    if any("\t" in line for line in lines):
        errors.append("tabs are not allowed")
    top_level_count = 0
    values: dict[str, str] = {}
    allowed_keys = {"display_name", "short_description", "default_prompt"}
    for line_number, line in enumerate(lines, start=1):
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        if line == "interface:":
            top_level_count += 1
            continue
        match = re.fullmatch(r'  ([a-z_]+): ("(?:[^"\\]|\\.)*")', line)
        if match is None:
            errors.append(f"line {line_number}: unexpected YAML structure")
            continue
        key, quoted_value = match.groups()
        if key not in allowed_keys:
            errors.append(f"line {line_number}: unexpected interface key `{key}`")
            continue
        if key in values:
            errors.append(f"line {line_number}: duplicate interface key `{key}`")
            continue
        try:
            value = json.loads(quoted_value)
        except json.JSONDecodeError:
            errors.append(f"line {line_number}: interface.{key} must be a valid quoted string")
            continue
        values[key] = value

    if top_level_count != 1:
        errors.append("agents/openai.yaml must contain exactly one top-level interface mapping")
    for key in sorted(allowed_keys - values.keys()):
        errors.append(f"interface.{key} must be present exactly once and quoted")

    short_description = values.get("short_description", "")
    if short_description and not 25 <= len(short_description) <= 64:
        errors.append("interface.short_description must contain 25 to 64 characters")

    default_prompt = values.get("default_prompt", "")
    if default_prompt and "$security-hardening" not in default_prompt:
        errors.append("interface.default_prompt must mention $security-hardening")

    return errors


def main() -> int:
    failures: list[Failure] = []
    references_by_path: dict[str, dict[str, object]] = {}
    slugs: dict[str, str] = {}

    reference_paths = sorted(REFERENCES_DIR.rglob("*.md"))
    for path in reference_paths:
        if path.name == "_index.md":
            continue
        rel = path.relative_to(ROOT).as_posix()
        try:
            meta, body = parse_frontmatter(path)
        except ValueError as exc:
            failures.append(Failure(rel, str(exc)))
            continue

        for error in validate_reference_frontmatter(path, meta):
            failures.append(Failure(rel, error))
        for error in validate_source_urls(meta):
            failures.append(Failure(rel, error))

        slug = meta.get("slug")
        if isinstance(slug, str):
            if slug in slugs and slugs[slug] != rel:
                failures.append(Failure(rel, f"duplicate slug `{slug}` also used in `{slugs[slug]}`"))
            else:
                slugs[slug] = rel

        references_by_path[rel] = meta

    skill_text = SKILL_PATH.read_text(encoding="utf-8")
    for error in validate_skill_manifest(skill_text):
        failures.append(Failure("SKILL.md", error))
    for error in validate_skill_routes(skill_text, references_by_path):
        failures.append(Failure("SKILL.md", error))

    route_documents = [INDEX_PATH, *sorted(REFERENCES_DIR.rglob("_index.md"))]
    for route_path in route_documents:
        route_text = route_path.read_text(encoding="utf-8")
        rel = route_path.relative_to(ROOT).as_posix()
        for error in validate_skill_routes(
            route_text,
            references_by_path,
            document_name=rel,
        ):
            failures.append(Failure(rel, error))

    for error in validate_openai_yaml(OPENAI_YAML_PATH):
        failures.append(Failure("agents/openai.yaml", error))

    for path in collect_markdown_targets(reference_paths):
        rel = path.relative_to(ROOT).as_posix()
        text = path.read_text(encoding="utf-8")
        for error in lint_urls(path, text):
            failures.append(Failure(rel, error))
        for error in lint_hidden_instructions(path, text):
            failures.append(Failure(rel, error))

    if failures:
        print("skill lint failed", file=sys.stderr)
        for failure in failures:
            print(f"- {failure.path}: {failure.message}", file=sys.stderr)
        return 1

    print("skill lint passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
