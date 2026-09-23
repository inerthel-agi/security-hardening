# Changelog

All notable changes to this repository are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Operational scan → triage → defensive fix → re-scan loop in `SKILL.md`, with runbook `references/appsec/ai-code-secure-remediation.md`.
- Non-destructive defaults: `detect-only` / `propose-fixes` / `apply-fixes` modes, DB/RCE blast-radius classification, and no production DB probing.
- Local Semgrep AI/vibecoder rule packs under `semgrep/` (including SQL injection AI patterns) and agent entrypoints `scripts/secure-review.py`, `scripts/map_findings.py`, `scripts/rescan-after-fix.py`.
- Vulnerable snippet fixtures under `evals/fixtures/vulnerable-snippet/` plus eval cases `c-036`–`c-039` for remediation and DB-safe detect routing.
- Scale harness `evals/scale/run_scale.py`, PHP Semgrep pack, propose/apply agent policy, and hard `safe_to_autofix=false` for db/secrets.
- CI Semgrep local-rules job and secure-review smoke job in `.github/workflows/security.yml`.
- Adversarial AI-agent eval fixtures for indirect prompt injection, path traversal, output exfiltration, and multi-turn tool abuse.
- Optional JSONL response grading and per-fixture prompt generation for Claude Code, Codex CLI, Gemini CLI, and other runtimes.
- Core adversarial case guidance in `references/ai/agent-evals-red-teaming.md`.
- Local ignore rules for `source.md`, generated eval prompts, and captured eval responses.
- Stable-vs-preview release guidance in `README.md`.
- Initial changelog and semantic tag mapping for the pre-refactor and v2 release-candidate lines.

## [v2.0.0-rc.1] - 2026-04-18

### Added

- Phase 1 corpus inventory, overlap matrix, and short ADR log for structural decisions.
- Phase 2 frontmatter across the full `references/` corpus plus `docs/stale.md`.
- Phase 4 shared `references/_core-invariants.md` baseline and router-style `SKILL.md`.
- Phase 5 offline eval harness with positive and negative routing fixtures.
- Phase 6 `scripts/lint-skill.py`, CI skill-integrity checks, and contribution guidance.

### Changed

- Reorganized `references/` by domain with generated `references/_index.md` and redirects.
- Reworked `SKILL.md` into a compact routing layer with explicit load and do-not-load guidance.

## [v1.0.0] - 2026-04-18

### Added

- Portable `SKILL.md` plus `references/` corpus for Claude, Codex, Gemini, and ChatGPT workflows.
- Official provider guidance from OpenAI, Google, and Anthropic, including Project Glasswing / Claude Mythos references.
- Defensive AI tool profiles and posture bundles under `templates/ai-tool-profiles/`.

### Changed

- Repositioned the repository from the old `tools/ai-skills` packaging into a portable skill layout.
- Tightened the root skill triggers and GitHub repository metadata for application-security and AI-agent-security discovery.

## [pre-semver]

### Added

- Initial security reference corpus, workflow templates, and GitHub automation before semantic tagging.

[Unreleased]: https://github.com/inerthel-agi/security-hardening/compare/v2.0.0-rc.1...HEAD
[v2.0.0-rc.1]: https://github.com/inerthel-agi/security-hardening/compare/v1.0.0...v2.0.0-rc.1
[v1.0.0]: https://github.com/inerthel-agi/security-hardening/releases/tag/v1.0.0
