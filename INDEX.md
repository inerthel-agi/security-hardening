# Security Hardening Routes

Machine-facing task router for this repository. Use [README.md](README.md) for installation and human onboarding, [SKILL.md](SKILL.md) for the response contract, and [references/_index.md](references/_index.md) for the exhaustive generated corpus catalog.

## Load Order

1. Read [SKILL.md](SKILL.md) and select the primary mission profile.
2. Load [references/_core-invariants.md](references/_core-invariants.md) once per active agent and context.
3. Choose the narrowest matching task route below.
4. Prefer one to three domain references per scoped pass. Add a secondary reference only when its condition is present.
5. If more than five distinct security surfaces are in scope, split the work into bounded passes and keep a visible coverage ledger; do not truncate coverage to meet a reference-count target.

Use `rg -n -i '<anchors>' <path>` to target sections in long references. If `rg` is unavailable, use the host's workspace or file search with the same anchors. Query [references/_index.md](references/_index.md) by category, slug, or title when no route names the exact file. For AI-only ambiguity, use [references/ai/_index.md](references/ai/_index.md).

## Task Routes

| Signal | Primary references | Add when | Search anchors |
|---|---|---|---|
| Code, diff, configuration, architecture, or whole-system security review | `references/appsec/security-diff-review.md` | Add the closest domain reference from `references/_index.md`; add `references/ops/defensive-security-baseline.md` for operational or whole-system baselines | `trust boundary|privilege|input|secret|dependency|fail open|blast radius` |
| API, IDOR/BOLA, input handling, web authorization | `references/appsec/api-security.md`, `references/iam/authorization-rbac.md` | Add `references/appsec/ssrf-deserialization-command-injection.md` for outbound fetches, deserialization, or shell execution | `IDOR|BOLA|object-level|deny-by-default|SSRF|command injection` |
| GraphQL authorization, batching, depth, persisted queries | `references/appsec/graphql-security.md`, `references/iam/authorization-rbac.md` | Add `references/appsec/security-testing-examples.md` when runnable regression checks are requested | `depth|batch|alias|persisted quer|resolver|authorization` |
| Threat model, abuse cases, security architecture | `references/appsec/threat-modeling.md` | Add `references/appsec/security-testing-examples.md` for tests or `references/ops/security-improvements.md` for a roadmap | `asset|actor|trust boundar|abuse case|data flow|residual risk` |
| Passwords, tokens, signing, encryption, webhooks | `references/appsec/applied-cryptography.md` | Add `references/iam/session-management.md` for sessions or `references/appsec/webhooks-security.md` for callbacks | `Argon2|AEAD|JWT|key rotation|signature|replay|session` |
| Secrets exposure, pre-push, local AI coding | `references/ops/secret-leak-prevention.md`, `references/ops/pre-push-checklist.md` | Add `references/ai/vibecoder-traps.md` when an AI tool handled the secret | `revoke|rotation|history|Gitleaks|pre-commit|prompt` |
| SSO, SAML, OIDC, AD, identity lifecycle | `references/iam/sso-saml-oidc-hardening.md`, `references/iam/identity-lifecycle-jml.md` | Add `references/iam/active-directory-hardening.md` for AD or Entra-specific controls | `issuer|audience|redirect|JIT|SCIM|offboard|conditional access` |
| Service accounts, workload identity, break-glass | `references/iam/machine-identity-and-service-accounts.md`, `references/iam/workload-identity-federation.md` | Add ownership or emergency-access references when inventory or recovery is in scope | `subject|audience|federat|owner|credential|break-glass` |
| Supply chain, CI/CD, GitHub Actions, containers | `references/infra/supply-chain-security.md` | Add `references/infra/github-actions-hardening.md` for workflows or `references/infra/container-k8s-hardening.md` for runtime isolation | `pinning|provenance|OIDC|permissions|runner|SBOM|admission` |
| Terraform, IaC, policy, cloud exceptions | `references/infra/terraform-iac-hardening.md` | Add policy recipes, exception handling, or rate limiting only for those explicit surfaces | `plan|state|provider|policy|exception|rate limit` |
| Desktop, Electron, mobile, memory safety | Select the matching `platform` file in `references/_index.md` | Add backend or supply-chain references only when that component is in scope | `sandbox|IPC|update|signing|keychain|memory|permission` |
| Workstation, MDM, browser or admin isolation | `references/platform/high-trust-admin-workstations.md` or the closest platform route in `references/_index.md` | Add `references/ops/secure-workstation-builds.md` for build baselines | `profile|isolation|admin|MDM|browser|clipboard|device` |
| AI agent, MCP, prompt injection, tool trust | `references/ai/llm-agent-security.md`, `references/ai/mcp-security.md` | Add hostile-corpus or CLI guidance only when untrusted content or a coding CLI is present | `prompt injection|tool trust|approval|capability|manifest|exfiltration` |
| Browser/computer use or authenticated GUI agent | `references/ai/browser-computer-use-security.md`, `references/ai/llm-agent-security.md` | Add CLI hardening when the browser is part of a local coding workflow | `sandbox|session|upload|download|confirmation|publish` |
| RAG, vector store, embeddings, document poisoning | `references/ai/rag-retrieval-security.md`, `references/ai/hostile-corpus-review.md` | Add general agent security when retrieved content can trigger tools | `tenant|filter|citation|poison|deletion|retrieval authorization` |
| Agent evals, multi-agent boundaries, approvals, memory | Select the matching AI governance route in `references/ai/_index.md` | Add release gates or incident response only when rollout or an event is in scope | `regression|delegation|approval|memory|retention|release gate` |
| Privacy, GDPR, retention, DSAR, AI vendors | Select the matching `privacy` file in `references/_index.md` | Add compliance evidence references only when audit evidence is requested | `minimi|retention|erasure|processor|transfer|DPIA|DSAR` |
| Compliance, questionnaires, SOC 2, ISO 27001, NIS2, DORA | Select the matching `compliance` file in `references/_index.md` | Add technical domain references only for controls that require implementation evidence | `control|evidence|owner|cadence|exception|notification` |
| Vulnerability management or security backlog | `references/ops/vuln-management.md`, `references/ops/security-backlog-triage-and-prioritization.md` | Add a domain reference for reachability or remediation details | `reachable|exploit|SLA|acceptance|compensating|priority` |
| Detection or incident response | `references/ops/incident-playbooks.md` or `references/ai/ai-agent-incident-response.md` | Add `references/ops/detection-engineering.md` for telemetry and alerts | `contain|evidence|blast radius|eradicate|recover|telemetry` |

## Machine Entrypoints

- [SKILL.md](SKILL.md): trigger, orchestration, evidence, and response-profile contract.
- [references/_core-invariants.md](references/_core-invariants.md): shared baseline loaded once per active agent and context.
- [references/_index.md](references/_index.md): exhaustive generated reference catalog and metadata.
- [references/ai/_index.md](references/ai/_index.md): narrow AI-domain subrouter.

## Validation

- `python scripts/build-index.py`
- `python scripts/lint-skill.py`
- `python evals/run.py`
