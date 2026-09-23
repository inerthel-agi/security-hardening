# Security Hardening Reference

A portable defensive application security and AI-agent security skill for developers, founders, DevOps engineers, and security practitioners. Covers secure design, secure code review, infrastructure hardening, identity, privacy, incident response, vulnerability management, and AI/LLM agent security.

Built on: **OWASP**, **NIST 800-53 / 800-63B**, **CIS Benchmarks**, **OWASP ASVS**.

---

## Entry points

- Humans: use this `README.md` for install, release channels, onboarding, and documentation licensing.
- Agents: use [INDEX.md](INDEX.md) for compact corpus navigation and [SKILL.md](SKILL.md) for routing rules.

## License

This repository is licensed under the Apache License, Version 2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE). If a file includes a different attribution or third-party restriction, that notice controls for that material.

---

## Core stance

- Treat prompt injection, system prompt leakage, RAG poisoning, MCP abuse, and excessive agent autonomy as first-class security problems.
- Do not treat the system prompt, model refusal behavior, or vendor defaults as security boundaries.
- Prefer read-only defaults, explicit elevation, tool trust zones, structured validation, and operator-visible kill switches.
- Use this repository as a portable skill and reference corpus; agents should follow the **scan → triage → defensive fix → re-scan** loop in `SKILL.md` when reviewing AI-generated patches.

### Operational secure review (agents)

When reviewing or hardening AI-generated code:

```bash
# Requires: Python 3, optionally semgrep and gitleaks on PATH (or Semgrep Docker image)
# Default is detect-only: static scan, no production DB touch, no file edits by the script.
python3 scripts/secure-review.py path/to/changed-code --mode detect -o review.json
python3 scripts/map_findings.py --report review.json
# Apply defensive source fixes only when explicitly requested, then:
python3 scripts/secure-review.py path/to/changed-code --mode detect -o review-after.json
python3 scripts/rescan-after-fix.py review.json review-after.json
```

Local Semgrep rules live under `semgrep/`. The runbook is `references/appsec/ai-code-secure-remediation.md`.

Example prompts:

```
Review and harden this AI-generated patch
Fix after Semgrep: shell=True in this file
Scan and fix secrets and injection risks in this diff
```

---

## Official provider signals baked into this repo

This corpus now explicitly incorporates recent official cybersecurity guidance and deployment signals from OpenAI, Google, and Anthropic:

- **OpenAI - Trusted Access for Cyber (February 5, 2026):** OpenAI says `GPT-5.3-Codex` can work autonomously for hours or days on complex cyber tasks, and pairs that capability with identity verification, classifier-based monitoring, and trust-based access for higher-risk workflows. Source: [OpenAI - Introducing Trusted Access for Cyber](https://openai.com/index/trusted-access-for-cyber/)
- **Google - SAIF Risk Assessment (October 24, 2024):** Google explicitly maps `Data Poisoning`, `Prompt Injection`, and `Model Source Tampering` to risk assessment and mitigation guidance for AI systems. Source: [Google - SAIF Risk Assessment](https://blog.google/innovation-and-ai/technology/safety-security/google-ai-saif-risk-assessment/)
- **Google - AI security announcements (July 15, 2025):** Google says its `Big Sleep` agent found a real-world security flaw at risk of exploitation, reinforcing the case for AI-assisted defense with strong governance. Source: [Google - A summer of security: empowering cyber defenders with AI](https://blog.google/innovation-and-ai/technology/safety-security/cybersecurity-updates-summer-2025/)
- **Anthropic - Project Glasswing (April 2026):** Anthropic says `Claude Mythos Preview` can surpass all but the most skilled humans at finding and exploiting software vulnerabilities, so access is being limited to defensive partners rather than opened broadly. Source: [Anthropic - Project Glasswing](https://www.anthropic.com/glasswing)
- **Anthropic - Mythos system card listing (April 2026):** Anthropic lists `Mythos Preview` on its official system cards page, which is the canonical public entry point for the model's capability and safety documentation. Source: [Anthropic - Model system cards](https://www.anthropic.com/system-cards)
- **Anthropic - Responsible Scaling Policy updates (page reviewed April 18, 2026):** Anthropic's RSP updates and required safeguards reinforce that stronger frontier models need stronger operational controls, including reviewed infrastructure changes and cloud security posture management. Source: [Anthropic - Responsible Scaling Policy](https://www.anthropic.com/responsible-scaling-policy)

The practical implication for this repository is simple: as cyber-capable models improve, the default answer is **not** to give them more power. The default answer is to improve gating, logging, trust separation, incident response, and recovery.

---

## Use as a skill

This repository is designed as a portable security knowledge base. It is primarily packaged as a **Claude Code skill**, but the same `SKILL.md` + `references/` corpus can be loaded into any AI coding assistant. Installation guides for all major tools are below.

### Release channels

- **Compatibility default:** `v1.0.0` is the last pre-refactor portable snapshot for existing consumers.
- **Preview / refactor line:** `v2.0.0-rc.1` contains the changes produced by phases 1-6 of the refactor.
- **Working branch:** `main` may move ahead of both tags during ongoing refactor work.

### 0. Install with agentskill.sh

If the assistant supports `agentskill.sh`, give it this exact instruction:

```text
Install the skill "security-hardening" from https://agentskill.sh/@inerthel-agi/security-hardening
```

`agentskill.sh` is a third-party skill installer. Review its source before trusting it in CI or on a shared machine.
The official install paths are documented below.

### 1. Clone the repository

```bash
git clone --branch v1.0.0 --depth 1 https://github.com/inerthel-agi/security-hardening.git
cd security-hardening
```

If you want the refactor preview instead, use:

```bash
git clone https://github.com/inerthel-agi/security-hardening.git
cd security-hardening
git checkout v2.0.0-rc.1
```

---

### Install in Claude Code (CLI / IDE)

Add the skill to your Claude Code settings file (`~/.claude/settings.json`):

```json
{
  "skills": [
    {
      "name": "security-hardening",
      "path": "/path/to/security-hardening"
    }
  ]
}
```

Claude Code will auto-load `SKILL.md` and the `references/` directory whenever a security trigger fires. Replace `/path/to/security-hardening` with your local clone path.

---

### Install in Claude on the Web (claude.ai Projects / Skills)

Claude on the web supports **Skills** and **Projects** with attached files.

**Option A - Skills (recommended):**

1. Open [claude.ai](https://claude.ai) > **Settings** > **Capabilities** > **Skills** > **Create skill**.
2. Name it `security-hardening`.
3. Upload `SKILL.md` and every file under `references/` (drag-and-drop the folder).
4. The skill activates automatically on security questions.

**Option B - Project knowledge:**

1. Create a new **Project** named "Security Hardening".
2. In **Project knowledge**, upload `SKILL.md` + the `references/` folder (zip if needed).
3. Paste the body of `SKILL.md` into the **Custom instructions** field so the model always applies the workflow.

---

### Install in Gemini CLI

[Gemini CLI](https://github.com/google-gemini/gemini-cli) reads context from `GEMINI.md` files and supports extensions.

**Option A - Project context (per-repo):**

```bash
cp /path/to/security-hardening/SKILL.md ./GEMINI.md
ln -s /path/to/security-hardening/references ./.gemini/security-references
```

**Option B - Global context (all projects):**

```bash
mkdir -p ~/.gemini
cat /path/to/security-hardening/SKILL.md >> ~/.gemini/GEMINI.md
ln -s /path/to/security-hardening/references ~/.gemini/security-references
```

Gemini CLI loads `GEMINI.md` automatically at session start. Reference individual files inline with `@.gemini/security-references/appsec/owasp-top10.md`.

---

### Install in ChatGPT (Custom GPT or Project)

**Option A - Custom GPT (shareable):**

1. Go to [chatgpt.com/gpts/editor](https://chatgpt.com/gpts/editor) > **Create**.
2. Name: `Security Hardening Auditor`.
3. **Instructions:** paste the contents of `SKILL.md`.
4. **Knowledge:** upload every file under `references/` (max 20 files per GPT - if you exceed the limit, zip rarely-used references or split into two GPTs by category).
5. **Capabilities:** enable **Code Interpreter** for log/config parsing.
6. Save and pin to your sidebar.

**Option B - Project (single account):**

1. Create a new **Project** in ChatGPT.
2. Add `SKILL.md` content as **Project instructions**.
3. Upload `references/*.md` to **Project files**.
4. Every chat in that Project will use the security knowledge base.

---

### Install in Codex / OpenAI Codex CLI

[Codex CLI](https://github.com/openai/codex) reads `AGENTS.md` files (project-level and global) for persistent instructions.

**Option A - Per-repo:**

```bash
cp /path/to/security-hardening/SKILL.md ./AGENTS.md
cp -r /path/to/security-hardening/references ./.codex/security-references
```

**Option B - Global (all repos):**

```bash
mkdir -p ~/.codex
cat /path/to/security-hardening/SKILL.md >> ~/.codex/AGENTS.md
cp -r /path/to/security-hardening/references ~/.codex/security-references
```

Codex loads `AGENTS.md` from the working directory and `~/.codex/AGENTS.md` globally on every session.

---

### Add the CI pipeline to your project

Copy the GitHub Actions workflow into your own project to get automated security scanning on every push:

```bash
mkdir -p your-project/.github/workflows
cp .github/workflows/security.yml your-project/.github/workflows/
cp .github/pull_request_template.md your-project/.github/
cp .github/dependabot.yml your-project/.github/
```

### Add the .gitignore template

```bash
cat .gitignore-security-template >> your-project/.gitignore
```

### Copy-paste defensive AI tool profiles

The repository now ships ready-to-copy profiles under `templates/ai-tool-profiles/` for:

- `Claude Code`
- `Codex`
- `Gemini CLI`
- `Cursor`
- no-code / low-code / automation tools

It also ships posture overlays under `templates/ai-tool-profiles/postures/` for:

- `solo`
- `startup`
- `prod-sensitive`
- `gdpr-sensitive`

Premerged bundles are available under `templates/ai-tool-profiles/bundles/` for:

- `claude-code-prod-sensitive`
- `cursor-prod-sensitive`
- `gemini-cli-prod-sensitive`
- `codex-gdpr-sensitive`
- `no-code-gdpr-sensitive`

See `references/ai/ai-tool-profiles.md` for base-profile selection, bundle selection, and exact copy paths per tool.

### Trigger phrases (any tool)

Once installed, the skill activates on prompts like:

```
"Is this code secure?"
"Review my authentication logic"
"Audit this API endpoint for OWASP issues"
"Harden my nginx config"
"Check for secret leaks in this file"
"Threat-model this feature"
"Review and harden this AI-generated patch"
"Fix after Semgrep"
```

### Maximum-Protection Quick Start

If your goal is "defense first", work through the corpus in this order:

1. `references/ops/defensive-security-baseline.md`
2. `references/ai/quick-start-ai-coding.md` + `references/ai/ai-cli-hardening.md`
3. `references/ai/ai-ide-no-code-security.md`
4. `references/ops/secret-leak-prevention.md` + `references/ops/pre-push-checklist.md`
5. `references/privacy/privacy-data-minimization.md` + `references/privacy/gdpr-security-ops.md`
6. `references/ai/ai-agent-incident-response.md` + `references/ops/incident-playbooks.md`

---

## Table of Contents

- [Core Stance](#core-stance)
- [Official Provider Signals Baked Into This Repo](#official-provider-signals-baked-into-this-repo)
- [Use as a Skill](#use-as-a-skill)
- [Web Application Security](#web-application-security)
- [Infrastructure & Configuration](#infrastructure--configuration)
- [Identity & Access Management](#identity--access-management)
- [Platform Security](#platform-security)
- [Human Layer](#human-layer)
- [Personal / Executive Defense](#personal--executive-defense)
- [AI / LLM, Agent & MCP Security](#ai--llm--agent-security)
- [Privacy and Operations](#privacy-and-operations)
- [Improvement Plan & Audit Tools](#improvement-plan--audit-tools)
- [Automation](#automation)
- [External References](#external-references)

---

## Web Application Security

### `references/appsec/owasp-top10.md`
Quick-reference for the **OWASP Top 10 (2021)**. For each category: what it is, attack examples, and practical fixes.

Covers: Broken Access Control, Cryptographic Failures, Injection, Insecure Design, Security Misconfiguration, Vulnerable Components, Auth Failures, Integrity Failures, Logging Failures, SSRF.

### `references/appsec/database-security.md`
**Database hardening** patterns: parameterized queries by ORM, Postgres Row-Level Security (RLS), least-privilege application accounts, encryption at rest, backup security, audit logging.

### `references/appsec/webhooks-security.md`
**Webhook security**: HMAC signature verification (timing-safe compare), replay protection (timestamp + nonce), idempotency keys, retry handling, IP allowlist limitations, secret rotation.

### `references/appsec/threat-modeling.md`
**Threat modeling** methodologies: STRIDE, LINDDUN (privacy), PASTA (risk-centric), Data Flow Diagrams, trust boundaries, abuse cases, threat library, sample workshop agenda.

### `references/appsec/api-security.md`
**OWASP API Security Top 10 (2023)** with code examples for every risk.

Covers: BOLA/IDOR, BFLA, mass assignment, rate limiting, JSON schema validation, SSRF, secure error handling, webhook signature verification, GraphQL depth/complexity limits, pagination security.

### `references/appsec/graphql-security.md`
**GraphQL security** beyond generic API checks.

Covers: object and field-level authorization, introspection disablement, depth and complexity budgets, alias/batching caps, persisted queries, multipart upload risks, WebSocket subscriptions, telemetry, and N+1 / backend fan-out abuse.

### `references/appsec/secure-headers.md`
**HTTP security header examples** with copy-paste values.

Covers: HSTS, CSP (nonce/hash-based), X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy, COEP/COOP/CORP, cookie attributes (`Secure`, `HttpOnly`, `SameSite`), CORS, headers to remove, drop-in blocks for **Nginx** and **Cloudflare Workers**.

### `references/appsec/browser-security-modern.md`
**Modern browser hardening** beyond classic headers.

Covers: Trusted Types, Subresource Integrity (SRI), COOP/COEP/CORP isolation, Permissions Policy, Worker / WebSocket / WASM surfaces, and report-only rollout strategy for legacy frontends.

### `references/appsec/language-patterns.md`
Per-language **dangerous code patterns** with vulnerable vs. safe alternatives for security audits.

| Language | Patterns covered |
|----------|-----------------|
| Node.js / JavaScript | Command injection, `eval`, prototype pollution, path traversal, NoSQL injection |
| Python | Command injection, `eval`/`exec`, `pickle.loads`, path traversal, SSTI (Jinja2) |
| PHP | Command injection, `eval`, file inclusion, SQL injection, `extract()` |
| Go | Template injection, command injection, path traversal, SQL injection |
| Ruby | Command injection, `eval`/ERB, `Marshal.load`, mass assignment |
| Java | SQL injection, XXE, unsafe deserialization |
| PowerShell | `Invoke-Expression`, command injection, path traversal, `ConvertTo-SecureString -AsPlainText`, TLS bypass, download-and-run, ExecutionPolicy myth, PSScriptAnalyzer rules |
| Bash / POSIX shell | Word splitting, unquoted `$var`, missing `set -Eeuo pipefail`, `find`/`xargs` injection, `curl \| sh`, temp file races, secrets in argv, `IFS`/`PATH` tampering, shellcheck rules |

### `references/ops/secret-leak-prevention.md`
Complete guide to preventing, detecting, and responding to secret leaks in Git. Covers every stage: pre-commit blocking, CI scanning, GitHub push protection, incident response (revoke first, then clean history), detection by secret type, frontend special cases, safe-by-design patterns, and a `.gitignore` security template.

Includes: per-provider revocation steps (OpenAI, AWS, GitHub, Stripe, GCP, Slack...), a detection table with regex patterns, frontend-safe vs. never-in-frontend key matrix, 8 common vibecoder leak traps, and secrets manager examples (Vault, AWS Secrets Manager, SOPS, Doppler).

### `references/ai/quick-start-ai-coding.md`
**Start here if you use AI to write code.** 10 things to check before every push, a false-sense-of-security table, what to do when something goes wrong, and a 5-minute security setup for a new project.

Covers: secret detection, dangerous patterns (eval/shell=True/pickle), IDOR prevention, password hashing, frontend key safety, error message leaks, input validation, TLS verify, dependency audit, and a quick-reference card.

### `references/ops/pre-push-checklist.md`
Operational checklist to run in 2 minutes before every `git push`. Organized by category with copy-paste `grep` commands for quick scanning.

Covers: secrets, dangerous patterns, auth/authorization, input/output, sensitive data, dependencies, configuration, and frontend-specific checks.

### `references/appsec/production-error-handling.md`
How to handle errors, logs, and config in production without leaking internals.

Covers: generic error responses with reference IDs, correct HTTP status codes (401 vs 403 vs 404), removing server banners, what to log vs. never log, log field redaction (Pino, Zap, structlog), startup config validation (fail-fast if secrets missing), debug mode risks, and CORS error response safety.

### `references/ai/vibecoder-traps.md`
**12 common mistakes** made by developers copy-pasting LLM-generated or Stack Overflow code, with fixes.

Covers: `eval`, `pickle.loads`, `shell=True`, SHA-256 for passwords, CORS wildcard with credentials, file upload without validation, logging PII/tokens, disabling TLS verify, Docker as root, mass assignment, missing rate limiting, trusting frontend for roles.

---

## Infrastructure & Configuration

### `references/appsec/secure-headers.md`
See [Web Application Security](#web-application-security) above - also includes Nginx hardening block and Cloudflare Workers config.

### `references/infra/rate-limiting-infrastructure.md`
**Infrastructure rate limiting patterns** at the edge, proxy, app, and shared-store layers.

Covers: Nginx examples, Redis-backed counters, per-route and per-identity quotas, `Retry-After`, 429 telemetry, proxy trust pitfalls, and abuse-specific limit design for login, OTP, search, uploads, and GraphQL.

### `references/infra/iot-ot-security.md`
**IoT and OT/Industrial** network security.

Covers: Purdue Model segmentation (IT/OT DMZ), default credential elimination, legacy protocol risks (Modbus, DNP3, BACnet, PROFINET), firmware/patch management, passive OT monitoring, OT-specific incident response (safety-first containment).

---

## Identity & Access Management

### `references/iam/authorization-rbac.md`
**RBAC, ABAC, and ReBAC** models with code examples. Deny-by-default pattern and IDOR/BOLA prevention.

Covers: RBAC implementation, ABAC with OPA, ReBAC with OpenFGA, deny-by-default, IDOR/BOLA safe patterns, common anti-patterns (frontend-only check, role from client payload), 404 vs 403 strategy.

### `references/iam/session-management.md`
**Session management** after login, not just authentication at the front door.

Covers: session rotation after login or privilege change, server-side invalidation, logout-all-devices, idle and absolute timeouts, fixation prevention, refresh-token revocation, cookie baselines, and concurrent session handling.

### `references/iam/webauthn-fido2.md`
**WebAuthn / FIDO2 implementation guide** for phishing-resistant authentication.

Covers: RP ID and origin verification, challenge lifecycle, registration/authentication ceremonies, passkeys, user-verification defaults, attestation decisions, counter handling, and secure recovery design.

### `references/iam/active-directory-hardening.md`
**Active Directory and Entra ID (Azure AD)** hardening.

Covers: Tiering Model (Tier 0/1/2), LAPS, disabling SMBv1 / LLMNR / NTLMv1, Kerberoasting and AS-REP Roasting mitigations, gMSA, Protected Users group, Conditional Access, PIM (just-in-time elevation), risky sign-in monitoring. Tools: BloodHound, PingCastle, Purple Knight.

---

## Platform Security

### `references/platform/mobile-security.md`
**OWASP Mobile Top 10 (2024)** for iOS and Android, with Swift and Kotlin code examples.

Covers: Keychain/Keystore secure storage, certificate pinning, cleartext traffic prevention, binary protections (ProGuard, obfuscation), root/jailbreak detection, permission least privilege, PII in logs, `debuggable=false`. Tools: MobSF, Frida, objection, Drozer.

### `references/platform/desktop-app-security.md`
**C/C++, C#/.NET, and Electron** application security.

Covers: Buffer overflows, format string injection, compiler hardening flags (ASLR, DEP, stack canaries), C# deserialization (BinaryFormatter), XXE, DLL hijacking mitigations, Electron secure configuration (`nodeIntegration: false`, `contextIsolation: true`, `sandbox: true`, IPC validation). Tools: Process Monitor, Electronegativity, AddressSanitizer.

### `references/platform/endpoint-vba-security.md`
**Office macros (VBA)** and endpoint hardening.

Covers: Dangerous VBA patterns (Shell, WScript, ADODB), AMSI integration, macro signing, AppLocker/WDAC application whitelisting, Credential Guard, EDR deployment, BitLocker/FileVault, local admin rights removal. Tools: CIS-CAT Lite, OSQuery, Sysinternals Autoruns.

---

## Human Layer

### `references/ops/social-engineering-physical.md`
**Phishing, BEC, vishing, and physical security** controls.

Covers: Email authentication (SPF, DKIM, DMARC `p=reject`), phishing-resistant MFA (FIDO2/WebAuthn), AiTM bypass risks, simulated phishing (GoPhish), CEO fraud / IBAN change verification procedures, clean desk policy, badge access control, tailgating prevention, MDM remote wipe, security awareness program KPIs.

---

## Personal / Executive Defense

### `references/ops/defensive-security-baseline.md`
**Maximum-protection defensive baseline** for developers, founders, executives, and small teams.

Covers: priority account hardening (password manager + FIDO2), separate admin accounts, full-disk encryption, browser/profile separation, safe AI usage, BEC-resistant payment verification, travel mode, immutable backups, SaaS/SSO hardening, and a 30-minute / 7-day / 30-day rollout plan.

---

## AI / LLM & Agent Security

### `references/ai/llm-agent-security.md`
**OWASP LLM Top 10 (2025)** and agentic security controls.

Covers: Prompt injection (direct and indirect), sensitive data disclosure via context, excessive agency, RAG poisoning, secrets in system prompts, agentic action audit logging, tool permission tiers (Level 0-3), output validation before execution, MCP server security (authentication, tool allowlists, sandboxing), plus official provider signals from **OpenAI**, **Google**, and **Anthropic** including `Claude Mythos Preview`.

### `references/ai/browser-computer-use-security.md`
**Dedicated browser / computer-use hardening guide** for GUI-driving agents and authenticated click-flow automation.

Covers: sandbox/VM isolation, domain allowlists, session hygiene, uploads/downloads, credential entry boundaries, login and publish confirmations, local-OS spillover risk, screenshot/action telemetry, and release gates for browser/computer-use before widening scope.

### `references/ai/mcp-security.md`
**Dedicated MCP (Model Context Protocol) security reference** covering the four main attack vectors when giving an AI agent "hands and eyes" via external tools.

Covers: Excessive Agency (HITL confirmation patterns, least-privilege Docker/volume configs, narrow endpoint design), Indirect Prompt Injection via MCP (step-by-step attack chain, LLM-as-a-Judge sanitization, chained-action prevention), Server Spoofing and malicious manifests (allowlist enforcement, static manifest validation, supply chain audit), Path Traversal and SSRF in MCP tool parameters (Python validators for `read_file` and `fetch_url`, Pydantic schema enforcement, SSRF blocklist with private ranges and AWS IMDS).

### `references/ai/rag-retrieval-security.md`
**Dedicated RAG / retrieval security guide** for vector stores, knowledge bases, semantic search, and embedding-backed systems.

Covers: corpus trust tiers, retrieval-aware authorization, attribute filtering, over-broad top-k retrieval, vector-store lifecycle and expiration, eventual-consistency deletion gaps, source attribution, document poisoning, and cross-tenant leakage in shared stores.

### `references/ai/hostile-corpus-review.md`
**Hostile corpus review workflow** for untrusted prompts, docs, tickets, MCP output, and copied code.

Covers: trust tiering, ingest-without-executing, normalization, hidden-instruction stripping, known-bad pattern scanning, fact-vs-instruction separation, quarantine decisions, and validation before adoption.

### `references/ai/ai-cli-hardening.md`
**Operational hardening baseline for AI coding CLIs** (Claude Code, Codex CLI, Gemini CLI, and similar tools).

Covers: default-deny permissions, tiered elevation model (read-only to high-impact actions), policy-as-code template, prompt/context firewall controls, secret-safe workflows, Git/release integrity controls, CI guardrails, and maturity roadmap by team size.

### `references/ai/ai-tool-profiles.md`
**Copy-paste defensive profile map** for Claude Code, Codex, Gemini CLI, Cursor, and no-code / low-code tools.

Covers: exact template paths, posture overlays, premerged bundle selection, direct copy paths for the repository's conservative presets, and links to official vendor documentation used for the field names or behavior.

### `references/ai/ai-ide-no-code-security.md`
**Security guide for AI IDE assistants, browser builders, and no-code / low-code tools**.

Covers: Cursor-style workspace risks, extension/plugin trust, public preview exposure, connector scope sprawl, service-account ownership, prompt/data hygiene, publish gates, exportability, and human review areas that cannot be delegated to the tool.

### `references/ai/agent-evals-red-teaming.md`
**Defensive adversarial-evaluation guide** for agentic systems before rollout or after model, tool, or permission changes.

Covers: release-gate design, hostile-fixture families, excessive-agency checks, MCP/tool abuse scenarios, telemetry expectations, regression metrics, and how to turn incidents or near misses back into standing eval cases.

### `references/ai/ai-agent-incident-response.md`
**Incident response playbook dedicated to AI agents** and MCP-enabled workflows.

Covers: severity model, first 15-minute containment steps, evidence collection, timeline reconstruction, blast radius analysis, eradication/recovery, communication template, and post-incident hardening actions specific to agentic systems.

---

## Privacy and Operations

### `references/privacy/gdpr-security-ops.md`
**Operational GDPR / RGPD security guide** mapping Articles 5/25/28/30/32/33/35 and transfer controls to engineering and security actions.

Covers: data inventory, RoPA, technical and organizational measures, DPA / SCC / TIA vendor checks, breach notification timeline, DSAR/delete/export workflows, evidence pack for audits, and common red flags.

### `references/privacy/privacy-data-minimization.md`
**Privacy by design** - how to stop leaking PII through logs, errors, exports, and analytics.

Covers: PII categories and what counts as sensitive in logs, structured log redaction (Pino `redact`, Zap custom fields, Python logging), automated log scanning for PII patterns, retention policy template per data category (logs 90d, transactions 7y, sessions TTL), scheduled anonymization/deletion jobs (Django + SQL), GDPR right to erasure implementation (multi-system erasure service), PII in exception reporting (Sentry `send_default_pii=False`, scrubbing hook), sensitive data in support dumps and backups (encryption), analytics data minimization (`userId` only, no email/phone), session recording masking (FullStory, LogRocket, Hotjar).

### `references/ops/vuln-management.md`
**Vulnerability management process** from scanner output to closed finding - triage, SLA, false positives, risk acceptance.

Covers: Vulnerability lifecycle diagram, finding sources and signal quality (SAST/SCA/DAST/secrets), severity classification with context adjustment rules (internet-facing = bump up, auth required = bump down), SLA table (Critical 24h, High 7d, Medium 30d, Low 90d), triage decision tree (reachable? exploitable? blast radius? mitigating controls?), triage outcome classification (fix/accept/false positive/not applicable/compensating control), false positive documentation with in-code suppression justification (nosemgrep/noqa with mandatory comment), risk acceptance template (expiry, dual approval, compensating controls), compensating controls per vulnerability type, metrics dashboard (MTTR, SLA compliance rate, recurring types), dependency reachability analysis (govulncheck, trivy --ignore-unfixed).

---

## Improvement Plan & Audit Tools

### `references/ops/security-improvements.md`
Structured **7-axis defense-in-depth improvement plan** with quick wins and long-term actions per axis. Sources: OWASP, NIST 800-53/800-63B, CIS Benchmarks.

Axes: code security, authentication, infrastructure, supply chain, CI/CD DevSecOps, monitoring/incident response, offensive testing.

### `references/ops/detection-engineering.md`
**Detection engineering starter pack** for app, identity, GraphQL, AI, cloud, and supply-chain abuse.

Covers: Sigma-style rules, threshold guidance, required log sources, and example detections for credential stuffing, token replay, IDOR/BOLA, GraphQL introspection or alias abuse, IMDS probing, suspicious AI tool sequences, Kubernetes secret/exec abuse, and CI/CD tampering.

### `references/appsec/frontend-frameworks-security.md`
**Security risks specific to modern SPA and SSR frameworks** (React, Next.js, Vue, Nuxt) beyond classic OWASP XSS coverage.

Covers: SSR data leaks - `__NEXT_DATA__` exposes full DB objects in HTML (audit command, fix pattern for `getServerSideProps` / `useAsyncData` / RSC), DOM-based XSS in React (`dangerouslySetInnerHTML` + DOMPurify, `javascript:` href injection) and Vue (`v-html`), Prototype Pollution (attack chain via `__proto__`, vulnerable lodash/jQuery/qs versions, `Object.freeze` and `structuredClone` mitigations), client-side secret exposure (`NEXT_PUBLIC_` trap, bundle audit), CSRF in SPAs (double-submit cookie pattern), nonce-based CSP with Next.js middleware.

### `references/infra/supply-chain-security.md`
**Software supply chain security** from code to production. Covers the attack surfaces exposed by SolarWinds, Log4Shell, and the XZ Utils backdoor.

Covers: SLSA framework (levels 0-3, requirements table, GitHub Actions provenance workflow with slsa-github-generator), SBOM generation (Syft and Trivy, SPDX and CycloneDX, CI attachment, CVE scan against SBOM), Dependency Confusion attack and mitigations (npm scoped packages, pip `--index-url` vs `--extra-index-url`, hash pinning), Cosign/Sigstore keyless image signing and verification, gitsign for commit signing, GitHub Actions hardening (commit SHA pinning, OIDC instead of static keys, minimal permissions per job), dependency scanning (npm audit, pip-audit, govulncheck, OpenSSF Scorecard).

### `references/appsec/applied-cryptography.md`
**Algorithm selection and copy-paste code examples** for developers who need to make cryptographic decisions. Covers the most common mistakes (CWE-916, CWE-327, CWE-338).

Covers: password hashing (Argon2id vs bcrypt vs MD5 - why fast hashes are wrong), authenticated encryption (AES-256-GCM and ChaCha20-Poly1305 with encrypt/decrypt examples in Python/Node.js/Go), asymmetric algorithm selection table (Ed25519, ECDSA P-256, RSA), TLS 1.3 configuration, CSPRNG usage (`secrets`, `crypto.randomBytes`, `crypto/rand`), HMAC vs plain hash, quick reference table (use case / recommended / never use), CWE mapping for 8 common crypto mistakes.

### `references/compliance/cwe-owasp-mapping.md`
**Cross-reference table** linking CWE, OWASP Top 10, OWASP ASVS controls, vulnerable code patterns, and SAST tool/rule for automated detection.

Covers: injection, authentication, access control, cryptography, secrets, supply chain. Includes quick tool command reference (Semgrep, Bandit, Gosec, Gitleaks, Trivy, OWASP ZAP).

### `references/compliance/compliance-mapping.md`
**Compliance crosswalk** linking the repo guidance to evidence expectations.

Covers: high-level mapping toward SOC 2, ISO 27001:2022, PCI-DSS v4.0, HIPAA, GDPR/RGPD, NIS2, and DORA, plus the evidence types auditors usually expect for technical and organizational controls.

### `references/ops/security-audit-levels.md`
Progressive audit framework from solo developer to expert review. Tells you exactly where to start, what to check at each level, how long it takes, which tools to use, and when to move to the next level.

| Level | For who | Time | Key focus |
|-------|---------|------|-----------|
| 1 | Solo dev / MVP | 30-90 min | Secrets, deps, basic headers, dangerous patterns |
| 2 | Live app with users | Half-day to 1 day | IDOR, input validation, CORS, rate limiting |
| 3 | Production SaaS / team | 1-3 days | AuthZ model, supply chain, infra hardening, detection |
| 4 | Regulated / critical | Days to weeks | Threat model, pentest, fuzzing, red team |

Also includes a coverage matrix linking every reference file in this repo to its audit level(s).

### `references/appsec/security-testing-examples.md`
Executable security tests ready to add to your test suite. Failing tests mean the security control is missing.

Covers (pytest, Jest, Go): IDOR/authorization, rate limiting, GraphQL introspection/depth/alias/authz checks, file upload (extension, MIME, size, path traversal, SVG XSS), SSRF (localhost, AWS metadata, private ranges), error handling (no stack trace, reference ID), security headers, webhook signature verification. Includes OWASP ZAP Docker baseline scan.

### `references/iam/cloud-iam-hardening.md`
**AWS, GCP, and Azure** hardening with audit commands and copy-paste configurations.

Covers: IAM least privilege, no wildcard policies, MFA enforcement, S3/GCS/Blob public access prevention, Secrets Manager usage, IMDSv2 (SSRF protection on EC2), CloudTrail audit logging, CI/CD OIDC (no long-lived keys), IaC scanning (Checkov, tfsec).

### `references/infra/container-k8s-hardening.md`
**Docker and Kubernetes** hardening from Dockerfile to cluster admission policies.

Covers: non-root Dockerfiles, multi-stage builds, read-only filesystems, Trivy image scanning, K8s Pod Security Standards, network policies (default-deny), Secrets via External Secrets Operator or Vault, RBAC minimal roles, Kyverno admission policies, Cosign image signing.

### `references/ops/incident-playbooks.md`
Step-by-step response procedures for the 6 most common security incidents.

Playbooks: compromised user account, webhook/integration token compromise, JWT signing secret leaked, cloud storage bucket exposed, verbose errors/debug mode in production, CORS misconfiguration. Each follows Detect - Contain - Investigate - Remediate - Review. Includes postmortem template.

### `references/compliance/coverage-matrix.md`
Overview of all reference files: depth, priority, **audit level**, review frequency, and automation availability. Includes coverage gaps backlog.

### `references/appsec/security-myths.md`
11 common misconceptions with explanation and fix: WAF as sole defense, SHA-256 for passwords, "JWT = security", CORS protecting APIs, secrets in .env, HTTPS being sufficient, no rate limiting, security through obscurity, OAuth misuse, Docker isolation, code review alone.

### `references/appsec/framework-examples.md`
Copy-paste security configurations per framework: headers, JWT auth middleware, input validation, rate limiting, safe error handling, IDOR-safe DB queries.

Covers: **Express**, **NestJS**, **FastAPI**, **Django**, **Laravel**, **Spring Boot**, **Go (Gin)**.

---

## Automation

### `.github/workflows/security.yml`
**GitHub Actions security pipeline** running on every push and PR - copy this into any project.

Jobs: Gitleaks (secret scanning), Semgrep (SAST), Trivy filesystem scan (dependency CVEs, blocks on CRITICAL/HIGH), Syft SBOM generation (artifact upload), Dependency Review (blocks PRs introducing vulnerable deps).

### `.github/pull_request_template.md`
**Security checklist** enforced on every PR before review.

Sections: input/output validation, authentication & authorization, privacy / GDPR, secrets & sensitive data, AI / automation, dependencies, network & API, code quality.

### `.github/dependabot.yml`
Keeps pinned GitHub Actions dependencies fresh with controlled update PRs.

### `.github/CODEOWNERS`
Provides a review boundary for sensitive repository paths.

---

## External References

| Standard / Tool | Link |
|----------------|------|
| OWASP Top 10 | https://owasp.org/www-project-top-ten/ |
| OWASP API Security Top 10 | https://owasp.org/www-project-api-security/ |
| OWASP Mobile Top 10 | https://owasp.org/www-project-mobile-top-10/ |
| OWASP LLM Top 10 | https://owasp.org/www-project-top-10-for-large-language-model-applications/ |
| OWASP ASVS | https://owasp.org/www-project-application-security-verification-standard/ |
| OWASP Secure Headers | https://owasp.org/www-project-secure-headers/ |
| NIST SP 800-82 Rev 3 (OT) | https://csrc.nist.gov/pubs/sp/800/82/r3/final |
| NIST SP 800-63B (Auth) | https://pages.nist.gov/800-63-3/sp800-63b.html |
| CIS Benchmarks | https://www.cisecurity.org/cis-benchmarks/ |
| MITRE ATT&CK for ICS | https://attack.mitre.org/matrices/ics/ |
| MITRE ATLAS (AI/ML) | https://atlas.mitre.org/ |
| OpenAI - Trusted Access for Cyber | https://openai.com/index/trusted-access-for-cyber/ |
| Google - SAIF Risk Assessment | https://blog.google/innovation-and-ai/technology/safety-security/google-ai-saif-risk-assessment/ |
| Google - A summer of security: empowering cyber defenders with AI | https://blog.google/innovation-and-ai/technology/safety-security/cybersecurity-updates-summer-2025/ |
| Anthropic - Project Glasswing | https://www.anthropic.com/glasswing |
| Anthropic - Model system cards | https://www.anthropic.com/system-cards |
| Anthropic - Responsible Scaling Policy | https://www.anthropic.com/responsible-scaling-policy |
| Mozilla Observatory | https://observatory.mozilla.org |
| CISA ICS Advisories | https://www.cisa.gov/ics-advisories |

