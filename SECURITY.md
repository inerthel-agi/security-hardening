# Security Policy

Thank you for helping keep `security-hardening` and its users safe. This repository ships security guidance and CI tooling that other projects copy into their own repos, so any defect in our content can have a wide blast radius. We treat reports seriously.

## Supported Versions

This repository is documentation-first. The `main` branch is the only supported version. Forks of pinned references should pull updates from `main` to receive fixes.

| Branch | Supported |
|--------|-----------|
| `main` | Yes       |
| Other  | No        |

## Reporting a Vulnerability

**Please do not open a public GitHub issue for security reports.**

Use the private reporting channel below:

1. **GitHub Private Vulnerability Reporting** (preferred) - open a report at
   <https://github.com/inerthel-agi/security-hardening/security/advisories/new>

An alternate email channel should be published here only once it is monitored and tested end-to-end.

When reporting, please include:

- A clear description of the issue and its impact (what an attacker could do, blast radius).
- Affected file(s) and line numbers, or workflow job names.
- Reproduction steps or a minimal proof of concept.
- Your suggested remediation, if you have one.
- Whether you would like public credit and how you wish to be named.

We will acknowledge receipt within **3 business days** and aim to provide a status update within **7 days**. We follow a coordinated disclosure model and will work with you on a fix and disclosure timeline (default 90 days, shorter for trivially exploitable issues).

## Scope

In scope:

- Anything in `references/*.md` that gives **wrong or dangerous** security advice (false positives that mislead users count).
- Workflows under `.github/workflows/` (privilege escalation, command injection, secret leak, supply chain).
- The skill manifest `SKILL.md` and any prompt-injection vectors it could enable in agentic tools.
- The `.gitignore-security-template` if it fails to exclude a known sensitive path.

Out of scope:

- Theoretical attacks against an upstream vendor (report directly to the vendor).
- Style, typos, and broken external links - open a normal issue or PR for those.
- Vulnerabilities in third-party tools we merely reference (Gitleaks, Trivy, Semgrep, etc.).

## Safe Harbor

We will not pursue legal action against researchers who:

- Make a good-faith effort to follow this policy.
- Do not exfiltrate data beyond what is necessary to demonstrate the issue.
- Do not degrade service availability for other users.
- Give us a reasonable time to remediate before any public disclosure.

## Hall of Fame

We are happy to credit reporters in the published advisory. Let us know your preferred handle when you report.
