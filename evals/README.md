# Evals

This directory tests two independent properties of the `security-hardening` skill:

1. **Trigger campaign** — a fresh agent receives only the user request. This measures whether the skill activates without being named or primed.
2. **Execution campaign** — a fresh agent is explicitly told to use the skill. This measures profile selection, reference routing, and response contracts.

The runner never sends fixture ground truth to the model. `expected_profile`, `should_load`, exclusions, and semantic contracts stay evaluator-only.

## Coverage and result states

Static preflight validates fixture schema, globally unique `c-NNN`/`n-NNN` IDs, filename/ID equality, reference existence against the canonical `references/**/*.md` corpus, and positive/negative invariants.

Captured behavior validates:

- trigger decision and response profile;
- a collector-verified reference trace, including core exactly once, required references, exclusions, and unexpected references;
- non-empty negative responses and defensive refusal/redirection for harmful requests;
- substantive concepts rather than negated mentions or keyword lists;
- structured, non-empty execution contract fields.

Reports keep these states separate:

- `Static PASS|FAIL`: fixture and corpus integrity;
- `Behavior PASS|FAIL`: a captured response was graded;
- `Behavior UNTESTED`: no captured response was supplied.

An offline preflight can pass while behavior remains untested. Only strict mode proves that every fixture has a captured response.

## Fixture schema

Required fields:

```yaml
id: "c-001"
input: "User request"
should_trigger: true
should_load: ["references/_core-invariants.md"]
must_not_load: []
must_mention: []
must_not_mention: []
```

Execution-contract fields:

```yaml
expected_profile: "review"
required_contract: ["evidence", "confidence", "validation"]
required_load: ["references/_core-invariants.md", "references/appsec/api-security.md"]
```

Profiles are `review`, `threat-model`, `incident`, `roadmap`, `compliance`, and `implementation`. Unknown keys and contracts fail preflight. `required_load` is the minimum traced subset and must be contained by `should_load`. By default, traced domain references must also be a subset of `should_load`; a fixture may explicitly set `allow_additional_load: true` for a scenario that requires adaptive routing.

Fixtures with `expected_profile` belong to the execution campaign. All other positive and negative fixtures belong to the blind trigger campaign.

## Run

Read-only offline preflight:

```bash
python evals/run.py --no-report
```

Generate sanitized prompts:

```bash
python evals/run.py --write-prompts evals/prompts --no-report
```

This creates:

- `evals/prompts/trigger/`: request-only prompts with no skill name, response schema, or ground truth;
- `evals/prompts/execution/`: prompts that name the skill but expose only the request.

Run every prompt in a fresh context. The trace-aware collector—not the evaluated model—must record whether the skill activated and which repository files were actually read. Do not infer `loaded_refs` from model prose.

Grade a partial capture:

```bash
python evals/run.py --responses evals/responses.jsonl --no-report
```

Require exactly one captured response for every fixture and reject missing or unknown IDs:

```bash
python evals/run.py --responses evals/responses.jsonl --strict-responses --no-report
```

Omit `--no-report` to write an immutable UTC-stamped report under `evals/results/`. Reports include the repository revision, response SHA-256, runtimes, models, and strict-mode flag.

## Captured response contract

Each JSONL object has exactly these fields:

```json
{"id":"c-036","runtime":"codex-cli","model":"gpt-example","triggered":true,"profile":"review","loaded_refs":["references/_core-invariants.md","references/appsec/api-security.md"],"trace_verified":true,"output":{"evidence":"Observed evidence with enough context.","confidence":"Confidence and rationale."}}
```

`trace_verified` may be `true` only when file/tool telemetry confirms `loaded_refs`. A model statement such as “I loaded X” is not evidence. For a non-trigger case, use `triggered: false`, `profile: null`, and no path under `references/`.

Execution fixtures with `required_contract` require an object-valued `output`. Every required field must hold substantive content; empty labels, repeated keywords, arrays with no content, and prose-only keyword salads fail.

`evals/responses.example.jsonl` is a complete synthetic contract fixture for testing the evaluator. It is not evidence of a live model run.
