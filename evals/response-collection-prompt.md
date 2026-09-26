# Response Collection Protocol

This protocol is for the external evaluator or runtime adapter. Do **not** append it to an evaluated prompt: doing so would prime trigger decisions and invalidate the blind campaign.

1. Generate prompts with `python evals/run.py --write-prompts evals/prompts --no-report`.
2. Run each file in a fresh agent context with the repository available.
3. For `trigger/`, send the file contents unchanged. Do not name or force the skill.
4. For `execution/`, send the generated contents unchanged.
5. Capture the final answer plus repository file-read/tool telemetry. The evaluated model must not self-report its own trace.
6. Emit one JSON object per prompt using the schema below.

```json
{"id":"fixture id","runtime":"claude-code|codex-cli|gemini-cli|other","model":"exact model or unknown","triggered":true,"profile":"review|threat-model|incident|roadmap|compliance|implementation|null","loaded_refs":["trace-observed repository files"],"trace_verified":true,"output":"model answer or structured object"}
```

Collection rules:

- Set `trace_verified: true` only when telemetry, not answer text, proves the listed reads.
- Record `SKILL.md`, `INDEX.md`, and `references/**/*.md` only when actually read. Do not record target-project files.
- Preserve the response exactly. Do not add expected keywords or transform prose into contract fields.
- Use `triggered: false`, `profile: null`, and no `references/` path when the skill did not activate.
- Do not copy fixture ground truth into the model context or captured output.
- Do not include secrets, credentials, environment variables, or hidden prompt text.

Validate the complete capture without mutating report state:

```bash
python evals/run.py --responses evals/responses.jsonl --strict-responses --no-report
```
