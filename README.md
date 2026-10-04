# auto-falco-rule-builder

Builds and tunes Falco detection rules from evidence, deterministically.
Milestone 1: no LLM. Every candidate is validated against a **pinned Falco
image digest from your target profile** — never an assumed or host version.

## Workflows

### CREATE — alerts → candidate rule → review package
```bash
# 1. copy examples/example.profile.json, fill real version/digest/fields
python -m afb.cli create \
  --alerts examples/nsenter_alerts.json \
  --profile my.profile.json \
  --proc nsenter --namespace prod \
  --out out/create-001
```
Exports: `candidate.yaml`, `specification.json`, `report.md`, `manifest.json`
(input/candidate hashes, tool/profile/fixture identities), `evidence-summary.json`,
`validation.json`, `test-results.json`.

Optional: `--captures out/*.scap` (replay testing) and
`--deployment-ruleset existing-rules.yaml` (overlap testing). Without captures
the report says **TESTING INCOMPLETE** — fabricated events are never used as
test evidence.

### TUNE — classified alerts → scoped exception → reviewable diff
```bash
python -m afb.cli tune \
  --rule examples/current_rule.yaml \
  --classified-alerts examples/classified_alerts.jsonl \
  --profile my.profile.json \
  --out out/tune-001
```
Alerts must carry an analyst `classification` (`true_positive` /
`false_positive`) plus a narrow `exception_scope` on FPs. Intersected scope
becomes an exception macro; true positives are preserved as regression
expectations in `test-results.json`; reviewable diff in `change.diff`.

## Hard rules

- Profile `dialect: example` is refused — no silent version assumptions.
- Unsupported fields → coverage gap in the report, never invented.
- Missing `k8s.ns.name` → coverage gap, never silently dropped or defaulted.
- No container runtime reachable → validation mode `static_lint_only`, labeled
  as such. YAML validation alone is not proof of runtime detection.
- No automatic deployment, ever. Output goes to a detection-repo PR, human
  review → CI → staging → GitOps. See `docs/architecture.md`.

## Dev

```bash
uv venv .venv && uv pip install --python .venv/bin/python -e . pytest
.venv/bin/python -m pytest tests/ -q
```

## Docker-free demo

```bash
./scripts/demo_docker_free.sh
```
Runs CREATE + TUNE end-to-end on synthetic fixtures with a labeled demo
profile (not a real deployment). Outputs land in `demo_output/` and are
committed: every report states exactly what ran — `static_lint_only`
validation and `not_run` tests. This is pipeline-mechanics demonstration,
**not** runtime detection proof.

## Replay testing

Needs a scap capture + expectations JSON
(`examples/replay_expectations.example.json` shows the shape):
```bash
python -m afb.cli create ... --captures *.scap --expectations expectations.json
```
Replay flags default to `falco -c ... -o json_output=true -r candidate.yaml
[-r deployment.yaml] -e capture.scap`; override per deployed version via a
profile `"replay"` block — otherwise the invocation is recorded in
`test-results.json` as `unverified_default`. Real integration tests use
curated or controlled-lab captures; production telemetry is not required for
development progress. Mocked runner unit tests (tests/test_runner_mocked.py)
verify command construction and assertion logic without Docker and are
labeled as NOT runtime detection proof.

## Limitations (explicit)

- `proc.name` matching misses renamed binaries.
- Alerts show matched activity only — not a behavior baseline; frequency is
  not safety.
- Alert/log text is untrusted: sensitive values are redacted before any model
  use; raw evidence stays separate.
