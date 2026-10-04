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
python scripts/demo_docker_free.py
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
Replay uses a pinned image, `/usr/bin/falco` as entrypoint, network disabled, and
`-o engine.kind=replay -o engine.replay.capture_file=/capture/input.scap`.
The invocation was exercised with Falco 0.45.0. Legacy flags can be configured
in the profile replay block; they must be checked for your target version.
Dependencies listed in profile `rules_files` (relative to the profile file) load
before the deployment ruleset and candidate. Optional `config_file` and
`runtime_args` apply equally to validation and replay; use them to configure
plugins installed in the target image. Specifying `--deployment-ruleset` runs
both isolated and combined replay to reveal overlaps.

Each supplied capture must have nonempty, noncontradictory expectations.
Replay failures return exit code 3 in both workflows; validation failures return
1; input/configuration errors return 2. TUNE exports analyst-derived regression
expectations, but these are not automatically converted into real capture fixtures.

## Reproducible real replay check

```powershell
# Windows, from the repository directory
.\.venv\Scripts\python.exe -m pytest tests -q
.\.venv\Scripts\python.exe scripts/replay_integration.py
```

The integration script downloads an official Falco libs capture at a fixed commit
and uses Falco 0.45.0 pinned by digest. Docker may pull the image on first run.
It validates and replays a generated curl rule (positive), an absent process rule
(negative), and a tuned exception suppressing curl. It also intentionally supplies
wrong positive and negative expectations to prove the harness detects failures.
The fixture is a host capture: it does **not** prove Kubernetes namespace-scoped
nsenter detection. Results and capture provenance are written to `local_run/replay`.
Review `docs/replay-validation.md` for the recorded run and remaining limits.

## Limitations (explicit)

- `proc.name` matching misses renamed binaries.
- Alerts show matched activity only — not a behavior baseline; frequency is
  not safety.
- Alert/log text is untrusted: sensitive values are redacted before any model
  use; raw evidence stays separate.
