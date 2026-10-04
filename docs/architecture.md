# auto-falco-rule-builder architecture

Status: **scaffold + milestone 1 (deterministic template vertical slice)**.
LLM interpretation is explicitly out of scope for this milestone.

## Workflows

### CREATE
```
Falco JSON alerts + target profile
  -> input adapters (falco_json)
  -> normalizer / evidence store (grouping, redaction, provenance, missing fields)
  -> specification planner + capability checker (detection spec vs profile fields)
  -> deterministic template generator (candidate Falco YAML)
  -> validator (pinned Falco container preferred; static lint fallback, honestly labeled)
  -> test runner (compatible captures or controlled lab; else testing_incomplete)
  -> reporter/exporter (candidate.yaml, specification.json, report.md, manifest.json,
     evidence-summary.json, validation.json, test-results.json)
```

### TUNE
```
existing rule YAML + analyst-classified alerts (JSONL)
  -> exception scoping (narrow: specific container image / cmdline / namespace)
  -> preserved-positive regression tests derived from true-positive alerts
  -> validator + test runner (same as CREATE)
  -> change.diff (reviewable, human-approved before merge)
```

## Org flow (out of builder scope)

telemetry/SOC evidence -> builder (central CLI/service) -> detection repo PR ->
security review -> CI -> staging observation -> GitOps deployment -> feedback.
The builder never deploys to production.

## Target profile

`profile.json` must state, and the tool will never assume:

- `falco_version` — actual version deployed
- `image` — exact image **with digest** (immutable)
- `supported_fields` — field list for the installed plugins/driver
- `plugins` — enabled plugins and capabilities
- `dialect` — must not be `example` for real runs

Any requested field absent from `supported_fields` is reported as a coverage
gap. The tool never invents fields. If the container runtime is unavailable,
validation mode is reported as `unavailable` (static lint only) and runtime
validation is listed as a blocker — YAML validation alone is not treated as
proof of detection.

## Evidence handling

- Provenance is preserved per alert: source file, record index, raw record hash.
- Missing fields are preserved as `null` and listed in `missing_fields`; a
  missing `k8s.ns.name` is a **coverage gap**, not a reason to drop scope
  silently or assume a namespace.
- Falco alerts show only matched activity — never a complete behavior
  baseline. Frequent activity is not automatically safe.
- Log/alert text is untrusted data. Values are redacted (SHA-256 truncated)
  before any model use; raw sensitive evidence stays in the raw evidence store,
  separate from exports.

## Known limitations (documented, not hidden)

- Renamed binaries: `proc.name` matching misses an attacker renaming
  `nsenter`; a full-path + inode-hardened rule variant is future work.
- Runtime testing requires a scap capture (or live lab) compatible with the
  pinned Falco version. Without one, tests are reported `not_run`.
- Static lint does not run the Falco engine; it checks structure, macro
  resolution, priority, and output-field presence against the profile.

## Components

| Component | Module | Status |
|---|---|---|
| input adapters | `afb/adapters/falco_json.py` | implemented |
| normalizer/evidence store | `afb/evidence.py` | implemented |
| target profile loader | `afb/profile.py` | implemented |
| spec planner / capability checker | `afb/planner.py` | implemented |
| template generator | `afb/template_gen.py` | implemented (deterministic) |
| validator | `afb/validator.py` | container path implemented, runtime unavailable in dev env |
| test runner | `afb/test_runner.py` | capture path implemented, no fixtures available |
| reporter/exporter | `afb/reporter.py` | implemented |
| TUNE workflow | `afb/tune.py` | implemented |
| LLM interpretation (constrained, advisory) | — | not started (planned) |
