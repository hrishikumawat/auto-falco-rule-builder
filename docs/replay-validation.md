# Falco validation and replay evidence

Run on 2026-10-04 using Docker Desktop's Linux engine from Windows.
Falco: 0.45.0, libs 0.26.0.
Image: falcosecurity/falco@sha256:788f1129c542171813083d4afc61b16730a47dde8c23d9c39370acef996349b6.
Capture: official falcosecurity/libs curl_google.scap at commit 8510814d3e8dd8b3582411aa0a2023aa9a1ba10e.
Capture SHA256: 115ebaf7404b26a5e5fb18461dd9f7ce41dd33605e1ace100cad582feb60c1d4.

## Real engine results

| Case | Result |
|---|---|
| Generated curl execution rule, validation | Passed |
| curl positive replay, isolated and with deployment rules | Passed, one candidate alert each |
| Absent-process negative replay, isolated and combined | Passed, no candidate alerts |
| Tuned exception suppresses curl | Passed |
| Nonmatching exception preserves curl | Passed |
| Ordered dependency macro, validation and replay | Passed |
| Earlier overlapping deployment rule | Correctly rejected: isolated passes, combined fails |
| Deliberately wrong positive expectation | Correctly failed |
| Deliberately wrong negative expectation | Correctly failed |
| CREATE CLI with real validation and positive replay | Exit 0; validation passed; tests passed |
| Namespace-scoped nsenter candidate, engine validation | Passed; detection testing incomplete |

These used the actual Falco binary, not mocked subprocess output. Run
`python scripts/replay_integration.py` to reproduce; the downloaded capture
checksum is verified. Detailed JSON stays in local_run/replay/results.json.
Containers have no network or host runtime socket access and only read-only
fixture/config mounts. No live workload behavior was executed.

## Scope and limitations

The capture is a host curl trace, with no Kubernetes namespace metadata.
It proves the runner, process-execution template, tuning examples, dependency
ordering, and assertions against this fixture. It does not prove prod/dev
namespace discrimination for nsenter or compatibility with an organization's
actual Falco deployment. The provided lab profile is explicitly not a production
profile. Full production configuration and Kubernetes captures remain necessary.
Falco 0.45 reports evt.dir as deprecated; the condition remains for older exit-event
compatibility and is accompanied by evt.rawres >= 0 to exclude failed execution.

## Review fixes

Both CLI workflows propagate replay and validation failures. Reports recognize
passed/failed states and distinguish mocks from actual runtime execution. Empty,
contradictory and ambiguous capture assertions fail. Validation and replay share
pinned entrypoint/configuration and ordered dependencies. Deployment comparison
runs isolated and combined cases. Synthetic demos cannot pull fake image digests.
TUNE preserves analyst expectations in exports, refuses broadening differing
approved scopes, and rejects exceptions covering known true positives.
