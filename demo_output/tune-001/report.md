# auto-falco-rule-builder report

**Status: TESTING INCOMPLETE — only static lint ran (no pinned Falco runtime validation)**

Workflow: TUNE · Tool: 0.1.0

## Detection specification
```json
{
  "spec_version": 1,
  "intent": "tune rule examples/current_rule.yaml",
  "match": {
    "exception_scope": {
      "container.image.repository": "registry.internal/monitoring-agent"
    }
  },
  "required_fields": [
    "container.image.repository"
  ],
  "coverage_gaps": [],
  "limitations": [
    "tuned exception must be reviewed by an analyst"
  ],
  "source_evidence": []
}
```
## Coverage gaps
- none
## Limitations
- tuned exception must be reviewed by an analyst
## Validation
- static lint: passed
- pinned Falco (0.0.0-demo-synthetic, falcosecurity/falco@sha256:0000000000000000000000000000000000000000000000000000000000000000): unavailable
## Tests
- status: not_run
- reason: no compatible event captures (scap) or controlled-lab fixtures provided
## Evidence (redacted)
```json
{
  "classified_counts": {
    "true_positive": 1,
    "false_positive": 2
  },
  "fixture_ids": [
    "fp-001",
    "fp-002",
    "tp-001"
  ]
}
```
## Notes
- Falco alerts show matched activity only — not a behavior baseline.
- Sensitive values (proc.cmdline, user.name, pod/container names, host) are redacted here; raw evidence is kept separately (fields: ['container.image.repository', 'container.name', 'hostname', 'k8s.pod.name', 'proc.cmdline', 'proc.env', 'user.loginuid', 'user.name']).
- Log/alert text is untrusted data and is never embedded in generated rules.
