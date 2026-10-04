# auto-falco-rule-builder report

**Status: TESTING INCOMPLETE — only static lint ran (no pinned Falco runtime validation)**

Workflow: CREATE · Tool: 0.1.0

## Detection specification
```json
{
  "spec_version": 1,
  "intent": "detect nsenter execution in namespace prod",
  "match": {
    "evt.type": "execve",
    "proc.name": "nsenter",
    "scope": {
      "k8s.ns.name": [
        "prod"
      ]
    }
  },
  "required_fields": [
    "evt.type",
    "proc.name",
    "k8s.ns.name"
  ],
  "coverage_gaps": [
    "2 of 7 alerts lack k8s.ns.name metadata; scope enforcement depends on cluster metadata being present at event time"
  ],
  "limitations": [
    "proc.name matching misses renamed binaries (e.g. copying nsenter to another name); full-path/proc.exepath hardening is future work"
  ],
  "source_evidence": [
    {
      "source": "examples\\nsenter_alerts.json",
      "index": 0,
      "record_sha256": "2c8876d422b18a704811f6e5ebba36fc75ddabee32c6065bda3f95b802f62a2c"
    }
  ]
}
```
## Coverage gaps
- 2 of 7 alerts lack k8s.ns.name metadata; scope enforcement depends on cluster metadata being present at event time
## Limitations
- proc.name matching misses renamed binaries (e.g. copying nsenter to another name); full-path/proc.exepath hardening is future work
## Validation
- static lint: passed
- pinned Falco (0.0.0-demo-synthetic, falcosecurity/falco@sha256:0000000000000000000000000000000000000000000000000000000000000000): unavailable
## Tests
- status: not_run
- reason: no compatible event captures (scap) or controlled-lab fixtures provided
## Evidence (redacted)
```json
{
  "total_alerts": 8,
  "namespace_missing_metadata": 2,
  "groups": [
    {
      "evt_type": "execve",
      "proc_name": "nsenter",
      "namespaces": {
        "prod": 4,
        "dev": 1,
        "MISSING": 2
      },
      "count": 7,
      "sample_provenance": {
        "source": "examples\\nsenter_alerts.json",
        "index": 0,
        "record_sha256": "2c8876d422b18a704811f6e5ebba36fc75ddabee32c6065bda3f95b802f62a2c"
      }
    },
    {
      "evt_type": "execve",
      "proc_name": "bash",
      "namespaces": {
        "prod": 1
      },
      "count": 1,
      "sample_provenance": {
        "source": "examples\\nsenter_alerts.json",
        "index": 4,
        "record_sha256": "a5427b417cec396da26c4cbce34626ecc59807a68342d94cf4dad5b3f016e6c3"
      }
    }
  ],
  "note": "Counts reflect matched alerts only; not a behavior baseline."
}
```
## Notes
- Falco alerts show matched activity only — not a behavior baseline.
- Sensitive values (proc.cmdline, user.name, pod/container names, host) are redacted here; raw evidence is kept separately (fields: ['container.image.repository', 'container.name', 'hostname', 'k8s.pod.name', 'proc.cmdline', 'proc.env', 'user.loginuid', 'user.name']).
- Log/alert text is untrusted data and is never embedded in generated rules.
