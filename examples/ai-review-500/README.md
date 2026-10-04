# Synthetic noise-reduction lab: 500 alerts, 10 rules

All logs are fabricated. Commands are fixture strings and are never executed.
Ten deliberately broad process-execution rules produce 50 alerts each:

| Rule | Process | Expected workload | Noise | Preserve |
|---|---|---|---:|---:|
| Health Check | curl | cron health check | 40 | 10 |
| Artifact Fetch | wget | deployment artifact download | 40 | 10 |
| Maintenance Shell | sh | scheduled log rotation | 40 | 10 |
| Backup Archive | tar | application backup | 40 | 10 |
| Cache Scan | find | expired-cache scan | 40 | 10 |
| Deploy Permissions | chmod | configuration permissions | 40 | 10 |
| Deploy Ownership | chown | release ownership | 40 | 10 |
| Cache Cleanup | rm | stale-marker removal | 40 | 10 |
| Metrics Script | python3 | scheduled metrics export | 40 | 10 |
| Port Probe | nc | database connectivity check | 40 | 10 |
| **Total** | | | **400** | **100** |

For every rule, the 10 events to preserve include five changed commands using
the authorized account/parent, three authorized commands using another account,
and two authorized commands using another parent. Excluding an entire process,
user, command or parent would hide some of these lookalikes. The intended
exception requires the exact command **and** parent **and** account.

`context.txt` states that authorization policy. `alerts.synthetic.jsonl` has
no classifications, exception scopes or must-detect annotations. The separate
`ground-truth.json` is an evaluation answer key; the CLI does not read it.
The seeded interleaving prevents the first group always being authorized.

## Run the review

From `C:\build\auto-falco-rule-builder`, with Ollama and Docker running:

```powershell
.\.venv\Scripts\python.exe -u -m afb.cli review `
  --rules-dir examples\ai-review-500\rules `
  --logs examples\ai-review-500\alerts.synthetic.jsonl `
  --context-file examples\ai-review-500\context.txt `
  --profile examples\ai-review-500\lab.profile.json `
  --validation-mode container
```

Review each exception, then enter `a` to accept, `r` to reject, `f` to give
feedback, or `q` to stop. Original files stay unchanged. Supply a new `--out`
directory if you want an explicit session location. No real replay captures are
included in this scenario, so replay is `not_run`.

If all ten correct exceptions are accepted, the projected alert count falls
from **500 to 100 (80% fewer)**, with all 100 suspicious lookalikes retained.
That is the scenario's target, not a guarantee about model output or production.

## Measure your decisions

Use the output path printed by the CLI:

```powershell
.\.venv\Scripts\python.exe scripts\score_noise_review.py --session-out out\review-YOUR-TIMESTAMP
```

The scorer shows each proposal's noise removal and suspicious activity it would
hide, and totals only accepted proposals. It compares exact scope values against
the fabricated alerts and separate answer key; it is not a Falco interpreter or
runtime detection test. A correct accepted session removes 400 noise events,
hides zero suspicious events, and retains 100 alerts.

## Initial proposal-only smoke test

On 2026-10-04, local `qwen3.5:0.8b` produced ten proposals. Eight matched the
intended scope. Health Check and Backup Archive instead selected the five
unauthorized changed-command events. All ten passed pinned Falco 0.45.0 engine
validation, showing that valid syntax does not establish safe authorization.
Every proposal was rejected during the smoke test. No rules were installed.
For an incorrect proposal, give feedback spelling out the authorized command,
parent and account, then inspect the revised diff before accepting.

## Reproduce the input

```powershell
.\.venv\Scripts\python.exe scripts\generate_noise_scenario.py --out local_run\noise-lab-new
```

The generator refuses existing output directories, uses seed 1729, and verifies
the 500/10 counts and every expected scope against the generated alert values.
The lab profile pins Falco 0.45.0 and is not a production deployment profile.
