# Interactive local-AI review

`afb review` reads your existing Falco rules and JSON/JSONL alert logs, uses local
Ollama to propose a narrow exception, and asks for approval one rule at a time.
Unlike `tune`, it does not require you to supply an `exception_scope` or classify
every alert beforehand. This version tunes existing rules; it does not discover
new detections or establish a complete behavior baseline from alert logs.

## Run

Start Ollama and install the selected model if needed:

```powershell
ollama pull qwen3.5:0.8b
```

From the repository directory, supply just the rules and logs:

```powershell
.\.venv\Scripts\python.exe -u -m afb.cli review --rules-dir C:\my-falco\rules --logs C:\my-falco\alerts.jsonl
```

It asks what activity is expected/authorized, then evaluates each rule with
matching alerts. Without a target profile it explicitly runs a **static preview**.
To use your pinned Falco image, add `--profile C:\my-falco\target.profile.json`.
Use `--validation-mode container` to require engine validation rather than
permit the automatic static fallback when Docker is unavailable.

For each proposal you see the AI explanation, exact exception values, blind
spot, actual file diff, validation status and replay status. Choose:

- `a`: accept this proposal for export and proceed to the next rule.
- `r`: reject this proposal and proceed to the next rule.
- `f`: explain what should change; the model revises the proposal.
- `q`: stop; already accepted proposals remain exported.

There is no default approval. Enter alone does not accept. When authorization
is unclear, the model can ask a question; Enter skips that rule. There are at
most three model attempts per rule, including feedback and invalid responses.
This version offers one accepted exception per rule per session. To tune another
distinct activity for the same rule, review the accepted rules in a new session.

## Synthetic example

The checked-in example has three authorized health-check alerts and two
unauthorized downloads, one using the same cron parent and service account.
All five alerts are fabricated, clearly labeled fixtures. The logs carry no
preselected exception scope; Qwen selects the proposal from observed evidence
and the expected-activity context.

```powershell
.\.venv\Scripts\python.exe -u -m afb.cli review `
  --rules-dir examples\ai-review\rules `
  --logs examples\ai-review\alerts.synthetic.jsonl `
  --context-file examples\ai-review\context.txt `
  --profile examples\ai-review\lab.profile.json `
  --validation-mode container
```

Docker and the pinned lab Falco image are required for this engine check. No
scap fixtures are supplied here, so replay is reported as `not_run`. This lab
profile is not a production configuration. For a Docker-free preview, omit
`--profile` and `--validation-mode`.

## Outputs and deployment

The default output is a fresh `out/review-<timestamp>` directory. You can set
`--out` to a new directory. Source rules are never edited. After each acceptance:

- `accepted-rules/` contains the complete input directory structure, with
  accepted edits only. Unchanged files are copied byte for byte.
- `accepted-bundle.yaml` contains the combined input rules in review load order.
- `change.diff` records the cumulative edits.
- `proposals/NNN/` contains each candidate bundle, exact diff and evidence,
  validation and replay reports, including rejected proposals.
- `session.json` records decisions, model digest, model responses, prompt
  hashes and input hashes. Session artifacts may contain sensitive values.

These are **replacement copies**, not an additional copy to load alongside
the original full rules. Loading both duplicates rule names. Inspect the files,
then manually use the accepted rules in your existing Helm/GitOps workflow.
Changes to a YAML file can reformat it and remove its comments; that is visible
in the approval diff. External profile dependencies are not copied into the
accepted bundle and must still load before it.

## Input and verification boundaries

Use a dedicated directory containing full rule definitions and their local
macros/lists. Nested YAML files are included. The default load order is sorted
path order; `--rule-order macros.yaml rules.yaml` explicitly sets it and must
list every discovered file exactly once. Duplicate rule names and rule
append/override fragments are refused: prepare a unique effective ruleset first.
Rules with no matching alerts are not changed; unmatched alert names are shown.

For real replay, add `--captures capture.scap --expectations expectations.json`.
Expectations use the same capture/rule format as CREATE/TUNE. Each candidate is
validated/replayed as the **cumulative complete rules bundle**, with external
dependencies from the target profile. A failed validation or replay blocks
acceptance. Static lint and alert-value checks are not runtime detection proof.
Profiles and their runtime arguments are trusted operator configuration.

Qwen selects observed groups and field names; Python derives their exact
values, builds an exception macro and adds it to the named existing rule.
The model has no shell, filesystem or deployment tools. Proposals must include
both an activity/target field and a workload/account context field, cannot
cover unselected evidence, and cannot suppress alerts explicitly marked
`must_detect: true` or `classification: true_positive`. Missing evidence fields
cannot be assumed safe. Repeated activity alone does not establish authorization.
The checks only constrain the observed evidence; future malicious activity
matching the approved exception will also be suppressed.

Ollama is called directly at `127.0.0.1:11434`, bypassing HTTP proxies and
rejecting redirects and remote-backed models. There is no cloud or larger-model
fallback. Selected command, account and path values are sent to the local model;
raw alert output strings are excluded. This is not blanket secret redaction.
Treat logs as untrusted and inspect every proposal, especially with a small
model. Model or input errors stop safely; invalid proposal retries never imply
approval. If input files change during review, restart the session.

Exit codes: `0` means review finished or you quit, **not** that every proposal
passed or was accepted; `1` means interrupted or invalid model attempts were
exhausted; `2` means an input, configuration or service error.

## Recorded verification

On 2026-10-04, the 69-test suite passed, including approval, rejection, feedback,
interruption, cumulative rule changes, input mutation, protected evidence,
validation/replay rejection and local-model restrictions. A live run with
`qwen3.5:0.8b` proposed the exact health-check command + cron + svc-health
exception. Pinned Falco 0.45.0 validation passed. Replaying the existing official
`curl_google.scap` host fixture against that candidate passed a must-fire check
for `Lab Curl Execution`: the unrelated curl event remained detectable. The
proposal was rejected at the prompt; no live-model change was accepted.

The existing replay integration suite also passed its positive, negative,
suppression, preservation, dependency-order and intentional-failure checks.
The live review capture does not contain the synthetic health-check activity,
so it does not prove that activity's suppression or Kubernetes coverage.
This is a smoke test, not a measured model accuracy claim.

For a larger exercise, use the [500-alert, 10-rule noise lab](../examples/ai-review-500/README.md).
It includes suspicious lookalikes, separate ground truth and a scorer for
accepted decisions. Its target is 400 noise events removed with 100 suspicious
events preserved; review every proposal rather than assuming that result.
