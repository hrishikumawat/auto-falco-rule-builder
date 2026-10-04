# Run the builder against your own Falco installation

This is the practical companion to [the builder component diagram](diagrams/builder-components.html). The diagram shows builder components only; Helm remains the engineer's handoff step.

## What the builder does today

Run the Python CLI locally. CREATE reads Falco JSON/JSONL alerts, groups matched activity, combines that evidence with an explicit process and optional namespace, checks a deployment profile, and generates a deterministic process-execution rule. It does not infer a complete workload baseline or interpret arbitrary natural-language intent.

The profile must match your Falco image digest, version, available fields, plugins, configuration and ordered dependencies. It is supplied by the engineer; the builder does not discover your Helm deployment automatically. The supplied lab profile is not a production profile.

The validator performs lint and pinned-container engine validation. The runner replays compatible scap captures with explicit `must_fire` / `must_not_fire` assertions. An existing deployment ruleset can be supplied for isolated-versus-combined comparison. That comparison must reflect the intended final file order; the current runner puts dependencies first, then the deployment ruleset, then the candidate. A different deployment order needs an appropriately assembled test setup.

The exporter writes `candidate.yaml`, specification, evidence summary, validation/test results, hashes and a report under `--out`. TUNE accepts an existing rules file and analyst-classified false/true positives, edits the first rule entry, and exports the complete resulting YAML plus a diff. It is not a general bulk ruleset tuner or a Falco `override`-fragment generator.

```sh
# Replace the paths and supply your own matching profile and captures.
python -m afb.cli create \
  --alerts inputs/alerts.jsonl \
  --profile inputs/my-falco.profile.json \
  --proc nsenter --namespace prod \
  --validation-mode container \
  --captures inputs/positive.scap inputs/negative.scap \
  --expectations inputs/expectations.json \
  --deployment-ruleset inputs/current-deployment.yaml \
  --out out/nsenter-prod
```

Inspect `report.md`, `validation.json`, and `test-results.json`. A successful CLI exit alone is insufficient: static lint or missing replay can still leave an incomplete report. Ready for review requires passed engine validation and passed real replay, and that evidence covers only the supplied fixtures/profile.

## Choose how to use candidate.yaml

| Choice | Engineer's action | What to check |
|---|---|---|
| Add a separate file (recommended for new detections) | Put the reviewed YAML in a new Helm `customRules` entry, such as `afb-nsenter-prod.yaml`. | Include its directory/path in `falco.rules_files`; test the complete ordered ruleset. |
| Replace an owned custom file | Replace that file's content or its Helm value with the reviewed candidate. | CREATE outputs only its generated detection; replacing a file containing other detections would remove them. TUNE exports the whole input YAML with its first rule changed. |
| Append entries to an existing file | Merge the YAML list entries, preserving required macro-before-rule order. | Avoid duplicate rule/macro names, preserve existing entries, and validate/replay the merged artifact. |

Current code exports files only. Automatic merge/append, backup, Helm-values generation, Helm upgrades and in-place deployed-file replacement are potential follow-up features, not implemented functionality.

## Helm loads separate files; it does not join their contents on disk

The official chart's `customRules` map can contain several filename keys. Helm mounts them under `/etc/falco/rules.d`. Falco loads that directory if configured in `falco.rules_files`. Files elsewhere need an explicit configured path. Local file creation does not automatically copy anything to Kubernetes.

For example, keep your existing custom entries and add one named entry containing the actual reviewed candidate:

```yaml
# Merge this structure into the engineer's existing values file.
customRules:
  afb-nsenter-prod.yaml: |-
    # Paste the full reviewed candidate.yaml here, including its macros.

falco:
  rules_files:
    - /etc/falco/falco_rules.yaml
    - /etc/falco/falco_rules.local.yaml
    - /etc/falco/rules.d
```

This example uses the documented default file locations. Preserve the file list actually used by your installation; replacing the list can remove other loaded rules. The placeholder above is not an installable detection until the candidate is pasted. To load only custom rules, use only the intended custom paths and retain any macros/lists on which they depend.

Use the existing release's versioned chart and complete values configuration when applying the change. Then inspect Falco startup/reload logs and verify detection in staging. Do not edit pod-mounted rule files as your persistent source of configuration.

Adding a second file is distinct from modifying an existing rule. New detections need unique rule names. Changes to an existing named rule need deliberate replacement or Falco's version-compatible `override` semantics, with the original definition loaded first. Ordinary shell text appending does not perform that semantic operation. The current generator also reuses a macro name, so combining several generated files requires name/dependency review even when rule names differ. With first-match behavior, an earlier overlapping rule can consume an event before the candidate; combined replay is necessary.

## Official references

- [Falco default/custom files and Helm configuration](https://falco.org/docs/concepts/rules/default-custom/)
- [Multiple Helm customRules entries](https://falco.org/docs/concepts/rules/custom-ruleset/)
- [Falco rule override semantics and load order](https://falco.org/docs/concepts/rules/overriding/)

Repository evidence: `hrishikumawat/auto-falco-rule-builder` at `0729170b4b8ad8949eb193878cac81d402e79411`. The diagram contains source links at that revision. The diagrams and this guide do not perform any cluster changes.
