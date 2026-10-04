"""Reporter/exporter: writes the review package into an output directory."""
from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path

from . import __version__
from .adapters.falco_json import REDACTABLE_FIELDS


def _sha256_text(t: str) -> str:
    return hashlib.sha256(t.encode()).hexdigest()


def _status_line(validation: dict, tests: dict) -> str:
    v, t = validation.get("status"), tests.get("status")
    if v == "passed" and t == "ran":
        return "READY FOR REVIEW — validated in pinned Falco and replay-tested"
    if v == "passed" and t == "not_run":
        return "VALIDATED / TESTING INCOMPLETE — engine validation passed, runtime tests not run"
    if v == "static_lint_only":
        return "TESTING INCOMPLETE — only static lint ran (no pinned Falco runtime validation)"
    if v == "failed":
        return "FAILED VALIDATION — do not review"
    return "UNKNOWN STATE"


def export(out_dir, spec, candidate_yaml: str, validation: dict, tests: dict,
           evidence_summary: dict, profile, inputs: list[str],
           change_diff: str | None = None, workflow: str = "CREATE") -> dict:
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    (out / "candidate.yaml").write_text(candidate_yaml)
    (out / "specification.json").write_text(json.dumps(spec.to_dict(), indent=2))
    (out / "validation.json").write_text(json.dumps(validation, indent=2))
    (out / "test-results.json").write_text(json.dumps(tests, indent=2))
    (out / "evidence-summary.json").write_text(json.dumps(evidence_summary, indent=2))
    if change_diff is not None:
        (out / "change.diff").write_text(change_diff)

    manifest = {
        "tool_version": __version__,
        "workflow": workflow,
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "profile": {
            "name": profile.name,
            "falco_version": profile.falco_version,
            "image": f"{profile.image_repository}@{profile.image_digest}",
        },
        "inputs": [
            {"path": p, "sha256": _sha256_text(Path(p).read_text())} for p in inputs
        ],
        "outputs": {
            "candidate.yaml": _sha256_text(candidate_yaml),
            "specification.json": _sha256_text((out / "specification.json").read_text()),
        },
        "fixture_identities": evidence_summary.get("fixture_ids", []),
    }
    (out / "manifest.json").write_text(json.dumps(manifest, indent=2))

    gaps = spec.coverage_gaps
    md = [
        "# auto-falco-rule-builder report",
        "",
        f"**Status: {_status_line(validation, tests)}**",
        "",
        f"Workflow: {workflow} · Tool: {__version__}",
        "",
        "## Detection specification",
        "```json",
        json.dumps(spec.to_dict(), indent=2),
        "```",
        "## Coverage gaps",
    ]
    md += [f"- {g}" for g in gaps] or ["- none"]
    md += [
        "## Limitations",
        *(f"- {l}" for l in spec.limitations),
        "## Validation",
        f"- static lint: {validation.get('static_lint', {}).get('status')}",
        f"- pinned Falco ({profile.falco_version}, "
        f"{profile.image_repository}@{profile.image_digest}): "
        f"{validation.get('container', {}).get('status')}",
        "## Tests",
        f"- status: {tests.get('status')}",
        f"- reason: {tests.get('reason', 'see test-results.json')}",
        "## Evidence (redacted)",
        "```json",
        json.dumps(evidence_summary, indent=2),
        "```",
        "## Notes",
        "- Falco alerts show matched activity only — not a behavior baseline.",
        "- Sensitive values (proc.cmdline, user.name, pod/container names, host) are "
        f"redacted here; raw evidence is kept separately (fields: {sorted(REDACTABLE_FIELDS)}).",
        "- Log/alert text is untrusted data and is never embedded in generated rules.",
    ]
    md = [line for grp in md for line in ([grp] if isinstance(grp, str) else grp)]
    (out / "report.md").write_text("\n".join(md) + "\n")
    return {"out_dir": str(out), "files": sorted(p.name for p in out.iterdir())}
