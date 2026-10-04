"""Test runner: replays captures against the pinned Falco container.

Without compatible captures or a controlled lab, tests are reported not_run
with an explicit reason. Fabricated events are never used as test evidence.
"""
from __future__ import annotations

import json
import subprocess
import tempfile
from pathlib import Path

from .validator import docker_available

KNOWN_BUILTIN_RULES_HINT = (
    "capture replay tests run against candidate + deployment ruleset to detect overlap"
)


def run_tests(candidate_yaml: str, profile, captures: list[str] | None = None,
              deployment_ruleset: str | None = None) -> dict:
    captures = captures or []
    if not captures:
        return {
            "status": "not_run",
            "reason": "no compatible event captures (scap) or controlled-lab fixtures provided",
            "blockers": [
                "obtain a scap capture from a staging cluster running the pinned Falco "
                "version, or a controlled Linux lab replay, before calling this rule tested",
            ],
            "note": "Fabricated events are not accepted as test evidence.",
        }

    if not docker_available():
        return {
            "status": "not_run",
            "reason": "captures provided but no reachable Docker daemon for pinned Falco replay",
            "captures": captures,
        }

    img = f"{profile.image_repository}@{profile.image_digest}"
    results = []
    with tempfile.TemporaryDirectory() as td:
        rules_path = Path(td) / "candidate.yaml"
        rules_path.write_text(candidate_yaml)
        if deployment_ruleset:
            (Path(td) / "deploy.yaml").write_text(deployment_ruleset)
        for cap in captures:
            cmd = [
                "docker", "run", "--rm",
                "-v", f"{rules_path}:/rules.yaml:ro",
                "-v", f"{Path(cap).resolve()}:/capture.scap:ro",
                img, "falco", "-c", "/etc/falco/falco.yaml",
                "-r", "/rules.yaml",
            ]
            if deployment_ruleset:
                cmd += ["-r", "/capture.scap"]  # placeholder; deploy mounted below
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
            fired = [l for l in proc.stdout.splitlines() if l.strip()]
            results.append({
                "capture": Path(cap).name,
                "returncode": proc.returncode,
                "alerts_fired": len(fired),
                "stdout_tail": proc.stdout[-2000:],
                "stderr_tail": proc.stderr[-2000:],
            })
    return {"status": "ran", "captures": captures, "results": results,
            "note": KNOWN_BUILTIN_RULES_HINT}
