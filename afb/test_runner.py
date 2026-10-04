"""Test runner: replays captures against the pinned Falco container and asserts
fixture expectations (must_fire / must_not_fire per rule).

Without compatible captures + expectations, or without a reachable container
runtime, tests are reported `not_run` with an explicit reason. Fabricated
events are never used as test evidence. Mocked-runner unit tests verify
command construction and assertion logic only — they are NOT runtime
detection proof.

Replay invocation notes (verify against your pinned Falco version):
  falco -c <config> -o json_output=true [-r rules...] [-e capture.scap]
  `-e` reads events from a scap capture; the profile may override flags via
  a "replay" block (see README) so the exact invocation can be pinned
  per deployed Falco version.
"""
from __future__ import annotations

import json
import subprocess
import tempfile
from pathlib import Path

from .validator import docker_available

DEFAULT_CAPTURE_ARG = "-e"
DEFAULT_ENGINE_ARGS = ["-o", "json_output=true", "-o", "json_include_output_property=true"]


def parse_alerts(stdout: str) -> list[dict]:
    """Parse Falco JSON alert records from stdout.

    Non-JSON lines are startup noise and are ignored, never counted as alerts.
    """
    alerts = []
    for line in stdout.splitlines():
        line = line.strip()
        if not (line.startswith("{") and line.endswith("}")):
            continue
        try:
            rec = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(rec, dict) and "rule" in rec:
            alerts.append(rec)
    return alerts


def fired_rules(alerts: list[dict]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for a in alerts:
        counts[a["rule"]] = counts.get(a["rule"], 0) + 1
    return counts


def _build_cmd(profile, candidate_path: Path, capture_path: Path,
               deploy_path: Path | None) -> list[str]:
    replay = getattr(profile, "replay", None) or {}
    capture_arg = replay.get("capture_arg", DEFAULT_CAPTURE_ARG)
    engine_args = replay.get("engine_args", DEFAULT_ENGINE_ARGS)
    falco_config = replay.get("config", "/etc/falco/falco.yaml")
    cmd = [
        "docker", "run", "--rm",
        "-v", f"{candidate_path}:/rules/candidate.yaml:ro",
        "-v", f"{capture_path}:/capture/input.scap:ro",
    ]
    if deploy_path is not None:
        cmd += ["-v", f"{deploy_path}:/rules/deployment.yaml:ro"]
    img = f"{profile.image_repository}@{profile.image_digest}"
    cmd += [img, "falco", "-c", falco_config]
    cmd += engine_args
    # candidate ruleset first, then the deployment ruleset for overlap testing
    # (ordering semantics of multiple -r flags: verify per Falco version)
    cmd += ["-r", "/rules/candidate.yaml"]
    if deploy_path is not None:
        cmd += ["-r", "/rules/deployment.yaml"]
    cmd += [capture_arg, "/capture/input.scap"]
    return cmd


def run_tests(candidate_yaml: str, profile, captures: list[str] | None = None,
              expectations: list[dict] | None = None,
              deployment_ruleset: str | None = None,
              run_fn=None, timeout_s: int | None = 600) -> dict:
    """expectations: [{"capture": <path-or-name>, "must_fire": [rule...],
                       "must_not_fire": [rule...]}]

    run_fn is injectable for mocked unit tests (command construction and
    assertion logic verified without Docker — labeled runner unit tests, not
    runtime detection proof).
    """
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
    if not expectations:
        return {
            "status": "not_run",
            "reason": "captures provided but no expectations supplied; "
                      "replay without assertions is not a test",
        }

    if run_fn is None:
        if not docker_available():
            return {
                "status": "not_run",
                "reason": "captures+expectations provided but no reachable Docker daemon "
                          "for pinned Falco replay",
                "captures": captures,
            }
        run_fn = _run_subprocess

    replay_config = getattr(profile, "replay", None)
    meta = {"replay_config": replay_config or "unverified_default",
            "note": "replay flags must be verified against the pinned Falco version"}

    results = []
    with tempfile.TemporaryDirectory() as td:
        cand = Path(td) / "candidate.yaml"
        cand.write_text(candidate_yaml)
        deploy = None
        if deployment_ruleset:
            deploy = Path(td) / "deployment.yaml"
            deploy.write_text(deployment_ruleset)

        for exp in expectations:
            name = exp["capture"]
            match = next((c for c in captures if Path(c).name == Path(name).name), None)
            if match is None:
                results.append({"capture": name, "status": "error",
                                "reason": "expectation references a capture not provided"})
                continue
            cmd = _build_cmd(profile, cand, Path(match).resolve(), deploy)
            try:
                proc = run_fn(cmd, timeout=timeout_s)
            except subprocess.TimeoutExpired:
                results.append({"capture": Path(match).name, "status": "error",
                                "reason": f"replay timed out after {timeout_s}s",
                                "cmd": cmd})
                continue
            if proc.returncode != 0:
                results.append({"capture": Path(match).name, "status": "error",
                                "reason": f"replay exited {proc.returncode}",
                                "stderr_tail": (getattr(proc, "stderr", "") or "")[-2000:],
                                "cmd": cmd})
                continue
            counts = fired_rules(parse_alerts(proc.stdout or ""))
            failures = []
            for r in exp.get("must_fire", []):
                if counts.get(r, 0) < 1:
                    failures.append(f"expected rule {r!r} did NOT fire (positive test failed)")
            for r in exp.get("must_not_fire", []):
                if counts.get(r, 0) > 0:
                    failures.append(
                        f"rule {r!r} fired {counts[r]}x but must not (negative test failed)")
            results.append({
                "capture": Path(match).name,
                "status": "failed" if failures else "passed",
                "failures": failures,
                "fired_rules": counts,
                "cmd": cmd,
            })

    statuses = {r["status"] for r in results}
    overall = "failed" if ("failed" in statuses or "error" in statuses) else "passed"
    return {"status": overall, "captures": captures, "results": results, **meta}


def _run_subprocess(cmd: list[str], timeout: int | None) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
