"""Replay compatible captures with explicit assertions; mock tests are not runtime proof."""
from __future__ import annotations
import json
import subprocess
import tempfile
from pathlib import Path
from .validator import docker_available
from .runtime import docker_command, rule_files

def parse_alerts(stdout):
    alerts = []
    for line in stdout.splitlines():
        try:
            rec = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(rec, dict) and isinstance(rec.get("rule"), str) and rec["rule"]:
            alerts.append(rec)
    return alerts

def fired_rules(alerts):
    counts = {}
    for alert in alerts:
        name = alert["rule"]
        counts[name] = counts.get(name, 0) + 1
    return counts

def _build_cmd(profile, candidate_path, capture_path, deploy_path):
    mounts, flags = rule_files(profile, candidate_path, deploy_path)
    mounts.append((capture_path, "/capture/input.scap"))
    cmd = docker_command(profile, mounts)
    replay = profile.replay or {}
    cmd += replay.get("engine_args", [])
    cmd += ["-o", "json_output=true", "-o", "stdout_output.enabled=true"]
    cmd += flags
    if replay.get("capture_arg"):
        cmd += [replay["capture_arg"], "/capture/input.scap"]
    else:
        cmd += ["-o", "engine.kind=replay", "-o", "engine.replay.capture_file=/capture/input.scap"]
    return cmd

def _resolve_capture(name, captures):
    exact = [c for c in captures if Path(c).resolve() == Path(name).resolve()]
    if exact:
        return exact[0]
    # Allow a basename only when it uniquely identifies a supplied capture.
    if Path(name).name == name:
        matches = [c for c in captures if Path(c).name == name]
        if len(matches) == 1:
            return matches[0]
    return None

def run_tests(candidate_yaml, profile, captures=None, expectations=None,
              deployment_ruleset=None, run_fn=None, timeout_s=600):
    captures = captures or []
    if not captures:
        return {"status": "not_run", "reason": "no compatible event captures (scap) or controlled-lab fixtures provided"}
    if not expectations:
        return {"status": "not_run", "reason": "captures provided but no expectations supplied; replay without assertions is not a test"}
    if profile.dialect.startswith("demo"):
        return {"status": "not_run", "reason": "demo profile cannot execute Falco"}
    if run_fn is None:
        if not docker_available():
            return {"status": "not_run", "reason": "no reachable Docker daemon"}
        run_fn = _run_subprocess
    results = []
    covered = set()
    with tempfile.TemporaryDirectory() as td:
        cand = Path(td) / "candidate.yaml"
        cand.write_text(candidate_yaml, encoding="utf-8")
        deploy = None
        if deployment_ruleset:
            deploy = Path(td) / "deployment.yaml"
            deploy.write_text(deployment_ruleset, encoding="utf-8")
        for exp in expectations:
            if not isinstance(exp, dict):
                results.append({"status": "error", "reason": "expectation must be an object"})
                continue
            name = exp.get("capture", "")
            capture = _resolve_capture(name, captures)
            if capture is None:
                results.append({"capture": name, "status": "error", "reason": "expectation references a capture not provided or ambiguous basename"})
                continue
            pos, neg = exp.get("must_fire", []), exp.get("must_not_fire", [])
            if (not isinstance(pos, list) or not isinstance(neg, list) or
                not pos and not neg or any(not isinstance(r, str) or not r for r in pos + neg) or set(pos) & set(neg)):
                results.append({"capture": name, "status": "error", "reason": "nonempty, noncontradictory rule assertions required"})
                continue
            covered.add(str(Path(capture).resolve()))
            modes = [("isolated", None)]
            if deploy is not None:
                modes.append(("deployment", deploy))
            for mode, dep in modes:
                cmd = _build_cmd(profile, cand, Path(capture).resolve(), dep)
                base = {"capture": str(Path(capture).resolve()), "mode": mode, "cmd": cmd}
                try:
                    if not Path(capture).is_file():
                        raise OSError("capture is not a regular file")
                    proc = run_fn(cmd, timeout=timeout_s)
                    if proc.returncode:
                        results.append({**base, "status": "error", "reason": f"replay exited {proc.returncode}", "stderr_tail": (proc.stderr or "")[-4000:]})
                        continue
                    counts = fired_rules(parse_alerts(proc.stdout or ""))
                    failures = [f"expected rule {r!r} did NOT fire (positive test failed)" for r in pos if not counts.get(r)]
                    failures += [f"rule {r!r} fired {counts[r]}x but must not (negative test failed)" for r in neg if counts.get(r)]
                    results.append({**base, "status": "failed" if failures else "passed", "failures": failures, "fired_rules": counts})
                except subprocess.TimeoutExpired:
                    results.append({**base, "status": "error", "reason": f"replay timed out after {timeout_s}s"})
                except OSError as exc:
                    results.append({**base, "status": "error", "reason": str(exc)})
    for capture in captures:
        if str(Path(capture).resolve()) not in covered:
            results.append({"capture": capture, "status": "error", "reason": "capture has no valid expectations"})
    return {"status": "passed" if results and all(r["status"] == "passed" for r in results) else "failed",
            "results": results, "captures": captures,
            "replay_config": profile.replay or "engine.replay.capture_file",
            "runtime_proof": run_fn is _run_subprocess,
            "note": "Scope proven only for these fixtures and target profile"}

def _run_subprocess(cmd, timeout):
    return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, encoding="utf-8", errors="replace")
