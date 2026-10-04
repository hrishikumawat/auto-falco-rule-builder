"""Runner UNIT tests with a mocked subprocess runner.

These verify command construction, mounts, JSON parsing and assertion logic
only. They are NOT runtime detection proof — no Falco engine, no real events.
"""
import json
import subprocess
from pathlib import Path

import pytest

from afb.test_runner import run_tests, parse_alerts, fired_rules, _build_cmd


def make_profile(**kw):
    from afb.profile import TargetProfile
    return TargetProfile(
        name="unit", falco_version="0.0-unit", image_repository="falcosecurity/falco",
        image_digest="sha256:" + "0" * 64,
        supported_fields=frozenset(["evt.type", "proc.name", "k8s.ns.name"]),
        plugins=[], dialect="unit", **kw)


RULE = "AFB Nsenter Execution"


def fake_run_factory(stdout="", returncode=0):
    from types import SimpleNamespace

    def run_fn(cmd, timeout=None):
        return SimpleNamespace(returncode=returncode, stdout=stdout, stderr="")
    return run_fn


ALERT_LINE = json.dumps({"time": "t", "rule": RULE, "priority": "Warning",
                         "output": "x", "output_fields": {"proc.name": "nsenter"}})
NOISY_STDOUT = f"falco: loading rules...\nFalco initialized...\n{ALERT_LINE}\n"


def test_parse_alerts_ignores_noise_and_counts_by_rule():
    alerts = parse_alerts(NOISY_STDOUT)
    assert len(alerts) == 1
    assert fired_rules(alerts) == {RULE: 1}


def test_command_construction_mounts_and_order(tmp_path):
    prof = make_profile()
    cand = tmp_path / "c.yaml"; cand.write_text("rules")
    cap = tmp_path / "cap.scap"; cap.touch()
    dep = tmp_path / "d.yaml"
    cmd = _build_cmd(prof, cand, cap, dep)
    assert "falcosecurity/falco@sha256:" + "0" * 64 in cmd
    mounts = [cmd[i + 1] for i, m in enumerate(cmd) if m == "-v"]
    assert any(m.endswith("/rules/candidate.yaml:ro") for m in mounts)
    assert any(m.endswith("/capture/input.scap:ro") for m in mounts)
    assert any(m.endswith("/rules/deployment.yaml:ro") for m in mounts)
    assert cmd[cmd.index("-r") + 1] == "/rules/candidate.yaml"
    assert cmd[cmd.index("falco") + 1:cmd.index("falco") + 3] == ["-c", "/etc/falco/falco.yaml"]
    assert "-o" in cmd and "json_output=true" in cmd
    # capture arg is last two tokens, after -r flags
    assert cmd[-2] == "-e" and cmd[-1] == "/capture/input.scap"


def test_command_uses_profile_replay_overrides(tmp_path):
    prof = make_profile(replay={"capture_arg": "--read", "engine_args": ["-o", "x=y"],
                                "config": "/custom/falco.yaml"})
    cand = tmp_path / "c.yaml"; cand.write_text("rules")
    cap = tmp_path / "cap.scap"; cap.touch()
    cmd = _build_cmd(prof, cand, cap, None)
    assert "/custom/falco.yaml" in cmd
    assert cmd[-2] == "--read"


def test_positive_and_negative_assertions(tmp_path):
    prof = make_profile()
    cap = str(tmp_path / "pos.scap"); Path(cap).touch()
    # positive pass + negative pass
    res = run_tests("rules", prof, captures=[cap],
                    expectations=[{"capture": "pos.scap", "must_fire": [RULE],
                                   "must_not_fire": ["Other Rule"]}],
                    run_fn=fake_run_factory(NOISY_STDOUT))
    assert res["status"] == "passed"
    # positive failure
    res = run_tests("rules", prof, captures=[cap],
                    expectations=[{"capture": "pos.scap", "must_fire": ["Missing Rule"]}],
                    run_fn=fake_run_factory(NOISY_STDOUT))
    assert res["status"] == "failed"
    assert any("positive test failed" in f for f in res["results"][0]["failures"])
    # negative failure
    res = run_tests("rules", prof, captures=[cap],
                    expectations=[{"capture": "pos.scap", "must_not_fire": [RULE]}],
                    run_fn=fake_run_factory(NOISY_STDOUT))
    assert res["status"] == "failed"
    assert any("negative test failed" in f for f in res["results"][0]["failures"])


def test_error_status_on_nonzero_exit_and_timeout(tmp_path):
    prof = make_profile()
    cap = str(tmp_path / "x.scap"); Path(cap).touch()
    res = run_tests("rules", prof, captures=[cap],
                    expectations=[{"capture": "x.scap", "must_fire": [RULE]}],
                    run_fn=fake_run_factory(returncode=137))
    assert res["status"] == "failed" and res["results"][0]["status"] == "error"
    assert "replay exited 137" in res["results"][0]["reason"]

    def timeout_run(cmd, timeout=None):
        raise subprocess.TimeoutExpired(cmd, timeout)
    res = run_tests("rules", prof, captures=[cap],
                    expectations=[{"capture": "x.scap", "must_fire": [RULE]}],
                    run_fn=timeout_run)
    assert res["status"] == "failed" and "timed out" in res["results"][0]["reason"]


def test_expectation_without_matching_capture_is_error(tmp_path):
    prof = make_profile()
    cap = str(tmp_path / "a.scap"); Path(cap).touch()
    res = run_tests("rules", prof, captures=[cap],
                    expectations=[{"capture": "ghost.scap", "must_fire": [RULE]}],
                    run_fn=fake_run_factory())
    assert res["status"] == "failed" and res["results"][0]["status"] == "error"


def test_captures_without_expectations_is_not_run(tmp_path):
    cap = str(tmp_path / "a.scap"); Path(cap).touch()
    res = run_tests("rules", make_profile(), captures=[cap], run_fn=fake_run_factory())
    assert res["status"] == "not_run"


def test_mocked_marker_in_docstring_is_present():
    doc = __doc__ or ""
    assert "NOT runtime detection proof" in doc
