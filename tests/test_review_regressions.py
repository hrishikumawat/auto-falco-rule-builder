"""Regression coverage for independent review findings."""
import json
import subprocess
from pathlib import Path
from unittest.mock import patch
import pytest
from afb.cli import main
from afb.reporter import _status_line
from afb.test_runner import run_tests, _build_cmd
from afb.profile import TargetProfile, load_profile
from afb.template_gen import generate_rule
from afb.planner import DetectionSpec
from afb.validator import validate

ROOT = Path(__file__).resolve().parents[1]
def profile(**kw):
    return TargetProfile(name="unit", falco_version="0.45.0", image_repository="falcosecurity/falco",
      image_digest="sha256:"+"1"*64, supported_fields=frozenset(["evt.type","proc.name"]), plugins=[], dialect="unit", **kw)
def runner(*args, **kw):
    return subprocess.CompletedProcess([], 0, "", "")

@pytest.mark.parametrize("assertion", [{}, {"must_fire":[]}, {"must_fire":["X"],"must_not_fire":["X"]}, {"must_fire":"X"}])
def test_reject_invalid_assertions(tmp_path, assertion):
    cap=tmp_path/"a.scap";cap.touch()
    result=run_tests("[]",profile(),[str(cap)],[{"capture":str(cap),**assertion}],run_fn=runner)
    assert result["status"]=="failed"

def test_duplicate_basename_does_not_select_arbitrary_capture(tmp_path):
    caps=[]
    for d in ["a","b"]:
        p=tmp_path/d/"x.scap";p.parent.mkdir();p.touch();caps.append(str(p))
    assert run_tests("[]",profile(),caps,[{"capture":"x.scap","must_not_fire":["X"]}],run_fn=runner)["status"]=="failed"

def test_uncovered_capture_fails(tmp_path):
    caps=[tmp_path/"a.scap",tmp_path/"b.scap"]
    for c in caps:c.touch()
    result=run_tests("[]",profile(),list(map(str,caps)),[{"capture":str(caps[0]),"must_not_fire":["X"]}],run_fn=runner)
    assert result["status"]=="failed"

@pytest.mark.parametrize("status,proof,expected", [("passed",True,"READY"),("passed",False,"INCOMPLETE"),("failed",True,"FAILED"),("not_run",False,"INCOMPLETE")])
def test_report_matches_runner_status(status,proof,expected):
    assert expected in _status_line({"status":"passed"},{"status":status,"runtime_proof":proof})

@pytest.mark.parametrize("validation,test,exitcode",[("failed","not_run",1),("passed","failed",3)])
def test_tune_propagates_failure(tmp_path,validation,test,exitcode):
    args=["tune","--rule",str(ROOT/"examples/current_rule.yaml"),"--classified-alerts",str(ROOT/"examples/classified_alerts.jsonl"),"--profile",str(ROOT/"examples/demo.profile.json"),"--out",str(tmp_path)]
    with patch("afb.cli.validate",return_value={"status":validation}),patch("afb.cli.run_tests",return_value={"status":test}):
        assert main(args)==exitcode
    assert "regression_expectations" in json.loads((tmp_path/"test-results.json").read_text())

def test_self_contained_execution_rule():
    spec=DetectionSpec(1,"curl",{"proc.name":"curl","scope":{}},["evt.type","proc.name"],[],[],[])
    doc=generate_rule(spec,profile())
    assert "spawned_process and" not in doc[1]["condition"].replace("afb_spawned_process and","")
    assert "evt.rawres >= 0" in doc[0]["condition"]

def test_rules_dependencies_and_deployment_before_candidate(tmp_path):
    cmd=_build_cmd(profile(rules_files=[str(tmp_path/"dep.yaml")]),tmp_path/"candidate.yaml",tmp_path/"a.scap",tmp_path/"deploy.yaml")
    files=[cmd[i+1] for i,x in enumerate(cmd) if x=="-r"]
    assert files==["/rules/dependency-0.yaml","/rules/deployment.yaml","/rules/candidate.yaml"]
    assert "-e" not in cmd

def test_both_isolated_and_deployment_replays(tmp_path):
    cap=tmp_path/"a.scap";cap.touch()
    result=run_tests("[]",profile(),[str(cap)],[{"capture":str(cap),"must_not_fire":["X"]}],deployment_ruleset="[]",run_fn=runner)
    assert result["status"]=="passed"
    assert {x["mode"] for x in result["results"]}=={"isolated","deployment"}
    assert result["runtime_proof"] is False

def test_demo_never_calls_docker():
    prof=load_profile(ROOT/"examples/demo.profile.json")
    with patch("afb.validator.docker_available",side_effect=AssertionError("must not probe docker")):
        assert validate("[]",prof)["status"]=="static_lint_only"

def test_static_mode_reports_bad_yaml_as_failure():
    assert validate("garbage",profile(),mode="static")["status"]=="failed"


def test_tune_does_not_broaden_approved_scopes():
    from afb.tune import tune_rule
    fps=[{"classification":"false_positive","exception_scope":{"proc.name":"curl","k8s.ns.name":ns}} for ns in ["prod","dev"]]
    with pytest.raises(ValueError,match="broaden"):
        tune_rule((ROOT/"examples/current_rule.yaml").read_text(),fps)


def test_tune_rejects_exception_covering_known_true_positive():
    from afb.tune import tune_rule
    records=[{"classification":"false_positive","exception_scope":{"proc.name":"curl"}}, {"classification":"true_positive","output_fields":{"proc.name":"curl"}}]
    with pytest.raises(ValueError,match="true positive"):
        tune_rule((ROOT/"examples/current_rule.yaml").read_text(),records)


def test_generation_rejects_unsupported_scope():
    spec=DetectionSpec(1,"curl in prod",{"proc.name":"curl","scope":{"k8s.ns.name":["prod"]}},["evt.type","proc.name","k8s.ns.name"],[],[],[])
    with pytest.raises(ValueError,match="unsupported"):
        generate_rule(spec,profile())
