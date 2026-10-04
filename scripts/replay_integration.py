"""Real Falco 0.45.0 replay against an upstream public capture, not Kubernetes proof.
Run: python scripts/replay_integration.py
Requires Docker. Downloads one pinned 22KB official Falco libs fixture.
Writes provenance, validation and assertion results into local_run/replay/.
"""
import hashlib
import json
import subprocess
import sys
import urllib.request
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from afb.profile import TargetProfile
from afb.planner import DetectionSpec
from afb.template_gen import generate_rule, render_yaml
from afb.validator import validate
from afb.test_runner import run_tests

IMAGE = "falcosecurity/falco@sha256:788f1129c542171813083d4afc61b16730a47dde8c23d9c39370acef996349b6"
SOURCE = "https://raw.githubusercontent.com/falcosecurity/libs/8510814d3e8dd8b3582411aa0a2023aa9a1ba10e/test/libsinsp_e2e/resources/captures/curl_google.scap"
out = ROOT / "local_run/replay"
out.mkdir(parents=True, exist_ok=True)
capture = out / "curl_google.scap"
if not capture.exists():
    capture.write_bytes(urllib.request.urlopen(SOURCE, timeout=30).read())
expected_sha = "115ebaf7404b26a5e5fb18461dd9f7ce41dd33605e1ace100cad582feb60c1d4"
if hashlib.sha256(capture.read_bytes()).hexdigest() != expected_sha:
    raise RuntimeError("capture checksum mismatch")
provenance = {"source": SOURCE, "sha256": hashlib.sha256(capture.read_bytes()).hexdigest(), "image": IMAGE}
(out / "provenance.json").write_text(json.dumps(provenance, indent=2), encoding="utf-8")
profile = TargetProfile(name="Falco 0.45.0 public capture lab", falco_version="0.45.0",
    image_repository=IMAGE.split("@")[0], image_digest=IMAGE.split("@")[1],
    supported_fields=frozenset(["evt.type", "proc.name"]), plugins=[], dialect="lab")
deployment = "- rule: Integration other process\n  desc: Benign other process\n  condition: evt.type = execve and proc.name = definitely_absent_process\n  output: other\n  priority: NOTICE\n"
cases = []
for proc, expected in [("curl", True), ("definitely_absent_process", False)]:
    spec = DetectionSpec(1, f"detect {proc}", {"proc.name": proc, "scope": {}}, ["evt.type", "proc.name"], [], ["Host fixture; no Kubernetes namespace assertions"], [])
    candidate = render_yaml(generate_rule(spec, profile))
    (out / (proc + ".yaml")).write_text(candidate, encoding="utf-8")
    validation = validate(candidate, profile, mode="container")
    rule = generate_rule(spec, profile)[1]["rule"]
    expectations = [{"capture": str(capture), "must_fire" if expected else "must_not_fire": [rule]}]
    tests = run_tests(candidate, profile, [str(capture)], expectations, deployment)
    cases.append({"case": proc, "validation": validation, "tests": tests})
# Actual tuning: suppress the curl event with an analyst-supplied process exception.
from afb.tune import tune_rule
curl_yaml=(out/"curl.yaml").read_text(encoding="utf-8")
tuned=tune_rule(curl_yaml,[{"classification":"false_positive","exception_scope":{"proc.name":"curl"},"output_fields":{"proc.name":"curl"}}])
cases.append({"case":"tune_suppresses_curl", "validation":validate(tuned["tuned_yaml"],profile,mode="container"),
    "tests":run_tests(tuned["tuned_yaml"],profile,[str(capture)],[{"capture":str(capture),"must_not_fire":["AFB Curl Execution"]}])})
# Preserve a real positive after adding an exception for a different process.
preserved=tune_rule(curl_yaml,[{"classification":"false_positive","exception_scope":{"proc.name":"definitely_absent_process"}}, {"classification":"true_positive","output_fields":{"proc.name":"curl"}}])
cases.append({"case":"tune_preserves_curl", "validation":validate(preserved["tuned_yaml"],profile,mode="container"),
    "tests":run_tests(preserved["tuned_yaml"],profile,[str(capture)],[{"capture":str(capture),"must_fire":["AFB Curl Execution"]}])})
# Dependency validation and replay use the same ordered files.
dep=out/"dependency.yaml"
dep.write_text('- macro: integration_exec\n  condition: evt.type in (execve, execveat) and evt.rawres >= 0\n',encoding="utf-8")
profile.rules_files=[str(dep)]
dependent=curl_yaml.replace("afb_spawned_process and", "integration_exec and")
cases.append({"case":"ordered_dependency", "validation":validate(dependent,profile,mode="container"),
    "tests":run_tests(dependent,profile,[str(capture)],[{"capture":str(capture),"must_fire":["AFB Curl Execution"]}])})
profile.rules_files=[]
# An overlapping earlier rule must fail combined replay while isolated replay passes.
overlap='- rule: Earlier curl rule\n  desc: Overlap control\n  condition: evt.type = execve and proc.name = curl\n  output: earlier\n  priority: NOTICE\n'
cases.append({"case":"overlap_failure_detected", "expected_status":"failed",
    "tests":run_tests(curl_yaml,profile,[str(capture)],[{"capture":str(capture),"must_fire":["AFB Curl Execution"]}],overlap)})
# Mutation controls prove the harness rejects intentionally wrong expectations.
cases.append({"case":"expected_positive_failure", "expected_status":"failed",
    "tests":run_tests(curl_yaml,profile,[str(capture)],[{"capture":str(capture),"must_fire":["Absent Rule"]}])})
cases.append({"case":"expected_negative_failure", "expected_status":"failed",
    "tests":run_tests(curl_yaml,profile,[str(capture)],[{"capture":str(capture),"must_not_fire":["AFB Curl Execution"]}])})
(out/"results.json").write_text(json.dumps(cases,indent=2),encoding="utf-8")
for case in cases:
    print(case["case"], case.get("validation",{}).get("status","n/a"),case["tests"]["status"])
ok=all(case["tests"]["status"]==case.get("expected_status","passed") and case.get("validation",{"status":"passed"})["status"]=="passed" for case in cases)
raise SystemExit(0 if ok else 1)
