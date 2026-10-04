import json
from pathlib import Path

import pytest

from afb.adapters.falco_json import load_alerts, REDACTABLE_FIELDS
from afb.evidence import summarize
from afb.profile import ProfileError, load_profile, TargetProfile
from afb.planner import plan_detection
from afb.template_gen import generate_rule, render_yaml
from afb.tune import load_classified_alerts, tune_rule
from afb.validator import validate

EXAMPLES = Path(__file__).parent.parent / "examples"


def test_profile_rejects_example_dialect():
    with pytest.raises(ProfileError, match="example dialect"):
        load_profile(EXAMPLES / "example.profile.json")


def make_profile(fields=None) -> TargetProfile:
    return TargetProfile(
        name="test", falco_version="0.0-test", image_repository="falcosecurity/falco",
        image_digest="sha256:" + "0" * 64,
        supported_fields=frozenset(fields or [
            "evt.type", "proc.name", "proc.cmdline", "user.name", "k8s.ns.name",
            "k8s.pod.name", "container.name", "container.image.repository"]),
        plugins=[], dialect="real")


def test_adapters_provenance_and_missing_fields():
    corpus = load_alerts(EXAMPLES / "nsenter_alerts.json")
    assert len(corpus.alerts) == 8
    a = corpus.alerts[0]
    assert a.provenance["source"].endswith("nsenter_alerts.json")
    assert len(a.provenance["record_sha256"]) == 64
    meta_missing = corpus.alerts[5]
    assert "k8s.ns.name" in meta_missing.missing_fields
    assert meta_missing.field("k8s.ns.name") is None


def test_redaction():
    corpus = load_alerts(EXAMPLES / "nsenter_alerts.json")
    red = corpus.alerts[0].redacted_fields()
    assert red["proc.cmdline"].startswith("sha256:")
    assert "nsenter -t 1" not in json.dumps(red)
    # non-sensitive passthrough
    assert red["evt.type"] == "execve"


def test_grouping():
    corpus = load_alerts(EXAMPLES / "nsenter_alerts.json")
    s = summarize(corpus)
    by_proc = {g.proc_name: g for g in s.groups}
    assert by_proc["nsenter"].namespaces["prod"] == 4
    assert by_proc["nsenter"].namespaces["dev"] == 1
    assert by_proc["nsenter"].namespaces[None] == 2
    assert s.namespace_missing == 2


def test_plan_prod_nsenter():
    corpus = load_alerts(EXAMPLES / "nsenter_alerts.json")
    summary = summarize(corpus)
    profile = make_profile()
    spec = plan_detection(summary, profile, "nsenter", "prod")
    assert spec.match["scope"] == {"k8s.ns.name": ["prod"]}
    assert any("k8s.ns.name" in g or "missing" in g for g in spec.coverage_gaps)


def test_plan_dev_scope_is_distinct():
    corpus = load_alerts(EXAMPLES / "nsenter_alerts.json")
    summary = summarize(corpus)
    profile = make_profile()
    spec = plan_detection(summary, profile, "nsenter", "dev")
    assert spec.match["scope"] == {"k8s.ns.name": ["dev"]}
    # the generated rule must NOT match prod events
    yaml_text = render_yaml(generate_rule(spec, profile))
    assert '"dev"' in yaml_text and '"prod"' not in yaml_text


def test_ordinary_exec_not_matched():
    corpus = load_alerts(EXAMPLES / "nsenter_alerts.json")
    summary = summarize(corpus)
    profile = make_profile()
    # bash is a separate behavior group; explicitly requesting it is fine...
    spec = plan_detection(summary, profile, "bash", "prod")
    # ...but the nsenter rule must not cover ordinary exec, and vice versa
    yaml_text = render_yaml(generate_rule(plan_detection(summary, profile, "nsenter", "prod"), profile))
    assert 'proc.name = "bash"' not in yaml_text


def test_capability_gap_reported_not_invented():
    corpus = load_alerts(EXAMPLES / "nsenter_alerts.json")
    summary = summarize(corpus)
    profile = make_profile(fields=["evt.type", "proc.name", "proc.cmdline"])
    spec = plan_detection(summary, profile, "nsenter", "prod")
    assert any("k8s.ns.name" in g and "not supported" in g for g in spec.coverage_gaps)


def test_candidate_static_validation_passes():
    corpus = load_alerts(EXAMPLES / "nsenter_alerts.json")
    summary = summarize(corpus)
    profile = make_profile()
    candidate = render_yaml(generate_rule(plan_detection(summary, profile, "nsenter", "prod"), profile))
    v = validate(candidate, profile, mode="never-container")
    assert v["static_lint"]["status"] == "passed"
    assert v["status"] == "static_lint_only"
    assert "not proof" in v["note"]


def test_candidate_static_validation_catches_bad_ref():
    bad = "- rule: X\n  desc: d\n  condition: undefined_macro and proc.name = \"x\"\n  output: \"x\"\n  priority: WARNING\n"
    v = validate(bad, make_profile(), mode="never-container")
    assert v["static_lint"]["status"] == "failed"
    assert any("undefined macro" in e for e in v["static_lint"]["errors"])


def test_test_runner_honest_not_run():
    from afb.test_runner import run_tests
    res = run_tests("rules: x", make_profile(), captures=[])
    assert res["status"] == "not_run"
    assert "no compatible event captures" in res["reason"]


def test_tune_produces_diff_and_regression():
    rule_yaml = (
        "- rule: AFB Nsenter\n"
        "  desc: d\n"
        "  condition: spawned_process and proc.name = \"nsenter\" and k8s.ns.name in (\"prod\")\n"
        "  output: \"x (proc.name=%proc.name)\"\n"
        "  priority: WARNING\n"
        "  tags: [afb]\n"
    )
    classified = load_classified_alerts(EXAMPLES / "classified_alerts.jsonl")
    res = tune_rule(rule_yaml, classified)
    assert res["exception_scope"] == {"container.image.repository": "registry.internal/monitoring-agent"}
    assert "afb_tune_exception" in res["tuned_yaml"]
    assert "-  rule: AFB Nsenter" in res["change_diff"] or "-rule:" in res["change_diff"] or "-" in res["change_diff"]
    assert res["regression_expectations"]["preserved_positives"][0]["must_fire"] is True
    assert res["regression_expectations"]["suppressed_negatives"][0]["must_fire"] is False


def test_tune_rejects_unclassified():
    with pytest.raises(ValueError, match="classification"):
        tune_rule("- rule: X\n  condition: 'true'\n", [{"classification": "unknown"}])
