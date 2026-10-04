#!/usr/bin/env python
"""auto-falco-rule-builder CLI.

CREATE: alerts -> detection spec -> candidate Falco YAML -> validation -> tests -> report.
TUNE:   existing rule + classified alerts -> scoped exception -> diff -> regression expectations.

No LLM in milestone 1. No automatic deployment, ever.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .adapters.falco_json import load_alerts
from .evidence import summarize
from .planner import plan_detection
from .profile import load_profile
from .template_gen import generate_rule, render_yaml
from .test_runner import run_tests
from .tune import load_classified_alerts, tune_rule
from .validator import validate
from .reporter import export


def _load_expectations(path: str | None) -> list[dict]:
    if not path:
        return []
    return json.loads(Path(path).read_text())


def _input_files(args, profile, primary):
    files = list(primary) + [args.profile] + list(args.captures or [])
    files += list(profile.rules_files or [])
    for path in [args.expectations, args.deployment_ruleset, profile.config_file]:
        if path:
            files.append(path)
    return list(dict.fromkeys(map(str, files)))


def cmd_create(args) -> int:
    profile = load_profile(args.profile)
    corpus = load_alerts(args.alerts)
    summary = summarize(corpus)
    spec = plan_detection(summary, profile, args.proc, args.namespace)
    rule_doc = generate_rule(spec, profile)
    candidate = render_yaml(rule_doc)
    validation = validate(candidate, profile, mode=args.validation_mode)
    tests = run_tests(candidate, profile, captures=args.captures or [],
                      expectations=_load_expectations(args.expectations),
                      deployment_ruleset=Path(args.deployment_ruleset).read_text(encoding="utf-8") if args.deployment_ruleset else None)
    result = export(args.out, spec, candidate, validation, tests,
                    summary.to_dict(), profile, _input_files(args, profile, [args.alerts]))
    rc = 0 if validation.get("status") in ("passed", "static_lint_only") else 1
    if tests.get("status") == "failed":
        rc = 3  # replay assertions failed â€” candidate does not behave as specified
    print(json.dumps({"status": validation.get("status"), "tests": tests.get("status"),
                      "out": result["out_dir"], "files": result["files"]}, indent=2))
    return rc


def cmd_tune(args) -> int:
    profile = load_profile(args.profile)
    classified = load_classified_alerts(args.classified_alerts)
    tuned = tune_rule(args.rule.read_text() if hasattr(args.rule, "read_text") else open(args.rule).read(), classified)
    validation = validate(tuned["tuned_yaml"], profile, mode=args.validation_mode)
    tests = run_tests(tuned["tuned_yaml"], profile, captures=args.captures or [],
                      expectations=_load_expectations(args.expectations),
                      deployment_ruleset=Path(args.deployment_ruleset).read_text(encoding="utf-8") if args.deployment_ruleset else None)
    tests["regression_expectations"] = tuned["regression_expectations"]
    from .planner import DetectionSpec
    spec = DetectionSpec(
        spec_version=1, intent=f"tune rule {args.rule}",
        match={"exception_scope": tuned["exception_scope"]},
        required_fields=list(tuned["exception_scope"]),
        coverage_gaps=[], limitations=["tuned exception must be reviewed by an analyst"],
        source_evidence=[],
    )
    result = export(args.out, spec, tuned["tuned_yaml"], validation, tests,
                    {"classified_counts": {
                        "true_positive": sum(1 for c in classified if c.get("classification") == "true_positive"),
                        "false_positive": sum(1 for c in classified if c.get("classification") == "false_positive"),
                    }, "fixture_ids": [c.get("alert_id") for c in classified]},
                    profile, _input_files(args, profile, [str(args.rule), args.classified_alerts]),
                    change_diff=tuned["change_diff"], workflow="TUNE")
    print(json.dumps({"status": validation.get("status"), "tests": tests.get("status"),
                      "exception_scope": tuned["exception_scope"], "out": result["out_dir"]}, indent=2))
    return 3 if tests.get("status") == "failed" else (0 if validation.get("status") in ("passed", "static_lint_only") else 1)


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="afb", description=__doc__)
    sub = p.add_subparsers(dest="cmd", required=True)

    c = sub.add_parser("create", help="CREATE workflow")
    c.add_argument("--alerts", required=True, help="Falco JSON/JSONL alerts file")
    c.add_argument("--profile", required=True, help="target profile JSON")
    c.add_argument("--proc", required=True, help="process name to detect (e.g. nsenter)")
    c.add_argument("--namespace", default=None, help="k8s namespace scope (omit = all namespaces)")
    c.add_argument("--captures", nargs="*", default=[], help="scap captures for replay testing")
    c.add_argument("--expectations", default=None, help="JSON: [{capture, must_fire[], must_not_fire[]}]")
    c.add_argument("--deployment-ruleset", default=None, help="existing ruleset for overlap testing")
    c.add_argument("--out", required=True)
    c.add_argument("--validation-mode", choices=["auto", "container", "static"], default="auto")
    c.set_defaults(func=cmd_create)

    t = sub.add_parser("tune", help="TUNE workflow")
    t.add_argument("--rule", required=True, help="existing rule YAML")
    t.add_argument("--classified-alerts", required=True, help="JSONL with analyst classification")
    t.add_argument("--profile", required=True)
    t.add_argument("--captures", nargs="*", default=[])
    t.add_argument("--expectations", default=None)
    t.add_argument("--out", required=True)
    t.add_argument("--validation-mode", choices=["auto", "container", "static"], default="auto")
    t.add_argument("--deployment-ruleset", default=None)
    t.set_defaults(func=cmd_tune)

    args = p.parse_args(argv)
    try:
        return args.func(args)
    except Exception as e:
        print(json.dumps({"error": str(e), "type": type(e).__name__}), file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
