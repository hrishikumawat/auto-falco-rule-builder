"""TUNE workflow: existing rule + analyst-classified alerts -> scoped exception.

Produces a reviewable diff and preserved-positive regression expectations.
Requires analyst classification; the builder never decides positivity itself.
"""
from __future__ import annotations

import difflib

import yaml
from pathlib import Path


def load_classified_alerts(path) -> list[dict]:
    import json
    text = Path(path).read_text()
    records = []
    for line in text.splitlines():
        line = line.strip()
        if line:
            records.append(json.loads(line))
    return records


def tune_rule(rule_yaml: str, classified: list[dict]) -> dict:
    """classified: [{"output_fields": {...}, "classification": "false_positive",
    "exception_scope": {"container.image.repository": "..."} or "proc.cmdline": "..."}]

    Exception scope must be supplied per alert by the analyst; the tool only
    intersects scopes across false positives and requires they be narrow.
    """
    fps = [c for c in classified if c.get("classification") == "false_positive"]
    tps = [c for c in classified if c.get("classification") == "true_positive"]
    missing = [c for c in classified if c.get("classification") not in ("false_positive", "true_positive")]
    if missing:
        raise ValueError(f"{len(missing)} alerts lack a valid analyst classification")

    docs = yaml.safe_load(rule_yaml)
    rule_idx = next(i for i, d in enumerate(docs) if "rule" in d)
    rule = docs[rule_idx]["rule"]
    original = yaml.safe_dump(docs, sort_keys=False, default_flow_style=False)

    # intersect exception scopes across all false positives (narrow by design)
    scopes = [c.get("exception_scope", {}) for c in fps]
    if not scopes:
        raise ValueError("no false positives with exception_scope â€” nothing to tune")
    if any(not scope for scope in scopes) or any(scope != scopes[0] for scope in scopes[1:]):
        raise ValueError("false-positive scopes differ; refusing to broaden analyst-approved exceptions")
    common: dict = {}
    keys = set.intersection(*[set(s) for s in scopes])
    for k in keys:
        vals = [s[k] for s in scopes]
        if all(v == vals[0] for v in vals):
            common[k] = vals[0]
    if not common:
        raise ValueError(
            "false positives share no common field value; cannot form a narrow "
            "exception â€” tune manually or collect more classification data"
        )

    import re
    if any(not re.fullmatch(r"[a-zA-Z_][a-zA-Z0-9_.]*", key) for key in common):
        raise ValueError("invalid exception field")
    if any(all(c.get("output_fields", {}).get(key) == value for key, value in common.items()) for c in tps):
        raise ValueError("exception would suppress a classified true positive")
    macro_name = "afb_tune_exception"
    import json
    scope_cond = " and ".join(f"{k} = {json.dumps(str(v))}" for k, v in common.items())
    if any(d.get("macro") == macro_name for d in docs):
        raise ValueError("rule already contains afb_tune_exception; review existing exception first")
    docs.insert(rule_idx, {"macro": macro_name, "condition": f"({scope_cond})"})
    rule_body = docs[rule_idx + 1]
    rule_body["condition"] = f"({rule_body['condition']}) and not {macro_name}"
    rule_body.setdefault("tags", []).append("afb-tuned")

    tuned = yaml.safe_dump(docs, sort_keys=False, default_flow_style=False)
    diff = "".join(difflib.unified_diff(
        original.splitlines(True), tuned.splitlines(True),
        fromfile="rule.current.yaml", tofile="rule.tuned.yaml",
    ))
    return {
        "tuned_yaml": tuned,
        "change_diff": diff,
        "exception_scope": common,
        "regression_expectations": {
            "preserved_positives": [
                {"output_fields": c.get("output_fields", {}), "must_fire": True} for c in tps
            ],
            "suppressed_negatives": [
                {"output_fields": c.get("output_fields", {}), "must_fire": False} for c in fps
            ],
        },
        "note": "Regression expectations need runtime replay to verify; see test runner.",
    }
