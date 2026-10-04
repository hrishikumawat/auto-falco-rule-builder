"""Synthetic pipeline demo; explicitly static, never runtime detection proof."""
import os
import sys
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]
os.chdir(ROOT)
sys.path.insert(0, str(ROOT))
from afb.cli import main
common = ["--profile", "examples/demo.profile.json", "--validation-mode", "static"]
rc = main(["create", "--alerts", "examples/nsenter_alerts.json", "--proc", "nsenter", "--namespace", "prod", "--out", "demo_output/create-001"] + common)
rc = max(rc, main(["tune", "--rule", "examples/current_rule.yaml", "--classified-alerts", "examples/classified_alerts.jsonl", "--out", "demo_output/tune-001"] + common))
raise SystemExit(rc)
