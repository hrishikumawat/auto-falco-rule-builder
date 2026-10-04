#!/usr/bin/env bash
# Docker-free demo: runs CREATE + TUNE end-to-end on SYNTHETIC fixtures with a
# SYNTHETIC profile. Demonstrates pipeline mechanics and honest status
# reporting only. This is NOT runtime detection proof:
#   - validation runs in static-lint-only mode (no Docker daemon / no Falco engine)
#   - tests report not_run (no scap captures, by design)
# For real integration testing, use curated or controlled-lab captures with a
# real pinned profile; production telemetry is not required for development.
set -euo pipefail
cd "$(dirname "$0")/.."
OUT=demo_output
rm -rf "$OUT"; mkdir -p "$OUT"

echo "== CREATE (demo) =="
.venv/bin/python -m afb.cli create \
  --alerts examples/nsenter_alerts.json \
  --profile examples/demo.profile.json \
  --proc nsenter --namespace prod \
  --out "$OUT/create-001"

echo "== TUNE (demo) =="
.venv/bin/python -m afb.cli tune \
  --rule examples/current_rule.yaml \
  --classified-alerts examples/classified_alerts.jsonl \
  --profile examples/demo.profile.json \
  --out "$OUT/tune-001"

echo "Demo outputs in $OUT/ (all synthetic; statuses are labeled inside report.md)."
