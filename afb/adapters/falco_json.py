"""Falco JSON alert ingestion.

Accepts a single alert object, a list, or JSONL. Every record gets provenance
(source path, index, sha256 of the raw record). Missing fields are preserved
as None and recorded — never dropped or defaulted.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

# Fields whose raw values are sensitive; redacted for model use, kept raw in
# the raw evidence store only.
REDACTABLE_FIELDS = frozenset(
    {
        "proc.cmdline",
        "proc.env",
        "user.name",
        "user.loginuid",
        "k8s.pod.name",
        "container.name",
        "container.image.repository",
        "hostname",
    }
)


@dataclass
class Alert:
    provenance: dict
    output_fields: dict[str, Any | None]
    missing_fields: list[str]
    rule: str | None
    priority: str | None
    time: str | None
    tags: list[str]
    output_text: str | None  # untrusted: never embedded in generated rules
    raw: dict

    def field(self, name: str) -> Any | None:
        return self.output_fields.get(name)

    def redacted_fields(self) -> dict[str, Any]:
        """Copy safe for model/report use: sensitive values become sha256:8."""
        out = {}
        for k, v in self.output_fields.items():
            if v is None:
                out[k] = None
            elif k in REDACTABLE_FIELDS:
                out[k] = "sha256:" + hashlib.sha256(str(v).encode()).hexdigest()[:8]
            else:
                out[k] = v
        return out


@dataclass
class AlertCorpus:
    source: str
    alerts: list[Alert] = field(default_factory=list)


def load_alerts(path: str | Path) -> AlertCorpus:
    p = Path(path)
    text = p.read_text(encoding="utf-8")
    alerts: list[Alert] = []

    def make(raw: dict, idx: int) -> Alert:
        raw_bytes = json.dumps(raw, sort_keys=True).encode()
        of = raw.get("output_fields") or {}
        observed = set(of.keys())
        # fields referenced by output text but absent -> recorded as missing
        missing = sorted(k for k in EXPECTED_COMMON if k not in observed)
        return Alert(
            provenance={
                "source": str(p),
                "index": idx,
                "record_sha256": hashlib.sha256(raw_bytes).hexdigest(),
            },
            output_fields={k: of.get(k) for k in observed},
            missing_fields=missing,
            rule=raw.get("rule"),
            priority=raw.get("priority"),
            time=raw.get("time"),
            tags=list(raw.get("tags") or []),
            output_text=raw.get("output"),
            raw=raw,
        )

    # try whole-file JSON first, then JSONL
    try:
        data = json.loads(text)
        records = data if isinstance(data, list) else [data]
        if not all(isinstance(r, dict) for r in records):
            raise ValueError("non-object record")
        alerts = [make(r, i) for i, r in enumerate(records)]
    except (json.JSONDecodeError, ValueError):
        for i, line in enumerate(text.splitlines()):
            line = line.strip()
            if not line:
                continue
            alerts.append(make(json.loads(line), i))

    if not alerts:
        raise ValueError(f"no alerts parsed from {p}")
    return AlertCorpus(source=str(p), alerts=alerts)


EXPECTED_COMMON = [
    "evt.type",
    "proc.name",
    "k8s.ns.name",
    "k8s.pod.name",
    "container.name",
    "user.name",
]
