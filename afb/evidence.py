"""Evidence store: grouping of repeated behavior over ingested alerts.

Frequencies describe matched activity only — never a behavior baseline.
"""
from __future__ import annotations

from collections import Counter, defaultdict
from dataclasses import dataclass

from .adapters.falco_json import Alert


@dataclass
class BehaviorGroup:
    evt_type: str | None
    proc_name: str | None
    namespaces: dict[str | None, int]  # namespace -> count (None = missing)
    count: int
    sample_provenance: dict

    def namespace_missing_count(self) -> int:
        return self.namespaces.get(None, 0)


@dataclass
class EvidenceSummary:
    groups: list[BehaviorGroup]
    total_alerts: int
    namespace_missing: int

    def to_dict(self) -> dict:
        return {
            "total_alerts": self.total_alerts,
            "namespace_missing_metadata": self.namespace_missing,
            "groups": [
                {
                    "evt_type": g.evt_type,
                    "proc_name": g.proc_name,
                    "namespaces": {str(k) if k is not None else "MISSING": v for k, v in g.namespaces.items()},
                    "count": g.count,
                    "sample_provenance": g.sample_provenance,
                }
                for g in self.groups
            ],
            "note": "Counts reflect matched alerts only; not a behavior baseline.",
        }


def summarize(corpus) -> EvidenceSummary:
    buckets: dict[tuple, list[Alert]] = defaultdict(list)
    ns_missing = 0
    for a in corpus.alerts:
        evt = a.field("evt.type")
        proc = a.field("proc.name")
        ns = a.field("k8s.ns.name")
        if ns is None:
            ns_missing += 1
        buckets[(evt, proc)].append(a)

    groups = []
    for (evt, proc), alerts in buckets.items():
        ns_counter: Counter = Counter()
        for a in alerts:
            ns_counter[a.field("k8s.ns.name")] += 1
        groups.append(
            BehaviorGroup(
                evt_type=evt,
                proc_name=proc,
                namespaces=dict(ns_counter),
                count=len(alerts),
                sample_provenance=alerts[0].provenance,
            )
        )
    groups.sort(key=lambda g: -g.count)
    return EvidenceSummary(
        groups=groups, total_alerts=len(corpus.alerts), namespace_missing=ns_missing
    )
