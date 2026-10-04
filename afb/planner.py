"""Detection spec planner + capability checker.

Turns evidence groups into a structured detection specification, then checks
every required Falco field against the target profile. Unsupported fields are
reported as coverage gaps — never invented.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from .profile import TargetProfile

SPEC_VERSION = 1

KNOWN_UNSAFE_PROC = {"nsenter", "kmod", "insmod", "modprobe", "fdisk"}


@dataclass
class DetectionSpec:
    spec_version: int
    intent: str
    match: dict
    required_fields: list[str]
    coverage_gaps: list[str]
    limitations: list[str]
    source_evidence: list[dict]

    def to_dict(self) -> dict:
        return {
            "spec_version": self.spec_version,
            "intent": self.intent,
            "match": self.match,
            "required_fields": self.required_fields,
            "coverage_gaps": self.coverage_gaps,
            "limitations": self.limitations,
            "source_evidence": self.source_evidence,
        }


def plan_detection(
    summary,
    profile: TargetProfile,
    intent_proc: str,
    scope_namespace: str | None,
) -> DetectionSpec:
    """Build a spec for detecting `intent_proc` in `scope_namespace`.

    scope_namespace=None means 'all namespaces' — the caller must acknowledge
    that explicitly; a missing namespace in evidence is never mapped to a scope.
    """
    group = next(
        (g for g in summary.groups if g.proc_name == intent_proc and g.evt_type in ("execve", "clone", None)),
        None,
    )
    coverage_gaps: list[str] = []
    limitations = [
        "proc.name matching misses renamed binaries (e.g. copying nsenter to another name); "
        "full-path/proc.exepath hardening is future work"
    ]

    if group is None:
        raise ValueError(f"no evidence group for proc.name={intent_proc!r}")

    if None in group.namespaces and group.namespaces[None] > 0:
        coverage_gaps.append(
            f"{group.namespaces[None]} of {group.count} alerts lack k8s.ns.name metadata; "
            "scope enforcement depends on cluster metadata being present at event time"
        )

    required = ["evt.type", "proc.name"]
    scope: dict = {}
    if scope_namespace is not None:
        required.append("k8s.ns.name")
        scope = {"k8s.ns.name": [scope_namespace]}
        if not profile.field_supported("k8s.ns.name"):
            coverage_gaps.append(
                f"k8s.ns.name not in target profile supported_fields; "
                "cannot enforce namespace scope — NOT generating an unscooped rule silently"
            )
    for f in required:
        if not profile.field_supported(f):
            coverage_gaps.append(f"required field {f!r} not supported by target profile")

    if not scope and scope_namespace is None and "k8s.ns.name" in profile.supported_fields:
        limitations.append(
            "rule is unscooped (fires in all namespaces); provide --namespace to scope it"
        )

    return DetectionSpec(
        spec_version=SPEC_VERSION,
        intent=f"detect {intent_proc} execution"
        + (f" in namespace {scope_namespace}" if scope_namespace else " (all namespaces)"),
        match={
            "evt.type": "execve",
            "proc.name": intent_proc,
            "scope": scope,
        },
        required_fields=required,
        coverage_gaps=coverage_gaps,
        limitations=limitations,
        source_evidence=[group.sample_provenance],
    )
