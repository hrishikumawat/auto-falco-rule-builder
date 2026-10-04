"""Validator: pinned-container Falco validation preferred, static lint fallback.

Runtime mode requires a reachable Docker daemon and a profile with an image
digest. If unavailable, the report says so â€” YAML validation alone is never
presented as proof of runtime detection.
"""
from __future__ import annotations

import shutil
import subprocess
import tempfile
from pathlib import Path
from .runtime import docker_command, rule_files

import yaml

BUILTIN_MACROS = {
    "spawned_process", "open_write", "open_read", "container", "not_container",
    "private_bins", "system_procs", "trusted_containers", "run_as_root",
    "evt_type", "modify", "created_by_trusted_containers",
}
VALID_PRIORITIES = {"EMERGENCY", "ALERT", "CRITICAL", "ERROR", "WARNING", "NOTICE", "INFORMATIONAL", "DEBUG"}


def docker_available() -> bool:
    if not shutil.which("docker"):
        return False
    try:
        subprocess.run(["docker", "info"], capture_output=True, timeout=15, check=True)
        return True
    except (subprocess.SubprocessError, OSError):
        return False


def _static_lint(rule_text: str) -> list[str]:
    errors: list[str] = []
    try:
        docs = yaml.safe_load(rule_text)
    except yaml.YAMLError as e:
        return [f"invalid YAML: {e}"]
    if not isinstance(docs, list):
        return ["rules file must be a YAML list of macro/list/rule entries"]
    defined: set[str] = set()
    entries = [e for e in docs if isinstance(e, dict)]
    for entry in entries:
        kind = next((k for k in ("macro", "rule", "list") if k in entry), None)
        if kind is None:
            errors.append(f"entry has no macro/rule/list name key: {sorted(entry)[:4]!r}")
            continue
        body = entry
        name = body.get(kind)
        if not name:
            errors.append(f"{kind} entry missing name: {body!r}")
            continue
        if kind == "rule":
            for req in ("condition", "output", "desc", "priority"):
                if not body.get(req):
                    errors.append(f"rule {name!r} missing {req}")
            if body.get("priority", "").upper() not in VALID_PRIORITIES:
                errors.append(f"rule {name!r} has invalid priority {body.get('priority')!r}")
            for field in _output_fields(body.get("output", "")):
                if "." in field and field not in ("evt.time",):
                    pass  # field support is checked against profile in reporter
        if kind == "macro" and body.get("condition"):
            for ref in _identifiers(body["condition"]):
                if ref not in defined and ref not in BUILTIN_MACROS:
                    errors.append(f"macro {name!r} references undefined macro {ref!r}")
        defined.add(name)
    # rule conditions referencing macros
    for entry in entries:
        if "rule" in entry and isinstance(entry.get("condition"), str):
            for ref in _identifiers(entry["condition"]):
                if ref not in defined and ref not in BUILTIN_MACROS:
                    errors.append(f"rule {entry['rule']!r} references undefined macro {ref!r}")
    return errors


def _output_fields(output: str) -> list[str]:
    return [tok[1:] for tok in output.split() if tok.startswith("%")]


def _identifiers(condition: str) -> set[str]:
    """Extract bare identifiers (possible macro refs) from a condition.

    Value lists following `in` (e.g. `evt.type in (execve, execveat)`) are
    values, not macro references â€” strip them before scanning.
    """
    import re
    condition = re.sub(r"\bin\s*\([^)]*\)", "", condition)
    toks = condition.replace("(", " ").replace(")", " ").replace(",", " ").split()
    out = set()
    for t in toks:
        if "." in t or t.startswith(("evt", "proc", "user", "k8s", "container", "fd", "span")):
            continue
        if t.replace("_", "").isalnum() and not t[0].isdigit():
            out.add(t)
    return out - {"and", "or", "not", "in", "contains", "startswith", "endswith", "icontains", "intersects", "exists"}


def validate(candidate_yaml: str, profile, mode: str = "auto") -> dict:
    """Returns validation.json content. status: passed|failed|unavailable."""
    result = {"static_lint": {}, "container": {}, "profile": {
        "falco_version": profile.falco_version,
        "image": f"{profile.image_repository}@{profile.image_digest}",
    }}
    dependency_docs = []
    for dep in profile.rules_files or []:
        loaded = yaml.safe_load(Path(dep).read_text(encoding="utf-8"))
        if not isinstance(loaded, list):
            raise ValueError(f"dependency is not a rules list: {dep}")
        dependency_docs.extend(loaded)
    if dependency_docs:
        loaded = yaml.safe_load(candidate_yaml)
        static_text = yaml.safe_dump(dependency_docs + loaded) if isinstance(loaded, list) else candidate_yaml
    else:
        static_text = candidate_yaml
    static_errors = _static_lint(static_text)
    result["static_lint"] = {"status": "passed" if not static_errors else "failed", "errors": static_errors}
    if static_errors:
        result["status"] = "failed"
        return result

    if profile.dialect.startswith("demo"):
        if mode == "container":
            result["status"] = "failed"
            result["container"] = {"status": "failed", "reason": "demo profile cannot execute Falco"}
            return result
        mode = "static"
    use_container = mode == "container" or (mode == "auto" and docker_available())
    if not use_container:
        result["container"] = {"status": "unavailable", "reason": "explicit static/demo mode" if mode == "static" else "no reachable Docker daemon"}
        result["status"] = "static_lint_only"
        result["note"] = (
            "Runtime validation NOT performed. YAML validation alone is not proof "
            "of runtime detection."
        )
        return result

    img = f"{profile.image_repository}@{profile.image_digest}"
    with tempfile.NamedTemporaryFile("w", suffix=".yaml", delete=False, encoding="utf-8") as f:
        f.write(candidate_yaml)
        tmp = f.name
    try:
        mounts, flags = rule_files(profile, Path(tmp), validate=True)
        proc = subprocess.run(
            docker_command(profile, mounts) + flags,
            capture_output=True, text=True, timeout=300,
        )
        if proc.returncode == 0:
            result["container"] = {"status": "passed", "image": img, "stderr": proc.stderr[-2000:]}
            result["status"] = "passed"
        else:
            result["container"] = {"status": "failed", "image": img, "stderr": proc.stderr[-4000:]}
            result["status"] = "failed"
    except (subprocess.SubprocessError, OSError) as exc:
        result["status"] = "failed"
        result["container"] = {"status": "error", "reason": str(exc)}
    finally:
        Path(tmp).unlink(missing_ok=True)
    return result
