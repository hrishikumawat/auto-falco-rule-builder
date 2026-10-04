"""Shared pinned Docker configuration and dependency ordering."""
from pathlib import Path

def rule_files(profile, candidate_path, deploy_path=None, validate=False):
    mounts, flags = [], []
    option = "-V" if validate else "-r"
    for i, file in enumerate(profile.rules_files or []):
        dest = f"/rules/dependency-{i}.yaml"
        mounts.append((Path(file).resolve(), dest))
        flags += [option, dest]
    if deploy_path is not None:
        mounts.append((deploy_path, "/rules/deployment.yaml"))
        flags += [option, "/rules/deployment.yaml"]
    mounts.append((candidate_path, "/rules/candidate.yaml"))
    flags += [option, "/rules/candidate.yaml"]
    return mounts, flags

def docker_command(profile, mounts):
    replay = profile.replay or {}
    cmd = ["docker", "run", "--rm", "--network", "none", "--entrypoint", "/usr/bin/falco"]
    for src, dest in mounts:
        cmd += ["-v", f"{Path(src).resolve()}:{dest}:ro"]
    config = replay.get("config", "/etc/falco/falco.yaml")
    if profile.config_file:
        cmd += ["-v", f"{Path(profile.config_file).resolve()}:/config/falco.yaml:ro"]
        config = "/config/falco.yaml"
    cmd += [f"{profile.image_repository}@{profile.image_digest}", "-c", config]
    cmd += profile.runtime_args or []
    return cmd
