"""Target profile loader. Never assumes a Falco version or silently falls back."""
from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path


class ProfileError(Exception):
    pass


@dataclass
class TargetProfile:
    name: str
    falco_version: str
    image_repository: str
    image_digest: str
    supported_fields: frozenset
    plugins: list[dict]
    dialect: str
    replay: dict | None = None

    def field_supported(self, field_name: str) -> bool:
        return field_name in self.supported_fields


def load_profile(path: str | Path) -> TargetProfile:
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    required = ["name", "falco_version", "image", "supported_fields", "plugins"]
    missing = [k for k in required if k not in data]
    if missing:
        raise ProfileError(f"profile missing required keys: {missing}")
    if data.get("dialect", "example") == "example":
        raise ProfileError(
            "profile is an example dialect; replace with your actual deployed "
            "Falco version and image digest before generating rules"
        )
    img = data["image"]
    if "digest" not in img or not img["digest"].startswith("sha256:"):
        raise ProfileError("image.digest must be an immutable sha256:... digest")
    return TargetProfile(
        name=data["name"],
        falco_version=str(data["falco_version"]),
        image_repository=img["repository"],
        image_digest=img["digest"],
        supported_fields=frozenset(data["supported_fields"]),
        plugins=list(data["plugins"]),
        dialect=data.get("dialect", "example"),
        replay=data.get("replay"),
    )
