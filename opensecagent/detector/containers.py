# OpenSecAgent - New container start detector
from __future__ import annotations

from typing import Any


class NewContainerDetector:
    def __init__(self, config: dict[str, Any]) -> None:
        self.config = config

    def check(self, docker_inv: dict[str, Any], last_container_ids: set[str]) -> dict[str, Any] | None:
        if not docker_inv.get("available"):
            return None
        current = {c.get("id", "") for c in docker_inv.get("containers", [])}
        running_now = {c.get("id", "") for c in docker_inv.get("containers", []) if c.get("status") == "running"}
        new_running = running_now - last_container_ids
        if not last_container_ids:
            return None
        if new_running:
            names = [c.get("name", c.get("id", "")) for c in docker_inv.get("containers", []) if c.get("id") in new_running]
            return {
                "event_id": f"new-container-{hash(frozenset(new_running)) % 2**32}",
                "source": "detector.containers",
                "event_type": "new_container",
                "severity": "P3",
                "summary": f"New container(s) started: {', '.join(names[:5])}",
                "raw": {"new_ids": list(new_running), "names": names},
                "asset_ids": list(new_running),
                "confidence": 1.0,
            }
        return None
