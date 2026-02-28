# OpenSecAgent - Normalizer: raw data -> common event schema
from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any


class Normalizer:
    def host_inventory_to_events(self, inv: dict[str, Any]) -> list[dict[str, Any]]:
        events: list[dict[str, Any]] = []
        e = {
            "event_id": f"host-inv-{uuid.uuid4().hex[:12]}",
            "source": "host_collector",
            "event_type": "host_inventory",
            "severity": "P4",
            "summary": f"Host inventory: {inv.get('hostname', 'unknown')}",
            "raw": inv,
            "ts": datetime.utcnow().isoformat() + "Z",
            "asset_ids": ["host"],
            "confidence": 1.0,
        }
        events.append(e)
        return events

    def docker_inventory_to_events(self, inv: dict[str, Any]) -> list[dict[str, Any]]:
        events: list[dict[str, Any]] = []
        if not inv.get("available"):
            return events
        e = {
            "event_id": f"docker-inv-{uuid.uuid4().hex[:12]}",
            "source": "docker_collector",
            "event_type": "docker_inventory",
            "severity": "P4",
            "summary": f"Docker: {len(inv.get('containers', []))} containers, {len(inv.get('images', []))} images",
            "raw": inv,
            "ts": datetime.utcnow().isoformat() + "Z",
            "asset_ids": ["host"] + [c.get("id", "") for c in inv.get("containers", [])[:20]],
            "confidence": 1.0,
        }
        events.append(e)
        return events
