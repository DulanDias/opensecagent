# OpenSecAgent - New listening port detector
from __future__ import annotations

from typing import Any


class NewPortDetector:
    def __init__(self, config: dict[str, Any]) -> None:
        self.config = config

    def check(self, host_inv: dict[str, Any], last_ports: set[str]) -> dict[str, Any] | None:
        current = {str(p.get("port", p.get("address", ""))) for p in host_inv.get("listening_ports", [])}
        new_ports = current - last_ports
        if not last_ports:
            return None
        if new_ports:
            return {
                "event_id": f"new-port-{hash(frozenset(new_ports)) % 2**32}",
                "source": "detector.ports",
                "event_type": "new_listening_port",
                "severity": "P3",
                "summary": f"New listening port(s) detected: {', '.join(sorted(new_ports)[:10])}",
                "raw": {"new_ports": list(new_ports), "current_ports": list(current)},
                "asset_ids": ["host"],
                "confidence": 1.0,
            }
        return None
