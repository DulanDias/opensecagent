# OpenSecAgent - Firewall audit detector: ufw/iptables status
from __future__ import annotations

import asyncio
import subprocess
from typing import Any

logger = __import__("logging").getLogger("opensecagent.detector.firewall")


def _run_firewall_audit(require_active: bool) -> list[dict[str, Any]]:
    """Check ufw status; emit if inactive when require_active. Run in executor."""
    events: list[dict[str, Any]] = []
    ufw_active = None
    try:
        r = subprocess.run(
            ["ufw", "status"],
            capture_output=True,
            text=True,
            timeout=5,
        )
        if r.returncode == 0 and r.stdout:
            first_line = (r.stdout or "").strip().split("\n")[0].lower()
            ufw_active = "active" in first_line and "inactive" not in first_line
    except FileNotFoundError:
        pass
    except Exception as e:
        logger.debug("UFW check failed: %s", e)

    if require_active and ufw_active is False:
        events.append({
            "event_id": "firewall-inactive-1",
            "source": "detector.firewall",
            "event_type": "firewall_inactive",
            "severity": "P2",
            "summary": "UFW firewall is inactive; consider enabling (ufw enable)",
            "raw": {"ufw_active": False},
            "asset_ids": ["host"],
            "confidence": 1.0,
        })
    elif require_active and ufw_active is None:
        try:
            r = subprocess.run(
                ["iptables", "-L", "-n"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            if r.returncode != 0 or not (r.stdout and "Chain" in r.stdout):
                events.append({
                    "event_id": "firewall-unclear-1",
                    "source": "detector.firewall",
                    "event_type": "firewall_audit",
                    "severity": "P3",
                    "summary": "No UFW and iptables may have no rules; verify host firewall is configured",
                    "raw": {},
                    "asset_ids": ["host"],
                    "confidence": 0.7,
                })
        except FileNotFoundError:
            events.append({
                "event_id": "firewall-none-1",
                "source": "detector.firewall",
                "event_type": "firewall_audit",
                "severity": "P3",
                "summary": "UFW not found; ensure a host firewall (ufw or iptables) is configured",
                "raw": {},
                "asset_ids": ["host"],
                "confidence": 0.8,
            })
    return events


class FirewallAuditDetector:
    """Emit events when firewall (ufw) is inactive or missing."""

    def __init__(self, config: dict[str, Any]) -> None:
        self.config = config
        det = config.get("detector", {})
        self._enabled = det.get("firewall_audit_enabled", True)
        self._require_active = det.get("firewall_require_active", True)

    async def check(self) -> list[dict[str, Any]]:
        if not self._enabled:
            return []
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(None, _run_firewall_audit, self._require_active)
