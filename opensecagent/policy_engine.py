# OpenSecAgent - Policy engine: allowed actions by tier, maintenance window
from __future__ import annotations

from datetime import datetime
from typing import Any

from opensecagent.models import ActionTier, Incident


class PolicyEngine:
    def __init__(self, config: dict[str, Any]) -> None:
        self.config = config
        tier = config.get("action_tier_max", 1)
        self._max_tier = ActionTier(tier) if isinstance(tier, int) else ActionTier.ALERT_ONLY
        self._maintenance_windows = config.get("maintenance_windows", [])

    def allowed_actions(self, incident: Incident) -> list[dict[str, Any]]:
        actions: list[dict[str, Any]] = []
        if self._in_maintenance_window():
            actions.append({"action": "alert_only", "reason": "maintenance_window"})
            return actions
        actions.append({"action": "alert_only", "reason": "always"})
        if self._max_tier >= ActionTier.SOFT_CONTAINMENT and incident.severity.value in ("P1", "P2"):
            if incident.event_type_matches("new_container"):
                actions.append({"action": "stop_container", "tier": 1, "timeout_minutes": 60})
            if incident.event_type_matches("auth_failures"):
                actions.append({"action": "block_ip_temporary", "tier": 1, "timeout_minutes": 30})
        return actions

    def _in_maintenance_window(self) -> bool:
        now = datetime.utcnow()
        for w in self._maintenance_windows:
            start = w.get("start")
            end = w.get("end")
            if start and end:
                try:
                    from dateutil import parser as dup
                    s = dup.parse(start)
                    e = dup.parse(end)
                    if s <= now <= e:
                        return True
                except Exception:
                    pass
        return False


