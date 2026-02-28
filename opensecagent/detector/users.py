# OpenSecAgent - New admin (sudo) user detector
from __future__ import annotations

from typing import Any


class NewAdminUserDetector:
    def __init__(self, config: dict[str, Any]) -> None:
        self.config = config

    def check(self, host_inv: dict[str, Any], last_sudo_users: set[str]) -> dict[str, Any] | None:
        current = set(host_inv.get("users_with_sudo", []))
        new_admins = current - last_sudo_users
        if not last_sudo_users:
            return None
        if new_admins:
            return {
                "event_id": f"new-admin-{hash(frozenset(new_admins)) % 2**32}",
                "source": "detector.users",
                "event_type": "new_admin_user",
                "severity": "P2",
                "summary": f"New admin (sudo) user(s) detected: {', '.join(sorted(new_admins))}",
                "raw": {"new_users": list(new_admins), "current_sudo": list(current)},
                "asset_ids": ["host"],
                "confidence": 1.0,
            }
        return None
