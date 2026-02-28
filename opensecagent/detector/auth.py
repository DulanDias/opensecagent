# OpenSecAgent - Auth failure detector
from __future__ import annotations

import asyncio
import re
from pathlib import Path
from typing import Any

logger = __import__("logging").getLogger("opensecagent.detector.auth")


class AuthFailureDetector:
    def __init__(self, config: dict[str, Any]) -> None:
        self.config = config
        det = config.get("detector", {})
        self._threshold = det.get("auth_failure_threshold", 5)
        self._window_sec = det.get("auth_failure_window_sec", 300)
        self._log_paths = ["/var/log/auth.log", "/var/log/secure"]
        self._pattern = re.compile(r"Failed password|Invalid user|authentication failure", re.I)

    async def check(self) -> dict[str, Any] | None:
        loop = asyncio.get_event_loop()
        count = await loop.run_in_executor(None, self._count_recent_failures)
        if count >= self._threshold:
            return {
                "event_id": f"auth-fail-{id(self) % 2**32}",
                "source": "detector.auth",
                "event_type": "auth_failures",
                "severity": "P2",
                "summary": f"Repeated auth failures detected: {count} in last {self._window_sec}s",
                "raw": {"count": count, "threshold": self._threshold, "window_sec": self._window_sec},
                "asset_ids": ["host"],
                "confidence": min(1.0, count / max(self._threshold * 2, 1)),
            }
        return None

    def _count_recent_failures(self) -> int:
        total = 0
        for path_str in self._log_paths:
            p = Path(path_str)
            if not p.exists():
                continue
            try:
                with open(p) as f:
                    lines = [line for line in f if self._pattern.search(line)]
                total = len(lines[-500:])
                break
            except (OSError, PermissionError) as e:
                logger.debug("Cannot read %s: %s", path_str, e)
        return total
