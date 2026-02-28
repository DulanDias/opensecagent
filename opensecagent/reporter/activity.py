# OpenSecAgent - Full activity logger (every collector, detector, command, LLM call)
from __future__ import annotations

import asyncio
import json
from datetime import datetime
from pathlib import Path
from typing import Any

logger = __import__("logging").getLogger("opensecagent.activity")


class ActivityLogger:
    """Logs every agent activity: collector runs, detector runs, commands, LLM calls."""

    def __init__(self, config: dict[str, Any]) -> None:
        """config: full app config (uses activity + agent sections)."""
        self.config = config
        act = config.get("activity", {})
        log_dir = Path(config.get("agent", {}).get("log_dir", "/var/log/opensecagent"))
        self._path = Path(act.get("file", str(log_dir / "activity.jsonl")))
        self._file: Any = None
        self._lock: asyncio.Lock | None = None
        self._enabled = act.get("enabled", True)

    async def start(self) -> None:
        if not self._enabled:
            return
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._file = open(self._path, "a")

    async def stop(self) -> None:
        if self._file:
            self._file.close()
            self._file = None

    async def _write(self, record: dict[str, Any]) -> None:
        if not self._enabled or not self._file:
            return
        if self._lock is None:
            self._lock = asyncio.Lock()
        async with self._lock:
            line = json.dumps({"ts": datetime.utcnow().isoformat() + "Z", **record}) + "\n"
            self._file.write(line)
            self._file.flush()

    async def log_collector_run(
        self,
        collector: str,
        started_at: str,
        duration_sec: float,
        summary: str,
        error: str | None = None,
    ) -> None:
        await self._write({
            "type": "collector_run",
            "collector": collector,
            "started_at": started_at,
            "duration_sec": round(duration_sec, 3),
            "summary": summary,
            "error": error,
        })

    async def log_detector_run(
        self,
        detector: str,
        events_found: int,
        event_types: list[str],
        duration_sec: float,
    ) -> None:
        await self._write({
            "type": "detector_run",
            "detector": detector,
            "events_found": events_found,
            "event_types": event_types,
            "duration_sec": round(duration_sec, 3),
        })

    async def log_policy_decision(
        self,
        incident_id: str,
        severity: str,
        allowed_actions: list[str],
        reason: str,
    ) -> None:
        await self._write({
            "type": "policy_decision",
            "incident_id": incident_id,
            "severity": severity,
            "allowed_actions": allowed_actions,
            "reason": reason,
        })

    async def log_command_execution(
        self,
        command: str,
        exit_code: int,
        stdout_preview: str,
        stderr_preview: str,
        duration_sec: float,
        source: str = "responder",
    ) -> None:
        await self._write({
            "type": "command_execution",
            "command": command,
            "exit_code": exit_code,
            "stdout_preview": stdout_preview[:2000] if stdout_preview else "",
            "stderr_preview": stderr_preview[:500] if stderr_preview else "",
            "duration_sec": round(duration_sec, 3),
            "source": source,
        })

    async def log_llm_call(
        self,
        purpose: str,
        prompt_tokens: int | None,
        completion_tokens: int | None,
        duration_sec: float,
        success: bool,
        error: str | None = None,
    ) -> None:
        await self._write({
            "type": "llm_call",
            "purpose": purpose,
            "prompt_tokens": prompt_tokens,
            "completion_tokens": completion_tokens,
            "duration_sec": round(duration_sec, 3),
            "success": success,
            "error": error,
        })

    async def log_agent_iteration(
        self,
        iteration: int,
        commands_suggested: int,
        commands_executed: int,
        done: bool,
        summary: str,
    ) -> None:
        await self._write({
            "type": "agent_iteration",
            "iteration": iteration,
            "commands_suggested": commands_suggested,
            "commands_executed": commands_executed,
            "done": done,
            "summary": summary[:500],
        })
