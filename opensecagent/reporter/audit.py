# OpenSecAgent - Audit logger (append-only JSONL)
from __future__ import annotations

import asyncio
import json
from datetime import datetime
from pathlib import Path
from typing import Any

from opensecagent.models import Incident

logger = __import__("logging").getLogger("opensecagent.audit")


def _incident_to_dict(incident: Incident) -> dict[str, Any]:
    return {
        "incident_id": incident.incident_id,
        "severity": incident.severity.value,
        "title": incident.title,
        "narrative": incident.narrative,
        "created_at": incident.created_at.isoformat() + "Z",
        "events": [
            {
                "event_id": e.event_id,
                "source": e.source,
                "event_type": e.event_type,
                "summary": e.summary,
            }
            for e in incident.events
        ],
        "evidence_summary": incident.evidence_summary,
        "recommended_actions": incident.recommended_actions,
        "actions_taken": incident.actions_taken,
        "llm_summary": incident.llm_summary,
    }


class AuditLogger:
    def __init__(self, config: dict[str, Any]) -> None:
        self.config = config
        self._path = Path(config.get("file", "/var/log/opensecagent/audit.jsonl"))
        self._file: Any = None
        self._lock: asyncio.Lock | None = None

    async def start(self) -> None:
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._file = open(self._path, "a")

    async def stop(self) -> None:
        if self._file:
            self._file.close()
            self._file = None

    async def log_incident(self, incident: Incident) -> None:
        if self._lock is None:
            self._lock = asyncio.Lock()
        async with self._lock:
            line = json.dumps({"type": "incident", "ts": datetime.utcnow().isoformat() + "Z", "payload": _incident_to_dict(incident)}) + "\n"
            self._file.write(line)
            self._file.flush()

    async def log_action(self, action: str, details: dict[str, Any], incident_id: str) -> None:
        if self._lock is None:
            self._lock = asyncio.Lock()
        async with self._lock:
            line = json.dumps({
                "type": "action",
                "ts": datetime.utcnow().isoformat() + "Z",
                "action": action,
                "incident_id": incident_id,
                "details": details,
            }) + "\n"
            self._file.write(line)
            self._file.flush()
