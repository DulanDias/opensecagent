# OpenSecAgent - Reporter manager: email immediate + daily digest
from __future__ import annotations

import asyncio
import logging
from typing import Any

from opensecagent.models import Incident

logger = logging.getLogger("opensecagent.reporter")


def _incident_to_dict(incident: Incident) -> dict[str, Any]:
    return {
        "incident_id": incident.incident_id,
        "severity": incident.severity.value,
        "title": incident.title,
        "narrative": incident.narrative,
        "created_at": incident.created_at.isoformat() + "Z",
        "events": [{"event_type": e.event_type, "summary": e.summary} for e in incident.events],
        "recommended_actions": incident.recommended_actions,
        "actions_taken": incident.actions_taken,
        "llm_summary": incident.llm_summary,
    }


class ReporterManager:
    def __init__(self, config: dict[str, Any], audit: Any) -> None:
        self.config = config
        self._audit = audit
        self._email_reporter: Any = None
        self._digest_task: asyncio.Task[Any] | None = None
        self._pending_digest: list[dict[str, Any]] = []

    async def start(self) -> None:
        from opensecagent.reporter.email_reporter import EmailReporter
        self._email_reporter = EmailReporter(self.config.get("notifications", {}))
        if self.config.get("notifications", {}).get("digest", {}).get("enabled"):
            self._digest_task = asyncio.create_task(self._run_digest_loop())

    async def cleanup(self) -> None:
        if self._digest_task:
            self._digest_task.cancel()
            try:
                await self._digest_task
            except asyncio.CancelledError:
                pass

    async def report_incident(self, incident: Incident, actions_taken: list[dict[str, Any]]) -> None:
        self._pending_digest.append(_incident_to_dict(incident))
        immediate = incident.severity.value in self.config.get("notifications", {}).get("immediate_severities", ["P1", "P2"])
        if immediate and self._email_reporter:
            await self._email_reporter.send_incident_alert(incident, actions_taken)

    async def send_vulnerability_alert(
        self,
        finding: dict[str, Any],
        threat_id: str,
        pdf_path: str | None = None,
    ) -> None:
        """Notify admins of a scan finding; attach PDF report if provided."""
        if self._email_reporter:
            await self._email_reporter.send_vulnerability_alert(finding, threat_id, pdf_path)

    async def send_resolution_notification(
        self,
        threat_id: str,
        title: str,
        description: str,
        actions_taken: list[str],
    ) -> None:
        """Notify admins that a vulnerability was resolved and what actions were taken."""
        if self._email_reporter:
            await self._email_reporter.send_resolution_notification(
                threat_id, title, description, actions_taken
            )

    async def _run_digest_loop(self) -> None:
        from datetime import datetime, time as dtime
        cfg = self.config.get("notifications", {}).get("digest", {})
        hour = cfg.get("hour_utc", 8)
        minute = cfg.get("minute", 0)
        while True:
            await asyncio.sleep(60)
            now = datetime.utcnow()
            if now.hour == hour and now.minute >= minute:
                if self._pending_digest:
                    copy = self._pending_digest[:]
                    self._pending_digest.clear()
                    if self._email_reporter:
                        await self._email_reporter.send_daily_digest(copy)
                await asyncio.sleep(3600)
