# OpenSecAgent - Email reporter: SMTP or Resend.com
from __future__ import annotations

import base64
import logging
from pathlib import Path
from typing import Any

from opensecagent.models import Incident

logger = logging.getLogger("opensecagent.email_reporter")


class EmailReporter:
    """Send notifications via SMTP or Resend.com (provider chosen in config)."""

    def __init__(self, config: dict[str, Any]) -> None:
        self.config = config
        self._admin_emails = config.get("admin_emails", []) or []
        self._provider = (config.get("provider") or "smtp").strip().lower()
        if self._provider not in ("smtp", "resend"):
            self._provider = "smtp"
        self._smtp = config.get("smtp", {})
        self._resend = config.get("resend", {})
        self._from = self._smtp.get("from", "OpenSecAgent <noreply@localhost>")
        if self._provider == "resend":
            self._from = self._resend.get("from", self._from)

    def _can_send(self) -> bool:
        if not self._admin_emails:
            return False
        if self._provider == "resend":
            return bool(self._resend.get("api_key")) and bool(self._resend.get("from"))
        return bool(self._smtp.get("host"))

    async def send_incident_alert(self, incident: Incident, actions_taken: list[dict[str, Any]]) -> None:
        if not self._can_send():
            return
        subject = f"[OpenSecAgent] {incident.severity.value}: {incident.title[:60]}"
        body = self._format_incident_body(incident, actions_taken)
        await self._send_mail(subject, body)

    async def send_vulnerability_alert(
        self,
        finding: dict[str, Any],
        threat_id: str,
        pdf_path: str | Path | None = None,
    ) -> None:
        if not self._can_send():
            return
        title = finding.get("title", "Vulnerability detected")
        severity = finding.get("severity", "P2")
        subject = f"[OpenSecAgent] Vulnerability: {title[:50]}"
        body = (
            f"OpenSecAgent has identified a potential vulnerability during scan.\n\n"
            f"Threat ID: {threat_id}\n"
            f"Severity: {severity}\n"
            f"Title: {title}\n\n"
            f"Description:\n{finding.get('description', 'N/A')}\n\n"
            "A detailed report is attached (PDF). Please review and take action.\n"
        )
        await self._send_mail(subject, body, attachment_path=pdf_path, attachment_name="vulnerability_report.pdf")

    async def send_resolution_notification(
        self,
        threat_id: str,
        title: str,
        description: str,
        actions_taken: list[str],
    ) -> None:
        if not self._can_send():
            return
        subject = f"[OpenSecAgent] Resolved: {title[:50]}"
        body = (
            f"OpenSecAgent has resolved the following vulnerability.\n\n"
            f"Threat ID: {threat_id}\n"
            f"Title: {title}\n\n"
            f"Description: {description[:500]}\n\n"
            "Actions taken to resolve:\n"
        )
        for a in actions_taken:
            body += f"  - {a}\n"
        body += "\nPlease verify the system state if needed.\n"
        await self._send_mail(subject, body)

    async def send_daily_digest(self, incidents: list[dict[str, Any]]) -> None:
        if not self._can_send():
            return
        subject = "[OpenSecAgent] Daily security digest"
        body = "OpenSecAgent Daily Digest\n\n"
        body += f"Incidents in last 24h: {len(incidents)}\n\n"
        for inc in incidents[:20]:
            body += f"- [{inc.get('severity', '')}] {inc.get('title', '')}\n"
        await self._send_mail(subject, body)

    async def send_run_report(self, subject: str, body: str) -> None:
        """Send a generic run report (e.g. after manual collect/drift/detect/agent)."""
        if not self._can_send():
            return
        await self._send_mail(subject, body)

    async def send_error_report(self, error: BaseException, context: str = "OpenSecAgent") -> None:
        """Send an error notification to admin emails (e.g. unhandled exception in daemon or CLI)."""
        if not self._can_send():
            return
        import traceback
        subject = f"[OpenSecAgent] Error: {str(error)[:80]}"
        body = f"{context} encountered an error.\n\n"
        body += f"Exception: {type(error).__name__}: {error}\n\n"
        body += "Traceback:\n"
        body += traceback.format_exc()
        await self._send_mail(subject, body)

    def _format_incident_body(self, incident: Incident, actions_taken: list[dict[str, Any]]) -> str:
        lines = [
            f"Incident: {incident.incident_id}",
            f"Severity: {incident.severity.value}",
            f"Title: {incident.title}",
            f"Time: {incident.created_at.isoformat()}Z",
            "",
            "Narrative:",
            incident.narrative,
            "",
            "Recommended actions:",
        ]
        for a in incident.recommended_actions:
            lines.append(f"  - {a}")
        lines.append("")
        lines.append("Actions taken (policy):")
        for s in actions_taken:
            lines.append(f"  - {s.get('action', s)}")
        if incident.actions_taken:
            lines.append("Executed:")
            for a in incident.actions_taken:
                lines.append(f"  - {a}")
        if incident.llm_summary:
            lines.append("")
            lines.append("Summary (LLM):")
            lines.append(incident.llm_summary)
        return "\n".join(lines)

    async def _send_mail(
        self,
        subject: str,
        body: str,
        attachment_path: str | Path | None = None,
        attachment_name: str = "attachment.pdf",
    ) -> None:
        if self._provider == "resend":
            await self._send_resend(subject, body, attachment_path, attachment_name)
        else:
            await self._send_smtp(subject, body, attachment_path, attachment_name)

    async def _send_smtp(
        self,
        subject: str,
        body: str,
        attachment_path: str | Path | None,
        attachment_name: str,
    ) -> None:
        try:
            from email.message import EmailMessage
            import aiosmtplib
            msg = EmailMessage()
            msg["From"] = self._from
            msg["To"] = ", ".join(self._admin_emails)
            msg["Subject"] = subject
            msg.set_content(body)
            if attachment_path and Path(attachment_path).exists():
                path = Path(attachment_path)
                msg.add_attachment(
                    path.read_bytes(),
                    maintype="application",
                    subtype="pdf",
                    filename=attachment_name,
                )
            await aiosmtplib.send(
                msg,
                hostname=self._smtp.get("host", ""),
                port=self._smtp.get("port", 587),
                use_tls=self._smtp.get("use_tls", True),
                username=self._smtp.get("user") or None,
                password=self._smtp.get("password") or None,
            )
        except Exception as e:
            logger.warning("Failed to send email (SMTP): %s", e)

    async def _send_resend(
        self,
        subject: str,
        body: str,
        attachment_path: str | Path | None,
        attachment_name: str,
    ) -> None:
        try:
            import httpx
            api_key = self._resend.get("api_key", "")
            payload: dict[str, Any] = {
                "from": self._from,
                "to": list(self._admin_emails),
                "subject": subject,
                "text": body,
            }
            if attachment_path and Path(attachment_path).exists():
                raw = Path(attachment_path).read_bytes()
                payload["attachments"] = [
                    {"content": base64.b64encode(raw).decode("ascii"), "filename": attachment_name}
                ]
            async with httpx.AsyncClient(timeout=30.0) as client:
                r = await client.post(
                    "https://api.resend.com/emails",
                    headers={"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"},
                    json=payload,
                )
            if r.status_code >= 400:
                logger.warning("Resend API error %s: %s", r.status_code, r.text[:200])
        except Exception as e:
            logger.warning("Failed to send email (Resend): %s", e)
