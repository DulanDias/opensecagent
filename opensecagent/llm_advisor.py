# OpenSecAgent - LLM Advisor: human-readable summaries (defensive only, sanitized)
from __future__ import annotations

import re
import logging
from typing import Any

from opensecagent.models import Incident

logger = logging.getLogger("opensecagent.llm")


def redact(text: str, patterns: list[str]) -> str:
    out = text
    for pat in patterns:
        out = re.sub(re.escape(pat), "[REDACTED]", out, flags=re.I)
    out = re.sub(r"(?i)(password|secret|token|api[_-]?key|credential)\s*[:=]\s*\S+", r"\1=[REDACTED]", out)
    return out


class LLMAdvisor:
    def __init__(self, config: dict[str, Any]) -> None:
        self.config = config.get("llm", {})
        self._enabled = self.config.get("enabled", False)
        self._api_key = self.config.get("api_key", "")
        self._provider = (self.config.get("provider") or "openai").strip().lower()
        if self._provider not in ("openai", "anthropic"):
            self._provider = "openai"
        self._model = self.config.get("model", "gpt-4o-mini")
        self._base_url = self.config.get("base_url", "")
        self._redact_patterns = self.config.get("redact_patterns", ["password", "secret", "token", "key"])

    async def summarize_incident(self, incident: Incident) -> str:
        if not self._enabled or not self._api_key:
            return ""
        safe_narrative = redact(incident.narrative, self._redact_patterns)
        safe_evidence = {k: redact(str(v), self._redact_patterns) for k, v in (incident.evidence_summary or {}).items()}
        prompt = (
            "You are a defensive security assistant. Summarize this security incident in 2-3 clear sentences "
            "for a system administrator. Do NOT suggest exploits or offensive actions. Only defensive remediation.\n\n"
            f"Title: {incident.title}\nNarrative: {safe_narrative}\nEvidence (sanitized): {safe_evidence}"
        )
        try:
            return await self._call_llm(prompt)
        except Exception as e:
            logger.warning("LLM summarize failed: %s", e)
            return ""

    async def _call_llm(self, prompt: str) -> str:
        from opensecagent.llm_client import chat
        return await chat(
            provider=self._provider,
            model=self._model,
            messages=[{"role": "user", "content": prompt}],
            max_tokens=self.config.get("max_tokens", 1024),
            api_key=self._api_key,
            base_url=self._base_url or None,
        )
