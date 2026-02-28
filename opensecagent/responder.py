# OpenSecAgent - Responder: execute approved containment actions (Tier 0/1)
from __future__ import annotations

import asyncio
import logging
import time
from typing import Any

from opensecagent.models import Incident

logger = logging.getLogger("opensecagent.responder")


class Responder:
    def __init__(self, config: dict[str, Any], audit: Any, activity: Any = None) -> None:
        self.config = config
        self._audit = audit
        self._activity = activity

    async def execute(self, action_spec: dict[str, Any], incident: Incident) -> None:
        action = action_spec.get("action")
        if action == "alert_only":
            return
        if action == "stop_container" and incident.event_type_matches("new_container"):
            await self._stop_containers(incident, action_spec)
        elif action == "block_ip_temporary" and incident.event_type_matches("auth_failures"):
            await self._block_ip_temporary(incident, action_spec)
        else:
            logger.info("No executor for action %s", action)

    async def _stop_containers(self, incident: Incident, spec: dict[str, Any]) -> None:
        raw = incident.events[0].raw if incident.events else {}
        new_ids = raw.get("new_ids", raw.get("names", []))
        if not new_ids:
            return
        try:
            import docker
            client = docker.from_env()
            for cid in new_ids[:5]:
                try:
                    t0 = time.perf_counter()
                    cont = client.containers.get(cid)
                    cont.stop(timeout=10)
                    duration = time.perf_counter() - t0
                    cmd = f"docker stop {cid}"
                    if self._activity:
                        await self._activity.log_command_execution(
                            cmd, 0, "stopped", "", duration, source="responder"
                        )
                    await self._audit.log_action("stop_container", {"container_id": cid}, incident.incident_id)
                    incident.actions_taken.append(f"Stopped container {cid}")
                except Exception as e:
                    logger.warning("Could not stop container %s: %s", cid, e)
                    if self._activity:
                        await self._activity.log_command_execution(
                            f"docker stop {cid}", -1, "", str(e), 0, source="responder"
                        )
        except Exception as e:
            logger.warning("Docker stop failed: %s", e)

    async def _block_ip_temporary(self, incident: Incident, spec: dict[str, Any]) -> None:
        timeout_min = spec.get("timeout_minutes", 30)
        logger.info("block_ip_temporary would block IP (Tier 1); timeout=%s min. Not implemented in MVP.", timeout_min)
        await self._audit.log_action("block_ip_temporary_skipped", {"timeout_minutes": timeout_min}, incident.incident_id)
