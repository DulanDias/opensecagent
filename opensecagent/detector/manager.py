# OpenSecAgent - Detector manager: run detectors, correlate events into incidents
from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from opensecagent.models import Event, Incident, Severity

from opensecagent.detector.auth import AuthFailureDetector
from opensecagent.detector.ports import NewPortDetector
from opensecagent.detector.containers import NewContainerDetector
from opensecagent.detector.users import NewAdminUserDetector
from opensecagent.detector.resources import ResourceDetector


class DetectorManager:
    def __init__(self, config: dict[str, Any], audit: Any) -> None:
        self.config = config
        self._audit = audit
        self._auth = AuthFailureDetector(config)
        self._ports = NewPortDetector(config)
        self._containers = NewContainerDetector(config)
        self._users = NewAdminUserDetector(config)
        self._resources = ResourceDetector(config)
        self._last_host_inv: dict[str, Any] = {}
        self._last_docker_inv: dict[str, Any] = {}
        self._last_ports: set[str] = set()
        self._last_containers: set[str] = set()
        self._last_sudo_users: set[str] = set()

    def ingest_inventory(self, event: dict[str, Any]) -> None:
        src = event.get("source")
        raw = event.get("raw", {})
        if src == "host_collector":
            self._last_host_inv = raw
            self._last_ports = {str(p.get("port", p.get("address", ""))) for p in raw.get("listening_ports", [])}
            self._last_sudo_users = set(raw.get("users_with_sudo", []))
        elif src == "docker_collector":
            self._last_docker_inv = raw
            self._last_containers = {c.get("id", "") for c in raw.get("containers", [])}

    def correlate_and_classify(self, event: dict[str, Any]) -> Incident | None:
        event_type = event.get("event_type")
        source = event.get("source")
        if source in ("host_collector", "docker_collector") and event_type in ("host_inventory", "docker_inventory"):
            self.ingest_inventory(event)
            return None
        ev = self._dict_to_event(event)
        severity = Severity(event.get("severity", "P4"))
        narrative = event.get("summary", "")
        recommended = self._recommended_actions(event_type, event)
        incident = Incident(
            incident_id=f"inc-{uuid.uuid4().hex[:12]}",
            severity=severity,
            title=event.get("summary", "Security event")[:200],
            narrative=narrative,
            events=[ev],
            evidence_summary={"event_type": event_type, "source": source, "raw_keys": list(event.get("raw", {}).keys())},
            recommended_actions=recommended,
        )
        return incident

    def _dict_to_event(self, d: dict[str, Any]) -> Event:
        return Event(
            event_id=d.get("event_id", ""),
            source=d.get("source", ""),
            event_type=d.get("event_type", ""),
            severity=Severity(d.get("severity", "P4")),
            summary=d.get("summary", ""),
            raw=d.get("raw", {}),
            ts=datetime.utcnow(),
            asset_ids=d.get("asset_ids", []),
            confidence=float(d.get("confidence", 1.0)),
        )

    def _recommended_actions(self, event_type: str, event: dict[str, Any]) -> list[str]:
        rec: list[str] = []
        if event_type == "config_drift":
            rec.append("Review changed file and confirm change is authorized.")
        elif event_type == "auth_failures":
            rec.append("Consider blocking source IP or locking account after review.")
        elif event_type == "new_admin_user":
            rec.append("Verify new admin is authorized; remove if not.")
        elif event_type == "new_listening_port":
            rec.append("Confirm new service is expected; stop or firewall if not.")
        elif event_type == "new_container":
            rec.append("Confirm new container is expected; stop if not.")
        elif event_type == "high_cpu":
            rec.append("Identify top processes (e.g. top/htop); consider scaling or limiting load.")
        elif event_type == "high_memory":
            rec.append("Check memory usage per process; consider freeing cache or adding capacity.")
        else:
            rec.append("Review evidence and take action as per runbook.")
        return rec

    async def run_detectors(self) -> list[dict[str, Any]]:
        events: list[dict[str, Any]] = []
        # Auth failures (from log / last auth state)
        auth_ev = await self._auth.check()
        if auth_ev:
            events.append(auth_ev)
        # New listening port
        if self._last_host_inv:
            port_ev = self._ports.check(self._last_host_inv, self._last_ports)
            if port_ev:
                events.append(port_ev)
            self._last_ports = {str(p.get("port", p.get("address", ""))) for p in self._last_host_inv.get("listening_ports", [])}
        # New container
        if self._last_docker_inv.get("available"):
            cont_ev = self._containers.check(self._last_docker_inv, self._last_containers)
            if cont_ev:
                events.append(cont_ev)
            self._last_containers = {c.get("id", "") for c in self._last_docker_inv.get("containers", [])}
        # New admin user
        if self._last_host_inv:
            user_ev = self._users.check(self._last_host_inv, self._last_sudo_users)
            if user_ev:
                events.append(user_ev)
            self._last_sudo_users = set(self._last_host_inv.get("users_with_sudo", []))
        # Resource usage (CPU, memory)
        resource_evs = await self._resources.check()
        events.extend(resource_evs)
        return events
