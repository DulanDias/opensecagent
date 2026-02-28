# OpenSecAgent - Daemon orchestrator
from __future__ import annotations

import asyncio
import logging
import time
from pathlib import Path
from typing import Any

from opensecagent.collector.host import HostCollector
from opensecagent.collector.docker_collector import DockerCollector
from opensecagent.collector.drift import DriftMonitor
from opensecagent.detector.manager import DetectorManager
from opensecagent.normalizer import Normalizer
from opensecagent.policy_engine import PolicyEngine
from opensecagent.responder import Responder
from opensecagent.reporter.audit import AuditLogger
from opensecagent.reporter.activity import ActivityLogger
from opensecagent.reporter.manager import ReporterManager
from opensecagent.llm_advisor import LLMAdvisor
from opensecagent.llm_agent import LLMAgent

logger = logging.getLogger("opensecagent")


def _effective_intervals(config: dict[str, Any]) -> dict[str, int]:
    """Resolve scan intervals from scan_level preset or raw config."""
    level = (config.get("scan_level") or "").strip().lower()
    presets = config.get("scan_frequencies", {})
    if level and level in presets:
        p = presets[level]
        return {
            "host_interval_sec": p.get("host_interval_sec", 300),
            "docker_interval_sec": p.get("docker_interval_sec", 60),
            "drift_interval_sec": p.get("drift_interval_sec", 300),
            "detector_interval_sec": p.get("detector_interval_sec", 60),
            "llm_scan_interval_sec": p.get("llm_scan_interval_sec", 3600),
        }
    coll = config.get("collector", {})
    det = config.get("detector", {})
    llm_agent = config.get("llm_agent", {})
    return {
        "host_interval_sec": coll.get("host_interval_sec", 300),
        "docker_interval_sec": coll.get("docker_interval_sec", 60),
        "drift_interval_sec": coll.get("drift_interval_sec", 300),
        "detector_interval_sec": det.get("detector_interval_sec", 60),
        "llm_scan_interval_sec": llm_agent.get("run_interval_sec", 3600),
    }


class Daemon:
    def __init__(self, config: dict[str, Any]) -> None:
        self.config = config
        self._intervals = _effective_intervals(config)
        self._running = False
        self._tasks: list[asyncio.Task[Any]] = []
        act_config = {**config, "activity": config.get("activity", {}), "agent": config.get("agent", {})}
        self._audit = AuditLogger(config.get("audit", {}))
        self._activity = ActivityLogger(act_config)
        self._normalizer = Normalizer()
        self._policy = PolicyEngine(config)
        self._responder = Responder(config, self._audit, self._activity)
        self._reporter = ReporterManager(config, self._audit)
        self._detector_manager = DetectorManager(config, self._audit)
        self._host_collector = HostCollector(config)
        self._docker_collector = DockerCollector(config)
        self._drift_monitor = DriftMonitor(config, self._audit)
        self._llm = LLMAdvisor(config)
        self._llm_agent = LLMAgent(config, self._activity)
        self._event_queue: asyncio.Queue[dict[str, Any]] | None = None
        self._last_host_inv: dict[str, Any] = {}
        self._last_docker_inv: dict[str, Any] = {}

    def shutdown(self) -> None:
        self._running = False

    async def run(self) -> None:
        self._running = True
        self._event_queue = asyncio.Queue()
        logger.info("OpenSecAgent daemon starting")
        await self._audit.start()
        await self._activity.start()
        await self._reporter.start()

        tasks = [
            asyncio.create_task(self._run_collectors()),
            asyncio.create_task(self._run_drift()),
            asyncio.create_task(self._run_event_processor()),
            asyncio.create_task(self._run_detectors()),
        ]
        if self._intervals.get("llm_scan_interval_sec", 0) > 0:
            tasks.append(asyncio.create_task(self._run_periodic_agent()))
        self._tasks = tasks
        await asyncio.gather(*self._tasks)

    async def cleanup(self) -> None:
        for t in self._tasks:
            t.cancel()
            try:
                await t
            except asyncio.CancelledError:
                pass
        await self._reporter.cleanup()
        await self._activity.stop()
        await self._audit.stop()
        logger.info("OpenSecAgent daemon stopped")

    async def _run_collectors(self) -> None:
        host_ival = self._intervals["host_interval_sec"]
        docker_ival = self._intervals["docker_interval_sec"]
        host_t, docker_t = 0, 0
        while self._running:
            if host_t <= 0:
                host_t = host_ival
                try:
                    t0 = time.perf_counter()
                    started = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
                    inv = await self._host_collector.collect()
                    self._last_host_inv = inv
                    duration = time.perf_counter() - t0
                    summary = f"hostname={inv.get('hostname','')} packages={len(inv.get('packages',[]))} ports={len(inv.get('listening_ports',[]))}"
                    await self._activity.log_collector_run("host", started, duration, summary, None)
                    for e in self._normalizer.host_inventory_to_events(inv):
                        await self._event_queue.put(e)  # type: ignore
                except Exception as e:
                    logger.exception("Host collector error: %s", e)
                    await self._activity.log_collector_run("host", "", 0, "", str(e))
            if docker_t <= 0:
                docker_t = docker_ival
                try:
                    t0 = time.perf_counter()
                    started = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
                    inv = await self._docker_collector.collect()
                    self._last_docker_inv = inv
                    duration = time.perf_counter() - t0
                    summary = f"containers={len(inv.get('containers',[]))} images={len(inv.get('images',[]))}"
                    await self._activity.log_collector_run("docker", started, duration, summary, None)
                    for e in self._normalizer.docker_inventory_to_events(inv):
                        await self._event_queue.put(e)  # type: ignore
                except Exception as e:
                    logger.exception("Docker collector error: %s", e)
                    await self._activity.log_collector_run("docker", "", 0, "", str(e))
            await asyncio.sleep(min(30, host_t, docker_t))
            host_t -= 30
            docker_t -= 30

    async def _run_drift(self) -> None:
        ival = self._intervals["drift_interval_sec"]
        while self._running:
            try:
                t0 = time.perf_counter()
                started = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
                events = await self._drift_monitor.check()
                duration = time.perf_counter() - t0
                summary = f"events={len(events)}"
                await self._activity.log_collector_run("drift", started, duration, summary, None)
                for e in events:
                    await self._event_queue.put(e)  # type: ignore
            except Exception as e:
                logger.exception("Drift monitor error: %s", e)
                await self._activity.log_collector_run("drift", "", 0, "", str(e))
            await asyncio.sleep(ival)

    async def _run_event_processor(self) -> None:
        while self._running:
            try:
                event = await asyncio.wait_for(self._event_queue.get(), timeout=5.0)  # type: ignore
                await self._process_event(event)
            except asyncio.TimeoutError:
                continue
            except Exception as e:
                logger.exception("Event processor error: %s", e)

    async def _process_event(self, event: dict[str, Any]) -> None:
        incident = self._detector_manager.correlate_and_classify(event)
        if not incident:
            return
        if self._llm._enabled:
            incident.llm_summary = await self._llm.summarize_incident(incident)
        await self._audit.log_incident(incident)
        allowed = self._policy.allowed_actions(incident)
        await self._activity.log_policy_decision(
            incident.incident_id,
            incident.severity.value,
            [a.get("action", "") for a in allowed],
            "policy_evaluation",
        )
        for action in allowed:
            await self._responder.execute(action, incident)
        await self._reporter.report_incident(incident, actions_taken=allowed)

        # LLM Agent: run on P1/P2 incident if enabled (resolve mode)
        llm_agent_cfg = self.config.get("llm_agent", {})
        if (
            llm_agent_cfg.get("enabled")
            and llm_agent_cfg.get("run_on_incident")
            and incident.severity.value in ("P1", "P2")
        ):
            from opensecagent.threat_registry import store_threat, mark_resolved

            threat_id = store_threat(
                self.config,
                title=incident.title,
                description=incident.narrative,
                severity=incident.severity.value,
                evidence=dict(incident.evidence_summary or {}),
                resolution_actions=None,
            )
            context = {
                "host": self._last_host_inv,
                "docker": self._last_docker_inv,
                "incident": {
                    "title": incident.title,
                    "narrative": incident.narrative,
                    "severity": incident.severity.value,
                },
            }
            result = await self._llm_agent.run_agent_loop(context, incident, mode="resolve")
            incident.llm_summary = (incident.llm_summary or "") + f"\n[Agent] {result.get('summary', '')}"
            actions_taken = result.get("actions_taken") or []
            if actions_taken:
                mark_resolved(self.config, threat_id, actions_taken)
                await self._reporter.send_resolution_notification(
                    threat_id,
                    incident.title,
                    incident.narrative,
                    actions_taken,
                )

    async def _run_detectors(self) -> None:
        ival = self._intervals["detector_interval_sec"]
        while self._running:
            try:
                t0 = time.perf_counter()
                events = await self._detector_manager.run_detectors()
                duration = time.perf_counter() - t0
                event_types = list({e.get("event_type", "") for e in events})
                await self._activity.log_detector_run("manager", len(events), event_types, duration)
                for e in events:
                    await self._event_queue.put(e)  # type: ignore
            except Exception as e:
                logger.exception("Detector error: %s", e)
            await asyncio.sleep(ival)

    async def _run_periodic_agent(self) -> None:
        ival = self._intervals["llm_scan_interval_sec"]
        while self._running:
            await asyncio.sleep(ival)
            if not self._running:
                break
            llm_cfg = self.config.get("llm_agent", {})
            if not llm_cfg.get("enabled"):
                continue
            try:
                context = {"host": self._last_host_inv, "docker": self._last_docker_inv}
                result = await self._llm_agent.run_agent_loop(context, None, mode="scan")
                finding = result.get("finding")
                if finding:
                    from opensecagent.threat_registry import store_threat
                    from opensecagent.reporter.pdf_report import generate_vulnerability_pdf

                    threat_id = store_threat(
                        self.config,
                        title=finding.get("title", "Vulnerability"),
                        description=finding.get("description", ""),
                        severity=finding.get("severity", "P2"),
                        evidence=finding.get("evidence") or {},
                        resolution_actions=None,
                    )
                    data_dir = Path(self.config.get("agent", {}).get("data_dir", "/var/lib/opensecagent"))
                    reports_dir = self.config.get("reports", {}).get("dir") or str(data_dir / "reports")
                    pdf_path = Path(reports_dir) / f"vuln-{threat_id}.pdf"
                    generate_vulnerability_pdf(
                        finding,
                        threat_id,
                        str(pdf_path),
                        host_context={"hostname": self._last_host_inv.get("hostname"), "os": "", "os_release": ""},
                    )
                    await self._reporter.send_vulnerability_alert(finding, threat_id, str(pdf_path))
            except Exception as e:
                logger.exception("Periodic agent error: %s", e)
