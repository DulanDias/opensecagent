# OpenSecAgent - Resource detector: CPU and memory usage thresholds
from __future__ import annotations

import asyncio
from typing import Any

logger = __import__("logging").getLogger("opensecagent.detector.resources")


def _sample_resources(cpu_threshold: float, mem_threshold: float) -> list[dict[str, Any]]:
    """Sync helper to sample CPU/memory (run in executor)."""
    try:
        import psutil
    except ImportError:
        return []
    events: list[dict[str, Any]] = []
    try:
        cpu = psutil.cpu_percent(interval=1)
        if cpu >= cpu_threshold:
            events.append({
                "event_id": f"resource-cpu-{id(cpu_threshold) % 2**32}",
                "source": "detector.resources",
                "event_type": "high_cpu",
                "severity": "P2",
                "summary": f"High CPU usage: {cpu:.1f}% (threshold {cpu_threshold}%)",
                "raw": {"cpu_percent": cpu, "threshold": cpu_threshold},
                "asset_ids": ["host"],
                "confidence": min(1.0, cpu / 100),
            })
    except Exception as e:
        logger.debug("CPU check failed: %s", e)
    try:
        mem = psutil.virtual_memory()
        if mem.percent >= mem_threshold:
            events.append({
                "event_id": f"resource-mem-{id(mem_threshold) % 2**32}",
                "source": "detector.resources",
                "event_type": "high_memory",
                "severity": "P2",
                "summary": f"High memory usage: {mem.percent:.1f}% (threshold {mem_threshold}%)",
                "raw": {
                    "memory_percent": mem.percent,
                    "threshold": mem_threshold,
                    "available_mb": mem.available // (1024 * 1024),
                },
                "asset_ids": ["host"],
                "confidence": min(1.0, mem.percent / 100),
            })
    except Exception as e:
        logger.debug("Memory check failed: %s", e)
    return events


class ResourceDetector:
    """Emit events when CPU or memory usage exceeds configured thresholds."""

    def __init__(self, config: dict[str, Any]) -> None:
        self.config = config
        det = config.get("detector", {})
        self._cpu_percent = det.get("resource_cpu_percent", 90)
        self._memory_percent = det.get("resource_memory_percent", 90)
        self._enabled = det.get("resource_detector_enabled", True)

    async def check(self) -> list[dict[str, Any]]:
        if not self._enabled:
            return []
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(
            None,
            _sample_resources,
            self._cpu_percent,
            self._memory_percent,
        )
