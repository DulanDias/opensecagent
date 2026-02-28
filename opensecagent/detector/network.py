# OpenSecAgent - Network usage detector: high throughput alert
from __future__ import annotations

import asyncio
import time
from typing import Any

logger = __import__("logging").getLogger("opensecagent.detector.network")


def _sample_network_rate_mb_per_sec(threshold_mb: float) -> list[dict[str, Any]]:
    """Sample net I/O over ~2s; emit event if rate exceeds threshold. Run in executor."""
    events: list[dict[str, Any]] = []
    try:
        import psutil
    except ImportError:
        return []
    try:
        c0 = psutil.net_io_counters()
        bytes0 = c0.bytes_sent + c0.bytes_recv
        time.sleep(2)
        c1 = psutil.net_io_counters()
        bytes1 = c1.bytes_sent + c1.bytes_recv
        rate_bps = max(0, (bytes1 - bytes0) / 2.0)
        rate_mb = rate_bps / (1024 * 1024)
        if threshold_mb > 0 and rate_mb >= threshold_mb:
            events.append({
                "event_id": f"network-high-{id(rate_mb) % 2**32}",
                "source": "detector.network",
                "event_type": "high_network_usage",
                "severity": "P3",
                "summary": f"High network throughput: {rate_mb:.1f} MB/s (threshold {threshold_mb} MB/s)",
                "raw": {
                    "rate_mb_per_sec": rate_mb,
                    "threshold_mb_per_sec": threshold_mb,
                    "bytes_sent": getattr(c1, "bytes_sent", 0),
                    "bytes_recv": getattr(c1, "bytes_recv", 0),
                },
                "asset_ids": ["host"],
                "confidence": min(1.0, rate_mb / max(threshold_mb * 1.5, 1)),
            })
    except Exception as e:
        logger.debug("Network check failed: %s", e)
    return events


class NetworkDetector:
    """Emit events when network I/O rate exceeds configured threshold (MB/s)."""

    def __init__(self, config: dict[str, Any]) -> None:
        self.config = config
        det = config.get("detector", {})
        self._enabled = det.get("network_detector_enabled", True)
        self._threshold_mb = float(det.get("network_mb_per_sec_threshold", 100))

    async def check(self) -> list[dict[str, Any]]:
        if not self._enabled:
            return []
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(
            None,
            _sample_network_rate_mb_per_sec,
            self._threshold_mb,
        )
