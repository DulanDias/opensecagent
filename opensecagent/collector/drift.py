# OpenSecAgent - Drift monitoring (critical files baseline + diff)
from __future__ import annotations

import asyncio
import hashlib
import json
from pathlib import Path
from typing import Any

logger = __import__("logging").getLogger("opensecagent.collector.drift")


class DriftMonitor:
    def __init__(self, config: dict[str, Any], audit: Any) -> None:
        self.config = config
        self._audit = audit
        self._baseline_path = Path(config["agent"]["data_dir"]) / "drift_baseline.json"
        self._baseline: dict[str, str] = {}
        self._critical = config.get("collector", {}).get("critical_files", [])

    async def ensure_baseline(self) -> None:
        if self._baseline_path.exists():
            loop = asyncio.get_event_loop()
            self._baseline = await loop.run_in_executor(None, self._load_baseline)
        else:
            await self._build_baseline()

    def _load_baseline(self) -> dict[str, str]:
        with open(self._baseline_path) as f:
            return json.load(f)

    async def _build_baseline(self) -> None:
        loop = asyncio.get_event_loop()
        self._baseline = await loop.run_in_executor(None, self._compute_hashes)
        self._baseline_path.parent.mkdir(parents=True, exist_ok=True)
        with open(self._baseline_path, "w") as f:
            json.dump(self._baseline, f, indent=0)
        logger.info("Drift baseline created for %d paths", len(self._baseline))

    def _compute_hashes(self) -> dict[str, str]:
        out: dict[str, str] = {}
        for entry in self._critical:
            if "*" in entry:
                base = Path(entry.split("*")[0].rstrip("/"))
                if base.exists():
                    for p in base.glob(entry.split("*")[-1].lstrip("/") or "*"):
                        if p.is_file():
                            try:
                                h = hashlib.sha256(p.read_bytes()).hexdigest()
                                out[str(p)] = h
                            except (OSError, PermissionError):
                                pass
            else:
                p = Path(entry)
                if p.is_file():
                    try:
                        out[entry] = hashlib.sha256(p.read_bytes()).hexdigest()
                    except (OSError, PermissionError):
                        pass
                elif p.is_dir():
                    for child in p.iterdir():
                        if child.is_file():
                            try:
                                out[str(child)] = hashlib.sha256(child.read_bytes()).hexdigest()
                            except (OSError, PermissionError):
                                pass
        return out

    async def check(self) -> list[dict[str, Any]]:
        if not self._baseline and self._baseline_path.exists():
            await self.ensure_baseline()
        if not self._baseline:
            await self._build_baseline()
            return []
        loop = asyncio.get_event_loop()
        current = await loop.run_in_executor(None, self._compute_hashes)
        events: list[dict[str, Any]] = []
        for path, new_hash in current.items():
            old_hash = self._baseline.get(path)
            if old_hash is None:
                events.append(
                    {
                        "event_id": f"drift-new-{hash(path) % 2**32}",
                        "source": "drift",
                        "event_type": "config_new_file",
                        "severity": "P3",
                        "summary": f"New critical file: {path}",
                        "raw": {"path": path, "hash": new_hash},
                        "asset_ids": ["host"],
                        "confidence": 1.0,
                    }
                )
            elif old_hash != new_hash:
                events.append(
                    {
                        "event_id": f"drift-change-{hash(path) % 2**32}",
                        "source": "drift",
                        "event_type": "config_drift",
                        "severity": "P2",
                        "summary": f"Critical file changed: {path}",
                        "raw": {"path": path, "old_hash": old_hash, "new_hash": new_hash},
                        "asset_ids": ["host"],
                        "confidence": 1.0,
                    }
                )
        for path in self._baseline:
            if path not in current:
                events.append(
                    {
                        "event_id": f"drift-deleted-{hash(path) % 2**32}",
                        "source": "drift",
                        "event_type": "config_deleted",
                        "severity": "P2",
                        "summary": f"Critical file removed: {path}",
                        "raw": {"path": path},
                        "asset_ids": ["host"],
                        "confidence": 1.0,
                    }
                )
        return events
