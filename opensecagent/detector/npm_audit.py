# OpenSecAgent - npm audit detector: find package.json dirs and run npm audit
from __future__ import annotations

import asyncio
import json
import subprocess
from pathlib import Path
from typing import Any

logger = __import__("logging").getLogger("opensecagent.detector.npm_audit")


def _find_package_json_dirs(search_paths: list[str], max_depth: int) -> list[Path]:
    out: list[Path] = []
    for sp in search_paths:
        p = Path(sp)
        if not p.exists() or not p.is_dir():
            continue
        try:
            for d in p.rglob("package.json"):
                if len(d.relative_to(p).parts) <= max_depth:
                    out.append(d.parent)
        except (PermissionError, OSError):
            continue
    return list(dict.fromkeys(out))[:50]


def _run_npm_audit_in_dir(project_dir: Path) -> dict[str, Any] | None:
    """Run npm audit --json in project_dir. Return parsed vuln summary or None."""
    try:
        r = subprocess.run(
            ["npm", "audit", "--json"],
            cwd=str(project_dir),
            capture_output=True,
            text=True,
            timeout=60,
        )
        if r.returncode not in (0, 1):
            return None
        data = json.loads(r.stdout or "{}")
        critical, high = 0, 0
        # npm 7+: top-level vulnerabilities dict, each value has severity
        vulns = data.get("vulnerabilities") or {}
        if isinstance(vulns, dict):
            for v in vulns.values():
                if isinstance(v, dict):
                    sev = (v.get("severity") or "").lower()
                    if sev == "critical":
                        critical += 1
                    elif sev == "high":
                        high += 1
        # npm 6: metadata.vulnerabilities with critical/high counts
        if critical == 0 and high == 0:
            meta = data.get("metadata", {}) or {}
            counts = meta.get("vulnerabilities", {}) if isinstance(meta.get("vulnerabilities"), dict) else {}
            critical = int(counts.get("critical", 0))
            high = int(counts.get("high", 0))
        total = critical + high
        if total > 0:
            return {"project_dir": str(project_dir), "critical": critical, "high": high, "total": total}
    except (json.JSONDecodeError, subprocess.TimeoutExpired, FileNotFoundError, PermissionError) as e:
        logger.debug("npm audit in %s failed: %s", project_dir, e)
    return None


def _run_npm_audit(search_paths: list[str], max_depth: int) -> list[dict[str, Any]]:
    """Find package.json dirs, run npm audit in each, emit events. Run in executor."""
    events: list[dict[str, Any]] = []
    dirs = _find_package_json_dirs(search_paths, max_depth)
    for d in dirs:
        result = _run_npm_audit_in_dir(d)
        if not result:
            continue
        critical = result.get("critical", 0)
        high = result.get("high", 0)
        total = result.get("total", 0)
        severity = "P1" if critical else "P2"
        summary = f"npm audit: {result['project_dir']} — {total} vuln(s) ({critical} critical, {high} high). Run 'npm audit fix' or 'npm audit fix --force'."
        events.append({
            "event_id": f"npm-audit-{hash(result['project_dir']) % 2**32}",
            "source": "detector.npm_audit",
            "event_type": "npm_audit_vulnerabilities",
            "severity": severity,
            "summary": summary[:300],
            "raw": result,
            "asset_ids": ["host"],
            "confidence": 1.0,
        })
    return events


class NpmAuditDetector:
    """Run npm audit in directories containing package.json; report critical/high vulnerabilities."""

    def __init__(self, config: dict[str, Any]) -> None:
        self.config = config
        det = config.get("detector", {})
        self._enabled = det.get("npm_audit_enabled", True)
        self._search_paths = det.get("npm_audit_paths", ["/var/www", "/opt", "/home"])
        if isinstance(self._search_paths, str):
            self._search_paths = [self._search_paths]
        self._max_depth = int(det.get("npm_audit_max_depth", 4))

    async def check(self) -> list[dict[str, Any]]:
        if not self._enabled:
            return []
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(
            None,
            _run_npm_audit,
            self._search_paths,
            self._max_depth,
        )
