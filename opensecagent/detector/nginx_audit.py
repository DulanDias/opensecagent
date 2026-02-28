# OpenSecAgent - Nginx audit detector: config validity and basic security checks
from __future__ import annotations

import asyncio
import re
import subprocess
from pathlib import Path
from typing import Any

logger = __import__("logging").getLogger("opensecagent.detector.nginx_audit")


def _run_nginx_audit(config_paths: list[str], check_security: bool) -> list[dict[str, Any]]:
    """Run nginx -t and optional security checks. Run in executor."""
    events: list[dict[str, Any]] = []
    # nginx -t (default config or first path)
    cmd = ["nginx", "-t"]
    if config_paths:
        for cpath in config_paths[:3]:
            p = Path(cpath)
            if p.exists():
                cmd = ["nginx", "-t", "-c", str(p.resolve())]
                break
    try:
        r = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=10,
        )
        if r.returncode != 0:
            events.append({
                "event_id": f"nginx-config-invalid-{id(cmd) % 2**32}",
                "source": "detector.nginx_audit",
                "event_type": "nginx_config_invalid",
                "severity": "P2",
                "summary": f"Nginx config test failed: {r.stderr[:200] if r.stderr else r.stdout[:200]}",
                "raw": {"command": " ".join(cmd), "stderr": (r.stderr or "")[:500], "returncode": r.returncode},
                "asset_ids": ["host"],
                "confidence": 1.0,
            })
    except FileNotFoundError:
        pass  # nginx not installed
    except subprocess.TimeoutExpired:
        events.append({
            "event_id": f"nginx-timeout-{id(cmd) % 2**32}",
            "source": "detector.nginx_audit",
            "event_type": "nginx_audit_error",
            "severity": "P3",
            "summary": "Nginx config test timed out",
            "raw": {},
            "asset_ids": ["host"],
            "confidence": 0.8,
        })
    except Exception as e:
        logger.debug("Nginx audit failed: %s", e)

    if check_security and not events:
        for cpath in config_paths or ["/etc/nginx/nginx.conf"]:
            p = Path(cpath)
            if not p.exists():
                continue
            try:
                content = p.read_text()
                if "server_tokens" in content and re.search(r"server_tokens\s+on", content, re.I):
                    events.append({
                        "event_id": f"nginx-server-tokens-{id(cpath) % 2**32}",
                        "source": "detector.nginx_audit",
                        "event_type": "nginx_security",
                        "severity": "P4",
                        "summary": f"Nginx server_tokens on in {cpath}; consider 'server_tokens off'",
                        "raw": {"config_path": str(p)},
                        "asset_ids": ["host"],
                        "confidence": 1.0,
                    })
                break
            except (OSError, PermissionError):
                continue
    return events


class NginxAuditDetector:
    """Check nginx config validity (nginx -t) and optional security directives."""

    def __init__(self, config: dict[str, Any]) -> None:
        self.config = config
        det = config.get("detector", {})
        self._enabled = det.get("nginx_audit_enabled", True)
        self._config_paths = det.get("nginx_config_paths", ["/etc/nginx/nginx.conf"])
        if isinstance(self._config_paths, str):
            self._config_paths = [self._config_paths]
        self._check_security = det.get("nginx_check_security", True)

    async def check(self) -> list[dict[str, Any]]:
        if not self._enabled:
            return []
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(
            None,
            _run_nginx_audit,
            self._config_paths,
            self._check_security,
        )
