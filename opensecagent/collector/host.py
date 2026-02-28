# OpenSecAgent - Host inventory collector
from __future__ import annotations

import asyncio
import platform
import subprocess
from typing import Any

logger = __import__("logging").getLogger("opensecagent.collector.host")


class HostCollector:
    def __init__(self, config: dict[str, Any]) -> None:
        self.config = config

    async def collect(self) -> dict[str, Any]:
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(None, self._collect_sync)

    def _collect_sync(self) -> dict[str, Any]:
        out: dict[str, Any] = {
            "os": platform.system(),
            "os_release": platform.release(),
            "hostname": platform.node(),
            "machine": platform.machine(),
            "packages": [],
            "services": [],
            "listening_ports": [],
            "users_with_sudo": [],
        }
        try:
            out["packages"] = self._get_packages()
        except Exception as e:
            logger.warning("Could not get packages: %s", e)
        try:
            out["services"] = self._get_services()
        except Exception as e:
            logger.warning("Could not get services: %s", e)
        try:
            out["listening_ports"] = self._get_listening_ports()
        except Exception as e:
            logger.warning("Could not get listening ports: %s", e)
        try:
            out["users_with_sudo"] = self._get_sudo_users()
        except Exception as e:
            logger.warning("Could not get sudo users: %s", e)
        return out

    def _get_packages(self) -> list[dict[str, str]]:
        packages: list[dict[str, str]] = []
        for cmd, parser in [
            ("dpkg-query -W -f '${Package}\t${Version}\n' 2>/dev/null", self._parse_dpkg),
            ("rpm -qa --queryformat '%{NAME}\t%{VERSION}\n' 2>/dev/null", self._parse_rpm),
        ]:
            try:
                r = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=30)
                if r.returncode == 0 and r.stdout:
                    packages = parser(r.stdout)
                    break
            except Exception:
                continue
        return packages[:5000]

    @staticmethod
    def _parse_dpkg(stdout: str) -> list[dict[str, str]]:
        out = []
        for line in stdout.strip().split("\n")[:5000]:
            parts = line.split("\t", 1)
            if len(parts) == 2:
                out.append({"name": parts[0], "version": parts[1]})
        return out

    @staticmethod
    def _parse_rpm(stdout: str) -> list[dict[str, str]]:
        out = []
        for line in stdout.strip().split("\n")[:5000]:
            parts = line.split("\t", 1)
            if len(parts) == 2:
                out.append({"name": parts[0], "version": parts[1]})
        return out

    def _get_services(self) -> list[dict[str, str]]:
        out: list[dict[str, str]] = []
        try:
            r = subprocess.run(
                ["systemctl", "list-units", "--type=service", "--state=running", "--no-pager", "-o", "json"],
                capture_output=True,
                text=True,
                timeout=10,
            )
            if r.returncode != 0:
                return out
            import json

            data = json.loads(r.stdout)
            for u in data.get("units", [])[:200]:
                out.append({"name": u.get("unit", ""), "state": u.get("sub", "running")})
        except Exception:
            pass
        return out

    def _get_listening_ports(self) -> list[dict[str, Any]]:
        out: list[dict[str, Any]] = []
        for cmd in (["ss", "-tln"], ["ss", "-tlnp"], ["netstat", "-tln"]):
            try:
                r = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
                if r.returncode != 0 or not r.stdout:
                    continue
                for line in r.stdout.strip().split("\n")[1:]:
                    parts = line.split()
                    if len(parts) >= 4:
                        addr = parts[3]
                        if ":" in addr:
                            _, port = addr.rsplit(":", 1)
                            out.append({"port": port, "address": addr})
                break
            except (FileNotFoundError, subprocess.TimeoutExpired, Exception):
                continue
        return out[:500]

    def _get_sudo_users(self) -> list[str]:
        out: list[str] = []
        try:
            r = subprocess.run(["getent", "group", "sudo"], capture_output=True, text=True, timeout=2)
            if r.returncode == 0 and r.stdout:
                parts = r.stdout.strip().split(":")
                if len(parts) >= 4 and parts[3]:
                    out = [u.strip() for u in parts[3].split(",")]
            if not out:
                r = subprocess.run(["getent", "group", "wheel"], capture_output=True, text=True, timeout=2)
                if r.returncode == 0 and r.stdout:
                    parts = r.stdout.strip().split(":")
                    if len(parts) >= 4 and parts[3]:
                        out = [u.strip() for u in parts[3].split(",")]
        except Exception:
            pass
        return out
