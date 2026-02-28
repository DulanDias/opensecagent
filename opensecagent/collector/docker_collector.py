# OpenSecAgent - Docker inventory collector
from __future__ import annotations

import asyncio
from typing import Any

logger = __import__("logging").getLogger("opensecagent.collector.docker")


class DockerCollector:
    def __init__(self, config: dict[str, Any]) -> None:
        self.config = config
        self._client: Any = None

    def _get_client(self) -> Any:
        if self._client is None:
            try:
                import docker

                self._client = docker.from_env()
            except Exception as e:
                logger.warning("Docker not available: %s", e)
        return self._client

    async def collect(self) -> dict[str, Any]:
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(None, self._collect_sync)

    def _collect_sync(self) -> dict[str, Any]:
        out: dict[str, Any] = {"available": False, "containers": [], "images": []}
        client = self._get_client()
        if not client:
            return out
        try:
            out["available"] = True
            for c in client.containers.list(all=True):
                out["containers"].append(
                    {
                        "id": c.id[:12],
                        "name": c.name,
                        "image": c.image.tags[0] if c.image.tags else c.image.short_id,
                        "status": c.status,
                        "labels": dict(c.labels) if c.labels else {},
                        "ports": self._format_ports(c.ports) if hasattr(c, "ports") else [],
                    }
                )
            for img in client.images.list():
                out["images"].append(
                    {
                        "id": img.short_id,
                        "tags": img.tags or [],
                        "created": str(img.attrs.get("Created", "")),
                    }
                )
        except Exception as e:
            logger.warning("Docker collect failed: %s", e)
            out["available"] = False
        return out

    @staticmethod
    def _format_ports(ports: dict[str, Any] | None) -> list[str]:
        if not ports:
            return []
        out = []
        for pub, bind in (ports or {}).items():
            if bind:
                out.append(f"{pub} -> {bind[0].get('HostPort', '') if isinstance(bind[0], dict) else bind[0]}")
            else:
                out.append(pub)
        return out[:50]
