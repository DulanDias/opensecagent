# OpenSecAgent - Threat registry: store and load past threats for LLM context
from __future__ import annotations

import json
import uuid
from datetime import datetime
from pathlib import Path
from typing import Any

logger = __import__("logging").getLogger("opensecagent.threat_registry")


def get_threats_dir(config: dict[str, Any]) -> Path:
    data_dir = Path(config.get("agent", {}).get("data_dir", "/var/lib/opensecagent"))
    return Path(config.get("threat_registry", {}).get("dir", str(data_dir / "threats")))


def ensure_threats_dir(config: dict[str, Any]) -> Path:
    d = get_threats_dir(config)
    d.mkdir(parents=True, exist_ok=True)
    return d


def store_threat(
    config: dict[str, Any],
    title: str,
    description: str,
    severity: str,
    evidence: dict[str, Any],
    resolution_actions: list[str] | None = None,
    threat_id: str | None = None,
) -> str:
    """Store a threat record; returns threat_id."""
    d = ensure_threats_dir(config)
    threat_id = threat_id or f"thr-{uuid.uuid4().hex[:12]}"
    record = {
        "threat_id": threat_id,
        "title": title,
        "description": description,
        "severity": severity,
        "evidence": evidence,
        "resolution_actions": resolution_actions or [],
        "detected_at": datetime.utcnow().isoformat() + "Z",
        "resolved_at": datetime.utcnow().isoformat() + "Z" if resolution_actions else None,
    }
    path = d / f"{threat_id}.json"
    with open(path, "w") as f:
        json.dump(record, f, indent=2)
    return threat_id


def mark_resolved(config: dict[str, Any], threat_id: str, actions_taken: list[str]) -> None:
    """Update a threat record with resolution actions."""
    d = get_threats_dir(config)
    path = d / f"{threat_id}.json"
    if not path.exists():
        return
    with open(path) as f:
        record = json.load(f)
    record["resolution_actions"] = actions_taken
    record["resolved_at"] = datetime.utcnow().isoformat() + "Z"
    with open(path, "w") as f:
        json.dump(record, f, indent=2)


def load_threats_for_context(config: dict[str, Any], limit: int = 20) -> str:
    """Load recent threat records and format for LLM system prompt."""
    d = get_threats_dir(config)
    if not d.exists():
        return ""
    records: list[dict[str, Any]] = []
    for p in sorted(d.glob("*.json"), key=lambda x: x.stat().st_mtime, reverse=True):
        try:
            with open(p) as f:
                records.append(json.load(f))
        except Exception as e:
            logger.debug("Skip threat file %s: %s", p, e)
        if len(records) >= limit:
            break
    if not records:
        return ""
    lines = [
        "Previous threats and resolutions (use for similar cases):",
        "",
    ]
    for r in records:
        lines.append(f"- [{r.get('severity', '')}] {r.get('title', '')}")
        lines.append(f"  Description: {r.get('description', '')[:300]}")
        if r.get("resolution_actions"):
            lines.append("  Resolved by: " + "; ".join(r["resolution_actions"][:5]))
        lines.append("")
    return "\n".join(lines)
