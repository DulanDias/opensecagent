# OpenSecAgent - Data models (Asset, Finding, Event, Incident, Policy)
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any

# --- Enums ---


class AssetType(str, Enum):
    HOST = "host"
    CONTAINER = "container"
    SERVICE = "service"


class Severity(str, Enum):
    P1 = "P1"  # Critical
    P2 = "P2"  # High
    P3 = "P3"  # Medium
    P4 = "P4"  # Low


class ActionTier(int, Enum):
    ALERT_ONLY = 0
    SOFT_CONTAINMENT = 1
    STRONG_CONTAINMENT = 2
    EMERGENCY = 3


# --- Core entities ---


@dataclass
class Asset:
    asset_type: AssetType
    id: str
    name: str
    metadata: dict[str, Any] = field(default_factory=dict)
    labels: dict[str, str] = field(default_factory=dict)


@dataclass
class Finding:
    asset_id: str
    finding_type: str
    title: str
    description: str
    severity: Severity
    evidence: dict[str, Any] = field(default_factory=dict)
    remediation: str = ""
    ts: datetime = field(default_factory=datetime.utcnow)


@dataclass
class Event:
    event_id: str
    source: str  # collector module name
    event_type: str
    severity: Severity
    summary: str
    raw: dict[str, Any]
    ts: datetime = field(default_factory=datetime.utcnow)
    asset_ids: list[str] = field(default_factory=list)
    confidence: float = 1.0


@dataclass
class Incident:
    incident_id: str
    severity: Severity
    title: str
    narrative: str
    events: list[Event]
    evidence_summary: dict[str, Any]
    recommended_actions: list[str]
    actions_taken: list[str] = field(default_factory=list)
    created_at: datetime = field(default_factory=datetime.utcnow)
    contained_at: datetime | None = None
    llm_summary: str = ""

    def event_type_matches(self, typ: str) -> bool:
        return typ in {e.event_type for e in self.events}


@dataclass
class Policy:
    action_tier_max: ActionTier
    maintenance_windows: list[dict[str, Any]]
    allowed_containment_actions: set[str] = field(default_factory=set)


def severity_from_str(s: str) -> Severity:
    return Severity(s) if s in [e.value for e in Severity] else Severity.P4
