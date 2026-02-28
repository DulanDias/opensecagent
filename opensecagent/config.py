# OpenSecAgent - Configuration loader
from __future__ import annotations

import os
from pathlib import Path
from typing import Any

import yaml


def load_config(path: str | Path | None = None) -> dict[str, Any]:
    path = path or os.environ.get("OPENSECAGENT_CONFIG")
    if path:
        path = Path(path)
        if path.exists():
            with open(path) as f:
                data = yaml.safe_load(f) or {}
            return _deep_merge(_default_config(), data)
    # Try project root config (development)
    base = Path(__file__).resolve().parent.parent
    dev_config = base / "config" / "default.yaml"
    if dev_config.exists():
        with open(dev_config) as f:
            data = yaml.safe_load(f) or {}
        return _deep_merge(_default_config(), data)
    # Try package-bundled config
    try:
        from importlib.resources import files
        cfg = files("opensecagent") / "config" / "default.yaml"
        data = yaml.safe_load((cfg.read_bytes()).decode()) or {}
        return _deep_merge(_default_config(), data)
    except Exception:
        pass
    return _default_config()


def _default_config() -> dict[str, Any]:
    return {
        "agent": {
            "name": "opensecagent",
            "version": "0.1.0",
            "data_dir": "/var/lib/opensecagent",
            "log_dir": "/var/log/opensecagent",
            "run_dir": "/run/opensecagent",
        },
        "environment": "prod",
        "action_tier_max": 1,
        "maintenance_windows": [],
        "scan_level": "",
        "scan_frequencies": {
            "quick": {"host_interval_sec": 600, "docker_interval_sec": 120, "drift_interval_sec": 600, "detector_interval_sec": 120, "llm_scan_interval_sec": 7200},
            "standard": {"host_interval_sec": 300, "docker_interval_sec": 60, "drift_interval_sec": 300, "detector_interval_sec": 60, "llm_scan_interval_sec": 3600},
            "deep": {"host_interval_sec": 180, "docker_interval_sec": 45, "drift_interval_sec": 180, "detector_interval_sec": 45, "llm_scan_interval_sec": 1800},
        },
        "collector": {
            "host_interval_sec": 300,
            "docker_interval_sec": 60,
            "drift_interval_sec": 300,
            "critical_files": [
                "/etc/passwd",
                "/etc/group",
                "/etc/sudoers",
                "/etc/ssh/sshd_config",
                "/etc/hosts",
                "/etc/crontab",
            ],
        },
        "detector": {
            "detector_interval_sec": 60,
            "auth_failure_threshold": 5,
            "auth_failure_window_sec": 300,
            "baseline_learning_days": 3,
        },
        "notifications": {
            "provider": "smtp",
            "admin_emails": [],
            "smtp": {
                "host": "",
                "port": 587,
                "use_tls": True,
                "user": "",
                "password": "",
                "from": "OpenSecAgent <noreply@localhost>",
            },
            "resend": {"api_key": "", "from": ""},
            "immediate_severities": ["P1", "P2"],
            "digest": {"enabled": True, "hour_utc": 8, "minute": 0},
        },
        "llm": {
            "enabled": False,
            "provider": "openai",
            "api_key": "",
            "model": "gpt-4o-mini",
            "model_scan": "",
            "model_resolve": "",
            "base_url": "",
            "max_tokens": 1024,
            "redact_patterns": ["password", "secret", "token", "key", "credential"],
        },
        "control_plane": {"enabled": False, "url": "", "agent_key": ""},
        "audit": {
            "file": "/var/log/opensecagent/audit.jsonl",
            "max_size_mb": 100,
            "retain_days": 90,
        },
        "activity": {
            "enabled": True,
            "file": "/var/log/opensecagent/activity.jsonl",
        },
        "llm_agent": {
            "enabled": False,
            "run_on_incident": True,
            "run_interval_sec": 0,
            "agent_max_iterations": 10,
        },
    }


def _deep_merge(base: dict, override: dict) -> dict:
    out = dict(base)
    for k, v in override.items():
        if k in out and isinstance(out[k], dict) and isinstance(v, dict):
            out[k] = _deep_merge(out[k], v)
        else:
            out[k] = v
    return out


def get_default_config() -> dict[str, Any]:
    """Return the default configuration dict (no file merge)."""
    return _default_config()


def save_config(path: str | Path, data: dict[str, Any]) -> None:
    """Write config dict to YAML file."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w") as f:
        yaml.safe_dump(data, f, default_flow_style=False, allow_unicode=True, sort_keys=False)


def set_config_key(data: dict[str, Any], key: str, value: Any) -> None:
    """Set a nested key using dot notation (e.g. 'notifications.smtp.port' or 'notifications.admin_emails.0')."""
    parts = key.split(".")
    cur: Any = data
    for i, p in enumerate(parts[:-1]):
        nxt = parts[i + 1]
        if nxt.isdigit():
            if p not in cur:
                cur[p] = []
            if not isinstance(cur[p], list):
                cur[p] = list(cur[p]) if cur[p] else []
            idx = int(nxt)
            while len(cur[p]) <= idx:
                cur[p].append(None)
            cur = cur[p]
            # last part will be the index into this list
        else:
            if p not in cur:
                cur[p] = {}
            cur = cur[p]
            if not isinstance(cur, dict):
                raise ValueError(f"Cannot set {key}: '{p}' is not a dict")
    last = parts[-1]
    if isinstance(value, str) and value.lower() in ("true", "false"):
        value = value.lower() == "true"
    elif isinstance(value, str) and value.isdigit():
        value = int(value)
    elif isinstance(value, str) and value.replace(".", "", 1).isdigit():
        value = float(value)
    if last.isdigit():
        if not isinstance(cur, list):
            raise ValueError(f"Cannot set {key}: parent is not a list")
        idx = int(last)
        while len(cur) <= idx:
            cur.append(None)
        cur[idx] = value
    else:
        if not isinstance(cur, dict):
            raise ValueError(f"Cannot set {key}: parent is not a dict")
        cur[last] = value


def validate_config(config: dict[str, Any]) -> list[str]:
    """Validate config; return list of error messages (empty if valid)."""
    errs: list[str] = []
    if not config.get("agent"):
        errs.append("Missing 'agent' section")
    else:
        if not config["agent"].get("data_dir"):
            errs.append("agent.data_dir is required")
        if not config["agent"].get("log_dir"):
            errs.append("agent.log_dir is required")
    if not isinstance(config.get("action_tier_max"), (int, type(None))):
        errs.append("action_tier_max must be 0-3")
    elif config.get("action_tier_max") not in (0, 1, 2, 3):
        errs.append("action_tier_max must be 0, 1, 2, or 3")
    notifications = config.get("notifications", {})
    if notifications.get("admin_emails") and not isinstance(notifications["admin_emails"], list):
        errs.append("notifications.admin_emails must be a list")
    if config.get("llm", {}).get("enabled") and not config.get("llm", {}).get("api_key"):
        errs.append("llm.enabled is true but llm.api_key is empty")
    return errs
