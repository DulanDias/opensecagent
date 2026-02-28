# OpenSecAgent - CLI: setup, configure, run, export (wizard-driven)
from __future__ import annotations

import argparse
import asyncio
import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any

from opensecagent import __version__
from opensecagent.config import (
    get_default_config,
    get_default_config_path,
    find_config_path,
    load_config,
    save_config,
    set_config_key,
    validate_config,
)


# --- Wizard helpers ---

def _prompt(msg: str, default: str = "") -> str:
    if default:
        out = input(f"  {msg} [{default}]: ").strip()
        return out if out else default
    return input(f"  {msg}: ").strip()


def _prompt_yn(msg: str, default: bool = False) -> bool:
    d = "Y/n" if default else "y/N"
    out = input(f"  {msg} [{d}]: ").strip().lower()
    if not out:
        return default
    return out in ("y", "yes", "1")


def _wizard_config_steps(config: dict[str, Any]) -> None:
    """Run interactive config questions (mutates config)."""
    print("\n  --- Scan frequency ---")
    print("    1 = Quick   (host/drift ~10min, docker 2min, LLM scan 2h)")
    print("    2 = Standard (host/drift 5min, docker 1min, LLM scan 1h)")
    print("    3 = Deep     (host/drift 3min, docker 45s, LLM scan 30min)")
    level_choice = _prompt("Scan frequency level (1=quick, 2=standard, 3=deep)", "2").strip()
    level_map = {"1": "quick", "2": "standard", "3": "deep"}
    config["scan_level"] = level_map.get(level_choice, "standard")
    config.setdefault("scan_frequencies", {})

    print("\n  --- Notifications ---")
    emails = _prompt("Admin email(s) for alerts (comma-separated)", "")
    if emails:
        config.setdefault("notifications", {})
        config["notifications"]["admin_emails"] = [e.strip() for e in emails.split(",") if e.strip()]
    provider = _prompt("Email provider (smtp | resend)", "resend").strip().lower() or "resend"
    config["notifications"]["provider"] = "resend" if provider == "resend" else "smtp"
    if provider == "resend":
        config["notifications"].setdefault("resend", {})
        config["notifications"]["resend"]["api_key"] = _prompt("Resend API key", "")
        config["notifications"]["resend"]["from"] = _prompt("From email (e.g. alerts@yourdomain.com)", "")
    else:
        config["notifications"].setdefault("smtp", {})
        smtp_host = _prompt("SMTP host", "")
        if smtp_host:
            config["notifications"]["smtp"]["host"] = smtp_host
            config["notifications"]["smtp"]["port"] = int(_prompt("SMTP port", "587") or "587")
            config["notifications"]["smtp"]["user"] = _prompt("SMTP user (optional)", "")
            pw = _prompt("SMTP password (optional)", "")
            if pw:
                config["notifications"]["smtp"]["password"] = pw
            config["notifications"]["smtp"]["from"] = _prompt("From address", "OpenSecAgent <noreply@localhost>") or "OpenSecAgent <noreply@localhost>"

    print("\n  --- Environment & policy ---")
    config["environment"] = _prompt("Environment (dev/staging/prod)", "prod") or "prod"
    tier = _prompt("Max action tier (0=alert only, 1=soft containment)", "1") or "1"
    config["action_tier_max"] = int(tier)

    print("\n  --- LLM (OpenAI / Anthropic) ---")
    if _prompt_yn("Enable LLM for summaries and agent?", True):
        config["llm"]["enabled"] = True
        config["llm"]["provider"] = _prompt("LLM provider (openai | anthropic)", "openai").strip().lower() or "openai"
        config["llm"]["api_key"] = _prompt("API key (OpenAI or Anthropic)", "")
        config.setdefault("llm_agent", {})["enabled"] = _prompt_yn("Run LLM agent on P1/P2 incidents?", True)
        run_interval = _prompt("Periodic LLM scan interval in seconds (0=disabled)", "3600") or "3600"
        config["llm_agent"]["run_interval_sec"] = int(run_interval)
    else:
        config["llm"]["enabled"] = False
        config.setdefault("llm_agent", {})["enabled"] = False


# --- Async commands (existing) ---

async def cmd_collect(config: dict) -> None:
    from opensecagent.collector.host import HostCollector
    from opensecagent.collector.docker_collector import DockerCollector
    h = HostCollector(config)
    d = DockerCollector(config)
    host_inv = await h.collect()
    docker_inv = await d.collect()
    print(json.dumps({"host": host_inv, "docker": docker_inv}, indent=2))


async def cmd_drift(config: dict) -> None:
    from opensecagent.collector.drift import DriftMonitor
    from opensecagent.reporter.audit import AuditLogger
    audit = AuditLogger(config.get("audit", {}))
    await audit.start()
    mon = DriftMonitor(config, audit)
    await audit.stop()
    events = await mon.check()
    print(json.dumps({"drift_events": [e for e in events], "count": len(events)}, indent=2))


async def cmd_detect(config: dict) -> None:
    from opensecagent.detector.manager import DetectorManager
    from opensecagent.reporter.audit import AuditLogger
    audit = AuditLogger(config.get("audit", {}))
    await audit.start()
    mgr = DetectorManager(config, audit)
    await audit.stop()
    events = await mgr.run_detectors()
    print(json.dumps({"detector_events": events, "count": len(events)}, indent=2))


async def cmd_export_audit(config: dict, path: str | None) -> None:
    audit_path = path or config.get("audit", {}).get("file", "/var/log/opensecagent/audit.jsonl")
    p = Path(audit_path)
    if not p.exists():
        print("[]", file=sys.stderr)
        return
    lines = []
    with open(p) as f:
        for line in f:
            line = line.strip()
            if line:
                lines.append(json.loads(line))
    print(json.dumps(lines, indent=2))


async def cmd_export_activity(config: dict, path: str | None) -> None:
    log_dir = Path(config.get("agent", {}).get("log_dir", "/var/log/opensecagent"))
    act = config.get("activity", {})
    activity_path = path or act.get("file", str(log_dir / "activity.jsonl"))
    p = Path(activity_path)
    if not p.exists():
        print("[]", file=sys.stderr)
        return
    lines = []
    with open(p) as f:
        for line in f:
            line = line.strip()
            if line:
                lines.append(json.loads(line))
    print(json.dumps(lines, indent=2))


async def cmd_agent(config: dict) -> None:
    from opensecagent.collector.host import HostCollector
    from opensecagent.collector.docker_collector import DockerCollector
    from opensecagent.reporter.activity import ActivityLogger
    from opensecagent.llm_agent import LLMAgent
    act_config = {**config, "activity": config.get("activity", {}), "agent": config.get("agent", {})}
    activity = ActivityLogger(act_config)
    await activity.start()
    h = HostCollector(config)
    d = DockerCollector(config)
    host_inv = await h.collect()
    docker_inv = await d.collect()
    context = {"host": host_inv, "docker": docker_inv}
    agent = LLMAgent(config, activity)
    result = await agent.run_agent_loop(context, None)
    await activity.stop()
    print(json.dumps(result, indent=2))


# --- Setup & config commands ---

def cmd_wizard() -> None:
    """Full wizard: paths → create dirs + config → configure → validate → optional install → status."""
    print("\n  ═══════════════════════════════════════════════════════")
    print("  OpenSecAgent Setup Wizard")
    print("  ═══════════════════════════════════════════════════════\n")

    print("  Step 1 — Paths")
    config_dir = _prompt("Config directory", "/etc/opensecagent")
    data_dir = _prompt("Data directory", "/var/lib/opensecagent")
    log_dir = _prompt("Log directory", "/var/log/opensecagent")
    config_dir = Path(config_dir).expanduser()
    data_dir = Path(data_dir).expanduser()
    log_dir = Path(log_dir).expanduser()
    config_path = config_dir / "config.yaml"

    try:
        config_dir.mkdir(parents=True, exist_ok=True)
        data_dir.mkdir(parents=True, exist_ok=True)
        log_dir.mkdir(parents=True, exist_ok=True)
    except PermissionError:
        # Fall back to user-writable paths when not root
        home = Path.home()
        config_dir = home / ".config" / "opensecagent"
        data_dir = home / ".local" / "share" / "opensecagent"
        log_dir = home / ".local" / "state" / "opensecagent"
        config_path = config_dir / "config.yaml"
        config_dir.mkdir(parents=True, exist_ok=True)
        data_dir.mkdir(parents=True, exist_ok=True)
        log_dir.mkdir(parents=True, exist_ok=True)
        print(f"\n  Using user paths (no write access to /etc or /var):")
    print(f"  Created: {config_dir}, {data_dir}, {log_dir}")

    config = get_default_config()
    config["agent"]["data_dir"] = str(data_dir)
    config["agent"]["log_dir"] = str(log_dir)
    config["audit"]["file"] = str(log_dir / "audit.jsonl")
    config["activity"]["file"] = str(log_dir / "activity.jsonl")

    if config_path.exists() and not _prompt_yn("Config already exists. Overwrite and continue?", False):
        print("  Skipped. Run with existing config: opensecagent --config", config_path, "status")
        return
    print("\n  Step 2 — Configuration")
    _wizard_config_steps(config)
    save_config(config_path, config)
    print(f"\n  Saved config to {config_path}")

    print("\n  Step 3 — Validate")
    errs = validate_config(config)
    if errs:
        print("  Warnings:")
        for e in errs:
            print("   -", e)
    else:
        print("  Config is valid.")

    print("\n  Step 4 — Install systemd service (Linux only)")
    try:
        subprocess.run(["systemctl", "--version"], capture_output=True, check=True)
    except (FileNotFoundError, subprocess.CalledProcessError):
        print("  systemctl not found. Skip install. Run daemon manually: opensecagent --config", config_path)
        print("\n  Done. Check status: opensecagent --config", config_path, "status\n")
        return

    if _prompt_yn("Install and enable systemd service?", True):
        install_dir = _prompt("Install directory (agent files)", "/opt/opensecagent")
        no_start = not _prompt_yn("Start service now?", True)
        cmd_install(str(config_path), install_dir, str(config_dir), str(data_dir), str(log_dir), no_start)
    else:
        print("  Skipped. To install later: sudo opensecagent install --config-dir", config_dir)

    print("\n  Step 5 — Status")
    cmd_status(str(config_path))
    print("\n  Wizard complete. Use: opensecagent --config", config_path, "(to run daemon)\n")


def cmd_setup(
    config_dir: str,
    data_dir: str,
    log_dir: str,
    config_file: str | None,
    force: bool,
    interactive: bool,
) -> None:
    """Create directories and default config. Interactive: prompt for paths and optional config wizard."""
    if interactive:
        print("\n  OpenSecAgent — Setup (interactive)\n")
        config_dir = _prompt("Config directory", "/etc/opensecagent")
        data_dir = _prompt("Data directory", "/var/lib/opensecagent")
        log_dir = _prompt("Log directory", "/var/log/opensecagent")
    config_dir = Path(config_dir).expanduser()
    data_dir = Path(data_dir).expanduser()
    log_dir = Path(log_dir).expanduser()
    config_path = config_dir / (config_file or "config.yaml")

    try:
        config_dir.mkdir(parents=True, exist_ok=True)
        data_dir.mkdir(parents=True, exist_ok=True)
        log_dir.mkdir(parents=True, exist_ok=True)
    except PermissionError:
        home = Path.home()
        config_dir = home / ".config" / "opensecagent"
        data_dir = home / ".local" / "share" / "opensecagent"
        log_dir = home / ".local" / "state" / "opensecagent"
        config_path = config_dir / (config_file or "config.yaml")
        config_dir.mkdir(parents=True, exist_ok=True)
        data_dir.mkdir(parents=True, exist_ok=True)
        log_dir.mkdir(parents=True, exist_ok=True)
        print("Using user paths (no write access to /etc or /var):")
    print(f"Created directories: {config_dir}, {data_dir}, {log_dir}")

    if not config_path.exists() or force:
        cfg = get_default_config()
        cfg["agent"]["data_dir"] = str(data_dir)
        cfg["agent"]["log_dir"] = str(log_dir)
        cfg["audit"]["file"] = str(log_dir / "audit.jsonl")
        cfg["activity"]["file"] = str(log_dir / "activity.jsonl")
        save_config(config_path, cfg)
        print(f"Wrote default config to {config_path}")
    else:
        print(f"Config already exists at {config_path} (use --force to overwrite)")

    if interactive and _prompt_yn("Run configuration wizard now?", True):
        config = load_config(config_path)
        print("")
        _wizard_config_steps(config)
        save_config(config_path, config)
        print(f"\nConfig saved to {config_path}")
    elif not interactive:
        print("Next: opensecagent --config", config_path, "config wizard")


def cmd_config_show(config_path: str | None) -> None:
    """Print merged config as YAML."""
    import yaml
    config = load_config(config_path)
    print(yaml.safe_dump(config, default_flow_style=False, allow_unicode=True, sort_keys=False))


def cmd_config_validate(config_path: str | None) -> None:
    """Validate config file and print errors."""
    config = load_config(config_path)
    errs = validate_config(config)
    if not errs:
        print("Config is valid.")
        return
    for e in errs:
        print(f"Error: {e}", file=sys.stderr)
    sys.exit(1)


def cmd_config_set(config_path: str | None, key: str, value: str, output_path: str | None) -> None:
    """Set a config key (dot notation) and save."""
    path = config_path or os.environ.get("OPENSECAGENT_CONFIG")
    if not path or not Path(path).exists():
        print("Error: No config file found. Run 'opensecagent setup' first.", file=sys.stderr)
        sys.exit(1)
    path = Path(path)
    config = load_config(path)
    try:
        set_config_key(config, key, value)
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)
    out = Path(output_path or path)
    save_config(out, config)
    print(f"Set {key} = {value!r}; saved to {out}")


def cmd_config_wizard(config_path: str | None) -> None:
    """Interactive wizard to set admin emails, SMTP, environment, LLM."""
    path = Path(config_path) if config_path else get_default_config_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        config = load_config(path)
    else:
        config = get_default_config()
        config["agent"]["data_dir"] = "/var/lib/opensecagent"
        config["agent"]["log_dir"] = "/var/log/opensecagent"
        config["audit"]["file"] = "/var/log/opensecagent/audit.jsonl"
        config["activity"]["file"] = "/var/log/opensecagent/activity.jsonl"
        config["activity"]["log_dir"] = "/var/log/opensecagent"

    print("\n  OpenSecAgent — Configuration wizard\n")
    _wizard_config_steps(config)
    save_config(path, config)
    print(f"\n  Config saved to {path}")
    errs = validate_config(config)
    if errs:
        print("  Warnings:", *errs, sep="\n    - ")
    else:
        print("  Config is valid. You can now run: opensecagent status   (no --config needed)\n")


def cmd_config(config_path: str | None) -> None:
    """Run config wizard and write YAML to default path. No --config needed afterward."""
    path = Path(config_path) if config_path else get_default_config_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        config = load_config(path)
    else:
        config = get_default_config()
        config["agent"]["data_dir"] = "/var/lib/opensecagent"
        config["agent"]["log_dir"] = "/var/log/opensecagent"
        config["audit"]["file"] = "/var/log/opensecagent/audit.jsonl"
        config["activity"]["file"] = "/var/log/opensecagent/activity.jsonl"
        config["activity"]["log_dir"] = "/var/log/opensecagent"

    print("\n  OpenSecAgent — Config (interactive)\n")
    print("  Answer the questions below; we'll write the config file for you.\n")
    _wizard_config_steps(config)
    save_config(path, config)
    print(f"\n  Config written to: {path}")
    errs = validate_config(config)
    if errs:
        print("  Warnings:", *errs, sep="\n    - ")
    else:
        print("  Done. Run  opensecagent status  or  opensecagent run  (no --config needed).\n")


def _get_systemd_unit_content() -> str:
    source = Path(__file__).resolve().parent.parent
    unit_file = source / "systemd" / "opensecagent.service"
    if unit_file.exists():
        return unit_file.read_text()
    try:
        from importlib.resources import files
        u = files("opensecagent") / ".." / ".." / "systemd" / "opensecagent.service"
        if u.exists():
            return u.read_text()
    except Exception:
        pass
    return """[Unit]
Description=OpenSecAgent - Autonomous Server Cybersecurity Expert Bot
After=network-online.target docker.service
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/bin/python3 -m opensecagent.main --config %CONFIG_DIR%/config.yaml
WorkingDirectory=%INSTALL_DIR%
Restart=on-failure
RestartSec=10

[Install]
WantedBy=multi-user.target
"""


def cmd_install(
    config_path: str | None,
    install_dir: str,
    config_dir: str,
    data_dir: str,
    log_dir: str,
    no_start: bool,
    interactive: bool,
) -> None:
    """Install systemd service (wizard-like when interactive)."""
    if interactive:
        print("\n  OpenSecAgent — Install systemd service (interactive)\n")
        install_dir = _prompt("Install directory (agent code)", "/opt/opensecagent")
        config_dir = _prompt("Config directory", "/etc/opensecagent")
        data_dir = _prompt("Data directory", "/var/lib/opensecagent")
        log_dir = _prompt("Log directory", "/var/log/opensecagent")
        no_start = not _prompt_yn("Start service after install?", True)
    config_dir = Path(config_dir)
    config_dir.mkdir(parents=True, exist_ok=True)
    Path(data_dir).mkdir(parents=True, exist_ok=True)
    Path(log_dir).mkdir(parents=True, exist_ok=True)

    config_file = config_dir / "config.yaml"
    if not config_file.exists():
        cfg = get_default_config()
        cfg["agent"]["data_dir"] = data_dir
        cfg["agent"]["log_dir"] = log_dir
        cfg["audit"]["file"] = f"{log_dir}/audit.jsonl"
        cfg["activity"]["file"] = f"{log_dir}/activity.jsonl"
        save_config(config_file, cfg)
        print(f"  Created {config_file}")

    unit = Path("/etc/systemd/system/opensecagent.service")
    if not unit.parent.exists():
        print("Cannot write to /etc/systemd/system. Run as root.", file=sys.stderr)
        sys.exit(1)
    unit_content = _get_systemd_unit_content().replace("%INSTALL_DIR%", install_dir).replace("%CONFIG_DIR%", str(config_dir))
    unit.write_text(unit_content)
    print(f"  Wrote {unit}")
    subprocess.run(["systemctl", "daemon-reload"], check=True)
    if not no_start:
        subprocess.run(["systemctl", "enable", "opensecagent"], check=True)
        subprocess.run(["systemctl", "start", "opensecagent"], check=True)
        print("  Started opensecagent. Logs: journalctl -u opensecagent -f")
    else:
        print("  Run: sudo systemctl enable opensecagent && sudo systemctl start opensecagent")
        print("  Logs: journalctl -u opensecagent -f")
    if interactive:
        print("\n  Config file:", config_file, "\n")


def cmd_status(config_path: str | None) -> None:
    """Show config path, version, paths, and whether daemon is running."""
    config = load_config(config_path)
    resolved = find_config_path(config_path)
    print("OpenSecAgent status")
    print("  Version:", __version__)
    print("  Config: ", resolved or config_path or os.environ.get("OPENSECAGENT_CONFIG") or "(defaults only)")
    print("  Data:   ", config.get("agent", {}).get("data_dir"))
    print("  Log:    ", config.get("agent", {}).get("log_dir"))
    print("  Audit:  ", config.get("audit", {}).get("file"))
    print("  Activity:", config.get("activity", {}).get("file"))
    try:
        r = subprocess.run(["systemctl", "is-active", "opensecagent"], capture_output=True, text=True)
        if r.returncode == 0 and r.stdout.strip() == "active":
            print("  Daemon:  running (systemd)")
        else:
            raise FileNotFoundError
    except FileNotFoundError:
        try:
            r2 = subprocess.run(["pgrep", "-f", "opensecagent.main"], capture_output=True)
            print("  Daemon:  running (pid)" if r2.returncode == 0 else "  Daemon:  not running")
        except FileNotFoundError:
            print("  Daemon:  unknown (no systemctl/pgrep)")


async def cmd_test(config: dict[str, Any]) -> None:
    """Test config, LLM connectivity, and email delivery."""
    print("\n  OpenSecAgent — Connectivity test\n")
    llm = config.get("llm", {})
    notif = config.get("notifications", {})
    agent_cfg = config.get("llm_agent", {})

    # Config summary
    print("  Config summary:")
    print(f"    LLM enabled:     {llm.get('enabled', False)}")
    print(f"    LLM provider:    {llm.get('provider', 'openai')}")
    print(f"    Model (default): {llm.get('model', 'gpt-4o-mini')}")
    print(f"    Model (scan):    {llm.get('model_scan') or llm.get('model', '—')}")
    print(f"    Model (resolve): {llm.get('model_resolve') or llm.get('model', '—')}")
    print(f"    LLM agent on P1/P2: {agent_cfg.get('run_on_incident', True)}")
    print(f"    Notifications:   {notif.get('provider', 'smtp')}")
    print(f"    Admin emails:     {notif.get('admin_emails', []) or '(none)'}")
    print()

    # Test LLM
    if llm.get("enabled") and llm.get("api_key"):
        print("  Testing LLM (one short completion)...")
        try:
            from opensecagent.llm_client import chat
            model = llm.get("model") or "gpt-4o-mini"
            out = await chat(
                provider=llm.get("provider", "openai"),
                model=model,
                messages=[{"role": "user", "content": "Reply with exactly: OK"}],
                max_tokens=10,
                api_key=llm.get("api_key", ""),
                base_url=llm.get("base_url") or None,
            )
            if out and "OK" in out.upper():
                print(f"    LLM: OK (model {model})")
            else:
                print(f"    LLM: responded but unexpected: {out[:80]!r}")
        except Exception as e:
            print(f"    LLM: FAILED — {e}")
    else:
        print("  LLM: skipped (disabled or no api_key)")

    # Test email
    if notif.get("admin_emails") and (
        (notif.get("provider") == "resend" and notif.get("resend", {}).get("api_key"))
        or (notif.get("provider") == "smtp" and notif.get("smtp", {}).get("host"))
    ):
        print("  Testing email (sending test to admin addresses)...")
        try:
            from opensecagent.reporter.email_reporter import EmailReporter
            reporter = EmailReporter(notif)
            await reporter._send_mail(
                "[OpenSecAgent] Test email",
                "This is a test email from OpenSecAgent. If you received this, email delivery is working.",
                None,
                "",
            )
            print("    Email: sent (check your inbox)")
        except Exception as e:
            print(f"    Email: FAILED — {e}")
    else:
        print("  Email: skipped (no admin_emails or missing Resend/SMTP config)")

    print("\n  Done.\n")


def cmd_uninstall(stop_only: bool) -> None:
    """Stop and disable systemd service; optionally remove unit file."""
    try:
        subprocess.run(["systemctl", "stop", "opensecagent"], capture_output=True)
        subprocess.run(["systemctl", "disable", "opensecagent"], capture_output=True)
        print("Stopped and disabled opensecagent service.")
        if not stop_only:
            unit = Path("/etc/systemd/system/opensecagent.service")
            if unit.exists():
                unit.unlink()
                subprocess.run(["systemctl", "daemon-reload"], capture_output=True)
                print("Removed systemd unit. Data and config were left in place.")
    except FileNotFoundError:
        print("systemctl not found (not a systemd system). No service to uninstall.", file=sys.stderr)


def main() -> None:
    ap = argparse.ArgumentParser(prog="opensecagent", description="OpenSecAgent - setup, configure, and run")
    ap.add_argument("--config", "-c", help="Config file path")
    sub = ap.add_subparsers(dest="command", required=True)

    # wizard (full interactive flow)
    sub.add_parser("wizard", help="Full setup wizard: paths → config → validate → optional install")

    # setup
    p_setup = sub.add_parser("setup", help="Create directories and default config (use --interactive for wizard)")
    p_setup.add_argument("--config-dir", default="/etc/opensecagent", help="Config directory")
    p_setup.add_argument("--data-dir", default="/var/lib/opensecagent", help="Data directory")
    p_setup.add_argument("--log-dir", default="/var/log/opensecagent", help="Log directory")
    p_setup.add_argument("--config-file", default="config.yaml", help="Config filename")
    p_setup.add_argument("--force", action="store_true", help="Overwrite existing config")
    p_setup.add_argument("--interactive", "-i", action="store_true", help="Prompt for paths and run config wizard")

    # config (no subcommand = run wizard and write YAML; no --config needed afterward)
    p_config = sub.add_parser("config", help="Interactive config wizard (writes YAML). Or: config show|validate|set")
    p_config_sub = p_config.add_subparsers(dest="config_cmd", required=False)
    p_config_sub.add_parser("show", help="Show merged config (YAML)")
    p_config_sub.add_parser("validate", help="Validate config file")
    p_config_set = p_config_sub.add_parser("set", help="Set a key (e.g. notifications.admin_emails.0=admin@example.com)")
    p_config_set.add_argument("key", help="Dot-separated key")
    p_config_set.add_argument("value", help="Value (string; true/false and numbers auto-parsed)")
    p_config_set.add_argument("--output", "-o", help="Write to this path instead of --config")
    p_config_sub.add_parser("wizard", help="Same as 'opensecagent config' (interactive wizard)")

    # install
    p_install = sub.add_parser("install", help="Install systemd service (--interactive for wizard)")
    p_install.add_argument("--install-dir", default="/opt/opensecagent", help="Installation directory")
    p_install.add_argument("--config-dir", default="/etc/opensecagent", help="Config directory")
    p_install.add_argument("--data-dir", default="/var/lib/opensecagent", help="Data directory")
    p_install.add_argument("--log-dir", default="/var/log/opensecagent", help="Log directory")
    p_install.add_argument("--no-start", action="store_true", help="Do not start service after install")
    p_install.add_argument("--interactive", "-i", action="store_true", help="Prompt for paths and start service")

    # status
    p_status = sub.add_parser("status", help="Show status and paths")

    # test (LLM + email connectivity)
    sub.add_parser("test", help="Test LLM and email: verify config, run one LLM call, send a test email")

    # uninstall
    p_uninstall = sub.add_parser("uninstall", help="Stop and remove systemd service")
    p_uninstall.add_argument("--remove-unit", action="store_true", help="Remove unit file (default: only stop/disable)")

    # Run/export commands
    sub.add_parser("collect", help="Run host + Docker collection once")
    sub.add_parser("drift", help="Run drift check once")
    sub.add_parser("detect", help="Run detectors once")
    sub.add_parser("agent", help="Run LLM agent loop once")
    p_ea = sub.add_parser("export-audit", help="Export audit log as JSON")
    p_ea.add_argument("--path", "-p", help="Audit file path")
    p_eact = sub.add_parser("export-activity", help="Export activity log as JSON")
    p_eact.add_argument("--path", "-p", help="Activity file path")

    args = ap.parse_args()
    config_path = getattr(args, "config", None)
    config = load_config(config_path)  # uses --config, env, or /etc/opensecagent/config.yaml, ~/.config/opensecagent/config.yaml

    if args.command == "wizard":
        cmd_wizard()
    elif args.command == "setup":
        cmd_setup(
            getattr(args, "config_dir", "/etc/opensecagent"),
            getattr(args, "data_dir", "/var/lib/opensecagent"),
            getattr(args, "log_dir", "/var/log/opensecagent"),
            getattr(args, "config_file", None),
            getattr(args, "force", False),
            getattr(args, "interactive", False),
        )
    elif args.command == "config":
        if args.config_cmd == "show":
            cmd_config_show(config_path)
        elif args.config_cmd == "validate":
            cmd_config_validate(config_path)
        elif args.config_cmd == "set":
            cmd_config_set(config_path, args.key, args.value, getattr(args, "output", None))
        elif args.config_cmd == "wizard":
            cmd_config_wizard(config_path)
        else:
            # No subcommand: run wizard and write config (no --config needed afterward)
            cmd_config(config_path)
    elif args.command == "install":
        cmd_install(
            config_path,
            getattr(args, "install_dir", "/opt/opensecagent"),
            getattr(args, "config_dir", "/etc/opensecagent"),
            getattr(args, "data_dir", "/var/lib/opensecagent"),
            getattr(args, "log_dir", "/var/log/opensecagent"),
            getattr(args, "no_start", False),
            getattr(args, "interactive", False),
        )
    elif args.command == "status":
        cmd_status(config_path)
    elif args.command == "test":
        asyncio.run(cmd_test(config))
    elif args.command == "uninstall":
        cmd_uninstall(getattr(args, "remove_unit", False))
    elif args.command == "collect":
        asyncio.run(cmd_collect(config))
    elif args.command == "drift":
        asyncio.run(cmd_drift(config))
    elif args.command == "detect":
        asyncio.run(cmd_detect(config))
    elif args.command == "agent":
        asyncio.run(cmd_agent(config))
    elif args.command == "export-audit":
        asyncio.run(cmd_export_audit(config, getattr(args, "path", None)))
    elif args.command == "export-activity":
        asyncio.run(cmd_export_activity(config, getattr(args, "path", None)))


if __name__ == "__main__":
    main()
