#!/usr/bin/env python3
# OpenSecAgent - Daemon entrypoint
from __future__ import annotations

import asyncio
import logging
import signal
import sys
from pathlib import Path

from opensecagent.config import load_config

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger("opensecagent")


def _config_path_from_argv() -> str | None:
    if "--config" not in sys.argv and "-c" not in sys.argv:
        return None
    for i, a in enumerate(sys.argv[1:], 1):
        if a in ("--config", "-c") and i < len(sys.argv) - 1:
            return sys.argv[i + 1]
    return None


def _send_error_email_to_admin(error: BaseException, context: str = "OpenSecAgent") -> None:
    """Try to load config and send error report to admin_emails. Swallows all exceptions."""
    try:
        config = load_config(_config_path_from_argv())
        notif = config.get("notifications", {})
        if not notif.get("admin_emails"):
            return
        if notif.get("provider") == "resend":
            if not (notif.get("resend", {}).get("api_key") and notif.get("resend", {}).get("from")):
                return
        elif not notif.get("smtp", {}).get("host"):
            return
        from opensecagent.reporter.email_reporter import EmailReporter
        reporter = EmailReporter(notif)
        asyncio.run(reporter.send_error_report(error, context))
    except Exception:
        pass


def main() -> None:
    try:
        _main()
    except Exception as e:
        _send_error_email_to_admin(e, "OpenSecAgent (daemon or CLI)")
        raise


def _main() -> None:
    # Run daemon only when no subcommand is given (e.g. "opensecagent" or "opensecagent --config /path")
    # If there is any positional arg (e.g. status, wizard, seup), use CLI so it handles valid commands or reports "invalid choice"
    positionals = [a for a in sys.argv[1:] if not a.startswith("-") and "=" not in a]
    if positionals or "--help" in sys.argv or "-h" in sys.argv:
        if "--help" in sys.argv or "-h" in sys.argv:
            from opensecagent.ascii_art import print_install_success
            print_install_success()
        from opensecagent.cli import main as cli_main
        cli_main()
        return
    config_path = _config_path_from_argv()
    # If no --config, load_config(None) uses /etc/opensecagent/config.yaml or ~/.config/opensecagent/config.yaml
    config = load_config(config_path)
    data_dir = Path(config["agent"]["data_dir"])
    log_dir = Path(config["agent"]["log_dir"])
    try:
        data_dir.mkdir(parents=True, exist_ok=True)
        log_dir.mkdir(parents=True, exist_ok=True)
    except PermissionError:
        logger.error(
            "Cannot create %s or %s (permission denied). "
            "Run as root, or run 'opensecagent config' and set agent.data_dir / agent.log_dir to a path you can write (e.g. under $HOME).",
            data_dir,
            log_dir,
        )
        sys.exit(1)

    from opensecagent.daemon import Daemon
    from opensecagent.ascii_art import print_daemon_banner

    print_daemon_banner()
    daemon = Daemon(config)
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)

    def shutdown():
        daemon.shutdown()
        loop.stop()

    for sig in (signal.SIGTERM, signal.SIGINT):
        try:
            loop.add_signal_handler(sig, shutdown)
        except NotImplementedError:
            pass

    try:
        loop.run_until_complete(daemon.run())
    except (KeyboardInterrupt, RuntimeError):
        pass
    finally:
        try:
            loop.run_until_complete(daemon.cleanup())
        except Exception:
            pass
        loop.close()


if __name__ == "__main__":
    main()
