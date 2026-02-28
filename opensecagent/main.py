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


CLI_COMMANDS = {
    "collect", "drift", "detect", "agent", "export-audit", "export-activity",
    "wizard", "setup", "config", "install", "status", "uninstall",
}


def main() -> None:
    # Dispatch to CLI for subcommands or --help (so we don't touch /var/lib without root)
    args = [a for a in sys.argv[1:] if not a.startswith("-") and "=" not in a]
    if any(a in CLI_COMMANDS for a in args) or "--help" in sys.argv or "-h" in sys.argv:
        from opensecagent.cli import main as cli_main
        cli_main()
        return
    config_path = None
    if "--config" in sys.argv or "-c" in sys.argv:
        for i, a in enumerate(sys.argv[1:], 1):
            if a in ("--config", "-c") and i < len(sys.argv) - 1:
                config_path = sys.argv[i + 1]
                break
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
