# OpenSecAgent - ASCII art and CLI animations
from __future__ import annotations

import sys
import time


def _clear_line() -> None:
    """Carriage return to overwrite current line (for animations)."""
    sys.stdout.write("\r")
    sys.stdout.flush()


def print_wizard_banner() -> None:
    """Print security-guard themed ASCII banner at wizard start."""
    banner = r"""
         .---------------------------------------------.
        /                                               \
       |     \     |     /      OpenSecAgent            |
       |      \    |    /       ----------------        |
       |       \   |   /        Your server's           |
       |        \  |  /         SECURITY GUARD          |
       |         \ | /                                  |
       |          \|/     Drift . Detectors . LLM       |
       |           *      Agent . Alerts                |
       |                                                 |
        \              S E T U P   W I Z A R D          /
         '---------------------------------------------'
    """
    print(banner)


def animate_wizard_complete() -> None:
    """Play a short ASCII animation when wizard completes successfully."""
    frames = [
        r"""
   +------------------+
   | [OK] Config      |
   | [OK] Paths       |
   | [OK] Validate    |
   | [..] Guard       |  << arming...
   +------------------+
""",
        r"""
   +------------------+
   | [OK] Config      |
   | [OK] Paths       |
   | [OK] Validate    |
   | [OK] Guard       |  << armed
   +------------------+
""",
        r"""
   * * *  GUARD ACTIVE  * * *
   --------------------------
   Your server is now under
   continuous security
   monitoring.
""",
    ]
    try:
        for i, frame in enumerate(frames):
            print(frame)
            if i < len(frames) - 1:
                time.sleep(0.55)
    except (KeyboardInterrupt, OSError):
        pass


def print_install_success() -> None:
    """Print when package is used (e.g. first status or --help). Simple one-off banner."""
    from opensecagent import __version__
    banner = f"""
  +-------------------------------------------------------------+
  |  OpenSecAgent v{__version__}  .  Security guard is ready.     |
  |  Run:  opensecagent wizard   or   opensecagent status       |
  +-------------------------------------------------------------+
"""
    print(banner)


def print_daemon_banner() -> None:
    """Short ASCII when daemon starts (guard on duty)."""
    banner = r"""
  [*] OpenSecAgent guard is on duty. Monitoring host, containers, drift, detectors.
  --------------------------------------------------------------------------------
"""
    print(banner)
