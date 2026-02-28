#!/usr/bin/env python3
"""
OpenSecAgent – safe attack simulation for testing detection and response.

Run this script ON the same machine where OpenSecAgent is running (or where you
will run `opensecagent detect`). It simulates high CPU usage so the resource
detector fires and (if the LLM agent is enabled) OpenSecAgent can investigate
and kill the process.

Usage:
  # Terminal 1: start the daemon (or leave it running)
  opensecagent --config ~/.config/opensecagent/config.yaml

  # Terminal 2: run the simulation (runs for ~2 min or until killed)
  python3 scripts/simulate_attack.py cpu

  # Or run detect manually after starting the burner:
  opensecagent detect

Tip: If your CPU threshold is 90%, ensure the script uses enough cores to exceed it.
     For a quick test, set detector.resource_cpu_percent to 50 in config.
"""
from __future__ import annotations

import multiprocessing
import os
import sys
import time


def _burn_cpu(_: object) -> None:
    """Use one core at 100% (tight loop)."""
    while True:
        pass


def run_cpu_stress(duration_sec: int = 120, num_workers: int | None = None) -> None:
    """Spawn workers that burn CPU to trigger high_cpu detector."""
    n = num_workers or max(1, multiprocessing.cpu_count())
    print(f"Simulating high CPU: {n} workers for {duration_sec}s (PID {os.getpid()})")
    print("OpenSecAgent should detect high_cpu and may run the LLM agent to kill this process.")
    print("Press Ctrl+C to stop early.\n")
    procs = [multiprocessing.Process(target=_burn_cpu, args=(None,)) for _ in range(n)]
    for p in procs:
        p.start()
    try:
        time.sleep(duration_sec)
    except KeyboardInterrupt:
        print("\nStopped.")
    finally:
        for p in procs:
            p.terminate()
            p.join(timeout=2)
            if p.is_alive():
                p.kill()
        print("Simulation ended.")


def main() -> None:
    if len(sys.argv) < 2 or sys.argv[1].lower() != "cpu":
        print(__doc__)
        sys.exit(0)
    duration = 120
    if len(sys.argv) > 2:
        try:
            duration = int(sys.argv[2])
        except ValueError:
            pass
    run_cpu_stress(duration_sec=duration)


if __name__ == "__main__":
    main()
