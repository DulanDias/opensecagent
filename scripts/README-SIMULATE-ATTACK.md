# Simulating an attack to test OpenSecAgent

Use these steps **on your home server** to verify OpenSecAgent detects and responds.

## Prerequisites

- OpenSecAgent installed and configured (`opensecagent status` works).
- For **auto-remediation**: `llm_agent.enabled: true` and `llm_agent.run_on_incident: true` in config, and a valid LLM API key.
- Optional: lower the CPU threshold for easier testing, e.g. in `~/.config/opensecagent/config.yaml`:
  ```yaml
  detector:
    resource_cpu_percent: 50   # default 90; use 50 to trigger with less load
  ```

---

## Test 1: High CPU (“crypto miner” simulation)

This triggers the **resource detector** (high_cpu) and, if the LLM agent is enabled, the agent can **find and kill** the process.

1. **Start the daemon** (if not already running):
   ```bash
   opensecagent --config ~/.config/opensecagent/config.yaml
   ```
   Or run it in the background / as a service.

2. **In another terminal**, run the CPU stress script (from the repo or copy the script to the server):
   ```bash
   cd /path/to/opensecagent   # or where you copied simulate_attack.py
   python3 scripts/simulate_attack.py cpu 120
   ```
   This runs for 120 seconds (or until you press Ctrl+C). It spawns one process per CPU core to push total CPU above the threshold.

3. **Wait for detection**  
   - If the daemon is running: it checks every `detector_interval_sec` (e.g. 60s). Within 1–2 minutes you should see a **high_cpu** incident.  
   - Or run **manual detect** while the burner is running:
     ```bash
     opensecagent detect
     ```

4. **Expected behaviour**  
   - **Without LLM agent**: You get an audit log entry and (if configured) an **email alert** about high CPU.  
   - **With LLM agent**: The agent runs in “resolve” mode, gets `top_processes` and context, and can run `ps aux` / `docker top`, then **kill -9 <pid>** on the stress process. The burner will stop and you’ll see “Guard active” / resolution in logs or email.

5. **Stop the simulation early**  
   Press **Ctrl+C** in the terminal where `simulate_attack.py` is running.

---

## Test 2: New listening port

Triggers the **new_listening_port** detector (and possibly firewall/nginx checks).

1. Start a temporary listener on a port that’s usually closed:
   ```bash
   python3 -m http.server 9999
   ```
   Or: `nc -l 9999` (leave it running).

2. Run a **host collect** then **detect** so the new port is seen:
   ```bash
   opensecagent collect
   opensecagent detect
   ```
   Or wait for the daemon’s next collector + detector cycle.

3. You should see an incident about **new listening port(s)** and (if configured) an email. The agent may suggest confirming the service or firewalling it.

4. Stop the test: **Ctrl+C** the `http.server` or `nc` process.

---

## Test 3: Suspected PHP malware (if you have a web root)

Triggers the **PHP malware detector** and (if enabled) the agent can suggest removing the file.

1. Create a **fake** PHP file that matches a malware pattern (only for testing):
   ```bash
   echo '<?php eval(base64_decode("dGVzdA==")); ?>' | sudo tee /var/www/html/test_malware_remove_me.php
   ```
   Use a path that’s under `detector.php_scan_paths` (e.g. `/var/www`, `/home`). Adjust if your web root is different.

2. Run detect (or wait for the daemon):
   ```bash
   opensecagent detect
   ```

3. You should get a **php_malware_suspected** incident and (with the agent) a suggestion to remove or quarantine the file.

4. **Clean up**:
   ```bash
   sudo rm /var/www/html/test_malware_remove_me.php
   ```

---

## Quick one-liner (CPU test only)

From the OpenSecAgent repo on the server:

```bash
# Terminal 1
opensecagent --config ~/.config/opensecagent/config.yaml

# Terminal 2
python3 scripts/simulate_attack.py cpu 90
# Wait ~1 min, then check email or logs; agent may kill the script.
```

After the test, check:

- Audit log: `opensecagent export-audit` (or the path in `audit.file`).
- Activity log: `activity.file` in your config.
- Email: if `notifications.admin_emails` and Resend/SMTP are set, you should receive alerts.
