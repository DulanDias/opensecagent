# OpenSecAgent – Deploy to 192.168.1.50

## One-time setup

1. **Copy project to server**
   ```bash
   cd /path/to/opensecagent
   tar czf /tmp/opensecagent.tar.gz opensecagent config requirements.txt scripts systemd README.md
   sshpass -p 'YOUR_PASSWORD' scp -o StrictHostKeyChecking=no /tmp/opensecagent.tar.gz dulan@192.168.1.50:/tmp/
   ```

2. **On server: extract and install**
   ```bash
   ssh dulan@192.168.1.50
   cd /tmp && tar xzf opensecagent.tar.gz
   python3 -m venv .venv && .venv/bin/pip install -r requirements.txt
   ```

3. **Run with test config (no root)**
   ```bash
   export PYTHONPATH=/tmp
   .venv/bin/python -m opensecagent.main --config /tmp/config/test.yaml
   ```
   Or use CLI:
   ```bash
   .venv/bin/python -m opensecagent.cli --config /tmp/config/test.yaml collect
   .venv/bin/python -m opensecagent.cli --config /tmp/config/test.yaml drift
   .venv/bin/python -m opensecagent.cli --config /tmp/config/test.yaml detect
   .venv/bin/python -m opensecagent.cli --config /tmp/config/test.yaml export-audit -p /tmp/opensecagent_log/audit.jsonl
   ```

4. **Production install (root)**
   ```bash
   sudo SOURCE_DIR=/tmp bash /tmp/scripts/install.sh
   sudo vi /etc/opensecagent/config.yaml   # set admin_emails, smtp
   sudo systemctl enable opensecagent && sudo systemctl start opensecagent
   sudo journalctl -u opensecagent -f
   ```

## Verified on 192.168.1.50

- **Collect**: Host inventory (OS, packages, services, ports, sudo users) and Docker inventory (containers, images) run successfully.
- **Drift**: Baseline creation and change detection (e.g. `/tmp/opensecagent_critical_test`) produce drift events.
- **Detect**: Auth/ports/containers/admin detectors run (no events when no prior state).
- **Daemon**: Full pipeline (drift → incident → audit log) verified; incidents appear in `/tmp/opensecagent_log/audit.jsonl`.
- **Export**: `export-audit` outputs audit log as JSON.
