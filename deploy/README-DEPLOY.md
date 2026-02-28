# Deploy OpenSecAgent to 192.168.1.50

SSH from your machine requires key-based auth or a password. Use one of the options below.

## Option A: Copy project and run install on the server

1. **Copy the project to the server** (from your Mac, with SSH access):
   ```bash
   rsync -avz --exclude=.venv --exclude=.git --exclude=__pycache__ \
     /Users/dulandias/Documents/opensecagent/ \
     ivan@192.168.1.50:/opt/opensecagent/
   ```
   Or use `scp -r`; replace `ivan` with your username on 192.168.1.50.

2. **Copy the pre-filled config** (OpenAI + Resend already set):
   ```bash
   scp deploy/config-home-server.yaml ivan@192.168.1.50:/etc/opensecagent/config.yaml
   ```
   Create the dir first if needed: `ssh ivan@192.168.1.50 "sudo mkdir -p /etc/opensecagent /var/lib/opensecagent /var/log/opensecagent"`

3. **On the server**, install and start:
   ```bash
   ssh ivan@192.168.1.50
   cd /opt/opensecagent
   sudo mkdir -p /etc/opensecagent /var/lib/opensecagent /var/log/opensecagent
   sudo cp deploy/config-home-server.yaml /etc/opensecagent/config.yaml
   # Edit to add your admin email: sudo nano /etc/opensecagent/config.yaml  → notifications.admin_emails: ["your@email.com"]
   python3 -m venv .venv && .venv/bin/pip install -r requirements.txt
   # Install systemd and start:
   sudo deploy/install-on-server.sh
   ```

4. **Add your admin email** so alerts are sent to you:
   ```bash
   sudo nano /etc/opensecagent/config.yaml
   # Set: admin_emails: ["your@email.com"] under notifications
   sudo systemctl restart opensecagent
   ```

## Option B: Run setup wizard on the server

After copying the project and config:

```bash
ssh ivan@192.168.1.50
cd /opt/opensecagent
.venv/bin/python -m opensecagent.main wizard
```

The wizard will ask for paths, **scan frequency** (Quick / Standard / Deep), **Resend** (API key and from address are pre-filled if you use config-home-server.yaml), and **OpenAI** API key. You can accept defaults or change them.

## Scan frequency levels (in wizard and config)

- **Quick**: Host/drift every 10 min, Docker every 2 min, LLM scan every 2 h.
- **Standard**: Host/drift every 5 min, Docker every 1 min, LLM scan every 1 h.
- **Deep**: Host/drift every 3 min, Docker every 45 s, LLM scan every 30 min.

Set `scan_level: quick|standard|deep` in config, or leave empty and set `collector.*` and `llm_agent.run_interval_sec` manually.

## Pre-filled config (config-home-server.yaml)

- **Email**: Resend with `alerts@home.dulandias.com` and the provided API key.
- **LLM**: OpenAI with the provided key; agent enabled; periodic scan every 3600 s.
- **Scan level**: `standard`.

**Important**: Add `notifications.admin_emails: ["your@email.com"]` so you receive alerts. Consider rotating the API key after deployment if this repo is shared.

## Commands on the server

- Status: `sudo systemctl status opensecagent`
- Logs: `journalctl -u opensecagent -f`
- Restart: `sudo systemctl restart opensecagent`
