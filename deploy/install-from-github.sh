#!/usr/bin/env bash
# OpenSecAgent - Install from GitHub on a fresh server
# Run on the server (e.g. 192.168.1.50). Uses your GitHub repo; no local copy needed.
#
# Usage:
#   curl -sSL https://raw.githubusercontent.com/DulanDias/opensecagent/main/deploy/install-from-github.sh | sudo bash
# Or clone first then:
#   sudo ./deploy/install-from-github.sh
#
# Optionally override (before running):
#   export INSTALL_DIR=/opt/opensecagent
#   export CONFIG_DIR=/etc/opensecagent
#   export OPENSECAGENT_REPO=git@github.com:DulanDias/opensecagent.git
#   export OPENSECAGENT_BRANCH=main

set -e
INSTALL_DIR="${INSTALL_DIR:-/opt/opensecagent}"
CONFIG_DIR="${CONFIG_DIR:-/etc/opensecagent}"
DATA_DIR="${DATA_DIR:-/var/lib/opensecagent}"
LOG_DIR="${LOG_DIR:-/var/log/opensecagent}"
REPO="${OPENSECAGENT_REPO:-https://github.com/DulanDias/opensecagent.git}"
BRANCH="${OPENSECAGENT_BRANCH:-main}"

echo "OpenSecAgent — install from GitHub"
echo "  Repo:   $REPO"
echo "  Branch: $BRANCH"
echo "  Install: $INSTALL_DIR"
echo "  Config:  $CONFIG_DIR"

# Clone or update
if [ -d "$INSTALL_DIR/.git" ]; then
  echo "Updating existing clone..."
  cd "$INSTALL_DIR"
  git fetch origin
  git checkout "$BRANCH" 2>/dev/null || true
  git pull origin "$BRANCH" || true
else
  echo "Cloning..."
  rm -rf "$INSTALL_DIR"
  git clone --depth 1 --branch "$BRANCH" "$REPO" "$INSTALL_DIR"
  cd "$INSTALL_DIR"
fi

mkdir -p "$CONFIG_DIR" "$DATA_DIR" "$LOG_DIR"

# Create default config if missing
if [ ! -f "$CONFIG_DIR/config.yaml" ]; then
  echo "Creating default config at $CONFIG_DIR/config.yaml"
  cp config/default.yaml "$CONFIG_DIR/config.yaml" 2>/dev/null || true
  # Merge in agent paths
  if command -v python3 &>/dev/null; then
    python3 -c "
import yaml
from pathlib import Path
p = Path('$CONFIG_DIR/config.yaml')
if p.exists():
    c = yaml.safe_load(p.read_text()) or {}
    c.setdefault('agent', {})['data_dir'] = '$DATA_DIR'
    c.setdefault('agent', {})['log_dir'] = '$LOG_DIR'
    c.setdefault('audit', {})['file'] = '$LOG_DIR/audit.jsonl'
    c.setdefault('activity', {})['file'] = '$LOG_DIR/activity.jsonl'
    c.setdefault('activity', {})['log_dir'] = '$LOG_DIR'
    p.write_text(yaml.dump(c, default_flow_style=False, allow_unicode=True, sort_keys=False))
" 2>/dev/null || true
  fi
  echo "  Edit $CONFIG_DIR/config.yaml to set API keys and notifications.admin_emails, then run: sudo systemctl restart opensecagent"
fi

# Venv and install
echo "Installing dependencies..."
python3 -m venv .venv 2>/dev/null || true
.venv/bin/pip install -q -r requirements.txt
.venv/bin/pip install -q -e . 2>/dev/null || .venv/bin/pip install -q .

# Systemd unit
UNIT="/etc/systemd/system/opensecagent.service"
PYTHON_EXEC="$INSTALL_DIR/.venv/bin/python"
cat > "$UNIT" << EOF
[Unit]
Description=OpenSecAgent - Autonomous Server Cybersecurity Expert Bot
After=network-online.target docker.service
Wants=network-online.target

[Service]
Type=simple
ExecStart=$PYTHON_EXEC -m opensecagent.main --config $CONFIG_DIR/config.yaml
WorkingDirectory=$INSTALL_DIR
Restart=on-failure
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable opensecagent
systemctl start opensecagent
echo ""
echo "Installed and started. Status:"
systemctl status opensecagent --no-pager || true
echo ""
echo "Next: edit $CONFIG_DIR/config.yaml (API keys, notifications.admin_emails). Then: sudo systemctl restart opensecagent"
echo "Logs: journalctl -u opensecagent -f"
