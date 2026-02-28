#!/usr/bin/env bash
# OpenSecAgent - Install and run on a Linux server
# Run this script ON THE TARGET SERVER (e.g. after copying project or cloning).
# Usage: sudo ./deploy/install-on-server.sh

set -e
INSTALL_DIR="${INSTALL_DIR:-/opt/opensecagent}"
CONFIG_DIR="${CONFIG_DIR:-/etc/opensecagent}"
DATA_DIR="${DATA_DIR:-/var/lib/opensecagent}"
LOG_DIR="${LOG_DIR:-/var/log/opensecagent}"

echo "OpenSecAgent install: $INSTALL_DIR"

# If we're inside the project, use it; else expect $INSTALL_DIR to exist with code
if [ -f "pyproject.toml" ] || [ -f "setup.py" ]; then
  SRC="$(pwd)"
  mkdir -p "$INSTALL_DIR"
  rsync -a --exclude=.git --exclude=.venv --exclude=__pycache__ "$SRC/" "$INSTALL_DIR/" 2>/dev/null || cp -a . "$INSTALL_DIR/"
  cd "$INSTALL_DIR"
fi

mkdir -p "$CONFIG_DIR" "$DATA_DIR" "$LOG_DIR"

if [ ! -f "$CONFIG_DIR/config.yaml" ]; then
  echo "Creating default config at $CONFIG_DIR/config.yaml"
  python3 -m opensecagent.main setup --config-dir "$CONFIG_DIR" --data-dir "$DATA_DIR" --log-dir "$LOG_DIR" 2>/dev/null || true
fi

# Install package and deps
if [ -f "requirements.txt" ]; then
  python3 -m venv .venv 2>/dev/null || true
  .venv/bin/pip install -q -r requirements.txt
fi
if [ -f "pyproject.toml" ]; then
  .venv/bin/pip install -q -e . 2>/dev/null || .venv/bin/pip install -q .
fi

# Install systemd unit
UNIT="/etc/systemd/system/opensecagent.service"
if [ -f "$INSTALL_DIR/.venv/bin/python" ]; then
  PYTHON_EXEC="$INSTALL_DIR/.venv/bin/python"
else
  PYTHON_EXEC="$(command -v python3)"
fi
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
echo "Installed. Status: systemctl status opensecagent"
systemctl status opensecagent --no-pager || true
