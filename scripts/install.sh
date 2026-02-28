#!/bin/bash
# OpenSecAgent - Install script (single server)
# Run from repo root or set SOURCE_DIR to extracted tarball path
set -e
SOURCE_DIR="${SOURCE_DIR:-$(cd "$(dirname "$0")/.." && pwd)}"
INSTALL_DIR="${INSTALL_DIR:-/opt/opensecagent}"
CONFIG_DIR="${CONFIG_DIR:-/etc/opensecagent}"
DATA_DIR="${DATA_DIR:-/var/lib/opensecagent}"
LOG_DIR="${LOG_DIR:-/var/log/opensecagent}"
RUN_USER="${RUN_USER:-root}"

echo "Installing OpenSecAgent from $SOURCE_DIR to $INSTALL_DIR"
mkdir -p "$INSTALL_DIR" "$CONFIG_DIR" "$DATA_DIR" "$LOG_DIR"
cp -r "$SOURCE_DIR/opensecagent" "$INSTALL_DIR/"
cp -r "$SOURCE_DIR/config" "$INSTALL_DIR/"
cp "$SOURCE_DIR/requirements.txt" "$INSTALL_DIR/"
[ -f "$SOURCE_DIR/pyproject.toml" ] && cp "$SOURCE_DIR/pyproject.toml" "$INSTALL_DIR/"
if [ ! -f "$CONFIG_DIR/config.yaml" ]; then
  cp "$INSTALL_DIR/config/default.yaml" "$CONFIG_DIR/config.yaml"
  echo "Config copied to $CONFIG_DIR/config.yaml - please edit (admin_emails, smtp, etc.)"
fi
chown -R "$RUN_USER" "$INSTALL_DIR" "$DATA_DIR" "$LOG_DIR"
chown -R "$RUN_USER" "$CONFIG_DIR" 2>/dev/null || true

# systemd
cp "$SOURCE_DIR/systemd/opensecagent.service" /etc/systemd/system/
sed -i "s|%INSTALL_DIR%|$INSTALL_DIR|g" /etc/systemd/system/opensecagent.service
sed -i "s|%CONFIG_DIR%|$CONFIG_DIR|g" /etc/systemd/system/opensecagent.service
systemctl daemon-reload
echo "Enable and start with: systemctl enable opensecagent && systemctl start opensecagent"
echo "Logs: journalctl -u opensecagent -f"
