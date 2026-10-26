#!/usr/bin/env bash
# One-time (idempotent) preparation of an Aegis Cloud node for CI deploys. Run as root on the node:
#
#   bash bootstrap_server.sh <release_signer_line> <deploy_ssh_public_key>
#
# - installs /usr/local/sbin/aegis-upgrade (from this directory)
# - pins the release public key in /etc/aegis-cloud/release_signer
# - moves daemon secrets out of the world-readable unit into /etc/aegis-cloud/env (0600) and gives
#   the daemon a stable AOS_ADMIN_SECRET (otherwise a random operator token is generated per start)
# - rewrites the systemd unit to use that EnvironmentFile (restart needed to take effect)
# - authorizes the deploy key for root with `aegis-upgrade` as its forced command only
set -euo pipefail

SIGNER_LINE="$1"
DEPLOY_PUBKEY="$2"
HERE="$(cd "$(dirname "$0")" && pwd)"
CONF_DIR=/etc/aegis-cloud
UNIT=/etc/systemd/system/aegis-cloud.service
DATA_ROOT="${DATA_ROOT:-/mnt/btrfs/aegis-cloud}"
PORT="${PORT:-17080}"
# 0.0.0.0 so the Caddy container can reach the daemon over the Docker bridge; ufw must keep the
# port closed to anything but the Docker networks.
LISTEN="${LISTEN:-0.0.0.0:${PORT}}"

[[ $EUID -eq 0 ]] || { echo "run as root" >&2; exit 1; }
[[ "$SIGNER_LINE" == "aegis-os-release@heurion.org ssh-ed25519 "* ]] || { echo "bad release signer line" >&2; exit 1; }
[[ "$DEPLOY_PUBKEY" == ssh-ed25519\ * ]] || { echo "deploy key must be ssh-ed25519" >&2; exit 1; }

install -d -m 0755 "$CONF_DIR"
install -m 0755 "$HERE/aegis-upgrade" /usr/local/sbin/aegis-upgrade
printf '%s\n' "$SIGNER_LINE" > "$CONF_DIR/release_signer"
chmod 0644 "$CONF_DIR/release_signer"

# Secrets: carry over values currently inlined in the unit, add a stable admin secret.
if [[ ! -f "$CONF_DIR/env" ]]; then
  umask 077
  {
    if [[ -f "$UNIT" ]]; then
      sed -n 's/^Environment="\(AOS_[A-Z_]*=.*\)"$/\1/p' "$UNIT" | grep -v '^AOS_REQUIRE_API_KEY=' || true
    fi
    echo "AOS_ADMIN_SECRET=$(openssl rand -hex 32)"
  } > "$CONF_DIR/env"
  umask 022
  echo "created $CONF_DIR/env (0600); operator token = AOS_ADMIN_SECRET in that file"
fi
chmod 0600 "$CONF_DIR/env"

cat > "$UNIT" <<EOF
[Unit]
Description=Aegis OS Multi-Tenant Cloud Sandbox PaaS Daemon
After=network.target

[Service]
Type=simple
WorkingDirectory=${DATA_ROOT}
EnvironmentFile=${CONF_DIR}/env
ExecStart=/usr/local/bin/aegis-os --runtime-dir ${DATA_ROOT} --workspace ${DATA_ROOT}/default_workspace daemon --listen ${LISTEN}
Restart=always
RestartSec=2
LimitNOFILE=65535

[Install]
WantedBy=multi-user.target
EOF
chmod 0644 "$UNIT"
systemctl daemon-reload

AUTH=/root/.ssh/authorized_keys
install -d -m 0700 /root/.ssh
touch "$AUTH" && chmod 0600 "$AUTH"
KEY_BODY="$(echo "$DEPLOY_PUBKEY" | awk '{print $2}')"
if ! grep -q "$KEY_BODY" "$AUTH"; then
  echo "command=\"/usr/local/sbin/aegis-upgrade\",no-port-forwarding,no-X11-forwarding,no-agent-forwarding,no-pty,no-user-rc $DEPLOY_PUBKEY" >> "$AUTH"
  echo "authorized deploy key (forced command: aegis-upgrade)"
fi

echo "bootstrap done. Restart to load the new unit: systemctl restart aegis-cloud"
