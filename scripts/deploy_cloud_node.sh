#!/usr/bin/env bash
# Turnkey Production Deployment Script for an Aegis Cloud PaaS Node (Ubuntu 22.04 / 24.04 LTS)
# Usage on any fresh Linux VPS (Hetzner / AWS / GCP / DigitalOcean):
#   sudo DOMAIN="cloud.yourdomain.com" POLAR_WEBHOOK_SECRET="whsec_..." bash scripts/deploy_cloud_node.sh
set -euo pipefail

DOMAIN="${DOMAIN:-}"
POLAR_WEBHOOK_SECRET="${POLAR_WEBHOOK_SECRET:-}"
PORT="${PORT:-17080}"
BTRFS_SIZE_GB="${BTRFS_SIZE_GB:-40}"
DATA_ROOT="/mnt/btrfs/aegis-cloud"

echo "==> [1/6] Installing Linux sandbox & CoW dependencies (bubblewrap, btrfs-progs, git, curl)..."
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq bubblewrap btrfs-progs git curl ca-certificates build-essential pkg-config libssl-dev

echo "==> [2/6] Provisioning Btrfs FICLONE Copy-on-Write volume at /mnt/btrfs (${BTRFS_SIZE_GB}G)..."
mkdir -p /mnt/btrfs
if ! mountpoint -q /mnt/btrfs; then
  BTRFS_IMG="/var/lib/aegis-btrfs.img"
  if [[ ! -f "${BTRFS_IMG}" ]]; then
    fallocate -l "${BTRFS_SIZE_GB}G" "${BTRFS_IMG}"
    mkfs.btrfs -f "${BTRFS_IMG}"
  fi
  mount -o loop,compress=zstd "${BTRFS_IMG}" /mnt/btrfs
  if ! grep -q "${BTRFS_IMG}" /etc/fstab; then
    echo "${BTRFS_IMG} /mnt/btrfs btrfs loop,compress=zstd,defaults 0 0" >> /etc/fstab
  fi
fi
mkdir -p "${DATA_ROOT}/default_workspace"

echo "==> [3/6] Installing Aegis OS binary (/usr/local/bin/aegis-os)..."
if [[ -f "./target/release/aegis-os" ]]; then
  cp ./target/release/aegis-os /usr/local/bin/aegis-os
else
  if ! command -v cargo >/dev/null 2>&1; then
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
    source "$HOME/.cargo/env"
  fi
  cargo build --release -p aos-cli
  cp ./target/release/aegis-os /usr/local/bin/aegis-os
fi
chmod +x /usr/local/bin/aegis-os
ln -sf /usr/local/bin/aegis-os /usr/local/bin/aos

echo "==> [4/6] Configuring systemd service (aegis-cloud.service on 127.0.0.1:${PORT})..."
cat > /etc/systemd/system/aegis-cloud.service <<EOF
[Unit]
Description=Aegis OS Multi-Tenant Cloud Sandbox PaaS Daemon
After=network.target

[Service]
Type=simple
WorkingDirectory=${DATA_ROOT}
Environment="AOS_REQUIRE_API_KEY=1"
Environment="AOS_BILLING_WEBHOOK_SECRET=${POLAR_WEBHOOK_SECRET}"
Environment="AOS_CHECKOUT_URL_PRO=https://buy.polar.sh/polar_cl_jCPpzbp4eOAyRbkDP4YzNIFVnYLddbvJZI5Fc27zL0x"
ExecStart=/usr/local/bin/aegis-os --runtime-dir ${DATA_ROOT} --workspace ${DATA_ROOT}/default_workspace daemon --bind 0.0.0.0:${PORT}
Restart=always
RestartSec=2
LimitNOFILE=65535

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable --now aegis-cloud.service

if [[ -n "${DOMAIN}" ]]; then
  echo "==> [5/6] Installing Caddy and enabling automatic HTTPS for https://${DOMAIN}..."
  apt-get install -y -qq debian-keyring debian-archive-keyring apt-transport-https
  curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/gpg.key' | gpg --dearmor -o /usr/share/keyrings/caddy-stable-archive-keyring.gpg --yes
  curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/debian.deb.txt' | tee /etc/apt/sources.list.d/caddy-stable.list >/dev/null
  apt-get update -qq && apt-get install -y -qq caddy
  cat > /etc/caddy/Caddyfile <<EOF
${DOMAIN} {
    reverse_proxy 127.0.0.1:${PORT}
}
EOF
  systemctl reload caddy || systemctl restart caddy
else
  echo "==> [5/6] (Optional) Set DOMAIN=cloud.yourdomain.com to auto-configure Caddy HTTPS."
fi

echo "==> [6/6] Verifying Aegis Cloud Node health..."
sleep 1
curl -sS "http://127.0.0.1:${PORT}/health"
echo ""
echo "=================================================================="
echo "Aegis Cloud PaaS Node is LIVE!"
if [[ -n "${DOMAIN}" ]]; then
  echo "  Public Endpoint : https://${DOMAIN}"
  echo "  Polar Webhook   : https://${DOMAIN}/v1/billing/webhook"
  echo "  Web Console     : https://${DOMAIN}/dashboard"
else
  echo "  Local Endpoint  : http://127.0.0.1:${PORT}"
fi
echo "=================================================================="
