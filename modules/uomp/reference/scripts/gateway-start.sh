#!/usr/bin/env bash
# Start UOMP Gateway with Cloudflare Tunnel for public access.
# Usage: ./scripts/gateway-start.sh [--no-tunnel]

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_DIR="$(dirname "$SCRIPT_DIR")"

GATEWAY_PORT="${UOMP_GATEWAY_PORT:-9443}"
GATEWAY_HOST="${UOMP_GATEWAY_HOST:-0.0.0.0}"

# ── Find cloudflared ───────────────────────────────────────
find_cloudflared() {
  for bin in cloudflared ~/.local/bin/cloudflared /usr/local/bin/cloudflared; do
    if command -v "$bin" >/dev/null 2>&1; then echo "$bin"; return; fi
    if [ -x "$bin" ]; then echo "$bin"; return; fi
  done
  return 1
}

# ── Install cloudflared if missing ─────────────────────────
CF=$(find_cloudflared 2>/dev/null) || true
if [ -z "$CF" ]; then
  echo "cloudflared not found. Installing..."
  CF_BIN="$HOME/.local/bin/cloudflared"
  mkdir -p "$(dirname "$CF_BIN")"
  curl -sL -o "$CF_BIN" https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-amd64
  chmod +x "$CF_BIN"
  CF="$CF_BIN"
  echo "  ✓ installed to $CF"
fi

# ── Start Gateway ──────────────────────────────────────────
echo "═══ UOMP Gateway ═══"
echo ""

node "$REPO_DIR/apps/gateway/dist/index.js" &
GW_PID=$!
sleep 2

# ── Start Cloudflare Tunnel ────────────────────────────────
echo ""
echo "Starting Cloudflare Tunnel..."
echo ""

$CF tunnel --url "http://127.0.0.1:$GATEWAY_PORT" 2>&1 | while IFS= read -r line; do
  echo "  $line"

  # Extract the trycloudflare.com URL
  if echo "$line" | grep -q 'trycloudflare\.com'; then
    URL=$(echo "$line" | grep -o 'https://[a-z0-9-]*\.trycloudflare\.com' | head -1)
    if [ -n "$URL" ]; then
      echo ""
      echo "═══ Public Gateway URL ═══"
      echo "  $URL"
      echo ""
      echo "Copy this URL as your Gateway endpoint:"
      echo "  export UOMP_BASE_URL=\"$URL\""
      echo ""
      echo "For remote-profile.json:"
      echo "  { \"gateway\": { \"endpoint\": \"$URL\" } }"
      echo ""
      echo "For DO Agent:"
      echo "  curl -X POST https://uomp-stock-analyst-mvblm.ondigitalocean.app/analyze \\"
      echo "    -H 'Content-Type: application/json' \\"
      echo "    -d '{\"token\":\"...\",\"gateway_url\":\"$URL\"}'"
      echo ""
      echo "══════════════════════════"
    fi
  fi
done &

CF_PID=$!

# ── Cleanup ────────────────────────────────────────────────
cleanup() {
  echo ""
  echo "Shutting down..."
  kill $GW_PID 2>/dev/null
  kill $CF_PID 2>/dev/null
  exit 0
}
trap cleanup INT TERM

wait $GW_PID
