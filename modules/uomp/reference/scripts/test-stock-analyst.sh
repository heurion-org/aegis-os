#!/usr/bin/env bash
# Full end-to-end test for stock-analyst v0.2
# Covers: local mode + remote Gateway mTLS mode

set -e

API_URL="${UOMP_API_URL:-http://127.0.0.1:9374}"
GW_URL="${UOMP_GATEWAY_URL:-https://localhost:9443}"
UOMP_DIR="$(dirname "$0")/.."

ADMIN_TOKEN_FILE="${UOMP_ADMIN_TOKEN_FILE:-$HOME/.uomp/.secrets/admin-token}"
ADMIN_TOKEN="$(cat "$ADMIN_TOKEN_FILE" 2>/dev/null || true)"
if [ -z "$ADMIN_TOKEN" ]; then
  echo "Admin token not found at $ADMIN_TOKEN_FILE" >&2
  exit 1
fi

echo "═══════════════════════════════════════"
echo "  UOMP Stock Analyst v0.2 E2E Test"
echo "═══════════════════════════════════════"

# ── 1. Import data ──────────────────────────────────────
echo ""
echo "==> Step 1: Import data"
node "$UOMP_DIR/packages/cli/dist/cli.js" import "$UOMP_DIR/examples/stock-analyst/sample-risk.json" --replace
node "$UOMP_DIR/packages/cli/dist/cli.js" import "$UOMP_DIR/examples/stock-analyst/sample-holdings.csv" \
  --tag portfolio:holdings --sensitivity high --replace

# ── 2. Discover Agent ───────────────────────────────────
echo ""
echo "==> Step 2: Discover Agent"
node "$UOMP_DIR/packages/cli/dist/cli.js" discover "$UOMP_DIR/examples/stock-analyst"

# ── 3. Local mode Authorization + Run ───────────────────
echo ""
echo "==> Step 3: Local mode — authorize and run"
node "$UOMP_DIR/packages/cli/dist/cli.js" authorize "$UOMP_DIR/examples/stock-analyst" \
  --scope portfolio:holdings profile:risk --allow-high portfolio:holdings --output /tmp/uomp-test.env --no-server

source /tmp/uomp-test.env
export UOMP_LANG=zh

# Get keys for high-sensitivity authorization
KEYS=$(sqlite3 ~/.uomp/memory.db "SELECT key FROM memory_items WHERE EXISTS (SELECT 1 FROM json_each(tags) WHERE value = 'portfolio:holdings');" | jq -R -s 'split("\n") | map(select(length>0))')

node "$UOMP_DIR/examples/stock-analyst/index.js"
echo "  Local mode: PASS"

# ── 4. Sessions & Audit ─────────────────────────────────
echo ""
echo "==> Step 4: Sessions & Audit"
node "$UOMP_DIR/packages/cli/dist/cli.js" sessions -a | head -n 5
node "$UOMP_DIR/packages/cli/dist/cli.js" audit --limit 3

# ── 5. Remote Gateway mode ──────────────────────────────
echo ""
echo "==> Step 5: Remote Gateway mTLS mode"

# Check Gateway is running
if ! curl -s -k --cert ~/.uomp/.gateway-certs/client.crt --key ~/.uomp/.gateway-certs/client.key "$GW_URL/v1/health" > /dev/null 2>&1; then
  echo "  Gateway not running. Starting..."
  node "$UOMP_DIR/apps/gateway/dist/index.js" &
  GW_PID=$!
  sleep 3
  trap "kill $GW_PID 2>/dev/null" EXIT
fi

SESS=$(curl -s -X POST "$API_URL/v1/sessions" -H 'Content-Type: application/json' \
  -H "x-uomp-admin-token: $ADMIN_TOKEN" \
  -d "{\"agent_id\":\"stock-analyst\",\"agent_name\":\"Stock Analyst\",\"requested_scopes\":{\"read\":{\"tags\":[\"portfolio:holdings\",\"profile:risk\"],\"keys\":$KEYS,\"denyTags\":[],\"denyKeys\":[]},\"write\":{\"tags\":[],\"keys\":[],\"denyTags\":[],\"denyKeys\":[]}},\"duration_minutes\":30}" | jq -r '.session_id')

echo "  Session: $SESS"

GRANT=$(jq -n --arg audience "$GW_URL" --argjson keys "$KEYS" \
  '{granted_scopes:{read:{tags:["portfolio:holdings","profile:risk"],keys:$keys,denyTags:[],denyKeys:[]},write:{tags:[],keys:[],denyTags:[],denyKeys:[]}},profile:"remote",audience:$audience,allowed_fields:["key","value"]}')
TOKEN=$(curl -s -X POST "$API_URL/v1/sessions/$SESS/grant" -H 'Content-Type: application/json' -H "x-uomp-admin-token: $ADMIN_TOKEN" -d "$GRANT" | jq -r '.token')

export UOM_TOKEN="$TOKEN"
export UOMP_BASE_URL="$GW_URL"
export UOMP_SESSION_ID="$SESS"

node "$UOMP_DIR/examples/stock-analyst/index.js"
echo "  Remote mode: PASS"

# ── 6. Verify session closed ────────────────────────────
echo ""
echo "==> Step 6: Verify session state"
STATUS=$(curl -s -X POST "$API_URL/v1/sessions/$SESS/close" | jq -r '.status')
echo "  Session status: $STATUS"

# ── 7. Revoke ───────────────────────────────────────────
echo ""
echo "==> Step 7: Revoke session"
node "$UOMP_DIR/packages/cli/dist/cli.js" revoke "$SESS"

echo ""
echo "═══════════════════════════════════════"
echo "  All tests passed."
echo "═══════════════════════════════════════"
