#!/usr/bin/env bash
# End-to-end smoke test for the UOMP Remote Authorization Gateway.

set -e

API_URL="${UOMP_API_URL:-http://127.0.0.1:9374}"
GW_URL="${UOMP_GATEWAY_URL:-https://localhost:9443}"
CERT_DIR="${UOMP_GATEWAY_CERT_DIR:-$HOME/.uomp/.gateway-certs}"

ADMIN_TOKEN_FILE="${UOMP_ADMIN_TOKEN_FILE:-$HOME/.uomp/.secrets/admin-token}"
ADMIN_TOKEN="$(cat "$ADMIN_TOKEN_FILE" 2>/dev/null || true)"
if [ -z "$ADMIN_TOKEN" ]; then
  echo "Admin token not found at $ADMIN_TOKEN_FILE" >&2
  exit 1
fi

echo "==> Creating remote session..."
SESS=$(curl -s -X POST "$API_URL/v1/sessions" \
  -H 'Content-Type: application/json' \
  -H "x-uomp-admin-token: $ADMIN_TOKEN" \
  -d '{
    "agent_id": "stock-analyst",
    "agent_name": "Stock Analyst",
    "requested_scopes": {
      "read": { "tags": ["portfolio:holdings", "risk-profile"], "keys": ["AAPL", "TSLA", "NVDA"], "denyTags": [], "denyKeys": [] },
      "write": { "tags": [], "keys": [], "denyTags": [], "denyKeys": [] }
    },
    "duration_minutes": 30
  }' | jq -r '.session_id')

echo "Session: $SESS"

echo "==> Granting remote token for Gateway..."
GRANT_BODY=$(jq -n \
  --arg audience "$GW_URL" \
  '{granted_scopes: {read: {tags: ["portfolio:holdings", "risk-profile"], keys: ["AAPL", "TSLA", "NVDA"], denyTags: [], denyKeys: []}, write: {tags: [], keys: [], denyTags: [], denyKeys: []}}, profile: "remote", audience: $audience}')
TOKEN=$(curl -s -X POST "$API_URL/v1/sessions/$SESS/grant" \
  -H 'Content-Type: application/json' \
  -H "x-uomp-admin-token: $ADMIN_TOKEN" \
  -d "$GRANT_BODY" | jq -r '.token')

if [ -z "$TOKEN" ] || [ "$TOKEN" = "null" ]; then
  echo "Failed to obtain token"
  exit 1
fi

echo "Token obtained."

echo "==> Querying memory through Gateway (mTLS)..."
curl -s -k --cert "$CERT_DIR/client.crt" --key "$CERT_DIR/client.key" \
  "$GW_URL/v1/memory?tag=portfolio:holdings" \
  -H "Authorization: Bearer $TOKEN" \
  -H "X-UOMP-Agent-Id: stock-analyst" | jq .

echo ""
echo "==> Querying audit trail through Gateway (mTLS)..."
curl -s -k --cert "$CERT_DIR/client.crt" --key "$CERT_DIR/client.key" \
  "$GW_URL/v1/audit?session_id=$SESS" \
  -H "Authorization: Bearer $TOKEN" \
  -H "X-UOMP-Agent-Id: stock-analyst" | jq .
