# UOMP Browser Dashboard (historical)

> **Deprecated (2026-10):** This example depended on `uomp gateway start --browser`, which is retired. It is kept as a historical reference. Remote Agents now use Aegis Cloud + Aegis Memory Gateway.

A zero-install portfolio dashboard that runs entirely in the browser. No CLI, no pnpm, no server-side code.

## Quick Start

```bash
# 1. Start Gateway with CORS for browser access
uomp gateway start --browser

# 2. Authorize
pnpm cli authorize ./examples/stock-analyst \
  --scope portfolio:holdings profile:risk \
  --allow-high portfolio:holdings \
  --output /tmp/uomp.env --no-server
source /tmp/uomp.env

# 3. Open the dashboard
#    Paste UOMP_BASE_URL into "Gateway URL"
#    Paste UOM_TOKEN into "Capability Token"
#    Click Connect
```

Or use a shareable link:

```
file:///path/to/examples/browser-dashboard/index.html#token=<UOM_TOKEN>&gateway=<UOMP_BASE_URL>
```

## What it shows

- Portfolio summary (total value, P&L, HHI, position count, risk profile)
- Holdings table (symbol, name, quantity, cost, price, P&L, weight, sector)
- Sector allocation bar chart
- Stop-loss / take-profit signals

## Architecture

```
Browser Dashboard ──HTTPS──► Gateway (CORS) ──► Memory Guard ──► SQLite
     ↑                          ↑
  Token from              uomp gateway start --browser
  uomp authorize
```
