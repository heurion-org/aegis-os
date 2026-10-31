# UOMP module

UOMP (User-Owned Memory Protocol) is the **memory consent module** of Aegis OS.

- **Protocol site:** <https://www.uomp.org/>
- **Protocol spec:** <https://www.uomp.org/spec/>
- **Native crates:**
  - `crates/aos-memory` — scope/lease mapping, deny/field filtering, remote token policy
  - `crates/aos-memory-store` — SQLite data plane, staged writes, payloads, Markdown importer
  - `crates/aos-memory-server` — native consent/auth server, session and audit store
  - `crates/aos-memory-gateway` — TLS/mTLS remote Agent gateway
- **CLI:** `aegis-os memory ...`
- **Website repository:** the separate `uomp` repository is documentation/website only.

## Role in Aegis OS

UOMP defines how an Agent asks for personal memory: scope, duration, revocation, and audit. Aegis OS enforces those semantics with policy, leases, sandboxing, trusted approval, and the native memory data plane.

```text
Agent
  │  UOMP request (scope, consent, lease)
  ▼
Aegis OS
  ├─ policy / lease / approval
  ├─ memory server (consent, sessions, tokens, audit)
  ├─ memory store (SQLite + Markdown connector + staged writes + payloads)
  ├─ memory gateway (remote Agent entry point)
  └─ audit
```

## Native status

Native parity is complete. The archived `uomp-core` / `uomp-mvp` reference is no longer vendored or invoked at runtime; `aegis-os` is the only product CLI entry point.

```bash
aegis-os memory serve                 # start the local consent/auth server
aegis-os memory setup claude --vault ~/Notes
aegis-os memory pending               # review consent requests
aegis-os memory approve <request-id>  # approve one request
aegis-os memory deny <request-id>
aegis-os memory sessions              # list sessions
aegis-os memory revoke <session-id>   # revoke one session; bound A2A task -> input-required
aegis-os memory audit                 # show the access audit log
aegis-os memory status
aegis-os memory import ~/Notes
aegis-os memory read <key>
aegis-os memory list --tag notes
aegis-os memory search <query>
aegis-os memory staged list
aegis-os memory payload list
aegis-os memory mcp                   # MCP stdio bridge
```

Agent-first consent: `memory setup` writes a bridge profile, not a pre-authorized token. The first `memory mcp` tool call creates a consent request and waits; the user approves it with `aegis-os memory approve`. High-sensitivity items stay outside Agent scopes, and no Agent can approve its own request. Consent requests and sessions carry an optional `task_id`; terminal A2A tasks revoke their memory sessions, and revoking a session moves its bound task to `input-required`.

The browser consent page is deferred. CLI approval is the native approval path for now.
