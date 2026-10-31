# Aegis Memory Data Plane

`crates/aos-memory-store` is the native Rust data plane for UOMP memory. It is used by the CLI, the MCP bridge, and the native consent server.

## Status

Implemented:

- SQLite schema compatible with the historical UOMP store (`memory_items`).
- `get`, `get_by_tag`, `set`, `delete`, `list_tags`, `count`.
- Markdown directory import with path-derived tags:
  - `projects/uomp/plan.md` → `notes`, `notes/projects`, `notes/projects/uomp`.
- Frontmatter `sensitivity: high|medium|low` parsing.
- Skips `.obsidian`, hidden directories, and `node_modules`.
- Staged Agent writes with user approval (`staged_writes`).
- Encrypted payload envelopes (`payloads`).
- Native consent server (`aos-memory-server`) with sessions, Ed25519 JWT issuance, consent requests, revocation, and audit.

The CLI entry point is `aegis-os memory ...`. `status`, `import`, `read`, `list`, `search`, `serve`, `setup`, `pending`, `approve`, `deny`, `connect`, `disconnect`, `sessions`, `revoke`, `audit`, `approvals`, `stop`, `staged`, `payload`, and `mcp` are all native. The archived `uomp-core` / `uomp-mvp` reference is not vendored or invoked.

## Why the schema is compatible

The table is intentionally the same shape as UOMP's `memory_items`:

```sql
CREATE TABLE memory_items (
  key TEXT PRIMARY KEY,
  value TEXT NOT NULL,
  tags TEXT NOT NULL,
  sensitivity TEXT NOT NULL,
  source TEXT NOT NULL,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  description TEXT
);
```

This lets Aegis open an existing `~/.uomp/memory.db` without a destructive migration.

## Consent and audit

`aegis-os memory serve` opens the local auth DB (`~/.uomp/auth.db`), issues short-lived Ed25519 tokens after approval, and records read/write decisions in `audit_logs`. `aegis-os memory mcp` uses `UOMP_BRIDGE_FILE` to request consent on the first tool call, polls the request status, then verifies the returned token locally. Every MCP tool call posts an audit event back to the server.

High-sensitivity writes are denied at the server boundary. Staged writes require a separate user approval.

A2A tasks can bind memory sessions: `consent_requests.task_id` and `sessions.task_id` are carried through approval, so `aegis-os memory pending` shows the task context and `memory sessions` shows the task context. When a task reaches a terminal state, the gateway calls `POST /v1/sessions/revoke-by-task` (configured with `AOS_MEMORY_URL` + `AOS_MEMORY_TASK_SECRET`; `AOS_MEMORY_BRIDGE_TOKEN` is the legacy fallback) to revoke its memory sessions. The task-scoped token is an HMAC over `task_id:timestamp`, valid for 120 seconds and only for that task. Audit events carry `task_id`; `aegis-os memory sessions --task-id <id>` filters sessions by task. In the other direction, `aegis-os memory revoke <session-id>` returns the bound `task_id` and asks the local A2A store to move that task to `input-required`.

## Next steps

1. Add CSV/JSON import connectors.
2. Add the browser consent page (CLI approval is the current path).
3. Add deletion proof / retention policy.
4. Wire the policy/lease layer to read directly from `aos-memory-store`.

## Test

```bash
cargo test -p aos-memory-store
cargo test -p aos-memory-server
cargo test -p aos-ipc --test multi_process
```

Current tests cover:

- set/get/get_by_tag/list_tags/delete
- Markdown import with path tags and high sensitivity
- hidden directory skipping
- native auth, consent, memory, staged writes, payloads, and audit
