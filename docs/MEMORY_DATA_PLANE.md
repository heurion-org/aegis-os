# Aegis Memory Data Plane

`crates/aos-memory-store` is the Rust-side foundation for moving the UOMP memory store and Markdown connector into Aegis OS.

## Status

Implemented:

- SQLite schema compatible with `uomp-mvp` (`memory_items`).
- `get`, `get_by_tag`, `set`, `delete`, `list_tags`, `count`.
- Markdown directory import with path-derived tags:
  - `projects/uomp/plan.md` → `notes`, `notes/projects`, `notes/projects/uomp`.
- Frontmatter `sensitivity: high|medium|low` parsing.
- Skips `.obsidian`, hidden directories, and `node_modules`.

Not yet wired:

- The Aegis Memory Gateway still forwards requests to the local UOMP Guard.
- CSV/JSON and richer connectors remain in `uomp-mvp`.
- Staged writes and payloads are still handled by UOMP Guard.
- The Aegis policy/lease layer does not yet read directly from `aos-memory-store`.

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

## Next steps

1. Add a `MemoryDataPlane` trait and make `SqliteMemoryStore` one implementation.
2. Port CSV/JSON import.
3. Move staged writes and payload metadata into the Aegis data plane.
4. Replace the Gateway's UOMP Guard proxy with the native data plane.
5. Keep `uomp-mvp` as the reference connector/CLI until parity is reached.

## Test

```bash
cargo test -p aos-memory-store
```

Current tests cover:

- set/get/get_by_tag/list_tags/delete
- Markdown import with path tags and high sensitivity
- hidden directory skipping
