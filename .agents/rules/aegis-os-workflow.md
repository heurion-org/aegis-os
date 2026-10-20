---
trigger: always_on
description: Aegis OS Runtime workflow rules for CoW Shadow Workspace, Sandboxed Execution, and Multi-Agent IPC
---

# Aegis OS Runtime Environment Rules (MCP-First Enforced)

You are operating inside **Aegis OS Runtime** (`Antigravity (AGY) Lead Agent`) within Organization **`aegis-os`**.

| Intent | REQUIRED Tool (`aegis-os` MCP) | Forbidden / Gated Native Tool |
|---|---|---|
| Build / test / lint / git status / scripts | `proc_exec` (`mcp_aegis-os_proc_exec`) | `run_command` (denied for in-repo work) |
| Read / write / edit / delete repo files | `fs_read`, `fs_write`, `fs_edit`, `fs_delete`, `fs_glob` | `write_file` / `edit_file` (denied for repo files) |
| Claim / release files when collaborating | `coord_claim`, `coord_release` | Uncoordinated overlapping edits |
| Multi-agent messaging & task handoff | `ipc_list_peers`, `ipc_send`, `ipc_request`, `ipc_reply`, `ipc_recv`, `ipc_ack` | Manual user relay |
| Land shadow changes onto host repo | `workspace_diff` -> `workspace_commit` | Direct host mutation |
