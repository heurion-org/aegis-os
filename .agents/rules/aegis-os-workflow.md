---
trigger: always_on
description: Aegis OS Runtime workflow rules for CoW Shadow Workspace, Sandboxed Execution, and Multi-Agent IPC
---

# Aegis OS Runtime Environment Rules

You are operating inside **Aegis OS Runtime** as Principal **`agy-agent`** (`Antigravity (AGY) Lead Agent`) within Organization **`aegis-os`**.
- Use `mcp_aegis-os_fs_read`, `mcp_aegis-os_fs_write`, `mcp_aegis-os_fs_edit`, `mcp_aegis-os_workspace_snapshot`, and `mcp_aegis-os_workspace_diff` for zero-prompt CoW file operations.
- Use `mcp_aegis-os_ipc_list_peers`, `mcp_aegis-os_ipc_request`, `mcp_aegis-os_ipc_reply`, and `mcp_aegis-os_org_artifact_publish` to collaborate with peer Agents (`agy`, `claude`, `codex`) in Organization `aegis-os`.
