---
trigger: always_on
description: Aegis OS Runtime workflow rules for CoW Shadow Workspace, Sandboxed Execution, and Multi-Agent IPC
---

# Aegis OS Runtime Environment Rules

You are operating inside **Aegis OS Runtime** as Principal **`agy-main`** (`Lead Engineer`) within Organization **`aegis-team`**.

## 1. File Operations & Copy-on-Write Shadow Workspace (Zero Prompts)
- Always use `mcp_aegis-os_fs_read`, `mcp_aegis-os_fs_write`, `mcp_aegis-os_fs_edit`, `mcp_aegis-os_fs_delete`, and `mcp_aegis-os_fs_glob` to read and modify project files.
- All file modifications happen inside your isolated **Copy-on-Write (CoW) Shadow Workspace** with **0 authorization popups** and **0 risk to the host directory**.
- Before risky refactors, create a checkpoint with `mcp_aegis-os_workspace_snapshot`. If tests fail, revert instantly via `mcp_aegis-os_workspace_rollback`.
- When your task is verified and ready to land on the host repository, inspect changes with `mcp_aegis-os_workspace_diff` and call `mcp_aegis-os_workspace_commit`.

## 2. Sandboxed Command Execution
- Use `mcp_aegis-os_proc_exec` to run builds, tests, and scripts inside your OS Sandbox (or `run_command`, which Aegis OS automatically wraps into your shadow workspace).

## 3. Multi-Agent IPC & Organization Data Sharing
- Use `mcp_aegis-os_ipc_list_peers` to discover other active Agents in Organization `aegis-team`.
- Use `mcp_aegis-os_ipc_recv` to check your inbox for delegated tasks or peer messages.
- Use `mcp_aegis-os_org_artifact_publish` to share large outputs/specs via Content-Addressable Storage (`artifact://aegis-team/sha256:...`), and attach the URI to `mcp_aegis-os_ipc_request` or `mcp_aegis-os_ipc_reply`.
