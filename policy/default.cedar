// Aegis OS Default Baseline Policy (Cedar Syntax)
// 1. Auto-permit all VFS operations within the Agent's own CoW Shadow Workspace and private Home directory
permit (
    principal is Agent,
    action in [
        Action::"fs_read",
        Action::"fs_write",
        Action::"fs_edit",
        Action::"fs_list",
        Action::"workspace_snapshot",
        Action::"workspace_diff",
        Action::"workspace_rollback"
    ],
    resource is WorkspaceResource
) when {
    resource.org_id == principal.org_id &&
    resource.owner_agent_id == principal.agent_id
};

// 2. Auto-permit sandbox command execution inside the Agent's isolated sandbox
permit (
    principal is Agent,
    action in [Action::"proc_exec", Action::"proc_manage"],
    resource is SandboxResource
) when {
    resource.org_id == principal.org_id &&
    resource.owner_agent_id == principal.agent_id
};

// 3. Auto-permit Intra-Organization data sharing (CAS Artifacts, Org KV, Shared Read-Only Mount)
permit (
    principal is Agent,
    action in [
        Action::"org_artifact_publish",
        Action::"org_artifact_fetch",
        Action::"org_kv_get",
        Action::"org_kv_put"
    ],
    resource is OrgResource
) when {
    resource.org_id == principal.org_id
};

// 4. Auto-permit Intra-Organization Inter-Agent Communication (IPC Mailbox, RPC Handoff, Topic Pub/Sub)
permit (
    principal is Agent,
    action in [
        Action::"ipc_register_peer",
        Action::"ipc_list_peers",
        Action::"ipc_send",
        Action::"ipc_request",
        Action::"ipc_reply",
        Action::"ipc_recv",
        Action::"ipc_ack",
        Action::"ipc_publish",
        Action::"ipc_subscribe"
    ],
    resource is IpcResource
) when {
    resource.org_id == principal.org_id
};

// 5. Explicitly forbid cross-organization resource access or IPC unless granted a federation lease
forbid (
    principal is Agent,
    action,
    resource
) when {
    principal.org_id != resource.org_id
};
