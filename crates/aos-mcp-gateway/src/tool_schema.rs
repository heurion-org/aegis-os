use crate::*;

/// Tools that mint leases. They stay callable in-process (CLI `aegis-os policy approve`, dashboard,
/// benches) but are never exposed to agents over MCP: an agent must not approve its own escalation.
pub const HUMAN_ONLY_TOOLS: &[&str] = &["policy_approve_escalation", "policy_grant_lease"];

/// MCP tool annotations, `(name, readOnlyHint, destructiveHint, idempotentHint, openWorldHint)`,
/// declared on every tool so hosts can decide what to confirm. "Read-only" means the call leaves the
/// shadow workspace, host repo and shared Org state untouched; "open world" means it can reach
/// systems outside the runtime. Keep in step with each handler when its behaviour changes.
pub const TOOL_ANNOTATIONS: &[(&str, bool, bool, bool, bool)] = &[
    ("fs_read", true, false, true, false),
    ("fs_write", false, true, true, false),
    ("fs_edit", false, true, false, false),
    ("fs_delete", false, true, true, false),
    ("fs_glob", true, false, true, false),
    ("fs_export_file", false, true, true, false),
    ("fs_import_file", false, false, true, false),
    // Auto-rebases the shadow onto the host before reporting.
    ("workspace_status", false, false, true, false),
    ("workspace_sync", false, false, true, false),
    ("workspace_snapshot", false, false, false, false),
    ("workspace_diff", false, false, true, false),
    ("workspace_rollback", false, true, true, false),
    ("workspace_commit", false, true, false, false),
    ("workspace_export_pr", false, false, false, false),
    ("workspace_switch", false, false, true, false),
    ("workspace_git_inspect", true, false, true, false),
    ("workspace_git", false, true, false, true),
    ("github_ci_inspect", true, false, true, true),
    ("github_ci_rerun", false, false, false, true),
    ("github_pr_inspect", true, false, true, true),
    ("github_issue_inspect", true, false, true, true),
    ("github_pr_create", false, false, false, true),
    ("github_comment_create", false, false, false, true),
    ("github_pr_merge", false, true, false, true),
    // Arbitrary sandboxed commands; network policy depends on the sandbox profile.
    ("proc_exec", false, true, false, true),
    ("pkg_install", false, false, false, true),
    ("host_exec", false, false, false, true),
    ("org_artifact_publish", false, false, true, false),
    ("org_artifact_fetch", true, false, true, false),
    ("org_kv_put", false, false, false, false),
    ("org_kv_get", true, false, true, false),
    ("ipc_list_peers", true, false, true, false),
    ("ipc_update_card", false, false, true, false),
    ("ipc_task_update", false, false, false, false),
    ("ipc_task_get", true, false, true, false),
    ("ipc_task_list", true, false, true, false),
    ("ipc_send", false, false, false, false),
    ("ipc_request", false, false, false, false),
    ("ipc_reply", false, false, false, false),
    ("ipc_recv", true, false, true, false),
    ("ipc_publish", false, false, false, false),
    ("ipc_subscribe", false, false, true, false),
    ("ipc_ack", false, false, true, false),
    ("ipc_wait", false, false, true, false),
    // Inspects and rewrites the request at the boundary; it does not forward it (yet).
    ("egress_http_request", false, false, false, true),
    ("coord_claim", false, false, true, false),
    ("coord_release", false, false, true, false),
    ("policy_list_escalations", true, false, true, false),
    ("memory_policy_evaluate", true, false, true, false),
    ("runtime_configure_mode", false, false, true, true),
    ("mcp_list_installed", true, false, true, false),
    ("mcp_discover", true, false, true, true),
    ("mcp_request_install", false, false, false, true),
    ("mcp_hot_list_tools", true, false, true, true),
    ("mcp_hot_call_tool", false, false, false, true),
];

/// Controls how many built-in Aegis runtime MCP tools are advertised via `tools/list`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum GatewayToolProfile {
    /// Core 10 transactional CoW / execution / egress / escalation inspection tools.
    Minimal,
    /// Core 10 + 17 multi-agent coordination / IPC / Org CAS / Git PR collaboration tools (27 tools).
    Collab,
    /// Default profile: all active runtime tools (50 tools).
    #[default]
    Standard,
}

impl GatewayToolProfile {
    pub fn from_str_or_env(explicit: Option<&str>) -> Self {
        let env_val = std::env::var("AOS_MCP_TOOL_PROFILE").ok();
        let raw = explicit
            .or(env_val.as_deref())
            .unwrap_or("standard")
            .trim()
            .to_ascii_lowercase();
        match raw.as_str() {
            "minimal" => Self::Minimal,
            "collab" => Self::Collab,
            _ => Self::Standard,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Minimal => "minimal",
            Self::Collab => "collab",
            Self::Standard => "standard",
        }
    }

    pub fn allows_tool(self, name: &str) -> bool {
        const MINIMAL_TOOLS: &[&str] = &[
            "workspace_status",
            "workspace_diff",
            "workspace_sync",
            "workspace_commit",
            "workspace_rollback",
            "proc_exec",
            "egress_http_request",
            "policy_list_escalations",
            "fs_export_file",
            "fs_import_file",
        ];
        const COLLAB_EXTRA_TOOLS: &[&str] = &[
            "coord_claim",
            "coord_release",
            "ipc_send",
            "ipc_recv",
            "ipc_request",
            "ipc_reply",
            "ipc_list_peers",
            "ipc_task_update",
            "ipc_task_get",
            "ipc_task_list",
            "org_artifact_publish",
            "org_artifact_fetch",
            "org_kv_put",
            "org_kv_get",
            "workspace_git_inspect",
            "workspace_git",
            "github_pr_create",
        ];

        match self {
            Self::Minimal => MINIMAL_TOOLS.contains(&name),
            Self::Collab => MINIMAL_TOOLS.contains(&name) || COLLAB_EXTRA_TOOLS.contains(&name),
            Self::Standard => true,
        }
    }
}

impl AegisRuntimeKernel {
    pub fn mcp_tools_schema() -> Value {
        Self::mcp_tools_schema_for_profile(GatewayToolProfile::Standard)
    }

    pub fn mcp_tools_schema_for_profile(profile: GatewayToolProfile) -> Value {
        let mut schema = Self::mcp_tools_schema_unannotated();
        if let Some(tools) = schema["tools"].as_array_mut() {
            tools.retain(|tool| {
                let name = tool["name"].as_str().unwrap_or_default();
                profile.allows_tool(name)
            });
            for tool in tools {
                let name = tool["name"].as_str().unwrap_or_default();
                if let Some(&(_, read_only, destructive, idempotent, open_world)) =
                    TOOL_ANNOTATIONS.iter().find(|(n, ..)| *n == name)
                {
                    tool["annotations"] = json!({
                        "readOnlyHint": read_only,
                        "destructiveHint": destructive,
                        "idempotentHint": idempotent,
                        "openWorldHint": open_world,
                    });
                }
            }
        }
        schema
    }

    fn mcp_tools_schema_unannotated() -> Value {
        json!({
            "tools": [
                {
                    "name": "fs_read",
                    "description": "[Zero-Prompt] Read a file inside the Agent's Copy-on-Write shadow workspace or `$TMPDIR/...` scratch dir.",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "path": { "type": "string" },
                            "encoding": {
                                "type": "string",
                                "enum": ["utf8", "base64"],
                                "description": "Optional output encoding ('utf8' default, or 'base64' for small binary files)."
                            }
                        },
                        "required": ["path"]
                    }
                },
                {
                    "name": "fs_write",
                    "description": "[Zero-Prompt] Create or overwrite a file in the Agent's CoW shadow workspace or `$TMPDIR/...` scratch dir without modifying the host (files under `$TMPDIR/` are excluded from workspace_diff/commit).",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "path": { "type": "string" },
                            "content": { "type": "string" },
                            "encoding": {
                                "type": "string",
                                "enum": ["utf8", "base64"],
                                "description": "Optional content encoding ('utf8' default, or 'base64' for binary payloads)."
                            }
                        },
                        "required": ["path", "content"]
                    }
                },
                {
                    "name": "fs_edit",
                    "description": "[Zero-Prompt] Surgically replace `target` with `replacement` in a file inside the CoW shadow workspace or `$TMPDIR/...` scratch dir.",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "path": { "type": "string" },
                            "target": { "type": "string" },
                            "replacement": { "type": "string" }
                        },
                        "required": ["path", "target", "replacement"]
                    }
                },
                {
                    "name": "fs_delete",
                    "description": "[Zero-Prompt] Delete a file inside the Agent's CoW shadow workspace or `$TMPDIR/...` scratch dir.",
                    "inputSchema": {
                        "type": "object",
                        "properties": { "path": { "type": "string" } },
                        "required": ["path"]
                    }
                },
                {
                    "name": "fs_glob",
                    "description": "[Zero-Prompt] List files and uncommitted change summary inside the Agent's CoW shadow workspace (or pass `pattern: \"$TMPDIR/...\"` to list agent scratch files).",
                    "inputSchema": {
                        "type": "object",
                        "properties": { "pattern": { "type": "string" } }
                    }
                },
                {
                    "name": "fs_export_file",
                    "description": "[Lease-Gated Zero-Copy] Export a file or binary artifact (e.g. PDF, PNG, ZIP, Parquet) directly from your CoW shadow workspace, $TMPDIR, or Org CAS (`artifact://...`) to an explicit host path without encoding bytes in tool arguments. Validates magic headers, freezes a SHA-256 CAS snapshot before approval, and writes atomically via OS CoW clone/copy.",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "src_path": {
                                "type": "string",
                                "description": "Source path inside CoW shadow, $TMPDIR/agent_home, org pub dir, or `artifact://<org>/sha256:<hash>`."
                            },
                            "dst_host_path": {
                                "type": "string",
                                "description": "Absolute destination path on the host filesystem."
                            },
                            "overwrite": {
                                "type": "boolean",
                                "description": "Overwrite existing regular file at destination (default: true)."
                            },
                            "totp": {
                                "type": "string",
                                "description": "Optional 6-digit TOTP authenticator code for Cloud mode approval."
                            }
                        },
                        "required": ["src_path", "dst_host_path"]
                    }
                },
                {
                    "name": "fs_import_file",
                    "description": "[Lease-Gated] Request human approval (SHA-256 pinned) to import a regular host file from outside the workspace (e.g. ~/Documents, ~/Downloads) into `<agent_home>/imports/` (default, keeps git diff clean) or explicitly into your CoW shadow (`import_to: 'shadow'`). Credential paths and `.env*` secrets are strictly blocked.",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "src_host_path": {
                                "type": "string",
                                "description": "Absolute host file path (or ~/...) to import."
                            },
                            "dst_path": {
                                "type": "string",
                                "description": "Optional relative filename/subpath at destination (defaults to source file basename)."
                            },
                            "import_to": {
                                "type": "string",
                                "enum": ["imports", "shadow"],
                                "description": "Destination root: 'imports' writes to `<agent_home>/imports/<dst_path>` (default); 'shadow' writes into the CoW shadow workspace."
                            },
                            "overwrite": {
                                "type": "boolean",
                                "description": "Overwrite existing destination file if present (default: true)."
                            },
                            "totp": {
                                "type": "string",
                                "description": "Optional 6-digit TOTP authenticator code for Cloud mode approval."
                            }
                        },
                        "required": ["src_host_path"]
                    }
                },
                {
                    "name": "workspace_status",
                    "description": "[Zero-Prompt] Get full status of the CoW shadow workspace, snapshots, unread IPC messages, and pending escalations.",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "include_diffs": {
                                "type": "boolean",
                                "description": "Include full `preview_diff` patch text in `uncommitted_changes` (default false to keep responses compact; paths, change types, sizes, and SHA-256 digests are always included)."
                            }
                        }
                    }
                },
                {
                    "name": "workspace_sync",
                    "description": "[Zero-Prompt] Rebase and 3-way merge host commits from peer Agents into your CoW shadow workspace, updating file mtimes and returning a detailed RefreshReport (including any conflict_details). Optionally adopt uncommitted shadow edits from a crashed/dead peer via `adopt_orphaned_agent`.",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "adopt_orphaned_agent": {
                                "type": "string",
                                "description": "Optional dead/crashed peer agent_id whose uncommitted shadow edits should be adopted into your shadow workspace."
                            }
                        }
                    }
                },
                {
                    "name": "workspace_snapshot",
                    "description": "[Zero-Prompt] Create an instant point-in-time CoW snapshot of the shadow workspace.",
                    "inputSchema": {
                        "type": "object",
                        "properties": { "label": { "type": "string" } }
                    }
                },
                {
                    "name": "workspace_diff",
                    "description": "[Zero-Prompt] Auto-rebase against host and inspect all uncommitted file changes in the shadow workspace relative to the host or a snapshot.",
                    "inputSchema": {
                        "type": "object",
                        "properties": { "snapshot_id": { "type": "string" } }
                    }
                },
                {
                    "name": "workspace_rollback",
                    "description": "[Zero-Prompt] Instantly revert the shadow workspace to a previous snapshot.",
                    "inputSchema": {
                        "type": "object",
                        "properties": { "snapshot_id": { "type": "string" } },
                        "required": ["snapshot_id"]
                    }
                },
                {
                    "name": "workspace_commit",
                    "description": "[Lease-Gated] Auto-rebase against host, 3-way merge non-overlapping text hunks, optionally run a sandboxed pre-commit verification command (`verify_cmd`, e.g., `cargo check --offline`) against the merged shadow tree, and atomically commit changes back to the host directory.",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "paths": { "type": "array", "items": { "type": "string" } },
                            "overwrite_binaries": {
                                "type": "boolean",
                                "description": "If true, allow your shadow copy of concurrently modified binary artifacts (e.g. PDFs) to overwrite the host copy."
                            },
                            "verify_cmd": {
                                "type": "string",
                                "description": "Optional shell command executed inside the OS kernel sandbox after Phase-1 3-way merge staging and before Phase-2 host commit; aborts commit if exit code != 0."
                            },
                            "verify_timeout_ms": {
                                "type": "integer",
                                "description": "Optional timeout in milliseconds for `verify_cmd` (default: 30000)."
                            },
                            "task_id": {
                                "type": "string",
                                "description": "Optional A2A task id. When set, approval binds the resulting lease to this task."
                            },
                            "release_claims": {
                                "type": "boolean",
                                "description": "If true (default), automatically release this Agent's file claims matching the committed paths and notify waiting peers."
                            },
                            "totp": {
                                "type": "string",
                                "description": "Optional 6-digit TOTP authenticator code provided by the human user in chat to approve a Cloud boundary escalation inline (for pure CLI / SSH sessions)."
                            }
                        }
                    }
                },
                {
                    "name": "workspace_export_pr",
                    "description": "[Lease-Gated] Merge your CoW shadow workspace into the repository via 4-Tier LCS Diff3, create a Git branch, commit changes, and export a unified Git patch and GitHub Pull Request payload.",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "workspace_id": { "type": "string" },
                            "branch_name": { "type": "string" },
                            "commit_title": { "type": "string" },
                            "overwrite_binaries": { "type": "boolean" }
                        }
                    }
                },
                {
                    "name": "workspace_switch",
                    "description": "[Zero-Prompt in Umbrella / Lease-Gated Outside] Switch this session's active CoW shadow workspace to a sibling, child, or specified project directory.",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "path": {
                                "type": "string",
                                "description": "Target project directory path (absolute, or relative to current workspace / umbrella container / parent)."
                            },
                            "org_id": {
                                "type": "string",
                                "description": "Optional organization ID override (defaults to preserving the current org ID, e.g. 'personal')."
                            }
                        },
                        "required": ["path"]
                    }
                },
                {
                    "name": "workspace_git_inspect",
                    "description": "[Zero-Prompt Read-Only] Inspect host Git repository status (plus pending CoW shadow file count), branches, recent commits, diffs, tags, remotes, or commit metadata safely with DLP secret redaction.",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "mode": {
                                "type": "string",
                                "enum": ["status", "branch", "log", "diff", "tag", "remote", "show"],
                                "description": "Read-only Git query mode (default: 'status')."
                            },
                            "limit": {
                                "type": "integer",
                                "description": "Maximum log entries to return in 'log' mode (1..=100, default 20)."
                            },
                            "rev": {
                                "type": "string",
                                "description": "Optional safe commit/ref/range for 'log', 'diff', or 'show'."
                            },
                            "paths": {
                                "type": "array",
                                "items": { "type": "string" },
                                "description": "Optional repo-relative path filters for 'status', 'log', 'diff', or 'show'."
                            },
                            "repo": {
                                "type": "string",
                                "description": "Optional child repository subpath relative to workspace root for multi-repo workspaces."
                            }
                        }
                    }
                },
                {
                    "name": "workspace_git",
                    "description": "[Lease-Gated] Single-approval host Git transaction: optionally verify & land CoW shadow changes (`auto_commit_shadow: true`), switch/create branches (`checkout_branch`), sync (`fetch`/`pull_ff_only`/`pull_rebase`), stage & commit explicit paths (with trailers), tag, and push (or `--force-with-lease` with sensitive escalation).",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "auto_commit_shadow": {
                                "type": "boolean",
                                "description": "If true, verify (`verify_cmd`) and land uncommitted CoW shadow changes to host atomically BEFORE `git add/commit` under a single SHA-256-pinned approval."
                            },
                            "repo": {
                                "type": "string",
                                "description": "Optional child repository subpath relative to workspace root for multi-repo workspaces."
                            },
                            "verify_cmd": {
                                "type": "string",
                                "description": "Optional sandboxed verification command before landing shadow changes when `auto_commit_shadow: true`."
                            },
                            "verify_timeout_ms": {
                                "type": "integer",
                                "description": "Optional timeout in milliseconds for `verify_cmd` (default: 30000)."
                            },
                            "skip_verify": {
                                "type": "boolean",
                                "description": "Skip configured repo verify gate during `auto_commit_shadow` (escalates as sensitive if configured)."
                            },
                            "overwrite_binaries": {
                                "type": "boolean",
                                "description": "Allow shadow binary overwrite during `auto_commit_shadow` (escalates as sensitive)."
                            },
                            "checkout_branch": {
                                "type": "string",
                                "description": "Optional validated branch name to checkout on the host repo."
                            },
                            "create_branch": {
                                "type": "boolean",
                                "description": "Create `checkout_branch` (`git checkout -b`) instead of switching to an existing branch."
                            },
                            "sync": {
                                "type": "string",
                                "enum": ["fetch", "pull_ff_only", "pull_rebase"],
                                "description": "Optional remote sync operation (`fetch`, `pull_ff_only`, or `pull_rebase`) followed by CoW shadow refresh."
                            },
                            "paths": {
                                "type": "array",
                                "items": { "type": "string" },
                                "description": "Explicit repo-relative file paths to stage & commit (auto-populated from CoW shadow when omitted with `auto_commit_shadow: true` + `commit_message`)."
                            },
                            "commit_message": {
                                "type": "string",
                                "description": "Commit message summary/body."
                            },
                            "trailers": {
                                "type": "array",
                                "items": { "type": "string" },
                                "description": "Optional commit trailer lines (e.g. `Aegis-OS-Verified: ...`)."
                            },
                            "tag": {
                                "type": "string",
                                "description": "Optional Git tag name to create on HEAD (e.g. `v0.4.8`)."
                            },
                            "force_tag": {
                                "type": "boolean",
                                "description": "Force-move an existing tag (`git tag -f` / `git push --force`; escalates as sensitive)."
                            },
                            "push": {
                                "type": "boolean",
                                "description": "Push branch and/or tag to the configured remote after commit/tag."
                            },
                            "force_push": {
                                "type": "boolean",
                                "description": "Force-push branch using `--force-with-lease` (requires `push: true`; escalates as HIGH RISK sensitive)."
                            },
                            "remote": {
                                "type": "string",
                                "description": "Configured remote name (default: `origin`; raw URLs are forbidden on normal operations)."
                            },
                            "bootstrap_repo": {
                                "type": "boolean",
                                "description": "[HIGH RISK · One-Shot Only] Initialize `.git` (if absent) and bind `origin` to an allowlisted GitHub URL (`bootstrap_remote_url`). Never overwrites an existing remote."
                            },
                            "bootstrap_remote_url": {
                                "type": "string",
                                "description": "Allowlisted GitHub URL (`https://github.com/<owner>/<repo>[.git]` or `git@github.com:<owner>/<repo>[.git]`) used only when `bootstrap_repo: true`."
                            },
                            "bootstrap_branch": {
                                "type": "string",
                                "description": "Initial branch name for `git init -b` when `bootstrap_repo: true` (default: `main`)."
                            },
                            "branch": {
                                "type": "string",
                                "description": "Optional branch name to push (defaults to `checkout_branch` or current HEAD branch)."
                            }
                        }
                    }
                },
                {
                    "name": "github_ci_inspect",
                    "description": "[Zero-Prompt Same-Repo / Approval Cross-Repo] Inspect GitHub Actions workflow runs, job steps, and DLP-redacted failed CI logs via the host broker.",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "repo": {
                                "type": "string",
                                "description": "GitHub repository slug (`owner/name`); auto-detected from host `.git/config` `origin` remote when omitted (cross-repo queries require approval)."
                            },
                            "workspace_repo": {
                                "type": "string",
                                "description": "Optional child repository subpath relative to workspace root used to auto-detect origin owner/name in multi-repo workspaces."
                            },
                            "run_id": {
                                "type": "integer",
                                "description": "Optional GitHub Actions workflow run ID to inspect (returns status + failed log tail)."
                            },
                            "job_id": {
                                "type": "integer",
                                "description": "Optional GitHub Actions job ID to inspect logs for directly."
                            },
                            "branch": {
                                "type": "string",
                                "description": "Optional branch filter when listing recent workflow runs."
                            },
                            "limit": {
                                "type": "integer",
                                "description": "Maximum workflow runs to return when listing (1..=20, default 8)."
                            },
                            "failed_only": {
                                "type": "boolean",
                                "description": "Fetch only failed step logs (`--log-failed`, default true) vs full log (`--log`) when `run_id` is given."
                            },
                            "tail_lines": {
                                "type": "integer",
                                "description": "Maximum trailing log lines to return after DLP secret redaction (1..=400, default 120)."
                            }
                        }
                    }
                },
                {
                    "name": "github_ci_rerun",
                    "description": "[Lease-Gated] Rerun failed jobs (or entire workflow / single job) for a GitHub Actions workflow run via the host broker after human approval.",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "run_id": {
                                "type": "integer",
                                "description": "GitHub Actions workflow run ID to rerun."
                            },
                            "repo": {
                                "type": "string",
                                "description": "GitHub repository slug (`owner/name`); defaults to host `origin`."
                            },
                            "workspace_repo": {
                                "type": "string",
                                "description": "Optional child repository subpath relative to workspace root used to auto-detect origin owner/name in multi-repo workspaces."
                            },
                            "failed_only": {
                                "type": "boolean",
                                "description": "Rerun only failed jobs (`--failed`, default true)."
                            },
                            "job_id": {
                                "type": "integer",
                                "description": "Optional specific job ID to rerun."
                            }
                        },
                        "required": ["run_id"]
                    }
                },
                {
                    "name": "github_pr_inspect",
                    "description": "[Zero-Prompt Same-Repo / Approval Cross-Repo] List or inspect GitHub Pull Requests, review status, checks, comments, and DLP-redacted diff via the host broker.",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "pr_number": {
                                "type": "integer",
                                "description": "Pull Request number to inspect (lists PRs when omitted)."
                            },
                            "state": {
                                "type": "string",
                                "enum": ["open", "closed", "merged", "all"],
                                "description": "Filter PR state when listing (default: 'open')."
                            },
                            "limit": {
                                "type": "integer",
                                "description": "Maximum PRs to return when listing (1..=30, default 10)."
                            },
                            "include_comments": { "type": "boolean" },
                            "include_checks": { "type": "boolean" },
                            "include_diff": { "type": "boolean" },
                            "repo": {
                                "type": "string",
                                "description": "GitHub repository slug (`owner/name`); defaults to host `origin`."
                            },
                            "workspace_repo": {
                                "type": "string",
                                "description": "Optional child repository subpath relative to workspace root used to auto-detect origin owner/name in multi-repo workspaces."
                            }
                        }
                    }
                },
                {
                    "name": "github_issue_inspect",
                    "description": "[Zero-Prompt Same-Repo / Approval Cross-Repo] List or inspect GitHub Issues and comments with DLP secret redaction via the host broker.",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "issue_number": {
                                "type": "integer",
                                "description": "Issue number to inspect (lists issues when omitted)."
                            },
                            "state": {
                                "type": "string",
                                "enum": ["open", "closed", "all"],
                                "description": "Filter issue state when listing (default: 'open')."
                            },
                            "limit": {
                                "type": "integer",
                                "description": "Maximum issues to return when listing (1..=30, default 10)."
                            },
                            "include_comments": { "type": "boolean" },
                            "repo": {
                                "type": "string",
                                "description": "GitHub repository slug (`owner/name`); defaults to host `origin`."
                            },
                            "workspace_repo": {
                                "type": "string",
                                "description": "Optional child repository subpath relative to workspace root used to auto-detect origin owner/name in multi-repo workspaces."
                            }
                        }
                    }
                },
                {
                    "name": "github_pr_create",
                    "description": "[Lease-Gated] Create a GitHub Pull Request after outbound DLP secret scanning and human approval (SHA-256 pinned to title/body/head/base).",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "title": { "type": "string" },
                            "body": { "type": "string" },
                            "base": { "type": "string" },
                            "head": { "type": "string" },
                            "draft": { "type": "boolean" },
                            "repo": {
                                "type": "string",
                                "description": "GitHub repository slug (`owner/name`); defaults to host `origin`."
                            },
                            "workspace_repo": {
                                "type": "string",
                                "description": "Optional child repository subpath relative to workspace root used to auto-detect origin owner/name in multi-repo workspaces."
                            }
                        },
                        "required": ["title"]
                    }
                },
                {
                    "name": "github_comment_create",
                    "description": "[Lease-Gated] Post a GitHub Pull Request or Issue comment after outbound DLP secret scanning and human approval (SHA-256 pinned to repo/number/body).",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "number": {
                                "type": "integer",
                                "description": "Target Pull Request or Issue number."
                            },
                            "body": {
                                "type": "string",
                                "description": "Markdown comment body (checked fail-closed by DLP)."
                            },
                            "repo": {
                                "type": "string",
                                "description": "GitHub repository slug (`owner/name`); defaults to host `origin`."
                            },
                            "workspace_repo": {
                                "type": "string",
                                "description": "Optional child repository subpath relative to workspace root used to auto-detect origin owner/name in multi-repo workspaces."
                            }
                        },
                        "required": ["number", "body"]
                    }
                },
                {
                    "name": "github_pr_merge",
                    "description": "[Lease-Gated · Destructive] Merge an approved GitHub Pull Request via the host broker after explicit human approval (SHA-256 pinned to pr_number/method/delete_branch/subject/body).",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "pr_number": {
                                "type": "integer",
                                "description": "Pull Request number to merge."
                            },
                            "method": {
                                "type": "string",
                                "enum": ["merge", "squash", "rebase"],
                                "description": "Merge strategy (default: 'squash')."
                            },
                            "delete_branch": {
                                "type": "boolean",
                                "description": "Whether to delete the remote head branch after merge (default: false)."
                            },
                            "subject": {
                                "type": "string",
                                "description": "Optional custom merge commit subject (checked fail-closed by DLP)."
                            },
                            "body": {
                                "type": "string",
                                "description": "Optional custom merge commit message body (checked fail-closed by DLP)."
                            },
                            "repo": {
                                "type": "string",
                                "description": "GitHub repository slug (`owner/name`); defaults to host `origin`."
                            },
                            "workspace_repo": {
                                "type": "string",
                                "description": "Optional child repository subpath relative to workspace root used to auto-detect origin owner/name in multi-repo workspaces."
                            }
                        },
                        "required": ["pr_number"]
                    }
                },
                {
                    "name": "proc_exec",
                    "description": "[Zero-Prompt] PREFERRED over native shell tools (run_command/Bash): execute a command (e.g. `sh -c \"grep -rn foo crates | head\"`, `cargo test`) kernel-confined inside the Agent's OS sandbox. Sandbox facts: (1) NO outbound internet (`curl`/`wget` fail — use `egress_http_request` for HTTP/HTTPS and `pkg_install` for packages); (2) on macOS Seatbelt host `/tmp` and `/private/tmp` are denied — always use `$TMPDIR` (writable, pre-created inside agent home); (3) avoid broad root scans like `find /` (use `which` or workspace paths); (4) pass `background: true` and poll `poll_pid` for tasks >30s. cwd = your CoW shadow workspace (host `node_modules`/`.venv` auto-linked read-only); writes stay in shadow until `workspace_commit`. Isolated 127.0.0.1 ports are exposed via `$AOS_DEV_PORT` and `$AOS_LOOPBACK_PORTS` (`loopback_ports`).",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "command": { "type": "string" },
                            "args": { "type": "array", "items": { "type": "string" } },
                            "cwd": { "type": "string" },
                            "timeout_ms": { "type": "integer" },
                            "background": { "type": "boolean" },
                            "poll_pid": { "type": "integer" },
                            "stdout_offset": {
                                "type": "integer",
                                "minimum": 0,
                                "description": "Optional byte offset into stdout when polling a background job with `poll_pid`."
                            },
                            "stderr_offset": {
                                "type": "integer",
                                "minimum": 0,
                                "description": "Optional byte offset into stderr when polling a background job with `poll_pid`."
                            },
                            "tail_bytes": {
                                "type": "integer",
                                "minimum": 0,
                                "maximum": 262144,
                                "description": "Maximum bytes of stdout/stderr to return when polling `poll_pid` (default 32768, max 262144; returns trailing bytes unless offset is set)."
                            },
                            "loopback_ports": {
                                "type": "integer",
                                "description": "Optional count of isolated 127.0.0.1 loopback ports (0..=8) to allocate for local dev/mock servers (exposed via $AOS_DEV_PORT and $AOS_LOOPBACK_PORTS)."
                            }
                        }
                    }
                },
                {
                    "name": "pkg_install",
                    "description": "[Lease-Gated] Install packages into the isolated CoW shadow workspace (`npm`/`pnpm`/`yarn`/`bun`/`pip`/`uv`/`cargo`/`go`) with unlinked dependency dirs (host stays untouched, CoW diff tracks only manifests/lockfiles) and an ephemeral registry-allowlisted egress proxy. Lifecycle scripts stay disabled by default (`allow_scripts: false`).",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "manager": {
                                "type": "string",
                                "enum": ["npm", "pnpm", "yarn", "bun", "pip", "uv", "cargo", "go"],
                                "description": "Package manager ecosystem to run inside the isolated CoW shadow."
                            },
                            "packages": {
                                "type": "array",
                                "items": { "type": "string" },
                                "description": "Optional package specifiers (e.g. [\"zod@^3.23.0\"]); omit or pass [] to install from existing lockfile/manifest."
                            },
                            "cwd": {
                                "type": "string",
                                "description": "Optional CoW shadow relative subdirectory (defaults to workspace root `.`)."
                            },
                            "dev": {
                                "type": "boolean",
                                "description": "Install as devDependency (JS/Rust)."
                            },
                            "allow_scripts": {
                                "type": "boolean",
                                "description": "Allow package lifecycle/build scripts (default false; true triggers elevated `pkg_install_scripts` approval)."
                            },
                            "offline": {
                                "type": "boolean",
                                "description": "Run strictly offline (`--offline` / `--no-index`) with zero egress proxy."
                            },
                            "timeout_ms": {
                                "type": "integer",
                                "description": "Optional execution timeout in milliseconds (default 180000)."
                            }
                        },
                        "required": ["manager"]
                    }
                },
                {
                    "name": "host_exec",
                    "description": "[HIGH RISK · SHA-256 Frozen Approval] Execute an unsandboxed host-brokered sibling process from an enforced SessionBroker (e.g. WardRun/sandbox benchmarks, containers, or simulators) with inputs frozen read-only, environment scrubbed, process group reaped, output files harvested into shadow, and outputs DLP-redacted.",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "program": {
                                "type": "string",
                                "description": "Host binary path or executable name resolved on clean host PATH (inline -c/-e flags and privilege escalation binaries are rejected)."
                            },
                            "script": {
                                "type": "string",
                                "description": "Workspace-relative script path (required for interpreters like python3/bash/node); frozen read-only and SHA-256 pinned before human approval."
                            },
                            "args": {
                                "type": "array",
                                "items": { "type": "string" },
                                "description": "Additional command-line arguments passed after script."
                            },
                            "inputs": {
                                "type": "array",
                                "items": { "type": "string" },
                                "description": "Optional extra workspace-relative files/modules to freeze into the read-only execution bundle."
                            },
                            "output_files": {
                                "type": "array",
                                "items": { "type": "string" },
                                "description": "Optional relative artifact/report paths to harvest back into CoW shadow after execution."
                            },
                            "pass_env": {
                                "type": "array",
                                "items": { "type": "string" },
                                "description": "Optional non-sensitive host environment variable names to forward explicitly."
                            },
                            "timeout_ms": {
                                "type": "integer",
                                "description": "Execution timeout in milliseconds (default 120000, max 900000)."
                            },
                            "rationale": {
                                "type": "string",
                                "description": "Reason why host-brokered sibling execution outside the OS sandbox is needed."
                            },
                            "totp": {
                                "type": "string",
                                "description": "Optional 6-digit TOTP authenticator code for Cloud mode approval."
                            }
                        },
                        "required": ["program"]
                    }
                },
                {
                    "name": "org_artifact_publish",
                    "description": "[Zero-Prompt Intra-Org] Publish an immutable artifact (UTF-8 text, base64 payload, or sandbox file via `source_path`) to the Organization's CAS store for peer Agents.",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "name": { "type": "string" },
                            "content": { "type": "string" },
                            "content_base64": {
                                "type": "string",
                                "description": "Optional base64-encoded binary content (alternative to `content` / `source_path`)."
                            },
                            "source_path": {
                                "type": "string",
                                "description": "Optional path inside CoW shadow or $TMPDIR/agent_home to publish raw bytes without passing content through JSON."
                            },
                            "content_type": { "type": "string" },
                            "metadata": { "type": "object" }
                        },
                        "required": ["name"]
                    }
                },
                {
                    "name": "org_artifact_fetch",
                    "description": "[Zero-Prompt Intra-Org] Fetch an artifact from the Organization's CAS store by `artifact://<org>/sha256:<hash>` (pass `dest_path` to write raw bytes directly into your CoW shadow workspace).",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "uri": { "type": "string" },
                            "dest_path": {
                                "type": "string",
                                "description": "Optional relative path in your CoW shadow workspace to write raw artifact bytes directly without JSON serialization."
                            }
                        },
                        "required": ["uri"]
                    }
                },
                {
                    "name": "org_kv_put",
                    "description": "[Zero-Prompt Intra-Org] Store a versioned key-value entry in the Organization shared store.",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "namespace": { "type": "string" },
                            "key": { "type": "string" },
                            "value": {},
                            "expected_version": { "type": "integer" }
                        },
                        "required": ["key", "value"]
                    }
                },
                {
                    "name": "org_kv_get",
                    "description": "[Zero-Prompt Intra-Org] Read a key-value entry from the Organization shared store.",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "namespace": { "type": "string" },
                            "key": { "type": "string" }
                        },
                        "required": ["key"]
                    }
                },
                {
                    "name": "ipc_list_peers",
                    "description": "[Zero-Prompt] Discover both current-Organization peers (`peers`) and the Global Workstation Peer List across all active repositories (`global_peers`, with Google A2A `agent_card`, `<org_id>/<agent_id>` address, `skills`, client, PID, liveness, and `workspace_root`). Automatically prunes exited client processes.",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "scope": {
                                "type": "string",
                                "enum": ["all", "global", "org"],
                                "description": "Optional scope ('all' default returns both org `peers` and workstation-wide `global_peers`)."
                            },
                            "skill_tag": {
                                "type": "string",
                                "description": "Optional A2A skill ID, tag, or keyword filter."
                            }
                        }
                    }
                },
                {
                    "name": "ipc_update_card",
                    "description": "[Zero-Prompt] Update this Agent's Google A2A `AgentCard` (`summary` and advertised `skills`) in the global peer registry.",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "summary": { "type": "string" },
                            "skills": {
                                "type": "array",
                                "items": {
                                    "type": "object",
                                    "properties": {
                                        "id": { "type": "string" },
                                        "name": { "type": "string" },
                                        "description": { "type": "string" },
                                        "tags": { "type": "array", "items": { "type": "string" } }
                                    },
                                    "required": ["id", "name"]
                                }
                            }
                        }
                    }
                },
                {
                    "name": "ipc_task_update",
                    "description": "[Zero-Prompt] Transition a Google A2A `Task` state (`working`, `input-required`, `completed`, `failed`, `canceled`, `rejected`) and optionally attach output `artifacts`.",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "task_id": { "type": "string" },
                            "state": {
                                "type": "string",
                                "enum": ["submitted", "working", "input-required", "completed", "failed", "canceled", "rejected"]
                            },
                            "message": { "type": "string" },
                            "artifacts": { "type": "array" },
                            "expected_revision": { "type": "integer", "description": "Optional CAS revision; rejects the update if the task has moved." }
                        },
                        "required": ["task_id", "state"]
                    }
                },
                {
                    "name": "ipc_task_get",
                    "description": "[Zero-Prompt] Retrieve a stateful Google A2A `Task` by `task_id` (including `state`, `parts`, `artifacts`, transition `history`, child `subtasks`, and tamper-evident SHA-256 `audit_trace`).",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "task_id": { "type": "string" },
                            "include_audit_trace": {
                                "type": "boolean",
                                "description": "If true (default), include the task's Flight Recorder audit trail and SHA-256 hash chain verification."
                            }
                        },
                        "required": ["task_id"]
                    }
                },
                {
                    "name": "ipc_task_list",
                    "description": "[Zero-Prompt] List stateful Google A2A `Task`s (with parent/child hierarchy, claimed paths, and hash chain health) in the caller's Organization. Cross-org listing is operator-only.",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "scope": { "type": "string", "enum": ["org"], "default": "org" },
                            "agent_id": { "type": "string" }
                        }
                    }
                },
                {
                    "name": "ipc_wait",
                    "description": "[Zero-Prompt] Reactive synchronization primitive: wait without busy-polling until a delegated `task_id` changes state, new inbox messages arrive (`wait_for_inbox`), or peer-held `claim_paths` are released (optionally auto-claiming and auto-rebasing your CoW shadow workspace onto the peer's latest commit).",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "task_id": {
                                "type": "string",
                                "description": "Optional A2A task ID to watch for state transitions or completion."
                            },
                            "since_revision": {
                                "type": "integer",
                                "description": "Optional task revision baseline; returns immediately if the task's revision has already advanced past this number."
                            },
                            "claim_paths": {
                                "type": "array",
                                "items": { "type": "string" },
                                "description": "Optional repo paths/globs to wait on until released by peers."
                            },
                            "auto_claim": {
                                "type": "boolean",
                                "description": "If true (default), automatically claim `claim_paths` and run `refresh_from_host` as soon as they are released."
                            },
                            "wait_for_inbox": {
                                "type": "boolean",
                                "description": "If true, wake up as soon as any unread message arrives in this Agent's inbox."
                            },
                            "timeout_ms": {
                                "type": "integer",
                                "description": "Maximum wait duration in milliseconds (default: 15000, max: 120000)."
                            }
                        }
                    }
                },
                {
                    "name": "ipc_send",
                    "description": "[Zero-Prompt] Send a direct point-to-point message to a peer Agent (`to_agent` accepts either `<agent_id>` or global `<org_id>/<agent_id>`).",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "to_agent": { "type": "string", "description": "Peer `<agent_id>` or global `<org_id>/<agent_id>` address from `ipc_list_peers`." },
                            "subject": { "type": "string" },
                            "payload": { "type": "object" },
                            "attachments": { "type": "array", "items": { "type": "string" } }
                        },
                        "required": ["to_agent", "subject", "payload"]
                    }
                },
                {
                    "name": "ipc_request",
                    "description": "[Zero-Prompt] Delegate a structured task to a peer Agent (`to_agent` accepts either `<agent_id>` or global `<org_id>/<agent_id>`) and correlate its `ipc_reply`.",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "to_agent": { "type": "string", "description": "Peer `<agent_id>` or global `<org_id>/<agent_id>` address from `ipc_list_peers`." },
                            "subject": { "type": "string" },
                            "payload": { "type": "object" },
                            "attachments": { "type": "array", "items": { "type": "string" } },
                            "timeout_secs": { "type": "integer" }
                        },
                        "required": ["to_agent", "subject", "payload"]
                    }
                },
                {
                    "name": "ipc_reply",
                    "description": "[Zero-Prompt Intra-Org] Reply to a peer Agent's `ipc_request` with structured output and CAS attachments.",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "msg_id": { "type": "string" },
                            "success": { "type": "boolean" },
                            "payload": { "type": "object" },
                            "attachments": { "type": "array", "items": { "type": "string" } }
                        },
                        "required": ["msg_id", "payload"]
                    }
                },
                {
                    "name": "ipc_recv",
                    "description": "[Zero-Prompt] Receive pending messages and task requests from this Agent's IPC mailbox.",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "unread_only": { "type": "boolean" },
                            "limit": { "type": "integer" }
                        }
                    }
                },
                {
                    "name": "ipc_publish",
                    "description": "[Zero-Prompt Intra-Org] Broadcast an event to all peer Agents subscribed to a topic in the Organization.",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "topic": { "type": "string" },
                            "subject": { "type": "string" },
                            "payload": { "type": "object" },
                            "attachments": { "type": "array", "items": { "type": "string" } }
                        },
                        "required": ["topic", "payload"]
                    }
                },
                {
                    "name": "ipc_subscribe",
                    "description": "[Zero-Prompt Intra-Org] Subscribe this Agent principal to one or more Organization broadcast topics.",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "topics": { "type": "array", "items": { "type": "string" } }
                        }
                    }
                },
                {
                    "name": "ipc_ack",
                    "description": "[Zero-Prompt Intra-Org] Acknowledge and mark an IPC message ID as processed.",
                    "inputSchema": {
                        "type": "object",
                        "properties": { "msg_id": { "type": "string" } },
                        "required": ["msg_id"]
                    }
                },
                {
                    "name": "egress_http_request",
                    "description": "[Boundary-Sanitized Host Proxy] Execute an approved outbound HTTP/HTTPS request from the host broker (since `proc_exec` has no internet). Supports full `url` (defaults `execute: true`) or legacy `target_domain`/`path` inspection (`execute: false`). Applies Org domain allowlists, Vault secret injection, and response DLP redaction.",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "url": { "type": "string", "description": "Full https:// (or allowed loopback http://) URL to fetch. Setting `url` defaults `execute` to true." },
                            "target_domain": { "type": "string", "description": "Legacy/inspection domain if `url` is omitted." },
                            "method": { "type": "string", "description": "HTTP method (GET, POST, PUT, PATCH, DELETE, HEAD). Defaults to GET." },
                            "path": { "type": "string", "description": "Path + query when using `target_domain` without `url`." },
                            "headers": { "type": "object" },
                            "body": { "type": "string", "description": "Optional request body string (e.g., JSON-RPC payload)." },
                            "execute": { "type": "boolean", "description": "Forward upstream over HTTP/HTTPS (default true when `url` is passed, false for legacy `target_domain`-only checks)." },
                            "timeout_ms": { "type": "integer", "description": "Request timeout in ms (1000..=60000, default 15000)." }
                        }
                    }
                },
                {
                    "name": "coord_claim",
                    "description": "[Zero-Prompt Intra-Org] Claim repo paths/globs (e.g. `crates/aos-vfs/**`) for a TTL. `mode: \"write\"` (default) is exclusive; `mode: \"read\"` may coexist with other read claims but conflicts with writes. Peers are notified automatically; writes to write-claimed paths are blocked until release or expiry.",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "paths": { "type": "array", "items": { "type": "string" } },
                            "ttl_secs": { "type": "integer" },
                            "note": { "type": "string" },
                            "mode": {
                                "type": "string",
                                "enum": ["read", "write"],
                                "description": "Claim mode; defaults to write."
                            }
                        },
                        "required": ["paths"]
                    }
                },
                {
                    "name": "coord_release",
                    "description": "[Zero-Prompt Intra-Org] Release your claims (all of them if `paths` is omitted) and notify peers.",
                    "inputSchema": {
                        "type": "object",
                        "properties": { "paths": { "type": "array", "items": { "type": "string" } } }
                    }
                },
                {
                    "name": "policy_list_escalations",
                    "description": "List pending boundary authorization escalations for the Organization.",
                    "inputSchema": { "type": "object", "properties": {} }
                },
                {
                    "name": "memory_policy_evaluate",
                    "description": "[UOMP] Evaluate a memory read/write request against Aegis policy. Returns allow, ask (with escalation_id), or deny. Does not read memory data.",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "action": { "type": "string", "enum": ["read", "write", "delete"] },
                            "resource": { "type": "string", "description": "UOMP memory resource, e.g. memory:tag:notes/projects or memory:key:note.projects.plan" }
                        },
                        "required": ["action", "resource"]
                    }
                },
                {
                    "name": "runtime_configure_mode",
                    "description": "[Zero-Prompt] Configure or switch the current workspace's Aegis OS execution mode directly from the Coding Agent (`mode`: `\"cloud\"` for Zero-Local-Load Cloud Sandbox, `\"pro\"` for Pro Multi-Agent Cloud Sandbox, `\"local\"` for Free Local CoW Sandbox mode, or `\"status\"` to inspect current mode). Credentials are automatically loaded from local `~/.aegis-os/cloud_bindings.json` or auto-provisioned by the local runtime — NEVER ask the user to paste raw `ak_live_*` API keys into chat.",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "mode": {
                                "type": "string",
                                "enum": ["cloud", "pro", "local", "status"],
                                "description": "Target execution mode (`\"cloud\"` or `\"pro\"` to offload to Aegis Cloud Sandbox, `\"local\"` for local CoW sandbox, `\"status\"` to inspect)."
                            },
                            "endpoint": {
                                "type": "string",
                                "description": "Optional Aegis Cloud PaaS endpoint URL (defaults to `https://heurion.org` or saved endpoint)."
                            },
                            "plan_tier": {
                                "type": "string",
                                "description": "Optional subscription tier (`pro`, `team`, `enterprise`, `community`)."
                            }
                        },
                        "required": ["mode"]
                    }
                },
                {
                    "name": "mcp_list_installed",
                    "description": "[Zero-Prompt Read-Only] Inspect Aegis-managed external MCP servers, Bundle skills, OAuth/static auth posture, DLP/Outbox policy, and Option B Hot-Bridge state (never exposes secrets).",
                    "inputSchema": {
                        "type": "object",
                        "properties": {}
                    }
                },
                {
                    "name": "mcp_discover",
                    "description": "[Zero-Prompt Read-Only] Search configured Open MCP Registries (e.g. `registry.modelcontextprotocol.io`) and workspace signals (`.aegis/mcp.json`, `.mcp.json`), ranked Tier 1 (Verified Remote HTTP+OAuth) -> Tier 2 (Remote Static Key) -> Tier 3 (Sandboxed Local Stdio).",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "query": { "type": "string", "description": "Search keywords or capability intent (e.g. `linear`, `postgres`, `sentry`)." },
                            "limit": { "type": "integer", "description": "Maximum candidates to return (1..=25, default 8)." },
                            "include_workspace_recommendations": { "type": "boolean", "description": "Include local repo manifest / context recommendations (default true)." }
                        },
                        "required": ["query"]
                    }
                },
                {
                    "name": "mcp_request_install",
                    "description": "[Human-Approval Gated · Option B] Propose installing an external MCP server or bundle (`target`: registry name, URL, `npm:<pkg>`, `pypi:<pkg>`, or bundle slug). Opens Host Web Approval Console where the human reviews Trust Tier/risks and optionally completes OAuth or seals API keys directly into Vault; once approved, enables immediate use via `mcp_hot_list_tools` / `mcp_hot_call_tool` and auto-promotes to a native 1:1 proxy on next session launch.",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "target": { "type": "string", "description": "Registry name (`app.linear/mcp`), HTTPS URL, bundle shorthand (`heurion`), `npm:<pkg>`, or `pypi:<pkg>`." },
                            "server_id": { "type": "string", "description": "Optional explicit server alias slug." },
                            "scope": { "type": "string", "enum": ["org", "workspace"], "description": "`org` (global across repos, default) or `workspace` (also records zero-secret declaration in `.aegis/mcp.json`)." },
                            "reason": { "type": "string", "description": "Why the agent needs this external MCP." },
                            "trust": { "type": "string", "enum": ["untrusted", "trusted"], "description": "Requested initial trust posture (defaults to `untrusted`)." },
                            "allow_local_http": { "type": "boolean", "description": "Allow plaintext http:// loopback endpoints (local dev/testing only)." }
                        },
                        "required": ["target"]
                    }
                },
                {
                    "name": "mcp_hot_list_tools",
                    "description": "[Option B Hot Session Bridge] List upstream tools for an external MCP newly approved & installed during this live session via `mcp_request_install` (fails closed for unapproved servers).",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "server_id": { "type": "string", "description": "Hot-bridged external MCP server ID." }
                        },
                        "required": ["server_id"]
                    }
                },
                {
                    "name": "mcp_hot_call_tool",
                    "description": "[Option B Hot Session Bridge · Firewall/DLP/Outbox Enforced] Invoke a tool on an external MCP newly approved & installed during this live session. Enforces identical Firewall, DLP pseudonymization, UntrustedExternal taint, and SHA-256 Outbox gates as native proxies.",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "server_id": { "type": "string", "description": "Hot-bridged external MCP server ID." },
                            "tool_name": { "type": "string", "description": "Upstream MCP tool name." },
                            "arguments": { "type": "object", "description": "JSON arguments for the upstream MCP tool." },
                            "dry_run": { "type": "boolean", "description": "Preview policy/DLP evaluation without executing writes (default false)." }
                        },
                        "required": ["server_id", "tool_name"]
                    }
                }
            ]
        })
    }


/// Concise operational instructions returned in the MCP `initialize` result so every client
/// knows Aegis OS sandbox boundaries from handshake before attempting failing shell commands.
pub const MCP_SERVER_INSTRUCTIONS: &str = concat!(
    "Aegis OS Runtime (MCP-First, Kernel-Sandboxed):\n",
    "- Repo edits & builds: use `fs_read`/`fs_write`/`fs_edit`/`fs_glob` + `proc_exec` (writes stay in CoW shadow until `workspace_commit` or `workspace_git`).\n",
    "- Outbound network: `proc_exec` has NO internet (`curl`/`wget`/network fail); use `egress_http_request` (`url` defaults `execute: true`) for HTTP/HTTPS and `pkg_install` for packages.\n",
    "- Temp files on macOS: host `/tmp` and `/private/tmp` are read-only in Seatbelt; always use `$TMPDIR` (`<agent_home>/tmp`).\n",
    "- Host visibility: Seatbelt (`tighten_home_read`) hides host `$HOME` paths outside the active workspace (e.g. `~/Library`, `~/.aegis`, sibling repos); use `host_exec` or ask the user for host-wide diagnostics (`tmutil`, `diskutil`, `du ~/Library`).\n",
    "- Long tasks & scans: never run `find /` or synchronous `du` across large `target/`/`node_modules/` dirs (especially `du ... | sort`, which buffers stdout); scope searches to workspace subdirs and pass `\"background\": true` + `\"poll_pid\"` for tasks >30s. Read `aegis_hint` on errors."
);

}
