# Aegis OS (`aegis-os`)

**[English](README.md) | [简体中文](README_CN.md) | [Aegis OS Website](https://heurion.org/aegis-os/) | [Tutorial](https://heurion.org/aegis-os/tutorial/) | [Cloud Console & Pro Subscription ($29/mo)](https://heurion.org/aegis-cloud/dashboard) | [Approval Console](https://heurion.org/aegis-cloud/approve)**

**A Transactional Multi-Tenant Operating System Runtime & Cloud PaaS for Eliminating Authorization Fatigue in Autonomous Coding Agents (`agy`, `claude`, `codex`)**

![Rust](https://img.shields.io/badge/Rust-1.80%2B%20(2021)-orange.svg)

![MCP](https://img.shields.io/badge/Protocol-MCP%202024--11--05-blue.svg)

![A2A](https://img.shields.io/badge/Protocol-Google%20A2A-34A853.svg)

![Paper](https://img.shields.io/badge/Paper-arXiv%20Preprint-b31b1b.svg)

[![M8ven Score](https://m8ven.ai/badge/mcp/heurion-org/aegis-os)](https://m8ven.ai/mcp/heurion-org/aegis-os?s=readme)

---

## Overview

Autonomous coding agents such as **Google Antigravity (`agy`)**, **Anthropic Claude Code (`claude`)**, and **OpenAI Codex CLI (`codex`)** face a fundamental **Security–Autonomy Dilemma**:

1. **Severe Authorization Fatigue**: Action-level Human-in-the-Loop (HITL) confirmation prompts interrupt developers on **45%–57%** of tool calls across multi-step software engineering trajectories, fragmenting autonomous execution to streaks of 4–7 steps.
2. **Unconfined Execution & In-Place Mutation Risks**: Bypassing prompts (`--yolo` / `--dangerously-skip-permissions`) exposes host files, SSH/cloud credentials (`~/.ssh/id_rsa`, `~/.aws/credentials`, `~/.kube/config`), and raw API tokens (`$GITHUB_TOKEN`) to indirect prompt injection and hallucinated corruption.
3. **Multi-Agent Workspace Collisions & Context Bloat**: Running multiple agents in parallel over a shared working tree causes silent lost updates, binary build artifact conflicts, and stale incremental compiler caches (`mtime` skew), while passing large specifications inline bloats LLM context windows.

**Aegis OS (`aegis-os`)** resolves this dilemma by shifting the authorization boundary from individual tool calls to **transactional workspace boundaries**, operating seamlessly both as a **local workstation runtime** and as a **Multi-Tenant Cloud Agent Runtime PaaS (`aegis-cloud`)**:

```
┌────────────────────────────────────────────────────────────────────────────────────────┐
│   Google Antigravity (agy)      Claude Code (claude)      OpenAI Codex / Cloud Swarms  │
│     Principal: agy-<hex>         Principal: claude-code     Bearer: ak_live_<token>    │
└──────────────┬─────────────────────────────┬─────────────────────────────┬─────────────┘
               │                             │                             │
               ▼                             ▼                             ▼
┌────────────────────────────────────────────────────────────────────────────────────────┐
│  Aegis MCP, Google A2A & Cloud PaaS Gateway (aos-mcp-gateway)                          │
│  • 39 MCP Tools + 7 Dynamic URI Resources (stdio, POST /mcp, POST /v1/mcp)             │
│  • Google A2A Hub (GET /.well-known/agent.json, POST /a2a, POST /v1/a2a)               │
│  • Cloud PaaS API (/v1/workspaces, /v1/workspaces/pr, /v1/tenants/keys, /v1/vault/*)   │
│  • Embedded Web Mission Control & 1-Click Approval UI (GET /dashboard, GET /approve)   │
└───────────────────────────────────────────────┬────────────────────────────────────────┘
                                                ▼
┌────────────────────────────────────────────────────────────────────────────────────────┐
│  Declarative Cedar Policy Engine & Session Lease Manager (aos-policy + default.cedar)  │
│  R0a: Host Red-Line Deny │ R0b: Commit Hook/CI Guard │ R1: Cross-Tenant Gate           │
│  R2: TTL/One-Shot Lease  │ R3: Cedar Auto-Allow      │ R4: Human-Readable Escalation   │
└───────┬──────────────────────────┬───────────────────────────┬────────────────────┬────┘
        ▼                          ▼                           ▼                    ▼
┌───────────────────┐  ┌───────────────────────┐  ┌──────────────────────┐  ┌────────────────────┐
│ Transactional VFS │  │ Dual-Tier OS Sandbox  │  │ A2A IPC Bus & CAS    │  │ Zero-Trust Egress  │
│ (aos-vfs)         │  │ (aos-sandbox)         │  │ (aos-ipc + aos-vfs)  │  │ (aos-egress)       │
│ • APFS clonefile  │  │ • macOS sandbox-exec  │  │ • Global Peer List   │  │ • HTTPS CONNECT &  │
│ • Linux FICLONE   │  │ • Linux bwrap/MicroVM │  │ • A2A AgentCard/Task │  │   HTTP Proxy       │
│ • 4-Tier LCS Diff3│  │ • PGID SIGSTOP/KILL   │  │ • Enforced Claims    │  │ • Domain + Path    │
│ • O(1) CoW / Lazy Copy│  │ • Separate cargo cache│  │ • artifact://sha256  │  │   $AOS_SECRET_*    │
└───────────────────┘  └───────────────────────┘  └──────────────────────┘  └────────────────────┘
```

---

## Quick Start (30-Second Setup)

### Option A: Homebrew (macOS & Linux)

```bash
# 1. Install the Aegis OS binary via Homebrew
brew tap heurion-org/aegis-os https://github.com/heurion-org/aegis-os.git
brew install aegis-os

# 2. Wire Antigravity (agy), Claude Code (claude), and Codex CLI (codex) globally (run once)
aegis-os install
```

### Option B: One-Line Signed Installer (Linux & macOS, No Homebrew Required)

Downloads the precompiled binary for your OS/architecture, verifies its OpenSSH cryptographic release signature (`aegis-os-release@heurion.org`), and runs `aegis-os install` automatically:

```bash
curl -fsSL https://heurion.org/aegis-cloud/install.sh | sh
# Or directly from GitHub:
curl -fsSL https://raw.githubusercontent.com/heurion-org/aegis-os/main/scripts/install.sh | sh
```

### Option C: Build from Source (Rust 1.80+)

```bash
git clone https://github.com/heurion-org/aegis-os.git && cd aegis-os
cargo install --path crates/aos-cli
aegis-os install
```

### Enforced Runtime (Phase 1, Linux)

The launcher-based enforced mode is available on Linux as a Phase 1 preview:

```bash
aegis-os install --enforce   # optional: create ~/.aegis/bin/claude shims
aegis-os --workspace . run -- claude
aegis-os status
aegis-os diff
aegis-os verify          # run .aegis/verify.json / AOS_VERIFY_CMD in the sandbox
aegis-os commit          # diff + evidence hash; --yes for non-interactive
aegis-os approvals list  # pending/approved commit tickets
aegis-os approvals approve <esc-id>
aegis-os why             # approval ticket + audit trail
aegis-os discard
```

What it enforces today:

- The agent process tree runs under `bwrap`; the host project is read-only and writes land in a per-session CoW shadow.
- `$HOME`, `/root`, `/run`, `/var`, `/tmp`, `/mnt`, `/media`, `/srv` and host SSH keys are masked; sensitive agent config files are read-only.
- A Git view (host `.git` read-only + writable session index) keeps `git status` / `git diff` usable.
- Agent state directories are seeded into the session home; OAuth credentials are written back atomically.

Current Phase 1 limits (do not treat this as a full security boundary yet):

- Linux only; requires bubblewrap **>= 0.10** (`--bind-fd` support). macOS is Phase 4.
- Egress is a CONNECT-only domain allowlist through the local proxy; host loopback is unreachable, but L7 DLP / secret injection is not implemented yet.
- Commit approvals, evidence hashes and `workspace_commit` leases are implemented; remaining: L7 DLP / Base URL reverse proxy, full policy broker UI, DomainProfile mergers and macOS Seatbelt.

### Daily Usage (Zero Manual Commands Needed)

After running `aegis-os install` once, you **never need to invoke `aegis-os` manually** during daily coding:

1. **Open your coding agent directly** (`agy`, `claude`, or `codex`) in any project directory.
2. **Automatic First-Run Mode Selection**: On first launch in a project, Aegis OS's `PreInvocation` hook instructs the coding agent to ask whether you want **Cloud Sandbox Mode** or **Free Local Community Mode**:
   - **Free Local Community Mode (`mode="local"`)**: Runs immediately inside a zero-copy Copy-on-Write shadow workspace with native OS kernel sandboxing (`sandbox-exec` on macOS, `bwrap` on Linux) and **zero intermediate permission prompts**.
   - **Aegis Cloud Sandbox Mode (`mode="cloud"`)**: Offloads all heavy compilation (`cargo`, `npm`, `pytest`) and parallel multi-agent sandboxes to remote Linux `btrfs` cloud nodes (**0% local CPU/RAM load**), syncing verified text-only diffs back to your laptop on commit.
3. **Verify Health Anytime**: Run `aegis-os doctor` to check client integrations, or `aegis-os top` to view the live multi-agent collaboration radar.

---

## Core Architectural Pillars

### 1. Transactional Copy-on-Write VFS & 4-Tier Auto-Rebase/Merge (`aos-vfs`)

- **Millisecond Zero-Copy Shadow Forking & Cross-Mount Lazy-CoW**: Clones repositories into `<runtime_dir>/orgs/<org>/agents/<agent>/cow_workspace/upper_workspace/` via **macOS APFS `libc::clonefile`** (`0.71–6.28 ms` for 100–1,000 files) or **Linux Btrfs/XFS single-open 7-syscall `ioctl(FICLONE)` reflink** (`15.6 ms` on btrfs; plus optional kernel `BTRFS_IOC_SNAP_CREATE_V2` subvolume snapshots via `AOS_BTRFS_SUBVOL=1`), allocating physical disk blocks only for modified files. On cross-mount setups (`ext4 -> tmpfs`), oversized assets fall back to full copies instead of symlinks: once the shadow is mounted at the original project path, a symlink back to that same path would be self-referential. OverlayFS/fuse-overlayfs is the planned O(1) fallback for ext4.
- **Continuous Auto-Rebase & `mtime` Sync**: Automatically runs `refresh_from_host()` at every turn start (`PreInvocation`) and workspace tool boundary (`workspace_status`, `workspace_sync`, `workspace_diff`, `workspace_commit`), bumping file `mtime`s on fast-forwarded and merged files so incremental compilers (`cargo`) always recompile peer-updated dependencies.
- **4-Tier Conflict Resolution Engine (`three_way_merge_lines`) & Pre-Commit Semantic Verification Gate (`verify_cmd`)**:
  1. **Tier 1 (Zero-Copy Fast-Forward)**: Untouched text and binary files updated on the host by peer agents are fast-forwarded into the shadow workspace and baseline snapshot automatically.
  2. **Tier 2 (2-Phase LCS Diff3, Superset & Commutative Declaration Merge)**: Concurrent edits to different lines, identical changes (`th == oh`), superset line additions (`is_subsequence`), or concurrent commutative import/module declarations (`use ...;`, `pub mod ...;`, `import ...`) at the same anchor line are merged automatically without false conflicts.
  3. **Tier 3 (Non-Destructive Conflict Isolation & Sandboxed Semantic Gate)**: True overlapping same-line conflicts never corrupt shadow source files with `<<<<<<<` markers; instead, `RefreshReport.conflict_details` records the exact file, line number, and both versions, pushing an `[Aegis-OS Merge Conflict Alert]` to the agent at `PreInvocation`. In addition, `workspace_commit` supports an optional sandboxed `verify_cmd` (explicitly passed, via `AOS_VERIFY_CMD`, or configured in `<repo>/.aegis/verify.json`) that catches disjoint-line semantic regressions before any host file is modified.
  4. **Tier 4 (Binary Artifact Guard)**: Prevents accidental overwrite of concurrently generated binary artifacts (`.pdf`, `.tar.gz`), supporting scoped `paths` commits or explicit `overwrite_binaries: true`.

### 2. Dual-Tier Kernel Sandbox & Confused-Deputy-Safe Egress Proxy (`aos-sandbox`, `aos-egress`)

- **Mandatory Access Control, Default-Deny `$HOME` Credential Isolation & Process-Group Lifecycle**: Executes every `proc_exec` command under macOS Seatbelt (`/usr/bin/sandbox-exec`) or Linux Bubblewrap (`/usr/bin/bwrap --unshare-all`) with a sanitized environment (`env_clear()`), denying all writes outside the shadow workspace (`(deny file-write*)`), blocking reads to `~/.ssh`, `~/.aws`, `~/.gnupg`, `~/.kube`, `~/.docker`, `~/.azure`, `~/.config/{gh,gcloud}`, `~/.npmrc`, `~/.netrc`, `~/.git-credentials`, and Keychains on macOS, and mounting a **default-deny empty `--tmpfs` over `$HOME`, `/root`, and `/home/*`** on Linux (before selectively re-binding read-only `.rustup` and `.cargo/{bin,registry,git}` toolchains) so even unknown custom credential paths in `$HOME` are completely hidden. Tracks active sandbox process groups (`active_pgids`) to enforce real kernel `SIGSTOP` / `SIGCONT` / `SIGKILL` across `pause()`, `resume()`, and `destroy()`.
- **L7 Method/Path-Scoped Boundary Secret Injection, HTTPS `CONNECT` Tunneling & Outbound DLP (`inspect_payload_dlp`)**: Agents receive only opaque `$AOS_SECRET_*` placeholders. Outbound requests traverse an identity-pinned local TCP proxy (`127.0.0.1:<port>`) enforced by Seatbelt `(allow network-outbound (remote ip "localhost:<port>"))` (or a token-authenticated Unix-socket egress bridge on Linux), supporting both **HTTPS `CONNECT host:port` bidirectional TCP tunnels** (validated against the organization domain allowlist) and **upstream HTTP forwarding** (`X-Aegis-Forward: 1` / `X-Aegis-Upstream`), which canonicalizes URL paths (RFC 3986 `normalize_request_path`), injects real credentials at the network boundary only when the destination `Host`, HTTP method, and URL path prefix match the secret's `SecretScopeRule`, and scans URL query strings and HTTP bodies via `inspect_payload_dlp` for leaked placeholders, vault values, and standard credential formats (PEM private keys, AWS `AKIA*`, GitHub `ghp_*`, `sk-*`, `xoxb-*`), rejecting exfiltration with `HTTP/1.1 403 Forbidden`.

### 3. Google A2A Inter-Agent IPC, Global Peer Discovery & Live Collaboration Radar (`aos-ipc`, `aos-cli`)

- **Agent-First / Zero-CLI Multi-Agent Orchestration**: Users never need to manually run `aegis-os` CLI commands to coordinate agents. Simply instruct your lead agent (`agy`, `claude`, or `codex`) in natural language—agents autonomously discover peers (`ipc_list_peers`), claim files (`coord_claim`), delegate hierarchical subtasks (`ipc_request` with `parent_task_id` / `depends_on`), wait for peer completion without polling (`ipc_wait`), and inspect task trees and tamper-evident audit traces (`ipc_task_get` / `ipc_task_list`).
- **Global Workstation Peer List & Zombie PID Pruning**: Discovers peers across both the current organization and all repositories on the workstation (`ipc_list_peers(scope="global")`, `<org_id>/<agent_id>` addressing), automatically pruning dead or PID-recycled client processes via kernel process start-time verification (`PROC_PIDTBSDINFO` / `/proc/<pid>/stat`).
- **Hierarchical Google A2A Tasks & Cascade Cancellation**: Synthesizes dynamic `AgentCard`s (`GET /.well-known/agent.json`, `ipc_update_card`) and tracks stateful `A2ATask` lifecycles (`submitted` → `working` → `input-required` → `completed` | `failed` | `canceled` | `rejected` via `POST /a2a` and `ipc_request`/`ipc_task_update`/`ipc_reply`). Tasks support parent-child hierarchies (`parent_task_id`), DAG dependencies (`depends_on`), and **recursive cascade cancellation**—canceling a parent task automatically cancels all non-terminal descendants and revokes their bound file claims, session leases, and UOMP memory sessions.
- **Task-Bound Glob File Claims, `proc_exec` Write Warnings & Auto-Release**: `coord_claim` detects overlapping glob patterns (`src/**` vs. `src/auth/*.rs`) via a 2D NFA + live workspace file-tree intersection engine, binds claims to the agent's active `task_id`, warns when sandboxed `proc_exec` scripts touch peer-claimed files (`coordination_warning`), and **automatically releases claims** upon `workspace_commit` or terminal task transitions.
- **Serialized Host Commits & Epoch Re-Verification**: Concurrent `workspace_commit` calls across agents are serialized via a cross-process host commit lock (`host_commit.lock`) and monotonic `host_commit_epoch`. If a peer commits while `verify_cmd` is running, `workspace_commit` automatically re-merges against the updated host trunk and re-runs `verify_cmd` before landing.
- **Tamper-Evident SHA-256 Hash-Chained Audit Ledger**: Every boundary action (`coord_claim`, `workspace_commit`, `ipc_request`, `policy_escalation`) is recorded in `aos-recorder` with `task_id`, `prev_hash`, and `event_hash = sha256(prev_hash || canonical_event)`. Agents and users can verify chain integrity directly via `ipc_task_get` (`audit_trace` + `hash_chain_verified: true`), while `aegis-os a2a board` / `aegis-os top` remain available as optional read-only terminal inspectors.
- **Reference-Based CAS (`FilePart`)**: Publishes large specifications to Content-Addressable Storage (`artifact://<org>/sha256:<hash>`), reducing in-transit IPC payload tokens by **99.85%**.

### 4. Declarative Cedar 5-Stage Policy Engine, TOCTOU-Pinned Leases & Commit-Time Poisoning Guards (`aos-policy`)

- Parses and evaluates declarative `permit` / `forbid` rules from [`policy/default.cedar`](policy/default.cedar) (plus optional custom policies via `AOS_CEDAR_POLICY_FILE`) across five priority tiers: **R0a** (Host Red-Line & Custom Cedar `forbid` Deny), **R0b** (Commit-Time Hook, CI & Build-Script Guard consolidating all touched sensitive paths such as `.git/hooks/*`, `.husky/*`, `.git/config`, `.envrc`, `.aegis/*`, `.github/workflows/*`, `build.rs`, `Makefile`, `package.json`, `Cargo.toml`, and `.cargo/config.toml` into a single `workspace_commit_sensitive` human review card even under an active lease), **R1** (Cross-Tenant Gate), **R2** (Cryptographically Pinned One-Shot `sha256:<evidence_hash>` Lease bounded to 15m to prevent TOCTOU diff swaps between `Ask` and `Approve`, or TTL-Scoped `15m`/`1h` `LeaseGrant` with 1-click revocation via `POST /v1/leases/revoke`), **R3** (Declarative Cedar Green-Zone Auto-Allow with 0 prompts), and **R4** (Human-Readable Boundary Escalation with 30m ticket TTL and explicit `approve_escalation` / `deny_escalation`).


### 5. Aegis Cloud PaaS Control Plane, Git-to-PR Pipeline & Vector Web Mission Control (`aos-mcp-gateway::paas`)

- **Scoped Multi-Tenant API Keys (`ak_live_*`)**: Issues SHA-256 hashed Bearer tokens (`POST /v1/tenants/keys`) cryptographically bound to `(org_id, agent_id, role, workspace_id)`, authenticating remote agent swarms over `POST /v1/mcp` and `POST /v1/a2a` without trusting client-supplied identity headers.
- **Cloud Git Workspace Provisioning & Automated PR Export**: `POST /v1/workspaces` provisions a base repository and forks parallel CoW agent environments in `<10ms`. When an agent finishes coding, `POST /v1/workspaces/pr` (or the `workspace_export_pr` MCP tool) reconciles changes via the 4-Tier LCS Diff3 Engine, commits onto a dedicated Git branch, and exports the commit SHA, `git format-patch` unified diff, and GitHub Pull Request payload.
- **Embedded Vector Web Mission Control & Keyless 1-Click Approval Console (`GET /dashboard`, `GET /approve`)**: Single-binary web consoles served by `aegis-os daemon` (with `/approve` automatically opened in your browser and auto-resumed whenever a boundary escalation occurs, requiring zero manual API key entry on local workstations and email-based lookup for cloud subscriptions):
  1. **Overview, Inline Diff Preview & HITL Approvals**: Paginated boundary escalation queue (`Inspect Diff` inline syntax-highlighted Unified Diff drawer via `GET /v1/approvals/diff`, `Approve Once (SHA-256 Pinned)`, `Grant 15m Lease`, `Grant 1h Lease`, `Deny`), interactive escalation simulator (`POST /v1/approvals/simulate`), and split Live Peer Radar + Google A2A Tasks tables.
  2. **CoW Workspaces & Git-to-PR**: Cloud workspace provisioner and slide-over Unified Diff Patch Inspector modal.
  3. **Zero-Trust Secret Vault & Active Lease Revocation**: Domain + path-prefix `$AOS_SECRET_*` binding, paginated Active Session Leases with live TTL countdowns, and 1-click `Revoke` (`POST /v1/leases/revoke`).
  4. **Connect Agent & API Keys**: One-click `ak_live_*` key minter that auto-populates copy-pasteable `mcp_config.json` and `curl` snippets.

---

## Memory Consent (UOMP)

Aegis OS is the reference runtime for **[UOMP](https://www.uomp.org/)**, an open protocol for agent memory consent. UOMP defines how an agent asks for personal memory — scope, duration, revocation, and audit — and Aegis OS enforces those semantics with its kernel sandbox, policy engine, leases, and trusted approval flow.

> **UOMP defines how agents ask for memory. Aegis OS enforces it.**

| UOMP concept | Aegis OS mechanism |
| :--- | :--- |
| Memory scope (`tag` / `key` / `field`) | Policy resources and actions in `aos-policy` |
| Consent request | Boundary escalation (`approval_required` + `escalation_id`) |
| Session / capability token | TTL or one-shot `LeaseGrant` |
| Memory Guard | MCP gateway + policy engine + sandboxed runtime |
| `uom.json` memory profile | Aegis manifest / policy resource declarations |
| Revocation | Lease expiry, explicit revoke, or session close |
| Audit trail | `aos-recorder` append-only event log |
| High-sensitivity approval | R4 human escalation + trusted approver UI |

The first Phase 1 building block lives in [`crates/aos-memory`](./crates/aos-memory): UOMP scope → Aegis resource mapping, lease planning, deny/field filtering, and high-sensitivity key detection. The `memory_policy_evaluate` MCP tool evaluates one UOMP memory resource and returns `allow`, `ask` (with an `escalation_id`), or `deny`. `aos_memory::validate_remote_access` provides the policy core for the remote Agent entry point (audience, expiry, revocation, endpoint, TTL, and scope checks). `aos-memory-gateway` adds EdDSA JWT verification, a session-status check, per-session rate limiting, JSONL audit, optional native TLS 1.3 / mTLS, and a minimal HTTP proxy for reads, staged writes, and encrypted payloads: `aegis-os memory-gateway --public-key <jwk> --audience <url> --guard-url <url>` (put a TLS 1.3 / mTLS terminator in front in production; see [Aegis Memory Gateway deployment](./docs/MEMORY_GATEWAY_DEPLOY.md)). UOMP is tracked as a first-class module in [`modules/uomp`](./modules/uomp). The user-facing memory entry point is `aegis-os memory ...`. Every memory command is native Rust: `status`, `import`, `read`, `list`, `search`, `serve`, `setup`, `ui`, `pending`, `approve`, `deny`, `connect`, `disconnect`, `sessions`, `revoke`, `audit`, `approvals`, `stop`, `staged`, `payload`, and `mcp`. `aos-memory-store` owns the data plane, `aos-memory-server` owns consent/sessions/tokens/audit, and `aos-memory-gateway` remains the remote Agent entry point. The archived `uomp-core` / `uomp-mvp` reference is no longer vendored or invoked.

```bash
aegis-os memory setup claude --vault ~/Notes
aegis-os memory ui          # local trusted consent page (auto-started by the MCP bridge)
aegis-os memory status
aegis-os memory staged list
aegis-os memory payload list
aegis-os memory approvals
```

`aegis-os memory ui` serves a loopback-only approval page at `127.0.0.1:9375`. The MCP bridge starts it automatically and opens the browser when a consent request is pending, so the user does not need a second terminal. The page shows the agent, task, session, expiry, and requested tags/keys; the user selects the exact scope and approves or denies. The admin token stays inside the UI process and is never exposed to the agent-facing bridge. `memory pending` / `approve` / `deny` remain as a CLI fallback.

The native data plane lives in [`crates/aos-memory-store`](./crates/aos-memory-store): a UOMP-compatible SQLite schema, Markdown importer, staged writes, and payloads. [`crates/aos-memory-server`](./crates/aos-memory-server) adds consent requests, Ed25519 sessions, revocation, and audit. See [Aegis Memory Data Plane](./docs/MEMORY_DATA_PLANE.md).

The protocol remains vendor-neutral and independently specified; Aegis OS is one implementation. See the [UOMP specification](https://www.uomp.org/spec/), the [UOMP website](https://www.uomp.org/), and the [UOMP → Aegis OS memory consent mapping](./docs/UOMP_MEMORY_CONSENT_MAPPING.md).

---

## MCP Tools, Dynamic URI Resources & Cloud PaaS Endpoints

| Subsystem                                                            | MCP Tools / Resources / HTTP Endpoints                                                                                                                                                                                                                                                                                | Default Policy & Runtime Semantics                                                                                                                                          |
| :------------------------------------------------------------------- | :-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | :-------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Transactional VFS** (`aos-vfs`, 7 tools)                           | `fs_read`, `fs_write`, `fs_edit`, `fs_delete`, `fs_glob`, `workspace_status`, `workspace_sync`                                                                                                                                                                                                                        | **Auto-Allow (0 Prompts)**: Confined to CoW shadow workspace; auto-rebases from host                                                                                        |
| **Time-Travel, Merge & PR** (`aos-vfs`, 5 tools)                     | `workspace_snapshot`, `workspace_diff`, `workspace_rollback`, `workspace_commit`, `workspace_export_pr`                                                                                                                                                                                                               | Snapshots/Diff/Rollback **Auto-Allow**; `workspace_commit` & `workspace_export_pr` **Approval/Lease Gate**                                                                  |
| **OS Process Sandbox** (`aos-sandbox`, 1 tool)                       | `proc_exec`                                                                                                                                                                                                                                                                                                           | **Auto-Allow (0 Prompts)**: Kernel Seatbelt/`bwrap` confinement; blocks credential reads                                                                                    |
| **Inter-Agent IPC & Claims** (`aos-ipc`, 11 tools)                   | `ipc_send`, `ipc_recv`, `ipc_request`, `ipc_reply`, `ipc_ack`, `ipc_wait`, `ipc_publish`, `ipc_subscribe`, `ipc_list_peers`, `coord_claim`, `coord_release`                                                                                                                                                           | **Auto-Allow Intra-Org & Verified Workstation Peers**: Enforces task-bound glob file claims (`coord_claim`), auto-release on commit, and blocking `ipc_wait`                 |
| **Google A2A Protocol** (`aos-ipc`, 4 tools + HTTP)                  | `ipc_update_card`, `ipc_task_update`, `ipc_task_get`, `ipc_task_list` + `GET /.well-known/agent.json`, `POST /a2a`, `POST /v1/a2a`                                                                                                                                                                                    | **Auto-Allow Discovery & Task Lifecycle**: Hierarchical `A2ATask` (`parent_task_id`, `depends_on`), cascade cancel, and SHA-256 `audit_trace` verification                  |
| **Org CAS & KV** (`aos-vfs`, 4 tools)                                | `org_artifact_publish`, `org_artifact_fetch`, `org_kv_put`, `org_kv_get`                                                                                                                                                                                                                                              | **Auto-Allow Intra-Org**: Cross-org `artifact://` `FilePart` fetch gated by Rule R1                                                                                         |
| **Zero-Trust Egress** (`aos-egress`, 1 tool)                         | `egress_http_request` + Pinned TCP Proxy (`127.0.0.1:<port>`)                                                                                                                                                                                                                                                         | **Allowlisted Domains + Path Prefixes Auto-Allow**: Injects `$AOS_SECRET_*` at boundary; blocks exfil (`403`)                                                               |
| **Policy, Leases & Mode Switch** (`aos-policy` + `aos-cli`, 2 tools) | `policy_list_escalations`, `runtime_configure_mode` + `aegis-os approve` (`aos approve`) & `GET /approve` (approvals and leases are human-only)                                                                                                                                                                                                 | Zero-CLI-switch human approvals (auto-opened `/approve` Web UI with auto-resume, IDE prompt, or `aos approve`), TTL session leases, and live Local/Cloud mode switch |
| **AAP-1.0 App Store & Proxy** (`aos-mcp-gateway`, 3 tools + CLI)     | `app_catalog_search`, `app_mount_session`, `app_call_tool` + `aegis-os app <connect\|list\|search\|info\|install\|login\|logout\|mount\|call>`                                                                                                                                                                           | **3-Tier Ecosystem (`first_party`, `verified`, `community`)**: 1-step `aegis-os app connect <app_id>`, user-bound `aegis_at_*` tokens, auto-install SOP skills, and MCP proxy |
| **Cloud PaaS Control Plane** (`aos-mcp-gateway`)                     | `GET /dashboard`, `GET /approve`, `GET /api/status`, `POST /v1/workspaces`, `POST /v1/workspaces/sync-up`, `POST /v1/workspaces/diff`, `POST /v1/workspaces/hibernate`, `POST /v1/workspaces/wake`, `POST /v1/workspaces/pr`, `POST /v1/tenants/plan`, `POST /v1/tenants/keys`, `POST /v1/vault/secrets`, `POST /v1/approvals/decide` | Multi-tenant cloud workspace provisioning, Scale-to-Zero hibernation (`<10ms` wake), auto-incremental source sync, Git-to-PR export, `ak_live_*` auth, and `/approve` Web UI |
| **Dynamic MCP URIs** (7 resources)                                   | `aegis://workspace/status`, `aegis://ipc/inbox`, `aegis://org/peers`, `aegis://global/peers`, `aegis://a2a/agent-cards`, `aegis://a2a/tasks`, `aegis://org/shared/catalog`                                                                                                                                            | Live introspection for IDE status bars, global peer topology, and A2A task tables                                                                                           |

---

## Local Community Mode (Free) vs. Aegis Cloud Mode (Subscription)

To coding agents (`agy`, `claude`, `codex`), **Local Mode** and **Cloud Mode** expose the **exact same 39 MCP tools and transactional CoW semantics (100% behavioral isomorphism)**. Under the hood, they provide two distinct execution tiers:

| Dimension                                              | Local Community Mode (Free / Open-Core)                                                                                                                                                     | Aegis Cloud Sandbox Mode (`Pro` / `Team` / `Enterprise`)                                                                                                                                                                                                                                              | Developer Value of Cloud Mode                                                                                                                |
| :----------------------------------------------------- | :------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | :---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | :------------------------------------------------------------------------------------------------------------------------------------------- |
| **1. Local CPU, Memory & Battery Load**                | **Runs on Local Machine**: Compilers (`cargo build`, `npm build`), test suites, and parallel agent sandboxes consume local CPU, RAM, and battery.                                           | **0% Local CPU/RAM Load**: Local machine runs only a `<5 MB` `mcp-stdio` transparent proxy (`serve_unified_stdio`); all heavy builds and tests execute on remote Linux cloud nodes.                                                                                                                   | Keep your MacBook completely silent and cool while driving 8–32 concurrent coding agents on heavy Rust/C++/TypeScript builds.                |
| **2. Isolation Boundary & Supply-Chain Safety**        | **Local OS Process Sandbox** (macOS `Seatbelt` / Linux `bwrap`): Masks `~/.ssh`, `~/.aws`, etc., and blocks direct host repo writes, but shares the host OS kernel and local network stack. | **Physical VM Isolation + Source-Only Diff Return**: Untrusted code and dependency scripts (`build.rs`, `postinstall`) execute inside remote Linux `bwrap` namespaces; binary artifacts (`NUL` bytes) are stripped at the boundary so **only verified text-only source diffs return to your laptop**. | Eliminates the risk of poisoned packages or hallucinated scripts attacking your local kernel, probing your LAN, or polluting local binaries. |
| **3. Multi-Agent Concurrency & CoW Engine**            | Bounded by laptop RAM and disk space (typically **1–2 concurrent local agents**).                                                                                                           | Backed by Linux **`btrfs` `FICLONE` block-level zero-copy** with elastic concurrency quotas (`Community`: 2, `Pro`: 8, `Team`: 32, `Enterprise`: 256 concurrent cloud agents) sharing pre-warmed build caches.                                                                                        | Launch large multi-agent swarms (parallel refactoring, test generation, bug fixing) with instant `<15ms` CoW branching.                      |
| **4. Scale-to-Zero Hibernation & Cross-Device Resume** | Ephemeral local state (`/tmp/aegis-os-runtime`); uncommitted shadow state is tied to a single machine.                                                                                      | **`Active <-> Hibernated` Scale-to-Zero Lifecycle**: Automatically releases in-memory kernel handles when idle (0 compute billing) while persisting CoW upper layers on `btrfs`; wakes automatically in **`<10ms`** on the next MCP call.                                                             | Close your laptop lid anytime with zero idle compute cost, and resume uncommitted CoW transactions seamlessly from another machine.          |
| **5. Team Collaboration & Direct Git PR Export**       | IPC bus, cooperative file claims (`coord_claim`), and CAS artifacts are scoped to windows on a single workstation.                                                                          | **Shared Cloud Organization & Git-to-PR Pipeline**: Multiple developers' agents collaborate over a shared cloud A2A/IPC bus and centralized Secret Vault (`$AOS_SECRET_*`), and export 3-way merged branches directly as GitHub/GitLab Pull Requests (`aegis-os cloud pr`).                           | Enables team-wide multi-agent collaboration and headless CI/CD agents that open verified PRs directly from the cloud.                        |
| **6. Quotas, Metering & Remote HITL Approvals**        | Local terminal/IDE approvals only; no usage metering.                                                                                                                                       | Built-in `TenantUsageRecord` metering (`total_syscalls`, `sandbox_exec_ms`, `cow_saved_bytes`), `ak_live_*` key management, and operator-only remote HITL approvals (`aegis-os cloud approvals` / `cloud approve`).                                                                                 | Full cost/usage visibility for solo Pro developers and centralized audit/lease governance for engineering teams.                             |

---

## Cloud Mode, Daemon Authentication & Approver Enrollment

### 1. Seamless Local <-> Cloud Mode Switching

1. **Open your coding agent directly** (`agy`, `claude`, or `codex`) in any project directory.
2. **Automatic First-Run Subscription Check**: On first launch in a project, Aegis OS's `PreInvocation` hook instructs the coding agent to ask whether you have an **Aegis Cloud Subscription**:
   - **With Subscription (Cloud Mode)**: The agent calls the `runtime_configure_mode(mode="cloud")` MCP tool, provisions your remote Linux `btrfs` CoW workspace, uploads clean source files, and **hot-switches the live IDE session to Zero-Local-Load Cloud Mode** without restarting. Whenever `workspace_commit` succeeds on the cloud sandbox, verified text-only source changes are automatically synced back to your local repo.
   - **Without Subscription (Local Mode)**: The agent calls `runtime_configure_mode(mode="local")` and runs immediately in **Free Local Community Mode** using your local CoW shadow workspace and native OS sandbox.
3. **Switch Anytime in Natural Language**: Simply tell your agent *"Switch to Cloud mode"* or *"Switch back to Local mode"* at any point in a conversation.

### Daemon authentication

`aegis-os daemon` requires authentication by default. Static pages, discovery (`/.well-known/*`), `/health` and the billing flow are public. Every other endpoint needs one of:

- **Operator token**: `AOS_ADMIN_SECRET`, or a random token printed at startup when it is unset. Send it as `Authorization: Bearer <token>`. Only the operator can see all orgs (`/api/status?org_id=*`), reset approvers or upgrade plans.
- **Tenant API key** (`ak_live_*`): confined to its own org. Any `org_id` naming another org is rejected with 403.

Anonymous callers can mint only the *first* key of an org that has none. `--insecure-no-auth` turns all of this off, for local debugging only.

### Approving Boundary Escalations (Zero Second-CLI-Session Needed)

When an agent reaches a host boundary (such as `workspace_commit`), you **never need to open a separate terminal session** or manually tell the agent to retry:

1. **Auto-Opened Web Approval Console (`/approve` & `/dashboard`) + Auto-Resume**: By default on desktop environments (`agy`, `claude`, `codex`), `aegis-os` automatically opens `/approve` in your browser (with a top-right link to `/dashboard`), waits for you to click **Approve Once** / **Approve for 1 Hour** (entering your 6-digit TOTP authenticator code in Cloud Mode), and **automatically resumes and completes the blocked tool call**.
2. **Pure CLI / Headless SSH Support**: On headless SSH sessions where no browser can open, Local Mode prompts inline via the `PreToolUse` hook (or `!aegis-os approve` inside Claude/Codex), and Cloud Mode lets you type your 6-digit TOTP code directly in the agent chat (`workspace_commit(totp: "123456")`) or run `aegis-os approve --code 123456`.
3. **Unified 1-Command CLI Approval (`aegis-os approve` / `aos approve`)**: Run `aegis-os approve` without arguments—it automatically detects Local vs. Cloud mode and selects the latest pending escalation (`--web` opens `/approve` in your browser; `--deny` rejects).

#### Cloud TOTP Approver Details

Agents hold the tenant key, so a tenant key alone never approves anything in Cloud Mode. Each Cloud org has one **approver**: a person with an authenticator app (TOTP, RFC 6238). Approving a Cloud escalation takes the tenant key **plus** the app's current 6-digit code, which the agent does not have.

- **Enroll, paid plans**: `aegis-os cloud subscribe --claim` (or `--wait`) claims the key and, if the org has no approver yet, mails an enrollment link to the **billing email** (from the payment provider). The claim itself never returns the secret, because the claim token is stored on disk where an agent could read it.
- **Enroll, any plan**: `aegis-os cloud approver enroll --email you@example.com` (or the inline enrollment form on `/approve`) mails a one-time link (30 min). Open it in a browser and press the button to get the QR code.
- **Approve**: Use the auto-opened `/approve` web console, or run `aegis-os approve` (or `aegis-os cloud approve [escalation_id]`). Codes are single-use, tenant leases are capped at 24h, and 5 wrong codes lock approvals for 5 minutes.
- **Operator**: `AOS_ADMIN_SECRET=<operator token> aegis-os approve [id]` still works; `DELETE /v1/approver?org_id=<org>` resets a lost device; `AOS_ADMIN_SECRET=<operator token> aegis-os cloud delete-org <org>` removes an org and all its data (`--force` if it still has an active subscription).
- **Agents are blocked** from running `aegis-os approve`, `aegis-os policy approve|lease`, `cloud approve`, `cloud approver …`, and `memory approve|deny|ui|connect` by the PreToolUse hook.

Mail delivery on the node follows Heurion's mailer: SMTP (`AOS_SMTP_HOST`, `AOS_SMTP_PORT` default 465, `AOS_SMTP_SECURE`, `AOS_SMTP_USER`, `AOS_SMTP_PASS`) first, else the Resend API (`AOS_RESEND_API_KEY`); sender `AOS_EMAIL_FROM` (default `Aegis Cloud <no-reply@heurion.org>`); `AOS_PUBLIC_URL` for the link (default `https://heurion.org/aegis-cloud`).

### 2. CLI-First Cloud Control (`aegis-os cloud`)

For developers who prefer explicit terminal control, 100% of Cloud PaaS operations (including Polar.sh subscription checkout & instant `ak_live_*` key activation) are available as first-class CLI subcommands:

- **Subscribe to Aegis Cloud Pro ($29/mo)**: [https://buy.polar.sh/polar_cl_jCPpzbp4eOAyRbkDP4YzNIFVnYLddbvJZI5Fc27zL0x](https://buy.polar.sh/polar_cl_jCPpzbp4eOAyRbkDP4YzNIFVnYLddbvJZI5Fc27zL0x)

```bash
# One-command subscribe: opens Polar.sh checkout in your browser, waits for payment,
# claims your `ak_live_*` key, and binds the current workspace (`cloud up`) automatically:
aegis-os cloud subscribe --plan pro --email you@example.com --wait

# Or run checkout and claim as two separate steps:
aegis-os cloud subscribe --plan pro --email you@example.com
aegis-os cloud subscribe --claim && aegis-os cloud up

# Authenticate or bind current project to an Aegis Cloud Sandbox (0% local CPU/RAM load)
aegis-os cloud login --endpoint https://heurion.org
aegis-os cloud up

# Inspect remote CoW unified code diff, pending HITL approvals, and tenant metering in terminal
aegis-os cloud diff
aegis-os cloud approvals
aegis-os cloud approver enroll --email you@example.com   # once: add your authenticator app
aegis-os cloud approve <escalation_id>                    # asks for the 6-digit code
aegis-os cloud status

# Sync source-only files, export a GitHub PR bundle, or trigger Scale-to-Zero hibernation
aegis-os cloud push
aegis-os cloud pull
aegis-os cloud pr --branch aegis/feat-1
aegis-os cloud hibernate
aegis-os cloud wake

# Unbind and return to Free Local Community Mode (automatically hibernates cloud workspace)
aegis-os cloud down
```

---

## AAP-1.0 Application Ecosystem & User Workflow Guide (`aegis-os app`)

**Aegis OS** includes native support for the **Aegis Application Protocol (`AAP-1.0`)** (full specification: [`docs/AEGIS_APPLICATION_PROTOCOL.md`](docs/AEGIS_APPLICATION_PROTOCOL.md)) — a unified 3-tier ecosystem (`first_party`, `verified`, `community`) with user-bound grant tokens (`aegis_at_<app_id>.*`), RFC 8628 Device Code passwordless terminal binding, automatic SOP skill installation (`/.well-known/aegis-skills/`), and Policy Kernel lease-gated tool governance.

### End-to-End User Workflow (4 Stages)

#### Stage 1: One-Time App Discovery, Installation & Account Binding
Users install first-party or third-party `AAP-1.0` applications (such as **Heurion 2.0 / 知衡 2.0 `heurion`**) and bind their personal account once:

```bash
# One-step connect (automatically installs manifest/skills, runs Device Code login, and mounts session):
aegis-os app connect heurion

# Or run individual commands (`app login` and `app mount` also auto-install if not yet installed):
aegis-os app list
aegis-os app login heurion --device-code
aegis-os app login heurion --token aegis_at_heurion.<grant_id>.<secret>
```

#### Stage 2: Daily Natural-Language Agent Workflow (Zero-Prompt & Progressive Disclosure)
Once bound, users do **not** need to manually configure per-client tokens or load dozens of tool schemas upfront. Simply talk to any Aegis-OS-connected agent (`agy`, `claude`, `codex`, `hermes`) in natural language:

1. **On-Demand Progressive Session Mounting (`app_mount_session`)**:
   - When a task involves clinical cohorts, biostatistics, or manuscript drafting, the Agent reads the installed `.agents/skills/heurion-clinical-research/SKILL.md` SOP and calls `app_mount_session(app_id: "heurion")` to mount the application on demand without polluting the global context window.
2. **Green-Zone `[Zero-Prompt]` Execution (`app_call_tool`)**:
   - Over 95% of daily research operations execute with **zero confirmation prompts**. Aegis-OS automatically injects `Authorization: Bearer aegis_at_<app_id>.*`, `X-Aegis-Agent-Id`, and `X-Aegis-Session-Id` at the gateway boundary:
     - **Downlink Data to CoW Sandbox**: Call `dataset_open` or `labs_open` to receive de-identified inline `csv_content` directly inside the Agent's isolated Aegis-OS Copy-on-Write (CoW) sandbox for Python (`lifelines`, `statsmodels`, `matplotlib`) execution.
     - **Uplink Figures with Code Provenance**: Call `asset_upload(data_base64, code, dataset_ids)` from the CoW sandbox to upload publication-grade figures alongside their exact generating script and dataset lineage.
     - **Multi-Agent Collaborative Editing & Turn-Level Undo**: Multiple agents can concurrently edit manuscripts via `doc_edit`; if any agent introduces an error, `doc_revert_turn` selectively rolls back only that agent's turn while preserving peer agents' edits.
3. **Direct CLI Tool Invocation (Optional for Scripting)**:
   ```bash
   aegis-os app mount heurion
   aegis-os app call heurion doc_list --args '{}'
   ```

#### Stage 3: Yellow-Zone `[Lease-Gated]` High-Sensitivity Approval Workflow
When an agent attempts an irreversible or clinically sensitive action (e.g., `report_resolve` / `lab_resolve` to commit AI-extracted lab values into the permanent patient record, or `doc_manage(purge)` to permanently destroy a document):

1. **Automatic Interception & Escalation**: The `AAP-1.0` gateway intercepts the call and returns `status: "approval_required"` with an `escalation_id` (e.g., `esc-heurion-...`) and `suggested_lease_scope`.
2. **One-Click Human-in-the-Loop Approval (Web UI or Terminal)**:
   - **Via Application Web UI**: Click **Approve (10-min Lease)** or **Reject** in the Account Center's pending escalations panel.
   - **Via Aegis-OS CLI**:
     ```bash
     aegis-os policy approve <escalation_id>
     ```
3. **Cryptographic Lease Verification**: Once approved, subsequent retries within the lease TTL automatically carry `X-Aegis-Lease-Token` (verified via the bound node's Ed25519 public key or active server lease) and record the approving user's identity in the immutable audit trail.

#### Stage 4: Credential Inspection & Instant Revocation
- **Revoke from Terminal**:
  ```bash
  aegis-os app logout heurion
  ```
- **Revoke from Web UI**: Inspect all bound Aegis-OS nodes, their last active timestamp, and calling `X-Aegis-Agent-Id` in the Web Account Center. Revoking a single grant or triggering **Logout Everywhere** (`token_version` increment) invalidates the corresponding `aegis_at_<app_id>.*` tokens immediately across all agents.

### Progressive MCP Tools Reference (`aos-mcp-gateway`)
| MCP Tool | Permission Tier | Description |
| :--- | :--- | :--- |
| `app_catalog_search` | `[Zero-Prompt]` | Search `first_party`, `verified`, and `community` `AAP-1.0` applications and check local install/auth status. |
| `app_mount_session` | `[Zero-Prompt]` | Mount an `AAP-1.0` application into the current Agent session and inspect its `zero_prompt` vs `lease_gated` tools and SOP skills. |
| `app_call_tool` | `[Zero-Prompt]` / `[Lease-Gated]` | Invoke any remote MCP tool over `POST /api/aegis/mcp` with automatic `Bearer aegis_at_...`, `X-Aegis-Agent-Id`, `X-Aegis-Session-Id`, and `X-Aegis-Lease-Token` injection. |

---

## Empirical Benchmark Suite (`aegis-os bench`)

Reproduce all 100+ unit/integration tests and all empirical experiments from our research paper ([`paper/aegis_os_arxiv_preprint.pdf`](paper/aegis_os_arxiv_preprint.pdf) and [`BENCHMARK_REPORT.md`](BENCHMARK_REPORT.md)):

```bash
cargo test --workspace
cargo run --release --bin aegis-os -- bench --report-out BENCHMARK_REPORT.md
python3 scripts/e6_real_traces.py
python3 scripts/e5_cli_sandboxes.py
cargo build --release -p aos-cli --features ablation && python3 scripts/e5_ablation.py
```

### Summary of Empirical Results (`macos-aarch64` APFS & `linux-aarch64` Ubuntu 24.04 btrfs/XFS/ext4)

| Experiment                                                                                  | Key Empirical Finding                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                      |
| :------------------------------------------------------------------------------------------ | :--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **EXP 1 & 1B: Authorization Friction (1,500 Controlled Calls + 28,087 Real Session Calls)** | Reduces human confirmation prompts by **94.19%–99.88%** across 50 controlled trajectories (from **57.33%** `Host-Interactive` / **45.33%** `Host-Static-Allowlist` to **3.33%** `Per-Task Commit Gate` and **0.07%** `1h Session Lease`), and by **90.7%–97.9%** across **52 real production coding-agent session logs (28,087 tool calls)**, lowering aggregate IPR from **53.31%** (`Ask-Every-Mutation`) and **28.54%** (`Path+Prefix Allowlist`) to **1.12%** (`Aegis OS`).                                                                                                                                                                                                                                                                                                                                                                                                                                                                            |
| **EXP 2, 2B & 6: Red-Team Security (80 Live Attacks, 8 Categories) & 9-Row Ablation**       | Lowers Attack Success Rate (ASR) from **100.0% (80/80 in `Host-YOLO`)** and **85.0% / 60.0% (68/80 and 48/80 in Stateless Native CLI Sandboxes)** to **0.0% (0/80 in `Aegis-OS`)** on both **macOS and Linux** across path escape (Cat. A), 10-store credential harvesting including `~/.config/gcloud` and unknown `~/custom_vault/secret_key.pem` via Linux default-deny `--tmpfs $HOME` (Cat. B), proxy/`--noproxy` exfiltration (Cat. C), cross-tenant IPC/CAS breaches (Cat. D), commit-time poisoning of git hooks, `.envrc`, CI workflows, `build.rs`, `Makefile`, `package.json`, and `.cargo/config.toml` under an active lease (Cat. E), cross-domain + same-domain L7 confused-deputy + outbound DLP payload exfiltration (Cat. F), partial commits on conflict (Cat. G), and silent lost updates (Cat. H). A 9-row component ablation (`scripts/e5_ablation.py`) confirms each safety component is necessary for the exact category it guards. |
| **EXP 3A, 3B & 3C: CoW Provisioning, Real-Tool Baselines & Micro-Latency**                  | Clones a 1,000-file (78.1 MB) repo in **`6.28 ± 0.65 ms` on macOS APFS** (**16× faster** than `cp -cR` at `99 ms` and **20× faster** than `git worktree add` at `125 ms`) and **`15.6 ms` on Linux btrfs** via our 7-syscall single-open `FICLONE` path (`35.1 ms` on ext4 `copy_file_range`), with **94.0%–97.5% disk savings** across 10 concurrent agents; `PolicyKernel::evaluate` is **`0.31 µs`** (`2.96M ops/s`), `IpcBus::send+recv` is **`1.06 µs`**, local `POST /mcp` is **`177.11 µs`**, cross-OS macOS-to-Linux `POST /v1/mcp` is **`0.80 ms`** (`P50 = 0.78 ms`, `P99 = 0.99 ms`), and 2-Phase LCS Diff3 `commit_to_host` is **`424.02 µs`**.                                                                                                                                                                                                                                                                                                |
| **EXP 4A, 4B & 4C: 3-Agent Concurrent Rust Build, Syntactic & Semantic Conflict Detection** | Preserves **3/3 (100%)** concurrent structural & function edits across `agy` + `claude` + `codex` (vs. 1/3 in shared host mode), detects **10/10 (100%)** overlapping line conflicts in Phase 1, intercepts **10/10 (100%)** disjoint-line semantic regressions via sandboxed pre-commit `verify_cmd` (`rustc --emit=metadata`), passes `cargo test --offline` (`exit code 0`), and achieves **99.85% in-transit IPC token reduction** via CAS `FilePart` URIs.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            |
| **EXP 5: Multi-File Corruption Time-Travel Rollback**                                       | Atomically rolls back 10, 50, and 200 corrupted Rust modules (up to 12.8 MB) in **`0.75 ± 0.04 ms`**, **`2.33 ± 0.14 ms`**, and **`8.68 ± 1.02 ms`** (**up to 2.4× faster** than sequential file restore), immediately verified by live `cargo check --offline`.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                           |

---

## Workspace Architecture

- [`crates/aos-core`](crates/aos-core): Core traits, syscall contracts, Google A2A state machine (`AgentCard`, `AgentSkill`, `A2ATask`, `A2APart`), session binding, and glob claim primitives.
- [`crates/aos-policy`](crates/aos-policy): Cedar-inspired 5-stage policy engine (`R0a`–`R4`), commit-time hook/CI poisoning guard, human-readable escalation queue (`approve_escalation` / `deny_escalation`), wildcard tenant introspection (`org_id = "*"`), and TTL session leases.
- [`crates/aos-vfs`](crates/aos-vfs): Cross-platform CoW shadow workspace (macOS APFS `libc::clonefile` + Linux Btrfs/XFS `ioctl(FICLONE)` reflink), snapshots, 4-tier LCS Diff3 + Superset 3-Way Merge Engine, `mtime` sync, and Org CAS/KV store.
- [`crates/aos-ipc`](crates/aos-ipc): Global & intra-org peer registry with kernel PID zombie pruning, Google A2A task lifecycle, P2P mailboxes, correlated RPC handoff, and topic Pub/Sub.
- [`crates/aos-sandbox`](crates/aos-sandbox): Dual-tier OS sandbox driver (`NativeOsSandboxDriver` via macOS Seatbelt / Linux `bwrap`, and `MicroVmSandboxDriver`).
- [`crates/aos-egress`](crates/aos-egress): Identity-pinned Zero-Trust TCP HTTP Egress Proxy with domain, HTTP method, and URL path-prefix boundary secret injection (`$AOS_SECRET_*`).
- [`crates/aos-recorder`](crates/aos-recorder): Append-only JSONL flight recorder for syscalls and security telemetry.
- [`crates/aos-mcp-gateway`](crates/aos-mcp-gateway): Unified MCP JSON-RPC & Google A2A server (`lib.rs`), AAP-1.0 App Store & Progressive MCP Proxy (`app_store.rs`), and Cloud PaaS Control Plane & Embedded Vector Web Mission Control Console (`paas.rs`, `assets/dashboard.html`).
- [`crates/aos-cli`](crates/aos-cli): Unified `aegis-os` binary (`install`, `doctor`, `stats`, `up`, `down`, `status`, `top`, `daemon`, `agy-hook`, `workspace`, `policy`, `ipc`, `app`, `cloud`, `memory`, `bench`, `demo`), modular installer & lifecycle hook handlers (`installer.rs`, `hooks.rs`, `telemetry.rs`, `memory_ui.rs`), MCP-first routing, and `PreInvocation` Live Collaboration Radar.
- [`policy/default.cedar`](policy/default.cedar): Baseline declarative Cedar policy rules loaded into `aos-policy` at compile time (extensible via `AOS_CEDAR_POLICY_FILE`).
- [`docs/AEGIS_APPLICATION_PROTOCOL.md`](docs/AEGIS_APPLICATION_PROTOCOL.md): Complete `AAP-1.0` Application Protocol specification (manifest schema, user-bound `aegis_at_*` grant tokens, RFC 8628 Device Code Flow, Ed25519 lease-gated governance, and CoW sandbox data bridge).
- [`paper/`](paper): LaTeX preprint (`main.tex`, `references.bib`, `aegis_os_arxiv_preprint.pdf`) and automated arXiv submission packager (`build_arxiv.sh`, `arxiv_submission.tar.gz`).

---

## Telemetry & Privacy (`DO_NOT_TRACK=1`)

To help us understand adoption across operating systems and coding clients (`agy`, `claude`, `codex`), `aegis-os` records a minimal, strictly anonymous ping during `aegis-os install` and at most once per UTC day on session start:

- **What is sent**: A one-way irreversible 16-hex-character hash (`anon-<16hex>`), Aegis OS version (`0.4.5`), OS/architecture (`macos-aarch64`, `linux-x86_64`), and client type (`agy`, `claude-code`, `codex-cli`).
- **What is NEVER sent**: No source code, file paths, repository names, environment variables, prompts, usernames, or hostnames are ever collected.
- **Inspect or Opt Out Anytime**:
  - View current telemetry & GitHub release stats in your terminal: `aegis-os stats`
  - Disable telemetry completely via environment variable or marker file:
    ```bash
    export DO_NOT_TRACK=1
    # or:
    export AOS_TELEMETRY_DISABLED=1
    # or:
    touch ~/.gemini/aegis-telemetry-opt-out
    ```

---

## Roadmap: Aegis Cloud PaaS (`aegis-cloud`)

We are evolving **Aegis OS** from a local workstation runtime into a **Multi-Tenant Cloud Agent Runtime PaaS** — *"The Cloudflare Workers + Neon Branching for Multi-Agent Systems"*:

### Phase 1: Linux Cloud Runtime, Multi-Tenant Control Plane, Git-to-PR & Embedded Approval UI (Completed)

- [x] **Linux `ioctl(FICLONE)` Reflink CoW & Scale-to-Zero Compute Pool**: Native zero-copy CoW workspace branching (`< 10 ms`) on Linux Btrfs/XFS cloud hosts alongside macOS APFS `clonefile`, paired with Linux `bwrap` / Firecracker MicroVM confinement and auto-idle `pause()` / `resume()`.
- [x] **Multi-Tenant API Gateway & Bearer Token Auth (`ak_live_*`)**: Scoped tenant API keys (`POST /v1/tenants/keys`), hosted Streamable HTTP + SSE MCP (`POST /v1/mcp`), and hosted Google A2A hub (`POST /v1/a2a`) with method/path-scoped `$AOS_SECRET_*` vault rules (`POST /v1/vault/secrets`).
- [x] **Cloud Git Workspace Provisioning & Automated PR Export**: Provision shared project workspaces directly from GitHub repositories (`POST /v1/workspaces`), fork parallel agent CoW branches in milliseconds, reconcile concurrent edits via the 4-Tier LCS Diff3 Engine, and export merged changes directly to a Git branch / Pull Request (`POST /v1/workspaces/pr`, `workspace_export_pr`).
- [x] **Embedded Vector Web Mission Control & HITL Approval Console**: Single-binary, pure-SVG 4-view Web UI served by `aegis-os daemon` (`GET /dashboard`) with live CoW workspace provisioning, PR Unified Diff modal inspector, interactive escalation simulator (`POST /v1/approvals/simulate`), and one-click boundary approvals (`[Approve Once]`, `[Grant 15m Lease]`, `[Grant 1h Lease]`, `[Deny]`).

### Phase 2: Lark / Slack Webhooks, Cloud SDKs & Enterprise BYOC (Next)

- [ ] **Lark (Feishu) & Slack Interactive Approval Webhooks**: Push interactive diff summaries and lease approval buttons directly to Lark and Slack channels whenever cloud agents hit `R0b` / `R4` boundaries.
- [ ] **Python & TypeScript Cloud SDKs (`aegis-cloud`)**: Ergonomic SDKs for orchestrating multi-agent swarms across Claude API, OpenAI Responses API, LangGraph, AutoGen, and CrewAI.
- [ ] **Usage Metering & Time-Travel Trajectory Replay**: Per-tenant CPU-ms / CoW storage metering and interactive replay of `aos-recorder` flight logs and CoW snapshots.
