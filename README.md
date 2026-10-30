# Aegis OS (`aegis-os`)

**A Transactional Multi-Tenant Operating System Runtime & Cloud PaaS for Eliminating Authorization Fatigue in Autonomous Coding Agents (`agy`, `claude`, `codex`)**

![Rust](https://img.shields.io/badge/Rust-1.99%2B-orange.svg)

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
│  • 35 MCP Tools + 7 Dynamic URI Resources (stdio, POST /mcp, POST /v1/mcp)             │
│  • Google A2A Hub (GET /.well-known/agent.json, POST /a2a, POST /v1/a2a)               │
│  • Cloud PaaS API (/v1/workspaces, /v1/workspaces/pr, /v1/tenants/keys, /v1/vault/*)   │
│  • Embedded Vector Web Mission Control & HITL Approval Console (GET /dashboard)        │
└───────────────────────────────────────────────┬────────────────────────────────────────┘
                                                ▼
┌────────────────────────────────────────────────────────────────────────────────────────┐
│  Cedar-Inspired 5-Stage Policy Engine & Session Lease Manager (aos-policy)             │
│  R0a: Host Red-Line Deny │ R0b: Commit Hook/CI Guard │ R1: Cross-Tenant Gate           │
│  R2: TTL/One-Shot Lease  │ R3: Green-Zone Auto-Allow │ R4: Human-Readable Escalation   │
└───────┬──────────────────────────┬───────────────────────────┬────────────────────┬────┘
        ▼                          ▼                           ▼                    ▼
┌───────────────────┐  ┌───────────────────────┐  ┌──────────────────────┐  ┌────────────────────┐
│ Transactional VFS │  │ Dual-Tier OS Sandbox  │  │ A2A IPC Bus & CAS    │  │ Zero-Trust Egress  │
│ (aos-vfs)         │  │ (aos-sandbox)         │  │ (aos-ipc + aos-vfs)  │  │ (aos-egress)       │
│ • APFS clonefile  │  │ • macOS sandbox-exec  │  │ • Global Peer List   │  │ • Identity-Pinned  │
│ • Linux FICLONE   │  │ • Linux bwrap/MicroVM │  │ • A2A AgentCard/Task │  │   Loopback Proxy   │
│ • 4-Tier LCS Diff3│  │ • Exact Port Filter   │  │ • Enforced Claims    │  │ • Domain + Path    │
│ • Git-to-PR Export│  │ • Separate cargo cache│  │ • artifact://sha256  │  │   $AOS_SECRET_*    │
└───────────────────┘  └───────────────────────┘  └──────────────────────┘  └────────────────────┘
```

---

## Core Architectural Pillars

### 1. Transactional Copy-on-Write VFS & 4-Tier Auto-Rebase/Merge (`aos-vfs`)

- **Millisecond Zero-Copy Shadow Forking**: Clones repositories into `<runtime_dir>/orgs/<org>/agents/<agent>/cow_workspace/upper_workspace/` via **macOS APFS `libc::clonefile`** (`0.71–6.28 ms` for 100–1,000 files) or **Linux Btrfs/XFS single-open 7-syscall `ioctl(FICLONE)` reflink** (`15.6 ms` on btrfs; plus optional kernel `BTRFS_IOC_SNAP_CREATE_V2` subvolume snapshots via `AOS_BTRFS_SUBVOL=1`), allocating physical disk blocks only for modified files.
- **Continuous Auto-Rebase & `mtime` Sync**: Automatically runs `refresh_from_host()` at every turn start (`PreInvocation`) and workspace tool boundary (`workspace_status`, `workspace_sync`, `workspace_diff`, `workspace_commit`), bumping file `mtime`s on fast-forwarded and merged files so incremental compilers (`cargo`) always recompile peer-updated dependencies.
- **4-Tier Conflict Resolution Engine (`three_way_merge_lines`) & Pre-Commit Semantic Verification Gate (`verify_cmd`)**:
  1. **Tier 1 (Zero-Copy Fast-Forward)**: Untouched text and binary files updated on the host by peer agents are fast-forwarded into the shadow workspace and baseline snapshot automatically.
  2. **Tier 2 (2-Phase LCS Diff3 & Superset Merge)**: Concurrent edits to different lines, identical changes (`th == oh`), or superset line additions (`is_subsequence`) within the same file are spliced together automatically.
  3. **Tier 3 (Non-Destructive Conflict Isolation & Sandboxed Semantic Gate)**: True overlapping same-line conflicts never corrupt shadow source files with `<<<<<<<` markers; instead, `RefreshReport.conflict_details` records the exact file, line number, and both versions, pushing an `[Aegis-OS Merge Conflict Alert]` to the agent at `PreInvocation`. In addition, `workspace_commit` supports an optional sandboxed `verify_cmd` (e.g., `rustc --emit=metadata` or `cargo check --offline`) that catches disjoint-line semantic regressions before any host file is modified.
  4. **Tier 4 (Binary Artifact Guard)**: Prevents accidental overwrite of concurrently generated binary artifacts (`.pdf`, `.tar.gz`), supporting scoped `paths` commits or explicit `overwrite_binaries: true`.

### 2. Dual-Tier Kernel Sandbox & Confused-Deputy-Safe Egress Proxy (`aos-sandbox`, `aos-egress`)

- **Mandatory Access Control & Default-Deny `$HOME` Credential Isolation**: Executes every `proc_exec` command under macOS Seatbelt (`/usr/bin/sandbox-exec`) or Linux Bubblewrap (`/usr/bin/bwrap --unshare-all`) with a sanitized environment (`env_clear()`), denying all writes outside the shadow workspace (`(deny file-write*)`), blocking reads to `~/.ssh`, `~/.aws`, `~/.gnupg`, `~/.kube`, `~/.docker`, `~/.azure`, `~/.config/{gh,gcloud}`, `~/.npmrc`, `~/.netrc`, `~/.git-credentials`, and Keychains on macOS, and mounting a **default-deny empty `--tmpfs` over `$HOME`, `/root`, and `/home/*`** on Linux (before selectively re-binding read-only `.rustup` and `.cargo/{bin,registry,git}` toolchains) so even unknown custom credential paths in `$HOME` are completely hidden.
- **L7 Method/Path-Scoped Boundary Secret Injection & Outbound DLP (`inspect_payload_dlp`)**: Agents receive only opaque `$AOS_SECRET_*` placeholders. Outbound requests traverse an identity-pinned local TCP proxy (`127.0.0.1:<port>`) enforced by Seatbelt `(allow network-outbound (remote ip "localhost:<port>"))` (or a token-authenticated Unix-socket egress bridge on Linux), which canonicalizes URL paths (RFC 3986 `normalize_request_path`), injects real credentials only when the destination `Host`, HTTP method, and URL path prefix match the secret's `SecretScopeRule`, and scans URL query strings and HTTP bodies via `inspect_payload_dlp` for leaked placeholders, vault values, and standard credential formats (PEM private keys, AWS `AKIA*`, GitHub `ghp_*`, `sk-*`, `xoxb-*`), rejecting exfiltration with `HTTP/1.1 403 Forbidden`.

### 3. Google A2A Inter-Agent IPC, Global Peer Discovery & Live Collaboration Radar (`aos-ipc`, `aos-cli`)

- **Global Workstation Peer List & Zombie PID Pruning**: Discovers peers across both the current organization and all repositories on the workstation (`ipc_list_peers(scope="global")`, `<org_id>/<agent_id>` addressing), automatically pruning dead or PID-recycled client processes via kernel process start-time verification (`PROC_PIDTBSDINFO` / `/proc/<pid>/stat`).
- **Native Google A2A Protocol**: Synthesizes dynamic `AgentCard`s (`GET /.well-known/agent.json`, `ipc_update_card`) and tracks stateful `A2ATask` lifecycles (`submitted` → `working` → `input-required` → `completed` | `failed` | `canceled` | `rejected` via `POST /a2a` and `ipc_request`/`ipc_task_update`/`ipc_reply`).
- **Zero-Prompt Live Collaboration Radar & File Claims**: Tracks delta changes in online peers, cooperative file locks (`coord_claim` / `coord_release`), and in-flight A2A tasks on every `PreInvocation`, automatically injecting `[Aegis-OS Live Collaboration Radar]` updates so parallel windows stay synchronized without manual user relay.
- **Reference-Based CAS (`FilePart`)**: Publishes large specifications to Content-Addressable Storage (`artifact://<org>/sha256:<hash>`), reducing in-transit IPC payload tokens by **99.85%**.

### 4. Cedar-Inspired 5-Stage Policy Engine & Commit-Time Poisoning Guards (`aos-policy`)

- Evaluates every syscall across five priority tiers: **R0a** (Host Red-Line Deny), **R0b** (Commit-Time Hook, CI & Build-Script Guard forcing human review on `.git/hooks/*`, `.git/config`, `.envrc`, `.github/workflows/*`, `build.rs`, `Makefile`, `package.json`, and `.cargo/config.toml` even under an active lease), **R1** (Cross-Tenant Gate), **R2** (One-Shot `ttl=0` or TTL-Scoped `LeaseGrant`), **R3** (Green-Zone Auto-Allow with 0 prompts), and **R4** (Human-Readable Boundary Escalation with explicit `approve_escalation` / `deny_escalation`).


### 5. Aegis Cloud PaaS Control Plane, Git-to-PR Pipeline & Vector Web Mission Control (`aos-mcp-gateway::paas`)

- **Scoped Multi-Tenant API Keys (`ak_live_*`)**: Issues SHA-256 hashed Bearer tokens (`POST /v1/tenants/keys`) cryptographically bound to `(org_id, agent_id, role, workspace_id)`, authenticating remote agent swarms over `POST /v1/mcp` and `POST /v1/a2a` without trusting client-supplied identity headers.
- **Cloud Git Workspace Provisioning & Automated PR Export**: `POST /v1/workspaces` provisions a base repository and forks parallel CoW agent environments in `<10ms`. When an agent finishes coding, `POST /v1/workspaces/pr` (or the `workspace_export_pr` MCP tool) reconciles changes via the 4-Tier LCS Diff3 Engine, commits onto a dedicated Git branch, and exports the commit SHA, `git format-patch` unified diff, and GitHub Pull Request payload.
- **Embedded Vector Web Mission Control & HITL Approval Console (`GET /dashboard`)**: Single-binary, pure-SVG 4-view web console served at `http://127.0.0.1:7080/dashboard`:
  1. **Overview & HITL Approvals**: 3-step architectural mental model banner, clickable KPI cards, one-click boundary escalation queue (`Approve Once (ttl=0)`, `Grant 15m Lease`, `Grant 1h Lease`, `Deny`), interactive escalation simulator (`POST /v1/approvals/simulate`), and split Live Peer Radar + Google A2A Tasks tables.
  2. **CoW Workspaces & Git-to-PR**: Cloud workspace provisioner and slide-over Unified Diff Patch Inspector modal.
  3. **Zero-Trust Secret Vault & Active Leases**: Domain + path-prefix `$AOS_SECRET_*` binding and live lease TTL countdowns.
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

The first Phase 1 building block lives in [`crates/aos-memory`](./crates/aos-memory): UOMP scope → Aegis resource mapping, lease planning, deny/field filtering, and high-sensitivity key detection. The `memory_policy_evaluate` MCP tool evaluates one UOMP memory resource and returns `allow`, `ask` (with an `escalation_id`), or `deny`. `aos_memory::validate_remote_access` provides the policy core for the remote Agent entry point (audience, expiry, revocation, endpoint, TTL, and scope checks). `aos-memory-gateway` adds EdDSA JWT verification, a Guard session-status check, per-session rate limiting, JSONL audit, optional native TLS 1.3 / mTLS, and a minimal HTTP proxy for reads and staged writes: `aegis-os memory-gateway --public-key <jwk> --audience <url> --guard-url <url>` (put a TLS 1.3 / mTLS terminator in front in production; see [Aegis Memory Gateway deployment](./docs/MEMORY_GATEWAY_DEPLOY.md)). It is not yet wired into a memory store or trusted UI.

The protocol remains vendor-neutral and independently specified; Aegis OS is one implementation. See the [UOMP specification](https://www.uomp.org/spec/), the [reference CLI repository](https://github.com/0xSynapse/uomp-core), and the [UOMP → Aegis OS memory consent mapping](./docs/UOMP_MEMORY_CONSENT_MAPPING.md).

---

## MCP Tools, Dynamic URI Resources & Cloud PaaS Endpoints

| Subsystem                                                            | MCP Tools / Resources / HTTP Endpoints                                                                                                                                                                                                                                                                                | Default Policy & Runtime Semantics                                                                                                                                          |
| :------------------------------------------------------------------- | :-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | :-------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Transactional VFS** (`aos-vfs`, 7 tools)                           | `fs_read`, `fs_write`, `fs_edit`, `fs_delete`, `fs_glob`, `workspace_status`, `workspace_sync`                                                                                                                                                                                                                        | **Auto-Allow (0 Prompts)**: Confined to CoW shadow workspace; auto-rebases from host                                                                                        |
| **Time-Travel, Merge & PR** (`aos-vfs`, 5 tools)                     | `workspace_snapshot`, `workspace_diff`, `workspace_rollback`, `workspace_commit`, `workspace_export_pr`                                                                                                                                                                                                               | Snapshots/Diff/Rollback **Auto-Allow**; `workspace_commit` & `workspace_export_pr` **Approval/Lease Gate**                                                                  |
| **OS Process Sandbox** (`aos-sandbox`, 1 tool)                       | `proc_exec`                                                                                                                                                                                                                                                                                                           | **Auto-Allow (0 Prompts)**: Kernel Seatbelt/`bwrap` confinement; blocks credential reads                                                                                    |
| **Inter-Agent IPC & Claims** (`aos-ipc`, 10 tools)                   | `ipc_send`, `ipc_recv`, `ipc_request`, `ipc_reply`, `ipc_ack`, `ipc_publish`, `ipc_subscribe`, `ipc_list_peers`, `coord_claim`, `coord_release`                                                                                                                                                                       | **Auto-Allow Intra-Org & Verified Workstation Peers**: Enforces cooperative file claims                                                                                     |
| **Google A2A Protocol** (`aos-ipc`, 4 tools + HTTP)                  | `ipc_update_card`, `ipc_task_update`, `ipc_task_get`, `ipc_task_list` + `GET /.well-known/agent.json`, `POST /a2a`, `POST /v1/a2a`                                                                                                                                                                                    | **Auto-Allow Discovery & Task Lifecycle**: Dynamic `AgentCard` & stateful `A2ATask` RPC                                                                                     |
| **Org CAS & KV** (`aos-vfs`, 4 tools)                                | `org_artifact_publish`, `org_artifact_fetch`, `org_kv_put`, `org_kv_get`                                                                                                                                                                                                                                              | **Auto-Allow Intra-Org**: Cross-org `artifact://` `FilePart` fetch gated by Rule R1                                                                                         |
| **Zero-Trust Egress** (`aos-egress`, 1 tool)                         | `egress_http_request` + Pinned TCP Proxy (`127.0.0.1:<port>`)                                                                                                                                                                                                                                                         | **Allowlisted Domains + Path Prefixes Auto-Allow**: Injects `$AOS_SECRET_*` at boundary; blocks exfil (`403`)                                                               |
| **Policy, Leases & Mode Switch** (`aos-policy` + `aos-cli`, 2 tools) | `policy_list_escalations`, `runtime_configure_mode` (approvals and leases are human-only: `aegis-os policy approve <id>`)                                                                                                                                                                                                                | Operator control plane for one-shot (`ttl=0`) or TTL-scoped session leases, plus live agent-driven switching between Local Community Mode and Cloud Sandbox Mode            |
| **AAP-1.0 App Store & Proxy** (`aos-mcp-gateway`, 3 tools + CLI)     | `app_catalog_search`, `app_mount_session`, `app_call_tool` + `aegis-os app <list\|search\|info\|install\|login\|logout\|mount\|call>`                                                                                                                                                                                 | **3-Tier Ecosystem (`first_party`, `verified`, `community`)**: User-bound `aegis_at_*` tokens, RFC 8628 Device Code login, SOP skill installer, and lease-gated MCP proxy  |
| **Cloud PaaS Control Plane** (`aos-mcp-gateway`)                     | `GET /dashboard`, `GET /api/status`, `POST /v1/workspaces`, `POST /v1/workspaces/sync-up`, `POST /v1/workspaces/diff`, `POST /v1/workspaces/hibernate`, `POST /v1/workspaces/wake`, `POST /v1/workspaces/pr`, `POST /v1/tenants/plan`, `POST /v1/tenants/keys`, `POST /v1/vault/secrets`, `POST /v1/approvals/decide` | Multi-tenant cloud workspace provisioning, Scale-to-Zero hibernation (`<10ms` wake), source-only sync, Git-to-PR export, `ak_live_*` auth, and minimalist developer console |
| **Dynamic MCP URIs** (7 resources)                                   | `aegis://workspace/status`, `aegis://ipc/inbox`, `aegis://org/peers`, `aegis://global/peers`, `aegis://a2a/agent-cards`, `aegis://a2a/tasks`, `aegis://org/shared/catalog`                                                                                                                                            | Live introspection for IDE status bars, global peer topology, and A2A task tables                                                                                           |

---

## Local Community Mode (Free) vs. Aegis Cloud Mode (Subscription)

To coding agents (`agy`, `claude`, `codex`), **Local Mode** and **Cloud Mode** expose the **exact same 25+ MCP tools and transactional CoW semantics (100% behavioral isomorphism)**. Under the hood, they provide two distinct execution tiers:

| Dimension                                              | Local Community Mode (Free / Open-Core)                                                                                                                                                     | Aegis Cloud Sandbox Mode (`Pro` / `Team` / `Enterprise`)                                                                                                                                                                                                                                              | Developer Value of Cloud Mode                                                                                                                |
| :----------------------------------------------------- | :------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | :---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | :------------------------------------------------------------------------------------------------------------------------------------------- |
| **1. Local CPU, Memory & Battery Load**                | **Runs on Local Machine**: Compilers (`cargo build`, `npm build`), test suites, and parallel agent sandboxes consume local CPU, RAM, and battery.                                           | **0% Local CPU/RAM Load**: Local machine runs only a `<5 MB` `mcp-stdio` transparent proxy (`serve_unified_stdio`); all heavy builds and tests execute on remote Linux cloud nodes.                                                                                                                   | Keep your MacBook completely silent and cool while driving 8–32 concurrent coding agents on heavy Rust/C++/TypeScript builds.                |
| **2. Isolation Boundary & Supply-Chain Safety**        | **Local OS Process Sandbox** (macOS `Seatbelt` / Linux `bwrap`): Masks `~/.ssh`, `~/.aws`, etc., and blocks direct host repo writes, but shares the host OS kernel and local network stack. | **Physical VM Isolation + Source-Only Diff Return**: Untrusted code and dependency scripts (`build.rs`, `postinstall`) execute inside remote Linux `bwrap` namespaces; binary artifacts (`NUL` bytes) are stripped at the boundary so **only verified text-only source diffs return to your laptop**. | Eliminates the risk of poisoned packages or hallucinated scripts attacking your local kernel, probing your LAN, or polluting local binaries. |
| **3. Multi-Agent Concurrency & CoW Engine**            | Bounded by laptop RAM and disk space (typically **1–2 concurrent local agents**).                                                                                                           | Backed by Linux **`btrfs` `FICLONE` block-level zero-copy** with elastic concurrency quotas (`Community`: 2, `Pro`: 8, `Team`: 32, `Enterprise`: 256 concurrent cloud agents) sharing pre-warmed build caches.                                                                                        | Launch large multi-agent swarms (parallel refactoring, test generation, bug fixing) with instant `<15ms` CoW branching.                      |
| **4. Scale-to-Zero Hibernation & Cross-Device Resume** | Ephemeral local state (`/tmp/aegis-os-runtime`); uncommitted shadow state is tied to a single machine.                                                                                      | **`Active <-> Hibernated` Scale-to-Zero Lifecycle**: Automatically releases in-memory kernel handles when idle (0 compute billing) while persisting CoW upper layers on `btrfs`; wakes automatically in **`<10ms`** on the next MCP call.                                                             | Close your laptop lid anytime with zero idle compute cost, and resume uncommitted CoW transactions seamlessly from another machine.          |
| **5. Team Collaboration & Direct Git PR Export**       | IPC bus, cooperative file claims (`coord_claim`), and CAS artifacts are scoped to windows on a single workstation.                                                                          | **Shared Cloud Organization & Git-to-PR Pipeline**: Multiple developers' agents collaborate over a shared cloud A2A/IPC bus and centralized Secret Vault (`$AOS_SECRET_*`), and export 3-way merged branches directly as GitHub/GitLab Pull Requests (`aegis-os cloud pr`).                           | Enables team-wide multi-agent collaboration and headless CI/CD agents that open verified PRs directly from the cloud.                        |
| **6. Quotas, Metering & Remote HITL Approvals**        | Local terminal/IDE approvals only; no usage metering.                                                                                                                                       | Built-in `TenantUsageRecord` metering (`total_syscalls`, `sandbox_exec_ms`, `cow_saved_bytes`), `ak_live_*` key management, and operator-only remote HITL approvals (`aegis-os cloud approvals` / `cloud approve`).                                                                                 | Full cost/usage visibility for solo Pro developers and centralized audit/lease governance for engineering teams.                             |

---

## Quick Start

### 1. Zero-CLI Onboarding (`brew install` → Directly Launch `agy` / `claude` / `codex`)

Users **never need to run `aegis-os` manually** after installation:

```bash
# Install via Homebrew (automatically wires AGY, Claude Code, and Codex CLI in 2 seconds)
brew tap heurion-org/aegis-os https://github.com/heurion-org/aegis-os.git
brew trust heurion-org/aegis-os
brew install aegis-os
```

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

### Approving Cloud escalations

Agents hold the tenant key, so a tenant key alone never approves anything. Each org has one **approver**: a person with an authenticator app (TOTP, RFC 6238). Approving an escalation takes the tenant key **plus** the app's current 6-digit code, which the agent does not have.

- **Enroll, paid plans**: `aegis-os cloud subscribe --claim` claims the key and, if the org has no approver yet, mails an enrollment link to the **billing email** (from the payment provider). The claim itself never returns the secret, because the claim token is stored on disk where an agent could read it.
- **Enroll, any plan**: `aegis-os cloud approver enroll --email you@example.com` mails a one-time link (30 min). Open it in a browser and press the button to get the QR code. Once an org has a billing or approver email, links only go to that address. Opening the link alone changes nothing.
- **Approve**: `aegis-os cloud approve <escalation_id>` shows the escalation and asks for the code (or `--code 123456`; `--deny` rejects). Codes are single-use, tenant leases are capped at 24h, and 5 wrong codes lock approvals for 5 minutes.
- **Operator**: `AOS_ADMIN_SECRET=<operator token> aegis-os cloud approve <id>` still works; `DELETE /v1/approver?org_id=<org>` resets a lost device.
- **Agents are blocked** from running `aegis-os policy approve|lease`, `cloud approve` and `cloud approver …` by the PreToolUse hook. Locally, approve with `aegis-os policy approve <id>` in your terminal (in Claude Code: `! aegis-os policy approve <id>`).

Mail delivery on the node follows Heurion's mailer: SMTP (`AOS_SMTP_HOST`, `AOS_SMTP_PORT` default 465, `AOS_SMTP_SECURE`, `AOS_SMTP_USER`, `AOS_SMTP_PASS`) first, else the Resend API (`AOS_RESEND_API_KEY`); sender `AOS_EMAIL_FROM` (default `Aegis Cloud <no-reply@heurion.org>`); `AOS_PUBLIC_URL` for the link (default `https://heurion.org/aegis-cloud`).

### 2. CLI-First Cloud Control (`aegis-os cloud`)

For developers who prefer explicit terminal control, 100% of Cloud PaaS operations (including Polar.sh subscription checkout & instant `ak_live_*` key activation) are available as first-class CLI subcommands:

- **Subscribe to Aegis Cloud Pro ($29/mo)**: [https://buy.polar.sh/polar_cl_jCPpzbp4eOAyRbkDP4YzNIFVnYLddbvJZI5Fc27zL0x](https://buy.polar.sh/polar_cl_jCPpzbp4eOAyRbkDP4YzNIFVnYLddbvJZI5Fc27zL0x)

```bash
# Subscribe to Aegis Cloud Pro ($29/mo) via Polar.sh & claim your `ak_live_*` key after checkout.
# `subscribe` saves a one-time claim token locally; only that token can collect the paid key.
aegis-os cloud subscribe --plan pro --email you@example.com
aegis-os cloud subscribe --claim

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
# 1. Browse or search the 3-tier AAP-1.0 application catalog (pre-registered with First-Party Heurion 2.0)
aegis-os app list
aegis-os app search heurion
aegis-os app info heurion

# 2. Install the application:
#    - Fetches /.well-known/aegis-app.json
#    - Automatically downloads declared SOP skills into .agents/skills/<skill_id>/SKILL.md
aegis-os app install heurion --url http://127.0.0.1:8787

# 3. Bind your user account (choose any of the 3 methods below):
#    Method A (Recommended — RFC 8628 Passwordless Device Code Flow):
#    Displays an 8-character code (e.g. HEUR-7K9P); enter it in the Web UI Account Center to bind!
aegis-os app login heurion --device-code

#    Method B (Direct Grant Token from Web UI):
aegis-os app login heurion --token aegis_at_heurion.<grant_id>.<secret>

#    Method C (Username & Password Exchange):
aegis-os app login heurion --username dr_zhang --password 'YourPassword'
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

Reproduce all 46 unit/integration tests and all empirical experiments from our research paper ([`paper/aegis_os_arxiv_preprint.pdf`](paper/aegis_os_arxiv_preprint.pdf) and [`BENCHMARK_REPORT.md`](BENCHMARK_REPORT.md)):

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
- [`crates/aos-mcp-gateway`](crates/aos-mcp-gateway): Unified MCP JSON-RPC & Google A2A server (`lib.rs`), AAP-1.0 App Store & Progressive MCP Proxy (`app_store.rs`), and Cloud PaaS Control Plane & Embedded Vector Web Mission Control Console (`paas.rs`).
- [`crates/aos-cli`](crates/aos-cli): Unified `aegis-os` binary (`up`, `down`, `status`, `install`, `doctor`, `top`, `daemon`, `agy-hook`, `workspace`, `policy`, `ipc`, `app`, `cloud`, `bench`, `demo`), MCP-first routing, and `PreInvocation` Live Collaboration Radar.
- [`docs/AEGIS_APPLICATION_PROTOCOL.md`](docs/AEGIS_APPLICATION_PROTOCOL.md): Complete `AAP-1.0` Application Protocol specification (manifest schema, user-bound `aegis_at_*` grant tokens, RFC 8628 Device Code Flow, Ed25519 lease-gated governance, and CoW sandbox data bridge).
- [`paper/`](paper): LaTeX preprint (`main.tex`, `references.bib`, `aegis_os_arxiv_preprint.pdf`) and automated arXiv submission packager (`build_arxiv.sh`, `arxiv_submission.tar.gz`).

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
