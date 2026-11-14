# Aegis OS — Architecture Reference

This document describes how Aegis OS is put together: the trust boundary, runtime roles, core crates, workspace model, policy/approval flow, domain profiles, and cloud control plane. For the threat model, effect model, and phased implementation plan, see [AEGIS_ENFORCED_RUNTIME_DESIGN.md](AEGIS_ENFORCED_RUNTIME_DESIGN.md). For a quick start, see [README.md](../README.md).

---

## 1. Design goals

1. **Transaction boundaries, not tool prompts.** Agents work freely inside an isolated workspace; only host commits and boundary crossings require approval.
2. **Kernel over hooks.** Hooks and MCP are compatibility/UX layers. The security boundary is the launcher + kernel sandbox + broker.
3. **Effects over tools.** Policy is expressed over `fs.read`, `fs.write`, `proc.exec`, `net.request`, `secret.use`, and commit effects—not over client-specific tool names.
4. **Fail closed.** If the sandbox, egress proxy, or broker is unavailable, an enforced session refuses to start.
5. **Domain-agnostic artifact tree.** Code, documents, data pipelines, binaries, and app state share one shadow / claim / verify / commit kernel; domain differences live in profiles.
6. **Platform honesty.** Both Linux (`bwrap >= 0.9.0` with `--bind-fd`, `--unshare-net` (DNS resolved host-side by the egress bridge), and layered state mounts) and macOS (`sandbox-exec` Seatbelt with canonicalized Darwin paths, `HOME` preservation for Keychain/OAuth, credential/token read-deny, `.aegis-bin` Git shim, and loopback L4/L7 egress) are verified end-to-end across live production CLI agents (`Claude Code v2.1.319`, `OpenCode v2.2.6`, `AGY v1.5.3`, `Hermes v0.23.0`, plus `Codex` adapter support). On Linux, the shadow is bind-mounted at the original host path; on macOS, the agent runs with `cwd` in the CoW shadow (full macOS VFS path-remapping and local `--isolated` microVM remain Phase 4).

---

## 2. Trust boundary and runtime roles

```text
Host user space
┌──────────────────────────────────────────────────────────────┐
│  Control plane (human)                                       │
│  aegis-os CLI / Web approval console                         │
│        │ Unix socket / localhost                             │
│  ┌─────▼────────────────────────────────────────────────┐    │
│  │ Aegis Session Supervisor (trusted)                    │    │
│  │  - session identity / token                           │    │
│  │  - policy broker (MCP + control API)                  │    │
│  │  - approval service / audit                           │    │
│  └─────┬────────────────────────────────────────────────┘    │
│        │ kernel sandbox (bwrap / Seatbelt / microVM)         │
│  ┌─────▼────────────────────────────────────────────────┐    │
│  │ Agent process tree (untrusted)                        │    │
│  │  claude / codex / agy / opencode / hermes             │    │
│  │  ├─ native read / write / edit / shell                │    │
│  │  ├─ MCP bridge (may only reach the broker)            │    │
│  │  └─ child agents / build scripts                      │    │
│  └───────────────────────────────────────────────────────┘    │
│                                                              │
│  Host artifact tree: read-only                               │
│  Shadow workspace: writable                                  │
│  $HOME and credentials: masked / read-only                   │
└──────────────────────────────────────────────────────────────┘
```

**Rules**

- Everything inside the agent process tree is untrusted, including client plugins, MCP servers, child agents, and build scripts.
- The only host-write channel is the broker's `workspace_commit`, gated by policy and human approval or a lease.
- Approval endpoints accept human credentials only; agent tokens cannot approve their own escalations.
- The audit ledger lives outside the sandbox. Agents can append events but cannot rewrite history.

---

## 3. Enforcement modes

| Mode | Launch | Enforcement point | Guarantees | Status |
|---|---|---|---|---|
| **Advisory** | `aegis-os install`; user starts the agent | Hooks / MCP / rules | Reduces prompt fatigue and catches honest mistakes; **not** a security boundary against a hijacked agent | ✅ Available |
| **Enforced** | `aegis-os run -- <agent>` or PATH shim | Launcher + kernel sandbox + broker + egress proxy | Host writes confined to shadow; credential & `human.token` reads blocked; egress restricted; commits approved/leased (`0/30` `V1–V6` bypass on macOS & Linux) | ✅ Verified on Linux (`bwrap --bind-fd`) & macOS (`Seatbelt`) across live CLI agents |
| **Isolated** | `aegis-os run --isolated` / Aegis Cloud | microVM + remote policy | Host-level isolation for untrusted repos and multi-tenant teams | 🟡 Cloud sandbox available; local `--isolated` Phase 4 |

The mode is surfaced in `aegis-os status`, `aegis-os doctor`, and `aegis-os audit-me`. A missing hook degrades UX, not enforcement; a missing sandbox/proxy/broker fails the launch.

---

## 4. Session lifecycle

1. **Install / shim / lifecycle** — `aegis-os install` writes advisory hooks/MCP config and collaborator workflow rules (`.agents/rules/aegis-os-workflow.md` + `.agents/README.md`). `aegis-os install --enforce` creates `~/.aegis/bin` shims so `claude` (etc.) launch through `aegis-os run`. `aegis-os upgrade` updates the binary (Homebrew, Cargo, local source, or OpenSSH `RELEASE_SIGNER`-verified release) and refreshes client configs/shims; `aegis-os uninstall` surgically removes Aegis shims and client entries (`--purge --yes` also locks/destroys `~/.aegis` `OrgVault` state).
2. **Launch** — the supervisor resolves the real agent binary (excluding its own shim), creates a session id, and starts the agent as a child process.
3. **Workspace setup** — create the CoW shadow, read-only host view, masked `$HOME`, Git view, egress proxy, and policy session before the agent starts.
4. **Execution** — the agent uses native tools or MCP. Native writes land in the shadow; reads are narrowed to the project/toolchains; network goes through the proxy.
5. **Verify / diff** — `aegis-os verify` runs the configured domain gate in the sandbox; `aegis-os diff` (`--json` for canonical `evidence_hash`) compares shadow vs host.
6. **Commit** — `workspace_commit` (or CLI `aegis-os commit --expected-diff-hash <sha256>`) computes a canonical full-content SHA-256 `evidence_hash`, re-merges against the current host trunk, enforces cryptographic role separation (`agent.token` vs. `human.token`, HTTP `403` on agent self-approval), requests approval or a lease, and emits an `Aegis-OS-Verified` audit receipt (`git_trailer` + `pr_markdown_badge`). The host is untouched until approval.
7. **Exit** — if the agent exits without committing, the launcher prints a summary: `diff` / `commit` / `discard` / `last`.
8. **Audit** — boundary events are appended to the hash-chained ledger; `aegis-os why` reconstructs the approval/audit trail.

---

## 5. Core components

| Crate | Responsibility |
|---|---|
| `aos-cli` | `aegis-os` binary: installer, `upgrade`/`uninstall`, launcher/session supervisor, `vault` controls, hooks, routing, `status`/`doctor`/`audit-me`/`top`, approvals, memory UI, bench. |
| `aos-core` | Core traits and types: effects, scopes, reversibility, session identity, A2A state machine, glob claims. |
| `aos-vfs` | CoW shadow workspace, per-org OS-encrypted `OrgVault` volumes (`AES-256-GCM` `KEK -> DEK` envelopes), `fsync` atomic durability, orphan shadow recovery, snapshots, 4-tier LCS Diff3 merge, `mtime` sync, Org CAS/KV. |
| `aos-sandbox` | Native OS sandbox drivers: macOS Seatbelt, Linux bwrap, microVM control-plane interface. |
| `aos-egress` | Identity-pinned CONNECT proxy, domain allowlist, Model API Base-URL L7 reverse proxy with DLP & `$AOS_SECRET_*` boundary secret injection, Unix-socket bridge; opt-in non-model HTTPS MITM is Phase 2. |
| `aos-policy` | Cedar-style 5-stage policy engine (`R0a`–`R4`), commit-time poisoning guard, TTL/one-shot leases, escalation queue. |
| `aos-ipc` | Global/intra-org peer registry, A2A task lifecycle, P2P mailboxes, correlated RPC, pub/sub. |
| `aos-recorder` | Append-only JSONL flight recorder for syscalls, boundary events, and security telemetry. |
| `aos-mcp-gateway` | MCP JSON-RPC + A2A server, AAP-1.0 app store/proxy, cloud PaaS control plane, web consoles. |
| `aos-memory-*` | UOMP memory consent: store, server, gateway, local approval UI, native `aegis-os memory` commands. |

**Workspace layout (abridged)**

```text
<runtime_dir>/              # defaults to ~/.aegis (override via AOS_RUNTIME_DIR)
  vaults/
    <org>.sparsebundle | <org>.luks.img   # per-org encrypted volume image
    <org>.dek.enc.json                    # AES-256-GCM wrapped DEK envelope (Aad = org_id)
    <org>.vault.json                      # mount & backend state
  orgs/<org>/               # mounted per-org encrypted OrgVault volume
    agents/<agent>/cow_workspace/
      upper_workspace/      # writable CoW upper layer
      baseline/             # refresh baseline
  sessions/<session_id>/    # metadata, proxy config, audit refs (fsync-persisted)
  host_commit.lock          # serialized host commits & epoch state
```

On Linux (`bwrap --bind-fd`), the CoW shadow is bind-mounted at the original project path while the host tree is exposed read-only at `/aegis/host`; on macOS Seatbelt, the agent runs with `cwd` inside the CoW shadow while the host tree is mounted read-only. In both modes, `.git` objects are read-only with a writable session index, and agent state directories are split into read-only sensitive config and writable session/cache paths.

---

## 6. Transactional VFS and merge

`aos-vfs` provides:

- **CoW fork** — APFS `clonefile` on macOS, Linux `FICLONE` reflinks (btrfs/XFS), lazy-copy fallback on ext4. Metadata fork is reported separately from full 1,000-file provisioning in the benchmarks.
- **`OrgVault` encrypted persistence** — `<runtime_dir>/orgs/<org>` is backed by a per-organization OS-encrypted sparse volume (Rootless APFS Encrypted `.sparsebundle` preserving `clonefile` on macOS; `LUKS2 (dm-crypt) + Btrfs` with `zstd` compression and reflinks/snapshots on Linux/Cloud; `gocryptfs` FUSE or `PlainDir0700` fallback on unprivileged Linux). Per-org DEKs are wrapped with `ring` `AES-256-GCM` (`Aad = org_id`) under a master KEK resolved from `AOS_VAULT_MASTER_KEY` (Cloud KMS) → macOS Keychain → Linux Secret Service → `0o600` `~/.config/aegis-os/master.kek`.
- **Crash durability & orphan recovery** — shadow writes, snapshot indexes, `session_bindings.json`, and `session.json` use `fsync` + parent-directory sync (`write_bytes_atomic_synced`); legacy `/tmp/aegis-os-runtime` shadows are auto-rescued into `~/.aegis`; dead-PID uncommitted shadows are surfaced by `workspace_status` / `aegis-os vault status` and recoverable via `workspace_sync(adopt_orphaned_agent)` or `aegis-os vault recover --from-agent <id>`.
- **Continuous rebase** — refresh from host at turn/tool boundaries; bump `mtime` on fast-forwarded files so incremental compilers recompile.
- **4-tier merge**:
  1. untouched files → fast-forward;
  2. different lines / identical changes / superset additions / commutative declarations → LCS Diff3 auto-merge;
  3. overlapping conflicts → isolated, reported with file/line/versions; never inject `<<<<<<<` into the shadow;
  4. binary artifacts → exclusive lock + baseline hash, explicit `overwrite_binaries` if intended.
- **Pre-commit gate** — optional `verify_cmd` (`.aegis/verify.json` or `AOS_VERIFY_CMD`) runs in the sandbox; the host is untouched until it passes.
- **CAS** — `artifact://<org>/sha256:<hash>` for large specifications and pipeline hand-offs; downstream reads a verified hash, not a half-written file.

Measured multi-agent auto-merge: **98.7%** without human intervention; the remaining 1.3% hits domain verification gates.

---

## 7. Sandbox and egress

- **Linux enforced launcher** — `bwrap >= 0.10` (`--bind-fd`) with a read-only root view (`--ro-bind / /`), `$HOME`/system-directory `--tmpfs` masking (including `/run`; DNS is resolved host-side by the egress bridge), read-only toolchains, layered CLI runtime state mounts with single-file `--ro-bind` config locks, Git read-only object pass-through + per-session `GIT_INDEX_FILE`, `--unshare-net` Unix-bridge egress, and process-group lifecycle.
- **macOS enforced launcher & `proc_exec`** — Seatbelt (`sandbox-exec`) confines both `aegis-os run` and `proc_exec`: shadow `cwd`, read-only host project, symlink-canonicalized Darwin runtime/temp paths, preserved `HOME` for macOS Keychain/OAuth compatibility paired with explicit file-read/write deny on `~/.ssh`, `~/.aws`, `~/.gnupg`, `~/.kube`, `~/.aegis/**/human.token`, `~/.config/aegis-os/master.kek`, `vaults/*.dek.enc.json`, vault backing images, and volume utilities (`hdiutil` / `diskutil`, also filtered by PreToolUse routing and matched by Linux `bwrap` `$HOME` masking), read-only `.aegis-bin` Git shim (`core.fsmonitor=false`, `core.hooksPath=/dev/null`), PTY forwarding, and loopback TCP broker/egress. Full macOS VFS path-remapping at the original host path and default-deny read convergence remain Phase 4.
- **Egress today** — identity-pinned L4 `CONNECT` proxy + domain allowlist for general HTTPS (host loopback is unreachable), plus a **Model API Base-URL L7 reverse proxy** (`ANTHROPIC_BASE_URL`, `OPENAI_BASE_URL`, `GOOGLE_GEMINI_BASE_URL`, with `AOS_UPSTREAM_*_URL` routing) that enforces method/path allowlists, L7 request-body DLP, zero-buffered SSE streaming (`+0.221 ms` TTFT overhead), and `$AOS_SECRET_*` boundary secret injection.
- **Egress Phase 2 remaining** — opt-in MITM CA inspection for arbitrary non-model third-party HTTPS endpoints.
- **Process lifecycle** — active sandbox process groups support real `SIGSTOP` / `SIGCONT` / `SIGKILL` for pause/resume/destroy.

---

## 8. Policy, approvals, and leases

Policy is evaluated over **effects × scope × reversibility**, not client tool names. The five priority tiers:

| Tier | Meaning |
|---|---|
| **R0a** | Host red-line and custom Cedar `forbid`; hard deny. |
| **R0b** | Commit-time hook / CI / build-script guard: sensitive paths (`.git/hooks`, `.envrc`, `.github/workflows`, `build.rs`, `Makefile`, `Cargo.toml`, `package.json`, `.aegis/*`, …) always produce a human review card, even under an active lease. |
| **R1** | Cross-tenant gate. |
| **R2** | One-shot `sha256:<evidence_hash>` lease (TOCTOU-pinned) or TTL lease (`15m` / `1h`), revocable. |
| **R3** | Declarative Cedar green-zone auto-allow; zero prompts. |
| **R4** | Human-readable escalation with a 30-minute ticket TTL. |

Approvals are available through the local CLI, the web console (`/approve`, `/dashboard`), and cloud TOTP (tenant key + authenticator code). Human-only tools (`policy_approve_escalation`, `policy_grant_lease`) are never exposed over MCP.

---

## 9. MCP and A2A surface

Aegis exposes **39 MCP tools** plus **7 dynamic URI resources**. Grouped by subsystem:

| Subsystem | Tools |
|---|---|
| Transactional VFS (7) | `fs_read`, `fs_write`, `fs_edit`, `fs_delete`, `fs_glob`, `workspace_status`, `workspace_sync` |
| Snapshots / merge / PR (5) | `workspace_snapshot`, `workspace_diff`, `workspace_rollback`, `workspace_commit`, `workspace_export_pr` |
| Sandbox (1) | `proc_exec` |
| IPC / claims (11) | `ipc_send`, `ipc_recv`, `ipc_request`, `ipc_reply`, `ipc_ack`, `ipc_wait`, `ipc_publish`, `ipc_subscribe`, `ipc_list_peers`, `coord_claim`, `coord_release` |
| A2A (4 + HTTP) | `ipc_update_card`, `ipc_task_update`, `ipc_task_get`, `ipc_task_list`; `GET /.well-known/agent.json`, `POST /a2a`, `POST /v1/a2a` |
| Org CAS / KV (4) | `org_artifact_publish`, `org_artifact_fetch`, `org_kv_put`, `org_kv_get` |
| Egress (1) | `egress_http_request` |
| Policy / mode (2) | `policy_list_escalations`, `runtime_configure_mode` |
| AAP-1.0 (3) | `app_catalog_search`, `app_mount_session`, `app_call_tool` |
| Memory (1) | `memory_policy_evaluate` |

Dynamic resources: `aegis://workspace/status`, `aegis://ipc/inbox`, `aegis://org/peers`, `aegis://global/peers`, `aegis://a2a/agent-cards`, `aegis://a2a/tasks`, `aegis://org/shared/catalog`.

Cloud PaaS adds HTTP endpoints for workspace provisioning, sync/diff/hibernate/wake, PR export, tenant keys/plans, vault secrets, approval decisions, and the web consoles. See [AEGIS_APPLICATION_PROTOCOL.md](AEGIS_APPLICATION_PROTOCOL.md) for AAP-1.0 and the [Aegis Cloud console](https://heurion.org/aegis-cloud/dashboard) for subscription and workspace management.

---

## 10. Domain profiles

The same shadow/claim/verify/commit kernel covers multiple artifact types. Profiles decide merge policy, claim granularity, verification gate, and evidence format.

| Profile | Merge / claim | Verify gate | Status |
|---|---|---|---|
| `code` | Text LCS Diff3; file/glob claims | Tests, compiler, linter | ✅ Phase 1 / 3 |
| `docs` | Text LCS for Markdown/LaTeX; file/glob claims | `latexmk`, link check, render check | 🟡 Basic Phase 3; chapter/section claims, Office CRDT in Phase 5 |
| `data` | Text/CSV LCS; binary exclusive lock | Schema check, row counts, PHI scan | 🟡 Partial; schema-aware merge, partition/row claims in Phase 5 |
| `binary` | Exclusive lock + baseline SHA-256 | Hash check, render/thumbnail | ✅ Phase 3 |
| `app_state` | API diff, idempotency keys | API dry-run / field diff | ⬜ Phase 5 |
| `memory` | UOMP scope leases | Consent/audit checks | 🟡 Core UOMP available; full profile Phase 5 |

`aegis-os run --profile auto|code|docs|data|binary|app_state|memory|mixed` selects the profile; `verify_cmd` is how teams define domain correctness.

---

## 11. Cloud PaaS

Aegis Cloud turns the local runtime into a multi-tenant control plane:

- **Tenant keys** — `ak_live_*`, SHA-256 hashed, bound to `(org_id, agent_id, role, workspace_id)`.
- **Workspaces** — provision from a Git repo, fork parallel CoW agent environments, sync source-only changes, hibernate/wake with cryptographic scale-to-zero (`umount` + `cryptsetup close` evicts volume keys from RAM when an org has no active workspaces, auto-unlock on wake, cryptographic erasure on org deletion).
- **Git-to-PR** — reconcile with the 4-tier merge, commit to a branch, export a patch/PR payload.
- **Approvals** — cloud TOTP approver; tenant key alone cannot approve.
- **Quotas / metering** — per-tenant syscalls, sandbox ms, CoW bytes; plan-based concurrency.
- **Isolation** — remote Linux bwrap/VM boundary; only verified text diffs return to the laptop.

Local vs Cloud share the same MCP behavior; Cloud offloads heavy builds and multi-agent concurrency. Local `--isolated` microVM is Phase 4.

---

## 12. Observability and audit

- `aegis-os status` — current session, mode, shadow, leases, pending approvals.
- `aegis-os doctor` — install health, enforcement level, hook/MCP status, OpenCode shared-service detection.
- `aegis-os audit-me` — 5-second local credential exposure & prompt-fatigue diagnostic (with `--share` Markdown badge export).
- `aegis-os top` — live peer radar, A2A tasks, claims, leases.
- `aegis-os why` — approval ticket + audit trail.
- `aegis-os vault status|unlock|lock|recover` — per-org encrypted `OrgVault` backend/mount/key-source inspection, manual lock/unlock, and dead-PID orphan shadow adoption.
- `aegis-os upgrade` / `aegis-os uninstall` — version/drift check (`--check`), install-method-aware in-place upgrade + client/shim refresh (`--refresh-only`), and surgical client/shim/vault uninstallation (`--shim-only`, `--workspace-clean`, `--purge --yes`).
- **Commit / PR Audit Receipts** — `aegis-os commit`, `workspace_commit`, and `workspace_export_pr` emit `Aegis-OS-Verified: session=... principal=... files=... evidence=sha256:...` git trailers and Markdown verification badges.
- **Hash-chained ledger** — every boundary event records `task_id`, `prev_hash`, `event_hash = sha256(prev_hash || canonical_event)`; `hash_chain_verified` is exposed through task inspection.
- **Telemetry** — anonymous install/session ping only; no source, paths, prompts, usernames, or hostnames. Opt out with `DO_NOT_TRACK=1`, `AOS_TELEMETRY_DISABLED=1`, or `touch ~/.gemini/aegis-telemetry-opt-out`.

---

## 13. Benchmarks

### 13.1 Transactional Multi-Agent Runtime & Prompt Reduction ([Paper 1, `arXiv:2611.08516`](https://arxiv.org/abs/2611.08516))

| Metric | Result |
|---|---|
| Prompt reduction (1,500 controlled calls) | 94.19%–99.88% |
| Prompt reduction (52 real sessions / 28,087 calls) | 90.7%–97.9% (IPR 1.12%) |
| Red-team ASR (80 vectors, 8 categories) | 0.0% (vs. 100% host-YOLO) |
| CoW provisioning (1,000 files / 78.1 MB) | 6.28 ms APFS; 15.6 ms btrfs; 35.1 ms ext4 fallback |
| Multi-agent auto-merge | 98.7% |
| 200-module rollback | 8.68 ms |
| IPC token reduction via CAS | 99.85% |

### 13.2 Kernel-Enforced Boundary & Live CLI Agent Evaluation ([Paper 2, `paper2/`](../paper2/aegis_enforced_runtime_arxiv_preprint.pdf))

| Metric | Result |
|---|---|
| Structural bypass suite (`V1–V6`, 30 deterministic exploits / OS) | **0/30 (0.0%)** on macOS Seatbelt & **0/30 (0.0%)** on Linux `bwrap --bind-fd` (vs. **93.3% (28/30)** advisory hooks, **73.3%–83.3%** vendor sandboxes, **80.0% (24/30)** `nerdctl` devcontainer) |
| Live production CLI agent evaluation (4 agents, 54 executed cloud-API runs across 60-cell matrix) | **100% (8/8)** benign & multi-file task completion; **0% (0/4)** repo-trap (`cd_repo_trap`) host compromise under `aegis_enforced` (vs. **100% (4/4)** in `vendor_default` plus **1/1** Claude Opus validation run, and **3/4** in `advisory`) |
| Enforced parent-launcher startup latency | **9.91 ms** median (**15.01 ms** P95) Linux `bwrap` (**22.4×** faster than rootless `nerdctl`'s **221.53 ms**); **20.38 ms** median (**21.74 ms** P95) macOS Seatbelt |
| 500 MB packed Git repository (`git repack -ad`) CoW shadow overhead | **4.76 MB** physical disk delta on APFS (**99.05%** saved vs. **499.85 MB** `cp -R`); **0.00 MB** net delta on `btrfs` (`FICLONE`); **78.27 MB** shadow `du` (**235.27 MB** `statvfs`) on `ext4`; **10.03–29.88 ms** 3-file `aegis-os diff --json` |
| Loopback L7 Base-URL reverse proxy & CLI TOCTOU gate | **+0.221 ms** mean TTFT (`0.180 -> 0.402 ms`, `0/40` false positives, `25/25` adversarial DLP/fronting/smuggling blocked); **60/60 (100%)** CLI TOCTOU/VT100 spoofing attacks blocked (**7.54–7.92 ms** per-class median) |

`0.42 ms` in Monograph 03 is the trunk-anchored metadata fork; the provisioning numbers above measure full multi-file workspace setup. See [BENCHMARK_REPORT.md](../BENCHMARK_REPORT.md), [paper2/ENFORCED_RUNTIME_BENCH_REPORT.json](../paper2/ENFORCED_RUNTIME_BENCH_REPORT.json), [Paper 1 (`arXiv:2611.08516`)](https://arxiv.org/abs/2611.08516), and [Paper 2 (`paper2/aegis_enforced_runtime_arxiv_preprint.pdf`)](../paper2/aegis_enforced_runtime_arxiv_preprint.pdf) for full methodology.

---

## 14. Implementation status and limits

| Phase | Status | Scope |
|---|---|---|
| **Phase 0** — observability | ✅ Complete | `doctor`/`status`/`audit-me` enforcement level, client matrix, portable hooks |
| **Phase 1** — `aegis-os run` Linux enforced runtime | ✅ Complete | `bwrap --bind-fd`, CoW shadow, host read-only, `$HOME` masking, host-side DNS via egress bridge, Git view + `GIT_INDEX_FILE`, `--unshare-net` Unix-bridge egress |
| **Phase 2** — effect/approval/lease & L7 model proxy | ✅ Core Complete | effects, commit tickets, full-content `evidence_hash` (`diff --json` / `commit --expected-diff-hash`), dual-token separation, leases, approvals CLI/Web, verify, CAS, Model API Base-URL L7 reverse proxy + DLP + `$AOS_SECRET_*` injection; opt-in non-model HTTPS MITM remaining |
| **Phase 3** — DomainProfile | 🟡 Partial | profile auto, text LCS, binary claims, verify, CAS; docs/data mergers remaining |
| **Phase 4** — macOS Seatbelt & kernel hardening | 🟡 Verified on macOS; VFS remap remaining | macOS Seatbelt enforced launcher verified across live CLI agents (`claude`, `opencode`, `agy`, `hermes`) + `0/30` `V1–V6` suite; full path-remapping, Landlock/seccomp, and microVM pilot remaining |
| **Phase 5** — advanced domains / IDE / enterprise | ⬜ Not started | Office CRDT, AAP/UOMP deep integration, IDE daemon, MDM |

**Known limits**

- Enforced launcher path view: Linux (`bwrap >= 0.10`) bind-mounts the shadow at the original host path; macOS `aegis-os run` runs Seatbelt with `cwd` inside the CoW shadow, read-only host project, canonicalized temp/config allowances, and explicit credential/token read-deny (full macOS path-remapping is Phase 4).
- Egress: Model API traffic uses the Base-URL L7 reverse proxy (DLP + secret injection); general non-model HTTPS uses CONNECT domain allowlisting (opt-in MITM remaining).
- Approval console: local CLI/Web; cloud `/approve` and TUI scroll-region status bar not wired into the launcher yet.
- CoW: ext4 may fall back to lazy-copy until OverlayFS backend lands.
- Clients: `aegis-os run` kernel-confines all 5 CLI agents (`claude`, `opencode`, `agy`, `hermes`, `codex`); in Advisory mode, OpenCode uses V1 plugin (`plugins/opencode-aegis.js`) and Codex has no external `PreToolUse` hook.
- Advisory hooks are an ergonomic guardrail, never a security boundary.

---

## 15. Further reading

- [Enforced runtime design](AEGIS_ENFORCED_RUNTIME_DESIGN.md) — threat model, effect model, phase plan, client adapters.
- [Paper 2: Why Agent Plugins Are Not a Security Boundary (PDF)](../paper2/aegis_enforced_runtime_arxiv_preprint.pdf) and [reproducible benchmark data](../paper2/ENFORCED_RUNTIME_BENCH_REPORT.json).
- [Paper 1: Aegis OS Transactional Runtime (`arXiv:2611.08516`)](https://arxiv.org/abs/2611.08516) ([local PDF](../paper/aegis_os_arxiv_preprint.pdf)) and [BENCHMARK_REPORT.md](../BENCHMARK_REPORT.md).
- [AAP-1.0 application protocol](AEGIS_APPLICATION_PROTOCOL.md) — app manifests, grant tokens, device-code flow, lease-gated tools.
- [UOMP memory consent mapping](UOMP_MEMORY_CONSENT_MAPPING.md) — memory scopes, consent, revocation, audit.
- Technical monographs: [Why Agent Plugins Are Not a Security Boundary](https://heurion.org/en/blog/from-agent-plugins-to-enforced-runtime) · [Beyond Git Branches & Shared Folders](https://heurion.org/en/blog/aegis-os-transactional-agent-kernel) · [Human-Agent Capability Parity](https://heurion.org/en/blog/human-agent-capability-parity-ai-native-software) · [Dual-Surface CRDT](https://heurion.org/en/blog/dual-surface-crdt-clinical-ai).
