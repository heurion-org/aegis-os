# Aegis OS (`aegis-os`)

**[English](README.md) | [简体中文](README_CN.md) | [Aegis OS Website](https://heurion.org/aegis-os/) | [Tutorial](https://heurion.org/aegis-os/tutorial/) | [Technical Blog](https://heurion.org/en/blog) | [Cloud Console & Pro Subscription ($29/mo)](https://heurion.org/aegis-cloud/dashboard) | [Approval Console](https://heurion.org/aegis-cloud/approve)**

**A transactional multi-tenant agent OS runtime for autonomous coding agents (`agy`, `claude`, `codex`, `opencode`, `hermes`) — kernel isolation, CoW shadow workspaces, A2A collaboration, and effect-level approvals.**

> **Enforcement levels**: `aegis-os install` = **advisory** (hooks / MCP / rules; compatibility, not a security boundary). `aegis-os run -- <agent>` = **enforced** (Aegis is the parent process; kernel sandbox + CoW shadow + egress proxy; Linux Phase 1, macOS Phase 4). `aegis-os run --isolated` / Aegis Cloud = **isolated** (microVM / cloud sandbox).

![Rust](https://img.shields.io/badge/Rust-1.80%2B%20(2021)-orange.svg)
![MCP](https://img.shields.io/badge/Protocol-MCP%202024--11--05-blue.svg)
![A2A](https://img.shields.io/badge/Protocol-Google%20A2A-34A853.svg)
![Paper](https://img.shields.io/badge/Paper-arXiv%20Preprint-b31b1b.svg)
[![Blog](https://img.shields.io/badge/Blog-heurion.org%2Fen%2Fblog-0A7D52.svg)](https://heurion.org/en/blog)
[![M8ven Score](https://m8ven.ai/badge/mcp/heurion-org/aegis-os)](https://m8ven.ai/mcp/heurion-org/aegis-os?s=readme)

---

## What it is

Aegis OS shifts the authorization boundary from individual tool calls to **transactional workspace boundaries**. In enforced mode, each agent gets a Copy-on-Write shadow workspace, a kernel sandbox, an identity-pinned egress proxy, and a policy/approval broker. Inside the workspace, agents run with **zero per-action prompts**; host commits and boundary crossings require human approval or a TTL lease.

It replaces both Git feature branches (late conflict explosions, heavyweight worktrees) and raw shared folders (**41.2%** silent overwrites in uncoordinated multi-agent benchmarks). It is intentionally domain-agnostic: code, documents, data pipelines, binary artifacts, and cross-application state use the same shadow / claim / verify / commit kernel, with domain-specific profiles for merge and verification. **Heurion 2.0 is the first reference application.**

## Security model

| Mode | How to start | Enforcement point | What it protects against | Status |
|---|---|---|---|---|
| **Advisory** | `aegis-os install`, then run the agent directly | Hooks / MCP / rules | Honest agent mistakes, accidental credential reads, prompt fatigue | ✅ Available (compatibility mode) |
| **Enforced** | `aegis-os run -- claude`, or `aegis-os install --enforce` then run `claude` | Kernel sandbox + broker + egress proxy | Prompt-injected or compromised agents; host writes; credential reads; arbitrary egress | ✅ Linux Phase 1; macOS Phase 4 |
| **Isolated** | `aegis-os run --isolated -- claude` / Aegis Cloud | microVM + remote policy | Untrusted repositories, multi-tenant teams, host-level isolation | 🟡 Cloud sandbox available; local `--isolated` Phase 4 |

**Advisory is not a security boundary.** Hooks and MCP servers are loaded *by* the agent; a hijacked agent can skip them, disable them through project config, or use native tools directly. In enforced mode, Aegis creates the shadow, sandbox, proxy, and policy session *before* the agent starts—the agent cannot opt out.

Tier A launch targets: **Claude Code, AGY, Codex, OpenCode (`--standalone`), Hermes**. The enforced path is client-agnostic; advisory hook quality varies by client (Codex currently has no tool-level hook). OpenCode must use `--standalone` so its shared background service cannot bypass the sandbox. The OpenCode plugin and Hermes adapter are still in progress; the enforced launcher path already works independently of them.

## Quick start

### Advisory integration

```bash
brew tap heurion-org/aegis-os https://github.com/heurion-org/aegis-os.git
brew install aegis-os
aegis-os install
```

This wires hooks / MCP / rules into detected agents. It reduces prompt fatigue, but does not claim to resist a compromised agent.

### Enforced runtime (Linux Phase 1)

```bash
aegis-os install --enforce   # create ~/.aegis/bin shims
aegis-os run -- claude       # or: aegis-os run -- codex / agy / opencode --standalone / hermes
```

Enforced mode gives you:

- Host project read-only; all writes land in a per-session CoW shadow.
- `$HOME`, `/root`, `/run`, `/var`, `/tmp`, `/mnt`, `/media`, `/srv`, and host SSH keys masked.
- Git view preserved (host `.git` read-only + writable session index).
- CONNECT-only egress allowlist through an identity-pinned local proxy.
- Commit tickets with `evidence_hash` / TOCTOU protection and TTL leases.
- **Fail closed**: missing `bwrap`, proxy, or broker refuses startup instead of silently degrading.

Session controls: `aegis-os status` · `aegis-os diff` · `aegis-os commit` · `aegis-os discard` · `aegis-os approvals`.

Current enforced-runtime limits:

- **Linux only**; requires bubblewrap **>= 0.10** (`--bind-fd`). The full macOS enforced launcher is Phase 4. macOS `proc_exec` sandboxing via Seatbelt exists separately, but `aegis-os run` parent-process isolation is not yet available on macOS.
- Egress is **CONNECT-only**; L7 DLP, base-URL reverse proxy, and opt-in MITM are Phase 2.
- Approval UI is local CLI/Web; cloud `/approve` and TUI-embedded panels are not yet wired into the enforced launcher.
- CoW may fall back to lazy-copy on ext4; the OverlayFS/fuse-overlayfs backend is not yet landed.

### Other install paths

```bash
# One-line signed installer (Linux & macOS)
curl -fsSL https://heurion.org/aegis-cloud/install.sh | sh

# Build from source
git clone https://github.com/heurion-org/aegis-os.git && cd aegis-os
cargo install --path crates/aos-cli
aegis-os install
```

## Core capabilities

- **Transactional CoW VFS** — 0.42 ms metadata fork; 6.28 ms / 15.6 ms for a 1,000-file workspace; 4-tier LCS auto-merge with domain verification gates.
- **Kernel sandbox & egress** — Linux bwrap enforced launcher; macOS Seatbelt for `proc_exec`; default-deny `$HOME`, credential masking, CONNECT-only domain allowlist (L7 DLP / secret injection in Phase 2).
- **A2A IPC & CAS** — peer discovery, hierarchical tasks, task-bound file claims, `artifact://sha256` content-addressed hand-offs.
- **Cedar policy, leases & audit** — effect-level approvals, TTL/one-shot leases, `evidence_hash` pinning, hash-chained audit ledger.
- **Cloud PaaS** — multi-tenant workspaces, Git-to-PR export, scale-to-zero hibernation, web approval console.

## Key benchmarks

| Metric | Result |
|---|---|
| Prompt reduction (52 real sessions, 28,087 tool calls) | **90.7%–97.9%** |
| Attack success rate (80 red-team vectors) | **0.0%** |
| CoW provisioning (1,000 files / 78.1 MB) | **6.28 ms** APFS · **15.6 ms** btrfs |
| Multi-agent auto-merge | **98.7%** |
| Rollback (200 corrupted modules) | **8.68 ms** |

> `0.42 ms` in Monograph 03 is the trunk-anchored metadata fork; the `6.28 ms` / `15.6 ms` figures measure full 1,000-file provisioning. See [`BENCHMARK_REPORT.md`](BENCHMARK_REPORT.md) for methodology.

## Documentation

- **Enforced runtime design** — advisory/enforced/isolated threat model, effect model, phase plan: [`docs/AEGIS_ENFORCED_RUNTIME_DESIGN.md`](docs/AEGIS_ENFORCED_RUNTIME_DESIGN.md)
- **Detailed architecture** — core pillars, MCP tool matrix, cloud mode, AAP-1.0, full benchmarks, roadmap: [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md)
- **Benchmark report** — [`BENCHMARK_REPORT.md`](BENCHMARK_REPORT.md)
- **Paper** — [`paper/aegis_os_arxiv_preprint.pdf`](paper/aegis_os_arxiv_preprint.pdf)
- **AAP-1.0 application protocol** — [`docs/AEGIS_APPLICATION_PROTOCOL.md`](docs/AEGIS_APPLICATION_PROTOCOL.md)
- **Memory consent / UOMP** — [`docs/UOMP_MEMORY_CONSENT_MAPPING.md`](docs/UOMP_MEMORY_CONSENT_MAPPING.md)
- **Technical monographs** — [Beyond Git Branches & Shared Folders](https://heurion.org/en/blog/aegis-os-transactional-agent-kernel) · [Human-Agent Capability Parity](https://heurion.org/en/blog/human-agent-capability-parity-ai-native-software) · [Dual-Surface CRDT](https://heurion.org/en/blog/dual-surface-crdt-clinical-ai)
- **Blog index** — https://heurion.org/en/blog (中文: https://heurion.org/blog)

## Telemetry & license

Anonymous install/session ping only; no source, paths, prompts, or credentials. Opt out with `DO_NOT_TRACK=1`, `AOS_TELEMETRY_DISABLED=1`, or `touch ~/.gemini/aegis-telemetry-opt-out`. Details: [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md).

Apache License 2.0. See [`LICENSE`](LICENSE).
