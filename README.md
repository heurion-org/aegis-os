# Aegis OS (`aegis-os`)

**A Transactional Multi-Tenant Operating System Runtime for Autonomous Coding Agents (`agy`, `claude`, `codex`)**

[![Rust](https://img.shields.io/badge/Rust-1.99%2B-orange.svg)](https://www.rust-lang.org/)
[![MCP](https://img.shields.io/badge/Protocol-MCP%202024--11--05-blue.svg)](https://modelcontextprotocol.io/)
[![Paper](https://img.shields.io/badge/Paper-arXiv%20Preprint-b31b1b.svg)](paper/aegis_os_arxiv_preprint.pdf)

---

## Overview

Autonomous coding agents such as **Google Antigravity (`agy`)**, **Anthropic Claude Code (`claude`)**, and **OpenAI Codex CLI (`codex`)** face a fundamental **Security–Autonomy Dilemma**:
1. **Interactive Per-Action Prompting** interrupts human developers on 43%–60% of tool calls, inducing severe authorization fatigue.
2. **Unconfined Host Execution (`--yolo` / `--dangerously-skip-permissions`)** exposes the host filesystem, `~/.ssh/id_rsa`, and API tokens to catastrophic prompt injection and multi-agent file clobbering.

**Aegis OS (`aegis-os`)** resolves this dilemma by shifting the security boundary from individual tool invocations to **transactional workspace boundaries**:
- **Transactional APFS Copy-on-Write (`aos-vfs`)**: Provisions isolated shadow workspaces in milliseconds via kernel `libc::clonefile`, with $O(1)$ snapshots, time-travel rollback, and a **3-Way Merge Engine (`three_way_merge_lines`)** for concurrent multi-agent commits.
- **Dual-Tier Kernel Sandbox (`aos-sandbox`)**: Enforces mandatory access control via macOS Seatbelt (`/usr/bin/sandbox-exec`) and Linux Bubblewrap/MicroVM, blocking outside-workspace writes and `~/.ssh` / `~/.aws` credential reads at the OS kernel boundary.
- **Zero-Trust Egress Proxy (`aos-egress`)**: Local TCP HTTP proxy that performs boundary secret injection (`$AOS_SECRET_*`) only for allowlisted domains and blocks cross-domain exfiltration (`HTTP/1.1 403 Forbidden`).
- **First-Class Inter-Agent IPC & CAS (`aos-ipc`)**: P2P mailboxes, correlated RPC task handoff (`ipc_request` / `ipc_reply`), topic Pub/Sub, and Content-Addressable Storage (`artifact://<org>/sha256:<hash>`) that cuts cross-agent context token overhead by **99.85%**.
- **Cedar-Aligned Policy Kernel & Leases (`aos-policy`)**: Auto-allows 100% of in-sandbox CoW mutations and intra-org IPC with **zero prompts**, gating only host commits (`workspace_commit`) and unlisted network egress via TTL session leases.

---

## Quick Start (Zero-Config for `agy`, `claude`, and `codex`)

```bash
# 1. Build & globally configure AGY, Claude Code, and Codex CLI
cargo run --release --bin aegis-os -- install

# 2. Verify integration health across all 3 clients
cargo run --release --bin aegis-os -- doctor

# 3. Launch the Mission Control dashboard for the current project
cargo run --release --bin aegis-os -- top

# 4. Run the persistent HTTP MCP daemon & Zero-Trust Egress Proxy
cargo run --release --bin aegis-os -- daemon --listen 127.0.0.1:7080 --egress-listen 127.0.0.1:18080
```

---

## Empirical Benchmark Suite (`aegis-os bench`)

Reproduce all five live empirical experiments from our research paper ([`paper/aegis_os_arxiv_preprint.pdf`](paper/aegis_os_arxiv_preprint.pdf) and [`BENCHMARK_REPORT.md`](BENCHMARK_REPORT.md)):

```bash
cargo test --workspace
cargo run --release --bin aegis-os -- bench --report-out BENCHMARK_REPORT.md
```

### Summary of Empirical Results (`macos-aarch64`)

| Experiment | Key Empirical Finding |
| :--- | :--- |
| **EXP 1: Authorization Friction (1,500 Syscalls)** | Reduces human confirmation prompts from **60.00%** (`Host-Interactive`) to **3.33%** (Per-Task Commit Gate, **94.44% reduction**) and **0.07%** (1h Session Lease, **99.89% reduction**; max autonomous streak extended **367.5x** to 1,470 steps). |
| **EXP 2: Live Red-Team Attacks (40 Attacks)** | Lowers Attack Success Rate (ASR) from **100.0% (40/40 compromised in `Host-YOLO`)** to **0.0% (0/40 compromised in `Aegis-OS`)** across path escape, `~/.ssh/id_rsa` reads, live TCP secret exfiltration, and cross-tenant IPC/CAS. |
| **EXP 3: CoW Provisioning & Daemon Latency** | Clones a 1,000-file (78.1 MB) repo in **`7.86 ± 0.91 ms`** (**21.1x faster** than full copy `165.90 ± 17.61 ms`) with **95.0% disk savings** for 10 agents; live TCP `POST /mcp` JSON-RPC roundtrip is **`291.8 µs`** (`3,373 ops/s`). |
| **EXP 4: 3-Agent Concurrent Rust Build** | Preserves **3/3 (100%)** concurrent features across `agy` + `claude` + `codex` (vs. 1/3 in shared host mode), verified by live `cargo test --offline` (`exit code 0`), with **99.85% token reduction** via CAS URIs. |
| **EXP 5: Multi-File Corruption Rollback** | Atomically rolls back 200 corrupted Rust modules in **`7.09 ± 0.48 ms`** (**2.4x faster** than sequential file restore), verified by live `cargo check --offline`. |

---

## Workspace Architecture

- `crates/aos-core`: Core traits, syscall contracts, and identity primitives (`Organization -> Agent -> Session`).
- `crates/aos-policy`: Cedar-aligned policy kernel, escalation queue, and TTL session leases.
- `crates/aos-vfs`: APFS `libc::clonefile` CoW shadow workspace, snapshots, 3-Way Merge Engine, and Org CAS/KV store.
- `crates/aos-ipc`: P2P mailboxes, correlated RPC handoff with broadcast wakeup, and topic Pub/Sub.
- `crates/aos-sandbox`: Dual-tier OS sandbox driver (`NativeOsSandboxDriver` via macOS Seatbelt / Linux `bwrap`, and `MicroVmSandboxDriver`).
- `crates/aos-egress`: Zero-Trust TCP HTTP Egress Proxy with boundary secret injection (`$AOS_SECRET_*`).
- `crates/aos-recorder`: Append-only JSONL flight recorder for syscalls and security telemetry.
- `crates/aos-mcp-gateway`: MCP JSON-RPC server over `stdio` and Streamable HTTP daemon (`POST /mcp`).
- `crates/aos-cli`: Unified `aegis-os` binary (`install`, `doctor`, `top`, `daemon`, `workspace`, `policy`, `ipc`, `bench`, `demo`).
- `paper/`: LaTeX source (`main.tex`), precompiled bibliography (`main.bbl`), preview PDF (`aegis_os_arxiv_preprint.pdf`), and automated arXiv submission packager (`build_arxiv.sh`, `ax.tar`).
