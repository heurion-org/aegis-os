# Aegis OS (`aegis-os`)

**[English](README.md) | [简体中文](README_CN.md) | [Aegis OS Website](https://heurion.org/en/aegis-os/) | [Tutorial](https://heurion.org/en/aegis-os/tutorial/) | [Paper 1 (arXiv:2611.08516)](https://arxiv.org/abs/2611.08516) | [Paper 2 (DOI: 10.5281/zenodo.24170505)](https://doi.org/10.5281/zenodo.24170505) | [Technical Blog](https://heurion.org/en/blog) | [Cloud Console & Pro ($29/mo)](https://heurion.org/aegis-cloud/dashboard) | [Approval Console](https://heurion.org/aegis-cloud/approve)**

**A transactional multi-tenant agent OS runtime for autonomous coding agents (`claude`, `opencode`, `agy`, `hermes`, `codex`) — parent-process kernel sandboxing, CoW shadow workspaces, A2A collaboration, and SHA-256 TOCTOU-pinned approvals.**

> **Enforcement levels**: `aegis-os install` = **advisory** (in-process hooks / MCP / rules; reduces prompt fatigue, *not* a security boundary). `aegis-os run -- <agent>` = **enforced** (Aegis is the parent OS supervisor; Linux `bwrap --bind-fd` + macOS Seatbelt confinement + CoW shadow + split `.git` shim + L4/L7 egress proxy with `$AOS_SECRET_*` boundary injection). `aegis-os run --isolated` / Aegis Cloud = **isolated** (64GB cloud sandbox / microVM).

![Rust](https://img.shields.io/badge/Rust-1.80%2B%20(2021)-orange.svg)
![MCP](https://img.shields.io/badge/Protocol-MCP%202024--11--05-blue.svg)
![A2A](https://img.shields.io/badge/Protocol-Google%20A2A-34A853.svg)
[![arXiv](https://img.shields.io/badge/arXiv-2611.08516-b31b1b.svg)](https://arxiv.org/abs/2611.08516)
[![DOI](https://zenodo.org/badge/DOI/10.5281/zenodo.24170505.svg)](https://doi.org/10.5281/zenodo.24170505)
[![Blog](https://img.shields.io/badge/Blog-heurion.org%2Fen%2Fblog-0A7D52.svg)](https://heurion.org/en/blog)
[![M8ven Score](https://m8ven.ai/badge/mcp/heurion-org/aegis-os)](https://m8ven.ai/mcp/heurion-org/aegis-os?s=readme)

---

## What it is

- **Stop `--yolo` credential exposure** — Run `claude --dangerously-skip-permissions`, `codex --full-auto`, or `agy` without exposing `~/.ssh`, `~/.aws`, `.env`, or arbitrary outbound hosts. Run `aegis-os audit-me` to check your machine in 5 seconds.
- **Cut 90.7%–97.9% of approval popups** — Agents run with zero per-action prompts inside a sub-millisecond Copy-on-Write shadow workspace; only host commits and boundary crossings require human approval or a TTL lease.
- **Run multiple agents in parallel without silent overwrites** — Replace heavyweight `git worktree` setups and raw shared folders (**41.2%** silent overwrite rate in uncoordinated multi-agent runs) with task-bound claims, 4-tier LCS auto-merge (**98.7%**), and cryptographic `Aegis-OS-Verified` commit/PR receipts.

Aegis OS shifts the authorization boundary from individual tool calls to **transactional workspace boundaries**. In enforced mode, each agent gets a Copy-on-Write shadow workspace, a kernel sandbox, an identity-pinned egress proxy, and a policy/approval broker. Inside the workspace, agents run with **zero per-action prompts**; host commits and boundary crossings require human approval or a TTL lease.

It replaces both Git feature branches (late conflict explosions, heavyweight worktrees) and raw shared folders (**41.2%** silent overwrites in uncoordinated multi-agent benchmarks). It is intentionally domain-agnostic: code, documents, data pipelines, binary artifacts, and cross-application state use the same shadow / claim / verify / commit kernel, with domain-specific profiles for merge and verification. **Heurion 2.0 is the first reference application.**

## Security model

| Mode | How to start | Enforcement point | What it protects against | Status |
|---|---|---|---|---|
| **Advisory** | `aegis-os install`, then run the agent directly | Hooks / MCP / rules | Honest agent mistakes, accidental credential reads, prompt fatigue | ✅ Available (compatibility mode) |
| **Enforced** | `aegis-os run -- claude`, or `aegis-os install --enforce` then run `claude` | Parent kernel sandbox (`bwrap` / Seatbelt) + dual-token broker + L4/L7 egress proxy | Prompt-injected or trojanized repo scripts (`V1`–`V6`); host writes; SSH/Keychain/API-key theft; config & `.git/config` RCE; TOCTOU commit swaps | ✅ Verified on Linux (`bwrap --bind-fd`) & macOS Seatbelt across `claude`, `opencode`, `agy`, `hermes` |
| **Isolated** | `aegis-os run --isolated -- claude` / Aegis Cloud | Remote 64GB cloud worker / microVM | Untrusted repositories, multi-tenant teams, host-level isolation | ✅ 64GB Cloud sandbox available; local microVM Phase 4 |

**Advisory is not a security boundary.** Hooks and MCP servers are loaded *by* the agent under your ambient UNIX UID; a prompt-injected tool output or trojanized project script (`python3 scripts/verify_env.py`) can bypass regex hooks, overwrite `.claude/settings.json` / `.mcp.json` / `opencode.json`, trigger `.git/config` `core.fsmonitor` execution during `git status`, or exfiltrate keys over raw sockets. In enforced mode, Aegis creates the CoW shadow, kernel namespace, split `.git` view, read-only config locks, L4/L7 egress proxy, and dual-token `SessionBroker` *before* `execve()`—the agent cannot opt out.

Verified production CLI targets: **Claude Code (`claude`), OpenCode (`opencode`), Google Antigravity (`agy`), Nous Hermes (`hermes`), and Codex (`codex`)**. On macOS Seatbelt, `aegis-os run` automatically wraps OpenCode and Hermes with per-session single-port loopback pinning and blocks `SecurityAgent` Keychain IPC popups (`exit 44` shim) while keeping system TLS verification (`com.apple.trustd`) intact.

## Quick start

### Advisory integration

```bash
brew tap heurion-org/aegis-os https://github.com/heurion-org/aegis-os.git
brew install aegis-os
aegis-os install
aegis-os audit-me            # 5s local credential exposure & prompt fatigue checkup (--share for Markdown badge)
```

This wires hooks / MCP / rules into detected agents. It reduces prompt fatigue, but does not claim to resist a compromised agent.

### Enforced runtime (Linux `bwrap` & macOS Seatbelt)

```bash
aegis-os install --enforce   # create ~/.aegis/bin shims
aegis-os run -- claude       # or: aegis-os run -- opencode / agy / hermes / codex

# Review JSON/unified diff & promote verified changes with SHA-256 TOCTOU pinning
aegis-os diff --json
aegis-os commit --expected-diff-hash <sha256>
```

Enforced mode gives you:

- **Host project read-only**; all writes land in a per-session CoW shadow (`clonefile` on APFS, `FICLONE` on `btrfs`, fast workspace-only copy on `ext4`).
- **Host credentials & Mach IPC masked**: `$HOME` SSH/cloud keys, Keychain CLI/Mach `SecurityAgent` popups, `launchctl`, and `osascript` are blocked by the kernel; protected hook/MCP configs (`.claude/settings.json`, `.mcp.json`, `opencode.json`, `.gemini/antigravity-cli/settings.json`, `.hermes/config.yaml`) are locked read-only.
- **Split `.git` view + hardened `.aegis-bin/git` shim** on both Linux and macOS: host `.git` objects are mounted read-only (saving **99.05%** of physical disk blocks on 500 MB packed repos on APFS) paired with a private session `GIT_INDEX_FILE` and forced `core.fsmonitor=false` / `core.hooksPath=/dev/null`.
- **Split-plane L4/L7 egress proxy**: Model API traffic routes through a local L7 Base-URL reverse proxy (`ANTHROPIC_BASE_URL`, `OPENAI_BASE_URL`, `GOOGLE_GEMINI_BASE_URL`) with 64 KiB outbound DLP scanning and host-boundary `$AOS_SECRET_*` secret injection (**zero TLS MITM**); general HTTPS uses an L4 `CONNECT` allowlist.
- **Principal-separated `SessionBroker` & frozen-stage SHA-256 commit gate**: Isolates `agent.token` from `human.token`, escapes VT100 CSI / Unicode Bidi control sequences in diffs, snapshots candidate files into `commit_frozen_stage`, and runs 6 `DomainProfile` verifiers (`code`, `docs`, `data`, `binary`, `app_state`, `memory`) before promoting to the host.
- **Fail closed**: missing `bwrap`/`sandbox-exec` (or restricted Ubuntu 24.04 AppArmor userns without profile), proxy, or broker refuses startup instead of silently degrading.

Session & observability controls: `aegis-os status` · `aegis-os diff --json` · `aegis-os verify` · `aegis-os commit --expected-diff-hash` · `aegis-os discard` · `aegis-os publish` · `aegis-os approvals` · `aegis-os why` · `aegis-os a2a board` · `aegis-os policy watch` · `aegis-os memory ui` · `aegis-os app list` · `aegis-os audit-me --share`.

Current enforced-runtime limits:

- **macOS `cwd` vs Linux path-remapping**: Linux uses `bwrap --bind-fd` to mount the CoW shadow at the exact original host path; macOS Seatbelt runs with the shadow directory as `cwd` while mounting the host repository read-only (full macOS FUSE/NFSv3 path-remapping is Phase 4).
- **Ubuntu 24.04+ unprivileged userns**: Ubuntu 24.04 enables `kernel.apparmor_restrict_unprivileged_userns=1` by default; `aegis-os run` fails closed with setup instructions if `/etc/apparmor.d/bwrap` is not installed.
- **Non-model HTTPS inspection**: Model API traffic uses the L7 Base-URL reverse proxy (64 KiB DLP + `$AOS_SECRET_*` injection); general allowlisted HTTPS uses L4 `CONNECT` domain filtering without TLS MITM.

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
- **Kernel sandbox & egress** — Linux `bwrap` and macOS Seatbelt enforced launchers; credential masking; Model API base-URL L7 reverse proxy with DLP & `$AOS_SECRET_*` injection + CONNECT domain allowlist.
- **A2A IPC & CAS** — peer discovery, hierarchical tasks, task-bound file claims, `artifact://sha256` content-addressed hand-offs.
- **Cedar policy, leases & audit** — effect-level approvals, TTL/one-shot leases, `evidence_hash` pinning, hash-chained audit ledger, and `Aegis-OS-Verified` commit/PR receipts.
- **Cloud PaaS** — multi-tenant workspaces, Git-to-PR export, scale-to-zero hibernation, web approval console.

## Key benchmarks

| Metric | Result |
|---|---|
| V1–V6 bypass coverage (30 executable payloads, macOS Seatbelt & Linux `bwrap`) | **0/30 (0.0%)** vs. **93.3%** advisory hooks · **73.3%–83.3%** vendor sandboxes · **80.0%** `nerdctl` devcontainer |
| Live 4-agent repo-trap compromise (`claude`, `opencode`, `agy`, `hermes`, 54 executed cloud-API runs across 60-cell matrix) | **0%** (`aegis_enforced`) vs. **100%** (`vendor_default`, incl. Claude Opus) · **100% (8/8)** benign & multi-file `unittest` pass rate |
| Enforced sandbox startup latency | **9.91 ms** Linux `bwrap` (**22.4× faster** than `nerdctl`'s 221.53 ms) · **20.38 ms** macOS Seatbelt |
| Packed 500 MB Git CoW disk allocation (`git repack -ad`) | **4.76 MB** on APFS (**99.05% physical disk saved**) · **0.00 MB** net delta on `btrfs` |
| Loopback L7 Egress Proxy overhead & CLI TOCTOU/VT100 gate | **+0.221 ms** mean TTFT (`0/40` FP, `25/25` DLP blocked) · **60/60 (100%)** TOCTOU swaps blocked (**7.54–7.92 ms** per-class median) |
| Prompt reduction (52 real sessions, 28,087 tool calls) & 4-tier LCS auto-merge | **90.7%–97.9%** fewer prompts · **98.7%** auto-merge · **8.68 ms** 200-module rollback |

> See [`BENCHMARK_REPORT.md`](BENCHMARK_REPORT.md) (Paper 1 multi-agent & VFS suite) and [`paper2/ENFORCED_RUNTIME_BENCH_REPORT.json`](paper2/ENFORCED_RUNTIME_BENCH_REPORT.json) + [`scripts/p2_live/README.md`](scripts/p2_live/README.md) (Paper 2 cross-platform & live CLI agent suite) for full reproduction instructions.

## Documentation

- **Enforced runtime design** — advisory/enforced/isolated threat model, effect model, phase plan: [`docs/AEGIS_ENFORCED_RUNTIME_DESIGN.md`](docs/AEGIS_ENFORCED_RUNTIME_DESIGN.md)
- **Detailed architecture** — trust boundary, core crates, workspace/merge model, MCP/A2A surface, domain profiles, cloud PaaS, benchmarks, status: [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md)
- **Benchmark reports** — [`BENCHMARK_REPORT.md`](BENCHMARK_REPORT.md) · [`paper2/ENFORCED_RUNTIME_BENCH_REPORT.json`](paper2/ENFORCED_RUNTIME_BENCH_REPORT.json) · [`scripts/p2_live/README.md`](scripts/p2_live/README.md)
- **Paper 1 (Transactional Agent OS · arXiv:2611.08516)** — [https://arxiv.org/abs/2611.08516](https://arxiv.org/abs/2611.08516) ([PDF](https://arxiv.org/pdf/2611.08516) · local copy: [`paper/aegis_os_arxiv_preprint.pdf`](paper/aegis_os_arxiv_preprint.pdf))
- **Paper 2 (Enforced Runtime & Plugin Security Boundary · DOI: 10.5281/zenodo.24170505)** — [https://doi.org/10.5281/zenodo.24170505](https://doi.org/10.5281/zenodo.24170505) ([Zenodo Record](https://zenodo.org/records/24170505) · local PDF: [`paper2/aegis_enforced_runtime_arxiv_preprint.pdf`](paper2/aegis_enforced_runtime_arxiv_preprint.pdf) · [LaTeX](paper2/main.tex))
- **AAP-1.0 application protocol** — [`docs/AEGIS_APPLICATION_PROTOCOL.md`](docs/AEGIS_APPLICATION_PROTOCOL.md)
- **Memory consent / UOMP** — [`docs/UOMP_MEMORY_CONSENT_MAPPING.md`](docs/UOMP_MEMORY_CONSENT_MAPPING.md)
- **Technical monographs** — [Why Agent Plugins Are Not a Security Boundary](https://heurion.org/en/blog/from-agent-plugins-to-enforced-runtime) · [Beyond Git Branches & Shared Folders](https://heurion.org/en/blog/aegis-os-transactional-agent-kernel) · [Human-Agent Capability Parity](https://heurion.org/en/blog/human-agent-capability-parity-ai-native-software) · [Dual-Surface CRDT](https://heurion.org/en/blog/dual-surface-crdt-clinical-ai)
- **Blog index** — https://heurion.org/en/blog (中文: https://heurion.org/blog)

## Citation

If you use Aegis OS in your research or engineering workflows, please cite our papers:

```bibtex
@article{zhao2026aegisos,
  title   = {Aegis OS: A Transactional Multi-Tenant Operating System Runtime for Eliminating Authorization Fatigue in Autonomous Coding Agents},
  author  = {Zhao, Hui},
  journal = {arXiv preprint arXiv:2611.08516},
  year    = {2026},
  eprint  = {2611.08516},
  archivePrefix = {arXiv},
  primaryClass  = {cs.OS},
  url     = {https://arxiv.org/abs/2611.08516}
}

@misc{zhao2026enforced,
  title     = {Why Agent Plugins Are Not a Security Boundary: Inverting Control from In-Process Hooks to a Kernel-Enforced Agent Runtime},
  author    = {Zhao, Hui},
  year      = {2026},
  month     = nov,
  publisher = {Zenodo},
  version   = {v1},
  doi       = {10.5281/zenodo.24170505},
  url       = {https://doi.org/10.5281/zenodo.24170505}
}
```

## Telemetry & license

Anonymous install/session ping only; no source, paths, prompts, or credentials. Opt out with `DO_NOT_TRACK=1`, `AOS_TELEMETRY_DISABLED=1`, or `touch ~/.gemini/aegis-telemetry-opt-out`. Details: [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md).

Apache License 2.0. See [`LICENSE`](LICENSE).
