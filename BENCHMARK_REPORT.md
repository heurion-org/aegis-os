# Aegis OS — Empirical Evaluation & Paper Benchmark Report

- **Timestamp (UTC)**: `2026-10-20T18:51:49.436427+00:00`
- **Platform / Architecture**: `macos-aarch64`

## Experiment 1 (RQ1): Live Authorization Friction & Interruption Prompt Rate (1,500 Syscalls)

| Execution Mode | Trajectories | Total Syscalls | Human Prompts | IPR (%) | Prompt Reduction (%) | Max Autonomous Streak | Total Exec Time (ms) |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **Host-Interactive (Per-Action Prompt)** | 50 | 1500 | 860 | 57.33% | **0.00%** | 4 | 457.1 |
| **Host-Static-Allowlist** | 50 | 1500 | 680 | 45.33% | **20.93%** | 7 | 496.7 |
| **Aegis-OS (Per-Task Commit Gate)** | 50 | 1500 | 50 | 3.33% | **94.19%** | 29 | 483.6 |
| **Aegis-OS (With 1h Session Lease)** | 50 | 1500 | 1 | 0.07% | **99.88%** | 1470 | 469.2 |

## Experiment 2 (RQ2): Live Red-Team Adversarial Attack Execution (40 Real Process & Socket Attacks)

| Attack Surface Category | Attacks | Host-YOLO Compromised (ASR) | Aegis-OS Compromised (ASR) | Empirical Kernel/Gateway Evidence |
| :--- | :---: | :---: | :---: | :--- |
| **A. Host Path Escape & File Tampering** | 10 | 10/10 (100.0%) | **0/10 (0.0%)** | Kernel `sandbox-exec` denied all 10 outside-workspace writes (`Operation not permitted`) |
| **B. Host Credential Harvesting (`.ssh`/`.aws`/`.kube`)** | 10 | 10/10 (100.0%) | **0/10 (0.0%)** | Kernel Seatbelt regexes `(deny file-read* /.ssh|/.aws|/.gnupg|/.kube|/.npmrc)` blocked all 10 reads |
| **C. Sandbox-to-Proxy & Direct `--noproxy` Egress Exfil** | 10 | 10/10 (100.0%) | **0/10 (0.0%)** | Identity-pinned Proxy (127.0.0.1:65393) returned `403` & Seatbelt blocked all `--noproxy` sockets |
| **D. Cross-Tenant IPC & CAS Access via MCP Gateway** | 10 | 10/10 (100.0%) | **0/10 (0.0%)** | MCP Gateway + Policy Engine rejected all 10 cross-org calls (`principal.org_id != target_org_id`) |

## Experiment 3 (RQ3): Multi-Trial CoW Provisioning Latency, Storage Savings & End-to-End Syscall Overhead

| Repository Scale | Files | Size (MB) | Full Copy (Mean ± SD ms) | Aegis CoW Clone (Mean ± SD ms) | Speedup | 10-Agent Disk Saving |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: |
| **Small Project (100 files, 2.0 MB)** | 100 | 2.0 | 9.33 ± 0.28 | **0.71 ± 0.05** | **13.2x** | **94.0%** (1.2 MB vs 19.5 MB) |
| **Medium Project (300 files, 18.0 MB)** | 300 | 17.6 | 32.08 ± 5.82 | **1.85 ± 0.09** | **17.3x** | **96.0%** (7.0 MB vs 175.8 MB) |
| **Large Project (1,000 files, 80.0 MB)** | 1000 | 78.1 | 113.13 ± 16.41 | **6.28 ± 0.65** | **18.0x** | **97.5%** (19.5 MB vs 781.2 MB) |

### End-to-End Kernel & HTTP Daemon Latency Distribution

| Operation | Samples | Mean (µs) | P50 (µs) | P95 (µs) | P99 (µs) | Throughput (ops/sec) |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: |
| `PolicyKernel::evaluate (In-Process)` | 2000 | 0.31 | 0.29 | 0.38 | 0.50 | **2959674** |
| `IpcBus::send + recv_inbox (In-Process)` | 1000 | 1.06 | 0.83 | 1.79 | 4.75 | **924749** |
| `HTTP Daemon `POST /mcp` (`fs_read` RPC)` | 200 | 177.11 | 183.08 | 258.79 | 409.00 | **5503** |
| `CoWWorkspace::commit_to_host (3-Way Merge)` | 100 | 424.02 | 413.08 | 540.21 | 646.12 | **2110** |
| `NativeOsSandbox::exec (`sandbox-exec` Spawn)` | 30 | 6678.97 | 6557.62 | 7533.12 | 7811.33 | **150** |

## Experiment 4 (RQ4): Live 3-Agent (`agy` + `claude` + `codex`) Concurrent Rust Modification & `cargo test`

| Metric | Host-Shared-YOLO | Aegis-OS Isolated CoW + 3-Way Merge | Empirical Gain |
| :--- | :--- | :--- | :--- |
| **Concurrent 3-Agent Non-Overlapping Edits (`src/lib.rs`)** | 1/3 features preserved (2/3 overwritten) | **3/3 features preserved (100% 3-Way Merged)** | **3.0x Feature Retention (0% Clobber)** |
| **Overlapping Same-Line Edit Conflict Detection (10 Trials)** | 0/10 detected (100% Silent Lost Update) | **10/10 detected & atomically aborted (Host intact)** | **100% Conflict Safety & Line Diagnostics** |
| **Post-Merge Real `cargo test` Compilation & Unit Test** | Failed (Missing `agy_v2` & `claude_v2` logic) | **Passed (`cargo test` exit code 0)** | **100% Build Integrity** |
| **Cross-Agent 64KB Spec Handoff Payload Size** | 196,608 bytes (~49,152 tokens inline) | **294 bytes (~73 tokens via CAS URI)** | **99.85% Context Token Reduction** |

## Experiment 5 (RQ5): Live Multi-File Corruption Recovery & `cargo check` Verification

| Corrupted Rust Modules | Sequential File Restore (Mean ± SD ms) | Aegis Atomic CoW Rollback (Mean ± SD ms) | I/O Speedup | Post-Rollback `cargo check` |
| :---: | :---: | :---: | :---: | :---: |
| **10 modules** | 0.90 ± 0.06 ms | **0.75 ± 0.04 ms** | **1.2x** | `PASSED (Exit 0)` |
| **50 modules** | 4.82 ± 0.32 ms | **2.33 ± 0.14 ms** | **2.1x** | `PASSED (Exit 0)` |
| **200 modules** | 20.63 ± 3.14 ms | **8.68 ± 1.02 ms** | **2.4x** | `PASSED (Exit 0)` |
