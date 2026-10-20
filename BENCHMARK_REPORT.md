# Aegis OS — Empirical Evaluation & Paper Benchmark Report

- **Timestamp (UTC)**: `2026-10-20T15:39:31.679353+00:00`
- **Platform / Architecture**: `macos-aarch64`

## Experiment 1 (RQ1): Live Authorization Friction & Interruption Prompt Rate (1,500 Syscalls)

| Execution Mode | Trajectories | Total Syscalls | Human Prompts | IPR (%) | Prompt Reduction (%) | Max Autonomous Streak | Total Exec Time (ms) |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **Host-Interactive (Per-Action Prompt)** | 50 | 1500 | 900 | 60.00% | **0.00%** | 4 | 307.3 |
| **Host-Static-Allowlist** | 50 | 1500 | 650 | 43.33% | **27.78%** | 5 | 307.3 |
| **Aegis-OS (Per-Task Commit Gate)** | 50 | 1500 | 50 | 3.33% | **94.44%** | 29 | 307.3 |
| **Aegis-OS (With 1h Session Lease)** | 50 | 1500 | 1 | 0.07% | **99.89%** | 1470 | 303.2 |

## Experiment 2 (RQ2): Live Red-Team Adversarial Attack Execution (40 Real Process & Socket Attacks)

| Attack Surface Category | Attacks | Host-YOLO Compromised (ASR) | Aegis-OS Compromised (ASR) | Empirical Kernel/Gateway Evidence |
| :--- | :---: | :---: | :---: | :--- |
| **A. Host Path Escape & File Tampering** | 10 | 10/10 (100.0%) | **0/10 (0.0%)** | Kernel `sandbox-exec` denied all 10 outside-workspace writes (`Operation not permitted`) |
| **B. `~/.ssh/id_rsa` Credential Harvesting** | 10 | 10/10 (100.0%) | **0/10 (0.0%)** | Kernel Seatbelt regex `(deny file-read* /.ssh)` blocked all 10 private key reads |
| **C. Live TCP Egress Secret Exfiltration** | 10 | 10/10 (100.0%) | **0/10 (0.0%)** | Live TCP Proxy (127.0.0.1:51194) returned `HTTP/1.1 403 Forbidden` on all 10 exfil domains |
| **D. Cross-Tenant IPC & CAS Access** | 10 | 10/10 (100.0%) | **0/10 (0.0%)** | Cedar Policy Kernel rejected all 10 cross-org requests (`principal.org_id != target_org_id`) |

## Experiment 3 (RQ3): Multi-Trial CoW Provisioning Latency, Storage Savings & End-to-End Syscall Overhead

| Repository Scale | Files | Size (MB) | Full Copy (Mean ± SD ms) | Aegis CoW Clone (Mean ± SD ms) | Speedup | 10-Agent Disk Saving |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: |
| **Small Project (100 files, 2.0 MB)** | 100 | 2.0 | 9.28 ± 1.26 | **0.60 ± 0.06** | **15.6x** | **95.0%** (1.0 MB vs 19.5 MB) |
| **Medium Project (300 files, 18.0 MB)** | 300 | 17.6 | 28.90 ± 0.48 | **1.79 ± 0.24** | **16.1x** | **95.0%** (8.8 MB vs 175.8 MB) |
| **Large Project (1,000 files, 80.0 MB)** | 1000 | 78.1 | 101.07 ± 7.79 | **5.62 ± 0.41** | **18.0x** | **95.0%** (39.1 MB vs 781.2 MB) |

### End-to-End Kernel & HTTP Daemon Latency Distribution

| Operation | Samples | Mean (µs) | P50 (µs) | P95 (µs) | P99 (µs) | Throughput (ops/sec) |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: |
| `PolicyKernel::evaluate (In-Process)` | 2000 | 0.1 | 0.1 | 0.1 | 0.1 | **8241747** |
| `IpcBus::send + recv_inbox (In-Process)` | 1000 | 1.1 | 0.9 | 1.9 | 4.4 | **902697** |
| `HTTP Daemon `POST /mcp` (`fs_read` RPC)` | 200 | 172.8 | 178.0 | 214.4 | 265.8 | **5630** |

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
| **10 modules** | 0.81 ± 0.06 ms | **0.63 ± 0.03 ms** | **1.3x** | `PASSED (Exit 0)` |
| **50 modules** | 4.01 ± 0.08 ms | **1.89 ± 0.05 ms** | **2.1x** | `PASSED (Exit 0)` |
| **200 modules** | 15.83 ± 0.31 ms | **6.21 ± 0.15 ms** | **2.5x** | `PASSED (Exit 0)` |
