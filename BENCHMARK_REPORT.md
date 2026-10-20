# Aegis OS — Empirical Evaluation & Paper Benchmark Report

- **Timestamp (UTC)**: `2026-10-20T14:59:58.312307+00:00`
- **Platform / Architecture**: `macos-aarch64`

## Experiment 1 (RQ1): Live Authorization Friction & Interruption Prompt Rate (1,500 Syscalls)

| Execution Mode | Trajectories | Total Syscalls | Human Prompts | IPR (%) | Prompt Reduction (%) | Max Autonomous Streak | Total Exec Time (ms) |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **Host-Interactive (Per-Action Prompt)** | 50 | 1500 | 900 | 60.00% | **0.00%** | 4 | 390.4 |
| **Host-Static-Allowlist** | 50 | 1500 | 650 | 43.33% | **27.78%** | 5 | 390.4 |
| **Aegis-OS (Per-Task Commit Gate)** | 50 | 1500 | 50 | 3.33% | **94.44%** | 29 | 390.4 |
| **Aegis-OS (With 1h Session Lease)** | 50 | 1500 | 1 | 0.07% | **99.89%** | 1470 | 381.2 |

## Experiment 2 (RQ2): Live Red-Team Adversarial Attack Execution (40 Real Process & Socket Attacks)

| Attack Surface Category | Attacks | Host-YOLO Compromised (ASR) | Aegis-OS Compromised (ASR) | Empirical Kernel/Gateway Evidence |
| :--- | :---: | :---: | :---: | :--- |
| **A. Host Path Escape & File Tampering** | 10 | 10/10 (100.0%) | **0/10 (0.0%)** | Kernel `sandbox-exec` denied all 10 outside-workspace writes (`Operation not permitted`) |
| **B. `~/.ssh/id_rsa` Credential Harvesting** | 10 | 10/10 (100.0%) | **0/10 (0.0%)** | Kernel Seatbelt regex `(deny file-read* /.ssh)` blocked all 10 private key reads |
| **C. Live TCP Egress Secret Exfiltration** | 10 | 10/10 (100.0%) | **0/10 (0.0%)** | Live TCP Proxy (127.0.0.1:65295) returned `HTTP/1.1 403 Forbidden` on all 10 exfil domains |
| **D. Cross-Tenant IPC & CAS Access** | 10 | 10/10 (100.0%) | **0/10 (0.0%)** | Cedar Policy Kernel rejected all 10 cross-org requests (`principal.org_id != target_org_id`) |

## Experiment 3 (RQ3): Multi-Trial CoW Provisioning Latency, Storage Savings & End-to-End Syscall Overhead

| Repository Scale | Files | Size (MB) | Full Copy (Mean ± SD ms) | Aegis CoW Clone (Mean ± SD ms) | Speedup | 10-Agent Disk Saving |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: |
| **Small Project (100 files, 2.0 MB)** | 100 | 2.0 | 9.81 ± 0.48 | **0.67 ± 0.07** | **14.6x** | **95.0%** (1.0 MB vs 19.5 MB) |
| **Medium Project (300 files, 18.0 MB)** | 300 | 17.6 | 39.34 ± 6.90 | **2.99 ± 1.63** | **13.2x** | **95.0%** (8.8 MB vs 175.8 MB) |
| **Large Project (1,000 files, 80.0 MB)** | 1000 | 78.1 | 165.90 ± 17.61 | **7.86 ± 0.91** | **21.1x** | **95.0%** (39.1 MB vs 781.2 MB) |

### End-to-End Kernel & HTTP Daemon Latency Distribution

| Operation | Samples | Mean (µs) | P50 (µs) | P95 (µs) | P99 (µs) | Throughput (ops/sec) |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: |
| `PolicyKernel::evaluate (In-Process)` | 2000 | 0.1 | 0.1 | 0.1 | 0.1 | **7914241** |
| `IpcBus::send + recv_inbox (In-Process)` | 1000 | 1.4 | 1.0 | 2.6 | 4.3 | **712441** |
| `HTTP Daemon `POST /mcp` (`fs_read` RPC)` | 200 | 291.8 | 255.9 | 441.8 | 535.3 | **3373** |

## Experiment 4 (RQ4): Live 3-Agent (`agy` + `claude` + `codex`) Concurrent Rust Modification & `cargo test`

| Metric | Host-Shared-YOLO | Aegis-OS Isolated CoW + 3-Way Merge | Empirical Gain |
| :--- | :--- | :--- | :--- |
| **Concurrent 3-Agent Feature Preservation (`src/lib.rs`)** | 1/3 features preserved (2/3 overwritten) | **3/3 features preserved (100% 3-Way Merged)** | **3.0x Feature Retention (0% Clobber)** |
| **Post-Merge Real `cargo test` Compilation & Unit Test** | Failed (Missing `agy_v2` & `claude_v2` logic) | **Passed (`cargo test` exit code 0)** | **100% Build Integrity** |
| **Cross-Agent 64KB Spec Handoff Payload Size** | 196,608 bytes (~49,152 tokens inline) | **294 bytes (~73 tokens via CAS URI)** | **99.85% Context Token Reduction** |

## Experiment 5 (RQ5): Live Multi-File Corruption Recovery & `cargo check` Verification

| Corrupted Rust Modules | Sequential File Restore (Mean ± SD ms) | Aegis Atomic CoW Rollback (Mean ± SD ms) | I/O Speedup | Post-Rollback `cargo check` |
| :---: | :---: | :---: | :---: | :---: |
| **10 modules** | 0.88 ± 0.08 ms | **0.71 ± 0.10 ms** | **1.2x** | `PASSED (Exit 0)` |
| **50 modules** | 4.33 ± 0.41 ms | **1.88 ± 0.04 ms** | **2.3x** | `PASSED (Exit 0)` |
| **200 modules** | 17.11 ± 0.82 ms | **7.09 ± 0.48 ms** | **2.4x** | `PASSED (Exit 0)` |
