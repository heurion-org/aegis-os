# Aegis OS — Empirical Evaluation & Paper Benchmark Report

- **Timestamp (UTC)**: `2026-10-21T18:52:14.277544+00:00`
- **Platform / Architecture**: `macos-aarch64`

## Experiment 1 (RQ1): Live Authorization Friction & Interruption Prompt Rate (1,500 Syscalls)

| Execution Mode | Trajectories | Total Syscalls | Human Prompts | IPR (%) | Prompt Reduction (%) | Max Autonomous Streak | Total Exec Time (ms) |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **Host-Interactive (Per-Action Prompt)** | 50 | 1500 | 860 | 57.33% | **0.00%** | 4 | 3325.9 |
| **Host-Static-Allowlist** | 50 | 1500 | 680 | 45.33% | **20.93%** | 7 | 3485.2 |
| **Aegis-OS (Per-Task Commit Gate)** | 50 | 1500 | 50 | 3.33% | **94.19%** | 29 | 2717.3 |
| **Aegis-OS (With 1h Session Lease)** | 50 | 1500 | 1 | 0.07% | **99.88%** | 1470 | 2354.6 |

## Experiment 2 (RQ2): Live Red-Team Adversarial Attack Execution (80 Real Process & Socket Attacks)

| Attack Surface Category | Attacks | Host-YOLO Compromised (ASR) | Aegis-OS Compromised (ASR) | Empirical Kernel/Gateway Evidence |
| :--- | :---: | :---: | :---: | :--- |
| **A. Host Path Escape & File Tampering** | 10 | 10/10 (100.0%) | **0/10 (0.0%)** | Kernel `sandbox-exec` denied all 10 outside-workspace writes (`Operation not permitted`) |
| **B. Host Credential Harvesting (`.ssh`/`.aws`/`.kube`)** | 10 | 4/10 (40.0%) | **0/10 (0.0%)** | Kernel Seatbelt regexes `(deny file-read* /.ssh|/.aws|/.gnupg|/.kube|/.npmrc)` blocked all 10 reads |
| **C. Sandbox-to-Proxy & Direct `--noproxy` Egress Exfil** | 10 | 10/10 (100.0%) | **0/10 (0.0%)** | Real token reached the attacker sink in 0/10 sandboxed runs; the identity-pinned proxy (127.0.0.1:50811) returned `403 blocked_exfiltration` to the sandboxed client in 0/10 runs (the remainder were contained by the kernel network confinement before reaching the proxy) |
| **D. Cross-Tenant IPC & CAS Access via MCP Gateway** | 10 | 10/10 (100.0%) | **0/10 (0.0%)** | Cross-org calls that succeeded: 0/5 IPC sends, 0/5 CAS fetches (the policy gate rejects `principal.org_id != target_org_id`; breaches here mean no other layer caught them) |
| **E. Commit-Time Poisoning (hooks / .envrc / CI)** | 10 | 10/10 (100.0%) | **0/10 (0.0%)** | With a standing commit lease active, the commit-time guard escalated 10/10 auto-executing paths to a human; 0/10 were auto-approved |
| **F. Secret-Binding Abuse (allowlisted, unbound domain)** | 10 | 10/10 (100.0%) | **0/10 (0.0%)** | Per-secret domain binding refused 10/10 injections toward allowlisted domains the secret is not bound to; 0/10 leaked the real token |
| **H. Silent Overwrite of a Peer's Edit (lost update)** | 10 | 10/10 (100.0%) | **0/10 (0.0%)** | Conflict detection preserved the peer's edit in 10/10 same-line conflicts; 0/10 were silently overwritten |
| **G. Partial Commit on Conflict (atomicity)** | 10 | 10/10 (100.0%) | **0/10 (0.0%)** | Two-phase commit left the host tree untouched in 10/10 conflicting batches; 0/10 applied the clean file anyway |

## Experiment 3 (RQ3): Multi-Trial CoW Provisioning Latency, Storage Savings & End-to-End Syscall Overhead

| Repository Scale | Files | Size (MB) | Full Copy (Mean ± SD ms) | Aegis CoW Clone (Mean ± SD ms) | Speedup | 10-Agent Disk Saving |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: |
| **Small Project (100 files, 2.0 MB)** | 100 | 2.0 | 11.63 ± 0.35 | **0.86 ± 0.04** | **13.6x** | **94.0%** (1.2 MB vs 19.5 MB) |
| **Medium Project (300 files, 18.0 MB)** | 300 | 17.6 | 38.77 ± 0.54 | **2.11 ± 0.30** | **18.4x** | **96.0%** (7.0 MB vs 175.8 MB) |
| **Large Project (1,000 files, 80.0 MB)** | 1000 | 78.1 | 129.46 ± 1.57 | **6.79 ± 2.49** | **19.1x** | **97.5%** (19.5 MB vs 781.2 MB) |

### End-to-End Kernel & HTTP Daemon Latency Distribution

| Operation | Samples | Mean (µs) | P50 (µs) | P95 (µs) | P99 (µs) | Throughput (ops/sec) |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: |
| `PolicyKernel::evaluate (In-Process)` | 2000 | 0.31 | 0.29 | 0.33 | 0.42 | **2994572** |
| `IpcBus::send + recv_inbox (In-Process)` | 1000 | 1.20 | 1.00 | 1.92 | 2.92 | **813201** |
| `HTTP Daemon `POST /mcp` (`fs_read` RPC)` | 200 | 435.80 | 433.58 | 456.75 | 501.96 | **2267** |
| `CoWWorkspace::commit_to_host (3-Way Merge)` | 100 | 1947.82 | 1905.08 | 2117.62 | 6123.04 | **499** |
| `NativeOsSandbox::exec (`sandbox-exec` Spawn)` | 30 | 6646.94 | 6486.29 | 7542.58 | 7568.04 | **150** |

## Experiment 4 (RQ4): Live 3-Agent (`agy` + `claude` + `codex`) Concurrent Rust Modification & `cargo test`

| Metric | Host-Shared-YOLO | Aegis-OS Isolated CoW + 3-Way Merge | Empirical Gain |
| :--- | :--- | :--- | :--- |
| **Concurrent 3-Agent Non-Overlapping Edits (`src/lib.rs`)** | 1/3 features preserved (2/3 overwritten) | **3/3 features preserved (100% 3-Way Merged)** | **3.0x Feature Retention (0% Clobber)** |
| **Overlapping Same-Line Edit Conflict Detection (10 Trials)** | 0/10 detected (100% Silent Lost Update) | **10/10 detected & atomically aborted (Host intact)** | **100% Conflict Safety & Line Diagnostics** |
| **Disjoint-Line Semantic Conflict Detection via `verify_cmd` (10 Trials)** | 0/10 detected (Broken host compilation) | **10/10 detected by sandboxed `rustc` gate (Host intact)** | **100% Semantic Build Safety** |
| **Post-Merge Real `cargo test` Compilation & Unit Test** | Failed (Missing `agy_v2` & `claude_v2` logic) | **Passed (`cargo test` exit code 0)** | **100% Build Integrity** |
| **Cross-Agent 64KB Spec Handoff Payload Size** | 196,608 bytes (~49,152 tokens inline) | **294 bytes (~73 tokens via CAS URI)** | **99.85% Context Token Reduction** |

## Experiment 5 (RQ5): Live Multi-File Corruption Recovery & `cargo check` Verification

| Corrupted Rust Modules | Sequential File Restore (Mean ± SD ms) | Aegis Atomic CoW Rollback (Mean ± SD ms) | I/O Speedup | Post-Rollback `cargo check` |
| :---: | :---: | :---: | :---: | :---: |
| **10 modules** | 1.14 ± 0.04 ms | **1.07 ± 0.05 ms** | **1.1x** | `PASSED (Exit 0)` |
| **50 modules** | 5.69 ± 0.22 ms | **2.14 ± 0.03 ms** | **2.7x** | `PASSED (Exit 0)` |
| **200 modules** | 25.21 ± 2.19 ms | **7.50 ± 0.56 ms** | **3.4x** | `PASSED (Exit 0)` |
