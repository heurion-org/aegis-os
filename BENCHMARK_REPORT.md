# Aegis OS — Empirical Evaluation & Paper Benchmark Report

- **Timestamp (UTC)**: `2026-10-21T18:11:26.579252+00:00`
- **Platform / Architecture**: `macos-aarch64`

## Experiment 1 (RQ1): Live Authorization Friction & Interruption Prompt Rate (1,500 Syscalls)

| Execution Mode | Trajectories | Total Syscalls | Human Prompts | IPR (%) | Prompt Reduction (%) | Max Autonomous Streak | Total Exec Time (ms) |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **Host-Interactive (Per-Action Prompt)** | 50 | 1500 | 860 | 57.33% | **0.00%** | 4 | 867.5 |
| **Host-Static-Allowlist** | 50 | 1500 | 680 | 45.33% | **20.93%** | 7 | 945.1 |
| **Aegis-OS (Per-Task Commit Gate)** | 50 | 1500 | 50 | 3.33% | **94.19%** | 29 | 1059.2 |
| **Aegis-OS (With 1h Session Lease)** | 50 | 1500 | 1 | 0.07% | **99.88%** | 1470 | 595.5 |

## Experiment 2 (RQ2): Live Red-Team Adversarial Attack Execution (80 Real Process & Socket Attacks)

| Attack Surface Category | Attacks | Host-YOLO Compromised (ASR) | Aegis-OS Compromised (ASR) | Empirical Kernel/Gateway Evidence |
| :--- | :---: | :---: | :---: | :--- |
| **A. Host Path Escape & File Tampering** | 10 | 10/10 (100.0%) | **0/10 (0.0%)** | Kernel `sandbox-exec` denied all 10 outside-workspace writes (`Operation not permitted`) |
| **B. Host Credential Harvesting (`.ssh`/`.aws`/`.kube`)** | 10 | 10/10 (100.0%) | **0/10 (0.0%)** | Kernel Seatbelt regexes `(deny file-read* /.ssh|/.aws|/.gnupg|/.kube|/.npmrc)` blocked all 10 reads |
| **C. Sandbox-to-Proxy & Direct `--noproxy` Egress Exfil** | 10 | 10/10 (100.0%) | **0/10 (0.0%)** | Real token reached the attacker sink in 0/10 sandboxed runs; the identity-pinned proxy (127.0.0.1:49876) returned `403 blocked_exfiltration` to the sandboxed client in 10/10 runs (the remainder were contained by the kernel network confinement before reaching the proxy) |
| **D. Cross-Tenant IPC & CAS Access via MCP Gateway** | 10 | 10/10 (100.0%) | **0/10 (0.0%)** | Cross-org calls that succeeded: 0/5 IPC sends, 0/5 CAS fetches (the policy gate rejects `principal.org_id != target_org_id`; breaches here mean no other layer caught them) |
| **E. Commit-Time Poisoning (hooks / .envrc / CI)** | 10 | 10/10 (100.0%) | **0/10 (0.0%)** | With a standing commit lease active, the commit-time guard escalated 10/10 auto-executing paths to a human; 0/10 were auto-approved |
| **F. Secret-Binding Abuse (allowlisted, unbound domain)** | 10 | 10/10 (100.0%) | **0/10 (0.0%)** | Per-secret domain binding refused 10/10 injections toward allowlisted domains the secret is not bound to; 0/10 leaked the real token |
| **H. Silent Overwrite of a Peer's Edit (lost update)** | 10 | 10/10 (100.0%) | **0/10 (0.0%)** | Conflict detection preserved the peer's edit in 10/10 same-line conflicts; 0/10 were silently overwritten |
| **G. Partial Commit on Conflict (atomicity)** | 10 | 10/10 (100.0%) | **0/10 (0.0%)** | Two-phase commit left the host tree untouched in 10/10 conflicting batches; 0/10 applied the clean file anyway |

## Experiment 3 (RQ3): Multi-Trial CoW Provisioning Latency, Storage Savings & End-to-End Syscall Overhead

| Repository Scale | Files | Size (MB) | Full Copy (Mean ± SD ms) | Aegis CoW Clone (Mean ± SD ms) | Speedup | 10-Agent Disk Saving |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: |
| **Small Project (100 files, 2.0 MB)** | 100 | 2.0 | 9.32 ± 0.33 | **0.76 ± 0.07** | **12.3x** | **94.0%** (1.2 MB vs 19.5 MB) |
| **Medium Project (300 files, 18.0 MB)** | 300 | 17.6 | 35.94 ± 3.70 | **2.13 ± 0.21** | **16.8x** | **96.0%** (7.0 MB vs 175.8 MB) |
| **Large Project (1,000 files, 80.0 MB)** | 1000 | 78.1 | 109.19 ± 6.53 | **8.24 ± 1.76** | **13.3x** | **97.5%** (19.5 MB vs 781.2 MB) |

### End-to-End Kernel & HTTP Daemon Latency Distribution

| Operation | Samples | Mean (µs) | P50 (µs) | P95 (µs) | P99 (µs) | Throughput (ops/sec) |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: |
| `PolicyKernel::evaluate (In-Process)` | 2000 | 0.28 | 0.29 | 0.29 | 0.33 | **3253577** |
| `IpcBus::send + recv_inbox (In-Process)` | 1000 | 1.14 | 0.88 | 1.88 | 3.29 | **861358** |
| `HTTP Daemon `POST /mcp` (`fs_read` RPC)` | 200 | 310.94 | 286.96 | 522.75 | 888.25 | **3148** |
| `CoWWorkspace::commit_to_host (3-Way Merge)` | 100 | 656.77 | 654.29 | 769.33 | 849.25 | **1389** |
| `NativeOsSandbox::exec (`sandbox-exec` Spawn)` | 30 | 6934.58 | 6773.75 | 7749.96 | 8444.58 | **144** |

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
| **10 modules** | 0.82 ± 0.03 ms | **0.71 ± 0.08 ms** | **1.2x** | `PASSED (Exit 0)` |
| **50 modules** | 4.28 ± 0.21 ms | **2.21 ± 0.12 ms** | **1.9x** | `PASSED (Exit 0)` |
| **200 modules** | 17.23 ± 0.24 ms | **8.05 ± 0.68 ms** | **2.1x** | `PASSED (Exit 0)` |
