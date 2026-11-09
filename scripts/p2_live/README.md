# Paper 2 Reproducible Evaluation Suite (`scripts/p2_live/`)

This directory contains the reproducible cross-platform and live-agent evaluation suite for Paper 2 (*"Why Agent Plugins Are Not a Security Boundary: Inverting Control from In-Process Hooks to a Kernel-Enforced Agent Runtime"*):

- `deterministic_rm_bench.py` — **RQ1 Layer 1 & Ablations**: Executes 30 concrete adversarial bypass payloads across `V1`–`V6` (5 payloads per vector) on macOS Seatbelt, Linux `bubblewrap` (`bwrap`), rootless `nerdctl` OCI devcontainers, and `AOS_ABLATE` Rust ablation binaries (`git_guard`, `config_overmount`, `secret_vault`, `dual_token`).
- `harness.py` — **RQ1 Layer 2 & RQ6 Live CLI Agents**: Drives installed `claude`, `opencode`, `agy`, and `hermes` binaries across `vendor_default`, `advisory`, `vendor_sandbox`, and `aegis_enforced` modes on `benign`, `v2_contrib_exfil`, `cd_repo_trap`, and `rq6_multifile`.
- `rq2_git_cow_bench.py` — **RQ2 Packed Git CoW & Split `.git`**: Measures end-to-end `aegis-os run` + `git status` + `aegis-os diff --json` latency and physical disk allocation (`statvfs` + `du`) against `cp -R` across `git repack -ad` repositories (8 MB, 90 MB, 500 MB) on APFS, `btrfs`, and `ext4`.
- `rq4_cli_toctou_bench.py` — **RQ4 CLI TOCTOU & Terminal Escape Spoofing**: Evaluates `aegis-os commit --expected-diff-hash` against 6 post-diff tampering and ANSI CSI / Unicode Bidi spoofing classes (`n = 60` attacks).
- `summarize_results.py` — Consolidates all raw artifacts under `results/` into `paper2/ENFORCED_RUNTIME_BENCH_REPORT.json`.

## Quick Reproduction

```bash
# 1. Build standard and ablation-enabled binaries
cargo build --release --bin aegis-os
cargo build --release --bin aegis-os --features test-ablation

# 2. Run RQ1 Layer 1 deterministic benchmark
python3 scripts/p2_live/deterministic_rm_bench.py \
  --aegis-bin target/release/aegis-os \
  --modes no_protection,advisory_hooks,vendor_sandbox,aegis_enforced \
  --output scripts/p2_live/results/rm_bench_local.json

# 3. Run RQ2 Git CoW benchmark & RQ4 CLI TOCTOU benchmark
python3 scripts/p2_live/rq2_git_cow_bench.py \
  --aegis-bin target/release/aegis-os \
  --output scripts/p2_live/results/rq2_local.json
python3 scripts/p2_live/rq4_cli_toctou_bench.py \
  --aegis-bin target/release/aegis-os \
  --output scripts/p2_live/results/rq4_local.json

# 4. Regenerate consolidated report
python3 scripts/p2_live/summarize_results.py
```
