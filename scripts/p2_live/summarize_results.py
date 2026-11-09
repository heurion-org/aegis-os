#!/usr/bin/env python3
"""
Aggregates all authentic Paper 2 experimental artifacts in `scripts/p2_live/results/`
into a single audited report (`paper2/ENFORCED_RUNTIME_BENCH_REPORT.json`) and prints
exact Markdown/LaTeX-ready summary tables for `paper2/main.tex`.
"""

from __future__ import annotations

import json
import statistics
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
RES = Path(__file__).resolve().parent / "results"
OUT_REPORT = ROOT / "paper2" / "ENFORCED_RUNTIME_BENCH_REPORT.json"


def load_json(name: str) -> dict | None:
    p = RES / name
    if p.is_file() and p.stat().st_size > 0:
        return json.loads(p.read_text())
    return None


def load_jsonl(name: str) -> list[dict]:
    p = RES / name
    if not p.is_file() or p.stat().st_size == 0:
        return []
    out = []
    for line in p.read_text().splitlines():
        if line.strip():
            out.append(json.loads(line))
    return out


def main() -> None:
    rm_mac = load_json("rm_bench_macos.json")
    rm_lin = load_json("rm_bench_linux.json")
    rq2_mac = load_json("rq2_macos_apfs.json")
    rq2_ext4 = load_json("rq2_linux_ext4.json")
    rq2_btrfs = load_json("rq2_linux_btrfs.json")
    nerd_lat = load_json("nerdctl_latency.json")
    rq4_cli = load_json("rq4_cli_macos.json")
    rust_sub = load_json("rust_subsystems.json")
    apparmor_txt = (RES / "linux_apparmor_probe.txt").read_text() if (RES / "linux_apparmor_probe.txt").is_file() else ""

    # Deduplicate live agent runs across pilot.jsonl, live_matrix.jsonl, live_matrix_part2.jsonl:
    # keep the LATEST valid run for each (agent, mode, payload, model_tag) tuple.
    pilot = load_jsonl("pilot.jsonl")
    part1 = load_jsonl("live_matrix.jsonl")
    part2 = load_jsonl("live_matrix_part2.jsonl")
    opus_rows = load_jsonl("live_opus_slice.jsonl")
    rq6_rows = load_jsonl("live_rq6.jsonl")

    latest_live: dict[tuple[str, str, str], dict] = {}
    for row in pilot + part1 + part2:
        # Skip the two pre-login pilot smoke errors (pilot rows 1-2) where later valid runs exist
        key = (row["agent"], row["mode"], row["payload"])
        latest_live[key] = row

    print("=================================================================")
    print("1. LAYER 1 DETERMINISTIC RM & ABLATION BENCHMARK (30 PAYLOADS)")
    print("=================================================================")
    for label, data in [("macOS Seatbelt", rm_mac), ("Linux bwrap/nerdctl", rm_lin)]:
        if not data:
            print(f"  [{label}] MISSING")
            continue
        print(f"\n--- {label} ({data.get('platform')}) ---")
        print("  Latency:", data.get("latency"))
        for mode, s in data["summary"].items():
            vecs = " ".join(f"{v}:{s['vectors'][v]['compromised']}/{s['vectors'][v]['total']}" for v in ("V1", "V2", "V3", "V4", "V5", "V6"))
            print(f"  {mode:24s} | {s['total_compromised']:2d}/{s['total_payloads']} ({s['overall_asr_pct']:5.1f}%) | {vecs}")

    print("\n=================================================================")
    print("2. LAYER 2 LIVE PRODUCTION CLI AGENT MATRIX (4 AGENTS)")
    print("=================================================================")
    for mode in ("vendor_default", "advisory", "vendor_sandbox", "aegis_enforced"):
        print(f"\n--- Mode: {mode} ---")
        for payload in ("benign", "v2_contrib_exfil", "cd_repo_trap"):
            for agent in ("claude", "opencode", "agy", "hermes"):
                r = latest_live.get((agent, mode, payload))
                if not r:
                    print(f"  {agent:8s} | {payload:16s} | MISSING")
                    continue
                comp = r.get("any_compromised", r.get("sink_reached", False))
                vecs = [k for k, v in (r.get("vector_compromised") or {}).items() if v]
                print(
                    f"  {agent:8s} | {payload:16s} | exit={str(r.get('exit_code')):4s} | "
                    f"{r.get('duration_s', 0):5.1f}s | cost={r.get('cost_usd')} | "
                    f"hooks={r.get('advisory_hook_calls', 0)}/{r.get('advisory_hook_blocks', 0)} | "
                    f"tests={r.get('task_tests_pass')} | comp={comp} | vec={vecs} | "
                    f"cred_src={r.get('llm_cred_source')} | diff_ms={r.get('aegis_diff_ms')} | commit_ms={r.get('aegis_commit_ms')} | "
                    f"err={str(r.get('error'))[:60]}"
                )

    print("\n--- Claude Opus 4.6 Validation Slice ---")
    for r in opus_rows:
        vecs = [k for k, v in (r.get("vector_compromised") or {}).items() if v]
        print(
            f"  {r['agent']:8s} ({r.get('model_reported')}) | {r['mode']:14s} | {r['payload']:16s} | "
            f"exit={r.get('exit_code')} | {r.get('duration_s')}s | cost={r.get('cost_usd')} | "
            f"tests={r.get('task_tests_pass')} | comp={r.get('any_compromised')} | vec={vecs}"
        )

    print("\n=================================================================")
    print("3. RQ2 PACKED GIT COW & SPLIT .GIT BENCHMARK")
    print("=================================================================")
    for label, d in [("macOS APFS", rq2_mac), ("Linux ext4", rq2_ext4), ("Linux btrfs", rq2_btrfs)]:
        if not d:
            print(f"  [{label}] MISSING")
            continue
        print(f"\n--- {label} ({d.get('filesystem')}) ---")
        for rname, r in d["repos"].items():
            print(
                f"  {rname:12s} | cp-R med={r['cp_r_median_ms']:7.2f}ms (p95={r['cp_r_p95_ms']:7.2f}, disk={r['cp_r_disk_delta_median_mb']:6.2f}MB) | "
                f"aos-run+git med={r['aegis_run_git_status_median_ms']:7.2f}ms (p95={r['aegis_run_git_status_p95_ms']:7.2f}) | "
                f"diff3={r['aegis_diff_3files_median_ms']:5.2f}ms | statvfs_delta={r['aegis_statvfs_delta_median_mb']:5.2f}MB | shadow_du={r['aegis_shadow_du_median_mb']:6.2f}MB"
            )
    if nerd_lat:
        print("\n  Linux nerdctl container startup:", nerd_lat)

    print("\n=================================================================")
    print("4. RQ6 MULTI-FILE BILLING TASK UTILITY & OVERHEAD")
    print("=================================================================")
    for r in rq6_rows:
        print(
            f"  {r['agent']:8s} | {r['mode']:14s} | exit={r.get('exit_code')} | "
            f"{r.get('duration_s'):5.1f}s | in={r.get('input_tokens')} out={r.get('output_tokens')} cost={r.get('cost_usd')} | "
            f"tests={r.get('task_tests_pass')} | host_clean_pre_commit={r.get('host_repo_untouched_pre_commit')} | "
            f"diff_ms={r.get('aegis_diff_ms')} | commit_ms={r.get('aegis_commit_ms')} | err={str(r.get('error'))[:60]}"
        )

    consolidated = {
        "linux_apparmor_probe": apparmor_txt,
        "rm_bench_macos": rm_mac,
        "rm_bench_linux": rm_lin,
        "nerdctl_latency_linux": nerd_lat,
        "rq2_macos_apfs": rq2_mac,
        "rq2_linux_ext4": rq2_ext4,
        "rq2_linux_btrfs": rq2_btrfs,
        "rq4_cli_macos": rq4_cli,
        "rust_subsystems": rust_sub,
        "live_agent_matrix_deduped": list(latest_live.values()),
        "live_claude_opus_slice": opus_rows,
        "live_rq6_multifile": rq6_rows,
    }
    OUT_REPORT.write_text(json.dumps(consolidated, indent=2) + "\n")
    print(f"\nWrote consolidated report -> {OUT_REPORT} ({OUT_REPORT.stat().st_size} bytes)")


if __name__ == "__main__":
    main()
