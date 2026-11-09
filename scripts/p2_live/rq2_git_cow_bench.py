#!/usr/bin/env python3
"""
RQ2 Real Git Packfile CoW & Split `.git` Benchmark (macOS APFS + Linux ext4/btrfs).

Addresses audit item P0-5:
  1. Constructs 3 genuine Git repositories with real `.git/objects/pack/*.pack` histories
     (`git gc` packed objects + realistic working trees):
       - small_repo:  ~8 MB total  (~5 MB packed .git + ~3 MB across 200 working-tree files)
       - medium_repo: ~90 MB total (~72 MB packed .git + ~18 MB across 1,200 working-tree files)
       - large_repo:  ~500 MB total (~420 MB packed .git + ~80 MB across 4,000 working-tree files)
  2. Benchmarks across n=10 trials per repo (reporting median, mean, and P95):
       - `cp -R` full repository clone latency (ms) & physical disk blocks (`du -sk`)
       - Real `aegis-os run --enforcement enforced -- git status --porcelain` session startup +
         CoW shadow init + split `.git` view + read-only `git status` execution latency (ms),
         plus shadow physical disk delta and `aegis-os diff --json` latency after 3 file edits!
"""

from __future__ import annotations

import argparse
import json
import os
import platform
import shutil
import statistics
import subprocess
import tempfile
import time
from pathlib import Path


def _git(cwd: Path, *args: str) -> None:
    subprocess.run(
        ["git", "-c", "gc.auto=0", *args],
        cwd=cwd,
        check=True,
        capture_output=True,
    )


def du_kib(path: Path) -> int:
    """Physical allocated disk blocks in KiB reported by `du -sk`."""
    out = subprocess.run(["du", "-sk", str(path)], capture_output=True, text=True, check=True).stdout
    return int(out.split()[0])


def logical_bytes(path: Path) -> int:
    total = 0
    for root, _, files in os.walk(path):
        for f in files:
            p = Path(root) / f
            if not p.is_symlink():
                total += p.stat().st_size
    return total


def build_packed_git_repo(
    dest: Path,
    num_files: int,
    file_size_bytes: int,
    pack_commits: int,
    blob_bytes_per_commit: int,
) -> dict:
    dest.mkdir(parents=True, exist_ok=True)
    _git(dest, "init", "-q")
    _git(dest, "config", "user.email", "rq2@example.invalid")
    _git(dest, "config", "user.name", "RQ2 Bench")

    # Create historical binary/random commits so `git repack -ad` produces genuine .pack/.idx files
    hist_dir = dest / ".history_blobs"
    hist_dir.mkdir(exist_ok=True)
    for c in range(pack_commits):
        blob_path = hist_dir / "asset.bin"
        blob_path.write_bytes(os.urandom(blob_bytes_per_commit))
        _git(dest, "add", ".history_blobs/asset.bin")
        _git(dest, "commit", "-q", "-m", f"history blob {c}")
    shutil.rmtree(hist_dir)
    _git(dest, "add", "-A")
    _git(dest, "commit", "-q", "-m", "drop history staging")

    # Populate realistic multi-directory working tree
    src = dest / "src"
    for i in range(num_files):
        mod_dir = src / f"pkg_{i % 25}"
        mod_dir.mkdir(parents=True, exist_ok=True)
        header = f"// module {i}\npub fn item_{i}() -> usize {{ {i} }}\n".encode()
        pad_len = max(0, file_size_bytes - len(header))
        pad = (f"// line_fill_{i:05d}_abcdef0123456789\n" * ((pad_len // 36) + 1)).encode()[:pad_len]
        (mod_dir / f"mod_{i}.rs").write_bytes(header + pad)

    _git(dest, "add", "-A")
    _git(dest, "commit", "-q", "-m", "populate working tree")
    # Pack objects into genuine .git/objects/pack/*.pack without slow delta search on urandom
    _git(dest, "-c", "pack.window=0", "-c", "pack.depth=0", "repack", "-a", "-d", "-q")

    pack_dir = dest / ".git" / "objects" / "pack"
    pack_files = list(pack_dir.glob("*.pack"))
    pack_bytes = sum(p.stat().st_size for p in pack_files)
    total_logical = logical_bytes(dest)
    git_logical = logical_bytes(dest / ".git")
    wt_logical = total_logical - git_logical
    return {
        "files_count": num_files,
        "pack_files_count": len(pack_files),
        "pack_bytes_mb": round(pack_bytes / (1024 * 1024), 2),
        "git_dir_mb": round(git_logical / (1024 * 1024), 2),
        "worktree_mb": round(wt_logical / (1024 * 1024), 2),
        "total_logical_mb": round(total_logical / (1024 * 1024), 2),
        "host_du_mb": round(du_kib(dest) / 1024.0, 2),
    }


def pct95(vals: list[float]) -> float:
    s = sorted(vals)
    return s[min(len(s) - 1, int(0.95 * (len(s) - 1)))]


def df_avail_kib(path: Path) -> int:
    st = os.statvfs(path)
    return (st.f_bavail * st.f_frsize) // 1024


def bench_one_repo(name: str, repo: Path, meta: dict, aegis_bin: Path, trials: int) -> dict:
    cp_ms_list = []
    cp_disk_mb_list = []
    aegis_run_git_ms_list = []
    aegis_diff_ms_list = []
    aegis_shadow_du_mb_list = []
    aegis_df_delta_mb_list = []

    with tempfile.TemporaryDirectory(prefix=f"rq2_work_{name}_", dir=repo.parent) as work_str:
        work = Path(work_str)
        fake_home = work / "home"
        fake_home.mkdir()
        env = dict(os.environ)
        env["HOME"] = str(fake_home)
        env.pop("AOS_ABLATE", None)

        for t in range(trials):
            # 1. Naive `cp -R` full copy (copies both working tree AND .git/objects/pack without CoW)
            cp_dst = work / f"cp_{t}"
            avail_before_cp = df_avail_kib(work)
            cp_cmd = ["cp", "-R", str(repo), str(cp_dst)]
            if platform.system() != "Darwin":
                cp_cmd = ["cp", "-R", "--reflink=never", str(repo), str(cp_dst)]
            t0 = time.perf_counter()
            subprocess.run(cp_cmd, check=True)
            cp_ms = (time.perf_counter() - t0) * 1000.0
            avail_after_cp = df_avail_kib(work)
            cp_du_mb = du_kib(cp_dst) / 1024.0
            cp_df_delta_mb = max(0.0, (avail_before_cp - avail_after_cp) / 1024.0)
            cp_ms_list.append(cp_ms)
            cp_disk_mb_list.append(cp_df_delta_mb if platform.system() == "Darwin" else cp_du_mb)
            shutil.rmtree(cp_dst)

            # 2. Real `aegis-os run --enforcement enforced`: CoW init + split .git + `git status` + 3 edits
            rt = work / f"rt_{t}"
            rt.mkdir()
            avail_before_aos = df_avail_kib(work)
            edit_cmd = (
                "git status --porcelain >/dev/null && "
                "printf '// edit\\n' >> src/pkg_0/mod_0.rs && "
                "printf '// edit\\n' >> src/pkg_1/mod_1.rs && "
                "printf '// edit\\n' >> src/pkg_2/mod_2.rs"
            )
            t1 = time.perf_counter()
            proc = subprocess.run(
                [
                    str(aegis_bin),
                    "--runtime-dir", str(rt),
                    "run",
                    "--workspace", str(repo),
                    "--enforcement", "enforced",
                    "--",
                    "/bin/sh", "-c", edit_cmd,
                ],
                env=env,
                capture_output=True,
                text=True,
                stdin=subprocess.DEVNULL,
            )
            aegis_ms = (time.perf_counter() - t1) * 1000.0
            assert proc.returncode in (0, 10), f"aegis-os run failed ({proc.returncode}): {proc.stderr}"
            avail_after_aos = df_avail_kib(work)
            aegis_run_git_ms_list.append(aegis_ms)

            # Measure `aegis-os diff --json` latency on the 3 modified files
            t2 = time.perf_counter()
            diff_p = subprocess.run(
                [str(aegis_bin), "--runtime-dir", str(rt), "diff", "--json"],
                env=env,
                capture_output=True,
                text=True,
                check=True,
            )
            diff_ms = (time.perf_counter() - t2) * 1000.0
            diff_data = json.loads(diff_p.stdout)
            assert diff_data["changed_count"] == 3, f"expected 3 changed files, got {diff_data['changed_count']}"
            aegis_diff_ms_list.append(diff_ms)

            shadow_path = Path(diff_data["shadow"])
            aegis_shadow_du_mb_list.append(du_kib(shadow_path) / 1024.0)
            aegis_df_delta_mb_list.append(max(0.0, (avail_before_aos - avail_after_aos) / 1024.0))
            for root, dirs, files in os.walk(rt):
                try:
                    os.chmod(root, 0o700)
                except OSError:
                    pass
                for d in dirs:
                    try:
                        os.chmod(os.path.join(root, d), 0o700)
                    except OSError:
                        pass
            shutil.rmtree(rt, ignore_errors=True)

    speedup = statistics.median(cp_ms_list) / max(0.01, statistics.median(aegis_run_git_ms_list))
    return {
        "meta": meta,
        "trials": trials,
        "cp_r_median_ms": round(statistics.median(cp_ms_list), 2),
        "cp_r_mean_ms": round(statistics.mean(cp_ms_list), 2),
        "cp_r_p95_ms": round(pct95(cp_ms_list), 2),
        "cp_r_disk_delta_median_mb": round(statistics.median(cp_disk_mb_list), 2),
        "aegis_run_git_status_median_ms": round(statistics.median(aegis_run_git_ms_list), 2),
        "aegis_run_git_status_mean_ms": round(statistics.mean(aegis_run_git_ms_list), 2),
        "aegis_run_git_status_p95_ms": round(pct95(aegis_run_git_ms_list), 2),
        "aegis_diff_3files_median_ms": round(statistics.median(aegis_diff_ms_list), 2),
        "aegis_diff_3files_p95_ms": round(pct95(aegis_diff_ms_list), 2),
        "aegis_shadow_du_median_mb": round(statistics.median(aegis_shadow_du_mb_list), 2),
        "aegis_statvfs_delta_median_mb": round(statistics.median(aegis_df_delta_mb_list), 2),
        "median_speedup_vs_cp_r": round(speedup, 2),
    }


def detect_fs_type(path: Path) -> str:
    if platform.system() == "Darwin":
        return "APFS (macOS clonefile)"
    out = subprocess.run(["df", "-T", str(path)], capture_output=True, text=True).stdout.splitlines()
    if len(out) >= 2:
        parts = out[1].split()
        if len(parts) >= 2:
            return parts[1]
    return "linux-fs"


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--aegis-bin", required=True, type=Path)
    ap.add_argument("--trials", type=int, default=10)
    ap.add_argument("--work-dir", type=Path, default=None)
    ap.add_argument("--out", required=True, type=Path)
    args = ap.parse_args()

    parent_dir = args.work_dir or Path(tempfile.gettempdir())
    parent_dir.mkdir(parents=True, exist_ok=True)

    specs = [
        # (name, num_files, file_size_bytes, pack_commits, blob_bytes_per_commit)
        ("small_8mb", 200, 15 * 1024, 5, 1024 * 1024),
        ("medium_90mb", 1200, 15 * 1024, 12, 6 * 1024 * 1024),
        ("large_500mb", 4000, 20 * 1024, 21, 20 * 1024 * 1024),
    ]

    results = {}
    with tempfile.TemporaryDirectory(prefix="rq2_suite_", dir=parent_dir) as suite_str:
        suite = Path(suite_str)
        fs_type = detect_fs_type(suite)
        print(f"[rq2_bench] filesystem={fs_type} dir={suite} trials={args.trials}", flush=True)
        for name, nfiles, fsize, ncommits, bsize in specs:
            repo_dir = suite / name
            print(f"[rq2_bench] building {name} ({nfiles} files + {ncommits} packed commits) ...", flush=True)
            meta = build_packed_git_repo(repo_dir, nfiles, fsize, ncommits, bsize)
            print(f"  built {name}: {meta}", flush=True)
            res = bench_one_repo(name, repo_dir, meta, args.aegis_bin.resolve(), args.trials)
            results[name] = res
            print(
                f"  -> {name}: cp -R={res['cp_r_median_ms']}ms (p95 {res['cp_r_p95_ms']}ms) | "
                f"aegis run+git status={res['aegis_run_git_status_median_ms']}ms (p95 {res['aegis_run_git_status_p95_ms']}ms) | "
                f"diff={res['aegis_diff_3files_median_ms']}ms",
                flush=True,
            )
            shutil.rmtree(repo_dir)

    out_obj = {
        "platform": platform.platform(),
        "system": platform.system(),
        "filesystem": fs_type,
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "repos": results,
    }
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(out_obj, indent=2) + "\n")
    print(f"[rq2_bench] saved {args.out}", flush=True)


if __name__ == "__main__":
    main()
