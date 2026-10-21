#!/usr/bin/env python3
"""E5: workspace-provisioning baselines for the Aegis OS paper.

Measures how long real tools take to create an isolated per-agent copy of a project tree, and how much
physical disk each copy really consumes, at the same three scales as `aegis-os bench` (EXP 3):

    Small  :   100 files x  20 KiB =  2 MB
    Medium :   300 files x  60 KiB = 18 MB
    Large  : 1,000 files x  80 KiB = 80 MB

Methods (all stdlib / system tools, no Aegis code involved):
    cp -R                  full copy
    cp (reflink)           macOS `cp -cR` (APFS clonefile) / Linux `cp -R --reflink=always`
    rsync -a               full copy with metadata
    git worktree add       needs a committed tree; shares the object store
    git clone --local      hardlinks objects, checks out a full working tree

The Aegis column is taken from `aegis-os bench` (EXP 3), which uses the same tree shapes.

Usage:  python3 scripts/e5_baselines.py --base DIR [--trials 7] [--json out.json]
`--base` must be on the filesystem under test (reflink needs btrfs / XFS-reflink / APFS).
"""
import argparse
import json
import os
import platform
import shutil
import statistics
import subprocess
import sys
import time

SCALES = [
    ("Small (100 files, 2 MB)", 100, 20 * 1024),
    ("Medium (300 files, 18 MB)", 300, 60 * 1024),
    ("Large (1,000 files, 80 MB)", 1000, 80 * 1024),
]


def free_bytes(path):
    st = os.statvfs(path)
    return st.f_bavail * st.f_frsize


def build_tree(root, count, fsize, with_git):
    """Deterministic tree: 20 subdirectories, unique content per file; optionally a git repo."""
    os.makedirs(root)
    for i in range(count):
        d = os.path.join(root, f"mod{i % 20}")
        os.makedirs(d, exist_ok=True)
        block = (f"file-{i}-".encode() * (fsize // 8 + 1))[:fsize]
        with open(os.path.join(d, f"f{i}.rs"), "wb") as fh:
            fh.write(block)
    if not with_git:
        return
    env = dict(os.environ, GIT_AUTHOR_NAME="e5", GIT_AUTHOR_EMAIL="e5@example.org",
               GIT_COMMITTER_NAME="e5", GIT_COMMITTER_EMAIL="e5@example.org")
    for cmd in (["git", "init", "-q"], ["git", "add", "-A"], ["git", "commit", "-q", "-m", "base"]):
        subprocess.run(cmd, cwd=root, env=env, check=True, stdout=subprocess.DEVNULL)


def methods(src, src_git):
    """`src` is a plain working tree; `src_git` is the same tree inside a git repository.

    Plain copy tools get the tree *without* `.git` so they are not charged for copying the object
    store, which Aegis OS also skips by design (`.git`, `target`, `node_modules`, ...). The git-based
    methods inherently need the repository.
    """
    mac = platform.system() == "Darwin"
    ms = {
        # Cost of merely spawning a process: the baselines below are external commands, whereas the
        # Aegis figure comes from an in-process call, so this floor must be subtracted when comparing.
        "(process spawn floor)": (src, lambda dst: ["true"]),
        "cp -R": (src, lambda dst: ["cp", "-R", src, dst]),
        # GNU cp defaults to `--reflink=auto`, i.e. plain `cp -R` already clones on btrfs/XFS. A
        # genuine full copy therefore needs `--reflink=never` on Linux (macOS `cp -R` never clones).
        "cp -R (no reflink)": (src, (lambda dst: ["cp", "-R", src, dst]) if mac
                               else (lambda dst: ["cp", "-R", "--reflink=never", src, dst])),
        "cp reflink": (src, (lambda dst: ["cp", "-cR", src, dst]) if mac
                       else (lambda dst: ["cp", "-R", "--reflink=always", src, dst])),
        "rsync -a": (src, lambda dst: ["rsync", "-a", src + "/", dst + "/"]),
        "git worktree add": (src_git, lambda dst: ["git", "-C", src_git, "worktree", "add", "-q",
                                                   "--detach", dst]),
        "git clone --local": (src_git, lambda dst: ["git", "clone", "-q", "--local", src_git, dst]),
    }
    return ms


def cleanup(src_git, dst):
    shutil.rmtree(dst, ignore_errors=True)
    subprocess.run(["git", "-C", src_git, "worktree", "prune"], stdout=subprocess.DEVNULL,
                   stderr=subprocess.DEVNULL)


def run_scale(base, name, count, fsize, trials):
    src = os.path.join(base, f"src_{count}")
    src_git = os.path.join(base, f"srcgit_{count}")
    for p in (src, src_git):
        shutil.rmtree(p, ignore_errors=True)
    build_tree(src, count, fsize, with_git=False)
    build_tree(src_git, count, fsize, with_git=True)
    os.sync()
    ms = methods(src, src_git)
    times = {k: [] for k in ms}
    disk = {k: [] for k in ms}
    failed = {}
    # Trial 0 is a warm-up (page cache, first-use costs) and is discarded. Methods are interleaved
    # within each trial so that background drift affects all of them equally.
    for t in range(trials + 1):
        for label, (_, mk) in ms.items():
            if label in failed:
                continue
            dst = os.path.join(base, f"dst_{count}")
            cleanup(src_git, dst)
            os.sync()
            before = free_bytes(base)
            t0 = time.perf_counter()
            r = subprocess.run(mk(dst), stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
            dt = (time.perf_counter() - t0) * 1000.0
            if r.returncode != 0:
                failed[label] = r.stderr.decode(errors="replace").strip()[:160]
                continue
            os.sync()
            used = before - free_bytes(base)
            if t > 0:
                times[label].append(dt)
                disk[label].append(used)
            cleanup(src_git, dst)
    for p in (src, src_git):
        shutil.rmtree(p, ignore_errors=True)
    rows = []
    for label in ms:
        if label in failed:
            rows.append({"method": label, "error": failed[label]})
            continue
        v = times[label]
        rows.append({
            "method": label,
            "mean_ms": statistics.mean(v),
            "std_ms": statistics.stdev(v) if len(v) > 1 else 0.0,
            "disk_mb": statistics.mean(disk[label]) / (1024 * 1024),
        })
    return {"scale": name, "files": count, "logical_mb": count * fsize / (1024 * 1024), "rows": rows}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--base", required=True)
    ap.add_argument("--trials", type=int, default=7)
    ap.add_argument("--json")
    a = ap.parse_args()
    os.makedirs(a.base, exist_ok=True)
    out = {"platform": platform.platform(), "machine": platform.machine(), "base": a.base,
           "trials": a.trials, "results": []}
    for name, count, fsize in SCALES:
        res = run_scale(a.base, name, count, fsize, a.trials)
        out["results"].append(res)
        print(f"\n{name}  (logical {res['logical_mb']:.0f} MB)")
        print(f"  {'method':<20} {'time (ms)':>18} {'extra disk (MB)':>16}")
        for r in res["rows"]:
            if "error" in r:
                print(f"  {r['method']:<20} FAILED: {r['error']}")
            else:
                print(f"  {r['method']:<20} {r['mean_ms']:>10.2f} +- {r['std_ms']:<5.2f} {r['disk_mb']:>14.1f}")
    if a.json:
        with open(a.json, "w") as fh:
            json.dump(out, fh, indent=2)
    return 0


if __name__ == "__main__":
    sys.exit(main())
