#!/usr/bin/env python3
"""Feasibility probe for an overlayfs-based shadow workspace (Linux).

Measures, on the filesystem under test and for two project shapes, the cost of each step a session
start could consist of:

  init(current)   `aegis-os workspace status`  = real session start today (3 full-tree clones)
  1 clone         cp -R (reflink where the fs supports it): the cost of a frozen lower/baseline
  stat manifest   one lstat per file (path, size, mtime): a metadata-only baseline fingerprint
  overlay mount   unprivileged overlayfs mount in a user namespace
"""
import os, shutil, statistics, subprocess, sys, time, tempfile
sys.path.insert(0, "/tmp")
import e5_baselines as e

BIN = sys.argv[1]
BASE = sys.argv[2]
SHAPES = [("1,000 files x 80 KiB", 1000, 80 * 1024), ("10,000 files x 8 KiB", 10000, 8 * 1024)]


def timed(fn, trials=5):
    v = []
    for _ in range(trials):
        t0 = time.perf_counter()
        fn()
        v.append((time.perf_counter() - t0) * 1000)
    return statistics.mean(v), min(v)


def manifest(root):
    out = {}
    stack = [root]
    while stack:
        d = stack.pop()
        with os.scandir(d) as it:
            for ent in it:
                if ent.is_dir(follow_symlinks=False):
                    stack.append(ent.path)
                else:
                    st = ent.stat(follow_symlinks=False)
                    out[ent.path] = (st.st_size, st.st_mtime_ns)
    return out


for label, n, size in SHAPES:
    work = os.path.join(BASE, f"probe_{n}")
    shutil.rmtree(work, ignore_errors=True)
    src = os.path.join(work, "proj")
    e.build_tree(src, n, size, with_git=False)
    os.sync()
    # Real projects are older than the session that opens them; the clone fast path (rightly) does
    # not trust files modified within the last 2 s, so let the synthetic tree age past that.
    time.sleep(2.5)
    res = {}

    def status(rt):
        subprocess.run([BIN, "--workspace", src, "--runtime-dir", rt, "--org", "p", "--agent", "a",
                        "workspace", "status"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                       check=True)

    # The first `workspace status` initialises the session (3 clones) AND computes a diff; a second
    # call on the initialised session costs only the diff. Their difference is the init alone.
    first, second = [], []
    for _ in range(5):
        rt = tempfile.mkdtemp(prefix="rt_", dir=work)
        t0 = time.perf_counter(); status(rt); first.append((time.perf_counter() - t0) * 1000)
        t0 = time.perf_counter(); status(rt); second.append((time.perf_counter() - t0) * 1000)
        shutil.rmtree(rt, ignore_errors=True)
    res["status, 1st call (init+diff)"] = (statistics.mean(first), min(first))
    res["status, 2nd call (diff only)"] = (statistics.mean(second), min(second))
    res["=> init alone (3 clones)"] = (statistics.mean(first) - statistics.mean(second),
                                       min(first) - min(second))

    def clone_once():
        d = os.path.join(work, "clone")
        shutil.rmtree(d, ignore_errors=True)
        subprocess.run(["cp", "-R", src, d], check=True)
    res["1 clone (cp -R)"] = timed(clone_once)
    shutil.rmtree(os.path.join(work, "clone"), ignore_errors=True)

    res["stat manifest"] = timed(lambda: manifest(src))

    up, wk, mnt = (os.path.join(work, x) for x in ("up", "wk", "mnt"))
    for d in (up, wk, mnt):
        os.makedirs(d, exist_ok=True)
    ov = lambda: subprocess.run(
        ["unshare", "-Urm", "sh", "-c",
         f"mount -t overlay overlay -o lowerdir={src},upperdir={up},workdir={wk} {mnt}"],
        check=True, stderr=subprocess.DEVNULL)
    try:
        res["overlay mount"] = timed(ov)
    except Exception as ex:
        res["overlay mount"] = (float("nan"), float("nan"))

    print(f"\n{label}")
    for k, (m, mn) in res.items():
        print(f"  {k:<26} {m:9.1f} ms  (min {mn:.1f})")
    shutil.rmtree(work, ignore_errors=True)
