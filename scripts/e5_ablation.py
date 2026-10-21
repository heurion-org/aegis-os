#!/usr/bin/env python3
"""E5b: component ablation matrix for Aegis OS.

Runs `aegis-os bench` once per ablated component and tabulates, for every red-team category, how
many of the 10 attacks compromise the system when that single component is switched off.

The binary MUST be built with `--features ablation`; without it `AOS_ABLATE` is ignored, which this
script detects (the `none` row must equal the row of every ablation that has no effect).

    cargo build --release -p aos-cli --features ablation
    python3 scripts/e5_ablation.py --bin target/release/aegis-os [extra bench args...]

Each run uses a scratch working directory, so repeated invocations do not clobber one another.
"""
import argparse
import os
import re
import subprocess
import sys
import tempfile

ABLATIONS = [
    ("none", "full system (control)"),
    ("kernel_sandbox", "no OS kernel sandbox (Seatbelt / bwrap)"),
    ("commit_guard", "no commit-time poisoning guard"),
    ("tenant_gate", "no cross-tenant policy gate"),
    ("secret_binding", "no per-secret domain binding"),
    ("merge", "no 3-way merge (last writer wins)"),
    ("prevalidate", "no Phase-1 pre-validation (non-atomic commit)"),
]
ROW = re.compile(r"^\s*•\s+([A-H])\.\s.*Aegis-OS Compromised:\s*(\d+)/10")
FEATURES = re.compile(r"Aegis-OS:\s*(\d)/3")


def run(binary, ablate, extra):
    env = dict(os.environ)
    if ablate == "none":
        env.pop("AOS_ABLATE", None)
    else:
        env["AOS_ABLATE"] = ablate
    with tempfile.TemporaryDirectory(prefix="aos_abl_") as cwd:
        out = subprocess.run(
            [binary, "bench", "--report-out", os.path.join(cwd, "r.md"), *extra],
            cwd=cwd, env=env, capture_output=True, text=True, timeout=900,
        ).stdout
    counts, feats = {}, None
    for line in out.splitlines():
        m = ROW.match(line)
        if m:
            counts[m.group(1)] = int(m.group(2))
        f = FEATURES.search(line)
        if f and "Agent Features Preserved" in line:
            feats = int(f.group(1))
    return counts, feats


def main():
    ap = argparse.ArgumentParser(
        description="Unrecognised arguments (e.g. --runtime-dir DIR) are passed through to `aegis-os bench`."
    )
    ap.add_argument("--bin", required=True)
    a, extra = ap.parse_known_args()
    a.extra = extra

    cats = "ABCDEFGH"
    print(f"{'ablated component':<18} " + " ".join(f"{c:>3}" for c in cats) + "  merge  description")
    print(f"{'':<18} " + " ".join(f"{'/10':>3}" for _ in cats) + "   /3")
    for name, desc in ABLATIONS:
        counts, feats = run(a.bin, name, a.extra)
        cells = " ".join(f"{counts.get(c, '?'):>3}" for c in cats)
        print(f"{name:<18} {cells}  {('?' if feats is None else feats):>5}  {desc}", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
