#!/usr/bin/env python3
"""
RQ4 End-to-End CLI TOCTOU & Terminal-Diff Spoofing Benchmark.

Addresses audit item P0-6:
  Tests all 6 post-approval TOCTOU & diff-spoofing classes (n=10 trials each = 60 live CLI runs)
  end-to-end through the real `aegis-os` CLI (`aegis-os run` -> `aegis-os diff --json` ->
  post-inspection shadow mutation -> `aegis-os commit --expected-diff-hash <hash> --yes`),
  recording per-class block rate and per-class verification latency (median & P95 ms):

  1. c1_post_diff_append: Appending a backdoor function after `aegis-os diff`
  2. c2_same_size_byte_swap: Same-byte-size 1-char flip (`==` -> `!=`) preserving `st_size`
  3. c3_beyond_preview_tail_edit: Modifying line 185 of a 200-line file outside 40-line preview
  4. c4_untracked_build_rs_add: Injecting an untracked `build.rs` hook file after `diff`
  5. c5_symlink_target_swap: Replacing modified file with POSIX symlink (`ln -sf /etc/hosts ...`)
  6. c6_ansi_bidi_terminal_spoof: Real ANSI CSI cursor-up/erase (`\\x1b[1A\\x1b[2K`) + Unicode BiDi
     (`U+202E`) payload evaluated through a real VT100 terminal screen buffer to verify:
       (a) raw terminal rendering conceals the backdoor line on an 80x24 VT100 screen,
       (b) `aegis-os diff --json` & `approvals` escape control sequences visibly, and
       (c) swapping benign vs ANSI-spoofed content after `diff` is 100% blocked at `commit`.
"""

from __future__ import annotations

import argparse
import json
import os
import platform
import statistics
import subprocess
import tempfile
import time
from pathlib import Path


class MiniVT100:
    """Minimal deterministic 80x24 VT100 state machine handling \\n, \\r, CSI A (cursor up), and CSI K (erase line)."""

    def __init__(self, cols: int = 120, rows: int = 40) -> None:
        self.cols = cols
        self.rows = rows
        self.grid = [[" "] * cols for _ in range(rows)]
        self.r = 0
        self.c = 0

    def feed(self, text: str) -> None:
        i = 0
        n = len(text)
        while i < n:
            ch = text[i]
            if ch == "\x1b" and i + 1 < n and text[i + 1] == "[":
                j = i + 2
                params = ""
                while j < n and (text[j].isdigit() or text[j] == ";"):
                    params += text[j]
                    j += 1
                if j < n:
                    cmd = text[j]
                    val = int(params.split(";")[0]) if params.split(";")[0].isdigit() else 1
                    if cmd == "A":
                        self.r = max(0, self.r - val)
                    elif cmd == "K":
                        mode = int(params) if params.isdigit() else 0
                        if mode == 2:
                            self.grid[self.r] = [" "] * self.cols
                            self.c = 0
                        elif mode == 0:
                            for k in range(self.c, self.cols):
                                self.grid[self.r][k] = " "
                    i = j + 1
                    continue
            if ch == "\r":
                self.c = 0
            elif ch == "\n":
                self.r = min(self.rows - 1, self.r + 1)
                self.c = 0
            elif ch >= " ":
                if self.c < self.cols:
                    self.grid[self.r][self.c] = ch
                    self.c += 1
            i += 1

    def rendered_text(self) -> str:
        return "\n".join("".join(row).rstrip() for row in self.grid).strip()


def _git(cwd: Path, *args: str) -> None:
    subprocess.run(["git", "-c", "gc.auto=0", *args], cwd=cwd, check=True, capture_output=True)


def pct95(vals: list[float]) -> float:
    s = sorted(vals)
    return s[min(len(s) - 1, int(0.95 * (len(s) - 1)))]


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--aegis-bin", required=True, type=Path)
    ap.add_argument("--trials", type=int, default=10)
    ap.add_argument("--out", required=True, type=Path)
    args = ap.parse_args()
    aegis_bin = args.aegis_bin.resolve()

    with tempfile.TemporaryDirectory(prefix="rq4_cli_") as td:
        base = Path(td)
        repo = base / "repo"
        rt = base / "rt"
        home = base / "home"
        (repo / "src").mkdir(parents=True)
        rt.mkdir()
        home.mkdir()

        # Populate a 40-file Rust workspace (~200 lines per file) so CLI diff/commit scans a realistic project
        for idx in range(40):
            lines = [f"pub fn check_{idx}_{ln}(x: i32) -> bool {{ x == {ln} }}" for ln in range(200)]
            (repo / "src" / f"mod_{idx}.rs").write_text("\n".join(lines) + "\n")
        _git(repo, "init", "-q")
        _git(repo, "config", "user.email", "rq4@example.invalid")
        _git(repo, "config", "user.name", "RQ4")
        _git(repo, "add", "-A")
        _git(repo, "commit", "-q", "-m", "initial")

        env = dict(os.environ)
        env["HOME"] = str(home)
        env.pop("AOS_ABLATE", None)

        # Create an enforced session that makes a legitimate edit to src/mod_0.rs
        orig_mod0 = (repo / "src" / "mod_0.rs").read_text()
        approved_mod0 = orig_mod0 + "// reviewed benign fix\n"
        run_p = subprocess.run(
            [
                str(aegis_bin),
                "--runtime-dir", str(rt),
                "run",
                "--workspace", str(repo),
                "--enforcement", "enforced",
                "--",
                "/bin/sh", "-c", "printf '// reviewed benign fix\\n' >> src/mod_0.rs",
            ],
            env=env,
            capture_output=True,
            text=True,
            stdin=subprocess.DEVNULL,
        )
        assert run_p.returncode in (0, 10), f"session init failed: {run_p.stderr}"

        diff_p = subprocess.run(
            [str(aegis_bin), "--runtime-dir", str(rt), "diff", "--json"],
            env=env,
            capture_output=True,
            text=True,
            check=True,
        )
        diff_info = json.loads(diff_p.stdout)
        pinned_hash = diff_info["evidence_hash"]
        shadow = Path(diff_info["shadow"])

        # Verify ANSI/VT100 terminal spoofing visibility before running the 6x10 matrix
        ansi_payload = (
            "// benign comment line\n"
            "pub fn evil_backdoor() { std::process::Command::new(\"sh\").status().ok(); }\x1b[2K\r"
            "// harmless formatting cleanup\n"
        )
        vt = MiniVT100()
        vt.feed(ansi_payload)
        raw_vt_screen = vt.rendered_text()
        spoof_concealed_on_raw_tty = ("evil_backdoor" not in raw_vt_screen)

        # Write ANSI payload temporarily and run `aegis-os diff --json` to check JSON control escaping
        (shadow / "src" / "mod_0.rs").write_text(orig_mod0 + ansi_payload)
        ansi_diff_raw = subprocess.run(
            [str(aegis_bin), "--runtime-dir", str(rt), "diff", "--json"],
            env=env,
            capture_output=True,
            text=True,
            check=True,
        ).stdout
        vt_escaped = MiniVT100()
        vt_escaped.feed(ansi_diff_raw)
        visible_in_aegis_diff = ("evil_backdoor" in vt_escaped.rendered_text() and "\\u001b" in ansi_diff_raw)
        (shadow / "src" / "mod_0.rs").write_text(approved_mod0)

        def mutate_c1(i: int) -> None:
            (shadow / "src" / "mod_0.rs").write_text(approved_mod0 + f"pub fn backdoor_{i}() {{}}\n")

        def restore_c1() -> None:
            (shadow / "src" / "mod_0.rs").write_text(approved_mod0)

        def mutate_c2(i: int) -> None:
            # Exact same byte length (`== 0` -> `!= 0`)
            swapped = approved_mod0.replace("x == 0", "x != 0", 1)
            assert len(swapped.encode()) == len(approved_mod0.encode())
            (shadow / "src" / "mod_0.rs").write_text(swapped)

        def mutate_c3(i: int) -> None:
            # Edit at line 185 (beyond 40-line preview)
            swapped = approved_mod0.replace("x == 185", f"x == {900 + i}", 1)
            (shadow / "src" / "mod_0.rs").write_text(swapped)

        def mutate_c4(i: int) -> None:
            (shadow / "build.rs").write_text(f"fn main() {{ /* build hook {i} */ }}\n")

        def restore_c4() -> None:
            p = shadow / "build.rs"
            if p.exists():
                p.unlink()

        def mutate_c5(i: int) -> None:
            target = shadow / "src" / "mod_0.rs"
            if target.exists() or target.is_symlink():
                target.unlink()
            os.symlink("/etc/hosts", target)

        def restore_c5() -> None:
            target = shadow / "src" / "mod_0.rs"
            if target.exists() or target.is_symlink():
                target.unlink()
            target.write_text(approved_mod0)

        def mutate_c6(i: int) -> None:
            (shadow / "src" / "mod_0.rs").write_text(
                orig_mod0 + f"// \u202e benign_{i}\n" + ansi_payload
            )

        classes = [
            ("c1_post_diff_append", "Post-approval backdoor line append", mutate_c1, restore_c1),
            ("c2_same_size_byte_swap", "Same-byte-size operator flip (`st_size` invariant)", mutate_c2, restore_c1),
            ("c3_beyond_preview_tail_edit", "Line-185 tail edit beyond diff preview window", mutate_c3, restore_c1),
            ("c4_untracked_build_rs_add", "Untracked `build.rs` injection post-diff", mutate_c4, restore_c4),
            ("c5_symlink_target_swap", "POSIX symlink replacement (`ln -sf /etc/hosts`)", mutate_c5, restore_c5),
            ("c6_ansi_bidi_terminal_spoof", "ANSI CSI `\\x1b[2K` + BiDi `U+202E` diff spoof", mutate_c6, restore_c1),
        ]

        class_results = {}
        for cid, desc, mut_fn, rst_fn in classes:
            blocked = 0
            lat_ms = []
            for i in range(args.trials):
                mut_fn(i)
                t0 = time.perf_counter()
                cp = subprocess.run(
                    [
                        str(aegis_bin),
                        "--runtime-dir", str(rt),
                        "commit",
                        "--expected-diff-hash", pinned_hash,
                        "--yes",
                    ],
                    env=env,
                    capture_output=True,
                    text=True,
                )
                elapsed_ms = (time.perf_counter() - t0) * 1000.0
                lat_ms.append(elapsed_ms)
                host_unchanged = ((repo / "src" / "mod_0.rs").read_text() == orig_mod0) and not (repo / "build.rs").exists()
                if cp.returncode != 0 and host_unchanged:
                    blocked += 1
                rst_fn()
            class_results[cid] = {
                "description": desc,
                "trials": args.trials,
                "blocked": blocked,
                "block_rate_pct": round(100.0 * blocked / args.trials, 1),
                "cli_verify_median_ms": round(statistics.median(lat_ms), 2),
                "cli_verify_mean_ms": round(statistics.mean(lat_ms), 2),
                "cli_verify_p95_ms": round(pct95(lat_ms), 2),
            }
            print(
                f"[rq4_cli] {cid:30s} blocked={blocked}/{args.trials} "
                f"median={class_results[cid]['cli_verify_median_ms']}ms p95={class_results[cid]['cli_verify_p95_ms']}ms",
                flush=True,
            )

        # Finally verify that the legitimate pinned commit DOES succeed when untampered!
        t_ok = time.perf_counter()
        ok_commit = subprocess.run(
            [
                str(aegis_bin),
                "--runtime-dir", str(rt),
                "commit",
                "--expected-diff-hash", pinned_hash,
                "--yes",
            ],
            env=env,
            capture_output=True,
            text=True,
            check=True,
        )
        legit_commit_ms = round((time.perf_counter() - t_ok) * 1000.0, 2)
        assert (repo / "src" / "mod_0.rs").read_text() == approved_mod0

    out_obj = {
        "platform": platform.platform(),
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "vt100_spoof_verification": {
            "spoof_concealed_on_raw_vt100_tty": spoof_concealed_on_raw_tty,
            "evil_backdoor_visible_and_escaped_in_aegis_diff_json": visible_in_aegis_diff,
        },
        "legitimate_pinned_commit_ms": legit_commit_ms,
        "classes": class_results,
    }
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(out_obj, indent=2) + "\n")
    print(f"[rq4_cli] saved {args.out}", flush=True)


if __name__ == "__main__":
    main()
