#!/usr/bin/env python3
"""
Experiment 1B: Real-World Coding-Agent Session Trace Evaluation (52 Sessions, ~28K Tool Calls)
===============================================================================================
Replays real coding-agent conversation transcripts to evaluate human approval fatigue
(Interruption Prompt Rate & Maximum Autonomous Streak) across four permission models:
  1. Ask-Every-Mutation (prompts on every file edit/write/delete, shell command, or commit)
  2. Path+Prefix Allowlist (auto-approves read-only tools, in-repo file edits, and standard
     single-command dev prefixes like cargo/git status/npm/pytest/ls, but prompts on compound
     shell pipelines `&&`/`|`/`python3 -c`, `rm`, external paths, network/VM ops, and commits)
  3. Vanilla CoW + Seatbelt (defers in-workspace file and shell mutations to the CoW shadow
     workspace; prompts at each host-visible commit/push or external boundary crossing)
  4. Aegis OS (CoW + Seatbelt + Action Lease + Pre-Commit Gate)

If local transcripts under ~/.gemini/antigravity-cli/brain/ are available and --refresh is
passed (or scripts/real_traces_anonymized.json does not exist), extracts anonymized event
sequences into scripts/real_traces_anonymized.json for reproducible artifact evaluation.
"""

import glob
import json
import os
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
ANON_DATASET_PATH = REPO_ROOT / "scripts" / "real_traces_anonymized.json"
TRANSCRIPT_GLOBS = [
    os.path.expanduser(
        "~/.gemini/antigravity-cli/brain/*/.system_generated/logs/transcript_full.jsonl"
    ),
    "/Users/huizhao/.gemini/antigravity-cli/brain/*/.system_generated/logs/transcript_full.jsonl",
]


def find_transcript_files() -> list[str]:
    for pat in TRANSCRIPT_GLOBS:
        found = sorted(glob.glob(pat))
        if found:
            return found
    return []


SAFE_SHELL_PREFIXES = (
    "cargo ",
    "rustc ",
    "git status",
    "git diff",
    "git log",
    "git branch",
    "git show",
    "ls",
    "pwd",
    "echo ",
    "cat ",
    "head ",
    "tail ",
    "wc ",
    "grep ",
    "rg ",
    "find ",
    "which ",
    "uname",
    "pytest",
    "npm test",
    "npm run",
    "node --version",
    "python3 --version",
    "pdflatex",
    "bibtex",
    "tectonic",
)

COMPOUND_OR_INTERPRETER_MARKERS = (
    "&&",
    "||",
    ";",
    "|",
    "$(",
    "`",
    "python3 -c",
    "python -c",
    "bash -c",
    "sh -c",
    " > ",
    " >> ",
)


def classify_shell_command(cmd: str) -> dict:
    c = cmd.strip()
    is_compound = any(m in c for m in COMPOUND_OR_INTERPRETER_MARKERS)
    is_rm = c.startswith("rm ") or " rm " in c or "rm -rf" in c
    is_commit_or_push = (
        "git push" in c
        or "git commit" in c
        or "gh pr " in c
        or "gh repo " in c
    )
    has_remote_curl = (
        "curl " in c
        and "localhost" not in c
        and "127.0.0.1" not in c
    )
    is_external = has_remote_curl or any(
        k in c
        for k in (
            "wget ",
            "ssh ",
            "scp ",
            "limactl ",
            "docker ",
            "sudo ",
            "brew ",
            "pip install",
            "npm install -g",
        )
    )
    starts_safe = c.startswith(SAFE_SHELL_PREFIXES)
    allowlist_ok = (
        starts_safe
        and not is_compound
        and not is_rm
        and not is_commit_or_push
        and not is_external
    )
    return {
        "kind": "shell",
        "is_compound": is_compound,
        "is_rm": is_rm,
        "is_commit_or_push": is_commit_or_push,
        "is_external": is_external,
        "allowlist_ok": allowlist_ok,
    }


def extract_anonymized_sessions() -> list:
    files = find_transcript_files()
    sessions = []
    for f in files:
        conv_id = f.split("/brain/")[1].split("/")[0][:8]
        steps = 0
        events = []
        aegis_mcp_count = 0
        with open(f, "r", errors="ignore") as fp:
            for line in fp:
                steps += 1
                try:
                    obj = json.loads(line)
                    for tc in obj.get("tool_calls", []):
                        name = tc.get("name", "")
                        args = tc.get("args", {})
                        if name == "call_mcp_tool" and args.get("ServerName") == "aegis-os":
                            aegis_mcp_count += 1
                            tname = args.get("ToolName", "")
                            targs = args.get("Arguments", {})
                            if tname == "proc_exec":
                                cmd = str(targs.get("command", "")) + " " + " ".join(
                                    str(x) for x in targs.get("args", [])
                                )
                                ev = classify_shell_command(cmd)
                                ev["aegis_tool"] = "proc_exec"
                                events.append(ev)
                            elif tname in ("fs_write", "fs_edit", "fs_delete"):
                                events.append(
                                    {
                                        "kind": "file_mutation",
                                        "is_delete": tname == "fs_delete",
                                        "is_external": False,
                                        "aegis_tool": tname,
                                    }
                                )
                            elif tname == "workspace_commit":
                                events.append(
                                    {
                                        "kind": "workspace_commit",
                                        "aegis_tool": "workspace_commit",
                                    }
                                )
                            elif tname == "egress_http_request":
                                events.append(
                                    {
                                        "kind": "egress_http",
                                        "aegis_tool": "egress_http_request",
                                    }
                                )
                            elif tname == "policy_approve_escalation":
                                events.append(
                                    {
                                        "kind": "escalation_approval",
                                        "aegis_tool": "policy_approve_escalation",
                                    }
                                )
                            else:
                                events.append(
                                    {
                                        "kind": "read_or_coord",
                                        "aegis_tool": tname,
                                    }
                                )
                        elif name == "run_command":
                            cmd = str(args.get("CommandLine", ""))
                            ev = classify_shell_command(cmd)
                            events.append(ev)
                        elif name in ("replace_file_content", "write_to_file", "edit_file", "write_file"):
                            path = str(args.get("TargetFile", args.get("Path", "")))
                            is_ext = path.startswith("/etc") or path.startswith("/usr")
                            events.append(
                                {
                                    "kind": "file_mutation",
                                    "is_delete": False,
                                    "is_external": is_ext,
                                }
                            )
                        else:
                            events.append({"kind": "read_or_coord"})
                except Exception:
                    pass
        if len(events) >= 10:
            sessions.append(
                {
                    "session_id": conv_id,
                    "steps": steps,
                    "total_tools": len(events),
                    "aegis_mcp_calls": aegis_mcp_count,
                    "events": events,
                }
            )
    return sessions


def evaluate_policy_on_events(events: list, policy: str) -> tuple[int, int]:
    """
    Returns (prompts, max_autonomous_streak) for a single session's event list.
    """
    prompts = 0
    current_streak = 0
    max_streak = 0
    commit_lease_remaining = 0
    ext_lease_remaining = 0

    has_explicit_commit = any(e.get("kind") == "workspace_commit" for e in events)
    mutations_since_commit = 0

    for ev in events:
        kind = ev.get("kind", "read_or_coord")
        prompted = False

        if policy == "ask_every_mutation":
            if kind in ("shell", "file_mutation", "workspace_commit", "egress_http"):
                prompted = True

        elif policy == "path_prefix_allowlist":
            if kind == "file_mutation":
                if ev.get("is_delete") or ev.get("is_external"):
                    prompted = True
            elif kind == "shell":
                if not ev.get("allowlist_ok", False):
                    prompted = True
            elif kind in ("workspace_commit", "egress_http"):
                prompted = True

        elif policy in ("vanilla_cow_seatbelt", "aegis_os_lease"):
            if kind == "read_or_coord":
                prompted = False
            elif kind == "file_mutation":
                if ev.get("is_external"):
                    prompted = True
                else:
                    mutations_since_commit += 1
            elif kind == "shell":
                if has_explicit_commit and ev.get("aegis_tool") != "proc_exec":
                    # In live Aegis OS sessions, host-level run_command calls are already
                    # gated by explicit policy_approve_escalation events in the transcript.
                    prompted = False
                elif ev.get("is_commit_or_push"):
                    if policy == "aegis_os_lease":
                        if commit_lease_remaining > 0:
                            commit_lease_remaining -= 1
                        else:
                            prompted = True
                            commit_lease_remaining = 4
                    else:
                        prompted = True
                elif ev.get("is_external"):
                    if policy == "aegis_os_lease":
                        if ext_lease_remaining > 0:
                            ext_lease_remaining -= 1
                        else:
                            prompted = True
                            ext_lease_remaining = 4
                    else:
                        prompted = True
                else:
                    mutations_since_commit += 1
            elif kind == "workspace_commit":
                if policy == "aegis_os_lease":
                    if commit_lease_remaining > 0:
                        commit_lease_remaining -= 1
                    else:
                        prompted = True
                        commit_lease_remaining = 4
                else:
                    prompted = True
                mutations_since_commit = 0
            elif kind == "escalation_approval":
                prompted = True

            if not has_explicit_commit and mutations_since_commit >= 25:
                mutations_since_commit = 0
                if policy == "aegis_os_lease":
                    if commit_lease_remaining > 0:
                        commit_lease_remaining -= 1
                    else:
                        prompted = True
                        commit_lease_remaining = 4
                else:
                    prompted = True

        if prompted:
            prompts += 1
            if current_streak > max_streak:
                max_streak = current_streak
            current_streak = 0
        else:
            current_streak += 1

    if current_streak > max_streak:
        max_streak = current_streak
    return prompts, max_streak


def summarize_corpus(name: str, sessions: list):
    total_sessions = len(sessions)
    total_steps = sum(s["steps"] for s in sessions)
    total_tools = sum(s["total_tools"] for s in sessions)

    shell_count = 0
    compound_count = 0
    rm_count = 0
    mut_count = 0
    read_count = 0
    for s in sessions:
        for ev in s["events"]:
            k = ev["kind"]
            if k == "shell":
                shell_count += 1
                if ev.get("is_compound"):
                    compound_count += 1
                if ev.get("is_rm"):
                    rm_count += 1
            elif k == "file_mutation":
                mut_count += 1
            elif k == "read_or_coord":
                read_count += 1

    print(f"\n=== {name} ===")
    print(
        f"Sessions: {total_sessions} | Conversation Steps: {total_steps:,} | Total Tool Calls: {total_tools:,}"
    )
    print(
        f"Breakdown: Read/Coord={read_count:,}, Shell={shell_count:,} "
        f"(Compound/Inline-Script={compound_count:,} [{compound_count / max(1, shell_count) * 100:.1f}%], rm={rm_count:,}), "
        f"FileEdit/Write={mut_count:,}"
    )
    print(
        f"{'Policy Model':<28} | {'Total Prompts':>13} | {'Aggregate IPR':>13} | {'Mean Session MAS':>16} | {'Prompt Reduction':>16}"
    )
    print("-" * 98)

    baseline_prompts = None
    for pol_key, pol_label in [
        ("ask_every_mutation", "Ask-Every-Mutation"),
        ("path_prefix_allowlist", "Path+Prefix Allowlist"),
        ("vanilla_cow_seatbelt", "Vanilla CoW + Seatbelt"),
        ("aegis_os_lease", "Aegis OS (CoW + Lease)"),
    ]:
        tot_p = 0
        mas_list = []
        for s in sessions:
            p, mas = evaluate_policy_on_events(s["events"], pol_key)
            tot_p += p
            mas_list.append(mas)
        if baseline_prompts is None:
            baseline_prompts = tot_p
        ipr = (tot_p / total_tools) * 100.0
        mean_mas = sum(mas_list) / len(mas_list)
        red = (1.0 - (tot_p / max(1, baseline_prompts))) * 100.0
        print(
            f"{pol_label:<28} | {tot_p:>13,} | {ipr:>12.2f}% | {mean_mas:>16.1f} | {red:>15.1f}%"
        )


def encode_event(ev: dict) -> str:
    # Compact deterministic encoding: "<kind>:<flags>"
    k = ev.get("kind", "read_or_coord")
    flags = []
    if ev.get("is_compound"):
        flags.append("c")
    if ev.get("is_rm"):
        flags.append("r")
    if ev.get("is_commit_or_push"):
        flags.append("p")
    if ev.get("is_external"):
        flags.append("e")
    if ev.get("allowlist_ok"):
        flags.append("a")
    if ev.get("is_delete"):
        flags.append("d")
    if ev.get("aegis_tool") == "proc_exec":
        flags.append("x")
    return f"{k[0]}:{''.join(flags)}"


def decode_event(code: str | dict) -> dict:
    if isinstance(code, dict):
        return code
    k_char, flags = code.split(":", 1)
    kind_map = {
        "r": "read_or_coord",
        "s": "shell",
        "f": "file_mutation",
        "w": "workspace_commit",
        "e": "escalation_approval",
        "g": "egress_http",
    }
    return {
        "kind": kind_map.get(k_char, "read_or_coord"),
        "is_compound": "c" in flags,
        "is_rm": "r" in flags,
        "is_commit_or_push": "p" in flags,
        "is_external": "e" in flags,
        "allowlist_ok": "a" in flags,
        "is_delete": "d" in flags,
        "aegis_tool": "proc_exec" if "x" in flags else "",
    }


def main():
    refresh = "--refresh" in sys.argv or not ANON_DATASET_PATH.exists()
    if refresh and find_transcript_files():
        raw_sessions = extract_anonymized_sessions()
        compact_sessions = []
        for s in raw_sessions:
            compact_sessions.append(
                {
                    "session_id": s["session_id"],
                    "steps": s["steps"],
                    "total_tools": s["total_tools"],
                    "aegis_mcp_calls": s["aegis_mcp_calls"],
                    "events": [encode_event(e) for e in s["events"]],
                }
            )
        with open(ANON_DATASET_PATH, "w") as fp:
            json.dump({"sessions": compact_sessions}, fp, separators=(",", ":"))
        print(
            f"Saved anonymized trace dataset ({len(compact_sessions)} sessions) to {ANON_DATASET_PATH}"
        )
    else:
        with open(ANON_DATASET_PATH, "r") as fp:
            compact_sessions = json.load(fp)["sessions"]
        print(
            f"Loaded anonymized trace dataset ({len(compact_sessions)} sessions) from {ANON_DATASET_PATH}"
        )

    sessions = []
    for s in compact_sessions:
        s_copy = dict(s)
        s_copy["events"] = [decode_event(e) for e in s["events"]]
        sessions.append(s_copy)

    summarize_corpus("Corpus A: All Real Coding-Agent Sessions (N=52)", sessions)
    aegis_sessions = [s for s in sessions if s.get("aegis_mcp_calls", 0) >= 10]
    summarize_corpus(
        f"Corpus B: Live Aegis OS Dogfooding Sessions (N={len(aegis_sessions)})",
        aegis_sessions,
    )


if __name__ == "__main__":
    main()
