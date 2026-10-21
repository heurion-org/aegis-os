#!/usr/bin/env python3
"""Verify cross-machine hybrid workflow: macOS IDE/Client -> Remote Linux Aegis OS Daemon on btrfs.

Starts `aegis-os daemon` inside the Linux VM (`aegis-linux`) backed by `/mnt/btrfs` and drives
a full multi-agent transactional workflow over HTTP/JSON-RPC from the macOS host:
  1. Provision a multi-agent workspace (`coder-alpha`, `reviewer-beta`) on Linux `btrfs`.
  2. Mint scoped `ak_live_*` tenant API keys for both agents.
  3. Execute `proc_exec` from macOS inside the remote Linux `bwrap` namespace sandbox (`uname -sr`,
      plus an attempted host-mutation attack `touch /etc/pwned`).
  4. Perform concurrent non-overlapping edits to `src/lib.rs` from both agents.
  5. Trigger `workspace_commit`, approve the HITL escalation remotely from macOS, and verify
     4-Tier LCS Diff3 3-way merge + Git PR bundle export (`/v1/workspaces/pr`).
"""
import json
import subprocess
import sys
import time
import urllib.request


def http_json(url: str, method: str = "GET", body: dict = None, token: str = None) -> dict:
    data = json.dumps(body).encode("utf-8") if body is not None else None
    headers = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    with urllib.request.urlopen(req, timeout=15) as resp:
        return json.loads(resp.read().decode("utf-8"))


def mcp_call(base_url: str, token: str, tool_name: str, arguments: dict) -> dict:
    res = http_json(
        f"{base_url}/v1/mcp",
        method="POST",
        token=token,
        body={
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {"name": tool_name, "arguments": arguments},
        },
    )
    text = res["result"]["content"][0]["text"]
    try:
        return json.loads(text)
    except Exception:
        raise RuntimeError(f"MCP tool {tool_name} returned error: {text}")


def main():
    port = 17088
    base_url = f"http://127.0.0.1:{port}"
    ssh_base = ["ssh", "-F", "/Users/huizhao/.lima/aegis-linux/ssh.config", "lima-aegis-linux"]
    setup_cmd = """set -e
pkill -f "aegis-os.*17088" || true
rm -rf /mnt/btrfs/remote_hybrid_test
mkdir -p /mnt/btrfs/remote_hybrid_test/repo/src
cd /mnt/btrfs/remote_hybrid_test/repo
git init -q
git config user.email "dev@aegis.os"
git config user.name "Aegis Dev"
printf 'pub fn alpha() -> i32 { 1 }\\npub fn beta() -> i32 { 2 }\\n' > src/lib.rs
git add . && git commit -qm "init"
"""
    subprocess.run(
        [*ssh_base, "bash"],
        input=setup_cmd,
        text=True,
        check=True,
    )

    daemon_proc = subprocess.Popen(
        [
            *ssh_base,
            "-L",
            f"127.0.0.1:{port}:127.0.0.1:{port}",
            "/mnt/btrfs/aegis-os/target/release/aegis-os",
            "--runtime-dir",
            "/mnt/btrfs/remote_hybrid_test/rt",
            "--workspace",
            "/mnt/btrfs/remote_hybrid_test/repo",
            "daemon",
            "--listen",
            f"127.0.0.1:{port}",
            "--egress-listen",
            f"127.0.0.1:{port + 1}",
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )

    try:
        # Wait for Linux daemon port to become reachable on macOS host via Lima port forwarding
        for _ in range(30):
            try:
                card = http_json(f"{base_url}/.well-known/agent.json")
                break
            except Exception:
                time.sleep(0.25)
        else:
            raise RuntimeError("Timed out waiting for remote Linux daemon")

        print("[1/5] Connected from macOS to Linux Aegis OS Daemon:", card.get("name", "ok"))

        # 1. Provision multi-agent workspace on Linux btrfs
        ws = http_json(
            f"{base_url}/v1/workspaces",
            method="POST",
            body={
                "org_id": "hybrid-org",
                "workspace_id": "ws-linux-btrfs",
                "source_url": "/mnt/btrfs/remote_hybrid_test/repo",
                "branch": "main",
                "agents": ["coder-alpha", "reviewer-beta"],
            },
        )
        assert ws["status"] == "provisioned", ws
        print("[2/5] Provisioned CoW shadow workspaces on Linux btrfs:", ws.get("workspace", {}).get("workspace_id", "ws-linux-btrfs"))

        # 2. Mint scoped API keys for both agents
        key_a = http_json(
            f"{base_url}/v1/tenants/keys",
            method="POST",
            body={
                "org_id": "hybrid-org",
                "agent_id": "coder-alpha",
                "workspace_id": "ws-linux-btrfs",
                "label": "macOS IDE Alpha",
            },
        )["api_key"]
        key_b = http_json(
            f"{base_url}/v1/tenants/keys",
            method="POST",
            body={
                "org_id": "hybrid-org",
                "agent_id": "reviewer-beta",
                "workspace_id": "ws-linux-btrfs",
                "label": "macOS IDE Beta",
            },
        )["api_key"]

        # 3. Execute sandboxed command inside Linux bwrap from macOS
        exec_out = mcp_call(
            base_url,
            key_a,
            "proc_exec",
            {
                "command": "sh",
                "args": ["-c", "uname -sr && (touch /etc/pwned 2>/dev/null || echo RO_ROOT_BLOCKED)"],
            },
        )
        print(
            "[3/5] Remote proc_exec on Linux:",
            exec_out["sandbox_profile_used"],
            "->",
            exec_out["stdout"].strip().replace("\n", " | "),
        )
        assert exec_out["sandbox_profile_used"] == "linux-bwrap-namespace-enforced"
        assert "Linux" in exec_out["stdout"] and "RO_ROOT_BLOCKED" in exec_out["stdout"]

        # 4. Concurrent disjoint edits by coder-alpha and reviewer-beta
        mcp_call(
            base_url,
            key_a,
            "fs_edit",
            {
                "path": "src/lib.rs",
                "target": "pub fn alpha() -> i32 { 1 }",
                "replacement": "pub fn alpha() -> i32 { 100 }",
            },
        )
        mcp_call(
            base_url,
            key_b,
            "fs_edit",
            {
                "path": "src/lib.rs",
                "target": "pub fn beta() -> i32 { 2 }",
                "replacement": "pub fn beta() -> i32 { 200 }",
            },
        )

        # Commit coder-alpha first
        ask_a = mcp_call(base_url, key_a, "workspace_commit", {})
        assert ask_a["status"] == "approval_required"
        http_json(
            f"{base_url}/v1/approvals/decide",
            method="POST",
            body={"escalation_id": ask_a["escalation_id"], "decision": "approve", "ttl_secs": 3600},
        )
        commit_a = mcp_call(base_url, key_a, "workspace_commit", {})
        assert commit_a["status"] == "committed_to_host"

        # Commit reviewer-beta second (triggers 3-way merge on Linux btrfs and exports PR bundle)
        ask_b = mcp_call(base_url, key_b, "workspace_commit", {})
        assert ask_b["status"] == "approval_required"
        http_json(
            f"{base_url}/v1/approvals/decide",
            method="POST",
            body={"escalation_id": ask_b["escalation_id"], "decision": "approve", "ttl_secs": 3600},
        )
        pr = http_json(
            f"{base_url}/v1/workspaces/pr",
            method="POST",
            token=key_b,
            body={
                "org_id": "hybrid-org",
                "workspace_id": "ws-linux-btrfs",
                "agent_id": "reviewer-beta",
                "branch_name": "aegis/hybrid/merged",
                "commit_title": "feat: concurrent macOS->Linux btrfs 3-way merge",
            },
        )
        assert pr["status"] == "pr_bundle_exported", pr
        print("[4/5] 3-Way Merged & Exported PR on Linux btrfs, commit SHA:", pr["git_commit_sha"])
        assert "+pub fn beta() -> i32 { 200 }" in pr["unified_patch"]

        # Verify host file on Linux btrfs contains BOTH edits
        host_lib = f"{pr['host_root']}/src/lib.rs"
        merged_file = subprocess.run(
            [*ssh_base, f"cat '{host_lib}'"],
            capture_output=True,
            text=True,
            check=True,
        ).stdout
        assert "100" in merged_file and "200" in merged_file, merged_file
        print("[5/5] Verified merged file on Linux btrfs contains both concurrent edits!")

        # Measure 50 cross-OS HTTP/JSON-RPC `POST /v1/mcp` (`fs_read`) round-trips from macOS to Linux daemon
        lat_ms = []
        for _ in range(50):
            t0 = time.perf_counter()
            mcp_call(base_url, key_a, "fs_read", {"path": "src/lib.rs"})
            lat_ms.append((time.perf_counter() - t0) * 1000.0)
        lat_ms.sort()
        mean_ms = sum(lat_ms) / len(lat_ms)
        p50_ms = lat_ms[len(lat_ms) // 2]
        p99_ms = lat_ms[int(len(lat_ms) * 0.99)]
        print(f"[Latency] Cross-OS macOS->Linux `POST /v1/mcp` (`fs_read`, N=50): Mean={mean_ms:.2f} ms, P50={p50_ms:.2f} ms, P99={p99_ms:.2f} ms")
    finally:
        daemon_proc.terminate()
        try:
            daemon_proc.wait(timeout=3)
        except Exception:
            daemon_proc.kill()
        subprocess.run(
            [*ssh_base, "pkill -f 'aegis-os.*17088' || true"],
            capture_output=True,
        )

    return 0


if __name__ == "__main__":
    sys.exit(main())
