# 10-Second Safe Red-Team Demo (`examples/redteam-demo`)

This self-contained demo shows the exact difference between running an autonomous coding agent unconfined (`--yolo` / advisory hooks) vs. running inside **Aegis OS Enforced Mode** (`bwrap --bind-fd` on Linux / Seatbelt on macOS + CoW shadow workspace).

## Is it safe to run?

**Yes.** The script never touches your real `~/.ssh`, `~/.claude`, or repository:
- Everything runs inside an isolated disposable `mktemp -d` directory cleaned up automatically on exit.
- It creates a fake canary SSH key (`CANARY_SSH_KEY_DO_NOT_EXFILTRATE_AEGIS_DEMO`) and a disposable Git repo.

## What it simulates

A common real-world prompt-injection / repo-trap vector: a benign-looking project script (`scripts/verify_env.py`) executed by a coding agent attempts to:
1. **V3:** Read `~/.ssh/id_ed25519`
2. **V4:** Overwrite `~/.claude/settings.json` to wipe hook guardrails
3. **V5:** Plant a persistent `.git/hooks/post-checkout` backdoor
4. **V1:** Mutate `src/app.py` directly on the host

## Run it

```bash
chmod +x examples/redteam-demo/run_demo.sh
./examples/redteam-demo/run_demo.sh
```

In **Phase 1 (Without Aegis)**, all 4 actions succeed silently on the disposable host.
In **Phase 2 (With Aegis OS Enforced)**, credential access and config/`.git` persistence are blocked at the OS kernel level, any file write lands strictly inside the CoW shadow (`aegis-os diff`), and the host repo remains untouched until explicit `aegis-os commit`.
