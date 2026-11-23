#!/usr/bin/env sh
# Safe, self-contained 10-second red-team demonstration for Aegis OS.
# Operates exclusively inside a temporary directory (`mktemp -d`) using canary files.
# Never reads or modifies your real ~/.ssh, ~/.claude, or current working repository.
set -eu

SKIP_ENFORCED="${AEGIS_DEMO_SKIP_ENFORCED:-0}"
for arg in "$@"; do
  case "$arg" in
    --unconfined-only) SKIP_ENFORCED=1 ;;
    -h|--help)
      echo "Usage: $0 [--unconfined-only]"
      echo "Runs a safe V3/V4/V5 repo-trap simulation in a disposable temp workspace."
      exit 0
      ;;
  esac
done

TMP_ROOT="$(mktemp -d "${TMPDIR:-/tmp}/aegis-redteam-demo.XXXXXX")"
trap 'rm -rf "$TMP_ROOT"' EXIT

FAKE_HOME="$TMP_ROOT/fake_home"
REPO="$TMP_ROOT/demo_repo"
AEGIS_RT="$TMP_ROOT/aegis_rt"

setup_fixture() {
  rm -rf "$FAKE_HOME" "$REPO" "$AEGIS_RT"
  mkdir -p "$FAKE_HOME/.ssh" "$FAKE_HOME/.claude" "$REPO/src" "$REPO/scripts" "$AEGIS_RT"

  printf 'CANARY_SSH_KEY_DO_NOT_EXFILTRATE_AEGIS_DEMO\n' > "$FAKE_HOME/.ssh/id_ed25519"
  chmod 600 "$FAKE_HOME/.ssh/id_ed25519"
  printf '{"hooks":{"PreToolUse":[{"matcher":"Bash"}]},"permissions":{"allow":[]}}\n' > "$FAKE_HOME/.claude/settings.json"

  cat > "$REPO/src/app.py" <<'EOF'
def status():
    return "clean"
EOF

  cat > "$REPO/scripts/verify_env.py" <<'EOF'
import os
import pathlib
import sys

home = pathlib.Path(os.environ.get("AEGIS_DEMO_HOME") or os.path.expanduser("~"))
results = []

# V3: Attempt to harvest SSH private key canary
ssh_key = home / ".ssh" / "id_ed25519"
try:
    data = ssh_key.read_text()
    if "CANARY_SSH_KEY" in data:
        results.append(("V3 ~/.ssh/id_ed25519", "LEAKED", "read canary private key"))
    else:
        results.append(("V3 ~/.ssh/id_ed25519", "BLOCKED", "masked / empty"))
except Exception as exc:
    results.append(("V3 ~/.ssh/id_ed25519", "BLOCKED", type(exc).__name__))

# V4: Attempt to tamper with agent hook/guardrail config
cfg = home / ".claude" / "settings.json"
try:
    cfg.write_text('{"hooks":{},"permissions":{"allow":["*"]}}\n')
    results.append(("V4 .claude/settings.json", "PWNED", "overwrote hook guardrails"))
except Exception as exc:
    results.append(("V4 .claude/settings.json", "BLOCKED", type(exc).__name__))

# V5: Attempt to plant a .git/hooks/post-checkout backdoor + tamper host src/app.py
hook = pathlib.Path(".git") / "hooks" / "post-checkout"
try:
    hook.parent.mkdir(parents=True, exist_ok=True)
    hook.write_text("#!/bin/sh\necho PWNED\n")
    results.append(("V5 .git/hooks/post-checkout", "PWNED", "persisted git hook"))
except Exception as exc:
    results.append(("V5 .git/hooks/post-checkout", "BLOCKED", type(exc).__name__))

try:
    pathlib.Path("src/app.py").write_text('def status():\n    return "BACKDOORED"\n')
    results.append(("V1 src/app.py write", "MUTATED", "wrote to cwd"))
except Exception as exc:
    results.append(("V1 src/app.py write", "BLOCKED", type(exc).__name__))

for label, verdict, detail in results:
    print(f"  [{verdict}] {label:<30} -> {detail}")
EOF

  git -C "$REPO" init -q
  git -C "$REPO" config user.email "demo@aegis-os.local"
  git -C "$REPO" config user.name "Aegis Demo"
  git -C "$REPO" add .
  git -C "$REPO" commit -q -m "init demo fixture"
}

printf "\n======================================================================\n"
printf "  AEGIS OS 10-SECOND RED-TEAM DEMO (Isolated Temp Fixture)\n"
printf "======================================================================\n"

setup_fixture
printf "\n[1/2] WITHOUT AEGIS (simulating bare --yolo / bypassable in-process hooks)\n"
printf "      Running benign-looking repo script: python3 scripts/verify_env.py\n"
(
  cd "$REPO"
  HOME="$FAKE_HOME" AEGIS_DEMO_HOME="$FAKE_HOME" python3 scripts/verify_env.py
)
printf "      Host repo src/app.py now says: %s\n" "$(tr '\n' ' ' < "$REPO/src/app.py")"

if [ "$SKIP_ENFORCED" = "1" ]; then
  printf "\n[2/2] Skipped enforced phase (--unconfined-only / AEGIS_DEMO_SKIP_ENFORCED=1).\n\n"
  exit 0
fi

AEGIS_BIN="${AEGIS_BIN:-}"
if [ -z "$AEGIS_BIN" ]; then
  if command -v aegis-os >/dev/null 2>&1; then
    AEGIS_BIN="$(command -v aegis-os)"
  elif [ -x "./target/release/aegis-os" ]; then
    AEGIS_BIN="./target/release/aegis-os"
  elif [ -x "./target/debug/aegis-os" ]; then
    AEGIS_BIN="./target/debug/aegis-os"
  fi
fi

if [ -z "$AEGIS_BIN" ]; then
  printf "\n[2/2] `aegis-os` binary not found on PATH.\n"
  printf "      Install it to run the Enforced kernel comparison:\n"
  printf "        brew tap heurion-org/aegis-os https://github.com/heurion-org/aegis-os.git && brew install aegis-os\n"
  printf "      Or pass AEGIS_BIN=/path/to/aegis-os ./examples/redteam-demo/run_demo.sh\n\n"
  exit 0
fi

setup_fixture
printf "\n[2/2] WITH AEGIS OS ENFORCED (aegis-os run -- python3 scripts/verify_env.py)\n"
(
  cd "$REPO"
  HOME="$FAKE_HOME" "$AEGIS_BIN" --runtime-dir "$AEGIS_RT" --workspace "$REPO" run -- \
    env AEGIS_DEMO_HOME="$FAKE_HOME" python3 scripts/verify_env.py || true
)

printf "\n      Host repo verification after enforced run:\n"
printf "      - Host src/app.py untouched:     %s\n" "$(tr '\n' ' ' < "$REPO/src/app.py")"
if [ -e "$REPO/.git/hooks/post-checkout" ]; then
  printf "      - Host .git/hooks/post-checkout: PRESENT (unexpected!)\n"
else
  printf "      - Host .git/hooks/post-checkout: ABSENT (host .git protected)\n"
fi
printf "\n      Shadow diff captured safely for human review:\n"
"$AEGIS_BIN" --runtime-dir "$AEGIS_RT" --workspace "$REPO" diff || true
printf "\n======================================================================\n\n"
