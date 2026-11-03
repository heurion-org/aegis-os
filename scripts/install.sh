#!/usr/bin/env sh
set -eu

# Release signing key. Every downloaded binary must carry a valid OpenSSH signature from this key
# (namespace `aegis-os-release`), produced by the release workflow. There is deliberately no switch
# to skip verification: the mirror is not trusted, the signature is.
RELEASE_SIGNER='aegis-os-release@heurion.org ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIObpFSqmFZ8/ObqSlGmN/zhTbFeDHDxlKx6ha6Y9Zi37'
RELEASE_PRINCIPAL="aegis-os-release@heurion.org"
RELEASE_NAMESPACE="aegis-os-release"

ENDPOINT="${AEGIS_CLOUD_ENDPOINT:-https://heurion.org}"
GITHUB_RELEASES="https://github.com/heurion-org/aegis-os/releases/latest/download"
OS="$(uname -s | tr '[:upper:]' '[:lower:]')"
ARCH="$(uname -m)"

case "$ARCH" in
  x86_64|amd64) ARCH="x86_64" ;;
  arm64|aarch64)
    if [ "$OS" = "darwin" ]; then
      ARCH="arm64"
    else
      ARCH="aarch64"
    fi
    ;;
  *)
    echo "Unsupported architecture: $ARCH" >&2
    exit 1
    ;;
esac

case "$RELEASE_SIGNER" in
  *REPLACE_WITH_RELEASE_PUBLIC_KEY*)
    echo "This installer has no release signing key configured; refusing to install an unverified binary." >&2
    exit 1
    ;;
esac
if ! command -v ssh-keygen >/dev/null 2>&1; then
  echo "ssh-keygen (OpenSSH 8.1+) is required to verify the download signature; install openssh-client and retry." >&2
  exit 1
fi

BIN_NAME="aegis-os-${OS}-${ARCH}"

INSTALL_DIR="${AEGIS_INSTALL_DIR:-}"
if [ -z "$INSTALL_DIR" ]; then
  # 1. If `aegis-os` is already on PATH (outside /tmp) and its directory is writable, upgrade it in-place
  EXISTING_BIN="$(command -v aegis-os 2>/dev/null || true)"
  if [ -n "$EXISTING_BIN" ]; then
    EXISTING_DIR="$(dirname "$EXISTING_BIN")"
    case "$EXISTING_DIR" in
      /tmp/*|/private/tmp/*) ;;
      *)
        if [ -w "$EXISTING_DIR" ] && { [ ! -e "$EXISTING_BIN" ] || [ -w "$EXISTING_BIN" ]; }; then
          INSTALL_DIR="$EXISTING_DIR"
        fi
        ;;
    esac
  fi
fi
if [ -z "$INSTALL_DIR" ]; then
  # 2. Prefer a writable directory that is ALREADY in the user's current PATH so `aegis-os` works immediately
  case ":${PATH}:" in
    *":${HOME}/.local/bin:"*)
      INSTALL_DIR="${HOME}/.local/bin"
      ;;
    *":/opt/homebrew/bin:"*)
      if [ -w "/opt/homebrew/bin" ]; then INSTALL_DIR="/opt/homebrew/bin"; fi
      ;;
    *":/usr/local/bin:"*)
      if [ -w "/usr/local/bin" ]; then INSTALL_DIR="/usr/local/bin"; fi
      ;;
  esac
fi
if [ -z "$INSTALL_DIR" ]; then
  INSTALL_DIR="${HOME}/.local/bin"
fi
mkdir -p "$INSTALL_DIR"
TARGET_BIN="${INSTALL_DIR}/aegis-os"

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

# Downloads the binary and its signature from one source; both must come from the same place.
fetch_from() {
  curl -fsSL "$1/${BIN_NAME}" -o "$WORK/$BIN_NAME" &&
    curl -fsSL "$1/${BIN_NAME}.sig" -o "$WORK/$BIN_NAME.sig"
}

SOURCE="${ENDPOINT}/aegis-cloud/releases"
echo "==> Downloading Aegis OS CLI (${OS}/${ARCH}) from ${SOURCE} ..."
if ! fetch_from "$SOURCE"; then
  SOURCE="$GITHUB_RELEASES"
  echo "==> Mirror unavailable; downloading from ${SOURCE} ..."
  if ! fetch_from "$SOURCE"; then
    echo "Download failed from both the mirror and GitHub Releases." >&2
    exit 1
  fi
fi

echo "==> Verifying release signature ..."
printf '%s\n' "$RELEASE_SIGNER" > "$WORK/allowed_signers"
if ! ssh-keygen -Y verify -f "$WORK/allowed_signers" -I "$RELEASE_PRINCIPAL" -n "$RELEASE_NAMESPACE" \
  -s "$WORK/$BIN_NAME.sig" < "$WORK/$BIN_NAME" >/dev/null 2>&1; then
  echo "Signature verification FAILED for ${BIN_NAME} from ${SOURCE}; refusing to install." >&2
  echo "(Requires OpenSSH 8.1+. If yours is older, install via Homebrew instead: brew tap heurion-org/aegis-os https://github.com/heurion-org/aegis-os.git && brew install aegis-os)" >&2
  exit 1
fi

# Replace via rename in the same directory: overwriting a signed binary in place makes macOS
# SIGKILL it on the next exec.
cp "$WORK/$BIN_NAME" "${TARGET_BIN}.tmp"
chmod +x "${TARGET_BIN}.tmp"
mv -f "${TARGET_BIN}.tmp" "$TARGET_BIN"

# When running a standard install (no custom AEGIS_INSTALL_DIR), also refresh any other writable
# `aegis-os` binary already present on PATH (e.g. /opt/homebrew/bin/aegis-os or ~/.cargo/bin/aegis-os)
# so an older binary earlier in PATH never shadows the newly installed release.
if [ -z "${AEGIS_INSTALL_DIR:-}" ]; then
  OLD_IFS="$IFS"
  IFS=":"
  for dir in $PATH /opt/homebrew/bin /usr/local/bin "${HOME}/.cargo/bin"; do
    IFS="$OLD_IFS"
    [ -n "$dir" ] || continue
    cand="${dir}/aegis-os"
    if [ "$cand" != "$TARGET_BIN" ] && [ -f "$cand" ] && [ -w "$cand" ] && [ -w "$dir" ]; then
      cp "$WORK/$BIN_NAME" "${cand}.tmp" 2>/dev/null && chmod +x "${cand}.tmp" 2>/dev/null && mv -f "${cand}.tmp" "$cand" 2>/dev/null || rm -f "${cand}.tmp" 2>/dev/null
    fi
  done
  IFS="$OLD_IFS"
fi

echo "==> Installed verified binary to: $TARGET_BIN"
"$TARGET_BIN" --version || true

echo "==> Configuring AI coding clients (Antigravity, Claude Code, Codex)..."
"$TARGET_BIN" install

case "$INSTALL_DIR" in
  /tmp/*|/private/tmp/*)
    # Never persist temporary test directories into user shell profiles
    ;;
  *)
    case ":${PATH}:" in
      *":${INSTALL_DIR}:"*) ;;
      *)
        for rc in "${HOME}/.bashrc" "${HOME}/.zshrc" "${HOME}/.profile"; do
          if [ -f "$rc" ] && ! grep -q "$INSTALL_DIR" "$rc" 2>/dev/null; then
            printf '\nexport PATH="%s:$PATH"\n' "$INSTALL_DIR" >> "$rc"
          fi
        done
        ;;
    esac
    ;;
esac

echo ""
echo "✅ Aegis OS installation complete!"
echo "   Export PATH in current shell (if needed): export PATH=\"${INSTALL_DIR}:\$PATH\""
echo "   Zero-CLI Local Mode (default): simply launch \`agy\`, \`claude\`, or \`codex\` in any project directory."
echo "   Useful 1-step commands:"
echo "     • Enable Free Cloud Sandbox (\$0/mo):  cd /path/to/your/project && ${TARGET_BIN} cloud up"
echo "     • Upgrade to Cloud Pro (\$29/mo):      ${TARGET_BIN} cloud subscribe --plan pro --email you@company.com --wait"
echo "     • Approve latest boundary commit:     ${TARGET_BIN} approve   (or auto-approved in IDE / /approve web UI)"
echo "     • Connect Heurion 2.0 AAP-1.0 app:    ${TARGET_BIN} app connect heurion"
