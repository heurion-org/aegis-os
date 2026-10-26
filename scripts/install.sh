#!/usr/bin/env sh
set -eu

# Release signing key. Every downloaded binary must carry a valid OpenSSH signature from this key
# (namespace `aegis-os-release`), produced by the release workflow. There is deliberately no switch
# to skip verification: the mirror is not trusted, the signature is.
RELEASE_SIGNER='aegis-os-release@heurion.org ssh-ed25519 REPLACE_WITH_RELEASE_PUBLIC_KEY'
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
  INSTALL_DIR="${HOME}/.local/bin"
  if [ -w "/usr/local/bin" ]; then
    INSTALL_DIR="/usr/local/bin"
  fi
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

echo "==> Installed verified binary to: $TARGET_BIN"
"$TARGET_BIN" --version || true

echo "==> Configuring AI coding clients (Antigravity, Claude Code, Codex)..."
"$TARGET_BIN" install

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

echo ""
echo "✅ Aegis OS installation complete!"
echo "   Export PATH in current shell (if needed): export PATH=\"${INSTALL_DIR}:\$PATH\""
echo "   Next step (Free Cloud Plan · 1 Workspace · 1 AI · \$0/mo):"
echo "     cd /path/to/your/project && ${TARGET_BIN} cloud up"
