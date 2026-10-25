#!/usr/bin/env sh
set -eu

ENDPOINT="${AEGIS_CLOUD_ENDPOINT:-https://heurion.org}"
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

BIN_NAME="aegis-os-${OS}-${ARCH}"
DOWNLOAD_URL="${ENDPOINT}/aegis-cloud/releases/${BIN_NAME}"

INSTALL_DIR="${HOME}/.local/bin"
if [ -w "/usr/local/bin" ]; then
  INSTALL_DIR="/usr/local/bin"
fi
mkdir -p "$INSTALL_DIR"
TARGET_BIN="${INSTALL_DIR}/aegis-os"

echo "==> Downloading Aegis OS CLI (${OS}/${ARCH}) from ${DOWNLOAD_URL} ..."
curl -fsSL "$DOWNLOAD_URL" -o "${TARGET_BIN}.tmp"
chmod +x "${TARGET_BIN}.tmp"
mv "${TARGET_BIN}.tmp" "$TARGET_BIN"

echo "==> Installed binary to: $TARGET_BIN"
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
