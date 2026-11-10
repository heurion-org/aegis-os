#!/usr/bin/env bash
# Package the local `aegis-os` v0.4.6 binary and register it in the local
# Homebrew Tap (`heurion-org/aegis-os`) so `brew reinstall aegis-os` /
# `brew upgrade aegis-os` works immediately on Linux or macOS before publishing
# the GitHub Release tag.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${REPO_ROOT}"

RAW_VER="$(grep -m1 '^version = ' Cargo.toml | sed -E 's/version = "([^"]+)"/\1/')"
VERSION="v${RAW_VER}"

OS_NAME="$(uname -s)"
ARCH_NAME="$(uname -m)"
if [[ "${OS_NAME}" == "Darwin" ]]; then
  if [[ "${ARCH_NAME}" == "arm64" || "${ARCH_NAME}" == "aarch64" ]]; then
    TRIPLE="aarch64-apple-darwin"
  else
    TRIPLE="x86_64-apple-darwin"
  fi
else
  if [[ "${ARCH_NAME}" == "arm64" || "${ARCH_NAME}" == "aarch64" ]]; then
    TRIPLE="aarch64-unknown-linux-gnu"
  else
    TRIPLE="x86_64-unknown-linux-gnu"
  fi
fi

BIN_SOURCE=""
NEED_BUILD=0
if [[ "${1:-}" == "--build" ]]; then
  NEED_BUILD=1
elif [[ -x "${REPO_ROOT}/target/release/aegis-os" ]]; then
  if [[ -n "$(find "${REPO_ROOT}/crates" -name '*.rs' -newer "${REPO_ROOT}/target/release/aegis-os" -print -quit 2>/dev/null)" ]]; then
    NEED_BUILD=1
  fi
elif [[ -x "${HOME}/.cargo/bin/aegis-os" ]]; then
  if [[ -n "$(find "${REPO_ROOT}/crates" -name '*.rs' -newer "${HOME}/.cargo/bin/aegis-os" -print -quit 2>/dev/null)" ]]; then
    NEED_BUILD=1
  fi
else
  NEED_BUILD=1
fi

if [[ "${NEED_BUILD}" -eq 1 ]]; then
  echo "==> [1/4] Building fresh release binary (aegis-os ${VERSION})..."
  cargo build --release -p aos-cli
  BIN_SOURCE="${REPO_ROOT}/target/release/aegis-os"
elif [[ -x "${REPO_ROOT}/target/release/aegis-os" ]] && "${REPO_ROOT}/target/release/aegis-os" --version | grep -q "${RAW_VER}"; then
  BIN_SOURCE="${REPO_ROOT}/target/release/aegis-os"
elif [[ -x "${HOME}/.cargo/bin/aegis-os" ]] && "${HOME}/.cargo/bin/aegis-os" --version | grep -q "${RAW_VER}"; then
  BIN_SOURCE="${HOME}/.cargo/bin/aegis-os"
else
  echo "==> [1/4] Building release binary (aegis-os ${VERSION})..."
  cargo build --release -p aos-cli
  BIN_SOURCE="${REPO_ROOT}/target/release/aegis-os"
fi
if [[ -d "${HOME}/.cargo/bin" && "${BIN_SOURCE}" != "${HOME}/.cargo/bin/aegis-os" ]]; then
  cp -f "${BIN_SOURCE}" "${HOME}/.cargo/bin/aegis-os"
  ln -sf "${HOME}/.cargo/bin/aegis-os" "${HOME}/.cargo/bin/aos"
fi
echo "==> [1/4] Using binary: ${BIN_SOURCE} ($(${BIN_SOURCE} --version))"

DIST_DIR="${REPO_ROOT}/dist"
mkdir -p "${DIST_DIR}"
ARCHIVE="${DIST_DIR}/aegis-os-${VERSION}-${TRIPLE}.tar.gz"

echo "==> [2/4] Packaging ${ARCHIVE}..."
cp "${BIN_SOURCE}" "${DIST_DIR}/aegis-os"
chmod +x "${DIST_DIR}/aegis-os"
tar -czf "${ARCHIVE}" -C "${DIST_DIR}" aegis-os
rm -f "${DIST_DIR}/aegis-os"

if command -v sha256sum >/dev/null 2>&1; then
  SHA256="$(sha256sum "${ARCHIVE}" | awk '{print $1}')"
else
  SHA256="$(shasum -a 256 "${ARCHIVE}" | awk '{print $1}')"
fi
echo "==> SHA-256: ${SHA256}"

BREW_REPO="$(brew --repository)"
TAP_DIR="${BREW_REPO}/Library/Taps/heurion-org/homebrew-aegis-os/Formula"
mkdir -p "${TAP_DIR}"

echo "==> [3/4] Updating local Homebrew Tap at ${TAP_DIR}/aegis-os.rb (${RAW_VER})..."
cat > "${TAP_DIR}/aegis-os.rb" <<EOF
class AegisOs < Formula
  desc "Multi-tenant Agent OS Runtime & Cloud PaaS with CoW VFS, Sandbox & IPC for AGY, Claude Code, and Codex"
  homepage "https://github.com/heurion-org/aegis-os"
  url "file://${ARCHIVE}"
  version "${RAW_VER}"
  sha256 "${SHA256}"
  license "Apache-2.0"

  def install
    bin.install "aegis-os"
    bin.install_symlink "aegis-os" => "aos"
  end

  def caveats
    <<~EOS
      Run this once to wire Aegis OS into Antigravity (\`agy\`), Claude Code (\`claude\`), OpenCode (\`opencode\`), and Codex (\`codex\`):
        aegis-os install

      To launch any coding agent inside the Parent-Process Kernel-Enforced Runtime:
        aos run -- claude
        aos run -- opencode
        aos run -- agy
    EOS
  end

  test do
    assert_match "aegis-os", shell_output("#{bin}/aegis-os --version")
    system "#{bin}/aegis-os", "install", "--home-dir", testpath, "--dry-run"
  end
end
EOF

echo "==> [4/4] Done! Now run:"
echo "    brew reinstall heurion-org/aegis-os/aegis-os"

