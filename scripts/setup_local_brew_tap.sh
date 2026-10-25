#!/usr/bin/env bash
# Build `aegis-os` v0.3.0 locally and register a local Homebrew Tap (`aegis-os/tap`)
# so `brew install aegis-os` works immediately on this Mac before publishing to GitHub Releases.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${REPO_ROOT}"

VERSION="v0.3.0"
TRIPLE="aarch64-apple-darwin"
if [[ "$(uname -m)" != "arm64" && "$(uname -m)" != "aarch64" ]]; then
  TRIPLE="x86_64-apple-darwin"
fi

echo "==> [1/4] Building release binary (aegis-os ${VERSION})..."
cargo build --release -p aos-cli

DIST_DIR="${REPO_ROOT}/dist"
mkdir -p "${DIST_DIR}"
ARCHIVE="${DIST_DIR}/aegis-os-${VERSION}-${TRIPLE}.tar.gz"

echo "==> [2/4] Packaging ${ARCHIVE}..."
cp "${REPO_ROOT}/target/release/aegis-os" "${DIST_DIR}/aegis-os"
chmod +x "${DIST_DIR}/aegis-os"
tar -czf "${ARCHIVE}" -C "${DIST_DIR}" aegis-os
rm -f "${DIST_DIR}/aegis-os"

SHA256="$(shasum -a 256 "${ARCHIVE}" | awk '{print $1}')"
echo "==> SHA-256: ${SHA256}"

TAP_DIR="$(brew --repository)/Library/Taps/aegis-os/homebrew-tap/Formula"
mkdir -p "${TAP_DIR}"

echo "==> [3/4] Registering local Homebrew Tap at ${TAP_DIR}/aegis-os.rb..."
cat > "${TAP_DIR}/aegis-os.rb" <<EOF
class AegisOs < Formula
  desc "Multi-tenant Agent OS Runtime & Cloud PaaS with CoW VFS, Sandbox & IPC for AGY, Claude Code, and Codex"
  homepage "https://github.com/heurion-org/aegis-os"
  url "file://${ARCHIVE}"
  version "0.3.0"
  sha256 "${SHA256}"
  license "Apache-2.0"

  def install
    bin.install "aegis-os"
    bin.install_symlink "aegis-os" => "aos"
  end

  def post_install
    system "#{bin}/aegis-os", "install"
  end

  def caveats
    <<~EOS
      Aegis OS has been automatically integrated into Antigravity (\`agy\`), Claude Code (\`claude\`), and Codex (\`codex\`).

      Zero-CLI Quickstart:
      - Simply launch \`agy\`, \`claude\`, or \`codex\` in ANY project directory (no need to run \`aos\` manually).
      - Subscribe to Aegis Cloud Pro (\$29/mo): https://buy.polar.sh/polar_cl_jCPpzbp4eOAyRbkDP4YzNIFVnYLddbvJZI5Fc27zL0x
    EOS
  end
end
EOF

echo "==> [4/4] Done! You can now run:"
echo "    brew install aegis-os"
echo "    (or 'brew reinstall aegis-os' if already installed)"
