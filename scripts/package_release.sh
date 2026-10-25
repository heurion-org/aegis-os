#!/usr/bin/env bash
# Package precompiled Aegis OS (`aegis-os` + `aos`) binary archive & SHA-256 checksum for Homebrew / GitHub Releases.
set -euo pipefail

VERSION="${1:-v0.3.0}"
TARGET_ARCH="$(uname -m)"
TARGET_OS="$(uname -s | tr '[:upper:]' '[:lower:]')"

if [[ "${TARGET_OS}" == "darwin" ]]; then
  if [[ "${TARGET_ARCH}" == "arm64" || "${TARGET_ARCH}" == "aarch64" ]]; then
    TRIPLE="aarch64-apple-darwin"
  else
    TRIPLE="x86_64-apple-darwin"
  fi
else
  if [[ "${TARGET_ARCH}" == "aarch64" || "${TARGET_ARCH}" == "arm64" ]]; then
    TRIPLE="aarch64-unknown-linux-gnu"
  else
    TRIPLE="x86_64-unknown-linux-gnu"
  fi
fi

echo "[1/3] Building optimized release binary for ${TRIPLE} (${VERSION})..."
cargo build --release -p aos-cli

DIST_DIR="dist"
mkdir -p "${DIST_DIR}"
ARCHIVE="${DIST_DIR}/aegis-os-${VERSION}-${TRIPLE}.tar.gz"

echo "[2/3] Packaging ${ARCHIVE}..."
cp target/release/aegis-os "${DIST_DIR}/aegis-os"
chmod +x "${DIST_DIR}/aegis-os"
tar -czf "${ARCHIVE}" -C "${DIST_DIR}" aegis-os -C .. README.md Formula/aegis-os.rb
rm -f "${DIST_DIR}/aegis-os"

echo "[3/3] Computing SHA-256 checksum..."
shasum -a 256 "${ARCHIVE}" | tee "${ARCHIVE}.sha256"
echo "Done! Upload ${ARCHIVE} to GitHub Release ${VERSION} and update Formula/aegis-os.rb sha256."
