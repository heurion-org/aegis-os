#!/usr/bin/env bash
# Builds static musl `aegis-guest-init` + packs verified MicroVM kernel & initramfs bundles
# for local `--from-dir` testing on macOS/Linux or automated CI release packaging on Linux.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
if [[ -d "${HOME:-}/.cargo/bin" ]]; then
  export PATH="${HOME}/.cargo/bin:${PATH}"
fi
ARCH="$(uname -m)"
if [[ "$ARCH" == "arm64" ]]; then
  ARCH="aarch64"
fi
VERSION="$(sed -n 's/^version = "\([^"]*\)"/\1/p' "$ROOT/Cargo.toml" | head -n 1)"
OUT_DIR=""
RELEASE_PREFIX=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --arch)
      ARCH="${2:?--arch requires a value}"
      shift 2
      ;;
    --version)
      VERSION="${2:?--version requires a value}"
      shift 2
      ;;
    --out)
      OUT_DIR="${2:?--out requires a value}"
      shift 2
      ;;
    --release-prefix)
      RELEASE_PREFIX="${2:?--release-prefix requires a value}"
      shift 2
      ;;
    -h|--help)
      cat <<EOF
Usage: $0 [--arch aarch64|x86_64] [--version X.Y.Z] [--out <dir>] [--release-prefix <path-prefix>]
EOF
      exit 0
      ;;
    *)
      echo "Unknown option: $1" >&2
      exit 1
      ;;
  esac
done

case "$ARCH" in
  aarch64|x86_64) ;;
  *)
    echo "Unsupported architecture '$ARCH' (expected aarch64 or x86_64)" >&2
    exit 1
    ;;
esac

if [[ -z "$OUT_DIR" ]]; then
  OUT_DIR="$ROOT/target/vm-bundle-$ARCH"
fi

TARGET="${ARCH}-unknown-linux-musl"
echo "[build_vm_images] building static aegis-guest-init for $TARGET ..."
rustup target add "$TARGET" >/dev/null 2>&1 || true

HOST_OS="$(uname -s)"
if [[ "$HOST_OS" == "Darwin" || "$ARCH" != "$(uname -m)" ]]; then
  SYSROOT="$(rustc --print sysroot)"
  RUST_LLD="$(find "$SYSROOT" -name rust-lld -type f 2>/dev/null | head -n 1 || true)"
  if [[ -z "$RUST_LLD" ]]; then
    echo "[build_vm_images] installing rustup llvm-tools for cross-linking ELF guest init ..."
    rustup component add llvm-tools-preview >/dev/null
    RUST_LLD="$(find "$SYSROOT" -name rust-lld -type f | head -n 1 || true)"
  fi
  if [[ -z "$RUST_LLD" ]]; then
    echo "rust-lld not found inside $SYSROOT; install llvm-tools-preview or build on Linux" >&2
    exit 1
  fi
  RUSTFLAGS="-C linker-flavor=ld.lld -C linker=${RUST_LLD} -C target-feature=+crt-static" \
    cargo build --manifest-path "$ROOT/Cargo.toml" --release --locked -p aos-guest-init --target "$TARGET"
else
  RUSTFLAGS="-C target-feature=+crt-static" \
    cargo build --manifest-path "$ROOT/Cargo.toml" --release --locked -p aos-guest-init --target "$TARGET"
fi

GUEST_ELF="$ROOT/target/${TARGET}/release/aegis-guest-init"
if [[ ! -f "$GUEST_ELF" ]]; then
  echo "Expected compiled guest init at $GUEST_ELF" >&2
  exit 1
fi

PACK_ARGS=(
  --arch "$ARCH"
  --version "$VERSION"
  --guest-init "$GUEST_ELF"
  --out-dir "$OUT_DIR"
)
if [[ -n "$RELEASE_PREFIX" ]]; then
  PACK_ARGS+=(--release-prefix "$RELEASE_PREFIX")
fi

python3 "$ROOT/scripts/release/pack_vm_bundle.py" "${PACK_ARGS[@]}"
echo "[build_vm_images] done! Test locally with:"
echo "  aegis-os vm pull --from-dir \"$OUT_DIR\" --force"
