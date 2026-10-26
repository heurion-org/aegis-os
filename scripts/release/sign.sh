#!/usr/bin/env bash
# Signs every release asset in DIR with the release key (OpenSSH signatures, namespace
# `aegis-os-release`) and writes a signed SHA256SUMS.
# Usage: scripts/release/sign.sh <private-key-file> <dir>
set -euo pipefail

KEY="$1"
DIR="$2"
NAMESPACE="aegis-os-release"

cd "$DIR"
rm -f SHA256SUMS ./*.sig
assets=()
for f in *; do
  [[ -f "$f" ]] && assets+=("$f")
done
if [[ ${#assets[@]} -eq 0 ]]; then
  echo "no release assets in $DIR" >&2
  exit 1
fi

if command -v sha256sum >/dev/null 2>&1; then
  sha256sum "${assets[@]}" > SHA256SUMS
else
  shasum -a 256 "${assets[@]}" > SHA256SUMS
fi
for f in "${assets[@]}" SHA256SUMS; do
  ssh-keygen -Y sign -q -f "$KEY" -n "$NAMESPACE" "$f"
done
echo "signed ${#assets[@]} assets + SHA256SUMS"
