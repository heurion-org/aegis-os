#!/usr/bin/env bash
# Verifies every `<asset>.sig` in DIR against the public key embedded in scripts/install.sh, the
# same key end users check against. Run after signing so a release can never ship with a key that
# installers would reject.
# Usage: scripts/release/verify.sh <dir> [install.sh]
set -euo pipefail

DIR="$1"
INSTALLER="${2:-$(dirname "$0")/../install.sh}"

signer_line() {
  sed -n "s/^${1}='\(.*\)'$/\1/p" "$INSTALLER"
}
SIGNER="$(signer_line RELEASE_SIGNER)"
PRINCIPAL="$(sed -n 's/^RELEASE_PRINCIPAL="\(.*\)"$/\1/p' "$INSTALLER")"
NAMESPACE="$(sed -n 's/^RELEASE_NAMESPACE="\(.*\)"$/\1/p' "$INSTALLER")"
if [[ -z "$SIGNER" || -z "$PRINCIPAL" || -z "$NAMESPACE" || "$SIGNER" == *REPLACE_WITH_RELEASE_PUBLIC_KEY* ]]; then
  echo "install.sh has no release public key configured" >&2
  exit 1
fi

allowed="$(mktemp)"
trap 'rm -f "$allowed"' EXIT
printf '%s\n' "$SIGNER" > "$allowed"

count=0
for sig in "$DIR"/*.sig; do
  asset="${sig%.sig}"
  ssh-keygen -Y verify -f "$allowed" -I "$PRINCIPAL" -n "$NAMESPACE" -s "$sig" < "$asset" >/dev/null
  count=$((count + 1))
done
for asset in "$DIR"/*; do
  [[ "$asset" == *.sig || ! -f "$asset" ]] && continue
  [[ -f "$asset.sig" ]] || { echo "unsigned asset: $asset" >&2; exit 1; }
done
echo "verified $count signatures against install.sh's release key"
