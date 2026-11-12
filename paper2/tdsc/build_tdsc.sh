#!/usr/bin/env bash
set -euo pipefail

# ==============================================================================
# Aegis Enforced Runtime (Paper 2) — IEEE TDSC Submission Builder
# Compiles main_tdsc.tex (IEEEtran 10pt,journal,compsoc) -> main_tdsc.pdf (<=14p)
# and packages clean tdsc_submission_source.{tar.gz,zip} for IEEE Author Portal.
# ==============================================================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

echo "[1/3] Compiling main_tdsc.tex with Tectonic..."
TECTONIC_BIN=""
for cand in "$HOME/.local/bin/tectonic" "/opt/homebrew/bin/tectonic" "$(command -v tectonic 2>/dev/null || true)"; do
  if [ -n "$cand" ] && [ -x "$cand" ]; then
    TECTONIC_BIN="$cand"
    break
  fi
done

if [ -n "$TECTONIC_BIN" ]; then
  "$TECTONIC_BIN" -r 2 --keep-intermediates --keep-logs main_tdsc.tex
else
  echo "  (tectonic not found in PATH; packaging existing precompiled main_tdsc.bbl + main_tdsc.pdf)"
fi

echo "[2/3] Packaging clean LaTeX source archives for IEEE Author Portal..."
rm -rf tmp_tdsc tdsc_submission_source.tar.gz tdsc_submission_source.zip
mkdir -p tmp_tdsc
cp main_tdsc.tex main_tdsc.bbl references.bib tmp_tdsc/

(
  cd tmp_tdsc
  COPYFILE_DISABLE=1 tar -czf ../tdsc_submission_source.tar.gz main_tdsc.tex main_tdsc.bbl references.bib
)
python3 - <<'PY'
import zipfile
from pathlib import Path

with zipfile.ZipFile("tdsc_submission_source.zip", "w", compression=zipfile.ZIP_DEFLATED) as zf:
    for name in ("main_tdsc.tex", "main_tdsc.bbl", "references.bib"):
        zf.write(Path("tmp_tdsc") / name, arcname=name)
PY
rm -rf tmp_tdsc
rm -f main_tdsc.log main_tdsc.blg main_tdsc.out main_tdsc.aux

echo "[3/3] Done!"
echo "=============================================================================="
echo "  IEEE TDSC Submission Package Ready:"
echo "  * Manuscript PDF     : $SCRIPT_DIR/main_tdsc.pdf"
echo "  * Source Archive ZIP : $SCRIPT_DIR/tdsc_submission_source.zip"
echo "  * Source Archive TGZ : $SCRIPT_DIR/tdsc_submission_source.tar.gz"
echo "  * Cover Letter       : $SCRIPT_DIR/COVER_LETTER_TDSC.txt"
echo "  * Submission Guide   : $SCRIPT_DIR/TDSC_SUBMISSION_GUIDE.md"
echo "=============================================================================="
