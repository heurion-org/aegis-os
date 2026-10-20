#!/usr/bin/env bash
set -euo pipefail

# ==============================================================================
# Aegis OS — Automated arXiv Submission Packager
# Strictly implements Trevor Campbell's 18-step arXiv Checklist:
#   https://trevorcampbell.me/html/arxiv.html
# ==============================================================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

echo "[1/5] Compiling main.tex with Tectonic to generate fresh PDF and precompiled main.bbl..."
if [ ! -d "$HOME/Library/Caches/TectonicProject.Tectonic" ] && [ -d "/Users/huizhao/Library/Caches/TectonicProject.Tectonic" ]; then
  mkdir -p "$HOME/Library/Caches"
  cp -cR /Users/huizhao/Library/Caches/TectonicProject.Tectonic "$HOME/Library/Caches/"
fi
TECTONIC_CACHE_FLAG=""
if [ -d "$HOME/Library/Caches/TectonicProject.Tectonic" ]; then
  TECTONIC_CACHE_FLAG="-C"
fi
/opt/homebrew/bin/tectonic $TECTONIC_CACHE_FLAG --keep-intermediates --keep-logs main.tex
cp main.pdf aegis_os_arxiv_preprint.pdf

echo "[2/5] Creating clean working deep copy (tmp_arxiv/)..."
rm -rf tmp_arxiv ax.tar arxiv_submission.tar.gz
mkdir -p tmp_arxiv

# Copy only required flat root files (main.tex + precompiled main.bbl)
cp main.tex tmp_arxiv/main.tex
cp main.bbl tmp_arxiv/main.bbl

echo "[3/5] Stripping any LaTeX comments (%) and verifying 4-pass \\typeout..."
python3 - <<'PY'
import re
from pathlib import Path

tex_path = Path("tmp_arxiv/main.tex")
lines = tex_path.read_text(encoding="utf-8").splitlines()
cleaned = []
for line in lines:
    # Remove full-line comments
    if line.lstrip().startswith("%"):
        continue
    # Keep trailing % used inside \resizebox{...}{!}{% macro invocations, strip any text after unescaped %
    m = re.search(r'(?<!\\)%', line)
    if m:
        prefix = line[:m.start() + 1]
        cleaned.append(prefix)
    else:
        cleaned.append(line)

content = "\n".join(cleaned) + "\n"
if "get arXiv to do 4 passes" not in content:
    content = content.replace(
        "\\end{document}",
        "\\typeout{get arXiv to do 4 passes: Label(s) may have changed. Rerun}\n\\end{document}",
    )
tex_path.write_text(content, encoding="utf-8")
PY

echo "[4/5] Verifying clean compilation inside isolated tmp_arxiv/ (without .bib)..."
(
  cd tmp_arxiv
  /opt/homebrew/bin/tectonic $TECTONIC_CACHE_FLAG main.tex >/dev/null
  # Delete generated PDF and any intermediate files so only main.tex and main.bbl remain
  rm -f main.pdf *.aux *.log *.out *.blg *.synctex* .DS_Store
)

echo "[5/5] Creating ax.tar and arxiv_submission.tar.gz (macOS extended attributes stripped)..."
(
  cd tmp_arxiv
  COPYFILE_DISABLE=1 tar -cvf ../ax.tar *
  COPYFILE_DISABLE=1 tar -czvf ../arxiv_submission.tar.gz *
)

echo ""
echo "=============================================================================="
echo "  arXiv Package Build Complete!"
echo "  • Preview PDF          : $SCRIPT_DIR/aegis_os_arxiv_preprint.pdf"
echo "  • Trevor Campbell tar  : $SCRIPT_DIR/ax.tar"
echo "  • Compressed tar.gz    : $SCRIPT_DIR/arxiv_submission.tar.gz"
echo "  • Web Form Metadata    : $SCRIPT_DIR/ARXIV_METADATA.txt"
echo "=============================================================================="
