#!/usr/bin/env python3
"""Points Formula/aegis-os.rb at a new release: version, archive URLs and their SHA-256s.

Usage: scripts/release/update_formula.py <tag> <SHA256SUMS> [formula]
"""
import re
import sys

TRIPLES = [
    "aarch64-apple-darwin",
    "x86_64-apple-darwin",
    "aarch64-unknown-linux-gnu",
    "x86_64-unknown-linux-gnu",
]


def main() -> int:
    tag, sums_path = sys.argv[1], sys.argv[2]
    formula_path = sys.argv[3] if len(sys.argv) > 3 else "Formula/aegis-os.rb"
    version = tag.lstrip("v")

    sums = {}
    with open(sums_path) as f:
        for line in f:
            digest, name = line.split()
            sums[name.lstrip("*")] = digest

    with open(formula_path) as f:
        formula = f.read()

    formula = re.sub(r'(\n  version ")[^"]*(")', rf"\g<1>{version}\g<2>", formula, count=1)
    for triple in TRIPLES:
        archive = f"aegis-os-{tag}-{triple}.tar.gz"
        if archive not in sums:
            print(f"missing {archive} in {sums_path}", file=sys.stderr)
            return 1
        url = f"https://github.com/heurion-org/aegis-os/releases/download/{tag}/{archive}"
        pattern = re.compile(
            r'url "https://github\.com/heurion-org/aegis-os/releases/download/[^/"]+/aegis-os-[^"]*-'
            + re.escape(triple)
            + r'\.tar\.gz"\n(\s*)sha256 "[0-9a-f]{64}"'
        )
        formula, n = pattern.subn(
            lambda m: f'url "{url}"\n{m.group(1)}sha256 "{sums[archive]}"', formula
        )
        if n != 1:
            print(f"expected one url/sha256 pair for {triple}, found {n}", file=sys.stderr)
            return 1

    with open(formula_path, "w") as f:
        f.write(formula)
    print(f"Formula updated to {tag}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
