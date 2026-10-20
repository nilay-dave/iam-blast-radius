"""Fail when an em dash or en dash appears in a tracked text file.

The house style for this repository is commas, colons, periods and parentheses.
This runs as a pre-commit hook over changed files, and the check is at the
Unicode code point level so a dash pasted in from a word processor is caught.

Usage:
    python tools/check_dashes.py [paths...]
"""

from __future__ import annotations

import sys
from pathlib import Path

# Built from code points rather than literals so that this file, which the hook
# runs over every other file, cannot itself trip the check it enforces. That is
# not hypothetical: the first version of this table held the literal characters
# and the provenance audit failed on this file.
FORBIDDEN = {
    chr(0x2014): "em dash",
    chr(0x2013): "en dash",
    chr(0x2012): "figure dash",
    chr(0x2015): "horizontal bar",
}
SKIP_SUFFIXES = {".parquet", ".png", ".jpg", ".jpeg", ".gif", ".mp4", ".zip", ".whl", ".ico", ".woff2"}


def check(path: Path) -> list[str]:
    if path.suffix.lower() in SKIP_SUFFIXES:
        return []
    try:
        text = path.read_text(encoding="utf-8")
    except (UnicodeDecodeError, OSError):
        return []

    findings = []
    for number, line in enumerate(text.splitlines(), start=1):
        for char, name in FORBIDDEN.items():
            column = line.find(char)
            if column >= 0:
                findings.append(f"{path}:{number}:{column + 1}: {name}")
    return findings


def main(argv: list[str]) -> int:
    paths = [Path(a) for a in argv] or sorted(Path(".").rglob("*.md"))
    findings = [f for path in paths if path.is_file() for f in check(path)]
    for finding in findings:
        print(finding, file=sys.stderr)
    if findings:
        print(f"\n{len(findings)} dash(es) found. Use commas, colons or parentheses.", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
