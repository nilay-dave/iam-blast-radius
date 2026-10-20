"""Check the report's colour tokens against WCAG contrast thresholds.

The report is read by analysts and sometimes projected in a review, and the
verdict column is where colour would otherwise carry meaning. Every verdict also
carries a glyph and a word, and these are the ratios behind that. This
parses the colour tokens straight out of the Jinja template, so it cannot drift
from what the template actually ships, and computes the real contrast ratios.

Thresholds: 4.5 for body text, 3.0 for large text. The verdict labels are small
bold text and are held to 4.5.

Usage:
    python tools/check_contrast.py
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TEMPLATE = ROOT / "src" / "ibr" / "report" / "templates" / "report.html.j2"

AA_BODY = 4.5
AA_LARGE = 3.0

# Each pair is (foreground token, background token, threshold, what it is).
PAIRS = [
    ("fg", "bg", AA_BODY, "body text on the page"),
    ("muted", "bg", AA_BODY, "secondary text on the page"),
    ("muted", "panel", AA_BODY, "secondary text on a panel"),
    ("bad", "panel", AA_LARGE, "the headline figure"),
    ("bad", "bg", AA_BODY, "admin status labels"),
    ("warn", "bg", AA_BODY, "reaches-admin status labels"),
    ("ok", "bg", AA_BODY, "contained status labels"),
    ("fg", "panel", AA_BODY, "text inside a panel"),
]


def _channel(value: float) -> float:
    value /= 255.0
    return value / 12.92 if value <= 0.04045 else ((value + 0.055) / 1.055) ** 2.4


def luminance(hex_colour: str) -> float:
    raw = hex_colour.lstrip("#")
    r, g, b = (int(raw[i : i + 2], 16) for i in (0, 2, 4))
    return 0.2126 * _channel(r) + 0.7152 * _channel(g) + 0.0722 * _channel(b)


def ratio(first: str, second: str) -> float:
    a, b = luminance(first), luminance(second)
    lighter, darker = max(a, b), min(a, b)
    return (lighter + 0.05) / (darker + 0.05)


def themes(text: str) -> dict[str, dict[str, str]]:
    """Pull every colour token out of each :root block in the template."""
    found: dict[str, dict[str, str]] = {}
    blocks = re.findall(r":root[^{]*\{([^}]*)\}", text)
    names = ["light", "dark"]
    for index, block in enumerate(blocks):
        tokens = dict(re.findall(r"--([a-z]+):\s*(#[0-9a-fA-F]{6})", block))
        if tokens:
            found[names[index] if index < len(names) else f"theme-{index}"] = tokens
    return found


def main() -> int:
    if not TEMPLATE.exists():
        print(f"template not found: {TEMPLATE}", file=sys.stderr)
        return 2

    found = themes(TEMPLATE.read_text(encoding="utf-8"))
    if not found:
        print("no colour tokens found in the template", file=sys.stderr)
        return 2

    failures = 0
    for theme, tokens in found.items():
        print(f"\n{theme} theme")
        for foreground, background, threshold, label in PAIRS:
            if foreground not in tokens or background not in tokens:
                continue
            value = ratio(tokens[foreground], tokens[background])
            ok = value >= threshold
            failures += 0 if ok else 1
            print(
                f"  {'PASS' if ok else 'FAIL'}  {value:5.2f}:1  "
                f"(needs {threshold}) {label}"
            )

    print()
    if failures:
        print(f"{failures} colour pair(s) below threshold", file=sys.stderr)
        return 1
    print("every checked colour pair meets its WCAG threshold")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
