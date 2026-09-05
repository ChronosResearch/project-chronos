"""Report punctuation density and replace characters that break web-form pastes.

Smart quotes, em-dashes and non-breaking spaces are valid UTF-8, but a form that
mishandles encoding renders them as mojibake (the "a-euro-trademark" garbage).
This converts them to ASCII equivalents and reports what it changed.

Usage:
    python scripts/normalize_text.py <file> [--apply]

Without --apply it only reports.
"""
import sys
import unicodedata

# Characters that survive badly in web forms, mapped to safe equivalents.
REPLACEMENTS = {
    "\u2014": ", ",     # em dash
    "\u2013": "-",      # en dash
    "\u2018": "'",      # left single quote
    "\u2019": "'",      # right single quote / apostrophe
    "\u201c": '"',      # left double quote
    "\u201d": '"',      # right double quote
    "\u2026": "...",    # ellipsis
    "\u00a0": " ",      # non-breaking space
    "\u2192": "->",     # right arrow
    "\u00d7": "x",      # multiplication sign
    "\u2264": "<=",
    "\u2265": ">=",
    "\u2248": "~",
}


def main() -> int:
    if len(sys.argv) < 2:
        sys.exit(__doc__)

    path = sys.argv[1]
    apply = "--apply" in sys.argv

    with open(path, encoding="utf-8") as fh:
        text = fh.read()

    words = len(text.split())
    print(f"file:  {path}")
    print(f"words: {words}\n")

    print("punctuation that can break a form paste:")
    total = 0
    for ch, repl in REPLACEMENTS.items():
        n = text.count(ch)
        if n:
            name = unicodedata.name(ch, "?")
            per = f"1 per {words // n} words" if n else ""
            print(f"  {n:>4}  U+{ord(ch):04X}  {name:<28} -> {repl!r:<8} {per}")
            total += n
    if not total:
        print("  none found")

    remaining = sorted({c for c in text if ord(c) > 127} - set(REPLACEMENTS))
    if remaining:
        print("\nother non-ASCII characters (left as-is, check manually):")
        for c in remaining:
            print(f"  U+{ord(c):04X}  {unicodedata.name(c, '?')}  x{text.count(c)}")

    if apply:
        out = text
        for ch, repl in REPLACEMENTS.items():
            out = out.replace(ch, repl)
        # ", ," can result from an em dash next to an existing comma.
        out = out.replace(", ,", ",").replace(",  ", ", ")
        with open(path, "w", encoding="utf-8", newline="\n") as fh:
            fh.write(out)
        still = sum(1 for c in out if ord(c) > 127)
        print(f"\napplied. {total} replacements. non-ASCII remaining: {still}")
    else:
        print("\nreport only. re-run with --apply to rewrite the file.")

    return 0


if __name__ == "__main__":
    sys.exit(main())
