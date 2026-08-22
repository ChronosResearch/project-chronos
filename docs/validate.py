"""Sanity-check docs/index.html before publishing.

Verifies the markup is well-formed, every internal anchor resolves, no retracted
claim reappeared, and the measured figures match the recorded benchmark run.
"""
import os
import re
import sys
from html.parser import HTMLParser

HERE = os.path.dirname(os.path.abspath(__file__))
PAGE = os.path.join(HERE, "index.html")

VOID = {"area", "base", "br", "col", "embed", "hr", "img", "input",
        "link", "meta", "source", "track", "wbr"}

# Claims retracted during the audit. Any reappearance is a regression.
BANNED = [
    "production-grade", "high-fidelity", "state-of-the-art", "world's first",
    "the first autonomous AI agent", "Proof of Sequential Work", "PoSW",
    "guarantees safety", "provably aligned agent", "unhackable",
]

# Figures that must agree with benchmark-results/.
REQUIRED = [
    "8,267", "128", "1,728", "1975 ms", "1846 ms", "2074 ms",
    "Wesolowski" if False else "sequential squarings",
    "single-party", "AGPL-3.0",
]


class Checker(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.stack = []
        self.errors = []
        self.ids = set()
        self.hrefs = []

    def handle_starttag(self, tag, attrs):
        d = dict(attrs)
        if d.get("id"):
            self.ids.add(d["id"])
        if d.get("href"):
            self.hrefs.append(d["href"])
        if tag not in VOID:
            self.stack.append((tag, self.getpos()[0]))

    def handle_endtag(self, tag):
        if tag in VOID:
            return
        if not self.stack:
            self.errors.append(f"line {self.getpos()[0]}: stray </{tag}>")
            return
        open_tag, line = self.stack.pop()
        if open_tag != tag:
            self.errors.append(
                f"line {self.getpos()[0]}: </{tag}> closes <{open_tag}> opened at line {line}")


def main() -> int:
    with open(PAGE, encoding="utf-8") as fh:
        html = fh.read()

    ok = True
    c = Checker()
    c.feed(html)

    print("markup:")
    for e in c.errors:
        print(f"  [FAIL] {e}")
        ok = False
    if c.stack:
        for tag, line in c.stack:
            print(f"  [FAIL] <{tag}> opened at line {line} never closed")
        ok = False
    if ok:
        print("  [OK  ] well-formed, all tags balanced")

    print("internal anchors:")
    anchors = [h[1:] for h in c.hrefs if h.startswith("#") and len(h) > 1]
    missing = sorted({a for a in anchors if a not in c.ids})
    for a in missing:
        print(f"  [FAIL] #{a} has no matching id")
        ok = False
    if not missing:
        print(f"  [OK  ] {len(set(anchors))} anchors all resolve")

    print("retracted claims:")
    found_any = False
    for term in BANNED:
        if re.search(re.escape(term), html, re.IGNORECASE):
            print(f"  [FAIL] present: {term}")
            found_any = True
            ok = False
    if not found_any:
        print("  [OK  ] none found")

    print("required figures:")
    for term in REQUIRED:
        present = term.lower() in html.lower()
        print(f"  [{'OK  ' if present else 'FAIL'}] {term}")
        ok = ok and present

    print(f"\npage size: {len(html):,} bytes, {html.count(chr(10)) + 1} lines")
    print("VALIDATION PASSED" if ok else "VALIDATION FAILED")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
