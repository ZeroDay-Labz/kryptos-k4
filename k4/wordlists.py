"""
Keyword corpus harvested from the security wordlists installed on this machine.

Every line of every .txt wordlist under /usr/share/wordlists (rockyou, SecLists,
Probable-Wordlists, FuzzDB), plus the system dictionary and John's list, is
reduced to its letters (so "berlin1989!" -> BERLIN, "i love you" -> ILOVEYOU),
upper-cased, and de-duplicated. Strings of 3-30 letters are kept.

The result is cached outside the project (it is large) at
~/.cache/krypto_k4/keywords.txt and rebuilt only if missing.

Run:  python wordlists.py        build if needed and print statistics
"""
from __future__ import annotations

import os
import subprocess
import sys
import time

ROOTS = ["/usr/share/wordlists", "/usr/share/dict", "/usr/share/john"]
CACHE_DIR = os.path.expanduser("~/.cache/krypto_k4")
KEYWORDS = os.path.join(CACHE_DIR, "keywords.txt")
MIN_LEN, MAX_LEN = 3, 30


def build(force: bool = False) -> str:
    """Harvest letters-only strings from all wordlists into KEYWORDS. Returns the path."""
    if os.path.exists(KEYWORDS) and not force:
        return KEYWORDS
    os.makedirs(CACHE_DIR, exist_ok=True)
    roots = " ".join(r for r in ROOTS if os.path.isdir(r))
    if not roots:
        raise FileNotFoundError("no wordlist directories found: " + ", ".join(ROOTS))
    tmp = KEYWORDS + ".tmp"
    # Text wordlists only; skip git internals and archives.
    pipeline = (
        f"find -L {roots} -type f -not -path '*/.git/*' "
        r"\( -iname '*.txt' -o -iname '*.lst' -o -iname '*.dic' -o -name 'words' -o -name 'linux.words' \) "
        "-print0 | xargs -0 cat 2>/dev/null "
        "| LC_ALL=C tr -cd 'A-Za-z\\n' | LC_ALL=C tr a-z A-Z "
        f"| LC_ALL=C awk 'length($0) >= {MIN_LEN} && length($0) <= {MAX_LEN}' "
        f"| LC_ALL=C sort -u -S 8G --parallel=8 > '{tmp}'"
    )
    subprocess.run(["bash", "-o", "pipefail", "-c", pipeline], check=True)
    os.replace(tmp, KEYWORDS)
    return KEYWORDS


def iter_keywords():
    with open(build(), encoding="ascii", errors="ignore") as fh:
        for line in fh:
            w = line.rstrip("\n")
            if w:
                yield w


def count() -> int:
    with open(build(), "rb") as fh:
        return sum(buf.count(b"\n") for buf in iter(lambda: fh.read(1 << 20), b""))


if __name__ == "__main__":
    t0 = time.time()
    fresh = not os.path.exists(KEYWORDS) or "--force" in sys.argv
    path = build(force="--force" in sys.argv)
    print(f"keyword corpus: {path}")
    print(f"  {count():,} distinct letter-strings, {os.path.getsize(path) / 1e6:.0f} MB"
          + (f" (built in {time.time() - t0:.0f}s)" if fresh else " (cached)"))
