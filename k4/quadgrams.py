"""
Quadgram log-probability scoring for English plaintext.

The gold-standard readability metric for spaceless classical-cipher output is
the sum of log P(quadgram) over a text. We build the model offline from the
system dictionary (word-internal quadgrams) plus the solved Kryptos plaintexts
(K1-K3) for some cross-word / sentence structure. The model is cached to
`quadgram_model.txt` so it is built only once.

Caveat: a dictionary-derived model weights every word equally rather than by
corpus frequency, so absolute scores differ from a running-text model like
Practical Cryptography's. For *ranking* K4 candidates against each other that is
fine -- English still scores far above noise.
"""
from __future__ import annotations

import functools
import math
import os

_MODEL_PATH = os.path.join(os.path.dirname(__file__), "quadgram_model.txt")
_WORDLIST = "/usr/share/dict/words"


def _iter_english_sources():
    """Yield uppercase A-Z-only strings to harvest quadgrams from."""
    try:
        with open(_WORDLIST, encoding="utf-8", errors="ignore") as fh:
            for line in fh:
                w = line.strip().upper()
                if w.isascii() and w.isalpha() and len(w) >= 4:
                    yield w
    except OSError:
        pass
    # Solved sections give real sentence-level letter transitions.
    from solve import K1_PT, K2_PT, K3_PT
    for s in (K1_PT, K2_PT, K3_PT):
        yield s


def build_model(path: str = _MODEL_PATH) -> dict[str, int]:
    counts: dict[str, int] = {}
    for s in _iter_english_sources():
        for i in range(len(s) - 3):
            q = s[i:i + 4]
            counts[q] = counts.get(q, 0) + 1
    with open(path, "w", encoding="utf-8") as fh:
        for q, c in sorted(counts.items()):
            fh.write(f"{q} {c}\n")
    return counts


@functools.lru_cache(maxsize=1)
def _load() -> tuple[dict[str, float], float]:
    if not os.path.exists(_MODEL_PATH):
        build_model()
    counts: dict[str, int] = {}
    total = 0
    with open(_MODEL_PATH, encoding="utf-8") as fh:
        for line in fh:
            q, c = line.split()
            counts[q] = int(c)
            total += int(c)
    logs = {q: math.log10(c / total) for q, c in counts.items()}
    floor = math.log10(0.01 / total)  # penalty for unseen quadgrams
    return logs, floor


def quadgram_score(text: str) -> float:
    """Average log10 quadgram probability (higher/less-negative = more English)."""
    logs, floor = _load()
    n = len(text) - 3
    if n <= 0:
        return floor
    total = 0.0
    for i in range(n):
        total += logs.get(text[i:i + 4], floor)
    return total / n


# --- running-prose model -------------------------------------------------------
# The dictionary model above rates word-like gibberish almost as highly as real
# sentences. This one is built from de-duplicated English prose found on the
# machine (READMEs, licences, docs), so it captures word boundaries and common
# words, which is what matters when judging a short key fragment.

_PROSE_PATH = os.path.join(os.path.dirname(__file__), "quadgram_prose.txt")


def build_prose_model(path: str = _PROSE_PATH, max_chars: int = 40_000_000) -> int:
    import hashlib
    import re
    counts: dict[str, int] = {}
    seen: set[bytes] = set()
    total = 0
    name_ok = re.compile(r"(README|NEWS|COPYING|LICEN[SC]E|\.txt$|\.md$)", re.I)
    for root in ("/usr/share/doc", "/usr/share/licenses"):
        for dirpath, _, files in os.walk(root):
            for f in files:
                if total > max_chars or not name_ok.search(f):
                    continue
                try:
                    with open(os.path.join(dirpath, f), encoding="utf-8", errors="ignore") as fh:
                        text = fh.read(2_000_000)
                except OSError:
                    continue
                for para in re.split(r"\n\s*\n", text):
                    words = re.findall(r"[A-Za-z]+", para)
                    if len(words) < 8:
                        continue
                    dense = len("".join(para.split()))
                    letters = sum(len(w) for w in words)
                    if letters < 0.8 * dense:
                        continue                      # code, tables, URLs
                    s = "".join(words).upper()
                    h = hashlib.md5(s.encode()).digest()
                    if h in seen:
                        continue                      # licences repeat a lot
                    seen.add(h)
                    for i in range(len(s) - 3):
                        q = s[i:i + 4]
                        counts[q] = counts.get(q, 0) + 1
                    total += len(s)
    with open(path, "w", encoding="utf-8") as fh:
        for q, c in sorted(counts.items()):
            if q.isascii() and q.isalpha():
                fh.write(f"{q} {c}\n")
    return total


@functools.lru_cache(maxsize=1)
def load_prose() -> tuple[dict[str, float], float]:
    if not os.path.exists(_PROSE_PATH):
        build_prose_model()
    counts: dict[str, int] = {}
    total = 0
    with open(_PROSE_PATH, encoding="utf-8") as fh:
        for line in fh:
            q, c = line.split()
            counts[q] = int(c)
            total += int(c)
    logs = {q: math.log10(c / total) for q, c in counts.items()}
    return logs, math.log10(0.01 / total)


if __name__ == "__main__":
    if not os.path.exists(_MODEL_PATH):
        print("building model...")
        build_model()
    for name, s in {
        "english": "THEQUICKBROWNFOXJUMPSOVERTHELAZYDOG",
        "k2crib":  "ITWASTOTALLYINVISIBLEHOWSTHATPOSSIBLE",
        "random":  "XJQZKWVBYFPMLGHCDNRUTOASEIXJQZKWVBY",
    }.items():
        print(f"{name:8} quadgram={quadgram_score(s):.3f}")
