"""
Plaintext scoring for Kryptos K4 candidate decryptions.

Three complementary signals, all offline (stdlib + /usr/share/dict/words):

* index of coincidence (ioc)   -- structural: is this monoalphabetic-like English?
* chi-squared vs English freq  -- cheap monogram prefilter for sweeps
* word_coverage                -- the real readability signal: fraction of
                                  letters tiled by dictionary words (no spaces needed)

Use chi2/ioc as a fast prefilter in large sweeps, then word_coverage on the
survivors. english_score blends them into one number (higher = better).
"""
from __future__ import annotations

import functools
from collections import Counter

# Standard English monogram frequencies (%), A..Z.
_ENG = [8.17, 1.49, 2.78, 4.25, 12.70, 2.23, 2.02, 6.09, 6.97, 0.15, 0.77,
        4.03, 2.41, 6.75, 7.51, 1.93, 0.10, 5.99, 6.33, 9.06, 2.76, 0.98,
        2.36, 0.15, 1.97, 0.07]
_ENG_P = [x / 100.0 for x in _ENG]

WORDLIST_PATH = "/usr/share/dict/words"
_MIN_WORD = 3
_MAX_WORD = 15


@functools.lru_cache(maxsize=1)
def _words() -> frozenset[str]:
    out = set()
    try:
        with open(WORDLIST_PATH, encoding="utf-8", errors="ignore") as fh:
            for line in fh:
                w = line.strip().upper()
                if _MIN_WORD <= len(w) <= _MAX_WORD and w.isalpha() and w.isascii():
                    out.add(w)
    except OSError:
        pass
    # A few high-value short words the dict may under-weight.
    out.update({"THE", "AND", "EAST", "WEST", "NORTH", "SOUTH", "BERLIN", "CLOCK"})
    return frozenset(out)


def ioc(text: str) -> float:
    """Index of coincidence x26. English prose ~1.73; random ~1.00."""
    n = len(text)
    if n < 2:
        return 0.0
    counts = Counter(text)
    s = sum(c * (c - 1) for c in counts.values())
    return 26.0 * s / (n * (n - 1))


def chi2(text: str) -> float:
    """Chi-squared distance to English monograms (lower = more English-like)."""
    n = len(text)
    if n == 0:
        return float("inf")
    counts = Counter(text)
    total = 0.0
    for i in range(26):
        expected = _ENG_P[i] * n
        observed = counts.get(chr(65 + i), 0)
        if expected > 0:
            total += (observed - expected) ** 2 / expected
    return total


def word_coverage(text: str) -> float:
    """Fraction of letters covered by a maximal tiling of dictionary words.

    DP over positions: best[i] = most letters of text[i:] coverable. A readable
    English plaintext tiles near 1.0 even without spaces; noise stays low.
    """
    words = _words()
    n = len(text)
    best = [0] * (n + 1)
    for i in range(n - 1, -1, -1):
        b = best[i + 1]  # leave text[i] uncovered
        hi = min(_MAX_WORD, n - i)
        for ln in range(_MIN_WORD, hi + 1):
            if text[i:i + ln] in words:
                cand = ln + best[i + ln]
                if cand > b:
                    b = cand
        best[i] = b
    return best[0] / n if n else 0.0


def english_score(text: str) -> float:
    """Blended readability score (higher = better).

    Word coverage dominates (strongest signal for spaceless plaintext); a
    quadgram term breaks ties among partial-English candidates. IoC nudges
    toward English-like letter distribution.
    """
    cov = word_coverage(text)
    io = ioc(text)
    try:
        from quadgrams import quadgram_score
        # quad is ~-4.5 (English) .. -8 (noise); map to a small positive bonus.
        quad_bonus = max(0.0, 8.0 + quadgram_score(text))  # 0..~3.5
    except Exception:
        quad_bonus = 0.0
    return 100.0 * cov + 10.0 * max(0.0, io - 1.0) + 5.0 * quad_bonus


if __name__ == "__main__":
    samples = {
        "english": "THEQUICKBROWNFOXJUMPSOVERTHELAZYDOG",
        "k4crib":  "EASTNORTHEASTBERLINCLOCK",
        "random":  "XJQZKWVBYFPMLGHCDNRUTOASEIXJQZKWVBY",
    }
    for name, s in samples.items():
        print(f"{name:8} cov={word_coverage(s):.2f} ioc={ioc(s):.2f} "
              f"chi2={chi2(s):7.1f} score={english_score(s):.1f}")
