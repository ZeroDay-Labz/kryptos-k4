"""
Evaluate a claimed full K4 plaintext.

Given a 97-letter candidate, derive the complete keystream under every
alphabet/arithmetic combination and look for structure a real hand cipher would
leave: a repeating period, an autokey relation, or a keystream that is itself
English (running key). Each statistic is compared with the same statistic on
shuffled keystreams, so "structure" means "beats chance", not "looks nice".

Usage: python candidate.py [PLAINTEXT]
"""
from __future__ import annotations

import random
import sys
from collections import Counter

from kryptos import CIPHERTEXT, matches_cribs
from frontier import ALPHAS, COMBOS, N, _shift
from quadgrams import quadgram_score

# Unverified public reconstruction (solvekryptos.com). Only the 24 crib letters
# are artist-confirmed; the authentic plaintext is not public.
RECONSTRUCTION = ("THECOMPASSROSEISHEREXEASTNORTHEASTTHISISYOURPOSITIONX"
                  "COMMISSIONBERLINCLOCKWHICHISNORTHEASTOFHEREX")


def keystream(pt: str, pa: str, ca: str, mode: str) -> list[int]:
    pr = {ch: i for i, ch in enumerate(ALPHAS[pa])}
    cr = {ch: i for i, ch in enumerate(ALPHAS[ca])}
    return [_shift(mode, pr[p], cr[c]) for p, c in zip(pt, CIPHERTEXT)]


def best_period(s: list[int]) -> tuple[float, int]:
    """Max over L of the fraction of positions agreeing with their slot's mode,
    corrected for the free parameters (L slots)."""
    best = (0.0, 0)
    for L in range(1, 33):
        agree = sum(max(Counter(s[i::L]).values()) for i in range(L))
        score = (agree - L) / (N - L)
        best = max(best, (score, L))
    return best


def best_autokey(s: list[int], pt: str) -> tuple[float, str]:
    best = (0.0, "")
    for xname, xa in ALPHAS.items():
        xr = {ch: i for i, ch in enumerate(xa)}
        for src_name, src in (("plaintext", pt), ("ciphertext", CIPHERTEXT)):
            for lag in range(1, 49):
                d = Counter((s[i] - xr[src[i - lag]]) % 26 for i in range(lag, N))
                frac = max(d.values()) / (N - lag)
                best = max(best, (frac, f"{src_name} lag={lag} keyalpha={xname}"))
    return best


def best_key_english(s: list[int]) -> tuple[float, str]:
    best = (-99.0, "")
    for xa in ALPHAS.values():
        for off in range(26):
            text = "".join(xa[(v + off) % 26] for v in s)
            best = max(best, (quadgram_score(text), text))
    return best


def null(stat, s, trials=200, seed=1):
    rng = random.Random(seed)
    vals = []
    for _ in range(trials):
        t = s[:]
        rng.shuffle(t)
        vals.append(stat(t))
    return max(vals)


def evaluate(pt: str) -> None:
    assert len(pt) == N and pt.isalpha(), "need 97 letters"
    print(f"candidate: {pt}")
    print(f"matches confirmed cribs: {matches_cribs(pt)}")
    print(f"{'combo':12} {'period score (L)':>18} {'null max':>9} "
          f"{'autokey frac':>13} {'null max':>9} {'key quadgram':>13} {'null max':>9}")
    for pa, ca, mode in COMBOS:
        s = keystream(pt, pa, ca, mode)
        p, L = best_period(s)
        a, adesc = best_autokey(s, pt)
        q, qtext = best_key_english(s)
        pn = null(lambda t: best_period(t)[0], s, 100)
        an = null(lambda t: best_autokey(t, pt)[0], s, 30)
        qn = null(lambda t: best_key_english(t)[0], s, 30)
        flag = " <-- beats null" if (p > pn or a > an or q > qn) else ""
        print(f"{pa}/{ca}/{mode:5} {p:>12.3f} (L={L:2d}) {pn:>9.3f} "
              f"{a:>13.3f} {an:>9.3f} {q:>13.2f} {qn:>9.2f}{flag}")
    s = keystream(pt, "A", "A", "vig")
    print("keystream (A/A/vig):", "".join(chr(65 + v) for v in s))
    s = keystream(pt, "K", "K", "vig")
    print("keystream (K/K/vig):", "".join(ALPHAS["K"][v] for v in s))


if __name__ == "__main__":
    evaluate(sys.argv[1].upper() if len(sys.argv) > 1 else RECONSTRUCTION)
