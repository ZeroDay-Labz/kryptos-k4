"""
Black-box diagnosis of K4: which kind of cipher leaves fingerprints like these?

Instead of assuming a method and testing it, measure statistical fingerprints of
the K4 ciphertext and of the 24 known plaintext/ciphertext pairs, then:

  1. permutation test - how unusual is each fingerprint for a random cipher?
     (reproduces the Monte Carlo figures in Bean, "Cryptodiagnosis of Kryptos K4")
  2. family simulation - encrypt thousands of English messages (with the same
     crib words at the same positions) under each candidate cipher family and
     count how often that family reproduces K4's fingerprints.

A family that almost never produces a fingerprint is a poor suspect; one that
produces all of them often is a good one. This narrows the *kind* of method
without needing its key.

Run:  python blackbox.py [samples]
"""
from __future__ import annotations

import os
import random
import re
import sys
from collections import Counter
from multiprocessing import get_context

from kryptos import CIPHERTEXT, ALPHABET, KRYPTOS_KEYED, keyed_alphabet
from frontier import CRIB, N
from gromark import transposed_alphabet

CTI = [ord(c) - 65 for c in CIPHERTEXT]
CRIB_POS = [i for i, _ in CRIB]
CRIB_PI = [ord(P) - 65 for _, P in CRIB]
KI = [ord(c) - 65 for c in KRYPTOS_KEYED]
KR = [KRYPTOS_KEYED.index(chr(65 + x)) for x in range(26)]
CACHE = os.path.expanduser("~/.cache/krypto_k4/prose_letters.txt")


# --- fingerprints -----------------------------------------------------------------

def ic(ct):
    n = len(ct)
    return sum(v * (v - 1) for v in Counter(ct).values()) / (n * (n - 1))


def vertical_repeats(ct, width=21):
    """Number of distinct vertical letter pairs (i, i+width) that occur more than once."""
    c = Counter((ct[i], ct[i + width]) for i in range(len(ct) - width))
    return sum(1 for v in c.values() if v > 1)


def doublet_alignment(ct, width=7):
    """Most doubled letters (XX) that start in the same column at the given width."""
    cols = Counter(i % width for i in range(len(ct) - 1) if ct[i] == ct[i + 1])
    return max(cols.values()) if cols else 0


def _dist(a, b):
    d = (a - b) % 26
    return min(d, 26 - d)


def near_pairs(ct, limit=3):
    """Crib letters whose ciphertext letter is within `limit` places in the A-Z alphabet."""
    return sum(1 for i, p in zip(CRIB_POS, CRIB_PI) if _dist(ct[i], p) <= limit)


def repeat_spread(ct):
    """Mean A-Z distance between the ciphertext letters standing for the same crib letter."""
    by = {}
    for i, p in zip(CRIB_POS, CRIB_PI):
        by.setdefault(p, []).append(ct[i])
    d = [_dist(a, b) for v in by.values() for k, a in enumerate(v) for b in v[k + 1:]]
    return sum(d) / len(d)


# (name, function, direction in which K4 is "extreme")
STATS = [
    ("flat letter frequencies (IC <= K4's)", ic, "le"),
    ("repeated vertical pairs at width 21", vertical_repeats, "ge"),
    ("doubled letters aligned at width 7", doublet_alignment, "ge"),
    ("clue letters within 3 places of their cipher letter", near_pairs, "ge"),
    ("same clue letter -> nearby cipher letters", repeat_spread, "le"),
]
K4 = [f(CTI) for _, f, _ in STATS]


def _extreme(values):
    return [(v <= k if d == "le" else v >= k) for v, k, (_, _, d) in zip(values, K4, STATS)]


# --- English plaintext for simulation -----------------------------------------------

def prose_letters() -> str:
    if os.path.exists(CACHE):
        return open(CACHE).read()
    out, total = [], 0
    for root in ("/usr/share/doc", "/usr/share/licenses"):
        for dirpath, _, files in os.walk(root):
            for f in files:
                if total > 3_000_000 or not re.search(r"(README|NEWS|\.txt$|\.md$)", f, re.I):
                    continue
                try:
                    text = open(os.path.join(dirpath, f), encoding="utf-8", errors="ignore").read(200_000)
                except OSError:
                    continue
                for para in re.split(r"\n\s*\n", text):
                    words = re.findall(r"[A-Za-z]+", para)
                    if len(words) >= 12 and sum(map(len, words)) > 0.8 * len("".join(para.split())):
                        s = "".join(words).upper()
                        out.append(s)
                        total += len(s)
    os.makedirs(os.path.dirname(CACHE), exist_ok=True)
    blob = "".join(out)
    open(CACHE, "w").write(blob)
    return blob


def _plaintext(rng, prose):
    a = rng.randrange(len(prose) - N)
    pt = [ord(c) - 65 for c in prose[a:a + N]]
    for i, p in zip(CRIB_POS, CRIB_PI):
        pt[i] = p
    return pt


# --- cipher families ------------------------------------------------------------------

def _rank(alpha):
    r = [0] * 26
    for i, ch in enumerate(alpha):
        r[ord(ch) - 65] = i
    return r


def _word(rng, words):
    return rng.choice(words)


def _mixed(rng, words):
    w = _word(rng, words)
    return keyed_alphabet(w) if rng.random() < 0.5 else transposed_alphabet(w)


def _lagged(rng, base, n=5):
    k = [rng.randrange(base) for _ in range(n)]
    while not any(k):
        k = [rng.randrange(base) for _ in range(n)]
    while len(k) < N:
        k.append((k[-n] + k[-n + 1]) % base)
    return k


def _tableau(pt, key, pa, ca):
    pr = _rank(pa)
    cai = [ord(c) - 65 for c in ca]
    return [cai[(pr[p] + k) % 26] for p, k in zip(pt, key)]


def fam_random(pt, rng, words, prose):
    return [rng.randrange(26) for _ in pt]


def fam_vigenere(pt, rng, words, prose):
    w = _word(rng, words)
    return [(p + ord(w[i % len(w)]) - 65) % 26 for i, p in enumerate(pt)]


def fam_k1(pt, rng, words, prose):
    w = _word(rng, words)
    return [KI[(KR[p] + KR[ord(w[i % len(w)]) - 65]) % 26] for i, p in enumerate(pt)]


def fam_quag_any(pt, rng, words, prose):
    w = _word(rng, words)
    pa, ca = _mixed(rng, words), _mixed(rng, words)
    return _tableau(pt, [ord(w[i % len(w)]) - 65 for i in range(N)], pa, ca)


def fam_autokey(pt, rng, words, prose):
    w = [ord(c) - 65 for c in _word(rng, words)]
    key = w + pt
    return [(p + key[i]) % 26 for i, p in enumerate(pt)]


def fam_running(pt, rng, words, prose):
    a = rng.randrange(len(prose) - N)
    return [(p + ord(prose[a + i]) - 65) % 26 for i, p in enumerate(pt)]


def fam_gronsfeld(pt, rng, words, prose):
    n = rng.randrange(5, 13)
    d = [rng.randrange(10) for _ in range(n)]
    return [(p + d[i % n]) % 26 for i, p in enumerate(pt)]


def _gromark(base, plain, cipher):
    def f(pt, rng, words, prose):
        pa = ALPHABET if plain == "A" else KRYPTOS_KEYED if plain == "K" else _mixed(rng, words)
        ca = ALPHABET if cipher == "A" else KRYPTOS_KEYED if cipher == "K" else _mixed(rng, words)
        return _tableau(pt, _lagged(rng, base), pa, ca)
    return f


def fam_transp_vig(pt, rng, words, prose):
    w = rng.randrange(5, 10)
    order = list(range(w))
    rng.shuffle(order)
    tr = [pt[i] for c in order for i in range(c, N, w)]
    kw = _word(rng, words)
    return [(p + ord(kw[i % len(kw)]) - 65) % 26 for i, p in enumerate(tr)]


def fam_hill2(pt, rng, words, prose):
    while True:
        a, b, c, d = (rng.randrange(26) for _ in range(4))
        det = (a * d - b * c) % 26
        if det % 2 and det % 13:
            break
    out = list(pt)
    for i in range(0, N - 1, 2):
        out[i], out[i + 1] = (a * pt[i] + b * pt[i + 1]) % 26, (c * pt[i] + d * pt[i + 1]) % 26
    return out


FAMILIES = [
    ("random letters (one-time pad)", fam_random),
    ("Vigenere, keyword key", fam_vigenere),
    ("K1/K2 method (KRYPTOS tableau)", fam_k1),
    ("Quagmire, two keyword alphabets", fam_quag_any),
    ("autokey", fam_autokey),
    ("running key (English text)", fam_running),
    ("Gronsfeld (repeating digits)", fam_gronsfeld),
    ("Gromark base 10, A-Z / A-Z", _gromark(10, "A", "A")),
    ("Gromark base 10, A-Z / keyword", _gromark(10, "A", "kw")),
    ("Gromark base 10, keyword / A-Z", _gromark(10, "kw", "A")),
    ("Gromark base 10, keyword / keyword", _gromark(10, "kw", "kw")),
    ("Gromark base 10, KRYPTOS / A-Z", _gromark(10, "K", "A")),
    ("Gromark base 5, keyword / A-Z", _gromark(5, "kw", "A")),
    ("Gromark base 3, keyword / A-Z", _gromark(3, "kw", "A")),
    ("Gromark base 2, keyword / A-Z", _gromark(2, "kw", "A")),
    ("columnar transposition + Vigenere", fam_transp_vig),
    ("Hill 2x2", fam_hill2),
]


def _simulate(args):
    fi, samples, seed = args
    rng = random.Random(seed)
    prose = prose_letters()
    words = _WORDS
    name, fam = FAMILIES[fi]
    counts = [0] * len(STATS)
    crib_both = cipher_both = everything = 0
    for _ in range(samples):
        ct = fam(_plaintext(rng, prose), rng, words, prose)
        e = _extreme([f(ct) for _, f, _ in STATS])
        for k, v in enumerate(e):
            counts[k] += v
        cipher_both += e[1] and e[2]
        crib_both += e[3] and e[4]
        everything += all(e[1:])
    return fi, counts, cipher_both, crib_both, everything


_WORDS: list[str] = []


def _load_words():
    with open("/usr/share/dict/words", encoding="utf-8", errors="ignore") as fh:
        ws = [w.strip().upper() for w in fh]
    _WORDS[:] = [w for w in ws if 5 <= len(w) <= 12 and w.isascii() and w.isalpha()]


def _rate(k, n):
    if k == 0:
        return f"<1 in {n:,}"
    return f"1 in {n / k:,.0f}" if k * 20 < n else f"{100 * k / n:.0f}%"


def permutation_report(trials=200_000):
    print("=== K4's fingerprints, and how often a random rearrangement of its letters matches them ===")
    rng = random.Random(1)
    ct = CTI[:]
    counts = [0] * len(STATS)
    for _ in range(trials):
        rng.shuffle(ct)
        for k, v in enumerate(_extreme([f(ct) for _, f, _ in STATS])):
            counts[k] += v
    for (name, _, _), k4, c in zip(STATS, K4, counts):
        val = f"{k4:.4f}" if isinstance(k4, float) else str(k4)
        note = "(same letters, so always equal)" if name.startswith("flat") else _rate(c, trials)
        print(f"  {name:52} K4 = {val:7}  chance: {note}")


def family_report(samples=20_000, procs=17):
    _load_words()
    prose_letters()
    print(f"\n=== how often each cipher family reproduces those fingerprints ({samples:,} messages each) ===")
    head = ["flat IC", "width-21", "width-7", "near letters", "near repeats", "both crib", "all four"]
    print(f"  {'family':38}" + "".join(f"{h:>14}" for h in head))
    ctx = get_context("fork")
    with ctx.Pool(procs) as pool:
        res = sorted(pool.imap_unordered(_simulate, [(i, samples, 100 + i) for i in range(len(FAMILIES))]))
    rows = []
    for fi, counts, cipher_both, crib_both, everything in res:
        cells = [_rate(c, samples) for c in counts] + [_rate(crib_both, samples), _rate(everything, samples)]
        print(f"  {FAMILIES[fi][0]:38}" + "".join(f"{c:>14}" for c in cells))
        rows.append((FAMILIES[fi][0], counts, crib_both, everything))
    print("  columns: share of that family's ciphertexts as extreme as K4 on each fingerprint;")
    print("  'both crib' = both clue-letter fingerprints at once; 'all four' = everything except flat IC.")
    return rows


if __name__ == "__main__":
    n = int(sys.argv[1]) if len(sys.argv) > 1 else 20_000
    permutation_report()
    family_report(n)
