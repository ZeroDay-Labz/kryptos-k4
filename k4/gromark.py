"""
Gromark-family attacks on K4 (after Bean, "Cryptodiagnosis of Kryptos K4", 2021).

Gromark: a short numeric primer is expanded into a non-repeating digit key by a
lagged-Fibonacci rule (k[i+n] = k[i] + k[i+1] mod base), and each plaintext
letter is shifted by its key digit between a plain and a cipher alphabet, which
may be keyword-mixed:      C = cipher_alpha[ rank_plain(P) + k ]  (mod 26)

G1  known keyword alphabets, ANY small-digit key (no rule assumed):
    the 24 forced shifts must all fall in a window of `base` consecutive values.
    Chance of a window <= 10 is ~3e-9 per alphabet pair, so this is decisive.

G2  ARBITRARY mixed alphabets, standard key rule: for each primer, the cribs
    link plain and cipher ranks (c[C] - p[P] = k). A primer survives only if no
    cycle is contradicted and no two letters of one alphabet are forced onto the
    same rank. Bean reports exactly 39 survivors for base 10 / 5 digits; this
    code must reproduce that.

Run:  python gromark.py [g1|g2|all]
"""
from __future__ import annotations

import itertools
import sys
import time
from collections import defaultdict
from multiprocessing import Pool

from kryptos import CIPHERTEXT, ALPHABET, KRYPTOS_KEYED, keyed_alphabet
from frontier import CRIB, N

CT = CIPHERTEXT


# --- alphabets ------------------------------------------------------------------

def transposed_alphabet(word: str) -> str:
    """ACA-style mixed alphabet: keyed alphabet written under the keyword, then
    read off by columns in alphabetical order of the keyword letters."""
    ka = keyed_alphabet(word)
    w = len(set(word))
    cols = sorted(range(w), key=lambda c: ka[c])
    return "".join(ka[r] for c in cols for r in range(c, 26, w))


def window(values) -> tuple[int, int]:
    """Smallest run of consecutive residues mod 26 containing all values.
    Returns (size, start)."""
    vs = sorted(set(values))
    if len(vs) == 1:
        return 1, vs[0]
    best_gap, start = -1, 0
    for a, b in zip(vs, vs[1:] + [vs[0] + 26]):
        if b - a > best_gap:
            best_gap, start = b - a, b % 26
    return 26 - best_gap + 1, start


def forced_shifts(pa: str, ca: str, sign: int) -> list[int]:
    """sign=-1: C = ca[p + k] (Vigenere-type).  sign=+1: C = ca[k - p] (Beaufort-type)."""
    pr = {ch: i for i, ch in enumerate(pa)}
    cr = {ch: i for i, ch in enumerate(ca)}
    return [(cr[CT[i]] + sign * pr[P]) % 26 for i, P in CRIB]


# --- G1 ---------------------------------------------------------------------------

def _g1_task(words):
    out = []
    for w in words:
        for kind, x in (("keyed", keyed_alphabet(w)), ("transposed", transposed_alphabet(w))):
            for pa, ca, role in ((ALPHABET, x, "plain=A-Z cipher=kw"), (x, ALPHABET, "plain=kw cipher=A-Z"),
                                 (x, x, "both=kw"), (KRYPTOS_KEYED, x, "plain=KRYPTOS cipher=kw"),
                                 (x, KRYPTOS_KEYED, "plain=kw cipher=KRYPTOS")):
                for sign in (-1, 1):
                    size, start = window(forced_shifts(pa, ca, sign))
                    if size <= 12:
                        out.append((size, w, kind, role, "vig" if sign < 0 else "beau", pa, ca, sign, start))
    return len(words), out


def g1_report(procs=30):
    print("\n=== G1: keyword alphabets, any small-digit key ===")
    print("  built-in alphabets (window size = smallest base that fits):")
    for pn, pa in (("A-Z", ALPHABET), ("KRYPTOS", KRYPTOS_KEYED)):
        for cn, ca in (("A-Z", ALPHABET), ("KRYPTOS", KRYPTOS_KEYED)):
            for sign in (-1, 1):
                print(f"    plain={pn:7} cipher={cn:7} {'vig ' if sign < 0 else 'beau'} "
                      f"window={window(forced_shifts(pa, ca, sign))[0]}")
    words, seen = [], set()
    with open("/usr/share/dict/words", encoding="utf-8", errors="ignore") as fh:
        for line in fh:
            w = line.strip().upper()
            if 3 <= len(w) <= 24 and w.isascii() and w.isalpha():
                key = (keyed_alphabet(w), len(set(w)))
                if key not in seen:
                    seen.add(key)
                    words.append(w)
    chunks = [words[i:i + 3000] for i in range(0, len(words), 3000)]
    t0 = time.time()
    total, hits = 0, []
    with Pool(procs) as pool:
        for n, h in pool.imap_unordered(_g1_task, chunks):
            total += n
            hits += h
    hits.sort()
    print(f"  dictionary keywords: {total:,} x 2 mixing styles x 5 roles x 2 arithmetics "
          f"({time.time() - t0:.0f}s)")
    print(f"  smallest window found: {hits[0][0] if hits else '>12'}   "
          f"(a base-10 Gromark needs <= 10; chance gives ~13+)")
    for size, w, kind, role, md, pa, ca, sign, start in hits[:8]:
        s = forced_shifts(pa, ca, sign)
        digits = "".join("0123456789ABC"[(v - start) % 26] for v in s)
        print(f"    window={size} {w} ({kind}) {role} {md}  digits {digits[:13]} | {digits[13:]}")
    return hits


# --- G2 ---------------------------------------------------------------------------

def _crib_graph():
    """Spanning forest over nodes ('p', letter) / ('c', letter) joined by cribs."""
    adj = defaultdict(list)
    for j, (i, P) in enumerate(CRIB):
        adj[("p", P)].append((("c", CT[i]), j, +1))    # c = p + k
        adj[("c", CT[i])].append((("p", P), j, -1))    # p = c - k
    order, seen, used = [], set(), set()
    for root in sorted(adj):
        if root in seen:
            continue
        seen.add(root)
        order.append((root, None, None, 0))
        stack = [root]
        while stack:
            u = stack.pop()
            for v, j, sgn in adj[u]:
                if v not in seen:
                    seen.add(v)
                    used.add(j)
                    order.append((v, u, j, sgn))
                    stack.append(v)
    extra = [j for j in range(len(CRIB)) if j not in used]      # cycle-closing cribs
    return order, extra


_ORDER, _EXTRA = _crib_graph()
_POS = [i for i, _ in CRIB]


def primer_ok(key) -> bool:
    """Can SOME pair of mixed alphabets turn the cribs into the ciphertext under `key`?"""
    val, comp = {}, {}
    cid = -1
    for node, parent, j, sgn in _ORDER:
        if parent is None:
            cid += 1
            val[node], comp[node] = 0, cid
        else:
            val[node] = (val[parent] + sgn * key[_POS[j]]) % 26
            comp[node] = cid
    for j in _EXTRA:
        i, P = CRIB[j]
        if (val[("c", CT[i])] - val[("p", P)] - key[i]) % 26:
            return False
    seen = set()
    for (side, _), v in val.items():
        tag = (side, comp[(side, _)], v)
        if tag in seen:
            return False            # two letters of one alphabet on the same rank
        seen.add(tag)
    return True


def expand(primer, base, taps=(0, 1), length=N):
    k = list(primer)
    n = len(primer)
    a, b = taps
    while len(k) < length:
        k.append((k[len(k) - n + a] + k[len(k) - n + b]) % base)
    return k


def _g2_task(args):
    base, n, taps, lead = args
    out = []
    count = 0
    for rest in itertools.product(range(base), repeat=n - len(lead)):
        primer = lead + rest
        if not any(primer):
            continue
        count += 1
        key = expand(primer, base, taps)
        if key[27] != key[65]:       # plain R -> cipher P at both positions
            continue
        if primer_ok(key):
            out.append(primer)
    return count, out


def g2_search(base, n, taps=(0, 1), procs=30):
    depth = min(n - 1, 2 if base ** n > 200_000 else 1)
    tasks = [(base, n, taps, lead) for lead in itertools.product(range(base), repeat=depth)]
    total, survivors = 0, []
    with Pool(procs) as pool:
        for c, s in pool.imap_unordered(_g2_task, tasks):
            total += c
            survivors += s
    return total, sorted(survivors)


def g2_report(max_keys=20_000_000):
    print("\n=== G2: arbitrary mixed alphabets, key rule k[i+n] = k[i] + k[i+1] mod base ===")
    total, surv = g2_search(10, 5)
    print(f"  validation, base 10 / 5 digits: {len(surv)} survivors of {total:,} "
          f"(Bean reports 39)")
    table = {}
    for base in range(3, 27):
        for n in range(2, 9):
            if base ** n > max_keys:
                continue
            t0 = time.time()
            total, surv = g2_search(base, n)
            table[(base, n)] = surv
            print(f"  base {base:2d}  primer length {n}: {len(surv):6d} of {total:>10,} primers survive "
                  f"({time.time() - t0:.0f}s)", flush=True)
    return table





# --- G3: one keyword alphabet + one arbitrary alphabet, any lagged-Fibonacci key ----
#
# If the plain alphabet is known, every cipher letter that stands for two different
# crib letters fixes a difference of key digits:  p[P1] - p[P2] = k2 - k1.  The 8-9
# such differences form a signature; a primer is compatible with a keyword alphabet
# only if their signatures match (chance 26^-8). Signatures of all dictionary
# alphabets go in a hash map, so every primer is checked against every keyword in
# one lookup. Likewise with a known cipher alphabet and an arbitrary plain one.

import math
import multiprocessing as mp

import quadgrams as _q

_ENG = [8.17, 1.49, 2.78, 4.25, 12.70, 2.23, 2.02, 6.09, 6.97, 0.15, 0.77, 4.03, 2.41,
        6.75, 7.51, 1.93, 0.10, 5.99, 6.33, 9.06, 2.76, 0.98, 2.36, 0.15, 1.97, 0.07]
_LLR = {chr(65 + i): math.log(v / 100 * 26) for i, v in enumerate(_ENG)}


def _chain_pairs(group_by_cipher: bool):
    groups = defaultdict(list)
    for j, (i, P) in enumerate(CRIB):
        groups[CT[i] if group_by_cipher else P].append(j)
    pairs = []
    for js in groups.values():
        for a, b in zip(js, js[1:]):
            pairs.append((a, b))
    return pairs


_PAIRS_PK = _chain_pairs(True)     # plain alphabet known: same cipher letter
_PAIRS_CK = _chain_pairs(False)    # cipher alphabet known: same plain letter
_KP = [(CRIB[a][0], CRIB[b][0]) for a, b in _PAIRS_PK]
_KC = [(CRIB[a][0], CRIB[b][0]) for a, b in _PAIRS_CK]
_MAXPOS = max(_POS) + 1

_MAP_P: dict = {}
_MAP_C: dict = {}


def _build_maps():
    names = {}
    with open("/usr/share/dict/words", encoding="utf-8", errors="ignore") as fh:
        for line in fh:
            w = line.strip().upper()
            if 3 <= len(w) <= 24 and w.isascii() and w.isalpha():
                names.setdefault(keyed_alphabet(w), w + " (keyed)")
                names.setdefault(transposed_alphabet(w), w + " (transposed)")
    names[ALPHABET] = "A-Z"
    names[KRYPTOS_KEYED] = "KRYPTOS (keyed)"
    for alpha, name in names.items():
        r = {ch: i for i, ch in enumerate(alpha)}
        sp = tuple((r[CRIB[a][1]] - r[CRIB[b][1]]) % 26 for a, b in _PAIRS_PK)
        sc = tuple((r[CT[CRIB[a][0]]] - r[CT[CRIB[b][0]]]) % 26 for a, b in _PAIRS_CK)
        _MAP_P.setdefault(sp, []).append(alpha)
        _MAP_C.setdefault(sc, []).append(alpha)
    return names


def _g3_task(args):
    base, n, taps, lead = args
    a, b = taps
    out, count = [], 0
    for rest in itertools.product(range(base), repeat=n - len(lead)):
        k = list(lead + rest)
        if not any(k):
            continue
        count += 1
        for t in range(n, _MAXPOS):
            k.append((k[t - n + a] + k[t - n + b]) % base)
        d = tuple((k[y] - k[x]) % 26 for x, y in _KP)        # k2 - k1
        if d in _MAP_P:
            out.append((base, n, taps, tuple(k[:n]), "plain", +1))
        d = tuple((-v) % 26 for v in d)
        if d in _MAP_P:
            out.append((base, n, taps, tuple(k[:n]), "plain", -1))
        d = tuple((k[x] - k[y]) % 26 for x, y in _KC)        # k1 - k2
        if d in _MAP_C:
            out.append((base, n, taps, tuple(k[:n]), "cipher", +1))
        d = tuple((-v) % 26 for v in d)
        if d in _MAP_C:
            out.append((base, n, taps, tuple(k[:n]), "cipher", -1))
    return count, out


_MODES = {"vig": (1, 1), "beau": (-1, 1), "var": (1, -1)}   # c = sp*p + sk*k


def _solve_candidate(key, known, alpha, mode):
    """Derive the other alphabet from the cribs; return partial plaintext or None."""
    sp, sk = _MODES[mode]
    r = {ch: i for i, ch in enumerate(alpha)}
    if known == "plain":
        cr = {}
        for i, P in CRIB:
            v = (sp * r[P] + sk * key[i]) % 26
            if cr.setdefault(CT[i], v) != v:
                return None
        if len(set(cr.values())) != len(cr):
            return None
        out = []
        for i, c in enumerate(CT):
            if c in cr:   # p = sp * (c - sk*k)   (sp is its own inverse)
                out.append(alpha[(sp * (cr[c] - sk * key[i])) % 26])
            else:
                out.append(".")
        return "".join(out)
    prk = {}                  # rank -> plain letter
    seen = {}
    for i, P in CRIB:
        v = (sp * (r[CT[i]] - sk * key[i])) % 26
        if prk.setdefault(v, P) != P or seen.setdefault(P, v) != v:
            return None
    return "".join(prk.get((sp * (r[c] - sk * key[i])) % 26, ".") for i, c in enumerate(CT))


def _score_partial(pt):
    crib_pos = set(_POS)
    new = [ch for i, ch in enumerate(pt) if ch != "." and i not in crib_pos]
    return sum(_LLR[ch] for ch in new), len(new)


def g3_report(procs=30, budget=40_000_000, bases=range(3, 27), lengths=range(2, 9)):
    print("\n=== G3: one keyword alphabet + one arbitrary alphabet, lagged-Fibonacci key ===")
    t0 = time.time()
    names = _build_maps()
    print(f"  keyword alphabets indexed: {len(names):,} ({time.time() - t0:.0f}s)")
    tasks = []
    space = 0
    for n in lengths:
        for base in bases:
            taps_all = [(a, b) for a in range(n) for b in range(a + 1, n)]
            if base ** n * len(taps_all) > budget:
                continue
            depth = 0 if base ** n < 20_000 else (1 if base ** n < 600_000 else 2)
            for taps in taps_all:
                for lead in itertools.product(range(base), repeat=depth):
                    tasks.append((base, n, taps, lead))
            space += base ** n * len(taps_all)
    print(f"  keys to test: {space:,} (bases 3-26, primer lengths 2-8, every pair of taps)")
    t0 = time.time()
    total, hits = 0, []
    ctx = mp.get_context("fork")
    with ctx.Pool(procs) as pool:
        for c, h in pool.imap_unordered(_g3_task, tasks, chunksize=4):
            total += c
            hits += h
    print(f"  tested {total:,} keys in {time.time() - t0:.0f}s; signature matches: {len(hits)}")
    rows = []
    for base, n, taps, primer, known, sign in hits:
        key = expand(primer, base, taps)
        d = (tuple((sign * (key[y] - key[x])) % 26 for x, y in _KP) if known == "plain"
             else tuple((sign * (key[x] - key[y])) % 26 for x, y in _KC))
        for alpha in (_MAP_P if known == "plain" else _MAP_C)[d]:
            for mode in _MODES:
                pt = _solve_candidate(key, known, alpha, mode)
                if pt is None:
                    continue
                llr, cnt = _score_partial(pt)
                rows.append((llr, cnt, pt, base, n, taps, primer, known, names[alpha], mode))
    rows.sort(reverse=True)
    print(f"  candidates that reproduce both cribs exactly: {len(rows)}")
    print("  ranked by how English the newly decoded letters are (LLR vs random; real text of")
    print("  ~30 new letters would score about +12):")
    for llr, cnt, pt, base, n, taps, primer, known, name, mode in rows[:15]:
        print(f"   LLR={llr:+6.1f} new={cnt:2d}  base {base} primer {''.join(map(str, primer)) if base <= 10 else primer} "
              f"taps {taps} {mode}  {known} alphabet = {name}")
        print(f"      {pt}")
    return rows


if __name__ == "__main__":
    what = sys.argv[1] if len(sys.argv) > 1 else "all"
    if what in ("g1", "all"):
        g1_report()
    if what in ("g2", "all"):
        g2_report()
    if what in ("g3", "all"):
        g3_report()
