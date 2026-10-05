"""
Fractionation tests for K4: Trifid (base 3, 27 symbols), Bifid on a 6x6 square, and
five-bit fractionation. Written first for Trifid:

Why: Scheidt spoke of changing the "language base", counted 98 characters (the 97
letters plus the "?"), and said special characters must be taken into account.
With the "?" K4 has exactly 27 symbols, the size of a Trifid cube. Trifid writes
each symbol as three base-3 digits (layer, row, column of a 3x3x3 cube), lays the
digits of a block of p symbols out in three rows, and reads them off in threes.

The test is exact and needs no keyword: the unknown is the whole cube. Each crib
letter forces equalities between digits of ciphertext symbols and digits of
plaintext symbols. A block length is possible only if all 27 symbols can still be
given distinct digit-triples.

Variants: 97 letters, or 98 with the leading "?" as the 27th symbol; and the two
directions (K4 = encrypt(plaintext) or K4 = decrypt(plaintext)).

Run:  python trifid.py
"""
from __future__ import annotations

import random
import sys

from kryptos import CIPHERTEXT, CRIBS

EXTRA = 26                      # index of the 27th symbol


def _setup(variant):
    off = 1 if variant == 98 else 0
    ct = ([EXTRA] if variant == 98 else []) + [ord(c) - 65 for c in CIPHERTEXT]
    pt = {a - 1 + i + off: ord(ch) - 65 for (a, b), w in CRIBS.items() for i, ch in enumerate(w)}
    return ct, pt


class _UF:
    def __init__(self, n):
        self.p = list(range(n))

    def find(self, x):
        while self.p[x] != x:
            self.p[x] = self.p[self.p[x]]
            x = self.p[x]
        return x

    def union(self, a, b):
        self.p[self.find(a)] = self.find(b)


def constraints(ct, pt, period, direction, k=3, nsym=27, offset=0):
    """Union-find over (symbol, digit) variables after applying every crib equality.
    `offset` > 0 puts a short first block of that length before the full blocks."""
    uf = _UF(nsym * k)
    n = len(ct)
    used = 0
    starts = ([0] if offset else []) + list(range(offset, n, period))
    for bi, s in enumerate(starts):
        L = (starts[bi + 1] if bi + 1 < len(starts) else n) - s
        for j in range(L):
            for t in range(k):
                idx = k * j + t
                row, pos = idx // L, idx % L
                if direction == "encrypt":      # cipher symbol j takes digit `row` of plain symbol pos
                    if s + pos in pt:
                        uf.union(k * ct[s + j] + t, k * pt[s + pos] + row)
                        used += 1
                else:                           # the roles of plaintext and ciphertext swap
                    if s + j in pt:
                        uf.union(k * pt[s + j] + t, k * ct[s + pos] + row)
                        used += 1
    return uf, used


def _matchable(sym_digits, b, k):
    nsym = len(sym_digits)
    """Can the 27 symbols get distinct digit-tuples given some fixed digits (None = free)?"""
    import itertools
    tuples = list(itertools.product(range(b), repeat=k))
    options = [[i for i, tr in enumerate(tuples)
                if all(d is None or d == x for d, x in zip(digs, tr))] for digs in sym_digits]
    owner = [-1] * len(tuples)

    def augment(s, seen):
        for i in options[s]:
            if i not in seen:
                seen.add(i)
                if owner[i] < 0 or augment(owner[i], seen):
                    owner[i] = s
                    return True
        return False

    return all(augment(s, set()) for s in sorted(range(nsym), key=lambda s: len(options[s])))


def satisfiable(uf, node_limit=300_000, b=3, k=3, nsym=27):
    """True/False, or None if the search budget ran out."""
    import itertools
    cls = [uf.find(v) for v in range(nsym * k)]
    members = {}
    for v, c in enumerate(cls):
        members.setdefault(c, []).append(v)
    shared = sorted((c for c, m in members.items() if len(m) > 1), key=lambda c: -len(members[c]))
    subsets = [sub for r in range(1, k + 1) for sub in itertools.combinations(range(k), r)]
    value = {}
    nodes = [0]

    def digits():
        return [tuple(value.get(cls[k * s + t]) for t in range(k)) for s in range(nsym)]

    def feasible():
        seen = {}
        for trip in digits():
            for sub in subsets:
                if all(trip[a] is not None for a in sub):
                    key = (sub, tuple(trip[a] for a in sub))
                    seen[key] = seen.get(key, 0) + 1
                    if seen[key] > b ** (k - len(sub)):
                        return False
        return True

    def dfs(i):
        nodes[0] += 1
        if nodes[0] > node_limit:
            raise TimeoutError
        if i == len(shared):
            return _matchable(digits(), b, k)
        for v in range(b):
            value[shared[i]] = v
            if feasible() and dfs(i + 1):
                return True
        value.pop(shared[i], None)
        return False

    try:
        return dfs(0)
    except TimeoutError:
        return None


# (name, base, digits per symbol, number of symbols in the square/cube)
SYSTEMS = [("Trifid (base 3, 27-symbol cube)", 3, 3, 27),
           ("Bifid on a 6x6 square (base 6)", 6, 2, 36),
           ("five-bit fractionation (base 2, 32 codes)", 2, 5, 32)]


def report(max_period=98, null_trials=30):
    rng = random.Random(9)
    cols = [(v, d) for v in (97, 98) for d in ("encrypt", "decrypt")]
    leads = []
    for name, b, k, nsym in SYSTEMS:
        print(f"\n=== {name} with ANY arrangement: which block lengths can produce the clues? ===")
        tally = {c: [0, 0, 0] for c in cols}          # pass, fail, undecided
        null_pass = {c: 0 for c in cols}
        for p in range(2, max_period + 1):
            for v, d in cols:
                ct, pt = _setup(v)
                # every alignment of the block boundaries, not just blocks starting at letter 1
                verdicts = [satisfiable(constraints(ct, pt, p, d, k, nsym, off)[0], b=b, k=k, nsym=nsym)
                            for off in range(p)]
                ok = True if True in verdicts else (None if None in verdicts else False)
                tally[(v, d)][0 if ok else (2 if ok is None else 1)] += 1
                passes = 0
                if ok is not False:
                    for _ in range(null_trials):
                        fake = ct[:]
                        letters = [x for x in fake if x != EXTRA]
                        rng.shuffle(letters)
                        it = iter(letters)
                        fake = [x if x == EXTRA else next(it) for x in fake]
                        passes += bool(satisfiable(constraints(fake, pt, p, d, k, nsym)[0], 20_000, b, k, nsym))
                    rate = passes / null_trials
                    print(f"  block length {p}, {v} chars, {d}: K4 {'passes' if ok else 'undecided'}; "
                          f"random ciphertext passes {rate:.0%} of the time", flush=True)
                    if ok and rate <= 0.05:
                        leads.append((name, p, v, d, rate))
        for (v, d), (yes, no, unk) in tally.items():
            print(f"  {v} chars, {d:7}: impossible (any block alignment) at {no} of {max_period - 1} block lengths, "
                  f"possible at {yes}, undecided at {unk}")
    print("\nblock lengths K4 passes but random text almost never does:", leads or "none")
    return leads


def control():
    """A planted Trifid message must pass at its own block length."""
    rng = random.Random(2)
    cube = list(range(27))
    rng.shuffle(cube)                           # cube[symbol] = position 0..26
    pos = {s: divmod(cube[s], 9)[0:1] + divmod(cube[s] % 9, 3) for s in range(27)}
    inv = {v: k for k, v in pos.items()}
    ct_real, pt_known = _setup(98)
    n, period = 98, 9
    plain = [rng.randrange(26) for _ in range(n)]
    for i, p in pt_known.items():
        plain[i] = p
    out = []
    for s in range(0, n, period):
        blk = plain[s:s + period]
        stream = [pos[x][r] for r in range(3) for x in blk]
        out += [inv[tuple(stream[3 * j:3 * j + 3])] for j in range(len(blk))]
    ok = satisfiable(constraints(out, pt_known, period, "encrypt")[0])
    wrong = [p for p in range(2, 15) if p != period
             and satisfiable(constraints(out, pt_known, p, "encrypt")[0], 50_000)]
    # Bifid control: a full 6x6 square (36 symbols), block length 7
    cells = list(range(36))
    rng.shuffle(cells)
    rc = {sym: divmod(cells[sym], 6) for sym in range(36)}
    back = {v: sym for sym, v in rc.items()}
    ct97, pt97 = _setup(97)
    plain2 = [rng.randrange(26) for _ in range(97)]
    for i, p in pt97.items():
        plain2[i] = p
    out2 = []
    for s0 in range(0, 97, 7):
        blk = plain2[s0:s0 + 7]
        stream = [rc[x][0] for x in blk] + [rc[x][1] for x in blk]
        out2 += [back[tuple(stream[2 * j:2 * j + 2])] for j in range(len(blk))]
    ok2 = satisfiable(constraints(out2, pt97, 7, "encrypt", 2, 36)[0], b=6, k=2, nsym=36)
    wrong2 = [p for p in range(2, 15) if p != 7
              and satisfiable(constraints(out2, pt97, p, "encrypt", 2, 36)[0], 50_000, 6, 2, 36)]
    print(f"[control] planted 6x6 Bifid (block length 7) passes at 7: {ok2}; "
          f"other lengths 2-14 that also pass: {wrong2}")
    ok = bool(ok) and bool(ok2)
    return bool(ok)


if __name__ == "__main__":
    assert control(), "positive control failed"
    report(int(sys.argv[1]) if len(sys.argv) > 1 else 98)
