"""
Is there ANY keyword whose alphabet turns K4's clue shifts into single digits?

blackbox.py says the 24 known letter pairs look like a cipher keyed with small
numbers over near-standard alphabets. gromark.py tried alphabets built from real
words (the dictionary, then 37.7M wordlist strings) and the best any of them
managed was 11 different shift values, where a decimal digit key needs 10.

This module removes the wordlist. A keyword alphabet is "keyword letters in some
order, then the remaining letters alphabetically" (as KRYPTOSABCDEFGH...). For
each alphabet role it searches EVERY such alphabet - any letters, any order - and
finds the smallest number base in which all 24 clue shifts would fit. That is an
exhaustive answer for this family, not a sample.

Roles:  plain A-Z / cipher keyword      plain keyword / cipher A-Z
        plain KRYPTOS / cipher keyword  plain keyword / cipher KRYPTOS
        both alphabets the same keyword
Arithmetic: cipher = plain + digit, and cipher = digit - plain.

Run:  python keyedcsp.py [max_base]
"""
from __future__ import annotations

import sys
import time

from kryptos import CIPHERTEXT, ALPHABET, KRYPTOS_KEYED, keyed_alphabet
from frontier import CRIB
from gromark import window

STD = list(range(26))
KRY = [KRYPTOS_KEYED.index(chr(65 + x)) for x in range(26)]
PAIRS = [(ord(CIPHERTEXT[i]) - 65, ord(P) - 65) for i, P in CRIB]      # (cipher letter, plain letter)

ROLES = [("plain A-Z, cipher keyword", STD, None), ("plain keyword, cipher A-Z", None, STD),
         ("plain KRYPTOS, cipher keyword", KRY, None), ("plain keyword, cipher KRYPTOS", None, KRY),
         ("both alphabets the same keyword", None, None)]


def _items(need_set):
    """Alphabet in order as clue letters and runs of letters that carry no clue."""
    items, run = [], 0
    for L in range(26):
        if L in need_set:
            if run:
                items.append(("run", run))
                run = 0
            items.append(("letter", L))
        else:
            run += 1
    if run:
        items.append(("run", run))
    remaining = [0] * (len(items) + 1)
    for i in range(len(items) - 1, -1, -1):
        remaining[i] = remaining[i + 1] + (items[i][1] if items[i][0] == "run" else 1)
    return items, remaining


def _match(domains):
    """Distinct positions for the keyword's clue letters (bipartite matching)."""
    owner = {}

    def augment(x, seen):
        for pos in domains[x]:
            if pos not in seen:
                seen.add(pos)
                if pos not in owner or augment(owner[pos], seen):
                    owner[pos] = x
                    return True
        return False

    if all(augment(x, set()) for x in sorted(domains, key=lambda x: len(domains[x]))):
        return {x: pos for pos, x in owner.items()}
    return None


def search(rank_p, rank_c, sign, base, node_limit=3_000_000):
    """Is there a keyword alphabet X for which every clue shift lies in a window of
    `base` consecutive values?  Returns (solution or None, exhausted).

    rank_p / rank_c: known rank table for that side, or None if that side uses X.
    sign=-1: shift = rank_c(C) - rank_p(P);  sign=+1: shift = rank_c(C) + rank_p(P)."""
    need = {c for c, _ in PAIRS if rank_c is None} | {p for _, p in PAIRS if rank_p is None}
    items, remaining = _items(need)
    one_sided = rank_p is not None or rank_c is not None
    exhausted = True

    for t in range(26):
        allowed = None
        if one_sided:                     # every constraint involves one unknown rank
            allowed = {}
            for x in need:
                ok = set(range(26))
                for c, p in PAIRS:
                    if rank_c is None and c == x:
                        ok &= {r for r in range(26) if (r + sign * rank_p[p] - t) % 26 < base}
                    if rank_p is None and p == x:
                        ok &= {r for r in range(26) if (rank_c[c] + sign * r - t) % 26 < base}
                allowed[x] = ok
            if any(not a for a in allowed.values()):
                continue
        for k in range(27):
            nodes = [0]
            found = [None]

            def pair_ok(rank):
                for c, p in PAIRS:
                    rc, rp = rank.get(c), rank.get(p)
                    if rc is not None and rp is not None and (rc + sign * rp - t) % 26 >= base:
                        return False
                return True

            def place(rank, kw):          # both-sides-unknown case: positions for keyword letters
                def dfs(i, used):
                    nodes[0] += 1
                    if nodes[0] > node_limit:
                        raise TimeoutError
                    if i == len(kw):
                        found[0] = dict(rank)
                        return True
                    for pos in range(k):
                        if pos not in used:
                            rank[kw[i]] = pos
                            if pair_ok(rank) and dfs(i + 1, used | {pos}):
                                return True
                            del rank[kw[i]]
                    return False
                return dfs(0, frozenset())

            def walk(i, n_kw, before, rank, kw):
                nodes[0] += 1
                if nodes[0] > node_limit:
                    raise TimeoutError
                if n_kw > k or n_kw + remaining[i] < k:
                    return False
                if i == len(items):
                    if one_sided:
                        m = _match({x: [pos for pos in allowed[x] if pos < k] for x in kw})
                        if m is None:
                            return False
                        found[0] = {**rank, **m}
                        return True
                    return place(rank, kw)
                kind, x = items[i]
                if kind == "run":
                    return any(walk(i + 1, n_kw + c, before + x, rank, kw)
                               for c in range(min(x, k - n_kw) + 1))
                r = k + (before - n_kw)                      # x stays in the alphabetical tail
                if r < 26 and (r in allowed[x] if one_sided else True):
                    rank[x] = r
                    if (one_sided or pair_ok(rank)) and walk(i + 1, n_kw, before + 1, rank, kw):
                        return True
                    del rank[x]
                if one_sided and not any(pos < k for pos in allowed[x]):
                    return False                             # x cannot sit in the keyword either
                return walk(i + 1, n_kw + 1, before + 1, rank, kw + [x])

            try:
                if walk(0, 0, 0, {}, []):
                    return (k, t, found[0]), True
            except TimeoutError:
                exhausted = False
    return None, exhausted


def search_same(sign, base, node_limit=6_000_000):
    """Both alphabets are the same keyword alphabet. Positions are chosen as each
    keyword letter is met, so every clue is checked as soon as both its letters are ranked."""
    need = {c for c, _ in PAIRS} | {p for _, p in PAIRS}
    items, remaining = _items(need)
    partners = {x: [(c, p) for c, p in PAIRS if x in (c, p)] for x in need}
    exhausted = True
    for t in range(26):
        for k in range(27):
            nodes = [0]
            rank = {}

            def fits(x):
                for c, p in partners[x]:
                    rc, rp = rank.get(c), rank.get(p)
                    if rc is not None and rp is not None and (rc + sign * rp - t) % 26 >= base:
                        return False
                return True

            def walk(i, n_kw, before, used):
                nodes[0] += 1
                if nodes[0] > node_limit:
                    raise TimeoutError
                if n_kw > k or n_kw + remaining[i] < k:
                    return False
                if i == len(items):
                    return True
                kind, x = items[i]
                if kind == "run":
                    return any(walk(i + 1, n_kw + c, before + x, used)
                               for c in range(min(x, k - n_kw) + 1))
                r = k + (before - n_kw)
                if r < 26:
                    rank[x] = r
                    if fits(x) and walk(i + 1, n_kw, before + 1, used):
                        return True
                    del rank[x]
                for pos in range(k):
                    if not used >> pos & 1:
                        rank[x] = pos
                        if fits(x) and walk(i + 1, n_kw + 1, before + 1, used | 1 << pos):
                            return True
                        del rank[x]
                return False

            try:
                if walk(0, 0, 0, 0):
                    return (k, t, dict(rank)), True
            except TimeoutError:
                exhausted = False
    return None, exhausted


def describe(sol):
    k, t, rank = sol
    kw = sorted((pos, chr(65 + L)) for L, pos in rank.items() if pos < k)
    slots = ["_"] * k
    for pos, ch in kw:
        slots[pos] = ch
    tail = "".join(chr(65 + L) for L, pos in sorted(rank.items(), key=lambda kv: kv[1]) if pos >= k)
    return f"keyword length {k}: {''.join(slots)}  (clue letters left in the alphabetical tail: {tail})"


def smallest_base(rank_p, rank_c, sign, max_base):
    """Smallest base with a solution, scanning up from 1.
    Returns (base, solution, proven) - proven means every smaller base was searched exhaustively."""
    proven = True
    for base in range(1, max_base + 1):
        if rank_p is None and rank_c is None:
            sol, done = search_same(sign, base)
        else:
            sol, done = search(rank_p, rank_c, sign, base)
        if sol:
            return base, sol, proven
        proven &= done
    return None, None, proven


def control():
    """The search must find a real keyword alphabet when one exists."""
    global PAIRS
    saved = PAIRS
    x = keyed_alphabet("PALIMPSEST")
    digits = [3, 1, 4, 1, 5, 9, 2, 6, 5, 3, 5, 8, 9, 7, 9, 3, 2, 3, 8, 4, 6, 2, 6, 4]
    PAIRS = [(ord(x[(ord(P) - 65 + d) % 26]) - 65, ord(P) - 65) for (_, P), d in zip(CRIB, digits)]
    base, sol, done = smallest_base(STD, None, -1, 12)
    PAIRS = saved
    ok = base is not None and base <= 9 and done   # another alphabet may do even better
    print(f"[control] planted digit key over a PALIMPSEST-keyed cipher alphabet: "
          f"smallest base found = {base}, proven minimal = {done} (true key uses 9 values): {ok}")
    return ok


def report(max_base=20):
    print("\n=== any keyword at all: smallest number base that fits all 24 clue shifts ===")
    print("  (a decimal digit key needs 10 or less; wordlist keywords bottomed out at 11)")
    for name, rp, rc in ROLES[:4]:
        for sign, arith in ((-1, "cipher = plain + digit"), (1, "cipher = digit - plain")):
            base, sol, proven = smallest_base(rp, rc, sign, max_base)
            print(f"  {name:32} {arith:24} smallest base {base}"
                  + ("" if proven else " (not proven minimal)"), flush=True)
    same_keyword_report()


# --- the same keyword alphabet on both sides (K1/K2 arrangement): C search -------------

CIPHER_LETTERS = "".join(CIPHERTEXT[i] for i, _ in CRIB)
PLAIN_LETTERS = "".join(P for _, P in CRIB)


def _kwcsp(sign, base, kmin, kmax, enum=None):
    import os
    import subprocess
    here = os.path.dirname(os.path.abspath(__file__))
    exe, src = os.path.join(here, "kwcsp"), os.path.join(here, "kwcsp.c")
    if not os.path.exists(exe) or os.path.getmtime(exe) < os.path.getmtime(src):
        subprocess.run(["gcc", "-O3", "-march=native", "-fopenmp", "-o", exe, src], check=True)
    args = [exe, CIPHER_LETTERS, PLAIN_LETTERS, str(sign), str(base), str(kmin), str(kmax)]
    if enum is not None:
        args.append(str(enum))
    env = dict(os.environ, OMP_NUM_THREADS="30")
    return subprocess.run(args, capture_output=True, text=True, env=env, check=True).stdout.splitlines()


def keyword_pattern(k, rank):
    s = ["_"] * k
    for L, r in enumerate(rank):
        if 0 <= r < k:
            s[r] = chr(65 + L)
    return "".join(s)


def lagged_rules(d):
    """Rules k[i+n] = k[i] + k[i+g] (mod m) obeyed inside both clues AND carrying the
    digits of the first clue forward onto the second."""
    hits = []
    w1, w2 = d[:13], d[13:]
    for m in range(max(max(d) + 1, 2), 14):
        for n in range(2, 10):
            for g in range(1, n):
                if all((w1[i + n] - w1[i] - w1[i + g]) % m == 0 for i in range(13 - n)) and \
                        all((w2[i + n] - w2[i] - w2[i + g]) % m == 0 for i in range(11 - n)):
                    seq = w1[:]
                    while len(seq) < 53:
                        seq.append((seq[-n] + seq[-n + g]) % m)
                    if seq[42:53] == w2:
                        hits.append((m, n, g))
    return hits


def same_keyword_report():
    print("\n=== the same keyword alphabet on both sides (the K1/K2 arrangement) ===")
    for sign, arith in ((-1, "cipher = plain + digit"), (1, "cipher = digit - plain")):
        for kmax in (8, 10, 11):
            for base in range(5, 17):
                if _kwcsp(sign, base, 0, kmax)[0].startswith("FOUND"):
                    print(f"  {arith}: keyword of at most {kmax:2d} letters -> smallest base {base}", flush=True)
                    break
    for sign, arith, base in ((-1, "cipher = plain + digit", 10), (1, "cipher = digit - plain", 11)):
        lines = _kwcsp(sign, base, 0, 11, 2_000_000)
        sols, patterns, ruled = 0, set(), []
        for line in lines:
            if not line.startswith("SOL"):
                continue
            v = list(map(int, line.split()[1:]))
            k, t, rank = v[0], v[1], v[2:]
            d = [(rank[ord(c) - 65] + sign * rank[ord(p) - 65] - t) % 26
                 for c, p in zip(CIPHER_LETTERS, PLAIN_LETTERS)]
            sols += 1
            patterns.add(keyword_pattern(k, rank))
            rules = lagged_rules(d)
            if rules:
                ruled.append((keyword_pattern(k, rank), d, rules))
        from quadgrams import quadgram_score
        wordy = sorted(patterns, key=lambda p: -quadgram_score(p.replace("_", "")))[:5]
        print(f"  {arith}, base {base}, keyword up to 11 letters: {sols:,} alphabets "
              f"({len(patterns):,} keyword patterns)")
        print(f"    most word-like keywords ('_' is one of D J U W X): {', '.join(wordy)}")
        print(f"    alphabets whose digits follow a lagged-Fibonacci rule through both clues: {len(ruled)}")
        for pat, d, rules in ruled[:5]:
            print(f"      {pat} digits {d} rules {rules}")


if __name__ == "__main__":
    assert control(), "positive control failed"
    report()
