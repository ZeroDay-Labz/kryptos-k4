"""
"Fixed table plus a number from 0 to 4": cipher = f(plain) + d, counting in A-Z order.

Observation (a sharper form of Bean's): if two of the 24 clue letters are set aside
(position 65, and one of the two O's at 27 / 72), every remaining plaintext letter goes to
cipher letters that lie within FIVE consecutive letters of each other. Shuffled clues manage
that about 1 time in 300-400. Five values is a base-5 digit, and the Mengenlehreuhr (the
"Berlin clock" Sanborn first pointed at) shows the time in base 5; Scheidt spoke of changing
the "base". This module asks what digit key d would go with it.

f is unknown, so each hypothesis about the digits is solved as a small constraint problem:
choose f(letter) for the 12-13 clue letters (distinct, each inside its 5-wide window) so that
the digits C - f(P) obey the rule.

  periodic    digits repeat with period L (1-11)
  stepping    digits repeat with period L but go up by s (mod 5) each time round (grid rows)
  fibonacci   d[i+n] = d[i] + d[i+g] mod 5 (Gromark rule in base 5)
  texts       digits are the letters of a known text reduced mod 5 (three numberings)

Run:  python base5.py
"""
from __future__ import annotations

import itertools

from kryptos import CIPHERTEXT
from frontier import CRIB

BASE = 5
PAIRS = [(i, P, ord(CIPHERTEXT[i]) - 65) for i, P in CRIB]          # 0-based position, plain, cipher rank


def domains(drop):
    groups = {}
    for i, P, c in PAIRS:
        if i not in drop:
            groups.setdefault(P, []).append(c)
    dom = {P: [f for f in range(26) if all((c - f) % 26 < BASE for c in cs)] for P, cs in groups.items()}
    return dom if all(dom.values()) else None


def drop_sets():
    """Every way of setting aside two clue letters that leaves a base-5 fit."""
    out = []
    for a, b in itertools.combinations([i for i, _, _ in PAIRS], 2):
        dom = domains({a, b})
        if dom and solve(dom, {a, b}, lambda d: True, first=True):
            out.append({a, b})
    return out


def solve(dom, drop, rule, first=False, limit=20):
    """All f (as {letter: rank}) with distinct values whose digit map {pos: d} satisfies rule (a
    function of the partial digit map that must hold for every prefix)."""
    letters = sorted(dom, key=lambda P: len(dom[P]))
    pos_of = {P: [(i, c) for i, Q, c in PAIRS if Q == P and i not in drop] for P in letters}
    out = []

    def rec(k, f, used, digits):
        if len(out) >= limit:
            return
        if k == len(letters):
            out.append((dict(f), dict(digits)))
            return
        P = letters[k]
        for v in dom[P]:
            if v in used:
                continue
            for i, c in pos_of[P]:
                digits[i] = (c - v) % 26
            if rule(digits):
                f[P] = v
                used.add(v)
                rec(k + 1, f, used, digits)
                used.discard(v)
                del f[P]
            for i, _ in pos_of[P]:
                del digits[i]

    rec(0, {}, set(), {})
    return out[:1] if first else out


def periodic_rule(L, step=0, width=None):
    w = width or L
    def rule(d):
        seen = {}
        for i, v in d.items():
            base = (v - step * (i // w)) % BASE
            if seen.setdefault(i % L, base) != base:
                return False
        return True
    return rule


def fib_rule(n, g):
    def rule(d):
        for i in d:
            if i + n in d and i + g in d and (d[i] + d[i + g] - d[i + n]) % BASE:
                return False
        return True
    return rule


def show(f, digits):
    seq = "".join(str(digits.get(i, "?")) if any(i == p for p, _, _ in PAIRS) else "." for i in range(97))
    return ("f: " + " ".join(f"{P}>{chr(65 + v)}" for P, v in sorted(f.items()))
            + f"\n        digits 22-34: {seq[21:34]}   64-74: {seq[63:74]}")


def run():
    drops = drop_sets()
    print("\n=== fixed table plus a base-5 digit: what digit key fits? ===")
    print("  pairs of clue positions that must be set aside for a base-5 fit: "
          + ", ".join(str(sorted(x + 1 for x in d)) for d in drops))
    found = 0
    for drop in drops:
        dom = domains(drop)
        tag = f"setting aside {sorted(x + 1 for x in drop)}"
        free = solve(dom, drop, lambda d: True, limit=10 ** 9)
        print(f"  {tag}: {len(free):,} possible tables f with no rule on the digits")
        for L in range(1, 12):
            for sol in solve(dom, drop, periodic_rule(L)):
                found += 1
                print(f"    PERIODIC period {L}  {tag}\n        {show(*sol)}")
            for s in range(1, BASE):
                for sol in solve(dom, drop, periodic_rule(L, s), limit=3):
                    found += 1
                    print(f"    STEPPING period {L}, +{s} each round  {tag}\n        {show(*sol)}")
        for n in range(2, 9):
            for g in range(1, n):
                sols = solve(dom, drop, fib_rule(n, g), limit=3)
                # only meaningful when the rule is actually exercised several times
                def uses(d):
                    return sum(1 for i in d if i + n in d and i + g in d)
                for sol in sols:
                    if uses(sol[1]) >= 8:
                        found += 1
                        print(f"    FIBONACCI d[i+{n}] = d[i] + d[i+{g}], checked {uses(sol[1])} times  {tag}\n        {show(*sol)}")
    if not found:
        print("  no periodic (1-11), stepping, or Fibonacci-type digit key fits")
    return found


def run_texts():
    """Digits = letters of a known text mod 5."""
    from texts import ALL_TEXTS
    from chain import sources
    srcs = sources()
    hits, tests = [], 0
    for drop in drop_sets():
        need = [(i, P, c) for i, P, c in PAIRS if i not in drop]
        for name, text in srcs.items():
            n = len(text)
            for numbering, val in (("A=0", lambda ch: ord(ch) - 65), ("A=1", lambda ch: ord(ch) - 64),
                                   ("KRYPTOS order", lambda ch: "KRYPTOSABCDEFGHIJLMNQUVWXZ".index(ch))):
                v = [val(ch) % BASE for ch in text]
                for step in (1, -1):
                    for start in range(n):
                        tests += 1
                        f, g, ok = {}, {}, True
                        for i, P, c in need:
                            x = (c - v[(start + step * i) % n]) % 26
                            if f.setdefault(P, x) != x or g.setdefault(x, P) != P:
                                ok = False
                                break
                        if ok:
                            hits.append((name, numbering, start, step, sorted(x + 1 for x in drop)))
    print("\n=== base-5 digits read from a known text (letter numbers mod 5) ===")
    print(f"  placements tested: {tests:,}; consistent with one fixed table: {len(hits)}")
    for h in hits[:8]:
        print("   ", h)
    return hits


if __name__ == "__main__":
    run()
    run_texts()


# --- joint search: the table and the most English-like reading together (b5solve.c) ---------

def _b5(ct, known, exc, steps, restarts, base=BASE, threads=30):
    import os
    import subprocess
    import gromark_sa
    here = os.path.dirname(os.path.abspath(__file__))
    gromark_sa.prepare()
    exe, src = os.path.join(here, "b5solve"), os.path.join(here, "b5solve.c")
    if not os.path.exists(exe) or os.path.getmtime(exe) < os.path.getmtime(src):
        subprocess.run(["gcc", "-O3", "-march=native", "-fopenmp", "-o", exe, src, "-lm"], check=True)
    res = subprocess.run([exe, gromark_sa.QUAD, str(steps), str(restarts), str(base)], input=f"{ct}\n{known}\n{exc}\n",
                         capture_output=True, text=True, check=True, env=dict(os.environ, OMP_NUM_THREADS=str(threads)))
    rows = [(float(a), b, c) for a, b, c in (line.split() for line in res.stdout.splitlines())]
    rows.sort(reverse=True)
    return rows


def _known(drop=()):
    known, exc = ["."] * 97, ["0"] * 97
    for i, P in CRIB:
        known[i] = P
        if i in drop:
            exc[i] = "1"
    return "".join(known), "".join(exc)


def _plant(text, seed, base=BASE):
    """Encipher text under a random table and random digits."""
    import random
    rng = random.Random(seed)
    f = list(range(26))
    rng.shuffle(f)
    return "".join(chr(65 + (f[ord(ch) - 65] + rng.randrange(base)) % 26) for ch in text)


def decode_calibrate(steps=40_000, restarts=60):
    """What the solver returns (a) when the model is true and the text is English, and
    (b) when the model is true but the hidden text is NOT English, so that any English it
    reports is manufactured. K4 has to beat (b) to mean anything."""
    import random
    from recipes import _planted_text
    from solve import K2_PT, K3_PT
    known, exc = _known()
    out = {"english": [], "gibberish": []}
    for seed in range(4):
        src = (K3_PT if seed % 2 else K2_PT)[40 + 31 * seed:40 + 31 * seed + 97]
        eng = list(src)
        rng = random.Random(100 + seed)
        gib = [chr(65 + rng.randrange(26)) for _ in range(97)]
        for i, P in CRIB:
            eng[i] = P
            gib[i] = P
        for kind, text in (("english", "".join(eng)), ("gibberish", "".join(gib))):
            rows = _b5(_plant(text, seed), known, exc, steps, restarts)
            right = sum(a == b for a, b in zip(rows[0][1], text))
            out[kind].append((rows[0][0], right))
    print("\n=== joint search calibration (table + best reading), 97 letters, same clue words in place ===")
    print("  hidden text is English:   best score, letters right: "
          + ", ".join(f"{s:.2f} ({r}/97)" for s, r in out["english"]))
    print("  hidden text is gibberish: best score (anything English here is manufactured): "
          + ", ".join(f"{s:.2f}" for s, _ in out["gibberish"]))
    return out


def decode_k4(steps=40_000, restarts=120):
    print("\n=== joint search on K4 ===")
    res = {}
    for drop in ({26, 64}, {64, 71}):
        known, exc = _known(drop)
        rows = _b5(CIPHERTEXT, known, exc, steps, restarts)
        res[tuple(sorted(drop))] = rows
        tag = sorted(x + 1 for x in drop)
        print(f"  setting aside {tag}: best scores " + ", ".join(f"{r[0]:.2f}" for r in rows[:5]))
        for sc, pt, tab in rows[:4]:
            print(f"    {sc:.3f} {pt}")
        # do the best restarts agree with each other?
        top = [r[1] for r in rows[:10]]
        agree = sum(1 for i in range(97) if len({t[i] for t in top}) == 1)
        print(f"    letters on which the 10 best restarts all agree: {agree} of 97 (24 are the clue letters)")
    return res
