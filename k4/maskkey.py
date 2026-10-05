"""
A masking table plus a repeating key, allowing for slips.

Scheidt: "I masked the English language." The simplest mask is a fixed letter-for-letter
table applied before (or after) an ordinary repeating-key step:

    model A   cipher = table(plain) + key[i mod L]      (mask first, then the key)
    model B   table(cipher) = plain + key[i mod L]      (key first, then the mask)

with the key step counted in A-Z or KRYPTOS order. The table is ANY of the 26! tables and
the key is any key of period L, so nothing is guessed: two clue letters in the same key
slot fix the difference between two table entries, and a period survives only if all those
differences are consistent and no two letters share a table entry. structural.py did this
for all 24 clue letters (no period up to 12 survives). Here up to two clue letters may be
set aside as slips (Sanborn made one in each of K1, K2 and K3).

"Loops closed" counts the independent checks a setting passed; each has a 1 in 26 chance
of passing by luck.

Run:  python maskkey.py
"""
from __future__ import annotations

import itertools

from kryptos import CIPHERTEXT, ALPHABET, KRYPTOS_KEYED
from frontier import CRIB

ORDERS = {"A-Z": ALPHABET, "KRYPTOS": KRYPTOS_KEYED}


def check(L, drop, model, order):
    """(ok, loops closed). Unknown table entries T[x]; known ranks r(y)."""
    r = {ch: i for i, ch in enumerate(ORDERS[order])}
    parent, off = {}, {}                       # value(x) = value(root) + off[x]

    def find(x):
        if parent.setdefault(x, x) == x:
            off.setdefault(x, 0)
            return x, 0
        root, o = find(parent[x])
        parent[x], off[x] = root, (off[x] + o) % 26
        return root, off[x]

    loops, last = 0, {}
    for i, P in CRIB:
        if i in drop:
            continue
        c = CIPHERTEXT[i]
        unk, known = (P, r[c]) if model == "A" else (c, r[P])      # T[unk] = known +/- key
        s = i % L
        if s in last:
            u2, k2 = last[s]
            # T[unk] - T[u2] = known - k2
            d = (known - k2) % 26
            (ra, oa), (rb, ob) = find(unk), find(u2)
            if ra == rb:
                if (oa - ob) % 26 != d:
                    return False, loops
                loops += 1
            else:
                parent[ra] = rb
                off[ra] = (ob + d - oa) % 26
        last[s] = (unk, known)
    seen = {}
    for x in list(parent):
        root, o = find(x)
        if seen.setdefault((root, o), x) != x:
            return False, loops                # two letters on one table entry
    return True, loops


def run(max_L=14, max_drop=2, flag=4):
    positions = [i for i, _ in CRIB]
    rows = []
    for nd in range(max_drop + 1):
        for drop in itertools.combinations(positions, nd):
            for model in "AB":
                for order in ORDERS:
                    for L in range(1, max_L + 1):
                        ok, loops = check(L, set(drop), model, order)
                        if ok and loops >= flag:
                            rows.append((loops, L, nd, model, order, tuple(p + 1 for p in drop)))
    rows.sort(key=lambda x: (-x[0], x[2], x[1]))
    tests = sum(1 for nd in range(max_drop + 1) for _ in itertools.combinations(positions, nd)) * 4 * max_L
    print("\n=== masking table + repeating key, up to two clue letters set aside ===")
    print(f"  settings tested: {tests:,}; passing with {flag}+ loops closed: {len(rows)}"
          f"  (by luck: about {tests * 26.0 ** -flag:.1f} at exactly {flag}, {tests * 26.0 ** -(flag + 2):.3f} at {flag + 2})")
    for loops, L, nd, model, order, drop in rows[:12]:
        print(f"    {loops} loops closed  period {L:2d}  model {model}  key counted in {order:8s} set aside {drop or 'nothing'}")
    if not rows:
        print("  nothing passes")
    return rows


if __name__ == "__main__":
    run()
