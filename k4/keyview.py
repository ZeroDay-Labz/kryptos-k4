"""
Reverse-engineer the key from known plaintext, shown plainly.

If you know a plaintext letter and its ciphertext letter, and you assume a cipher
method, the key letter at that position is forced. This script does that:

1. on K1 and K2, where the answer is known, so you can watch the keywords
   PALIMPSEST and ABSCISSA fall out;
2. on K4's 24 confirmed letters, under each method.

What it shows: the method works, and on K4 it yields 24 key letters with no
visible pattern. Those 24 letters only fix the key AT those 24 positions. The
other 73 positions follow only if the key has a rule (repeats, is a readable
text, is generated from a seed, ...), and each such rule is what frontier.py,
structural.py and gromark.py test.
"""
from __future__ import annotations

from kryptos import CIPHERTEXT, CRIBS, ALPHABET, KRYPTOS_KEYED
from frontier import CRIB, _consistent_mod
from sculpture import K1_CT, K2_CT, K4_CELLS
from solve import K1_PT, K2_PT

K = KRYPTOS_KEYED
KR = {ch: i for i, ch in enumerate(K)}


def key_tableau(pt: str, ct: str) -> str:
    """Key letters under the sculpture's own tableau, as used for K1 and K2."""
    return "".join(K[(KR[c] - KR[p]) % 26] for p, c in zip(pt, ct))


def key_plain(pt: str, ct: str, mode: str) -> str:
    out = []
    for p, c in zip(pt, ct):
        pi, ci = ord(p) - 65, ord(c) - 65
        v = {"vigenere": ci - pi, "beaufort": ci + pi, "variant": pi - ci}[mode]
        out.append(ALPHABET[v % 26])
    return "".join(out)


def show_known():
    print("=== the method, on sections where we know the answer ===")
    for name, pt, ct in (("K1", K1_PT, K1_CT), ("K2", K2_PT[:40], K2_CT[:40])):
        n = min(len(pt), 40)
        print(f"  {name} plaintext : {pt[:n]}")
        print(f"  {name} ciphertext: {ct[:n]}")
        print(f"  {name} forced key: {key_tableau(pt[:n], ct[:n])}   <- the keyword, repeating")
        print()


def show_k4():
    print("=== the same reverse-engineering on K4's 24 confirmed letters ===")
    segs = [(a - 1, b, w) for (a, b), w in CRIBS.items()]
    for a, b, w in segs:
        ct = CIPHERTEXT[a:b]
        print(f"  positions {a + 1}-{b}")
        print(f"    plaintext                     : {w}")
        print(f"    ciphertext                    : {ct}")
        print(f"    key, sculpture tableau (K1/K2): {key_tableau(w, ct)}")
        print(f"    key, plain Vigenere           : {key_plain(w, ct, 'vigenere')}")
        print(f"    key, plain Beaufort           : {key_plain(w, ct, 'beaufort')}")
        print(f"    key, variant Beaufort         : {key_plain(w, ct, 'variant')}")
        print()
    full = ["."] * 97
    for a, b, w in segs:
        full[a:b] = key_tableau(w, CIPHERTEXT[a:b])
    print("  the whole 97-letter key as far as the clues determine it (tableau method):")
    print("    " + "".join(full))
    known = sum(ch != "." for ch in full)
    print(f"    {known} positions known, {97 - known} unknown")


def show_position_formula():
    """Is the forced shift any simple function of where the letter sits on the sculpture?"""
    print("\n=== is the key a simple function of position on the sculpture? ===")
    found = []
    for name, pr, cr in (("plain alphabet", None, None), ("KRYPTOS alphabet", KR, KR)):
        rank_p = (lambda ch: ord(ch) - 65) if pr is None else pr.__getitem__
        rank_c = (lambda ch: ord(ch) - 65) if cr is None else cr.__getitem__
        s = [(rank_c(CIPHERTEXT[i]) - rank_p(P)) % 26 for i, P in CRIB]
        rows = []
        for (i, _), v in zip(CRIB, s):
            r, col = K4_CELLS[i]
            rows.append([1, i, r, col, r * col, v])
        if _consistent_mod(rows, 2, 5)[1][0] and _consistent_mod(rows, 13, 5)[1][0]:
            found.append(name)
    print("  shift = a + b*index + c*row + d*column + e*row*column :",
          "fits for " + ", ".join(found) if found else "no fit")


if __name__ == "__main__":
    show_known()
    show_k4()
    show_position_formula()
    print("""
=== what this means ===
  The clues pin the key down only where the clues are. To get the other 73
  letters the key must follow a rule, and every rule tested so far fails on
  these 24 letters:
    repeats with any period up to 23          (frontier.py)
    any single mixed alphabet, any period      (structural.py)
    built from earlier plaintext/ciphertext    (autokey, feedback)
    counts up, polynomial, Fibonacci-style     (progressive, recurrence, Gromark)
    read off the sculpture or the Morse text   (structural.py sources)
    readable English text                      (structural.py english)
  So either the method is not one of these families, or the key is long and
  arbitrary, in which case 24 letters cannot recover the rest.""")
