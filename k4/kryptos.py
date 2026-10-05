"""
Kryptos K4 analysis toolkit.

Ground-truth data and classical-cipher machinery for experimenting against the
unsolved K4 passage. Nothing here claims to solve K4 -- it is a correct,
auditable platform for testing hypotheses the way the cryptanalysis community
does: anchor the confirmed cribs, run candidate ciphers *backward* from known
plaintext to inspect the implied key, and score candidate plaintexts.

Conventions
-----------
* Positions are 1-indexed inclusive, matching how the cribs are published.
* A=0 .. Z=25 for modular arithmetic.
"""
from __future__ import annotations

from dataclasses import dataclass

# --- Ground truth -----------------------------------------------------------

# The 97-character K4 ciphertext (CIA / Sanborn confirmed).
CIPHERTEXT = (
    "OBKRUOXOGHULBSOLIFBBWFLRVQQPRNGKSSO"
    "TWTQSJQSSEKZZWATJKLUDIAWINFBNYP"
    "VTTMZFPKWGDKZXTJCDIGKUHUAUEKCAR"
)
assert len(CIPHERTEXT) == 97, len(CIPHERTEXT)

# Sanborn-confirmed plaintext cribs: 1-indexed inclusive -> plaintext.
# Verified against CIPHERTEXT above.
CRIBS: dict[tuple[int, int], str] = {
    (22, 34): "EASTNORTHEAST",
    (64, 74): "BERLINCLOCK",
}

ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
KRYPTOS_KEYED = "KRYPTOSABCDEFGHIJLMNQUVWXZ"  # 'KRYPTOS' then remaining letters


# --- Helpers ----------------------------------------------------------------

def keyed_alphabet(keyword: str) -> str:
    """Build a keyed alphabet: unique letters of `keyword`, then the rest A-Z."""
    seen: list[str] = []
    for ch in (keyword + ALPHABET):
        ch = ch.upper()
        if ch.isalpha() and ch not in seen:
            seen.append(ch)
    return "".join(seen)


def crib_pairs() -> list[tuple[int, str, str]]:
    """Yield (position_1indexed, plaintext_char, ciphertext_char) for every crib letter."""
    out = []
    for (a, b), pt in CRIBS.items():
        assert b - a + 1 == len(pt), f"crib {a}-{b} length mismatch"
        for i, p in enumerate(pt):
            pos = a + i
            out.append((pos, p, CIPHERTEXT[pos - 1]))
    return out


# --- Key-recovery under cipher assumptions (standard A-Z) -------------------
# Given known plaintext P and ciphertext C, what key letter K is implied?
#   Vigenere:          C = P + K      ->  K = C - P
#   Beaufort:          C = K - P      ->  K = P + C
#   Variant Beaufort:  C = P - K      ->  K = P - C

def _idx(c: str) -> int:
    return ord(c.upper()) - 65


def _chr(i: int) -> str:
    return chr((i % 26) + 65)


def implied_key(cipher: str) -> str:
    """Key fragment implied by the cribs under `cipher`, '.' where unknown."""
    key = ["."] * 97
    for pos, p, c in crib_pairs():
        pi, ci = _idx(p), _idx(c)
        if cipher == "vigenere":
            k = ci - pi
        elif cipher == "beaufort":
            k = pi + ci
        elif cipher == "variant":
            k = pi - ci
        else:
            raise ValueError(cipher)
        key[pos - 1] = _chr(k)
    return "".join(key)


# --- Decryption primitives (standard A-Z, repeating key) --------------------

def decrypt(ciphertext: str, key: str, cipher: str = "vigenere") -> str:
    out = []
    for i, c in enumerate(ciphertext):
        ci, ki = _idx(c), _idx(key[i % len(key)])
        if cipher == "vigenere":
            p = ci - ki
        elif cipher == "beaufort":
            p = ki - ci
        elif cipher == "variant":
            p = ci + ki
        else:
            raise ValueError(cipher)
        out.append(_chr(p))
    return "".join(out)


def matches_cribs(plaintext: str) -> bool:
    for (a, b), pt in CRIBS.items():
        if plaintext[a - 1:b] != pt:
            return False
    return True


if __name__ == "__main__":
    print("K4 ciphertext (97):", CIPHERTEXT)
    print()
    print("Crib letter pairs (pos: P<-C):")
    for pos, p, c in crib_pairs():
        print(f"  {pos:>2}: {p} <- {c}")
    print()
    for cipher in ("vigenere", "beaufort", "variant"):
        print(f"implied key [{cipher:8}]: {implied_key(cipher)}")
