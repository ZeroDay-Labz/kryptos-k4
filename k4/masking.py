"""
Masking hypotheses for K4: a transposition composed with the substitution.

Ed Scheidt has described a "masking technique" for K4. The leading structural
idea is that a transposition is layered with the polyalphabetic substitution, so
that no single periodic key is visible in the ciphertext -- which is consistent
with the aperiodicity we demonstrated in cribdrag.py.

Two encryption orders, both decryptable here and both crib-checkable because the
final output is plaintext in natural order:

  order="ST"  (substitute, then transpose)
        decrypt: un-transpose the ciphertext -> substituted text in plaintext
        order -> crib-drag the substitution at the original crib positions.

  order="TS"  (transpose, then substitute)
        decrypt: the substitution is positional on the ciphertext, but each
        crib letter was moved by the transposition first. We map every crib's
        plaintext position to the ciphertext position the transposition sent it
        to, crib-drag the substitution there, then un-transpose to read it.

This composes the transposition sweep with the keyspace-complete crib-drag, so
for each transposition key we test ALL indicator keys for free. Still a
hypothesis platform, not a claim -- the search space of transpositions is huge
and Sanborn's exact scheme is unknown.
"""
from __future__ import annotations

from dataclasses import dataclass

from kryptos import CIPHERTEXT, CRIBS, keyed_alphabet
from ciphers import columnar_decrypt, columnar_encrypt, _col_order
from cribdrag import attack, MODES
from quadgrams import quadgram_score


def _crib_positions() -> list[tuple[int, str]]:
    out = []
    for (a, b), word in CRIBS.items():
        for i, ch in enumerate(word):
            out.append((a + i, ch))
    return out


def _encrypt_perm(n: int, keyword: str) -> list[int]:
    """perm[plaintext_index] = ciphertext_index under columnar_encrypt."""
    marker = list(range(n))
    cols = len(keyword)
    order = _col_order(keyword)
    grid = [marker[i:i + cols] for i in range(0, n, cols)]
    seq = []
    for target in range(cols):
        col = order.index(target)
        for row in grid:
            if col < len(row):
                seq.append(row[col])
    # seq[cipher_index] = plaintext_index ; invert to perm[plaintext]=cipher
    perm = [0] * n
    for cipher_idx, plain_idx in enumerate(seq):
        perm[plain_idx] = cipher_idx
    return perm


@dataclass
class MaskHit:
    order: str
    trans_kw: str
    alpha_kw: str
    mode: str
    period: int
    coverage: float
    quad: float
    plaintext: str


def attack_order_ST(trans_kw: str, alpha_kw: str, periods=range(2, 27)) -> list[MaskHit]:
    untransposed = columnar_decrypt(CIPHERTEXT, trans_kw)
    ka = keyed_alphabet(alpha_kw)
    pairs = [(pos, ch, untransposed[pos - 1]) for pos, ch in _crib_positions()]
    hits = []
    for mode in MODES:
        for c in attack(ka, ka, mode, periods, alpha_kw, ct=untransposed, pairs=pairs):
            hits.append(MaskHit("ST", trans_kw, alpha_kw, mode, c.period,
                                c.coverage, c.quad, c.plaintext))
    return hits


def attack_order_TS(trans_kw: str, alpha_kw: str, periods=range(2, 27)) -> list[MaskHit]:
    n = len(CIPHERTEXT)
    perm = _encrypt_perm(n, trans_kw)  # perm[plaintext_idx] = cipher_idx
    ka = keyed_alphabet(alpha_kw)
    # Each crib letter (plaintext pos) maps to the cipher position perm sent it to.
    pairs = [(perm[pos - 1] + 1, ch, CIPHERTEXT[perm[pos - 1]]) for pos, ch in _crib_positions()]
    hits = []
    for mode in MODES:
        for c in attack(ka, ka, mode, periods, alpha_kw, ct=CIPHERTEXT, pairs=pairs):
            # c.plaintext is the transposed-plaintext sequence; un-transpose to read.
            readable = _untranspose_from_cipherorder(c.plaintext, trans_kw)
            hits.append(MaskHit("TS", trans_kw, alpha_kw, mode, c.period,
                                c.coverage, quadgram_score(readable.replace(".", "")), readable))
    return hits


def _untranspose_from_cipherorder(seq_in_cipher_order: str, trans_kw: str) -> str:
    """seq is indexed by cipher position; return it reordered to plaintext order."""
    n = len(seq_in_cipher_order)
    perm = _encrypt_perm(n, trans_kw)  # perm[plain]=cipher
    out = ["."] * n
    for plain_idx in range(n):
        out[plain_idx] = seq_in_cipher_order[perm[plain_idx]]
    return "".join(out)


def sweep(trans_kws, alpha_kws, orders=("ST", "TS"), min_cov=0.85, top_n=15):
    hits: list[MaskHit] = []
    for tkw in trans_kws:
        for akw in alpha_kws:
            if "ST" in orders:
                hits += attack_order_ST(tkw, akw)
            if "TS" in orders:
                hits += attack_order_TS(tkw, akw)
    hits = [h for h in hits if h.coverage >= min_cov]
    hits.sort(key=lambda h: -h.quad)
    return hits[:top_n]


if __name__ == "__main__":
    # Positive control: encrypt a crib-bearing plaintext with ST, recover it.
    pt = list("MOVEALONGNOTHINGTOSEE" * 5)[:97]
    for (a, b), w in CRIBS.items():
        for i, ch in enumerate(w):
            pt[a - 1 + i] = ch
    pt = "".join(pt)
    ka = keyed_alphabet("KRYPTOS")
    pr = {c: i for i, c in enumerate(ka)}
    key = "ABSCISSA"
    sub = "".join(ka[(pr[p] + pr[key[i % len(key)]]) % 26] for i, p in enumerate(pt))
    ct_planted = columnar_encrypt(sub, "PALIMPSEST")

    import masking, kryptos
    masking.CIPHERTEXT = ct_planted
    kryptos.CIPHERTEXT = ct_planted
    # ST decrypt: untranspose then crib-drag
    unt = columnar_decrypt(ct_planted, "PALIMPSEST")
    pairs = [(pos, ch, unt[pos - 1]) for pos, ch in _crib_positions()]
    cands = attack(ka, ka, "vigenere", range(2, 13), "KRYPTOS", ct=unt, pairs=pairs)
    best = next(c for c in cands if c.period == len(key))
    ok = all(a == b for a, b in zip(best.plaintext, pt) if a != ".")
    print(f"[positive control ST] L={best.period} cov={best.coverage:.2f} match={ok}")

    print("\n[real K4] masking sweep (corpus x corpus, both orders):")
    from solve import CORPUS
    for h in sweep(CORPUS, CORPUS)[:10]:
        print(f"  quad={h.quad:.3f} cov={h.coverage:.2f} {h.order} trans={h.trans_kw} "
              f"alpha={h.alpha_kw} {h.mode} L={h.period}")
        print(f"     {h.plaintext}")
