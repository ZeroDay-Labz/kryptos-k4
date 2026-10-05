"""
Crib-dragging attack on periodic (Quagmire-family) hypotheses for K4.

Instead of guessing the indicator keyword, we DERIVE it. For a fixed keyed
alphabet and cipher mode, each crib letter forces the *shift* at one key slot.
If, for a candidate key period L, every crib letter that lands on the same slot
forces the same shift, the hypothesis is internally consistent and we can
decrypt every position whose slot a crib touched -- no keyword guessing.

Key fact (see module header of cipher work): the key-alignment OFFSET does not
affect the recovered plaintext, only how the key spells. So we work in shift
space and skip the 26x offset loop entirely. This makes a full-dictionary sweep
over the *alphabet* keyword cheap, and it covers the entire indicator keyspace
for free -- the strongest possible test of "is K4 a periodic Quagmire?".

Community result (reproduced here): no small-period Quagmire III over sensible
alphabets yields English outside the cribs. That is the real evidence K4 is
aperiodic.
"""
from __future__ import annotations

from dataclasses import dataclass

from kryptos import CIPHERTEXT, crib_pairs, keyed_alphabet, ALPHABET
from quadgrams import quadgram_score

MODES = ("vigenere", "beaufort", "variant")


def _forced_shift(mode: str, p: int, r: int) -> int:
    if mode == "vigenere":
        return (r - p) % 26
    if mode == "beaufort":
        return (p + r) % 26
    if mode == "variant":
        return (p - r) % 26
    raise ValueError(mode)


def _decrypt_rank(mode: str, r: int, s: int) -> int:
    if mode == "vigenere":
        return (r - s) % 26
    if mode == "beaufort":
        return (s - r) % 26
    if mode == "variant":
        return (r + s) % 26
    raise ValueError(mode)


@dataclass
class Candidate:
    alpha_kw: str
    mode: str
    period: int
    coverage: float      # fraction of the 97 positions decrypted
    quad: float          # quadgram score of the decrypted letters
    plaintext: str       # '.' where the slot was never fixed by a crib


def attack(pt_alpha: str, ct_alpha: str, mode: str, periods, alpha_kw="",
           ct: str = CIPHERTEXT, pairs=None) -> list[Candidate]:
    pr = {c: i for i, c in enumerate(pt_alpha)}
    cr = {c: i for i, c in enumerate(ct_alpha)}
    pairs = pairs if pairs is not None else crib_pairs()
    n = len(ct)
    # Forced shift for each crib position (offset-independent).
    forced = [(pos, _forced_shift(mode, pr[P], cr[C])) for pos, P, C in pairs]
    out: list[Candidate] = []
    for L in periods:
        slot_shift: dict[int, int] = {}
        ok = True
        for pos, s in forced:
            idx = (pos - 1) % L
            if idx in slot_shift:
                if slot_shift[idx] != s:
                    ok = False
                    break
            else:
                slot_shift[idx] = s
        if not ok:
            continue
        # Decrypt every position whose slot a crib fixed.
        chars = []
        known = 0
        for j, c in enumerate(ct):
            idx = j % L
            if idx in slot_shift:
                p = _decrypt_rank(mode, cr[c], slot_shift[idx])
                chars.append(pt_alpha[p])
                known += 1
            else:
                chars.append(".")
        pt = "".join(chars)
        cov = known / n
        scored = pt.replace(".", "")
        out.append(Candidate(alpha_kw, mode, L, cov, quadgram_score(scored), pt))
    return out


def sweep_quagmire3(alpha_kws, periods=range(2, 25), min_cov=0.9, top_n=25):
    """Quagmire III (single keyed alphabet) over many alphabet keywords."""
    results: list[Candidate] = []
    for kw in alpha_kws:
        ka = keyed_alphabet(kw)
        for mode in MODES:
            for cand in attack(ka, ka, mode, periods, alpha_kw=kw):
                if cand.coverage >= min_cov:
                    results.append(cand)
    results.sort(key=lambda c: -c.quad)
    return results[:top_n]


if __name__ == "__main__":
    # Positive control: a periodic Quagmire III solution must be recovered.
    from ciphers import gen_decrypt
    import kryptos as K

    planted_pt = list("ATTACKATDAWNFROM" * 7)[:97]
    for (a, b), w in K.CRIBS.items():
        for i, ch in enumerate(w):
            planted_pt[a - 1 + i] = ch
    planted_pt = "".join(planted_pt)
    ka = keyed_alphabet("KRYPTOS")
    pr = {c: i for i, c in enumerate(ka)}
    key = "SECRET"
    ct = []
    for i, p in enumerate(planted_pt):
        s = pr[key[i % len(key)]]
        ct.append(ka[(pr[p] + s) % 26])
    ct = "".join(ct)
    # Crib pairs against the PLANTED ciphertext (period of 'SECRET' is 6).
    planted_pairs = [(pos, planted_pt[pos - 1], ct[pos - 1])
                     for (a, b) in K.CRIBS for pos in range(a, b + 1)]
    cands = attack(ka, ka, "vigenere", range(2, 13), "KRYPTOS",
                   ct=ct, pairs=planted_pairs)
    best = next(c for c in cands if c.period == 6)
    match = all(a == b for a, b in zip(best.plaintext, planted_pt) if a != ".")
    print(f"[positive control] L={best.period} cov={best.coverage:.2f} match={match}")
    print(f"  recovered: {best.plaintext}")
    print(f"  planted  : {planted_pt}")

    print("\n[real K4] Quagmire III full attack over KRYPTOS-family alphabets:")
    from solve import CORPUS
    for c in sweep_quagmire3(CORPUS, min_cov=0.5)[:10]:
        print(f"  quad={c.quad:.3f} cov={c.coverage:.2f} alpha={c.alpha_kw} {c.mode} L={c.period}")
        print(f"     {c.plaintext}")
