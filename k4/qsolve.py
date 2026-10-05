"""
Driver for qsolve.c: repeating-key tableau cipher with ARBITRARY alphabets and an
unknown key, solved by annealing on the English of the whole 97-letter decryption.

structural.py shows the 24 clue letters cannot decide these periods (8, 13, 16, 19,
20, 23...) when the alphabets are unknown. A full-text search can: a true solution
reads as English everywhere, a wrong period tops out well below.

Models (other alphabet = A-Z or KRYPTOS where "fixed"):
  QIV      both alphabets unknown
  QIII     both alphabets the same unknown one
  P=A / P=K / C=A / C=K   one alphabet fixed, the other unknown; plain and Beaufort

Run:  python qsolve.py control
      python qsolve.py run [steps] [restarts]
"""
from __future__ import annotations

import os
import random
import subprocess
import sys
import time

from kryptos import CIPHERTEXT, ALPHABET, KRYPTOS_KEYED
import gromark_sa

HERE = os.path.dirname(os.path.abspath(__file__))
BIN = os.path.join(HERE, "qsolve")

MODELS = [("QIV", 0, "-", "-", 0), ("QIII", 0, "-", "-", 1), ("QIII beau", 1, "-", "-", 1)]
for _n, _a in (("A", ALPHABET), ("K", KRYPTOS_KEYED)):
    for _m, _mn in ((0, ""), (1, " beau")):
        MODELS.append((f"P={_n}{_mn}", _m, _a, "-", 0))
        MODELS.append((f"C={_n}{_mn}", _m, "-", _a, 0))


def _build():
    gromark_sa.prepare()
    src = os.path.join(HERE, "qsolve.c")
    if not os.path.exists(BIN) or os.path.getmtime(BIN) < os.path.getmtime(src):
        subprocess.run(["gcc", "-O3", "-march=native", "-fopenmp", "-o", BIN, src, "-lm"], check=True)


def solve(ct, model, L, steps=1_500_000, restarts=60, threads=30):
    """Best first: [(score, mismatches, plaintext, pa, ca, key)]; clue-exact solutions sort first."""
    _, mode, pa, ca, tie = model
    env = dict(os.environ, OMP_NUM_THREADS=str(threads))
    res = subprocess.run([BIN, gromark_sa.QUAD, ct, str(mode), str(L), pa, ca, str(tie), str(steps), str(restarts)],
                         capture_output=True, text=True, env=env, check=True)
    out = []
    for line in res.stdout.splitlines():
        sc, mis, pt, a, b, key = line.split()
        out.append((float(sc), int(mis), pt, a, b, key))
    out.sort(key=lambda r: (r[1] > 0, -r[0]))
    return out


_PT = ("THECOMPASSROSEISHEREXEASTNORTHEASTTHISISYOURPOSITIONX"
       "COMMISSIONBERLINCLOCKWHICHISNORTHEASTOFHEREX")


def plant(L, seed, pa=None, ca=None):
    rng = random.Random(seed)
    pa, ca = list(pa or ALPHABET), list(ca or ALPHABET)
    if len(set(pa)) == 26 and "".join(pa) == ALPHABET:
        rng.shuffle(pa)
    rng.shuffle(ca)
    key = [rng.randrange(26) for _ in range(L)]
    return "".join(ca[(pa.index(p) + key[i % L]) % 26] for i, p in enumerate(_PT))


def control(steps=1_500_000, restarts=60):
    """One alphabet known is recoverable. With BOTH alphabets and the key unknown the annealer
    does not find a planted solution (it reaches clue-exact word salad instead), so QIV / QIII
    results from this solver are not evidence either way."""
    _build()
    ok = True
    by = {m[0]: m for m in MODELS}
    for name, pa, ca in (("C=K", None, KRYPTOS_KEYED), ("P=K", KRYPTOS_KEYED, None)):
        for L in (13, 19):
            rng = random.Random(7 * L)
            x = rng.sample(ALPHABET, 26)
            p_, c_ = (x, list(ca)) if ca else (list(pa), x)
            key = [rng.randrange(26) for _ in range(L)]
            ct = "".join(c_[(p_.index(p) + key[i % L]) % 26] for i, p in enumerate(_PT))
            best = solve(ct, by[name], L, steps, restarts)[0]
            wrong = solve(ct, by[name], L - 1, steps, restarts)[0]
            same = sum(a == b for a, b in zip(best[2], _PT))
            print(f"[control qsolve] planted {name} period {L}: score {best[0]:.2f}, {same}/97 letters right;"
                  f" at a wrong period: {wrong[0]:.2f} with {wrong[1]} clue letters wrong")
            ok &= same >= 75 and best[1] == 0
    return ok


def run(steps=3_000_000, restarts=120, periods=range(8, 25), models=None):
    _build()
    lo, med = gromark_sa.english_reference()
    print("\n=== repeating key with arbitrary alphabets: full-text annealing ===")
    print(f"  real English scores {med:.2f} (worst {lo:.2f}); {restarts} restarts x {steps:,} steps per cell")
    rows, t0 = [], time.time()
    for model in models or MODELS[3:]:
        for L in periods:
            b = solve(CIPHERTEXT, model, L, steps, restarts)[0]
            rows.append((b[0] if b[1] == 0 else -9, model[0], L) + b)
            print(f"  {model[0]:10} L={L:2d}  best {b[0]:.3f}  clue letters wrong: {b[1]}", flush=True)
    rows.sort(reverse=True)
    print(f"  best clue-exact decryptions ({time.time() - t0:.0f} s):")
    for _, name, L, sc, mis, pt, pa, ca, key in rows[:8]:
        print(f"    {sc:.3f} {name} L={L} key={key}\n      {pt}\n      PA={pa} CA={ca}")
    return rows


if __name__ == "__main__":
    a = sys.argv[1:]
    if a and a[0] == "control":
        print("control passed:", control())
    else:
        run(*(int(x) for x in a[1:3]))
