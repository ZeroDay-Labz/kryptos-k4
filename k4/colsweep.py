"""
Exhaustive columnar transposition x any repeating key, in C (CPU) or OpenCL (GPU).

frontier.py does this in Python up to width 11. This driver writes the clue tables
once, runs colsweep (CPU) or colsweep_gpu (GPU) over every column order of a width,
and decrypts whatever passes. Each order is tested forward and inverse, key following
plaintext or ciphertext order, 8 alphabet/arithmetic settings, plus a single
substitution. A pass needs MINEQ forced equalities (chance 26**-MINEQ per try).

Run:  python colsweep.py control
      python colsweep.py W [MINEQ] [gpu]
"""
from __future__ import annotations

import math
import os
import struct
import subprocess
import sys
import tempfile
import time

from kryptos import CIPHERTEXT
from frontier import (CRIB, CRIB_IDX, COMBOS, ST_PAIRS, TABS, N, columnar_map, inverse, decrypt_hit, test_map,
                      MIN_COLL)
from quadgrams import quadgram_score

HERE = os.path.dirname(os.path.abspath(__file__))


def _build(name, extra=()):
    exe, src = os.path.join(HERE, name), os.path.join(HERE, name + ".c")
    dep = os.path.join(HERE, "colcore.h")
    if not os.path.exists(exe) or os.path.getmtime(exe) < max(os.path.getmtime(src), os.path.getmtime(dep)):
        subprocess.run(["gcc", "-O3", "-march=native", "-fopenmp", "-o", exe, src, *extra], check=True)
    return exe


def write_tables(path, ct=CIPHERTEXT):
    t = bytearray(ord(c) - 65 for c in ct)
    t += bytes(CRIB_IDX)
    t += bytes(ord(P) - 65 for _, P in CRIB)
    for L in range(41):
        t += bytes((x % L if L else 0) for x in range(97))
    assert len(t) == 145 + 97 * 41
    st = [(L, p) for L, p in ST_PAIRS if len(p) >= MIN_COLL]
    t.append(len(st))
    for L, pairs in st:
        t += bytes([L, len(pairs)])
        for a, b in pairs:
            t += bytes([a, b])
    v = []
    for j in range(24):
        for c in range(26):
            v.append(sum(TABS[k][j][c] << (8 * k) for k in range(8)))
    with open(path, "wb") as fh:
        fh.write(struct.pack("<i", len(t)) + bytes(t) + struct.pack("<%dQ" % len(v), *v))


def run(w, mineq=None, gpu=False, ct=CIPHERTEXT, quiet=False):
    maps = math.factorial(w) * 2
    if mineq is None:        # keep the expected number of chance passes below about one
        mineq = max(MIN_COLL, math.ceil(math.log(maps * 8 * 50, 26)))
    exe = _build("colsweep_gpu", ("-l:libOpenCL.so.1",)) if gpu else _build("colsweep")
    with tempfile.TemporaryDirectory() as tmp:
        path = os.path.join(tmp, "tables.bin")
        write_tables(path, ct)
        t0 = time.time()
        res = subprocess.run([exe, path, str(w), str(mineq)], capture_output=True, text=True, check=True,
                             env=dict(os.environ, OMP_NUM_THREADS="30"), cwd=HERE)
    rows = []
    for line in res.stdout.splitlines():
        if not line.startswith("HIT"):
            continue
        _, order, kind, inv, L, eq, mask = line.split()
        order = tuple(map(int, order.split(",")))
        m = columnar_map(w, order)
        if inv == "1":
            m = inverse(m)
        kind = ("MONO", "ST", "TS")[int(kind)]
        for k in range(8):
            if int(mask) >> k & 1:
                pt = "(single substitution)" if kind == "MONO" else decrypt_hit(m, kind, int(L), k, ct=ct)
                rows.append((int(eq), quadgram_score(pt.replace(".", "")) if kind != "MONO" else 0, kind, int(L),
                             "/".join(COMBOS[k]), order, inv == "1", pt))
                if kind == "MONO":
                    break
    rows.sort(key=lambda r: (-r[0], -r[1]))
    if not quiet:
        tail = [x for x in res.stdout.splitlines() if x.startswith("DONE")]
        print(f"\n=== columnar width {w}: every column order ({maps:,} maps) x any repeating key, {'GPU' if gpu else 'CPU'} ===")
        print(f"  {tail[0] if tail else ''}  ({time.time() - t0:.0f} s); passes with >= {mineq} equalities: {len(rows)}")
        print(f"  rough upper bound on chance passes at exactly {mineq}: {maps * 8 * 50 * 26.0 ** -mineq:.2f}")
        for eq, q, kind, L, combo, order, inv, pt in rows[:8]:
            print(f"    {eq} equalities quad={q:.2f} {kind} L={L} {combo} order={order}{' (inverse)' if inv else ''}\n      {pt}")
    return rows


def control(gpu=False):
    """The C/OpenCL test must agree with frontier.py's Python test on every order of width 7,
    on a planted message (columnar SHADOWS-order + Vigenere, key following the ciphertext)."""
    import itertools
    from recipes import _planted_text
    pt, m0 = _planted_text(), columnar_map(7, (3, 0, 6, 2, 5, 1, 4))
    ct = [""] * N
    for i, p in enumerate(pt):
        ct[m0[i]] = chr((ord(p) - 65 + ord("FORCES"[m0[i] % 6]) - 65) % 26 + 65)
    ct = "".join(ct)
    cti = [ord(c) - 65 for c in ct]
    want = set()
    for order in itertools.permutations(range(7)):
        for inv, m in ((False, columnar_map(7, order)), (True, inverse(columnar_map(7, order)))):
            for kind, L, k, eq in test_map(m, cti=cti):
                if kind != "MONO":
                    want.add((order, inv, kind, L, "/".join(COMBOS[k])))
    rows = run(7, MIN_COLL, gpu, ct=ct, quiet=True)
    got = {(r[5], r[6], r[2], r[3], r[4]) for r in rows if r[2] != "MONO"}
    found = any(r[7] == pt and r[5] == (3, 0, 6, 2, 5, 1, 4) and r[2] == "TS" and r[3] == 6 for r in rows)
    print(f"[control colsweep {'GPU' if gpu else 'CPU'}] width 7 planted: Python finds {len(want)} passes, "
          f"C finds {len(got)}, identical: {want == got}; planted solution recovered: {found}")
    return want == got and found


if __name__ == "__main__":
    a = sys.argv[1:]
    gpu = "gpu" in a
    a = [x for x in a if x != "gpu"]
    if a and a[0] == "control":
        sys.exit(0 if control(gpu) else "control failed")
    run(int(a[0]), int(a[1]) if len(a) > 1 else None, gpu)
