"""
Key chain behind a transposition ("matrix" step + chained key).

chain.py tests: a known text decoded by a repeating key becomes K4's key. This
module puts a transposition in front of or behind that:

  ST  substitute with the chained key, then transpose
  TS  transpose, then substitute with the chained key (key follows cipher order)

for every transposition in frontier.py's small families (decimation, rail fence,
serpentine, single and K3-style double rotation), masks.py's routes, and every
columnar order of widths 2..MAX_W, each forward and inverse. The text is any
contiguous reading (any start, either direction) of the texts in chain.sources();
key1 is any repeating key, derived from the clues. The search itself is chaint.c.

Run:  python chaint.py [control|run [max_width]]
"""
from __future__ import annotations

import itertools
import multiprocessing as mp
import os
import subprocess
import sys
import tempfile
import time

from kryptos import CIPHERTEXT
from frontier import CRIB, CRIB_IDX, N, COMBOS, ALPHAS, _dec, columnar_map, inverse, small_families
from masks import route_families, mirror_families, stepped_families
from chain import RANK, sources
from quadgrams import quadgram_score

_CTX = mp.get_context("fork")
HERE = os.path.dirname(os.path.abspath(__file__))
BIN = os.path.join(HERE, "chaint")
PLAIN = "".join(P for _, P in CRIB)
RECODE = [("A", "A"), ("A", "K"), ("K", "A")]      # (alphabet the key letter is read in, made in)
MIN_EQ = 9
_CT = CIPHERTEXT
_WANT: set = set()


def _build():
    src = os.path.join(HERE, "chaint.c")
    if not os.path.exists(BIN) or os.path.getmtime(BIN) < os.path.getmtime(src):
        subprocess.run(["gcc", "-O3", "-march=native", "-fopenmp", "-o", BIN, src], check=True)


def _cases(m):
    """(order, 48-byte case) for one plain->cipher map."""
    c = bytes(ord(_CT[m[i]]) - 65 for i in CRIB_IDX)
    return (("ST", c + bytes(CRIB_IDX)), ("TS", c + bytes(m[i] for i in CRIB_IDX)))


def _labelled(job):
    """All (label, map) of one job: ('small',), ('routes',) or ('col', w, prefix)."""
    if job[0] == "small":
        gen = small_families()
    elif job[0] == "routes":
        gen = route_families()
    elif job[0] == "mirrors":
        gen = mirror_families()
    elif job[0] == "stepped":
        gen = stepped_families()
    else:
        _, w, prefix = job
        rest = [c for c in range(w) if c not in prefix]
        gen = ((f"columnar w={w} order={prefix + tail}", columnar_map(w, prefix + tail))
               for tail in itertools.permutations(rest))
    for label, m in gen:
        yield label, m
        yield label + " (inverse)", inverse(m)


def _case_task(job):
    out, n = set(), 0
    for _, m in _labelled(job):
        n += 1
        for _, case in _cases(m):
            out.add(case)
    return n, out


def _find_task(job):
    return [(label, m, order, case) for label, m in _labelled(job)
            for order, case in _cases(m) if case in _WANT]


def jobs(max_w):
    out = [("small",), ("routes",), ("mirrors",), ("stepped",)]
    for w in range(2, max_w + 1):
        out += [("col", w, (a,)) for a in range(w)] if w < 8 else \
               [("col", w, (a, b)) for a in range(w) for b in range(w) if a != b]
    return out


def decrypt(m, order, text, start, step, x, L, ti, sg, ct=None):
    ct = ct or _CT
    pa, ca, mode = COMBOS[ti // 3]
    g, b = RECODE[ti % 3]
    pr = {ch: i for i, ch in enumerate(ALPHAS[pa])}
    cr = {ch: i for i, ch in enumerate(ALPHAS[ca])}
    kp = (lambda i: i) if order == "ST" else (lambda i: m[i])
    r = lambda i: RANK[x][ord(text[(start + step * kp(i)) % len(text)]) - 65]
    slot = {}
    for i, P in CRIB:
        s = ((cr[ct[m[i]]] - pr[P]) if mode == "vig" else (pr[P] + cr[ct[m[i]]])) % 26
        t = RANK[b][ord(ALPHAS[g][s]) - 65]
        slot[kp(i) % L] = (r(i) - sg * t) % 26
    out = []
    for i in range(N):
        if kp(i) % L not in slot:
            out.append(".")
            continue
        tv = (sg * (r(i) - slot[kp(i) % L])) % 26
        s = ALPHAS[g].index(ALPHAS[b][tv])
        out.append(ALPHAS[pa][_dec(mode, cr[ct[m[i]]], s)])
    return "".join(out)


def run(max_w=9, srcs=None, job_list=None, min_eq=MIN_EQ, procs=30, quiet=False):
    global _WANT
    _build()
    srcs = srcs or sources()
    names = list(srcs)
    job_list = job_list or jobs(max_w)
    t0, cases, nmaps = time.time(), set(), 0
    with _CTX.Pool(procs) as pool:
        for n, c in pool.imap_unordered(_case_task, job_list):
            nmaps += n
            cases |= c
    cases = sorted(cases)
    with tempfile.TemporaryDirectory() as tmp:
        cpath, spath = os.path.join(tmp, "cases.bin"), os.path.join(tmp, "sources.txt")
        with open(cpath, "wb") as fh:
            fh.write(b"".join(cases))
        with open(spath, "w") as fh:
            fh.write("\n".join(srcs[n] for n in names) + "\n")
        res = subprocess.run([BIN, cpath, spath, PLAIN, str(min_eq), "23"], capture_output=True, text=True,
                             check=True)
    raw = [tuple(line.split()[1:]) for line in res.stdout.splitlines() if line.startswith("HIT")]
    _WANT = {cases[int(h[0])] for h in raw}
    found = {}
    if _WANT:
        with _CTX.Pool(procs) as pool:
            for part in pool.imap_unordered(_find_task, job_list):
                for label, m, order, case in part:
                    found.setdefault(case, (label, m, order))
    rows = []
    for ci, si, start, step, al, L, eq, mask in raw:
        label, m, order = found[cases[int(ci)]]
        bits = int(mask, 16)
        for bit in range(48):
            if bits >> bit & 1:
                ti, sg = bit // 2, (-1 if bit & 1 else 1)
                x = "AK"[int(al)]
                pt = decrypt(m, order, srcs[names[int(si)]], int(start), int(step), x, int(L), ti, sg)
                rows.append((int(eq), quadgram_score(pt.replace(".", "")), label, order, names[int(si)],
                             int(start), int(step), x, int(L), ti, sg, pt))
    rows.sort(key=lambda r: (-r[0], -r[1]))
    if not quiet:
        readings = sum(len(t) for t in srcs.values()) * 4
        keys = len(cases) * readings * 48
        print("\n=== key chain behind a transposition ===")
        print(f"  {nmaps:,} transpositions x 2 layer orders = {len(cases):,} distinct cases; {readings:,} text readings"
              f" x 48 settings = {keys:,} keys, key1 of any period ({time.time() - t0:.0f} s)")
        by = {}
        for r in rows:
            by[r[0]] = by.get(r[0], 0) + 1
        for eq in sorted(by):
            print(f"  passes at {eq} equalities: {by[eq]}   (chance per tested period: {keys * 26.0 ** -eq:.2f})")
        for eq, q, label, order, name, start, step, x, L, ti, sg, pt in rows[:12]:
            print(f"  PASS {eq} eq quad={q:.2f}  {label} {order}; {name} start={start} dir={step} in {x}, key1 period {L};"
                  f" {'/'.join(COMBOS[ti // 3])} recode {RECODE[ti % 3]} sign {sg:+d}\n       {pt}")
        if not rows:
            print("  no configuration is consistent with the clues")
    return rows


def control():
    global _CT
    from recipes import _planted_text
    from sculpture import K2_CT
    from solve import K3_PT
    from kryptos import KRYPTOS_KEYED as K
    saved, pt, rk, ok = _CT, _planted_text(), RANK["K"], True
    m = columnar_map(7, (3, 0, 6, 2, 5, 1, 4))
    srcs = {"K2 ct": K2_CT, "K3 pt": K3_PT}
    try:
        for order in ("ST", "TS"):
            kp = (lambda i: i) if order == "ST" else (lambda i: m[i])
            key = lambda i: (rk[ord(K2_CT[40 + kp(i)]) - 65] - rk[ord("SHADOW"[kp(i) % 6]) - 65]) % 26
            ct = [""] * N
            for i, p in enumerate(pt):
                ct[m[i]] = K[(rk[ord(p) - 65] + key(i)) % 26]
            _CT = "".join(ct)
            rows = run(srcs=srcs, job_list=[("col", 7, (3,)), ("routes",)], procs=4, quiet=True)
            good = any(r[11] == pt and r[3] == order and r[4:7] == ("K2 ct", 40, 1) and r[8] == 6 for r in rows)
            ok &= good
            print(f"[control chaint] columnar + chained key ({order}) recovered: {good}")
    finally:
        _CT = saved
    return ok


if __name__ == "__main__":
    what = sys.argv[1] if len(sys.argv) > 1 else "run"
    if what == "control":
        sys.exit(0 if control() else "control failed")
    run(int(sys.argv[2]) if len(sys.argv) > 2 else 9)
