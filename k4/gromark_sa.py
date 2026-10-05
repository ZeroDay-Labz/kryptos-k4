"""
Driver for gsolve.c: solve the two unknown alphabets of a Gromark-type cipher by
simulated annealing, for every primer that survives the crib constraints.

Run:  python gromark_sa.py control
      python gromark_sa.py run BASE:LEN [BASE:LEN ...] [--steps N] [--restarts R]
"""
from __future__ import annotations

import array
import os
import random
import subprocess
import sys
import time

import quadgrams
from kryptos import CIPHERTEXT, CRIBS, ALPHABET

HERE = os.path.dirname(os.path.abspath(__file__))
BIN = os.path.join(HERE, "gsolve")
QUAD = os.path.join(HERE, "quadgram_prose.bin")


def prepare():
    if not os.path.exists(QUAD):
        logs, floor = quadgrams.load_prose()
        arr = array.array("f", [floor]) * (26 ** 4)
        for q, v in logs.items():
            i = 0
            for ch in q:
                i = i * 26 + ord(ch) - 65
            arr[i] = v
        with open(QUAD, "wb") as fh:
            arr.tofile(fh)
    src = os.path.join(HERE, "gsolve.c")
    if not os.path.exists(BIN) or os.path.getmtime(BIN) < os.path.getmtime(src):
        subprocess.run(["gcc", "-O3", "-march=native", "-fopenmp", "-o", BIN, src, "-lm"], check=True)


def solve(jobs, ct=CIPHERTEXT, steps=300_000, restarts=4, threads=30):
    """jobs: list of (label, key[97]). Returns [(score, label, plaintext, pa, ca)] best first."""
    prepare()
    text = ct + "\n" + "".join(f"{label} {' '.join(map(str, key))}\n" for label, key in jobs)
    env = dict(os.environ, OMP_NUM_THREADS=str(threads))
    res = subprocess.run([BIN, QUAD, str(steps), str(restarts)], input=text,
                         capture_output=True, text=True, env=env, check=True)
    out = []
    for line in res.stdout.splitlines():
        sc, label, pt, pa, ca = line.split()
        out.append((float(sc), label, pt, pa, ca))
    out.sort(reverse=True)
    return out


def english_reference():
    """Score of real 97-letter English under the same model, for comparison."""
    logs, floor = quadgrams.load_prose()
    from solve import K2_PT, K3_PT
    vals = []
    for src in (K2_PT, K3_PT):
        for a in range(0, len(src) - 97, 7):
            t = src[a:a + 97]
            vals.append(sum(logs.get(t[i:i + 4], floor) for i in range(94)) / 94)
    vals.sort()
    return vals[0], vals[len(vals) // 2]


def control(steps=300_000, restarts=4):
    from gromark import expand
    rng = random.Random(21)
    # English plaintext with the cribs in place (the public reconstruction text
    # is convenient: right length, cribs at the right positions).
    pt = ("THECOMPASSROSEISHEREXEASTNORTHEASTTHISISYOURPOSITIONX"
          "COMMISSIONBERLINCLOCKWHICHISNORTHEASTOFHEREX")
    pa, ca = list(ALPHABET), list(ALPHABET)
    rng.shuffle(pa)
    rng.shuffle(ca)
    true_key = expand((2, 6, 7, 1, 7), 10)
    pr = {c: i for i, c in enumerate(pa)}
    ct = "".join(ca[(pr[p] + k) % 26] for p, k in zip(pt, true_key))
    jobs = [("true-26717", true_key)]
    for primer in ((1, 0, 3, 1, 9), (9, 8, 8, 0, 0), (3, 8, 8, 8, 8), (5, 2, 6, 5, 4)):
        jobs.append(("wrong-" + "".join(map(str, primer)), expand(primer, 10)))
    t0 = time.time()
    res = solve(jobs, ct=ct, steps=steps, restarts=restarts)
    print(f"[control] planted Gromark, random alphabets, primer 26717 ({time.time() - t0:.1f}s)")
    for sc, label, out, _, _ in res:
        same = sum(a == b for a, b in zip(out, pt))
        print(f"   {sc:.3f} {label:12} {same:2d}/97 letters correct  {out}")
    # Detection is what matters: the true primer must lead by a clear margin and
    # come out mostly readable. (A hit would then be re-run at higher effort.)
    top = res[0]
    margin = top[0] - res[1][0] if len(res) > 1 else 9
    return (top[1] == "true-26717" and margin >= 0.3
            and sum(a == b for a, b in zip(top[2], pt)) >= 60)


if __name__ == "__main__":
    args = sys.argv[1:]
    steps = int(args[args.index("--steps") + 1]) if "--steps" in args else 300_000
    restarts = int(args[args.index("--restarts") + 1]) if "--restarts" in args else 4
    if args and args[0] == "control":
        print("control passed:", control(steps, restarts))
    elif args and args[0] in ("run", "all"):
        from gromark import g2_search, expand
        lo, med = english_reference()
        print(f"real English (97 letters) scores: median {med:.2f}, worst {lo:.2f}", flush=True)
        if args[0] == "all":
            specs = [(b, n) for n in range(3, 8) for b in range(3, 27) if b ** n <= 20_000_000]
        else:
            specs = [tuple(map(int, a.split(":"))) for a in args[1:] if ":" in a]
        jobs = []
        for base, n in specs:
            _, surv = g2_search(base, n)
            jobs += [(f"b{base}n{n}:{'.'.join(map(str, p))}", expand(p, base)) for p in surv]
        print(f"primers to solve: {len(jobs):,}", flush=True)
        t0 = time.time()
        res = solve(jobs, steps=steps, restarts=restarts)
        print(f"stage 1 solved in {time.time() - t0:.0f}s", flush=True)
        keys = dict(jobs)
        top = res[:300]
        t0 = time.time()
        res2 = solve([(label, keys[label]) for _, label, *_ in top], steps=3_000_000, restarts=10)
        print(f"stage 2 (top {len(top)} re-run at 25x effort) in {time.time() - t0:.0f}s")
        with open(os.path.join(HERE, "gromark_results.txt"), "w") as fh:
            for sc, label, pt, pa, ca in res2:
                fh.write(f"{sc:.4f} {label} {pt} {pa} {ca}\n")
        scores = sorted(r[0] for r in res)
        print(f"stage 1 score distribution: best {scores[-1]:.2f}, 99th pct "
              f"{scores[int(len(scores) * 0.99)]:.2f}, median {scores[len(scores) // 2]:.2f}")
        print("best decryptions after stage 2:")
        for sc, label, pt, pa, ca in res2[:12]:
            print(f"  {sc:.3f} {label}\n      {pt}")
