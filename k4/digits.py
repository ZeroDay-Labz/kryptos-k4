"""
Digit keys with two unknown mixed alphabets.

blackbox.py shows K4's clue letters behave like a cipher keyed with SMALL NUMBERS
over near-standard alphabets. gromark.py / gromark_sa.py covered digit keys grown
from a primer by the lagged-Fibonacci rule. This module covers the other simple
ways a hand cipher gets a digit key:

  period8   every repeating 8-digit key (e.g. a date): periods 1-7 and 9-12 are
            already impossible for ANY alphabets, and 8 is the only short period
            left. All 10^8 keys are filtered by the clue constraints, then the
            survivors go to the alphabet solver (gsolve).
  named     specific numbers tied to the sculpture and Sanborn's papers
            (coordinates, dates, job numbers, keyword-to-number conversions),
            repeating or Gromark-expanded, with both alphabets unknown.

Run:  python digits.py [period8|named|all]
"""
from __future__ import annotations

import itertools
import sys
import time
from multiprocessing import get_context

from frontier import N
import gromark
import gromark_sa

_CTX = get_context("fork")


def _period_task(args):
    L, lead = args
    out = []
    for rest in itertools.product(range(10), repeat=L - len(lead)):
        d = lead + rest
        if d[27 % L] != d[65 % L]:          # plain R -> cipher P at both positions
            continue
        key = [d[i % L] for i in range(N)]
        if gromark.primer_ok(key):
            out.append(d)
    return out


def periodic_survivors(L=8, procs=30):
    tasks = [(L, lead) for lead in itertools.product(range(10), repeat=3)]
    out = []
    with _CTX.Pool(procs) as pool:
        for s in pool.imap_unordered(_period_task, tasks, chunksize=4):
            out += s
    return sorted(out)


def _solve_and_report(jobs, title, top=300):
    lo, med = gromark_sa.english_reference()
    print(f"  keys that survive the clue constraints: {len(jobs):,}", flush=True)
    if not jobs:
        return []
    t0 = time.time()
    res = gromark_sa.solve(jobs, steps=500_000, restarts=4)
    keys = dict(jobs)
    res2 = gromark_sa.solve([(label, keys[label]) for _, label, *_ in res[:top]],
                            steps=3_000_000, restarts=10)
    scores = sorted(r[0] for r in res)
    print(f"  solved in {time.time() - t0:.0f}s; real English scores {med:.2f} (worst {lo:.2f})")
    print(f"  first pass: best {scores[-1]:.2f}, median {scores[len(scores) // 2]:.2f}; "
          f"best after re-running the top {min(top, len(res))} at 25x effort:")
    for sc, label, pt, pa, ca in res2[:8]:
        print(f"    {sc:.3f} {label}\n      {pt}")
    return res2


def run_period8():
    print("\n=== every repeating 8-digit key, both alphabets unknown ===")
    t0 = time.time()
    surv = periodic_survivors(8)
    print(f"  100,000,000 keys filtered in {time.time() - t0:.0f}s")
    jobs = [("".join(map(str, d)), [d[i % 8] for i in range(N)]) for d in surv]
    return _solve_and_report(jobs, "period 8")


def run_named():
    import recipes
    print("\n=== numbers from the sculpture and Sanborn's papers as digit keys, both alphabets unknown ===")
    jobs, seen = [], set()
    for label, key in recipes._numeric_keys():
        t = tuple(key)
        if t in seen or not gromark.primer_ok(key):
            continue
        seen.add(t)
        jobs.append((label.replace(" ", "_"), key))
    return _solve_and_report(jobs, "named numbers", top=100)


if __name__ == "__main__":
    what = sys.argv[1] if len(sys.argv) > 1 else "all"
    if what in ("named", "all"):
        run_named()
    if what in ("period8", "all"):
        run_period8()
