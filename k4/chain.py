"""
Key chains: a basic key decodes a text into a second key, which decodes K4 (or
decodes another text into a third key, which decodes K4).

Why only long keys are tested here: a chain that ENDS in a repeating key of
period <= 23 on the A-Z / KRYPTOS tableaux is already excluded however that key
was produced, because cribdrag.py and frontier.py derive the key from the clues
instead of guessing it. So a chain can only matter if the final key is a long,
non-repeating stream. The natural hand method for that (and Scheidt's "the keys
were concealed at the sculpture", "it conveys not only the encrypted data, but
also the key") is: take a text you can read off the sculpture, decode it with a
short keyword on the tableau, and use the RESULT as the running key.

  level 2   key2 = tableau(X, key1)                 K4 keyed by key2
  level 3   key2 = tableau(X1, key1), key3 = tableau(X2, key2)   K4 keyed by key3
  feedback  key2 = tableau(K4 plaintext shifted by a lag, key1)  (autokey + keyword)

X, X1, X2 are any stretch of a known text (sculpture ciphertext including K4
itself, K1-K3 plaintext, the tableau, the Morse text, Sanborn's source
documents), read from any start, forwards or backwards, every n-th letter.
key1 is NOT guessed: it is any repeating key of period <= 18, derived from the
clues. Each tableau step may use the A-Z or the KRYPTOS alphabet, add or
subtract, and the intermediate key letters may be re-read in the other alphabet.

A configuration passes if the 24 clue letters force consistent values for key1;
with c forced equalities a chance pass has probability 26**-c.

  derived   key2 = tableau(word, key1) is a short derived keyword (not a word any
            more), used to build K4's alphabet or as the key of an inner tableau
            layer; key3 = tableau(word, key2) likewise. Fed to keyhunt.py.

Run:  python chain.py [control|level2|level3|feedback|derived|themed|all]
"""
from __future__ import annotations

import multiprocessing as mp
import os
import subprocess
import sys
import time

from kryptos import CIPHERTEXT, ALPHABET, KRYPTOS_KEYED
from frontier import CRIB, CRIB_IDX, N, COMBOS, ALPHAS, _shift, _dec, _slot_pairs
from sculpture import TABLEAU_ROWS
from texts import ALL_TEXTS
from quadgrams import quadgram_score

_CTX = mp.get_context("fork")
RANK = {x: [a.index(chr(65 + c)) for c in range(26)] for x, a in ALPHAS.items()}
MIN_EQ = 6                 # equalities needed to report a level-2 pass
MIN_EQ3 = 8                # level 3 has ~10^11 configurations, so it needs more
MAX_STRIDE = 30
PAIRS = {L: _slot_pairs(CRIB_IDX, L) for L in range(1, 24)}


def sources() -> dict[str, str]:
    width = max(len(r) for r in TABLEAU_ROWS)
    out = dict(ALL_TEXTS)
    out["tableau by columns"] = "".join(r[c] for c in range(width) for r in TABLEAU_ROWS
                                        if c < len(r) and r[c] != " ")
    out["tableau body"] = "".join(r[1:] for r in TABLEAU_ROWS[1:-1])
    return out


def targets(ct: str):
    """Distinct sequences t that key2 must produce at the clue positions.

    s = shift K4 needs under one alphabet/arithmetic setting; the key letter that
    gives that shift is read in alphabet g, and was produced by a tableau step
    whose output alphabet is b. t = rank_b(g[s])."""
    seen, out = set(), []
    for k, (pa, ca, mode) in enumerate(COMBOS):
        pr = {ch: i for i, ch in enumerate(ALPHAS[pa])}
        cr = {ch: i for i, ch in enumerate(ALPHAS[ca])}
        s = [_shift(mode, pr[P], cr[ct[i]]) for i, P in CRIB]
        for g, b in (("A", "A"), ("A", "K"), ("K", "A")):
            t = tuple(RANK[b][ord(ALPHAS[g][v]) - 65] for v in s)
            if t not in seen:
                seen.add(t)
                out.append((t, k, g, b))
    return out


def _sig(v, pairs):
    return bytes([(v[a] - v[b]) % 26 for a, b in pairs])


def _target_sigs(ct, min_eq):
    """{L: {signature: [(target index, sign)]}} for the periods worth testing."""
    tg = targets(ct)
    table = {}
    for L, pairs in PAIRS.items():
        if len(pairs) < min_eq:
            continue
        d = {}
        for ti, (t, _, _, _) in enumerate(tg):
            for sg in (1, -1):
                d.setdefault(_sig([sg * x for x in t], pairs), []).append((ti, sg))
        table[L] = d
    return tg, table


def _stream(src, start, step):
    n = len(src)
    return [src[(start + step * i) % n] for i in CRIB_IDX]


# --- level 2 --------------------------------------------------------------------

_SRC: dict[str, str] = {}
_TSIG = {}


def _level2_task(args):
    name, step = args
    src = [ord(c) - 65 for c in _SRC[name]]
    hits = []
    for start in range(len(src)):
        key = _stream(src, start, step)
        for x in "AK":
            r = [RANK[x][c] for c in key]
            for L, d in _TSIG.items():
                got = d.get(_sig(r, PAIRS[L]))
                if got:
                    hits += [(name, start, step, x, L, ti, sg) for ti, sg in got]
    return len(src), hits


def level2_decrypt(ct, tg, hit, srcs):
    name, start, step, x, L, ti, sg = hit
    t, k, g, b = tg[ti]
    pa, ca, mode = COMBOS[k]
    src, n = srcs[name], len(srcs[name])
    r = lambda i: RANK[x][ord(src[(start + step * i) % n]) - 65]
    slot = {i % L: (r(i) - sg * t[j]) % 26 for j, i in enumerate(CRIB_IDX)}
    return _finish(ct, lambda i: sg * (r(i) - slot[i % L]) if i % L in slot else None, g, b, pa, ca, mode)


def _finish(ct, tval, g, b, pa, ca, mode):
    cr = {ch: i for i, ch in enumerate(ALPHAS[ca])}
    out = []
    for i in range(N):
        tv = tval(i)
        if tv is None:
            out.append(".")
            continue
        s = ALPHAS[g].index(ALPHAS[b][tv % 26])
        out.append(ALPHAS[pa][_dec(mode, cr[ct[i]], s)])
    return "".join(out)


def run_level2(ct=CIPHERTEXT, srcs=None, max_stride=MAX_STRIDE, procs=30, quiet=False):
    global _SRC, _TSIG
    srcs = srcs or sources()
    tg, _TSIG = _target_sigs(ct, MIN_EQ)
    _SRC = srcs
    jobs = [(name, sg * st) for name in srcs for st in range(1, max_stride + 1) for sg in (1, -1)]
    t0, total, hits = time.time(), 0, []
    with _CTX.Pool(procs) as pool:
        for n, h in pool.imap_unordered(_level2_task, jobs, chunksize=4):
            total += n
            hits += h
    rows = []
    for h in hits:
        pt = level2_decrypt(ct, tg, h, srcs)
        rows.append((len(PAIRS[h[4]]), quadgram_score(pt.replace(".", "")), h, pt))
    rows.sort(key=lambda r: (-r[0], -r[1]))
    if not quiet:
        tests = total * 2 * 2 * len(tg)
        print("\n=== level 2: known text decoded by a repeating key, result used as K4's key ===")
        print(f"  {len(srcs)} texts, {total:,} readings (start x stride <= {max_stride} x direction)"
              f" x {2 * 2 * len(tg)} settings = {tests:,} keys; key1 of any period <= {max(_TSIG)}")
        print(f"  expected by chance at {MIN_EQ} equalities: {tests * 26.0 ** -MIN_EQ:.2f}")
        _print_rows(rows, tg, t0)
    return rows


def _print_rows(rows, tg, t0):
    for eq, q, h, pt in rows[:12]:
        print(f"  PASS {eq} equalities  quad={q:.2f}  {_describe(h, tg)}\n       {pt}")
    if not rows:
        print("  no configuration is consistent with the clues")
    print(f"  ({time.time() - t0:.0f} s)")


def _describe(h, tg):
    if len(h) == 7:
        name, start, step, x, L, ti, sg = h
        t, k, g, b = tg[ti]
        return (f"{name} start={start} stride={step} read in {x}, {'minus' if sg > 0 else 'plus'} key1 "
                f"period {L}; K4 as {'/'.join(COMBOS[k])} key letters {b}->{g}")
    (n1, s1, st1, x1), (n2, s2, st2, x2), f, L, ti, e = h
    t, k, g, b = tg[ti]
    return (f"[{n1} start={s1} dir={st1} in {x1}] {'+' if f > 0 else '-'} [{n2} start={s2} dir={st2} in {x2}]"
            f", key1 period {L}; K4 as {'/'.join(COMBOS[k])} key letters {b}->{g} sign {e:+d}")


# --- level 3 --------------------------------------------------------------------

_STREAMS = []        # (name, start, step, alphabet, ranks at the clue positions)
_JOIN = {}           # {L: {signature: [stream index]}}
_TG = []


def _level3_task(args):
    L, lo, hi = args
    pairs, join = PAIRS[L], _JOIN[L]
    tsig = [(ti, e, _sig([e * x for x in t], pairs)) for ti, (t, _, _, _) in enumerate(_TG) for e in (1, -1)]
    hits = []
    for j in range(lo, hi):
        s2 = _sig(_STREAMS[j][4], pairs)
        for f in (1, -1):
            for ti, e, ts in tsig:
                # R1 + f*R2 - e*t is periodic  <=>  sig(R1) = e*sig(t) - f*sig(R2)
                q = bytes([(a - f * c) % 26 for a, c in zip(ts, s2)])
                for i in join.get(q, ()):
                    if i < j or (i == j and f == 1):
                        hits.append((i, j, f, L, ti, e))
    return hi - lo, hits


def level3_decrypt(ct, tg, hit, srcs):
    (n1, a1, st1, x1), (n2, a2, st2, x2), f, L, ti, e = hit
    t, k, g, b = tg[ti]
    pa, ca, mode = COMBOS[k]
    r1 = lambda i: RANK[x1][ord(srcs[n1][(a1 + st1 * i) % len(srcs[n1])]) - 65]
    r2 = lambda i: RANK[x2][ord(srcs[n2][(a2 + st2 * i) % len(srcs[n2])]) - 65]
    slot = {i % L: (r1(i) + f * r2(i) - e * t[j]) % 26 for j, i in enumerate(CRIB_IDX)}
    return _finish(ct, lambda i: e * (r1(i) + f * r2(i) - slot[i % L]) if i % L in slot else None,
                   g, b, pa, ca, mode)


def run_level3(ct=CIPHERTEXT, srcs=None, procs=30, quiet=False):
    global _STREAMS, _JOIN, _TG
    srcs = srcs or sources()
    _TG = tg = targets(ct)
    _STREAMS = []
    for name, text in srcs.items():
        src = [ord(c) - 65 for c in text]
        for step in (1, -1):
            for start in range(len(src)):
                key = _stream(src, start, step)
                for x in "AK":
                    _STREAMS.append((name, start, step, x, [RANK[x][c] for c in key]))
    periods = [L for L, p in PAIRS.items() if len(p) >= MIN_EQ3]
    _JOIN = {}
    for L in periods:
        d = {}
        for i, st in enumerate(_STREAMS):
            d.setdefault(_sig(st[4], PAIRS[L]), []).append(i)
        _JOIN[L] = d
    m = len(_STREAMS)
    jobs = [(L, lo, min(lo + 2000, m)) for L in periods for lo in range(0, m, 2000)]
    t0, hits = time.time(), []
    with _CTX.Pool(procs) as pool:
        for _, h in pool.imap_unordered(_level3_task, jobs):
            hits += h
    rows = []
    for i, j, f, L, ti, e in hits:
        h = (_STREAMS[i][:4], _STREAMS[j][:4], f, L, ti, e)
        pt = level3_decrypt(ct, tg, h, srcs)
        rows.append((len(PAIRS[L]), quadgram_score(pt.replace(".", "")), h, pt))
    rows.sort(key=lambda r: (-r[0], -r[1]))
    if not quiet:
        tests = m * (m + 1) * len(tg) * 2
        print("\n=== level 3: text decoded by key1 gives key2, which decodes a second text into K4's key ===")
        print(f"  {m:,} readings (every start, both directions, both alphabets) paired = {tests:,} keys;"
              f" key1 of any period <= {max(periods)}")
        by = {}
        for eq, *_ in rows:
            by[eq] = by.get(eq, 0) + 1
        for eq in sorted(by):
            n_per = sum(1 for L in periods if len(PAIRS[L]) == eq)
            print(f"  passes at {eq} equalities: {by[eq]}   (expected by chance: {tests * n_per * 26.0 ** -eq:.2f})")
        _print_rows(rows, tg, t0)
    return rows


# --- feedback: the message itself, shifted, is the text ----------------------------

def run_feedback(ct=CIPHERTEXT, quiet=False, min_eq=5):
    """key2 letter at i = tableau(plaintext[i - lag], key1[i mod L]): autokey with a keyword
    re-applied. (Ciphertext feedback is part of level 2: K4 is in the sculpture text.)"""
    tg = targets(ct)
    pos = {i: j for j, i in enumerate(CRIB_IDX)}
    found = []
    for lag in range(1, N):
        js = [(j, pos[i - lag]) for j, i in enumerate(CRIB_IDX) if i - lag in pos]
        if len(js) < min_eq + 1:
            continue
        for L in range(1, 24):
            pairs = _slot_pairs([CRIB_IDX[j] for j, _ in js], L)
            if len(pairs) < min_eq:
                continue
            for x in "AK":
                r = [RANK[x][ord(CRIB[jj][1]) - 65] for _, jj in js]
                for ti, (t, k, g, b) in enumerate(tg):
                    for sg in (1, -1):
                        d = [(r[n] - sg * t[j]) % 26 for n, (j, _) in enumerate(js)]
                        if all(d[a] == d[b2] for a, b2 in pairs):
                            found.append((len(pairs), lag, L, x, "/".join(COMBOS[k]), sg))
    if not quiet:
        print("\n=== feedback: K4 plaintext at a lag, decoded by a repeating key, is K4's key ===")
        for row in sorted(found, reverse=True)[:10]:
            print("  PASS %d equalities  lag=%d period=%d alphabet=%s %s sign=%+d" % row)
        if not found:
            print(f"  no lag 1-{N - 1} with any key period <= 23 is consistent (>= {min_eq} equalities)")
    return found


# --- derived keywords ---------------------------------------------------------------

CORE = "KRYPTOS PALIMPSEST PALIMPCEST ABSCISSA SHADOW FORCES LUCID MEMORY BERLIN CLOCK IQLUSION DYAHR".split()
DERIVED = os.path.join(os.path.expanduser("~/.cache/krypto_k4"), "derived_keys.txt")
_OPS = [(x, sp, sk) for x in "AK" for sp, sk in ((1, -1), (-1, 1), (1, 1))]     # text - key, key - text, text + key


def _combine(text, key, op):
    """One tableau step: `text` decoded by `key` (repeated), as a new keyword."""
    x, sp, sk = op
    r, a, n = RANK[x], ALPHAS[x], len(key)
    return "".join(a[(sp * r[ord(c) - 65] + sk * r[ord(key[i % n]) - 65]) % 26] for i, c in enumerate(text))


_CORE_NOW = CORE


def _derive_task(words):
    out = []
    for w in words:
        for c in _CORE_NOW:
            for op in _OPS:
                out.append(_combine(w, c, op))
                out.append(_combine(c, w, op))
    return "\n".join(out) + "\n"


def build_derived(path=DERIVED, procs=30, core=None):
    """core x dictionary (two levels, either word as the text) and themed x themed x core (three)."""
    global _CORE_NOW
    import recipes as R
    if os.path.exists(path):
        return path
    _CORE_NOW = core or CORE
    raw = path + ".raw"
    words = R.load_words()
    with open(raw, "w") as fh:
        with _CTX.Pool(procs) as pool:
            for block in pool.imap_unordered(_derive_task, [words[i:i + 2000] for i in range(0, len(words), 2000)]):
                fh.write(block)
        for t in R.THEMED:
            for u in R.THEMED:
                for op in _OPS:
                    k2 = _combine(t, u, op)
                    fh.write(k2 + "\n")
                    for c in R.THEMED:
                        for op2 in _OPS:
                            fh.write(_combine(c, k2, op2) + "\n")
    subprocess.run(f"LC_ALL=C awk 'length($0) >= 3' '{raw}' | LC_ALL=C sort -u -S 4G --parallel=8 > '{path}'"
                   f" && rm '{raw}'", shell=True, check=True)
    return path


def run_themed():
    """Every themed word, every two-word phrase, and every one-step chain of two themed words,
    through all the keyword-guessing tests in keyhunt.py."""
    import recipes as R
    import keyhunt
    keys = set(R.THEMED)
    for t in R.THEMED:
        for u in R.THEMED:
            keys.add(t + u)
            for op in _OPS:
                keys.add(_combine(t, u, op))
    path = os.path.join(os.path.expanduser("~/.cache/krypto_k4"), "themed_keys.txt")
    with open(path, "w") as fh:
        fh.write("\n".join(sorted(k for k in keys if 3 <= len(k) <= 30)) + "\n")
    print(f"\n=== themed keys: {len(R.THEMED)} words, two-word phrases and one-step chains = {len(keys):,} keys"
          " (headings below say 37.7M; this run uses the themed list) ===")
    for f in (keyhunt.run_alphabets, keyhunt.run_layers, keyhunt.run_pairs, keyhunt.run_texts,
              keyhunt.run_tolerant, keyhunt.run_autokey):
        f(path)


def run_derived(core=None, path=DERIVED):
    import keyhunt
    path = build_derived(path, core=core)
    print(f"\n=== derived keywords: tableau(word, basic key), and a third level on the themed list ===")
    print(f"  {path}: {os.path.getsize(path) / 1e6:.0f} MB (the headings below say 37.7M; this run uses the derived list)")
    keyhunt.run_alphabets(path)
    keyhunt.run_layers(path)


# --- control ----------------------------------------------------------------------

def control():
    from recipes import _planted_text
    from sculpture import K2_CT
    from solve import K3_PT
    pt = _planted_text()
    K, rk = KRYPTOS_KEYED, RANK["K"]
    code = lambda s: [ord(c) - 65 for c in s]
    # level 2: K2 ciphertext from letter 40, decoded on the KRYPTOS tableau by SHADOW,
    # is the key of a KRYPTOS-tableau Vigenere
    key2 = [(rk[c] - rk[ord("SHADOW"[i % 6]) - 65]) % 26 for i, c in enumerate(code(K2_CT[40:40 + N]))]
    ct = "".join(K[(rk[ord(p) - 65] + key2[i]) % 26] for i, p in enumerate(pt))
    rows = run_level2(ct, {"K2 ct": K2_CT, "K3 pt": K3_PT}, max_stride=3, procs=4, quiet=True)
    ok2 = any(r[3] == pt and r[2][:3] == ("K2 ct", 40, 1) and r[2][4] == 6 for r in rows)
    print(f"[control chain] level 2 (K2 ciphertext + SHADOW -> key) recovered: {ok2}")
    # level 3: key2 above decodes K3 plaintext (from letter 100, backwards) into key3
    x2 = [rk[c] for c in code(K3_PT)]
    key3 = [(x2[(100 - i) % len(x2)] - key2[i]) % 26 for i in range(N)]
    ct = "".join(K[(rk[ord(p) - 65] + key3[i]) % 26] for i, p in enumerate(pt))
    rows = run_level3(ct, {"K2 ct": K2_CT, "K3 pt": K3_PT}, procs=4, quiet=True)
    ok3 = any(r[3] == pt and r[2][3] == 6 for r in rows)
    print(f"[control chain] level 3 (K2 ciphertext + SHADOW -> key2; K3 plaintext + key2 -> key3) recovered: {ok3}")
    # feedback: autokey lag 3 with LUCID added
    p = code(pt)
    ct = "".join(chr(65 + (p[i] + (p[i - 3] if i >= 3 else 3) + ord("LUCID"[i % 5]) - 65) % 26) for i in range(N))
    okf = any(row[1] == 3 and row[2] == 5 for row in run_feedback(ct, quiet=True))
    print(f"[control chain] feedback (autokey lag 3 + LUCID) recovered: {okf}")
    return ok2 and ok3 and okf


if __name__ == "__main__":
    what = sys.argv[1] if len(sys.argv) > 1 else "all"
    COMMANDS = ("control", "level2", "level3", "feedback", "derived", "themed", "from", "all")
    if what not in COMMANDS:            # bare words: treat them as basic keys, like "from"
        if not all(a.isalpha() for a in sys.argv[1:]):
            sys.exit(f"usage: python chain.py [{'|'.join(COMMANDS)}]  or  python chain.py WORD [WORD ...]")
        sys.argv.insert(1, "from")
        what = "from"
    if what in ("control", "all"):
        if not control():
            sys.exit("control failed")
    if what in ("level2", "all"):
        run_level2()
    if what in ("feedback", "all"):
        run_feedback()
    if what in ("level3", "all"):
        run_level3()
    if what == "themed":
        run_themed()
    if what in ("derived", "all"):
        run_derived()
    if what == "from":                  # python chain.py from QLUEO ILLUSION ...  (basic keys of your choice)
        keys = [k.upper() for k in sys.argv[2:]]
        run_derived(keys, DERIVED.replace("derived_keys", "derived_" + "_".join(keys)[:60]))
