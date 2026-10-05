"""
Structural tests on K4 that do not depend on guessing a keyword or alphabet.

A  general periodic substitution  - any 26 unrelated alphabets, period L
B  Quagmire with ARBITRARY mixed alphabets - solve the alphabet ranks as a
   linear system over Z26 (mod 2 and mod 13); a period is impossible if the
   cribs force two different letters onto the same rank
C  Hill cipher (2x2, 3x3, optionally affine)
D  polynomial key  shift_i = a0 + a1*i + ... + aD*i^D
E  keys read off the sculpture: any start/stride/direction through the
   ciphertext, tableau, K1-K3 plaintext or Morse text, and grid-aligned cells;
   fuzzy (tolerates wrong letters, since Sanborn makes errors)
F  running key in English: do the implied key fragments read as words?

Run:  python structural.py [control|periodic|hill|sources|english|maps|all]
"""
from __future__ import annotations

import itertools
import random
import sys
import time
from collections import Counter
from multiprocessing import Pool

from kryptos import CIPHERTEXT, ALPHABET, KRYPTOS_KEYED, keyed_alphabet
from frontier import (CRIB, CRIB_IDX, N, ALPHAS, COMBOS, TABS, CTI, _shift, _slot_pairs,
                      _consistent_mod, columnar_map, inverse, small_families)
import quadgrams

CRIB_P = [P for _, P in CRIB]
MODELS = ["QIII", "QIV", "QI:A", "QI:K", "QII:A", "QII:K"]


# --- A. general periodic substitution ---------------------------------------

def general_periodic_ok(cl, kp, L):
    fwd, rev = {}, {}
    for P, c, x in zip(CRIB_P, cl, kp):
        s = x % L
        if fwd.setdefault((s, P), c) != c or rev.setdefault((s, c), P) != P:
            return False
    return True


# --- B. Quagmire with arbitrary alphabets ------------------------------------

def _param(rows, p, n):
    """Solve [A|b] over GF(p). None if inconsistent, else per-variable signature
    (coefficients on the free variables, constant); equal signatures = forced equal."""
    rows = [[v % p for v in r] for r in rows]
    piv_cols, rank = [], 0
    for col in range(n):
        piv = next((r for r in range(rank, len(rows)) if rows[r][col]), None)
        if piv is None:
            continue
        rows[rank], rows[piv] = rows[piv], rows[rank]
        inv = pow(rows[rank][col], -1, p)
        rows[rank] = [(v * inv) % p for v in rows[rank]]
        for r in range(len(rows)):
            if r != rank and rows[r][col]:
                f = rows[r][col]
                rows[r] = [(a - f * b) % p for a, b in zip(rows[r], rows[rank])]
        piv_cols.append(col)
        rank += 1
    if any(rows[r][n] for r in range(rank, len(rows))):
        return None
    free = [c for c in range(n) if c not in piv_cols]
    sig = {}
    for r, col in enumerate(piv_cols):
        sig[col] = (tuple((-rows[r][f]) % p for f in free), rows[r][n])
    for f in free:
        sig[f] = (tuple(1 if g == f else 0 for g in free), 0)
    return sig


def quagmire_any_ok(cl, kp, L, model, mode):
    """False = no Quagmire of this type and period can produce the cribs,
    whatever the mixed alphabet(s). True = not excluded."""
    pairs = _slot_pairs(kp, L)
    if not pairs:
        return True
    kind, _, known = model.partition(":")
    # `known` is "A", "K", or a literal 26-letter alphabet
    known_rank = {ch: i for i, ch in enumerate(ALPHAS.get(known, known))} if known else None
    var = {}

    def v(block, letter):
        return var.setdefault((block, letter), len(var))

    sigma = -1 if mode == "vig" else 1
    eqs = []
    for a, b in pairs:
        terms = [("c", cl[a], 1), ("p", CRIB_P[a], sigma),
                 ("c", cl[b], -1), ("p", CRIB_P[b], -sigma)]
        coef, rhs = {}, 0
        for block, letter, w in terms:
            if kind == "QIII":
                block = "x"
            if (kind == "QI" and block == "c") or (kind == "QII" and block == "p"):
                rhs -= w * known_rank[letter]
            else:
                i = v(block, letter)
                coef[i] = coef.get(i, 0) + w
        eqs.append((coef, rhs))
    n = len(var)
    rows = [[coef.get(i, 0) for i in range(n)] + [rhs] for coef, rhs in eqs]
    s2, s13 = _param(rows, 2, n), _param(rows, 13, n)
    if s2 is None or s13 is None:
        return False
    seen = set()
    for (block, _), i in var.items():
        key = (block, s2[i], s13[i])
        if key in seen:
            return False            # two letters forced to the same rank
        seen.add(key)
    return True


def cipher_letters(m, ct=CIPHERTEXT):
    return [ct[m[i]] for i in CRIB_IDX]


def periodic_report(max_L=26, null_trials=400):
    ident = list(range(N))
    cl = cipher_letters(ident)
    rng = random.Random(7)
    nulls = []
    for _ in range(null_trials):
        m = ident[:]
        rng.shuffle(m)
        nulls.append(cipher_letters(m))
    print("\n=== periodic substitution with ARBITRARY alphabets (no transposition) ===")
    print("cell = real K4 passes? (share of random texts that pass)")
    cols = ["any-alphabets"] + [f"{mo}/{md}" for mo in MODELS for md in ("vig", "beau")]
    print("  L  " + "  ".join(f"{c:>13}" for c in cols))
    survivors = []
    for L in range(1, max_L + 1):
        cells = []
        ok = general_periodic_ok(cl, CRIB_IDX, L)
        rate = sum(general_periodic_ok(x, CRIB_IDX, L) for x in nulls) / null_trials
        cells.append(f"{'PASS' if ok else 'no':>4} ({rate:5.1%})")
        for mo in MODELS:
            for md in ("vig", "beau"):
                ok = quagmire_any_ok(cl, CRIB_IDX, L, mo, md)
                rate = sum(quagmire_any_ok(x, CRIB_IDX, L, mo, md) for x in nulls[:100]) / 100
                cells.append(f"{'PASS' if ok else 'no':>4} ({rate:5.1%})")
                if ok and rate <= 0.05:
                    survivors.append((L, mo, md, rate))
        print(f"{L:3d}  " + "  ".join(f"{c:>13}" for c in cells))
    print("passes that random text rarely achieves (<=5%):", survivors or "none")
    return survivors


# --- C. Hill ------------------------------------------------------------------

def hill_report():
    print("\n=== Hill cipher (C = M.P [+ b]), all block alignments ===")
    found = []
    for n in (2, 3, 4):
        for a in range(n):
            blocks = [s for s in range(a, N - n + 1, n)
                      if all((s + u) in dict(CRIB) for u in range(n))]
            for pa, ca in itertools.product("AK", repeat=2):
                pr = {ch: i for i, ch in enumerate(ALPHAS[pa])}
                cr = {ch: i for i, ch in enumerate(ALPHAS[ca])}
                cd = dict(CRIB)
                for affine in (False, True):
                    nu = n + affine
                    if len(blocks) <= nu:
                        continue            # not enough known blocks to test
                    ok = True
                    for t in range(n):
                        rows = [[pr[cd[s + u]] for u in range(n)] + ([1] if affine else [])
                                + [cr[CIPHERTEXT[s + t]]] for s in blocks]
                        if not (_consistent_mod(rows, 2, nu)[1][0]
                                and _consistent_mod(rows, 13, nu)[1][0]):
                            ok = False
                            break
                    if ok:
                        found.append((n, a, pa, ca, affine, len(blocks)))
    for f in found:
        print("  consistent:", f)
    if not found:
        print("  no crib-consistent configuration (2x2, 3x3 linear and affine; 4x4 linear)")
    return found


# --- D. polynomial key --------------------------------------------------------

def polynomial_report(max_deg=8):
    print("\n=== polynomial key  shift_i = a0 + a1*i + ... + aD*i^D ===")
    S = [[tab[j][CTI[i]] for j, i in enumerate(CRIB_IDX)] for tab in TABS]
    found = []
    for D in range(0, max_deg + 1):
        rows = [[pow(i, d, 26) for d in range(D + 1)] + [s[j] for s in S]
                for j, i in enumerate(CRIB_IDX)]
        ok2 = _consistent_mod(rows, 2, D + 1)[1]
        ok13 = _consistent_mod(rows, 13, D + 1)[1]
        found += [(D, COMBOS[k]) for k in range(len(COMBOS)) if ok2[k] and ok13[k]]
    print("  consistent:", found or "none (degrees 0-%d)" % max_deg)
    return found


# --- D2. keys generated by a recurrence or feedback rule ------------------------

_WINDOWS = [(21, 33), (63, 73)]     # crib index ranges (inclusive)


def recurrence_report(ct=CIPHERTEXT, quiet=False):
    """Is the forced key consistent with ANY rule of these forms (coefficients free)?

      linear recurrence   s_i = c0 + c1*s_(i-1) + ... + cr*s_(i-r)          r <= 5
      lagged Fibonacci    s_i = c0 + s_(i-a) + s_(i-b)                      a < b <= 10
      mixed feedback      s_i = c0 + c1*i + a*P_(i-L) + b*C_(i-L) + g*s_(i-L)   L <= 7
    """
    cd = dict(CRIB)
    found = []
    for k, (pa, ca, mode) in enumerate(COMBOS):
        pr = {ch: i for i, ch in enumerate(ALPHAS[pa])}
        cr = {ch: i for i, ch in enumerate(ALPHAS[ca])}
        s = {i: _shift(mode, pr[P], cr[ct[i]]) for i, P in CRIB}

        def consistent(rows, nu):
            return (len(rows) - nu >= 4 and _consistent_mod(rows, 2, nu)[1][0]
                    and _consistent_mod(rows, 13, nu)[1][0])

        for r in range(1, 6):
            rows = [[1] + [s[i - j] for j in range(1, r + 1)] + [s[i]]
                    for lo, hi in _WINDOWS for i in range(lo + r, hi + 1)]
            if consistent(rows, r + 1):
                found.append((f"linear recurrence order {r}", COMBOS[k]))
        for a in range(1, 11):
            for b in range(a + 1, 11):
                d = {(s[i] - s[i - a] - s[i - b]) % 26
                     for lo, hi in _WINDOWS for i in range(lo + b, hi + 1)}
                n = sum(hi - lo - b + 1 for lo, hi in _WINDOWS if hi - lo - b + 1 > 0)
                if n >= 5 and len(d) == 1:
                    found.append((f"lagged Fibonacci lags {a},{b}", COMBOS[k]))
        for L in range(1, 8):
            rows = [[1, i, pr[cd[i - L]], cr[ct[i - L]], s[i - L], s[i]]
                    for lo, hi in _WINDOWS for i in range(lo + L, hi + 1)]
            if consistent(rows, 5):
                found.append((f"mixed feedback lag {L}", COMBOS[k]))
    if not quiet:
        print("\n=== keys generated by a recurrence or feedback rule (coefficients free) ===")
        print("  consistent:", found or "none")
    return found


# --- E. keys read off the sculpture -------------------------------------------

def _shift_sets(ct=CIPHERTEXT):
    out = []
    for pa, ca, mode in COMBOS:
        pr = {ch: i for i, ch in enumerate(ALPHAS[pa])}
        cr = {ch: i for i, ch in enumerate(ALPHAS[ca])}
        out.append([_shift(mode, pr[P], cr[ct[i]]) for i, P in CRIB])
    return out


def _best_agreement(S, key_letters, ranks):
    """Most crib positions agreeing on shift - rank(key) = const, over combos/alphabets."""
    best = (0, None)
    for xname, xr in ranks.items():
        kr = [xr[ch] for ch in key_letters]
        for k, s in enumerate(S):
            cnt = max(Counter((a - b) % 26 for a, b in zip(s, kr)).values())
            if cnt > best[0]:
                best = (cnt, (k, xname))
    return best


def sources_report(ct=CIPHERTEXT, max_stride=120, flag=11, quiet=False, only=None):
    from sculpture import FULL_CT_LETTERS, TABLEAU_ROWS, CIPHER_ROWS, MORSE, K4_CELLS
    from solve import K1_PT, K2_PT, K3_PT
    S = _shift_sets(ct)
    ranks = {x: {ch: i for i, ch in enumerate(a)} for x, a in ALPHAS.items()}
    tab_rows = [r.replace(" ", "") for r in TABLEAU_ROWS]
    width = max(len(r) for r in TABLEAU_ROWS)
    tab_cols = "".join(r[c] for c in range(width) for r in TABLEAU_ROWS
                       if c < len(r) and r[c] != " ")
    sources = {
        "sculpture ciphertext K1-K4": FULL_CT_LETTERS,
        "K1-K3 plaintext": K1_PT + K2_PT + K3_PT,
        "tableau by rows": "".join(tab_rows),
        "tableau by columns": tab_cols,
        "tableau body (no labels/headers)": "".join(r[1:] for r in TABLEAU_ROWS[1:-1]),
        "Morse text": MORSE,
        "KRYPTOS alphabet": KRYPTOS_KEYED,
    }
    if only is not None:            # test just these texts, no grid placements
        sources = only
    hits, tests, top = [], 0, (0, "")
    for name, src in sources.items():
        n = len(src)
        for stride in range(1, min(max_stride, n) + 1):
            for sign in (1, -1):
                for start in range(n):
                    key = [src[(start + sign * stride * i) % n] for i in CRIB_IDX]
                    cnt, who = _best_agreement(S, key, ranks)
                    tests += 1
                    desc = f"{name} start={start} stride={sign * stride}"
                    if cnt > top[0]:
                        top = (cnt, desc)
                    if cnt >= flag:
                        hits.append((cnt, desc, who))
    # grid-aligned: key letter sits at a fixed offset from each K4 cell
    grids = {} if only is not None else {"ciphertext grid": CIPHER_ROWS, "tableau grid": TABLEAU_ROWS}
    crib_cells = [K4_CELLS[i] for i in CRIB_IDX]
    for gname, grid in grids.items():
        for align in ("left", "mirrored", "right"):
            for dr in range(-27, 28):
                for dc in range(-32, 33):
                    key = []
                    for r, c in crib_cells:
                        rr = r + dr
                        if not 0 <= rr < len(grid):
                            break
                        row = grid[rr]
                        if align == "left":
                            cc = c + dc
                        elif align == "mirrored":
                            cc = len(row) - 1 - c + dc
                        else:  # same distance from the right edge
                            cc = len(row) - (len(CIPHER_ROWS[r]) - c) + dc
                        if not 0 <= cc < len(row) or not row[cc].isalpha():
                            break
                        key.append(row[cc])
                    if len(key) < len(crib_cells):
                        continue
                    cnt, who = _best_agreement(S, key, ranks)
                    tests += 1
                    desc = f"{gname} {align} dr={dr} dc={dc}"
                    if cnt > top[0]:
                        top = (cnt, desc)
                    if cnt >= flag:
                        hits.append((cnt, desc, who))
    if not quiet:
        print("\n=== keys read off the sculpture (fuzzy: >=%d of 24 crib letters agree) ===" % flag)
        print(f"  key placements tested: {tests:,} x 16 alphabet/arithmetic settings")
        print(f"  best agreement anywhere: {top[0]}/24  [{top[1]}]")
        for cnt, desc, who in sorted(hits, reverse=True)[:10]:
            print(f"  HIT {cnt}/24  {desc}  {'/'.join(COMBOS[who[0]])} keyalpha={who[1]}")
        if not hits:
            print("  no placement reaches the threshold (chance alone gives ~7-9)")
    return hits, top


# --- F. running key in English -------------------------------------------------

_LOGS, _FLOOR = quadgrams.load_prose()
_SEG = [(0, 13), (13, 24)]          # crib fragments inside the 24-letter list


def _frag_score(text24):
    tot = 0.0
    for a, b in _SEG:
        for i in range(a, b - 3):
            tot += _LOGS.get(text24[i:i + 4], _FLOOR)
    return tot / 18


def _key_texts(s, alphas):
    """Key spellings for forced vig-type shifts s under Vigenere and variant reading."""
    for xname, xa in alphas:
        yield xname, "".join(xa[v] for v in s)
        yield xname + "-neg", "".join(xa[-v % 26] for v in s)


def english_bar():
    """What real English key fragments score, for comparison."""
    from solve import K2_PT, K3_PT
    rng = random.Random(3)
    vals = []
    for _ in range(2000):
        src = rng.choice((K2_PT, K3_PT))
        a = rng.randrange(len(src) - 13)
        b = rng.randrange(len(src) - 11)
        vals.append(_frag_score(src[a:a + 13] + src[b:b + 11]))
    vals.sort()
    return vals[len(vals) // 20], vals[len(vals) // 2]     # 5th percentile, median


def english_plain_report():
    lo, med = english_bar()
    print("\n=== running key in English: do the implied key fragments read as words? ===")
    print(f"  real English fragments score: median {med:.2f}, 5th percentile {lo:.2f}")
    best = []
    for k, (pa, ca, mode) in enumerate(COMBOS):
        s = [TABS[k][j][CTI[i]] for j, i in enumerate(CRIB_IDX)]
        for off in range(26):
            so = [(v + off) % 26 for v in s]
            for xname, text in _key_texts(so, ALPHAS.items()):
                best.append((_frag_score(text), f"{pa}/{ca}/{mode} key={xname} off={off}", text))
    best.sort(reverse=True)
    print("  no transposition, 8 settings x 26 offsets x 4 spellings; best:")
    for sc, desc, text in best[:3]:
        print(f"    {sc:.2f}  {text[:13]} | {text[13:]}   [{desc}]")
    return lo


def _english_dict_task(words):
    out = []
    for w in words:
        ka = keyed_alphabet(w)
        for pa, ca, tag in ((ka, ALPHABET, "QI"), (ALPHABET, ka, "QII"), (ka, ka, "QIII"),
                            (ka, KRYPTOS_KEYED, "QIV kw/K"), (KRYPTOS_KEYED, ka, "QIV K/kw")):
            pr = {ch: i for i, ch in enumerate(pa)}
            cr = {ch: i for i, ch in enumerate(ca)}
            for mode in ("vig", "beau"):
                s = [_shift(mode, pr[P], cr[CIPHERTEXT[i]]) for i, P in CRIB]
                for xname, text in _key_texts(s, (("std", ALPHABET), ("kw", ka))):
                    sc = _frag_score(text)
                    if sc > -5.4:
                        out.append((sc, f"{w} {tag} {mode} key={xname}", text))
    return len(words), out


def _english_columnar_task(args):
    w, prefix = args
    rest = [c for c in range(w) if c not in prefix]
    out, n = [], 0
    alphas = tuple(ALPHAS.items())
    for tail in itertools.permutations(rest):
        order = prefix + tail
        m0 = columnar_map(w, order)
        for tag, m in (("", m0), (" inv", inverse(m0))):
            n += 1
            cidx = [CTI[m[i]] for i in CRIB_IDX]
            for k, tab in enumerate(TABS):
                s = [tab[j][c] for j, c in enumerate(cidx)]
                for xname, text in _key_texts(s, alphas):
                    sc = _frag_score(text)
                    if sc > -5.4:
                        out.append((sc, f"columnar w={w} {order}{tag} {'/'.join(COMBOS[k])} key={xname}", text))
    return n, out


def english_sweeps_report(widths=(2, 3, 4, 5, 6, 7, 8, 9), procs=30):
    words, seen = [], set()
    with open("/usr/share/dict/words", encoding="utf-8", errors="ignore") as fh:
        for line in fh:
            w = line.strip().upper()
            if 3 <= len(w) <= 24 and w.isascii() and w.isalpha():
                ka = keyed_alphabet(w)
                if ka not in seen:
                    seen.add(ka)
                    words.append(w)
    chunks = [words[i:i + 3000] for i in range(0, len(words), 3000)]
    tasks = []
    for w in widths:
        depth = 0 if w <= 7 else 1
        tasks += [(w, p) for p in itertools.permutations(range(w), depth)]
    for title, fn, work in (("dictionary-keyed alphabets", _english_dict_task, chunks),
                            ("columnar transposition (key applied before it), widths %s" % (widths,),
                             _english_columnar_task, tasks)):
        t0 = time.time()
        total, hits = 0, []
        with Pool(procs) as pool:
            for n, h in pool.imap_unordered(fn, work):
                total += n
                hits += h
        hits.sort(reverse=True)
        print(f"  {title}: {total:,} cases ({time.time() - t0:.0f}s); best key fragments:")
        for sc, desc, text in hits[:5]:
            print(f"    {sc:.2f}  {text[:13]} | {text[13:]}   [{desc}]")
        if not hits:
            print("    nothing above -5.4")


# --- B over transpositions ------------------------------------------------------

def _maps_task(items):
    out = []
    for label, m, settings in items:
        cl = cipher_letters(m)
        for order, kp in (("ST", CRIB_IDX), ("TS", [m[i] for i in CRIB_IDX])):
            for L, mo, md in settings:
                if len(_slot_pairs(kp, L)) < 14:
                    continue
                if quagmire_any_ok(cl, kp, L, mo, md):
                    out.append((label, order, L, mo, md))
    return len(items), out


def maps_report(settings, widths=(2, 3, 4, 5, 6, 7, 8), procs=30):
    """Arbitrary-alphabet Quagmire test over transposition families."""
    items = []
    for label, m in small_families():
        items.append((label, m, settings))
        items.append((label + " inv", inverse(m), settings))
    for w in widths:
        for order in itertools.permutations(range(w)):
            m = columnar_map(w, order)
            items.append((f"columnar w={w} {order}", m, settings))
            items.append((f"columnar w={w} {order} inv", inverse(m), settings))
    chunks = [items[i:i + 500] for i in range(0, len(items), 500)]
    t0 = time.time()
    total, hits = 0, []
    with Pool(procs) as pool:
        for n, h in pool.imap_unordered(_maps_task, chunks):
            total += n
            hits += h
    print(f"\n=== arbitrary-alphabet Quagmire over transpositions ===")
    print(f"  maps: {total:,} ({time.time() - t0:.0f}s)  settings per map: {len(settings)}  passes: {len(hits)}")
    tally = Counter((mo, L) for _, _, L, mo, _ in hits)
    for mo in ("QIII", "QIV"):
        row = ", ".join(f"L={L}: {tally.get((mo, L), 0)}" for L in sorted({s[0] for s in settings if s[1] == mo}))
        print(f"  {mo} passes by period -> {row}")
    return hits


def _one_known_task(words):
    cl = cipher_letters(list(range(N)))
    out = []
    for w in words:
        ka = keyed_alphabet(w)
        for model in ("QI:" + ka, "QII:" + ka):
            for md in ("vig", "beau"):
                if quagmire_any_ok(cl, CRIB_IDX, 8, model, md):
                    out.append((w, model[:3].rstrip(":"), md))
    return len(words), out


def dict_one_known_report(procs=30):
    """Period 8, one alphabet dictionary-keyed, the OTHER alphabet arbitrary."""
    words, seen = [], set()
    with open("/usr/share/dict/words", encoding="utf-8", errors="ignore") as fh:
        for line in fh:
            w = line.strip().upper()
            if 3 <= len(w) <= 24 and w.isascii() and w.isalpha():
                ka = keyed_alphabet(w)
                if ka not in seen:
                    seen.add(ka)
                    words.append(w)
    chunks = [words[i:i + 1000] for i in range(0, len(words), 1000)]
    t0 = time.time()
    total, hits = 0, []
    with Pool(procs) as pool:
        for n, h in pool.imap_unordered(_one_known_task, chunks):
            total += n
            hits += h
    print("\n=== period 8: one dictionary-keyed alphabet + one arbitrary alphabet ===")
    print(f"  alphabets: {total:,} ({time.time() - t0:.0f}s)  not excluded: {len(hits)}")
    for h in hits[:20]:
        print("   ", h)
    return hits


# --- controls -------------------------------------------------------------------

def control():
    rng = random.Random(11)
    pt = list(("ITISBURIEDOUTTHERESOMEWHEREWHOKNOWSTHEEXACTLOCATION" * 2)[:N])
    for i, ch in CRIB:
        pt[i] = ch
    pt = "".join(pt)
    ok = True
    # B: Quagmire IV with two RANDOM mixed alphabets, period 7
    pa, ca = list(ALPHABET), list(ALPHABET)
    rng.shuffle(pa)
    rng.shuffle(ca)
    key = [rng.randrange(26) for _ in range(7)]
    ct = "".join(ca[(pa.index(p) + key[i % 7]) % 26] for i, p in enumerate(pt))
    cl = [ct[i] for i in CRIB_IDX]
    passes = [L for L in range(2, 13) if quagmire_any_ok(cl, CRIB_IDX, L, "QIV", "vig")]
    # The test only excludes; the true period must never be excluded.
    good = 7 in passes and all(
        quagmire_any_ok(cl, CRIB_IDX, 7, mo, "vig")
        for mo in ("QIV", "QI:" + "".join(ca), "QII:" + "".join(pa)))
    ok &= good
    print(f"[control B] random-alphabet Quagmire IV period 7 not excluded: {good} "
          f"(unexcluded periods 2-12: {passes})")
    # ...and a single arbitrary alphabet (Quagmire III) likewise
    ct3 = "".join(pa[(pa.index(p) + key[i % 7]) % 26] for i, p in enumerate(pt))
    cl3 = [ct3[i] for i in CRIB_IDX]
    passes3 = [L for L in range(2, 13) if quagmire_any_ok(cl3, CRIB_IDX, L, "QIII", "vig")]
    good = 7 in passes3
    ok &= good
    print(f"[control B] random-alphabet Quagmire III period 7 not excluded: {good} "
          f"(unexcluded periods 2-12: {passes3})")
    # E: key read from the tableau with stride, two letters corrupted
    from sculpture import TABLEAU_ROWS
    src = "".join(r.replace(" ", "") for r in TABLEAU_ROWS)
    keytxt = [src[(137 + 5 * i) % len(src)] for i in range(N)]
    ctl = [chr((ord(p) + ord(k) - 130) % 26 + 65) for p, k in zip(pt, keytxt)]
    ctl[23] = "Q"
    ctl[70] = "Q"
    hits, top = sources_report(ct="".join(ctl), max_stride=6, quiet=True)
    good = any("tableau by rows start=137 stride=5" in d for _, d, _ in hits)
    ok &= good
    print(f"[control E] tableau key (start 137, stride 5, 2 errors) found: {good} ({top[0]}/24)")
    # C: Hill 2x2
    M = [[3, 3], [2, 5]]
    h = list(pt)
    for s in range(0, N - 1, 2):
        a, b = ord(pt[s]) - 65, ord(pt[s + 1]) - 65
        h[s] = chr((M[0][0] * a + M[0][1] * b) % 26 + 65)
        h[s + 1] = chr((M[1][0] * a + M[1][1] * b) % 26 + 65)
    global CIPHERTEXT
    saved, CIPHERTEXT = CIPHERTEXT, "".join(h)
    import io, contextlib
    with contextlib.redirect_stdout(io.StringIO()):
        found = hill_report()
    CIPHERTEXT = saved
    good = (2, 0, "A", "A", False, 11) in found
    ok &= good
    print(f"[control C] planted Hill 2x2 detected: {good}")
    # D2: key from s_i = 3 + 5*s_(i-1) + 2*s_(i-2), and from mixed feedback
    ks = [4, 9]
    for i in range(2, N):
        ks.append((3 + 5 * ks[-1] + 2 * ks[-2]) % 26)
    ct_r = "".join(chr((ord(p) - 65 + x) % 26 + 65) for p, x in zip(pt, ks))
    f1 = recurrence_report(ct=ct_r, quiet=True)
    c, ks = [], []
    for i, p in enumerate(pt):
        x = 7 if i < 3 else (1 + 3 * i + 5 * (ord(pt[i - 3]) - 65) + 2 * (ord(c[i - 3]) - 65)
                             + 11 * ks[i - 3]) % 26
        ks.append(x)
        c.append(chr((ord(p) - 65 + x) % 26 + 65))
    f2 = recurrence_report(ct="".join(c), quiet=True)
    good = (("linear recurrence order 2", ("A", "A", "vig")) in f1
            and ("mixed feedback lag 3", ("A", "A", "vig")) in f2)
    ok &= good
    print(f"[control D2] planted recurrence and mixed-feedback keys detected: {good}")
    # F: English running key scores like English
    from solve import K2_PT
    lo, med = english_bar()
    k = K2_PT[40:137]
    s = [(ord(c) - 65) for c in k]
    sc = _frag_score("".join(ALPHABET[s[i]] for i in CRIB_IDX))
    good = sc > lo
    ok &= good
    print(f"[control F] English key fragment scores {sc:.2f} (bar {lo:.2f}): {good}")
    return ok


if __name__ == "__main__":
    what = sys.argv[1] if len(sys.argv) > 1 else "all"
    if what in ("control", "all"):
        assert control(), "positive control failed"
    if what in ("periodic", "all"):
        periodic_report()
    if what in ("hill", "all"):
        hill_report()
        polynomial_report()
        recurrence_report()
    if what in ("sources", "all"):
        t0 = time.time()
        sources_report()
        print(f"  ({time.time() - t0:.0f}s)")
    if what in ("english", "all"):
        english_plain_report()
        english_sweeps_report()
    if what == "maps":
        settings = ([(L, "QIII", md) for L in range(2, 8) for md in ("vig", "beau")]
                    + [(L, "QIV", md) for L in range(2, 6) for md in ("vig", "beau")])
        maps_report(settings)
    if what == "dict8":
        dict_one_known_report()
