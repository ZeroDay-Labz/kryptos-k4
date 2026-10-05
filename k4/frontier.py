"""
Frontier attacks on K4: transposition x substitution, autokey, progressive key.

Detector
--------
Every test here is a *consistency* test on the 24 confirmed crib letters, so no
keyword is ever guessed and no English scoring is needed to spot a hit:

* periodic key (period L): crib letters sharing a key slot must force the same
  shift. With c such equalities the chance of a random pass is 26**-c.
* monoalphabetic: the crib P->C map must be a function and injective.
* autokey / progressive key: the forced shifts must follow the feedback rule.

A "map" m sends plaintext index -> ciphertext index (the transposition). Each
map is tested in both layer orders:

  ST  substitute then transpose   key slot of plaintext i is  i      mod L
  TS  transpose then substitute   key slot of plaintext i is  m[i]   mod L

and with every pairing of the standard (A) and KRYPTOS-keyed (K) alphabets for
plaintext/ciphertext, in Vigenere and Beaufort arithmetic (Quagmire I-IV with
those alphabets are all covered, since the per-slot shifts are free).

Run:  python frontier.py [small|columnar W|dict|alphabets|autokey|control|all]
"""
from __future__ import annotations

import itertools
import math
import os
import sys
import time
from multiprocessing import Pool

from kryptos import CIPHERTEXT, CRIBS, ALPHABET, KRYPTOS_KEYED, keyed_alphabet
from quadgrams import quadgram_score

# K4_VARIANT=q98 treats the "?" carved before OBKR as K4's first character, giving
# 98 = 7 x 14 characters (a complete grid, like K3's). Crib positions shift by one.
VARIANT = os.environ.get("K4_VARIANT", "")
TEXT = ("?" + CIPHERTEXT) if VARIANT == "q98" else CIPHERTEXT
_OFF = 1 if VARIANT == "q98" else 0
N = len(TEXT)
CRIB = [(a - 1 + i + _OFF, ch) for (a, b), w in CRIBS.items() for i, ch in enumerate(w)]
CRIB_IDX = [i for i, _ in CRIB]
ALPHAS = {"A": ALPHABET, "K": KRYPTOS_KEYED}
COMBOS = [(pa, ca, mode) for pa in "AK" for ca in "AK" for mode in ("vig", "beau")]
MIN_COLL = 6          # report periodic hits with >= this many forced equalities
MAX_L_TS = 40


def _code(text: str) -> list[int]:
    return [ord(c) - 65 for c in text]


CTI = [26 if c == "?" else ord(c) - 65 for c in TEXT]


def _shift(mode: str, p: int, r: int) -> int:
    return (r - p) % 26 if mode == "vig" else (p + r) % 26


def _dec(mode: str, r: int, s: int) -> int:
    return (r - s) % 26 if mode == "vig" else (s - r) % 26


def build_tabs(pt_alpha: str, ct_alpha: str, mode: str) -> list[list[int]]:
    """tab[j][c] = shift forced at crib j if its ciphertext letter code is c."""
    pr = {ch: i for i, ch in enumerate(pt_alpha)}
    cr = [ct_alpha.index(chr(65 + c)) for c in range(26)]
    return [[_shift(mode, pr[P], cr[c]) for c in range(26)] for _, P in CRIB]


TABS = [build_tabs(ALPHAS[pa], ALPHAS[ca], mode) for pa, ca, mode in COMBOS]


def _slot_pairs(keypos, L):
    """Equalities forced between cribs that share a key slot (chained per slot)."""
    last = {}
    pairs = []
    for j, x in enumerate(keypos):
        sl = x % L
        if sl in last:
            pairs.append((last[sl], j))
        last[sl] = j
    return pairs


# ST key positions are the crib indices themselves -> precompute per period.
ST_PAIRS = [(L, _slot_pairs(CRIB_IDX, L)) for L in range(1, 49)]
ST_PAIRS_SIG = [(L, p) for L, p in ST_PAIRS if len(p) >= MIN_COLL]


def test_map(m, cti=CTI, tabs=TABS):
    """Return hits [(kind, L, combo_index, n_equalities)] for transposition m."""
    hits = []
    cidx = [cti[m[i]] for i in CRIB_IDX]
    if 26 in cidx:
        return hits            # a clue letter cannot sit on the "?"
    # monoalphabetic substitution after/before the transposition
    fwd, rev, ok = {}, {}, True
    for (_, P), c in zip(CRIB, cidx):
        if fwd.setdefault(P, c) != c or rev.setdefault(c, P) != P:
            ok = False
            break
    if ok:
        hits.append(("MONO", 0, -1, 11))
    S = [[tab[j][c] for j, c in enumerate(cidx)] for tab in tabs]
    for L, pairs in ST_PAIRS_SIG:
        for k, s in enumerate(S):
            for a, b in pairs:
                if s[a] != s[b]:
                    break
            else:
                hits.append(("ST", L, k, len(pairs)))
    kp = [m[i] for i in CRIB_IDX]
    for L in range(1, MAX_L_TS + 1):
        pairs = _slot_pairs(kp, L)
        if len(pairs) < MIN_COLL:
            continue
        for k, s in enumerate(S):
            for a, b in pairs:
                if s[a] != s[b]:
                    break
            else:
                hits.append(("TS", L, k, len(pairs)))
    return hits


def decrypt_hit(m, kind, L, k, ct=TEXT, combos=None):
    """Plaintext implied by a periodic hit ('.' where the key slot is unknown)."""
    pa, ca, mode = (combos or COMBOS)[k]
    pt_alpha, ct_alpha = ALPHAS.get(pa, pa), ALPHAS.get(ca, ca)
    pr = {ch: i for i, ch in enumerate(pt_alpha)}
    cr = {ch: i for i, ch in enumerate(ct_alpha)}
    slot = (lambda i: i % L) if kind == "ST" else (lambda i: m[i] % L)
    shifts = {}
    for i, P in CRIB:
        shifts[slot(i)] = _shift(mode, pr[P], cr[ct[m[i]]])
    out = []
    for i in range(N):
        s = shifts.get(slot(i))
        if ct[m[i]] == "?":
            out.append("?")
        else:
            out.append("." if s is None else pt_alpha[_dec(mode, cr[ct[m[i]]], s)])
    return "".join(out)


def inverse(m):
    inv = [0] * len(m)
    for i, x in enumerate(m):
        inv[x] = i
    return inv


# --- transposition families -------------------------------------------------

def columnar_map(w, order):
    """Plain->cipher map for columnar transposition reading columns in `order`."""
    m = [0] * N
    k = 0
    for c in order:
        for p in range(c, N, w):
            m[p] = k
            k += 1
    return m


def _map_from_seq(seq):
    """seq[k] = plaintext index that lands at cipher position k."""
    m = [0] * N
    for k, p in enumerate(seq):
        m[p] = k
    return m


def _rot_seq(w, cw):
    rows = -(-N // w)
    seq = []
    cols = range(w) if cw else range(w - 1, -1, -1)
    for c in cols:
        rr = range(rows - 1, -1, -1) if cw else range(rows)
        for r in rr:
            idx = r * w + c
            if idx < N:
                seq.append(idx)
    return seq


def _railfence_seq(rails):
    period = 2 * (rails - 1)
    def rail(i):
        x = i % period
        return x if x < rails else period - x
    return sorted(range(N), key=lambda i: (rail(i), i))


def _serpentine_seqs(w):
    rows = -(-N // w)
    by_rows = []
    for r in range(rows):
        row = [r * w + c for c in range(w) if r * w + c < N]
        by_rows += row if r % 2 == 0 else row[::-1]
    by_cols = []
    for c in range(w):
        col = [r * w + c for r in range(rows) if r * w + c < N]
        by_cols += col if c % 2 == 0 else col[::-1]
    return by_rows, by_cols


def small_families():
    yield "identity", list(range(N))
    for k in range(1, N):
        if math.gcd(k, N) != 1:
            continue
        for s in range(N):
            yield f"decimation k={k} s={s}", [(s + k * i) % N for i in range(N)]
    for r in range(2, 49):
        yield f"railfence rails={r}", _map_from_seq(_railfence_seq(r))
    for w in range(2, 49):
        a, b = _serpentine_seqs(w)
        yield f"serpentine-rows w={w}", _map_from_seq(a)
        yield f"serpentine-cols w={w}", _map_from_seq(b)
    rots = [(w, cw, _rot_seq(w, cw)) for w in range(2, 49) for cw in (True, False)]
    for w, cw, s in rots:
        yield f"rotate w={w} {'cw' if cw else 'ccw'}", _map_from_seq(s)
    # K3-style double rotation: T2(T1(x))
    for w1, cw1, s1 in rots:
        for w2, cw2, s2 in rots:
            seq = [s1[x] for x in s2]
            yield (f"double-rotate w1={w1}{'cw' if cw1 else 'ccw'} "
                   f"w2={w2}{'cw' if cw2 else 'ccw'}"), _map_from_seq(seq)


def _test_both(label, m, out):
    for tag, mm in (("", m), (" (inverse)", inverse(m))):
        for h in test_map(mm):
            out.append((label + tag, mm, h))


def run_small():
    hits, n = [], 0
    for label, m in small_families():
        _test_both(label, m, hits)
        n += 2
    return n, hits


def _columnar_task(args):
    w, prefix = args
    rest = [c for c in range(w) if c not in prefix]
    hits, n = [], 0
    for tail in itertools.permutations(rest):
        order = prefix + tail
        _test_both(f"columnar w={w} order={order}", columnar_map(w, order), hits)
        n += 2
    return n, hits


def run_columnar(widths, procs=30):
    tasks = []
    for w in widths:
        depth = 0 if w <= 7 else (1 if w <= 9 else 2)
        tasks += [(w, p) for p in itertools.permutations(range(w), depth)]
    total, hits = 0, []
    with Pool(procs) as pool:
        for n, h in pool.imap_unordered(_columnar_task, tasks):
            total += n
            hits += h
    return total, hits


def _double_task(args):
    w1, order1, max_w = args
    m1 = columnar_map(w1, order1)
    hits, n = [], 0
    for w2 in range(2, max_w + 1):
        for order2 in itertools.permutations(range(w2)):
            m2 = columnar_map(w2, order2)
            _test_both(f"double columnar {w1}{order1} then {w2}{order2}",
                       [m2[x] for x in m1], hits)
            n += 2
    return n, hits


def run_double_columnar(max_w=7, procs=30):
    """Every pair of columnar transpositions with widths 2..max_w."""
    tasks = [(w, o, max_w) for w in range(2, max_w + 1)
             for o in itertools.permutations(range(w))]
    total, hits = 0, []
    with Pool(procs) as pool:
        for n, h in pool.imap_unordered(_double_task, tasks, chunksize=8):
            total += n
            hits += h
    return total, hits


def run_mixed(max_w=6):
    """A columnar transposition composed with a grid rotation, in either order."""
    rots = [(f"rotate w={w} {'cw' if cw else 'ccw'}", _map_from_seq(_rot_seq(w, cw)))
            for w in range(2, 49) for cw in (True, False)]
    hits, n = [], 0
    for w in range(2, max_w + 1):
        for order in itertools.permutations(range(w)):
            mc = columnar_map(w, order)
            for name, mr in rots:
                _test_both(f"columnar {w}{order} then {name}", [mr[x] for x in mc], hits)
                _test_both(f"{name} then columnar {w}{order}", [mc[x] for x in mr], hits)
                n += 4
    return n, hits


def _triple_task(args):
    w1, cw1 = args
    s1 = _rot_seq(w1, cw1)
    rots = [(w, cw, _rot_seq(w, cw)) for w in range(2, 50) for cw in (True, False)]
    hits, n = [], 0
    for w2, cw2, s2 in rots:
        s12 = [s1[x] for x in s2]
        for w3, cw3, s3 in rots:
            label = (f"triple-rotate {w1}{'cw' if cw1 else 'ccw'} {w2}{'cw' if cw2 else 'ccw'} "
                     f"{w3}{'cw' if cw3 else 'ccw'}")
            _test_both(label, _map_from_seq([s12[x] for x in s3]), hits)
            n += 2
    return n, hits


def run_triple_rotation(procs=30):
    """K3-style grid rotation applied three times, every combination of widths 2-49."""
    tasks = [(w, cw) for w in range(2, 50) for cw in (True, False)]
    total, hits = 0, []
    with Pool(procs) as pool:
        for n, h in pool.imap_unordered(_triple_task, tasks):
            total += n
            hits += h
    return total, hits


def _dict_orders(min_len, max_len):
    seen = set()
    with open("/usr/share/dict/words", encoding="utf-8", errors="ignore") as fh:
        for line in fh:
            w = line.strip().upper()
            if min_len <= len(w) <= max_len and w.isascii() and w.isalpha():
                order = tuple(sorted(range(len(w)), key=lambda i: (w[i], i)))
                if order not in seen:
                    seen.add(order)
                    yield w, order


def _dict_task(chunk):
    hits = []
    for word, order in chunk:
        _test_both(f"columnar key={word}", columnar_map(len(order), order), hits)
    return 2 * len(chunk), hits


def run_dict_columnar(min_len=12, max_len=24, procs=30):
    items = list(_dict_orders(min_len, max_len))
    chunks = [items[i:i + 2000] for i in range(0, len(items), 2000)]
    total, hits = 0, []
    with Pool(procs) as pool:
        for n, h in pool.imap_unordered(_dict_task, chunks):
            total += n
            hits += h
    return total, hits


# --- no-transposition tests -------------------------------------------------

def _alpha_task(words):
    """Dictionary-keyed alphabets in every Quagmire role, periods with c>=MIN_COLL."""
    ident = list(range(N))
    out = []
    for w in words:
        ka = keyed_alphabet(w)
        for pa, ca, tag in ((ka, ALPHABET, "QI"), (ALPHABET, ka, "QII"), (ka, ka, "QIII"),
                            (ka, KRYPTOS_KEYED, "QIV kw/KRYPTOS"),
                            (KRYPTOS_KEYED, ka, "QIV KRYPTOS/kw")):
            for mode in ("vig", "beau"):
                tab = build_tabs(pa, ca, mode)
                s = [tab[j][CTI[i]] for j, i in enumerate(CRIB_IDX)]
                for L, pairs in ST_PAIRS_SIG:
                    if all(s[a] == s[b] for a, b in pairs):
                        out.append((w, tag, mode, L, len(pairs)))
    return len(words), out


def run_alphabets(procs=30):
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
    total, hits = 0, []
    with Pool(procs) as pool:
        for n, h in pool.imap_unordered(_alpha_task, chunks):
            total += n
            hits += h
    return total, hits


def run_autokey_progressive(ct=CIPHERTEXT, crib=CRIB):
    """Keyspace-complete autokey (any seed) and progressive-key tests."""
    cti = _code(ct)
    pos = {i: j for j, (i, _) in enumerate(crib)}
    found = []
    for k, (pa, ca, mode) in enumerate(COMBOS):
        pr = {ch: i for i, ch in enumerate(ALPHAS[pa])}
        cr = {ch: i for i, ch in enumerate(ALPHAS[ca])}
        s = [_shift(mode, pr[P], cr[ct[i]]) for i, P in crib]
        for xname, xa in ALPHAS.items():
            xr = {ch: i for i, ch in enumerate(xa)}
            for lag in range(1, N):
                # plaintext autokey: shift_i = rank(P[i-lag]) + const
                d = [(s[j] - xr[crib[pos[i - lag]][1]]) % 26
                     for j, (i, _) in enumerate(crib) if (i - lag) in pos]
                if len(d) >= 5 and len(set(d)) == 1:
                    found.append((f"autokey-plaintext lag={lag} keyalpha={xname}", k, len(d) - 1))
                # ciphertext autokey: shift_i = rank(C[i-lag]) + const
                d = [(s[j] - xr[ct[i - lag]]) % 26
                     for j, (i, _) in enumerate(crib) if i - lag >= 0]
                if len(d) >= 5 and len(set(d)) == 1:
                    found.append((f"autokey-ciphertext lag={lag} keyalpha={xname}", k, len(d) - 1))
        # progressive key: shift_i = base[i mod L] + step*(i//L)   or  + step*i
        for L, pairs in ST_PAIRS_SIG:
            for step in range(1, 26):
                for name, f in (("per-period", lambda i: step * (i // L)),
                                ("per-letter", lambda i: step * i)):
                    adj = [(s[j] - f(i)) % 26 for j, (i, _) in enumerate(crib)]
                    if all(adj[a] == adj[b] for a, b in pairs):
                        found.append((f"progressive {name} L={L} step={step}", k, len(pairs)))
    return found


def _consistent_mod(rows, p, n_unknowns):
    """Gauss-eliminate rows [coeffs | rhs...] over GF(p).

    Returns (rank, [consistent? per rhs column])."""
    rows = [[v % p for v in r] for r in rows]
    n_rhs = len(rows[0]) - n_unknowns
    rank = 0
    for col in range(n_unknowns):
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
        rank += 1
    ok = [all(rows[r][n_unknowns + k] == 0 for r in range(rank, len(rows)))
          for k in range(n_rhs)]
    return rank, ok


def run_double_period(ct=CIPHERTEXT, max_len=30):
    """Two superimposed periodic keys: shift_i = a[i mod L1] + b[i mod L2].

    Covers 'the K1/K2 cipher applied twice' (effective period lcm(L1, L2), far
    beyond what a single-period test reaches). Linear system over Z26, solved
    mod 2 and mod 13."""
    S = []
    for pa, ca, mode in COMBOS:
        pr = {ch: i for i, ch in enumerate(ALPHAS[pa])}
        cr = {ch: i for i, ch in enumerate(ALPHAS[ca])}
        S.append([_shift(mode, pr[P], cr[ct[i]]) for i, P in CRIB])
    found = []
    for L1 in range(2, max_len + 1):
        for L2 in range(L1 + 1, max_len + 1):
            rows = []
            for j, i in enumerate(CRIB_IDX):
                row = [0] * (L1 + L2)
                row[i % L1] = 1
                row[L1 + i % L2] = 1
                rows.append(row + [s[j] for s in S])
            r2, ok2 = _consistent_mod(rows, 2, L1 + L2)
            r13, ok13 = _consistent_mod(rows, 13, L1 + L2)
            log26 = ((len(rows) - r2) * 0.2127 + (len(rows) - r13) * 0.7873)
            if log26 < MIN_COLL:
                continue
            for k in range(len(COMBOS)):
                if ok2[k] and ok13[k]:
                    found.append((L1, L2, k, log26))
    return found


# --- reporting ---------------------------------------------------------------

def report(title, total, hits, t0):
    print(f"\n=== {title} ===")
    print(f"maps tested: {total:,}  ({time.time() - t0:.0f}s)   raw hits: {len(hits)}")
    rows = []
    for label, m, (kind, L, k, c) in hits:
        if kind == "MONO":
            rows.append((99, 0.0, 1.0, label, "monoalphabetic-consistent", ""))
            continue
        pt = decrypt_hit(m, kind, L, k)
        cov = 1 - pt.count(".") / N
        q = quadgram_score(pt.replace(".", ""))
        rows.append((c, q, cov, label, f"{kind} L={L} {'/'.join(COMBOS[k])}", pt))
    rows.sort(key=lambda r: (-r[0], -r[1]))
    for c, q, cov, label, desc, pt in rows[:12]:
        print(f"  equalities={c:2d} (p~26^-{c})  quad={q:.2f} cov={cov:.2f}  {desc}  [{label}]")
        if pt:
            print(f"      {pt}")
    if not hits:
        print("  no crib-consistent configuration")
    return rows


def control():
    """Planted solutions must be found by the same code paths."""
    pt = list(("ITISBURIEDOUTTHERESOMEWHEREWHOKNOWSTHEEXACTLOCATION" * 2)[:N])
    for i, ch in CRIB:
        pt[i] = ch
    pt = "".join(pt)
    ka = KRYPTOS_KEYED
    pr = {c: i for i, c in enumerate(ka)}
    key = "ABSCISSA"
    order = (3, 0, 5, 1, 6, 2, 4)
    m = columnar_map(7, order)
    ok = True
    # ST: substitute (Quagmire III) then transpose
    sub = [ka[(pr[p] + pr[key[i % 8]]) % 26] for i, p in enumerate(pt)]
    ct = [""] * N
    for i in range(N):
        ct[m[i]] = sub[i]
    ct_st = "".join(ct)
    # TS: transpose then substitute
    tr = [""] * N
    for i in range(N):
        tr[m[i]] = pt[i]
    ct_ts = "".join(ka[(pr[p] + pr[key[j % 8]]) % 26] for j, p in enumerate(tr))
    for kind, ctext in (("ST", ct_st), ("TS", ct_ts)):
        cti = _code(ctext)
        found = None
        for o in itertools.permutations(range(7)):     # full family enumeration
            mm = columnar_map(7, o)
            for h in test_map(mm, cti):
                if h[0] == kind and h[1] == 8 and COMBOS[h[2]] == ("K", "K", "vig"):
                    found = (o, decrypt_hit(mm, kind, 8, h[2], ct=ctext))
        good = found is not None and found[0] == order and found[1] == pt
        ok &= good
        print(f"[control {kind}] columnar w=7 + Quagmire III/ABSCISSA recovered: {good}")
    # autokey control (plaintext autokey, lag 5, standard alphabet)
    seed = "QUEEN"
    ks = seed + pt
    ct_ak = "".join(chr((ord(p) - 65 + ord(ks[i]) - 65) % 26 + 65) for i, p in enumerate(pt))
    res = run_autokey_progressive(ct=ct_ak)
    good = any(r[0].startswith("autokey-plaintext lag=5 keyalpha=A") and COMBOS[r[1]] == ("A", "A", "vig")
               for r in res)
    ok &= good
    print(f"[control autokey] plaintext-autokey lag 5 detected: {good}")
    # double periodic key control (periods 5 and 7, standard alphabet)
    k1, k2 = "LUCID", "SHADOWS"
    ct_dp = "".join(chr((ord(p) + ord(k1[i % 5]) + ord(k2[i % 7]) - 195) % 26 + 65)
                    for i, p in enumerate(pt))
    res = run_double_period(ct=ct_dp, max_len=12)
    good = any(r[:2] == (5, 7) and COMBOS[r[2]] == ("A", "A", "vig") for r in res)
    ok &= good
    print(f"[control double-period] periods 5+7 detected: {good} "
          f"(total configurations flagged: {len(res)})")
    return ok


if __name__ == "__main__":
    what = sys.argv[1] if len(sys.argv) > 1 else "all"
    if what in ("control", "all"):
        assert control(), "positive control failed"
    if what in ("autokey", "all"):
        res = run_autokey_progressive()
        print("\n=== autokey (any seed) + progressive key, no transposition ===")
        for desc, k, c in res:
            print(f"  {desc} {'/'.join(COMBOS[k])} constraints={c}")
        if not res:
            print("  no crib-consistent configuration")
        res = run_double_period()
        print("\n=== two superimposed periodic keys, periods 2-30, no transposition ===")
        for L1, L2, k, c in res:
            print(f"  L1={L1} L2={L2} {'/'.join(COMBOS[k])} (p~26^-{c:.1f})")
        if not res:
            print("  no crib-consistent configuration")
    if what in ("small", "all"):
        t0 = time.time()
        report("identity / decimation / railfence / serpentine / K3-style rotations",
               *run_small(), t0)
    if what in ("alphabets", "all"):
        t0 = time.time()
        total, hits = run_alphabets()
        print(f"\n=== dictionary-keyed alphabets as Quagmire I/II/III/IV, no transposition ===")
        print(f"alphabets: {total:,} ({time.time() - t0:.0f}s)  periods<=23 consistent: {len(hits)}")
        for h in hits[:10]:
            print("  ", h)
    if what in ("dict", "all"):
        t0 = time.time()
        report("columnar, dictionary keys length 12-24", *run_dict_columnar(), t0)
    if what == "grid":
        tag = "98 characters with the leading ?" if VARIANT == "q98" else "97 characters"
        t0 = time.time()
        report(f"[{tag}] decimation / railfence / serpentine / rotations / double rotations",
               *run_small(), t0)
        t0 = time.time()
        report(f"[{tag}] triple rotation, widths 2-49", *run_triple_rotation(), t0)
        t0 = time.time()
        report(f"[{tag}] columnar, every column order, widths 2-10",
               *run_columnar([2, 3, 4, 5, 6, 7, 8, 9, 10]), t0)
    if what == "double":
        t0 = time.time()
        report("columnar composed with grid rotation, widths 2-6", *run_mixed(), t0)
        t0 = time.time()
        report("double columnar transposition, every pair of widths 2-7",
               *run_double_columnar(), t0)
    if what == "columnar":
        widths = [int(x) for x in sys.argv[2:]]
        t0 = time.time()
        report(f"columnar exhaustive widths {widths}", *run_columnar(widths), t0)
