"""
Pencil-and-paper *recipes* for K4: combinations of simple letter-for-letter steps.

Earlier modules test one cipher family at a time. This one enumerates multi-stage
hand methods, guided by two published statements: Sanborn says the encryption is
letter-for-letter, and Scheidt says it is simple, keyword-driven and has more
than one stage. Wherever one stage's key can be DERIVED from the 24 crib letters
(or two stages matched by a hash join) nothing is guessed for that stage, so a
dictionary x dictionary search costs about one dictionary pass.

  P1  two polyalphabetic layers with different alphabets ("layer two"):
      inner keyword from the dictionary, outer key of any period <= 23 derived
  P2  Quagmire IV with ANY two dictionary keywords as the alphabets
      (keyed / transposed / reversed), any key of period <= 23, by hash join
  P3  irregular key use: keyword restarts, skips or stalls on a trigger letter,
      at word boundaries, or every n letters
  P4  numeric keys from the sculpture's own numbers and from keywords

  P5  three stages: a K3-style transposition plus the two layers of P1

Run:  python recipes.py [control|p1|p2|p3|p4|p5|all]
"""
from __future__ import annotations

import multiprocessing as mp
import random
import sys
import time
from collections import Counter

from kryptos import CIPHERTEXT, ALPHABET, KRYPTOS_KEYED, keyed_alphabet
from frontier import CRIB, CRIB_IDX, N, ST_PAIRS_SIG, _slot_pairs, COMBOS, ALPHAS, _shift, _dec
from gromark import transposed_alphabet, expand
import quadgrams

A, K = ALPHABET, KRYPTOS_KEYED
CRIB_P = [P for _, P in CRIB]
CRIB_PI = [ord(P) - 65 for P in CRIB_P]
_CT = CIPHERTEXT                       # controls swap this before starting a pool
_CTX = mp.get_context("fork")          # workers inherit module state, incl. _CT
_LOGS, _FLOOR = quadgrams.load_prose()


def english(text: str) -> float:
    """Average prose-quadgram score of the decoded letters (real English ~ -4.3)."""
    t = text.replace(".", "")
    n = len(t) - 3
    return sum(_LOGS.get(t[i:i + 4], _FLOOR) for i in range(n)) / n if n > 0 else -99.0


def load_words(min_len=3, max_len=24) -> list[str]:
    seen, out = set(), []
    with open("/usr/share/dict/words", encoding="utf-8", errors="ignore") as fh:
        for line in fh:
            w = line.strip().upper()
            if min_len <= len(w) <= max_len and w.isascii() and w.isalpha() and w not in seen:
                seen.add(w)
                out.append(w)
    return out


def _chunks(items, size):
    return [items[i:i + size] for i in range(0, len(items), size)]


# Outer-layer shift tables: SHT[k][x][y] = shift forced when letter x maps to letter y.
def _shift_tables():
    out = []
    for pa, ca, mode in COMBOS:
        pr = [ALPHAS[pa].index(chr(65 + x)) for x in range(26)]
        cr = [ALPHAS[ca].index(chr(65 + y)) for y in range(26)]
        out.append([[_shift(mode, pr[x], cr[y]) for y in range(26)] for x in range(26)])
    return out


SHT = _shift_tables()


def _periods_ok(s):
    """Periods <= 23 at which the forced shifts s (one per crib) are consistent."""
    hits = []
    for L, pairs in ST_PAIRS_SIG:
        for a, b in pairs:
            if s[a] != s[b]:
                break
        else:
            hits.append((L, len(pairs)))
    return hits


# =============================================================================
# P1  two polyalphabetic layers with different alphabets
# =============================================================================

_RK = [K.index(chr(65 + x)) for x in range(26)]
_KI = [ord(ch) - 65 for ch in K]


def _inner_table(alpha: str, mode: str):
    """T[letter][key_rank] -> letter, for one tableau step."""
    r = [alpha.index(chr(65 + x)) for x in range(26)]
    ai = [ord(ch) - 65 for ch in alpha]
    f = {"vig": lambda p, k: p + k, "beau": lambda p, k: k - p, "var": lambda p, k: p - k}[mode]
    return [[ai[f(r[x], k) % 26] for k in range(26)] for x in range(26)]


def _inner_inverse_table(alpha: str, mode: str):
    r = [alpha.index(chr(65 + x)) for x in range(26)]
    ai = [ord(ch) - 65 for ch in alpha]
    f = {"vig": lambda m, k: m - k, "beau": lambda m, k: k - m, "var": lambda m, k: m + k}[mode]
    return [[ai[f(r[x], k) % 26] for k in range(26)] for x in range(26)]


# (alphabet, arithmetic, alphabet the key letter is ranked in)
INNER = [("A", m, "A") for m in ("vig", "beau", "var")] + \
        [("K", m, kr) for kr in ("K", "A") for m in ("vig", "beau", "var")]
_INNER_T = [_inner_table(ALPHAS[x], m) for x, m, _ in INNER]
_INNER_INV = [_inner_inverse_table(ALPHAS[x], m) for x, m, _ in INNER]


def _key_ranks(word: str, kr: str):
    return [ord(c) - 65 for c in word] if kr == "A" else [_RK[ord(c) - 65] for c in word]


def _two_layer(words, cti, kp, periods):
    """Two-layer hits for cribs whose cipher letters are cti and key positions kp."""
    out = []
    for w in words:
        n = len(w)
        ranks = {"A": _key_ranks(w, "A"), "K": _key_ranks(w, "K")}
        for si, (_, _, kr) in enumerate(INNER):
            tab = _INNER_T[si]
            kk = [ranks[kr][x % n] for x in kp]
            for order, src in (("inner-first", CRIB_PI), ("outer-first", cti)):
                m = [tab[x][k] for x, k in zip(src, kk)]
                for k2, sh in enumerate(SHT):
                    if order == "inner-first":
                        s = [sh[a][b] for a, b in zip(m, cti)]
                    else:
                        s = [sh[a][b] for a, b in zip(CRIB_PI, m)]
                    for L, pairs in periods:
                        for a, b in pairs:
                            if s[a] != s[b]:
                                break
                        else:
                            out.append((w, si, order, k2, L, len(pairs)))
    return out


def _p1_task(words):
    cti = [ord(_CT[i]) - 65 for i in CRIB_IDX]
    return len(words), _two_layer(words, cti, CRIB_IDX, ST_PAIRS_SIG)


def p1_decrypt(word, si, order, k2, L, m=None, key_follows="plain"):
    """Full decryption for a two-layer hit. With a transposition m (plain index ->
    cipher index), key positions follow the plaintext order or the cipher order."""
    alpha, mode, kr = INNER[si]
    pa2, ca2, mode2 = COMBOS[k2]
    pa2, ca2 = ALPHAS[pa2], ALPHAS[ca2]
    pr2 = {ch: i for i, ch in enumerate(pa2)}
    cr2 = {ch: i for i, ch in enumerate(ca2)}
    ranks = _key_ranks(word, kr)
    n = len(word)
    tab, inv = _INNER_T[si], _INNER_INV[si]
    m = m if m is not None else list(range(N))
    cl = [_CT[m[i]] for i in range(N)]                       # cipher letter of plain index i
    q = list(range(N)) if key_follows == "plain" else m      # key position of plain index i
    shifts = {}
    out = []
    if order == "inner-first":           # C = outer(inner(P))
        for i, P in CRIB:
            mch = chr(65 + tab[ord(P) - 65][ranks[q[i] % n]])
            shifts[q[i] % L] = _shift(mode2, pr2[mch], cr2[cl[i]])
        for i in range(N):
            if q[i] % L not in shifts:
                out.append(".")
                continue
            mch = pa2[_dec(mode2, cr2[cl[i]], shifts[q[i] % L])]
            out.append(chr(65 + inv[ord(mch) - 65][ranks[q[i] % n]]))
    else:                                # P -> outer -> M, and M = table(C)
        mid = [chr(65 + tab[ord(cl[i]) - 65][ranks[q[i] % n]]) for i in range(N)]
        for i, P in CRIB:
            shifts[q[i] % L] = _shift(mode2, pr2[P], cr2[mid[i]])
        for i in range(N):
            out.append(pa2[_dec(mode2, cr2[mid[i]], shifts[q[i] % L])] if q[i] % L in shifts else ".")
    return "".join(out)


def p1_run(words=None, procs=30, quiet=False):
    words = words if words is not None else load_words()
    t0 = time.time()
    total, hits = 0, []
    with _CTX.Pool(procs) as pool:
        for n, h in pool.imap_unordered(_p1_task, _chunks(words, 2000)):
            total += n
            hits += h
    rows = []
    for w, si, order, k2, L, neq in hits:
        pt = p1_decrypt(w, si, order, k2, L)
        rows.append((english(pt), neq, w, INNER[si], order, COMBOS[k2], L, pt))
    rows.sort(reverse=True)
    if not quiet:
        print("\n=== P1: two polyalphabetic layers, inner keyword from the dictionary, outer key derived ===")
        print(f"  inner keywords: {total:,} x {len(INNER)} tableau settings x 2 layer orders "
              f"x 8 outer settings x periods <= 23  ({time.time() - t0:.0f}s)")
        print(f"  crib-consistent recipes: {len(rows)}")
        for sc, neq, w, inner, order, outer, L, pt in rows[:8]:
            print(f"    english={sc:.2f} equalities={neq} inner={w}/{'/'.join(inner)} {order} "
                  f"outer={'/'.join(outer)} L={L}")
            print(f"      {pt}")
    return rows


# =============================================================================
# P2  Quagmire IV with any two dictionary alphabets (hash join)
# =============================================================================

_ALPHA_LIST: list[str] = []
_ALPHA_NAME: list[str] = []
_ALPHA_RANK: list[bytes] = []


def build_alphabets(words):
    names = {A: "A-Z", A[::-1]: "A-Z reversed", K: "KRYPTOS keyed", K[::-1]: "KRYPTOS keyed reversed"}
    for w in words:
        ka, ta = keyed_alphabet(w), transposed_alphabet(w)
        names.setdefault(ka, w + " keyed")
        names.setdefault(ta, w + " transposed")
        names.setdefault(ka[::-1], w + " keyed reversed")
        names.setdefault(ta[::-1], w + " transposed reversed")
    _ALPHA_LIST[:] = list(names)
    _ALPHA_NAME[:] = [names[a] for a in _ALPHA_LIST]
    _ALPHA_RANK[:] = [bytes(a.index(chr(65 + x)) for x in range(26)) for a in _ALPHA_LIST]
    return len(_ALPHA_LIST)


def _p2_task(li):
    L, pairs = ST_PAIRS_SIG[li]
    pp = [(CRIB_PI[a], CRIB_PI[b]) for a, b in pairs]
    cc = [(ord(_CT[CRIB_IDX[a]]) - 65, ord(_CT[CRIB_IDX[b]]) - 65) for a, b in pairs]
    by_c: dict[bytes, list[int]] = {}
    for idx, r in enumerate(_ALPHA_RANK):
        by_c.setdefault(bytes((r[x] - r[y]) % 26 for x, y in cc), []).append(idx)
    hits, count = [], 0
    for idx, r in enumerate(_ALPHA_RANK):
        m = by_c.get(bytes((r[x] - r[y]) % 26 for x, y in pp))
        if m:
            count += len(m)
            if len(hits) < 20000:
                hits += [(idx, j) for j in m[:50]]
    return L, len(pairs), count, hits


def p2_decrypt(pi, ci, L):
    pa, cr = _ALPHA_LIST[pi], _ALPHA_RANK[ci]
    pr = _ALPHA_RANK[pi]
    shifts = {i % L: (cr[ord(_CT[i]) - 65] - pr[ord(P) - 65]) % 26 for i, P in CRIB}
    return "".join(pa[(cr[ord(c) - 65] - shifts[i % L]) % 26] if i % L in shifts else "."
                   for i, c in enumerate(_CT))


def p2_run(words=None, procs=23, quiet=False):
    words = words if words is not None else load_words()
    t0 = time.time()
    n_alpha = build_alphabets(words)
    with _CTX.Pool(procs) as pool:
        results = sorted(pool.imap_unordered(_p2_task, range(len(ST_PAIRS_SIG))))
    rows = []
    for L, neq, count, hits in results:
        for pi, ci in hits:
            pt = p2_decrypt(pi, ci, L)
            rows.append((english(pt), L, neq, _ALPHA_NAME[pi], _ALPHA_NAME[ci], pt))
    rows.sort(reverse=True)
    if not quiet:
        print("\n=== P2: Quagmire IV, both alphabets from dictionary keywords, key of any period <= 23 ===")
        print(f"  alphabets: {n_alpha:,} (keyed, transposed, and each reversed) on each side "
              f"({time.time() - t0:.0f}s)")
        expect = {L: n_alpha * n_alpha * 26.0 ** -neq for L, neq, _, _ in results}
        print("  consistent alphabet pairs by period (chance expectation in brackets):")
        print("   ", "  ".join(f"L={L}: {count} ({expect[L]:.2g})" for L, _, count, _ in results))
        print("  (each pair also appears with both alphabets reversed, which doubles the counts;")
        print("   periods 19 and 38 get one equality free from the R->P coincidence)")
        print("  most English-looking decryptions for periods <= 23 (real English ~ -4.3):")
        for sc, L, neq, pn, cn, pt in [r for r in rows if r[1] <= 23][:8]:
            print(f"    english={sc:.2f} L={L} equalities={neq} plain={pn} cipher={cn}")
            print(f"      {pt}")
        if not rows:
            print("    none")
    return rows, results


# =============================================================================
# P3  irregular key use
# =============================================================================

def _forced(ct):
    """The 8 forced-shift vectors (one value per crib) for ciphertext ct."""
    return [[sh[p][ord(ct[i]) - 65] for p, i in zip(CRIB_PI, CRIB_IDX)] for sh in SHT]


def _slot_hits(S, slots, L, min_eq):
    pairs = _slot_pairs(slots, L)
    if len(pairs) < min_eq:
        return []
    return [(k, len(pairs)) for k, s in enumerate(S) if all(s[a] == s[b] for a, b in pairs)]


def _step(g, trig, action):
    if action == "restart":
        return 0 if trig else g + 1
    if action == "skip":
        return g + (2 if trig else 1)
    return g + (0 if trig else 1)        # stall


def _trigger_slots(letters, t, action, timing, start):
    """Key index for each position of `letters`, entering with index `start`."""
    out, g = [], start
    for i, ch in enumerate(letters):
        if timing == "at":
            g = _step(g - 1, ch == t, action)
            out.append(g)
            g += 1
        else:                            # the change takes effect on the next letter
            out.append(g)
            g = _step(g, ch == t, action)
    return out


def p3_run(ct=None, quiet=False, min_eq=8):
    ct = ct or _CT
    S = _forced(ct)
    found = []
    tests = 0
    w1 = list(range(21, 34))
    w2 = list(range(63, 74))
    # (a) restart at each word: EAST | NORTHEAST | BERLIN | CLOCK
    word_slots = list(range(4)) + list(range(9)) + list(range(6)) + list(range(5))
    for L in range(1, 24):
        tests += 1
        for k, neq in _slot_hits(S, word_slots, L, min_eq):
            found.append((neq, f"restart at each word, L={L}", k))
    # (b) restart every n letters, keyword shorter than n
    for n in range(2, 61):
        for L in range(1, min(23, n - 1) + 1):
            tests += 1
            for k, neq in _slot_hits(S, [i % n for i in CRIB_IDX], L, min_eq):
                found.append((neq, f"restart every {n} letters, L={L}", k))
    # (c) ciphertext-letter triggers: the whole index sequence is known
    for t in ALPHABET:
        for action in ("restart", "skip", "stall"):
            for timing in ("after", "at"):
                g = _trigger_slots(ct, t, action, timing, 0)
                slots = [g[i] for i in CRIB_IDX]
                for L in range(1, 24):
                    tests += 1
                    for k, neq in _slot_hits(S, slots, L, min_eq):
                        found.append((neq, f"cipher letter {t}: {action} ({timing}), L={L}", k))
    # (d) plaintext-letter triggers: index known inside each crib up to an entry offset
    p1, p2 = CRIB_P[:13], CRIB_P[13:]
    for t in sorted(set(CRIB_P)):
        for action in ("restart", "skip", "stall"):
            for timing in ("after", "at"):
                for L in range(1, 24):
                    starts1 = range(L) if action == "restart" else (0,)
                    for o1 in starts1:
                        a = _trigger_slots(p1, t, action, timing, o1)
                        for o2 in range(L):
                            tests += 1
                            slots = a + _trigger_slots(p2, t, action, timing, o2)
                            for k, neq in _slot_hits(S, slots, L, min_eq + 1):
                                found.append((neq, f"plain letter {t}: {action} ({timing}), L={L}, "
                                                   f"entry offsets {o1},{o2}", k))
    found.sort(reverse=True)
    if not quiet:
        print("\n=== P3: irregular key use (restart / skip / stall on a trigger, word or block restarts) ===")
        print(f"  rule settings tested: {tests:,} x 8 alphabet/arithmetic settings")
        for neq, desc, k in found[:10]:
            print(f"    equalities={neq}  {desc}  {'/'.join(COMBOS[k])}")
        if not found:
            print("  no crib-consistent rule")
    return found


# =============================================================================
# P4  numeric keys
# =============================================================================

NUMBERS = {
    "K2 coordinates 38 57 6.5 N 77 8 44 W": "385765778 44".replace(" ", ""),
    "K2 latitude": "385765", "K2 longitude": "77844",
    "coordinates zero-padded": "3857065770844",
    "1986 (Egypt)": "1986", "1989 (Berlin Wall)": "1989", "1990 (dedication)": "1990",
    "3 Nov 1990": "11031990", "3 Nov 1990 (d-m-y)": "03111990", "1990-11-03": "19901103",
    "9 Nov 1989": "11091989", "9 Nov 1989 (d-m-y)": "09111989", "1989-11-09": "19891109",
    "26 Nov 1922 (tomb)": "11261922", "26 Nov 1922 (d-m-y)": "26111922",
    "1986+1989": "19861989", "sculpture 865/869/97": "86586997", "97": "97",
    # header of Sanborn's tableau printout: JOB 57562-0000-03 / REV 02-10 EXP 02-10 / SIZ 22.02
    "tableau job number": "57562000003", "tableau job 57562": "57562", "job 57562-03": "5756203",
    "tableau rev/exp 02-10": "0210", "tableau size 22.02": "2202", "job header all": "5756200000302100210 2202".replace(" ", ""),
    # the padding E's in the Morse text: how many stand before/after each word
    "Morse E counts": "216322531", "Morse E counts (+1)": "2163225311",
    "Morse E counts per line": "93941", "Morse word lengths": "9971366561248",
    "Morse E counts and word lengths": "2916932713622655361",
    # World Clock (Urania-Weltzeituhr), Alexanderplatz: Sanborn's "Berlin Clock" (Nov 2025 letter)
    "World Clock opened 30 Sep 1969": "09301969", "30 Sep 1969 (d-m-y)": "30091969", "1969": "1969",
    "World Clock 24 zones / 146 places": "24146", "24": "24", "1969+1989": "19691989",
    "World Clock position 52 31 16 N 13 24 48 E (approx.)": "523116132448",
    "essay date 18 May 1964": "05181964", "18 May 1964 (d-m-y)": "18051964", "168 BC / 233 AD": "168233",
}
THEMED = """KRYPTOS PALIMPSEST PALIMPCEST ABSCISSA SANBORN SCHEIDT LANGLEY WEBSTER IQLUSION ILLUSION
UNDERGRUUND UNDERGROUND DESPARATLY SHADOW FORCES LUCID MEMORY VIRTUALLY INVISIBLE DIGETAL
INTERPRETATIT POSITION BERLIN CLOCK EAST NORTHEAST NORTH WEST SOUTH COMPASS ROSE LODESTONE
MAGNETIC FIELD LAYERTWO IDBYROWS YAR DYAHR HILL MATRIX CARTER CARNARVON TUTANKHAMUN EGYPT
WELTZEITUHR URANIA ALEXANDERPLATZ WALL MESSAGE SECRET POWER POINT ENIGMA CIA AGENCY
INTELLIGENCE WONDERFULTHINGS CANYOUSEEANYTHING TOMB CANDLE CHAMBER MIST
FUMEE SMOKE MIRRORS MEDUSA QUMRAN SCROLLS DEADSEA DEADSEASCROLLS ALBRIGHT PASTERNAK ZHIVAGO
SAKHAROV SOLZHENITSYN ANDROPOV GORKY TRADECRAFT COUNTERINTELLIGENCE CLANDESTINE
LOCKSTOCKANDBARREL SONSOFLIGHT SONSOFDARKNESS CYRILLIC PROJECTOR ANTIPODES
WASHINGTON ALEXANDRIA ARLINGTON RANDOLPHMACON PRATT COVELL BEDOUINS HABAKUK ISAIAH DENISOVICH
APPROXIMATLY HEIGTH IMMEDIATLY MONESTARY RITIOUS ARAMIC LAMBETH QUADRILATERAL BRENT
WORLDCLOCK WORLDTIMECLOCK URANIAWELTZEITUHR ERICHJOHN WINDROSE COMPASSROSE BERLINWALL BERLINERMAUER
MAUER MAUERFALL TIMEZONE TIMEZONES ZEITZONE GREENWICH MERIDIAN DATELINE EASTBERLIN OSTBERLIN
CHECKPOINTCHARLIE BRANDENBURGGATE NOVEMBER GATHERINGPLACE DELIVERINGAMESSAGE MENGENLEHREUHR
CAIRO KAIRO GIZA LUXOR NILE PYRAMID SPHINX VALLEYOFTHEKINGS HOWARDCARTER WORLD TIME
MOSKAU MOSCOW LENINGRAD ALMAATA PRAG WARSCHAU BUDAPEST SOFIA BUKAREST HAVANNA HANOI PEKING
ULANBATOR TOKIO NEWYORK LONDON PARIS ROM WLADIWOSTOK HONOLULU""".split()


def _numeric_keys():
    """Yield (label, key[97]) for every numeric key candidate."""
    seqs = {}
    for name, digits in NUMBERS.items():
        d = [int(ch) for ch in digits]
        seqs[name + " digits"] = d
        if len(d) >= 4:
            seqs[name + " digit pairs"] = [(10 * a + b) % 26 for a, b in zip(d[::2], d[1::2])]
    for w in THEMED:
        order = sorted(range(len(w)), key=lambda i: (w[i], i))
        rank = [0] * len(w)
        for r, i in enumerate(order):
            rank[i] = r + 1
        seqs[w + " column order"] = rank
        seqs[w + " A1Z26"] = [ord(c) - 64 for c in w]
        seqs[w + " A0Z25"] = [ord(c) - 65 for c in w]
        seqs[w + " A1Z26 digits"] = [int(ch) for c in w for ch in str(ord(c) - 64)]
    for name, v in seqs.items():
        n = len(v)
        for rot in range(n):
            yield f"{name}, repeating, rotation {rot}", [v[(i + rot) % n] % 26 for i in range(N)]
        for base in (5, 8, 10, 12, 26):
            for plen in range(2, min(8, n) + 1):
                primer = tuple(x % base for x in v[:plen])
                if any(primer):
                    yield f"{name}, Gromark base {base} primer {plen}", expand(primer, base)


def p4_run(ct=None, quiet=False, use_dictionary=True, flag=11):
    ct = ct or _CT
    S = _forced(ct)
    keys = list(_numeric_keys())
    fuzzy, best = [], (0, "")
    for label, key in keys:
        kk = [key[i] for i in CRIB_IDX]
        for k, s in enumerate(S):
            for sign in (1, -1):
                cnt = max(Counter((a - sign * b) % 26 for a, b in zip(s, kk)).values())
                if cnt > best[0]:
                    best = (cnt, label)
                if cnt >= flag:
                    fuzzy.append((cnt, label, COMBOS[k], sign))
    exact = []
    if use_dictionary:                     # numeric key + one keyword alphabet + one arbitrary
        import gromark as g
        if not g._MAP_P:
            names = g._build_maps()
            p4_run._names = names
        names = p4_run._names
        for label, key in keys:
            for known, pairs, table in (("plain", g._KP, g._MAP_P), ("cipher", g._KC, g._MAP_C)):
                for sign in (1, -1):
                    d = (tuple((sign * (key[y] - key[x])) % 26 for x, y in pairs) if known == "plain"
                         else tuple((sign * (key[x] - key[y])) % 26 for x, y in pairs))
                    for alpha in table.get(d, ()):
                        for mode in g._MODES:
                            pt = g._solve_candidate(key, known, alpha, mode)
                            if pt:
                                exact.append((english(pt), label, known, names[alpha], mode, pt))
        exact.sort(reverse=True)
    fuzzy.sort(reverse=True)
    if not quiet:
        print("\n=== P4: numeric keys from the sculpture's numbers and from keywords ===")
        print(f"  numeric keys tested: {len(keys):,}")
        print(f"  A-Z / KRYPTOS alphabets: best agreement {best[0]}/24 [{best[1]}] (chance gives ~7-9)")
        for cnt, label, combo, sign in fuzzy[:5]:
            print(f"    HIT {cnt}/24 {label} {'/'.join(combo)} sign={sign}")
        if use_dictionary:
            print(f"  with one dictionary-keyword alphabet + one arbitrary: {len(exact)} reproduce the cribs")
            for sc, label, known, name, mode, pt in exact[:5]:
                print(f"    english={sc:.2f} {label} | {known} alphabet {name} {mode}\n      {pt}")
    return fuzzy, exact, best


p4_run._names = {}


# =============================================================================
# P5  three stages: a K3-style transposition plus two keyword layers
# =============================================================================

def _p5_task(items):
    out = []
    for label, m in items:
        cti = [ord(_CT[m[i]]) - 65 for i in CRIB_IDX]
        kp = [m[i] for i in CRIB_IDX]
        cipher_periods = [(L, p) for L in range(1, 24) for p in [_slot_pairs(kp, L)] if len(p) >= 7]
        for follows, pos, periods in (("plain", CRIB_IDX, ST_PAIRS_SIG), ("cipher", kp, cipher_periods)):
            for hit in _two_layer(THEMED, cti, pos, periods):
                out.append((label, m, follows) + hit)
    return len(items), out


def p5_maps(max_width=6):
    import itertools
    from frontier import small_families, columnar_map, inverse
    for label, m in small_families():
        if label == "identity":
            continue
        yield label, m
        yield label + " (inverse)", inverse(m)
    for w in range(2, max_width + 1):
        for order in itertools.permutations(range(w)):
            m = columnar_map(w, order)
            yield f"columnar w={w} {order}", m
            yield f"columnar w={w} {order} (inverse)", inverse(m)


def p5_run(maps=None, procs=30, quiet=False):
    items = list(maps if maps is not None else p5_maps())
    t0 = time.time()
    total, hits = 0, []
    with _CTX.Pool(procs) as pool:
        for n, h in pool.imap_unordered(_p5_task, _chunks(items, 100)):
            total += n
            hits += h
    rows = []
    for label, m, follows, w, si, order, k2, L, neq in hits:
        pt = p1_decrypt(w, si, order, k2, L, m=m, key_follows=follows)
        rows.append((neq, english(pt), label, follows, w, INNER[si], order, COMBOS[k2], L, pt))
    rows.sort(reverse=True)
    if not quiet:
        print("\n=== P5: K3-style transposition + two keyword layers (three stages) ===")
        print(f"  transpositions: {total:,} x key following plain or cipher order x {len(THEMED)} themed "
              f"inner keywords x {len(INNER)} settings x 2 layer orders, outer key derived "
              f"({time.time() - t0:.0f}s)")
        print(f"  crib-consistent recipes: {len(rows)}  (7 equalities is the chance floor; "
              f"a real solution would show 10+ and read as English)")
        for neq, sc, label, follows, w, inner, order, outer, L, pt in rows[:8]:
            print(f"    equalities={neq} english={sc:.2f} [{label}] key follows {follows} order; "
                  f"inner={w}/{'/'.join(inner)} {order} outer={'/'.join(outer)} L={L}")
            print(f"      {pt}")
    return rows


# =============================================================================
# controls
# =============================================================================

def _planted_text():
    pt = list(("ITISBURIEDOUTTHERESOMEWHEREWHOKNOWSTHEEXACTLOCATION" * 2)[:N])
    for i, ch in CRIB:
        pt[i] = ch
    return "".join(pt)


def control():
    global _CT
    saved = _CT
    pt = _planted_text()
    ok = True
    rk = {ch: i for i, ch in enumerate(K)}
    try:
        # sanity: the inner tableau step is K1's actual method
        from sculpture import K1_CT
        from solve import K1_PT
        si = INNER.index(("K", "vig", "K"))
        kr = _key_ranks("PALIMPSEST", "K")
        enc = "".join(chr(65 + _INNER_T[si][ord(p) - 65][kr[i % 10]]) for i, p in enumerate(K1_PT))
        good = enc == K1_CT
        ok &= good
        print(f"[control P1] tableau step reproduces K1 from PALIMPSEST: {good}")

        # P1: K1 method with PALIMPSEST, then plain Vigenere with SHADOW
        mid = "".join(chr(65 + _INNER_T[si][ord(p) - 65][kr[i % 10]]) for i, p in enumerate(pt))
        _CT = "".join(chr((ord(m) + ord("SHADOW"[i % 6]) - 130) % 26 + 65) for i, m in enumerate(mid))
        rows = p1_run(words=["KRYPTOS", "PALIMPSEST", "ABSCISSA", "BERLIN", "DECOY"], procs=2, quiet=True)
        good = any(r[2] == "PALIMPSEST" and r[4] == "inner-first" and r[6] == 6 and r[7] == pt for r in rows)
        ok &= good
        print(f"[control P1] PALIMPSEST tableau layer + Vigenere layer recovered: {good}")

        # P2: plain alphabet ABSCISSA keyed reversed, cipher alphabet PALIMPSEST transposed, period 7
        pa, ca = keyed_alphabet("ABSCISSA")[::-1], transposed_alphabet("PALIMPSEST")
        key = [3, 17, 8, 22, 5, 11, 19]
        _CT = "".join(ca[(pa.index(p) + key[i % 7]) % 26] for i, p in enumerate(pt))
        rows, _ = p2_run(words=["KRYPTOS", "PALIMPSEST", "ABSCISSA", "BERLIN", "DECOY"], procs=4, quiet=True)
        good = any(r[1] == 7 and "ABSCISSA keyed reversed" in r[3] and "PALIMPSEST transposed" == r[4]
                   and r[5] == pt for r in rows)
        ok &= good
        print(f"[control P2] two-keyword Quagmire IV recovered: {good}")

        # P3: Vigenere with SHADOW whose key restarts after every ciphertext Q
        c, g = [], 0
        for p in pt:
            ch = chr((ord(p) + ord("SHADOW"[g % 6]) - 130) % 26 + 65)
            c.append(ch)
            g = 0 if ch == "Q" else g + 1
        _CT = "".join(c)
        found = p3_run(quiet=True)
        good = any("cipher letter Q: restart (after), L=6" in d and COMBOS[k] == ("A", "A", "vig")
                   for _, d, k in found)
        ok &= good
        print(f"[control P3] restart-on-Q rule recovered: {good}")
        # ...and one that skips a key letter after every plaintext T
        c, g = [], 0
        for p in pt:
            c.append(chr((ord(p) + ord("SHADOW"[g % 6]) - 130) % 26 + 65))
            g += 2 if p == "T" else 1
        _CT = "".join(c)
        found = p3_run(quiet=True)
        good = any("plain letter T: skip (after), L=6" in d and COMBOS[k] == ("A", "A", "vig")
                   for _, d, k in found)
        ok &= good
        print(f"[control P3] skip-after-T rule recovered: {good}")

        # P5: K3-style rotation, then K1's tableau with PALIMPSEST, then Vigenere with SHADOW
        from frontier import _rot_seq, _map_from_seq
        m = _map_from_seq(_rot_seq(8, True))
        tr = [""] * N
        for i in range(N):
            tr[m[i]] = pt[i]
        mid = [chr(65 + _INNER_T[si][ord(p) - 65][kr[j % 10]]) for j, p in enumerate(tr)]
        _CT = "".join(chr((ord(x) + ord("SHADOW"[j % 6]) - 130) % 26 + 65) for j, x in enumerate(mid))
        rows = p5_run(maps=[("rotate w=8 cw", m), ("decoy", list(range(N))[::-1])], procs=2, quiet=True)
        good = any(r[2] == "rotate w=8 cw" and r[3] == "cipher" and r[4] == "PALIMPSEST"
                   and r[8] == 6 and all(a == b for a, b in zip(r[9], pt) if a != ".")
                   for r in rows)
        ok &= good
        print(f"[control P5] rotation + PALIMPSEST tableau + Vigenere recovered: {good}")

        # P4: Gronsfeld with the K2 coordinate digits
        d = [int(ch) for ch in NUMBERS["K2 coordinates 38 57 6.5 N 77 8 44 W"]]
        _CT = "".join(chr((ord(p) - 65 + d[i % len(d)]) % 26 + 65) for i, p in enumerate(pt))
        fuzzy, _, best = p4_run(quiet=True, use_dictionary=False)
        good = any("K2 coordinates" in label and "rotation 0" in label and cnt == 24
                   for cnt, label, _, _ in fuzzy)
        ok &= good
        print(f"[control P4] coordinate-digit key recovered: {good}")
    finally:
        _CT = saved
    return ok


if __name__ == "__main__":
    what = sys.argv[1] if len(sys.argv) > 1 else "all"
    if what in ("control", "all"):
        assert control(), "positive control failed"
    if what in ("p1", "all"):
        p1_run()
    if what in ("p2", "all"):
        p2_run()
    if what in ("p3", "all"):
        p3_run()
    if what in ("p4", "all"):
        p4_run()
    if what in ("p5", "all"):
        p5_run()
