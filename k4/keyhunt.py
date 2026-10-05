"""
Keyword hunt: re-run every stage that has to GUESS a keyword, using the 37.7M
letter-strings harvested from the installed security wordlists (wordlists.py).

A repeating key never needs guessing: it is derived from the cribs, which covers
every possible key. A wordlist matters only where a keyword is enumerated:

  alphabets  keyword builds a mixed alphabet (keyed or ACA-transposed), used as
             Quagmire I/II/III or IV-with-KRYPTOS with any key of period <= 23;
             the same alphabets as Gromark alphabets (any small-digit key, and
             standard lagged-Fibonacci keys with the other alphabet arbitrary)
  layers     keyword is the key of an inner tableau layer; outer layer derived
  pairs      keyword alphabet paired with any English-dictionary alphabet
             (Quagmire IV with two keywords), key derived

  texts      keyword alphabet + a running key read from a known text (the K1-K3
             plaintexts, the sculpture, the Morse text, Sanborn's source documents)

  tolerant   the repeating-key tests again, allowing one wrong crib letter or a
             dropped/extra letter between the clues (Sanborn made both in K1-K2)

  autokey    keyword alphabet + a key taken from the message itself (autokey)

Run:  python keyhunt.py [control|alphabets|layers|pairs|texts|tolerant|autokey|all]
"""
from __future__ import annotations

import itertools
import multiprocessing as mp
import os
import random
import sys
import tempfile
import time
from collections import defaultdict

from kryptos import CIPHERTEXT, ALPHABET, KRYPTOS_KEYED, keyed_alphabet
from frontier import CRIB, CRIB_IDX, N, ST_PAIRS_SIG
from gromark import transposed_alphabet, window, expand
import recipes as R
import wordlists

_CT = CIPHERTEXT
_CTX = mp.get_context("fork")
PERIODS = [(L, p) for L, p in ST_PAIRS_SIG if L <= 23]
_RK = [KRYPTOS_KEYED.index(chr(65 + x)) for x in range(26)]
PA = [ord(P) - 65 for _, P in CRIB]
PROCS = 30

# state shared with forked workers
_SIG_P: dict = {}
_SIG_C: dict = {}
_GPK: list = []
_GCK: list = []
_JOIN_C: dict = {}
_JOIN_P: dict = {}


# --- reading the corpus in byte ranges ------------------------------------------

def _ranges(path, pieces=240):
    size = os.path.getsize(path)
    step = max(1, size // pieces)
    return [(path, a, min(size, a + step)) for a in range(0, size, step)]


def _read(path, a, b):
    with open(path, "rb") as fh:
        if a:
            fh.seek(a - 1)
            fh.readline()
        pos = fh.tell()
        while pos < b:
            line = fh.readline()
            if not line:
                break
            pos += len(line)
            w = line.strip().decode("ascii", "ignore")
            if w:
                yield w


def _ranks(alpha):
    r = [0] * 26
    for i, ch in enumerate(alpha):
        r[ord(ch) - 65] = i
    return r


# --- Gromark key signatures (standard rule, the other alphabet arbitrary) ---------

def _chain_pairs(ct, by_cipher):
    groups = defaultdict(list)
    for j, (i, P) in enumerate(CRIB):
        groups[ct[i] if by_cipher else P].append(j)
    return [(a, b) for js in groups.values() for a, b in zip(js, js[1:])]


def _key_sig_task(args):
    base, n, lead, kp, kc, free_p, free_c = args
    out_p, out_c = [], []
    top = max(CRIB_IDX) + 1
    for rest in itertools.product(range(base), repeat=n - len(lead)):
        primer = lead + rest
        if not any(primer):
            continue
        k = expand(primer, base, length=top)
        d = bytes((k[y] - k[x]) % 26 for x, y in kp)
        # the alphabet side fixes some of these differences; skip keys that cannot match
        if all(d[i] == v for i, v in free_p):
            out_p.append((d, base, primer))
        d = bytes((k[x] - k[y]) % 26 for x, y in kc)
        if all(d[i] == v for i, v in free_c):
            out_c.append((d, base, primer))
    return out_p, out_c


def build_key_signatures(ct):
    """Signatures of every standard Gromark key: base 10 up to 6 digits, bases 3-12
    up to 5 digits, bases 3-26 up to 4 digits."""
    pk, ck = _chain_pairs(ct, True), _chain_pairs(ct, False)
    _GPK[:] = [(ord(CRIB[a][1]) - 65, ord(CRIB[b][1]) - 65) for a, b in pk]
    _GCK[:] = [(ord(ct[CRIB[a][0]]) - 65, ord(ct[CRIB[b][0]]) - 65) for a, b in ck]
    kp = [(CRIB[a][0], CRIB[b][0]) for a, b in pk]
    kc = [(CRIB[a][0], CRIB[b][0]) for a, b in ck]
    # pairs whose two letters are identical force a key difference of 0
    free_p = [(i, 0) for i, (x, y) in enumerate(_GPK) if x == y]
    free_c = [(i, 0) for i, (x, y) in enumerate(_GCK) if x == y]
    specs = {(10, n) for n in range(2, 7)} | {(b, n) for b in range(3, 13) for n in range(2, 6)} \
        | {(b, n) for b in range(3, 27) for n in range(2, 5)}
    tasks = []
    for base, n in sorted(specs):
        depth = 1 if base ** n > 20000 else 0
        for lead in itertools.product(range(base), repeat=depth):
            tasks.append((base, n, lead, kp, kc, free_p, free_c))
    _SIG_P.clear()
    _SIG_C.clear()
    with _CTX.Pool(PROCS) as pool:
        for out_p, out_c in pool.imap_unordered(_key_sig_task, tasks, chunksize=4):
            for d, base, primer in out_p:
                _SIG_P.setdefault(d, []).append((base, primer, 1))
                _SIG_P.setdefault(bytes((-v) % 26 for v in d), []).append((base, primer, -1))
            for d, base, primer in out_c:
                _SIG_C.setdefault(d, []).append((base, primer, 1))
                _SIG_C.setdefault(bytes((-v) % 26 for v in d), []).append((base, primer, -1))


# --- pass 1: keyword as alphabet ---------------------------------------------------

def _alphabet_task(args):
    path, a, b = args
    ca_ = [ord(_CT[i]) - 65 for i in CRIB_IDX]
    pk_, ck_ = [_RK[p] for p in PA], [_RK[c] for c in ca_]
    periodic, g1, g3, count = [], [], [], 0
    for w in _read(path, a, b):
        count += 1
        ka = keyed_alphabet(w)
        for style, x in (("keyed", ka), ("transposed", transposed_alphabet(w))):
            r = _ranks(x)
            px, cx = [r[p] for p in PA], [r[c] for c in ca_]
            for role, p, c in (("plain=kw cipher=A-Z", px, ca_), ("plain=A-Z cipher=kw", PA, cx),
                               ("both=kw", px, cx), ("plain=kw cipher=KRYPTOS", px, ck_),
                               ("plain=KRYPTOS cipher=kw", pk_, cx)):
                for mode in ("vig", "beau"):
                    s = ([(y - z) % 26 for z, y in zip(p, c)] if mode == "vig"
                         else [(y + z) % 26 for z, y in zip(p, c)])
                    for L, pairs in PERIODS:
                        for i, j in pairs:
                            if s[i] != s[j]:
                                break
                        else:
                            periodic.append((len(pairs), L, w, style, role, mode))
                    if len(set(s)) <= 11:
                        size, _ = window(s)
                        if size <= 11:
                            g1.append((size, w, style, role, mode))
            sp = bytes((r[i] - r[j]) % 26 for i, j in _GPK)
            if sp in _SIG_P:
                g3.append((w, style, "plain", x, sp))
            sc = bytes((r[i] - r[j]) % 26 for i, j in _GCK)
            if sc in _SIG_C:
                g3.append((w, style, "cipher", x, sc))
    return count, periodic, g1, g3


_MODES = {"vig": (1, 1), "beau": (-1, 1), "var": (1, -1)}      # c = sp*p + sk*k


def _gromark_solve(key, known, alpha, mode, ct):
    """Derive the unknown alphabet from the cribs; partial plaintext or None."""
    sp, sk = _MODES[mode]
    r = {ch: i for i, ch in enumerate(alpha)}
    if known == "plain":
        cr = {}
        for i, P in CRIB:
            v = (sp * r[P] + sk * key[i]) % 26
            if cr.setdefault(ct[i], v) != v:
                return None
        if len(set(cr.values())) != len(cr):
            return None
        return "".join(alpha[(sp * (cr[c] - sk * key[i])) % 26] if c in cr else "."
                       for i, c in enumerate(ct))
    rank_to_plain, plain_rank = {}, {}
    for i, P in CRIB:
        v = (sp * (r[ct[i]] - sk * key[i])) % 26
        if rank_to_plain.setdefault(v, P) != P or plain_rank.setdefault(P, v) != v:
            return None
    return "".join(rank_to_plain.get((sp * (r[c] - sk * key[i])) % 26, ".") for i, c in enumerate(ct))


def _decrypt_periodic(pa, ca, mode, L, ct):
    pr = {ch: i for i, ch in enumerate(pa)}
    cr = {ch: i for i, ch in enumerate(ca)}
    sgn = -1 if mode == "vig" else 1
    shifts = {i % L: (cr[ct[i]] + sgn * pr[P]) % 26 for i, P in CRIB}
    out = []
    for i, c in enumerate(ct):
        s = shifts.get(i % L)
        out.append("." if s is None else pa[((cr[c] - s) if mode == "vig" else (s - cr[c])) % 26])
    return "".join(out)


def _role_alphabets(word, style, role):
    x = keyed_alphabet(word) if style == "keyed" else transposed_alphabet(word)
    return {"plain=kw cipher=A-Z": (x, ALPHABET), "plain=A-Z cipher=kw": (ALPHABET, x),
            "both=kw": (x, x), "plain=kw cipher=KRYPTOS": (x, KRYPTOS_KEYED),
            "plain=KRYPTOS cipher=kw": (KRYPTOS_KEYED, x)}[role]


def run_alphabets(path=None, quiet=False):
    path = path or wordlists.build()
    t0 = time.time()
    build_key_signatures(_CT)
    total, periodic, g1, g3 = 0, [], [], []
    with _CTX.Pool(PROCS) as pool:
        for n, p, a, b in pool.imap_unordered(_alphabet_task, _ranges(path)):
            total += n
            periodic += p
            g1 += a
            g3 += b
    rows = []
    for neq, L, w, style, role, mode in periodic:
        pa, ca = _role_alphabets(w, style, role)
        pt = _decrypt_periodic(pa, ca, mode, L, _CT)
        rows.append((R.english(pt), neq, L, w, style, role, mode, pt))
    rows.sort(reverse=True)
    grows = []
    for w, style, known, alpha, sig in g3:
        for base, primer, sign in (_SIG_P if known == "plain" else _SIG_C)[sig]:
            key = expand(primer, base)
            for mode in _MODES:
                pt = _gromark_solve(key, known, alpha, mode, _CT)
                if pt:
                    grows.append((R.english(pt), w, style, known, base, primer, mode, pt))
    grows = sorted(set(grows), reverse=True)
    if not quiet:
        print("\n=== keyword as ALPHABET (37.7M wordlist strings) ===")
        print(f"  keywords: {total:,} x 2 mixing styles ({time.time() - t0:.0f}s)")
        print(f"  Quagmire I/II/III/IV-with-KRYPTOS, any key of period <= 23: {len(rows)} crib-consistent")
        for sc, neq, L, w, style, role, mode, pt in rows[:8]:
            print(f"    english={sc:.2f} equalities={neq} L={L} {w} ({style}) {role} {mode}\n      {pt}")
        g1.sort()
        print(f"  Gromark, any digit key: smallest base that fits = "
              f"{g1[0][0] if g1 else '12 or more'} (a real fit needs <= 10; chance bottoms out near 11-12)")
        for size, w, style, role, mode in g1[:5]:
            print(f"    base {size}: {w} ({style}) {role} {mode}")
        print(f"  Gromark, standard key rule, other alphabet arbitrary "
              f"({sum(len(v) for v in _SIG_P.values()) // 2:,} usable keys): "
              f"{len(grows)} reproduce the cribs")
        for sc, w, style, known, base, primer, mode, pt in grows[:8]:
            print(f"    english={sc:.2f} {known} alphabet {w} ({style}) base {base} primer {primer} {mode}\n      {pt}")
    return rows, g1, grows


# --- pass 2: keyword as the key of an inner layer -----------------------------------

def _layer_task(args):
    path, a, b = args
    cti = [ord(_CT[i]) - 65 for i in CRIB_IDX]
    words = list(_read(path, a, b))
    return len(words), R._two_layer(words, cti, CRIB_IDX, PERIODS)


def run_layers(path=None, quiet=False):
    path = path or wordlists.build()
    t0 = time.time()
    total, hits = 0, []
    with _CTX.Pool(PROCS) as pool:
        for n, h in pool.imap_unordered(_layer_task, _ranges(path, 600)):
            total += n
            hits += h
    R._CT = _CT
    rows = []
    for w, si, order, k2, L, neq in hits:
        pt = R.p1_decrypt(w, si, order, k2, L)
        rows.append((R.english(pt), neq, w, R.INNER[si], order, R.COMBOS[k2], L, pt))
    rows.sort(reverse=True)
    if not quiet:
        print("\n=== keyword as INNER-LAYER KEY, outer layer derived (37.7M wordlist strings) ===")
        print(f"  keywords: {total:,} x {len(R.INNER)} tableau settings x 2 layer orders x 8 outer settings "
              f"({time.time() - t0:.0f}s)")
        print(f"  crib-consistent recipes: {len(rows)}  (about 1 expected by chance, at L=23)")
        for sc, neq, w, inner, order, outer, L, pt in rows[:8]:
            print(f"    english={sc:.2f} equalities={neq} inner={w}/{'/'.join(inner)} {order} "
                  f"outer={'/'.join(outer)} L={L}\n      {pt}")
    return rows


# --- pass 3: keyword alphabet x English-dictionary alphabet -------------------------

JOIN_PERIODS = [(L, p) for L, p in PERIODS if len(p) >= 8]


def _add(table, key, idx):
    old = table.get(key)
    if old is None:
        table[key] = idx
    elif isinstance(old, int):
        table[key] = (old, idx)
    elif len(old) < 12:
        table[key] = old + (idx,)


def build_join_maps(words):
    R._CT = _CT
    R.build_alphabets(words)
    _JOIN_C.clear()
    _JOIN_P.clear()
    for L, pairs in JOIN_PERIODS:
        pp = [(PA[a], PA[b]) for a, b in pairs]
        cc = [(ord(_CT[CRIB_IDX[a]]) - 65, ord(_CT[CRIB_IDX[b]]) - 65) for a, b in pairs]
        tc, tp = {}, {}
        for idx, r in enumerate(R._ALPHA_RANK):
            _add(tc, bytes((r[x] - r[y]) % 26 for x, y in cc), idx)
            _add(tp, bytes((r[x] - r[y]) % 26 for x, y in pp), idx)
        _JOIN_C[L], _JOIN_P[L] = (cc, tc), (pp, tp)
    return len(R._ALPHA_RANK)


def _pair_task(args):
    path, a, b = args
    out, count = [], 0
    for w in _read(path, a, b):
        count += 1
        for style, x in (("keyed", keyed_alphabet(w)), ("transposed", transposed_alphabet(w))):
            r = _ranks(x)
            for L, _ in JOIN_PERIODS:
                pp, tp = _JOIN_P[L]
                cc, tc = _JOIN_C[L]
                m = tc.get(bytes((r[i] - r[j]) % 26 for i, j in pp))    # keyword = plain alphabet
                if m is not None:
                    out.append((L, w, style, "plain", m))
                m = tp.get(bytes((r[i] - r[j]) % 26 for i, j in cc))    # keyword = cipher alphabet
                if m is not None:
                    out.append((L, w, style, "cipher", m))
    return count, out


def run_pairs(path=None, words=None, quiet=False):
    path = path or wordlists.build()
    t0 = time.time()
    n_dict = build_join_maps(words if words is not None else R.load_words())
    t1 = time.time()
    total, hits = 0, []
    with _CTX.Pool(PROCS) as pool:
        for n, h in pool.imap_unordered(_pair_task, _ranges(path, 600)):
            total += n
            hits += h
    neq_of = {L: len(p) for L, p in JOIN_PERIODS}
    rows, per_L = [], defaultdict(int)
    for L, w, style, side, m in hits:
        x = keyed_alphabet(w) if style == "keyed" else transposed_alphabet(w)
        for idx in ((m,) if isinstance(m, int) else m):
            other = R._ALPHA_LIST[idx]
            pa, ca = (x, other) if side == "plain" else (other, x)
            pt = _decrypt_periodic(pa, ca, "vig", L, _CT)
            per_L[L] += 1
            rows.append((R.english(pt), L, neq_of[L], f"{w} ({style})", R._ALPHA_NAME[idx], side, pt))
    rows.sort(reverse=True)
    if not quiet:
        print("\n=== keyword alphabet x English-dictionary alphabet (Quagmire IV, two keywords) ===")
        print(f"  {total:,} wordlist strings x 2 styles against {n_dict:,} dictionary alphabets, "
              f"both ways round (maps {t1 - t0:.0f}s, search {time.time() - t1:.0f}s)")
        print("  consistent pairs by period (chance expectation in brackets):")
        print("   ", "  ".join(f"L={L}: {per_L[L]} ({4 * total * n_dict * 26.0 ** -neq_of[L]:.2g})"
                               for L, _ in JOIN_PERIODS))
        print("  most English-looking decryptions (real English ~ -4.3):")
        for sc, L, neq, kw, other, side, pt in rows[:8]:
            print(f"    english={sc:.2f} L={L} equalities={neq} wordlist {kw} as {side} alphabet, "
                  f"dictionary {other}\n      {pt}")
        if not rows:
            print("    none")
    return rows


# --- pass 4: running key from a known text, with a keyword-mixed alphabet -------------

_GRAMS: dict = {}
_TEXTS: dict = {}


def build_grams(sources):
    """Index every 13-letter window of every source text, forwards and backwards."""
    _GRAMS.clear()
    _TEXTS.clear()
    for name, t in sources.items():
        for direction, text in (("forwards", t), ("backwards", t[::-1])):
            _TEXTS[(name, direction)] = text
            for pos in range(len(text) - 12):
                _GRAMS.setdefault(text[pos:pos + 13], []).append((name, direction, pos))


def _text_task(args):
    path, a, b = args
    ca_ = [ord(_CT[i]) - 65 for i in CRIB_IDX]
    pk_, ck_ = [_RK[p] for p in PA], [_RK[c] for c in ca_]
    out, count = [], 0
    for w in _read(path, a, b):
        count += 1
        for style, x in (("keyed", keyed_alphabet(w)), ("transposed", transposed_alphabet(w))):
            r = _ranks(x)
            px, cx = [r[p] for p in PA], [r[c] for c in ca_]
            for role, p, c in (("plain=kw cipher=A-Z", px, ca_), ("plain=A-Z cipher=kw", PA, cx),
                               ("both=kw", px, cx), ("plain=kw cipher=KRYPTOS", px, ck_),
                               ("plain=KRYPTOS cipher=kw", pk_, cx)):
                for mode, s in (("vig", [(y - z) % 26 for z, y in zip(p, c)]),
                                ("beau", [(y + z) % 26 for z, y in zip(p, c)]),
                                ("var", [(z - y) % 26 for z, y in zip(p, c)])):
                    for spell, alpha in (("A-Z", ALPHABET), ("KRYPTOS", KRYPTOS_KEYED), ("kw", x)):
                        frag = "".join([alpha[v] for v in s[:13]])
                        if frag in _GRAMS:
                            out.append((w, style, role, mode, spell, frag,
                                        "".join([alpha[v] for v in s[13:]])))
    return count, out


def run_texts(path=None, sources=None, quiet=False):
    import texts
    path = path or wordlists.build()
    build_grams(sources if sources is not None else texts.ALL_TEXTS)
    t0 = time.time()
    total, hits = 0, []
    with _CTX.Pool(PROCS) as pool:
        for n, h in pool.imap_unordered(_text_task, _ranges(path)):
            total += n
            hits += h
    rows = []
    for w, style, role, mode, spell, frag, frag2 in hits:
        for name, direction, pos in _GRAMS[frag]:
            text = _TEXTS[(name, direction)]
            both = text[pos + 42:pos + 53] == frag2
            rows.append((both, w, style, role, mode, spell, name, direction, pos - 21, frag, frag2))
    rows.sort(reverse=True)
    if not quiet:
        print("\n=== running key from a known text, with a wordlist-keyword alphabet ===")
        print(f"  texts indexed: {len(_TEXTS) // 2} ({len(_GRAMS):,} distinct 13-letter windows)")
        print(f"  keywords: {total:,} x 2 styles x 5 alphabet roles x 3 arithmetics x 3 key spellings "
              f"({time.time() - t0:.0f}s)")
        print(f"  key fragments found in a text: {len(rows)}  (chance: essentially zero)")
        for both, w, style, role, mode, spell, name, direction, start, frag, frag2 in rows[:10]:
            print(f"    {w} ({style}) {role} {mode}, key spelled in {spell}: {frag}|{frag2} = "
                  f"{name} read {direction} from offset {start}; second clue also matches: {both}")
    return rows


# --- pass 5: tolerate an error on the sculpture ---------------------------------------
#
# Sanborn's ciphertext has known slips: a wrong letter in K1 and K2, and a dropped
# letter in K2. If K4 has one inside or between the clue positions, every exact
# test rejects the true method. Two tolerant versions of the repeating-key test:
#   wrong letter : consistent once any ONE crib letter is ignored
#   dropped/extra letter between the clues : the second clue's key position is
#                  offset by `delta` relative to the first

def _groups(slots, L):
    by = defaultdict(list)
    for j, x in enumerate(slots):
        by[x % L].append(j)
    return [g for g in by.values() if len(g) > 1]


def _mismatches(s, groups, limit):
    """Fewest crib letters to ignore so every slot group agrees (stops past limit)."""
    bad = 0
    for g in groups:
        a = s[g[0]]
        for j in g:
            if s[j] != a:
                vals = [s[k] for k in g]
                bad += len(vals) - max(map(vals.count, vals))
                break
        if bad > limit:
            return bad
    return bad


def _delta_slots(delta):
    return [i + (delta if i >= 63 else 0) for i in CRIB_IDX]


def _neq(groups):
    return sum(len(g) - 1 for g in groups)


TOL_WRONG = [(L, _neq(g), g) for L in range(1, 24) for g in [_groups(CRIB_IDX, L)] if _neq(g) >= 10]
TOL_DELTA = [(d, L, R._slot_pairs(_delta_slots(d), L)) for d in (-3, -2, -1, 1, 2, 3) for L in range(1, 24)]
TOL_DELTA = [(d, L, p) for d, L, p in TOL_DELTA if len(p) >= 9]


def tolerant_builtin(ct=None, quiet=False):
    """Error-tolerant repeating-key test with the A-Z / KRYPTOS alphabets."""
    ct = ct or _CT
    S = R._forced(ct)
    found = []
    for k, s in enumerate(S):
        for L in range(1, 24):
            g = _groups(CRIB_IDX, L)
            bad = _mismatches(s, g, 2)
            if 0 < bad <= 2 and _neq(g) - bad >= 8:
                found.append((_neq(g) - bad, f"L={L}, {bad} wrong crib letter(s)", k))
            for delta in range(1, L):
                g = _groups(_delta_slots(delta), L)
                bad = _mismatches(s, g, 1)
                if bad <= 1 and _neq(g) - bad >= 8:
                    found.append((_neq(g) - bad, f"L={L}, second clue's key offset by {delta} (mod {L})"
                                  + (", 1 wrong crib letter" if bad else ""), k))
    found.sort(reverse=True)
    if not quiet:
        print("\n=== error-tolerant repeating-key test, A-Z / KRYPTOS alphabets ===")
        print("  allowing up to 2 wrong crib letters, or any dropped/extra letters between the clues")
        for neq, desc, k in found[:8]:
            print(f"    equalities left={neq}  {desc}  {'/'.join(R.COMBOS[k])}")
        if not found:
            print("  nothing consistent")
    return found


def _tolerant_task(args):
    path, a, b = args
    ca_ = [ord(_CT[i]) - 65 for i in CRIB_IDX]
    pk_, ck_ = [_RK[p] for p in PA], [_RK[c] for c in ca_]
    out, count = [], 0
    for w in _read(path, a, b):
        count += 1
        for style, x in (("keyed", keyed_alphabet(w)), ("transposed", transposed_alphabet(w))):
            r = _ranks(x)
            px, cx = [r[p] for p in PA], [r[c] for c in ca_]
            for role, p, c in (("plain=kw cipher=A-Z", px, ca_), ("plain=A-Z cipher=kw", PA, cx),
                               ("both=kw", px, cx), ("plain=kw cipher=KRYPTOS", px, ck_),
                               ("plain=KRYPTOS cipher=kw", pk_, cx)):
                for mode in ("vig", "beau"):
                    s = ([(y - z) % 26 for z, y in zip(p, c)] if mode == "vig"
                         else [(y + z) % 26 for z, y in zip(p, c)])
                    for L, neq, groups in TOL_WRONG:
                        if _mismatches(s, groups, 1) <= 1:
                            out.append((neq - 1, f"L={L}, 1 wrong crib letter", w, style, role, mode))
                    for delta, L, pairs in TOL_DELTA:
                        for i, j in pairs:
                            if s[i] != s[j]:
                                break
                        else:
                            out.append((len(pairs), f"L={L}, second clue's key offset by {delta:+d}",
                                        w, style, role, mode))
    return count, out


def run_tolerant(path=None, quiet=False):
    path = path or wordlists.build()
    builtin = tolerant_builtin(quiet=quiet)
    t0 = time.time()
    total, hits = 0, []
    with _CTX.Pool(PROCS) as pool:
        for n, h in pool.imap_unordered(_tolerant_task, _ranges(path)):
            total += n
            hits += h
    hits.sort(reverse=True)
    if not quiet:
        print("\n=== error-tolerant repeating-key test, wordlist-keyword alphabets ===")
        print(f"  keywords: {total:,} x 2 styles x 5 roles x 2 arithmetics; one wrong crib letter, "
              f"or the second clue offset by 1-3 positions ({time.time() - t0:.0f}s)")
        print(f"  consistent: {len(hits)}")
        for neq, desc, w, style, role, mode in hits[:10]:
            print(f"    equalities={neq}  {desc}  {w} ({style}) {role} {mode}")
    return builtin, hits


# --- pass 6: autokey with a keyword-mixed alphabet -------------------------------------
#
# Scheidt (2003 notes): "How do you deliver a message in such a way that it conveys
# not only the encrypted data, but also the key?"  The classical answer is autokey:
# the key is the message itself, shifted by a lag. With the A-Z and KRYPTOS
# alphabets this is excluded for every seed (frontier.py). Here the alphabet comes
# from a wordlist keyword.

_PA_LAGS = []          # plaintext-autokey lags with >= 10 usable crib pairs


def _autokey_tables():
    pos = {i: j for j, i in enumerate(CRIB_IDX)}
    _PA_LAGS.clear()
    for lag in range(1, 60):
        pairs = [(j, pos[i - lag]) for j, i in enumerate(CRIB_IDX) if (i - lag) in pos]
        if len(pairs) >= 10:
            _PA_LAGS.append((lag, pairs))


def _autokey_task(args):
    path, a, b = args
    ca_ = [ord(_CT[i]) - 65 for i in CRIB_IDX]
    pk_, ck_ = [_RK[p] for p in PA], [_RK[c] for c in ca_]
    cti = [ord(c) - 65 for c in _CT]
    # ciphertext letters `lag` places before each crib (None once any falls off the start)
    back = []
    for lag in range(1, 64):
        js = [j for j, i in enumerate(CRIB_IDX) if i - lag >= 0]
        if len(js) >= 11:
            back.append((lag, js, [cti[CRIB_IDX[j] - lag] for j in js]))
    std = list(range(26))
    out, count = [], 0
    for w in _read(path, a, b):
        count += 1
        for style, x in (("keyed", keyed_alphabet(w)), ("transposed", transposed_alphabet(w))):
            r = _ranks(x)
            px, cx = [r[p] for p in PA], [r[c] for c in ca_]
            for role, p, c in (("plain=kw cipher=A-Z", px, ca_), ("plain=A-Z cipher=kw", PA, cx),
                               ("both=kw", px, cx), ("plain=kw cipher=KRYPTOS", px, ck_),
                               ("plain=KRYPTOS cipher=kw", pk_, cx)):
                for mode in ("vig", "beau"):
                    s = ([(y - z) % 26 for z, y in zip(p, c)] if mode == "vig"
                         else [(y + z) % 26 for z, y in zip(p, c)])
                    for kname, kr in (("kw", r), ("A-Z", std), ("KRYPTOS", _RK)):
                        for lag, js, letters in back:                    # ciphertext feedback
                            d = (s[js[0]] - kr[letters[0]]) % 26
                            for j, ch in zip(js, letters):
                                if (s[j] - kr[ch]) % 26 != d:
                                    break
                            else:
                                out.append(("ciphertext", lag, d, w, style, role, mode, kname, len(js)))
                        for lag, pairs in _PA_LAGS:                      # plaintext feedback
                            j0, k0 = pairs[0]
                            d = (s[j0] - kr[PA[k0]]) % 26
                            for j, k in pairs:
                                if (s[j] - kr[PA[k]]) % 26 != d:
                                    break
                            else:
                                out.append(("plaintext", lag, d, w, style, role, mode, kname, len(pairs)))
    return count, out


def _autokey_decrypt(lag, d, word, style, role, mode, kname):
    """Full decryption for a ciphertext-feedback hit (the key is known everywhere)."""
    pa, ca = _role_alphabets(word, style, role)
    x = keyed_alphabet(word) if style == "keyed" else transposed_alphabet(word)
    kalpha = {"kw": x, "A-Z": ALPHABET, "KRYPTOS": KRYPTOS_KEYED}[kname]
    cr = {ch: i for i, ch in enumerate(ca)}
    out = []
    for i, c in enumerate(_CT):
        if i < lag:
            out.append(".")
            continue
        sh = (kalpha.index(_CT[i - lag]) + d) % 26
        out.append(pa[((cr[c] - sh) if mode == "vig" else (sh - cr[c])) % 26])
    return "".join(out)


def run_autokey(path=None, quiet=False):
    path = path or wordlists.build()
    _autokey_tables()
    t0 = time.time()
    total, hits = 0, []
    with _CTX.Pool(PROCS) as pool:
        for n, h in pool.imap_unordered(_autokey_task, _ranges(path, 600)):
            total += n
            hits += h
    rows = []
    for fb, lag, d, w, style, role, mode, kname, n in hits:
        pt = _autokey_decrypt(lag, d, w, style, role, mode, kname) if fb == "ciphertext" else ""
        rows.append((R.english(pt) if pt else -99.0, fb, lag, w, style, role, mode, kname, n, pt))
    rows.sort(reverse=True)
    if not quiet:
        print("\n=== autokey with a wordlist-keyword alphabet (the message supplies its own key) ===")
        print(f"  keywords: {total:,} x 2 styles x 5 roles x 2 arithmetics x 3 key alphabets; "
              f"ciphertext feedback lags 1-63, plaintext feedback lags "
              f"{', '.join(str(l) for l, _ in _PA_LAGS)} ({time.time() - t0:.0f}s)")
        print(f"  crib-consistent: {len(rows)}")
        for sc, fb, lag, w, style, role, mode, kname, n, pt in rows[:8]:
            print(f"    {fb} feedback lag {lag}: {w} ({style}) {role} {mode}, key ranked in {kname}; "
                  f"{n} clue letters agree" + (f"; english={sc:.2f}\n      {pt}" if pt else ""))
    return rows


# --- controls -------------------------------------------------------------------------

def control():
    global _CT
    saved = _CT
    rng = random.Random(4)
    pt = list(("ITISBURIEDOUTTHERESOMEWHEREWHOKNOWSTHEEXACTLOCATION" * 2)[:N])
    for i, ch in CRIB:
        pt[i] = ch
    pt = "".join(pt)
    secret = "TRUSTNOONEXFILES"            # a password-style string, not a dictionary word
    with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False) as fh:
        fh.write("\n".join(sorted(["PASSWORD", "QWERTYUIOP", "LETMEIN", "DRAGON", secret, "ZZTOP"])) + "\n")
        path = fh.name
    ok = True
    try:
        x = keyed_alphabet(secret)
        key = [3, 17, 8, 22, 5, 11, 19]
        _CT = "".join(KRYPTOS_KEYED[(x.index(p) + key[i % 7]) % 26] for i, p in enumerate(pt))
        rows, _, _ = run_alphabets(path, quiet=True)
        good = any(r[3] == secret and r[2] == 7 and r[5] == "plain=kw cipher=KRYPTOS" and r[7] == pt for r in rows)
        ok &= good
        print(f"[control alphabets] wordlist keyword as Quagmire alphabet recovered: {good}")

        rnd = list(ALPHABET)
        rng.shuffle(rnd)
        gkey = expand((2, 6, 7, 1, 7), 10)
        _CT = "".join(rnd[(x.index(p) + k) % 26] for p, k in zip(pt, gkey))
        _, _, grows = run_alphabets(path, quiet=True)
        good = any(r[1] == secret and r[5] == (2, 6, 7, 1, 7)
                   and all(a == b for a, b in zip(r[7], pt) if a != ".") for r in grows)
        ok &= good
        print(f"[control alphabets] wordlist keyword as Gromark alphabet recovered: {good}")

        si = R.INNER.index(("K", "vig", "K"))
        kr = R._key_ranks(secret, "K")
        mid = "".join(chr(65 + R._INNER_T[si][ord(p) - 65][kr[i % len(secret)]]) for i, p in enumerate(pt))
        _CT = "".join(chr((ord(m) + ord("SHADOW"[i % 6]) - 130) % 26 + 65) for i, m in enumerate(mid))
        rows = run_layers(path, quiet=True)
        good = any(r[2] == secret and r[6] == 6 and r[7] == pt for r in rows)
        ok &= good
        print(f"[control layers] wordlist keyword as inner-layer key recovered: {good}")

        # tolerant: same Quagmire, but one crib letter carved wrong, then one letter dropped
        good_ct = "".join(KRYPTOS_KEYED[(x.index(p) + key[i % 7]) % 26] for i, p in enumerate(pt))
        _CT = good_ct[:27] + ("Q" if good_ct[27] != "Q" else "Z") + good_ct[28:]
        _, hits = run_tolerant(path, quiet=True)
        good = any(h[2] == secret and h[1] == "L=7, 1 wrong crib letter" for h in hits)
        ok &= good
        print(f"[control tolerant] solution with one wrong crib letter recovered: {good}")
        shifted = "".join(KRYPTOS_KEYED[(x.index(p) + key[(i + (1 if i >= 45 else 0)) % 7]) % 26]
                          for i, p in enumerate(pt))
        _CT = shifted
        _, hits = run_tolerant(path, quiet=True)
        good = any(h[2] == secret and h[1] == "L=7, second clue's key offset by +1" for h in hits)
        ok &= good
        print(f"[control tolerant] solution with a dropped letter between the clues recovered: {good}")

        # autokey: ciphertext feedback with lag 7 through the wordlist-keyed alphabet
        c = []
        for i, p in enumerate(pt):
            k = x.index(c[i - 7]) if i >= 7 else key[i]
            c.append(x[(x.index(p) + k + 3) % 26])
        _CT = "".join(c)
        rows = run_autokey(path, quiet=True)
        good = any(r[1] == "ciphertext" and r[2] == 7 and r[3] == secret and r[5] == "both=kw"
                   and r[9][7:] == pt[7:] for r in rows)
        ok &= good
        print(f"[control autokey] ciphertext-autokey with a wordlist alphabet recovered: {good}")

        import texts
        rk_text = texts.SANBORN_TEXTS["tradecraft paragraph"][100:197]
        _CT = "".join(x[(x.index(p) + x.index(k)) % 26] for p, k in zip(pt, rk_text))
        rows = run_texts(path, quiet=True)
        good = any(r[0] and r[1] == secret and r[3] == "both=kw" and r[6] == "tradecraft paragraph"
                   and r[7] == "forwards" and r[8] == 100 for r in rows)
        ok &= good
        print(f"[control texts] running key from a source text with a wordlist alphabet recovered: {good}")

        ca = transposed_alphabet("PALIMPSEST")
        _CT = "".join(ca[(x.index(p) + key[i % 7]) % 26] for i, p in enumerate(pt))
        rows = run_pairs(path, words=["KRYPTOS", "PALIMPSEST", "ABSCISSA", "BERLIN"], quiet=True)
        good = any(r[1] == 7 and secret in r[3] and r[4] == "PALIMPSEST transposed" and r[6] == pt for r in rows)
        ok &= good
        print(f"[control pairs] wordlist alphabet x dictionary alphabet recovered: {good}")
    finally:
        _CT = saved
        R._CT = saved
        os.unlink(path)
    return ok


if __name__ == "__main__":
    what = sys.argv[1] if len(sys.argv) > 1 else "all"
    if what in ("control", "all"):
        assert control(), "positive control failed"
    if what in ("alphabets", "all"):
        run_alphabets()
    if what in ("layers", "all"):
        run_layers()
    if what in ("pairs", "all"):
        run_pairs()
    if what in ("texts", "all"):
        run_texts()
    if what in ("tolerant", "all"):
        run_tolerant()
    if what in ("autokey", "all"):
        run_autokey()
