"""
Masks: ways the text could be split or re-ordered before an ordinary tableau step.

Scheidt: "I masked the English language… you need to solve the technique first
and then go for the puzzle." Earlier modules test one key running through the
whole message. Here the message is first PARTITIONED into streams, and each
stream gets its own repeating key and its own alphabet setting:

  interleaved   every m-th letter forms a stream (m = 2..8)
  rows          each line of K4 on the sculpture is a stream
  regions       each clue sits in its own separately keyed region
  by letter     streams chosen by the kind of letter (vowel/consonant, a letter
                of KRYPTOS or not, first/second half of the alphabet), taken
                from the plaintext or from the ciphertext

A stream passes if its clue letters are consistent with SOME repeating key; with
c forced equalities a chance pass has probability 26**-c. Streams are judged
separately, so one clean stream would show up even if the other is something else.

Also here: route masks (spiral and diagonal reading of a grid), tested like the
other transpositions with any tableau key.

Run:  python masks.py [control|streams|routes|mirrors|all]
"""
from __future__ import annotations

import math
import sys
import time
from collections import defaultdict

from kryptos import CIPHERTEXT
from frontier import CRIB, CRIB_IDX, N, COMBOS, _slot_pairs, _map_from_seq, _test_both, report
from sculpture import K4_CELLS
import recipes as R

KRY = set("KRYPTOS")
VOWELS = set("AEIOU")
FLAG = 6            # equalities needed to report a stream on its own


def partitions(ct=CIPHERTEXT):
    """Yield (name, [(class, index) per crib]). Index is the stream's own counter."""
    for m in range(2, 9):
        yield f"every {m}th letter, stream counter", [(i % m, i // m) for i in CRIB_IDX]
        yield f"every {m}th letter, global counter", [(i % m, i) for i in CRIB_IDX]
    yield "sculpture rows, counter = column", [K4_CELLS[i] for i in CRIB_IDX]
    for m in (2, 3, 4):
        yield f"sculpture column mod {m}", [(K4_CELLS[i][1] % m, i) for i in CRIB_IDX]
        yield f"sculpture row+column mod {m}", [(sum(K4_CELLS[i]) % m, i) for i in CRIB_IDX]
    yield "each clue in its own region", [(0 if i < 48 else 1, i) for i in CRIB_IDX]
    kinds = {"vowel / consonant": lambda ch: ch in VOWELS,
             "letter of KRYPTOS / other": lambda ch: ch in KRY,
             "A-M / N-Z": lambda ch: ch <= "M",
             "reads the same in a mirror (AHIMOTUVWXY) / other": lambda ch: ch in "AHIMOTUVWXY"}
    for name, f in kinds.items():
        yield f"plaintext {name}, global counter", [(f(P), i) for i, P in CRIB]
        yield f"ciphertext {name}, global counter", [(f(ct[i]), i) for i in CRIB_IDX]
        # the decipherer can count ciphertext letters of each kind as they go
        count, seen = [], defaultdict(int)
        for ch in ct:
            k = f(ch)
            count.append((k, seen[k]))
            seen[k] += 1
        yield f"ciphertext {name}, stream counter", [count[i] for i in CRIB_IDX]


MORSE_CODE = {"A": ".-", "B": "-...", "C": "-.-.", "D": "-..", "E": ".", "F": "..-.", "G": "--.", "H": "....",
              "I": "..", "J": ".---", "K": "-.-", "L": ".-..", "M": "--", "N": "-.", "O": "---", "P": ".--.",
              "Q": "--.-", "R": ".-.", "S": "...", "T": "-", "U": "..-", "V": "...-", "W": ".--", "X": "-..-",
              "Y": "-.--", "Z": "--.."}


def morse_partitions():
    """The entrance Morse as a switch: its dots and dashes, read from any point forwards or
    backwards, decide which of two keys / alphabets each K4 letter uses ("two systems")."""
    from sculpture import MORSE_VARIANTS
    seen = set()
    for vname, text in MORSE_VARIANTS.items():
        bits = "".join(MORSE_CODE[ch] for ch in text)
        for direction, b in (("forwards", bits), ("backwards", bits[::-1])):
            for start in range(len(b)):
                sel = [b[(start + i) % len(b)] for i in range(N)]
                key = "".join(sel)
                if key in seen:
                    continue
                seen.add(key)
                count, n = [], {".": 0, "-": 0}
                for x in sel:
                    count.append((x, n[x]))
                    n[x] += 1
                yield f"Morse dots/dashes ({vname}) {direction} from {start}, global counter", \
                    [(sel[i], i) for i in CRIB_IDX]
                yield f"Morse dots/dashes ({vname}) {direction} from {start}, stream counter", \
                    [count[i] for i in CRIB_IDX]


def run_morse_streams(ct=None, quiet=False):
    ct = ct or CIPHERTEXT
    S = R._forced(ct)
    found, n = [], 0
    for name, assign in morse_partitions():
        n += 1
        classes = defaultdict(list)
        for j, (c, idx) in enumerate(assign):
            classes[c].append((j, idx))
        best = {c: max(stream_passes(S, [j for j, _ in items], [x for _, x in items]), default=None)
                for c, items in classes.items()}
        for c, b in best.items():
            if b and b[0] >= FLAG:
                found.append((b[0], name, f"stream {c} alone: L={b[1]} {'/'.join(COMBOS[b[2]])}"))
        if len(best) == 2 and all(best.values()) and sum(b[0] for b in best.values()) >= 10:
            found.append((sum(b[0] for b in best.values()), name,
                          "; ".join(f"{c}: L={b[1]} {'/'.join(COMBOS[b[2]])} ({b[0]} eq)" for c, b in best.items())))
    found.sort(reverse=True)
    if not quiet:
        print("\n=== Morse dots and dashes as a switch between two keyed streams ===")
        print(f"  switch patterns tested: {n:,}")
        for eq, name, note in found[:8]:
            print(f"    {eq} equalities  [{name}]  {note}")
        if not found:
            print(f"  no pattern gives a stream with {FLAG}+ equalities, or 10+ across both streams")
    return found


def stream_passes(S, members, counters, max_L=23):
    """Passes for one stream: [(equalities, L, combo)] with at least 3 equalities."""
    out = []
    for L in range(1, max_L + 1):
        pairs = _slot_pairs(counters, L)
        if len(pairs) < 3:
            continue
        for k, s in enumerate(S):
            if all(s[members[a]] == s[members[b]] for a, b in pairs):
                out.append((len(pairs), L, k))
    return out


def run_streams(ct=None, quiet=False):
    ct = ct or CIPHERTEXT
    S = R._forced(ct)
    found, tests = [], 0
    for name, assign in partitions(ct):
        classes = defaultdict(list)
        for j, (c, idx) in enumerate(assign):
            classes[c].append((j, idx))
        best = {}
        for c, items in classes.items():
            members = [j for j, _ in items]
            counters = [idx for _, idx in items]
            passes = stream_passes(S, members, counters)
            tests += 23 * 8
            best[c] = max(passes, default=None)
            for neq, L, k in passes:
                if neq >= FLAG:
                    found.append((neq, name, c, len(members), L, k, "single stream"))
        # every stream consistent at once, each with at least 3 equalities
        if len(best) > 1 and all(b is not None for b in best.values()):
            total = sum(b[0] for b in best.values())
            if total >= FLAG + 2:
                desc = "; ".join(f"stream {c}: L={b[1]} {'/'.join(COMBOS[b[2]])} ({b[0]} eq)"
                                 for c, b in sorted(best.items(), key=lambda kv: str(kv[0])))
                found.append((total, name, "all", len(assign), 0, -1, desc))
    found.sort(key=lambda r: -r[0])
    if not quiet:
        print("\n=== streams: the message split into separately keyed parts ===")
        print(f"  partitions: {len(list(partitions(ct)))}; stream/key-length/alphabet settings: {tests:,}")
        for neq, name, c, size, L, k, note in found[:12]:
            if c == "all":
                print(f"    {neq} equalities in total  [{name}]  {note}")
            else:
                print(f"    {neq} equalities  [{name}] stream {c} ({size} clue letters), "
                      f"key length {L}, {'/'.join(COMBOS[k])}")
        if not found:
            print(f"  no stream is consistent with a repeating key at {FLAG}+ equalities")
    return found


# --- route masks -------------------------------------------------------------------

def _spiral(rows, cols):
    top, bottom, left, right = 0, rows - 1, 0, cols - 1
    out = []
    while top <= bottom and left <= right:
        out += [(top, c) for c in range(left, right + 1)]
        out += [(r, right) for r in range(top + 1, bottom + 1)]
        if top < bottom:
            out += [(bottom, c) for c in range(right - 1, left - 1, -1)]
        if left < right:
            out += [(r, left) for r in range(bottom - 1, top, -1)]
        top, bottom, left, right = top + 1, bottom - 1, left + 1, right - 1
    return out


def route_families():
    for w in range(2, 49):
        rows = -(-N // w)
        cells = {}
        base = {"spiral": _spiral(rows, w),
                "spiral (down first)": [(r, c) for c, r in _spiral(w, rows)],
                "diagonal": sorted(((r, c) for r in range(rows) for c in range(w)),
                                   key=lambda rc: (rc[0] + rc[1], rc[0])),
                "diagonal (zigzag)": sorted(((r, c) for r in range(rows) for c in range(w)),
                                            key=lambda rc: (rc[0] + rc[1],
                                                            rc[0] if (rc[0] + rc[1]) % 2 else -rc[0])),
                "anti-diagonal": sorted(((r, c) for r in range(rows) for c in range(w)),
                                        key=lambda rc: (rc[0] - rc[1], rc[0]))}
        for name, path in base.items():
            for flip_r in (False, True):
                for flip_c in (False, True):
                    seq = []
                    for r, c in path:
                        rr = rows - 1 - r if flip_r else r
                        cc = w - 1 - c if flip_c else c
                        idx = rr * w + cc
                        if idx < N:
                            seq.append(idx)
                    key = tuple(seq)
                    if len(seq) == N and key not in cells:
                        cells[key] = True
                        yield (f"{name} w={w}" + (" flipped rows" if flip_r else "")
                               + (" flipped columns" if flip_c else "")), _map_from_seq(seq)
                        yield (f"{name} w={w} reversed" + (" flipped rows" if flip_r else "")
                               + (" flipped columns" if flip_c else "")), _map_from_seq(seq[::-1])


def mirror_families():
    """K4 seen from behind, in a mirror, or as a shadow: the grid of letters flipped
    left-right, top-bottom, or both, then read by rows or by columns. Grid widths
    2-48 with the text starting at any column (31 wide starting at column 27 is how
    K4 sits on the copper and on Sanborn's 14 x 31 worksheet for K3 + K4)."""
    seen = set()
    for w in range(2, 49):
        for o in range(w):
            cells = [((i + o) // w, (i + o) % w) for i in range(N)]
            for fr in (1, -1):
                for fc in (1, -1):
                    for major in ("rows", "columns"):
                        key = (lambda i: (fr * cells[i][0], fc * cells[i][1])) if major == "rows" else \
                              (lambda i: (fc * cells[i][1], fr * cells[i][0]))
                        seq = tuple(sorted(range(N), key=key))
                        if seq in seen:
                            continue
                        seen.add(seq)
                        yield (f"mirror w={w} start col {o}" + (" flipped top-bottom" if fr < 0 else "")
                               + (" flipped left-right" if fc < 0 else "") + f" read by {major}"), _map_from_seq(seq)


def run_mirrors():
    t0 = time.time()
    hits, n = [], 0
    for label, m in mirror_families():
        _test_both(label, m, hits)
        n += 2
    return report("mirror / shadow readings: grid flipped left-right or top-bottom, widths 2-48, any start column",
                  n, hits, t0)


def stepped_families():
    """NSA's description of K3 (declassified 2014 summary): plaintext written in a few long
    rows (4 x 86 for K3), columns taken bottom-to-top, every 7th column moving left. The
    same recipe for K4 with any number of rows, any column step, start and direction."""
    seen = set()
    for rows in range(2, 33):
        w = -(-N // rows)
        for step in range(1, w):
            if math.gcd(step, w) != 1:
                continue
            for start in range(w):
                for sgn in (1, -1):
                    for up in (True, False):
                        seq = []
                        for k in range(w):
                            c = (start + sgn * step * k) % w
                            col = [r * w + c for r in range(rows) if r * w + c < N]
                            seq += col[::-1] if up else col
                        key = tuple(seq)
                        if key in seen:
                            continue
                        seen.add(key)
                        yield (f"stepped columns rows={rows} width={w} step={sgn * step} start={start} "
                               f"{'up' if up else 'down'}"), _map_from_seq(seq)


def run_stepped():
    t0 = time.time()
    hits, n = [], 0
    for label, m in stepped_families():
        _test_both(label, m, hits)
        n += 2
    return report("K3 recipe as NSA describes it: long rows, columns taken at a fixed step", n, hits, t0)


def run_routes():
    t0 = time.time()
    hits, n = [], 0
    for label, m in route_families():
        _test_both(label, m, hits)
        n += 2
    return report("route masks: spiral and diagonal reading of a grid, widths 2-48", n, hits, t0)


# --- control ------------------------------------------------------------------------

def control():
    pt = list(("ITISBURIEDOUTTHERESOMEWHEREWHOKNOWSTHEEXACTLOCATION" * 2)[:N])
    for i, ch in CRIB:
        pt[i] = ch
    # odd letters: Vigenere with SHADOW; even letters: KRYPTOS tableau with LUCID
    from kryptos import KRYPTOS_KEYED as K
    out = []
    for i, p in enumerate(pt):
        q = i // 2
        if i % 2:
            out.append(chr((ord(p) + ord("SHADOW"[q % 6]) - 130) % 26 + 65))
        else:
            out.append(K[(K.index(p) + K.index("LUCID"[q % 5])) % 26])
    found = run_streams("".join(out), quiet=True)
    ok = any(r[1] == "every 2th letter, stream counter" and r[2] == "all"
             and "stream 0: L=5 K/K/vig" in r[6] and "stream 1: L=6 A/A/vig" in r[6] for r in found)
    print(f"[control] two interleaved streams with different keys and alphabets recovered: {ok}")
    return ok


if __name__ == "__main__":
    what = sys.argv[1] if len(sys.argv) > 1 else "all"
    if what in ("control", "all"):
        assert control(), "positive control failed"
    if what in ("streams", "all"):
        run_streams()
    if what in ("routes", "all"):
        run_routes()
    if what in ("mirrors", "all"):
        run_mirrors()
    if what in ("stepped", "all"):
        run_stepped()
    if what in ("morse", "all"):
        run_morse_streams()
