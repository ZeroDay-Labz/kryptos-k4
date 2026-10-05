"""
Compass ciphers: ways a compass rose could key K4.

Sanborn's notebook lists "Compass cipher" next to "Beaufort cipher"; a compass rose is
set in the ground at the entrance, and EASTNORTHEAST is in the plaintext. No standard
cipher has that name, so these are the simplest readings:

  window    the key is a compass POINT at each letter (8, 16 or 32 points), i.e. a small
            number: do the 24 clue shifts fit inside 8 / 16 / 32... consecutive values?
  turning   the alphabet wheel turns by a fixed BEARING each letter (not a whole number
            of letters): shift_i = floor or round(step * i + start) mod 26, any real step
  bearing   the key is a list of bearings read as numbers (ENE = 67.5 deg = point 3 of 16
            = point 6 of 32, and the full rose in order), repeating or cumulative

Run:  python compass.py
"""
from __future__ import annotations

import math
import random

from kryptos import CIPHERTEXT
from frontier import CRIB, CRIB_IDX, COMBOS, ALPHAS, _shift, _dec, N
from quadgrams import quadgram_score


def shift_sets(ct=CIPHERTEXT):
    out = []
    for pa, ca, mode in COMBOS:
        pr = {ch: i for i, ch in enumerate(ALPHAS[pa])}
        cr = {ch: i for i, ch in enumerate(ALPHAS[ca])}
        out.append([_shift(mode, pr[P], cr[ct[i]]) for i, P in CRIB])
    return out


def window(vals):
    """Smallest run of consecutive values (mod 26) containing all of vals."""
    present = sorted(set(vals))
    gaps = [(present[(i + 1) % len(present)] - v) % 26 or 26 for i, v in enumerate(present)]
    return 26 - max(gaps) + 1


def run_window(trials=20000):
    S = shift_sets()
    print("\n=== compass points as the key: do the clue shifts fit in a small range? ===")
    rng = random.Random(5)
    null = sorted(min(window([rng.randrange(26) for _ in range(24)]) for _ in S) for _ in range(trials))
    best = min(window(s) for s in S)
    for (pa, ca, mode), s in zip(COMBOS, S):
        print(f"  {pa}/{ca}/{mode}: {len(set(s))} different shifts, all inside {window(s)} consecutive values")
    print(f"  best range {best}; random keys give {null[len(null) // 2]} (smallest in {trials:,} tries: {null[0]})")
    print("  an 8-point rose needs a range of 8, 16 points need 16")


def run_turning():
    """shift_i = f(step * i + start) mod 26 for real step; exact agreement count over the clues."""
    S = shift_sets()
    best = (0, None)
    tests = 0
    for k, s in enumerate(S):
        for fname, f in (("floor", math.floor), ("round", round)):
            for a1000 in range(1, 26000):                 # step in thousandths of a letter
                a = a1000 / 1000
                base = [a * i for i in CRIB_IDX]
                for b10 in range(10):                     # fractional start
                    v = [int(f(x + b10 / 10)) % 26 for x in base]
                    d = [(x - y) % 26 for x, y in zip(s, v)]
                    cnt = max(d.count(z) for z in set(d))  # whole-letter start is free
                    tests += 1
                    if cnt > best[0]:
                        best = (cnt, ("/".join(COMBOS[k]), fname, a, b10 / 10))
    print("\n=== alphabet wheel turning by a fixed bearing each letter (any real step) ===")
    print(f"  settings tested: {tests:,}; best agreement {best[0]}/24 {best[1]}")
    print("  (67.5 deg per letter on a 26-letter wheel is a step of 4.875; chance gives about 6-7 of 24)")
    return best


POINTS16 = "N NNE NE ENE E ESE SE SSE S SSW SW WSW W WNW NW NNW".split()


def run_bearing():
    S = shift_sets()
    keys = {}
    for npts in (8, 16, 32):
        rose = list(range(npts))
        keys[f"{npts}-point rose in order"] = rose
        keys[f"{npts}-point rose from ENE"] = rose[npts * 3 // 16:] + rose[:npts * 3 // 16]
        keys[f"{npts}-point rose anticlockwise"] = rose[::-1]
    keys["ENE as E, N, E on a 16-point rose (4, 0, 4)"] = [4, 0, 4]
    keys["EASTNORTHEAST words (4, 0, 4)"] = [4, 0, 4]
    keys["67.5 as digits"] = [6, 7, 5]
    keys["bearings of the 16 points / 22.5, doubled"] = [2 * i for i in range(16)]
    keys["degrees of ENE and WSW (67, 247)"] = [67 % 26, 247 % 26]
    letters = "".join(POINTS16)                     # the rose's own letters: N, NNE, NE, ...
    keys["rose point names as letters"] = [ord(c) - 65 for c in letters]
    best = (0, None)
    for name, key in keys.items():
        for cum in (False, True):
            stream, acc = [], 0
            for i in range(N):
                acc += key[i % len(key)]
                stream.append((acc if cum else key[i % len(key)]) % 26)
            for off in range(len(key)):
                for k, s in enumerate(S):
                    v = [stream[(i + off) % N] for i in CRIB_IDX]
                    d = [(x - y) % 26 for x, y in zip(s, v)]
                    cnt = max(d.count(z) for z in set(d))
                    if cnt > best[0]:
                        best = (cnt, (name, "cumulative" if cum else "repeating", off, "/".join(COMBOS[k])))
    print("\n=== bearings and rose points as the key ===")
    print(f"  {len(keys)} keys, repeating and cumulative, every start: best agreement {best[0]}/24 {best[1]}")
    return best


if __name__ == "__main__":
    run_window()
    run_bearing()
    run_turning()


# --- the KRYPTOS alphabet laid round the compass (thekryptosproject.com diagram) ------------
#
# In the KRYPTOS alphabet the letters S, E, N, W occur in that order, 5, 8, 4 and 9 places
# apart. Wrapped once round a compass they can sit on South, East, North and West, with the
# other letters spread evenly inside each quadrant: 18 deg apart from S to E, 11.25 deg from
# E to N (the points of a 32-point compass), 22.5 deg from N to W (a 16-point compass) and
# 10 deg from W back to S. East-northeast (67.5 deg) is then the letter G, and the needle's
# other end (about 250 deg) is Z. This is a published HYPOTHESIS about the rose, not
# something engraved on it (the stone has only N, E, S, W). A wheel with uneven spacing is
# a "visual" cipher: turning it by an angle is not a fixed number of letters.

RES = 7200                                  # angle grid: 0.05 degrees


def compass_wheel(clockwise=False):
    """{letter: bearing in degrees} for the KRYPTOS alphabet on the compass."""
    from kryptos import KRYPTOS_KEYED as K
    card = {"S": 180.0, "E": 90.0, "N": 0.0, "W": 270.0}
    order = "SENW"
    ang = {}
    for a, b in zip(order, order[1:] + order[0]):
        i, j = K.index(a), K.index(b)
        n = (j - i) % 26
        span = ((card[b] - card[a] + 180) % 360) - 180          # signed quarter turn
        for t in range(n):
            ang[K[(i + t) % 26]] = (card[a] + span * t / n) % 360
    if clockwise:
        ang = {ch: (-v) % 360 for ch, v in ang.items()}
    return ang


def even_wheel(alpha):
    return {ch: 360.0 * i / 26 for i, ch in enumerate(alpha)}


def _arc_mask(lo, hi):
    """Bitmask of grid angles in the arc lo..hi (degrees, going up, may wrap)."""
    a, b = int(round(lo / 360 * RES)) % RES, int(round(hi / 360 * RES)) % RES
    full = (1 << RES) - 1
    if a <= b:
        return ((1 << (b + 1)) - 1) & ~((1 << a) - 1)
    return full & ~(((1 << a) - 1) & ~((1 << (b + 1)) - 1))


def _cells(wheel):
    """{letter: (lo, hi)}: the arc of angles nearer to this letter than to any other."""
    items = sorted(wheel.items(), key=lambda kv: kv[1])
    out = {}
    for n, (ch, a) in enumerate(items):
        prev, nxt = items[n - 1][1], items[(n + 1) % len(items)][1]
        out[ch] = ((a - ((a - prev) % 360) / 2) % 360, (a + ((nxt - a) % 360) / 2) % 360)
    return out


def run_wheel(ct=CIPHERTEXT, quiet=False):
    """Plain letter on wheel 1, turn by the key angle, read the nearest letter on wheel 2.
    Key: one angle per slot of a repeating key (any angles), or an angle growing by a fixed
    amount each letter. Each clue pair allows an arc of key angles; a period survives if the
    arcs of the clue letters sharing a slot overlap."""
    from kryptos import ALPHABET as A, KRYPTOS_KEYED as K
    wheels = {"compass (KRYPTOS on S-E-N-W)": compass_wheel(), "compass, mirrored": compass_wheel(True),
              "even A-Z": even_wheel(A), "even KRYPTOS": even_wheel(K)}
    rows = []
    for n1, w1 in wheels.items():
        for n2, w2 in wheels.items():
            if "compass" not in n1 + n2:
                continue                                   # two even wheels = ordinary shifts, done elsewhere
            cells = _cells(w2)
            for sign, sname in ((1, "turn forward"), (-1, "mirror (key minus plain)")):
                masks = []
                for i, P in CRIB:
                    lo, hi = cells[ct[i]]
                    # forward: angle2 = angle1 + key ; mirror: angle2 = key - angle1
                    masks.append(_arc_mask(lo - sign * w1[P], hi - sign * w1[P]))
                ok = []
                for L in range(1, 24):
                    slot = {}
                    for j, i in enumerate(CRIB_IDX):
                        slot[i % L] = slot.get(i % L, (1 << RES) - 1) & masks[j]
                    if all(slot.values()):
                        ok.append(L)
                # steady turning: key angle = start + step * position
                best = 0
                for step in range(0, RES, 2):
                    acc = {}
                    for j, i in enumerate(CRIB_IDX):
                        sh = (step * i) % RES
                        m = masks[j]
                        m = ((m >> sh) | (m << (RES - sh))) & ((1 << RES) - 1)   # subtract step*i
                        acc[j] = m
                    # deepest overlap: greedy count of how many arcs share some angle
                    common, cnt = (1 << RES) - 1, 0
                    for j in sorted(acc, key=lambda j: -bin(acc[j]).count("1")):
                        if common & acc[j]:
                            common &= acc[j]
                            cnt += 1
                    best = max(best, cnt)
                rows.append((n1, n2, sname, ok, best))
    if not quiet:
        print("\n=== compass wheel: KRYPTOS alphabet on the rose, unevenly spaced ===")
        cw = compass_wheel()
        print("  bearings: " + " ".join(f"{ch}{cw[ch]:g}" for ch in K))
        for n1, n2, sname, ok, best in rows:
            print(f"  plain on {n1:30s} cipher on {n2:30s} {sname:26s} repeating key fits at periods: "
                  f"{ok or 'none'}; steady turn: best {best}/24")
    return rows


def wheel_control():
    """Plant a message enciphered on the compass wheel with a 7-angle repeating key."""
    from recipes import _planted_text
    from kryptos import ALPHABET as A
    pt, w1, w2 = _planted_text(), even_wheel(A), compass_wheel()
    key = [13.0, 250.0, 67.5, 101.0, 199.5, 311.0, 42.0]
    def nearest(a):
        return min(w2, key=lambda ch: min((w2[ch] - a) % 360, (a - w2[ch]) % 360))
    ct = "".join(nearest((w1[p] + key[i % 7]) % 360) for i, p in enumerate(pt))
    rows = run_wheel(ct, quiet=True)
    ok = any(n1 == "even A-Z" and n2.startswith("compass (") and s == "turn forward" and 7 in fits
             for n1, n2, s, fits, _ in rows)
    print(f"[control compass wheel] planted 7-angle key on the compass wheel recovered: {ok}")
    return ok
