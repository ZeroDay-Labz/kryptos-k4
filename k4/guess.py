"""
Guessing plaintext: which words could stand where in K4?

With no known method there is no free way to check a guess. This module uses the one
regularity the 24 confirmed letters show (base5.py): each plaintext letter lands within
five consecutive cipher letters, i.e. cipher = table(plain) + 0..4, once positions 65 and
one of 27 / 72 are set aside. IF that holds for the whole message, then at every other
position each of the 13 letters that occur in the clues (A B C E H I K L N O R S T) is
either allowed or ruled out by the cipher letter there. That gives a crossword-style
mask, and a guessed word can be placed against it.

It is a filter built on a hypothesis that is itself only about 1-in-60 against chance.
A word that fits is not confirmed; a word that fails is only excluded if the hypothesis
is true. Every result is compared with the same search on a scrambled ciphertext.

Run:  python guess.py                 the mask, and themed / common words that fit
      python guess.py WORD [WORD...]  where your own words could go
"""
from __future__ import annotations

import math
import random
import sys

from kryptos import CIPHERTEXT
from frontier import CRIB
import base5

KNOWN = dict(CRIB)
N = 97
VARIANTS = {"O as at 72": {26, 64}, "O as at 27": {64, 71}}


def masks(ct=CIPHERTEXT):
    """{variant: [set of clue letters allowed at each position]} (clue positions: the clue letter)."""
    out = {}
    for name, drop in VARIANTS.items():
        dom = base5.domains(drop)
        m = []
        for i in range(N):
            if i in KNOWN:
                m.append({KNOWN[i]})
                continue
            c = ord(ct[i]) - 65
            m.append({P for P, d in dom.items() if any((c - f) % 26 < base5.BASE for f in d)})
        out[name] = (m, set(dom))
    return out


def fits(word, start, mask, letters):
    """True if every clue-type letter of the word is allowed where it would fall."""
    if start < 0 or start + len(word) > N:
        return False
    for j, ch in enumerate(word):
        i = start + j
        if i in KNOWN:
            if KNOWN[i] != ch:
                return False
        elif ch in letters and ch not in mask[i]:
            return False
    return True


def rarity(word, mask, letters):
    """-log10 of the chance that a word fits a random free position (higher = more telling)."""
    free = [i for i in range(N) if i not in KNOWN]
    s = 0.0
    for ch in word:
        if ch in letters:
            p = sum(ch in mask[i] for i in free) / len(free)
            s -= math.log10(max(p, 1e-3))
    return s


def scan(words, ct=CIPHERTEXT, min_rarity=3.0):
    rows = []
    for vname, (mask, letters) in masks(ct).items():
        for w in words:
            r = rarity(w, mask, letters)
            if r < min_rarity:
                continue
            for start in range(N - len(w) + 1):
                if any(start + j in KNOWN for j in range(len(w))):
                    continue                      # only the unknown stretches
                if fits(w, start, mask, letters):
                    rows.append((r, w, start + 1, vname))
    rows.sort(reverse=True)
    return rows


def show_mask():
    print("\n=== which clue-type letters are possible at each position (base-5 hypothesis) ===")
    print("  '.' = none of A B C E H I K L N O R S T can stand here; capital = confirmed clue letter")
    for vname, (mask, letters) in masks().items():
        print(f"  [{vname}]")
        for a in range(0, N, 20):
            cells = []
            for i in range(a, min(a + 20, N)):
                if i in KNOWN:
                    cells.append(KNOWN[i])
                else:
                    cells.append("".join(sorted(mask[i])).lower() or ".")
            print(f"   {a + 1:2d}  " + " ".join(f"{c:>4s}" for c in cells))
        none = sum(1 for i in range(N) if i not in KNOWN and not mask[i])
        print(f"   positions where no clue-type letter is possible: {none} of 73")


THEMED = """THE AND THIS THAT WITH FROM HERE THERE WHERE WHICH WHAT WHEN INTO UNDER OVER NEAR BETWEEN BEHIND
BENEATH BELOW ABOVE AROUND WORLD CLOCK BERLIN WALL EAST WEST NORTH SOUTH NORTHEAST NORTHWEST SOUTHEAST
SOUTHWEST DEGREES MINUTES SECONDS BEARING HEADING COMPASS ROSE LODESTONE NEEDLE MAGNETIC POSITION LOCATION
EGYPT CAIRO NILE TOMB PYRAMID SPHINX CHAMBER DOORWAY PASSAGE CANDLE BURIED UNDERGROUND SOMEWHERE EXACT
MESSAGE DELIVER DELIVERED DELIVERING SECRET HIDDEN INVISIBLE SHADOW LIGHT ILLUSION LAYER TWO THREE FOUR FIVE
SIX SEVEN EIGHT NINE TEN TWELVE MIDNIGHT NOON HOUR HOURS TIME ALEXANDERPLATZ WELTZEITUHR URANIA GATHERING
CROWD CROWDS FREEDOM CHECKPOINT CHARLIE BRANDENBURG GATE NOVEMBER NINETEEN EIGHTYNINE EIGHTYSIX LANGLEY
AGENCY COURTYARD SCULPTURE KRYPTOS STONE GRANITE COPPER WATER POOL TREE PETRIFIED MARKER SURVEY BENCHMARK
POINT LINE DIRECTION DIRECTIONS FOLLOW WALK STEPS FEET METERS PACES TURN LEFT RIGHT FACE FACING LOOK FIND DIG
OPEN CLOSE ENTER SLOWLY ONLY KNOWS LAST FIRST SECOND THIRD FINAL ANSWER RIDDLE QUESTION POWER SHADOWS FORCES
LUCID MEMORY VIRTUALLY DIGITAL INTERPRETATION YOUR THEIR THEY SHOULD WOULD COULD ABOUT TOTALLY POSSIBLE
INFORMATION GATHERED TRANSMITTED UNKNOWN WHO DOES KNOW IT IS WAS HIS HER ARE NOT BUT FOR ALL ONE OUT CAN YOU SEE
ANYTHING REMAINS DEBRIS ENCUMBERED LOWER PART REMOVED TREMBLING HANDS MADE TINY BREACH UPPER CORNER WIDENING
HOLE LITTLE INSERTED PEERED HOT AIR ESCAPING CAUSED FLAME FLICKER PRESENTLY DETAILS ROOM WITHIN EMERGED MIST""".split()


def run(words=None):
    show_mask()
    words = sorted(set(words or THEMED))
    rows = scan(words)
    rng = random.Random(9)
    nulls = []
    for _ in range(30):
        ct = list(CIPHERTEXT)
        free = [i for i in range(N) if i not in KNOWN]
        vals = [ct[i] for i in free]
        rng.shuffle(vals)
        for i, v in zip(free, vals):
            ct[i] = v
        nulls.append(scan(words, "".join(ct)))
    for thr in (4.0, 5.0, 6.0):
        real = sum(1 for r in rows if r[0] >= thr)
        nl = sorted(sum(1 for r in n if r[0] >= thr) for n in nulls)
        print(f"\n  placements with rarity >= {thr:.0f}: K4 has {real}; scrambled K4 has {nl[len(nl) // 2]} typically"
              f" (range {nl[0]}-{nl[-1]})")
    print("\n  the most telling placements in K4 (they fit, which is not the same as being right):")
    for r, w, pos, v in rows[:25]:
        print(f"    {w:16s} at {pos:2d}-{pos + len(w) - 1:2d}   rarity {r:.1f}   [{v}]")
    return rows


def place(words):
    for w in words:
        w = "".join(ch for ch in w.upper() if ch.isalpha())
        print(f"\n  {w}:")
        for vname, (mask, letters) in masks().items():
            ok = [s + 1 for s in range(N - len(w) + 1) if fits(w, s, mask, letters)]
            print(f"    [{vname}] rarity {rarity(w, mask, letters):.1f}; fits starting at: {ok or 'nowhere'}")


if __name__ == "__main__":
    if len(sys.argv) > 1:
        place(sys.argv[1:])
    else:
        run()
