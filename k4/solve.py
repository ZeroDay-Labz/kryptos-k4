"""
Sweep drivers for Kryptos K4.

Each driver enumerates a hypothesis space, keeps only decryptions that satisfy
*both* confirmed cribs, and ranks the survivors by english_score. Crib-matching
is the hard filter: a correct K4 method must reproduce EASTNORTHEAST and
BERLINCLOCK at their exact positions, so anything that doesn't is discarded
before scoring.

Honest expectation: these reproduce the community's negative results on the
classical families and surface the best near-misses. They are a platform for
hypotheses, not a promise of a solution.
"""
from __future__ import annotations

import heapq
from dataclasses import dataclass, field

from kryptos import CIPHERTEXT, matches_cribs, keyed_alphabet, ALPHABET
from ciphers import gen_decrypt, autokey_decrypt, running_key_decrypt, columnar_decrypt
from scoring import english_score

# Kryptos-relevant keyword corpus (sculpture, artists, prior keys, themes).
CORPUS = [
    "KRYPTOS", "PALIMPSEST", "ABSCISSA", "SANBORN", "SCHEIDT", "LANGLEY",
    "IQLUSION", "UNDERGROUND", "SHADOW", "FORCES", "LUCID", "MEMORY",
    "BERLIN", "CLOCK", "EAST", "NORTHEAST", "GIRASOL", "MAGNETIC", "FIELD",
    "INVISIBLE", "DIGETAL", "INTERPRETATI", "TANGIBLE", "WHOKNOWS",
    "NYPVTT", "COPPER", "COMPASS", "LODESTONE", "AGENCY", "INTELLIGENCE",
    "WELTZEIT", "ZEITUHR", "MENGENLEHRE", "WATCH", "TIME", "NORTH", "WEST",
]


@dataclass(order=True)
class Hit:
    score: float
    label: str = field(compare=False)
    plaintext: str = field(compare=False)


class TopHits:
    """Keep the top-N highest-scoring crib-passing decryptions."""
    def __init__(self, n: int = 20):
        self.n = n
        self._heap: list[Hit] = []

    def offer(self, score: float, label: str, pt: str) -> None:
        h = Hit(score, label, pt)
        if len(self._heap) < self.n:
            heapq.heappush(self._heap, h)
        elif score > self._heap[0].score:
            heapq.heapreplace(self._heap, h)

    def best(self) -> list[Hit]:
        return sorted(self._heap, key=lambda h: -h.score)


def _consider(top: TopHits, pt: str, label: str) -> bool:
    """Record pt if it passes both cribs. Returns True on crib pass."""
    if matches_cribs(pt):
        top.offer(english_score(pt), label, pt)
        return True
    return False


# --- 1. Quagmire III / IV sweep --------------------------------------------

def sweep_quagmire(alpha_kws=None, indicator_kws=None, modes=("vigenere", "beaufort", "variant"),
                   quag4=False, top_n=20) -> tuple[TopHits, int, int]:
    alpha_kws = alpha_kws or CORPUS
    indicator_kws = indicator_kws or CORPUS
    top = TopHits(top_n)
    tried = crib_hits = 0
    for akw in alpha_kws:
        pt_alpha = keyed_alphabet(akw)
        ct_alphas = [(bkw, keyed_alphabet(bkw)) for bkw in (alpha_kws if quag4 else [akw])]
        for bkw, ct_alpha in ct_alphas:
            for ikw in indicator_kws:
                for mode in modes:
                    for off in range(26):
                        pt = gen_decrypt(CIPHERTEXT, ikw, pt_alpha=pt_alpha,
                                         ct_alpha=ct_alpha, offset=off, mode=mode)
                        tried += 1
                        label = f"Q{'4' if quag4 else '3'} pt={akw} ct={bkw} key={ikw} {mode} off={off}"
                        if _consider(top, pt, label):
                            crib_hits += 1
    return top, tried, crib_hits


# --- 2. Transposition then re-examine cribs --------------------------------

def sweep_transposition_then_vigenere(trans_kws=None, vig_kws=None, top_n=20):
    """Un-transpose with a columnar key, then Vigenere-decrypt, check cribs."""
    trans_kws = trans_kws or CORPUS
    vig_kws = vig_kws or CORPUS
    top = TopHits(top_n)
    tried = crib_hits = 0
    for tkw in trans_kws:
        untransposed = columnar_decrypt(CIPHERTEXT, tkw)
        for vkw in vig_kws:
            for mode in ("vigenere", "beaufort", "variant"):
                pt = gen_decrypt(untransposed, vkw, mode=mode)
                tried += 1
                # NOTE: transposition moves crib positions, so matches_cribs on
                # the de-transposed text is only meaningful if the transposition
                # is the OUTER layer. This tests the "substitution-then-transpose"
                # encryption order (decrypt = un-transpose, then un-substitute).
                if _consider(top, pt, f"TxN trans={tkw} vig={vkw} {mode}"):
                    crib_hits += 1
    return top, tried, crib_hits


# --- 3. Autokey sweep ------------------------------------------------------

def sweep_autokey(seeds=None, modes=("vigenere", "beaufort", "variant"),
                  feedbacks=("plaintext", "ciphertext"), top_n=20):
    seeds = seeds or CORPUS
    top = TopHits(top_n)
    tried = crib_hits = 0
    for seed in seeds:
        for mode in modes:
            for fb in feedbacks:
                pt = autokey_decrypt(CIPHERTEXT, seed, mode=mode, feedback=fb)
                tried += 1
                if _consider(top, pt, f"AUTOKEY seed={seed} {mode} fb={fb}"):
                    crib_hits += 1
    return top, tried, crib_hits


# --- 4. Running key sweep --------------------------------------------------

# Plaintexts of the solved sections, used as candidate running keys.
K1_PT = ("BETWEENSUBTLESHADINGANDTHEABSENCEOFLIGHTLIESTHENUANCEOFIQLUSION")
K2_PT = ("ITWASTOTALLYINVISIBLEHOWSTHATPOSSIBLETHEYUSEDTHEEARTHSMAGNETICFIELDX"
         "THEINFORMATIONWASGATHEREDANDTRANSMITTEDUNDERGRUUNDTOANUNKNOWNLOCATIONX"
         "DOESLANGLEYKNOWABOUTTHISTHEYSHOULDITSBURIEDOUTTHERESOMEWHEREX"
         "WHOKNOWSTHEEXACTLOCATIONONLYWWTHISWASHISLASTMESSAGEX"
         "THIRTYEIGHTDEGREESFIFTYSEVENMINUTESSIXPOINTFIVESECONDSNORTH"
         "SEVENTYSEVENDEGREESEIGHTMINUTESFORTYFOURSECONDSWESTIDBYROWS")
K3_PT = ("SLOWLYDESPARATLYSLOWLYTHEREMAINSOFPASSAGEDEBRISTHATENCUMBEREDTHELOWERPART"
         "OFTHEDOORWAYWASREMOVEDWITHTREMBLINGHANDSIMADEATINYBREACHINTHEUPPERLEFT"
         "HANDCORNERANDTHENWIDENINGTHEHOLEALITTLEIINSERTEDTHECANDLEANDPEEREDIN"
         "THEHOTAIRESCAPINGFROMTHECHAMBERCAUSEDTHEFLAMETOFLICKERBUTPRESENTLY"
         "DETAILSOFTHEROOMWITHINEMERGEDFROMTHEMISTXCANYOUSEEANYTHINGQ")


def sweep_running_key(streams=None, modes=("vigenere", "beaufort", "variant"), top_n=20):
    streams = streams or {"K1": K1_PT, "K2": K2_PT, "K3": K3_PT,
                          "K2+K3": K2_PT + K3_PT, "K3+K2": K3_PT + K2_PT}
    top = TopHits(top_n)
    tried = crib_hits = 0
    for name, stream in streams.items():
        if len(stream) < 97:
            continue
        for start in range(0, len(stream) - 97 + 1):
            window = stream[start:]
            for mode in modes:
                pt = running_key_decrypt(CIPHERTEXT, window, mode=mode)
                tried += 1
                if _consider(top, pt, f"RUNKEY {name}@{start} {mode}"):
                    crib_hits += 1
    return top, tried, crib_hits


def _report(title, result):
    top, tried, crib_hits = result
    print(f"\n=== {title} ===")
    print(f"tried={tried:,}  crib-passing={crib_hits}")
    for h in top.best()[:10]:
        print(f"  {h.score:6.1f}  {h.label}")
        print(f"          {h.plaintext}")
    if crib_hits == 0:
        print("  (no decryption reproduced both cribs)")


if __name__ == "__main__":
    _report("Quagmire III", sweep_quagmire(quag4=False))
    _report("Quagmire IV", sweep_quagmire(quag4=True))
    _report("Transposition then Vigenere", sweep_transposition_then_vigenere())
    _report("Autokey", sweep_autokey())
    _report("Running key (K1/K2/K3 plaintext)", sweep_running_key())
