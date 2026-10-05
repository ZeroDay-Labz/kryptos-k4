"""
Candidate key texts: documents Sanborn is known to have worked from.

These cannot be K4's plaintext (none contains EASTNORTHEAST / BERLINCLOCK at the
confirmed positions), but any of them could have served as a running key. Text
taken from notes on Sanborn's papers supplied by the user; letters only are used.
"""
from __future__ import annotations

from solve import K1_PT, K2_PT, K3_PT
from sculpture import FULL_CT_LETTERS, TABLEAU_ROWS, MORSE_VARIANTS

_RAW = {
    "counterintelligence paragraph": """
        Counterintelligence is a special branch of intelligence activity separate and distinct
        from other its purpose is to discover hostile foreign intelligence operations and destroy
        their effectiveness. This objective involves the protection of the United States
        Government against infiltration by foreign agents as well as control and manipulation of
        adversary intelligence operations. An effort is made to both discern and deceive the plans
        and intentions of enemy intelligence services.""",
    "tradecraft paragraph": """
        The highest art in tradecraft is to develop a source that you own lock, stock, and barrel.
        According to the clandestine ethos, a controlled source provides the most reliable
        intelligence. Controlled means, of course, bought or otherwise obligated. Traditionally it
        has been the aim of the professional in the clandestine service to weave a psychological
        web around any fruitful contact and tighten that web whenever possible. Opportunities are
        limited, but for those in the clandestine service who successfully develop controlled
        sources, rewards in status and peer respect are high. The modus operandi required,
        however, is the very antithesis of ethical interpersonal relationships.""",
    "Executive Order 12333 paragraph": """
        Agencies within the Intelligence Community shall use the least intrusive collection
        techniques feasible within the United States or directed against United States persons
        abroad. Agencies are not authorized to use such techniques as electronic surveillance,
        unconsented physical search, mail surveillance, physical surveillance, or monitoring
        devices unless they are in accordance with procedures established by the head of the
        agency concerned and approved by the Attorney General. Such procedures shall protect
        constitutional and other legal rights and limit use of such information to lawful
        governmental purposes.""",
    "Dead Sea Scrolls essay: opening": """
        The Dead Sea Scrolls are a series of biblical writings which were written some time
        between 168 B.C. and 233 A.D.""",
    "Dead Sea Scrolls essay: spring and cave": """
        replenished their water supply. While they were at a small spring a few of their number
        went on a short excursion to the cliffs not far from the spring and came upon a cave""",
    "Dead Sea Scrolls essay: Albright": "The greatest manuscript discovery of modern times",
    "Dead Sea Scrolls essay: Qumran": """
        Kirbet Qumran, a series of ancient ruins, located near the caves was where the scrolls
        were written.""",
    "Dead Sea Scrolls essay: fifth scroll": """
        The fifth scroll is called the War of the Sons of Light with the Sons of Darkness""",
    "FUMEE repeated": "FUMEE" * 40,
    # second set of notes: variant wording, class notes, misspellings as written
    "counterintelligence paragraph (form)": """
        Counterintelligence is a special form of intelligence activity separate and distinct
        from other its purpose is to discover hostile foreign intelligence operations and destroy
        their effectiveness. This objective involves the protection of the United States
        Government against infiltration by foreign agents as well as control and manipulation of
        adversary intelligence operations. An effort is made to both discern and deceive the plans
        and intentions of enemy intelligence services.""",
    "Dead Sea Scrolls essay: fifth scroll (long)": """
        The fifth scroll is called the War of the Sons of Light with the Sons of Darkness This
        scroll also reflects a conflict between the ritious and the wicked""",
    "class notes: common herd": """
        This statement shows the great influence of the common herd, as opposed to, originality
        of thought.""",
    "class notes: everybody does it": """
        The statement everybody does it may pertain to many things, whether they be drinking,
        cribbing on exams, or sexual experience before marriage, and each is detrimental to ones
        reputation if used wrongly""",
    "class notes: grades": """
        Grades are an ever present thing at college and we must not let grades be all that we go
        to college for we should intersperse theology with all of our other mechanical courses.""",
    "class notes: church unity": """
        nuclear giants and ethical infants Why is there a pressing need for Church Unity 4 things
        are proposed in the Chicago Lambeth quadrilateral cooperation is the first and this is
        achieved through councils like the one in 1927 where Bishop Brent unified many at work
        and in life""",
}


def _letters(t: str) -> str:
    return "".join(ch for ch in t.upper() if "A" <= ch <= "Z")


# Texts from the notes.
SANBORN_TEXTS = {name: _letters(t) for name, t in _RAW.items()}

# Everything on or about the sculpture that could be read as a key.
SCULPTURE_TEXTS = {
    "K1 plaintext": K1_PT, "K2 plaintext": K2_PT, "K3 plaintext": K3_PT,
    "K1-K3 plaintext": K1_PT + K2_PT + K3_PT,
    "sculpture ciphertext": FULL_CT_LETTERS,
    "tableau by rows": "".join(r.replace(" ", "") for r in TABLEAU_ROWS),
    **MORSE_VARIANTS,
}

ALL_TEXTS = {**SANBORN_TEXTS, **SCULPTURE_TEXTS}

# Keywords suggested by the same notes (added to the themed list in recipes.py).
NOTE_KEYWORDS = """SHADOW TEHb FUMEE SMOKE MIRRORS MEDUSA QUMRAN SCROLLS DEADSEA DEADSEASCROLLS ALBRIGHT
PASTERNAK ZHIVAGO SAKHAROV SOLZHENITSYN ANDROPOV GORKY TRADECRAFT COUNTERINTELLIGENCE CLANDESTINE
LOCKSTOCKANDBARREL SONSOFLIGHT SONSOFDARKNESS COVELL CYRILLIC PROJECTOR ANTIPODES
WASHINGTON ALEXANDRIA ARLINGTON RANDOLPHMACON PRATT BEDOUINS HABAKUK ISAIAH DENISOVICH
APPROXIMATLY HEIGTH IMMEDIATLY MONESTARY RITIOUS ARAMIC LAMBETH QUADRILATERAL BRENT""".split()
NOTE_KEYWORDS = [w for w in NOTE_KEYWORDS if w.isalpha() and w.isupper()]

if __name__ == "__main__":
    for name, t in ALL_TEXTS.items():
        print(f"{len(t):5d} letters  {name}")
