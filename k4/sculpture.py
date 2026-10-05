"""
Full text of the Kryptos sculpture: the 28-row ciphertext side and the 28-row
tableau side, as grids. Transcribed from the standard published layout and
validated in `__main__` by decrypting K1 and K2 and anagram-checking K3.
"""
from __future__ import annotations

from kryptos import KRYPTOS_KEYED, ALPHABET

CIPHER_ROWS = [
    "EMUFPHZLRFAXYUSDJKZLDKRNSHGNFIVJ",
    "YQTQUXQBQVYUVLLTREVJYQTMKYRDMFD",
    "VFPJUDEEHZWETZYVGWHKKQETGFQJNCE",
    "GGWHKK?DQMCPFQZDQMMIAGPFXHQRLG",
    "TIMVMZJANQLVKQEDAGDVFRPJUNGEUNA",
    "QZGZLECGYUXUEENJTBJLBQCRTBJDFHRR",
    "YIZETKZEMVDUFKSJHKFWHKUWQLSZFTI",
    "HHDDDUVH?DWKBFUFPWNTDFIYCUQZERE",
    "EVLDKFEZMOQQJLTTUGSYQPFEUNLAVIDX",
    "FLGGTEZ?FKZBSFDQVGOGIPUFXHHDRKF",
    "FHQNTGPUAECNUVPDJMQCLQUMUNEDFQ",
    "ELZZVRRGKFFVOEEXBDMVPNFQXEZLGRE",
    "DNQFMPNZGLFLPMRJQYALMGNUVPDXVKP",
    "DQUMEBEDMHDAFMJGZNUPLGEWJLLAETG",
    "ENDYAHROHNLSRHEOCPTEOIBIDYSHNAIA",
    "CHTNREYULDSLLSLLNOHSNOSMRWXMNE",
    "TPRNGATIHNRARPESLNNELEBLPIIACAE",
    "WMTWNDITEENRAHCTENEUDRETNHAEOE",
    "TFOLSEDTIWENHAEIOYTEYQHEENCTAYCR",
    "EIFTBRSPAMHHEWENATAMATEGYEERLB",
    "TEEFOASFIOTUETUAEOTOARMAEERTNRTI",
    "BSEDDNIAAHTTMSTEWPIEROAGRIEWFEB",
    "AECTDDHILCEIHSITEGOEAOSDDRYDLORIT",
    "RKLMLEHAGTDHARDPNEOHMGFMFEUHE",
    "ECDMRIPFEIMEHNLSSTTRTVDOHW?OBKR",
    "UOXOGHULBSOLIFBBWFLRVQQPRNGKSSO",
    "TWTQSJQSSEKZZWATJKLUDIAWINFBNYP",
    "VTTMZFPKWGDKZXTJCDIGKUHUAUEKCAR",
]

_HEADER = " " + ALPHABET + "ABCD"


def _tableau_rows() -> list[str]:
    rows = [_HEADER]
    for r in range(26):
        body = "".join(KRYPTOS_KEYED[(r + c) % 26] for c in range(30))
        rows.append(ALPHABET[r] + body + ("L" if ALPHABET[r] == "N" else ""))
    rows.append(_HEADER)
    return rows


TABLEAU_ROWS = _tableau_rows()

MORSE = ("VIRTUALLYINVISIBLE" "DIGETALINTERPRETATU" "SHADOWFORCES"
         "LUCIDMEMORY" "TISYOURPOSITION" "SOS" "RQ")

# Other published readings of the Morse text: with the padding E's, and with the
# last word read as INTERPRETATIT / INTERPRETATIU.
MORSE_VARIANTS = {
    "Morse with E padding (INTERPRETATIT)":
        "EEVIRTUALLYEEEEEEEINVISIBLEDIGETALEEEINTERPRETATITEESHADOWEEFORCESEEEEE"
        "LUCIDEEEMEMORYETISYOURPOSITIONESOSRQ",
    "Morse with E padding (INTERPRETATIU)":
        "EEVIRTUALLYEEEEEEEINVISIBLEDIGETALEEEINTERPRETATIUEESHADOWEEFORCESEEEEE"
        "LUCIDEEEMEMORYETISYOURPOSITIONESOSRQ",
    "Morse no padding (INTERPRETATIT)":
        "VIRTUALLYINVISIBLEDIGETALINTERPRETATITSHADOWFORCESLUCIDMEMORYTISYOURPOSITIONSOSRQ",
    "Morse no padding (INTERPRETATIU)":
        "VIRTUALLYINVISIBLEDIGETALINTERPRETATIUSHADOWFORCESLUCIDMEMORYTISYOURPOSITIONSOSRQ",
}

FULL_CT = "".join(CIPHER_ROWS)
FULL_CT_LETTERS = FULL_CT.replace("?", "")
K1_CT = FULL_CT_LETTERS[:63]
K2_CT = FULL_CT_LETTERS[63:63 + 369]
K3_CT = FULL_CT_LETTERS[63 + 369:63 + 369 + 336]
K4_CT = FULL_CT_LETTERS[-97:]

# (row, col) of each K4 letter in the ciphertext grid.
K4_CELLS = [(r, c) for r, row in enumerate(CIPHER_ROWS) for c, ch in enumerate(row)][-97:]


if __name__ == "__main__":
    from kryptos import CIPHERTEXT
    from ciphers import quagmire3
    from solve import K1_PT, K3_PT
    assert K4_CT == CIPHERTEXT, "K4 mismatch"
    print("rows:", len(CIPHER_ROWS), "letters:", len(FULL_CT_LETTERS))
    for off in range(26):
        p = quagmire3(K1_CT, "KRYPTOS", "PALIMPSEST", off)
        if p.startswith("BETWEEN"):
            print("K1:", p, "| matches known plaintext:", p == K1_PT)
    for off in range(26):
        p = quagmire3(K2_CT, "KRYPTOS", "ABSCISSA", off)
        if p.startswith("ITWAS"):
            print("K2:", p[:70], "...", p[-40:])
    def rotate(text, w, clockwise=True):
        """Write text in rows of width w, turn the grid 90 degrees, read it off."""
        rows = -(-len(text) // w)
        cols = range(w) if clockwise else range(w - 1, -1, -1)
        return "".join(text[r * w + c] for c in cols
                       for r in (range(rows - 1, -1, -1) if clockwise else range(rows))
                       if r * w + c < len(text))
    k3 = rotate(rotate(K3_CT, 8), 24)
    print("K3:", k3[:60], "...", "| matches known plaintext:", k3 == K3_PT)
    print("tableau rows:", len(TABLEAU_ROWS), "widths:", sorted({len(r) for r in TABLEAU_ROWS}))
    print("K4 starts at row/col:", K4_CELLS[0], "ends:", K4_CELLS[-1])
