"""
Classical cipher primitives for Kryptos K4 experiments.

One generalized periodic-substitution engine (`gen_decrypt`) subsumes the whole
Vigenere/Beaufort/Quagmire family by parameterizing the plaintext alphabet,
ciphertext alphabet, key-alignment offset, and arithmetic mode:

    pt_alpha == ct_alpha == A-Z, mode=vigenere      -> classic Vigenere
    pt_alpha == ct_alpha == keyed(kw)               -> Quagmire III
    pt_alpha == keyed(kw1), ct_alpha == keyed(kw2)  -> Quagmire IV
    pt_alpha keyed, ct_alpha A-Z                     -> Quagmire I   (and swap -> II)

`offset` (0..25) absorbs any key-alignment convention, so sweeps never miss a
valid setting on a technicality. Plus autokey, running-key, and columnar
transposition. All decryption here; encrypt helpers only where needed to verify.
"""
from __future__ import annotations

from kryptos import keyed_alphabet, ALPHABET

Mode = str  # "vigenere" | "beaufort" | "variant"


def _rank_map(alpha: str) -> dict[str, int]:
    return {c: i for i, c in enumerate(alpha)}


def gen_decrypt(ct: str, key: str, *, pt_alpha: str = ALPHABET,
                ct_alpha: str = ALPHABET, offset: int = 0,
                mode: Mode = "vigenere") -> str:
    """Generalized periodic polyalphabetic decryption. See module docstring."""
    pr = _rank_map(pt_alpha)
    cr = _rank_map(ct_alpha)
    L = len(key)
    out = []
    for i, c in enumerate(ct):
        k = key[i % L]
        s = (pr[k] + offset) % 26
        r = cr[c]
        if mode == "vigenere":
            p = (r - s) % 26
        elif mode == "beaufort":
            p = (s - r) % 26
        elif mode == "variant":
            p = (r + s) % 26
        else:
            raise ValueError(mode)
        out.append(pt_alpha[p])
    return "".join(out)


def quagmire3(ct: str, alpha_kw: str, key: str, offset: int = 0,
              mode: Mode = "vigenere") -> str:
    ka = keyed_alphabet(alpha_kw)
    return gen_decrypt(ct, key, pt_alpha=ka, ct_alpha=ka, offset=offset, mode=mode)


def quagmire4(ct: str, pt_kw: str, ct_kw: str, key: str, offset: int = 0,
              mode: Mode = "vigenere") -> str:
    return gen_decrypt(ct, key, pt_alpha=keyed_alphabet(pt_kw),
                       ct_alpha=keyed_alphabet(ct_kw), offset=offset, mode=mode)


def autokey_decrypt(ct: str, seed: str, *, pt_alpha: str = ALPHABET,
                    ct_alpha: str = ALPHABET, offset: int = 0,
                    mode: Mode = "vigenere", feedback: str = "plaintext") -> str:
    """Autokey: key stream = seed, then recovered plaintext (or ciphertext)."""
    pr = _rank_map(pt_alpha)
    cr = _rank_map(ct_alpha)
    keystream = list(seed)
    out = []
    for i, c in enumerate(ct):
        k = keystream[i]
        s = (pr[k] + offset) % 26
        r = cr[c]
        if mode == "vigenere":
            p = (r - s) % 26
        elif mode == "beaufort":
            p = (s - r) % 26
        elif mode == "variant":
            p = (r + s) % 26
        else:
            raise ValueError(mode)
        pc = pt_alpha[p]
        out.append(pc)
        keystream.append(pc if feedback == "plaintext" else c)
    return "".join(out)


def running_key_decrypt(ct: str, key_stream: str, *, pt_alpha: str = ALPHABET,
                        ct_alpha: str = ALPHABET, offset: int = 0,
                        mode: Mode = "vigenere") -> str:
    """Key is a continuous text at least as long as the ciphertext."""
    if len(key_stream) < len(ct):
        raise ValueError("running key shorter than ciphertext")
    return gen_decrypt(ct, key_stream[:len(ct)], pt_alpha=pt_alpha,
                       ct_alpha=ct_alpha, offset=offset, mode=mode)


# --- Columnar transposition ------------------------------------------------

def _col_order(keyword: str) -> list[int]:
    """Column read order from a keyword (ties broken left-to-right)."""
    pairs = sorted(range(len(keyword)), key=lambda i: (keyword[i], i))
    order = [0] * len(keyword)
    for rank, col in enumerate(pairs):
        order[col] = rank
    return order


def columnar_encrypt(text: str, keyword: str) -> str:
    cols = len(keyword)
    order = _col_order(keyword)
    grid = [text[i:i + cols] for i in range(0, len(text), cols)]
    out = []
    for target in range(cols):
        col = order.index(target)
        for row in grid:
            if col < len(row):
                out.append(row[col])
    return "".join(out)


def columnar_decrypt(text: str, keyword: str) -> str:
    cols = len(keyword)
    n = len(text)
    rows = -(-n // cols)
    short = cols * rows - n  # number of columns short by one in the last row
    order = _col_order(keyword)
    col_len = {}
    for col in range(cols):
        full = rows if col < cols - short else rows - 1
        col_len[col] = full
    cells = [[""] * cols for _ in range(rows)]
    idx = 0
    for target in range(cols):
        col = order.index(target)
        for r in range(col_len[col]):
            cells[r][col] = text[idx]
            idx += 1
    return "".join(cells[r][c] for r in range(rows) for c in range(cols)
                   if cells[r][c])


if __name__ == "__main__":
    # Sanity: gen_decrypt with A-Z == classic Vigenere; columnar round-trips.
    from kryptos import decrypt, CIPHERTEXT
    key = "PALIMPSEST"
    assert gen_decrypt(CIPHERTEXT, key) == decrypt(CIPHERTEXT, key, "vigenere")
    msg = "WEAREDISCOVEREDFLEEATONCEX"
    assert columnar_decrypt(columnar_encrypt(msg, "ZEBRAS"), "ZEBRAS") == msg
    print("ciphers.py self-check OK")
