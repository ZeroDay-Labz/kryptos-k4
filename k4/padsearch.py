"""
Is K4's key a stretch of a public text? (The "one-time pad anyone could look up" idea.)

For a running key on the A-Z / KRYPTOS tables the 24 clue letters dictate 24 key
letters: 13 in a row, a gap of 29, then 11 in a row. This module searches texts for
those letters, read forwards or backwards, every n-th letter (n <= MAX_STRIDE), and
as the first or last letters of consecutive words. 24 settings: plain and cipher
alphabet A-Z or KRYPTOS, key letters read on either alphabet, Vigenere / Beaufort /
variant. A 7-letter piece of either fragment is used as a seed, then all 24 letters
are compared, so up to 4 wrong letters are tolerated (Sanborn makes slips).

Texts: every .txt under ~/.cache/krypto_k4/texts (Project Gutenberg downloads: King
James Bible, Declaration of Independence, Constitution, Webster's dictionary,
Shakespeare, ...) plus the texts already in texts.py.

Run:  python padsearch.py [control]
"""
from __future__ import annotations

import glob
import multiprocessing as mp
import os
import re
import sys
import time

from kryptos import CIPHERTEXT, ALPHABET, KRYPTOS_KEYED
from frontier import CRIB
from texts import ALL_TEXTS

DIR = os.path.expanduser("~/.cache/krypto_k4/texts")
MAX_STRIDE = 40
MIN_AGREE = 20
_CTX = mp.get_context("fork")
ALPH = {"A": ALPHABET, "K": KRYPTOS_KEYED}
_TEXTS: dict[str, bytes] = {}
_TARGETS = []


def targets(ct=CIPHERTEXT):
    """[(label, key letters needed at the 24 clue positions)] without duplicates."""
    seen, out = set(), []
    for pa in "AK":
        for ca in "AK":
            for ka in "AK":
                for mode, f in (("vig", lambda p, c: c - p), ("beau", lambda p, c: c + p), ("var", lambda p, c: p - c)):
                    key = "".join(ALPH[ka][f(ALPH[pa].index(P), ALPH[ca].index(ct[i])) % 26] for i, P in CRIB)
                    if key not in seen:
                        seen.add(key)
                        out.append((f"plain {pa} / cipher {ca} / key {ka} / {mode}", key))
    return out


def load():
    texts = {name: t.encode() for name, t in ALL_TEXTS.items()}
    words = {}
    for path in sorted(glob.glob(os.path.join(DIR, "*.txt"))):
        raw = open(path, encoding="utf-8", errors="ignore").read().upper()
        name = os.path.basename(path)
        title = re.search(r"TITLE: (.+)", raw)
        name = f"{name} ({title.group(1).strip().title()[:50]})" if title else name
        texts[name] = re.sub(r"[^A-Z]", "", raw).encode()
        w = re.findall(r"[A-Z]+", raw)
        words[name + " [first letters of words]"] = "".join(x[0] for x in w).encode()
        words[name + " [last letters of words]"] = "".join(x[-1] for x in w).encode()
    texts.update(words)
    return texts


def _scan(stream: bytes, where, hits):
    """Seeds: 7-letter pieces of each fragment; then compare all 24 letters."""
    n = len(stream)
    for label, key in _TARGETS:
        k = key.encode()
        for off in (0, 6, 13, 17):                      # pieces of fragment 1 (0-12) and 2 (13-23)
            seed = k[off:off + 7]
            pos = stream.find(seed)
            while pos >= 0:
                start = pos - (off if off < 13 else off - 13 + 42)     # stream index of clue position 22
                if start >= 0 and start + 53 <= n:
                    got = stream[start:start + 13] + stream[start + 42:start + 53]
                    agree = sum(a == b for a, b in zip(got, k))
                    if agree >= MIN_AGREE:
                        hits.add((agree, where, start, label, got.decode()))
                pos = stream.find(seed, pos + 1)


def _task(args):
    name, stride = args
    t, hits = _TEXTS[name], set()
    for r in range(abs(stride)):
        s = t[r::abs(stride)]
        _scan(s if stride > 0 else s[::-1], f"{name} stride {stride} phase {r}", hits)
    return len(t), hits


def run(texts=None, ct=CIPHERTEXT, max_stride=MAX_STRIDE, procs=30, quiet=False):
    global _TEXTS, _TARGETS
    _TEXTS, _TARGETS = texts or load(), targets(ct)
    jobs = [(name, sg * st) for name in _TEXTS for st in range(1, max_stride + 1) for sg in (1, -1)]
    jobs.sort(key=lambda j: -len(_TEXTS[j[0]]))
    t0, hits, letters = time.time(), set(), 0
    with _CTX.Pool(procs) as pool:
        for n, h in pool.imap_unordered(_task, jobs, chunksize=1):
            letters += n
            hits |= h
    rows = sorted(hits, reverse=True)
    if not quiet:
        total = sum(len(t) for t in _TEXTS.values())
        print("\n=== key as a stretch of a public text (running key / book pad) ===")
        print(f"  {len(_TEXTS)} texts, {total:,} letters; strides 1-{max_stride}, both directions;"
              f" {len(_TARGETS)} table settings ({time.time() - t0:.0f} s)")
        for agree, where, start, label, got in rows[:10]:
            print(f"  HIT {agree}/24  {where} at {start}  [{label}]  key letters {got}")
        if not rows:
            print(f"  no stretch of any text gives {MIN_AGREE} or more of the 24 key letters")
    return rows


def control():
    from recipes import _planted_text
    pt = _planted_text()
    src = ALL_TEXTS["K2 plaintext"]
    key = src[30:30 + 97 * 3:3]                                   # every 3rd letter of K2's plaintext
    K = KRYPTOS_KEYED
    ct = "".join(K[(K.index(p) + K.index(k)) % 26] for p, k in zip(pt, key))
    rows = run({"K2 plaintext": src.encode(), "noise": ALL_TEXTS["K3 plaintext"].encode()}, ct, 5, 2, quiet=True)
    ok = any(r[0] == 24 and "stride 3" in r[1] for r in rows)
    print(f"[control padsearch] key = every 3rd letter of a known text recovered: {ok}")
    return ok


if __name__ == "__main__":
    if not control():
        sys.exit("control failed")
    if len(sys.argv) < 2 or sys.argv[1] != "control":
        run()
