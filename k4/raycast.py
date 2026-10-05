"""
Driver for raycast.c: sunlight through the S-shaped screen as the key selector.
See raycast.c for the model. Writes the clue data and tableau grid, builds and runs.

Run:  python raycast.py
"""
from __future__ import annotations

import os
import subprocess
import tempfile

from kryptos import CIPHERTEXT
from frontier import CRIB_IDX
from sculpture import TABLEAU_ROWS, K4_CELLS
from structural import _shift_sets

HERE = os.path.dirname(os.path.abspath(__file__))


def run(threads=30):
    exe, src = os.path.join(HERE, "raycast"), os.path.join(HERE, "raycast.c")
    if not os.path.exists(exe) or os.path.getmtime(exe) < os.path.getmtime(src):
        subprocess.run(["gcc", "-O3", "-march=native", "-fopenmp", "-o", exe, src, "-lm"], check=True)
    with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False) as fh:
        for s in _shift_sets(CIPHERTEXT):
            fh.write(" ".join(map(str, s)) + "\n")
        for i in CRIB_IDX:
            fh.write("%d %d\n" % K4_CELLS[i])
        for r in TABLEAU_ROWS:
            fh.write(r.replace(" ", "_") + "\n")
        path = fh.name
    print("\n=== sunlight through the S-shaped screen: parametric ray trace ===")
    out = subprocess.run([exe, path], capture_output=True, text=True, check=True,
                         env=dict(os.environ, OMP_NUM_THREADS=str(threads))).stdout
    os.unlink(path)
    print("  " + out.replace("\n", "\n  ").rstrip())
    print("  (a real pairing would give 24, or 20+ with slips; chance over this many settings reaches about 12-13)")


if __name__ == "__main__":
    run()
