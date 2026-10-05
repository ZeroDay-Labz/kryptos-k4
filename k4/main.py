"""
Kryptos K4 toolkit launcher.

    python main.py                 interactive menu
    python main.py list            show all commands
    python main.py <command>       run one command (e.g. controls, structural)
    python main.py candidate TEXT  test a 97-letter plaintext guess

Each command runs one of the project's scripts in a child process, streams its
output with colour, and reports whether it finished cleanly.
"""
from __future__ import annotations

import os
import shutil
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))

# PyCharm's run console renders ANSI colours but is not a TTY.
_COLOR = "NO_COLOR" not in os.environ and (sys.stdout.isatty() or "PYCHARM_HOSTED" in os.environ)


def c(text: str, *codes: str) -> str:
    return f"\033[{';'.join(codes)}m{text}\033[0m" if _COLOR else text


BOLD, DIM, RED, GREEN, YELLOW, CYAN = "1", "2", "31", "32", "33", "36"

# name -> (description, rough duration, heavy?, [(script, args), ...])
COMMANDS: dict[str, tuple[str, str, bool, list[tuple[str, list[str]]]]] = {
    "info": ("Ciphertext, confirmed cribs and the keys they imply", "instant", False,
             [("kryptos.py", [])]),
    "key": ("Reverse-engineer the key from the clues (shown on K1/K2, then K4)", "instant", False,
            [("keyview.py", [])]),
    "verify": ("Check the sculpture transcription by decrypting K1 and K2", "instant", False,
               [("sculpture.py", [])]),
    "controls": ("Planted-solution checks: every attack must find a known answer", "~1 min", False,
                 [("frontier.py", ["control"]), ("structural.py", ["control"]),
                  ("gromark_sa.py", ["control"]), ("recipes.py", ["control"]),
                  ("keyhunt.py", ["control"]), ("masks.py", ["control"]),
                  ("chain.py", ["control"])]),
    "recipes": ("Multi-stage hand recipes: two layers, two keyword alphabets, irregular keys, "
                "numeric keys, K3 transposition + two layers", "~4 min", True,
                [("recipes.py", ["all"])]),
    "blackbox": ("Black-box diagnosis: which cipher families reproduce K4's fingerprints", "~1 min", False,
                 [("blackbox.py", [])]),
    "anykeyword": ("Is there ANY keyword whose alphabet turns the clue shifts into digits? (exhaustive)",
                   "~4 min", True, [("keyedcsp.py", [])]),
    "masks": ("Masks: separately keyed streams (interleaved, by row, by letter type) and route readings",
              "~5 s", False, [("masks.py", [])]),
    "chain": ("Key chains: a text decoded by one key becomes the next key (two and three levels)",
              "~15 s", False, [("chain.py", ["level2"]), ("chain.py", ["feedback"]), ("chain.py", ["level3"])]),
    "chain-transposition": ("Key chains behind a transposition (columnar widths 2-9, rotations, routes)",
                            "~5 min", True, [("chaint.py", ["control"]), ("chaint.py", ["run"])]),
    "pad": ("Public texts as the pad (Bible, Declaration, dictionary, ...; skip, reverse, word initials)",
            "~1 min", False, [("padsearch.py", [])]),
    "light": ("Light projection through the screen: affine pairing, curved-screen warp, ray trace",
              "~30 s", False, [("projection.py", []), ("raycast.py", [])]),
    "anneal": ("One known alphabet + any alphabet + any repeating key, judged on whole-text English",
               "~25 min", True, [("qsolve.py", ["control"]), ("qsolve.py", ["run"])]),
    "columnar-gpu": ("Every columnar order of widths 12-14 x any repeating key, on the GPU (OpenCL)",
                     "~16 min", True, [("colsweep.py", ["control", "gpu"]), ("colsweep.py", ["12", "gpu"]),
                                       ("colsweep.py", ["13", "gpu"]), ("colsweep.py", ["14", "gpu"])]),
    "pairs": ("Pair-based ciphers on a grid: fingerprint, Slidefair, four-square on a 26-letter rectangle",
              "~3 min", False, [("pairs.py", [])]),
    "block": ("K3 + ? + K4 as one 14 x 31 block: K3's letters as K4's key", "~1 min", False, [("block.py", [])]),
    "compass": ("Compass schemes: points, bearings, the KRYPTOS alphabet on the rose as a wheel", "~2 min", False,
                [("compass.py", [])]),
    "base5": ("Fixed table plus a base-5 digit: which digit keys fit", "~1 min", False, [("base5.py", [])]),
    "chain-derived": ("Key chains: derived keywords as alphabets and inner-layer keys (64M)",
                      "~45 min", True, [("chain.py", ["derived"])]),
    "fractionation": ("Trifid, 6x6 Bifid and five-bit fractionation with any arrangement", "~15 s", False,
                      [("trifid.py", [])]),
    "digits": ("Digit keys with two unknown alphabets: named numbers, then every 8-digit key",
               "~20 min", True, [("digits.py", ["all"])]),
    "wordlists": ("Build the keyword corpus from the installed security wordlists", "~1 min once", False,
                  [("wordlists.py", [])]),
    "keyhunt": ("Keyword hunt: 37.7M wordlist strings as alphabet keywords, inner-layer keys, "
                "alphabet pairs, running-key texts, and error-tolerant tests", "~50 min", True,
                [("keyhunt.py", ["all"])]),
    "frontier": ("Autokey, progressive and double keys, transposition sweeps", "~3 min", True,
                 [("frontier.py", ["all"])]),
    "structural": ("Arbitrary alphabets, Hill, recurrence keys, sculpture keys, English running key",
                   "~5 min", True, [("structural.py", ["all"])]),
    "gromark": ("Gromark: keyword alphabets and surviving-primer counts", "~5 min", True,
                [("gromark.py", ["all"])]),
    "gromark-solve": ("Gromark alphabet solver over every surviving primer", "~30+ min", True,
                      [("gromark_sa.py", ["all"])]),
    "columnar": ("Exhaustive columnar transposition, widths 10-11", "~14 min", True,
                 [("frontier.py", ["columnar", "10", "11"])]),
    "double": ("Double columnar transposition, widths 2-7", "~15 min", True,
               [("frontier.py", ["double"])]),
    "results": ("Show the best decryptions saved by the Gromark solver", "instant", False, []),
}


def paint(line: str) -> str:
    """Colour one line of child output by what it says."""
    s = line.rstrip("\n")
    low = s.lower()
    if s.startswith("==="):
        return c(s, BOLD, CYAN)
    if ("[control" in low or low.startswith("control passed")) and ("true" in low or "false" in low):
        return c(s, GREEN if "false" not in low else RED)
    if "traceback" in low or "error" in low or "assert" in low:
        return c(s, RED)
    if " hit " in low or low.lstrip().startswith("hit") or "consistent:" in low and "none" not in low:
        return c(s, BOLD, GREEN)
    if any(k in low for k in ("no crib-consistent", "none", "nothing above", "no placement",
                              "not excluded: 0", "chance")):
        return c(s, DIM)
    return s


def busy_jobs() -> list[str]:
    """Other heavy K4 jobs already running on this machine."""
    if not shutil.which("pgrep"):
        return []
    try:
        out = subprocess.run(["pgrep", "-af", r"gsolve|frontier\.py|structural\.py|gromark"],
                             capture_output=True, text=True, timeout=5).stdout
    except (OSError, subprocess.SubprocessError):
        return []
    mine = str(os.getpid())
    jobs = []
    for line in out.splitlines():
        pid, _, cmd = line.partition(" ")
        exe = os.path.basename(cmd.split()[0]) if cmd.split() else ""
        # count only real workers: a Python interpreter or the compiled solver
        if pid != mine and (exe.startswith("python") or exe == "gsolve") \
                and "forkserver" not in cmd and "resource_tracker" not in cmd:
            jobs.append(line)
    return jobs


def run_script(script: str, args: list[str]) -> tuple[bool, float]:
    """Run one project script, streaming coloured output. Returns (ok, seconds)."""
    path = os.path.join(HERE, script)
    label = " ".join([script, *args])
    print(c(f"\n▶ {label}", BOLD, YELLOW))
    t0 = time.time()
    if not os.path.exists(path):
        print(c(f"  missing file: {path}", RED))
        return False, 0.0
    try:
        proc = subprocess.Popen([sys.executable, "-u", path, *args], cwd=HERE,
                                stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    except OSError as e:
        print(c(f"  could not start: {e}", RED))
        return False, 0.0
    try:
        assert proc.stdout is not None
        for line in proc.stdout:
            print(paint(line))
        code = proc.wait()
    except KeyboardInterrupt:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
        print(c("\n  stopped by you (Ctrl+C)", YELLOW))
        return False, time.time() - t0
    dt = time.time() - t0
    if code == 0:
        print(c(f"✔ {label} finished in {dt:.0f}s", GREEN))
    else:
        print(c(f"✘ {label} failed (exit code {code}) after {dt:.0f}s", BOLD, RED))
        if script == "gromark_sa.py" and not shutil.which("gcc"):
            print(c("  gromark_sa.py needs gcc to build gsolve.c, and gcc was not found.", RED))
    return code == 0, dt


def show_results() -> bool:
    path = os.path.join(HERE, "gromark_results.txt")
    if not os.path.exists(path):
        print(c("No gromark_results.txt yet. Run:  python main.py gromark-solve", YELLOW))
        return False
    print(c("\n=== best Gromark decryptions (higher score = more English; real English ≈ -4.3) ===",
            BOLD, CYAN))
    try:
        with open(path, encoding="utf-8") as fh:
            rows = [line.split() for line in fh if line.strip()]
    except OSError as e:
        print(c(f"could not read results: {e}", RED))
        return False
    for score, label, text, *_ in rows[:15]:
        colour = GREEN if float(score) > -4.6 else DIM
        print(f"  {c(score, colour)}  {label}\n      {text}")
    return True


def run_command(name: str, extra: list[str]) -> bool:
    if name == "candidate":
        if not extra:
            print(c("usage: python main.py candidate YOUR97LETTERGUESS", RED))
            return False
        guess = "".join(ch for ch in "".join(extra).upper() if ch.isalpha())
        if len(guess) != 97:
            print(c(f"A K4 plaintext must be 97 letters; that was {len(guess)}.", RED))
            return False
        return run_script("candidate.py", [guess])[0]
    if name == "results":
        return show_results()
    if name not in COMMANDS:
        print(c(f"unknown command: {name}", RED))
        list_commands()
        return False
    desc, _, heavy, steps = COMMANDS[name]
    print(c(f"\n{name}: {desc}", BOLD))
    if heavy:
        others = busy_jobs()
        if others:
            print(c(f"  note: {len(others)} other K4 job(s) are already running; "
                    "this will be slower while they finish.", YELLOW))
    summary = [(f"{s} {' '.join(a)}".strip(), *run_script(s, a)) for s, a in steps]
    if len(summary) > 1:
        print(c("\nsummary", BOLD))
        for label, ok, dt in summary:
            print(f"  {c('✔', GREEN) if ok else c('✘', RED)} {label} ({dt:.0f}s)")
    return all(ok for _, ok, _ in summary)


def list_commands() -> None:
    print(c("\nKryptos K4 toolkit", BOLD, CYAN))
    for i, (name, (desc, dur, _, _)) in enumerate(COMMANDS.items(), 1):
        print(f"  {c(f'{i:2d}', YELLOW)}  {c(f'{name:14}', BOLD)} {desc} {c(f'({dur})', DIM)}")
    print(f"      {c('candidate TEXT', BOLD)} test a 97-letter plaintext guess")


def menu() -> None:
    names = list(COMMANDS)
    while True:
        list_commands()
        try:
            choice = input(c("\nnumber or name (q to quit): ", BOLD)).strip()
        except (EOFError, KeyboardInterrupt):
            print()
            return
        if choice.lower() in ("q", "quit", "exit", ""):
            return
        parts = choice.split()
        name = names[int(parts[0]) - 1] if parts[0].isdigit() and 1 <= int(parts[0]) <= len(names) else parts[0]
        run_command(name, parts[1:])


def main(argv: list[str]) -> int:
    if not argv:
        menu()
        return 0
    if argv[0] in ("list", "-h", "--help", "help"):
        list_commands()
        return 0
    return 0 if run_command(argv[0], argv[1:]) else 1


if __name__ == "__main__":
    try:
        sys.exit(main(sys.argv[1:]))
    except KeyboardInterrupt:
        print(c("\ninterrupted", YELLOW))
        sys.exit(130)
    except Exception as e:  # last-resort guard so the launcher never dies with a bare traceback
        print(c(f"\nunexpected error in the launcher: {type(e).__name__}: {e}", BOLD, RED))
        sys.exit(1)
