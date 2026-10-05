# Results in detail

Every test run in this project, grouped by the kind of method it rules out. For the summary see the
[README](../README.md); for the sources behind each idea see [CLUES.md](CLUES.md).

**How to read the tables.** A test "passes" only if the 24 confirmed clue letters are reproduced. Most tests
do not guess a key: they work out what the key would have to be at the clue positions and ask whether that is
consistent with the rule being tested. "Equalities" (or "loops closed") are the independent checks a setting
passed; each has a 1 in 26 chance of passing by luck, so a handful of passes at the minimum are expected in a
large search and are reported as chance. Scores such as −4.3 are average log-probabilities of four-letter
groups: ordinary English is about −4.3, random letters about −7.

**Controls.** Each module has a planted-solution control (`python <module>.py control`, or `python main.py
controls`): a message is enciphered with the method under test and the search must recover it.

All commands are run from the `k4/` directory.

## 1. Repeating keys, with and without rearranging the text

### Results of the built-in sweeps (curated keyword corpus)

| family | attempts | decryptions reproducing both cribs |
|--------|---------:|-----------------------------------:|
| Quagmire III | 106,782 | 0 |
| Quagmire IV | 3,950,934 | 0 |
| Transposition → Vigenère | 4,107 | 0 |
| Autokey | 222 | 0 |
| Running key (K1/K2/K3 plaintext) | 5,193 | 0 |

The harness is validated by a **positive control**: planting a known Quagmire III
solution and confirming the sweep recovers it.

### Crib-dragging: the decisive aperiodicity result (`cribdrag.py`)

Rather than guess the indicator keyword, we **derive** it: each crib letter forces
the *shift* at one key slot (offset-independent — a proven simplification that
collapses the 26× alignment loop). This covers the **entire indicator keyspace
for free** for any fixed alphabet, so it is the strongest possible test of a
periodic Quagmire.

- **KRYPTOS alphabet:** no key period 2–26 is even *consistent* with both cribs.
  Only 27–29 are consistent — and only because the key is then nearly as long as
  the 97-char text — and they decrypt to noise (quad ≈ −7.0) outside the cribs.
- **Full dictionary** (292,865 distinct keyed alphabets, swept in ~37 s): the best
  short-period candidate English can offer scores quad = **−6.319** (noise; random
  ≈ −7.9, English ≈ −4.6) and still needs L = 26.

**Conclusion:** no periodic key of length ≤ 23 over these alphabets is consistent
with the cribs. (Periods ≥ 24 leave too few shared key slots for the 24 crib
letters to test; they are not excluded.)

### Frontier sweeps (`frontier.py`)

Pure consistency tests on the 24 crib letters — no keyword guessing, no English
scoring. A configuration passes only if crib letters sharing a key slot force the
same shift; with c such equalities a random pass has probability 26^-c, and only
c ≥ 6 is reported. Every transposition is tried in both layer orders, forward
and inverse, with all four standard/KRYPTOS alphabet pairings in Vigenère and
Beaufort arithmetic, plus a monoalphabetic check.

| hypothesis | size | crib-consistent |
|---|---:|---:|
| autokey, any seed, plaintext or ciphertext feedback, lags 1–96 | complete | 0 |
| progressive key, periods ≤ 23, all steps | complete | 0 |
| two superimposed periodic keys (cipher applied twice), periods 2–30 | complete | 0 |
| dictionary-keyed alphabets as Quagmire I/II/III/IV (with KRYPTOS) | 339,152 alphabets | 0 |
| decimation, rail fence, serpentine, single and K3-style double rotation | 36,768 maps | 0 |
| columnar transposition, every column order, widths 2–9 | 818,224 maps | 0 |
| columnar transposition, every column order, widths 10–11 | 87,091,200 maps | 0 above chance* |
| columnar transposition, dictionary keys of length 12–24 | 172,096 maps | 0 |
| columnar transposition, every column order, widths 12–15 (`colsweep.py`, C and OpenCL on the GPU; key before or after, forward and inverse) | 2,803,117,363,200 maps | 0 (≥ 9 equalities at widths 12–13, ≥ 10 at width 14, ≥ 11 at width 15) |
| columnar composed with a grid rotation, widths 2–6, either order | 327,872 maps | 0 |
| double columnar, every pair of column orders, widths 2–7 | 69,903,488 maps | 0 above chance* |

\* The double-columnar run likewise gave 18 passes, all at exactly 6 equalities
and long periods (26–36), all decrypting to gibberish. For widths 10–11: six
configurations passed at exactly the minimum threshold (6 equalities, long
periods 28 and 47). About that many are expected by chance at this sample size
(87M maps × 8 alphabet/arithmetic combinations × 26^-6 ≈ 2 per tested period),
none has 7 or more, and their non-crib text is gibberish (`GWRNF…`, `ZXXKBXK…`).

Planted-solution controls (`python frontier.py control`) confirm each code path
finds a real solution of that type.

### Grid variants (`frontier.py grid`)

Scheidt counted 98 characters (with the `?`), which is a 7 × 14 grid, and Sanborn
spoke of "double matrixes and triple matrixes". `K4_VARIANT=q98` runs the
transposition sweeps on the 98-character text.

| text | rotations, double rotations, decimation, etc. | triple rotations | columnar widths 2–10 |
|---|---:|---:|---:|
| 98 characters | 0 of 26,376 | 0 of 1,769,472 | 0 of 8,075,824 |
| 97 characters | 0 of 36,768 | 0 of 1,769,472 | 0 of 8,075,824 |

### Masking: transposition + substitution (`masking.py`)

Models Scheidt's hinted "masking" as a columnar transposition composed with the
substitution, in both encryption orders (substitute-then-transpose,
transpose-then-substitute), each composed with the keyspace-complete crib-drag.
Validated by a positive control. Over the curated corpus, real K4 again yields
only near-aperiodic (L = 26) noise. The exhaustive transposition sweeps above and in `colsweep.py`
supersede this keyword-driven version.

### Masks: separately keyed streams and routes (`masks.py`)

Scheidt: "you need to solve the technique first and then go for the puzzle." Here
the message is first split into streams, each with its own repeating key and its
own alphabet setting, and each stream is judged on its own.

| mask | result |
|---|---|
| every m-th letter is a stream, m = 2–8 | no stream fits a repeating key (not even at 4 equalities) |
| each sculpture row is a stream; streams by column or row+column | none |
| each clue in its own separately keyed region | none |
| streams by letter type (vowel/consonant, letter of KRYPTOS or not, A–M/N–Z), from plaintext or ciphertext | none |
| spiral and diagonal reading of a grid, widths 2–48, 97 and 98 characters, then any tableau key | 0 of 6,008 |
| mirror / shadow readings (`masks.py mirrors`): grid flipped left-right, top-bottom or both, read by rows or columns, widths 2–48, any start column; then any tableau key, a single substitution, or a chained key | 0 of 14,096 (and 0 of 3.7 × 10¹⁰ chained keys) |
| streams by mirror-symmetric letters (AHIMOTUVWXY / other) | none |
| K3's recipe as NSA describes it (`masks.py stepped`): a few long rows, columns taken at a fixed step (every 7th for K3), any rows 2–32, step, start, direction; then any tableau key, a single substitution, or a chained key | 0 of 16,832 (and 0 of 5.5 × 10¹⁰ chained keys) |

Inserting null letters is ruled out without a test: plaintext and ciphertext are
both 97 letters and the clue words are contiguous.

## 2. Unknown alphabets

### Structural tests (`structural.py`, `sculpture.py`)

Tests that need no keyword or alphabet guess. `sculpture.py` holds the full
28-row ciphertext and tableau grids, validated by decrypting K1 and K2 from them.

| hypothesis | result |
|---|---|
| Quagmire III with **any** mixed alphabet, periods 1–26 | Vigenère form impossible at every period; Beaufort form survives only at 23 and 26 |
| any periodic substitution (26 unrelated alphabets) | impossible at periods 1–7, 9, 10, 14, 15, 17, 21, 25 |
| Quagmire IV with two arbitrary alphabets | not excluded at 8, 13, 16, 19, 20, 23, 24, 26 (random text passes most of these 26–99% of the time, so this is "undecidable", not a lead) |
| period 8, one dictionary alphabet + one arbitrary | 1 of 339,152 survives (`MANATOID`); its decryption is gibberish |
| Hill 2×2, 3×3, linear and affine, all alignments | none consistent |
| polynomial key, degree ≤ 8 | none consistent |
| linear recurrence (order ≤ 5), lagged Fibonacci, mixed plaintext/ciphertext feedback | none consistent |
| key read off the sculpture: ciphertext, tableau, K1–K3 plaintext, Morse; any start/stride/direction/grid offset (1,009,815 placements, fuzzy) | best 10 of 24 agree = chance level |
| English running key (prose quadgram model): plain, 339,152 dictionary alphabets, columnar widths 2–9 | best fragments score −4.8 to −5.1 and are not words; typical English scores −4.3 |
| arbitrary-alphabet Quagmire over 129,232 transpositions | Quagmire III excluded at periods 2–3; longer periods pass at chance rates and cannot be decided with 24 letters |

The period-19 passes in several columns come from one coincidence: plaintext `R`
encrypts to `P` at both position 28 and position 66 (38 apart). About 0.5 such
coincidences are expected by chance among the cribs' repeated letters.

### Any keyword at all (`keyedcsp.py`, `kwcsp.c`)

The black-box result says the clue letters look like small-number shifts over
near-standard alphabets. Instead of trying keywords from a list, this searches
EVERY keyword alphabet (any letters in any order, then the rest alphabetically)
and asks for the smallest number base in which all 24 clue shifts fit. A decimal
digit key needs 10 or less.

| alphabets | smallest base, proven |
|---|---|
| one side A–Z, other side any keyword (either way round, both arithmetics) | 12 |
| plain KRYPTOS, cipher any keyword | 14 |
| plain any keyword, cipher KRYPTOS | 12 |
| same keyword on both sides, keyword ≤ 8 letters | 11 (plain + digit), 12 (digit − plain) |
| same keyword on both sides, keyword ≤ 10 letters | 9, 11 |
| same keyword on both sides, keyword ≤ 11 letters | 8, 10 |

So a digit key with one standard or KRYPTOS alphabet is impossible for any
keyword. With the same keyword on both sides it is possible only for keywords of
9+ letters, and all 544,820 such alphabets (keyword ≤ 11 letters, base 10) were
listed: none is a word (the most word-like is `SC_REM_PAYO`), and in none do the
digits follow a lagged-Fibonacci rule through both clues.

### Repeating key with unknown alphabets: full-text annealing (`qsolve.py`, `gsolve period`)

The 24 clue letters cannot decide a repeating key when the alphabets are unknown,
so these runs judge the English of the whole 97-letter decryption instead.

| model | size | result |
|---|---:|---|
| one alphabet A–Z or KRYPTOS, the other ANY alphabet, any repeating key of period 8–24, plain and Beaufort (`qsolve.py`) | 8 models × 17 periods, clues strictly enforced | best clue-exact decryption −5.18 (gibberish); planted messages of this type come back at −4.16 to −4.56 |
| period 8, BOTH alphabets unknown: every key the clues allow, alphabets annealed for each (`gsolve quad steps restarts period 8`) | 8,031,810,176 keys, 4,503,912 allowed, 8 h on 30 cores | 39 score above −5.0; re-solved at 25× effort the best is −4.93 (word salad; real English −4.30) |

Caveats: annealing can miss; in a check on planted period-8 messages the first pass
recognised the true key clearly in 2 of 3 cases and scored the third −4.90. With
both alphabets and the key all unknown at periods above 8 (13, 16, 19, 20, 23),
`qsolve.py` does not recover a planted message, so those remain open.

## 3. Several stages and chained keys

### Multi-stage recipes (`recipes.py`)

Scheidt describes K4 as simple, keyword-driven and "more than one stage". These
tests enumerate combinations of simple letter-for-letter steps. One stage's
keyword is enumerated; the other stage's key is derived from the cribs or matched
by hash join, so nothing is guessed twice.

| recipe | size | result |
|---|---:|---|
| P1 two tableau layers with different alphabets: inner keyword from the dictionary, outer key of any period ≤ 23 | 415,221 keywords × 9 settings × 2 layer orders × 8 outer settings | 0 |
| P2 Quagmire IV with any two dictionary keywords as alphabets (keyed, transposed, reversed), any key of period ≤ 23 | 1,370,062 × 1,370,062 alphabets | none at periods ≤ 15; counts at 16, 19 and 23 match chance and decrypt to gibberish |
| P3 irregular key use: restart / skip / stall on a trigger letter, at word boundaries, or every n letters | 131,491 rules × 8 settings | 0 |
| P4 numeric keys from the coordinates, dates and keyword-to-number conversions; repeating and Gromark-expanded | 10,138 keys | best 10 of 24 (chance); 0 with dictionary alphabets |
| P5 three stages: K3-style transposition + tableau layer with a themed keyword + derived outer layer | 38,510 transpositions × 62 keywords × 9 settings × 2 orders × 2 key orders | 2 passes at the chance floor (6 equalities), gibberish |

Each phase recovers a planted solution of its own type (`python recipes.py control`).

### Keyword hunt with security wordlists (`wordlists.py`, `keyhunt.py`)

`wordlists.py` reduces every line of the installed wordlists (rockyou, SecLists,
Probable-Wordlists, FuzzDB, the system dictionary) to its letters: 37,715,951
distinct strings, cached at `~/.cache/krypto_k4/keywords.txt`. A repeating key
never needs a wordlist (it is derived from the cribs); these runs cover the
places where a keyword has to be guessed.

| role of the keyword | size | result |
|---|---:|---|
| builds an alphabet (Quagmire I/II/III, IV with KRYPTOS), any key ≤ 23 | 37.7M × 2 mixing styles | 0 |
| builds a Gromark alphabet, any digit key | same | smallest fitting base 11 (needs ≤ 10); the two base-11 fits follow no rule |
| builds a Gromark alphabet, standard key rule, other alphabet arbitrary | same × 290,346 keys | 0 |
| key of an inner tableau layer, outer layer derived | 37.7M × 9 settings × 2 orders × 8 outer | 0 |
| alphabet paired with an English-dictionary alphabet (two-keyword Quagmire IV) | 75.4M × 1.37M pairs | none at periods 1–15, 20–22; ~1,100 each at 16 and 19 = chance, gibberish |
| alphabet + running key read from a known text (K1–K3, sculpture, Morse, Sanborn's source documents and class notes) | 37.7M × 45 settings | 0 |
| error-tolerant: one wrong crib letter, or the second clue offset by 1–3 | 37.7M × 20 settings | 0 |
| error-tolerant with A–Z / KRYPTOS: up to 2 wrong crib letters, any offset | complete | 0 |
| alphabet + autokey (key taken from the message itself): ciphertext feedback lags 1–63, plaintext feedback lags 1–7 and 39–43 | 37.7M × 60 settings | 0 |

### Key chains (`chain.py`)

Theory: a basic key decodes something into a second key, which decodes K4 or
yields a third key that does. A chain that ends in a repeating key of period
≤ 23 on the A–Z / KRYPTOS tableaux is already excluded whatever produced it
(the key is derived from the clues, never guessed). So the chain can only matter
if the final key is a long stream, or is used to build an alphabet.

| chain | size | result |
|---|---:|---|
| level 2: a known text (sculpture ciphertext incl. K4, K1–K3 plaintext, tableau, Morse, Sanborn's documents; any start, stride ≤ 30, either direction) decoded by ANY repeating key, result is K4's key | 49,305,600 keys | 0 |
| level 3: text 1 decoded by any repeating key gives key 2; key 2 decodes text 2 into K4's key (any two contiguous readings) | 56,275,768,320 keys | 1 pass at the chance floor (8 equalities, 0.27 expected), gibberish |
| feedback: K4's own plaintext at any lag, decoded by any repeating key (autokey + keyword) | lags 1–96 | 0 |
| derived keyword `tableau(word, basic key)` (12 basic keys × 415,221 words, either as text; three levels on the themed list) used to build the alphabet, any key ≤ 23 | 64,457,081 × 2 mixing styles | 0; one base-10 digit fit (`PEOPLEIZE`+`ABSCISSA`), digits follow no rule = chance |
| the same derived keyword as the key of an inner tableau layer, outer layer derived | 64,457,081 × 9 × 2 × 8 | 2 passes at 7 equalities (1 expected), gibberish |
| level 2 behind a transposition (`chaint.py`, `chaint.c`): decimation, rail fence, serpentine, rotations, routes, every columnar order of widths 2–9, forward and inverse, both layer orders; contiguous readings | 857,992 transpositions, 1.53 × 10¹² keys | 0 (≥ 9 equalities) |
| themed keys incl. World Clock / Berlin Wall / Egypt words (160 words, every two-word phrase and one-step chain = 165,655 keys) through every keyword test in `keyhunt.py`, plus numeric keys (27,346) and the three-stage recipes | `python chain.py themed`, `recipes.py p4 p5`, `digits.py named` | nothing above chance |
| grid key: shift = row value + column value, widths 2–48, every offset | complete | 0 (only widths ≥ 30, where the clues do not constrain it) |
| repeating key of period 24–30, 36, 48 (24 time zones) | complete | fewer than 2 of the shared slots agree |

Each tableau step may use either alphabet, add or subtract, and re-read the
intermediate key letters in the other alphabet. `python chain.py control`
recovers a planted two-level, three-level and feedback chain.

## 4. Number keys

### Gromark (`gromark.py`, `gromark_sa.py`, `gsolve.c`)

Bean ("Cryptodiagnosis of Kryptos K4", HistoCrypt 2021) argues from the crib
statistics, and from Sanborn's statement that the encryption is letter-for-letter,
that K4 has **no transposition** and may be a Gromark: a short numeric primer
expanded Fibonacci-style (`k[i+n] = k[i] + k[i+1] mod base`) into a non-repeating
digit key, used with mixed plain and cipher alphabets.

| test | size | result |
|---|---:|---|
| validation against Bean's published counts | base 10: 5 and 4 digits; base 8: 5 digits | 39, 3 and 4 survivors — identical to the paper |
| both alphabets from dictionary keywords, any digit key | 345,891 keywords × 2 mixing styles × 5 roles | smallest base that fits is 12 = chance; excluded for base ≤ 11 |
| one keyword alphabet + one arbitrary alphabet, bases 3–26, primer lengths 2–8, every pair of taps | 233,779,728 keys × 685,031 alphabets | 0 reproduce the cribs |
| both alphabets arbitrary: simulated-annealing solver on every surviving primer (standard taps, lengths 3–7) | 61,822 primers | best −4.83, word salad; real English scores −4.30 |

The solver holds the cribs fixed exactly and searches the two alphabets for the
most English-like 97-letter decryption. On a planted Gromark with random
alphabets it finds the true primer and a readable text; wrong primers top out
near −5.3 at low effort and −4.8 at high effort. So this is strong evidence
against a standard-rule Gromark, not proof: annealing can miss.

Also from this round: the Morse text in all published readings as a key (best 9
of 24, chance), and Hill 4×4 (not consistent).

### Digit keys with unknown alphabets (`digits.py`)

| key | size | result |
|---|---:|---|
| named numbers (coordinates, dates, tableau job numbers, keyword-to-number), repeating or Gromark-expanded | ~12,000 keys | 2 fit the clues; both decrypt to gibberish (−5.2) |
| every repeating 8-digit key (periods 1–7 and 9–12 are impossible for any alphabets) | 100,000,000 keys, 68,874 fit the clues | best −5.00, word salad; real English scores −4.30 (annealing solver, so strong evidence rather than proof) |

### Black-box diagnosis (`blackbox.py`)

Measures K4's fingerprints, then simulates 17 cipher families (40,000 messages
each, same crib words in the same positions) to see which reproduce them. The
fingerprint values match Bean's paper exactly.

- Two fingerprints of the 24 known pairs (clue letters land within 3 places of
  their cipher letter; the same clue letter maps to nearby cipher letters) occur
  together in 14–40% of **digit-keyed** ciphers (Gronsfeld, Gromark), 1 in 185
  for Vigenère, and 1 in 3,600 to 1 in 40,000 for one-time pad, running key,
  autokey, the K1/K2 method, transposition + Vigenère and Hill.
- Two fingerprints of the ciphertext (repeated vertical pairs at width 21,
  doubled letters aligned at width 7) are not explained by any family simulated.

### Fixed table plus a base-5 digit (`base5.py`)

Working backwards from the clue letters: each plaintext letter goes to nearly the same
cipher letter every time (A→K,L; S→R,S; T→R,S,V; E→F,G; L→V,Z; C→M,P; N→Q,T). If two
of the 24 clue letters are set aside (position 65, and one of the two O's at 27 / 72),
all the rest fit **cipher = f(plain) + d** with d between 0 and 4, counting in A–Z
order. Shuffled clues do that about 1 time in 350 (3,000 shuffles, two kinds). This is
a sharper form of Bean's observation; five values is a base-5 digit (Mengenlehreuhr;
Scheidt's "different base"). It also explains the doubled letters (NO→QQ, ST→SS).

| question | result |
|---|---|
| which clue letters must be set aside | exactly [27, 65] or [65, 72]; with none or one set aside the best range is 12 and 9 |
| same test counting in KRYPTOS order | no effect (range 11–12, like shuffles) |
| is the table f a keyword alphabet? (`keyedcsp.py` with the two letters set aside) | only with an 18–19-letter "keyword", i.e. no |
| digit key repeating with period 1–11 | none |
| digit key stepping by a fixed amount each round of a period (grid rows) | none |
| Gromark / Fibonacci rule mod 5 | none |
| digits = letters of a known text mod 5 (three numberings, all project texts, any start, both directions) | 0 of 102,720 |

So the "table + small number" shape is supported at about the 1-in-350 level (roughly
1 in 60 after allowing for the choices made), but no rule for the numbers has been found.

**Joint search (`b5solve.c`, `base5.decode_k4`).** With the table unknown and the digits
free, each cipher letter can be one of five plaintext letters; the solver anneals the
table and finds the best-scoring reading exactly (dynamic programming over quadgrams).
Calibration on planted messages with the same clue words (16 each):

| hidden text | best score found | letters right |
|---|---|---|
| English | −3.71 to −3.94 (mean −3.83) | only 53–63 of 97: the solver finds wrong readings that score BETTER than the truth |
| random letters | −3.83 to −4.14 (mean −3.99) | – (all "English" here is manufactured) |
| **K4** | **−4.04 and −4.06** | – |

Two conclusions. The model has too much freedom to decode anything: it writes
fluent-looking text out of random letters (K4 "reads" `…ANDINTERINGADDIFIEHANGED…`,
which is an artefact, not a solution). And K4 scores inside the random-letter range
and below all 16 English plants, so the whole ciphertext gives no support to "fixed
table + free base-5 digits" with ordinary English underneath.

## 5. Keys taken from a text or from the rest of the sculpture

### Public texts as the pad (`padsearch.py`)

If the key is a stretch of a text anyone can look up, the clues dictate 24 of its
letters (13 in a row, a gap of 29, 11 in a row). Searched: 50 Project Gutenberg
texts (King James Bible, Declaration of Independence, Constitution, Webster's
dictionary, Shakespeare, classics; cached in `~/.cache/krypto_k4/texts`) plus the
project's own texts, 95 million letters in all, read every n-th letter for
n ≤ 40 in both directions and as first / last letters of words, 24 table settings,
up to 4 wrong letters allowed. **No text gives 20 or more of the 24 key letters.**

### K3 + ? + K4 as one block (`block.py`)

| test | result |
|---|---|
| key letter for each K4 cell taken a fixed number of rows up / columns across (plain or mirrored) in the 14 × 31 worksheet grid, from K3's ciphertext, plaintext or half-way text | best 8 of 24 over 3,123 placements = chance |
| K3's letters read in the orders its own method uses (grids 4–86 wide; rows, columns, rotations) as a running key, any start | best 9 of 24 = chance |
| the same readings decoded by any repeating key first (key chain) | 0 |

## 6. Physical readings: light, overlays and the compass

### Light projection as the key (`projection.py`)

If sunlight through a K4 letter picks out a letter on the tableau side (or elsewhere
on the cipher side) and that letter is the key, the pairing is roughly an affine map
between the two grids. Swept: column scale −3 to 3, any offset, row shift, shear.
1,699,625 placements × 16 settings: best 10 of 24 clue letters, which is chance.

Curved screen (`projection.py` `run_warp`, `raycast.py` / `raycast.c`): an uneven
but order-preserving projection onto any tableau row puts at most 8 of the 13
EASTNORTHEAST letters in order (chance: about 9). A parametric ray trace of two
cylindrical panels forming the S (arc angles 0.3–3.8 and 0.5–5.9 rad, row pitch
1.0–1.2, every ray azimuth, elevations ±75°, both column directions) gives at best
10 of 24. No surveyed geometry of the sculpture is public (only "about 12 ft × 20 ft,
3-inch letters"), so the model is a sweep over plausible shapes, not a measurement.

### Compass schemes (`compass.py`)

Sanborn's notebook lists a "Compass cipher"; no standard cipher has that name, so
these are the simplest readings.

| scheme | result |
|---|---|
| key = a compass point per letter (8/16/32 points, so a small number): do the clue shifts fit a small range? | best range 20 of 26 (random keys: 21); needs 8 or 16 |
| alphabet wheel turned by a fixed bearing each letter (any real step, floor or round) | best 9 of 24 over 4.2M settings = chance |
| rose points and bearings as number keys, repeating or cumulative | best 6 of 24 |
| moving on the KRYPTOS table by compass steps | equals a small shift per letter, already excluded by the first row |
| KRYPTOS alphabet laid round the rose with S, E, N, W on the cardinal points (thekryptosproject.com diagram; quadrant spacings 18°, 11.25°, 22.5°, 10°) used as an uneven cipher wheel against itself, its mirror, or an even A–Z / KRYPTOS wheel; key = any angle per slot of a repeating key (periods 1–23) or a steadily growing angle | no period fits in any of 24 wheel pairings; steady turn best 9 of 24 (`compass.py` `run_wheel`; planted control recovered) |

## 7. Other cipher families

### Fractionation: changing the number base (`trifid.py`)

Scheidt spoke of changing the "language base", counted 98 characters and said
special characters must be taken into account. With the `?`, K4 has 27 symbols,
the size of a Trifid cube. These tests leave the whole cube or square unknown:
each crib letter forces equalities between digits of ciphertext and plaintext
symbols, and a block length survives only if every symbol can still get a
distinct digit pattern.

| system | block lengths 2–98, every block alignment, 97 and 98 characters, both directions | result |
|---|---|---|
| Trifid (base 3, 27-symbol cube) | all | impossible everywhere |
| Bifid on a 6 × 6 square (base 6) | all | impossible everywhere |
| five-bit fractionation (base 2, 32 codes) | all | impossible everywhere |

Planted Trifid and Bifid messages pass at their true block length and at no other.

### Pair-based ciphers on a grid (`pairs.py`)

Motivated by the ciphertext itself: letter pairs 21 apart repeat 11 times (2 of 3,000
shuffles do as well at that spacing; about 3% after allowing for the 48 spacings
tried), and NSA noted "a slight interval 7 property". A cipher on PAIRS of letters
stacked in a grid would cause that; a letter-at-a-time cipher with a long key would not.

| test | result |
|---|---|
| fingerprint: repeated cipher pairs when K4 is paired vertically in rows of width w (best alignment, 2,000 shuffles each) | width 21 is the most unusual of 48 (6 repeats among 42 pairs, p = 0.002; luck alone gives about 0.02 for the best width), and the four most unusual widths are 21, 7, 42 and 28, all multiples of 7 |
| fixed pair table at width 21 against the clues | the repeats come largely from the doubled letters QQ, ZZ, TT sitting exactly 21 apart; under a fixed pair table those force equal plaintext where the clues differ (N/O under QQ, I/N under TT). 41 of the 42 block alignments are contradicted; one survives (rows starting at letter 6) |
| generic pair substitution, fully known pairs only | cannot be decided: at most 11 fully known pairs and almost no repeated plain pair |
| Slidefair on vertical pairs (table lookup, one key letter per pair): key-free test on fully known pairs, then any repeating key over the pairs; widths 1–48, every alignment, A–Z / KRYPTOS, straight and crossed | best 4 of 10 pairs agree; no repeating key fits |
| four-square / two-square on a 26-letter rectangle (2 × 13, 13 × 2; Playfair is out because K encrypts to K), cipher squares from 161 keyword alphabets, plain squares A–Z or KRYPTOS, vertical pairs at widths 1–48 | 463,260,112 decryptions: best 9 of 24 clue letters; a solution needs all 24 |

## 8. Guessed plaintexts

### Guessing plaintext (`guess.py`)

There is no free way to check a guessed word without the method. `guess.py` uses the
base-5 pattern as a conditional filter: if cipher = table(plain) + 0..4 held everywhere,
each of the 13 clue-type letters (A B C E H I K L N O R S T) would be allowed or ruled
out at every other position. `python guess.py WORD…` shows where a word could stand.

- Ordinary English laid over K4 has 73% of its clue-type letters ruled out; the
  solvekryptos text has 46–48 of 61 ruled out, i.e. no better than arbitrary English.
- `THE` could stand only at 81–83; `THE BERLIN CLOCK` and `WORLD CLOCK` cannot stand
  anywhere. Under the pattern, the three letters before BERLIN would be one of
  A/B/C/H/K/R, then E or O, then O or a non-clue letter.
- 300 themed and common words scanned over every free position: no placement reaches
  the level a scrambled K4 does not also reach (rarity ≥ 4: 0 in K4, 0–2 in scrambles).

So the filter excludes a great deal but confirms nothing, and it is only as good as the
base-5 pattern (about 1 in 60 against chance, and not supported by the joint search).

### The solvekryptos.com reconstruction (`solvekryptos_check.py`, `candidate.py`)

The site's mechanism is `shift = f(cipher letter) + g_row(helper letter) + gate`, with a 26-value `f` card and
four `g` cards. That is 108 adjustable values for 97 letters, and the equations form a forest, so cards exist
for any 97-letter text: 300 of 300 random texts with the clue words in place "decode" exactly, with no gate.
The mechanism is therefore no evidence for the text. Taking the text as true, the key it needs shows no
repeat (best 55% at period 48, shuffles reach 56%), is not the message or ciphertext at a lag, does not read as
text (−7.5), and appears nowhere in 95 million letters of public text. Only Paradigm's checker can confirm or
reject the plaintext itself.
