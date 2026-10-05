# Kryptos K4: every known clue, hint and statement

Compiled 1 October 2026 from web research and extended on 4 October 2026 with Sanborn's working papers, the NSA summary and the Smithsonian finding aid. Test results that follow from each clue are in [RESULTS.md](RESULTS.md). Each item carries a verification level:

- **PRIMARY** – read on the cited page (original, published transcript, or archived copy).
- **SECONDARY** – a report or note-taker's account of what was said; the original is not readable.
- **UNVERIFIED** – no readable source found.

Dinner and lunch "quotes" are attendees' notes, not recordings. Treat them as paraphrase.

## 1. Status (as of 4 October 2026)

- **K4 is publicly unsolved.** Neither the authenticated plaintext nor the method has been published.
- **The plaintext exists privately.** Jarett Kobek and Richard Byrne found it in Sanborn's papers at the Smithsonian on 2 Sep 2025; Sanborn confirmed it; the material is sealed until 2075. Kobek (June 2026): "There will never be a moment in which the plaintext is published by me." PRIMARY (Zona Motel interview; Wired 12 Jun 2026).
- **The archive sold for $962,500** on 20 Nov 2025 (RR Auction). The buyer, revealed 12 Jun 2026, is the crypto investment firm **Paradigm**. PRIMARY (paradigm.xyz/writing/kryptos; Wired).
- **There is a public answer checker.** In March 2026 Sanborn typed the K4 plaintext into a laptop; a SHA-256 hash went to a cloud key service to make a verification tag. Anyone can submit a candidate plaintext at paradigm.xyz/kryptos for $1. No hash is published, so candidates cannot be checked offline. Paradigm says it has not looked at the answer.
- **K5 exists but is unreleased.** Paradigm holds its ciphertext: "We plan to release K5 in the future."

## 2. Hard facts about K4

| Fact | Source | Level |
|---|---|---|
| 97 characters, `OBKR…KCAR` | Sanborn repeatedly; NPR 2005, 2020 | PRIMARY |
| `NYPVTT` = `BERLIN`, positions 64–69 | NYT 20 Nov 2010 | PRIMARY |
| `MZFPK` = `CLOCK`, positions 70–74 | NYT 20 Nov 2014 | PRIMARY |
| `QQPRNGKSS` = `NORTHEAST`, positions 26–34 | NYT 29 Jan 2020 | PRIMARY |
| `FLRV` = `EAST`, positions 22–25 | given privately Apr 2020, public Aug 2020 (elonka.com) | PRIMARY |
| Position 74: plaintext K, ciphertext K (a letter can encrypt to itself) | Wikipedia; Bean 2021 | PRIMARY |
| K4 itself has no carving error: "that one's actually safe and sound and fairly accurate" | Sanborn, NPR 21 Apr 2006 | PRIMARY |
| "It could be done with pencil and paper" | Sanborn to A.J. Jacobs, 2020 | PRIMARY |
| Solving does not need access to CIA grounds | Sanborn, Wired 2005; NOVA 2007 | PRIMARY |
| Scheidt counted "98 characters left" (i.e. including the `?`) | Wired 2005 | PRIMARY |

Sanborn hedged on the length once ("Whether it's 97, whether it's 100, I seem to like to manipulate the information", CNN 2005) but has otherwise held to 97.

## 3. Sanborn on the method

- **"Matrix codes" combined with the table.** "It's also well-known that I did use some matrix codes Ed gave me, and I have also designed visual systems for encoding." (Wired, 20 Jan 2005, PRIMARY.) "I use a combination of systems. The matrix possibly, and then this [the Vigenère table], in combination with one another… sometimes I used double matrixes and triple matrixes." (CNN B-roll transcript 2005, PRIMARY.) The CIA's own page: the artist "used this 'chart' system, in combination with matrix coding systems".
- **How many techniques on the whole sculpture:** "I would think five or six." (Wired 2005, PRIMARY.)
- **Modified systems.** Scheidt "gave me some ideas for… systems that didn't necessarily depend on mathematics… coding systems that I could then modify in a myriad of ways. So that even he would not know what it says." (Smithsonian oral history, 2009, PRIMARY.) Asked in 2013 whether he changed or invented systems: "probably". Why K4 is different: "it's just harder." (email Q&A, kryptosfan, PRIMARY for the blog.)
- **Not mathematics.** "…being an artist, I have an advantage in that I can employ methods that don't have anything to do with mathematics." (NPR 2020, PRIMARY.) "Who says it is even a math solution?" and "I was fortunate not to understand mathematics, probably in my ability to make the code." (Scientific American, 12 Nov 2025, PRIMARY.)
- **Visual and spatial systems.** "There are encoding systems which use pattern, light and shadow… I like to use spatial systems of encoding and decoding." (NPR 1999, SECONDARY.)
- **The coding charts matter.** Of the K1/K2 charts he gave the NYT in 2010: "once the Krypto-philes study it in a forensic manner, there might be revelations in there." (NPR 22 Nov 2010, PRIMARY.)
- **Letter-for-letter?** At a 2019 lunch an attendee reported: "BERLINCLOCK in plain matches directly with NYPVTTMZFPK. It is a one-to-one match." Elonka Dunin's account of the same event is that Sanborn "backed off" and would commit only to length 97 and BERLIN starting at position 64. SECONDARY and contested. At the 2013 ACA dinner he reportedly confirmed N=B, Y=E, P=R, V=L, T=I, T=N. SECONDARY.
- **Nobody else has the method.** "They do not have the key. They don't have the method with which it's deciphered… nobody has the method but me." (AP, 12 Nov 2025, PRIMARY.)

## 4. Scheidt on the method

- **Masking.** "The first three processes were designed so that a person could, through cryptographic analysis, have access to the English language. And the last process, I masked the English language so it's more of a challenge now." "…with this other technique (in the fourth part), I disguise that. So… you need to solve the technique first and then go for the puzzle." "The masking technique may not be known." (Wired, 21 Jan 2005, PRIMARY.) "The first challenge then is, well, what masking technique was used?" (NOVA 2007, PRIMARY.)
- **Order of masking and encryption:** asked directly in 2015, he gave no clear answer ("Let me defer…"). PRIMARY (low-fidelity transcript).
- **More than one stage.** Asked whether K4 is one-stage like K1–K3: "no, I would consider it more than one stage." "…it lends itself to building layers or you could mix and match which is a certain amount of that took place." (2015 workshop transcript, PRIMARY.)
- **Four processes.** "There are four different processes. Two of them are similar and the other two are different things." (Wired 2005, PRIMARY.) "There was a change in the methodology… It was intentional." (Baltimore Sun, 17 Mar 2000, PRIMARY.)
- **Classical.** "Classical cryptography… includes substitution and it includes transposition." (NOVA 2007, PRIMARY.) Systems were "classical cryptography, 'not something weird'." (2006 notes, SECONDARY.) He used methods "that had a historic basis… that didn't compromise any current methods." (Washington Post 1999, PRIMARY.)
- **Analog, pencil and paper.** "This is analogue… you don't see a lot of analog answers in cryptography in usage today." (2015, PRIMARY.) Part 4 "is designed to be solved in a straight-forward manner with pencil and paper." (2003 notes, SECONDARY.)
- **"The key is the algorithm."** "In a modern digital system, the 'key' is the keyword or number… In analog systems (as used in Kryptos) the 'key' is the algorithm." (Dunin's 2003 notes, SECONDARY.)
- **Keys are at the sculpture.** "It was necessary to recover the keys, and… the keys were concealed at the sculpture." Parts 1–3 "had been solved without recovering the key first." (2003 notes, SECONDARY.) David Stein was told his K1–K3 solution "is correct, but you didn't do it in the way I intended." (Washington Post 1999.)
- **The message carries its own key.** "Imagine that you have an operative… It could be 15 years down the road… You have to assume that they will not remember the 'key'. How do you deliver a message in such a way that it conveys not only the encrypted data, but also the key?" (2003 notes, SECONDARY.)
- **Multiple keys.** "Part of the code was designed to be solved with multiple keys — a code where different keys could be given to different people, but they'd all still be able to solve it." (2003 notes, SECONDARY.)
- **Field cipher.** "K4 cryptography is similar to what would be provided agents or pilots in case of capture." and "[K4 cryptography] is not mathematical (although this does not preclude it being modeled mathematically), it is simple, can be remembered, and executed years later when used with the correct key word/s." (Zola dinner 2011, relayed by Hannon, quoted in Bean 2021. SECONDARY; the brackets show it is partly paraphrase.) Supported on record in 2015: "I used to make those codes, for captured people."
- **Number base.** 2015: "the thing that I had thought of and I was asked not to do… I could have moved to a different math base… different folks thought that's not fair." (PRIMARY.) 2020, per Bean quoting the Jacobs interview: "if you can change the language base then it becomes in my favor… when it was used as the mask it was current, 2020 secret." (SECONDARY.) The two statements pull in different directions.
- **Steganography.** "I used a bit of stego when designing the fourth part of Kryptos"; later: "there was a piece relating to Stego, but [I] did not state how or in what context." (2004 talk, SECONDARY, source labelled unreliable but partly confirmed.)
- **Special characters.** "Special characters don't work, you have to take that into account." (2015, PRIMARY.)
- **Every letter is used.** "Every letter in K4 will be used, 'like the other sections'." (2005 notes, SECONDARY.)
- **Dead ends.** "He had built in some dead-ends to throw some people off the track." (2003 notes, SECONDARY.)
- **Scheidt never checked K4.** "I know what the message was to be. (But) since he's the one who had the chisel in his hands, there could be some changes." (Wired 2005, PRIMARY.) "To be honest, I don't know the answer. After Jim finished the sculpture, I never went back to check the code." (CIA.gov 2008, PRIMARY.)
- **Difficulty.** "Its intent was to last roughly five years." (Baltimore Sun 2000, PRIMARY.) "Nine out of ten" appears only in a 2021 article by Bean with no stated origin. UNVERIFIED as a Scheidt quote.
- **Disowned:** a 2007 remark that K4 uses a system "unknown to anyone on the planet"; in 2013 he did not recall saying it.

## 5. Content and theme

- "All of the passages are fiction writings of mine [except Carter]." (CNN transcript 2005, PRIMARY.)
- "The plain text itself is cryptic and alludes to things beyond Kryptos." (oral history 2009, PRIMARY.)
- "It's a 97-character phrase. And that phrase is in itself a riddle. It's mysterious. It's going to lead to something else." (NPR 2020, PRIMARY.)
- "The final passage will lead in several directions. The word directions is — I use intentionally." (NPR 2010, PRIMARY.)
- November 2025 letter (excerpts, PRIMARY for the excerpts):
  - "Two events had a significant role to play while I was writing the plain text of Kryptos in 1988. The first was my second trip to Egypt in late 1986, and the second was the fall of the Berlin Wall."
  - "The Berlin Clock in K4 is the World Clock in Berlin that was the gathering place for the crowds that brought down the Berlin wall."
  - "The codes of Kryptos from the morse code at the beginning through K5 are about delivering a message."
- In 2014 he had pointed at the Mengenlehreuhr: "You'd better delve into that particular clock", adding "There are several really interesting clocks in Berlin." (NYT, PRIMARY.)
- "Not that it doesn't say something about clandestine trade craft." (Wired 2005, PRIMARY.)
- Reporter paraphrases, no direct quote: the plaintext "is not standard English and would require a second level of cryptanalysis" (Wired 2009); "the text of K4 is actually an instruction for how to solve it" (Wired, 14 Aug 2025).

## 6. After decryption: the riddle and K5

- "Once the plate is deciphered I'm not convinced the true meaning will be clear even then. There's another deeper mystery." (ABC 1991, PRIMARY.)
- "You do decipher it as in removing layers of an onion… when you decipher one part, it might hark back to the first part… there will be a relationship between all parts when the fourth part is deciphered." (CNN transcript 2005, PRIMARY.)
- "I will say that I have left instructions in the earlier text that refer to later text." (Wired 2005, PRIMARY.)
- "In part of the code that's been deciphered, I refer to an act that took place when I was at the agency and a location that's on the grounds… I made reference in the encoded text to something I could have done there." (Wired 2005, PRIMARY.)
- A bronze USGS marker was once buried "adjacent to Kryptos… they had removed it, but it is important." (2013 notes, SECONDARY.)
- **K5:**
  - "Even when K4 has been solved, its riddle will persist as K5." (open letter Aug 2025, PRIMARY.)
  - It is 97 characters, will appear in a public space, uses "a similar coding system to K4", and "both 97-letter messages will share some of the same coded words in the same position", with BERLINCLOCK in the same place. (Scientific American and Washington Post, Nov 2025, PRIMARY paraphrase.)
  - The auction lot calls it "an unpublished 1988 alternate of the K4 plaintext and coding chart". (RR Auction, PRIMARY.)
  - "K5 cannot be solved without K4." (2013 notes, SECONDARY.)

## 7. Errors and misspellings

- **IQLUSION (K1).** Sanborn's own chart spells ILLUSION correctly and writes the key once as `PALIMPCEST`; the C produces the ciphertext K. So the sculpture copies the worksheet, and the "Q" only appears when decrypting with the correct key. PRIMARY (NYT chart image, 2010).
- **UNDERGRUUND (K2).** The chart has it right (ciphertext E); the copper has R. The change happened at cutting. Antipodes has the correct E. PRIMARY.
- **DESPARATLY (K3).** No Sanborn statement specific to this word was found.
- **Intentional?** "Sanborn has said that those two errors — iqlusion and undergruund — are deliberate… it wasn't what they were that was so important, as their orientation or positioning." (Elonka's FAQ, PRIMARY.) "That's an ancient tool for making codes more difficult to crack… if you want to say it's intentional, it's intentional." (CNN 2005, PRIMARY.) But also: "There was nobody I could ask to proofread KRYPTOS." (Jacobs 2020, PRIMARY.)
- **The omitted letter in K2.** A missing ciphertext S makes the ending read `IDBYROWS` instead of `XLAYERTWO`. Sanborn, April 2006: solvers "were, in fact, missing a clue." Wired says he removed it "for aesthetic reasons". PRIMARY. Scheidt, 2013: it "may not have been a mistake after all. Sometimes in spycraft you deliberately do these things." SECONDARY.

## 8. Physical anomalies

- **Raised letters.** In the first row of K3 (`ENDYAHROHNLS…`) the letters Y, A and R sit a couple of centimetres high; the five-letter group is `DYAHR`. No explanation from Sanborn. PRIMARY (Elonka, with rubbings).
- **Extra L on the tableau.** Row N has 32 characters, so the right-hand column reads H, I, L, L. Bauer, Link and Molle read this as a pointer to the Hill cipher. It is on the same row as the raised letters. PRIMARY for the fact.
- **Tableau** is "intentionally flipped" (CIA page).
- **Morse code** (entrance slabs), with isolated dots shown as `e`:
  ```
  e e VIRTUALLY e | e e e e e e INVISIBLE
  DIGETAL e e e | INTERPRETATI(cut off)
  e e SHADOW e e | FORCES e e e e e
  LUCID e e e | MEMORY e
  T IS YOUR | POSITION (e)?
  SOS
  RQ
  ```
  `DIGETAL` is misspelled. The stream is palindromic: read backwards it is still valid Morse. PRIMARY.
- **Compass rose and lodestone** at the entrance. Blog authors claim the needle points east-northeast; no measurement or Sanborn confirmation. UNVERIFIED as fact.
- **K2 coordinates** (38°57′6.5″N 77°8′44″W) point 100–175 ft southeast of the sculpture.
- **The `?` before `OBKR`.** Usually assigned to K3. Counting it gives 98 = 7 × 14.
- **Antipodes** (Sanborn's 1997 copy of the text): K4 is letter-for-letter identical to the CIA sculpture and follows K3 directly. The only differences anywhere are the corrected UNDERGROUND and two dots in "W.W." PRIMARY as a transcript diff.

## 8a. Worksheets and community observations (added 4 Oct 2026)

- **K3 + `?` + K4 worksheet is 14 lines × 31 characters** (NOVA 2007 video, "Top #4", circled 3). 336 + 1 + 97 = 434 = 14 × 31, so K4 sits as 4 letters at columns 27–30, then three full rows of 31. The K1/K2 charts are also 31 cells wide; the copper line lengths were adjusted afterwards. SECONDARY (kryptos site description of the video frame).
- **Sanborn's 2010 K4 sheet** numbers K4 1–97 and puts the `?` with K3, unnumbered. PRIMARY (NYT PDF).
- **Worksheet note "? on line 4, 8, 10, 25 not coded"** (kryptosbot.com archive image, via Reddit). SECONDARY.
- **K1/K2 chart forensics:** IQLUSION comes from the key being written `PALIMPCEST` on the sheet; UNDERGRUUND arose after the sheet. So IQLUSION was not a visible choice on the plaintext line. SECONDARY (third-party analysis of the NYT image).
- **Buried USGS marker** next to the sculpture, later removed, "but it is important". SECONDARY (2013 dinner notes).
- **Reddit `EGYPTXQUNDIG`:** `OBKRUOX` with key `QUXXLAT` on the KRYPTOS tableau gives `EGYPTXQ` (arithmetic verified here). The key is assembled after the fact from anomaly letters with two speculative X's, a random 5-letter key yields some dictionary word 1 time in 540, and the same method gives key `RDUMRIYWOYNKY` / `ELYOIECBAQK` at the confirmed clues, which is not related. Treated as coincidence.
- **Mirror / shadow idea** (letters are cut through; seen from behind or as a shadow the grid is flipped): tested in `masks.py mirrors`, see README.

- **solvekryptos.com mechanism checked (`solvekryptos_check.py`).** Its machine is `shift = f(cipher letter) + g_pass(helper letter) + gate`, with a 26-value f card and four g cards. That is 108 card cells for 97 equations, and the equations form a forest (no cycles), so cards exist for ANY 97-letter text: 300 of 300 random gibberish texts with the clue words in place "decode" exactly, with no gate at all. The mechanism is therefore no evidence for the reconstructed plaintext, which stays unverified (only Paradigm's $1 checker can test it).

- **NSA summary (declassified 2014, DOCID 4145037; read in full 4 Oct 2026, PRIMARY).** NSA read K1–K3 in 1992 after Webster challenged them; "dozens" of NSA analysts worked K4 and "no one has ever gotten that last part". On K4: "a fairly flat distribution, although there are eight Ks", "no long repeats, but there is a slight interval 7 property"; plaintext and ciphertext autokey were tried without result; the author asks whether K4, like K2, has a missing letter. NSA describes K3 as a 4 × 86 matrix with columns taken bottom-to-top every 7th column to the left, the column order being the KRYPTOS numeric key (4 1 5 2 6 3 7), so K3's transposition is itself keyed by KRYPTOS with interval 7. Two passages near K1 and at the end are still redacted. That recipe applied to K4 (any rows, step, start, direction) is tested in `masks.py stepped`.

## 8b. Sanborn's working papers (kryptosbot.com/archive, photographs from a March 2026 visit to the Archives of American Art; images read directly 4 Oct 2026)

- **Dedication remarks, 3 Nov 1990 (typescript, IMG_1249). PRIMARY.** "Around to the other side there are two plates of copper and that is Vigenère's table… I used that table to encipher the top plate. This top plate is enciphered by that chart over there… The bottom plate is enciphered in a much more difficult fashion and the whole piece is designed to unveil itself, as if you were to pull up one layer, then you can come to the next… **There are two systems of enciphering the bottom text.** No one really asked me if there are two systems to encipher the bottom text until today at sort of the eleventh hour, and yes, there are two separate systems and that is a major clue in itself." The bottom plate is K3 + K4. He ties the table to the TOP plate only.
- **Notebook list (IMG_1569). PRIMARY.** "Beaufort cipher / Compass cipher / Morse code / Alphabet code", then "Cryptonyms".
- **Handwritten KRYPTOS tableau (IMG_1223, IMG_1224). PRIMARY.** 26 rows of the KRYPTOS alphabet, 30 wide, no row labels, plain A–Z + ABCD row at the bottom. Three cells are circled (my reading of the photograph): **T** in the row beginning B (9th row, 23rd column), **K** in the row beginning G (14th row, 14th column), **H** in the row beginning Q (21st row, 21st column). K and H lie on the main diagonal; the row beginning G is the sculpture's row N, the one with the extra L. Against the K4 clues only one pair touches a circled cell (position 25, T/V), which is chance level.
- **Notes (IMG_1340, site transcription). SECONDARY.** "Keywords chosen for their mysterious nature AND how they fit into the Aesthetics"; "Extra L at end of line, Bottom chart s[…]".
- **"He lied" (IMG_1384, site transcription). SECONDARY.** Two coordinate sets, 38° 57′ 6.5″ N and 37° 57′ 6.5″ N (both 77° 8′ 44″ W), with "He lied" circled between them.
- **Other notes (site transcriptions):** "encrypted message is included within set of modern day font characters. Could be done to shade an area"; "I wrote the plain text to be enigmatic… I encoded it to make it challenging"; "Avoid the pitfall of the obvious"; "Frequency Tables forming".

- **Compass rose (published photographs, viewed 4 Oct 2026).** The engraved rose has only the four letters N, E, S, W and one long needle lying roughly on the ENE–WSW line, with the lodestone beside it. No alphabet or 16/32 points are engraved. A diagram from thekryptosproject.com ("Front Compass Strata") overlays the KRYPTOS alphabet round the circle: in that alphabet S, E, N, W occur in order, 5, 8, 4 and 9 places apart, so they can sit on the four cardinal points; ENE (67.5°) then falls exactly on G and 250° on Z. That overlay is the site's hypothesis, not part of the stone. Tested as a cipher wheel in `compass.py`: no fit.

Further archive images read directly (4 Oct 2026, all 42 downloaded, 13 viewed):

- **IMG_1555, sketch:** a sheet labelled "Code Breaker" lying at an angle on a sheet labelled "Coded", both with wavy text lines. An overlay / grille idea. Tested as one plate laid on the other in all 8 orientations (`projection.py` `run_overlay`): best 8 of 24, chance.
- **IMG_1518, compass rose studies:** three pencil roses on graph paper, N/E/S/W only, each with one needle running WSW to ENE at a slightly different angle. No letters or numbers.
- **IMG_1384:** "38° 57 6.5 N / 77° 8 44 W" and "37° 57′ 6.5″ / 77° 8′ 44 W" with "He lied" circled. One degree of latitude apart.
- **IMG_1340 (reread):** talking points at the foot of a to-do list: "Code originally developed to keep things secret in the military"; "Keywords chosen for their mysterious nature and how they fit into the aesthetics"; "Extra L at end of line, bottom chart section"; "? on line 4, 8, 10, 25 [not] coded".
- **IMG_1221:** amber map-like transparency over the handwritten table, with a loose vertical strip of the KRYPTOS alphabet taped beside it (a slide for working the table by hand).
- **IMG_1202:** enciphering worksheet for a later Russian-text piece: blocks of three rows, plaintext / МЕДУЗА repeated / ciphertext. The same working method as the K1/K2 charts.
- **IMG_1238:** typesetting job slip "JOB 55741-0001-01 JIM SANBORN REV:11-10 EXP:11-10 MW SIZ: 21.06" with sample newspaper text; a font proof, not a cipher.
- **IMG_1236:** "encrypted message is included within set of modern day font characters. Could be done to shade an area", under a sketch of a slab with symbols.
- **IMG_1410:** "I wrote the plain text to be enigmatic and… I encoded it to make it challenging… in 1988 codes were forgotten arts…" (notes for a talk).

## 8c. Smithsonian finding aid: Jim Sanborn papers, circa 1950–2023 (Archives of American Art)

Read 4 Oct 2026 from Internet Archive copies (snapshots of Feb–Mar 2025 and Nov 2025); the live
site answers automated requests with a verification page. The finding aid lists folders only;
no Kryptos document is digitised ("Image assets for this folder have not been fully processed").

- **Series 3, Commission Files — "Kryptos" CIA Headquarters, Box 6:** Sculpture 1993–2009 (folders 9–10); Book (11); Pre-Production and Notes, 1990[–1999] (12; shown as Box 6 Folder 10 in a later snapshot); Stencil Patterns, circa 1988 (13); **Codes Research, undated (14)**; Dedication, 1990 (15); Correspondence, Attempts at Deciphering Codes, 1988–2015 (16–20); **Cracked Codes and Charts, 1999–2013 (21–23)**; Articles (24); Miscellaneous, 2003–2009, with an unlabeled CD (25).
- **Series 8 / 9 (photographs etc.):** "Kryptos", "Code Room", "Kryptos Sculpture, 1978–1991".
- **Series 10 (video):** ABC, CBS and CNN coverage of the CIA sculpture, 1991; "Network Coverage Jim Sanborn's Kryptos Project".
- **Access as of the March 2025 snapshot:** "open for research", originals by appointment at the Washington, D.C. Research Center only. Press reports say the Smithsonian sealed material after the September 2025 discovery; kryptosbot.com's photographs are dated to a March 2026 visit, so some folders evidently remained available. Current status not verified.

## 9. Statistical observations on the ciphertext

All reproduced by `blackbox.py` unless noted. Main source: Bean, "Cryptodiagnosis of Kryptos K4" (2021).

- Index of coincidence 0.0361 (flat; random is 0.0385).
- **Width 21:** 11 repeated vertical letter pairs. About 1 in 6,750 by chance.
- **Width 7:** five of six doubled letters (BB, QQ, SS, ZZ, TT) start in the same column. With the `?` prefixed (98 = 7 × 14) they sit in the last two columns.
- **`DIAWINFBN`** (positions 56–64): each of the first five letters is 5 less than the letter four places to its right.
- **Clue letters stay close.** Plaintext letters in K-R-Y-P-T-O-S map to ciphertext letters at most a few places away (S→R, T→V, O→Q, R→P, T→R, S→S, T→S, R→P, K→K). About 1 in 5,520.
- **Same letter, nearby cipher letters.** Mean distance 3.6 between ciphertext letters standing for the same clue letter. About 1 in 240.
- Plaintext R maps to P twice (positions 28 and 66).
- `PRNG` appears in both K3 and K4.
- Bean's inference: no transposition; a Gromark-type digit-key cipher.

## 10. The 2025 discovery

- What was found: five pages of "scrambled text" — copies Sanborn made in 1990 for the CIA's "Department of Historical Intelligence", for which he "cut sentences into strips and taped them together out of order". Kobek: "It's exactly the right length. It makes semantic sense… the known plaintexts are exactly in the right position." PRIMARY (RR Auction; Zona Motel).
- Sanborn: "What they found was scrambled text, and not by solving the cryptogram. They did not solve K4 and they certainly did not find the key." "K4 has been discovered and it points in the direction of K5." PRIMARY.
- Kobek: "this is not necessarily something that's ever going to be solved by cryptanalysis or STEM or math." PRIMARY.
- The auction lot lists "the original coding system for K4" and coding charts, which implies a chart-based hand method.

## 11. Check of commonly repeated claims

| Claim | Verdict |
|---|---|
| "Position 27" rule | **Partly.** It was a friend's screening question, NYT 2010: "'What do you have in letter-position 27?'… If that's not the same letter, 'Game over.'" With NORTHEAST at 26–34, position 27 is `O`. |
| Sanborn used steganography; "the most obvious key" unnoticed | **Partly.** "The most obvious key to the sculpture, nobody has picked up on" is Sanborn (WSJ 2005, SECONDARY). The steganography remark is Scheidt's, not Sanborn's. |
| "Harks back to the first part"; onion | **Confirmed** (CNN transcript 2005). |
| K4's text deals with finding or opening a secret | **Not found.** The nearest quotes are about K3 or the plaintext in general. |
| "I made reference in the encoded text to something I could have done there." | **Confirmed** (Wired 2005). He means the already-solved text. |
| "X-rays everything you do every night" | **Confirmed** (Wired 2005). |
| His plan was to "fool" the CIA | **Partly.** He said "I tricked them" and "I duped them"; no "fool" or "from the beginning". |
| BERLIN CLOCK is the World Clock | **Confirmed** (Nov 2025 letter). |
| Solved passages contain clues to K4 | **Partly.** Mostly reporter paraphrase; his words are "I have left instructions in the earlier text that refer to later text." |
| "Who says it is even a math solution?" | **Confirmed** (Scientific American 2025). |
| "(CLUE) what's the point? Power resides with a secret, not without it." | **Confirmed** (open letter Aug 2025). |
| Scheidt: "agents or pilots in case of capture"; "not mathematical… simple… key word/s" | **Partly.** One login-walled post relayed through Bean. |
| Scheidt: "the algorithm itself is the key" | **Partly.** Notes say "the 'key' is the algorithm". |
| Scheidt masked the English | **Confirmed** (Wired 2005). |
| Scheidt: "more than one stage" | **Confirmed** (2015 workshop). |
| Scheidt on "language base" | **Confirmed in substance**, but in 2015 he said he was asked *not* to change base. |
| Scheidt: nine out of ten difficulty | **Not located** as a Scheidt quote. |
| Scheidt: Sanborn may have changed things while carving | **Confirmed** (Wired 2005). |
| The Smithsonian texts (EO 12333 etc.) as K4 plaintext | **Impossible.** They do not contain the clue words at the clue positions. |
| The solvekryptos.com 97-letter text | **A reconstruction**, by its own statement not the authenticated plaintext. |

## 12. What the clues imply for the search

Where each line of evidence points, and what testing it showed (details in [RESULTS.md](RESULTS.md)).

1. **A mask plus a cipher, in two or more stages.** "Solve the technique first and then go for the puzzle." Tested: two table layers, keyword alphabets, a masking table of any kind plus any repeating key (with up to two slips), transposition plus table. All negative.
2. **"Matrix" plus the Vigenère table; "two systems of enciphering the bottom text".** K3 is a matrix transposition. Tested: every columnar order of widths 2–15, rotations, routes, mirrors, K3's own recipe, each with any repeating key and with chained keys. All negative. Sanborn ties the table to the *top* plate only, which leaves open that K4 does not use the table at all.
3. **The message carries its key; the keys are at the sculpture.** Tested: autokey of every kind, every regular reading of both sides of the sculpture as a key, K1–K3 plaintext, the Morse text, key chains through all of these, light-projection and overlay pairings. All negative.
4. **Small-number key.** The clue letters behave like a fixed table plus a number from 0 to 4 once two letters are set aside (about 1 in 350 by shuffle test; roughly 1 in 60 allowing for choices). No rule for the numbers was found, and the rest of the ciphertext does not support it.
5. **Interval 7.** Scheidt counted 98 characters (7 × 14); NSA noted "a slight interval 7 property"; five of the six doubled letters start in the same column of a 7-wide grid, and QQ, ZZ, TT are exactly 21 apart. Unexplained by every method tested.
6. **"Compass cipher".** In Sanborn's notebook next to "Beaufort cipher". The engraved rose has only N, E, S, W and one needle on the ENE–WSW line. Simple compass schemes and the KRYPTOS-alphabet wheel were tested: negative.
7. **K5 is the best future lever.** It uses a similar system and shares coded words in the same positions. If the key depends only on position, the two ciphertexts together expose it.

## Sources

- Bean, "Cryptodiagnosis of Kryptos K4", HistoCrypt 2021: https://ecp.ep.liu.se/index.php/histocrypt/article/view/153
- 2015 Scheidt workshop transcript: https://scienceblogs.de/klausis-krypto-kolumne/kryptos-workshop-transcript/
- Wired 2005 Sanborn Q&A: https://www.wired.com/2005/01/questions-for-kryptos-creator/
- Wired 2005 Scheidt interview: https://www.wired.com/2005/01/inside-info-on-kryptos-codes/
- CNN 2005 B-roll transcript: https://elonka.com/x/2005CNN.html
- Dunin's 2003 notes and other hints: http://scirealm.org/KryptosHints.html
- Elonka Dunin's Kryptos site and FAQ: https://elonka.com/kryptos/ , https://elonka.com/kryptos/faq.html
- Sanborn's August 2025 open letter: https://elonka.com/kryptos/OpenLetterAug2025.html
- Scientific American, final clues (12 Nov 2025): https://www.scientificamerican.com/article/cia-kryptos-puzzle-creator-releases-final-clues/
- RR Auction, "discovered, not solved": https://content.rrauction.com/kryptos-k4-discovered-not-solved-heres-what-actually-happened/
- Zona Motel interview with Kobek and Byrne: https://zonamotel.substack.com/p/interview-kryptos-k4-uncovered-jarett
- Paradigm, "Project Kryptos": https://www.paradigm.xyz/writing/kryptos
- Wired, 12 Jun 2026: https://www.wired.com/story/crypto-guys-bought-the-answer-to-the-cias-mysterious-kryptos-sculpture/
- NYT clue articles: https://www.nytimes.com/2010/11/21/us/21code.html , https://www.nytimes.com/interactive/2020/01/29/climate/kryptos-sculpture-final-clue.html
- Smithsonian oral history (2009): https://www.aaa.si.edu/collections/interviews/oral-history-interview-jim-sanborn-15700
- kryptosfan notes: https://kryptosfan.wordpress.com/2013/10/28/kryptos-notes-from-the-aca-convention/
- Antipodes transcript: http://scirealm.org/Antipodes.html
- NSA, "The CIA Kryptos Sculpture: a summary of previous work…" (declassified 2014): https://www.nsa.gov/portals/75/documents/news-features/declassified-documents/cia-kryptos-sculpture/KRYPTOS_Summary.pdf
- Sanborn papers, photographs and transcriptions (kryptosbot.com): https://kryptosbot.com/archive/
- Jim Sanborn papers finding aid, Archives of American Art: https://www.aaa.si.edu/collections/jim-sanborn-papers-22298
- The Kryptos Project, strata and compass diagrams: http://www.thekryptosproject.com/kryptos/pok/strata.php
- CIA, "Kryptos" sculpture page: https://www.cia.gov/legacy/headquarters/kryptos-sculpture/
- Wired / Steven Levy, Sanborn on AI-generated "solutions" (2025)
- solvekryptos.com reconstruction (unverified): https://solvekryptos.com/solution
