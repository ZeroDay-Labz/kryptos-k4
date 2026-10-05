/*
 * colcore.h - test one columnar transposition (column order `ord`, width w) against the
 * K4 clues. Shared verbatim by the CPU driver (colsweep.c) and the OpenCL kernel
 * (colsweep.cl), so it uses only plain C: U8 / U64 are typedef'd by the includer and
 * GLOBAL is the address-space qualifier for the tables (empty on the CPU, __global in OpenCL);
 * the tables are passed in as one byte array T laid out by colsweep.py:
 *
 *   T[0..96]                 ciphertext letter codes
 *   T[97..120]               clue positions (0-based)
 *   T[121..144]              clue plaintext letter codes
 *   T[145 + 97*L + x]        x mod L, for L = 0..40
 *   then ST pair lists: nL, and per period: L, npairs, pairs (a, b)...
 * V[24*26] holds, for clue j and cipher letter c, the shift needed under each of the 8
 * alphabet/arithmetic settings, one per byte.
 *
 * Returns the number of hits written to out (each hit: kind 0 MONO / 1 ST / 2 TS, inverse
 * flag, L, equalities, 8-bit setting mask).
 */
#define NCRIB 24
#define NTXT 97
#define MAXTS 40
#define HI 0x8080808080808080UL

static inline U64 eqbytes(U64 x) {            /* 0x80 in every byte of x that is zero */
    U64 y = (x & 0x7F7F7F7F7F7F7F7FUL) + 0x7F7F7F7F7F7F7F7FUL;
    return ~(y | x | 0x7F7F7F7F7F7F7F7FUL);
}

static inline int pack_mask(U64 m) {
    int r = 0;
    for (int k = 0; k < 8; k++) if ((m >> (8 * k + 7)) & 1) r |= 1 << k;
    return r;
}

static int test_order(const U8 *ord, int w, const GLOBAL U8 *T, const GLOBAL U64 *V, int st_off, int mineq, int *out, int maxout) {
    int startc[32], startj[33], nout = 0, acc = 0;
    for (int j = 0; j < w; j++) {
        int c = ord[j];
        startj[j] = acc; startc[c] = acc;
        acc += (NTXT - c + w - 1) / w;
    }
    startj[w] = acc;
    for (int inv = 0; inv < 2; inv++) {
        int kp[NCRIB];
        U64 v[NCRIB];
        int fwd[26], rev[26], mono = 1;
        for (int i = 0; i < 26; i++) fwd[i] = rev[i] = -1;
        for (int j = 0; j < NCRIB; j++) {
            int p = T[97 + j], m;
            if (!inv) m = startc[p % w] + p / w;
            else {
                int q = 0;
                while (startj[q + 1] <= p) q++;
                m = (p - startj[q]) * w + ord[q];
            }
            kp[j] = m;
            int c = T[m], P = T[121 + j];
            v[j] = V[j * 26 + c];
            if (fwd[P] < 0) fwd[P] = c; else if (fwd[P] != c) mono = 0;
            if (rev[c] < 0) rev[c] = P; else if (rev[c] != P) mono = 0;
        }
        if (mono && nout + 5 <= maxout) { out[nout] = 0; out[nout + 1] = inv; out[nout + 2] = 0; out[nout + 3] = 11; out[nout + 4] = 255; nout += 5; }
        /* ST: key follows plaintext order, pairs are fixed */
        int o = st_off, nL = T[o++];
        for (int i = 0; i < nL; i++) {
            int L = T[o++], np = T[o++];
            U64 mask = HI;
            if (np >= mineq)
                for (int q = 0; q < np && mask; q++) mask &= eqbytes(v[T[o + 2 * q]] ^ v[T[o + 2 * q + 1]]);
            else mask = 0;
            o += 2 * np;
            if (mask && nout + 5 <= maxout) { out[nout] = 1; out[nout + 1] = inv; out[nout + 2] = L; out[nout + 3] = np; out[nout + 4] = pack_mask(mask); nout += 5; }
        }
        /* TS: key follows ciphertext order, pairs depend on the map */
        for (int L = 1; L <= MAXTS; L++) {
            char last[MAXTS];
            for (int s = 0; s < L; s++) last[s] = -1;
            U64 mask = HI;
            int cnt = 0;
            const GLOBAL U8 *md = T + 145 + 97 * L;
            for (int j = 0; j < NCRIB && mask; j++) {
                int s = md[kp[j]];
                if (last[s] >= 0) { mask &= eqbytes(v[(int)last[s]] ^ v[j]); cnt++; }
                last[s] = (char)j;
            }
            if (mask && cnt >= mineq && nout + 5 <= maxout) { out[nout] = 2; out[nout + 1] = inv; out[nout + 2] = L; out[nout + 3] = cnt; out[nout + 4] = pack_mask(mask); nout += 5; }
        }
    }
    return nout / 5;
}
