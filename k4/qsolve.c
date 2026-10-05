/*
 * qsolve.c - simulated annealing for a repeating-key tableau cipher whose
 * alphabets AND key are all unknown (Quagmire I-IV with arbitrary alphabets).
 *
 * Model:  C_i = CA[ rankPA(P_i) + k[i mod L] ]            (mode 0)
 *         C_i = CA[ k[i mod L] - rankPA(P_i) ]            (mode 1, Beaufort)
 * Unknown: PA and/or CA (26! each) and the L shifts. Either alphabet can be
 * fixed (a 26-letter string instead of "-"), or the two tied together (Quagmire III).
 * Objective: quadgram log-probability of the whole decryption, minus a penalty
 * for every clue letter not reproduced. gsolve.c needs the key given; here the
 * key is searched too, so the 24 clue letters alone need not decide the period.
 *
 * usage: qsolve quad.bin CT mode L PA|- CA|- tie steps restarts [penalty]
 * prints one line per restart: score mismatches plaintext PA CA key
 * build: gcc -O3 -march=native -fopenmp -o qsolve qsolve.c -lm
 */
#include <math.h>
#include <omp.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAXN 128
static float Q[26 * 26 * 26 * 26];
static int N, CT[MAXN], CP[MAXN];            /* CP[i] = clue letter at i, or -1 */
static int MODE, L, TIE, FIXP, FIXC;
static double PEN = 8.0;

typedef struct { int pr[26], pinv[26], cr[26], k[32]; } State;

static inline uint64_t rnd(uint64_t *s) { uint64_t x = *s; x ^= x << 13; x ^= x >> 7; x ^= x << 17; return *s = x; }
static inline int ri(uint64_t *s, int n) { return (int)((rnd(s) >> 11) % (uint64_t)n); }
static inline double ru(uint64_t *s) { return (rnd(s) >> 11) * (1.0 / 9007199254740992.0); }

static inline double score(const State *S, int *pt, int *mis) {
    int m = 0;
    for (int i = 0; i < N; i++) {
        int r = MODE ? S->k[i % L] - S->cr[CT[i]] : S->cr[CT[i]] - S->k[i % L];
        r %= 26; if (r < 0) r += 26;
        pt[i] = S->pinv[r];
        if (CP[i] >= 0 && CP[i] != pt[i]) m++;
    }
    double s = 0;
    for (int i = 0; i + 3 < N; i++) s += Q[((pt[i] * 26 + pt[i + 1]) * 26 + pt[i + 2]) * 26 + pt[i + 3]];
    *mis = m;
    return s - PEN * m;
}

static void set_alpha(const char *a, int *rank) { for (int r = 0; r < 26; r++) rank[a[r] - 'A'] = r; }
static void shuffle(int *rank, uint64_t *rs) {
    for (int i = 0; i < 26; i++) rank[i] = i;
    for (int i = 25; i > 0; i--) { int j = ri(rs, i + 1), t = rank[i]; rank[i] = rank[j]; rank[j] = t; }
}

int main(int argc, char **argv) {
    if (argc < 10) { fprintf(stderr, "usage: qsolve quad.bin CT mode L PA|- CA|- tie steps restarts [penalty]\n"); return 1; }
    FILE *fq = fopen(argv[1], "rb");
    if (!fq || fread(Q, sizeof(float), 26 * 26 * 26 * 26, fq) != 26 * 26 * 26 * 26) return 1;
    fclose(fq);
    N = strlen(argv[2]);
    for (int i = 0; i < N; i++) { CT[i] = argv[2][i] - 'A'; CP[i] = -1; }
    static const char *crib[2] = {"EASTNORTHEAST", "BERLINCLOCK"};
    static const int at[2] = {21, 63};
    for (int c = 0; c < 2; c++) for (int j = 0; crib[c][j]; j++) CP[at[c] + j] = crib[c][j] - 'A';
    MODE = atoi(argv[3]); L = atoi(argv[4]);
    FIXP = argv[5][0] != '-'; FIXC = argv[6][0] != '-'; TIE = atoi(argv[7]);
    long steps = atol(argv[8]); int restarts = atoi(argv[9]);
    if (argc > 10) PEN = atof(argv[10]);

    #pragma omp parallel for schedule(dynamic, 1)
    for (int rst = 0; rst < restarts; rst++) {
        uint64_t rs = 0x9E3779B97F4A7C15ULL ^ ((uint64_t)(rst + 1) * 0xBF58476D1CE4E5B9ULL) ^ ((uint64_t)L << 40) ^ MODE;
        for (int i = 0; i < 8; i++) rnd(&rs);
        State S, B, best;
        int pt[MAXN], mis;
        if (FIXP) set_alpha(argv[5], S.pr); else shuffle(S.pr, &rs);
        if (FIXC) set_alpha(argv[6], S.cr); else shuffle(S.cr, &rs);
        if (TIE) memcpy(S.cr, S.pr, sizeof S.pr);
        for (int x = 0; x < 26; x++) S.pinv[S.pr[x]] = x;
        for (int j = 0; j < L; j++) S.k[j] = ri(&rs, 26);
        double cur = score(&S, pt, &mis), bs = cur;
        best = S;
        const double T0 = 3.0, T1 = 0.10;
        double T = T0, f = pow(T1 / T0, 1.0 / (double)steps);
        for (long it = 0; it < steps; it++, T *= f) {
            B = S;
            int m = ri(&rs, 100);
            if (m < 30) {                                   /* change one shift */
                int j = ri(&rs, L);
                S.k[j] = (m & 1) ? ri(&rs, 26) : (S.k[j] + (ri(&rs, 2) ? 1 : 25)) % 26;
            } else if ((m < 65 || FIXC) && !FIXP) {         /* swap two plain letters */
                int a = ri(&rs, 26), b = ri(&rs, 26);
                if (a == b) continue;
                int t = S.pr[a]; S.pr[a] = S.pr[b]; S.pr[b] = t;
                S.pinv[S.pr[a]] = a; S.pinv[S.pr[b]] = b;
                if (TIE) memcpy(S.cr, S.pr, sizeof S.pr);
            } else if (!FIXC && !TIE) {                     /* swap two cipher letters */
                int a = ri(&rs, 26), b = ri(&rs, 26);
                if (a == b) continue;
                int t = S.cr[a]; S.cr[a] = S.cr[b]; S.cr[b] = t;
            } else continue;
            double ns = score(&S, pt, &mis);
            if (ns >= cur || ru(&rs) < exp((ns - cur) / T)) {
                cur = ns;
                if (cur > bs) { bs = cur; best = S; }
            } else S = B;
        }
        double fin = score(&best, pt, &mis);
        char out[MAXN + 1], pa[27], ca[27], key[33];
        for (int i = 0; i < N; i++) out[i] = 'A' + pt[i];
        out[N] = 0;
        for (int x = 0; x < 26; x++) { pa[best.pr[x]] = 'A' + x; ca[best.cr[x]] = 'A' + x; }
        pa[26] = ca[26] = 0;
        for (int j = 0; j < L; j++) key[j] = 'A' + best.k[j];
        key[L] = 0;
        #pragma omp critical
        { printf("%.4f %d %s %s %s %s\n", (fin + PEN * mis) / (N - 3), mis, out, pa, ca, key); fflush(stdout); }
    }
    return 0;
}
