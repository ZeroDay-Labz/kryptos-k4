/*
 * b5solve.c - joint search for "fixed table plus a digit 0..B-1".
 *
 * Model: cipher rank (A-Z order) = f(plain) + d, d in 0..B-1 free at every position.
 * Unknown: the table f (a permutation of 26). With f fixed, each cipher letter can be
 * one of B plaintext letters; the most English-like reading of the whole message is
 * found exactly by dynamic programming over quadgrams (like predictive text). The table
 * is searched by simulated annealing on that best-reading score.
 *
 * stdin: line 1 ciphertext; line 2 known plaintext ('.' = unknown), same length;
 *        line 3 a string of 0/1: 1 = this known letter is an exception (keep the plaintext
 *        letter but do not let it constrain the table)
 * usage: b5solve quad.bin steps restarts [B]
 * prints: score plaintext table(letter at each rank)
 * build: gcc -O3 -march=native -fopenmp -o b5solve b5solve.c -lm
 */
#include <math.h>
#include <omp.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAXN 128
static float Q[26 * 26 * 26 * 26];
static int N, B = 5, CT[MAXN], KN[MAXN], EXC[MAXN];
static unsigned char allowed[26][26];          /* allowed[letter][rank] */

static inline uint64_t rnd(uint64_t *s) { uint64_t x = *s; x ^= x << 13; x ^= x >> 7; x ^= x << 17; return *s = x; }
static inline int ri(uint64_t *s, int n) { return (int)((rnd(s) >> 11) % (uint64_t)n); }
static inline double ru(uint64_t *s) { return (rnd(s) >> 11) * (1.0 / 9007199254740992.0); }

/* best reading for table pinv (rank -> letter); returns total log score, fills pt if not NULL */
static float decode(const int *pinv, int *pt) {
    static __thread int opt[MAXN][8], no[MAXN];
    static __thread float dp[2][8][8][8];
    static __thread unsigned char bp[MAXN][8][8][8];
    for (int i = 0; i < N; i++) {
        if (KN[i] >= 0) { opt[i][0] = KN[i]; no[i] = 1; }
        else { no[i] = B; for (int d = 0; d < B; d++) opt[i][d] = pinv[((CT[i] - d) % 26 + 26) % 26]; }
    }
    int cur = 0;
    for (int a = 0; a < no[0]; a++) for (int b = 0; b < no[1]; b++) for (int c = 0; c < no[2]; c++) dp[0][a][b][c] = 0;
    for (int i = 3; i < N; i++) {
        int nx = cur ^ 1;
        for (int b = 0; b < no[i - 2]; b++) for (int c = 0; c < no[i - 1]; c++) for (int d = 0; d < no[i]; d++) {
            float best = -1e30f; int arg = 0;
            int base = ((opt[i - 2][b] * 26 + opt[i - 1][c]) * 26 + opt[i][d]);
            for (int a = 0; a < no[i - 3]; a++) {
                float v = dp[cur][a][b][c] + Q[opt[i - 3][a] * 17576 + base];
                if (v > best) { best = v; arg = a; }
            }
            dp[nx][b][c][d] = best; bp[i][b][c][d] = (unsigned char)arg;
        }
        cur = nx;
    }
    float best = -1e30f; int sb = 0, sc = 0, sd = 0;
    for (int b = 0; b < no[N - 3]; b++) for (int c = 0; c < no[N - 2]; c++) for (int d = 0; d < no[N - 1]; d++)
        if (dp[cur][b][c][d] > best) { best = dp[cur][b][c][d]; sb = b; sc = c; sd = d; }
    if (pt) {
        int ix[MAXN];
        ix[N - 3] = sb; ix[N - 2] = sc; ix[N - 1] = sd;
        for (int i = N - 1; i >= 3; i--) ix[i - 3] = bp[i][ix[i - 2]][ix[i - 1]][ix[i]];
        for (int i = 0; i < N; i++) pt[i] = opt[i][ix[i]];
    }
    return best;
}

int main(int argc, char **argv) {
    if (argc < 4) { fprintf(stderr, "usage: b5solve quad.bin steps restarts [B]\n"); return 1; }
    long steps = atol(argv[2]); int restarts = atoi(argv[3]);
    if (argc > 4) B = atoi(argv[4]);
    FILE *fq = fopen(argv[1], "rb");
    if (!fq || fread(Q, sizeof(float), 26 * 26 * 26 * 26, fq) != 26 * 26 * 26 * 26) return 1;
    fclose(fq);
    char ct[256], kn[256], ex[256];
    if (scanf("%255s %255s %255s", ct, kn, ex) != 3) return 1;
    N = strlen(ct);
    memset(allowed, 1, sizeof allowed);
    for (int i = 0; i < N; i++) {
        CT[i] = ct[i] - 'A'; KN[i] = kn[i] == '.' ? -1 : kn[i] - 'A'; EXC[i] = ex[i] == '1';
        if (KN[i] >= 0 && !EXC[i])
            for (int r = 0; r < 26; r++) { int d = ((CT[i] - r) % 26 + 26) % 26; if (d >= B) allowed[KN[i]][r] = 0; }
    }
    #pragma omp parallel for schedule(dynamic, 1)
    for (int rst = 0; rst < restarts; rst++) {
        uint64_t rs = 0x9E3779B97F4A7C15ULL ^ ((uint64_t)(rst + 1) * 0xBF58476D1CE4E5B9ULL);
        for (int i = 0; i < 8; i++) rnd(&rs);
        int pinv[26], pr[26], ok = 0;
        /* random table respecting the clue windows (retry until every letter is allowed) */
        for (int attempt = 0; attempt < 200000 && !ok; attempt++) {
            for (int r = 0; r < 26; r++) pinv[r] = -1;
            int order[26]; ok = 1;
            for (int i = 0; i < 26; i++) order[i] = i;
            /* most constrained letters first */
            for (int i = 0; i < 26; i++) for (int j = i + 1; j < 26; j++) {
                int ci = 0, cj = 0;
                for (int r = 0; r < 26; r++) { ci += allowed[order[i]][r]; cj += allowed[order[j]][r]; }
                if (cj < ci) { int t = order[i]; order[i] = order[j]; order[j] = t; }
            }
            for (int i = 0; i < 26 && ok; i++) {
                int L = order[i], cand[26], nc = 0;
                for (int r = 0; r < 26; r++) if (allowed[L][r] && pinv[r] < 0) cand[nc++] = r;
                if (!nc) { ok = 0; break; }
                int r = cand[ri(&rs, nc)];
                pinv[r] = L; pr[L] = r;
            }
        }
        if (!ok) continue;
        double cur = decode(pinv, 0), best = cur;
        int bestp[26];
        memcpy(bestp, pinv, sizeof pinv);
        const double T0 = 2.0, T1 = 0.08;
        double T = T0, f = pow(T1 / T0, 1.0 / (double)steps);
        for (long it = 0; it < steps; it++, T *= f) {
            int x = ri(&rs, 26), y = ri(&rs, 26);
            if (x == y) continue;
            int a = pinv[x], b = pinv[y];
            if (!allowed[a][y] || !allowed[b][x]) continue;
            pinv[x] = b; pinv[y] = a;
            double ns = decode(pinv, 0);
            if (ns >= cur || ru(&rs) < exp((ns - cur) / T)) {
                cur = ns;
                if (cur > best) { best = cur; memcpy(bestp, pinv, sizeof pinv); }
            } else { pinv[x] = a; pinv[y] = b; }
        }
        int pt[MAXN];
        decode(bestp, pt);
        char out[MAXN + 1], tab[27];
        for (int i = 0; i < N; i++) out[i] = 'A' + pt[i];
        out[N] = 0;
        for (int r = 0; r < 26; r++) tab[r] = 'A' + bestp[r];
        tab[26] = 0;
        #pragma omp critical
        { printf("%.4f %s %s\n", best / (N - 3), out, tab); fflush(stdout); }
    }
    return 0;
}
