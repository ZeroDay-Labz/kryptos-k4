/*
 * chaint.c - key chain behind a transposition.
 *
 * For each "case" (the 24 cipher letters that a transposition puts on the clue
 * letters, and the 24 key positions they use) and each reading of each known
 * text, ask: is  rank(text letter) -/+ t  constant on every key slot of some
 * period L, where t is the key value K4 needs there?  That is "text decoded by
 * a repeating key gives K4's key". 24 targets (8 alphabet/arithmetic settings x
 * 3 key-letter recodings) x 2 signs are carried as a 48-bit mask and narrowed
 * one forced equality at a time.
 *
 * usage: chaint CASES SOURCES PLAIN24 MINEQ LMAX
 *   CASES    binary, 48 bytes per case: 24 cipher letter codes, 24 key positions
 *   SOURCES  one text per line, letters A-Z
 * prints: HIT case source start step alphabet L eq maskhex
 * build: gcc -O3 -march=native -fopenmp -o chaint chaint.c
 */
#include <omp.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define NC 24
#define MAXL 23
static const char *KA = "KRYPTOSABCDEFGHIJLMNQUVWXZ";
static int RK[2][26];                 /* rank of letter code in A-Z, KRYPTOS */
static int nsrc, slen[256];
static unsigned char *src[256];

int main(int argc, char **argv) {
    if (argc < 6) { fprintf(stderr, "usage\n"); return 2; }
    int MINEQ = atoi(argv[4]), LMAX = atoi(argv[5]);
    if (LMAX > MAXL) LMAX = MAXL;
    for (int c = 0; c < 26; c++) { RK[0][c] = c; RK[1][KA[c] - 'A'] = c; }
    int P[NC];
    for (int j = 0; j < NC; j++) P[j] = argv[3][j] - 'A';

    FILE *f = fopen(argv[1], "rb");
    fseek(f, 0, SEEK_END); long ncase = ftell(f) / 48; fseek(f, 0, SEEK_SET);
    unsigned char *cases = malloc(ncase * 48);
    if (fread(cases, 48, ncase, f) != (size_t)ncase) return 3;
    fclose(f);
    f = fopen(argv[2], "r");
    static char line[1 << 16];
    while (fgets(line, sizeof line, f) && nsrc < 256) {
        int n = 0;
        unsigned char *s = malloc(strlen(line) + 1);
        for (char *p = line; *p; p++) if (*p >= 'A' && *p <= 'Z') s[n++] = *p - 'A';
        if (n) { src[nsrc] = s; slen[nsrc++] = n; }
    }
    fclose(f);

    #pragma omp parallel
    {
        uint64_t (*M)[NC][26] = malloc(sizeof(uint64_t) * (MAXL + 1) * NC * 26);
        int pa[MAXL + 1][NC], pb[MAXL + 1][NC], np[MAXL + 1];
        #pragma omp for schedule(dynamic, 64)
        for (long ci = 0; ci < ncase; ci++) {
            const unsigned char *C = cases + ci * 48, *kp = C + 24;
            int t[24][NC];
            for (int k = 0; k < 8; k++) {
                int xa = (k >> 2) & 1, xc = (k >> 1) & 1, beau = k & 1;
                for (int j = 0; j < NC; j++) {
                    int p = RK[xa][P[j]], r = RK[xc][C[j]];
                    int s = beau ? (p + r) % 26 : (r - p + 26) % 26;
                    t[k * 3][j] = s;                 /* key letter read where it was made   */
                    t[k * 3 + 1][j] = RK[1][s];      /* made on KRYPTOS, read on A-Z         */
                    t[k * 3 + 2][j] = KA[s] - 'A';   /* made on A-Z, read on KRYPTOS         */
                }
            }
            int nact = 0, act[MAXL + 1];
            for (int L = 1; L <= LMAX; L++) {
                int last[MAXL + 1], n = 0;
                for (int s = 0; s < L; s++) last[s] = -1;
                for (int j = 0; j < NC; j++) {
                    int s = kp[j] % L;
                    if (last[s] >= 0) { pa[L][n] = last[s]; pb[L][n] = j; n++; }
                    last[s] = j;
                }
                np[L] = n;
                if (n < MINEQ) continue;
                act[nact++] = L;
                memset(M[L], 0, sizeof(uint64_t) * NC * 26);
                for (int q = 0; q < n; q++)
                    for (int ti = 0; ti < 24; ti++) {
                        int d = (t[ti][pa[L][q]] - t[ti][pb[L][q]] + 26) % 26;
                        M[L][q][d] |= 1ULL << (2 * ti);
                        M[L][q][(26 - d) % 26] |= 1ULL << (2 * ti + 1);
                    }
            }
            if (!nact) continue;
            for (int si = 0; si < nsrc; si++) {
                int n = slen[si];
                const unsigned char *S = src[si];
                int kpm[NC];
                for (int j = 0; j < NC; j++) kpm[j] = kp[j] % n;
                for (int step = 1; step >= -1; step -= 2)
                    for (int start = 0; start < n; start++) {
                        int x[NC];
                        for (int j = 0; j < NC; j++) {
                            int idx = start + step * kpm[j];
                            if (idx < 0) idx += n; else if (idx >= n) idx -= n;
                            x[j] = S[idx];
                        }
                        for (int al = 0; al < 2; al++) {
                            int r[NC];
                            for (int j = 0; j < NC; j++) r[j] = RK[al][x[j]];
                            for (int a = 0; a < nact; a++) {
                                int L = act[a];
                                uint64_t m = ~0ULL;
                                for (int q = 0; q < np[L] && m; q++)
                                    m &= M[L][q][(r[pa[L][q]] - r[pb[L][q]] + 26) % 26];
                                if (m) {
                                    #pragma omp critical
                                    printf("HIT %ld %d %d %d %d %d %d %llx\n", ci, si, start, step, al, L,
                                           np[L], (unsigned long long)m);
                                }
                            }
                        }
                    }
            }
        }
        free(M);
    }
    printf("DONE %ld cases %d sources\n", ncase, nsrc);
    return 0;
}
