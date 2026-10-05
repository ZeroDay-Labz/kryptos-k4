/*
 * kwcsp.c - exhaustive search over every keyword alphabet used on BOTH sides.
 *
 * A keyword alphabet X is: keyword letters in some order, then the remaining
 * letters alphabetically. Question: is there any X such that, for all clue pairs
 * (C, P), the shift  rank(C) + sign*rank(P)  falls in one window of `base`
 * consecutive values mod 26?
 *
 * usage: kwcsp CIPHERLETTERS PLAINLETTERS sign base [kmin kmax [maxprint]]
 * Without maxprint: stops at the first solution, prints "FOUND k t <26 ranks>" or "NONE".
 * With maxprint: counts EVERY solution with keyword length kmin..kmax and prints
 * up to maxprint of them as "SOL k t <26 ranks>", then "count N". Always ends "nodes N".
 * build: gcc -O3 -march=native -fopenmp -o kwcsp kwcsp.c
 */
#include <omp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int NP, PC[64], PP[64], SIGN, BASE;
static int nitems, item_kind[32], item_val[32], remaining[33];
static int npart[26], part[26][64];
static volatile int done = 0;
static int KMIN = 0, KMAX = 26, ENUM = 0, MAXPRINT = 0;
static long long COUNT = 0;
static int printed = 0;

typedef struct { int k, t, rank[26]; long long nodes; } Ctx;

static inline int fits(const Ctx *c, int x) {
    for (int a = 0; a < npart[x]; a++) {
        int j = part[x][a], rc = c->rank[PC[j]], rp = c->rank[PP[j]];
        if (rc >= 0 && rp >= 0) {
            int v = ((rc + SIGN * rp - c->t) % 26 + 52) % 26;
            if (v >= BASE) return 0;
        }
    }
    return 1;
}

static int walk(Ctx *c, int i, int n_kw, int before, unsigned used) {
    if (done) return 0;
    c->nodes++;
    if (n_kw > c->k || n_kw + remaining[i] < c->k) return 0;
    if (i == nitems) {
        if (!ENUM) return 1;
        #pragma omp critical
        {
            COUNT++;
            if (printed < MAXPRINT) {
                printed++;
                printf("SOL %d %d", c->k, c->t);
                for (int x = 0; x < 26; x++) printf(" %d", c->rank[x]);
                printf("\n");
            }
        }
        return 0;                                  /* keep searching */
    }
    if (item_kind[i] == 0) {                       /* run of letters that carry no clue */
        int size = item_val[i], maxc = c->k - n_kw < size ? c->k - n_kw : size;
        for (int cnt = 0; cnt <= maxc; cnt++)
            if (walk(c, i + 1, n_kw + cnt, before + size, used)) return 1;
        return 0;
    }
    int x = item_val[i];
    int r = c->k + (before - n_kw);                /* x stays in the alphabetical tail */
    if (r < 26) {
        c->rank[x] = r;
        if (fits(c, x) && walk(c, i + 1, n_kw, before + 1, used)) return 1;
    }
    for (int pos = 0; pos < c->k; pos++) {         /* x is a keyword letter at `pos` */
        if (used >> pos & 1) continue;
        c->rank[x] = pos;
        if (fits(c, x) && walk(c, i + 1, n_kw + 1, before + 1, used | 1u << pos)) return 1;
    }
    c->rank[x] = -1;
    return 0;
}

int main(int argc, char **argv) {
    if (argc < 5) return 1;
    NP = (int)strlen(argv[1]);
    SIGN = atoi(argv[3]); BASE = atoi(argv[4]);
    if (argc > 6) { KMIN = atoi(argv[5]); KMAX = atoi(argv[6]); }
    if (argc > 7) { ENUM = 1; MAXPRINT = atoi(argv[7]); }
    int need[26] = {0};
    for (int j = 0; j < NP; j++) {
        PC[j] = argv[1][j] - 'A'; PP[j] = argv[2][j] - 'A';
        need[PC[j]] = need[PP[j]] = 1;
    }
    for (int x = 0; x < 26; x++)
        for (int j = 0; j < NP; j++)
            if (PC[j] == x || PP[j] == x) part[x][npart[x]++] = j;
    int run = 0;
    for (int L = 0; L < 26; L++) {
        if (need[L]) {
            if (run) { item_kind[nitems] = 0; item_val[nitems++] = run; run = 0; }
            item_kind[nitems] = 1; item_val[nitems++] = L;
        } else run++;
    }
    if (run) { item_kind[nitems] = 0; item_val[nitems++] = run; }
    for (int i = nitems - 1; i >= 0; i--)
        remaining[i] = remaining[i + 1] + (item_kind[i] == 0 ? item_val[i] : 1);

    long long total = 0;
    Ctx best; best.k = -1;
    #pragma omp parallel for schedule(dynamic, 1) reduction(+:total)
    for (int job = 0; job < 26 * 27; job++) {
        if (done) continue;
        Ctx c; c.t = job / 27; c.k = job % 27; c.nodes = 0;
        if (c.k < KMIN || c.k > KMAX) continue;
        for (int x = 0; x < 26; x++) c.rank[x] = -1;
        int ok = walk(&c, 0, 0, 0, 0u);
        total += c.nodes;
        if (ok) {
            #pragma omp critical
            { if (!done) { done = 1; best = c; } }
        }
    }
    if (ENUM) printf("count %lld\n", COUNT);
    else if (best.k >= 0) {
        printf("FOUND %d %d", best.k, best.t);
        for (int x = 0; x < 26; x++) printf(" %d", best.rank[x]);
        printf("\n");
    } else printf("NONE\n");
    printf("nodes %lld\n", total);
    return 0;
}
