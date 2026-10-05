/*
 * gsolve.c - simulated-annealing alphabet solver for Gromark-type hypotheses on K4.
 *
 * Model:  C_i = cipher_alpha[ rank_plain(P_i) + k_i  mod 26 ],  key k given per job.
 * Unknown: the plain and cipher alphabets (two permutations of A-Z).
 * The 24 crib letters are enforced exactly: they tie plain and cipher ranks
 * together into components, each of which can only slide as a block. The search
 * moves are (1) swap two non-crib cipher letters, (2) swap two non-crib plain
 * letters, (3) slide a component. Objective: quadgram log-probability of the
 * full 97-letter decryption.
 *
 * stdin : line 1 = ciphertext (97 letters); then one job per line:
 *         <label> k0 k1 ... k96
 * stdout: <avg quadgram score> <label> <plaintext> <plain alphabet> <cipher alphabet>
 *
 * build: gcc -O3 -march=native -fopenmp -o gsolve gsolve.c -lm
 * usage: gsolve quad.bin [steps] [restarts]
 *        gsolve quad.bin steps restarts period L [threshold [lo hi]]   (every repeating key of period L)
 */
#include <math.h>
#include <omp.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define N 97
#define NCRIB 24
#define MAXJOBS 400000

static float Q[26 * 26 * 26 * 26];
static int CT[N];
static const int CRIB_POS[NCRIB] = {21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33,
                                    63, 64, 65, 66, 67, 68, 69, 70, 71, 72, 73};
static const char CRIB_PT[] = "EASTNORTHEASTBERLINCLOCK";

typedef struct { int pr[26], pinv[26], cr[26], cinv[26]; } State;

typedef struct {
    int ncomp;
    int pcomp[26], poff[26];   /* plain letter -> component (-1 = free), offset */
    int ccomp[26], coff[26];
    int nfp, fp[26];           /* free (non-crib) plain letters */
    int nfc, fc[26];
} Layout;

static inline uint64_t rnd(uint64_t *s) {
    uint64_t x = *s;
    x ^= x << 13; x ^= x >> 7; x ^= x << 17;
    return *s = x;
}
static inline int rint_(uint64_t *s, int n) { return (int)((rnd(s) >> 11) % (uint64_t)n); }
static inline double runif(uint64_t *s) { return (rnd(s) >> 11) * (1.0 / 9007199254740992.0); }

/* Build components from cribs under key. Returns 0 if the key is impossible. */
static int build_layout(const int *key, Layout *L) {
    for (int i = 0; i < 26; i++) { L->pcomp[i] = L->ccomp[i] = -1; L->poff[i] = L->coff[i] = 0; }
    L->ncomp = 0;
    int changed = 1;
    int assignedP[26] = {0}, assignedC[26] = {0};
    for (int seed = 0; seed < NCRIB; seed++) {
        int p0 = CRIB_PT[seed] - 'A';
        if (assignedP[p0]) continue;
        int id = L->ncomp++;
        L->pcomp[p0] = id; L->poff[p0] = 0; assignedP[p0] = 1;
        changed = 1;
        while (changed) {
            changed = 0;
            for (int j = 0; j < NCRIB; j++) {
                int p = CRIB_PT[j] - 'A', c = CT[CRIB_POS[j]], k = key[CRIB_POS[j]];
                if (assignedP[p] && L->pcomp[p] == id) {
                    int v = ((L->poff[p] + k) % 26 + 26) % 26;
                    if (!assignedC[c]) { L->ccomp[c] = id; L->coff[c] = v; assignedC[c] = 1; changed = 1; }
                    else if (L->ccomp[c] != id || L->coff[c] != v) return 0;
                } else if (assignedC[c] && L->ccomp[c] == id) {
                    int v = ((L->coff[c] - k) % 26 + 26) % 26;
                    if (!assignedP[p]) { L->pcomp[p] = id; L->poff[p] = v; assignedP[p] = 1; changed = 1; }
                    else if (L->pcomp[p] != id || L->poff[p] != v) return 0;
                }
            }
        }
    }
    /* injectivity inside each component */
    for (int a = 0; a < 26; a++)
        for (int b = a + 1; b < 26; b++) {
            if (L->pcomp[a] >= 0 && L->pcomp[a] == L->pcomp[b] && L->poff[a] == L->poff[b]) return 0;
            if (L->ccomp[a] >= 0 && L->ccomp[a] == L->ccomp[b] && L->coff[a] == L->coff[b]) return 0;
        }
    L->nfp = L->nfc = 0;
    for (int i = 0; i < 26; i++) {
        if (L->pcomp[i] < 0) L->fp[L->nfp++] = i;
        if (L->ccomp[i] < 0) L->fc[L->nfc++] = i;
    }
    return 1;
}

static int init_state(const Layout *L, State *S, uint64_t *rs) {
    for (int attempt = 0; attempt < 2000; attempt++) {
        int usedP[26] = {0}, usedC[26] = {0}, ok = 1;
        int order[26];
        for (int i = 0; i < L->ncomp; i++) order[i] = i;
        for (int i = L->ncomp - 1; i > 0; i--) { int j = rint_(rs, i + 1), t = order[i]; order[i] = order[j]; order[j] = t; }
        for (int i = 0; i < 26; i++) S->pr[i] = S->cr[i] = -1;
        for (int oi = 0; oi < L->ncomp && ok; oi++) {
            int id = order[oi], valid[26], nv = 0;
            for (int d = 0; d < 26; d++) {
                int good = 1;
                for (int x = 0; x < 26 && good; x++) {
                    if (L->pcomp[x] == id && usedP[(L->poff[x] + d) % 26]) good = 0;
                    if (L->ccomp[x] == id && usedC[(L->coff[x] + d) % 26]) good = 0;
                }
                if (good) valid[nv++] = d;
            }
            if (!nv) { ok = 0; break; }
            int d = valid[rint_(rs, nv)];
            for (int x = 0; x < 26; x++) {
                if (L->pcomp[x] == id) { S->pr[x] = (L->poff[x] + d) % 26; usedP[S->pr[x]] = 1; }
                if (L->ccomp[x] == id) { S->cr[x] = (L->coff[x] + d) % 26; usedC[S->cr[x]] = 1; }
            }
        }
        if (!ok) continue;
        int freeP[26], nP = 0, freeC[26], nC = 0;
        for (int r = 0; r < 26; r++) { if (!usedP[r]) freeP[nP++] = r; if (!usedC[r]) freeC[nC++] = r; }
        for (int i = nP - 1; i > 0; i--) { int j = rint_(rs, i + 1), t = freeP[i]; freeP[i] = freeP[j]; freeP[j] = t; }
        for (int i = nC - 1; i > 0; i--) { int j = rint_(rs, i + 1), t = freeC[i]; freeC[i] = freeC[j]; freeC[j] = t; }
        for (int i = 0; i < L->nfp; i++) S->pr[L->fp[i]] = freeP[i];
        for (int i = 0; i < L->nfc; i++) S->cr[L->fc[i]] = freeC[i];
        for (int x = 0; x < 26; x++) { S->pinv[S->pr[x]] = x; S->cinv[S->cr[x]] = x; }
        return 1;
    }
    return 0;
}

static inline float score(const State *S, const int *key, int *pt) {
    for (int i = 0; i < N; i++) {
        int r = S->cr[CT[i]] - key[i];
        r %= 26; if (r < 0) r += 26;
        pt[i] = S->pinv[r];
    }
    float s = 0;
    for (int i = 0; i + 3 < N; i++)
        s += Q[((pt[i] * 26 + pt[i + 1]) * 26 + pt[i + 2]) * 26 + pt[i + 3]];
    return s;
}

/* Slide one side (plain or cipher) of component `id` by delta. 0 if blocked. */
static int slide_side(const int *comp, int id, int delta, int *rank, int *inv) {
    int members[26], nm = 0, inS[26] = {0}, inT[26] = {0};
    for (int x = 0; x < 26; x++) if (comp[x] == id) { members[nm++] = x; inS[rank[x]] = 1; }
    for (int i = 0; i < nm; i++) {
        int nr = (rank[members[i]] + delta) % 26;
        inT[nr] = 1;
        int holder = inv[nr];
        if (comp[holder] >= 0 && comp[holder] != id) return 0;   /* another component's crib letter */
    }
    int displaced[26], nd = 0, vacated[26], nv = 0;
    for (int r = 0; r < 26; r++) {
        if (inT[r] && !inS[r]) displaced[nd++] = inv[r];
        if (inS[r] && !inT[r]) vacated[nv++] = r;
    }
    for (int i = 0; i < nm; i++) rank[members[i]] = (rank[members[i]] + delta) % 26;
    for (int i = 0; i < nd; i++) rank[displaced[i]] = vacated[i];
    for (int x = 0; x < 26; x++) inv[rank[x]] = x;
    return 1;
}

static float anneal(const Layout *L, const int *key, long steps, uint64_t *rs, State *bestS) {
    State S, B;
    int pt[N];
    if (!init_state(L, &S, rs)) return -1e9f;
    float cur = score(&S, key, pt), best = cur;
    *bestS = S;
    const double T0 = 2.5, T1 = 0.12;
    double T = T0, f = pow(T1 / T0, 1.0 / (double)steps);
    for (long it = 0; it < steps; it++, T *= f) {
        B = S;
        int m = rint_(rs, 100);
        if (m < 45 && L->nfc >= 2) {
            int a = L->fc[rint_(rs, L->nfc)], b = L->fc[rint_(rs, L->nfc)];
            if (a == b) continue;
            int t = S.cr[a]; S.cr[a] = S.cr[b]; S.cr[b] = t;
            S.cinv[S.cr[a]] = a; S.cinv[S.cr[b]] = b;
        } else if (m < 80 && L->nfp >= 2) {
            int a = L->fp[rint_(rs, L->nfp)], b = L->fp[rint_(rs, L->nfp)];
            if (a == b) continue;
            int t = S.pr[a]; S.pr[a] = S.pr[b]; S.pr[b] = t;
            S.pinv[S.pr[a]] = a; S.pinv[S.pr[b]] = b;
        } else {
            int id = rint_(rs, L->ncomp);
            int delta = (m & 1) ? 1 + rint_(rs, 25) : (rint_(rs, 2) ? 1 : 25);
            if (!slide_side(L->pcomp, id, delta, S.pr, S.pinv) ||
                !slide_side(L->ccomp, id, delta, S.cr, S.cinv)) { S = B; continue; }
        }
        float ns = score(&S, key, pt);
        if (ns >= cur || runif(rs) < exp((ns - cur) / T)) {
            cur = ns;
            if (cur > best) { best = cur; *bestS = S; }
        } else {
            S = B;
        }
    }
    return best;
}

int main(int argc, char **argv) {
    if (argc < 2) { fprintf(stderr, "usage: gsolve quad.bin [steps] [restarts]\n"); return 1; }
    long steps = argc > 2 ? atol(argv[2]) : 300000;
    int restarts = argc > 3 ? atoi(argv[3]) : 4;
    FILE *fq = fopen(argv[1], "rb");
    if (!fq || fread(Q, sizeof(float), 26 * 26 * 26 * 26, fq) != 26 * 26 * 26 * 26) { fprintf(stderr, "bad quad file\n"); return 1; }
    fclose(fq);
    char ctline[256];
    if (!fgets(ctline, sizeof ctline, stdin)) return 1;
    for (int i = 0; i < N; i++) CT[i] = ctline[i] - 'A';

    if (argc > 5 && !strcmp(argv[4], "period")) {
        /* Enumerate EVERY repeating key of period L (first shift fixed at 0: a common
         * shift only rotates the cipher alphabet), keep those the clues allow, anneal
         * each, print the ones scoring above `threshold`. */
        int L = atoi(argv[5]);
        double thr = argc > 6 ? atof(argv[6]) : -5.0;
        int lo = argc > 8 ? atoi(argv[7]) : 0, hi = argc > 8 ? atoi(argv[8]) : 26 * 26;
        long total = 0, alive = 0;
        #pragma omp parallel for schedule(dynamic, 1) reduction(+:total, alive)
        for (int top = lo; top < hi; top++) {
            int k[32] = {0}, key[N];
            k[1] = top / 26; k[2] = top % 26;
            long inner = 1;
            for (int j = 3; j < L; j++) inner *= 26;
            for (long v = 0; v < inner; v++) {
                long x = v;
                for (int j = 3; j < L; j++) { k[j] = x % 26; x /= 26; }
                int bad = 0;
                for (int a = 0; a < NCRIB && !bad; a++)
                    for (int b = a + 1; b < NCRIB; b++) {
                        int sp = CRIB_PT[a] == CRIB_PT[b], sc = CT[CRIB_POS[a]] == CT[CRIB_POS[b]];
                        int sk = k[CRIB_POS[a] % L] == k[CRIB_POS[b] % L];
                        if ((sp && sc && !sk) || (sp != sc && sk)) { bad = 1; break; }
                    }
                total++;
                if (bad) continue;
                for (int i = 0; i < N; i++) key[i] = k[i % L];
                Layout Lay;
                if (!build_layout(key, &Lay)) continue;
                alive++;
                uint64_t rs = 0x9E3779B97F4A7C15ULL ^ ((uint64_t)(top + 1) * 0xBF58476D1CE4E5B9ULL) ^ (uint64_t)v;
                State best, S;
                float bs = -1e9f;
                for (int r = 0; r < restarts; r++) {
                    float s = anneal(&Lay, key, steps, &rs, &S);
                    if (s > bs) { bs = s; best = S; }
                }
                if (bs / (N - 3) < thr) continue;
                int pt[N];
                score(&best, key, pt);
                char out[N + 1], pa[27], ca[27], lab[33];
                for (int i = 0; i < N; i++) out[i] = 'A' + pt[i];
                out[N] = 0;
                for (int r = 0; r < 26; r++) { pa[r] = 'A' + best.pinv[r]; ca[r] = 'A' + best.cinv[r]; }
                pa[26] = ca[26] = 0;
                for (int j = 0; j < L; j++) lab[j] = 'A' + k[j];
                lab[L] = 0;
                #pragma omp critical
                { printf("%.4f %s %s %s %s\n", bs / (N - 3), lab, out, pa, ca); fflush(stdout); }
            }
        }
        fprintf(stderr, "keys %ld allowed %ld\n", total, alive);
        return 0;
    }

    static char labels[MAXJOBS][48];
    int (*keys)[N] = malloc(sizeof(int[N]) * MAXJOBS);
    int njobs = 0;
    while (njobs < MAXJOBS && scanf("%47s", labels[njobs]) == 1) {
        for (int i = 0; i < N; i++) if (scanf("%d", &keys[njobs][i]) != 1) return 1;
        njobs++;
    }
    #pragma omp parallel for schedule(dynamic, 1)
    for (int j = 0; j < njobs; j++) {
        Layout L;
        if (!build_layout(keys[j], &L)) continue;
        uint64_t rs = 0x9E3779B97F4A7C15ULL ^ ((uint64_t)(j + 1) * 0xBF58476D1CE4E5B9ULL);
        State best, S;
        float bs = -1e9f;
        for (int r = 0; r < restarts; r++) {
            float s = anneal(&L, keys[j], steps, &rs, &S);
            if (s > bs) { bs = s; best = S; }
        }
        if (bs < -1e8f) continue;
        int pt[N];
        score(&best, keys[j], pt);
        char out[N + 1], pa[27], ca[27];
        for (int i = 0; i < N; i++) out[i] = 'A' + pt[i];
        out[N] = 0;
        for (int r = 0; r < 26; r++) { pa[r] = 'A' + best.pinv[r]; ca[r] = 'A' + best.cinv[r]; }
        pa[26] = ca[26] = 0;
        #pragma omp critical
        { printf("%.4f %s %s %s %s\n", bs / (N - 3), labels[j], out, pa, ca); fflush(stdout); }
    }
    return 0;
}
