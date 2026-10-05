/*
 * raycast.c - sunlight through the S-shaped screen: which tableau letter does a ray
 * through each K4 clue letter hit?
 *
 * No surveyed geometry of Kryptos is public, so this sweeps a parametric model:
 * two cylindrical panels joined at the middle of the S (cipher panel curving one
 * way with arc angle a1, tableau panel the other way with arc angle a2), 31 letter
 * columns each, 28 rows, row pitch rho (in column widths). A ray has azimuth phi
 * relative to the sculpture (this absorbs the unknown compass orientation) and
 * elevation eps (negative = traced the other way). For every setting the 24 rays
 * are traced from the cipher panel to the tableau panel, the letters they land on
 * are read (both column directions on each panel), and the score is how many clue
 * letters get the key they need (up to a constant, 16 table settings).
 *
 * usage: raycast DATA    (DATA written by raycast.py)
 * build: gcc -O3 -march=native -fopenmp -o raycast raycast.c -lm
 */
#include <math.h>
#include <omp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define NC 24
static int S[8][NC], CR[NC], CC[NC], RK[2][26];
static char TAB[28][40];
static int TLEN[28];

int main(int argc, char **argv) {
    FILE *f = fopen(argv[1], "r");
    for (int k = 0; k < 8; k++) for (int j = 0; j < NC; j++) if (fscanf(f, "%d", &S[k][j]) != 1) return 1;
    for (int j = 0; j < NC; j++) if (fscanf(f, "%d %d", &CR[j], &CC[j]) != 2) return 1;
    for (int r = 0; r < 28; r++) { if (fscanf(f, "%39s", TAB[r]) != 1) return 1; TLEN[r] = strlen(TAB[r]); }
    fclose(f);
    const char *KA = "KRYPTOSABCDEFGHIJLMNQUVWXZ";
    for (int c = 0; c < 26; c++) { RK[0][c] = c; RK[1][KA[c] - 'A'] = c; }
    const double L = 31.0, PI = 3.14159265358979323846;
    long hist[NC + 1] = {0}, traced = 0;
    int best = 0; char bestdesc[256] = "";
    #pragma omp parallel for collapse(2) schedule(dynamic, 1) reduction(+:traced)
    for (int i1 = 0; i1 <= 14; i1++)                        /* a1 = 0.3 .. 3.8 rad */
        for (int i2 = 0; i2 <= 12; i2++) {                  /* a2 = 0.5 .. 5.9 rad */
            double a1 = 0.3 + 0.25 * i1, a2 = 0.5 + 0.45 * i2;
            double R1 = L / a1, R2 = L / a2;
            long lh[NC + 1] = {0};
            int lbest = 0; char ldesc[256] = "";
            for (int ir = 0; ir < 3; ir++) {
                double rho = 1.0 + 0.1 * ir;
                for (int o1 = 0; o1 < 2; o1++) {
                    double px[NC], py[NC], pz[NC];
                    for (int j = 0; j < NC; j++) {
                        double s = (o1 ? L - (CC[j] + 0.5) : CC[j] + 0.5);
                        px[j] = -R1 * sin(s / R1); py[j] = R1 - R1 * cos(s / R1);
                        pz[j] = (27.5 - CR[j]) * rho;
                    }
                    for (int ie = -30; ie <= 30; ie++) {
                        if (!ie) continue;
                        double eps = ie * 2.5 * PI / 180, ce = cos(eps), se = sin(eps);
                        for (int ip = 0; ip < 360; ip++) {
                            double phi = ip * PI / 180, dx = ce * cos(phi), dy = ce * sin(phi), dz = -se;
                            int row[NC], hit = 0; double sarc[NC];
                            for (int j = 0; j < NC; j++) {
                                /* circle centre (0,-R2), radius R2 */
                                double ox = px[j], oy = py[j] + R2;
                                double a = dx * dx + dy * dy, b = 2 * (ox * dx + oy * dy), c = ox * ox + oy * oy - R2 * R2;
                                double disc = b * b - 4 * a * c;
                                row[j] = -1;
                                if (disc < 0) continue;
                                double sq = sqrt(disc);
                                for (int root = 0; root < 2 && row[j] < 0; root++) {
                                    double t = (-b + (root ? sq : -sq)) / (2 * a);
                                    if (t <= 1e-6) continue;
                                    double hx = ox + t * dx, hy = oy + t * dy;
                                    double ang = atan2(hx, hy);              /* 0 at the junction, grows along +x */
                                    if (ang < 0) ang += 2 * PI;
                                    double s = ang * R2;
                                    if (s < 0 || s >= L) continue;
                                    double z = pz[j] + t * dz;
                                    int r = (int)floor(28.0 - z / rho);
                                    if (r < 0 || r > 27) continue;
                                    row[j] = r; sarc[j] = s; hit++;
                                }
                            }
                            if (hit < 20) continue;
                            traced++;
                            for (int o2 = 0; o2 < 2; o2++) {
                                int key[NC];
                                for (int j = 0; j < NC; j++) {
                                    key[j] = -1;
                                    if (row[j] < 0) continue;
                                    int c = (int)(o2 ? L - sarc[j] : sarc[j]);
                                    if (c < 0 || c >= TLEN[row[j]] || TAB[row[j]][c] < 'A' || TAB[row[j]][c] > 'Z') continue;
                                    key[j] = TAB[row[j]][c] - 'A';
                                }
                                int top = 0;
                                for (int k = 0; k < 8; k++) for (int x = 0; x < 2; x++) {
                                    int cnt[26] = {0};
                                    for (int j = 0; j < NC; j++) if (key[j] >= 0) {
                                        int v = ++cnt[((S[k][j] - RK[x][key[j]]) % 26 + 26) % 26];
                                        if (v > top) top = v;
                                    }
                                }
                                lh[top]++;
                                if (top > lbest) {
                                    lbest = top;
                                    snprintf(ldesc, sizeof ldesc, "arc angles %.2f / %.2f rad, row pitch %.1f, column directions %d/%d,"
                                             " ray azimuth %d deg, elevation %.1f deg", a1, a2, rho, o1, o2, ip, ie * 2.5);
                                }
                            }
                        }
                    }
                }
            }
            #pragma omp critical
            {
                for (int v = 0; v <= NC; v++) hist[v] += lh[v];
                if (lbest > best) { best = lbest; strcpy(bestdesc, ldesc); }
            }
        }
    printf("ray settings where at least 20 of the 24 rays reach the tableau panel: %ld\n", traced);
    for (int v = 8; v <= NC; v++) if (hist[v]) printf("  %2d of 24 clue letters agree: %ld settings\n", v, hist[v]);
    printf("best: %d of 24  [%s]\n", best, bestdesc);
    return 0;
}
