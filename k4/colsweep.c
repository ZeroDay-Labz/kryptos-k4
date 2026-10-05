/*
 * colsweep.c - every columnar transposition of width w (all w! column orders, forward and
 * inverse), each tested against the K4 clues with any repeating key in both layer orders.
 * CPU driver (OpenMP). The same test in OpenCL is colsweep_gpu.c / colsweep.cl.
 *
 * usage: colsweep TABLES w mineq
 * prints: HIT order(comma list) kind inverse L equalities mask
 * build: gcc -O3 -march=native -fopenmp -o colsweep colsweep.c
 */
#include <omp.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
typedef uint8_t U8;
typedef uint64_t U64;
#define GLOBAL
#include "colcore.h"

static U8 T[16384];
static U64 V[24 * 26];

int main(int argc, char **argv) {
    FILE *f = fopen(argv[1], "rb");
    int w = atoi(argv[2]), mineq = atoi(argv[3]), tlen;
    if (fread(&tlen, 4, 1, f) != 1 || fread(T, 1, tlen, f) != (size_t)tlen || fread(V, 8, 24 * 26, f) != 24 * 26) return 1;
    fclose(f);
    int st_off = 145 + 97 * 41;
    long total = 0;
    #pragma omp parallel for schedule(dynamic, 1) reduction(+:total)
    for (int pre = 0; pre < w * w; pre++) {
        int a = pre / w, b = pre % w;
        if (a == b && w > 1) continue;
        U8 ord[32];
        int n = 0, out[400];
        ord[n++] = a; if (w > 1) ord[n++] = b;
        for (int c = 0; c < w; c++) if (c != a && c != b) ord[n++] = c;
        int lo = w > 1 ? 2 : 1;
        for (;;) {
            int h = test_order(ord, w, T, V, st_off, mineq, out, 400);
            total++;
            if (h) {
                #pragma omp critical
                for (int i = 0; i < h; i++) {
                    printf("HIT ");
                    for (int j = 0; j < w; j++) printf("%d%s", ord[j], j + 1 < w ? "," : " ");
                    printf("%d %d %d %d %d\n", out[5 * i], out[5 * i + 1], out[5 * i + 2], out[5 * i + 3], out[5 * i + 4]);
                }
            }
            /* next permutation of ord[lo..w-1] */
            int i = w - 2;
            while (i >= lo && ord[i] >= ord[i + 1]) i--;
            if (i < lo) break;
            int j = w - 1;
            while (ord[j] <= ord[i]) j--;
            U8 t = ord[i]; ord[i] = ord[j]; ord[j] = t;
            for (int x = i + 1, y = w - 1; x < y; x++, y--) { t = ord[x]; ord[x] = ord[y]; ord[y] = t; }
        }
    }
    printf("DONE %ld orders\n", total);
    return 0;
}
