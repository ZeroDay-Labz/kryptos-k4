/* colsweep.cl - one work item = one column order (unranked from its index), tested by colcore.h */
typedef uchar U8;
typedef ulong U64;
#define GLOBAL __global
#include "colcore.h"

__kernel void sweep(ulong base, int w, int mineq, int st_off, __global const uchar *T, __global const ulong *V,
                    __global const ulong *fact, volatile __global uint *count, __global uint *hits, uint maxhits) {
    ulong rank = base + get_global_id(0);
    if (rank >= fact[w]) return;
    uchar pool[32], ord[32];
    for (int i = 0; i < w; i++) pool[i] = (uchar)i;
    ulong r = rank;
    for (int i = 0; i < w; i++) {
        ulong f = fact[w - 1 - i];
        int d = (int)(r / f);
        r -= (ulong)d * f;
        ord[i] = pool[d];
        for (int j = d; j < w - 1 - i; j++) pool[j] = pool[j + 1];
    }
    int out[60];
    int h = test_order(ord, w, T, V, st_off, mineq, out, 60);
    for (int i = 0; i < h; i++) {
        uint slot = atomic_inc(count);
        if (slot < maxhits) {
            hits[7 * slot] = (uint)(rank & 0xFFFFFFFFUL);
            hits[7 * slot + 1] = (uint)(rank >> 32);
            for (int k = 0; k < 5; k++) hits[7 * slot + 2 + k] = (uint)out[5 * i + k];
        }
    }
}
