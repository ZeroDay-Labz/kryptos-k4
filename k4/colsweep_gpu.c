/*
 * colsweep_gpu.c - OpenCL driver for the exhaustive columnar sweep (kernel: colsweep.cl,
 * test: colcore.h). Same output format as colsweep.c.
 *
 * The OpenCL headers are not installed here, so the handful of declarations needed are
 * written out below; they match the Khronos OpenCL 1.2 ABI.
 *
 * usage: colsweep_gpu TABLES w mineq [batch_log2]
 * build: gcc -O2 -o colsweep_gpu colsweep_gpu.c -lOpenCL
 */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

typedef struct _cl_platform_id *cl_platform_id;
typedef struct _cl_device_id *cl_device_id;
typedef struct _cl_context *cl_context;
typedef struct _cl_command_queue *cl_command_queue;
typedef struct _cl_mem *cl_mem;
typedef struct _cl_program *cl_program;
typedef struct _cl_kernel *cl_kernel;
typedef struct _cl_event *cl_event;
typedef int32_t cl_int;
typedef uint32_t cl_uint;
typedef uint64_t cl_ulong, cl_bitfield;
#define CL_DEVICE_TYPE_GPU (1 << 2)
#define CL_MEM_READ_WRITE (1 << 0)
#define CL_MEM_READ_ONLY (1 << 2)
#define CL_MEM_COPY_HOST_PTR (1 << 5)
#define CL_PROGRAM_BUILD_LOG 0x1183
#define CL_DEVICE_NAME 0x102B
extern cl_int clGetPlatformIDs(cl_uint, cl_platform_id *, cl_uint *);
extern cl_int clGetDeviceIDs(cl_platform_id, cl_bitfield, cl_uint, cl_device_id *, cl_uint *);
extern cl_int clGetDeviceInfo(cl_device_id, cl_uint, size_t, void *, size_t *);
extern cl_context clCreateContext(const intptr_t *, cl_uint, const cl_device_id *, void *, void *, cl_int *);
extern cl_command_queue clCreateCommandQueue(cl_context, cl_device_id, cl_bitfield, cl_int *);
extern cl_program clCreateProgramWithSource(cl_context, cl_uint, const char **, const size_t *, cl_int *);
extern cl_int clBuildProgram(cl_program, cl_uint, const cl_device_id *, const char *, void *, void *);
extern cl_int clGetProgramBuildInfo(cl_program, cl_device_id, cl_uint, size_t, void *, size_t *);
extern cl_kernel clCreateKernel(cl_program, const char *, cl_int *);
extern cl_mem clCreateBuffer(cl_context, cl_bitfield, size_t, void *, cl_int *);
extern cl_int clSetKernelArg(cl_kernel, cl_uint, size_t, const void *);
extern cl_int clEnqueueNDRangeKernel(cl_command_queue, cl_kernel, cl_uint, const size_t *, const size_t *,
                                     const size_t *, cl_uint, const cl_event *, cl_event *);
extern cl_int clEnqueueReadBuffer(cl_command_queue, cl_mem, cl_uint, size_t, size_t, void *, cl_uint,
                                  const cl_event *, cl_event *);
extern cl_int clEnqueueWriteBuffer(cl_command_queue, cl_mem, cl_uint, size_t, size_t, const void *, cl_uint,
                                   const cl_event *, cl_event *);
extern cl_int clFinish(cl_command_queue);

#define CHECK(e, what) if (e) { fprintf(stderr, "OpenCL error %d at %s\n", (int)(e), what); return 1; }
#define MAXHITS 200000

int main(int argc, char **argv) {
    if (argc < 4) { fprintf(stderr, "usage: colsweep_gpu TABLES w mineq [batch_log2]\n"); return 2; }
    static uint8_t T[16384];
    static uint64_t V[24 * 26];
    int tlen, w = atoi(argv[2]), mineq = atoi(argv[3]), blog = argc > 4 ? atoi(argv[4]) : 24;
    FILE *f = fopen(argv[1], "rb");
    if (!f || fread(&tlen, 4, 1, f) != 1 || fread(T, 1, tlen, f) != (size_t)tlen || fread(V, 8, 24 * 26, f) != 24 * 26) return 1;
    fclose(f);
    f = fopen("colsweep.cl", "rb");
    if (!f) { fprintf(stderr, "colsweep.cl not found (run from the project directory)\n"); return 1; }
    static char src[1 << 16];
    size_t n = fread(src, 1, sizeof src - 1, f);
    src[n] = 0;
    fclose(f);

    cl_int err;
    cl_platform_id plat[8]; cl_uint np = 0;
    CHECK(clGetPlatformIDs(8, plat, &np), "platforms");
    cl_device_id dev = 0;
    for (cl_uint i = 0; i < np && !dev; i++) { cl_uint nd = 0; if (clGetDeviceIDs(plat[i], CL_DEVICE_TYPE_GPU, 1, &dev, &nd) || !nd) dev = 0; }
    if (!dev) { fprintf(stderr, "no OpenCL GPU found\n"); return 1; }
    char name[256] = "";
    clGetDeviceInfo(dev, CL_DEVICE_NAME, sizeof name, name, 0);
    cl_context ctx = clCreateContext(0, 1, &dev, 0, 0, &err); CHECK(err, "context");
    cl_command_queue q = clCreateCommandQueue(ctx, dev, 0, &err); CHECK(err, "queue");
    const char *sp = src;
    cl_program prog = clCreateProgramWithSource(ctx, 1, &sp, 0, &err); CHECK(err, "source");
    err = clBuildProgram(prog, 1, &dev, "-I .", 0, 0);
    if (err) {
        static char log[1 << 16];
        clGetProgramBuildInfo(prog, dev, CL_PROGRAM_BUILD_LOG, sizeof log, log, 0);
        fprintf(stderr, "build failed:\n%s\n", log);
        return 1;
    }
    cl_kernel k = clCreateKernel(prog, "sweep", &err); CHECK(err, "kernel");
    uint64_t fact[21] = {1};
    for (int i = 1; i <= 20; i++) fact[i] = fact[i - 1] * i;
    static uint32_t hits[7 * MAXHITS];
    uint32_t count = 0, maxhits = MAXHITS;
    cl_mem bT = clCreateBuffer(ctx, CL_MEM_READ_ONLY | CL_MEM_COPY_HOST_PTR, tlen, T, &err); CHECK(err, "bT");
    cl_mem bV = clCreateBuffer(ctx, CL_MEM_READ_ONLY | CL_MEM_COPY_HOST_PTR, sizeof V, V, &err); CHECK(err, "bV");
    cl_mem bF = clCreateBuffer(ctx, CL_MEM_READ_ONLY | CL_MEM_COPY_HOST_PTR, sizeof fact, fact, &err); CHECK(err, "bF");
    cl_mem bC = clCreateBuffer(ctx, CL_MEM_READ_WRITE | CL_MEM_COPY_HOST_PTR, 4, &count, &err); CHECK(err, "bC");
    cl_mem bH = clCreateBuffer(ctx, CL_MEM_READ_WRITE, sizeof hits, 0, &err); CHECK(err, "bH");
    int st_off = 145 + 97 * 41;
    clSetKernelArg(k, 1, 4, &w); clSetKernelArg(k, 2, 4, &mineq); clSetKernelArg(k, 3, 4, &st_off);
    clSetKernelArg(k, 4, sizeof bT, &bT); clSetKernelArg(k, 5, sizeof bV, &bV); clSetKernelArg(k, 6, sizeof bF, &bF);
    clSetKernelArg(k, 7, sizeof bC, &bC); clSetKernelArg(k, 8, sizeof bH, &bH); clSetKernelArg(k, 9, 4, &maxhits);

    size_t batch = (size_t)1 << blog;
    uint64_t total = fact[w];
    time_t t0 = time(0), tlast = t0;
    for (uint64_t base = 0; base < total; base += batch) {
        clSetKernelArg(k, 0, 8, &base);
        CHECK(clEnqueueNDRangeKernel(q, k, 1, 0, &batch, 0, 0, 0, 0), "enqueue");
        CHECK(clFinish(q), "finish");
        time_t now = time(0);
        if (now - tlast >= 60) {
            tlast = now;
            fprintf(stderr, "  %s: %.1f%% after %ld s\n", name, 100.0 * (base + batch) / total, (long)(now - t0));
        }
    }
    CHECK(clEnqueueReadBuffer(q, bC, 1, 0, 4, &count, 0, 0, 0), "read count");
    if (count > MAXHITS) { fprintf(stderr, "hit buffer overflow (%u hits): raise mineq\n", count); count = MAXHITS; }
    if (count) CHECK(clEnqueueReadBuffer(q, bH, 1, 0, 28 * (size_t)count, hits, 0, 0, 0), "read hits");
    for (uint32_t i = 0; i < count; i++) {
        uint64_t r = hits[7 * i] | ((uint64_t)hits[7 * i + 1] << 32);
        int pool[32], m = w;
        for (int j = 0; j < w; j++) pool[j] = j;
        printf("HIT ");
        for (int j = 0; j < w; j++) {
            uint64_t fc = fact[w - 1 - j];
            int d = (int)(r / fc);
            r -= d * fc;
            printf("%d%s", pool[d], j + 1 < w ? "," : " ");
            for (int x = d; x < m - 1; x++) pool[x] = pool[x + 1];
            m--;
        }
        printf("%u %u %u %u %u\n", hits[7 * i + 2], hits[7 * i + 3], hits[7 * i + 4], hits[7 * i + 5], hits[7 * i + 6]);
    }
    printf("DONE %llu orders on %s in %ld s\n", (unsigned long long)total, name, (long)(time(0) - t0));
    return 0;
}
