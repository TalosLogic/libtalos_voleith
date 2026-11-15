/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * test_threading_alloc.c - the WS2 gate (T2.5): prove the threaded commit does
 * NO per-job / per-worker heap allocation.
 *
 * The prover's VOLE commit runs tau jobs across worker threads.  After T2.3 the
 * only buffer that was allocated per tau-job (the ConvertToVOLE butterfly `r`)
 * comes from preallocated per-worker scratch on the threading context, so a
 * commit's heap-allocation count must be a small CONSTANT that does not grow
 * with tau (the job count) or with the worker count.
 *
 * This test counts heap allocations (malloc / calloc / realloc) during one
 * scratch-backed voleith_vole_commit via the linker's --wrap mechanism, and
 * asserts the count is (a) small and (b) IDENTICAL for a tau=16 (em_128f) and a
 * tau=32 (em_256f) parameter set.  If any per-job or per-leaf allocation were
 * reintroduced, the tau=32 / larger-tree case would allocate strictly more and
 * the equality check would fail.
 *
 * Linux / GNU ld only (macOS ld64 has no --wrap); the CMake target is gated to
 * non-Apple.  The counted region excludes pool creation (done while counting is
 * off) and does no I/O, so only the library's own allocations are counted
 * (libc-internal allocations are not redirected by --wrap).
 */

/* POSIX for ichor's clock/thread bits pulled in transitively; harmless here. */
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200112L
#endif

#include "vc.h"
#include "convert.h"
#include <ichor/pool.h>

#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* The real allocators, provided by the linker under --wrap. */
extern void *__real_malloc(size_t);
extern void *__real_calloc(size_t, size_t);
extern void *__real_realloc(void *, size_t);
extern void __real_free(void *);

static atomic_int g_count_on = 0;
static atomic_long g_allocs = 0;

static void
bump(void)
{
    if (atomic_load_explicit(&g_count_on, memory_order_relaxed)) {
        atomic_fetch_add_explicit(&g_allocs, 1, memory_order_relaxed);
    }
}

void *
__wrap_malloc(size_t n)
{
    bump();
    return __real_malloc(n);
}

void *
__wrap_calloc(size_t n, size_t sz)
{
    bump();
    return __real_calloc(n, sz);
}

void *
__wrap_realloc(void *p, size_t n)
{
    bump();
    return __real_realloc(p, n);
}

void
__wrap_free(void *p)
{
    __real_free(p);
}

static int test_count = 0;
static int pass_count = 0;

static void
check(const char *name, int cond)
{
    test_count++;
    if (cond) {
        pass_count++;
    } else {
        printf("  FAIL: %s\n", name);
    }
}

/*
 * Run one scratch-backed voleith_vole_commit and return the number of heap
 * allocations it performed.  A warm commit precedes the counted one so any
 * lazily-initialized global state is already allocated and not counted.
 */
static long
count_commit_allocs(int lambda, int tau, int T_open, unsigned nthreads)
{
    voleith_vc_params_t p;
    voleith_vc_params_init(&p, lambda, tau, 8, 2, T_open);

    uint8_t seed[32], iv[16];
    for (size_t i = 0; i < sizeof(seed); i++)
        seed[i] = (uint8_t)(0x11 ^ i);
    for (size_t i = 0; i < sizeof(iv); i++)
        iv[i] = (uint8_t)(0x22 ^ i);

    unsigned int ellhat = 256;
    size_t eb = (ellhat + 7) / 8;
    size_t c_len = ((size_t)p.tau - 1) * eb;

    uint8_t *c = calloc(c_len, 1);
    uint8_t *u = calloc(eb, 1);
    uint8_t **v = calloc((size_t)p.lambda, sizeof(uint8_t *));
    uint8_t *vs = calloc((size_t)p.lambda * eb, 1);
    for (int i = 0; i < p.lambda; i++)
        v[i] = vs + (size_t)i * eb;

    ichor_pool_t *pool = NULL;
    ichor_pool_create(&pool, nthreads);
    voleith_threadctx_t tctx = {.pool = pool, .owns_pool = 0};
    voleith_threadctx_scratch_init(&tctx, &p, eb);

    /* Warm run (not counted): faults in the per-worker scratch slots. */
    voleith_bavc_t warm;
    voleith_vole_commit(&p, seed, iv, ellhat, &warm, c, u, v, &tctx);
    voleith_bavc_free(&warm);

    /* Counted run. */
    voleith_bavc_t bavc;
    atomic_store_explicit(&g_allocs, 0, memory_order_relaxed);
    atomic_store_explicit(&g_count_on, 1, memory_order_relaxed);
    voleith_vole_commit(&p, seed, iv, ellhat, &bavc, c, u, v, &tctx);
    atomic_store_explicit(&g_count_on, 0, memory_order_relaxed);
    long n = atomic_load_explicit(&g_allocs, memory_order_relaxed);
    voleith_bavc_free(&bavc);

    voleith_threadctx_scratch_free(&tctx);
    ichor_pool_destroy(pool);
    free(c);
    free(u);
    free(v);
    free(vs);
    return n;
}

int
main(void)
{
    printf("test_threading_alloc: per-job allocation gate (threaded=%d)\n",
           ichor_pool_threaded());

    /* tau=16 and tau=32 at 4 workers.  The only per-commit heap allocations are
     * the per-proof BAVC result buffers (tree + leaf_coms + leaf_seeds) and the
     * ichor per-batch label records, all independent of tau and worker count.
     * The per-worker scratch is preallocated, so the tau jobs allocate nothing.
     */
    long a128 = count_commit_allocs(128, 16, 112, 4);
    long a256 = count_commit_allocs(256, 32, 234, 4);

    printf("  allocs per scratch-backed commit: tau=16 -> %ld, tau=32 -> %ld\n",
           a128, a256);

    /* No per-job / per-leaf allocation: doubling tau (and the tree size) must
     * not change the count. */
    check("alloc count is tau-independent (no per-job allocation)",
          a128 == a256);

    /* Sanity bound: a handful of per-proof allocations, nowhere near tau. */
    check("alloc count is a small constant", a128 > 0 && a128 <= 16);

    /* Worker count must not change it either (scratch keyed by worker index,
     * preallocated per worker). */
    long a128_w8 = count_commit_allocs(128, 16, 112, 8);
    check("alloc count is worker-count-independent", a128_w8 == a128);

    printf("  %d / %d passed\n", pass_count, test_count);
    return (pass_count == test_count) ? 0 : 1;
}
