/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * test_shipshape_witgen_construction_bench.c - W8.6 performance sanity check for
 * the crypto-v2 CONSTRUCTION witness backends (labelled "slow").
 *
 * Generates the full witness for a DEEP secret-direction Merkle path many times
 * two ways:
 *   (a) no backend registered: the generic Tier 1 evaluator runs the
 *       brute-force voleith_gf8_inv per S-box internal witness across the leaf
 *       hash and every inode hash on the path.
 *   (b) the construction backends registered: the skip is active, so the
 *       backend fills the span natively (vt leaf / inode build-witness walk) and
 *       the generic pass skips the inverse for those slots.
 *
 * A deep tree is used so the per-inode inv scan dominates and the dispatched
 * path has real work to short-circuit.  The only HARD assertion is that the two
 * witnesses are byte-identical (the correctness gate; a faster path that changes
 * output is a bug).  Timings are printed for information only and never
 * asserted.
 *
 * Vehicle: merkle/path_secret[grostl_256] at depth 8.  grostl_256 (32-byte
 * nodes) gives the most inode S-box work per level among the cheap options.
 * The root is an OUTPUT wire, so no instance bytes are needed; a consistent tree
 * is not required (the inv span is independent of constraint satisfaction).
 */

#include "shipshape.h"
#include "shipshape_witgen_construction.h"
#include "shipshape_witgen_dispatch.h"
#include "shipshape_witness.h"
#include "util.h"

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

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

/* crypto-v2 header. */
#define HDR_V2                                                                 \
    ".shipshape 1\n"                                                           \
    "field GF(2^8) irreducible 0x11B\n"                                        \
    "stdlib crypto-v2\n"

/* grostl_256 node width and the path depth. */
#define NODE_BYTES 32u
#define DEPTH 8u
#define LEAF_BYTES 16u

/*
 * merkle/path_secret[grostl_256] at depth 8:
 *   leaf=16, sib=8*32=256, dirs=8.  ext = leaf(16)|sib(256)|dirs(8), len=280.
 *   root is an OUTPUT wire, not INSTANCE.
 */
#define BENCH_SRC                                                              \
    HDR_V2 "WITNESS  -> %leaf : byte[16]\n"                                    \
           "WITNESS  -> %sib  : byte[256]\n"                                   \
           "WITNESS  -> %dirs : byte[8]\n"                                     \
           "stdlib/crypto/merkle/path_secret[grostl_256]"                      \
           "(%leaf, %sib, %dirs) -> %root\n"

#define EXT_LEN (LEAF_BYTES + DEPTH * NODE_BYTES + DEPTH)

/* Generate the witness ITERS times; return total CPU seconds, or -1.0. */
static double
time_witgen(const voleith_shipshape_parsed_t *p, const uint8_t *ext,
            size_t ext_len, int iters, uint8_t **last_out, size_t *last_len)
{
    clock_t t0, t1;
    uint8_t *wit = NULL;
    size_t wit_len = 0;
    int i, r;

    *last_out = NULL;
    *last_len = 0;

    t0 = clock();
    for (i = 0; i < iters; i++) {
        wit = NULL;
        wit_len = 0;
        r = voleith_shipshape_witness_gen(p, ext, ext_len, NULL, 0, 0, &wit,
                                          &wit_len);
        if (r != 0) {
            free(wit);
            return -1.0;
        }
        if (i == iters - 1) {
            /* Keep the last witness for the equivalence check. */
            *last_out = wit;
            *last_len = wit_len;
        } else {
            if (wit != NULL)
                voleith_secure_zero(wit, wit_len);
            free(wit);
        }
    }
    t1 = clock();
    return (double)(t1 - t0) / (double)CLOCKS_PER_SEC;
}

int
main(void)
{
    voleith_shipshape_parsed_t p = {0};
    uint8_t ext[EXT_LEN];
    uint8_t *generic = NULL, *dispatched = NULL;
    size_t generic_len = 0, dispatched_len = 0;
    double t_generic, t_dispatched;
    const int iters = 20;
    size_t i;
    int r;

    printf("test_shipshape_witgen_construction_bench (slow)\n");

    /* Deterministic ext; dirs (the last DEPTH bytes) must be in {0,1}. */
    for (i = 0; i < LEAF_BYTES + DEPTH * NODE_BYTES; i++)
        ext[i] = (uint8_t)(i & 0xff);
    for (i = 0; i < DEPTH; i++)
        ext[LEAF_BYTES + DEPTH * NODE_BYTES + i] = (uint8_t)(i & 1u);

    r = voleith_shipshape_parse_buffer(&p, BENCH_SRC, 0, NULL);
    check("bench: parses", r == 0 && p.circuit != NULL);
    if (r != 0 || p.circuit == NULL) {
        voleith_shipshape_parsed_free(&p);
        printf("%d/%d tests passed\n", pass_count, test_count);
        return 1;
    }

    /* (a) generic: no backend registered. */
    voleith_shipshape_witgen_reset();
    t_generic =
        time_witgen(&p, ext, sizeof(ext), iters, &generic, &generic_len);
    check("bench: generic gen succeeds", t_generic >= 0.0 && generic != NULL);

    /* (b) dispatched: construction backends registered. */
    voleith_shipshape_witgen_reset();
    check("bench: register construction backends",
          voleith_shipshape_witgen_register_constructions() == 0);
    t_dispatched =
        time_witgen(&p, ext, sizeof(ext), iters, &dispatched, &dispatched_len);
    check("bench: dispatched gen succeeds",
          t_dispatched >= 0.0 && dispatched != NULL);

    /* HARD gate: byte-identical output. */
    check("bench: dispatched witness equals generic byte-for-byte",
          generic != NULL && dispatched != NULL &&
              generic_len == dispatched_len &&
              memcmp(generic, dispatched, generic_len) == 0);

    if (t_generic > 0.0 && t_dispatched > 0.0) {
        printf("  generic:    %.4f s over %d iters\n", t_generic, iters);
        printf("  dispatched: %.4f s over %d iters\n", t_dispatched, iters);
        printf("  speedup:    %.2fx\n", t_generic / t_dispatched);
    }

    if (generic != NULL)
        voleith_secure_zero(generic, generic_len);
    free(generic);
    if (dispatched != NULL)
        voleith_secure_zero(dispatched, dispatched_len);
    free(dispatched);
    voleith_shipshape_witgen_reset();
    voleith_shipshape_parsed_free(&p);

    printf("%d/%d tests passed\n", pass_count, test_count);
    return pass_count == test_count ? 0 : 1;
}
