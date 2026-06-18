/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * test_shipshape_witgen_bench.c - W8.4 performance sanity check for the Tier 2a
 * interleaved-skip witness dispatch (labelled "slow").
 *
 * Generates the full witness for an AES-heavy circuit many times two ways:
 *   (a) no backend registered: the generic Tier 1 evaluator runs the
 *       brute-force voleith_gf8_inv per S-box internal witness.
 *   (b) the AES and CMAC backends registered: the skip is active, so the
 *       backends fill the witness span natively and the generic pass skips the
 *       inverse for those slots.
 *
 * The only HARD assertion is that the two witnesses are byte-identical (the
 * correctness gate; a faster path that changes output is a bug).  Timings are
 * printed for information only: absolute timing is host-dependent and flaky, so
 * it is never asserted.
 */

#include "shipshape.h"
#include "shipshape_witgen_aes.h"
#include "shipshape_witgen_cmac_grostl.h"
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

/*
 * cmac/aes_128 over a 256-byte message: 16 CBC blocks plus the subkey block,
 * each an AES-128 encryption (200 S-box inverses), so the witness has many
 * thousands of brute-force inverses on the generic path.
 */
#define MSG_LEN 256
#define BENCH_SRC                                                              \
    ".shipshape 1\n"                                                           \
    "field GF(2^8) irreducible 0x11B\n"                                        \
    "stdlib crypto-v1\n"                                                       \
    "WITNESS -> %key : byte[16]\n"                                             \
    "WITNESS -> %msg : byte[256]\n"                                            \
    "stdlib/crypto/cmac/aes_128(%key, %msg) -> %tag\n"

/* Generate the witness ITERS times; return total wall-ish CPU seconds. */
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
    uint8_t ext[16 + MSG_LEN];
    uint8_t *generic = NULL, *dispatched = NULL;
    size_t generic_len = 0, dispatched_len = 0;
    double t_generic, t_dispatched;
    const int iters = 20;
    size_t i;
    int r;

    printf("test_shipshape_witgen_bench (slow)\n");

    for (i = 0; i < sizeof(ext); i++)
        ext[i] = (uint8_t)(i & 0xff);

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

    /* (b) dispatched: AES and CMAC backends registered. */
    voleith_shipshape_witgen_reset();
    check("bench: register AES backends",
          voleith_shipshape_witgen_register_aes() == 0);
    check("bench: register CMAC backends",
          voleith_shipshape_witgen_register_cmac() == 0);
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
