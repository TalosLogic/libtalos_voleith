/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * test_shipshape_witgen_cmac_grostl.c - equivalence tests for the W8.3c native
 * PARAMETRIC witness backends (parsers/shipshape_witgen_cmac_grostl.c).
 *
 * For each of the six PARAMETRIC entries (cmac/aes_128, cmac/aes_256,
 * grostl/hash_256, grostl/hash_256_t27, grostl/hash_512, grostl/hash_512_t59)
 * this generates the full witness twice over the same external inputs:
 *
 *   baseline:   no backend registered (generic Tier 1 evaluator).
 *   dispatched: register_cmac() + register_grostl() registered.
 *
 * The two MUST be byte-identical (same length, memcmp == 0).  This is the
 * STDLIB equivalence-oracle property: a Tier 2a backend is a pure speed layer
 * that must reproduce the generic witness exactly.
 *
 * Because these entries are PARAMETRIC (variable message length), each case is
 * run over MULTIPLE message lengths: structural name keying must serve every
 * length from one backend, and the lengths are chosen to cross padding and
 * compression-block boundaries (cmac: 0, 1, 16, 17, 40; grostl: 0, 1, 32, 64).
 *
 * The external-input bytes are arbitrary (incrementing test vectors).  Both
 * witgen paths interpret ext identically, so equivalence holds regardless of
 * whether the "key" / "msg" bytes are meaningful.
 */

#include "shipshape.h"
#include "shipshape_witgen_cmac_grostl.h"
#include "shipshape_witgen_dispatch.h"
#include "shipshape_witness.h"

#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

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

/* Fill buf[0..len-1] with incrementing bytes (deterministic test vector). */
static void
fill_incrementing(uint8_t *buf, size_t len)
{
    size_t i;

    for (i = 0; i < len; i++)
        buf[i] = (uint8_t)(i & 0xff);
}

/*
 * Run one equivalence case: parse `src`, generate the witness with no backend
 * (baseline) and with the cmac + grostl backends registered (dispatched), then
 * assert the two are byte-identical.
 *
 * ext / ext_len: the external WITNESS bytes in declaration order.
 */
static void
run_case(const char *name, const char *src, const uint8_t *ext, size_t ext_len)
{
    voleith_shipshape_parsed_t p = {0};
    uint8_t *baseline = NULL, *dispatched = NULL;
    size_t baseline_len = 0, dispatched_len = 0;
    int r;

    r = voleith_shipshape_parse_buffer(&p, src, 0, NULL);
    check(name, r == 0);
    if (r != 0) {
        voleith_shipshape_parsed_free(&p);
        return;
    }

    /* Sanity: ext_len must match the circuit's external witness length. */
    check(name, voleith_shipshape_external_witness_len(&p) == ext_len);

    /* Baseline: no backend registered. */
    voleith_shipshape_witgen_reset();
    r = voleith_shipshape_witness_gen(&p, ext, ext_len, NULL, 0, 0, &baseline,
                                      &baseline_len);
    check(name, r == 0 && baseline != NULL);

    /* Dispatched: cmac + grostl backends registered. */
    voleith_shipshape_witgen_reset();
    r = voleith_shipshape_witgen_register_cmac();
    check(name, r == 0);
    r = voleith_shipshape_witgen_register_grostl();
    check(name, r == 0);
    r = voleith_shipshape_witness_gen(&p, ext, ext_len, NULL, 0, 0, &dispatched,
                                      &dispatched_len);
    check(name, r == 0 && dispatched != NULL);

    /* Equivalence oracle: byte-for-byte identical. */
    check(name, baseline != NULL && dispatched != NULL &&
                    baseline_len == dispatched_len &&
                    memcmp(baseline, dispatched, baseline_len) == 0);

    free(baseline);
    free(dispatched);
    voleith_shipshape_parsed_free(&p);
    voleith_shipshape_witgen_reset();
}

/*
 * Build and run a cmac/* equivalence case for one (key_bytes, msg_len) pair.
 * The .ship source declares a key and a msg witness vector (byte[msg_len], or
 * byte[0] for the empty message) and makes one call to `fqn`.  ext is
 * key || msg = key_bytes + msg_len arbitrary bytes.
 */
static void
run_cmac_case(const char *name, const char *fqn, size_t key_bytes,
              size_t msg_len)
{
    char src[512];
    uint8_t ext[16 + 32 + 64];

    snprintf(src, sizeof(src),
             ".shipshape 1\n"
             "field GF(2^8) irreducible 0x11B\n"
             "stdlib crypto-v1\n"
             "WITNESS -> %%key : byte[%zu]\n"
             "WITNESS -> %%msg : byte[%zu]\n"
             "%s(%%key, %%msg) -> %%tag\n",
             key_bytes, msg_len, fqn);

    fill_incrementing(ext, key_bytes + msg_len);
    run_case(name, src, ext, key_bytes + msg_len);
}

/*
 * Build and run a grostl/* equivalence case for one msg_len.  The .ship source
 * declares a msg witness vector (byte[msg_len], or byte[0] for the empty
 * message) and makes one call to `fqn`.  ext is msg = msg_len arbitrary bytes.
 */
static void
run_grostl_case(const char *name, const char *fqn, size_t msg_len)
{
    char src[512];
    uint8_t ext[128];

    snprintf(src, sizeof(src),
             ".shipshape 1\n"
             "field GF(2^8) irreducible 0x11B\n"
             "stdlib crypto-v1\n"
             "WITNESS -> %%msg : byte[%zu]\n"
             "%s(%%msg) -> %%out\n",
             msg_len, fqn);

    fill_incrementing(ext, msg_len);
    run_case(name, src, ext, msg_len);
}

int
main(void)
{
    /*
     * cmac message lengths exercise padding and 16-byte block boundaries:
     *   0  -> empty (single padded block)
     *   1  -> sub-block (padded)
     *   16 -> exactly one block (no padding)
     *   17 -> one full block + one padded block
     *   40 -> multi-block with a partial final block
     */
    static const size_t cmac_lens[] = {0, 1, 16, 17, 40};
    /*
     * grostl message lengths cross compression-block boundaries:
     *   0  -> empty (padding-only block)
     *   1  -> sub-block
     *   32 -> half a 256 block / quarter of a 512 block
     *   64 -> exactly one 256 compression block (+ length spill)
     */
    static const size_t grostl_lens[] = {0, 1, 32, 64};
    char name[128];
    size_t i;

    printf("test_shipshape_witgen_cmac_grostl\n");

    /* 1. cmac/aes_128 over several message lengths. */
    for (i = 0; i < sizeof(cmac_lens) / sizeof(cmac_lens[0]); i++) {
        snprintf(name, sizeof(name), "cmac/aes_128 equivalence (msg=%zu)",
                 cmac_lens[i]);
        run_cmac_case(name, "stdlib/crypto/cmac/aes_128", 16, cmac_lens[i]);
    }

    /* 2. cmac/aes_256 over several message lengths. */
    for (i = 0; i < sizeof(cmac_lens) / sizeof(cmac_lens[0]); i++) {
        snprintf(name, sizeof(name), "cmac/aes_256 equivalence (msg=%zu)",
                 cmac_lens[i]);
        run_cmac_case(name, "stdlib/crypto/cmac/aes_256", 32, cmac_lens[i]);
    }

    /* 3. grostl/hash_256 over several message lengths. */
    for (i = 0; i < sizeof(grostl_lens) / sizeof(grostl_lens[0]); i++) {
        snprintf(name, sizeof(name), "grostl/hash_256 equivalence (msg=%zu)",
                 grostl_lens[i]);
        run_grostl_case(name, "stdlib/crypto/grostl/hash_256", grostl_lens[i]);
    }

    /* 4. grostl/hash_256_t27: shares the hash_256 witness builder. */
    for (i = 0; i < sizeof(grostl_lens) / sizeof(grostl_lens[0]); i++) {
        snprintf(name, sizeof(name),
                 "grostl/hash_256_t27 equivalence (msg=%zu)", grostl_lens[i]);
        run_grostl_case(name, "stdlib/crypto/grostl/hash_256_t27",
                        grostl_lens[i]);
    }

    /* 5. grostl/hash_512 over several message lengths. */
    for (i = 0; i < sizeof(grostl_lens) / sizeof(grostl_lens[0]); i++) {
        snprintf(name, sizeof(name), "grostl/hash_512 equivalence (msg=%zu)",
                 grostl_lens[i]);
        run_grostl_case(name, "stdlib/crypto/grostl/hash_512", grostl_lens[i]);
    }

    /* 6. grostl/hash_512_t59: shares the hash_512 witness builder. */
    for (i = 0; i < sizeof(grostl_lens) / sizeof(grostl_lens[0]); i++) {
        snprintf(name, sizeof(name),
                 "grostl/hash_512_t59 equivalence (msg=%zu)", grostl_lens[i]);
        run_grostl_case(name, "stdlib/crypto/grostl/hash_512_t59",
                        grostl_lens[i]);
    }

    printf("%d/%d tests passed\n", pass_count, test_count);
    return pass_count == test_count ? 0 : 1;
}
