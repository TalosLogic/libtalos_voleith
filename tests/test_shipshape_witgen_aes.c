/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * test_shipshape_witgen_aes.c - equivalence tests for the W8.3b native AES
 * witness backends (parsers/shipshape_witgen_aes.c).
 *
 * For each of the seven FIXED aes/* registry entries this generates the full
 * witness twice over the same external inputs:
 *
 *   baseline:   no backend registered (generic Tier 1 evaluator).
 *   dispatched: voleith_shipshape_witgen_register_aes() registered.
 *
 * The two MUST be byte-identical (same length, memcmp == 0).  This is the
 * STDLIB equivalence-oracle property: a Tier 2a backend is a pure speed layer
 * that must reproduce the generic witness exactly.
 *
 * The external-input bytes are arbitrary (incrementing test vectors).  For the
 * encrypt_rounds_* entries the "round keys" are fed as arbitrary bytes, not a
 * real key schedule: the test only compares the two witgen paths against each
 * other, and both interpret ext identically, so the inv-witnesses match
 * regardless of whether the round keys are a valid schedule.
 */

#include "shipshape.h"
#include "shipshape_witgen_aes.h"
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

/* ================================================================
 * Per-entry .ship sources.  Each declares its external WITNESS inputs in
 * signature order and makes one call to the entry under test.
 * ================================================================ */

#define SBOX_SRC                                                               \
    ".shipshape 1\n"                                                           \
    "field GF(2^8) irreducible 0x11B\n"                                        \
    "stdlib crypto-v1\n"                                                       \
    "WITNESS -> %a : byte\n"                                                   \
    "stdlib/crypto/aes/sbox(%a) -> %b\n"

#define KS128_SRC                                                              \
    ".shipshape 1\n"                                                           \
    "field GF(2^8) irreducible 0x11B\n"                                        \
    "stdlib crypto-v1\n"                                                       \
    "WITNESS -> %key : byte[16]\n"                                             \
    "stdlib/crypto/aes/keyschedule_128(%key) -> %rk\n"

#define ENCR128_SRC                                                            \
    ".shipshape 1\n"                                                           \
    "field GF(2^8) irreducible 0x11B\n"                                        \
    "stdlib crypto-v1\n"                                                       \
    "WITNESS -> %rk : byte[176]\n"                                             \
    "WITNESS -> %pt : byte[16]\n"                                              \
    "stdlib/crypto/aes/encrypt_rounds_128(%rk, %pt) -> %ct\n"

#define ENC128_SRC                                                             \
    ".shipshape 1\n"                                                           \
    "field GF(2^8) irreducible 0x11B\n"                                        \
    "stdlib crypto-v1\n"                                                       \
    "WITNESS -> %key : byte[16]\n"                                             \
    "WITNESS -> %pt : byte[16]\n"                                              \
    "stdlib/crypto/aes/encrypt_128(%key, %pt) -> %ct\n"

#define KS256_SRC                                                              \
    ".shipshape 1\n"                                                           \
    "field GF(2^8) irreducible 0x11B\n"                                        \
    "stdlib crypto-v1\n"                                                       \
    "WITNESS -> %key : byte[32]\n"                                             \
    "stdlib/crypto/aes/keyschedule_256(%key) -> %rk\n"

#define ENCR256_SRC                                                            \
    ".shipshape 1\n"                                                           \
    "field GF(2^8) irreducible 0x11B\n"                                        \
    "stdlib crypto-v1\n"                                                       \
    "WITNESS -> %rk : byte[240]\n"                                             \
    "WITNESS -> %pt : byte[16]\n"                                              \
    "stdlib/crypto/aes/encrypt_rounds_256(%rk, %pt) -> %ct\n"

#define ENC256_SRC                                                             \
    ".shipshape 1\n"                                                           \
    "field GF(2^8) irreducible 0x11B\n"                                        \
    "stdlib crypto-v1\n"                                                       \
    "WITNESS -> %key : byte[32]\n"                                             \
    "WITNESS -> %pt : byte[16]\n"                                              \
    "stdlib/crypto/aes/encrypt_256(%key, %pt) -> %ct\n"

/*
 * Run one equivalence case: parse `src`, generate witness without backends
 * (baseline) and with the AES backends registered (dispatched), assert the
 * two are byte-identical.
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

    /* Dispatched: AES backends registered. */
    voleith_shipshape_witgen_reset();
    r = voleith_shipshape_witgen_register_aes();
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

/* Fill buf[0..len-1] with incrementing bytes (deterministic test vector). */
static void
fill_incrementing(uint8_t *buf, size_t len)
{
    size_t i;

    for (i = 0; i < len; i++)
        buf[i] = (uint8_t)(i & 0xff);
}

int
main(void)
{
    uint8_t ext[256];

    printf("test_shipshape_witgen_aes\n");

    /* 1. sbox: 1 input byte. */
    fill_incrementing(ext, 1);
    ext[0] = 0x53; /* nonzero S-box input */
    run_case("sbox equivalence", SBOX_SRC, ext, 1);

    /* sbox zero input: inv_in must be 0 in both paths. */
    ext[0] = 0x00;
    run_case("sbox zero-input equivalence", SBOX_SRC, ext, 1);

    /* 2. keyschedule_128: key byte[16] = 16 ext bytes. */
    fill_incrementing(ext, 16);
    run_case("keyschedule_128 equivalence", KS128_SRC, ext, 16);

    /* 3. encrypt_rounds_128: rk byte[176] + pt byte[16] = 192 ext bytes. */
    fill_incrementing(ext, 192);
    run_case("encrypt_rounds_128 equivalence", ENCR128_SRC, ext, 192);

    /* 4. encrypt_128: key byte[16] + pt byte[16] = 32 ext bytes. */
    fill_incrementing(ext, 32);
    run_case("encrypt_128 equivalence", ENC128_SRC, ext, 32);

    /* 5. keyschedule_256: key byte[32] = 32 ext bytes. */
    fill_incrementing(ext, 32);
    run_case("keyschedule_256 equivalence", KS256_SRC, ext, 32);

    /* 6. encrypt_rounds_256: rk byte[240] + pt byte[16] = 256 ext bytes. */
    fill_incrementing(ext, 256);
    run_case("encrypt_rounds_256 equivalence", ENCR256_SRC, ext, 256);

    /* 7. encrypt_256: key byte[32] + pt byte[16] = 48 ext bytes. */
    fill_incrementing(ext, 48);
    run_case("encrypt_256 equivalence", ENC256_SRC, ext, 48);

    printf("%d/%d tests passed\n", pass_count, test_count);
    return pass_count == test_count ? 0 : 1;
}
