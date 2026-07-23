/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * test_shipshape_witness.c - generic Tier 1 witness generator (W6.2 of
 * the implementation plan; the witness-generation design).
 *
 * For each registry primitive, parse a `.ship` calling it with the same
 * witness / instance split the hand-written builder assumes, run the generic
 * evaluator over the external input, and assert the full witness array equals
 * the corresponding circuits/<...>_build_witness output byte for byte.  Plus the
 * INV fill directly (a bare INV), a hand-written INV pattern (external, not
 * filled), an INSTANCE + MUL circuit, and the input-validation error paths.
 *
 * The witness / instance split per primitive matches the GF(2^8) examples:
 *   AES   key = witness, plaintext = instance  (witness = key + S-box invs)
 *   CMAC  key = witness, message  = instance   (witness = key + invs)
 *   Grostl message = witness                   (witness = msg + invs)
 */

#include "aes_cmac_gf8_circuit.h"
#include "aes_gf8_circuit.h"
#include "field.h"
#include "gf8_circuit.h"
#include "grostl_gf8_circuit.h"
#include "shipshape.h"
#include "shipshape_witness.h"

#include <stddef.h>
#include <stdint.h>
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

#define HDR                                                                    \
    ".shipshape 1\n"                                                           \
    "field GF(2^8) irreducible 0x11B\n"                                        \
    "stdlib crypto-v1\n"

/* Deterministic non-trivial filler so key/pt/msg are not all-equal. */
static void
fill(uint8_t *buf, size_t n, uint8_t seed)
{
    for (size_t i = 0; i < n; i++)
        buf[i] = (uint8_t)(seed + i * 7u + (i >> 2));
}

/*
 * Parse `src`, generate the witness over (ext, inst), and assert it equals
 * the `ref` array (which witness_count must also match).  `flags` is passed
 * to the generator (SELF_CHECK for the registry circuits, whose constraints
 * the completed witness must satisfy).
 */
static void
gen_eq(const char *name, const char *src, const uint8_t *ext, size_t ext_len,
       const uint8_t *inst, size_t inst_len, const uint8_t *ref, size_t ref_len,
       unsigned flags)
{
    voleith_shipshape_parsed_t p;
    uint8_t *out = NULL;
    size_t out_len = 0;
    char label[96];
    int r;

    r = voleith_shipshape_parse_buffer(&p, src, 0, NULL);
    snprintf(label, sizeof(label), "%s: parses", name);
    check(label, r == 0 && p.circuit != NULL);

    if (r == 0 && p.circuit != NULL) {
        snprintf(label, sizeof(label), "%s: witness_count", name);
        check(label, voleith_gf8_circuit_witness_count(p.circuit) == ref_len);

        r = voleith_shipshape_witness_gen(&p, ext, ext_len, inst, inst_len,
                                          flags, &out, &out_len);
        snprintf(label, sizeof(label), "%s: gen ok", name);
        check(label, r == 0);
        snprintf(label, sizeof(label), "%s: equals build_witness", name);
        check(label, r == 0 && out_len == ref_len && out != NULL &&
                         memcmp(out, ref, ref_len) == 0);
    }

    free(out);
    voleith_shipshape_parsed_free(&p);
}

static void
test_aes(void)
{
    uint8_t key[32], pt[16], ct[16];
    uint8_t ref128[216], ref256[308];
    uint8_t ext[32];

    /* AES-128: key witness, pt instance. */
    fill(key, 16, 0x11);
    fill(pt, 16, 0x80);
    aes128_gf8_build_witness(key, pt, ref128, ct);
    memcpy(ext, key, 16);
    gen_eq("aes/encrypt_128",
           HDR "WITNESS -> %key : byte[16]\n"
               "INSTANCE -> %pt : byte[16]\n"
               "stdlib/crypto/aes/encrypt_128(%key, %pt) -> %ct\n",
           ext, 16, pt, 16, ref128, 216, VOLEITH_SHIPSHAPE_WITGEN_SELF_CHECK);

    /* AES-256: 32-byte key witness, pt instance. */
    fill(key, 32, 0x22);
    fill(pt, 16, 0x40);
    aes256_gf8_build_witness(key, pt, ref256, ct);
    memcpy(ext, key, 32);
    gen_eq("aes/encrypt_256",
           HDR "WITNESS -> %key : byte[32]\n"
               "INSTANCE -> %pt : byte[16]\n"
               "stdlib/crypto/aes/encrypt_256(%key, %pt) -> %ct\n",
           ext, 32, pt, 16, ref256, 308, VOLEITH_SHIPSHAPE_WITGEN_SELF_CHECK);
}

static void
test_cmac(void)
{
    uint8_t key[32], msg[40], tag[16];
    uint8_t *ref;
    size_t rlen;

    /* CMAC-128 over 40 bytes: key witness, message instance. */
    fill(key, 16, 0x33);
    fill(msg, 40, 0x10);
    rlen = aes_cmac_gf8_witness_bytes(16, 40);
    ref = malloc(rlen);
    if (ref != NULL) {
        aes_cmac_gf8_build_witness(key, 16, msg, 40, ref, tag);
        gen_eq("cmac/aes_128 n=40",
               HDR "WITNESS -> %key : byte[16]\n"
                   "INSTANCE -> %msg : byte[40]\n"
                   "stdlib/crypto/cmac/aes_128(%key, %msg) -> %tag\n",
               key, 16, msg, 40, ref, rlen,
               VOLEITH_SHIPSHAPE_WITGEN_SELF_CHECK);
        free(ref);
    }

    /* CMAC-256 over 16 bytes (single block): 32-byte key witness. */
    fill(key, 32, 0x44);
    fill(msg, 16, 0x20);
    rlen = aes_cmac_gf8_witness_bytes(32, 16);
    ref = malloc(rlen);
    if (ref != NULL) {
        aes_cmac_gf8_build_witness(key, 32, msg, 16, ref, tag);
        gen_eq("cmac/aes_256 n=16",
               HDR "WITNESS -> %key : byte[32]\n"
                   "INSTANCE -> %msg : byte[16]\n"
                   "stdlib/crypto/cmac/aes_256(%key, %msg) -> %tag\n",
               key, 32, msg, 16, ref, rlen,
               VOLEITH_SHIPSHAPE_WITGEN_SELF_CHECK);
        free(ref);
    }
}

static void
test_grostl(void)
{
    uint8_t msg[120];
    uint8_t *ref;
    size_t rlen;

    /* Grostl-256 over 55 bytes: message is witness. */
    fill(msg, 55, 0x55);
    rlen = grostl256_gf8_witness_bytes(55);
    ref = malloc(rlen);
    if (ref != NULL) {
        grostl256_gf8_build_witness(msg, 55, ref);
        gen_eq("grostl/hash_256 n=55",
               HDR "WITNESS -> %msg : byte[55]\n"
                   "stdlib/crypto/grostl/hash_256(%msg) -> %h\n",
               msg, 55, NULL, 0, ref, rlen,
               VOLEITH_SHIPSHAPE_WITGEN_SELF_CHECK);
        free(ref);
    }

    /* Grostl-512 over 120 bytes. */
    fill(msg, 120, 0x66);
    rlen = grostl512_gf8_witness_bytes(120);
    ref = malloc(rlen);
    if (ref != NULL) {
        grostl512_gf8_build_witness(msg, 120, ref);
        gen_eq("grostl/hash_512 n=120",
               HDR "WITNESS -> %msg : byte[120]\n"
                   "stdlib/crypto/grostl/hash_512(%msg) -> %h\n",
               msg, 120, NULL, 0, ref, rlen,
               VOLEITH_SHIPSHAPE_WITGEN_SELF_CHECK);
        free(ref);
    }
}

static void
test_inv_and_instance(void)
{
    uint8_t a = 0x53;
    uint8_t ref2[2];

    /* Bare INV: the internal witness is the field inverse of its source. */
    ref2[0] = a;
    ref2[1] = (uint8_t)voleith_gf8_inv(a);
    gen_eq("inv: sugar fills inverse",
           HDR "WITNESS -> %a : byte\n"
               "INV %a -> %ai\n",
           &a, 1, NULL, 0, ref2, 2, VOLEITH_SHIPSHAPE_WITGEN_SELF_CHECK);

    /*
     * Hand-written INV pattern: the inverse witness is declared, so it is
     * EXTERNAL and passed through verbatim, not computed.  Supplying a value
     * that is not the inverse proves it is not being filled (no self-check,
     * since that value violates the product).
     */
    {
        uint8_t ext[2] = {a, 0xAB}; /* 0xAB is not inv(a) */
        uint8_t ref_ext[2] = {a, 0xAB};

        gen_eq("inv: hand-written witness is external",
               HDR "WITNESS -> %a : byte\n"
                   "WITNESS -> %ai : byte\n"
                   "SQUARE %a -> %a2\n"
                   "ASSERT_PRODUCT %a2 %ai %a\n"
                   "SQUARE %ai -> %ai2\n"
                   "ASSERT_PRODUCT %a %ai2 %ai\n",
               ext, 2, NULL, 0, ref_ext, 2, 0);
    }

    /* INSTANCE threading with a MUL gate; the lone witness passes through. */
    {
        uint8_t wa = 0x9C, ib = 0x3D;
        uint8_t ref1[1] = {wa};

        gen_eq("instance: witness + instance MUL",
               HDR "WITNESS -> %a : byte\n"
                   "INSTANCE -> %b : byte\n"
                   "MUL %a %b -> %p\n",
               &wa, 1, &ib, 1, ref1, 1, VOLEITH_SHIPSHAPE_WITGEN_SELF_CHECK);
    }
}

static void
test_errors(void)
{
    voleith_shipshape_parsed_t p;
    uint8_t a = 0x01, out_sentinel;
    uint8_t *out = (uint8_t *)&out_sentinel;
    size_t out_len = 99;
    int r;

    r = voleith_shipshape_parse_buffer(
        &p, HDR "WITNESS -> %a : byte\nINV %a -> %ai\n", 0, NULL);
    check("errors: setup parses", r == 0);

    /* External length mismatch (expects 1 byte, given 2). */
    {
        uint8_t ext2[2] = {a, a};
        r = voleith_shipshape_witness_gen(&p, ext2, 2, NULL, 0, 0, &out,
                                          &out_len);
        check("errors: wrong ext len => EXT_LEN",
              r == VOLEITH_SHIPSHAPE_WITGEN_EXT_LEN && out == NULL &&
                  out_len == 0);
    }

    /* Instance length mismatch (circuit has no instance wires). */
    out = (uint8_t *)&out_sentinel;
    out_len = 99;
    r = voleith_shipshape_witness_gen(&p, &a, 1, &a, 1, 0, &out, &out_len);
    check("errors: wrong instance len => INSTANCE_LEN",
          r == VOLEITH_SHIPSHAPE_WITGEN_INSTANCE_LEN && out == NULL);

    /* NULL out pointer. */
    r = voleith_shipshape_witness_gen(&p, &a, 1, NULL, 0, 0, NULL, &out_len);
    check("errors: NULL out => NULL_ARG",
          r == VOLEITH_SHIPSHAPE_WITGEN_NULL_ARG);

    voleith_shipshape_parsed_free(&p);

    /* NULL parsed. */
    out = (uint8_t *)&out_sentinel;
    r = voleith_shipshape_witness_gen(NULL, &a, 1, NULL, 0, 0, &out, &out_len);
    check("errors: NULL parsed => NULL_ARG",
          r == VOLEITH_SHIPSHAPE_WITGEN_NULL_ARG && out == NULL);
}

int
main(void)
{
    printf("test_shipshape_witness: starting\n");
    test_aes();
    test_cmac();
    test_grostl();
    test_inv_and_instance();
    test_errors();
    printf("test_shipshape_witness: %d/%d passed\n", pass_count, test_count);
    return (pass_count == test_count) ? 0 : 1;
}
