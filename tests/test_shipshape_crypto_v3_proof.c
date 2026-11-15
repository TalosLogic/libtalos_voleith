/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * test_shipshape_crypto_v3_proof.c - prove / verify round-trip for crypto-v3
 * norm standalone registry entries, driven entirely through the generic
 * witness generator (the Shipshape spec 7.8).
 *
 * The norm entries commit packed subfield-norm and s_tilde witnesses that the
 * frozen inverse-fill path cannot derive; the generic generator now solves
 * them (parsers/shipshape_witness.c).  These entries are pure functions (no
 * INSTANCE), so the statement proved is "I know inputs producing this output":
 * a successful witness-gen under SELF_CHECK means every internal norm
 * constraint (PRODUCT3 and the paired-round reset) holds, i.e. the generic
 * generator produced the correct norm witnesses.  prove/verify then closes the
 * pipeline.  A corrupted internal (norm) witness byte must make the prover
 * reject, confirming the norm witnesses are genuinely constrained.
 *
 * aes/encrypt_128_norm exercises the AES norm solver; grostl/hash_256_norm
 * exercises the Grostl norm solver (and the PARAMETRIC path).
 */

#include "gf8_proof.h"
#include "shipshape.h"
#include "shipshape_witness.h"
#include "util.h"

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

#define HDR_V3                                                                 \
    ".shipshape 1\n"                                                           \
    "field GF(2^8) irreducible 0x11B\n"                                        \
    "stdlib crypto-v3\n"

/* aes/encrypt_128_norm: (key : byte[16], pt : byte[16]) -> (ct : byte[16]). */
static const char AES_SRC[] =
    HDR_V3 "WITNESS -> %key : byte[16]\n"
           "WITNESS -> %pt  : byte[16]\n"
           "stdlib/crypto/aes/encrypt_128_norm(%key, %pt) -> %ct\n";

/* grostl/hash_256_norm: (msg : byte[n]) -> (out : byte[32]). */
static const char GROSTL_SRC[] =
    HDR_V3 "WITNESS -> %msg : byte[16]\n"
           "stdlib/crypto/grostl/hash_256_norm(%msg) -> %out\n";

static const uint8_t FS_SEED[16] = {0x11, 0x22, 0x33, 0x44, 0x55, 0x66,
                                    0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC,
                                    0xDD, 0xEE, 0xFF, 0x01};

static void
zfree(uint8_t *buf, size_t len)
{
    if (buf != NULL && len > 0)
        voleith_secure_zero(buf, len);
    free(buf);
}

/*
 * Parse a norm standalone entry, generate its witness generically (SELF_CHECK
 * on), prove, verify, and reject a tampered proof.  No INSTANCE wires.
 */
static void
roundtrip(const char *label, const char *src, const uint8_t *ext,
          size_t ext_len)
{
    const voleith_params_t *params = &voleith_params_em_128f;
    voleith_shipshape_parsed_t p;
    voleith_proof_t proof;
    uint8_t *wit = NULL;
    size_t wit_len = 0;
    char line[128];
    int r;

    r = voleith_shipshape_parse_buffer(&p, src, 0, NULL);
    snprintf(line, sizeof(line), "%s: parse ok", label);
    check(line, r == 0 && p.circuit != NULL);
    if (r != 0 || p.circuit == NULL) {
        voleith_shipshape_parsed_free(&p);
        return;
    }

    /* Generic witness generation fills the norm witnesses; SELF_CHECK means a
     * wrong norm witness is caught here. */
    r = voleith_shipshape_witness_gen(&p, ext, ext_len, NULL, 0,
                                      VOLEITH_SHIPSHAPE_WITGEN_SELF_CHECK, &wit,
                                      &wit_len);
    snprintf(line, sizeof(line), "%s: generic witgen ok", label);
    check(line, r == 0);

    if (r == 0) {
        r = voleith_gf8_prove_v2(&proof, params, p.circuit, wit, wit_len, NULL,
                                 0, FS_SEED, sizeof(FS_SEED));
        snprintf(line, sizeof(line), "%s: prove ok", label);
        check(line, r == 0);

        if (r == 0) {
            r = voleith_gf8_verify_v2(&proof, params, p.circuit, NULL, 0,
                                      FS_SEED, sizeof(FS_SEED));
            snprintf(line, sizeof(line), "%s: verify accepts", label);
            check(line, r == 0);

            proof.data[0] ^= 0xFF;
            r = voleith_gf8_verify_v2(&proof, params, p.circuit, NULL, 0,
                                      FS_SEED, sizeof(FS_SEED));
            snprintf(line, sizeof(line), "%s: tampered proof rejected", label);
            check(line, r != 0);
            proof.data[0] ^= 0xFF;

            voleith_proof_free(&proof);
        }
    }

    zfree(wit, wit_len);
    voleith_shipshape_parsed_free(&p);
}

/*
 * Corrupt an internal (norm) witness byte and confirm the prover rejects: the
 * last witness byte is a norm s_tilde commitment (the external key||pt bytes
 * are first), so flipping it violates a paired-round reset constraint.
 */
static void
test_corrupt_norm_witness(void)
{
    const voleith_params_t *params = &voleith_params_em_128f;
    voleith_shipshape_parsed_t p;
    voleith_proof_t proof;
    uint8_t ext[32];
    uint8_t *wit = NULL;
    size_t wit_len = 0;
    int r;

    for (size_t i = 0; i < sizeof(ext); i++)
        ext[i] = (uint8_t)(i * 7u + 0x3Au);

    r = voleith_shipshape_parse_buffer(&p, AES_SRC, 0, NULL);
    check("corrupt: parse ok", r == 0 && p.circuit != NULL);
    if (r != 0 || p.circuit == NULL) {
        voleith_shipshape_parsed_free(&p);
        return;
    }

    /* No SELF_CHECK: we want the (now corrupted) witness to reach the prover. */
    r = voleith_shipshape_witness_gen(&p, ext, sizeof(ext), NULL, 0, 0, &wit,
                                      &wit_len);
    check("corrupt: witgen ok", r == 0 && wit != NULL && wit_len > 32);
    if (r == 0 && wit != NULL && wit_len > 32) {
        wit[wit_len - 1] ^= 0x01; /* flip a norm s_tilde byte */
        r = voleith_gf8_prove_v2(&proof, params, p.circuit, wit, wit_len, NULL,
                                 0, FS_SEED, sizeof(FS_SEED));
        check("corrupt: prover rejects corrupted norm witness", r != 0);
        if (r == 0)
            voleith_proof_free(&proof);
    }

    zfree(wit, wit_len);
    voleith_shipshape_parsed_free(&p);
}

int
main(void)
{
    uint8_t aes_ext[32];
    uint8_t grostl_ext[16];
    size_t i;

    printf("test_shipshape_crypto_v3_proof: starting\n");

    for (i = 0; i < sizeof(aes_ext); i++)
        aes_ext[i] = (uint8_t)(i * 11u + 0x5Cu);
    for (i = 0; i < sizeof(grostl_ext); i++)
        grostl_ext[i] = (uint8_t)(i * 13u + 0x21u);

    roundtrip("aes/encrypt_128_norm", AES_SRC, aes_ext, sizeof(aes_ext));
    roundtrip("grostl/hash_256_norm", GROSTL_SRC, grostl_ext,
              sizeof(grostl_ext));
    test_corrupt_norm_witness();

    printf("test_shipshape_crypto_v3_proof: %d/%d passed\n", pass_count,
           test_count);
    return (pass_count == test_count) ? 0 : 1;
}
