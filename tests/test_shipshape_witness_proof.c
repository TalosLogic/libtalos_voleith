/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * test_shipshape_witness_proof.c - prove / verify round-trip for parsed
 * Shipshape circuits with generated witnesses (W6.3 of
 * docs/SHIPSHAPE_IMPLEMENTATION_PLAN.md; docs/CIRC_WITNESS_GEN.md §9).
 *
 * Closes the loop: a `.ship` file is parsed (W3), its full witness is
 * generated from the external input (W6.2), and the parsed circuit plus the
 * generated witness go through voleith_gf8_prove_v2 / voleith_gf8_verify_v2.
 * A valid witness proves and verifies; a tampered proof is rejected; a wrong
 * witness is rejected at prove time; a wrong instance is rejected at verify
 * time (the fail-closed property of ISA §1.5 / CIRC_WITNESS_GEN.md §7).
 *
 * All circuits are deliberately tiny (ell = 2) so proving stays fast.
 */

#include "gf8_circuit.h"
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

#define HDR                                                                    \
    ".shipshape 1\n"                                                           \
    "field GF(2^8) irreducible 0x11B\n"                                        \
    "stdlib crypto-v1\n"

static const uint8_t FS_SEED[16] = {0x11, 0x22, 0x33, 0x44, 0x55, 0x66,
                                    0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC,
                                    0xDD, 0xEE, 0xFF, 0x01};

/* Zero the secret witness buffer before releasing it. */
static void
zfree(uint8_t *buf, size_t len)
{
    if (buf != NULL && len > 0)
        voleith_secure_zero(buf, len);
    free(buf);
}

/*
 * Parse `src`, generate the witness from (ext, inst), prove, verify, and
 * tamper.  Records named checks; frees everything.
 */
static void
roundtrip(const char *name, const char *src, const uint8_t *ext, size_t ext_len,
          const uint8_t *inst, size_t inst_len)
{
    const voleith_params_t *params = &voleith_params_em_128f;
    voleith_shipshape_parsed_t p;
    voleith_proof_t proof;
    uint8_t *wit = NULL;
    size_t wit_len = 0;
    char label[96];
    int r;

    r = voleith_shipshape_parse_buffer(&p, src, 0, NULL);
    snprintf(label, sizeof(label), "%s: parses", name);
    check(label, r == 0 && p.circuit != NULL);
    if (r != 0 || p.circuit == NULL) {
        voleith_shipshape_parsed_free(&p);
        return;
    }

    r = voleith_shipshape_witness_gen(&p, ext, ext_len, inst, inst_len,
                                      VOLEITH_SHIPSHAPE_WITGEN_SELF_CHECK, &wit,
                                      &wit_len);
    snprintf(label, sizeof(label), "%s: witness gen", name);
    check(label, r == 0);

    if (r == 0) {
        r = voleith_gf8_prove_v2(&proof, params, p.circuit, wit, wit_len, inst,
                                 inst_len, FS_SEED, sizeof(FS_SEED));
        snprintf(label, sizeof(label), "%s: prove", name);
        check(label, r == 0);

        if (r == 0) {
            r = voleith_gf8_verify_v2(&proof, params, p.circuit, inst, inst_len,
                                      FS_SEED, sizeof(FS_SEED));
            snprintf(label, sizeof(label), "%s: verify accepts", name);
            check(label, r == 0);

            /* Tamper: flipping a proof byte must make verify reject. */
            proof.data[0] ^= 0xFF;
            r = voleith_gf8_verify_v2(&proof, params, p.circuit, inst, inst_len,
                                      FS_SEED, sizeof(FS_SEED));
            snprintf(label, sizeof(label), "%s: tampered proof rejected", name);
            check(label, r != 0);
            proof.data[0] ^= 0xFF;

            voleith_proof_free(&proof);
        }
    }

    zfree(wit, wit_len);
    voleith_shipshape_parsed_free(&p);
}

static void
test_roundtrips(void)
{
    uint8_t a = 0x53;
    uint8_t x = 0x9C;
    uint8_t wit_a = 0x07, inst_b = 0x2B;

    /* INV gadget: external %a, internal inverse filled by the generator. */
    roundtrip("inv",
              HDR "WITNESS -> %a : byte\n"
                  "INV %a -> %ai\n",
              &a, 1, NULL, 0);

    /* A registry S-box, end to end through parse + witness gen + proof. */
    roundtrip("sbox",
              HDR "WITNESS -> %x : byte\n"
                  "stdlib/crypto/aes/sbox(%x) -> %y\n",
              &x, 1, NULL, 0);

    /* A circuit with an INSTANCE wire and a product constraint binding it. */
    roundtrip("instance_product",
              HDR "WITNESS -> %a : byte\n"
                  "INSTANCE -> %b : byte\n"
                  "MUL %a %b -> %p\n"
                  "ASSERT_PRODUCT %a %b %p\n",
              &wit_a, 1, &inst_b, 1);
}

static void
test_wrong_witness_rejected_at_prove(void)
{
    const voleith_params_t *params = &voleith_params_em_128f;
    voleith_shipshape_parsed_t p;
    voleith_proof_t proof;
    uint8_t a = 0x53;
    uint8_t *wit = NULL;
    size_t wit_len = 0;
    int r;

    r = voleith_shipshape_parse_buffer(
        &p, HDR "WITNESS -> %a : byte\nINV %a -> %ai\n", 0, NULL);
    check("wrong-witness: setup parses", r == 0);
    if (r != 0) {
        voleith_shipshape_parsed_free(&p);
        return;
    }

    r = voleith_shipshape_witness_gen(&p, &a, 1, NULL, 0, 0, &wit, &wit_len);
    check("wrong-witness: gen ok", r == 0 && wit_len == 2);

    if (r == 0) {
        /* Corrupt the inverse byte so the product constraints no longer
         * hold; the prover must refuse to prove an unsatisfied circuit. */
        wit[1] ^= 0x01;
        r = voleith_gf8_prove_v2(&proof, params, p.circuit, wit, wit_len, NULL,
                                 0, FS_SEED, sizeof(FS_SEED));
        check("wrong-witness: prove rejects corrupted witness", r != 0);
        if (r == 0)
            voleith_proof_free(&proof);

        /* Sanity: the un-corrupted witness still proves. */
        wit[1] ^= 0x01;
        r = voleith_gf8_prove_v2(&proof, params, p.circuit, wit, wit_len, NULL,
                                 0, FS_SEED, sizeof(FS_SEED));
        check("wrong-witness: correct witness proves", r == 0);
        if (r == 0)
            voleith_proof_free(&proof);
    }

    zfree(wit, wit_len);
    voleith_shipshape_parsed_free(&p);
}

static void
test_wrong_instance_rejected_at_verify(void)
{
    const voleith_params_t *params = &voleith_params_em_128f;
    voleith_shipshape_parsed_t p;
    voleith_proof_t proof;
    uint8_t wit_a = 0x07, inst_b = 0x2B, wrong_b = 0x2C;
    uint8_t *wit = NULL;
    size_t wit_len = 0;
    int r;

    r = voleith_shipshape_parse_buffer(&p,
                                       HDR "WITNESS -> %a : byte\n"
                                           "INSTANCE -> %b : byte\n"
                                           "MUL %a %b -> %p\n"
                                           "ASSERT_PRODUCT %a %b %p\n",
                                       0, NULL);
    check("wrong-instance: setup parses", r == 0);
    if (r != 0) {
        voleith_shipshape_parsed_free(&p);
        return;
    }

    r = voleith_shipshape_witness_gen(&p, &wit_a, 1, &inst_b, 1, 0, &wit,
                                      &wit_len);
    check("wrong-instance: gen ok", r == 0);

    if (r == 0) {
        r = voleith_gf8_prove_v2(&proof, params, p.circuit, wit, wit_len,
                                 &inst_b, 1, FS_SEED, sizeof(FS_SEED));
        check("wrong-instance: prove", r == 0);
        if (r == 0) {
            /* Verifying against a different public input must reject: the
             * committed a*b no longer equals the claimed product. */
            r = voleith_gf8_verify_v2(&proof, params, p.circuit, &wrong_b, 1,
                                      FS_SEED, sizeof(FS_SEED));
            check("wrong-instance: verify rejects wrong instance", r != 0);

            /* The correct instance still verifies. */
            r = voleith_gf8_verify_v2(&proof, params, p.circuit, &inst_b, 1,
                                      FS_SEED, sizeof(FS_SEED));
            check("wrong-instance: verify accepts correct instance", r == 0);

            voleith_proof_free(&proof);
        }
    }

    zfree(wit, wit_len);
    voleith_shipshape_parsed_free(&p);
}

int
main(void)
{
    printf("test_shipshape_witness_proof: starting\n");
    test_roundtrips();
    test_wrong_witness_rejected_at_prove();
    test_wrong_instance_rejected_at_verify();
    printf("test_shipshape_witness_proof: %d/%d passed\n", pass_count,
           test_count);
    return (pass_count == test_count) ? 0 : 1;
}
