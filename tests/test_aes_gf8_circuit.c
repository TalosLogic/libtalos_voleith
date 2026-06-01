/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * test_aes_gf8_circuit.c - Tests for the GF(2⁸) element-level AES circuit
 *
 * Tests:
 *   1:  S-box evaluated on all 256 inputs matches reference S-box
 *   2:  S-box VOLE slot cost: 1 witness, 0 mul gates, 2 assert_products
 *   3:  AES-128 structural: witness_count=216, mul_count=0,
 *       assert_product_count=400, ell=216
 *   4:  AES-256 structural: witness_count=308, mul_count=0,
 *       assert_product_count=552, ell=308
 *   5:  AES-128 FIPS 197 Appendix C.1 test vector (round-trip evaluate)
 *   6:  AES-128 FIPS 197 Appendix B test vector
 *   7:  AES-128 wrong inv_in witness fails assert_product constraints
 *   8:  AES-256 FIPS 197 Appendix C.3 test vector (round-trip evaluate)
 *   9:  AES-128 ciphertext output matches voleith_aes_encrypt (core AES)
 *  10:  AES-256 ciphertext output matches voleith_aes_encrypt (core AES)
 *  11:  AES-256 split (expand_key + encrypt_rk) matches monolithic
 *       wrapper in witness/assert counts and ciphertext
 *  12:  AES-256 split witness builders produce byte-identical inv_in
 *       and ciphertext to aes256_gf8_build_witness
 */

#include "../circuits/aes_gf8_circuit.h"
#include "../proof/gf8_circuit.h"
#include "../core/field.h"
#include "../core/aes.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>

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
 * Reference S-box (independent implementation for cross-check)
 * ================================================================ */

static uint8_t
gf8_mul_ref(uint8_t a, uint8_t b)
{
    uint8_t r = 0;
    for (int i = 0; i < 8; i++) {
        if (b & 1)
            r ^= a;
        uint8_t hi = (uint8_t)(a >> 7);
        a = (uint8_t)(a << 1);
        if (hi)
            a ^= 0x1B;
        b >>= 1;
    }
    return r;
}

static uint8_t
gf8_inv_ref(uint8_t x)
{
    if (x == 0)
        return 0;
    for (int y = 1; y < 256; y++)
        if (gf8_mul_ref(x, (uint8_t)y) == 1)
            return (uint8_t)y;
    return 0;
}

static uint8_t
sbox_ref(uint8_t x)
{
    uint8_t t = gf8_inv_ref(x);
    uint8_t r = 0;
    for (int i = 0; i < 8; i++) {
        uint8_t b = ((t >> i) & 1) ^ ((t >> ((i + 4) % 8)) & 1) ^
                    ((t >> ((i + 5) % 8)) & 1) ^ ((t >> ((i + 6) % 8)) & 1) ^
                    ((t >> ((i + 7) % 8)) & 1) ^ ((0x63 >> i) & 1);
        r |= (uint8_t)(b << i);
    }
    return r;
}

/* ================================================================
 * Test helpers
 * ================================================================ */

/*
 * Build and evaluate a circuit with a single aes_gf8_sbox call.
 * Returns the evaluated S-box output for input `x`.
 * Also reads out the wire_count and constraint counts.
 */
static uint8_t
eval_single_sbox(uint8_t x, size_t *out_witness_count, size_t *out_mul_count,
                 size_t *out_assert_product_count)
{
    voleith_gf8_circuit_t *c = voleith_gf8_circuit_new();

    /* Input: one witness wire for the S-box input. */
    gf8_wire_id in_wire = voleith_gf8_add_witness(c);
    gf8_wire_id out_wire = aes_gf8_sbox(c, in_wire);

    if (out_witness_count)
        *out_witness_count = voleith_gf8_circuit_witness_count(c);
    if (out_mul_count)
        *out_mul_count = voleith_gf8_circuit_mul_count(c);
    if (out_assert_product_count)
        *out_assert_product_count = voleith_gf8_circuit_assert_product_count(c);

    /* Build witness: [x, inv(x)].
     * The circuit adds inv_in as the second witness, so witness = {x, inv_in}. */
    uint8_t inv_x = 0;
    if (x != 0) {
        for (int y = 1; y < 256; y++) {
            if (voleith_gf8_mul(x, (uint8_t)y) == 1) {
                inv_x = (uint8_t)y;
                break;
            }
        }
    }
    uint8_t witness[2] = {x, inv_x};

    size_t n = voleith_gf8_circuit_wire_count(c);
    uint8_t *vals = calloc(n, 1);
    voleith_gf8_circuit_eval(c, witness, NULL, vals);

    uint8_t result = vals[out_wire];
    free(vals);
    voleith_gf8_circuit_free(c);
    return result;
}

/* ================================================================
 * Test 1: S-box correct for all 256 inputs
 * ================================================================ */
static void
test_sbox_all_inputs(void)
{
    int all_ok = 1;
    for (int x = 0; x < 256; x++) {
        uint8_t got = eval_single_sbox((uint8_t)x, NULL, NULL, NULL);
        uint8_t expected = sbox_ref((uint8_t)x);
        if (got != expected) {
            printf("  FAIL: S-box(0x%02X) = 0x%02X, expected 0x%02X\n", x, got,
                   expected);
            all_ok = 0;
            break;
        }
    }
    check("S-box correct for all 256 inputs", all_ok);
}

/* ================================================================
 * Test 2: S-box VOLE slot cost
 * ================================================================ */
static void
test_sbox_vole_cost(void)
{
    size_t wc, mc, apc;
    eval_single_sbox(0x53, &wc, &mc, &apc);

    /* witness 0 = external input (in_wire); witness 1 = inv_in (added by S-box) */
    check("S-box: witness_count = 2 (in + inv_in)", wc == 2);
    check("S-box: mul_count = 0 (no add_mul gates)", mc == 0);
    check("S-box: assert_product_count = 2", apc == 2);
}

/* ================================================================
 * Helpers for AES circuit structure tests
 * ================================================================ */

static void
build_aes128_circuit(voleith_gf8_circuit_t **c_out, gf8_wire_id key_out[16],
                     gf8_wire_id pt_out[16], gf8_wire_id ct_out[16])
{
    voleith_gf8_circuit_t *c = voleith_gf8_circuit_new();
    for (int i = 0; i < 16; i++)
        key_out[i] = voleith_gf8_add_witness(c);
    for (int i = 0; i < 16; i++)
        pt_out[i] = voleith_gf8_add_instance(c);
    aes128_gf8_circuit(c, key_out, pt_out, ct_out);
    *c_out = c;
}

static void
build_aes256_circuit(voleith_gf8_circuit_t **c_out, gf8_wire_id key_out[32],
                     gf8_wire_id pt_out[16], gf8_wire_id ct_out[16])
{
    voleith_gf8_circuit_t *c = voleith_gf8_circuit_new();
    for (int i = 0; i < 32; i++)
        key_out[i] = voleith_gf8_add_witness(c);
    for (int i = 0; i < 16; i++)
        pt_out[i] = voleith_gf8_add_instance(c);
    aes256_gf8_circuit(c, key_out, pt_out, ct_out);
    *c_out = c;
}

/* ================================================================
 * Test 3: AES-128 structural properties
 * ================================================================ */
static void
test_aes128_structure(void)
{
    voleith_gf8_circuit_t *c;
    gf8_wire_id key[16], pt[16], ct[16];
    build_aes128_circuit(&c, key, pt, ct);

    /* 16 key witnesses + 200 inv_in witnesses (40 key schedule + 160 data path) */
    check("AES-128: witness_count = 216",
          voleith_gf8_circuit_witness_count(c) == 216);
    check("AES-128: mul_count = 0 (no add_mul gates)",
          voleith_gf8_circuit_mul_count(c) == 0);
    /* 200 S-boxes × 2 assert_product each = 400 */
    check("AES-128: assert_product_count = 400",
          voleith_gf8_circuit_assert_product_count(c) == 400);
    /* ell = witness_count + mul_count = 216 */
    check("AES-128: ell = 216", voleith_gf8_qs_ell(c) == 216);
    check("AES-128: instance_count = 16",
          voleith_gf8_circuit_instance_count(c) == 16);

    voleith_gf8_circuit_free(c);
}

/* ================================================================
 * Test 4: AES-256 structural properties
 * ================================================================ */
static void
test_aes256_structure(void)
{
    voleith_gf8_circuit_t *c;
    gf8_wire_id key[32], pt[16], ct[16];
    build_aes256_circuit(&c, key, pt, ct);

    /* 32 key witnesses + 276 inv_in witnesses (52 key schedule + 224 data path) */
    check("AES-256: witness_count = 308",
          voleith_gf8_circuit_witness_count(c) == 308);
    check("AES-256: mul_count = 0", voleith_gf8_circuit_mul_count(c) == 0);
    /* 276 S-boxes × 2 = 552 */
    check("AES-256: assert_product_count = 552",
          voleith_gf8_circuit_assert_product_count(c) == 552);
    check("AES-256: ell = 308", voleith_gf8_qs_ell(c) == 308);

    voleith_gf8_circuit_free(c);
}

/* ================================================================
 * Evaluate AES-128 circuit and return ciphertext bytes.
 * witness[216] and instance[16] must be pre-built.
 * ================================================================ */
static void
eval_aes128(const uint8_t key[16], const uint8_t plaintext[16],
            uint8_t ct_out[16])
{
    voleith_gf8_circuit_t *c;
    gf8_wire_id key_wires[16], pt_wires[16], ct_wires[16];
    build_aes128_circuit(&c, key_wires, pt_wires, ct_wires);

    uint8_t witness[216];
    aes128_gf8_build_witness(key, plaintext, witness, NULL);

    size_t n = voleith_gf8_circuit_wire_count(c);
    uint8_t *vals = calloc(n, 1);
    int ok = voleith_gf8_circuit_eval(c, witness, plaintext, vals);
    (void)ok;

    for (int i = 0; i < 16; i++)
        ct_out[i] = vals[ct_wires[i]];

    free(vals);
    voleith_gf8_circuit_free(c);
}

static void
eval_aes256(const uint8_t key[32], const uint8_t plaintext[16],
            uint8_t ct_out[16])
{
    voleith_gf8_circuit_t *c;
    gf8_wire_id key_wires[32], pt_wires[16], ct_wires[16];
    build_aes256_circuit(&c, key_wires, pt_wires, ct_wires);

    uint8_t witness[308];
    aes256_gf8_build_witness(key, plaintext, witness, NULL);

    size_t n = voleith_gf8_circuit_wire_count(c);
    uint8_t *vals = calloc(n, 1);
    voleith_gf8_circuit_eval(c, witness, plaintext, vals);

    for (int i = 0; i < 16; i++)
        ct_out[i] = vals[ct_wires[i]];

    free(vals);
    voleith_gf8_circuit_free(c);
}

/* ================================================================
 * Test 5: AES-128 FIPS 197 Appendix C.1
 * Key:        00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f
 * Plaintext:  00 11 22 33 44 55 66 77 88 99 aa bb cc dd ee ff
 * Ciphertext: 69 c4 e0 d8 6a 7b 04 30 d8 cd b7 80 70 b4 c5 5a
 * ================================================================ */
static void
test_aes128_fips197_c1(void)
{
    static const uint8_t KEY[16] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05,
                                    0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b,
                                    0x0c, 0x0d, 0x0e, 0x0f};
    static const uint8_t PT[16] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55,
                                   0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb,
                                   0xcc, 0xdd, 0xee, 0xff};
    static const uint8_t EXPECTED[16] = {0x69, 0xc4, 0xe0, 0xd8, 0x6a, 0x7b,
                                         0x04, 0x30, 0xd8, 0xcd, 0xb7, 0x80,
                                         0x70, 0xb4, 0xc5, 0x5a};

    uint8_t ct[16];
    eval_aes128(KEY, PT, ct);
    check("AES-128 FIPS 197 C.1: ciphertext matches",
          memcmp(ct, EXPECTED, 16) == 0);

    /* Also verify build_witness returns the correct ciphertext. */
    uint8_t witness[216], ct2[16];
    aes128_gf8_build_witness(KEY, PT, witness, ct2);
    check("AES-128 build_witness returns correct ciphertext",
          memcmp(ct2, EXPECTED, 16) == 0);
}

/* ================================================================
 * Test 6: AES-128 FIPS 197 Appendix B
 * Key:        2b 7e 15 16 28 ae d2 a6 ab f7 15 88 09 cf 4f 3c
 * Plaintext:  32 43 f6 a8 88 5a 30 8d 31 31 98 a2 e0 37 07 34
 * Ciphertext: 39 25 84 1d 02 dc 09 fb dc 11 85 97 19 6a 0b 32
 * ================================================================ */
static void
test_aes128_fips197_b(void)
{
    static const uint8_t KEY[16] = {0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae,
                                    0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88,
                                    0x09, 0xcf, 0x4f, 0x3c};
    static const uint8_t PT[16] = {0x32, 0x43, 0xf6, 0xa8, 0x88, 0x5a,
                                   0x30, 0x8d, 0x31, 0x31, 0x98, 0xa2,
                                   0xe0, 0x37, 0x07, 0x34};
    static const uint8_t EXPECTED[16] = {0x39, 0x25, 0x84, 0x1d, 0x02, 0xdc,
                                         0x09, 0xfb, 0xdc, 0x11, 0x85, 0x97,
                                         0x19, 0x6a, 0x0b, 0x32};

    uint8_t ct[16];
    eval_aes128(KEY, PT, ct);
    check("AES-128 FIPS 197 Appendix B: ciphertext matches",
          memcmp(ct, EXPECTED, 16) == 0);
}

/* ================================================================
 * Test 7: Wrong inv_in witness fails assert_product constraints
 * ================================================================ */
static void
test_aes128_wrong_witness_fails(void)
{
    static const uint8_t KEY[16] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05,
                                    0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b,
                                    0x0c, 0x0d, 0x0e, 0x0f};
    static const uint8_t PT[16] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55,
                                   0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb,
                                   0xcc, 0xdd, 0xee, 0xff};

    voleith_gf8_circuit_t *c;
    gf8_wire_id key_wires[16], pt_wires[16], ct_wires[16];
    build_aes128_circuit(&c, key_wires, pt_wires, ct_wires);
    (void)ct_wires;

    uint8_t witness[216];
    aes128_gf8_build_witness(KEY, PT, witness, NULL);

    /* Corrupt one inv_in byte (witness[16] is first key schedule inv_in). */
    witness[16] ^= 0xFF;

    size_t n = voleith_gf8_circuit_wire_count(c);
    uint8_t *vals = calloc(n, 1);
    int ok = voleith_gf8_circuit_eval(c, witness, PT, vals);

    check("AES-128 wrong inv_in witness fails constraints", ok == 0);

    free(vals);
    voleith_gf8_circuit_free(c);
}

/* ================================================================
 * Test 8: AES-256 FIPS 197 Appendix C.3
 * Key:        00 01 02 ... 1e 1f
 * Plaintext:  00 11 22 33 44 55 66 77 88 99 aa bb cc dd ee ff
 * Ciphertext: 8e a2 b7 ca 51 67 45 bf ea fc 49 90 4b 49 60 89
 * ================================================================ */
static void
test_aes256_fips197_c3(void)
{
    static const uint8_t KEY[32] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a,
        0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15,
        0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f};
    static const uint8_t PT[16] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55,
                                   0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb,
                                   0xcc, 0xdd, 0xee, 0xff};
    static const uint8_t EXPECTED[16] = {0x8e, 0xa2, 0xb7, 0xca, 0x51, 0x67,
                                         0x45, 0xbf, 0xea, 0xfc, 0x49, 0x90,
                                         0x4b, 0x49, 0x60, 0x89};

    uint8_t ct[16];
    eval_aes256(KEY, PT, ct);
    check("AES-256 FIPS 197 C.3: ciphertext matches",
          memcmp(ct, EXPECTED, 16) == 0);

    uint8_t witness[308], ct2[16];
    aes256_gf8_build_witness(KEY, PT, witness, ct2);
    check("AES-256 build_witness returns correct ciphertext",
          memcmp(ct2, EXPECTED, 16) == 0);
}

/* ================================================================
 * Test 9: AES-128 circuit output matches core AES (voleith_aes_encrypt)
 * ================================================================ */
static void
test_aes128_matches_core_aes(void)
{
    static const uint8_t KEY[16] = {0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe,
                                    0xba, 0xbe, 0x01, 0x23, 0x45, 0x67,
                                    0x89, 0xab, 0xcd, 0xef};
    static const uint8_t PT[16] = {0x48, 0x65, 0x6c, 0x6c, 0x6f, 0x2c,
                                   0x20, 0x57, 0x6f, 0x72, 0x6c, 0x64,
                                   0x21, 0x00, 0x00, 0x00};

    /* Reference via core AES. */
    voleith_aes_ctx_t ctx;
    voleith_aes_key_expand(&ctx, KEY, 128);
    uint8_t ref_ct[16];
    voleith_aes_encrypt(&ctx, ref_ct, PT);

    /* GF(2⁸) circuit AES. */
    uint8_t circuit_ct[16];
    eval_aes128(KEY, PT, circuit_ct);

    check("AES-128 circuit matches voleith_aes_encrypt",
          memcmp(circuit_ct, ref_ct, 16) == 0);
}

/* ================================================================
 * Test 10: AES-256 circuit output matches core AES
 * ================================================================ */
static void
test_aes256_matches_core_aes(void)
{
    static const uint8_t KEY[32] = {
        0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0xba, 0xbe, 0x01, 0x23, 0x45,
        0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xed, 0xfa, 0xce, 0xde, 0xad,
        0xbe, 0xef, 0xfe, 0xed, 0xfa, 0xce, 0xde, 0xad, 0xbe, 0xef};
    static const uint8_t PT[16] = {0x48, 0x65, 0x6c, 0x6c, 0x6f, 0x2c,
                                   0x20, 0x57, 0x6f, 0x72, 0x6c, 0x64,
                                   0x21, 0x00, 0x00, 0x00};

    voleith_aes_ctx_t ctx;
    voleith_aes_key_expand(&ctx, KEY, 256);
    uint8_t ref_ct[16];
    voleith_aes_encrypt(&ctx, ref_ct, PT);

    uint8_t circuit_ct[16];
    eval_aes256(KEY, PT, circuit_ct);

    check("AES-256 circuit matches voleith_aes_encrypt",
          memcmp(circuit_ct, ref_ct, 16) == 0);
}

/* ================================================================
 * Test 11: AES-256 split functions (expand_key + encrypt_rk) emit the
 * same circuit and same ciphertext as the monolithic wrapper.
 * ================================================================ */
static void
test_aes256_split_circuit_equivalence(void)
{
    static const uint8_t KEY[32] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a,
        0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15,
        0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f};
    static const uint8_t PT[16] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55,
                                   0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb,
                                   0xcc, 0xdd, 0xee, 0xff};
    static const uint8_t EXPECTED[16] = {0x8e, 0xa2, 0xb7, 0xca, 0x51, 0x67,
                                         0x45, 0xbf, 0xea, 0xfc, 0x49, 0x90,
                                         0x4b, 0x49, 0x60, 0x89};

    voleith_gf8_circuit_t *c = voleith_gf8_circuit_new();
    gf8_wire_id key[32], pt[16], ct[16];
    gf8_wire_id rk[15][16];
    for (int i = 0; i < 32; i++)
        key[i] = voleith_gf8_add_witness(c);
    for (int i = 0; i < 16; i++)
        pt[i] = voleith_gf8_add_instance(c);
    aes256_gf8_expand_key(c, key, rk);
    aes256_gf8_encrypt_rk(c, rk, pt, ct);

    check("AES-256 split: witness_count = 308",
          voleith_gf8_circuit_witness_count(c) == 308);
    check("AES-256 split: assert_product_count = 552",
          voleith_gf8_circuit_assert_product_count(c) == 552);
    check("AES-256 split: mul_count = 0",
          voleith_gf8_circuit_mul_count(c) == 0);

    uint8_t witness[308];
    aes256_gf8_build_witness(KEY, PT, witness, NULL);
    size_t n = voleith_gf8_circuit_wire_count(c);
    uint8_t *vals = calloc(n, 1);
    voleith_gf8_circuit_eval(c, witness, PT, vals);
    uint8_t got[16];
    for (int i = 0; i < 16; i++)
        got[i] = vals[ct[i]];
    check("AES-256 split: ciphertext matches FIPS 197 C.3",
          memcmp(got, EXPECTED, 16) == 0);

    free(vals);
    voleith_gf8_circuit_free(c);
}

static void
test_aes256_split_witness_equivalence(void)
{
    static const uint8_t KEY[32] = {
        0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0xba, 0xbe, 0x01, 0x23, 0x45,
        0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xed, 0xfa, 0xce, 0xde, 0xad,
        0xbe, 0xef, 0xfe, 0xed, 0xfa, 0xce, 0xde, 0xad, 0xbe, 0xef};
    static const uint8_t PT[16] = {0x48, 0x65, 0x6c, 0x6c, 0x6f, 0x2c,
                                   0x20, 0x57, 0x6f, 0x72, 0x6c, 0x64,
                                   0x21, 0x00, 0x00, 0x00};

    uint8_t w_mono[308], ct_mono[16];
    aes256_gf8_build_witness(KEY, PT, w_mono, ct_mono);

    uint8_t inv_ks[AES256_GF8_KS_INVIN_BYTES];
    uint8_t inv_enc[AES256_GF8_ENC_INVIN_BYTES];
    uint8_t rk[15][16], ct_split[16];
    aes256_gf8_expand_key_witness(KEY, inv_ks, rk);
    aes256_gf8_encrypt_rk_witness(rk, PT, inv_enc, ct_split);

    check("AES-256 split witness: KS inv_in matches monolithic",
          memcmp(inv_ks, w_mono + 32, AES256_GF8_KS_INVIN_BYTES) == 0);
    check("AES-256 split witness: data-path inv_in matches monolithic",
          memcmp(inv_enc, w_mono + 32 + AES256_GF8_KS_INVIN_BYTES,
                 AES256_GF8_ENC_INVIN_BYTES) == 0);
    check("AES-256 split witness: ciphertext matches monolithic",
          memcmp(ct_split, ct_mono, 16) == 0);
}

/* ================================================================
 * main
 * ================================================================ */
int
main(void)
{
    printf("test_aes_gf8_circuit: GF(2^8) element-level AES circuit\n");

    test_sbox_all_inputs();
    test_sbox_vole_cost();
    test_aes128_structure();
    test_aes256_structure();
    test_aes128_fips197_c1();
    test_aes128_fips197_b();
    test_aes128_wrong_witness_fails();
    test_aes256_fips197_c3();
    test_aes128_matches_core_aes();
    test_aes256_matches_core_aes();
    test_aes256_split_circuit_equivalence();
    test_aes256_split_witness_equivalence();

    printf("  %d / %d passed\n", pass_count, test_count);
    return (pass_count == test_count) ? 0 : 1;
}
