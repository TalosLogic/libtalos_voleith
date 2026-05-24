/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * test_aes_circuit.c - Tests for the AES S-box and AES-128/256 Boolean circuits
 *
 * Tests:
 *   1: S-box circuit evaluated on all 256 inputs matches AES SBOX table
 *   2: S-box AND gate count == 36 per invocation
 *   3: AES-128 circuit evaluates NIST test vector correctly
 *   4: AES-128 AND gate count == 7200 (200 S-boxes × 36 ANDs)
 *   5: AES-128 correct constraint check (valid witness passes, wrong key fails)
 *   6: AES-256 circuit evaluates NIST test vector correctly
 *   7: AES-256 AND gate count == 9936 (276 S-boxes × 36 ANDs)
 */

#include "aes_circuit.h"
#include "circuit.h"
#include "aes.h" /* for reference AES implementation */
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
 * Reference AES SBOX (computed from FIPS 197 definition)
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
    uint8_t t2 = gf8_mul_ref(x, x);
    uint8_t t3 = gf8_mul_ref(x, t2);
    uint8_t t5 = gf8_mul_ref(t3, t2);
    uint8_t t7 = gf8_mul_ref(t5, t2);
    uint8_t t14 = gf8_mul_ref(t7, t7);
    uint8_t t28 = gf8_mul_ref(t14, t14);
    uint8_t t56 = gf8_mul_ref(t28, t28);
    uint8_t t63 = gf8_mul_ref(t56, t7);
    uint8_t t126 = gf8_mul_ref(t63, t63);
    uint8_t t252 = gf8_mul_ref(t126, t126);
    return gf8_mul_ref(t252, t2);
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
 * Helpers: pack/unpack bits into/from wire IDs
 * ================================================================ */

/* Evaluate circuit on packed witness/instance, return the value of 8 output wires. */
static uint8_t
eval_byte_wires(voleith_circuit_t *c, const uint8_t *witness,
                const uint8_t *instance, const wire_id out[8])
{
    size_t n_wires = voleith_circuit_wire_count(c);
    uint8_t *vals = calloc((n_wires + 7) / 8, 1);
    if (!vals)
        return 0;
    voleith_circuit_eval(c, witness, instance, vals);
    uint8_t byte = 0;
    for (int b = 0; b < 8; b++)
        byte |= (uint8_t)(((vals[out[b] / 8] >> (out[b] % 8)) & 1) << b);
    free(vals);
    return byte;
}

/* Evaluate circuit and return values of 128 output wires as 16 bytes. */
static void
eval_block_wires(voleith_circuit_t *c, const uint8_t *witness,
                 const uint8_t *instance, const wire_id out[128],
                 uint8_t block[16])
{
    size_t n_wires = voleith_circuit_wire_count(c);
    uint8_t *vals = calloc((n_wires + 7) / 8, 1);
    if (!vals) {
        memset(block, 0, 16);
        return;
    }
    voleith_circuit_eval(c, witness, instance, vals);
    for (int i = 0; i < 16; i++) {
        block[i] = 0;
        for (int b = 0; b < 8; b++) {
            wire_id w = out[i * 8 + b];
            block[i] |= (uint8_t)(((vals[w / 8] >> (w % 8)) & 1) << b);
        }
    }
    free(vals);
}

/* Pack a 16-byte block into a bit array (little-endian per byte). */
static void
pack_bits_128(const uint8_t block[16], uint8_t bits[16])
{
    memcpy(bits, block, 16);
}

/* ================================================================
 * Test 1: S-box circuit matches reference for all 256 inputs
 * ================================================================ */
static void
test_sbox_all_inputs(void)
{
    int ok = 1;

    for (int x = 0; x < 256 && ok; x++) {
        voleith_circuit_t *c = voleith_circuit_new();
        wire_id in[8], out[8];
        for (int b = 0; b < 8; b++)
            in[b] = voleith_circuit_add_witness(c);

        aes_sbox_circuit(c, in, out);

        /* Build witness: byte value x */
        uint8_t witness[1] = {(uint8_t)x};
        uint8_t result = eval_byte_wires(c, witness, NULL, out);
        uint8_t expected = sbox_ref((uint8_t)x);

        if (result != expected) {
            printf("  FAIL: S-box(0x%02x) = 0x%02x, expected 0x%02x\n", x,
                   result, expected);
            ok = 0;
        }
        voleith_circuit_free(c);
    }

    check("S-box circuit correct for all 256 inputs", ok);
}

/* ================================================================
 * Test 2: S-box AND gate count
 * ================================================================ */
static void
test_sbox_and_count(void)
{
    voleith_circuit_t *c = voleith_circuit_new();
    wire_id in[8], out[8];
    for (int b = 0; b < 8; b++)
        in[b] = voleith_circuit_add_witness(c);

    size_t and_before = voleith_circuit_and_gate_count(c);
    aes_sbox_circuit(c, in, out);
    size_t and_after = voleith_circuit_and_gate_count(c);

    check("S-box uses 36 AND gates", (and_after - and_before) == 36);
    voleith_circuit_free(c);
}

/* ================================================================
 * Test 3: AES-128 NIST test vector
 *
 * Key:        00 01 02 03 04 05 06 07  08 09 0a 0b 0c 0d 0e 0f
 * Plaintext:  00 11 22 33 44 55 66 77  88 99 aa bb cc dd ee ff
 * Ciphertext: 69 c4 e0 d8 6a 7b 04 30  d8 cd b7 80 70 b4 c5 5a
 *
 * (FIPS 197, Appendix B)
 * ================================================================ */
static void
test_aes128_nist_vector(void)
{
    static const uint8_t key[16] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05,
                                    0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b,
                                    0x0c, 0x0d, 0x0e, 0x0f};
    static const uint8_t plaintext[16] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55,
                                          0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb,
                                          0xcc, 0xdd, 0xee, 0xff};
    static const uint8_t expected_ct[16] = {0x69, 0xc4, 0xe0, 0xd8, 0x6a, 0x7b,
                                            0x04, 0x30, 0xd8, 0xcd, 0xb7, 0x80,
                                            0x70, 0xb4, 0xc5, 0x5a};

    voleith_circuit_t *c = voleith_circuit_new();

    /* Key as witness wires (128 bits). */
    wire_id key_wires[128];
    for (int i = 0; i < 128; i++)
        key_wires[i] = voleith_circuit_add_witness(c);

    /* Plaintext as instance wires (128 bits). */
    wire_id pt_wires[128];
    for (int i = 0; i < 128; i++)
        pt_wires[i] = voleith_circuit_add_instance(c);

    wire_id ct_wires[128];
    aes128_circuit(c, key_wires, pt_wires, ct_wires);

    /* Build witness and instance from known values. */
    uint8_t witness[16], instance[16];
    pack_bits_128(key, witness);
    pack_bits_128(plaintext, instance);

    uint8_t result[16];
    eval_block_wires(c, witness, instance, ct_wires, result);

    check("AES-128 NIST vector: ciphertext byte 0",
          result[0] == expected_ct[0]);
    check("AES-128 NIST vector: ciphertext byte 7",
          result[7] == expected_ct[7]);
    check("AES-128 NIST vector: ciphertext byte 15",
          result[15] == expected_ct[15]);
    int all_ok = (memcmp(result, expected_ct, 16) == 0);
    check("AES-128 NIST vector: all 16 bytes correct", all_ok);

    if (!all_ok) {
        printf("    Got:      ");
        for (int i = 0; i < 16; i++)
            printf("%02x ", result[i]);
        printf("\n    Expected: ");
        for (int i = 0; i < 16; i++)
            printf("%02x ", expected_ct[i]);
        printf("\n");
    }

    voleith_circuit_free(c);
}

/* ================================================================
 * Test 4: AES-128 AND gate count
 * ================================================================ */
static void
test_aes128_and_count(void)
{
    voleith_circuit_t *c = voleith_circuit_new();

    wire_id key_wires[128];
    for (int i = 0; i < 128; i++)
        key_wires[i] = voleith_circuit_add_witness(c);
    wire_id pt_wires[128];
    for (int i = 0; i < 128; i++)
        pt_wires[i] = voleith_circuit_add_instance(c);
    wire_id ct_wires[128];

    size_t and_before = voleith_circuit_and_gate_count(c);
    aes128_circuit(c, key_wires, pt_wires, ct_wires);
    size_t and_count = voleith_circuit_and_gate_count(c) - and_before;

    /* 200 S-box calls (160 encryption + 40 key schedule) × 36 ANDs = 7200. */
    check("AES-128 uses 7200 AND gates (200 S-boxes × 36)", and_count == 7200);
    printf("    AES-128 AND gate count: %zu\n", and_count);

    voleith_circuit_free(c);
}

/* ================================================================
 * Test 5: AES-128 constraint check (wrong key fails)
 * ================================================================ */
static void
test_aes128_constraint_check(void)
{
    static const uint8_t key[16] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05,
                                    0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b,
                                    0x0c, 0x0d, 0x0e, 0x0f};
    static const uint8_t plaintext[16] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55,
                                          0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb,
                                          0xcc, 0xdd, 0xee, 0xff};
    static const uint8_t expected_ct[16] = {0x69, 0xc4, 0xe0, 0xd8, 0x6a, 0x7b,
                                            0x04, 0x30, 0xd8, 0xcd, 0xb7, 0x80,
                                            0x70, 0xb4, 0xc5, 0x5a};

    voleith_circuit_t *c = voleith_circuit_new();

    wire_id key_wires[128];
    for (int i = 0; i < 128; i++)
        key_wires[i] = voleith_circuit_add_witness(c);
    wire_id pt_wires[128];
    for (int i = 0; i < 128; i++)
        pt_wires[i] = voleith_circuit_add_instance(c);
    wire_id ct_wires[128];
    aes128_circuit(c, key_wires, pt_wires, ct_wires);

    /* Add instance wires for expected ciphertext and assert equality. */
    for (int i = 0; i < 128; i++) {
        wire_id expected = voleith_circuit_add_instance(c);
        voleith_circuit_assert_equal(c, ct_wires[i], expected);
    }

    /* Witness = key (128 bits), instance = plaintext (128 bits) + ciphertext (128 bits). */
    uint8_t witness[16], instance[32];
    memcpy(witness, key, 16);
    memcpy(instance, plaintext, 16);
    memcpy(instance + 16, expected_ct, 16);

    size_t n_wires = voleith_circuit_wire_count(c);
    uint8_t *vals = calloc((n_wires + 7) / 8, 1);

    int r = voleith_circuit_eval(c, witness, instance, vals);
    check("AES-128 constraint: correct key passes", r == 1);

    /* Now use a wrong key (flip first bit). */
    memset(vals, 0, (n_wires + 7) / 8);
    witness[0] ^= 0x01;
    r = voleith_circuit_eval(c, witness, instance, vals);
    check("AES-128 constraint: wrong key fails", r == 0);

    free(vals);
    voleith_circuit_free(c);
}

/* ================================================================
 * Test 6: AES-256 NIST test vector
 *
 * Key:        00 01 02 03 04 05 06 07  08 09 0a 0b 0c 0d 0e 0f
 *             10 11 12 13 14 15 16 17  18 19 1a 1b 1c 1d 1e 1f
 * Plaintext:  00 11 22 33 44 55 66 77  88 99 aa bb cc dd ee ff
 * Ciphertext: 8e a2 b7 ca 51 67 45 bf  ea fc 49 90 4b 49 60 89
 *
 * (FIPS 197, Appendix B)
 * ================================================================ */
static void
test_aes256_nist_vector(void)
{
    static const uint8_t key[32] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a,
        0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15,
        0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f};
    static const uint8_t plaintext[16] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55,
                                          0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb,
                                          0xcc, 0xdd, 0xee, 0xff};
    static const uint8_t expected_ct[16] = {0x8e, 0xa2, 0xb7, 0xca, 0x51, 0x67,
                                            0x45, 0xbf, 0xea, 0xfc, 0x49, 0x90,
                                            0x4b, 0x49, 0x60, 0x89};

    voleith_circuit_t *c = voleith_circuit_new();

    wire_id key_wires[256];
    for (int i = 0; i < 256; i++)
        key_wires[i] = voleith_circuit_add_witness(c);
    wire_id pt_wires[128];
    for (int i = 0; i < 128; i++)
        pt_wires[i] = voleith_circuit_add_instance(c);
    wire_id ct_wires[128];
    aes256_circuit(c, key_wires, pt_wires, ct_wires);

    uint8_t witness[32], instance[16];
    memcpy(witness, key, 32);
    memcpy(instance, plaintext, 16);

    uint8_t result[16];
    eval_block_wires(c, witness, instance, ct_wires, result);

    int all_ok = (memcmp(result, expected_ct, 16) == 0);
    check("AES-256 NIST vector: all 16 bytes correct", all_ok);

    if (!all_ok) {
        printf("    Got:      ");
        for (int i = 0; i < 16; i++)
            printf("%02x ", result[i]);
        printf("\n    Expected: ");
        for (int i = 0; i < 16; i++)
            printf("%02x ", expected_ct[i]);
        printf("\n");
    }

    voleith_circuit_free(c);
}

/* ================================================================
 * Test 7: faest-ref FAEST_128F OWF test vector (AES-128)
 *
 * From third_party/faest-ref/tests/owf_tvs.hpp, FAEST_128F:
 * For FAEST (non-EM), the OWF is standard AES-128 encryption.
 * ================================================================ */
static void
test_aes128_faest_vector(void)
{
    static const uint8_t key[16] = {0xd0, 0x22, 0xe7, 0xd5, 0x20, 0xf8,
                                    0xe9, 0x38, 0xa1, 0x4e, 0x18, 0x8c,
                                    0x47, 0x30, 0x8c, 0xfe};
    static const uint8_t plaintext[16] = {0xf5, 0xff, 0xf7, 0xf7, 0x28, 0xb9,
                                          0xf8, 0xfb, 0xf5, 0x1c, 0x7c, 0xcc,
                                          0xcc, 0x4c, 0x24, 0x01};
    static const uint8_t expected_ct[16] = {0xe4, 0x1d, 0xcd, 0x85, 0x5f, 0x4d,
                                            0x0c, 0x39, 0xa3, 0xd5, 0x9a, 0x16,
                                            0xc1, 0x8d, 0x8b, 0x85};

    voleith_circuit_t *c = voleith_circuit_new();

    wire_id key_wires[128];
    for (int i = 0; i < 128; i++)
        key_wires[i] = voleith_circuit_add_witness(c);
    wire_id pt_wires[128];
    for (int i = 0; i < 128; i++)
        pt_wires[i] = voleith_circuit_add_instance(c);
    wire_id ct_wires[128];
    aes128_circuit(c, key_wires, pt_wires, ct_wires);

    uint8_t witness[16], instance[16];
    pack_bits_128(key, witness);
    pack_bits_128(plaintext, instance);

    uint8_t result[16];
    eval_block_wires(c, witness, instance, ct_wires, result);

    check("AES-128 faest-ref OWF vector (FAEST_128F): all 16 bytes correct",
          memcmp(result, expected_ct, 16) == 0);

    voleith_circuit_free(c);
}

/* ================================================================
 * Test 8: faest-ref FAEST_256F OWF test vector (AES-256 first block)
 *
 * FAEST_256F OWF = AES-256(key, input) || AES-256(key, input XOR ctr).
 * We only test the first block (standard AES-256 encryption).
 * ================================================================ */
static void
test_aes256_faest_vector(void)
{
    static const uint8_t key[32] = {
        0xb1, 0x20, 0x51, 0xc3, 0xf3, 0x7d, 0x08, 0xa9, 0x70, 0x20, 0x61,
        0x35, 0xc3, 0x0d, 0xcb, 0x09, 0x2f, 0x68, 0x7d, 0x75, 0x72, 0x7c,
        0xa5, 0xcb, 0xb5, 0xeb, 0xc1, 0xce, 0x46, 0xb4, 0xae, 0x00};
    static const uint8_t plaintext[16] = {0xa7, 0xb5, 0x29, 0xa4, 0x1e, 0x74,
                                          0x7f, 0xc6, 0xf5, 0x92, 0x57, 0xe0,
                                          0x95, 0xce, 0x39, 0x04};
    /* First 16 bytes of FAEST_256F output = AES-256(key, plaintext). */
    static const uint8_t expected_ct[16] = {0x3b, 0x5c, 0x52, 0x5c, 0x2f, 0x68,
                                            0xa9, 0x10, 0x52, 0x0e, 0x5e, 0xcf,
                                            0xd1, 0x9a, 0x17, 0xdd};

    voleith_circuit_t *c = voleith_circuit_new();

    wire_id key_wires[256];
    for (int i = 0; i < 256; i++)
        key_wires[i] = voleith_circuit_add_witness(c);
    wire_id pt_wires[128];
    for (int i = 0; i < 128; i++)
        pt_wires[i] = voleith_circuit_add_instance(c);
    wire_id ct_wires[128];
    aes256_circuit(c, key_wires, pt_wires, ct_wires);

    uint8_t witness[32], instance[16];
    memcpy(witness, key, 32);
    memcpy(instance, plaintext, 16);

    uint8_t result[16];
    eval_block_wires(c, witness, instance, ct_wires, result);

    check("AES-256 faest-ref OWF vector (FAEST_256F first block): all 16 bytes "
          "correct",
          memcmp(result, expected_ct, 16) == 0);

    voleith_circuit_free(c);
}

/* ================================================================
 * Test 9: NIST CAVP all-zeros AES-128
 * key = 00...00 (16 bytes), pt = 00...00 → ct = 66e94bd4ef8a2c3b884cfa59ca342b2e
 * Source: NIST CAVP ECBGFSbox128 / ECBVarKey128 zero-key case
 * ================================================================ */
static void
test_aes128_cavp_zeros(void)
{
    static const uint8_t key[16] = {0};
    static const uint8_t plaintext[16] = {0};
    static const uint8_t expected_ct[16] = {0x66, 0xe9, 0x4b, 0xd4, 0xef, 0x8a,
                                            0x2c, 0x3b, 0x88, 0x4c, 0xfa, 0x59,
                                            0xca, 0x34, 0x2b, 0x2e};

    voleith_circuit_t *c = voleith_circuit_new();

    wire_id key_wires[128];
    for (int i = 0; i < 128; i++)
        key_wires[i] = voleith_circuit_add_witness(c);
    wire_id pt_wires[128];
    for (int i = 0; i < 128; i++)
        pt_wires[i] = voleith_circuit_add_instance(c);
    wire_id ct_wires[128];
    aes128_circuit(c, key_wires, pt_wires, ct_wires);

    uint8_t witness[16], instance[16];
    memcpy(witness, key, 16);
    memcpy(instance, plaintext, 16);

    uint8_t result[16];
    eval_block_wires(c, witness, instance, ct_wires, result);

    check("NIST CAVP all-zeros AES-128: output matches",
          memcmp(result, expected_ct, 16) == 0);

    voleith_circuit_free(c);
}

/* ================================================================
 * Test 10: NIST CAVP all-zeros AES-256
 * key = 00...00 (32 bytes), pt = 00...00 → ct = dc95c078a2408989ad48a21492842087
 * Source: NIST CAVP ECBVarKey256 zero-key case
 * ================================================================ */
static void
test_aes256_cavp_zeros(void)
{
    static const uint8_t key[32] = {0};
    static const uint8_t plaintext[16] = {0};
    static const uint8_t expected_ct[16] = {0xdc, 0x95, 0xc0, 0x78, 0xa2, 0x40,
                                            0x89, 0x89, 0xad, 0x48, 0xa2, 0x14,
                                            0x92, 0x84, 0x20, 0x87};

    voleith_circuit_t *c = voleith_circuit_new();

    wire_id key_wires[256];
    for (int i = 0; i < 256; i++)
        key_wires[i] = voleith_circuit_add_witness(c);
    wire_id pt_wires[128];
    for (int i = 0; i < 128; i++)
        pt_wires[i] = voleith_circuit_add_instance(c);
    wire_id ct_wires[128];
    aes256_circuit(c, key_wires, pt_wires, ct_wires);

    uint8_t witness[32], instance[16];
    memcpy(witness, key, 32);
    memcpy(instance, plaintext, 16);

    uint8_t result[16];
    eval_block_wires(c, witness, instance, ct_wires, result);

    check("NIST CAVP all-zeros AES-256: output matches",
          memcmp(result, expected_ct, 16) == 0);

    voleith_circuit_free(c);
}

/* ================================================================
 * Test 7: AES-256 AND gate count
 * ================================================================ */
static void
test_aes256_and_count(void)
{
    voleith_circuit_t *c = voleith_circuit_new();

    wire_id key_wires[256];
    for (int i = 0; i < 256; i++)
        key_wires[i] = voleith_circuit_add_witness(c);
    wire_id pt_wires[128];
    for (int i = 0; i < 128; i++)
        pt_wires[i] = voleith_circuit_add_instance(c);
    wire_id ct_wires[128];

    size_t and_before = voleith_circuit_and_gate_count(c);
    aes256_circuit(c, key_wires, pt_wires, ct_wires);
    size_t and_count = voleith_circuit_and_gate_count(c) - and_before;

    /* 276 S-box calls (224 encryption + 52 key schedule) × 36 ANDs = 9936. */
    check("AES-256 uses 9936 AND gates (276 S-boxes × 36)", and_count == 9936);
    printf("    AES-256 AND gate count: %zu\n", and_count);

    voleith_circuit_free(c);
}

/* ================================================================
 * Main
 * ================================================================ */
int
main(void)
{
    printf("test_aes_circuit: AES S-box and AES-128/256 Boolean circuits\n");

    test_sbox_all_inputs();
    test_sbox_and_count();
    test_aes128_nist_vector();
    test_aes128_and_count();
    test_aes128_constraint_check();
    test_aes256_nist_vector();
    test_aes256_and_count();
    test_aes128_faest_vector();
    test_aes256_faest_vector();
    test_aes128_cavp_zeros();
    test_aes256_cavp_zeros();

    printf("  %d / %d passed\n", pass_count, test_count);
    return (pass_count == test_count) ? 0 : 1;
}
