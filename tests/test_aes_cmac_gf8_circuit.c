/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * test_aes_cmac_gf8_circuit.c - Tests for the GF(2⁸) element-level AES-CMAC circuit
 *
 * Tests:
 *   1: AES-128-CMAC, empty message       (RFC 4493 Example 1)
 *   2: AES-128-CMAC, 16-byte message     (RFC 4493 Example 2)
 *   3: AES-128-CMAC, 40-byte message     (RFC 4493 Example 3)
 *   4: AES-128-CMAC, 64-byte message     (RFC 4493 Example 4)
 *   5: Witness count: empty (16+2×200=416)
 *   6: Witness count: 16-byte message (16+2×200=416)
 *   7: Witness count: 40-byte message (16+4×200=816)
 *   8: AES-256-CMAC matches software reference (40-byte message)
 *   9: AES-256-CMAC matches software reference (empty message)
 *  10: AES-128-CMAC NIST CAVP vectors   (Mlen=10,20 K2 path; Mlen=32,33 K1/K2)
 *  11: AES-256-CMAC NIST CAVP vectors   (Mlen=10,15 K2 path; Mlen=16,48 K1 path)
 */

#include "aes_cmac_gf8_circuit.h"
#include "gf8_circuit.h"
#include "aes.h"
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
 * Software AES-CMAC reference (RFC 4493)
 * ================================================================ */

static void
cmac_ref(const uint8_t *key, int key_bits, const uint8_t *msg, size_t msg_bytes,
         uint8_t tag[16])
{
    voleith_aes_ctx_t ctx;
    voleith_aes_key_expand(&ctx, key, key_bits);

    uint8_t L[16] = {0};
    voleith_aes_encrypt(&ctx, L, L);

    uint8_t K1[16], K2[16];
    uint8_t msb;

    msb = (L[0] >> 7) & 1;
    for (int i = 0; i < 15; i++)
        K1[i] = (uint8_t)((L[i] << 1) | (L[i + 1] >> 7));
    K1[15] = (uint8_t)((L[15] << 1) ^ (msb ? 0x87u : 0u));

    msb = (K1[0] >> 7) & 1;
    for (int i = 0; i < 15; i++)
        K2[i] = (uint8_t)((K1[i] << 1) | (K1[i + 1] >> 7));
    K2[15] = (uint8_t)((K1[15] << 1) ^ (msb ? 0x87u : 0u));

    size_t n_full_blocks = msg_bytes / 16;
    size_t last_bytes = msg_bytes % 16;
    int needs_padding = (msg_bytes == 0) || (last_bytes != 0);

    uint8_t X[16] = {0};
    size_t n_inner = needs_padding
                         ? n_full_blocks
                         : (n_full_blocks > 0 ? n_full_blocks - 1 : 0);

    for (size_t blk = 0; blk < n_inner; blk++) {
        uint8_t inp[16];
        for (int i = 0; i < 16; i++)
            inp[i] = X[i] ^ msg[blk * 16 + i];
        voleith_aes_encrypt(&ctx, X, inp);
    }

    uint8_t last_inp[16];
    if (!needs_padding) {
        for (int i = 0; i < 16; i++)
            last_inp[i] = X[i] ^ msg[(n_full_blocks - 1) * 16 + i] ^ K1[i];
    } else {
        uint8_t padded[16] = {0};
        for (size_t b = 0; b < last_bytes; b++)
            padded[b] = msg[n_full_blocks * 16 + b];
        padded[last_bytes] = 0x80;
        for (int i = 0; i < 16; i++)
            last_inp[i] = X[i] ^ padded[i] ^ K2[i];
    }

    voleith_aes_encrypt(&ctx, tag, last_inp);
}

/* ================================================================
 * Circuit evaluation helper
 * ================================================================ */

/*
 * Build and evaluate an aes_cmac_gf8_circuit, returning the 16-byte tag.
 *
 * key bytes are witness wires; message bytes are instance wires.
 * voleith_gf8_circuit_eval assigns witness slots in declaration order, so
 * the key and message byte arrays can be passed directly as-is.
 */
static int
eval_cmac_gf8_circuit(const uint8_t *key, size_t key_bytes, const uint8_t *msg,
                      size_t msg_bytes, uint8_t result[16])
{
    voleith_gf8_circuit_t *c = voleith_gf8_circuit_new();
    if (!c)
        return -1;

    gf8_wire_id key_wires[32];
    for (size_t i = 0; i < key_bytes; i++)
        key_wires[i] = voleith_gf8_add_witness(c);

    gf8_wire_id *msg_wires = NULL;
    if (msg_bytes > 0) {
        msg_wires = calloc(msg_bytes, sizeof(gf8_wire_id));
        if (!msg_wires) {
            voleith_gf8_circuit_free(c);
            return -1;
        }
        for (size_t i = 0; i < msg_bytes; i++)
            msg_wires[i] = voleith_gf8_add_instance(c);
    }

    gf8_wire_id tag_wires[16];
    aes_cmac_gf8_circuit(c, key_wires, key_bytes, msg_wires, msg_bytes,
                         tag_wires);

    size_t n_wires = voleith_gf8_circuit_wire_count(c);
    uint8_t *vals = calloc(n_wires, 1);
    if (!vals) {
        free(msg_wires);
        voleith_gf8_circuit_free(c);
        return -1;
    }

    size_t w_bytes = aes_cmac_gf8_witness_bytes(key_bytes, msg_bytes);
    uint8_t *witness = calloc(w_bytes, 1);
    if (!witness) {
        free(vals);
        free(msg_wires);
        voleith_gf8_circuit_free(c);
        return -1;
    }

    aes_cmac_gf8_build_witness(key, key_bytes, msg, msg_bytes, witness, NULL);

    int ok =
        voleith_gf8_circuit_eval(c, witness, msg_bytes > 0 ? msg : NULL, vals);

    for (int i = 0; i < 16; i++)
        result[i] = vals[tag_wires[i]];

    free(witness);
    free(vals);
    free(msg_wires);
    voleith_gf8_circuit_free(c);
    return ok;
}

/* ================================================================
 * Tests 1-4: AES-128-CMAC vs RFC 4493 known-answer vectors
 *
 * K = 2B7E151628AED2A6ABF7158809CF4F3C
 * ================================================================ */

static void
test_cmac_rfc4493(void)
{
    static const uint8_t K[16] = {0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae,
                                  0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88,
                                  0x09, 0xcf, 0x4f, 0x3c};

    /* Example 1: Mlen = 0 */
    {
        static const uint8_t expected[16] = {0xbb, 0x1d, 0x69, 0x29, 0xe9, 0x59,
                                             0x37, 0x28, 0x7f, 0xa3, 0x7d, 0x12,
                                             0x9b, 0x75, 0x67, 0x46};
        uint8_t result[16];
        eval_cmac_gf8_circuit(K, 16, NULL, 0, result);
        check("AES-128-CMAC GF8 empty message (RFC 4493 Ex.1)",
              memcmp(result, expected, 16) == 0);
    }

    /* Example 2: Mlen = 16 bytes */
    {
        static const uint8_t M[16] = {0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40,
                                      0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11,
                                      0x73, 0x93, 0x17, 0x2a};
        static const uint8_t expected[16] = {0x07, 0x0a, 0x16, 0xb4, 0x6b, 0x4d,
                                             0x41, 0x44, 0xf7, 0x9b, 0xdd, 0x9d,
                                             0xd0, 0x4a, 0x28, 0x7c};
        uint8_t result[16];
        eval_cmac_gf8_circuit(K, 16, M, 16, result);
        check("AES-128-CMAC GF8 16 bytes (RFC 4493 Ex.2)",
              memcmp(result, expected, 16) == 0);
    }

    /* Example 3: Mlen = 40 bytes */
    {
        static const uint8_t M[40] = {
            0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d,
            0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a, 0xae, 0x2d, 0x8a, 0x57,
            0x1e, 0x03, 0xac, 0x9c, 0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf,
            0x8e, 0x51, 0x30, 0xc8, 0x1c, 0x46, 0xa3, 0x5c, 0xe4, 0x11};
        static const uint8_t expected[16] = {0xdf, 0xa6, 0x67, 0x47, 0xde, 0x9a,
                                             0xe6, 0x30, 0x30, 0xca, 0x32, 0x61,
                                             0x14, 0x97, 0xc8, 0x27};
        uint8_t result[16];
        eval_cmac_gf8_circuit(K, 16, M, 40, result);
        check("AES-128-CMAC GF8 40 bytes (RFC 4493 Ex.3)",
              memcmp(result, expected, 16) == 0);
    }

    /* Example 4: Mlen = 64 bytes */
    {
        static const uint8_t M[64] = {
            0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e,
            0x11, 0x73, 0x93, 0x17, 0x2a, 0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03,
            0xac, 0x9c, 0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51, 0x30,
            0xc8, 0x1c, 0x46, 0xa3, 0x5c, 0xe4, 0x11, 0xe5, 0xfb, 0xc1, 0x19,
            0x1a, 0x0a, 0x52, 0xef, 0xf6, 0x9f, 0x24, 0x45, 0xdf, 0x4f, 0x9b,
            0x17, 0xad, 0x2b, 0x41, 0x7b, 0xe6, 0x6c, 0x37, 0x10};
        static const uint8_t expected[16] = {0x51, 0xf0, 0xbe, 0xbf, 0x7e, 0x3b,
                                             0x9d, 0x92, 0xfc, 0x49, 0x74, 0x17,
                                             0x79, 0x36, 0x3c, 0xfe};
        uint8_t result[16];
        eval_cmac_gf8_circuit(K, 16, M, 64, result);
        check("AES-128-CMAC GF8 64 bytes (RFC 4493 Ex.4)",
              memcmp(result, expected, 16) == 0);
    }
}

/* ================================================================
 * Tests 5-7: Witness counts
 *
 * Witness slots = key_bytes + n_aes_calls × inv_per_call
 * where n_aes_calls = aes_cmac_gf8_n_aes_calls(message_bytes)
 * and inv_per_call = 200 (AES-128) or 276 (AES-256).
 * ================================================================ */

static void
test_witness_counts(void)
{
    /* Empty message: 1 subkey AES + 1 CBC AES = 2 × 200 + 16 key = 416 */
    {
        voleith_gf8_circuit_t *c = voleith_gf8_circuit_new();
        gf8_wire_id key[16];
        for (int i = 0; i < 16; i++)
            key[i] = voleith_gf8_add_witness(c);
        gf8_wire_id tag[16];
        aes_cmac_gf8_circuit(c, key, 16, NULL, 0, tag);
        size_t got = voleith_gf8_circuit_witness_count(c);
        check("AES-128-CMAC GF8 witness count (empty): 16+2×200=416",
              got == 416);
        voleith_gf8_circuit_free(c);
    }

    /* 16-byte message: 1 subkey AES + 1 CBC AES = 2 × 200 + 16 = 416 */
    {
        voleith_gf8_circuit_t *c = voleith_gf8_circuit_new();
        gf8_wire_id key[16];
        for (int i = 0; i < 16; i++)
            key[i] = voleith_gf8_add_witness(c);
        gf8_wire_id msg[16];
        for (int i = 0; i < 16; i++)
            msg[i] = voleith_gf8_add_instance(c);
        gf8_wire_id tag[16];
        aes_cmac_gf8_circuit(c, key, 16, msg, 16, tag);
        size_t got = voleith_gf8_circuit_witness_count(c);
        check("AES-128-CMAC GF8 witness count (1 block): 16+2×200=416",
              got == 416);
        voleith_gf8_circuit_free(c);
    }

    /* 40-byte message: 1 subkey + 3 CBC = 4 AES calls → 16+4×200=816 */
    {
        voleith_gf8_circuit_t *c = voleith_gf8_circuit_new();
        gf8_wire_id key[16];
        for (int i = 0; i < 16; i++)
            key[i] = voleith_gf8_add_witness(c);
        gf8_wire_id msg[40];
        for (int i = 0; i < 40; i++)
            msg[i] = voleith_gf8_add_instance(c);
        gf8_wire_id tag[16];
        aes_cmac_gf8_circuit(c, key, 16, msg, 40, tag);
        size_t got = voleith_gf8_circuit_witness_count(c);
        check("AES-128-CMAC GF8 witness count (40 bytes): 16+4×200=816",
              got == 816);
        voleith_gf8_circuit_free(c);
    }
}

/* ================================================================
 * Tests 8-9: AES-256-CMAC circuit matches software reference
 * ================================================================ */

static void
test_cmac_aes256(void)
{
    static const uint8_t K[32] = {
        0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe, 0x2b, 0x73, 0xae,
        0xf0, 0x85, 0x7d, 0x77, 0x81, 0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61,
        0x08, 0xd7, 0x2d, 0x98, 0x10, 0xa3, 0x09, 0x14, 0xdf, 0xf4};

    /* 40-byte message */
    static const uint8_t M[40] = {
        0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d,
        0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a, 0xae, 0x2d, 0x8a, 0x57,
        0x1e, 0x03, 0xac, 0x9c, 0x9e, 0xb7, 0x6f, 0xad, 0xc5, 0xc9,
        0xd5, 0x6e, 0xf0, 0x9f, 0x4d, 0xf1, 0x00, 0x00, 0x00, 0x00};

    uint8_t ref[16], result[16];

    cmac_ref(K, 256, M, 40, ref);
    eval_cmac_gf8_circuit(K, 32, M, 40, result);
    check("AES-256-CMAC GF8 matches software reference (40 bytes)",
          memcmp(result, ref, 16) == 0);

    cmac_ref(K, 256, NULL, 0, ref);
    eval_cmac_gf8_circuit(K, 32, NULL, 0, result);
    check("AES-256-CMAC GF8 matches software reference (empty)",
          memcmp(result, ref, 16) == 0);
}

/* ================================================================
 * Test 10: AES-128-CMAC GF8 vs NIST CAVP vectors
 *
 *   Mlen=10: K2 path, partial first block     (VerAES128 Count=122, Tlen=8)
 *   Mlen=20: K2 path, 1 full + 4-byte partial (VerAES128 Count=164, Tlen=8)
 *   Mlen=32: K1 path, 2 exact blocks          (GenAES128 Count=40,  Tlen=15)
 *   Mlen=33: K2 path, 2 full + 1-byte partial (GenAES128 Count=56,  Tlen=15)
 * ================================================================ */

static void
test_cmac_cavp_aes128(void)
{
    uint8_t result[16];

    /* Mlen=10: K2 path, partial first block (VerAES128 Count=122) */
    {
        static const uint8_t K[16] = {0x1b, 0x31, 0x63, 0xe2, 0xd3, 0xa4,
                                      0x71, 0xb9, 0x82, 0x35, 0x25, 0xab,
                                      0xc7, 0x54, 0x3c, 0x4c};
        static const uint8_t M[10] = {0xca, 0xda, 0x03, 0xe8, 0xc9,
                                      0x67, 0xf9, 0x73, 0x2a, 0x81};
        static const uint8_t expected[8] = {0x53, 0x70, 0x2f, 0xa9,
                                            0x8e, 0x6f, 0x9a, 0x19};
        eval_cmac_gf8_circuit(K, 16, M, 10, result);
        check("AES-128-CMAC GF8 10 bytes K2 (CAVP VerAES128 #122)",
              memcmp(result, expected, 8) == 0);
    }

    /* Mlen=20: K2 path, 1 full + 4-byte partial (VerAES128 Count=164) */
    {
        static const uint8_t K[16] = {0x09, 0x8c, 0x12, 0x05, 0x8a, 0x0b,
                                      0xc5, 0x95, 0x1f, 0xc0, 0x92, 0xab,
                                      0xa3, 0x22, 0xe1, 0xa0};
        static const uint8_t M[20] = {0xa2, 0xb7, 0x68, 0x35, 0x22, 0x90, 0x17,
                                      0xbd, 0x0e, 0x81, 0x67, 0xa4, 0x0e, 0xa1,
                                      0xe2, 0xe1, 0x8c, 0xc5, 0xdb, 0x0a};
        static const uint8_t expected[8] = {0x1d, 0x44, 0x12, 0x8c,
                                            0x3d, 0xb0, 0xf7, 0xb9};
        eval_cmac_gf8_circuit(K, 16, M, 20, result);
        check("AES-128-CMAC GF8 20 bytes K2 (CAVP VerAES128 #164)",
              memcmp(result, expected, 8) == 0);
    }

    /* Mlen=32: K1 path, 2 exact blocks (GenAES128 Count=40) */
    {
        static const uint8_t K[16] = {0x53, 0x4c, 0x6f, 0x8f, 0x88, 0xbc,
                                      0x35, 0x3f, 0xae, 0xe5, 0x26, 0x64,
                                      0x99, 0x5d, 0x54, 0x57};
        static const uint8_t M[32] = {
            0x49, 0x81, 0xc5, 0x1f, 0xcc, 0x09, 0x35, 0xf6, 0x19, 0xec, 0x6b,
            0xf8, 0x62, 0x68, 0x3b, 0x00, 0x25, 0xcc, 0x48, 0x72, 0x48, 0x39,
            0xbc, 0x1e, 0x67, 0xaa, 0x3c, 0x68, 0x6d, 0x32, 0x1b, 0xa6};
        static const uint8_t expected[15] = {0x63, 0x77, 0xc6, 0xcf, 0xe8,
                                             0xdd, 0x60, 0x5e, 0xf0, 0xa6,
                                             0x2a, 0x84, 0x5a, 0xb3, 0xf7};
        eval_cmac_gf8_circuit(K, 16, M, 32, result);
        check("AES-128-CMAC GF8 32 bytes K1 (CAVP GenAES128 #40)",
              memcmp(result, expected, 15) == 0);
    }

    /* Mlen=33: K2 path, 2 full + 1-byte partial (GenAES128 Count=56) */
    {
        static const uint8_t K[16] = {0xa0, 0xc3, 0x34, 0xff, 0x35, 0x01,
                                      0xc9, 0x9a, 0x9d, 0x5f, 0x26, 0x60,
                                      0xf4, 0xa2, 0xcc, 0x5f};
        static const uint8_t M[33] = {
            0xb4, 0x69, 0x3a, 0x2a, 0xa1, 0x1c, 0xf9, 0xa5, 0x44, 0x2f, 0x08,
            0xdf, 0xa7, 0x18, 0x59, 0x0f, 0xef, 0xf8, 0xd3, 0x8f, 0xdf, 0x15,
            0xf8, 0xee, 0x9d, 0x8a, 0xc5, 0x41, 0xb9, 0x3d, 0xd9, 0xb9, 0x6b};
        static const uint8_t expected[15] = {0x6d, 0x4b, 0xf5, 0x0d, 0x3a,
                                             0x13, 0xa2, 0x6d, 0x9d, 0xc7,
                                             0x56, 0x6d, 0xee, 0x12, 0x23};
        eval_cmac_gf8_circuit(K, 16, M, 33, result);
        check("AES-128-CMAC GF8 33 bytes K2 (CAVP GenAES128 #56)",
              memcmp(result, expected, 15) == 0);
    }
}

/* ================================================================
 * Test 11: AES-256-CMAC GF8 vs NIST CAVP vectors
 *
 *   Mlen=10: K2 path, partial first block     (GenAES256 Count=56, Tlen=10)
 *   Mlen=15: K2 path, maximal partial block   (GenAES256 Count=72, Tlen=10)
 *   Mlen=16: K1 path, 1 exact block           (GenAES256 Count=24, Tlen=10)
 *   Mlen=48: K1 path, 3 exact blocks          (GenAES256 Count=40, Tlen=10)
 * ================================================================ */

static void
test_cmac_cavp_aes256(void)
{
    uint8_t result[16];

    /* Mlen=10: K2 path, partial first block (GenAES256 Count=56) */
    {
        static const uint8_t K[32] = {
            0x71, 0x2e, 0x6c, 0xc3, 0x3d, 0x3d, 0x1f, 0x44, 0x27, 0x76, 0xd5,
            0x46, 0xf4, 0xd5, 0xa2, 0x5b, 0x7d, 0x23, 0x40, 0x2a, 0x5f, 0xd6,
            0x5e, 0x6e, 0xf3, 0x33, 0x3a, 0x42, 0x81, 0xb5, 0x72, 0x9b};
        static const uint8_t M[10] = {0x56, 0xc0, 0x26, 0xb8, 0xa7,
                                      0x19, 0x74, 0xff, 0x7e, 0xcd};
        static const uint8_t expected[10] = {0xdf, 0x8d, 0xc0, 0x96, 0xf5,
                                             0xb3, 0x85, 0xfa, 0xaf, 0xfa};
        eval_cmac_gf8_circuit(K, 32, M, 10, result);
        check("AES-256-CMAC GF8 10 bytes K2 (CAVP GenAES256 #56)",
              memcmp(result, expected, 10) == 0);
    }

    /* Mlen=15: K2 path, maximal partial first block (GenAES256 Count=72) */
    {
        static const uint8_t K[32] = {
            0x2f, 0x4a, 0x65, 0x01, 0xd8, 0xfe, 0x7b, 0x65, 0xf6, 0x07, 0x75,
            0x7d, 0xdf, 0xf6, 0xed, 0x87, 0xae, 0x06, 0x81, 0xb9, 0x8b, 0x53,
            0x33, 0x1d, 0x2d, 0x46, 0x10, 0x9f, 0x9c, 0x54, 0x10, 0x65};
        static const uint8_t M[15] = {0x4f, 0xa9, 0xac, 0x1b, 0x54,
                                      0x4a, 0xfc, 0xd8, 0x5a, 0xc3,
                                      0x2a, 0xc0, 0x90, 0x9c, 0x74};
        static const uint8_t expected[10] = {0xc0, 0x2e, 0x8b, 0x66, 0xf9,
                                             0xfc, 0x26, 0x3b, 0x8f, 0xb0};
        eval_cmac_gf8_circuit(K, 32, M, 15, result);
        check("AES-256-CMAC GF8 15 bytes K2 (CAVP GenAES256 #72)",
              memcmp(result, expected, 10) == 0);
    }

    /* Mlen=16: K1 path, 1 exact block (GenAES256 Count=24) */
    {
        static const uint8_t K[32] = {
            0x3a, 0x75, 0xa9, 0xd2, 0xbd, 0xb8, 0xc8, 0x04, 0xba, 0x4a, 0xb4,
            0x98, 0x35, 0x73, 0xa6, 0xb2, 0x53, 0x16, 0x0d, 0xd9, 0x0f, 0x8e,
            0xdd, 0xfb, 0x2f, 0xdc, 0x2a, 0xb1, 0x76, 0x04, 0xf5, 0xc5};
        static const uint8_t M[16] = {0x42, 0xf3, 0x5d, 0x5a, 0xa5, 0x33,
                                      0xa7, 0xa0, 0xa5, 0xf7, 0x4e, 0x14,
                                      0x4f, 0x2a, 0x5f, 0x20};
        static const uint8_t expected[10] = {0xf1, 0x53, 0x2f, 0x87, 0x32,
                                             0xd9, 0xf5, 0x90, 0x30, 0x07};
        eval_cmac_gf8_circuit(K, 32, M, 16, result);
        check("AES-256-CMAC GF8 16 bytes K1 (CAVP GenAES256 #24)",
              memcmp(result, expected, 10) == 0);
    }

    /* Mlen=48: K1 path, 3 exact blocks (GenAES256 Count=40) */
    {
        static const uint8_t K[32] = {
            0xd1, 0xab, 0xde, 0x73, 0xd9, 0x27, 0xee, 0xf3, 0x81, 0xf3, 0x7a,
            0xbc, 0x25, 0x4e, 0xd9, 0x95, 0xfe, 0xd9, 0x33, 0xd4, 0x99, 0x41,
            0x95, 0x23, 0x87, 0x1d, 0x44, 0x84, 0x57, 0x1a, 0x52, 0x93};
        static const uint8_t M[48] = {
            0x21, 0xed, 0x22, 0xab, 0xc7, 0xbb, 0xb6, 0x2f, 0xb2, 0xd5,
            0x1d, 0x1f, 0xb8, 0x83, 0x0c, 0xa9, 0x5b, 0x16, 0x21, 0x3f,
            0x56, 0x29, 0x1a, 0xf9, 0x76, 0x27, 0x49, 0x34, 0xab, 0x0d,
            0x43, 0x80, 0x5f, 0x71, 0xd9, 0xb9, 0x06, 0xc4, 0x49, 0x73,
            0xf7, 0xd4, 0xb5, 0x9b, 0x7a, 0x94, 0xd3, 0x5c};
        static const uint8_t expected[10] = {0x3a, 0xd1, 0x2d, 0xf7, 0xac,
                                             0xeb, 0xdf, 0x36, 0xee, 0x1a};
        eval_cmac_gf8_circuit(K, 32, M, 48, result);
        check("AES-256-CMAC GF8 48 bytes K1 (CAVP GenAES256 #40)",
              memcmp(result, expected, 10) == 0);
    }
}

int
main(void)
{
    printf("=== test_aes_cmac_gf8_circuit ===\n");

    printf("\n[AES-128-CMAC GF8 RFC 4493 known-answer vectors]\n");
    test_cmac_rfc4493();

    printf("\n[AES-128-CMAC GF8 witness counts]\n");
    test_witness_counts();

    printf("\n[AES-256-CMAC GF8 software reference comparison]\n");
    test_cmac_aes256();

    printf("\n[AES-128-CMAC GF8 NIST CAVP vectors]\n");
    test_cmac_cavp_aes128();

    printf("\n[AES-256-CMAC GF8 NIST CAVP vectors]\n");
    test_cmac_cavp_aes256();

    printf("\n  %d / %d passed\n", pass_count, test_count);
    return (pass_count == test_count) ? 0 : 1;
}
