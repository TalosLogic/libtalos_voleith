/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * test_kdf_ctr_cmac_circuit.c - Tests for the KDF-CTR-CMAC Boolean circuit
 *
 * Tests:
 *   1-4: NIST CAVS 14.4 known-answer vectors (SP 800-108 Counter Mode,
 *        CMAC_AES128 and CMAC_AES256, CTRLOCATION=BEFORE_FIXED, RLEN=32_BITS)
 *        - two vectors per key size (L=128 for n=1, L=256 for n=2)
 *   5-7: AND gate counts
 *   8-9: Circuit output matches software reference (AES-128 and AES-256)
 */

#include "kdf_ctr_cmac_circuit.h"
#include "circuit.h"
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
 * Software KDF-CTR-CMAC reference
 *
 * Matches the circuit exactly:
 *   K(i) = CMAC(K_IN, [i]_32be || fixed_input),  i = 1..n
 *   K_OUT = leftmost output_bytes*8 bits of K(1) || K(2) || ... || K(n)
 * ================================================================ */

static void
kdf_ref(const uint8_t *key, int key_bits, const uint8_t *fixed_input,
        size_t fixed_input_bytes, uint8_t *output, size_t output_bytes)
{
    size_t n = (output_bytes * 8 + 127) / 128;
    size_t msg_bytes = 4 + fixed_input_bytes;

    uint8_t *msg = calloc(msg_bytes, 1);
    if (!msg)
        return;

    if (fixed_input_bytes > 0 && fixed_input)
        memcpy(msg + 4, fixed_input, fixed_input_bytes);

    for (size_t i = 1; i <= n; i++) {
        msg[0] = (uint8_t)((i >> 24) & 0xFF);
        msg[1] = (uint8_t)((i >> 16) & 0xFF);
        msg[2] = (uint8_t)((i >> 8) & 0xFF);
        msg[3] = (uint8_t)((i >> 0) & 0xFF);

        uint8_t Ki[16];
        cmac_ref(key, key_bits, msg, msg_bytes, Ki);

        size_t out_offset = (i - 1) * 16;
        size_t bytes_to_copy = (out_offset + 16 <= output_bytes)
                                   ? 16
                                   : (output_bytes - out_offset);
        memcpy(output + out_offset, Ki, bytes_to_copy);
    }

    free(msg);
}

/* ================================================================
 * Circuit evaluation helper
 *
 * Key as witness wires, fixed_input as instance wires.
 * voleith_circuit_eval indexes inputs by sequential bit position
 * in declaration order, so raw byte arrays can be passed directly.
 * ================================================================ */

static void
eval_kdf_circuit(const uint8_t *key, int key_bits, const uint8_t *fixed_input,
                 size_t fixed_input_bytes, uint8_t *output, size_t output_bytes)
{
    voleith_circuit_t *c = voleith_circuit_new();
    if (!c) {
        memset(output, 0, output_bytes);
        return;
    }

    wire_id key_wires[256];
    for (int i = 0; i < key_bits; i++)
        key_wires[i] = voleith_circuit_add_witness(c);

    wire_id *fi_wires = NULL;
    if (fixed_input_bytes > 0) {
        fi_wires = calloc(fixed_input_bytes * 8, sizeof(wire_id));
        if (!fi_wires) {
            voleith_circuit_free(c);
            memset(output, 0, output_bytes);
            return;
        }
        for (size_t i = 0; i < fixed_input_bytes * 8; i++)
            fi_wires[i] = voleith_circuit_add_instance(c);
    }

    size_t output_bits = output_bytes * 8;
    wire_id *out_wires = calloc(output_bits, sizeof(wire_id));
    if (!out_wires) {
        free(fi_wires);
        voleith_circuit_free(c);
        memset(output, 0, output_bytes);
        return;
    }

    kdf_ctr_cmac_circuit(c, key_wires, (size_t)key_bits, fi_wires,
                         fixed_input_bytes * 8, out_wires, output_bits);

    size_t n_wires = voleith_circuit_wire_count(c);
    uint8_t *vals = calloc((n_wires + 7) / 8, 1);
    if (!vals) {
        free(out_wires);
        free(fi_wires);
        voleith_circuit_free(c);
        memset(output, 0, output_bytes);
        return;
    }

    voleith_circuit_eval(c, key, fixed_input_bytes > 0 ? fixed_input : NULL,
                         vals);

    for (size_t byte_idx = 0; byte_idx < output_bytes; byte_idx++) {
        output[byte_idx] = 0;
        for (int bit = 0; bit < 8; bit++) {
            wire_id w = out_wires[byte_idx * 8 + bit];
            output[byte_idx] |=
                (uint8_t)(((vals[w / 8] >> (w % 8)) & 1) << bit);
        }
    }

    free(vals);
    free(out_wires);
    free(fi_wires);
    voleith_circuit_free(c);
}

/* ================================================================
 * Tests 1-4: NIST CAVS 14.4 known-answer vectors
 *
 * Source: CAVS 14.4 SP800-108 KDF, Counter Mode, BEFORE_FIXED, RLEN=32
 * Note: AES-192 is not tested (not supported by this library).
 * ================================================================ */

static void
test_cavs_aes128(void)
{
    /*
     * COUNT=0, L=128 (n=1)
     * KI = c10b152e8c97b77e18704e0f0bd38305
     * FixedInputData (60 bytes):
     *   98cd4cbbbebe15d17dc86e6dbad800a2dcbd64f7c7ad0e78e9cf94ff
     *   dba89d03e97eadf6c4f7b806caf52aa38f09d0eb71d71f497bcc6906b48d36c4
     * instring = 00000001 || FixedInputData
     * KO = 26faf61908ad9ee881b8305c221db53f
     */
    {
        static const uint8_t KI[16] = {0xc1, 0x0b, 0x15, 0x2e, 0x8c, 0x97,
                                       0xb7, 0x7e, 0x18, 0x70, 0x4e, 0x0f,
                                       0x0b, 0xd3, 0x83, 0x05};
        static const uint8_t FI[60] = {
            0x98, 0xcd, 0x4c, 0xbb, 0xbe, 0xbe, 0x15, 0xd1, 0x7d, 0xc8,
            0x6e, 0x6d, 0xba, 0xd8, 0x00, 0xa2, 0xdc, 0xbd, 0x64, 0xf7,
            0xc7, 0xad, 0x0e, 0x78, 0xe9, 0xcf, 0x94, 0xff, 0xdb, 0xa8,
            0x9d, 0x03, 0xe9, 0x7e, 0xad, 0xf6, 0xc4, 0xf7, 0xb8, 0x06,
            0xca, 0xf5, 0x2a, 0xa3, 0x8f, 0x09, 0xd0, 0xeb, 0x71, 0xd7,
            0x1f, 0x49, 0x7b, 0xcc, 0x69, 0x06, 0xb4, 0x8d, 0x36, 0xc4};
        static const uint8_t KO[16] = {0x26, 0xfa, 0xf6, 0x19, 0x08, 0xad,
                                       0x9e, 0xe8, 0x81, 0xb8, 0x30, 0x5c,
                                       0x22, 0x1d, 0xb5, 0x3f};
        uint8_t result[16];
        eval_kdf_circuit(KI, 128, FI, 60, result, 16);
        check("CAVS AES-128 L=128 (n=1)", memcmp(result, KO, 16) == 0);
    }

    /*
     * COUNT=10, L=256 (n=2)
     * KI = 695f1b1a16c949cea51cdf2554ec9d42
     * FixedInputData (60 bytes):
     *   4fce5942832a390aa1cbe8a0bf9d202cb799e986c9d6b51f45e4d597
     *   a6b57f06a4ebfec6467335d116b7f5f9c5b954062f661820f5db2a5bbb3e0625
     * KO = d34b601ec18c34dfa0f9e0b7523e218bdddb9befe8d08b6c0202d75ace0dba89
     */
    {
        static const uint8_t KI[16] = {0x69, 0x5f, 0x1b, 0x1a, 0x16, 0xc9,
                                       0x49, 0xce, 0xa5, 0x1c, 0xdf, 0x25,
                                       0x54, 0xec, 0x9d, 0x42};
        static const uint8_t FI[60] = {
            0x4f, 0xce, 0x59, 0x42, 0x83, 0x2a, 0x39, 0x0a, 0xa1, 0xcb,
            0xe8, 0xa0, 0xbf, 0x9d, 0x20, 0x2c, 0xb7, 0x99, 0xe9, 0x86,
            0xc9, 0xd6, 0xb5, 0x1f, 0x45, 0xe4, 0xd5, 0x97, 0xa6, 0xb5,
            0x7f, 0x06, 0xa4, 0xeb, 0xfe, 0xc6, 0x46, 0x73, 0x35, 0xd1,
            0x16, 0xb7, 0xf5, 0xf9, 0xc5, 0xb9, 0x54, 0x06, 0x2f, 0x66,
            0x18, 0x20, 0xf5, 0xdb, 0x2a, 0x5b, 0xbb, 0x3e, 0x06, 0x25};
        static const uint8_t KO[32] = {
            0xd3, 0x4b, 0x60, 0x1e, 0xc1, 0x8c, 0x34, 0xdf, 0xa0, 0xf9, 0xe0,
            0xb7, 0x52, 0x3e, 0x21, 0x8b, 0xdd, 0xdb, 0x9b, 0xef, 0xe8, 0xd0,
            0x8b, 0x6c, 0x02, 0x02, 0xd7, 0x5a, 0xce, 0x0d, 0xba, 0x89};
        uint8_t result[32];
        eval_kdf_circuit(KI, 128, FI, 60, result, 32);
        check("CAVS AES-128 L=256 (n=2)", memcmp(result, KO, 32) == 0);
    }
}

static void
test_cavs_aes256(void)
{
    /*
     * COUNT=0, L=128 (n=1)
     * KI = d0b1b3b70b2393c48ca05159e7e28cbeadea93f28a7cdae964e5136070c45d5c
     * FixedInputData (60 bytes):
     *   dd2f151a3f173492a6fbbb602189d51ddf8ef79fc8e96b8fcbe6dabe
     *   73a35b48104f9dff2d63d48786d2b3af177091d646a9efae005bdfacb61a1214
     * KO = 8c449fb474d1c1d4d2a33827103b656a
     */
    {
        static const uint8_t KI[32] = {
            0xd0, 0xb1, 0xb3, 0xb7, 0x0b, 0x23, 0x93, 0xc4, 0x8c, 0xa0, 0x51,
            0x59, 0xe7, 0xe2, 0x8c, 0xbe, 0xad, 0xea, 0x93, 0xf2, 0x8a, 0x7c,
            0xda, 0xe9, 0x64, 0xe5, 0x13, 0x60, 0x70, 0xc4, 0x5d, 0x5c};
        static const uint8_t FI[60] = {
            0xdd, 0x2f, 0x15, 0x1a, 0x3f, 0x17, 0x34, 0x92, 0xa6, 0xfb,
            0xbb, 0x60, 0x21, 0x89, 0xd5, 0x1d, 0xdf, 0x8e, 0xf7, 0x9f,
            0xc8, 0xe9, 0x6b, 0x8f, 0xcb, 0xe6, 0xda, 0xbe, 0x73, 0xa3,
            0x5b, 0x48, 0x10, 0x4f, 0x9d, 0xff, 0x2d, 0x63, 0xd4, 0x87,
            0x86, 0xd2, 0xb3, 0xaf, 0x17, 0x70, 0x91, 0xd6, 0x46, 0xa9,
            0xef, 0xae, 0x00, 0x5b, 0xdf, 0xac, 0xb6, 0x1a, 0x12, 0x14};
        static const uint8_t KO[16] = {0x8c, 0x44, 0x9f, 0xb4, 0x74, 0xd1,
                                       0xc1, 0xd4, 0xd2, 0xa3, 0x38, 0x27,
                                       0x10, 0x3b, 0x65, 0x6a};
        uint8_t result[16];
        eval_kdf_circuit(KI, 256, FI, 60, result, 16);
        check("CAVS AES-256 L=128 (n=1)", memcmp(result, KO, 16) == 0);
    }

    /*
     * COUNT=10, L=256 (n=2)
     * KI = d54b6fd94f7cf98fd955517f937e9927f9536caebe148fba1818c1ba46bba3a4
     * FixedInputData (60 bytes):
     *   94c4a0c69526196c1377cebf0a2ae0fb4b57797c61bea8eeb0518ca0
     *   8652d14a5e1bd1b116b1794ac8a476acbdbbcd4f6142d7b8515bad09ec72f7af
     * KO = 2e1efed4aef3fdd324e098c0a07c0d97f8fd2c748a996ce29861ca042474daea
     */
    {
        static const uint8_t KI[32] = {
            0xd5, 0x4b, 0x6f, 0xd9, 0x4f, 0x7c, 0xf9, 0x8f, 0xd9, 0x55, 0x51,
            0x7f, 0x93, 0x7e, 0x99, 0x27, 0xf9, 0x53, 0x6c, 0xae, 0xbe, 0x14,
            0x8f, 0xba, 0x18, 0x18, 0xc1, 0xba, 0x46, 0xbb, 0xa3, 0xa4};
        static const uint8_t FI[60] = {
            0x94, 0xc4, 0xa0, 0xc6, 0x95, 0x26, 0x19, 0x6c, 0x13, 0x77,
            0xce, 0xbf, 0x0a, 0x2a, 0xe0, 0xfb, 0x4b, 0x57, 0x79, 0x7c,
            0x61, 0xbe, 0xa8, 0xee, 0xb0, 0x51, 0x8c, 0xa0, 0x86, 0x52,
            0xd1, 0x4a, 0x5e, 0x1b, 0xd1, 0xb1, 0x16, 0xb1, 0x79, 0x4a,
            0xc8, 0xa4, 0x76, 0xac, 0xbd, 0xbb, 0xcd, 0x4f, 0x61, 0x42,
            0xd7, 0xb8, 0x51, 0x5b, 0xad, 0x09, 0xec, 0x72, 0xf7, 0xaf};
        static const uint8_t KO[32] = {
            0x2e, 0x1e, 0xfe, 0xd4, 0xae, 0xf3, 0xfd, 0xd3, 0x24, 0xe0, 0x98,
            0xc0, 0xa0, 0x7c, 0x0d, 0x97, 0xf8, 0xfd, 0x2c, 0x74, 0x8a, 0x99,
            0x6c, 0xe2, 0x98, 0x61, 0xca, 0x04, 0x24, 0x74, 0xda, 0xea};
        uint8_t result[32];
        eval_kdf_circuit(KI, 256, FI, 60, result, 32);
        check("CAVS AES-256 L=256 (n=2)", memcmp(result, KO, 32) == 0);
    }
}

/* ================================================================
 * Tests 5-7: AND gate counts
 *
 * msg_bytes per CMAC call = 4 (counter) + fixed_input_bytes.
 * CMAC AES calls = 1 (subkey) + ceil(msg_bytes / 16) if msg is full-block
 *                                aligned, else 1 + ceil padding blocks.
 * ================================================================ */

static void
test_and_gate_counts(void)
{
    /*
     * Case A: empty fixed_input, n=1.
     *   msg_bytes = 4, needs_padding=true, n_cbc_blocks=1.
     *   CMAC AES calls = 1 + 1 = 2.  AND = 1 × 2 × 7200 = 14400.
     */
    {
        voleith_circuit_t *c = voleith_circuit_new();
        wire_id key[128];
        for (int i = 0; i < 128; i++)
            key[i] = voleith_circuit_add_witness(c);
        wire_id out[128];
        kdf_ctr_cmac_circuit(c, key, 128, NULL, 0, out, 128);
        size_t got = voleith_circuit_and_gate_count(c);
        check("KDF AND gates: empty fixed_input, n=1: 1×2×7200 = 14400",
              got == 14400);
        voleith_circuit_free(c);
    }

    /*
     * Case B: empty fixed_input, n=2.
     *   Same 4-byte message per call.  AND = 2 × 2 × 7200 = 28800.
     */
    {
        voleith_circuit_t *c = voleith_circuit_new();
        wire_id key[128];
        for (int i = 0; i < 128; i++)
            key[i] = voleith_circuit_add_witness(c);
        wire_id out[256];
        kdf_ctr_cmac_circuit(c, key, 128, NULL, 0, out, 256);
        size_t got = voleith_circuit_and_gate_count(c);
        check("KDF AND gates: empty fixed_input, n=2: 2×2×7200 = 28800",
              got == 28800);
        voleith_circuit_free(c);
    }

    /*
     * Case C: 28-byte fixed_input, n=1.
     *   msg_bytes = 4 + 28 = 32 bytes = 2 full blocks, no padding.
     *   n_inner = 1, CMAC AES calls = 1 + 2 = 3.
     *   AND = 1 × 3 × 7200 = 21600.
     */
    {
        voleith_circuit_t *c = voleith_circuit_new();
        wire_id key[128];
        for (int i = 0; i < 128; i++)
            key[i] = voleith_circuit_add_witness(c);
        wire_id fi[28 * 8];
        for (int i = 0; i < 28 * 8; i++)
            fi[i] = voleith_circuit_add_instance(c);
        wire_id out[128];
        kdf_ctr_cmac_circuit(c, key, 128, fi, 28 * 8, out, 128);
        size_t got = voleith_circuit_and_gate_count(c);
        check("KDF AND gates: 28-byte fixed_input, n=1: 1×3×7200 = 21600",
              got == 21600);
        voleith_circuit_free(c);
    }
}

/* ================================================================
 * Tests 8-9: Circuit matches software reference
 * ================================================================ */

static void
test_software_reference(void)
{
    /* AES-128, 8-byte fixed_input, 256-bit output */
    {
        static const uint8_t key[16] = {0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae,
                                        0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88,
                                        0x09, 0xcf, 0x4f, 0x3c};
        static const uint8_t fi[8] = {0x00, 0x01, 0x02, 0x03,
                                      0x04, 0x05, 0x06, 0x07};
        uint8_t ref[32], result[32];
        kdf_ref(key, 128, fi, 8, ref, 32);
        eval_kdf_circuit(key, 128, fi, 8, result, 32);
        check("Software reference: AES-128, 8-byte fixed_input, 256-bit output",
              memcmp(result, ref, 32) == 0);
    }

    /* AES-256, empty fixed_input, 128-bit output */
    {
        static const uint8_t key[32] = {
            0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe, 0x2b, 0x73, 0xae,
            0xf0, 0x85, 0x7d, 0x77, 0x81, 0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61,
            0x08, 0xd7, 0x2d, 0x98, 0x10, 0xa3, 0x09, 0x14, 0xdf, 0xf4};
        uint8_t ref[16], result[16];
        kdf_ref(key, 256, NULL, 0, ref, 16);
        eval_kdf_circuit(key, 256, NULL, 0, result, 16);
        check("Software reference: AES-256, empty fixed_input, 128-bit output",
              memcmp(result, ref, 16) == 0);
    }
}

int
main(void)
{
    printf("=== test_kdf_ctr_cmac_circuit ===\n");

    printf("\n[NIST CAVS 14.4 known-answer vectors]\n");
    test_cavs_aes128();
    test_cavs_aes256();

    printf("\n[AND gate counts]\n");
    test_and_gate_counts();

    printf("\n[Software reference comparison]\n");
    test_software_reference();

    printf("\n  %d / %d passed\n", pass_count, test_count);
    return (pass_count == test_count) ? 0 : 1;
}
