/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * test_kdf_ctr_cmac_gf8_circuit.c - Tests for the GF(2⁸) KDF-CTR-CMAC circuit
 *
 * Tests:
 *   1-4: NIST CAVS 14.4 known-answer vectors (SP 800-108 Counter Mode,
 *        CMAC_AES128 and CMAC_AES256, CTRLOCATION=BEFORE_FIXED, RLEN=32_BITS)
 *        - two vectors per key size (L=128 for n=1, L=256 for n=2)
 *   5-7: Witness counts
 *   8-9: Circuit output matches software reference (AES-128 and AES-256)
 */

#include "kdf_ctr_cmac_gf8_circuit.h"
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
 * Software KDF-CTR-CMAC reference
 * ================================================================ */

static void
kdf_ref(const uint8_t *key, int key_bits, const uint8_t *fixed_input,
        size_t fixed_input_bytes, uint8_t *output, size_t output_bytes)
{
    size_t n = (output_bytes + 15) / 16;
    size_t msg_bytes = 4 + fixed_input_bytes;

    uint8_t *msg = calloc(msg_bytes ? msg_bytes : 1, 1);
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
 * Key bytes are witness wires; fixed_input bytes are instance wires.
 * ================================================================ */

static void
eval_kdf_gf8_circuit(const uint8_t *key, size_t key_bytes,
                     const uint8_t *fixed_input, size_t fixed_input_bytes,
                     uint8_t *output, size_t output_bytes)
{
    voleith_gf8_circuit_t *c = voleith_gf8_circuit_new();
    if (!c) {
        memset(output, 0, output_bytes);
        return;
    }

    gf8_wire_id key_wires[32];
    for (size_t i = 0; i < key_bytes; i++)
        key_wires[i] = voleith_gf8_add_witness(c);

    gf8_wire_id *fi_wires = NULL;
    if (fixed_input_bytes > 0) {
        fi_wires = calloc(fixed_input_bytes, sizeof(gf8_wire_id));
        if (!fi_wires) {
            voleith_gf8_circuit_free(c);
            memset(output, 0, output_bytes);
            return;
        }
        for (size_t i = 0; i < fixed_input_bytes; i++)
            fi_wires[i] = voleith_gf8_add_instance(c);
    }

    gf8_wire_id *out_wires = calloc(output_bytes, sizeof(gf8_wire_id));
    if (!out_wires) {
        free(fi_wires);
        voleith_gf8_circuit_free(c);
        memset(output, 0, output_bytes);
        return;
    }

    kdf_ctr_cmac_gf8_circuit(c, key_wires, key_bytes, fi_wires,
                             fixed_input_bytes, out_wires, output_bytes);

    size_t n_wires = voleith_gf8_circuit_wire_count(c);
    uint8_t *vals = calloc(n_wires, 1);
    size_t w_bytes = kdf_ctr_cmac_gf8_witness_bytes(key_bytes, output_bytes,
                                                    fixed_input_bytes);
    uint8_t *witness = calloc(w_bytes, 1);
    if (!vals || !witness) {
        free(vals);
        free(witness);
        free(out_wires);
        free(fi_wires);
        voleith_gf8_circuit_free(c);
        memset(output, 0, output_bytes);
        return;
    }

    kdf_ctr_cmac_gf8_build_witness(key, key_bytes, fixed_input,
                                   fixed_input_bytes, output_bytes, witness,
                                   NULL);

    voleith_gf8_circuit_eval(c, witness,
                             fixed_input_bytes > 0 ? fixed_input : NULL, vals);

    for (size_t b = 0; b < output_bytes; b++)
        output[b] = vals[out_wires[b]];

    free(witness);
    free(vals);
    free(out_wires);
    free(fi_wires);
    voleith_gf8_circuit_free(c);
}

/* ================================================================
 * Tests 1-4: NIST CAVS 14.4 known-answer vectors
 * ================================================================ */

static void
test_cavs_aes128(void)
{
    /* COUNT=0, L=128 (n=1) */
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
        eval_kdf_gf8_circuit(KI, 16, FI, 60, result, 16);
        check("CAVS AES-128 GF8 L=128 (n=1)", memcmp(result, KO, 16) == 0);
    }

    /* COUNT=10, L=256 (n=2) */
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
        eval_kdf_gf8_circuit(KI, 16, FI, 60, result, 32);
        check("CAVS AES-128 GF8 L=256 (n=2)", memcmp(result, KO, 32) == 0);
    }
}

static void
test_cavs_aes256(void)
{
    /* COUNT=0, L=128 (n=1) */
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
        eval_kdf_gf8_circuit(KI, 32, FI, 60, result, 16);
        check("CAVS AES-256 GF8 L=128 (n=1)", memcmp(result, KO, 16) == 0);
    }

    /* COUNT=10, L=256 (n=2) */
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
        eval_kdf_gf8_circuit(KI, 32, FI, 60, result, 32);
        check("CAVS AES-256 GF8 L=256 (n=2)", memcmp(result, KO, 32) == 0);
    }
}

/* ================================================================
 * Tests 5-7: Witness counts
 *
 * witness_count = key_bytes + n_iterations × aes_calls_per_cmac × inv_per_call
 *
 * For AES-128 (inv_per_call=200):
 *   Case A: empty fixed_input, n=1 → msg=4B, n_aes=2, wits=16+1×2×200=416
 *   Case B: empty fixed_input, n=2 → msg=4B, n_aes=2, wits=16+2×2×200=816
 *   Case C: 28B fixed_input, n=1  → msg=32B, n_aes=3, wits=16+1×3×200=616
 * ================================================================ */

static void
test_witness_counts(void)
{
    /* Case A: empty fixed_input, output=16B (n=1): 16+2×200=416 */
    {
        voleith_gf8_circuit_t *c = voleith_gf8_circuit_new();
        gf8_wire_id key[16];
        for (int i = 0; i < 16; i++)
            key[i] = voleith_gf8_add_witness(c);
        gf8_wire_id out[16];
        kdf_ctr_cmac_gf8_circuit(c, key, 16, NULL, 0, out, 16);
        size_t got = voleith_gf8_circuit_witness_count(c);
        check("KDF GF8 witness count: empty fixed_input, n=1: 16+2×200=416",
              got == 416);
        voleith_gf8_circuit_free(c);
    }

    /* Case B: empty fixed_input, output=32B (n=2): 16+4×200=816 */
    {
        voleith_gf8_circuit_t *c = voleith_gf8_circuit_new();
        gf8_wire_id key[16];
        for (int i = 0; i < 16; i++)
            key[i] = voleith_gf8_add_witness(c);
        gf8_wire_id out[32];
        kdf_ctr_cmac_gf8_circuit(c, key, 16, NULL, 0, out, 32);
        size_t got = voleith_gf8_circuit_witness_count(c);
        check("KDF GF8 witness count: empty fixed_input, n=2: 16+4×200=816",
              got == 816);
        voleith_gf8_circuit_free(c);
    }

    /* Case C: 28B fixed_input, output=16B (n=1): msg=32B → n_aes=3, 16+3×200=616 */
    {
        voleith_gf8_circuit_t *c = voleith_gf8_circuit_new();
        gf8_wire_id key[16];
        for (int i = 0; i < 16; i++)
            key[i] = voleith_gf8_add_witness(c);
        gf8_wire_id fi[28];
        for (int i = 0; i < 28; i++)
            fi[i] = voleith_gf8_add_instance(c);
        gf8_wire_id out[16];
        kdf_ctr_cmac_gf8_circuit(c, key, 16, fi, 28, out, 16);
        size_t got = voleith_gf8_circuit_witness_count(c);
        check("KDF GF8 witness count: 28B fixed_input, n=1: 16+3×200=616",
              got == 616);
        voleith_gf8_circuit_free(c);
    }
}

/* ================================================================
 * CIR-2 regression: kdf_ctr_cmac_gf8_circuit signals -1 when
 * the per-iteration message length exceeds the internal stack-VLA
 * bound KDF_GF8_MSG_MAX_BYTES (= VOLEITH_STACK_BUF_MAX/sizeof(gf8_wire_id)
 * = 4096/4 = 1024 with the current settings).  Previously this case
 * silently returned without building any circuit, leaving the caller
 * unaware.
 * ================================================================ */

static void
test_cir2_stack_bound_signaled(void)
{
    /* fixed_input_bytes = 2048 → msg_bytes = 2052 > 1024 = bound. */
    const size_t HUGE_FI = 2048;
    voleith_gf8_circuit_t *c = voleith_gf8_circuit_new();
    gf8_wire_id key[16];
    for (int i = 0; i < 16; i++)
        key[i] = voleith_gf8_add_witness(c);
    /* fixed_input pointer is never dereferenced (the bound check
     * fires before the wire-copy loop), but provide a non-NULL one
     * for hygiene with the documented "may be NULL when bytes==0"
     * contract. */
    gf8_wire_id dummy_fi = voleith_gf8_add_instance(c);
    gf8_wire_id out[16];
    int rc = kdf_ctr_cmac_gf8_circuit(c, key, 16, &dummy_fi, HUGE_FI, out, 16);
    check("CIR-2: kdf_ctr_cmac_gf8_circuit returns -1 on stack-VLA "
          "bound violation",
          rc == -1);
    voleith_gf8_circuit_free(c);
}

/* ================================================================
 * Tests 8-9: Circuit matches software reference
 * ================================================================ */

static void
test_software_reference(void)
{
    /* AES-128, 8-byte fixed_input, 32-byte output (n=2) */
    {
        static const uint8_t key[16] = {0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae,
                                        0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88,
                                        0x09, 0xcf, 0x4f, 0x3c};
        static const uint8_t fi[8] = {0x00, 0x01, 0x02, 0x03,
                                      0x04, 0x05, 0x06, 0x07};
        uint8_t ref[32], result[32];
        kdf_ref(key, 128, fi, 8, ref, 32);
        eval_kdf_gf8_circuit(key, 16, fi, 8, result, 32);
        check("GF8 software reference: AES-128, 8B fixed_input, 32B output",
              memcmp(result, ref, 32) == 0);
    }

    /* AES-256, empty fixed_input, 16-byte output (n=1) */
    {
        static const uint8_t key[32] = {
            0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe, 0x2b, 0x73, 0xae,
            0xf0, 0x85, 0x7d, 0x77, 0x81, 0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61,
            0x08, 0xd7, 0x2d, 0x98, 0x10, 0xa3, 0x09, 0x14, 0xdf, 0xf4};
        uint8_t ref[16], result[16];
        kdf_ref(key, 256, NULL, 0, ref, 16);
        eval_kdf_gf8_circuit(key, 32, NULL, 0, result, 16);
        check("GF8 software reference: AES-256, empty fixed_input, 16B output",
              memcmp(result, ref, 16) == 0);
    }
}

int
main(void)
{
    printf("=== test_kdf_ctr_cmac_gf8_circuit ===\n");

    printf("\n[NIST CAVS 14.4 known-answer vectors]\n");
    test_cavs_aes128();
    test_cavs_aes256();

    printf("\n[Witness counts]\n");
    test_witness_counts();

    printf("\n[Software reference comparison]\n");
    test_software_reference();

    printf("\n[CIR-2 stack-VLA bound signaling]\n");
    test_cir2_stack_bound_signaled();

    printf("\n  %d / %d passed\n", pass_count, test_count);
    return (pass_count == test_count) ? 0 : 1;
}
