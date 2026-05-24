/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * kdf_ctr_cmac_circuit.c - KDF in Counter Mode using AES-CMAC as PRF
 *
 * NIST SP 800-108r1-upd1, Section 4.1.
 *
 * Per-iteration message (r = 32, counter before fixed input):
 *   K(i) = CMAC(K_IN, [i]_32 || fixed_input),  i = 1..n
 *   K_OUT = leftmost output_bits of K(1) || ... || K(n)
 *
 * Bit/byte encoding for [i]_32 (big-endian 32-bit integer):
 *   byte 0 = (i >> 24) & 0xFF  (most significant)
 *   byte 3 = (i >>  0) & 0xFF  (least significant)
 *   In our LSB-first-per-byte wire convention:
 *     wire[8*k + b] = ((i >> (24 - 8*k)) >> b) & 1
 *   for k = 0..3, b = 0..7.
 */

#include "kdf_ctr_cmac_circuit.h"
#include "aes_cmac_circuit.h"
#include <stdint.h>

/*
 * Maximum VLA stack allocation for the per-iteration message buffer.
 * msg_bits = 32 (counter) + fixed_input_bits; each wire_id is 4 bytes.
 * VOLEITH_STACK_BUF_MAX bytes / 4 = wire IDs → fixed_input_bits ≤ (limit - 32) bits.
 * Callers with larger fixed inputs must not use this function.
 */
#define KDF_MSG_MAX_BITS (VOLEITH_STACK_BUF_MAX / sizeof(wire_id))

/*
 * add_u32_const - emit 32 constant wires for a big-endian uint32_t.
 *
 * Wire layout: byte 0 (MSByte) in out[0..7], byte 3 (LSByte) in out[24..31].
 * Within each byte, bit 0 = LSB (out[8k]) .. bit 7 = MSB (out[8k+7]).
 */
static void
add_u32_const(voleith_circuit_t *c, uint32_t val, wire_id out[32])
{
    for (int k = 0; k < 4; k++) {
        uint8_t byte_val = (uint8_t)((val >> (24 - 8 * k)) & 0xFF);
        for (int b = 0; b < 8; b++)
            out[8 * k + b] = voleith_circuit_add_const(c, (byte_val >> b) & 1);
    }
}

void
kdf_ctr_cmac_circuit(voleith_circuit_t *c, const wire_id *key, size_t key_bits,
                     const wire_id *fixed_input, size_t fixed_input_bits,
                     wire_id *output, size_t output_bits)
{
    size_t n = (output_bits + 127) / 128; /* n = ceil(output_bits / 128) */

    /*
     * Message layout per iteration: [i]_32 || fixed_input
     *   Bits 0..31:                    counter [i]_32  (constant, varies per i)
     *   Bits 32..31+fixed_input_bits:  fixed_input     (caller-supplied wires)
     */
    size_t msg_bits = 32 + fixed_input_bits;
    if (msg_bits > KDF_MSG_MAX_BITS)
        return; /* guard against stack overflow */

    wire_id msg[msg_bits]; /* VLA; size bounded by KDF_MSG_MAX_BITS */

    /* Fill fixed_input portion once - constant across all iterations. */
    for (size_t b = 0; b < fixed_input_bits; b++)
        msg[32 + b] = fixed_input[b];

    for (size_t i = 1; i <= n; i++) {
        /* Fill [i]_32 counter portion. */
        wire_id ctr_wires[32];
        add_u32_const(c, (uint32_t)i, ctr_wires);
        for (int b = 0; b < 32; b++)
            msg[b] = ctr_wires[b];

        wire_id Ki[128];
        aes_cmac_circuit(c, key, key_bits, msg, msg_bits, Ki);

        /* Copy Ki bits to output, truncating the last block if needed. */
        size_t out_offset = (i - 1) * 128;
        size_t bits_to_copy = (out_offset + 128 <= output_bits)
                                  ? 128
                                  : (output_bits - out_offset);
        for (size_t b = 0; b < bits_to_copy; b++)
            output[out_offset + b] = Ki[b];
    }
}
