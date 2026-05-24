/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * kdf_ctr_cmac_gf8_circuit.c - KDF in Counter Mode using GF(2⁸) AES-CMAC as PRF
 *
 * NIST SP 800-108r1-upd1, Section 4.1.
 *
 * Per-iteration message (counter before fixed input, r = 32):
 *   K(i) = CMAC(K_IN, [i]_32 || fixed_input),  i = 1..n
 *   K_OUT = leftmost output_bytes of K(1) || ... || K(n)
 *
 * The 4-byte counter [i]_32be is represented as four constant byte-wires,
 * costing zero VOLE slots. All VOLE cost is inside aes_cmac_gf8_circuit.
 */

#include "kdf_ctr_cmac_gf8_circuit.h"
#include "circuit.h" /* VOLEITH_STACK_BUF_MAX */
#include "../core/util.h"
#include <string.h>
#include <stdlib.h>
#include <stdint.h>

/*
 * Maximum message size (in bytes, hence byte-wire count) to allocate on the
 * stack per iteration. msg_bytes = 4 + fixed_input_bytes; each gf8_wire_id
 * is sizeof(gf8_wire_id) bytes.
 */
#define KDF_GF8_MSG_MAX_BYTES (VOLEITH_STACK_BUF_MAX / sizeof(gf8_wire_id))

int
kdf_ctr_cmac_gf8_circuit(voleith_gf8_circuit_t *c, const gf8_wire_id *key,
                         size_t key_bytes, const gf8_wire_id *fixed_input,
                         size_t fixed_input_bytes, gf8_wire_id *output,
                         size_t output_bytes)
{
    size_t n = (output_bytes + 15) / 16; /* ceil(output_bytes / 16) */
    size_t msg_bytes = 4 + fixed_input_bytes;

    /* CIR-2: stack-VLA bound check.  Returning -1 (instead of the
     * previous silent no-op) lets the caller distinguish a built
     * circuit from a skipped one. */
    if (msg_bytes > KDF_GF8_MSG_MAX_BYTES)
        return -1;

    gf8_wire_id msg[msg_bytes]; /* VLA; size bounded by KDF_GF8_MSG_MAX_BYTES */

    /* Fill the fixed_input portion once - same wires across all iterations. */
    for (size_t b = 0; b < fixed_input_bytes; b++)
        msg[4 + b] = fixed_input[b];

    for (size_t i = 1; i <= n; i++) {
        /* Emit four constant byte-wires for [i]_32be counter. */
        uint32_t ctr = (uint32_t)i;
        msg[0] = voleith_gf8_add_const(c, (uint8_t)((ctr >> 24) & 0xFF));
        msg[1] = voleith_gf8_add_const(c, (uint8_t)((ctr >> 16) & 0xFF));
        msg[2] = voleith_gf8_add_const(c, (uint8_t)((ctr >> 8) & 0xFF));
        msg[3] = voleith_gf8_add_const(c, (uint8_t)((ctr >> 0) & 0xFF));

        gf8_wire_id Ki[16];
        aes_cmac_gf8_circuit(c, key, key_bytes, msg, msg_bytes, Ki);

        /* Copy Ki bytes to output, truncating the last block if needed. */
        size_t out_offset = (i - 1) * 16;
        size_t bytes_to_copy = (out_offset + 16 <= output_bytes)
                                   ? 16
                                   : (output_bytes - out_offset);
        for (size_t b = 0; b < bytes_to_copy; b++)
            output[out_offset + b] = Ki[b];
    }
    return 0;
}

/* ================================================================
 * Witness builder
 * ================================================================ */

int
kdf_ctr_cmac_gf8_build_witness(const uint8_t *key, size_t key_bytes,
                               const uint8_t *fixed_input,
                               size_t fixed_input_bytes, size_t output_bytes,
                               uint8_t *witness_out, uint8_t *output_out)
{
    /* Witness layout: [key_bytes key] [inv_in for all AES calls, in order]. */
    memcpy(witness_out, key, key_bytes);
    uint8_t *inv_ptr = witness_out + key_bytes;

    size_t n = (output_bytes + 15) / 16;
    size_t msg_bytes = 4 + fixed_input_bytes;

    /* Per-CMAC-call witness size (key portion will be skipped). */
    size_t cmac_w_bytes = aes_cmac_gf8_witness_bytes(key_bytes, msg_bytes);
    size_t inv_per_cmac = cmac_w_bytes - key_bytes;

    uint8_t *cmac_w = malloc(cmac_w_bytes);
    uint8_t *msg = malloc(msg_bytes ? msg_bytes : 1);
    if (!cmac_w || !msg) {
        /* CIR-2: signal allocation failure to the caller instead of
         * silently leaving witness_out / output_out in an
         * inconsistent state. */
        free(cmac_w);
        free(msg);
        return -1;
    }

    if (fixed_input_bytes > 0 && fixed_input)
        memcpy(msg + 4, fixed_input, fixed_input_bytes);

    for (size_t i = 1; i <= n; i++) {
        msg[0] = (uint8_t)((i >> 24) & 0xFF);
        msg[1] = (uint8_t)((i >> 16) & 0xFF);
        msg[2] = (uint8_t)((i >> 8) & 0xFF);
        msg[3] = (uint8_t)((i >> 0) & 0xFF);

        uint8_t tag[16];
        aes_cmac_gf8_build_witness(key, key_bytes, msg, msg_bytes, cmac_w, tag);

        /* Extract only the inv_in portion (skip the key prefix). */
        memcpy(inv_ptr, cmac_w + key_bytes, inv_per_cmac);
        inv_ptr += inv_per_cmac;

        if (output_out) {
            size_t out_offset = (i - 1) * 16;
            size_t bytes_to_copy = (out_offset + 16 <= output_bytes)
                                       ? 16
                                       : (output_bytes - out_offset);
            memcpy(output_out + out_offset, tag, bytes_to_copy);
        }
        /* Clear the per-iteration tag (a CMAC output, intermediate
         * keystream block under the master key). */
        voleith_secure_zero(tag, sizeof(tag));
    }

    /*
     * CIR-5: cmac_w holds the per-CMAC-call witness, including all AES
     * S-box inversion intermediates derived from the master key.  Each
     * iteration overwrites it; zero the final state before freeing.
     * msg holds the counter+fixed_input - fixed_input may be sensitive
     * depending on caller, counter is public, so zero for safety.
     */
    voleith_secure_zero(cmac_w, cmac_w_bytes);
    voleith_secure_zero(msg, msg_bytes ? msg_bytes : 1);
    free(msg);
    free(cmac_w);
    return 0;
}
