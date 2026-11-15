/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * kdf_ctr_cmac_gf8_internal.h - shared KDF-Counter-Mode orchestration
 * (NIST SP 800-108r1-upd1 Section 4.1) over AES-CMAC.
 *
 * KDF-CTR is CTR-mode iteration over a CMAC PRF: the counter construction,
 * fixed-input layout, output truncation, and witness layout are identical
 * whether the inner CMAC uses the frozen 8-bit-inverse AES or the FAEST
 * paired-round norm AES.  Both translation units (kdf_ctr_cmac_gf8_circuit.c
 * and kdf_ctr_cmac_norm_gf8_circuit.c) drive the same skeletons here with a
 * `norm` flag, so the mode logic is a single source of truth and the frozen
 * and norm KDFs cannot drift.
 *
 * The flag selects the CMAC call (circuit, witness, and witness-size) at the
 * three sites where it matters; everything else is byte identical.  For
 * norm = 0 the skeletons emit exactly the gates the frozen circuit emitted
 * before this header existed, so the frozen circuit's output, fingerprint and
 * KATs are unchanged.
 */

#ifndef VOLEITH_KDF_CTR_CMAC_GF8_INTERNAL_H
#define VOLEITH_KDF_CTR_CMAC_GF8_INTERNAL_H

#include "../proof/gf8_circuit.h"
#include "aes_cmac_gf8_circuit.h"      /* frozen CMAC */
#include "aes_cmac_norm_gf8_circuit.h" /* norm CMAC */
#include "circuit.h"                   /* VOLEITH_STACK_BUF_MAX */
#include "../core/util.h"              /* voleith_secure_zero */
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

/*
 * Maximum per-iteration message size (in byte-wires) to place on the stack.
 * msg_bytes = 4 + fixed_input_bytes; each gf8_wire_id is sizeof(gf8_wire_id).
 */
#define KDF_GF8_MSG_MAX_BYTES (VOLEITH_STACK_BUF_MAX / sizeof(gf8_wire_id))

/* ================================================================
 * CMAC dispatch (the only variation points).
 * ================================================================ */

static inline void
kdf_cmac_circuit(voleith_gf8_circuit_t *c, const gf8_wire_id *key,
                 size_t key_bytes, const gf8_wire_id *msg, size_t msg_bytes,
                 gf8_wire_id tag[16], int norm)
{
    if (norm)
        aes_cmac_norm_gf8_circuit(c, key, key_bytes, msg, msg_bytes, tag);
    else
        aes_cmac_gf8_circuit(c, key, key_bytes, msg, msg_bytes, tag);
}

static inline size_t
kdf_cmac_witness_bytes(size_t key_bytes, size_t msg_bytes, int norm)
{
    return norm ? aes_cmac_norm_gf8_witness_bytes(key_bytes, msg_bytes)
                : aes_cmac_gf8_witness_bytes(key_bytes, msg_bytes);
}

static inline void
kdf_cmac_build_witness(const uint8_t *key, size_t key_bytes, const uint8_t *msg,
                       size_t msg_bytes, uint8_t *w, uint8_t tag[16], int norm)
{
    if (norm)
        aes_cmac_norm_gf8_build_witness(key, key_bytes, msg, msg_bytes, w, tag);
    else
        aes_cmac_gf8_build_witness(key, key_bytes, msg, msg_bytes, w, tag);
}

/* ================================================================
 * Circuit skeleton.  Returns 0, or -1 if (4 + fixed_input_bytes) exceeds the
 * stack-VLA bound (circuit left unchanged).
 * ================================================================ */

static inline int
kdf_circuit_skeleton(voleith_gf8_circuit_t *c, const gf8_wire_id *key,
                     size_t key_bytes, const gf8_wire_id *fixed_input,
                     size_t fixed_input_bytes, gf8_wire_id *output,
                     size_t output_bytes, int norm)
{
    size_t n = (output_bytes + 15) / 16; /* ceil(output_bytes / 16) */
    size_t msg_bytes = 4 + fixed_input_bytes;

    if (msg_bytes > KDF_GF8_MSG_MAX_BYTES)
        return -1;

    gf8_wire_id msg[msg_bytes]; /* VLA; bounded by KDF_GF8_MSG_MAX_BYTES */

    /* fixed_input portion is the same wires across all iterations. */
    for (size_t b = 0; b < fixed_input_bytes; b++)
        msg[4 + b] = fixed_input[b];

    for (size_t i = 1; i <= n; i++) {
        uint32_t ctr = (uint32_t)i;
        msg[0] = voleith_gf8_add_const(c, (uint8_t)((ctr >> 24) & 0xFF));
        msg[1] = voleith_gf8_add_const(c, (uint8_t)((ctr >> 16) & 0xFF));
        msg[2] = voleith_gf8_add_const(c, (uint8_t)((ctr >> 8) & 0xFF));
        msg[3] = voleith_gf8_add_const(c, (uint8_t)((ctr >> 0) & 0xFF));

        gf8_wire_id Ki[16];
        kdf_cmac_circuit(c, key, key_bytes, msg, msg_bytes, Ki, norm);

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
 * Witness skeleton.  Returns 0, or -1 on allocation failure.
 * ================================================================ */

static inline int
kdf_witness_skeleton(const uint8_t *key, size_t key_bytes,
                     const uint8_t *fixed_input, size_t fixed_input_bytes,
                     size_t output_bytes, uint8_t *witness_out,
                     uint8_t *output_out, int norm)
{
    /* Witness layout: [key_bytes key] [inv_in for all AES calls, in order]. */
    memcpy(witness_out, key, key_bytes);
    uint8_t *inv_ptr = witness_out + key_bytes;

    size_t n = (output_bytes + 15) / 16;
    size_t msg_bytes = 4 + fixed_input_bytes;

    size_t cmac_w_bytes = kdf_cmac_witness_bytes(key_bytes, msg_bytes, norm);
    size_t inv_per_cmac = cmac_w_bytes - key_bytes;

    uint8_t *cmac_w = malloc(cmac_w_bytes);
    uint8_t *msg = malloc(msg_bytes ? msg_bytes : 1);
    if (!cmac_w || !msg) {
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
        kdf_cmac_build_witness(key, key_bytes, msg, msg_bytes, cmac_w, tag,
                               norm);

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
        voleith_secure_zero(tag, sizeof(tag));
    }

    voleith_secure_zero(cmac_w, cmac_w_bytes);
    voleith_secure_zero(msg, msg_bytes ? msg_bytes : 1);
    free(msg);
    free(cmac_w);
    return 0;
}

#endif /* VOLEITH_KDF_CTR_CMAC_GF8_INTERNAL_H */
