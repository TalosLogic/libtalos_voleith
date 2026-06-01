/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * hirose.c - Hirose double-block-length compression over AES-256.
 *
 * Naive two-encrypt implementation that delegates to voleith_aes_*.
 * See hirose.h for design notes on why the primitive does not share
 * the AES key schedule across the two encryptions (it serves as an
 * independent oracle for the circuit version's KS-shared form).
 */

#include "hirose.h"
#include "aes.h"
#include "util.h"
#include <string.h>

static void
xor16(uint8_t out[16], const uint8_t a[16], const uint8_t b[16])
{
    for (int i = 0; i < 16; i++)
        out[i] = a[i] ^ b[i];
}

void
voleith_hirose_iteration(const uint8_t G[16], const uint8_t H[16],
                         const uint8_t M[16], const uint8_t c_const[16],
                         uint8_t G_out[16], uint8_t H_out[16])
{
    uint8_t key[32];
    uint8_t G_buf[16];
    uint8_t Gxc[16];
    uint8_t ct_G[16];
    uint8_t ct_Gxc[16];
    uint8_t Gn[16];
    uint8_t Hn[16];
    voleith_aes_ctx_t ctx;

    /* Snapshot G so the in-place case (G_out == G) is safe. */
    memcpy(G_buf, G, 16);

    /* K = H || M. */
    memcpy(key, H, 16);
    memcpy(key + 16, M, 16);

    voleith_aes_key_expand(&ctx, key, 256);

    /* G_next = AES_K(G) XOR G. */
    voleith_aes_encrypt(&ctx, ct_G, G_buf);
    xor16(Gn, ct_G, G_buf);

    /* H_next = AES_K(G XOR c) XOR (G XOR c). */
    xor16(Gxc, G_buf, c_const);
    voleith_aes_encrypt(&ctx, ct_Gxc, Gxc);
    xor16(Hn, ct_Gxc, Gxc);

    memcpy(G_out, Gn, 16);
    memcpy(H_out, Hn, 16);

    /* CIR-11: clear the AES context and all locals that contain
     * intermediate AES output / message-derived state. */
    voleith_aes_ctx_clear(&ctx);
    voleith_secure_zero(key, sizeof(key));
    voleith_secure_zero(G_buf, sizeof(G_buf));
    voleith_secure_zero(Gxc, sizeof(Gxc));
    voleith_secure_zero(ct_G, sizeof(ct_G));
    voleith_secure_zero(ct_Gxc, sizeof(ct_Gxc));
    voleith_secure_zero(Gn, sizeof(Gn));
    voleith_secure_zero(Hn, sizeof(Hn));
}
