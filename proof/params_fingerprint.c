/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * params_fingerprint.c - Compute the 16-byte SHAKE-128 params fingerprint.
 *
 * See params_fingerprint.h for the canonical serialization spec.
 */

#include "params_fingerprint.h"

#include "../core/hash.h"
#include "../core/util.h"
#include "proof_header.h" /* voleith_fs_kind_t, voleith_bavc_kind_t */

#include <string.h>

int
voleith_params_fingerprint(const voleith_params_t *params,
                           uint8_t out[VOLEITH_PARAMS_FINGERPRINT_BYTES])
{
    voleith_hash_ctx_t ctx;
    static const uint8_t domain_tag[] =
        VOLEITH_PARAMS_FINGERPRINT_DOMAIN_TAG "\x00";
    static const uint8_t zero_padding[6] = {0};
    uint8_t fs_bavc[2];

    if (params == NULL || out == NULL)
        return -1;

    voleith_shake128_init(&ctx);

    /* Subtract 1 to drop the compiler's implicit '\0' terminator on
     * the string literal; only the explicit 0x00 we glued on belongs
     * in the absorbed bytes. */
    voleith_shake128_absorb(&ctx, domain_tag, sizeof(domain_tag) - 1);

    voleith_shake128_absorb_u32_le(&ctx, (uint32_t)params->lambda);
    voleith_shake128_absorb_u32_le(&ctx, (uint32_t)params->tau);
    voleith_shake128_absorb_u32_le(&ctx, (uint32_t)params->w_grind);
    voleith_shake128_absorb_u32_le(&ctx, (uint32_t)params->n_leafcom);
    voleith_shake128_absorb_u32_le(&ctx, (uint32_t)params->T_open);

    fs_bavc[0] = (uint8_t)params->fs_kind;
    fs_bavc[1] = (uint8_t)params->bavc_kind;
    voleith_shake128_absorb(&ctx, fs_bavc, sizeof(fs_bavc));

    voleith_shake128_absorb(&ctx, zero_padding, sizeof(zero_padding));

    voleith_shake128_squeeze(&ctx, out, VOLEITH_PARAMS_FINGERPRINT_BYTES);
    voleith_hash_ctx_clear(&ctx);

    return 0;
}
