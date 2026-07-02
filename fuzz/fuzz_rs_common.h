/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * fuzz_rs_common.h - shared fixed configuration for the composable
 * ring-signature fuzz harnesses (1.8.0 security review follow-up: fuzz
 * voleith_rs_sig_unpack and voleith_rs_verify against malformed input).
 *
 * Both harnesses (and the seed generator) must agree on the exact cfg,
 * params, ring contents and message so that a seed produced by the
 * generator verifies against the configuration the harness reconstructs.
 * The single source of truth is here: deterministic secret keys, a small
 * V1 membership-only ring (cheapest circuit = fastest fuzz iterations),
 * the AES-DM 16-byte node hash, and the em_128f parameter set.
 *
 * Everything is header-only / static so no extra translation unit is added
 * to the library; each harness gets its own copy.
 */

#ifndef VOLEITH_FUZZ_RS_COMMON_H
#define VOLEITH_FUZZ_RS_COMMON_H

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "node_hash_vt.h"
#include "rs_gf8.h"

/* Fixed ring geometry: 2 members at depth 1 keeps the superset circuit
 * (and therefore each verify) as small as possible. */
#define FUZZ_RS_DEPTH_M 1u
#define FUZZ_RS_N_MEMBERS 2u
#define FUZZ_RS_SK_BYTES 16u
#define FUZZ_RS_SIGNER 1u

/* The message bound via Fiat-Shamir; constant across generator and harness. */
#define FUZZ_RS_MESSAGE "voleith-fuzz-rs"
#define FUZZ_RS_MESSAGE_LEN (sizeof(FUZZ_RS_MESSAGE) - 1u)

/* Fill cfg with the fixed V1 membership-only configuration.  AES-DM is a
 * variable-leaf vt, so sk_bytes is unconstrained; node_bytes == 16. */
static inline void
fuzz_rs_make_cfg(voleith_rs_config_t *cfg)
{
    memset(cfg, 0, sizeof(*cfg));
    cfg->membership.tree_hash = &voleith_node_hash_aes_dm;
    cfg->membership.sk_bytes = FUZZ_RS_SK_BYTES;
    cfg->membership.depth_m = FUZZ_RS_DEPTH_M;
}

/* Deterministic secret-key material for the ring (identical in the
 * generator and the harness, so the rebuilt root matches the seed). */
static inline void
fuzz_rs_fill_sks(uint8_t *sks)
{
    for (size_t i = 0; i < FUZZ_RS_N_MEMBERS; i++)
        for (size_t j = 0; j < FUZZ_RS_SK_BYTES; j++)
            sks[i * FUZZ_RS_SK_BYTES + j] = (uint8_t)(i * 31u + j * 7u + 0x11u);
}

#endif /* VOLEITH_FUZZ_RS_COMMON_H */
