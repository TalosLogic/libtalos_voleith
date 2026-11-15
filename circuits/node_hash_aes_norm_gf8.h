/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * node_hash_aes_norm_gf8.h - AES-DM and AES-128-CMAC node-hash vts,
 * FAEST paired-round norm S-box data path.
 *
 * Drop-in siblings of voleith_node_hash_aes_dm / _aes_cmac128: same
 * node output (same MMO / CMAC construction, same domain constants,
 * same 2^64 collision resistance), but each inner AES call commits
 * packed 4-bit subfield norms, so the per-call inv_in is 160 bytes
 * instead of 200 (AES128_NORM_GF8_WITNESS_BYTES - 16; the AES key
 * schedule stays frozen 8-bit, so only the encryption S-boxes shrink).
 * The construction bodies are shared verbatim with the frozen vts
 * through node_hash_aes_gf8_internal.h.
 *
 * The vt instances themselves are declared in node_hash_vt.h (the
 * umbrella vt header); this file is the implementation-side anchor for
 * the AES-family norm vts.
 */

#ifndef VOLEITH_NODE_HASH_AES_NORM_GF8_H
#define VOLEITH_NODE_HASH_AES_NORM_GF8_H

#include "node_hash_vt.h"

#endif /* VOLEITH_NODE_HASH_AES_NORM_GF8_H */
