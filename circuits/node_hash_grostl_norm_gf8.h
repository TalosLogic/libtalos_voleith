/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * node_hash_grostl_norm_gf8.h - fixed-input Grostl node-hash vts, FAEST
 * paired-round norm S-box data path.
 *
 * Drop-in siblings of voleith_node_hash_grostl256_fixed /
 * _grostl512_fixed / _grostl256_fixed128 / _grostl512_fixed256: same
 * node output (same fixed-input Grostl compression, same IV constants,
 * same collision resistance), but each permutation round-pair commits
 * packed 4-bit subfield norms instead of one inverse byte per S-box.
 * Grostl has no key schedule, so the witness is a clean 0.75 of the
 * frozen one.  The construction bodies are shared verbatim with the
 * frozen vts through node_hash_grostl_gf8_internal.h.
 *
 * The four DEPRECATED Merkle-Damgard variants (grostl256 / _t27 / 512 /
 * _t59) have no norm twin.  The vt instances are declared in
 * node_hash_vt.h (the umbrella vt header).
 */

#ifndef VOLEITH_NODE_HASH_GROSTL_NORM_GF8_H
#define VOLEITH_NODE_HASH_GROSTL_NORM_GF8_H

#include "node_hash_vt.h"

#endif /* VOLEITH_NODE_HASH_GROSTL_NORM_GF8_H */
