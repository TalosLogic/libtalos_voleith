/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * hirose.h - Hirose double-block-length compression function over
 * AES-256 (Hirose, FSE 2006).
 *
 * Implements one iteration of the compression `f` only.  The
 * Merkle-layer constructions (leaf hash, inode hash, the variable-leaf
 * `10*` padding rule, and the domain-separation constants
 * HIROSE_IV_LEAF / HIROSE_C_LEAF_* / HIROSE_C_INODE) live in
 * `circuits/node_hash_hirose_gf8.c` alongside the vt.  This keeps
 * `core/` free of application-specific framing and prevents the
 * primitive from being accidentally used as a general-purpose hash.
 *
 * The primitive is intentionally written as the naive two-encrypt
 * form (one key schedule + two AES-256 encrypts per iteration), with
 * no key-schedule sharing.  Sharing is a gate-count optimization in
 * the circuit version; in software it would only complicate the
 * primitive without changing output.  Computing both encryptions
 * through `voleith_aes_encrypt` lets this routine serve as an
 * independent oracle for the circuit's KS-shared form: any divergence
 * in circuit output points to a circuit bug, not a primitive bug.
 *
 * See docs/HIROSE_MERKLE_DESIGN.md for the construction, and
 * docs/HASH_AGNOSTIC_MERKLE_DESIGN.md §3.2 for the role in the
 * 1.2.0 hash-agnostic Merkle framework.
 */

#ifndef VOLEITH_HIROSE_H
#define VOLEITH_HIROSE_H

#include <stdint.h>
#include <stddef.h>

/*
 * voleith_hirose_iteration - one Hirose compression iteration `f`.
 *
 * Given a 256-bit chaining value (G, H), a 128-bit message block M,
 * and a 128-bit nonzero tweak constant `c`, computes:
 *
 *     K       = H || M                    (256-bit AES-256 key)
 *     G_out   = AES_K(G)        XOR G
 *     H_out   = AES_K(G XOR c)  XOR G XOR c
 *
 * The same key K is used for both encryptions (Hirose's defining
 * property).  `c` MUST be nonzero - a zero `c` collapses the two
 * encryptions to the same call and breaks the construction's
 * collision-resistance bound.
 *
 * G, H, M, c_const: 16-byte input blocks.
 * G_out, H_out:     16-byte output blocks (may alias any input).
 *
 * Constant-time with respect to all four inputs (provided the AES
 * backend is constant-time: AES-NI, ARMv8 Crypto, or bitsliced).
 */
void voleith_hirose_iteration(const uint8_t G[16], const uint8_t H[16],
                              const uint8_t M[16], const uint8_t c_const[16],
                              uint8_t G_out[16], uint8_t H_out[16]);

#endif /* VOLEITH_HIROSE_H */
