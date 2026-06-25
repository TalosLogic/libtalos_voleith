/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * node_hash_vt.h - voleith_node_hash_vt: hash-agnostic node-hash
 * interface for GF(2^8) Merkle / IMT circuits.
 *
 * The vt is consumed during circuit *construction*.  Indirect calls
 * happen at build time only; the prover/verifier hot paths see just
 * the resulting gate stream and pay no run-time vt indirection cost.
 * See docs/HASH_AGNOSTIC_MERKLE_DESIGN.md for the framework and the
 * roadmap to extend it to AES-DM, AES-CMAC, and Grøstl vts.
 *
 * Vt instances exposed via this header:
 *   voleith_node_hash_hirose           - variable-leaf Hirose-AES-256 (32B, 2^128 CR)
 *   voleith_node_hash_hirose_fixed32   - fixed-32B-leaf Hirose-AES-256 (32B, 2^128 CR)
 *   voleith_node_hash_aes_dm           - AES-128 Davies-Meyer          (16B, 2^64  CR)
 *   voleith_node_hash_aes_cmac128      - AES-128-CMAC                  (16B, 2^64  CR)
 *   voleith_node_hash_grostl256        - Grøstl-256                    (32B, 2^128 CR)
 *   voleith_node_hash_grostl256_t27    - Grøstl-256 truncated to 27B   (27B, 2^108 CR)
 *   voleith_node_hash_grostl512        - Grøstl-512                    (64B, 2^256 CR)
 *   voleith_node_hash_grostl512_t59    - Grøstl-512 truncated to 59B   (59B, 2^236 CR)
 *
 * AES-256-CMAC is intentionally NOT wrapped (strictly dominated by
 * AES-128-CMAC: same 2^64 CR, ~1.4x the S-box cost).  Its existing
 * fixed-hash entry point in merkle_gf8_circuit.c continues to work
 * unchanged.  See docs/HASH_AGNOSTIC_MERKLE_DESIGN.md section 6.
 */

#ifndef VOLEITH_NODE_HASH_VT_H
#define VOLEITH_NODE_HASH_VT_H

#include "../proof/gf8_circuit.h"
#include <stdint.h>
#include <stddef.h>

/*
 * Maximum node_bytes the generic vt-driven Merkle / IMT circuit bodies
 * can carry.  The bodies size MERKLE_VT_MAX_NODE_BYTES-byte stack
 * arrays per level for `current`, `next`, and (secret-dir) `left` /
 * `right`; a vt with node_bytes > this would overflow the stack.
 *
 * Every vt declared below is checked at compile time via
 * _Static_assert in its definition .c file, and the merkle_vt entry
 * points re-check at runtime to defend against third-party vts.
 *
 * The current ceiling (64) accommodates Grøstl-512 nodes (the widest
 * in-tree vt).  Raise in lockstep with the stack-array sizes if a
 * wider hash family is added.
 */
#define MERKLE_VT_MAX_NODE_BYTES 64u

typedef struct {
    /* identity */
    const char *name;  /* human-readable, for tracing */
    size_t node_bytes; /* 16, 27, 32, 59, or 64 */
    size_t cr_bits;    /* 64, 108, 128, 236, or 256 */

    /*
     * Fixed-leaf input width.  0 means the vt is variable-leaf (any
     * leaf_data_bytes >= 0 is valid).  Non-zero means the vt's
     * leaf_circuit / leaf_hash require exactly this many input bytes;
     * any other value is a contract violation (currently silently
     * truncated by some vts, but consumers that validate up-front
     * should reject it instead of letting a wrong-width sk reach the
     * leaf builders).  Used by voleith_rs_membership_validate to enforce
     * the sk-width match.
     *
     * Only hirose-aes-256-fixed32 (= 32) is non-zero today; the other
     * shipped vts are variable-leaf and get 0 via C99 designated
     * initializers (unmentioned fields = 0).
     */
    size_t fixed_leaf_bytes;

    /* witness sizing */
    size_t (*leaf_invin_bytes)(size_t leaf_data_bytes);
    size_t (*inode_invin_bytes)(void);

    /* in-circuit */
    void (*leaf_circuit)(voleith_gf8_circuit_t *c, const gf8_wire_id *leaf_data,
                         size_t leaf_data_bytes,
                         gf8_wire_id *out_node); /* node_bytes wires */

    void (*inode_circuit)(voleith_gf8_circuit_t *c,
                          const gf8_wire_id *left,  /* node_bytes wires */
                          const gf8_wire_id *right, /* node_bytes wires */
                          gf8_wire_id *out_node);   /* node_bytes wires */

    /*
     * Witness builders (out-of-circuit inv_in computation) and software
     * helpers (test oracle / tree construction).  Return 0 on success,
     * -1 on internal allocation failure.  Some vts (variable-length
     * AES-CMAC leaf) need a transient heap buffer sized by leaf_data_bytes;
     * fixed-size vts always succeed but share the int signature for
     * uniformity.
     */
    int (*leaf_build_witness)(const uint8_t *leaf_data, size_t leaf_data_bytes,
                              uint8_t *inv_out); /* leaf_invin_bytes() */

    int (*inode_build_witness)(const uint8_t *left,  /* node_bytes */
                               const uint8_t *right, /* node_bytes */
                               uint8_t *inv_out);    /* inode_invin_bytes() */

    int (*leaf_hash)(const uint8_t *leaf_data, size_t leaf_data_bytes,
                     uint8_t *out); /* node_bytes */

    int (*inode_hash)(const uint8_t *left,  /* node_bytes */
                      const uint8_t *right, /* node_bytes */
                      uint8_t *out);        /* node_bytes */
} voleith_node_hash_vt;

/*
 * Hirose-AES-256 vts.  Both have node_bytes=32 and cr_bits=128, share
 * inode_circuit / inode_build_witness / inode_hash, and differ in the
 * leaf_*  fields (fixed-32 = no padding, 2-iter; variable = 10*
 * padding, n-iter).  Domain separation between the two vts is
 * realized via distinct c_leaf constants (see
 * circuits/node_hash_hirose_gf8.c).
 *
 * See docs/HIROSE_MERKLE_DESIGN.md for the construction and §5 of
 * docs/HASH_AGNOSTIC_MERKLE_DESIGN.md for the fixed-width vt rationale.
 */
extern const voleith_node_hash_vt voleith_node_hash_hirose;
extern const voleith_node_hash_vt voleith_node_hash_hirose_fixed32;

/*
 * AES-family vts.  Both have node_bytes=16 and cr_bits=64.
 *
 *   voleith_node_hash_aes_dm:
 *     leaf  - Merkle-Damgaard chain over AES-128 with CMAC-style 10*
 *             padding; IV = MERKLE_LEAF_DOMAIN.
 *     inode - H(L,R) = AES_L(R XOR C_inode) XOR (R XOR C_inode).
 *
 *   voleith_node_hash_aes_cmac128:
 *     leaf  - CMAC(K_leaf,  leaf_data),  K_leaf  = MERKLE_LEAF_DOMAIN.
 *     inode - CMAC(K_inode, L || R),     K_inode = MERKLE_INODE_DOMAIN.
 *
 * Domain separation between leaf and inode is realized differently
 * across the two vts (DM uses distinct IV vs distinct XOR constant
 * with an MD-vs-EMD shape; CMAC uses distinct fixed keys), and is
 * structurally identical to the existing fixed-hash entry points in
 * circuits/merkle_gf8_circuit.c.  See circuits/node_hash_aes_gf8.h.
 */
extern const voleith_node_hash_vt voleith_node_hash_aes_dm;
extern const voleith_node_hash_vt voleith_node_hash_aes_cmac128;

/*
 * Grøstl-family vts.  All four share the same RFC-6962 domain
 * separation (leaf = Grøstl(0x00 || data), inode = Grøstl(0x01 || L || R)
 * with the domain byte enforced as a constant wire).  They differ in
 * node_bytes (output truncation), underlying Grøstl variant (256 vs
 * 512), and consequent CR bound and inode S-box cost.  See
 * circuits/node_hash_grostl_gf8.h for the variant matrix and
 * docs/GROSTL_PRIMITIVE_DESIGN.md for the construction rationale.
 *
 *   grostl256        : 32B node, 2^128 CR, 3200 inode S-boxes (2 compressions)
 *   grostl256_t27    : 27B node, 2^108 CR, 1920 inode S-boxes (1 compression)
 *   grostl512        : 64B node, 2^256 CR, 8960 inode S-boxes (2 compressions)
 *   grostl512_t59    : 59B node, 2^236 CR, 5376 inode S-boxes (1 compression)
 *
 * DEPRECATED: all four are superseded by grostl256_fixed /
 * grostl512_fixed below (full CR at single-compression cost); retained
 * as frozen wire-format commitments, not recommended for new circuits.
 */
extern const voleith_node_hash_vt voleith_node_hash_grostl256;
extern const voleith_node_hash_vt voleith_node_hash_grostl256_t27;
extern const voleith_node_hash_vt voleith_node_hash_grostl512;
extern const voleith_node_hash_vt voleith_node_hash_grostl512_t59;

/*
 * Fixed-input single-compression Grøstl vts.  H = Omega(f(IV, block))
 * over exactly one block (no Merkle-Damgård padding), leaf vs inode
 * domain-separated by distinct chaining values IV_leaf / IV_inode
 * (NOT a 1-byte in-message prefix).  Fixed-leaf (fixed_leaf_bytes =
 * node_bytes): the leaf payload is zero-padded to the block.  See
 * circuits/node_hash_grostl_gf8.h and docs/DESIGN.md.
 *
 *   grostl256_fixed  : 32B node, 2^128 CR, 1920 inode S-boxes (1 compression)
 *   grostl512_fixed  : 64B node, 2^256 CR, 5376 inode S-boxes (1 compression)
 *
 * Both deliver full collision resistance at the same S-box cost as the
 * truncated _t27 / _t59 variants, dominating all four older Grøstl vts
 * above (which are retained as frozen wire-format commitments).
 */
extern const voleith_node_hash_vt voleith_node_hash_grostl256_fixed;
extern const voleith_node_hash_vt voleith_node_hash_grostl512_fixed;

#endif /* VOLEITH_NODE_HASH_VT_H */
