/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * rs_membership_gf8.h - reusable ring-signature membership core
 * (data layer).
 *
 * The voleith_rs_membership_* surface defines the anonymity baseline
 * shared by every ring-signature variant whose membership proof is the
 * same secret-dir Merkle (and, optionally, indexed-Merkle non-revocation)
 * path: V1 (membership + revocation), V2 (linkable), V4 (claimable),
 * V5 (traceable), and V7 (threshold).  V3 (attribute-predicate) changes
 * the leaf shape and V6 (forward-secure) uses a different tree primitive,
 * so they extend rather than reuse this layer.
 *
 * This header holds only the membership cfg, layout, path struct,
 * validator, canonical-encoding absorber, and witness packer.  It pulls
 * in no fs_seed / serialization machinery, so V2/V3/V4 can build on the
 * core without depending on V1's signature wrappers.  Those V1 wrappers
 * (voleith_rsv1_*, voleith_ring_sig_*) live in proof/ring_sig_v1_gf8.h,
 * which re-includes this header.  The circuit builder
 * (voleith_rs_membership_build_circuit) lives in
 * circuits/rs_membership_gf8_circuit.h.
 *
 * See docs/RSV1_DESIGN.md §3 for the membership protocol and
 * docs/RING_SIGNATURE_DESIGN.md for the V1-V7 variant matrix.
 */

#ifndef VOLEITH_RS_MEMBERSHIP_GF8_H
#define VOLEITH_RS_MEMBERSHIP_GF8_H

#include "../circuits/node_hash_vt.h"
#include "../core/hash.h" /* voleith_hash_ctx_t for the canonical absorber */

#include <stddef.h>
#include <stdint.h>

/*
 * Membership / revocation Merkle depth ceiling.  A ring of depth d
 * holds up to 2^d members; 64 is far past any practical ring (>= 2^64
 * members would exhaust pointer arithmetic before it exhausted the
 * proof system) yet leaves headroom over the depth of any IMT a real
 * deployment would use.  The ceiling exists to give validate a defined
 * upper bound; tighten it if a future consumer needs a stricter cap.
 */
#define VOLEITH_RS_MEMBERSHIP_MAX_DEPTH 64u

/*
 * voleith_rs_membership_config_t - parameters that fix a ring's
 * membership identity.
 *
 * The V1 cfg-fingerprint and any future Vx cfg-fingerprint binds these
 * fields (plus that variant's own fields) into the signature's
 * fs_seed.  Two callers that disagree on any of these fields fail to
 * verify each other's signatures by design.
 *
 * Fields match docs/RSV1_DESIGN.md §3 (V1 uses these directly; V2+
 * embed this struct).
 *
 *   tree_hash  - Node hash for the Merkle path (membership tree and,
 *                when enabled, revocation tree).
 *
 *   owf_hash   - OWF for sk -> leaf node.  NULL = same vt as tree_hash
 *                (the common case).  When non-NULL, must have the same
 *                node_bytes as tree_hash, and cr_bits >= tree_hash's
 *                cr_bits (strength relationship; OWF would be the weak
 *                link otherwise).
 *
 *   sk_bytes   - sk byte length.  Variable-leaf vts accept any
 *                sk_bytes >= 1.  Fixed-leaf vts require sk_bytes ==
 *                vt->fixed_leaf_bytes.
 *
 *   depth_m    - Membership tree depth (log2 of ring capacity).  Must
 *                satisfy 1 <= depth_m <= VOLEITH_RS_MEMBERSHIP_MAX_DEPTH.
 *
 *   depth_r    - Revocation tree depth.  0 disables revocation
 *                entirely; otherwise must satisfy depth_r <=
 *                VOLEITH_RS_MEMBERSHIP_MAX_DEPTH.
 */
typedef struct {
    const voleith_node_hash_vt *tree_hash;
    const voleith_node_hash_vt *owf_hash;
    size_t sk_bytes;
    size_t depth_m;
    size_t depth_r;
} voleith_rs_membership_config_t;

/*
 * voleith_rs_membership_validate - reject malformed configs.
 *
 * Checks (all conditions must hold; first failure returns -1):
 *
 *   cfg != NULL
 *   cfg->tree_hash != NULL
 *   1 <= cfg->depth_m <= VOLEITH_RS_MEMBERSHIP_MAX_DEPTH
 *        cfg->depth_r <= VOLEITH_RS_MEMBERSHIP_MAX_DEPTH (depth_r == 0 ok)
 *   cfg->sk_bytes >= 1
 *
 *   When cfg->owf_hash != NULL:
 *     owf_hash->node_bytes == tree_hash->node_bytes
 *       (OWF output IS the Merkle leaf node)
 *     owf_hash->cr_bits   >= tree_hash->cr_bits
 *       (OWF must not be the system's weak link)
 *
 *   The effective owf_vt = cfg->owf_hash ? cfg->owf_hash : cfg->tree_hash.
 *   If owf_vt->fixed_leaf_bytes != 0, require sk_bytes ==
 *   owf_vt->fixed_leaf_bytes.  Variable-leaf vts (fixed_leaf_bytes == 0)
 *   accept any sk_bytes >= 1.
 *
 * Returns 0 if every check passes, -1 otherwise.  Does not allocate.
 */
int voleith_rs_membership_validate(const voleith_rs_membership_config_t *cfg);

/*
 * voleith_rs_membership_validate_structural - the membership checks that
 * are independent of the leaf-preimage width: cfg / tree_hash non-NULL,
 * depth_m in [1, MAX_DEPTH], depth_r <= MAX_DEPTH, sk_bytes >= 1, and
 * (when owf_hash is set) the owf/tree node_bytes match and owf cr_bits
 * is not weaker.
 *
 * Excludes the fixed-leaf "sk_bytes == fixed_leaf_bytes" check.
 * voleith_rs_membership_validate is exactly this plus that check.  The
 * composable validator (voleith_rs_config_validate) calls this directly
 * so it can apply its own leaf-width rule (sk + attribute bytes against
 * the OWF's single-compression capacity leaf_block_bytes) without the
 * V1 leaf = OWF(sk) assumption.
 *
 * Returns 0 if every check passes, -1 otherwise.  Does not allocate.
 */
int voleith_rs_membership_validate_structural(
    const voleith_rs_membership_config_t *cfg);

/*
 * voleith_rs_membership_absorb_canonical - absorb the membership cfg
 * into a SHAKE context in canonical order.  No init, no squeeze.
 *
 * Canonical encoding (absorbed in order, identical across V1 / V2 / V4
 * / V5 / V7):
 *
 *   u32_le owf_name_len
 *   owf_name_bytes                       (no null terminator)
 *   u32_le tree_name_len
 *   tree_name_bytes                      (no null terminator)
 *   u64_le sk_bytes
 *   u64_le depth_m
 *   u64_le depth_r
 *
 * Uses vt->name (NOT pointer identity) so the encoding is portable
 * across processes / library builds.  Length-prefixing each name keeps
 * the encoding injective (no ambiguity between adjacent names of
 * unequal lengths).
 *
 * Per-variant fingerprint functions (voleith_rsv1_config_fingerprint
 * and future voleith_rsv2_config_fingerprint etc.) call this between
 * their own domain-tag absorb and the final squeeze, so every Vx's
 * fingerprint shares one source of truth for the membership encoding.
 *
 * cfg->tree_hash, the effective owf vt, and both names must be
 * non-NULL.  Caller is responsible for that precondition (validate
 * first if unsure).
 */
void voleith_rs_membership_absorb_canonical(
    voleith_hash_ctx_t *ctx, const voleith_rs_membership_config_t *cfg);

/*
 * Byte width of the IMT next_index field used by the revocation branch.
 *
 * Fixed at 8 bytes so the on-the-wire layout is deterministic in (cfg,
 * vt) and does not require callers to compute a per-depth_r index width.
 * 8 bytes accommodates the depth_r ceiling of VOLEITH_RS_MEMBERSHIP_MAX_DEPTH
 * (= 64) leaves without truncation; smaller revocation trees still
 * encode next_index in 8 bytes with the upper bytes zero-padded.
 */
#define VOLEITH_RSV1_REV_INDEX_BYTES 8u

/*
 * voleith_rs_membership_layout_t - witness / instance byte-layout
 * descriptor.
 *
 * Populated by voleith_rs_membership_build_circuit
 * (circuits/rs_membership_gf8_circuit.h) and consumed by
 * voleith_rs_membership_pack_witness and the per-variant signature
 * layers.  Byte offsets are into the flat witness / instance buffers
 * in wire-declaration order; both the builder and the packer commit to
 * the same order, never hand-derive offsets on the side.
 *
 * Sections appear in this order:
 *   witness:  sk | dirs | siblings | owf inv_in | per-level inode inv_in
 *             (depth_m levels, each path_invin_per_level bytes)
 *             [iff depth_r > 0]
 *             | rev_low_value | rev_low_next | rev_next_index
 *             | rev_dirs | rev_siblings
 *             | rev leaf inv_in | per-level rev inode inv_in (depth_r levels)
 *   instance: membership_root [iff depth_r > 0: rev_root]
 *
 * Siblings are witness, not instance: the secret-dir Merkle path hides
 * the leaf *index*, and the sibling node values would identify which
 * leaf signed (each member's path has different siblings) - ring
 * anonymity requires hiding them.  Only the membership root (and, when
 * revocation is enabled, the revocation root) is public.
 *
 * The revocation adjacent-leaf record (low_value, low_next, next_index)
 * is also witness, not instance: each signer's adjacent record depends
 * on where their leaf sits in the sorted revocation set, so publishing
 * it would leak signer identity.
 *
 * Rev offsets are 0 and rev byte counts are 0 when cfg->depth_r == 0;
 * inst_rev_root_off / inst_rev_root_bytes are likewise zero in that
 * case.  The witness_bytes and instance_bytes totals include the
 * revocation slots when present.
 */
typedef struct {
    /* ----- witness layout ------------------------------------------ */
    size_t sk_off;
    size_t sk_bytes;

    size_t dirs_off;
    size_t dirs_bytes; /* = depth_m */

    size_t siblings_off;
    size_t siblings_bytes; /* = depth_m * node_bytes */

    size_t owf_invin_off;
    size_t owf_invin_bytes;

    size_t path_invin_off;
    size_t path_invin_per_level; /* = tree_hash->inode_invin_bytes() */
    size_t path_invin_bytes;     /* = depth_m * path_invin_per_level */

    /* ----- revocation witness slots (cfg->depth_r > 0) ------------- */
    size_t rev_low_value_off;
    size_t rev_low_value_bytes; /* = node_bytes */
    size_t rev_low_next_off;
    size_t rev_low_next_bytes; /* = node_bytes */
    size_t rev_next_index_off;
    size_t rev_next_index_bytes; /* = VOLEITH_RSV1_REV_INDEX_BYTES */

    size_t rev_dirs_off;
    size_t rev_dirs_bytes; /* = depth_r */

    size_t rev_siblings_off;
    size_t rev_siblings_bytes; /* = depth_r * node_bytes */

    size_t rev_leaf_invin_off;
    size_t rev_leaf_invin_bytes; /* = tree_hash->leaf_invin_bytes(
                                  *     2 * node_bytes + rev_index_bytes) */

    size_t rev_path_invin_off;
    size_t rev_path_invin_per_level; /* = tree_hash->inode_invin_bytes() */
    size_t rev_path_invin_bytes;     /* = depth_r * rev_path_invin_per_level */

    size_t witness_bytes; /* total witness byte count */

    /* ----- instance layout ----------------------------------------- */
    size_t inst_root_off;
    size_t inst_root_bytes; /* = node_bytes */

    size_t inst_rev_root_off;   /* valid iff depth_r > 0 */
    size_t inst_rev_root_bytes; /* = node_bytes when depth_r > 0; else 0 */

    size_t instance_bytes; /* total instance byte count */

    /* ----- sizing meta (mirrors cfg, captured for convenience) ----- */
    size_t depth_m;
    size_t depth_r;
    size_t node_bytes;      /* = tree_hash->node_bytes */
    size_t rev_index_bytes; /* = VOLEITH_RSV1_REV_INDEX_BYTES iff depth_r > 0 */
} voleith_rs_membership_layout_t;

/*
 * voleith_rs_membership_path_t - signer-side path bundle.
 *
 * Wraps the data voleith_rs_membership_pack_witness needs to assemble
 * one of the witness sections (membership or revocation) for a specific
 * signer.  Owned by the caller; the packer reads through pointers and
 * does not retain them.
 *
 * Per the V1 sign/verify signature, an instance of this struct is
 * passed in one of two roles:
 *
 *   "membership" role - leaf_index / siblings used; rev_* ignored.
 *     leaf_index: signer's position in the ring (range 0..2^depth_m - 1).
 *                 Per-level direction bits are derived as
 *                 path_dirs[k] = bit k of leaf_index (LSB first).
 *     siblings:   depth_m * tree_hash->node_bytes bytes, leaf-level
 *                 first.  voleith_merkle_vt_compute_path emits this.
 *
 *   "revocation" role (cfg->depth_r > 0) - rev_* fields used;
 *   leaf_index / siblings ignored.
 *     rev_adj_leaf_index: index of the adjacent IMT record (the one
 *                         whose value < signer_leaf_node < next_value).
 *                         Returned by voleith_imt_vt_lookup_nonmember.
 *     rev_siblings:       depth_r * tree_hash->node_bytes bytes, the
 *                         adjacent record's Merkle sibling path
 *                         (leaf-level first).
 *     rev_low_value:      node_bytes bytes: the adjacent record's value
 *                         field.
 *     rev_low_next:       node_bytes bytes: the adjacent record's
 *                         next_value field.
 *     rev_next_index:     VOLEITH_RSV1_REV_INDEX_BYTES bytes: the
 *                         adjacent record's next_index field, included
 *                         verbatim in the IMT leaf hash.
 *
 * The two-role design is intentional: V2+ may want to thread the same
 * structural concept (a Merkle/IMT path) through more callsites, and
 * keeping one type per Merkle-shape avoids a struct-zoo without forcing
 * an in-circuit union.  Callers who find this confusing can declare
 * dedicated locals (one for membership, one for revocation) and zero
 * the unused fields per role.
 */
typedef struct {
    /* Membership role. */
    size_t leaf_index;
    const uint8_t *siblings;

    /* Revocation role (cfg->depth_r > 0). */
    size_t rev_adj_leaf_index;
    const uint8_t *rev_siblings;
    const uint8_t *rev_low_value;
    const uint8_t *rev_low_next;
    const uint8_t *rev_next_index;
} voleith_rs_membership_path_t;

/*
 * voleith_rs_membership_pack_witness - assemble the membership (and,
 * iff cfg->depth_r > 0, revocation) witness byte buffer.
 *
 * Writes layout->witness_bytes bytes into witness_out in the wire
 * declaration order documented in
 * circuits/rs_membership_gf8_circuit.h:
 *
 *   1. sk (sk_bytes) at layout->sk_off
 *   2. dirs (depth_m bytes; bit k of membership->leaf_index, LSB first)
 *      at layout->dirs_off
 *   3. siblings (depth_m * node_bytes; leaf-level first) at
 *      layout->siblings_off
 *   4. owf inv_in (owf_vt->leaf_build_witness(sk)) at
 *      layout->owf_invin_off
 *   5. per-level inode inv_in (tree_vt->inode_build_witness(L, R) per
 *      level) at layout->path_invin_off + k * path_invin_per_level
 *
 * When cfg->depth_r > 0, the revocation parameter must be non-NULL and
 * the packer additionally writes:
 *
 *   6. rev_low_value, rev_low_next, rev_next_index (the adjacent IMT
 *      record) at rev_low_value_off / rev_low_next_off /
 *      rev_next_index_off
 *   7. rev_dirs (depth_r bytes; bit k of revocation->rev_adj_leaf_index)
 *      at layout->rev_dirs_off
 *   8. rev_siblings (depth_r * node_bytes) at layout->rev_siblings_off
 *   9. revocation leaf inv_in
 *      (tree_vt->leaf_build_witness(low_value || low_next || next_index))
 *      at layout->rev_leaf_invin_off
 *  10. per-level revocation inode inv_in at
 *      layout->rev_path_invin_off + k * rev_path_invin_per_level
 *
 * Caller is responsible for: providing a witness_out buffer of at
 * least layout->witness_bytes bytes; providing membership->siblings of
 * at least depth_m * tree_hash->node_bytes bytes; when cfg->depth_r >
 * 0, providing revocation->rev_siblings (depth_r * node_bytes) and the
 * three adjacent-record byte buffers (rev_low_value / rev_low_next of
 * node_bytes each, rev_next_index of VOLEITH_RSV1_REV_INDEX_BYTES).
 *
 * Returns 0 on success.  Returns -1 if any required pointer arg is
 * NULL, if membership->leaf_index >= 2^depth_m, if
 * revocation->rev_adj_leaf_index >= 2^depth_r (when depth_r > 0), if
 * revocation is NULL when depth_r > 0, if cfg fails
 * voleith_rs_membership_validate, or if any vt builder signals
 * internal failure (leaf_build_witness, inode_build_witness, leaf_hash,
 * inode_hash all return -1 on allocation failure on some vts).  On
 * failure witness_out is left in an unspecified state.
 *
 * Deterministic: given the same (cfg, layout, sk, membership, revocation),
 * the output is byte-identical across calls and across builds.
 */
int voleith_rs_membership_pack_witness(
    const voleith_rs_membership_config_t *cfg,
    const voleith_rs_membership_layout_t *layout, const uint8_t *sk,
    const voleith_rs_membership_path_t *membership,
    const voleith_rs_membership_path_t *revocation, uint8_t *witness_out);

#endif /* VOLEITH_RS_MEMBERSHIP_GF8_H */
