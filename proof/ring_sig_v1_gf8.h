/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * ring_sig_v1_gf8.h - RSv1 data layer (V1-specific + shared
 * "membership" layer).
 *
 * Two layered surfaces live here today:
 *
 *   1. voleith_rs_membership_* - the membership cfg, layout, path,
 *      validate, witness packer, and canonical-encoding absorber.
 *      Reusable across V1, V2 (linkable), V4 (claimable), V5 (traceable),
 *      and V7 (threshold) - every Vx whose anonymity baseline is the
 *      same secret-dir Merkle membership.  V3 (attribute-predicate)
 *      changes the leaf shape and V6 (forward-secure) uses a different
 *      tree primitive, so they extend rather than reuse this layer.
 *
 *   2. voleith_rsv1_* - V1-specific helpers built on top of the
 *      membership layer.  Currently: the V1 cfg-fingerprint (binds
 *      V1's identity into the signature's fs_seed; see design §5).
 *      T6 adds voleith_rsv1_sign/_verify; T7 adds voleith_ring_sig_t
 *      serialization with the "VRS1" magic.
 *
 * See docs/RSV1_DESIGN.md for the V1 protocol and docs/RING_SIGNATURE_DESIGN.md
 * for the V1-V7 variant matrix.
 *
 * Tickets:
 *   T2 - membership cfg + validate + V1 fingerprint
 *   T3 - membership layout, build_circuit (circuits/ring_sig_v1_gf8_circuit.h)
 *   T4 - membership path + pack_witness
 *   T5+ - ring builders, sign/verify, serialization
 */

#ifndef VOLEITH_RING_SIG_V1_GF8_H
#define VOLEITH_RING_SIG_V1_GF8_H

#include "../circuits/node_hash_vt.h"
#include "../core/hash.h" /* voleith_hash_ctx_t for the canonical absorber */
#include "params_fingerprint.h" /* VOLEITH_PARAMS_FINGERPRINT_BYTES */
#include "proof.h"              /* voleith_params_t, voleith_proof_t */

#include <stddef.h>
#include <stdint.h>

/* ================================================================
 * Membership layer (reusable across V1, V2, V4, V5, V7).
 * ================================================================ */

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
 *                VOLEITH_RS_MEMBERSHIP_MAX_DEPTH.  Revocation circuit
 *                work lands in T8.
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
 * (circuits/ring_sig_v1_gf8_circuit.h) and consumed by
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
 * circuits/ring_sig_v1_gf8_circuit.h:
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

/* ================================================================
 * V1-specific helpers (built on the membership layer above).
 * ================================================================ */

/*
 * Sentinel byte used to fill unfilled leaf-node slots in a sub-capacity
 * ring.  Each unused slot becomes node_bytes copies of this byte (i.e.
 * an all-zero leaf node when this is 0x00).
 *
 * Rationale: an OWF output of all-zero bytes is vanishingly unlikely
 * for any sk under any of the wrapped node-hash vts, so a sentinel slot
 * cannot collide with a real member's leaf node.  This means the ring
 * can be built once at capacity 2^depth_m and sub-capacity rings still
 * yield a well-defined root; downstream verifiers see only the root
 * and need not know the ring is sub-capacity.
 */
#define VOLEITH_RSV1_SENTINEL_LEAF_BYTE 0x00

/*
 * voleith_rsv1_ring_build - build a membership Merkle ring from
 * n_members raw secrets and emit per-member path bundles.
 *
 * For each member i, owf_vt->leaf_hash(sks + i * sk_bytes, sk_bytes)
 * is taken as the leaf node.  Unused slots [n_members .. 2^depth_m)
 * are filled with the documented sentinel (see
 * VOLEITH_RSV1_SENTINEL_LEAF_BYTE).  The membership root and each
 * member's sibling path are then produced by voleith_merkle_vt_build
 * and voleith_merkle_vt_compute_path (see
 * circuits/merkle_vt_gf8_helpers.h).
 *
 * Ownership / lifetime: siblings_storage is caller-owned, of length
 *
 *   n_members * cfg->depth_m * cfg->tree_hash->node_bytes
 *
 * bytes.  This function fills it and assigns
 *
 *   paths_out[i].siblings = siblings_storage + i * cfg->depth_m
 *                           * cfg->tree_hash->node_bytes
 *
 * so each path's sibling buffer points into the caller-managed block.
 * Freeing siblings_storage invalidates every paths_out[i].siblings.
 *
 * cfg              - validated via voleith_rs_membership_validate.
 * sks              - n_members * cfg->sk_bytes bytes, member 0 first.
 * n_members        - 1..2^cfg->depth_m.  Exceeding capacity returns -1.
 * root_out         - cfg->tree_hash->node_bytes bytes, written iff 0.
 * paths_out        - n_members entries; on success .leaf_index[i] = i
 *                    and .siblings[i] is wired into siblings_storage.
 * siblings_storage - as documented above.
 *
 * Returns 0 on success, -1 on NULL argument, cfg validation failure,
 * n_members == 0 or > ring capacity, propagated vt callback failure,
 * or allocation failure.  On failure root_out, paths_out, and
 * siblings_storage are left in an unspecified state.
 */
int voleith_rsv1_ring_build(const voleith_rs_membership_config_t *cfg,
                            const uint8_t *sks, size_t n_members,
                            uint8_t *root_out,
                            voleith_rs_membership_path_t *paths_out,
                            uint8_t *siblings_storage);

/* SHAKE-256 fingerprint width.  Matches params_fingerprint and
 * circuit_fingerprint for cross-layer convention consistency. */
#define VOLEITH_RSV1_CONFIG_FINGERPRINT_BYTES 16

/*
 * Canonical encoding domain tag absorbed first by V1's fingerprint
 * function.  The "-v1" suffix pins the V1 fingerprint layout; future
 * Vx fingerprints use their own domain tags so their outputs never
 * collide with V1's.
 */
#define VOLEITH_RSV1_CONFIG_FINGERPRINT_DOMAIN_TAG "voleith-rsv1-cf-v1"

/*
 * voleith_rsv1_config_fingerprint - 16-byte SHAKE-256 fingerprint
 * binding the V1 cfg identity.
 *
 * Internally: SHAKE-256(init) || absorb(VOLEITH_RSV1_CONFIG_FINGERPRINT_DOMAIN_TAG
 * || 0x00) || voleith_rs_membership_absorb_canonical(ctx, cfg) ||
 * squeeze(16).
 *
 * V1's cfg is exactly the membership cfg, so this fingerprint takes a
 * voleith_rs_membership_config_t directly.  V2's voleith_rsv2_config_t
 * will embed the membership cfg and add nullifier-PRF fields; its
 * fingerprint will absorb a V2 domain tag, then call
 * voleith_rs_membership_absorb_canonical on the embedded mem cfg, then
 * absorb the V2 extension, then squeeze.  Same canonical-membership
 * source of truth shared across variants.
 *
 * Both tree_hash and the effective owf vt (= owf_hash ?: tree_hash)
 * must have non-NULL .name.  Returns 0 on success, -1 if cfg is NULL,
 * out is NULL, cfg->tree_hash is NULL, or either name is NULL.
 *
 * Note: this function does not run voleith_rs_membership_validate.
 * Callers that need both invariants and a fingerprint should call
 * validate first.
 */
int voleith_rsv1_config_fingerprint(
    const voleith_rs_membership_config_t *cfg,
    uint8_t out[VOLEITH_RSV1_CONFIG_FINGERPRINT_BYTES]);

/* ================================================================
 * Sign / verify (T6).
 * ================================================================ */

/* Byte length of the fs_seed produced by voleith_rsv1_compute_fs_seed
 * and consumed by voleith_rsv1_sign / _verify. */
#define VOLEITH_RSV1_FS_SEED_BYTES 16

/* Single-byte version tag locking the §5 absorb layout to "RSv1 fs_seed
 * format 1".  Bump if the construction in voleith_rsv1_compute_fs_seed
 * ever changes; old verifiers reject the new value loudly. */
#define VOLEITH_RSV1_FS_SEED_FMT_VERSION 0x01

/* Width of the 16-byte ASCII domain tag absorbed by the fs_seed
 * construction.  Distinct from every other domain tag in the project. */
#define VOLEITH_RSV1_DOMAIN_TAG_BYTES 16

/* 16-byte ASCII domain tag absorbed second by the fs_seed construction
 * (right after the version byte).  "VOLEitH-RSv1" is 12 visible bytes;
 * the trailing four bytes pad to 16. */
extern const uint8_t voleith_rsv1_domain_tag[VOLEITH_RSV1_DOMAIN_TAG_BYTES];

/*
 * voleith_rsv1_compute_fs_seed - construct the §5 Fiat-Shamir seed.
 *
 * Absorbs, in order:
 *   FS_SEED_FMT_VERSION                          (1 byte)
 *   voleith_rsv1_domain_tag                      (16 bytes)
 *   voleith_rsv1_config_fingerprint(cfg)         (16 bytes)
 *   membership_root                              (tree_hash->node_bytes)
 *   revocation_root_or_null,
 *     else node_bytes zero bytes                 (tree_hash->node_bytes)
 *   m_len as 8-byte big-endian                   (8 bytes)
 *   m                                            (m_len bytes)
 *
 * Squeezes VOLEITH_RSV1_FS_SEED_BYTES bytes into out.  Exposed publicly
 * so the T6a KAT can pin its byte stream directly without going through
 * voleith_rsv1_sign.
 *
 * Returns 0 on success, -1 if any required pointer arg is NULL (cfg,
 * membership_root, out; m may be NULL only if m_len == 0; revocation
 * may be NULL, which means "absorb node_bytes zeros") or if cfg fails
 * voleith_rs_membership_validate / fingerprinting.
 */
int voleith_rsv1_compute_fs_seed(const voleith_rs_membership_config_t *cfg,
                                 const uint8_t *membership_root,
                                 const uint8_t *revocation_root_or_null,
                                 const uint8_t *m, size_t m_len,
                                 uint8_t out[VOLEITH_RSV1_FS_SEED_BYTES]);

/*
 * voleith_ring_sig_t - on-the-wire ring signature.
 *
 * In T6 (this ticket) the .data buffer is the raw gf8_proof bytes
 * emitted by voleith_gf8_prove_v2.  T7 wraps these bytes with the
 * versioned "VRS1" envelope (magic | version | cfg_fp | params_fp |
 * proof_len | proof).
 *
 * Allocated by voleith_rsv1_sign; freed with voleith_ring_sig_free.
 */
typedef struct {
    uint8_t *data;
    size_t len;
} voleith_ring_sig_t;

/* Free sig->data and zero the struct.  Safe to call on a zeroed or
 * already-freed sig (NULL data). */
void voleith_ring_sig_free(voleith_ring_sig_t *sig);

/*
 * voleith_rsv1_sign - produce an RSv1 ring signature.
 *
 * Steps (per design §4.2 + §5):
 *   1. Validate cfg.
 *   2. Build the membership circuit + layout via
 *      voleith_rs_membership_build_circuit.
 *   3. Pack the witness from (sk, membership) via
 *      voleith_rs_membership_pack_witness.
 *   4. Pack the instance: caller-supplied membership_root.
 *   5. Compute fs_seed via voleith_rsv1_compute_fs_seed.
 *   6. Call voleith_gf8_prove_v2.  If (sk, path) does NOT walk to
 *      membership_root, the assert_equal_root constraint fires inside
 *      the QuickSilver eval pass and prove returns -1 up-front (X-10
 *      discipline).
 *   7. Move the resulting proof bytes into *sig_out.
 *
 * cfg              - validated.
 * params           - voleith_params_validate'd by the prover.
 * sk               - cfg->sk_bytes bytes.
 * membership_root  - the ring's published root (tree_hash->node_bytes).
 *                    The caller obtained this from voleith_rsv1_ring_build
 *                    (or from the ring authority) and committed to it
 *                    out-of-band.  The signer does NOT recompute it from
 *                    (sk, path); supplying the real R here is what makes
 *                    wrong-sk / wrong-sibling fail at sign time.
 * membership       - signer's path bundle (leaf_index + sibling bytes).
 * revocation_root  - the published revocation IMT root (V).  Required
 *                    iff cfg->depth_r > 0; must be NULL when
 *                    cfg->depth_r == 0.
 * revocation       - signer's non-membership bundle for the revocation
 *                    IMT (rev_* fields of the path struct).  Required
 *                    iff cfg->depth_r > 0; must be NULL when
 *                    cfg->depth_r == 0.  The signer typically obtains
 *                    this by calling voleith_imt_vt_lookup_nonmember on
 *                    the published revocation record set with their
 *                    own leaf node as target.
 * m                - message to bind via Fiat-Shamir.  May be NULL only
 *                    when m_len == 0.
 * m_len            - up to 2^64 - 1.
 * sig_out          - on success, sig_out->data is malloc'd; caller frees
 *                    with voleith_ring_sig_free.  On failure sig_out is
 *                    zeroed.
 *
 * Returns 0 on success, -1 on validation failure, packing failure,
 * proof-system failure (incl. witness that doesn't satisfy the
 * circuit), or any NULL argument.
 */
int voleith_rsv1_sign(voleith_ring_sig_t *sig_out,
                      const voleith_rs_membership_config_t *cfg,
                      const voleith_params_t *params, const uint8_t *sk,
                      const uint8_t *membership_root,
                      const voleith_rs_membership_path_t *membership,
                      const uint8_t *revocation_root,
                      const voleith_rs_membership_path_t *revocation,
                      const uint8_t *m, size_t m_len);

/*
 * voleith_rsv1_verify - verify an RSv1 ring signature.
 *
 * Steps:
 *   1. Validate cfg.
 *   2. Build the membership circuit + layout (deterministic in cfg).
 *   3. Pack the instance from membership_root.
 *   4. Compute fs_seed via voleith_rsv1_compute_fs_seed.
 *   5. Call voleith_gf8_verify_v2 on the raw proof bytes in sig.
 *
 * cfg                       - validated.
 * params                    - same params used at sign time.
 * membership_root           - tree_hash->node_bytes bytes.
 * revocation_root_or_null   - required iff cfg->depth_r > 0; must be
 *                             NULL when cfg->depth_r == 0.
 * m, m_len                  - message bytes the signer committed to.
 *
 * Returns 0 if the signature verifies, -1 otherwise.
 */
int voleith_rsv1_verify(const voleith_ring_sig_t *sig,
                        const voleith_rs_membership_config_t *cfg,
                        const voleith_params_t *params,
                        const uint8_t *membership_root,
                        const uint8_t *revocation_root_or_null,
                        const uint8_t *m, size_t m_len);

/* ================================================================
 * Serialization (T7).
 *
 * Wire envelope wrapping the raw gf8_proof bytes inside sig->data with
 * a versioned, self-describing header.  Per design §7:
 *
 *   offset  size  field
 *   ------  ----  -----
 *        0     4  magic = "VRS1"
 *        4     1  format_version = 1
 *        5    16  cfg_fingerprint  (voleith_rsv1_config_fingerprint)
 *       21    16  params_fingerprint (voleith_params_fingerprint)
 *       37     4  gf8_proof_len, big-endian uint32
 *       41   ...  gf8_proof bytes
 *
 * Header overhead is VOLEITH_RING_SIG_HEADER_BYTES (= 41); total packed
 * length is 41 + gf8_proof_len.  Endianness on the length field matches
 * the project's other length-encoding conventions (m_len in §5,
 * proof_header lengths) which use big-endian.
 *
 * The magic separates RSv1 signatures from raw VOLEitH proofs in mixed
 * bytestreams; cfg_fingerprint and params_fingerprint make unpack fail
 * loudly when a caller supplies a different cfg or params than the one
 * the signature was produced under.  Inner gf8_proof bytes are not
 * re-validated by unpack; they are validated by voleith_rsv1_verify on
 * the unpacked sig.
 * ================================================================ */

/* Magic bytes at offset 0: 'V', 'R', 'S', '1'. */
#define VOLEITH_RING_SIG_MAGIC_0 'V'
#define VOLEITH_RING_SIG_MAGIC_1 'R'
#define VOLEITH_RING_SIG_MAGIC_2 'S'
#define VOLEITH_RING_SIG_MAGIC_3 '1'

/* Current on-the-wire format version.  Bumped if the envelope changes
 * shape; old unpackers reject the new value loudly. */
#define VOLEITH_RING_SIG_FORMAT_VERSION 1u

/* Fixed header bytes (magic + version + cfg_fp + params_fp + len) preceding
 * the gf8_proof body. */
#define VOLEITH_RING_SIG_HEADER_BYTES                                          \
    (4u + 1u + VOLEITH_RSV1_CONFIG_FINGERPRINT_BYTES +                         \
     VOLEITH_PARAMS_FINGERPRINT_BYTES + 4u)

/*
 * voleith_ring_sig_packed_len - total packed buffer length for an
 * unpacked sig.
 *
 * Equals VOLEITH_RING_SIG_HEADER_BYTES + sig->len.  Returned as a
 * size_t to avoid the uint32 cap inside the helpers; pack rejects any
 * sig.len that does not fit in a uint32_t.
 *
 * Returns 0 if sig is NULL.
 */
size_t voleith_ring_sig_packed_len(const voleith_ring_sig_t *sig);

/*
 * voleith_ring_sig_pack - serialize sig into out_buf.
 *
 * Computes cfg_fingerprint and params_fingerprint internally; the caller
 * must supply the same cfg / params they passed to voleith_rsv1_sign,
 * since those identities bind the signature.
 *
 * Caller provides out_buf of length out_len.  out_len must equal
 * voleith_ring_sig_packed_len(sig); pack rejects mismatches rather than
 * silently truncating.  written_out, if non-NULL, receives the number
 * of bytes written on success (same as voleith_ring_sig_packed_len).
 *
 * Returns 0 on success, -1 on:
 *   any NULL pointer arg (out_buf, sig, cfg, params; sig->data may be
 *     NULL only if sig->len is 0)
 *   sig->data == NULL with sig->len != 0 or vice versa
 *   sig->len > UINT32_MAX (cannot encode in the 4-byte length field)
 *   out_len != voleith_ring_sig_packed_len(sig)
 *   fingerprint computation failure (NULL .name on the cfg's vts, etc.)
 */
int voleith_ring_sig_pack(uint8_t *out_buf, size_t out_len, size_t *written_out,
                          const voleith_ring_sig_t *sig,
                          const voleith_rs_membership_config_t *cfg,
                          const voleith_params_t *params);

/*
 * voleith_ring_sig_unpack - parse buf into sig_out.
 *
 * Validates magic, format version, cfg_fingerprint (against the caller's
 * cfg), params_fingerprint (against the caller's params), and that
 * buf_len == VOLEITH_RING_SIG_HEADER_BYTES + encoded_proof_len.  On
 * success sig_out->data is malloc'd and holds the inner gf8_proof
 * bytes; caller frees with voleith_ring_sig_free.
 *
 * Returns 0 on success.  Returns -1 on:
 *   any NULL pointer arg
 *   buf_len < VOLEITH_RING_SIG_HEADER_BYTES
 *   magic mismatch
 *   format version mismatch
 *   cfg_fingerprint mismatch (constant-time comparison via
 *     voleith_const_memcmp)
 *   params_fingerprint mismatch (constant-time)
 *   length-field mismatch (truncated or oversized buffer)
 *   allocation failure for sig_out->data
 *
 * On failure sig_out is zeroed.
 */
int voleith_ring_sig_unpack(voleith_ring_sig_t *sig_out, const uint8_t *buf,
                            size_t buf_len,
                            const voleith_rs_membership_config_t *cfg,
                            const voleith_params_t *params);

#endif /* VOLEITH_RING_SIG_V1_GF8_H */
