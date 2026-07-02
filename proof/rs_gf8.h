/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * rs_gf8.h - composable ring-signature config (data layer).
 *
 * The 1.8.0 superset config embeds the V1 membership config
 * (voleith_rs_membership_config_t) and turns each new capability
 * (V2 linkable nullifier, V3 attribute predicates, V4 claimable
 * commitment) into an independently-enableable module.  "V2", "V3",
 * "V4" are documented presets of enabled modules, not three separate
 * codebases; see the RS implementation plan.
 *
 * This header declares the config type, the attribute schema (declared
 * here so the fingerprint can absorb it even when V3 circuit work lands
 * later), the superset validator, the module bitmap helper, and the
 * composable cfg-fingerprint.  Circuit / sign / verify surfaces arrive
 * in later tickets (V2.CIRC, V3.CIRC, V4.CIRC, RS.SIGN).
 *
 * The reusable membership core (cfg, layout, path, validate, canonical
 * absorber, witness packer) lives in proof/rs_membership_gf8.h, which
 * this header re-includes.  V1's frozen wrappers stay in
 * proof/ring_sig_v1_gf8.h.
 */

#ifndef VOLEITH_RS_GF8_H
#define VOLEITH_RS_GF8_H

#include "gf8_circuit.h"        /* voleith_gf8_circuit_t, gf8_wire_id */
#include "params_fingerprint.h" /* VOLEITH_PARAMS_FINGERPRINT_BYTES */
#include "proof.h"              /* voleith_params_t, voleith_proof_t */
#include "rs_membership_gf8.h"  /* membership core: cfg, validate, absorber */

#include <stddef.h>
#include <stdint.h>

/*
 * voleith_rs_attr_pred_kind_t - predicate applied to a V3 attribute
 * field.  Target / bound *values* are not part of the schema; they are
 * per-signature public inputs (see V3.3), so one ring (fixed leaf
 * format) supports many thresholds.
 */
typedef enum {
    VOLEITH_RS_ATTR_PRED_NONE = 0,  /* hidden, unconstrained */
    VOLEITH_RS_ATTR_PRED_EQ = 1,    /* attr == target (target public) */
    VOLEITH_RS_ATTR_PRED_RANGE = 2, /* low <= attr <= high (bounds public) */
} voleith_rs_attr_pred_kind_t;

/* Highest valid predicate enum value; used by validate to reject
 * out-of-range pred bytes. */
#define VOLEITH_RS_ATTR_PRED_MAX VOLEITH_RS_ATTR_PRED_RANGE

/*
 * voleith_rs_attr_field_t - one attribute field in the leaf preimage.
 *
 *   width_bytes - little-endian field width (>= 1).
 *   pred        - predicate applied to this field (NONE = hidden).
 */
typedef struct {
    size_t width_bytes;
    voleith_rs_attr_pred_kind_t pred;
} voleith_rs_attr_field_t;

/*
 * voleith_rs_attr_schema_t - the ordered attribute layout V3 appends to
 * the leaf preimage (leaf = OWF(sk || attr_0 || ... || attr_{n-1})).
 * NULL config->attr_schema disables attributes (leaf = OWF(sk) only).
 */
typedef struct {
    const voleith_rs_attr_field_t *fields;
    size_t n_fields;
} voleith_rs_attr_schema_t;

/*
 * Cap on the summed attribute width.  The attribute bytes ride into the
 * OWF leaf preimage, so the bound exists only to reject absurd schemas
 * that would balloon the leaf-hash circuit; 4096 bytes is far past any
 * realistic credential payload yet well under any vt's internal block
 * accounting limits.  Tighten if a consumer needs a stricter cap.
 */
#define VOLEITH_RS_ATTR_TOTAL_MAX_BYTES 4096u

/*
 * voleith_rs_config_t - the composable superset config.
 *
 * Embeds the V1 membership config and layers each new capability as an
 * independently-enableable module.  A config with every module off is
 * layout-compatible with the V1 builder (it is still a distinct
 * protocol via the composed fingerprint / domain tag; see the plan Q2).
 */
typedef struct {
    /* Baseline (V1).  Embeds tree_hash, owf_hash, sk_bytes, depth_m,
     * depth_r. */
    voleith_rs_membership_config_t membership;

    /* --- V3: attribute predicates (NULL disables; leaf == OWF(sk)) --- */
    const voleith_rs_attr_schema_t *attr_schema;

    /*
     * V3 escape hatch (Q5): optional callback applied after the built-in
     * {EQ, RANGE, NONE} schema pass, on the same leaf-derived attribute
     * wires.  NULL = built-in vocabulary only.  Emits arbitrary extra
     * gates (OR, cross-attribute arithmetic, set membership); receives
     * wire IDs only (never plaintext) so circuit structure stays
     * data-independent.  A callback that adds witness wires must pair
     * with a matching witness emitter.  The emitted gates are bound by the
     * proof's circuit fingerprint (voleith_gf8_circuit_fingerprint, checked
     * at verify time via voleith_proof_header_check_identity_gf8), so
     * prover/verifier gate-stream divergence rejects up front.  These gates
     * are NOT bound through fs_seed: voleith_rs_config_fingerprint, which
     * fs_seed absorbs, deliberately excludes the custom_predicate function
     * pointer (function pointers are not portable across processes / builds).
     */
    void (*custom_predicate)(voleith_gf8_circuit_t *c,
                             const gf8_wire_id *attr_wires, size_t n_attrs,
                             void *ctx);
    void *custom_predicate_ctx;

    /* --- V2: linkable nullifier (scope_bytes == 0 disables) --- */
    size_t scope_bytes; /* fixed public scope width; T = PRF(sk, scope) */
    size_t depth_s;     /* in-circuit spent-set IMT depth (0 = none) */

    /* --- V4: claimable commitment (enable_commitment == 0 disables) --- */
    int enable_commitment;
    size_t commit_id_bytes;   /* id handle width (= lambda; shared with V5) */
    size_t commit_rand_bytes; /* blinding randomness width */
} voleith_rs_config_t;

/* ================================================================
 * Module bitmap.
 * ================================================================ */

#define VOLEITH_RS_MODULE_REVOCATION 0x01u /* bit0: membership.depth_r > 0 */
#define VOLEITH_RS_MODULE_NULLIFIER 0x02u  /* bit1: scope_bytes > 0 */
#define VOLEITH_RS_MODULE_PREDICATE 0x04u  /* bit2: attr_schema && any pred */
#define VOLEITH_RS_MODULE_COMMITMENT 0x08u /* bit3: enable_commitment */
#define VOLEITH_RS_MODULE_SPENT_SET 0x10u  /* bit4: depth_s > 0 */

/*
 * voleith_rs_module_bitmap - the set of enabled modules as a single
 * byte.  Self-describes the fingerprint / fs_seed absorb stream so a
 * field-shifting ambiguity between module combinations is impossible.
 *
 * bit0 revocation (membership.depth_r > 0), bit1 nullifier
 * (scope_bytes > 0), bit2 predicate (attr_schema != NULL and at least
 * one field's pred != NONE), bit3 commitment (enable_commitment != 0),
 * bit4 spent_set (depth_s > 0).
 *
 * Returns 0 if cfg is NULL.  Does not validate; combine with
 * voleith_rs_config_validate when correctness of the combination
 * matters.
 */
uint8_t voleith_rs_module_bitmap(const voleith_rs_config_t *cfg);

/* ================================================================
 * Validation.
 * ================================================================ */

/*
 * voleith_rs_config_validate - reject malformed superset configs.
 *
 * Runs voleith_rs_membership_validate_structural(&cfg->membership) (the
 * width-independent membership checks; NOT the V1 sk == fixed_leaf_bytes
 * check, since the composable leaf preimage is OWF(sk || attributes)),
 * then checks each enabled module:
 *
 *   attr_schema (if non-NULL): n_fields >= 1; every field width_bytes
 *     >= 1; sum(width_bytes) <= VOLEITH_RS_ATTR_TOTAL_MAX_BYTES; every
 *     pred in the enum range.
 *
 *   OWF input width (always): let preimage = sk_bytes + sum(width_bytes).
 *     If the effective OWF vt advertises a single-compression capacity
 *     (leaf_block_bytes != 0), require preimage <= leaf_block_bytes (a
 *     fixed-input OWF carries attributes up to the hash block boundary
 *     in one compression; the leaf circuit zero-pads any shortfall, and
 *     the exact preimage length is fixed by the schema and bound into
 *     the fingerprint).  Concrete capacities: hirose-fixed32 = 32,
 *     grostl-256-fixed = 64, grostl-512-fixed = 128.  If the vt is
 *     fixed-exact with no advertised capacity (leaf_block_bytes == 0,
 *     fixed_leaf_bytes != 0), require preimage == fixed_leaf_bytes.
 *     Variable-leaf vts (both 0) accept any preimage (subject to the
 *     attribute cap above).
 *
 *   nullifier: scope_bytes > 0 imposes no extra constraint on its own.
 *
 *   spent_set: depth_s > 0 requires scope_bytes > 0 (a spent set needs a
 *     nullifier to spend) and depth_s <= VOLEITH_RS_MEMBERSHIP_MAX_DEPTH.
 *
 *   commitment: enable_commitment != 0 requires commit_id_bytes >= 1 and
 *     commit_rand_bytes >= 1.
 *
 * Returns 0 if every check passes, -1 otherwise.  Does not allocate.
 */
int voleith_rs_config_validate(const voleith_rs_config_t *cfg);

/* ================================================================
 * Composable cfg-fingerprint.
 * ================================================================ */

/* SHAKE-256 fingerprint width.  Matches params_fingerprint,
 * circuit_fingerprint, and the V1 cfg-fingerprint. */
#define VOLEITH_RS_CONFIG_FINGERPRINT_BYTES 16

/*
 * 16-byte ASCII domain tag absorbed first by the composable fingerprint.
 * "VOLEitH-RSc-cf" is 14 visible bytes; the trailing two NULs pad to 16.
 * Distinct from the V1 "-cf-v1" tag so a composable fingerprint never
 * collides with a V1 one.
 */
#define VOLEITH_RS_CONFIG_FINGERPRINT_DOMAIN_TAG "VOLEitH-RSc-cf\x00\x00"

/*
 * voleith_rs_config_fingerprint - 16-byte SHAKE-256 fingerprint binding
 * the composable cfg identity.
 *
 * Absorbs, in order:
 *   VOLEITH_RS_CONFIG_FINGERPRINT_DOMAIN_TAG          (16 bytes)
 *   voleith_rs_membership_absorb_canonical(membership)
 *   module bitmap                                     (1 byte)
 *   [if nullifier]  scope_bytes_le8 || depth_s_le8
 *   [if commitment] commit_id_bytes_le8 || commit_rand_bytes_le8
 *   [if predicate]  n_fields_le8 || (width_bytes_le8 || pred_byte)*
 *
 * then squeezes 16 bytes.  Revocation sizing (depth_r) is already inside
 * the membership absorber; spent-set depth_s rides with the nullifier
 * block (a spent set always implies a nullifier).  The module bitmap
 * byte makes the conditional absorb stream unambiguous.
 *
 * The custom_predicate callback is NOT absorbed (function pointers are
 * not portable); it is bound instead by the whole-circuit gate-stream
 * fingerprint folded into fs_seed at sign/verify time.
 *
 * Both tree_hash and the effective owf vt must have non-NULL .name.
 * Returns 0 on success, -1 if cfg or out is NULL, cfg->membership.tree_hash
 * is NULL, or either vt name is NULL.  Does not run validate; callers
 * needing both should validate first.
 */
int
voleith_rs_config_fingerprint(const voleith_rs_config_t *cfg,
                              uint8_t out[VOLEITH_RS_CONFIG_FINGERPRINT_BYTES]);

/* ================================================================
 * Witness packer + ring builder (RS.PACK).
 * ================================================================ */

/* Forward declaration; the full definition lives in
 * circuits/rs_gf8_circuit.h (the builder owns the layout).  Declaring the
 * tag here lets the packer take a layout pointer without a circular
 * include of the circuit header. */
typedef struct voleith_rs_layout voleith_rs_layout_t;

/*
 * voleith_rs_path_t - prover-side path bundle for the superset packer.
 *
 * Embeds the V1 membership/revocation path (leaf_index + siblings +
 * rev_* adjacent record) and adds the V2 scope value (public, but needed
 * to recompute the nullifier CMAC inv_in) and the V2 spent-set adjacent
 * IMT record for T.  Public values (scope/T/C/bounds) live in the
 * instance buffer, not the witness; scope appears here only because the
 * CMAC inv_in derivation needs it.
 *
 * Fields for a disabled module are ignored.  Attribute values, id, and
 * rand are passed to voleith_rs_pack_witness as separate arguments (not
 * in this struct).
 */
typedef struct {
    voleith_rs_membership_path_t membership; /* leaf_index, siblings, rev_* */

    const uint8_t *scope; /* V2: scope_bytes (public PRF input) */

    /* V4 commitment opening (witness): the leaf-preimage handle id and
     * the blinding rand.  Used by voleith_rs_sign (which threads them
     * into voleith_rs_pack_witness). */
    const uint8_t *commit_id;   /* commit_id_bytes */
    const uint8_t *commit_rand; /* commit_rand_bytes */

    /* V2 spent-set adjacent IMT record straddling T. */
    size_t spent_adj_leaf_index;
    const uint8_t *spent_siblings;   /* depth_s * node_bytes */
    const uint8_t *spent_low_value;  /* voleith_rs_nullifier_bytes(cfg) */
    const uint8_t *spent_low_next;   /* voleith_rs_nullifier_bytes(cfg) */
    const uint8_t *spent_next_index; /* VOLEITH_RSV1_REV_INDEX_BYTES (8) */
} voleith_rs_path_t;

/*
 * voleith_rs_pack_witness - assemble the full superset witness buffer
 * matching voleith_rs_build_circuit's layout.
 *
 * Writes layout->witness_bytes bytes into witness_out:
 *   sk | attributes | membership dirs | siblings | [id | rand] |
 *   leaf inv_in (over sk||attrs) | path inv_in | [commit inv_in] |
 *   [nullifier CMAC inv_in] | [revocation inv_in] | [spent-set inv_in]
 *
 * cfg / layout MUST come from the same voleith_rs_build_circuit call.
 * sk is cfg->membership.sk_bytes.  attrs is the schema-ordered attribute
 * payload (NULL iff no attr_schema).  id / rand are commit_id_bytes /
 * commit_rand_bytes (NULL iff !enable_commitment).  path supplies the
 * membership leaf_index + siblings, the revocation adjacent record (iff
 * depth_r > 0), the scope value (iff scope_bytes > 0), and the spent-set
 * adjacent record (iff depth_s > 0).
 *
 * Returns 0 on success, -1 on NULL required argument, leaf_index out of
 * range, config validation failure, or propagated vt builder failure.
 * On failure witness_out is left in an unspecified state.
 */
int voleith_rs_pack_witness(const voleith_rs_config_t *cfg,
                            const voleith_rs_layout_t *layout,
                            const uint8_t *sk, const uint8_t *attrs,
                            const voleith_rs_path_t *path, const uint8_t *id,
                            const uint8_t *rand, uint8_t *witness_out);

/*
 * voleith_rs_ring_build - build the membership ring and emit per-member
 * paths.  leaf_i = owf_vt->leaf_hash(sk_i || attrs_i).
 *
 * sks               - n_members * cfg->membership.sk_bytes bytes.
 * attrs_or_null     - n_members * (sum of attr widths) bytes when
 *                     cfg->attr_schema != NULL; MUST be NULL otherwise.
 * n_members         - 1 .. 2^depth_m.  Vacant slots are filled with the
 *                     documented sentinel (VOLEITH_RSV1_SENTINEL_LEAF_BYTE).
 * root_out          - node_bytes bytes.
 * paths_out         - n_members entries; .membership.leaf_index = i and
 *                     .membership.siblings is wired into siblings_storage.
 *                     The scope / revocation / spent fields are left for
 *                     the caller to fill (they come from separate IMTs).
 * siblings_storage  - n_members * depth_m * node_bytes bytes (caller-owned).
 *
 * Returns 0 on success, -1 on NULL argument, validation failure,
 * n_members == 0 or > capacity, attrs/schema mismatch, or propagated
 * failure.
 */
int voleith_rs_ring_build(const voleith_rs_config_t *cfg, const uint8_t *sks,
                          const uint8_t *attrs_or_null, size_t n_members,
                          uint8_t *root_out, voleith_rs_path_t *paths_out,
                          uint8_t *siblings_storage);

/* ================================================================
 * Composed Fiat-Shamir seed (RS.FS).
 * ================================================================ */

/* Byte length of the composed fs_seed. */
#define VOLEITH_RS_FS_SEED_BYTES 16

/* Single-byte version tag locking the §1.4 absorb layout. */
#define VOLEITH_RS_FS_SEED_FMT_VERSION 0x01

/* 16-byte ASCII domain tag absorbed second (after the version byte).
 * "VOLEitH-RSc-fs" is 14 visible bytes; two trailing NULs pad to 16.
 * Distinct from the V1 fs_seed tag ("VOLEitH-RSv1\0\0\0\0") and from the
 * composable cfg-fingerprint tag ("VOLEitH-RSc-cf\0\0"). */
#define VOLEITH_RS_FS_SEED_DOMAIN_TAG "VOLEitH-RSc-fs\x00\x00"

/*
 * voleith_rs_public_t - the public inputs bound into the composed
 * fs_seed (the verifier already holds all of these).
 *
 *   membership_root - node_bytes (required).
 *   revocation_root - node_bytes, or NULL to absorb node_bytes zeros
 *                     (the §1.4 "revocation_root_or_zero" slot, absorbed
 *                     unconditionally).
 *   commitment      - C, node_bytes; required iff cfg->enable_commitment.
 *   scope           - scope_bytes; required iff cfg->scope_bytes > 0.
 *   nullifier       - T, voleith_rs_nullifier_bytes(cfg) (16 or 32);
 *                     required iff cfg->scope_bytes > 0.
 *   spent_root      - node_bytes; required iff cfg->depth_s > 0.
 *   bounds          - the predicate-bound bytes in the same layout as the
 *                     instance bounds section (EQ -> width target; RANGE
 *                     -> width low then width high, in schema order over
 *                     fields with pred != NONE); required iff the
 *                     predicate module is enabled (any pred != NONE).
 *   bounds_len      - length of bounds (sanity; must match the schema).
 *
 * Fields for a disabled module are ignored.
 */
typedef struct {
    const uint8_t *membership_root;
    const uint8_t *revocation_root;
    const uint8_t *commitment;
    const uint8_t *scope;
    const uint8_t *nullifier;
    const uint8_t *spent_root;
    const uint8_t *bounds;
    size_t bounds_len;
} voleith_rs_public_t;

/*
 * voleith_rs_compute_fs_seed - construct the §1.4 composed Fiat-Shamir
 * seed.
 *
 * Absorbs, in order:
 *   FS_SEED_FMT_VERSION (1) || DOMAIN_TAG_RS_COMPOSED (16) ||
 *   cfg_fingerprint (16) || module_bitmap (1) ||
 *   membership_root (node_bytes) || revocation_root_or_zero (node_bytes) ||
 *   [commitment]  C (node_bytes) ||
 *   [nullifier]   scope_len_be8 || scope || T (16 or 32) ||
 *   [spent_set]   spent_root (node_bytes) ||
 *   [predicate]   n_pred_be8 ||
 *                 (field_idx_be8 || pred_kind ||
 *                  EQ: width_be8 || target;
 *                  RANGE: width_be8 || low || width_be8 || high)* ||
 *   m_len_be8 || m
 * then squeezes VOLEITH_RS_FS_SEED_BYTES bytes.  All length prefixes are
 * 8-byte big-endian (matching the V1 m_len convention).
 *
 * Returns 0 on success, -1 on a NULL required argument (per the module
 * gating documented on voleith_rs_public_t; m may be NULL only when
 * m_len == 0), config validation/fingerprint failure, or node_bytes
 * exceeding MERKLE_VT_MAX_NODE_BYTES.
 */
int voleith_rs_compute_fs_seed(const voleith_rs_config_t *cfg,
                               const voleith_rs_public_t *pub, const uint8_t *m,
                               size_t m_len,
                               uint8_t out[VOLEITH_RS_FS_SEED_BYTES]);

/* ================================================================
 * Sign / verify (RS.SIGN).
 * ================================================================ */

/*
 * voleith_rs_sig_t - on-the-wire composable ring signature.
 *
 * In RS.SIGN the .data buffer is the raw gf8_proof bytes from
 * voleith_gf8_prove_v2.  RS.SER wraps these with the versioned "VRSC"
 * envelope.  Allocated by voleith_rs_sign; freed with voleith_rs_sig_free.
 */
typedef struct {
    uint8_t *data;
    size_t len;
} voleith_rs_sig_t;

/* Free sig->data and zero the struct.  Safe on a zeroed/already-freed sig. */
void voleith_rs_sig_free(voleith_rs_sig_t *sig);

/*
 * voleith_rs_sign - produce a composable ring signature.
 *
 * Builds the superset circuit, packs the witness from the secret inputs
 * (sk, attrs, path-borne id/rand and adjacent records), fills the
 * instance from the public inputs, composes the fs_seed, and calls
 * voleith_gf8_prove_v2.  Because prove_v2 runs circuit_eval first, a
 * wrong sk / wrong sibling / wrong attribute / out-of-range predicate /
 * wrong T fails here with -1 (X-10 discipline).
 *
 *   sig_out - on success sig_out->data is malloc'd (raw proof bytes);
 *             caller frees with voleith_rs_sig_free.  Zeroed on failure.
 *   cfg     - validated via voleith_rs_config_validate.
 *   params  - proof parameter set.
 *   sk      - cfg->membership.sk_bytes.
 *   attrs   - schema-ordered attribute payload; NULL iff no attr_schema.
 *   path    - membership leaf_index + siblings, plus the enabled modules'
 *             prover-side data: revocation adjacency (depth_r > 0), scope
 *             (scope_bytes > 0), spent-set adjacency (depth_s > 0), and
 *             commit_id / commit_rand (enable_commitment).
 *   pub     - all public inputs (membership_root + each enabled module's
 *             public fields), bound into both the instance and the fs_seed.
 *   m,m_len - message bound via Fiat-Shamir (m NULL only if m_len == 0).
 *
 * Returns 0 on success, -1 on NULL/invalid argument, a missing required
 * public/secret field for an enabled module, proof-system failure (incl.
 * a witness that does not satisfy the circuit), or allocation failure.
 */
int voleith_rs_sign(voleith_rs_sig_t *sig_out, const voleith_rs_config_t *cfg,
                    const voleith_params_t *params, const uint8_t *sk,
                    const uint8_t *attrs, const voleith_rs_path_t *path,
                    const voleith_rs_public_t *pub, const uint8_t *m,
                    size_t m_len);

/*
 * voleith_rs_verify - verify a composable ring signature.
 *
 * Rebuilds the circuit (deterministic in cfg), fills the instance from
 * pub, recomputes the fs_seed, and calls voleith_gf8_verify_v2.
 *
 * Returns 0 if the signature verifies, -1 otherwise.  A different cfg or
 * any tampered public field changes the fs_seed / instance and rejects.
 */
int voleith_rs_verify(const voleith_rs_sig_t *sig,
                      const voleith_rs_config_t *cfg,
                      const voleith_params_t *params,
                      const voleith_rs_public_t *pub, const uint8_t *m,
                      size_t m_len);

/* ================================================================
 * Linkability (V2.LINK).
 * ================================================================ */

/*
 * Nullifier block / floor width: one AES-CMAC tag = 16 bytes.  This is the
 * minimum nullifier width and the CMAC block granularity; the effective
 * width for a given config is derived from the tree's collision-resistance
 * strength by voleith_rs_nullifier_bytes() below (16 for a <= 128-bit-CR
 * tree, 32 for a 256-bit-CR tree).  T is its own public instance value (not
 * a tree node), so this is independent of the tree node_bytes.  Defined
 * here (rather than in rs_gf8_circuit.h, which includes this header) so the
 * linkability helpers and the public-input struct can reference it without
 * a circular include.
 */
#define VOLEITH_RS_NULLIFIER_BYTES 16u

/*
 * Maximum nullifier width (256-bit-CR tree -> 32 bytes).  Bounds stack
 * arrays that hold the computed-nullifier wires / bytes.
 */
#define VOLEITH_RS_NULLIFIER_MAX_BYTES 32u

/*
 * Wide (>= 256-bit) nullifier construction: NIST SP 800-108r1 §4.1 KDF in
 * Counter Mode with the AES-CMAC PRF.  The FixedInputData is
 *
 *   Label || 0x00 || scope || [L]_2
 *
 * where Label = "VOLEitH-Nullifier" (domain-separates this PRF use of sk
 * from the leaf OWF), 0x00 is the SP 800-108 separator, scope is the public
 * Context, and [L]_2 is the 32-bit big-endian output length in *bits*.  The
 * circuit (rs_gf8_circuit.c step E) and the witness packer (rs_gf8.c) build
 * this identical byte sequence; the 16-byte (<= 128-bit-CR) path instead
 * uses the raw T = AES-CMAC(sk, scope) and ignores this layout.
 */
#define VOLEITH_RS_NULLIFIER_KDF_LABEL "VOLEitH-Nullifier"
#define VOLEITH_RS_NULLIFIER_KDF_LABEL_BYTES 17u

/*
 * voleith_rs_nullifier_bytes - effective nullifier width for a config.
 *
 * The nullifier output width tracks the membership tree's node-hash
 * collision-resistance strength so the nullifier is never the weakest link:
 * a 2^256-CR tree paired with a 128-bit (2^64 accidental-collision)
 * nullifier would defeat the point of the strong tree.  The width is the
 * tree's cr_bits expressed in bytes, floored at the 16-byte AES-CMAC block
 * and rounded up to a whole number of CMAC blocks (so the SP 800-108
 * KDF-CTR-CMAC output length stays block-aligned):
 *
 *   cr_bits  <= 128  -> 16 bytes  (T = AES-CMAC(sk, scope))
 *   cr_bits in (128,256] -> 32 bytes (T = KDF-CTR-CMAC(sk, ...), L = 256)
 *
 * See RING_SIGNATURES_DESIGN.md "Nullifier width vs tree collision-
 * resistance strength".  Returns VOLEITH_RS_NULLIFIER_BYTES (the 16-byte
 * floor) on any NULL argument or when the membership tree_hash is unset.
 */
size_t voleith_rs_nullifier_bytes(const voleith_rs_config_t *cfg);

/*
 * voleith_rs_nullifier_equal - constant-time nullifier comparison.
 *
 * T is a public field carried alongside the signature (pub->nullifier),
 * so the verifier already holds it; this helper lets applications
 * implement a seen-set / one-per-scope policy without reaching into proof
 * internals.  Two signatures by the same signer under the same scope
 * yield equal T; a different scope (or a different signer) yields an
 * unequal T.
 *
 * t_bytes is the nullifier width = voleith_rs_nullifier_bytes(cfg) (16 or
 * 32).  Compares via voleith_const_memcmp (no early-out on the first
 * differing
 * byte).  Returns 1 if the two t_bytes-long nullifiers are equal, 0
 * otherwise (including any NULL argument or t_bytes == 0).
 *
 * Consensus rule (RING_SIGNATURE_DESIGN.md §5.1): accept a signature iff
 * voleith_rs_verify passes AND its T has not been seen before in this
 * scope.  The library proves unlinkable-unless-same-scope; enforcing
 * one-time use is the application's seen-set, keyed on T per scope.
 */
int voleith_rs_nullifier_equal(const uint8_t *t1, const uint8_t *t2,
                               size_t t_bytes);

/*
 * voleith_rs_nullifier - extract the published nullifier T from a public
 * inputs bundle.
 *
 * Returns pub->nullifier (the voleith_rs_nullifier_bytes(cfg)-long T) when
 * the nullifier module is enabled (cfg->scope_bytes > 0), else NULL.  A
 * convenience accessor so callers key their seen-set on the right field
 * without duplicating the module-gating logic.  Returns NULL on any NULL
 * argument.
 */
const uint8_t *voleith_rs_nullifier(const voleith_rs_config_t *cfg,
                                    const voleith_rs_public_t *pub);

/* ================================================================
 * Claimable commitment (V4.CLAIM).
 * ================================================================ */

/*
 * voleith_rs_claim_t - an out-of-circuit authorship claim opening.
 *
 * A V4 signature binds a hiding commitment C = tree_hash(id || rand) into
 * its fs_seed, so C attaches to *this* signature.  Revealing the opening
 * (id, rand) later proves the signer authored that signature without
 * touching the anonymous proof itself.  rand is the blinding secret:
 * losing it loses the ability to claim (design §4 V4); id is the
 * leaf-preimage handle shared with the future V5 designated opener.
 *
 *   id / rand          - borrowed pointers to the opening (not copied).
 *   commitment         - the recomputed C, tree_hash node_bytes wide.
 *   commitment_bytes   - C width (= cfg->membership.tree_hash->node_bytes).
 */
typedef struct {
    const uint8_t *id;
    const uint8_t *rand;
    uint8_t commitment[MERKLE_VT_MAX_NODE_BYTES];
    size_t commitment_bytes;
} voleith_rs_claim_t;

/*
 * voleith_rs_claim_produce - build the authorship-claim opening for a V4
 * signature.
 *
 * Records (id, rand) in *claim_out and recomputes
 * C = cfg->membership.tree_hash->leaf_hash(id || rand) for the caller's
 * convenience (the same C the signer bound into fs_seed).  The id / rand
 * pointers are borrowed, not copied, so they must outlive any later use
 * of claim_out->id / claim_out->rand; the recomputed commitment is copied
 * into claim_out and is self-contained.
 *
 * cfg must enable the commitment module (validated).  id is
 * cfg->commit_id_bytes, rand is cfg->commit_rand_bytes.
 *
 * Returns 0 on success, -1 on NULL argument, a config with the commitment
 * module disabled, validation failure, node_bytes over
 * MERKLE_VT_MAX_NODE_BYTES, or leaf-hash failure.  claim_out is zeroed on
 * failure.
 */
int voleith_rs_claim_produce(const voleith_rs_config_t *cfg, const uint8_t *id,
                             const uint8_t *rand,
                             voleith_rs_claim_t *claim_out);

/*
 * voleith_rs_claim_verify - check an authorship claim against a
 * signature's bound commitment C.
 *
 * Recomputes tree_hash(id || rand) and compares it constant-time
 * (voleith_const_memcmp) against the node_bytes-wide C the verifier
 * pulled from the claimed signature's public inputs (pub->commitment).  A
 * claim is meaningful only because C was bound into that signature's
 * fs_seed: a correct (id, rand) for a *different* signature's C fails
 * here, giving non-transferability.
 *
 * cfg must enable the commitment module (validated).  C is node_bytes,
 * id is cfg->commit_id_bytes, rand is cfg->commit_rand_bytes.
 *
 * Returns 0 on a valid claim, -1 on NULL argument, disabled commitment
 * module, validation/leaf-hash failure, or a mismatch (wrong id, wrong
 * rand, or C from another signature).
 */
int voleith_rs_claim_verify(const voleith_rs_config_t *cfg, const uint8_t *C,
                            const uint8_t *id, const uint8_t *rand);

/* ================================================================
 * Serialization (RS.SER): "VRSC" envelope around the gf8_proof bytes.
 *
 *   offset  size  field
 *   ------  ----  -----
 *        0     4  magic = "VRSC"
 *        4     1  format_version = 1
 *        5    16  cfg_fingerprint    (voleith_rs_config_fingerprint)
 *       21    16  params_fingerprint (voleith_params_fingerprint)
 *       37     4  gf8_proof_len, big-endian uint32
 *       41   ...  gf8_proof bytes
 *
 * Mirrors the V1 "VRS1" envelope (proof/ring_sig_v1_gf8.h) but binds the
 * composable cfg fingerprint, so a VRSC blob never unpacks under a V1 or
 * mismatched config.
 * ================================================================ */

#define VOLEITH_RS_SIG_MAGIC_0 'V'
#define VOLEITH_RS_SIG_MAGIC_1 'R'
#define VOLEITH_RS_SIG_MAGIC_2 'S'
#define VOLEITH_RS_SIG_MAGIC_3 'C'

#define VOLEITH_RS_SIG_FORMAT_VERSION 1u

#define VOLEITH_RS_SIG_HEADER_BYTES                                            \
    (4u + 1u + VOLEITH_RS_CONFIG_FINGERPRINT_BYTES +                           \
     VOLEITH_PARAMS_FINGERPRINT_BYTES + 4u)

/*
 * voleith_rs_sig_packed_len - total packed length = HEADER_BYTES + sig->len.
 * Returns 0 if sig is NULL.
 */
size_t voleith_rs_sig_packed_len(const voleith_rs_sig_t *sig);

/*
 * voleith_rs_sig_pack - serialize sig into out_buf.
 *
 * Computes cfg/params fingerprints internally; the caller must pass the
 * same cfg / params used at sign time.  out_len must equal
 * voleith_rs_sig_packed_len(sig).  written_out (if non-NULL) receives the
 * byte count written.
 *
 * Returns 0 on success, -1 on NULL arg, sig->data/len inconsistency,
 * sig->len > UINT32_MAX, out_len mismatch, or fingerprint failure.
 */
int voleith_rs_sig_pack(uint8_t *out_buf, size_t out_len, size_t *written_out,
                        const voleith_rs_sig_t *sig,
                        const voleith_rs_config_t *cfg,
                        const voleith_params_t *params);

/*
 * voleith_rs_sig_unpack - parse buf into sig_out.
 *
 * Validates magic, format version, cfg_fingerprint and params_fingerprint
 * (constant-time, against the caller's cfg/params), and the length field.
 * On success sig_out->data is malloc'd (caller frees with
 * voleith_rs_sig_free).  Inner proof bytes are not re-validated here.
 *
 * Returns 0 on success, -1 on NULL arg, short buffer, magic/version
 * mismatch, fingerprint mismatch, length mismatch, or allocation failure.
 * sig_out is zeroed on failure.
 */
int voleith_rs_sig_unpack(voleith_rs_sig_t *sig_out, const uint8_t *buf,
                          size_t buf_len, const voleith_rs_config_t *cfg,
                          const voleith_params_t *params);

#endif /* VOLEITH_RS_GF8_H */
