/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * rs_gf8_circuit.h - composable ring-signature circuit builder.
 *
 * voleith_rs_build_circuit emits the superset membership circuit plus
 * each enabled module's branch, in the canonical wire-declaration order
 * of the RS implementation plan §1.3.  It starts from
 * the V1 membership circuit (voleith_rs_membership_build_circuit) and
 * grows one module branch per ticket:
 *
 *   V2.CIRC  (this file): nullifier T = PRF(sk, scope), in-circuit checked.
 *   V2.SPENT: spent-set non-membership on T.
 *   V3.CIRC : leaf over sk || attributes + per-attribute predicates.
 *   V4.CIRC : claimable commitment C = H(id || rand).
 *
 * A config with every module off emits the same layout as the V1
 * builder (still a distinct protocol via the composed fingerprint).
 *
 * The reusable membership data layer (cfg, validate, fingerprint, the
 * membership layout / path / packer) lives in proof/rs_gf8.h and
 * proof/rs_membership_gf8.h.
 */

#ifndef VOLEITH_RS_GF8_CIRCUIT_H
#define VOLEITH_RS_GF8_CIRCUIT_H

#include "../proof/gf8_circuit.h"
#include "../proof/rs_gf8.h"
#include "../proof/rs_membership_gf8.h"

#include <stddef.h>

/* VOLEITH_RS_NULLIFIER_BYTES (the 16-byte AES-CMAC tag width) is defined
 * in proof/rs_gf8.h, included above. */

/*
 * voleith_rs_layout_t - superset witness / instance byte-layout
 * descriptor.
 *
 * Embeds the V1 membership layout (sk / dirs / siblings / owf+path
 * inv_in / revocation offsets and the node_bytes / depth meta) with the
 * same field meanings, and adds a section per enabled module.  Byte
 * offsets are into the flat witness / instance buffers in
 * wire-declaration order; the builder and the (future) packer commit to
 * the same order.
 *
 * membership.witness_bytes / membership.instance_bytes are NOT the
 * superset totals (they would omit module sections); use this struct's
 * witness_bytes / instance_bytes for buffer sizing.  membership's
 * per-section offsets remain correct (computed against the same base),
 * and membership.inst_rev_root_off already accounts for the module
 * instances declared before the revocation root.
 *
 * Module sections are all zero when their module is disabled.  V3 / V4
 * sections are added by their tickets; only the V2 nullifier section
 * exists today.
 */
typedef struct voleith_rs_layout {
    voleith_rs_membership_layout_t membership;

    /* ----- V3 attributes (attr_schema != NULL) --------------------- */
    /* witness: the attribute payload, laid out per field in schema order,
     * declared right after sk (canonical §1.3 step 2).  The membership
     * leaf is OWF(sk || attributes), so owf_invin_bytes already reflects
     * the widened preimage. */
    size_t attr_off;
    size_t attr_bytes; /* = sum of schema field width_bytes */

    /* instance: predicate bounds for fields with pred != NONE, declared
     * after T and before the revocation root (§1.3 step 11).  Laid out in
     * schema order: EQ contributes one width-byte target; RANGE
     * contributes width-byte low then width-byte high; NONE contributes
     * nothing.  Per-field offsets are derived from the schema by walking
     * it from inst_bounds_off (the bounds are public per-signature
     * inputs, so one ring supports varying thresholds). */
    size_t inst_bounds_off;
    size_t inst_bounds_bytes;

    /* ----- V4 claimable commitment (enable_commitment) ------------- */
    /* witness: id || rand (the leaf-preimage handle and blinding), then
     * the commitment leaf-hash inv_in.  id/rand are declared right after
     * membership_root (§1.3 steps 6-7); commit_rand_off ==
     * commit_id_off + commit_id_bytes (they are contiguous). */
    size_t commit_id_off;
    size_t commit_id_bytes;
    size_t commit_rand_off;
    size_t commit_rand_bytes;
    size_t commit_invin_off;
    size_t commit_invin_bytes; /* = tree_vt->leaf_invin_bytes(id + rand) */
    /* instance: C = H(id || rand), declared after membership_root and
     * before scope/T (§1.3 step 8). */
    size_t inst_commit_off;
    size_t inst_commit_bytes; /* = node_bytes */

    /* ----- V2 nullifier (scope_bytes > 0) -------------------------- */
    /* witness: AES-CMAC inv_in for T = CMAC(sk, scope).  The CMAC key is
     * the already-declared sk wires, so only the inv_in (not the key) is
     * declared here, right after the membership path inv_in and before
     * any revocation witnesses. */
    size_t nullifier_invin_off;
    size_t nullifier_invin_bytes; /* = aes_cmac_gf8_n_aes_calls(scope) *
                                   *   (sk_bytes == 16 ? 200 : 276) */

    /* instance: scope (public PRF input) then T (the published nullifier),
     * declared after membership_root and before the revocation root. */
    size_t inst_scope_off;
    size_t inst_scope_bytes; /* = scope_bytes */
    size_t inst_t_off;
    size_t inst_t_bytes; /* = VOLEITH_RS_NULLIFIER_BYTES (16) */

    /* ----- V2 spent-set IMT non-membership on T (depth_s > 0) ------ */
    /* Opt-in (Q4): proves T is not in the spent set at spent_root, so a
     * stateless verifier enforces one-time use in-proof.  Mirrors the
     * revocation branch but the IMT target is the 16-byte nullifier T
     * (value width = VOLEITH_RS_NULLIFIER_BYTES), not the leaf node.
     * Declared after the revocation wires (canonical §1.3 step 13). */
    size_t spent_low_value_off;
    size_t spent_low_value_bytes; /* = VOLEITH_RS_NULLIFIER_BYTES (16) */
    size_t spent_low_next_off;
    size_t spent_low_next_bytes; /* = VOLEITH_RS_NULLIFIER_BYTES (16) */
    size_t spent_next_index_off;
    size_t spent_next_index_bytes; /* = VOLEITH_RSV1_REV_INDEX_BYTES (8) */
    size_t spent_dirs_off;
    size_t spent_dirs_bytes; /* = depth_s */
    size_t spent_siblings_off;
    size_t spent_siblings_bytes; /* = depth_s * node_bytes */
    size_t spent_leaf_invin_off;
    size_t spent_leaf_invin_bytes;
    size_t spent_path_invin_off;
    size_t spent_path_invin_per_level;
    size_t spent_path_invin_bytes;
    size_t inst_spent_root_off;
    size_t inst_spent_root_bytes; /* = node_bytes */
    size_t depth_s;

    /* ----- V6 epoch subtree (depth_e > 0) -------------------------- */
    /* witness: sk_t (epoch seed) declared in sk's slot, then the leaf salt
     * (when configured), the epoch attribute tail is the shared V3 attr
     * wires, the epoch tree siblings, and the epoch leaf / per-level inode
     * inv_in emitted by stage A0.  instance: the depth_e epoch direction
     * bytes (bits of t), declared first (before membership_root). */
    size_t epoch_sk_off;
    size_t epoch_sk_bytes; /* = cfg->epoch_sk_bytes (16 or 32) */
    size_t salt_off;
    size_t salt_bytes; /* = cfg->leaf_salt_bytes (0 = none) */
    size_t epoch_siblings_off;
    size_t epoch_siblings_bytes; /* = depth_e * node_bytes */
    size_t epoch_leaf_invin_off;
    size_t epoch_leaf_invin_bytes; /* = epoch_hash->leaf_invin_bytes(sk_t) */
    size_t epoch_path_invin_off;
    size_t epoch_path_invin_per_level;
    size_t epoch_path_invin_bytes; /* = depth_e * inode_invin */
    size_t inst_epoch_dirs_off;
    size_t inst_epoch_dirs_bytes; /* = depth_e */
    size_t depth_e;

    /* ----- superset totals ----------------------------------------- */
    size_t witness_bytes;
    size_t instance_bytes;
} voleith_rs_layout_t;

/*
 * voleith_rs_build_circuit - emit the superset ring-signature circuit.
 *
 * Declares wires and emits gates in the canonical order (§1.3):
 *
 *   witness:  sk | membership dirs | membership siblings
 *   instance: membership_root [| scope | T (V2)]  [| rev_root]
 *   gates:    leaf = OWF(sk); merkle path; assert computed_root == root;
 *             [V2: T_computed = CMAC(sk, scope); assert == T];
 *             [revocation non-membership branch]
 *
 * The interleaved inv_in witnesses land in emission order: owf leaf,
 * membership path, [V2 nullifier CMAC], [revocation].
 *
 * Modules built so far:
 *   nullifier (cfg->scope_bytes > 0): requires cfg->membership.sk_bytes
 *     in {16, 32} (the AES-CMAC key width).  T width is fixed at 16.
 *   spent-set (cfg->depth_s > 0, opt-in; implies the nullifier): proves
 *     the 16-byte T is not in the spent-set IMT at spent_root, via the
 *     secret-dir indexed non-membership circuit.  The IMT leaf record is
 *     low_value(16) || low_next(16) || next_index(8) = 40 bytes, so the
 *     tree vt's leaf must accept a 40-byte preimage (returns -1 if not,
 *     e.g. hirose_fixed32's 32-byte cap).
 *   attributes (cfg->attr_schema != NULL): the leaf is OWF(sk || attrs)
 *     (via rs_leaf_gf8_build_circuit), and each field with pred != NONE
 *     gets a public bound: EQ asserts byte-equality to a target vector;
 *     RANGE calls assert_in_range_gf8(attr, low, high).  An optional
 *     cfg->custom_predicate callback runs after the built-in pass over
 *     the attribute wires.  Predicate gates add mul gates but no
 *     witnesses; only the attribute payload and the widened leaf inv_in
 *     grow the witness.
 *   epoch (cfg->depth_e > 0, V6 forward secure): stage A0 emits
 *     h_t = epoch_hash->leaf_circuit(sk_t) then walks the epoch tree with
 *     public directions (bits of t on instance wires, slot-free
 *     mux_instance) to epoch_root.  The leaf stage then uses epoch_root in
 *     sk's place: without V3 the ring leaf IS epoch_root; with V3 it is
 *     OWF(epoch_root || attrs || salt).  membership.sk_bytes is 0 (EP.CFG);
 *     when the nullifier is also on, its PRF keys off sk_t (not sk).  All
 *     of this is inert when depth_e == 0, so a non-epoch config yields the
 *     exact 1.8.0 wire/gate stream.
 *   commitment (cfg->enable_commitment): binds a hiding commitment
 *     C = tree_vt->leaf_hash(id || rand) as a public instance, with id
 *     (the leaf-preimage handle shared with the future V5 opener) and
 *     rand (high-entropy blinding) as witnesses.  The gate emits after
 *     the membership root binding and before the nullifier (§1.3 step D).
 *
 * cfg is validated via voleith_rs_config_validate.  Returns 0 on
 * success and fills *layout_out; returns -1 on NULL argument, config
 * validation failure, an unsupported nullifier sk width, node_bytes >
 * MERKLE_VT_MAX_NODE_BYTES, or allocation failure.
 */
int voleith_rs_build_circuit(voleith_gf8_circuit_t *c,
                             const voleith_rs_config_t *cfg,
                             voleith_rs_layout_t *layout_out);

#endif /* VOLEITH_RS_GF8_CIRCUIT_H */
