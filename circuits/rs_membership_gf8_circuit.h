/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * rs_membership_gf8_circuit.h - secret-dir Merkle membership circuit
 * builder.
 *
 * Assembles the GF(2^8) QuickSilver circuit that proves "I know sk
 * such that owf_vt.leaf_hash(sk) sits at some witness leaf index in a
 * Merkle tree whose root is the public membership_root R", per
 * docs/RSV1_DESIGN.md §4.1.
 *
 * The builder is variant-agnostic: it emits ONLY the secret-dir
 * membership (and, when cfg->depth_r > 0, indexed-Merkle non-revocation)
 * branch.  V1 (RSv1) wraps it directly.  Future Vx variants (V2 linkable,
 * V4 claimable, V5 traceable, V7 threshold) call it to lay down the same
 * anonymity baseline then append their own gates after.  V3
 * (attribute-predicate) and V6 (forward-secure) deviate from this
 * membership shape and do not reuse this builder.  See
 * docs/RING_SIGNATURE_DESIGN.md.
 *
 * The circuit is parameterised by voleith_rs_membership_config_t (see
 * proof/rs_membership_gf8.h):
 *
 *   tree_hash - inode hash for the membership path
 *   owf_hash  - one-way function for sk -> leaf_node
 *               (NULL = same vt as tree_hash, the common case)
 *   sk_bytes  - secret-key byte length
 *   depth_m   - membership tree depth
 *   depth_r   - revocation tree depth (0 disables the revocation branch)
 *
 * Wire-declaration order (deterministic in cfg, matching the layout
 * struct returned to the caller; the witness packer relies on this
 * order):
 *
 *   witness section, in declaration order:
 *     1. sk            (sk_bytes wires)
 *     2. dirs          (depth_m wires; secret leaf-index bits, LSB
 *                       first per level)
 *     3. siblings      (depth_m * tree_hash->node_bytes wires,
 *                       leaf-level first; node-bytes per level)
 *     4. owf inv_in    (owf_vt->leaf_invin_bytes(sk_bytes) wires,
 *                       declared internally by owf_vt->leaf_circuit)
 *     5. per-level inode inv_in (tree_hash->inode_invin_bytes() wires
 *                       per level, declared internally by the merkle
 *                       path body)
 *     [iff depth_r > 0: rev_low_value | rev_low_next | rev_next_index |
 *                       rev_dirs | rev_siblings | rev leaf inv_in |
 *                       per-level rev inode inv_in]
 *
 *   instance section, in declaration order:
 *     1. membership_root (tree_hash->node_bytes wires)
 *     [iff depth_r > 0: revocation_root (tree_hash->node_bytes wires)]
 *
 * Siblings are witness, not instance: each member's path has different
 * sibling values, so publishing them would identify the signer and
 * defeat ring anonymity.  Only the root is public.
 *
 * Constraints emitted:
 *   - owf_vt->leaf_circuit's internal inverse-product constraints
 *   - per-level inode_circuit's internal inverse-product constraints
 *   - per-level assert_product(dir, dir, dir) booleanity constraint
 *     (inherited from merkle_vt_gf8_path_from_leaf_node_secret_dir)
 *   - tree_hash->node_bytes assert_equal constraints binding the
 *     computed root to the membership_root instance wires
 *   - when depth_r > 0: the indexed-Merkle non-membership constraints
 *     plus node_bytes assert_equal constraints binding the computed
 *     revocation root to the revocation_root instance wires
 */

#ifndef VOLEITH_RS_MEMBERSHIP_GF8_CIRCUIT_H
#define VOLEITH_RS_MEMBERSHIP_GF8_CIRCUIT_H

#include "../proof/gf8_circuit.h"
#include "../proof/rs_membership_gf8.h"

#include <stddef.h>

/*
 * voleith_rs_membership_build_circuit - emit the secret-dir Merkle
 * membership (and optional non-revocation) circuit.
 *
 * Declares wires in the deterministic order documented in this
 * header's preamble and emits all required gates and constraints, then
 * fills *layout_out with the byte offsets / counts each section landed
 * at.
 *
 * c          - empty (or partially built) circuit to append to.  Wires
 *              declared before this call are NOT counted in the layout
 *              offsets (the offsets are relative to *this* invocation's
 *              first witness / instance byte).  Reuse on a non-empty
 *              circuit is not supported by the witness packer.
 * cfg        - configuration; passed to voleith_rs_membership_validate
 *              before any wire is declared.  Failed validation returns
 *              -1 with no wires added.
 * layout_out - written iff the function returns 0.  Untouched on
 *              failure.
 *
 * Returns 0 on success, -1 on cfg validation failure or internal
 * builder error (e.g. unsupported node_bytes for the merkle path body).
 */
int
voleith_rs_membership_build_circuit(voleith_gf8_circuit_t *c,
                                    const voleith_rs_membership_config_t *cfg,
                                    voleith_rs_membership_layout_t *layout_out);

#endif /* VOLEITH_RS_MEMBERSHIP_GF8_CIRCUIT_H */
