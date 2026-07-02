/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * rs_leaf_gf8_circuit.h - ring-signature membership leaf over
 * sk [|| attributes].
 *
 * Generalizes the V1 membership leaf (leaf = OWF(sk)) to
 * leaf = OWF(sk || attr_0 || ... || attr_{n-1}) for V3 attribute rings,
 * while staying byte-identical to V1 when attr_total_bytes == 0.  The
 * concatenated preimage is fed to the OWF vt's existing leaf slots, so
 * this layer is hash-agnostic: any voleith_node_hash_vt works, subject
 * to its leaf-input capacity (variable-leaf vts accept any width;
 * fixed-input vts accept up to leaf_block_bytes, see
 * voleith_rs_config_validate).
 *
 * This is the one place V3 cannot reuse the V1 leaf step unchanged: the
 * attribute bytes must enter the same OWF compression as sk (so the leaf
 * node binds them), not a separate hash.
 *
 * See the RS implementation plan (RS.LEAF) for the
 * design and the per-vt leaf-capacity / VOLE-slot cost table.
 */

#ifndef VOLEITH_RS_LEAF_GF8_CIRCUIT_H
#define VOLEITH_RS_LEAF_GF8_CIRCUIT_H

#include "../proof/gf8_circuit.h"
#include "node_hash_vt.h"

#include <stddef.h>
#include <stdint.h>

/*
 * rs_leaf_gf8_build_circuit - emit leaf_node = OWF(sk || attributes).
 *
 * Assembles a contiguous preimage wire array (sk_wires followed by
 * attr_wires; wire IDs only, no value copy) and feeds it to
 * owf_vt->leaf_circuit.  out_leaf_node receives owf_vt->node_bytes wires.
 *
 * When attr_total_bytes == 0 this is exactly the V1 leaf step:
 * owf_vt->leaf_circuit(c, sk_wires, sk_bytes, out_leaf_node) with no
 * intervening reshuffling, so the emitted gate stream is byte-identical
 * to V1.
 *
 *   c                - target circuit.
 *   owf_vt           - the OWF node-hash vt (= cfg's owf_hash ?: tree_hash).
 *   sk_wires         - sk_bytes wire IDs (the secret).  May be NULL only
 *                      if sk_bytes == 0 (not a valid ring, but tolerated
 *                      for symmetry).
 *   sk_bytes         - sk width.
 *   attr_wires       - attr_total_bytes wire IDs (the attribute payload,
 *                      already laid out in schema order by the caller).
 *                      May be NULL iff attr_total_bytes == 0.
 *   attr_total_bytes - summed attribute width (0 = V1 leaf).
 *   out_leaf_node    - owf_vt->node_bytes wires, written by the vt.
 *
 * Returns 0 on success, -1 on a NULL required argument (c, owf_vt,
 * out_leaf_node; sk_wires when sk_bytes > 0; attr_wires when
 * attr_total_bytes > 0), size overflow of the preimage width, or
 * allocation failure for the preimage wire array.
 *
 * Does NOT itself check the preimage against owf_vt->leaf_block_bytes;
 * that is voleith_rs_config_validate's job.  Passing a preimage wider
 * than a fixed-input vt's capacity is a caller error (the vt's
 * leaf_circuit defines the truncation / zero-pad behavior).
 */
int rs_leaf_gf8_build_circuit(voleith_gf8_circuit_t *c,
                              const voleith_node_hash_vt *owf_vt,
                              const gf8_wire_id *sk_wires, size_t sk_bytes,
                              const gf8_wire_id *attr_wires,
                              size_t attr_total_bytes,
                              gf8_wire_id *out_leaf_node);

/*
 * rs_leaf_gf8_invin_bytes - inv_in witness byte count the leaf emits,
 * = owf_vt->leaf_invin_bytes(sk_bytes + attr_total_bytes).
 *
 * Returns 0 if owf_vt is NULL.
 */
size_t rs_leaf_gf8_invin_bytes(const voleith_node_hash_vt *owf_vt,
                               size_t sk_bytes, size_t attr_total_bytes);

/*
 * rs_leaf_gf8_build_witness - compute the leaf inv_in witness over the
 * concatenated preimage sk || attributes.
 *
 * Concatenates sk (sk_bytes) and attrs (attr_total_bytes) into a
 * transient buffer and calls owf_vt->leaf_build_witness on it, writing
 * rs_leaf_gf8_invin_bytes(owf_vt, sk_bytes, attr_total_bytes) bytes to
 * inv_out.
 *
 * Returns 0 on success, -1 on a NULL required argument, size overflow,
 * allocation failure, or propagated vt builder failure.  The transient
 * preimage buffer is securely zeroed before return.
 */
int rs_leaf_gf8_build_witness(const voleith_node_hash_vt *owf_vt,
                              const uint8_t *sk, size_t sk_bytes,
                              const uint8_t *attrs, size_t attr_total_bytes,
                              uint8_t *inv_out);

/*
 * rs_leaf_gf8_hash - software leaf node over the concatenated preimage
 * sk || attributes (test oracle / ring construction).
 *
 * Writes owf_vt->node_bytes bytes to out_node.  Returns 0 on success,
 * -1 on a NULL required argument, size overflow, allocation failure, or
 * propagated vt hash failure.  The transient preimage buffer is securely
 * zeroed before return.
 */
int rs_leaf_gf8_hash(const voleith_node_hash_vt *owf_vt, const uint8_t *sk,
                     size_t sk_bytes, const uint8_t *attrs,
                     size_t attr_total_bytes, uint8_t *out_node);

#endif /* VOLEITH_RS_LEAF_GF8_CIRCUIT_H */
