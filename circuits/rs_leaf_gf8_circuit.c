/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * rs_leaf_gf8_circuit.c - ring-signature membership leaf over
 * sk [|| attributes].
 *
 * Thin hash-agnostic wrapper: concatenate sk and the attribute payload
 * into one preimage and drive the OWF vt's existing leaf slots.  See
 * rs_leaf_gf8_circuit.h for the contract.
 */

#include "rs_leaf_gf8_circuit.h"

#include "../core/util.h"

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

int
rs_leaf_gf8_build_circuit(voleith_gf8_circuit_t *c,
                          const voleith_node_hash_vt *owf_vt,
                          const gf8_wire_id *sk_wires, size_t sk_bytes,
                          const gf8_wire_id *attr_wires,
                          size_t attr_total_bytes, gf8_wire_id *out_leaf_node)
{
    gf8_wire_id *pre;
    size_t total;

    if (c == NULL || owf_vt == NULL || out_leaf_node == NULL)
        return -1;
    if (sk_bytes > 0 && sk_wires == NULL)
        return -1;
    if (attr_total_bytes > 0 && attr_wires == NULL)
        return -1;
    if (sk_bytes > SIZE_MAX - attr_total_bytes)
        return -1;

    total = sk_bytes + attr_total_bytes;

    /*
     * attr_total_bytes == 0 is the V1 leaf: hand sk_wires straight to
     * the vt with no copy, so the emitted gate stream is byte-identical
     * to V1 (which calls owf_vt->leaf_circuit(c, sk_wires, sk_bytes, ...)).
     */
    if (attr_total_bytes == 0) {
        owf_vt->leaf_circuit(c, sk_bytes ? sk_wires : NULL, sk_bytes,
                             out_leaf_node);
        return 0;
    }

    /* Wire IDs only (no secret values), so no secure-zero needed. */
    pre = calloc(total, sizeof(*pre));
    if (pre == NULL)
        return -1;

    for (size_t i = 0; i < sk_bytes; i++)
        pre[i] = sk_wires[i];
    for (size_t i = 0; i < attr_total_bytes; i++)
        pre[sk_bytes + i] = attr_wires[i];

    owf_vt->leaf_circuit(c, pre, total, out_leaf_node);

    free(pre);
    return 0;
}

size_t
rs_leaf_gf8_invin_bytes(const voleith_node_hash_vt *owf_vt, size_t sk_bytes,
                        size_t attr_total_bytes)
{
    if (owf_vt == NULL)
        return 0;
    if (sk_bytes > SIZE_MAX - attr_total_bytes)
        return 0;
    return owf_vt->leaf_invin_bytes(sk_bytes + attr_total_bytes);
}

/*
 * Build the transient sk || attrs preimage into *pre_out (caller frees).
 * Returns 0 on success, -1 on bad args / overflow / allocation failure.
 */
static int
assemble_preimage(const uint8_t *sk, size_t sk_bytes, const uint8_t *attrs,
                  size_t attr_total_bytes, uint8_t **pre_out, size_t *total_out)
{
    uint8_t *pre;
    size_t total;

    if (sk_bytes > 0 && sk == NULL)
        return -1;
    if (attr_total_bytes > 0 && attrs == NULL)
        return -1;
    if (sk_bytes > SIZE_MAX - attr_total_bytes)
        return -1;

    total = sk_bytes + attr_total_bytes;
    if (total == 0)
        return -1;

    pre = calloc(total, 1);
    if (pre == NULL)
        return -1;

    if (sk_bytes > 0)
        memcpy(pre, sk, sk_bytes);
    if (attr_total_bytes > 0)
        memcpy(pre + sk_bytes, attrs, attr_total_bytes);

    *pre_out = pre;
    *total_out = total;
    return 0;
}

int
rs_leaf_gf8_build_witness(const voleith_node_hash_vt *owf_vt, const uint8_t *sk,
                          size_t sk_bytes, const uint8_t *attrs,
                          size_t attr_total_bytes, uint8_t *inv_out)
{
    uint8_t *pre = NULL;
    size_t total = 0;
    int rc;

    if (owf_vt == NULL || inv_out == NULL)
        return -1;
    if (assemble_preimage(sk, sk_bytes, attrs, attr_total_bytes, &pre,
                          &total) != 0)
        return -1;

    rc = owf_vt->leaf_build_witness(pre, total, inv_out);

    voleith_secure_zero(pre, total);
    free(pre);
    return rc;
}

int
rs_leaf_gf8_hash(const voleith_node_hash_vt *owf_vt, const uint8_t *sk,
                 size_t sk_bytes, const uint8_t *attrs, size_t attr_total_bytes,
                 uint8_t *out_node)
{
    uint8_t *pre = NULL;
    size_t total = 0;
    int rc;

    if (owf_vt == NULL || out_node == NULL)
        return -1;
    if (assemble_preimage(sk, sk_bytes, attrs, attr_total_bytes, &pre,
                          &total) != 0)
        return -1;

    rc = owf_vt->leaf_hash(pre, total, out_node);

    voleith_secure_zero(pre, total);
    free(pre);
    return rc;
}
