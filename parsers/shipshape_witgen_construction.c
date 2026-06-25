/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * parsers/shipshape_witgen_construction.c - Tier 2a native witness backends for
 * the crypto-v2 hash-parametric CONSTRUCTION registry entries (W8.5b).
 *
 * Each backend composes the node-hash vt's leaf_build_witness with a per-level
 * inode_build_witness walk to fill a region's INTERNAL inv-witness span:
 *
 *   span = [leaf invs] ++ depth x [inode invs]
 *
 * This is exactly what the generic Tier 1 evaluator (parsers/shipshape_witness.c)
 * fills as it walks the leaf_circuit then the per-level inode_circuit of the
 * vt-driven circuit body, so the output is byte-identical (the equivalence
 * oracle).  The composition mirrors voleith_rs_membership_pack_witness sections
 * 4 and 5 (proof/ring_sig_v1_gf8.c) verbatim.  No new crypto math lives here:
 * the vt method IS the implementation and the equivalence oracle.
 *
 * The secret-dir mux and the per-level assert_product(dir, dir, dir) booleanity
 * check add NO internal witness wires: the direction wire is an external input
 * witness, and the mux / product outputs are mul-gate / derived wires, not
 * witness slots.  The indexed entry's assert_lt comparison likewise emits only
 * const / linear-map / mul / xor / assert gates, none of which introduce a
 * witness slot.  All three internal spans are therefore precisely
 * [leaf invs][inode invs] (confirmed by reading the three circuit builders).
 *
 * Every backend is fail-closed: it re-checks ext, ext_len, the region witness
 * span, and the vt resolution, and returns -1 on any mismatch.  The dispatcher
 * only calls a backend on a confirmed bracketed-name match against a crypto-v2
 * construction region carrying the resolved parameters, so the shape is
 * guaranteed in practice; these checks are belt-and-suspenders.
 *
 * Secret material (leaf / sk / accumulated node bytes) lives only in fixed
 * stack buffers here; each handler secure-zeroes them before return.
 */

#include "shipshape_witgen_construction.h"

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "node_hash_vt.h"
#include "shipshape.h"
#include "shipshape_node_hash_types.h"
#include "shipshape_witgen_dispatch.h"
#include "util.h"

/*
 * Shared inv-witness composer.  Resolves the vt, validates the internal span
 * against [leaf invs][inode invs], then writes the leaf invs followed by the
 * per-level inode invs directly into full[region->first_witness ..].
 *
 *   vt           - resolved node-hash vt (caller resolves; non-NULL).
 *   leaf_data    - leaf record bytes (NULL only when leaf_data_bytes == 0).
 *   siblings     - depth * node_bytes sibling bytes (NULL only when depth == 0).
 *   dirs         - depth direction bytes, each in {0, 1}.
 *
 * Returns 0 on success, -1 on any width / span mismatch or vt-method failure.
 */
static int
compose_leaf_inode_span(const voleith_shipshape_region_t *region,
                        const voleith_node_hash_vt *vt,
                        const uint8_t *leaf_data, size_t leaf_data_bytes,
                        const uint8_t *siblings, const uint8_t *dirs,
                        size_t depth, uint8_t *full)
{
    size_t node_bytes;
    size_t leaf_invin_bytes;
    size_t inode_invin_bytes;
    size_t expected_span;
    size_t off;
    size_t k;
    uint8_t current[MERKLE_VT_MAX_NODE_BYTES];
    uint8_t next[MERKLE_VT_MAX_NODE_BYTES];
    int rc = -1;

    node_bytes = vt->node_bytes;
    if (node_bytes > MERKLE_VT_MAX_NODE_BYTES)
        return -1;

    leaf_invin_bytes = vt->leaf_invin_bytes(leaf_data_bytes);
    inode_invin_bytes = vt->inode_invin_bytes();
    expected_span = leaf_invin_bytes + depth * inode_invin_bytes;
    if (region->n_witness != expected_span)
        return -1;

    /* Section 4 (leaf invs): full[first .. first + leaf_invin_bytes). */
    off = region->first_witness;
    if (vt->leaf_build_witness(leaf_data, leaf_data_bytes, full + off) != 0)
        goto out;
    off += leaf_invin_bytes;

    /* Section 5 (per-level inode invs): walk the path, recomputing the
     * accumulated chain value at each level - the same inode walk the
     * in-circuit body runs (merkle_vt walk_inodes_secret_dir). */
    if (vt->leaf_hash(leaf_data, leaf_data_bytes, current) != 0)
        goto out;

    for (k = 0; k < depth; k++) {
        const uint8_t *sib = siblings + k * node_bytes;
        uint8_t dir = dirs[k];
        const uint8_t *left = dir ? sib : current;
        const uint8_t *right = dir ? current : sib;

        if (vt->inode_build_witness(left, right, full + off) != 0)
            goto out;
        off += inode_invin_bytes;
        if (vt->inode_hash(left, right, next) != 0)
            goto out;
        memcpy(current, next, node_bytes);
    }

    rc = 0;

out:
    voleith_secure_zero(current, sizeof(current));
    voleith_secure_zero(next, sizeof(next));
    return rc;
}

/* ================================================================
 * merkle/path_secret:
 *   (leaf : byte[L], siblings : byte[depth*node], dirs : byte[depth])
 *       -> (root : byte[node])
 *   ext   = leaf(L) | siblings(depth*node) | dirs(depth)
 *   leaf  = ext[0 .. L);  siblings = ext + L;  dirs = ext + L + depth*node
 *   span  = leaf_invin(L) + depth * inode_invin
 * ================================================================ */
static int
witgen_merkle_secret(const voleith_shipshape_region_t *region,
                     const uint8_t *ext, size_t ext_len, uint8_t *full)
{
    const voleith_shipshape_node_hash_type_t *nht;
    const voleith_node_hash_vt *vt;
    size_t node_bytes, depth, leaf_bytes, need;
    const uint8_t *leaf_data;
    const uint8_t *siblings;
    const uint8_t *dirs;

    nht = voleith_shipshape_node_hash_type_by_id(region->cv2_type_id);
    if (nht == NULL || nht->vt == NULL)
        return -1;
    vt = nht->vt;
    node_bytes = vt->node_bytes;

    if (region->cv2_depth_param >= region->cv2_n_params ||
        region->cv2_leaf_param >= region->cv2_n_params)
        return -1;
    depth = region->cv2_params[region->cv2_depth_param];
    leaf_bytes = region->cv2_params[region->cv2_leaf_param];

    need = leaf_bytes + depth * node_bytes + depth;
    if (ext == NULL && need > 0)
        return -1;
    if (ext_len < need)
        return -1;

    leaf_data = (leaf_bytes > 0) ? ext : NULL;
    siblings = ext + leaf_bytes;
    dirs = ext + leaf_bytes + depth * node_bytes;

    return compose_leaf_inode_span(region, vt, leaf_data, leaf_bytes, siblings,
                                   dirs, depth, full);
}

/* ================================================================
 * ring_sig/v1:
 *   (sk : byte[skb], dirs : byte[depth], siblings : byte[depth*node],
 *    root : byte[node])
 *   ext   = sk(skb) | dirs(depth) | siblings(depth*node) | root(node)
 *   leaf  = sk = ext[0 .. skb);  dirs = ext + skb;  siblings = ext + skb + depth
 *   (the trailing root bytes are ignored)
 *   span  = leaf_invin(skb) + depth * inode_invin
 * ================================================================ */
static int
witgen_ring_sig_v1(const voleith_shipshape_region_t *region, const uint8_t *ext,
                   size_t ext_len, uint8_t *full)
{
    const voleith_shipshape_node_hash_type_t *nht;
    const voleith_node_hash_vt *vt;
    size_t node_bytes, depth, sk_bytes, need;
    const uint8_t *leaf_data;
    const uint8_t *siblings;
    const uint8_t *dirs;

    nht = voleith_shipshape_node_hash_type_by_id(region->cv2_type_id);
    if (nht == NULL || nht->vt == NULL)
        return -1;
    vt = nht->vt;
    node_bytes = vt->node_bytes;

    if (region->cv2_depth_param >= region->cv2_n_params ||
        region->cv2_leaf_param >= region->cv2_n_params)
        return -1;
    depth = region->cv2_params[region->cv2_depth_param];
    sk_bytes = region->cv2_params[region->cv2_leaf_param];

    /* ext also carries the trailing root(node) bytes; require them present. */
    need = sk_bytes + depth + depth * node_bytes + node_bytes;
    if (ext == NULL && need > 0)
        return -1;
    if (ext_len < need)
        return -1;

    leaf_data = (sk_bytes > 0) ? ext : NULL;
    dirs = ext + sk_bytes;
    siblings = ext + sk_bytes + depth;

    return compose_leaf_inode_span(region, vt, leaf_data, sk_bytes, siblings,
                                   dirs, depth, full);
}

/* ================================================================
 * indexed_merkle/nonmember_secret:
 *   (target : byte[tb], low : byte[tb], hi : byte[tb], nidx : byte[ib],
 *    siblings : byte[depth*node], dirs : byte[depth], root : byte[node])
 *   ext   = target(tb) | low(tb) | hi(tb) | nidx(ib)
 *           | siblings(depth*node) | dirs(depth) | root(node)
 *   leaf record = low || hi || nidx, contiguous in ext at offset tb:
 *       leaf_data = ext + tb;  leaf_data_bytes = 2*tb + ib
 *   siblings = ext + 3*tb + ib;  dirs = ext + 3*tb + ib + depth*node
 *   span  = leaf_invin(2*tb + ib) + depth * inode_invin
 *
 * cv2_params layout for this entry: [0]=tb, [1]=ib, [2]=depth.
 * cv2_leaf_param == 0 (tb), cv2_depth_param == 2 (depth); both read from the
 * region.  ib is read from cv2_params[1] directly (it has no dedicated role
 * index, the registry signature fixes its position).
 * ================================================================ */
static int
witgen_indexed_secret(const voleith_shipshape_region_t *region,
                      const uint8_t *ext, size_t ext_len, uint8_t *full)
{
    const voleith_shipshape_node_hash_type_t *nht;
    const voleith_node_hash_vt *vt;
    size_t node_bytes, depth, tb, ib, leaf_bytes, need;
    const uint8_t *leaf_data;
    const uint8_t *siblings;
    const uint8_t *dirs;

    nht = voleith_shipshape_node_hash_type_by_id(region->cv2_type_id);
    if (nht == NULL || nht->vt == NULL)
        return -1;
    vt = nht->vt;
    node_bytes = vt->node_bytes;

    if (region->cv2_n_params < 3)
        return -1;
    if (region->cv2_depth_param >= region->cv2_n_params ||
        region->cv2_leaf_param >= region->cv2_n_params)
        return -1;
    tb = region->cv2_params[region->cv2_leaf_param]; /* leaf_param == 0 */
    ib = region->cv2_params[1];
    depth = region->cv2_params[region->cv2_depth_param]; /* depth_param == 2 */

    leaf_bytes = 2 * tb + ib;

    /* ext = target(tb) | low(tb) | hi(tb) | nidx(ib) | siblings | dirs | root */
    need = 3 * tb + ib + depth * node_bytes + depth + node_bytes;
    if (ext == NULL && need > 0)
        return -1;
    if (ext_len < need)
        return -1;

    /* leaf record = low || hi || nidx, contiguous at offset tb. */
    leaf_data = (leaf_bytes > 0) ? ext + tb : NULL;
    siblings = ext + 3 * tb + ib;
    dirs = ext + 3 * tb + ib + depth * node_bytes;

    return compose_leaf_inode_span(region, vt, leaf_data, leaf_bytes, siblings,
                                   dirs, depth, full);
}

/* ================================================================
 * Registration.  Each confirmed construction is registered under the bracketed
 * name "stdlib/crypto/<entry>[<type>]" for every node-hash type, because the
 * composition is vt-generic.  register_construction borrows the name pointer
 * (does NOT copy), so the names live in a static buffer array filled once here.
 * ================================================================ */

typedef struct {
    const char *entry; /* crypto-v2 construction fqn (without bracket) */
    voleith_shipshape_witgen_backend_fn fn;
} witgen_construction_entry_t;

static const witgen_construction_entry_t s_constructions[] = {
    {"stdlib/crypto/merkle/path_secret", witgen_merkle_secret},
    {"stdlib/crypto/ring_sig/v1", witgen_ring_sig_v1},
    {"stdlib/crypto/indexed_merkle/nonmember_secret", witgen_indexed_secret},
};

#define N_CONSTRUCTIONS (sizeof(s_constructions) / sizeof(s_constructions[0]))

/*
 * Static storage for the bracketed names.  register_construction borrows the
 * pointer, so the buffers must outlive every dispatch.  Sized for one name per
 * (construction, node-hash type) pair.  The bound below must be >=
 * voleith_shipshape_node_hash_types_count (10: the append-only type table);
 * register_constructions returns -1 if the live count ever exceeds it.
 */
#define N_NODE_HASH_TYPES_MAX 10u
#define BRACKETED_NAME_MAX 96u

static char s_names[N_CONSTRUCTIONS * N_NODE_HASH_TYPES_MAX]
                   [BRACKETED_NAME_MAX];

int
voleith_shipshape_witgen_register_constructions(void)
{
    size_t ci, ti, slot;
    size_t n_types = voleith_shipshape_node_hash_types_count;

    if (n_types > N_NODE_HASH_TYPES_MAX)
        return -1;

    for (ci = 0; ci < N_CONSTRUCTIONS; ci++) {
        for (ti = 0; ti < n_types; ti++) {
            const char *type_name = voleith_shipshape_node_hash_types[ti].name;
            int n;

            slot = ci * n_types + ti;
            n = snprintf(s_names[slot], BRACKETED_NAME_MAX, "%s[%s]",
                         s_constructions[ci].entry, type_name);
            if (n < 0 || (size_t)n >= BRACKETED_NAME_MAX)
                return -1;

            if (voleith_shipshape_witgen_register_construction(
                    s_names[slot], s_constructions[ci].fn) != 0)
                return -1;
        }
    }
    return 0;
}
