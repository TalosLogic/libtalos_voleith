/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * test_rs_opener_e2e_gf8.c - OP.CIRC.4 full consistent-tuple eval.
 *
 * Builds the complete opener circuit (membership + syndrome + KDF + DEM),
 * packs the witness and instance with voleith_rs_pack_witness /
 * voleith_rs_pack_instance, and clear-domain evals it against the OP.SYN
 * software helpers (voleith_rs_opener_argus_syndrome / _kdf) as ground truth:
 * a consistent (id, support, s, tag_ct) tuple must accept, and a wrong s bit /
 * wrong tag_ct / malformed support must reject.  Uses the smallest shipped set
 * (128_5); marked slow.
 */

#include "rs_gf8.h"
#include "rs_gf8_circuit.h"
#include "rs_leaf_gf8_circuit.h"
#include "merkle_vt_gf8_helpers.h"
#include "node_hash_vt.h"
#include "gf8_circuit.h"
#include "../proof/rs_opener_argus_gf8.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

static int test_count = 0;
static int pass_count = 0;

static void
check(const char *name, int cond)
{
    test_count++;
    if (cond) {
        pass_count++;
        printf("  ok   %s\n", name);
    } else {
        printf("  FAIL %s\n", name);
    }
}

/* tamper: 0 honest, 1 flip an s bit, 2 flip tag_ct, 3 malformed support. */
static int
run_eval(int tamper)
{
    const voleith_node_hash_vt *vt = &voleith_node_hash_aes_dm;
    const voleith_rs_opener_argus_set_t set = VOLEITH_RS_OPENER_ARGUS_SET_128_5;
    const voleith_rs_opener_argus_params_t *op =
        voleith_rs_opener_argus_params(set);
    const size_t n_leaves = 4; /* depth_m = 2 */
    size_t Mlen;
    uint8_t *M = NULL;
    uint32_t *support = NULL;
    uint8_t *s_packed = NULL;
    uint8_t sk[16], id[16], K[16], tag_ct[16];
    uint8_t leaves[4 * 16], root[16], siblings[2 * 16];
    voleith_rs_config_t cfg;
    voleith_rs_layout_t L;
    voleith_gf8_circuit_t *c = NULL;
    uint8_t *witness = NULL, *instance = NULL, *wire_vals = NULL;
    voleith_rs_path_t path;
    voleith_rs_public_t pub;
    int res = -1;
    size_t i;
    uint32_t stride;

    if (op == NULL)
        return -1;
    Mlen = (size_t)(op->n0 - 1u) * op->block_bytes;
    M = malloc(Mlen);
    support = malloc((size_t)op->t * sizeof(uint32_t));
    s_packed = malloc(op->block_bytes);
    if (M == NULL || support == NULL || s_packed == NULL)
        goto done;

    for (i = 0; i < 16; i++) {
        sk[i] = (uint8_t)(0x40 + i);
        id[i] = (uint8_t)(0xA0 + i);
    }
    for (i = 0; i < Mlen; i++)
        M[i] = (uint8_t)(0x9eu * (unsigned)i + 0x37u);
    stride = op->n / op->t;
    for (i = 0; i < op->t; i++)
        support[i] = (uint32_t)(i * stride); /* ascending distinct in [0, n) */
    if (tamper == 3)
        support[1] = support[0]; /* duplicate: not strictly ascending */

    /* s + tag_ct from the OP.SYN software helpers (ground truth). */
    if (voleith_rs_opener_argus_syndrome(op, s_packed, M, support) != 0)
        goto done;
    if (voleith_rs_opener_argus_kdf(op, K, op->prim_default, support) != 0)
        goto done;
    for (i = 0; i < 16; i++)
        tag_ct[i] = (uint8_t)(K[i] ^ id[i]);

    /* Opener leaf = OWF(sk || id); a 4-leaf tree; path for leaf 0. */
    memset(leaves, 0, sizeof(leaves));
    if (rs_leaf_gf8_hash(vt, sk, 16, id, 16, leaves) != 0)
        goto done;
    for (i = 1; i < n_leaves; i++)
        leaves[i * 16] = (uint8_t)(0x11u * i);
    if (voleith_merkle_vt_build(vt, leaves, n_leaves, root) != 0)
        goto done;
    if (voleith_merkle_vt_compute_path(vt, leaves, n_leaves, 0, siblings) != 0)
        goto done;

    memset(&cfg, 0, sizeof(cfg));
    cfg.membership.tree_hash = vt;
    cfg.membership.sk_bytes = 16;
    cfg.membership.depth_m = 2;
    cfg.enable_opener = 1;
    cfg.opener_set = set;
    cfg.opener_pk = M;
    cfg.opener_pk_bytes = Mlen;

    c = voleith_gf8_circuit_new();
    if (voleith_rs_build_circuit(c, &cfg, &L) != 0)
        goto done;

    witness = calloc(L.witness_bytes ? L.witness_bytes : 1, 1);
    instance = calloc(L.instance_bytes ? L.instance_bytes : 1, 1);
    if (witness == NULL || instance == NULL)
        goto done;

    memset(&path, 0, sizeof(path));
    path.membership.leaf_index = 0;
    path.membership.siblings = siblings;
    path.opener_support = support;
    if (voleith_rs_pack_witness(&cfg, &L, sk, NULL, &path, id, NULL, witness) !=
        0)
        goto done;

    memset(&pub, 0, sizeof(pub));
    pub.membership_root = root;
    pub.opener_s = s_packed;
    pub.opener_tag_ct = tag_ct;
    if (voleith_rs_pack_instance(&cfg, &L, &pub, instance) != 0)
        goto done;

    if (tamper == 1)
        instance[L.inst_opener_s_off] ^= 1u; /* flip s bit 0 */
    if (tamper == 2)
        instance[L.inst_opener_tag_ct_off] ^= 1u; /* flip tag_ct byte 0 */

    wire_vals = malloc(voleith_gf8_circuit_wire_count(c));
    if (wire_vals == NULL)
        goto done;
    res = voleith_gf8_circuit_eval(c, witness, instance, wire_vals);
    if (res != 1 && res != 0)
        res = -1;

done:
    free(M);
    free(support);
    free(s_packed);
    free(witness);
    free(instance);
    free(wire_vals);
    if (c != NULL)
        voleith_gf8_circuit_free(c);
    return res;
}

int
main(void)
{
    printf("test_rs_opener_e2e_gf8 (OP.CIRC.4 full tuple, set 128_5)\n");
    check("honest (id, support, s, tag_ct) accepts", run_eval(0) == 1);
    check("wrong s bit rejects", run_eval(1) == 0);
    check("wrong tag_ct rejects", run_eval(2) == 0);
    check("malformed support (duplicate) rejects", run_eval(3) == 0);
    printf("\n%d/%d passed\n", pass_count, test_count);
    return (pass_count == test_count) ? 0 : 1;
}
