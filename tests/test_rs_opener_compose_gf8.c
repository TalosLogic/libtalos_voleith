/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * test_rs_opener_compose_gf8.c - OP.TEST composition matrix for the V5
 * designated opener.
 *
 * Confirms the opener composes with the other modules through the shared
 * voleith_rs_sign / voleith_rs_verify path, and that the opener id, the V4
 * commitment id, and the leaf preimage id are one and the same wire (Q8):
 *
 *   V5+V4  the signer binds a claimable commitment C = H(id || rand) AND a
 *          tracing tag whose DEM wraps the SAME id; the claim opens with (id,
 *          rand) and the opener recovers that id.  A commit_id_bytes != key_bytes
 *          config is rejected at validate (Q8 width contract).
 *   V5+V2  a scope nullifier T = CMAC(sk, scope) and the tracing tag coexist;
 *          two signatures under one scope carry the same T (linkable) and both
 *          open to the same id.
 *   V5+V6  the opener over the forward-secure epoch tree: ring leaf =
 *          OWF(epoch_root || id), sign at two epochs from one state, opener
 *          recovers the SAME enrolled id from both.
 *   V5+V3  validate-only: the opener id widens the leaf preimage, so a fixed-cap
 *          OWF (hirose_fixed32) rejects the config while a multi-block OP.VT vt
 *          (grostl256_fixed) accepts it.
 *
 * The opener side is checked with voleith_rs_opener_verify (software opener; the
 * real libtalos_syndrome decode path is tests/test_rs_opener_oracle_gf8.c).
 * Set 128_5, aes-dm tree (V5+V4/V2/V6), lambda = 128; marked slow.
 *
 * Carry-forward (not here): the byte-exact KAT pins (cfg-fingerprint / fs_seed /
 * VRSC v2), batched into OP.REL per the DEFERRED KATs list.
 */

#include "aes_cmac_gf8_circuit.h"
#include "merkle_vt_gf8_helpers.h"
#include "node_hash_vt.h"
#include "rs_epoch_gf8.h"
#include "rs_gf8.h"
#include "rs_leaf_gf8_circuit.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int test_count = 0;
static int pass_count = 0;

static void
check(const char *name, int cond)
{
    test_count++;
    if (cond)
        pass_count++;
    else
        printf("  FAIL: %s\n", name);
}

#define N_MEMBERS 4
#define DEPTH_M 2
#define KB 16 /* key_bytes = lambda/8 at 128_5 */

/* Shared context for one composition: a 4-member ring whose leaf `signer`
 * carries the sealed opener id. */
struct ctx {
    voleith_rs_config_t cfg;
    const voleith_rs_opener_argus_params_t *op;
    const voleith_rs_opener_scheme_t *scheme;
    uint8_t M[4096]; /* >= (n0-1)*block_bytes = 4*979 = 3916 at 128_5 */
    size_t Mlen;
    uint8_t sks[N_MEMBERS * KB];
    uint8_t ids[N_MEMBERS * KB];
    uint8_t root[KB];
    uint8_t sib[(size_t)N_MEMBERS * DEPTH_M * KB];
    voleith_rs_path_t paths[N_MEMBERS];
    /* per-signature opener artifacts */
    uint32_t support[512];
    uint8_t s[3916];
    uint8_t tag_ct[KB];
    uint8_t tag[1 + 3916 + KB];
    size_t tag_len;
};

static const size_t signer = 2;

/* Build the opener-aware ring: leaf i = OWF(sk_i || id_i), signer carries the
 * sealed id.  Leaves the paths / root / siblings in the ctx. */
static int
build_ring(struct ctx *c)
{
    voleith_rs_ring_builder_t *b = NULL;
    size_t i;

    if (voleith_rs_ring_build_init(&b, &c->cfg, N_MEMBERS, c->root, c->paths,
                                   c->sib) != 0)
        return -1;
    for (i = 0; i < N_MEMBERS; i++) {
        if (voleith_rs_ring_member_begin(b) != 0 ||
            voleith_rs_ring_member_set(b, VOLEITH_RS_LEAF_FIELD_SK,
                                       c->sks + i * KB, KB) != 0 ||
            voleith_rs_ring_member_set(b, VOLEITH_RS_LEAF_FIELD_ID,
                                       c->ids + i * KB, KB) != 0 ||
            voleith_rs_ring_member_end(b) != 0) {
            voleith_rs_ring_build_free(b);
            return -1;
        }
    }
    return voleith_rs_ring_build_final(b); /* consumes b */
}

/* Assemble the tracing tag = prim_default || s || tag_ct from the sealed
 * artifacts (what OP.SER emits and the opener consumes). */
static void
assemble_tag(struct ctx *c)
{
    c->tag[0] = c->op->prim_default;
    memcpy(c->tag + 1, c->s, c->op->block_bytes);
    memcpy(c->tag + 1 + c->op->block_bytes, c->tag_ct, KB);
    c->tag_len = 1u + c->op->block_bytes + KB;
}

/* Common init: opener cfg + real-shape (public) M + member material + a sealed
 * id for `signer`.  Extra module fields are set by the caller before build. */
static int
ctx_init(struct ctx *c)
{
    uint8_t rnd[KB];
    size_t i;

    memset(c, 0, sizeof(*c));
    c->op = voleith_rs_opener_argus_params(VOLEITH_RS_OPENER_ARGUS_SET_128_5);
    c->scheme = voleith_rs_opener_scheme(VOLEITH_RS_OPENER_SCHEME_ARGUS);
    if (c->op == NULL || c->scheme == NULL)
        return -1;
    c->Mlen = (size_t)(c->op->n0 - 1u) * c->op->block_bytes;
    if (c->Mlen > sizeof(c->M) || c->op->block_bytes > sizeof(c->s) ||
        c->op->t > (uint32_t)(sizeof(c->support) / sizeof(c->support[0])) ||
        c->op->key_bytes != KB)
        return -1;
    for (i = 0; i < c->Mlen; i++)
        c->M[i] = (uint8_t)(0x9eu * (unsigned)i + 0x37u);
    for (i = 0; i < sizeof(c->sks); i++)
        c->sks[i] = (uint8_t)(0x40u + i);
    for (i = 0; i < sizeof(c->ids); i++)
        c->ids[i] = (uint8_t)(0xA0u + i);
    for (i = 0; i < KB; i++)
        rnd[i] = (uint8_t)(0x5Au + i);

    c->cfg.membership.tree_hash = &voleith_node_hash_aes_dm;
    c->cfg.membership.sk_bytes = KB;
    c->cfg.membership.depth_m = DEPTH_M;
    c->cfg.enable_opener = 1;
    c->cfg.opener_set = VOLEITH_RS_OPENER_ARGUS_SET_128_5;
    c->cfg.opener_pk = c->M;
    c->cfg.opener_pk_bytes = c->Mlen;

    if (voleith_rs_opener_seal(&c->cfg, rnd, KB, c->ids + signer * KB, KB,
                               c->support, c->s, c->tag_ct) != 0)
        return -1;
    assemble_tag(c);
    return 0;
}

/* --- V5 + V4: claimable commitment sharing the opener id (Q8) ------------- */

static void
test_v5_v4_shared_id(void)
{
    voleith_params_t params = voleith_params_em_128f;
    struct ctx c;
    const uint8_t *id;
    uint8_t rand[KB];
    voleith_rs_claim_t claim;
    voleith_rs_path_t path;
    voleith_rs_public_t pub;
    voleith_rs_sig_t sig = {NULL, 0};
    voleith_rs_opener_witness_t w;
    const uint8_t m[] = "V5+V4 compose";
    size_t m_len = sizeof(m) - 1, i;

    if (ctx_init(&c) != 0) {
        check("v5+v4: ctx init", 0);
        return;
    }
    id = c.ids + signer * KB;
    for (i = 0; i < KB; i++)
        rand[i] = (uint8_t)(0x21u + i);

    c.cfg.enable_commitment = 1;
    c.cfg.commit_id_bytes = KB;
    c.cfg.commit_rand_bytes = KB;

    /* Q8 width contract: a commit_id_bytes != key_bytes config is rejected. */
    check("v5+v4: matched commit_id_bytes validates",
          voleith_rs_config_validate(&c.cfg) == 0);
    c.cfg.commit_id_bytes = KB - 1;
    check("v5+v4: mismatched commit_id_bytes rejected at validate",
          voleith_rs_config_validate(&c.cfg) != 0);
    c.cfg.commit_id_bytes = KB;

    if (voleith_rs_claim_produce(&c.cfg, id, rand, &claim) != 0) {
        check("v5+v4: claim_produce", 0);
        return;
    }
    if (build_ring(&c) != 0) {
        check("v5+v4: ring build", 0);
        return;
    }

    memset(&path, 0, sizeof(path));
    path.membership = c.paths[signer].membership;
    path.opener_support = c.support;
    path.commit_id = id; /* the SAME id feeds leaf, commitment, and DEM */
    path.commit_rand = rand;
    memset(&pub, 0, sizeof(pub));
    pub.membership_root = c.root;
    pub.commitment = claim.commitment;
    pub.opener_s = c.s;
    pub.opener_tag_ct = c.tag_ct;

    check("v5+v4: sign ok",
          voleith_rs_sign(&sig, &c.cfg, &params, c.sks + signer * KB, NULL,
                          &path, &pub, m, m_len) == 0);
    check("v5+v4: verify accepts",
          voleith_rs_verify(&sig, &c.cfg, &params, &pub, m, m_len) == 0);

    /* Same id opens BOTH facilities: the claim and the tracing tag. */
    check("v5+v4: claim opens with (id, rand)",
          voleith_rs_claim_verify(&c.cfg, claim.commitment, id, rand) == 0);
    voleith_rs_opener_argus_witness(&w, c.support);
    check("v5+v4: opener recovers the same id",
          voleith_rs_opener_verify(
              c.scheme, (uint32_t)VOLEITH_RS_OPENER_ARGUS_SET_128_5, c.M, c.tag,
              c.tag_len, &w, id, KB) == VOLEITH_RS_OPENER_OK);
    /* A different id opens neither. */
    {
        uint8_t other[KB];

        memcpy(other, id, KB);
        other[0] ^= 0xFFu;
        check("v5+v4: claim rejects a wrong id",
              voleith_rs_claim_verify(&c.cfg, claim.commitment, other, rand) !=
                  0);
        check("v5+v4: opener rejects a wrong id",
              voleith_rs_opener_verify(
                  c.scheme, (uint32_t)VOLEITH_RS_OPENER_ARGUS_SET_128_5, c.M,
                  c.tag, c.tag_len, &w, other,
                  KB) == VOLEITH_RS_OPENER_EIDENTITY);
    }

    voleith_rs_sig_free(&sig);
}

/* --- V5 + V2: scope nullifier alongside the tracing tag ------------------- */

static void
test_v5_v2_nullifier(void)
{
    voleith_params_t params = voleith_params_em_128f;
    struct ctx c;
    const size_t scope_bytes = 12;
    uint8_t scope[12], T[16];
    uint8_t *cmac_tmp = NULL;
    const uint8_t *id, *sk;
    voleith_rs_path_t path;
    voleith_rs_public_t pub;
    voleith_rs_sig_t sig1 = {NULL, 0}, sig2 = {NULL, 0};
    voleith_rs_opener_witness_t w;
    const uint8_t m1[] = "V5+V2 sig one";
    const uint8_t m2[] = "V5+V2 sig two";
    size_t i;

    if (ctx_init(&c) != 0) {
        check("v5+v2: ctx init", 0);
        return;
    }
    id = c.ids + signer * KB;
    sk = c.sks + signer * KB;
    for (i = 0; i < scope_bytes; i++)
        scope[i] = (uint8_t)(0x90u + i);

    c.cfg.scope_bytes = scope_bytes;
    if (voleith_rs_config_validate(&c.cfg) != 0) {
        check("v5+v2: validate", 0);
        return;
    }

    /* Nullifier T = AES-CMAC(sk, scope). */
    cmac_tmp = malloc(aes_cmac_gf8_witness_bytes(KB, scope_bytes));
    if (cmac_tmp == NULL) {
        check("v5+v2: alloc", 0);
        return;
    }
    aes_cmac_gf8_build_witness(sk, KB, scope, scope_bytes, cmac_tmp, T);
    free(cmac_tmp);

    if (build_ring(&c) != 0) {
        check("v5+v2: ring build", 0);
        return;
    }

    memset(&path, 0, sizeof(path));
    path.membership = c.paths[signer].membership;
    path.opener_support = c.support;
    path.commit_id = id;
    path.scope = scope;
    memset(&pub, 0, sizeof(pub));
    pub.membership_root = c.root;
    pub.scope = scope;
    pub.nullifier = T;
    pub.opener_s = c.s;
    pub.opener_tag_ct = c.tag_ct;

    /* Two signatures under the SAME scope: both verify, same nullifier T. */
    check("v5+v2: sign #1 ok",
          voleith_rs_sign(&sig1, &c.cfg, &params, sk, NULL, &path, &pub, m1,
                          sizeof(m1) - 1) == 0);
    check("v5+v2: sign #2 ok",
          voleith_rs_sign(&sig2, &c.cfg, &params, sk, NULL, &path, &pub, m2,
                          sizeof(m2) - 1) == 0);
    check("v5+v2: verify #1", voleith_rs_verify(&sig1, &c.cfg, &params, &pub,
                                                m1, sizeof(m1) - 1) == 0);
    check("v5+v2: verify #2", voleith_rs_verify(&sig2, &c.cfg, &params, &pub,
                                                m2, sizeof(m2) - 1) == 0);
    /* Linkability: the nullifier is the same public T for both (a spent-set
     * verifier would reject the second). */
    {
        uint8_t T2[16];
        uint8_t *tmp2 = malloc(aes_cmac_gf8_witness_bytes(KB, scope_bytes));

        if (tmp2 != NULL) {
            aes_cmac_gf8_build_witness(sk, KB, scope, scope_bytes, tmp2, T2);
            free(tmp2);
            check("v5+v2: same scope -> same nullifier (linkable)",
                  memcmp(T, T2, 16) == 0);
        } else {
            check("v5+v2: nullifier recompute alloc", 0);
        }
    }

    /* The opener still traces both to the enrolled id. */
    voleith_rs_opener_argus_witness(&w, c.support);
    check("v5+v2: opener recovers the enrolled id",
          voleith_rs_opener_verify(
              c.scheme, (uint32_t)VOLEITH_RS_OPENER_ARGUS_SET_128_5, c.M, c.tag,
              c.tag_len, &w, id, KB) == VOLEITH_RS_OPENER_OK);

    voleith_rs_sig_free(&sig1);
    voleith_rs_sig_free(&sig2);
}

/* --- V5 + V6: designated opener over the forward-secure epoch tree --------
 *
 * Each member is an identity with its own GGM epoch tree; under V5 its ring leaf
 * is OWF(epoch_root || id) (V6-alone would use the bare epoch root).  The signer
 * seals a fresh tracing tag per signature and signs at two epochs from one state
 * (t=0 covers both); the opener recovers the SAME enrolled id from both. */
static void
test_v5_v6_epoch(void)
{
    voleith_params_t params = voleith_params_em_128f;
    const voleith_node_hash_vt *vt = &voleith_node_hash_aes_dm;
    const voleith_rs_opener_argus_params_t *op =
        voleith_rs_opener_argus_params(VOLEITH_RS_OPENER_ARGUS_SET_128_5);
    const voleith_rs_opener_scheme_t *scheme =
        voleith_rs_opener_scheme(VOLEITH_RS_OPENER_SCHEME_ARGUS);
    const size_t depth_e = 3; /* 8 epochs per identity */
    const size_t W = vt->node_bytes;
    voleith_rs_config_t cfg;
    voleith_rs_epoch_state_t signer_state;
    voleith_rs_path_t path;
    voleith_rs_public_t pub;
    voleith_rs_opener_witness_t w0, w5;
    voleith_rs_sig_t sig0 = {NULL, 0}, sig5 = {NULL, 0};
    uint8_t M[4096];
    uint8_t ids[N_MEMBERS * KB];
    uint8_t *leaves = NULL, *msibs = NULL;
    uint8_t root[MERKLE_VT_MAX_NODE_BYTES] = {0};
    uint8_t epoch_root[MERKLE_VT_MAX_NODE_BYTES];
    /* two fresh seals (epoch 0 and epoch 5) wrapping the same enrolled id */
    uint32_t sup0[512], sup5[512];
    uint8_t s0[3916], s5[3916], t0[KB], t5[KB];
    uint8_t tag0[1 + 3916 + KB], tag5[1 + 3916 + KB], rnd[KB];
    size_t Mlen, tag_len, i;
    const uint8_t *id;
    const uint8_t m[] = "V5+V6 compose";
    size_t m_len = sizeof(m) - 1;
    int have_state = 0;

    memset(&signer_state, 0, sizeof(signer_state));
    if (op == NULL || scheme == NULL || W > MERKLE_VT_MAX_NODE_BYTES) {
        check("v5+v6: params", 0);
        return;
    }
    Mlen = (size_t)(op->n0 - 1u) * op->block_bytes;
    if (Mlen > sizeof(M) || op->block_bytes > sizeof(s0) ||
        op->key_bytes != KB) {
        check("v5+v6: sizes", 0);
        return;
    }
    for (i = 0; i < Mlen; i++)
        M[i] = (uint8_t)(0x9eu * (unsigned)i + 0x37u);
    for (i = 0; i < sizeof(ids); i++)
        ids[i] = (uint8_t)(0xA0u + i);
    id = ids + signer * KB;
    tag_len = 1u + op->block_bytes + KB;

    memset(&cfg, 0, sizeof(cfg));
    cfg.membership.tree_hash = vt;
    cfg.membership.sk_bytes = 0; /* V6: leaf secret is the epoch seed sk_t */
    cfg.membership.depth_m = DEPTH_M;
    cfg.depth_e = depth_e;
    cfg.epoch_sk_bytes = 16;
    cfg.enable_opener = 1;
    cfg.opener_set = VOLEITH_RS_OPENER_ARGUS_SET_128_5;
    cfg.opener_pk = M;
    cfg.opener_pk_bytes = Mlen;
    if (voleith_rs_config_validate(&cfg) != 0) {
        check("v5+v6: config validates", 0);
        return;
    }

    leaves = calloc(N_MEMBERS, W);
    msibs = calloc(DEPTH_M, W);
    if (leaves == NULL || msibs == NULL) {
        check("v5+v6: alloc", 0);
        goto done;
    }

    /* Enroll: per member, keygen its epoch tree, then ring leaf =
     * OWF(epoch_root || id).  Keep only the signer's forward-secure state. */
    for (i = 0; i < N_MEMBERS; i++) {
        uint8_t master[64];
        voleith_rs_epoch_state_t tmp;
        size_t j;

        for (j = 0; j < cfg.epoch_sk_bytes; j++)
            master[j] = (uint8_t)(i * 37u + j * 11u + 0x05u);
        memset(&tmp, 0, sizeof(tmp));
        if (voleith_rs_epoch_keygen(&cfg, master, NULL /* no salt */,
                                    i == signer ? &signer_state : &tmp,
                                    epoch_root) != 0) {
            if (i != signer)
                voleith_rs_epoch_state_clear(&tmp);
            check("v5+v6: epoch keygen", 0);
            goto done;
        }
        if (i == signer)
            have_state = 1;
        if (rs_leaf_gf8_hash(vt, epoch_root, W, ids + i * KB, KB,
                             leaves + i * W) != 0) {
            if (i != signer)
                voleith_rs_epoch_state_clear(&tmp);
            check("v5+v6: leaf hash", 0);
            goto done;
        }
        if (i != signer)
            voleith_rs_epoch_state_clear(&tmp);
    }
    if (voleith_merkle_vt_build(vt, leaves, N_MEMBERS, root) != 0 ||
        voleith_merkle_vt_compute_path(vt, leaves, N_MEMBERS, signer, msibs) !=
            0) {
        check("v5+v6: membership tree", 0);
        goto done;
    }

    /* Two fresh seals of the same enrolled id. */
    for (i = 0; i < KB; i++)
        rnd[i] = (uint8_t)(0x11u + i);
    if (voleith_rs_opener_seal(&cfg, rnd, KB, id, KB, sup0, s0, t0) != 0) {
        check("v5+v6: seal epoch 0", 0);
        goto done;
    }
    for (i = 0; i < KB; i++)
        rnd[i] = (uint8_t)(0x83u + i);
    if (voleith_rs_opener_seal(&cfg, rnd, KB, id, KB, sup5, s5, t5) != 0) {
        check("v5+v6: seal epoch 5", 0);
        goto done;
    }
    tag0[0] = tag5[0] = op->prim_default;
    memcpy(tag0 + 1, s0, op->block_bytes);
    memcpy(tag0 + 1 + op->block_bytes, t0, KB);
    memcpy(tag5 + 1, s5, op->block_bytes);
    memcpy(tag5 + 1 + op->block_bytes, t5, KB);

    memset(&path, 0, sizeof(path));
    path.membership.leaf_index = signer;
    path.membership.siblings = msibs;
    path.commit_id = id; /* opener id in the leaf tail (Q2/Q8) */
    memset(&pub, 0, sizeof(pub));
    pub.membership_root = root;

    /* Sign at epoch 0. */
    path.opener_support = sup0;
    pub.opener_s = s0;
    pub.opener_tag_ct = t0;
    pub.epoch = 0;
    check("v5+v6: epoch_sign @0 ok",
          voleith_rs_epoch_sign(&sig0, &signer_state, &cfg, &params, NULL,
                                &path, &pub, m, m_len) == 0);
    check("v5+v6: verify @0",
          voleith_rs_verify(&sig0, &cfg, &params, &pub, m, m_len) == 0);

    /* Sign at epoch 5 from the same (unadvanced) state. */
    path.opener_support = sup5;
    pub.opener_s = s5;
    pub.opener_tag_ct = t5;
    pub.epoch = 5;
    check("v5+v6: epoch_sign @5 ok",
          voleith_rs_epoch_sign(&sig5, &signer_state, &cfg, &params, NULL,
                                &path, &pub, m, m_len) == 0);
    check("v5+v6: verify @5",
          voleith_rs_verify(&sig5, &cfg, &params, &pub, m, m_len) == 0);

    /* The opener recovers the SAME enrolled id from both epochs' tags. */
    voleith_rs_opener_argus_witness(&w0, sup0);
    voleith_rs_opener_argus_witness(&w5, sup5);
    check("v5+v6: opener recovers id @0",
          voleith_rs_opener_verify(
              scheme, (uint32_t)VOLEITH_RS_OPENER_ARGUS_SET_128_5, M, tag0,
              tag_len, &w0, id, KB) == VOLEITH_RS_OPENER_OK);
    check("v5+v6: opener recovers id @5",
          voleith_rs_opener_verify(
              scheme, (uint32_t)VOLEITH_RS_OPENER_ARGUS_SET_128_5, M, tag5,
              tag_len, &w5, id, KB) == VOLEITH_RS_OPENER_OK);

done:
    voleith_rs_sig_free(&sig0);
    voleith_rs_sig_free(&sig5);
    if (have_state)
        voleith_rs_epoch_state_clear(&signer_state);
    free(leaves);
    free(msibs);
}

/* --- V5 + V3: opener id widens the leaf preimage past a fixed-cap OWF -------
 *
 * Validate-only (fast).  The leaf preimage is sk || attrs || id; the capacity
 * check (voleith_rs_config_validate) counts the opener id.  With one 16-byte
 * attribute the preimage is 48 B with the opener on, 32 B off, so hirose_fixed32
 * (32 B cap) rejects the opener config but accepts the same attrs without the
 * opener, while a multi-block OP.VT vt (grostl256_fixed, 128 B cap) accepts it. */
static void
test_v5_v3_capacity(void)
{
    const voleith_rs_opener_argus_params_t *op =
        voleith_rs_opener_argus_params(VOLEITH_RS_OPENER_ARGUS_SET_128_5);
    voleith_rs_attr_field_t field = {16, VOLEITH_RS_ATTR_PRED_NONE};
    voleith_rs_attr_schema_t schema = {&field, 1};
    voleith_rs_config_t cfg;
    uint8_t *M = NULL;
    size_t Mlen;

    if (op == NULL) {
        check("v5+v3: params", 0);
        return;
    }
    Mlen = (size_t)(op->n0 - 1u) * op->block_bytes;
    M = calloc(Mlen ? Mlen : 1, 1);
    if (M == NULL) {
        check("v5+v3: alloc", 0);
        return;
    }

    memset(&cfg, 0, sizeof(cfg));
    cfg.membership.sk_bytes = 16;
    cfg.membership.depth_m = DEPTH_M;
    cfg.attr_schema = &schema;
    cfg.enable_opener = 1;
    cfg.opener_set = VOLEITH_RS_OPENER_ARGUS_SET_128_5;
    cfg.opener_pk = M;
    cfg.opener_pk_bytes = Mlen;

    /* hirose_fixed32 (cap 32): 16 + 16 + 16 = 48 > 32 -> rejected. */
    cfg.membership.tree_hash = &voleith_node_hash_hirose_fixed32;
    check("v5+v3: opener preimage overflows hirose_fixed32 (reject)",
          voleith_rs_config_validate(&cfg) != 0);

    /* grostl256_fixed (multi-block OP.VT vt, cap 128): 48 <= 128 -> accepted. */
    cfg.membership.tree_hash = &voleith_node_hash_grostl256_fixed;
    check("v5+v3: capacity vt accepts the opener preimage",
          voleith_rs_config_validate(&cfg) == 0);

    /* Same attrs without the opener: preimage 32 == cap -> accepted, so the
     * opener id is exactly what tipped it over. */
    cfg.membership.tree_hash = &voleith_node_hash_hirose_fixed32;
    cfg.enable_opener = 0;
    cfg.opener_pk = NULL;
    cfg.opener_pk_bytes = 0;
    check("v5+v3: same attrs fit hirose_fixed32 without the opener",
          voleith_rs_config_validate(&cfg) == 0);

    free(M);
}

int
main(void)
{
    printf("test_rs_opener_compose_gf8 (OP.TEST V5 composition matrix)\n");
    test_v5_v4_shared_id();
    test_v5_v2_nullifier();
    test_v5_v6_epoch();
    test_v5_v3_capacity();
    printf("\n%d/%d passed\n", pass_count, test_count);
    return (pass_count == test_count) ? 0 : 1;
}
