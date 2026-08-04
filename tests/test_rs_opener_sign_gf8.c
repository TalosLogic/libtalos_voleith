/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * test_rs_opener_sign_gf8.c - OP.SIGN full sign / verify roundtrip for the V5
 * designated opener.
 *
 * Drives the whole signer path: voleith_rs_opener_seal (fresh e -> support, s,
 * tag_ct), the streaming ring builder with the opener id in the leaf, then
 * voleith_rs_sign / voleith_rs_verify at real proof parameters.  An honest
 * signature verifies; tampering with the message, s, tag_ct, or the enrolled id
 * rejects; a non-canonical s is rejected by the boundary check; and two
 * signatures by the same member carry distinct, unlinkable (s, tag_ct) while
 * keeping identical proof length.  Smallest shipped set (128_5); marked slow.
 */
#include "rs_gf8.h"

#include "node_hash_vt.h"

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

/* Shared fixture: opener cfg + a 4-member ring whose leaf 0 carries id0. */
struct fixture {
    voleith_rs_config_t cfg;
    const voleith_rs_opener_argus_params_t *op;
    uint8_t *M;
    size_t Mlen;
    uint8_t sks[N_MEMBERS * 16];
    uint8_t ids[N_MEMBERS * 16];
    uint8_t root[16];
    uint8_t sib[N_MEMBERS * DEPTH_M * 16];
    voleith_rs_path_t paths[N_MEMBERS];
};

/* Build the ring with per-member (sk, id) leaves via the streaming builder.
 * id_override != NULL replaces leaf 0's id (to force a sign-time mismatch). */
static int
build_ring(struct fixture *f, const uint8_t *id_override)
{
    voleith_rs_ring_builder_t *b = NULL;
    size_t i;

    if (voleith_rs_ring_build_init(&b, &f->cfg, N_MEMBERS, f->root, f->paths,
                                   f->sib) != 0)
        return -1;
    for (i = 0; i < N_MEMBERS; i++) {
        const uint8_t *id = f->ids + i * 16;

        if (i == 0 && id_override != NULL)
            id = id_override;
        if (voleith_rs_ring_member_begin(b) != 0 ||
            voleith_rs_ring_member_set(b, VOLEITH_RS_LEAF_FIELD_SK,
                                       f->sks + i * 16, 16) != 0 ||
            voleith_rs_ring_member_set(b, VOLEITH_RS_LEAF_FIELD_ID, id, 16) !=
                0 ||
            voleith_rs_ring_member_end(b) != 0) {
            voleith_rs_ring_build_free(b);
            return -1;
        }
    }
    return voleith_rs_ring_build_final(b); /* consumes b */
}

static int
fixture_init(struct fixture *f)
{
    size_t i;

    memset(f, 0, sizeof(*f));
    f->op = voleith_rs_opener_argus_params(VOLEITH_RS_OPENER_ARGUS_SET_128_5);
    if (f->op == NULL)
        return -1;
    f->Mlen = (size_t)(f->op->n0 - 1u) * f->op->block_bytes;
    f->M = malloc(f->Mlen);
    if (f->M == NULL)
        return -1;
    for (i = 0; i < f->Mlen; i++)
        f->M[i] = (uint8_t)(0x9eu * (unsigned)i + 0x37u);
    for (i = 0; i < sizeof(f->sks); i++)
        f->sks[i] = (uint8_t)(0x40 + i);
    for (i = 0; i < sizeof(f->ids); i++)
        f->ids[i] = (uint8_t)(0xA0 + i);

    f->cfg.membership.tree_hash = &voleith_node_hash_aes_dm;
    f->cfg.membership.sk_bytes = 16;
    f->cfg.membership.depth_m = DEPTH_M;
    f->cfg.enable_opener = 1;
    f->cfg.opener_set = VOLEITH_RS_OPENER_ARGUS_SET_128_5;
    f->cfg.opener_pk = f->M;
    f->cfg.opener_pk_bytes = f->Mlen;
    return 0;
}

static void
test_opener_sign_roundtrip(void)
{
    voleith_params_t params = voleith_params_em_128f;
    struct fixture f;
    uint32_t *support = NULL;
    uint8_t *s = NULL, *tag = NULL;
    uint8_t rnd[16];
    voleith_rs_path_t path;
    voleith_rs_public_t pub;
    voleith_rs_sig_t sig = {NULL, 0};
    const uint8_t m[] = "opener sign roundtrip";
    size_t m_len = sizeof(m) - 1, i;

    if (fixture_init(&f) != 0) {
        check("opener-sign: fixture", 0);
        return;
    }
    support = malloc((size_t)f.op->t * 4);
    s = malloc(f.op->block_bytes);
    tag = malloc(f.op->key_bytes);
    if (!support || !s || !tag) {
        check("opener-sign: alloc", 0);
        goto done;
    }
    for (i = 0; i < 16; i++)
        rnd[i] = (uint8_t)(0x5Au + i);

    /* Seal member 0's identity, then enroll it in the ring leaf. */
    if (voleith_rs_opener_seal(&f.cfg, rnd, 16, f.ids, 16, support, s, tag) !=
        0) {
        check("opener-sign: seal", 0);
        goto done;
    }
    if (build_ring(&f, NULL) != 0) {
        check("opener-sign: ring build", 0);
        goto done;
    }

    memset(&path, 0, sizeof(path));
    path.membership = f.paths[0].membership;
    path.opener_support = support;
    path.commit_id = f.ids; /* leaf id (Q8: opener id rides commit_id) */
    memset(&pub, 0, sizeof(pub));
    pub.membership_root = f.root;
    pub.opener_s = s;
    pub.opener_tag_ct = tag;

    check("opener-sign: honest sign ok",
          voleith_rs_sign(&sig, &f.cfg, &params, f.sks, NULL, &path, &pub, m,
                          m_len) == 0);
    check("opener-sign: honest verify accepts",
          voleith_rs_verify(&sig, &f.cfg, &params, &pub, m, m_len) == 0);

    /* Tampered message. */
    {
        uint8_t bad[sizeof(m)];

        memcpy(bad, m, m_len);
        bad[0] ^= 0x01u;
        check("opener-sign: tampered m rejects",
              voleith_rs_verify(&sig, &f.cfg, &params, &pub, bad, m_len) == -1);
    }

    /* Tampered public s (flip a valid bit: still canonical, wrong value). */
    s[0] ^= 0x01u;
    check("opener-sign: tampered s rejects",
          voleith_rs_verify(&sig, &f.cfg, &params, &pub, m, m_len) == -1);
    s[0] ^= 0x01u;

    /* Tampered tag_ct. */
    tag[0] ^= 0x01u;
    check("opener-sign: tampered tag_ct rejects",
          voleith_rs_verify(&sig, &f.cfg, &params, &pub, m, m_len) == -1);
    tag[0] ^= 0x01u;

    /* Non-canonical s: set a top pad bit of the last block byte (p not a
     * multiple of 8 for the shipped sets), rejected by the boundary check. */
    if ((f.op->p & 7u) != 0) {
        uint8_t save = s[f.op->block_bytes - 1];

        s[f.op->block_bytes - 1] |= (uint8_t)(1u << (f.op->p & 7u));
        check("opener-sign: non-canonical s rejects",
              voleith_rs_verify(&sig, &f.cfg, &params, &pub, m, m_len) == -1);
        s[f.op->block_bytes - 1] = save;
    }

    /* Honest verify still accepts after restoring every field. */
    check("opener-sign: verify accepts again after restore",
          voleith_rs_verify(&sig, &f.cfg, &params, &pub, m, m_len) == 0);

    voleith_rs_sig_free(&sig);

    /* Enrolled-id mismatch: seal binds f.ids[0], but leaf 0 carries a different
     * id, so the in-circuit DEM (tag_ct == K XOR leaf_id) fails at sign. */
    {
        uint8_t other[16];

        for (i = 0; i < 16; i++)
            other[i] = (uint8_t)(f.ids[i] ^ 0xFFu);
        if (build_ring(&f, other) != 0) {
            check("opener-sign: ring rebuild (id mismatch)", 0);
            goto done;
        }
        path.membership = f.paths[0].membership;
        path.commit_id = other; /* leaf carries `other`; seal bound f.ids[0] */
        pub.membership_root = f.root;
        check("opener-sign: enrolled-id mismatch rejected at sign",
              voleith_rs_sign(&sig, &f.cfg, &params, f.sks, NULL, &path, &pub,
                              m, m_len) == -1);
        voleith_rs_sig_free(&sig);
    }

done:
    voleith_rs_sig_free(&sig);
    free(f.M);
    free(support);
    free(s);
    free(tag);
}

/* Two signatures by the same member with fresh randomness: distinct, unlinkable
 * (s, tag_ct); both verify; equal proof length (signer-independent size). */
static void
test_opener_anonymity_smoke(void)
{
    voleith_params_t params = voleith_params_em_128f;
    struct fixture f;
    uint32_t *supA = NULL, *supB = NULL;
    uint8_t *sA = NULL, *sB = NULL, *tA = NULL, *tB = NULL;
    uint8_t rndA[16], rndB[16];
    voleith_rs_path_t path;
    voleith_rs_public_t pubA, pubB;
    voleith_rs_sig_t sigA = {NULL, 0}, sigB = {NULL, 0};
    const uint8_t m[] = "opener anonymity";
    size_t m_len = sizeof(m) - 1, i;

    if (fixture_init(&f) != 0) {
        check("opener-anon: fixture", 0);
        return;
    }
    supA = malloc((size_t)f.op->t * 4);
    supB = malloc((size_t)f.op->t * 4);
    sA = malloc(f.op->block_bytes);
    sB = malloc(f.op->block_bytes);
    tA = malloc(f.op->key_bytes);
    tB = malloc(f.op->key_bytes);
    if (!supA || !supB || !sA || !sB || !tA || !tB) {
        check("opener-anon: alloc", 0);
        goto done;
    }
    for (i = 0; i < 16; i++) {
        rndA[i] = (uint8_t)(0x01u + i);
        rndB[i] = (uint8_t)(0x81u + i);
    }
    if (voleith_rs_opener_seal(&f.cfg, rndA, 16, f.ids, 16, supA, sA, tA) !=
            0 ||
        voleith_rs_opener_seal(&f.cfg, rndB, 16, f.ids, 16, supB, sB, tB) !=
            0) {
        check("opener-anon: seals", 0);
        goto done;
    }
    check("opener-anon: distinct s across signatures",
          memcmp(sA, sB, f.op->block_bytes) != 0);
    check("opener-anon: distinct tag_ct across signatures",
          memcmp(tA, tB, f.op->key_bytes) != 0);

    /* Both signatures need leaf 0 to carry f.ids[0]; either seal's tag_ct opens
     * to the same enrolled id, so one ring serves both. */
    if (build_ring(&f, NULL) != 0) {
        check("opener-anon: ring build", 0);
        goto done;
    }
    memset(&path, 0, sizeof(path));
    path.membership = f.paths[0].membership;
    path.commit_id = f.ids; /* leaf id (Q8: opener id rides commit_id) */
    memset(&pubA, 0, sizeof(pubA));
    pubA.membership_root = f.root;
    pubB = pubA;

    path.opener_support = supA;
    pubA.opener_s = sA;
    pubA.opener_tag_ct = tA;
    check("opener-anon: sign A ok",
          voleith_rs_sign(&sigA, &f.cfg, &params, f.sks, NULL, &path, &pubA, m,
                          m_len) == 0);

    path.opener_support = supB;
    pubB.opener_s = sB;
    pubB.opener_tag_ct = tB;
    check("opener-anon: sign B ok",
          voleith_rs_sign(&sigB, &f.cfg, &params, f.sks, NULL, &path, &pubB, m,
                          m_len) == 0);

    check("opener-anon: verify A",
          voleith_rs_verify(&sigA, &f.cfg, &params, &pubA, m, m_len) == 0);
    check("opener-anon: verify B",
          voleith_rs_verify(&sigB, &f.cfg, &params, &pubB, m, m_len) == 0);
    check("opener-anon: proof length independent of randomness",
          sigA.len == sigB.len);

done:
    voleith_rs_sig_free(&sigA);
    voleith_rs_sig_free(&sigB);
    free(f.M);
    free(supA);
    free(supB);
    free(sA);
    free(sB);
    free(tA);
    free(tB);
}

int
main(void)
{
    printf("test_rs_opener_sign_gf8 (OP.SIGN full sign/verify, set 128_5)\n");
    test_opener_sign_roundtrip();
    test_opener_anonymity_smoke();
    printf("\n%d/%d passed\n", pass_count, test_count);
    return (pass_count == test_count) ? 0 : 1;
}
