/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * test_rs_opener_oracle_gf8.c - OP.ORACLE: syndrome-backed opener end-to-end.
 *
 * The one opener test that links the REAL libtalos_syndrome as the decap oracle
 * (the other opener tests use a synthetic M and voleith's own software opener).
 * It closes the loop of the designated-opener facility over the shared, frozen
 * (M, s) wire:
 *
 *   1. syndrome_kem_keypair -> (pk = the opener matrix M, sk = the opener key).
 *      pk feeds cfg.opener_pk verbatim; the two libraries agree on the layout.
 *   2. voleith_rs_opener_seal draws a fresh error e, computes s = M*e^T and
 *      tag_ct = id XOR KDF(support); the id is enrolled in a ring leaf via the
 *      opener-aware streaming builder.
 *   3. voleith_rs_sign / voleith_rs_verify: an honest signature verifies.
 *   4. The signature is serialized to VRSC v2 (proof + opener section), then the
 *      opener section (hash_id || s || tag_ct) is unpacked and handed VERBATIM to
 *      syndrome_argus_open under the mandatory SIGNATURE_VERIFIED gate (D1). The
 *      recovered identity equals the enrolled id, and no signature in the corpus
 *      is unopenable (DFR-zero DoD).
 *   5. voleith_rs_opener_verify accepts the signer-side (support, id) witness for
 *      the same tag: the software opener and the real decoder agree on the tuple.
 *
 * Also checks the D1 gate fails closed (an UNVERIFIED gate is rejected before the
 * tag is read). Cheapest circuit at each level (n0=5); marked slow. When
 * libtalos_syndrome is not found at configure time the test builds as a loud
 * SKIP, so the suite still runs (the e2e is REQUIRED at the 1.11.0 release gate).
 */

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifndef VOLEITH_HAVE_SYNDROME

int
main(void)
{
    printf(
        "test_rs_opener_oracle_gf8: SKIP (libtalos_syndrome not found at "
        "configure time; set -DVOLEITH_SYNDROME_ROOT to enable the OP.ORACLE "
        "e2e. REQUIRED for the release gate.)\n");
    return 0;
}

#else /* VOLEITH_HAVE_SYNDROME */

#include "rs_gf8.h"
#include "node_hash_vt.h"
#include "../proof/rs_opener_argus_gf8.h"
#include "../proof/rs_opener_gf8.h"

#include <talos_syndrome.h>

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

/*
 * One end-to-end run at a given (voleith set, syndrome set) pair. tree_hash is
 * the lambda-wide node hash for the ring; params is the matching proof set;
 * kb = key_bytes = lambda/8 = the sk / id / DEM-key width.
 */
static void
run_level(const char *label, voleith_rs_opener_argus_set_t vset,
          syndrome_set_id sset, const voleith_node_hash_vt *tree_hash,
          const voleith_params_t *params, size_t kb)
{
    const voleith_rs_opener_argus_params_t *op =
        voleith_rs_opener_argus_params(vset);
    const voleith_rs_opener_scheme_t *scheme =
        voleith_rs_opener_scheme(VOLEITH_RS_OPENER_SCHEME_ARGUS);
    voleith_rs_config_t cfg;
    voleith_rs_path_t paths[N_MEMBERS], path;
    voleith_rs_public_t pub;
    voleith_rs_sig_t sig = {NULL, 0};
    voleith_rs_ring_builder_t *rb = NULL;
    voleith_rs_sig_packer_t *packer = NULL;
    voleith_rs_sig_unpacker_t *unpacker = NULL;
    uint8_t *pk = NULL, *sk = NULL;
    uint8_t *sks = NULL, *ids = NULL, *root = NULL, *sib = NULL;
    uint8_t *s = NULL, *tag_ct = NULL, *rnd = NULL;
    uint8_t *blob = NULL, *id_out = NULL;
    uint32_t *support = NULL;
    size_t pk_bytes, sk_bytes, Mlen, i, blen = 0, written = 0, tag_len = 0;
    const uint8_t *tag = NULL;
    int rc;

    printf("[%s] voleith set %d <-> syndrome set %d\n", label, (int)vset,
           (int)sset);

    if (op == NULL || scheme == NULL) {
        check("params/scheme resolve", 0);
        return;
    }
    if (!syndrome_set_enabled(sset)) {
        printf("  SKIP: syndrome build lacks this set\n");
        return;
    }

    pk_bytes = syndrome_pk_bytes(sset);
    sk_bytes = syndrome_sk_bytes(sset);
    Mlen = (size_t)(op->n0 - 1u) * op->block_bytes;
    check("voleith M size == syndrome pk size", pk_bytes == Mlen);
    check("op->key_bytes == lambda/8", op->key_bytes == kb);

    pk = malloc(pk_bytes ? pk_bytes : 1);
    sk = malloc(sk_bytes ? sk_bytes : 1);
    sks = calloc(N_MEMBERS * kb, 1);
    ids = calloc(N_MEMBERS * kb, 1);
    root = calloc(kb, 1);
    sib = calloc((size_t)N_MEMBERS * DEPTH_M * kb, 1);
    support = malloc((size_t)op->t * sizeof(uint32_t));
    s = malloc(op->block_bytes);
    tag_ct = malloc(kb);
    rnd = malloc(kb);
    id_out = malloc(op->id_max);
    if (!pk || !sk || !sks || !ids || !root || !sib || !support || !s ||
        !tag_ct || !rnd || !id_out) {
        check("alloc", 0);
        goto done;
    }

    /* Real opener keypair: pk is the shared (M) wire, sk opens. */
    if (syndrome_kem_keypair(sset, pk, sk) != 0) {
        check("syndrome_kem_keypair", 0);
        goto done;
    }

    /* Deterministic member material; leaf 0 carries the traced id. */
    for (i = 0; i < N_MEMBERS * kb; i++) {
        sks[i] = (uint8_t)(0x40u + i);
        ids[i] = (uint8_t)(0xA0u + i);
    }
    for (i = 0; i < kb; i++)
        rnd[i] = (uint8_t)(0x5Au + i);

    memset(&cfg, 0, sizeof(cfg));
    cfg.membership.tree_hash = tree_hash;
    cfg.membership.sk_bytes = kb;
    cfg.membership.depth_m = DEPTH_M;
    cfg.enable_opener = 1;
    cfg.opener_set = vset;
    cfg.opener_pk = pk;
    cfg.opener_pk_bytes = pk_bytes;

    /* Seal member 0's identity against the REAL M. */
    if (voleith_rs_opener_seal(&cfg, rnd, kb, ids, kb, support, s, tag_ct) !=
        0) {
        check("opener_seal", 0);
        goto done;
    }

    /* Enroll every member (leaf 0 = the sealed id) via the opener-aware ring. */
    if (voleith_rs_ring_build_init(&rb, &cfg, N_MEMBERS, root, paths, sib) !=
        0) {
        check("ring_build_init", 0);
        goto done;
    }
    for (i = 0; i < N_MEMBERS; i++) {
        if (voleith_rs_ring_member_begin(rb) != 0 ||
            voleith_rs_ring_member_set(rb, VOLEITH_RS_LEAF_FIELD_SK,
                                       sks + i * kb, kb) != 0 ||
            voleith_rs_ring_member_set(rb, VOLEITH_RS_LEAF_FIELD_ID,
                                       ids + i * kb, kb) != 0 ||
            voleith_rs_ring_member_end(rb) != 0) {
            voleith_rs_ring_build_free(rb);
            rb = NULL;
            check("ring member enroll", 0);
            goto done;
        }
    }
    if (voleith_rs_ring_build_final(rb) != 0) { /* consumes rb */
        rb = NULL;
        check("ring_build_final", 0);
        goto done;
    }
    rb = NULL;

    memset(&path, 0, sizeof(path));
    path.membership = paths[0].membership;
    path.opener_support = support;
    path.commit_id = ids; /* leaf id (Q8: opener id rides commit_id) */
    memset(&pub, 0, sizeof(pub));
    pub.membership_root = root;
    pub.opener_s = s;
    pub.opener_tag_ct = tag_ct;

    {
        const uint8_t msg[] = "OP.ORACLE end-to-end";
        size_t msg_len = sizeof(msg) - 1;

        check("honest sign ok",
              voleith_rs_sign(&sig, &cfg, params, sks, NULL, &path, &pub, msg,
                              msg_len) == 0);
        check("honest verify accepts",
              voleith_rs_verify(&sig, &cfg, params, &pub, msg, msg_len) == 0);
        if (sig.data == NULL)
            goto done;

        /* Serialize to VRSC v2: proof + opener section. */
        if (voleith_rs_sig_pack_init(&packer, &cfg, params,
                                     VOLEITH_RS_SIG_FORMAT_AUTO) != 0 ||
            voleith_rs_sig_pack_proof(packer, &sig) != 0 ||
            voleith_rs_sig_pack_opener(packer, &pub) != 0) {
            check("v2 pack (proof+opener)", 0);
            goto done;
        }
        blen = voleith_rs_sig_pack_len(packer);
        blob = malloc(blen ? blen : 1);
        if (blob == NULL) {
            check("blob alloc", 0);
            goto done;
        }
        if (voleith_rs_sig_pack_final(packer, blob, blen, &written) != 0) {
            packer = NULL; /* final frees on success and failure */
            check("v2 pack_final", 0);
            goto done;
        }
        packer = NULL;
        check("v2 blob written", written == blen && blen > 0);

        /* Unpack the opener section: hash_id || s || tag_ct, zero-copy. */
        if (voleith_rs_sig_unpack_init(&unpacker, blob, blen, &cfg, params) !=
            0) {
            check("v2 unpack_init", 0);
            goto done;
        }
        if (voleith_rs_sig_unpack_opener(unpacker, &tag, &tag_len) != 0) {
            check("v2 unpack_opener", 0);
            goto done;
        }
        check("tag length = 1 + block_bytes + key_bytes",
              tag_len == 1u + op->block_bytes + kb);
    }

    /* D1 gate fails closed: an unverified gate is rejected before the tag. */
    rc = syndrome_argus_open(sset, id_out, kb, tag, tag_len, sk,
                             SYNDROME_ARGUS_TAG_UNVERIFIED);
    check("open rejects UNVERIFIED gate (EARGS)", rc == SYNDROME_ARGUS_EARGS);

    /* The real decap oracle recovers exactly the enrolled identity. */
    memset(id_out, 0, op->id_max);
    rc = syndrome_argus_open(sset, id_out, kb, tag, tag_len, sk,
                             SYNDROME_ARGUS_TAG_SIGNATURE_VERIFIED);
    check("open OK under SIGNATURE_VERIFIED gate", rc == SYNDROME_ARGUS_OK);
    check("no decode failure over the corpus (DFR-zero)",
          rc != SYNDROME_ARGUS_EUNOPENABLE);
    check("recovered id == enrolled id",
          rc == SYNDROME_ARGUS_OK && memcmp(id_out, ids, kb) == 0);

    /* Cross-check: voleith's software opener accepts the same (support, id). */
    {
        voleith_rs_opener_witness_t w;

        voleith_rs_opener_argus_witness(&w, support);
        check("voleith_rs_opener_verify accepts the tuple",
              voleith_rs_opener_verify(scheme, (uint32_t)vset, pk, tag, tag_len,
                                       &w, ids, kb) == VOLEITH_RS_OPENER_OK);
    }

done:
    if (rb != NULL)
        voleith_rs_ring_build_free(rb);
    if (packer != NULL)
        voleith_rs_sig_pack_free(packer);
    if (unpacker != NULL)
        voleith_rs_sig_unpack_free(unpacker);
    voleith_rs_sig_free(&sig);
    free(pk);
    free(sk);
    free(sks);
    free(ids);
    free(root);
    free(sib);
    free(support);
    free(s);
    free(tag_ct);
    free(rnd);
    free(id_out);
    free(blob);
}

int
main(void)
{
    printf("test_rs_opener_oracle_gf8 (OP.ORACLE syndrome-backed e2e)\n");
    run_level("lambda128", VOLEITH_RS_OPENER_ARGUS_SET_128_5,
              SYNDROME_SET_128_5, &voleith_node_hash_aes_dm,
              &voleith_params_em_128f, 16);
    run_level("lambda256", VOLEITH_RS_OPENER_ARGUS_SET_256_5,
              SYNDROME_SET_256_5, &voleith_node_hash_grostl256,
              &voleith_params_em_256f, 32);
    printf("\n%d/%d passed\n", pass_count, test_count);
    return (pass_count == test_count) ? 0 : 1;
}

#endif /* VOLEITH_HAVE_SYNDROME */
