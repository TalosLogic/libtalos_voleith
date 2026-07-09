/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * test_erasure_rs_retriever.c - retriever-side sufficiency flow
 * (erasure/rs_retriever.c, plan T6.6).
 *
 * Builds a real dataset (RS-encode a message, FWK-blind the chunk tree, issue
 * certificates), then drives the retriever: duplicates do not advance the
 * distinct count, a tampered chunk is rejected, k distinct verified chunks
 * decode to the original message, and (secret-index) identical-content chunks
 * at different indices are both counted via dedup-by-recovered-index.
 */

#include "rs_retriever.h"

#include "rs.h"
#include "rs_chunk_cert_proof.h"
#include "rs_membership.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int tests_run = 0;
static int tests_passed = 0;

#define TEST(name)                                                             \
    do {                                                                       \
        tests_run++;                                                           \
        printf("  %-52s ", name);                                              \
    } while (0)

#define PASS()                                                                 \
    do {                                                                       \
        tests_passed++;                                                        \
        printf("[PASS]\n");                                                    \
    } while (0)

#define FAIL(msg)                                                              \
    do {                                                                       \
        printf("[FAIL] %s\n", msg);                                            \
    } while (0)

struct ds {
    voleith_rs_cr_profile_t cr;
    size_t n, k, cb, W, digb, fwkb, depth;
    uint8_t fwk[32];
    uint8_t *message; /* k * cb */
    voleith_rs_t rs;
    int rs_init;
    uint8_t *codeword; /* n * cb */
    uint8_t *digests;  /* n * digb */
    uint8_t root[64];
    uint8_t R[64];
    uint8_t *siblings; /* n * depth * W */
    voleith_rs_metadata_t meta;
};

static int
ds_init(struct ds *d, voleith_rs_cr_profile_t cr, size_t n, size_t k, size_t cb,
        int identical01)
{
    const voleith_node_hash_vt *vt = voleith_rs_chunk_node_vt(cr);

    memset(d, 0, sizeof(*d));
    d->cr = cr;
    d->n = n;
    d->k = k;
    d->cb = cb;
    d->W = vt->node_bytes;
    d->digb = voleith_rs_cr_digest_bytes(cr);
    d->fwkb = voleith_rs_fwk_bytes(cr);
    d->depth = voleith_rs_tree_depth_for_n(n);

    for (size_t i = 0; i < d->fwkb; i++)
        d->fwk[i] = (uint8_t)(0x42 + i);

    d->message = calloc(k, cb);
    d->codeword = calloc(n, cb);
    d->digests = calloc(n, d->digb);
    if (d->message == NULL || d->codeword == NULL || d->digests == NULL)
        return -1;

    for (size_t i = 0; i < k; i++)
        for (size_t j = 0; j < cb; j++)
            d->message[i * cb + j] = (uint8_t)(i * 17u + j + 5u);
    if (identical01 && k >= 2)
        memcpy(d->message + cb, d->message, cb);

    if (voleith_rs_init(&d->rs, n, k, VOLEITH_EC_MATRIX_CAUCHY) !=
        VOLEITH_EC_OK)
        return -1;
    d->rs_init = 1;
    if (voleith_rs_encode(&d->rs, d->message, cb, d->codeword) != VOLEITH_EC_OK)
        return -1;

    for (size_t i = 0; i < n; i++)
        if (voleith_rs_chunk_digest(cr, d->codeword + i * cb, cb,
                                    d->digests + i * d->digb,
                                    d->digb) != VOLEITH_EC_OK)
            return -1;

    if (voleith_rs_tree_root(cr, d->fwk, d->digests, n, d->root,
                             sizeof(d->root)) != VOLEITH_EC_OK)
        return -1;

    if (d->depth > 0) {
        d->siblings = calloc(n, d->depth * d->W);
        if (d->siblings == NULL)
            return -1;
        for (size_t i = 0; i < n; i++)
            if (voleith_rs_tree_sibling_path(cr, d->fwk, d->digests, n, i,
                                             d->siblings + i * d->depth * d->W,
                                             d->depth * d->W) != VOLEITH_EC_OK)
                return -1;
    }

    d->meta.cr_profile = cr;
    d->meta.chunk_size = (uint32_t)cb;
    d->meta.file_len = (uint64_t)k * cb;
    d->meta.n = (uint16_t)n;
    d->meta.k = (uint16_t)k;
    d->meta.whole_file_digest = NULL;
    d->meta.attr_restriction = NULL;
    d->meta.attr_restriction_len = 0;
    d->meta.por_params = NULL;
    d->meta.por_params_len = 0;

    if (voleith_rs_compute_R(d->root, d->W, &d->meta, d->R, sizeof(d->R)) !=
        VOLEITH_EC_OK)
        return -1;
    return 0;
}

static void
ds_free(struct ds *d)
{
    free(d->message);
    free(d->codeword);
    free(d->digests);
    free(d->siblings);
    if (d->rs_init)
        voleith_rs_free(&d->rs);
}

static const uint8_t *
ds_sib(const struct ds *d, size_t i)
{
    return d->depth > 0 ? d->siblings + i * d->depth * d->W : NULL;
}

static int
prove_cert(const struct ds *d, const voleith_params_t *params, size_t i,
           int secret, voleith_proof_t *out)
{
    const uint8_t *digest = d->digests + i * d->digb;
    const uint8_t *sib = ds_sib(d, i);

    if (secret)
        return voleith_rs_chunk_cert_prove_secret_dir(out, params, d->cr, d->n,
                                                      i, d->fwk, digest,
                                                      d->root, sib, &d->meta);
    return voleith_rs_chunk_cert_prove(out, params, d->cr, d->n, i, d->fwk,
                                       digest, d->root, sib, &d->meta);
}

static void
test_public(void)
{
    voleith_params_t params = voleith_params_em_128f;
    struct ds d;
    voleith_rs_retriever_t r;
    voleith_proof_t certs[2];
    voleith_rs_chunk_disposition_t disp;
    uint8_t *msg_out = NULL;
    uint8_t bad[16];
    int ok = 0;
    size_t n = 4, k = 2, cb = 16, i;

    for (i = 0; i < 2; i++) {
        certs[i].data = NULL;
        certs[i].len = 0;
    }

    TEST("public: dedup / reject / decode (CR-128 n=4 k=2)");

    if (ds_init(&d, VOLEITH_RS_CR_128, n, k, cb, 0) != 0) {
        FAIL("ds_init");
        ds_free(&d);
        return;
    }
    if (voleith_rs_retriever_init(&r, d.cr, &params, VOLEITH_EC_MATRIX_CAUCHY,
                                  0, d.root, d.R, d.W, &d.meta, NULL) != 0) {
        FAIL("retriever_init");
        ds_free(&d);
        return;
    }

    /* k distinct chunks, all accepted. */
    for (i = 0; i < k; i++) {
        if (prove_cert(&d, &params, i, 0, &certs[i]) != 0) {
            FAIL("prove");
            goto cleanup;
        }
        if (voleith_rs_retriever_offer(&r, d.codeword + i * cb, cb, &certs[i],
                                       i, NULL, &disp) != 0 ||
            disp != VOLEITH_RS_CHUNK_ACCEPTED) {
            FAIL("offer accept");
            goto cleanup;
        }
    }
    if (voleith_rs_retriever_distinct(&r) != k ||
        !voleith_rs_retriever_have_enough(&r) ||
        voleith_rs_retriever_need_more(&r) != 0) {
        FAIL("count after k");
        goto cleanup;
    }

    /* Duplicate (same chunk again) does not advance the count. */
    if (voleith_rs_retriever_offer(&r, d.codeword, cb, &certs[0], 0, NULL,
                                   &disp) != 0 ||
        disp != VOLEITH_RS_CHUNK_DUPLICATE ||
        voleith_rs_retriever_distinct(&r) != k) {
        FAIL("duplicate");
        goto cleanup;
    }

    /* Tampered bytes (digest no longer matches the cert) are rejected. */
    memcpy(bad, d.codeword + 1 * cb, cb);
    bad[0] ^= 0xff;
    if (voleith_rs_retriever_offer(&r, bad, cb, &certs[1], 1, NULL, &disp) !=
            0 ||
        disp != VOLEITH_RS_CHUNK_REJECTED ||
        voleith_rs_retriever_distinct(&r) != k) {
        FAIL("reject tampered");
        goto cleanup;
    }

    /* k distinct chunks decode to the original message. */
    msg_out = calloc(k, cb);
    if (msg_out == NULL) {
        FAIL("oom");
        goto cleanup;
    }
    if (voleith_rs_retriever_decode(&r, msg_out, k * cb) != 0 ||
        memcmp(msg_out, d.message, k * cb) != 0) {
        FAIL("decode");
        goto cleanup;
    }

    ok = 1;

cleanup:
    voleith_rs_retriever_free(&r);
    for (i = 0; i < 2; i++)
        voleith_proof_free(&certs[i]);
    free(msg_out);
    ds_free(&d);
    if (ok)
        PASS();
}

static void
test_secret_identical(void)
{
    voleith_params_t params = voleith_params_em_128f;
    struct ds d;
    voleith_rs_retriever_t r;
    voleith_proof_t certs[2];
    voleith_rs_chunk_disposition_t disp;
    uint8_t *msg_out = NULL;
    int ok = 0;
    size_t n = 4, k = 2, cb = 16, i;

    for (i = 0; i < 2; i++) {
        certs[i].data = NULL;
        certs[i].len = 0;
    }

    TEST("secret: identical-content dedup-by-index / decode");

    /* Chunks 0 and 1 have identical content (and thus identical digests). */
    if (ds_init(&d, VOLEITH_RS_CR_128, n, k, cb, 1) != 0) {
        FAIL("ds_init");
        ds_free(&d);
        return;
    }
    if (memcmp(d.digests, d.digests + d.digb, d.digb) != 0) {
        FAIL("setup: chunks 0,1 not identical");
        ds_free(&d);
        return;
    }
    if (voleith_rs_retriever_init(&r, d.cr, &params, VOLEITH_EC_MATRIX_CAUCHY,
                                  1, d.root, d.R, d.W, &d.meta, d.fwk) != 0) {
        FAIL("retriever_init");
        ds_free(&d);
        return;
    }

    /* Offer chunks 0 and 1 (identical bytes): both distinct by recovered index,
     * so the count reaches 2 rather than collapsing them to one. */
    for (i = 0; i < k; i++) {
        if (prove_cert(&d, &params, i, 1, &certs[i]) != 0) {
            FAIL("prove_secret");
            goto cleanup;
        }
        if (voleith_rs_retriever_offer(&r, d.codeword + i * cb, cb, &certs[i],
                                       0, ds_sib(&d, i), &disp) != 0 ||
            disp != VOLEITH_RS_CHUNK_ACCEPTED ||
            voleith_rs_retriever_distinct(&r) != i + 1) {
            FAIL("offer accept (identical content)");
            goto cleanup;
        }
    }

    /* Re-offering chunk 0 is a duplicate (recovered index already held). */
    if (voleith_rs_retriever_offer(&r, d.codeword, cb, &certs[0], 0,
                                   ds_sib(&d, 0), &disp) != 0 ||
        disp != VOLEITH_RS_CHUNK_DUPLICATE ||
        voleith_rs_retriever_distinct(&r) != k) {
        FAIL("duplicate");
        goto cleanup;
    }

    msg_out = calloc(k, cb);
    if (msg_out == NULL) {
        FAIL("oom");
        goto cleanup;
    }
    if (voleith_rs_retriever_decode(&r, msg_out, k * cb) != 0 ||
        memcmp(msg_out, d.message, k * cb) != 0) {
        FAIL("decode");
        goto cleanup;
    }

    ok = 1;

cleanup:
    voleith_rs_retriever_free(&r);
    for (i = 0; i < 2; i++)
        voleith_proof_free(&certs[i]);
    free(msg_out);
    ds_free(&d);
    if (ok)
        PASS();
}

int
main(void)
{
    printf("=== RS retriever sufficiency-flow tests ===\n");

    test_public();
    test_secret_identical();

    printf("\n=== Results: %d/%d passed ===\n", tests_passed, tests_run);
    return (tests_passed == tests_run) ? 0 : 1;
}
