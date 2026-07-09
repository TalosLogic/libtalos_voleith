/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * test_erasure_rs_chunk_cert.c - non-interactive RS chunk membership
 * certificate prove/verify (proof/rs_chunk_cert_proof.c, plan T6.5).
 *
 * Exercises the full Fiat-Shamir certificate: a genuine certificate verifies;
 * only an FWK holder can produce one; every proof-section tamper, a wrong
 * authoritative R, wrong metadata, wrong merkle_root, wrong chunk_digest, and
 * (public mode) a wrong index are rejected; the secret-index variant verifies
 * without the index and does not cross-verify against the public variant.
 */

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

/* A fully populated dataset: secret FWK, per-chunk digests, the Merkle root,
 * the chunk's sibling path, the metadata, and the dataset root R. */
struct dataset {
    voleith_rs_cr_profile_t cr;
    size_t n, index, W, digb, fwkb, depth;
    uint8_t fwk[32];
    uint8_t *digests;
    uint8_t root[64];
    uint8_t R[64];
    uint8_t *siblings;
    voleith_rs_metadata_t meta;
};

static int
dataset_init(struct dataset *d, voleith_rs_cr_profile_t cr, size_t n,
             size_t index)
{
    const voleith_node_hash_vt *vt = voleith_rs_chunk_node_vt(cr);

    memset(d, 0, sizeof(*d));
    d->cr = cr;
    d->n = n;
    d->index = index;
    d->W = vt->node_bytes;
    d->digb = voleith_rs_cr_digest_bytes(cr);
    d->fwkb = voleith_rs_fwk_bytes(cr);
    d->depth = voleith_rs_tree_depth_for_n(n);

    for (size_t i = 0; i < d->fwkb; i++)
        d->fwk[i] = (uint8_t)(0x90 + i);

    d->digests = calloc(n, d->digb);
    if (d->digests == NULL)
        return -1;
    for (size_t i = 0; i < n; i++) {
        uint8_t chunk[48];
        for (size_t j = 0; j < sizeof(chunk); j++)
            chunk[j] = (uint8_t)(i * 13u + j + 1u);
        if (voleith_rs_chunk_digest(cr, chunk, sizeof(chunk),
                                    d->digests + i * d->digb,
                                    d->digb) != VOLEITH_EC_OK)
            return -1;
    }

    if (voleith_rs_tree_root(cr, d->fwk, d->digests, n, d->root,
                             sizeof(d->root)) != VOLEITH_EC_OK)
        return -1;

    if (d->depth > 0) {
        d->siblings = calloc(d->depth, d->W);
        if (d->siblings == NULL)
            return -1;
        if (voleith_rs_tree_sibling_path(cr, d->fwk, d->digests, n, index,
                                         d->siblings,
                                         d->depth * d->W) != VOLEITH_EC_OK)
            return -1;
    }

    d->meta.cr_profile = cr;
    d->meta.chunk_size = 1024;
    d->meta.file_len = (uint64_t)n * 1024u;
    d->meta.n = (uint16_t)n;
    d->meta.k = (uint16_t)(n > 1 ? n / 2 : 1);
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
dataset_free(struct dataset *d)
{
    free(d->digests);
    free(d->siblings);
}

static const uint8_t *
digest_of(const struct dataset *d, size_t i)
{
    return d->digests + i * d->digb;
}

/* Returns 1 iff flipping a byte at several sampled offsets of the proof makes
 * the public verify reject every time. */
static int
public_tamper_all_reject(const voleith_proof_t *proof,
                         const voleith_params_t *params,
                         const struct dataset *d)
{
    size_t offs[3];
    offs[0] = 0;
    offs[1] = proof->len / 2;
    offs[2] = proof->len - 1;

    for (size_t t = 0; t < 3; t++) {
        voleith_proof_t view;
        uint8_t *copy = malloc(proof->len);
        int rv;
        if (copy == NULL)
            return 0;
        memcpy(copy, proof->data, proof->len);
        copy[offs[t]] ^= 0xff;
        view.data = copy;
        view.len = proof->len;
        rv = voleith_rs_chunk_cert_verify(&view, params, d->cr, d->n, d->index,
                                          digest_of(d, d->index), d->root,
                                          &d->meta, d->R, d->W);
        free(copy);
        if (rv == 0)
            return 0;
    }
    return 1;
}

static void
test_public(voleith_rs_cr_profile_t cr, size_t n, size_t index,
            const char *name)
{
    voleith_params_t params = voleith_params_em_128f;
    struct dataset d;
    voleith_proof_t proof = {NULL, 0};
    uint8_t bad_fwk[32];
    voleith_rs_metadata_t bad_meta;
    uint8_t bad_root[64], bad_R[64];

    TEST(name);

    if (dataset_init(&d, cr, n, index) != 0) {
        FAIL("dataset_init");
        dataset_free(&d);
        return;
    }

    /* Genuine certificate verifies. */
    if (voleith_rs_chunk_cert_prove(&proof, &params, cr, n, index, d.fwk,
                                    digest_of(&d, index), d.root, d.siblings,
                                    &d.meta) != 0) {
        FAIL("prove");
        goto done;
    }
    if (voleith_rs_chunk_cert_verify(&proof, &params, cr, n, index,
                                     digest_of(&d, index), d.root, &d.meta, d.R,
                                     d.W) != 0) {
        FAIL("genuine verify");
        goto done;
    }

    /* Only an FWK holder can prove: a wrong FWK fails at prove time. */
    memcpy(bad_fwk, d.fwk, d.fwkb);
    bad_fwk[0] ^= 0x01;
    {
        voleith_proof_t p2 = {NULL, 0};
        if (voleith_rs_chunk_cert_prove(&p2, &params, cr, n, index, bad_fwk,
                                        digest_of(&d, index), d.root,
                                        d.siblings, &d.meta) == 0) {
            voleith_proof_free(&p2);
            FAIL("wrong FWK proved");
            goto done;
        }
    }

    /* Every proof-section tamper is rejected. */
    if (!public_tamper_all_reject(&proof, &params, &d)) {
        FAIL("proof tamper accepted");
        goto done;
    }

    /* Wrong authoritative R: two-layer check fails. */
    memcpy(bad_R, d.R, d.W);
    bad_R[0] ^= 0x01;
    if (voleith_rs_chunk_cert_verify(&proof, &params, cr, n, index,
                                     digest_of(&d, index), d.root, &d.meta,
                                     bad_R, d.W) == 0) {
        FAIL("wrong R accepted");
        goto done;
    }

    /* Wrong metadata: R no longer matches. */
    bad_meta = d.meta;
    bad_meta.k = (uint16_t)(d.meta.k + 1);
    if (voleith_rs_chunk_cert_verify(&proof, &params, cr, n, index,
                                     digest_of(&d, index), d.root, &bad_meta,
                                     d.R, d.W) == 0) {
        FAIL("wrong metadata accepted");
        goto done;
    }

    /* Wrong merkle_root. */
    memcpy(bad_root, d.root, d.W);
    bad_root[0] ^= 0x01;
    if (voleith_rs_chunk_cert_verify(&proof, &params, cr, n, index,
                                     digest_of(&d, index), bad_root, &d.meta,
                                     d.R, d.W) == 0) {
        FAIL("wrong merkle_root accepted");
        goto done;
    }

    /* Wrong chunk_digest (a different chunk's digest). */
    if (voleith_rs_chunk_cert_verify(&proof, &params, cr, n, index,
                                     digest_of(&d, (index + 1) % n), d.root,
                                     &d.meta, d.R, d.W) == 0) {
        FAIL("wrong chunk_digest accepted");
        goto done;
    }

    /* Wrong index (different circuit / fs_seed). */
    if (voleith_rs_chunk_cert_verify(&proof, &params, cr, n, (index + 1) % n,
                                     digest_of(&d, index), d.root, &d.meta, d.R,
                                     d.W) == 0) {
        FAIL("wrong index accepted");
        goto done;
    }

    /* A public certificate must not verify as secret-index. */
    if (voleith_rs_chunk_cert_verify_secret_dir(&proof, &params, cr, n,
                                                digest_of(&d, index), d.root,
                                                &d.meta, d.R, d.W) == 0) {
        FAIL("public cert verified as secret");
        goto done;
    }

    PASS();

done:
    voleith_proof_free(&proof);
    dataset_free(&d);
}

static void
test_secret(voleith_rs_cr_profile_t cr, size_t n, size_t index,
            const char *name)
{
    voleith_params_t params = voleith_params_em_128f;
    struct dataset d;
    voleith_proof_t proof = {NULL, 0};
    voleith_rs_metadata_t bad_meta;
    uint8_t bad_root[64];

    TEST(name);

    if (dataset_init(&d, cr, n, index) != 0) {
        FAIL("dataset_init");
        dataset_free(&d);
        return;
    }

    /* Genuine secret-index certificate verifies (no index at verify). */
    if (voleith_rs_chunk_cert_prove_secret_dir(
            &proof, &params, cr, n, index, d.fwk, digest_of(&d, index), d.root,
            d.siblings, &d.meta) != 0) {
        FAIL("prove_secret");
        goto done;
    }
    if (voleith_rs_chunk_cert_verify_secret_dir(&proof, &params, cr, n,
                                                digest_of(&d, index), d.root,
                                                &d.meta, d.R, d.W) != 0) {
        FAIL("genuine secret verify");
        goto done;
    }

    /* A secret certificate must not verify as public-index. */
    if (voleith_rs_chunk_cert_verify(&proof, &params, cr, n, index,
                                     digest_of(&d, index), d.root, &d.meta, d.R,
                                     d.W) == 0) {
        FAIL("secret cert verified as public");
        goto done;
    }

    /* Proof tamper (sampled offsets) rejected. */
    {
        size_t offs[3] = {0, proof.len / 2, proof.len - 1};
        for (size_t t = 0; t < 3; t++) {
            voleith_proof_t view;
            uint8_t *copy = malloc(proof.len);
            int rv;
            if (copy == NULL) {
                FAIL("oom");
                goto done;
            }
            memcpy(copy, proof.data, proof.len);
            copy[offs[t]] ^= 0xff;
            view.data = copy;
            view.len = proof.len;
            rv = voleith_rs_chunk_cert_verify_secret_dir(
                &view, &params, cr, n, digest_of(&d, index), d.root, &d.meta,
                d.R, d.W);
            free(copy);
            if (rv == 0) {
                FAIL("secret proof tamper accepted");
                goto done;
            }
        }
    }

    /* Wrong metadata / merkle_root rejected by the two-layer check. */
    bad_meta = d.meta;
    bad_meta.file_len ^= 0x01;
    if (voleith_rs_chunk_cert_verify_secret_dir(&proof, &params, cr, n,
                                                digest_of(&d, index), d.root,
                                                &bad_meta, d.R, d.W) == 0) {
        FAIL("secret wrong metadata accepted");
        goto done;
    }

    memcpy(bad_root, d.root, d.W);
    bad_root[0] ^= 0x01;
    if (voleith_rs_chunk_cert_verify_secret_dir(&proof, &params, cr, n,
                                                digest_of(&d, index), bad_root,
                                                &d.meta, d.R, d.W) == 0) {
        FAIL("secret wrong merkle_root accepted");
        goto done;
    }

    /* Wrong chunk_digest rejected. */
    if (voleith_rs_chunk_cert_verify_secret_dir(
            &proof, &params, cr, n, digest_of(&d, (index + 1) % n), d.root,
            &d.meta, d.R, d.W) == 0) {
        FAIL("secret wrong chunk_digest accepted");
        goto done;
    }

    PASS();

done:
    voleith_proof_free(&proof);
    dataset_free(&d);
}

int
main(void)
{
    printf("=== RS chunk membership certificate prove/verify tests ===\n");

    test_public(VOLEITH_RS_CR_128, 8, 5, "public CR-128 n=8 idx=5");
    test_public(VOLEITH_RS_CR_256, 4, 2, "public CR-256 n=4 idx=2");
    test_secret(VOLEITH_RS_CR_128, 8, 5, "secret CR-128 n=8 idx=5");

    printf("\n=== Results: %d/%d passed ===\n", tests_passed, tests_run);
    return (tests_passed == tests_run) ? 0 : 1;
}
