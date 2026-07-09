/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * example_rs_chunk_membership.c - end-to-end RS chunk membership use case
 * (design sections 6.6 / 6.8 / 6.9, plan T6.8).
 *
 * Walks the full storage flow with no circuit-internal details exposed:
 *
 *   Owner side
 *     1. RS-encode a sample blob into n chunks (any k rebuild it, MDS).
 *     2. Digest each chunk, FWK-blind the chunk Merkle tree, and bind the
 *        root plus metadata into the dataset commitment R.
 *     3. Issue a per-chunk membership certificate (a non-interactive proof
 *        that the chunk is a genuine member of the dataset under R).
 *
 *   Retriever side
 *     4. Offer downloaded chunks to the retriever, which verifies each
 *        certificate against R, deduplicates by index, and stops once it
 *        holds k distinct verified chunks.
 *     5. RS-decode the k chunks back to the original blob.
 *     6. Capability-3 plaintext consistency check: re-encode the recovered
 *        blob and confirm every chunk digest matches what the owner
 *        committed, plus the whole-file digest.
 *
 * The example also shows the retriever rejecting a tampered chunk and
 * treating a re-offered chunk as a duplicate, then prints PASS / FAIL.
 *
 * Returns 0 on full success; nonzero on any unexpected failure.
 */

#include "rs.h"
#include "rs_chunk_cert_proof.h"
#include "rs_consistency.h"
#include "rs_membership.h"
#include "rs_retriever.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Dataset shape: an 8-chunk dataset where any 4 chunks rebuild the blob. */
#define N_CHUNKS 8
#define K_CHUNKS 4
#define CHUNK_BYTES 32

static int
fail(const char *msg)
{
    printf("  [FAIL] %s\n", msg);
    return 1;
}

int
main(void)
{
    const voleith_rs_cr_profile_t cr = VOLEITH_RS_CR_128;
    voleith_params_t params = voleith_params_em_128f;
    const voleith_node_hash_vt *vt = voleith_rs_chunk_node_vt(cr);
    const size_t n = N_CHUNKS, k = K_CHUNKS, cb = CHUNK_BYTES;
    const size_t digb = voleith_rs_cr_digest_bytes(cr);
    const size_t W = vt->node_bytes;
    const size_t depth = voleith_rs_tree_depth_for_n(n);

    voleith_rs_t rs;
    int rs_init = 0;
    voleith_rs_retriever_t r;
    int r_init = 0;
    uint8_t fwk[16];
    uint8_t *message = NULL, *recovered = NULL;
    uint8_t *codeword = NULL, *digests = NULL, *siblings = NULL;
    voleith_proof_t certs[N_CHUNKS];
    uint8_t root[64], R[64], wfd[32], tampered[CHUNK_BYTES];
    voleith_rs_metadata_t meta;
    voleith_rs_chunk_disposition_t disp;
    int rc = 1;
    size_t i;

    for (i = 0; i < n; i++) {
        certs[i].data = NULL;
        certs[i].len = 0;
    }

    printf("=== RS chunk membership end-to-end (CR-128, n=%zu k=%zu) ===\n", n,
           k);

    /* ---- Owner: build a sample blob and RS-encode it. ---- */
    message = calloc(k, cb);
    codeword = calloc(n, cb);
    digests = calloc(n, digb);
    recovered = calloc(k, cb);
    if (message == NULL || codeword == NULL || digests == NULL ||
        recovered == NULL) {
        fail("out of memory");
        goto cleanup;
    }
    for (i = 0; i < k * cb; i++)
        message[i] = (uint8_t)(i * 31u + 7u);

    if (voleith_rs_init(&rs, n, k, VOLEITH_EC_MATRIX_CAUCHY) != VOLEITH_EC_OK) {
        fail("rs_init");
        goto cleanup;
    }
    rs_init = 1;
    if (voleith_rs_encode(&rs, message, cb, codeword) != VOLEITH_EC_OK) {
        fail("rs_encode");
        goto cleanup;
    }
    printf("  encoded %zu-byte blob into %zu chunks of %zu bytes\n", k * cb, n,
           cb);

    /* ---- Owner: digest chunks, FWK-blind the tree, commit R. ---- */
    for (i = 0; i < (size_t)16; i++)
        fwk[i] = (uint8_t)(0x42 + i);

    for (i = 0; i < n; i++)
        if (voleith_rs_chunk_digest(cr, codeword + i * cb, cb,
                                    digests + i * digb,
                                    digb) != VOLEITH_EC_OK) {
            fail("chunk_digest");
            goto cleanup;
        }
    if (voleith_rs_tree_root(cr, fwk, digests, n, root, sizeof(root)) !=
        VOLEITH_EC_OK) {
        fail("tree_root");
        goto cleanup;
    }

    siblings = calloc(n, depth * W);
    if (siblings == NULL) {
        fail("out of memory");
        goto cleanup;
    }
    for (i = 0; i < n; i++)
        if (voleith_rs_tree_sibling_path(cr, fwk, digests, n, i,
                                         siblings + i * depth * W,
                                         depth * W) != VOLEITH_EC_OK) {
            fail("sibling_path");
            goto cleanup;
        }

    if (voleith_rs_whole_file_digest(cr, message, (uint64_t)k * cb, wfd,
                                     sizeof(wfd)) != VOLEITH_EC_OK) {
        fail("whole_file_digest");
        goto cleanup;
    }

    memset(&meta, 0, sizeof(meta));
    meta.cr_profile = cr;
    meta.chunk_size = (uint32_t)cb;
    meta.file_len = (uint64_t)k * cb;
    meta.n = (uint16_t)n;
    meta.k = (uint16_t)k;
    meta.whole_file_digest = wfd;

    if (voleith_rs_compute_R(root, W, &meta, R, sizeof(R)) != VOLEITH_EC_OK) {
        fail("compute_R");
        goto cleanup;
    }
    printf("  committed dataset root R (%zu-byte tree, depth %zu)\n", W, depth);

    /* ---- Owner: issue a membership certificate for every chunk. ---- */
    for (i = 0; i < n; i++)
        if (voleith_rs_chunk_cert_prove(&certs[i], &params, cr, n, i, fwk,
                                        digests + i * digb, root,
                                        siblings + i * depth * W, &meta) != 0) {
            fail("cert_prove");
            goto cleanup;
        }
    printf("  issued %zu membership certificates\n", n);

    /* ---- Retriever: verify, dedup, and collect k distinct chunks. ---- */
    if (voleith_rs_retriever_init(&r, cr, &params, VOLEITH_EC_MATRIX_CAUCHY, 0,
                                  root, R, W, &meta, NULL) != 0) {
        fail("retriever_init");
        goto cleanup;
    }
    r_init = 1;

    /* A tampered chunk (bytes no longer hash to the committed digest) is
     * rejected even though it carries a genuine certificate. */
    memcpy(tampered, codeword, cb);
    tampered[0] ^= 0xff;
    if (voleith_rs_retriever_offer(&r, tampered, cb, &certs[0], 0, NULL,
                                   &disp) != 0 ||
        disp != VOLEITH_RS_CHUNK_REJECTED) {
        fail("tampered chunk not rejected");
        goto cleanup;
    }
    printf("  tampered chunk rejected\n");

    /* Offer chunks 2, 4, 6, 7 (any k distinct suffice). */
    static const size_t pick[K_CHUNKS] = {2, 4, 6, 7};
    for (i = 0; i < k; i++) {
        size_t idx = pick[i];
        if (voleith_rs_retriever_offer(&r, codeword + idx * cb, cb, &certs[idx],
                                       idx, NULL, &disp) != 0 ||
            disp != VOLEITH_RS_CHUNK_ACCEPTED) {
            fail("genuine chunk not accepted");
            goto cleanup;
        }
    }

    /* Re-offering chunk 2 is a duplicate and does not advance the count. */
    if (voleith_rs_retriever_offer(&r, codeword + 2 * cb, cb, &certs[2], 2,
                                   NULL, &disp) != 0 ||
        disp != VOLEITH_RS_CHUNK_DUPLICATE) {
        fail("re-offered chunk not a duplicate");
        goto cleanup;
    }
    printf("  accepted %zu distinct chunks, dropped 1 duplicate\n",
           voleith_rs_retriever_distinct(&r));

    if (!voleith_rs_retriever_have_enough(&r) ||
        voleith_rs_retriever_need_more(&r) != 0) {
        fail("retriever not rebuild-ready after k chunks");
        goto cleanup;
    }

    /* ---- Retriever: rebuild the blob and check it bit-exactly. ---- */
    if (voleith_rs_retriever_decode(&r, recovered, k * cb) != 0) {
        fail("decode");
        goto cleanup;
    }
    if (memcmp(recovered, message, k * cb) != 0) {
        fail("recovered blob does not match original");
        goto cleanup;
    }
    printf("  rebuilt the %zu-byte blob bit-exactly\n", k * cb);

    /* ---- Retriever: capability-3 plaintext consistency check. ---- */
    if (voleith_rs_check_consistency(&rs, cr, recovered, cb, digests, &meta) !=
        VOLEITH_EC_OK) {
        fail("consistency check failed on a correct codeword");
        goto cleanup;
    }
    printf("  consistency check passed (codeword + whole-file digest)\n");

    /* A flipped committed digest simulates a malicious / buggy owner: the
     * consistency check must now reject. */
    digests[0] ^= 0x01;
    if (voleith_rs_check_consistency(&rs, cr, recovered, cb, digests, &meta) ==
        VOLEITH_EC_OK) {
        fail("consistency check passed on an inconsistent codeword");
        goto cleanup;
    }
    digests[0] ^= 0x01;
    printf("  inconsistent codeword correctly rejected\n");

    rc = 0;
    printf("\n=== PASS ===\n");

cleanup:
    if (r_init)
        voleith_rs_retriever_free(&r);
    for (i = 0; i < n; i++)
        voleith_proof_free(&certs[i]);
    if (rs_init)
        voleith_rs_free(&rs);
    free(message);
    free(recovered);
    free(codeword);
    free(digests);
    free(siblings);
    if (rc != 0)
        printf("\n=== FAIL ===\n");
    return rc;
}
