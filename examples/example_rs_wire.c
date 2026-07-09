/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * example_rs_wire.c - the RS dataset on the wire (design section 6.10, plan
 * T6.10).
 *
 * Where example_rs_chunk_membership walks the storage flow with the data held
 * in process structures, this example shows the bytes that actually circulate
 * in the swarm: the per-dataset descriptor (a tracker metainfo, fetched once)
 * and the per-chunk packet (header + chunk bytes).
 *
 *   Owner side
 *     1. RS-encode a blob, FWK-blind the chunk Merkle tree, commit R, and
 *        issue a membership certificate for one chunk (reusing the membership
 *        APIs; this example adds only the wire framing).
 *     2. Serialize the descriptor  = merkle_root || canonical_serialize(meta).
 *     3. Serialize the chunk packet = chunk_header || chunk_bytes, where the
 *        header carries version, flags, R, and the certificate blob.
 *
 *   Retriever side (holding nothing but the two byte buffers)
 *     4. Parse the descriptor and recompute R = H(merkle_root || H(meta)),
 *        then check it against the authoritative R it was given.
 *     5. Parse the chunk header (under the profile from the descriptor), confirm
 *        its R matches the descriptor's, recompute the chunk digest from the
 *        chunk bytes, and verify the certificate against (merkle_root, meta, R).
 *     6. Show that flipping a byte of the descriptor changes R (so a swapped
 *        parameter set is caught) and that a truncated header fails to parse.
 *
 * Returns 0 on full success; nonzero on any unexpected failure.
 */

#include "rs.h"
#include "rs_chunk_cert_proof.h"
#include "rs_consistency.h"
#include "rs_membership.h"
#include "rs_wire.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Dataset shape: an 8-chunk dataset where any 4 chunks rebuild the blob. */
#define N_CHUNKS 8
#define K_CHUNKS 4
#define CHUNK_BYTES 32
#define SHOW_INDEX 3 /* the chunk we package onto the wire. */

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
    const size_t idx = SHOW_INDEX;

    voleith_rs_t rs;
    int rs_init = 0;
    uint8_t fwk[16];
    uint8_t *message = NULL, *codeword = NULL, *digests = NULL,
            *siblings = NULL;
    uint8_t *descriptor = NULL, *packet = NULL;
    voleith_proof_t cert = {NULL, 0};
    uint8_t root[64], R[64], wfd[32];
    voleith_rs_metadata_t meta;
    int rc = 1;
    size_t i;

    printf("=== RS dataset on the wire (CR-128, n=%zu k=%zu) ===\n", n, k);

    /* ---- Owner: encode, FWK-blind the tree, commit R. ---- */
    message = calloc(k, cb);
    codeword = calloc(n, cb);
    digests = calloc(n, digb);
    if (message == NULL || codeword == NULL || digests == NULL) {
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

    siblings = calloc(1, depth * W);
    if (siblings == NULL) {
        fail("out of memory");
        goto cleanup;
    }
    if (voleith_rs_tree_sibling_path(cr, fwk, digests, n, idx, siblings,
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

    /* ---- Owner: issue the membership certificate for chunk SHOW_INDEX. ---- */
    if (voleith_rs_chunk_cert_prove(&cert, &params, cr, n, idx, fwk,
                                    digests + idx * digb, root, siblings,
                                    &meta) != 0) {
        fail("cert_prove");
        goto cleanup;
    }

    /* ---- Owner: serialize the descriptor (fetched once per dataset). ---- */
    {
        size_t dlen, wrote;

        if (voleith_rs_descriptor_serialized_len(&meta, &dlen) !=
            VOLEITH_EC_OK) {
            fail("descriptor_serialized_len");
            goto cleanup;
        }
        descriptor = calloc(1, dlen);
        if (descriptor == NULL) {
            fail("out of memory");
            goto cleanup;
        }
        if (voleith_rs_descriptor_serialize(root, W, &meta, descriptor, dlen,
                                            &wrote) != VOLEITH_EC_OK ||
            wrote != dlen) {
            fail("descriptor_serialize");
            goto cleanup;
        }
        printf("  descriptor: %zu bytes (merkle_root %zu + metadata %zu)\n",
               dlen, W, dlen - W);
    }

    /* ---- Owner: serialize the chunk packet = header || chunk_bytes. ---- */
    {
        size_t hlen, plen, wrote;

        /* v1.9.0: no possession tag (flag 0, field absent). */
        if (voleith_rs_chunk_header_serialized_len(cr, cert.len, 0, &hlen) !=
            VOLEITH_EC_OK) {
            fail("chunk_header_serialized_len");
            goto cleanup;
        }
        plen = hlen + cb;
        packet = calloc(1, plen);
        if (packet == NULL) {
            fail("out of memory");
            goto cleanup;
        }
        if (voleith_rs_chunk_header_serialize(cr, R, W, cert.data, cert.len,
                                              NULL, 0, packet, hlen,
                                              &wrote) != VOLEITH_EC_OK ||
            wrote != hlen) {
            fail("chunk_header_serialize");
            goto cleanup;
        }
        memcpy(packet + hlen, codeword + idx * cb, cb);
        printf(
            "  chunk packet: %zu bytes (header %zu [cert %zu] + chunk %zu)\n",
            plen, hlen, cert.len, cb);
    }

    /*
     * ============ The wire boundary. From here the retriever holds only the
     * `descriptor` and `packet` byte buffers plus the authoritative R it was
     * handed out of band (here `R`); everything else is reconstructed. ========
     */

    /* ---- Retriever: parse the descriptor and recompute / check R. ---- */
    {
        const uint8_t *root_p;
        size_t root_len, R_len;
        voleith_rs_metadata_t pmeta;
        uint8_t R_check[64];
        size_t dlen;

        if (voleith_rs_descriptor_serialized_len(&meta, &dlen) !=
            VOLEITH_EC_OK) {
            fail("descriptor length");
            goto cleanup;
        }
        if (voleith_rs_descriptor_parse(descriptor, dlen, &root_p, &root_len,
                                        &pmeta) != VOLEITH_EC_OK) {
            fail("descriptor_parse");
            goto cleanup;
        }
        if (voleith_rs_descriptor_parse_compute_R(descriptor, dlen, R_check,
                                                  sizeof(R_check),
                                                  &R_len) != VOLEITH_EC_OK ||
            R_len != W || memcmp(R_check, R, W) != 0) {
            fail("descriptor R does not match authoritative R");
            goto cleanup;
        }
        printf("  retriever parsed descriptor, R matches (profile CR-%s)\n",
               pmeta.cr_profile == VOLEITH_RS_CR_128 ? "128" : "256");

        /* ---- Retriever: parse the chunk header and verify the cert. ---- */
        {
            const uint8_t *R_p, *cert_p, *poss_p;
            size_t R_hlen, cert_len, poss_len, consumed, plen;
            const uint8_t *chunk_bytes;
            uint8_t cdigest[64];
            voleith_proof_t cert_view;

            if (voleith_rs_chunk_header_serialized_len(
                    cr, cert.len, 0, &consumed) != VOLEITH_EC_OK) {
                fail("header length");
                goto cleanup;
            }
            plen = consumed + cb;

            /* cr is known from the descriptor; len(R) follows from it. */
            if (voleith_rs_chunk_header_parse(pmeta.cr_profile, packet, plen,
                                              &R_p, &R_hlen, &cert_p, &cert_len,
                                              &poss_p, &poss_len,
                                              &consumed) != VOLEITH_EC_OK) {
                fail("chunk_header_parse");
                goto cleanup;
            }
            if (poss_p != NULL || poss_len != 0) {
                fail("unexpected possession tag in v1.9.0 packet");
                goto cleanup;
            }
            if (R_hlen != W || memcmp(R_p, R, W) != 0) {
                fail("header R does not match the authoritative R");
                goto cleanup;
            }
            chunk_bytes = packet + consumed;

            /* chunk_digest is recomputable from the chunk bytes (design 6.10:
             * not restated on the wire). */
            if (voleith_rs_chunk_digest(cr, chunk_bytes, cb, cdigest,
                                        sizeof(cdigest)) != VOLEITH_EC_OK) {
                fail("recompute chunk_digest");
                goto cleanup;
            }

            /* The certificate is a zero-copy view into the packet buffer; the
             * verify only reads it. */
            cert_view.data = (uint8_t *)(uintptr_t)cert_p;
            cert_view.len = cert_len;

            if (voleith_rs_chunk_cert_verify(&cert_view, &params, cr, n, idx,
                                             cdigest, root_p, &pmeta, R,
                                             W) != 0) {
                fail("certificate did not verify from the wire bytes");
                goto cleanup;
            }
            printf("  retriever parsed packet, verified certificate for chunk "
                   "%zu\n",
                   idx);
        }
    }

    /* ---- Tamper checks. ---- */
    {
        const uint8_t *root_p;
        size_t root_len, dlen;
        voleith_rs_metadata_t pmeta;
        uint8_t R_bad[64];
        size_t R_len;

        if (voleith_rs_descriptor_serialized_len(&meta, &dlen) !=
            VOLEITH_EC_OK) {
            fail("descriptor length");
            goto cleanup;
        }

        /*
         * Flip a byte of the chunk_size field (metadata offset 2, so
         * merkle_root + 2).  chunk_size stays structurally valid, so the parse
         * still succeeds and the swap is caught cleanly by R: the recomputed R
         * no longer matches the authoritative R.  (A tamper that instead breaks
         * a metadata invariant, e.g. k > n, is caught even earlier, by the
         * recompute returning an error rather than a wrong R.)
         */
        descriptor[W + 2] ^= 0x01;
        if (voleith_rs_descriptor_parse(descriptor, dlen, &root_p, &root_len,
                                        &pmeta) != VOLEITH_EC_OK ||
            voleith_rs_descriptor_parse_compute_R(descriptor, dlen, R_bad,
                                                  sizeof(R_bad),
                                                  &R_len) != VOLEITH_EC_OK) {
            fail("tampered descriptor parse");
            goto cleanup;
        }
        if (memcmp(R_bad, R, W) == 0) {
            fail("tampered descriptor still matches R");
            goto cleanup;
        }
        descriptor[W + 2] ^= 0x01;
        printf("  tampered descriptor changes R (parameter swap caught)\n");

        /* A truncated chunk header fails to parse. */
        {
            const uint8_t *R_p, *cert_p, *poss_p;
            size_t R_hlen, cert_len, poss_len, consumed;

            if (voleith_rs_chunk_header_parse(
                    cr, packet, 4, &R_p, &R_hlen, &cert_p, &cert_len, &poss_p,
                    &poss_len, &consumed) != VOLEITH_EC_ERR_PARAM) {
                fail("truncated header accepted");
                goto cleanup;
            }
            printf("  truncated chunk header rejected\n");
        }
    }

    rc = 0;
    printf("\n=== PASS ===\n");

cleanup:
    voleith_proof_free(&cert);
    if (rs_init)
        voleith_rs_free(&rs);
    free(message);
    free(codeword);
    free(digests);
    free(siblings);
    free(descriptor);
    free(packet);
    if (rc != 0)
        printf("\n=== FAIL ===\n");
    return rc;
}
