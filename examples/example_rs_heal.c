/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * example_rs_heal.c - healer / repair flow for an RS dataset
 * (design section 6.2, plan T6.9).
 *
 * A storage node lost several chunks of a dataset and a healer regenerates
 * them.  The MDS property means any k of the n chunks reconstruct the
 * message, so the healer:
 *
 *   1. picks the set of LOST target chunks to regenerate;
 *   2. picks k random surviving chunks (the minimum needed to rebuild);
 *   3. decodes the message ONCE from those k survivors;
 *   4. re-encodes every lost target from that one message with
 *      voleith_rs_encode_indices (decode-once / encode-many);
 *   5. confirms each regenerated chunk is byte-identical to the original
 *      and that its chunk_digest matches the committed value (a
 *      bit-identical re-encode, so the dataset commitment R is unchanged).
 *
 * This is cheaper than repairing each chunk independently (which would
 * decode the message once per target).  Contrast example_rs_chunk_membership
 * for the retriever-side rebuild-and-verify flow.
 *
 * Returns 0 on full success; nonzero on any unexpected failure.
 */

#include "rs.h"
#include "rs_membership.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

/* Dataset shape: 12 chunks, any 5 rebuild the blob; heal 3 lost chunks. */
#define N_CHUNKS 12
#define K_CHUNKS 5
#define N_LOST 3
#define CHUNK_BYTES 32

static int
fail(const char *msg)
{
    printf("  [FAIL] %s\n", msg);
    return 1;
}

/*
 * Fisher-Yates: fills perm[0..n) with a random permutation of [0, n).  Just
 * a demo helper for picking the lost / surviving sets; rand() is fine here.
 */
static void
shuffle(size_t *perm, size_t n)
{
    size_t i, j, tmp;

    for (i = 0; i < n; i++)
        perm[i] = i;
    for (i = n; i > 1; i--) {
        j = (size_t)rand() % i;
        tmp = perm[i - 1];
        perm[i - 1] = perm[j];
        perm[j] = tmp;
    }
}

int
main(void)
{
    const voleith_rs_cr_profile_t cr = VOLEITH_RS_CR_128;
    const size_t n = N_CHUNKS, k = K_CHUNKS, lost = N_LOST, cb = CHUNK_BYTES;
    const size_t digb = voleith_rs_cr_digest_bytes(cr);

    voleith_rs_t rs;
    int rs_init = 0;
    uint8_t *message = NULL, *codeword = NULL, *recovered = NULL;
    uint8_t *survivor_chunks = NULL, *healed = NULL;
    size_t perm[N_CHUNKS];
    size_t lost_idx[N_LOST];
    size_t survivor_idx[K_CHUNKS];
    uint8_t want_digest[64], got_digest[64];
    int rc = 1;
    size_t i;

    srand((unsigned)time(NULL));

    printf(
        "=== RS heal (decode-once / encode-many, n=%zu k=%zu, heal %zu) ===\n",
        n, k, lost);

    /* ---- Owner: encode a blob into n chunks. ---- */
    message = calloc(k, cb);
    codeword = calloc(n, cb);
    recovered = calloc(k, cb);
    survivor_chunks = calloc(k, cb);
    healed = calloc(lost, cb);
    if (message == NULL || codeword == NULL || recovered == NULL ||
        survivor_chunks == NULL || healed == NULL) {
        fail("out of memory");
        goto cleanup;
    }
    for (i = 0; i < k * cb; i++)
        message[i] = (uint8_t)(i * 53u + 11u);

    if (voleith_rs_init(&rs, n, k, VOLEITH_EC_MATRIX_CAUCHY) != VOLEITH_EC_OK) {
        fail("rs_init");
        goto cleanup;
    }
    rs_init = 1;
    if (voleith_rs_encode(&rs, message, cb, codeword) != VOLEITH_EC_OK) {
        fail("rs_encode");
        goto cleanup;
    }

    /* ---- Pick a random lost set and k random survivors. ---- */
    shuffle(perm, n);
    for (i = 0; i < lost; i++)
        lost_idx[i] = perm[i];
    for (i = 0; i < k; i++)
        survivor_idx[i] = perm[lost + i]; /* disjoint from the lost set. */

    printf("  lost chunks:     ");
    for (i = 0; i < lost; i++)
        printf("%zu%s", lost_idx[i], i + 1 < lost ? ", " : "\n");
    printf("  using survivors: ");
    for (i = 0; i < k; i++)
        printf("%zu%s", survivor_idx[i], i + 1 < k ? ", " : "\n");

    for (i = 0; i < k; i++)
        memcpy(survivor_chunks + i * cb, codeword + survivor_idx[i] * cb, cb);

    /* ---- Healer: decode ONCE, then re-encode all lost targets. ---- */
    if (voleith_rs_decode(&rs, survivor_idx, survivor_chunks, k, cb,
                          recovered) != VOLEITH_EC_OK) {
        fail("decode");
        goto cleanup;
    }
    if (voleith_rs_encode_indices(&rs, recovered, cb, lost_idx, lost, healed) !=
        VOLEITH_EC_OK) {
        fail("encode_indices");
        goto cleanup;
    }
    printf("  decoded once, re-encoded %zu chunks\n", lost);

    /* ---- Verify: byte-exact and digest-exact (R unchanged). ---- */
    for (i = 0; i < lost; i++) {
        const uint8_t *orig = codeword + lost_idx[i] * cb;
        const uint8_t *got = healed + i * cb;

        if (memcmp(got, orig, cb) != 0) {
            fail("regenerated chunk != original bytes");
            goto cleanup;
        }
        if (voleith_rs_chunk_digest(cr, orig, cb, want_digest, digb) !=
                VOLEITH_EC_OK ||
            voleith_rs_chunk_digest(cr, got, cb, got_digest, digb) !=
                VOLEITH_EC_OK) {
            fail("chunk_digest");
            goto cleanup;
        }
        if (memcmp(want_digest, got_digest, digb) != 0) {
            fail("regenerated chunk_digest != committed");
            goto cleanup;
        }
    }
    printf("  all healed chunks bit-identical (digests match, R unchanged)\n");

    rc = 0;
    printf("\n=== PASS ===\n");

cleanup:
    if (rs_init)
        voleith_rs_free(&rs);
    free(message);
    free(codeword);
    free(recovered);
    free(survivor_chunks);
    free(healed);
    if (rc != 0)
        printf("\n=== FAIL ===\n");
    return rc;
}
