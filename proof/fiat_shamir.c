/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * fiat_shamir.c - Fiat-Shamir transcript implementation
 *
 * See fiat_shamir.h for the full API and protocol description.
 */

#include "fiat_shamir.h"
#include "util.h"
#include <assert.h>

/* ================================================================
 * Internal helpers - dispatch to SHAKE128 or SHAKE256
 * ================================================================ */

static void
shake_init(voleith_transcript_t *t)
{
    if (t->lambda == 128)
        voleith_shake128_init(&t->ctx);
    else
        voleith_shake256_init(&t->ctx);
}

/*
 * Returns 0 on success, VOLEITH_HASH_ERR_FINALIZED if the transcript has
 * already been squeezed (absorb-after-finalize).  The public transcript
 * wrappers are void, so they assert this internally; see the note there.
 */
static int
shake_absorb(voleith_transcript_t *t, const uint8_t *data, size_t len)
{
    if (t->lambda == 128)
        return voleith_shake128_absorb(&t->ctx, data, len);
    return voleith_shake256_absorb(&t->ctx, data, len);
}

static void
shake_squeeze(voleith_transcript_t *t, uint8_t *out, size_t len)
{
    if (t->lambda == 128)
        voleith_shake128_squeeze(&t->ctx, out, len);
    else
        voleith_shake256_squeeze(&t->ctx, out, len);
}

/* ================================================================
 * Public API
 * ================================================================ */

void
voleith_transcript_init(voleith_transcript_t *t, unsigned int lambda,
                        uint8_t domain_sep)
{
    t->lambda = lambda;
    t->domain_sep = domain_sep;
    t->squeezed = 0;
    shake_init(t);
}

void
voleith_transcript_absorb(voleith_transcript_t *t, const uint8_t *data,
                          size_t len)
{
    /*
     * A nonzero return means absorb-after-squeeze, a caller sequencing bug
     * (this transcript has already produced a challenge).  This function is
     * public and void, so the error cannot be propagated without a signature
     * change; it is asserted here to catch the misuse in debug builds.
     * Planned for v1.11.0: change this to return int (an additive,
     * source-compatible change, hence a minor bump).
     */
    int rc = shake_absorb(t, data, len);
    assert(rc == 0 && "voleith_transcript_absorb after squeeze");
    (void)rc;
}

void
voleith_transcript_squeeze(voleith_transcript_t *t, uint8_t *out, size_t len)
{
    if (!t->squeezed) {
        /* Append the domain separator byte before finalizing (FAEST spec 3.3).
         * Guarded by !squeezed, so this absorb precedes any squeeze and cannot
         * return the finalized error; asserted for consistency. */
        int rc = shake_absorb(t, &t->domain_sep, 1);
        assert(rc == 0);
        (void)rc;
        t->squeezed = 1;
    }
    shake_squeeze(t, out, len);
}

void
voleith_transcript_clear(voleith_transcript_t *t)
{
    voleith_hash_ctx_clear(&t->ctx);
    t->lambda = 0;
    t->domain_sep = 0;
    t->squeezed = 0;
}

void
voleith_fs_hash(unsigned int lambda, uint8_t domain_sep, const uint8_t *data,
                size_t len, uint8_t *out, size_t out_len)
{
    voleith_transcript_t t;
    voleith_transcript_init(&t, lambda, domain_sep);
    if (len > 0)
        voleith_transcript_absorb(&t, data, len);
    voleith_transcript_squeeze(&t, out, out_len);
    voleith_transcript_clear(&t);
}
