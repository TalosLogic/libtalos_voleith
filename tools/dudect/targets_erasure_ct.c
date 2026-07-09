/* Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * Constant-time targets for the confidential-RLNC codec's secret-input
 * data path (security review M-2).  Two hand-masked primitives are
 * validated here:
 *
 *   - voleith_ec_matrix_invert_ct: inverts the SECRET coefficient matrix L
 *     (keygen / decode) with oblivious masked pivoting and unconditional
 *     elimination.  A residual data-dependent pivot search or a zero-factor
 *     skip branch would show up as a timing difference between a fixed and a
 *     random matrix.
 *   - voleith_confrlnc_permute / _permute_inverse: apply the SECRET partial
 *     permutation with a masked O(n^2) scan, never turning a perm entry into
 *     a memory index.  A secret-indexed gather would leak perm through cache
 *     timing, caught as fixed-vs-random perm variation.
 *
 * Class A (cls 0): a single FIXED input, reused every trial.
 * Class B (cls 1): a fresh RANDOM input each trial.
 * This is the canonical dudect fixed-vs-random design; a constant-time
 * implementation yields statistically indistinguishable timing.
 *
 * Two more secret-input entry points are covered:
 *
 *   - voleith_confrlnc_validate_key: validates a SECRET permutation and inverts
 *     the SECRET matrix L.  The permutation check is an oblivious O(n^2) scan
 *     (no secret-indexed access, no reject branch on the permutation) followed
 *     by voleith_ec_matrix_invert_ct.
 *   - voleith_confrlnc_keygen: derives the SECRET permutation with an oblivious
 *     Fisher-Yates shuffle (masked full-array swap) whose index draws consume a
 *     FIXED number of PRG bytes (Lemire multiply-shift, no reject loop), then
 *     rejection-samples L.  Class A/B vary the seed.  Fixed PRG consumption is
 *     what makes total keygen time seed-independent here: an earlier reject-loop
 *     index sampler leaked the seed through byte-consumption / block-refill
 *     count and failed this very target (|t| ~ 700+) before being replaced.
 *
 * Both primitives execute a fixed number of passes independent of their
 * input (invert always runs k pivot/elimination passes; permute/validate always
 * runs the full n^2 scan), including the singular case, so the classes are only
 * distinguished by input VALUES, not by iteration counts.  A random k-by-k
 * matrix over GF(2^16) is invertible except with probability ~2^-16, so no
 * rejection loop is needed for class B; a rare singular draw runs the same
 * passes and differs only in the final one-bit return code (the intended,
 * unavoidable observable).  (keygen's L rejection sampler accepts on the first
 * attempt with the same ~2^-16 miss rate, so its data-dependent iteration count
 * is a negligible, documented residual.)
 *
 * EVIDENCE BOUNDARY (read before trusting a pass here): these targets measure
 * TOTAL execution time under a Welch t-test.  That is sensitive to access-COUNT
 * and data-dependent-branch leaks, but largely BLIND to access-ORDER (cache
 * address-pattern) leaks that keep a fixed total instruction count -- which is
 * exactly the shape of a secret-indexed permutation gather/scatter.  A pass here
 * is therefore necessary but not sufficient evidence of obliviousness: the
 * masked-scan / masked-swap access pattern of the permute, validate, keygen
 * shuffle, and route paths is established by construction and code inspection,
 * not by these total-time targets alone.
 */
#include "dudect_target.h"

#include "erasure.h"
#include "matrix.h"
#include "permutation_gf16_circuit.h"
#include "rlnc_confidential.h"

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

static volatile uint16_t erasure_ct_sink;

/* xorshift64 PRNG for the random (class B) inputs.  Deterministic seed keeps
 * runs reproducible; the value distribution is all that matters here. */
static uint64_t erasure_ct_prng = 0x0123456789abcdefULL;

static uint16_t
prng16(void)
{
    uint64_t x = erasure_ct_prng;
    x ^= x << 13;
    x ^= x >> 7;
    x ^= x << 17;
    erasure_ct_prng = x;
    return (uint16_t)x;
}

/* ----- voleith_ec_matrix_invert_ct (secret matrix L) ----------------- */

#define INVERT_CT_K 8 /* representative generation size m for L (m x m). */

typedef struct {
    voleith_ec_matrix_t a;                   /* descriptor into buf below. */
    uint16_t buf[INVERT_CT_K * INVERT_CT_K]; /* backing storage for a. */
} invert_ct_state_t;

static void
invert_ct_setup(int cls, void *state)
{
    invert_ct_state_t *s = (invert_ct_state_t *)state;
    size_t i;

    s->a.e = s->buf;
    s->a.rows = INVERT_CT_K;
    s->a.cols = INVERT_CT_K;
    s->a.field = VOLEITH_EC_FIELD_GF16;

    if (cls == 0) {
        /* Fixed, well-conditioned matrix: identity plus a constant on the
         * super-diagonal (unit-triangular, always invertible). */
        for (i = 0; i < INVERT_CT_K * INVERT_CT_K; i++)
            s->buf[i] = 0;
        for (i = 0; i < INVERT_CT_K; i++) {
            s->buf[i * INVERT_CT_K + i] = 1;
            if (i + 1 < INVERT_CT_K)
                s->buf[i * INVERT_CT_K + (i + 1)] = 0x2a2a;
        }
    } else {
        /* Fresh random matrix (invertible w.h.p. over GF(2^16)). */
        for (i = 0; i < INVERT_CT_K * INVERT_CT_K; i++)
            s->buf[i] = prng16();
    }
}

static void
invert_ct_run(const void *state)
{
    const invert_ct_state_t *s = (const invert_ct_state_t *)state;
    voleith_ec_matrix_t inv;
    int rc;

    memset(&inv, 0, sizeof(inv));
    rc = voleith_ec_matrix_invert_ct(&s->a, &inv);
    if (rc == VOLEITH_EC_OK) {
        erasure_ct_sink ^= inv.e[0];
        voleith_ec_matrix_free(&inv);
    } else {
        erasure_ct_sink ^= (uint16_t)rc;
    }
}

const dudect_target_t target_voleith_ec_matrix_invert_ct = {
    .name = "voleith_ec_matrix_invert_ct",
    .setup_class = invert_ct_setup,
    .run = invert_ct_run,
    .state_size = sizeof(invert_ct_state_t),
    .reps_per_trial = 20,
};

/* ----- voleith_confrlnc_permute / _permute_inverse (secret perm) ----- */

/* Fixed codec shape giving a modest grid: n = m * l * t = 4 * 4 * 2 = 32. */
#define PERMUTE_M 4
#define PERMUTE_L 4
#define PERMUTE_T 2
#define PERMUTE_N (PERMUTE_M * PERMUTE_L * PERMUTE_T)

typedef struct {
    voleith_confrlnc_params_t p;
    size_t perm[PERMUTE_N];
    uint16_t in[PERMUTE_N];
} permute_state_t;

static void
permute_fill(int cls, permute_state_t *s)
{
    size_t i;

    s->p.coding_field = VOLEITH_EC_FIELD_GF16;
    s->p.t = PERMUTE_T;
    s->p.m = PERMUTE_M;
    s->p.l = PERMUTE_L;

    for (i = 0; i < PERMUTE_N; i++) {
        s->perm[i] = i;
        s->in[i] = (uint16_t)(0x1000 + i);
    }
    if (cls != 0) {
        /* Fisher-Yates shuffle into a fresh random permutation. */
        for (i = PERMUTE_N; i-- > 1;) {
            size_t j = (size_t)(prng16() % (uint16_t)(i + 1));
            size_t tmp = s->perm[i];
            s->perm[i] = s->perm[j];
            s->perm[j] = tmp;
        }
    }
}

static void
permute_setup(int cls, void *state)
{
    permute_fill(cls, (permute_state_t *)state);
}

static void
permute_run(const void *state)
{
    const permute_state_t *s = (const permute_state_t *)state;
    uint16_t out[PERMUTE_N];
    voleith_confrlnc_permute(&s->p, s->in, s->perm, out);
    erasure_ct_sink ^= out[0];
}

static void
permute_inverse_run(const void *state)
{
    const permute_state_t *s = (const permute_state_t *)state;
    uint16_t out[PERMUTE_N];
    voleith_confrlnc_permute_inverse(&s->p, s->in, s->perm, out);
    erasure_ct_sink ^= out[0];
}

const dudect_target_t target_voleith_confrlnc_permute = {
    .name = "voleith_confrlnc_permute",
    .setup_class = permute_setup,
    .run = permute_run,
    .state_size = sizeof(permute_state_t),
    .reps_per_trial = 200,
};

const dudect_target_t target_voleith_confrlnc_permute_inverse = {
    .name = "voleith_confrlnc_permute_inverse",
    .setup_class = permute_setup,
    .run = permute_inverse_run,
    .state_size = sizeof(permute_state_t),
    .reps_per_trial = 200,
};

/* ----- voleith_perm_gf16_route (secret permutation -> control bits) --- */

/* Routing grid size; S(ROUTE_N) control bits fit well under ROUTE_BITS_MAX. */
#define ROUTE_N 64
#define ROUTE_BITS_MAX 512

typedef struct {
    size_t perm[ROUTE_N];
} route_state_t;

static void
route_setup(int cls, void *state)
{
    route_state_t *s = (route_state_t *)state;
    size_t i;

    for (i = 0; i < ROUTE_N; i++)
        s->perm[i] = i; /* class A: identity */
    if (cls != 0) {
        /* class B: fresh random permutation (Fisher-Yates). */
        for (i = ROUTE_N; i-- > 1;) {
            size_t j = (size_t)(prng16() % (uint16_t)(i + 1));
            size_t tmp = s->perm[i];
            s->perm[i] = s->perm[j];
            s->perm[j] = tmp;
        }
    }
}

static void
route_run(const void *state)
{
    const route_state_t *s = (const route_state_t *)state;
    uint16_t bits[ROUTE_BITS_MAX];
    if (voleith_perm_gf16_route(s->perm, ROUTE_N, bits) == 0)
        erasure_ct_sink ^= bits[0];
}

const dudect_target_t target_voleith_perm_gf16_route = {
    .name = "voleith_perm_gf16_route",
    .setup_class = route_setup,
    .run = route_run,
    .state_size = sizeof(route_state_t),
    .reps_per_trial = 5,
};

/* ----- voleith_confrlnc_validate_key (secret perm + secret L) --------- */

/* Same codec shape as the permute targets: n = m * l * t = 32, L is m x m. */
#define VALIDATE_M PERMUTE_M
#define VALIDATE_L PERMUTE_L
#define VALIDATE_T PERMUTE_T
#define VALIDATE_N PERMUTE_N

typedef struct {
    voleith_confrlnc_params_t p;
    size_t perm[VALIDATE_N];
    uint16_t mat[VALIDATE_M * VALIDATE_M];
} validate_state_t;

static void
validate_setup(int cls, void *state)
{
    validate_state_t *s = (validate_state_t *)state;
    size_t i;

    s->p.coding_field = VOLEITH_EC_FIELD_GF16;
    s->p.t = VALIDATE_T;
    s->p.m = VALIDATE_M;
    s->p.l = VALIDATE_L;

    for (i = 0; i < VALIDATE_N; i++)
        s->perm[i] = i; /* class A: identity permutation */
    /* Unit-triangular L (always invertible) as the fixed class-A matrix. */
    for (i = 0; i < VALIDATE_M * VALIDATE_M; i++)
        s->mat[i] = 0;
    for (i = 0; i < VALIDATE_M; i++) {
        s->mat[i * VALIDATE_M + i] = 1;
        if (i + 1 < VALIDATE_M)
            s->mat[i * VALIDATE_M + (i + 1)] = 0x2a2a;
    }

    if (cls != 0) {
        /* class B: fresh random (still valid) permutation and random L. */
        for (i = VALIDATE_N; i-- > 1;) {
            size_t j = (size_t)(prng16() % (uint16_t)(i + 1));
            size_t tmp = s->perm[i];
            s->perm[i] = s->perm[j];
            s->perm[j] = tmp;
        }
        for (i = 0; i < VALIDATE_M * VALIDATE_M; i++)
            s->mat[i] = prng16(); /* invertible w.h.p. over GF(2^16) */
    }
}

static void
validate_run(const void *state)
{
    const validate_state_t *s = (const validate_state_t *)state;
    int rc = voleith_confrlnc_validate_key(&s->p, s->mat, s->perm);
    erasure_ct_sink ^= (uint16_t)rc;
}

const dudect_target_t target_voleith_confrlnc_validate_key = {
    .name = "voleith_confrlnc_validate_key",
    .setup_class = validate_setup,
    .run = validate_run,
    .state_size = sizeof(validate_state_t),
    .reps_per_trial = 20,
};

/* ----- voleith_confrlnc_keygen (secret seed -> perm + L) -------------- */

/* Same codec shape; the secret input varied across classes is the 16-byte
 * seed (lambda = 128).  The generation_id is fixed and public. */
#define KEYGEN_M PERMUTE_M
#define KEYGEN_L PERMUTE_L
#define KEYGEN_T PERMUTE_T
#define KEYGEN_N PERMUTE_N
#define KEYGEN_SEED_LEN 16

typedef struct {
    voleith_confrlnc_params_t p;
    uint8_t seed[KEYGEN_SEED_LEN];
    size_t perm[KEYGEN_N];
    uint16_t mat[KEYGEN_M * KEYGEN_M];
} keygen_state_t;

static void
keygen_setup(int cls, void *state)
{
    keygen_state_t *s = (keygen_state_t *)state;
    size_t i;

    s->p.coding_field = VOLEITH_EC_FIELD_GF16;
    s->p.t = KEYGEN_T;
    s->p.m = KEYGEN_M;
    s->p.l = KEYGEN_L;

    if (cls == 0) {
        /* Fixed nonzero seed (all 0x5a); reused every trial. */
        for (i = 0; i < KEYGEN_SEED_LEN; i++)
            s->seed[i] = 0x5a;
    } else {
        /* Fresh random seed each trial; the all-zero tripwire is astronomically
         * unlikely and would only add a rare early-out, not a per-value leak. */
        for (i = 0; i < KEYGEN_SEED_LEN; i++)
            s->seed[i] = (uint8_t)prng16();
    }
}

static void
keygen_run(const void *state)
{
    const keygen_state_t *s = (const keygen_state_t *)state;
    /* run/state is const by the harness contract; keygen writes only its own
     * outputs, kept in run-local scratch so the shared state stays read-only. */
    size_t perm[KEYGEN_N];
    uint16_t mat[KEYGEN_M * KEYGEN_M];
    int rc =
        voleith_confrlnc_keygen(&s->p, s->seed, KEYGEN_SEED_LEN, 0u, perm, mat);
    if (rc == VOLEITH_EC_OK)
        erasure_ct_sink ^= (uint16_t)perm[0];
    else
        erasure_ct_sink ^= (uint16_t)rc;
}

const dudect_target_t target_voleith_confrlnc_keygen = {
    .name = "voleith_confrlnc_keygen",
    .setup_class = keygen_setup,
    .run = keygen_run,
    .state_size = sizeof(keygen_state_t),
    .reps_per_trial = 20,
};
