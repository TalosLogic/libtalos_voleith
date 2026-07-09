/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * rlnc_confidential.c - Confidential RLNC plaintext codec, paper 2 scheme 1
 * (P7 T7.2).  See rlnc_confidential.h for the security posture and pipeline.
 */

#include "rlnc_confidential.h"

#include "matrix.h" /* voleith_ec_matrix_*: precode multiply, invert, rank */
#include "prg.h"    /* core/prg.c: AES-CTR PRG for safe-default keygen */
#include "util.h"   /* voleith_secure_zero */

#include <stdlib.h>
#include <string.h>

/* ========================================================================
 * Parameter helpers
 * ======================================================================== */

/* Coding-element bit width: the field enum value is the width (GF8=8, GF16=16). */
static unsigned
w1_of(const voleith_confrlnc_params_t *p)
{
    return (unsigned)p->coding_field;
}

int
voleith_confrlnc_params_check(const voleith_confrlnc_params_t *p)
{
    if (!p)
        return VOLEITH_EC_ERR_PARAM;
    if (p->coding_field != VOLEITH_EC_FIELD_GF8 &&
        p->coding_field != VOLEITH_EC_FIELD_GF16)
        return VOLEITH_EC_ERR_FIELD;
    if (p->t == 0 || p->m == 0 || p->l == 0)
        return VOLEITH_EC_ERR_PARAM;

    unsigned w1 = w1_of(p);
    if (w1 % p->t != 0)
        return VOLEITH_EC_ERR_PARAM;
    unsigned w2 = w1 / p->t;
    if (w2 < 1 || w2 > 8)
        return VOLEITH_EC_ERR_PARAM;
    return 0;
}

/* ========================================================================
 * Precode (RLNC encode / decode) via the validated matrix layer
 * ======================================================================== */

/* Wrap a caller buffer as an ec_matrix descriptor (elements not copied).  The
 * matrix layer reads inputs only; the const cast is safe (see matrix.h). */
static voleith_ec_matrix_t
wrap(const uint16_t *e, size_t rows, size_t cols, voleith_ec_field_t field)
{
    voleith_ec_matrix_t m;
    m.e = (uint16_t *)(uintptr_t)e;
    m.rows = rows;
    m.cols = cols;
    m.field = field;
    return m;
}

int
voleith_confrlnc_precode_encode(const voleith_confrlnc_params_t *p,
                                const uint16_t *L, const uint16_t *P,
                                uint16_t *C_out)
{
    int rc = voleith_confrlnc_params_check(p);
    if (rc != 0)
        return rc;
    if (!L || !P || !C_out)
        return VOLEITH_EC_ERR_PARAM;

    voleith_ec_matrix_t Lm = wrap(L, p->m, p->m, p->coding_field);
    voleith_ec_matrix_t Pm = wrap(P, p->m, p->l, p->coding_field);
    voleith_ec_matrix_t Cm;
    memset(&Cm, 0, sizeof(Cm));

    rc = voleith_ec_matrix_mul(&Lm, &Pm, &Cm); /* C = L . P */
    if (rc != 0)
        return rc;
    memcpy(C_out, Cm.e, p->m * p->l * sizeof(uint16_t));
    voleith_ec_matrix_free_secure(&Cm); /* C is secret coded plaintext */
    return 0;
}

int
voleith_confrlnc_precode_decode(const voleith_confrlnc_params_t *p,
                                const uint16_t *L, const uint16_t *C,
                                uint16_t *P_out)
{
    int rc = voleith_confrlnc_params_check(p);
    if (rc != 0)
        return rc;
    if (!L || !C || !P_out)
        return VOLEITH_EC_ERR_PARAM;

    voleith_ec_matrix_t Lm = wrap(L, p->m, p->m, p->coding_field);
    voleith_ec_matrix_t Linv;
    memset(&Linv, 0, sizeof(Linv));
    /* L is secret: use the constant-time inverse (M-2). */
    rc = voleith_ec_matrix_invert_ct(&Lm, &Linv); /* ERR_SINGULAR if none */
    if (rc != 0)
        return rc;

    voleith_ec_matrix_t Cm = wrap(C, p->m, p->l, p->coding_field);
    voleith_ec_matrix_t Pm;
    memset(&Pm, 0, sizeof(Pm));
    rc = voleith_ec_matrix_mul(&Linv, &Cm, &Pm); /* P = L^{-1} . C */
    voleith_ec_matrix_free_secure(&Linv);        /* L^{-1} is as secret as L */
    if (rc != 0)
        return rc;
    memcpy(P_out, Pm.e, p->m * p->l * sizeof(uint16_t));
    voleith_ec_matrix_free_secure(&Pm); /* P is secret precode plaintext */
    return 0;
}

/* ========================================================================
 * T vectorization (split) and T^{-1} (join), high-part-first
 * ======================================================================== */

int
voleith_confrlnc_split(const voleith_confrlnc_params_t *p, const uint16_t *mat,
                       uint16_t *grid_out)
{
    int rc = voleith_confrlnc_params_check(p);
    if (rc != 0)
        return rc;
    if (!mat || !grid_out)
        return VOLEITH_EC_ERR_PARAM;

    unsigned t = p->t;
    unsigned w2 = w1_of(p) / t;
    uint16_t mask = (uint16_t)((1u << w2) - 1u);
    size_t lt = p->l * t;

    for (size_t r = 0; r < p->m; r++) {
        for (size_t c = 0; c < p->l; c++) {
            uint16_t v = mat[r * p->l + c];
            for (unsigned i = 0; i < t; i++) {
                unsigned shift = w2 * (t - 1 - i); /* high part first */
                grid_out[r * lt + c * t + i] = (uint16_t)((v >> shift) & mask);
            }
        }
    }
    return 0;
}

int
voleith_confrlnc_join(const voleith_confrlnc_params_t *p, const uint16_t *grid,
                      uint16_t *mat_out)
{
    int rc = voleith_confrlnc_params_check(p);
    if (rc != 0)
        return rc;
    if (!grid || !mat_out)
        return VOLEITH_EC_ERR_PARAM;

    unsigned t = p->t;
    unsigned w2 = w1_of(p) / t;
    uint16_t mask = (uint16_t)((1u << w2) - 1u);
    size_t lt = p->l * t;

    for (size_t r = 0; r < p->m; r++) {
        for (size_t c = 0; c < p->l; c++) {
            uint16_t v = 0;
            for (unsigned i = 0; i < t; i++) {
                unsigned shift = w2 * (t - 1 - i);
                uint16_t part = (uint16_t)(grid[r * lt + c * t + i] & mask);
                v = (uint16_t)(v | (uint16_t)(part << shift));
            }
            mat_out[r * p->l + c] = v;
        }
    }
    return 0;
}

/* ========================================================================
 * Partial permutation (forward / inverse), global row-major over n entries
 *
 * perm is SECRET key material, so the apply must not turn a perm entry into a
 * memory index (that leaks perm through cache timing, security review M-2).
 * Both directions therefore use a constant-time masked scan: the access
 * pattern over in[] and out[] is fixed, and perm entries are consumed only in
 * constant-time equality comparisons.  This is O(n^2); it is a per-generation
 * data-owner-side step, not the hot proving path.
 * ======================================================================== */

/* Optimizer barrier keeping a {0, ~0} mask opaque (zero instructions). */
static inline uint16_t
ct_barrier_u16(uint16_t x)
{
#if defined(__GNUC__) || defined(__clang__)
    __asm__ volatile("" : "+r"(x));
    return x;
#else
    volatile uint16_t v = x;
    return v;
#endif
}

/* Returns ~0 (uint16_t) if a == b, else 0, in constant time. */
static inline uint16_t
ct_mask_eq_size(size_t a, size_t b)
{
    size_t d = a ^ b;
    /* high bit of (d | -d) is set iff d != 0; invert to get the equal case. */
    size_t nz = (d | (size_t)(0 - d)) >> (sizeof(size_t) * 8 - 1);
    return ct_barrier_u16((uint16_t)(0u - (uint16_t)(nz ^ (size_t)1)));
}

/* Optimizer barrier for a size_t {0, ~0} mask (zero instructions). */
static inline size_t
ct_barrier_sz(size_t x)
{
#if defined(__GNUC__) || defined(__clang__)
    __asm__ volatile("" : "+r"(x));
    return x;
#else
    volatile size_t v = x;
    return v;
#endif
}

/*
 * Constant-time check that perm is a permutation of [0, n): every entry in
 * range and each target occurs exactly once.  No secret-indexed access and no
 * secret-dependent branch; the reject path leaks nothing about a valid table.
 * O(n^2), in line with the codec apply cost.  Returns 0 if valid, -1 otherwise.
 */
static int
perm_is_valid_ct(const size_t *perm, size_t n)
{
    size_t bad = 0;
    for (size_t i = 0; i < n; i++) {
        size_t in_range = (size_t)(perm[i] < n);    /* 0 or 1 */
        bad |= (size_t)0 - (size_t)(in_range ^ 1u); /* ~0 iff out of range */
    }
    for (size_t target = 0; target < n; target++) {
        size_t cnt = 0;
        for (size_t i = 0; i < n; i++)
            cnt += (ct_mask_eq_size(perm[i], target) & 1u);
        bad |= (size_t)0 - (size_t)(cnt != 1); /* ~0 iff not exactly once */
    }
    return ct_barrier_sz(bad) == 0 ? 0 : -1;
}

/* Full-width size_t mask: ~0 if a == b, else 0. */
static inline size_t
ct_eq_sz(size_t a, size_t b)
{
    size_t d = a ^ b;
    size_t nz = (d | (size_t)(0 - d)) >> (sizeof(size_t) * 8 - 1);
    return ct_barrier_sz((size_t)0 - (nz ^ (size_t)1));
}

/* Select b if mask is all-ones, a if all-zero (mask must be 0 or ~0). */
static inline size_t
ct_sel_sz(size_t mask, size_t a, size_t b)
{
    return (a & ~mask) | (b & mask);
}

/* Read arr[idx] (idx secret) by masked scan over count entries. */
static inline size_t
ct_gather_sz(const size_t *arr, size_t count, size_t idx)
{
    size_t r = 0;
    for (size_t j = 0; j < count; j++)
        r |= arr[j] & ct_eq_sz(idx, j);
    return r;
}

int
voleith_confrlnc_permute(const voleith_confrlnc_params_t *p, const uint16_t *in,
                         const size_t *perm, uint16_t *out)
{
    int rc = voleith_confrlnc_params_check(p);
    if (rc != 0)
        return rc;
    if (!in || !perm || !out || in == out)
        return VOLEITH_EC_ERR_PARAM;

    size_t n = voleith_confrlnc_grid_size(p);
    for (size_t i = 0; i < n; i++) {
        size_t pi = perm[i]; /* read at public index i */
        uint16_t acc = 0;
        for (size_t j = 0; j < n; j++)
            acc = (uint16_t)(acc | (in[j] & ct_mask_eq_size(pi, j)));
        out[i] = acc; /* out[i] = in[perm[i]] */
    }
    return 0;
}

int
voleith_confrlnc_permute_inverse(const voleith_confrlnc_params_t *p,
                                 const uint16_t *in, const size_t *perm,
                                 uint16_t *out)
{
    int rc = voleith_confrlnc_params_check(p);
    if (rc != 0)
        return rc;
    if (!in || !perm || !out || in == out)
        return VOLEITH_EC_ERR_PARAM;

    size_t n = voleith_confrlnc_grid_size(p);
    for (size_t t = 0; t < n; t++) {
        uint16_t acc = 0;
        for (size_t i = 0; i < n; i++)
            acc = (uint16_t)(acc | (in[i] & ct_mask_eq_size(perm[i], t)));
        out[t] = acc; /* out[perm[i]] = in[i] */
    }
    return 0;
}

/* ========================================================================
 * Full encrypt / decrypt (scheme 1)
 * ======================================================================== */

int
voleith_confrlnc_encrypt(const voleith_confrlnc_params_t *p, const uint16_t *L,
                         const size_t *perm, const uint16_t *P,
                         uint16_t *data_out)
{
    int rc = voleith_confrlnc_params_check(p);
    if (rc != 0)
        return rc;
    if (!L || !perm || !P || !data_out)
        return VOLEITH_EC_ERR_PARAM;

    size_t ms = voleith_confrlnc_matrix_size(p);
    size_t n = voleith_confrlnc_grid_size(p);
    uint16_t *C = calloc(ms, sizeof(uint16_t));
    uint16_t *g0 = calloc(n, sizeof(uint16_t));
    uint16_t *g1 = calloc(n, sizeof(uint16_t));
    if (!C || !g0 || !g1) {
        rc = VOLEITH_EC_ERR_NOMEM;
        goto out;
    }

    rc = voleith_confrlnc_precode_encode(p, L, P, C); /* C = L . P */
    if (rc != 0)
        goto out;
    rc = voleith_confrlnc_split(p, C, g0); /* T */
    if (rc != 0)
        goto out;
    rc = voleith_confrlnc_permute(p, g0, perm, g1); /* permute */
    if (rc != 0)
        goto out;
    rc = voleith_confrlnc_join(p, g1, data_out); /* T^{-1} */

out:
    /* C, g0, g1 are secret (coded plaintext and its permutation). */
    if (C)
        voleith_secure_zero(C, ms * sizeof(uint16_t));
    if (g0)
        voleith_secure_zero(g0, n * sizeof(uint16_t));
    if (g1)
        voleith_secure_zero(g1, n * sizeof(uint16_t));
    free(C);
    free(g0);
    free(g1);
    return rc;
}

int
voleith_confrlnc_decrypt(const voleith_confrlnc_params_t *p, const uint16_t *L,
                         const size_t *perm, const uint16_t *data,
                         uint16_t *P_out)
{
    int rc = voleith_confrlnc_params_check(p);
    if (rc != 0)
        return rc;
    if (!L || !perm || !data || !P_out)
        return VOLEITH_EC_ERR_PARAM;

    size_t ms = voleith_confrlnc_matrix_size(p);
    size_t n = voleith_confrlnc_grid_size(p);
    uint16_t *g0 = calloc(n, sizeof(uint16_t));
    uint16_t *g1 = calloc(n, sizeof(uint16_t));
    uint16_t *C = calloc(ms, sizeof(uint16_t));
    if (!g0 || !g1 || !C) {
        rc = VOLEITH_EC_ERR_NOMEM;
        goto out;
    }

    rc = voleith_confrlnc_split(p, data, g0); /* T */
    if (rc != 0)
        goto out;
    rc =
        voleith_confrlnc_permute_inverse(p, g0, perm, g1); /* inverse permute */
    if (rc != 0)
        goto out;
    rc = voleith_confrlnc_join(p, g1, C); /* T^{-1} */
    if (rc != 0)
        goto out;
    rc = voleith_confrlnc_precode_decode(p, L, C, P_out); /* P = L^{-1} . C */

out:
    /* g0, g1, C are secret (coded plaintext and its permutation). */
    if (g0)
        voleith_secure_zero(g0, n * sizeof(uint16_t));
    if (g1)
        voleith_secure_zero(g1, n * sizeof(uint16_t));
    if (C)
        voleith_secure_zero(C, ms * sizeof(uint16_t));
    free(g0);
    free(g1);
    free(C);
    return rc;
}

/* ========================================================================
 * Transmitted-matrix framing
 * ======================================================================== */

int
voleith_confrlnc_attach_identity(const voleith_confrlnc_params_t *p,
                                 const uint16_t *data, uint16_t *mc_out)
{
    int rc = voleith_confrlnc_params_check(p);
    if (rc != 0)
        return rc;
    if (!data || !mc_out)
        return VOLEITH_EC_ERR_PARAM;

    size_t cols = voleith_confrlnc_transmitted_cols(p); /* m + l */
    memset(mc_out, 0, p->m * cols * sizeof(uint16_t));
    for (size_t r = 0; r < p->m; r++) {
        mc_out[r * cols + r] = 1; /* I_m block */
        for (size_t c = 0; c < p->l; c++)
            mc_out[r * cols + p->m + c] = data[r * p->l + c];
    }
    return 0;
}

int
voleith_confrlnc_strip_identity(const voleith_confrlnc_params_t *p,
                                const uint16_t *mc, uint16_t *data_out)
{
    int rc = voleith_confrlnc_params_check(p);
    if (rc != 0)
        return rc;
    if (!mc || !data_out)
        return VOLEITH_EC_ERR_PARAM;

    size_t cols = voleith_confrlnc_transmitted_cols(p);
    for (size_t r = 0; r < p->m; r++)
        for (size_t c = 0; c < p->l; c++)
            data_out[r * p->l + c] = mc[r * cols + p->m + c];
    return 0;
}

/* ========================================================================
 * Scheme 2 (RREF precode + PRNG-sync symbol)
 *
 * The precode RREF-reduces [L | P] to [I_m | C], i.e. C = L^{-1} . P.  That is
 * computed here with the validated invert + multiply layer: RREF([L | P]) is by
 * definition [I | L^{-1}P], so invert(L) then L^{-1} . P is identical to the
 * augmented elimination, on the tested matrix code path.  Decode is the L
 * multiply (RLNC encode).  The split / permute / join stages are scheme 1's,
 * reused unchanged.
 * ======================================================================== */

int
voleith_confrlnc_precode_encode_s2(const voleith_confrlnc_params_t *p,
                                   const uint16_t *L, const uint16_t *P,
                                   uint16_t *C_out)
{
    /* C = L^{-1} . P: this is exactly scheme 1's decode shape (multiply by the
     * inverse), so reuse it.  Returns VOLEITH_EC_ERR_SINGULAR if L is singular. */
    return voleith_confrlnc_precode_decode(p, L, P, C_out);
}

int
voleith_confrlnc_precode_decode_s2(const voleith_confrlnc_params_t *p,
                                   const uint16_t *L, const uint16_t *C,
                                   uint16_t *P_out)
{
    /* P = L . C: scheme 1's encode shape (multiply by L). */
    return voleith_confrlnc_precode_encode(p, L, C, P_out);
}

int
voleith_confrlnc_encrypt_s2(const voleith_confrlnc_params_t *p,
                            const uint16_t *L, const size_t *perm,
                            const uint16_t *P, uint16_t *data_out)
{
    int rc = voleith_confrlnc_params_check(p);
    if (rc != 0)
        return rc;
    if (!L || !perm || !P || !data_out)
        return VOLEITH_EC_ERR_PARAM;

    size_t ms = voleith_confrlnc_matrix_size(p);
    size_t n = voleith_confrlnc_grid_size(p);
    uint16_t *C = calloc(ms, sizeof(uint16_t));
    uint16_t *g0 = calloc(n, sizeof(uint16_t));
    uint16_t *g1 = calloc(n, sizeof(uint16_t));
    if (!C || !g0 || !g1) {
        rc = VOLEITH_EC_ERR_NOMEM;
        goto out;
    }

    rc = voleith_confrlnc_precode_encode_s2(p, L, P, C); /* C = L^{-1} . P */
    if (rc != 0)
        goto out;
    rc = voleith_confrlnc_split(p, C, g0); /* T */
    if (rc != 0)
        goto out;
    rc = voleith_confrlnc_permute(p, g0, perm, g1); /* permute */
    if (rc != 0)
        goto out;
    rc = voleith_confrlnc_join(p, g1, data_out); /* T^{-1} */

out:
    /* C, g0, g1 are secret (coded plaintext and its permutation). */
    if (C)
        voleith_secure_zero(C, ms * sizeof(uint16_t));
    if (g0)
        voleith_secure_zero(g0, n * sizeof(uint16_t));
    if (g1)
        voleith_secure_zero(g1, n * sizeof(uint16_t));
    free(C);
    free(g0);
    free(g1);
    return rc;
}

int
voleith_confrlnc_decrypt_s2(const voleith_confrlnc_params_t *p,
                            const uint16_t *L, const size_t *perm,
                            const uint16_t *data, uint16_t *P_out)
{
    int rc = voleith_confrlnc_params_check(p);
    if (rc != 0)
        return rc;
    if (!L || !perm || !data || !P_out)
        return VOLEITH_EC_ERR_PARAM;

    size_t ms = voleith_confrlnc_matrix_size(p);
    size_t n = voleith_confrlnc_grid_size(p);
    uint16_t *g0 = calloc(n, sizeof(uint16_t));
    uint16_t *g1 = calloc(n, sizeof(uint16_t));
    uint16_t *C = calloc(ms, sizeof(uint16_t));
    if (!g0 || !g1 || !C) {
        rc = VOLEITH_EC_ERR_NOMEM;
        goto out;
    }

    rc = voleith_confrlnc_split(p, data, g0); /* T */
    if (rc != 0)
        goto out;
    rc =
        voleith_confrlnc_permute_inverse(p, g0, perm, g1); /* inverse permute */
    if (rc != 0)
        goto out;
    rc = voleith_confrlnc_join(p, g1, C); /* T^{-1} */
    if (rc != 0)
        goto out;
    rc = voleith_confrlnc_precode_decode_s2(p, L, C, P_out); /* P = L . C */

out:
    /* g0, g1, C are secret (coded plaintext and its permutation). */
    if (g0)
        voleith_secure_zero(g0, n * sizeof(uint16_t));
    if (g1)
        voleith_secure_zero(g1, n * sizeof(uint16_t));
    if (C)
        voleith_secure_zero(C, ms * sizeof(uint16_t));
    free(g0);
    free(g1);
    free(C);
    return rc;
}

int
voleith_confrlnc_attach_identity_s2(const voleith_confrlnc_params_t *p,
                                    const uint16_t *n, const uint16_t *data,
                                    uint16_t *mc_out)
{
    int rc = voleith_confrlnc_params_check(p);
    if (rc != 0)
        return rc;
    if (!n || !data || !mc_out)
        return VOLEITH_EC_ERR_PARAM;

    size_t cols = voleith_confrlnc_transmitted_cols_s2(p); /* m + 1 + l */
    memset(mc_out, 0, p->m * cols * sizeof(uint16_t));
    for (size_t r = 0; r < p->m; r++) {
        mc_out[r * cols + r] = 1;       /* I_m block */
        mc_out[r * cols + p->m] = n[r]; /* n sync column */
        for (size_t c = 0; c < p->l; c++)
            mc_out[r * cols + p->m + 1 + c] = data[r * p->l + c];
    }
    return 0;
}

int
voleith_confrlnc_strip_identity_s2(const voleith_confrlnc_params_t *p,
                                   const uint16_t *mc, uint16_t *n_out,
                                   uint16_t *data_out)
{
    int rc = voleith_confrlnc_params_check(p);
    if (rc != 0)
        return rc;
    if (!mc)
        return VOLEITH_EC_ERR_PARAM;

    size_t cols = voleith_confrlnc_transmitted_cols_s2(p);
    for (size_t r = 0; r < p->m; r++) {
        if (n_out)
            n_out[r] = mc[r * cols + p->m];
        if (data_out)
            for (size_t c = 0; c < p->l; c++)
                data_out[r * p->l + c] = mc[r * cols + p->m + 1 + c];
    }
    return 0;
}

/* ========================================================================
 * Safe-default key generation
 *
 * Deterministic, versioned derivation (a wire contract): seed seeds the PRG,
 * generation_id goes into the PRG IV (low 4 bytes, LE), and an unbounded byte
 * stream is drawn block by block (block index = PRG tweak).  The permutation
 * is consumed first (uniform Fisher-Yates), then L (rejection-sampled to full
 * rank).  generation_id is OPAQUE: it touches only the IV, never L's value.
 * ======================================================================== */

#define CONFRLNC_STREAM_BLK 64u

typedef struct {
    voleith_prg_ctx_t prg;
    uint8_t iv[16];
    uint32_t next_twk;
    uint8_t buf[CONFRLNC_STREAM_BLK];
    size_t pos;
    size_t len;
} confrlnc_stream_t;

static void
stream_refill(confrlnc_stream_t *s)
{
    voleith_prg_gen(&s->prg, s->buf, s->iv, s->next_twk++,
                    CONFRLNC_STREAM_BLK * 8);
    s->pos = 0;
    s->len = CONFRLNC_STREAM_BLK;
}

static uint8_t
stream_byte(confrlnc_stream_t *s)
{
    if (s->pos >= s->len)
        stream_refill(s);
    return s->buf[s->pos++];
}

/* High 64 bits of the 128-bit product a*b, computed from 32-bit limbs.  Uses
 * only multiplies and adds, so it is constant-time in both operands on every
 * target of interest -- unlike a 64-bit hardware divide, whose latency is
 * operand-dependent on some x86 parts (e.g. Sandy Bridge), which would make a
 * modulo reduction leak the secret dividend on its own. */
static uint64_t
ct_mulhi64(uint64_t a, uint64_t b)
{
    uint64_t alo = a & 0xffffffffu, ahi = a >> 32;
    uint64_t blo = b & 0xffffffffu, bhi = b >> 32;
    uint64_t lolo = alo * blo;
    uint64_t lohi = alo * bhi;
    uint64_t hilo = ahi * blo;
    uint64_t hihi = ahi * bhi;
    uint64_t cross = (lolo >> 32) + (hilo & 0xffffffffu) + (lohi & 0xffffffffu);
    return hihi + (hilo >> 32) + (lohi >> 32) + (cross >> 32);
}

/* Bytes consumed per bounded draw.  FIXED and independent of bound and of the
 * (secret) stream values, so keygen's total PRG consumption -- hence its block-
 * refill count and total time -- does not depend on the seed. */
#define STREAM_REDUCE_BYTES 8u

/*
 * Uniform-enough integer in [0, bound) (bound >= 1) with FIXED stream
 * consumption and no data-dependent branch.  Draws a constant STREAM_REDUCE_BYTES
 * bytes and maps them into [0, bound) by Lemire multiply-shift, (v * bound) >> 64.
 * The residual bias is <= bound / 2^64 (< 2^-32 for any realistic grid size),
 * the same negligible trade Kyber / Dilithium make for constant-time sampling.
 *
 * This replaces an earlier reject-above-window sampler whose loop count -- and
 * thus its PRG byte consumption and block-refill count -- depended on the
 * secret-seeded stream, a real timing leak the dudect keygen target caught
 * (|t| ~ 700+, fixed-vs-random).  bound here is public (a Fisher-Yates loop
 * bound), so branching on it leaks nothing; the multiply is constant-time
 * regardless.
 */
static size_t
stream_bounded(confrlnc_stream_t *s, size_t bound)
{
    uint64_t v = 0;
    for (unsigned i = 0; i < STREAM_REDUCE_BYTES; i++)
        v = (v << 8) | stream_byte(s);
    if (bound <= 1)
        return 0;
    return (size_t)ct_mulhi64(v, (uint64_t)bound);
}

/* Draw one coding-field element (w1 bits) from the stream. */
static uint16_t
stream_elem(confrlnc_stream_t *s, unsigned w1)
{
    uint16_t v = (uint16_t)stream_byte(s);
    if (w1 > 8)
        v = (uint16_t)(v | ((uint16_t)stream_byte(s) << 8));
    uint16_t mask = (w1 >= 16) ? (uint16_t)0xFFFF : (uint16_t)((1u << w1) - 1u);
    return (uint16_t)(v & mask);
}

int
voleith_confrlnc_keygen(const voleith_confrlnc_params_t *p, const uint8_t *seed,
                        size_t seed_len, uint32_t generation_id,
                        size_t *perm_out, uint16_t *L_out)
{
    int rc = voleith_confrlnc_params_check(p);
    if (rc != 0)
        return rc;
    if (!seed || !perm_out || !L_out)
        return VOLEITH_EC_ERR_PARAM;

    int lambda;
    switch (seed_len) {
    case 16:
        lambda = 128;
        break;
    case 24:
        lambda = 192;
        break;
    case 32:
        lambda = 256;
        break;
    default:
        return VOLEITH_EC_ERR_PARAM;
    }

    /* Misuse tripwire, NOT an entropy check: reject an all-zero seed, which is
     * the fingerprint of a forgotten / uninitialized seed buffer.  A nonzero
     * but low-entropy seed still passes -- seed entropy is the caller's
     * responsibility (see the header warning).  seed_len is validated above, so
     * the scan is bounded.  Constant-time OR so the reject does not leak the
     * seed contents through timing. */
    {
        uint8_t seed_or = 0;
        for (size_t i = 0; i < seed_len; i++)
            seed_or = (uint8_t)(seed_or | seed[i]);
        if (seed_or == 0)
            return VOLEITH_EC_ERR_PARAM;
    }

    confrlnc_stream_t s;
    memset(&s, 0, sizeof(s));
    if (voleith_prg_init(&s.prg, seed, lambda) != 0)
        return VOLEITH_EC_ERR_PARAM;
    /* IV = generation_id in the low 4 bytes, little-endian; rest zero.  The
     * KDF version domain-separates this derivation from any other PRG use. */
    s.iv[0] = (uint8_t)(generation_id & 0xff);
    s.iv[1] = (uint8_t)((generation_id >> 8) & 0xff);
    s.iv[2] = (uint8_t)((generation_id >> 16) & 0xff);
    s.iv[3] = (uint8_t)((generation_id >> 24) & 0xff);
    s.iv[4] = VOLEITH_CONFRLNC_KDF_VERSION;
    s.next_twk = 0;
    s.pos = 0;
    s.len = 0;

    size_t n = voleith_confrlnc_grid_size(p);
    unsigned w1 = w1_of(p);

    /* Permutation: uniform Fisher-Yates.  Consume the stream FIRST so the
     * matrix draw that follows is at a fixed contract position.  The swap is
     * done obliviously: j is secret (drawn from the secret-seeded stream), so
     * perm_out[j] is read and written by a masked scan over the whole array
     * rather than by a secret index.  This is byte-for-byte the same shuffle as
     * a direct-indexed Fisher-Yates (same stream draws, same result), only with
     * a fixed memory-access pattern.  O(n^2), a per-generation data-owner step. */
    for (size_t i = 0; i < n; i++)
        perm_out[i] = i;
    for (size_t i = n; i-- > 1;) {
        size_t j = stream_bounded(&s, i + 1);     /* secret, in [0, i] */
        size_t vi = perm_out[i];                  /* i is public: direct read */
        size_t vj = ct_gather_sz(perm_out, n, j); /* oblivious read of [j] */
        for (size_t kk = 0; kk < n; kk++) /* oblivious write vi -> [j] */
            perm_out[kk] = ct_sel_sz(ct_eq_sz(kk, j), perm_out[kk], vi);
        perm_out[i] = vj; /* i public: direct write */
    }

    /* Matrix L: rejection-sample m*m elements until full rank.  A random
     * matrix over GF(2^w1) is singular with vanishing probability, so the
     * cap is never reached in practice; it bounds the worst case. */
    const unsigned MAX_ATTEMPTS = 256;
    voleith_ec_matrix_t Lm = wrap(L_out, p->m, p->m, p->coding_field);
    unsigned attempt;
    for (attempt = 0; attempt < MAX_ATTEMPTS; attempt++) {
        for (size_t idx = 0; idx < p->m * p->m; idx++)
            L_out[idx] = stream_elem(&s, w1);

        voleith_ec_matrix_t inv;
        memset(&inv, 0, sizeof(inv));
        int ir = voleith_ec_matrix_invert_ct(&Lm, &inv); /* L secret (M-2) */
        if (ir == 0) {
            voleith_ec_matrix_free_secure(&inv); /* inverse of secret L */
            break;                               /* full rank */
        }
        if (ir != VOLEITH_EC_ERR_SINGULAR) {
            rc = ir; /* a real error (alloc / bad arg), not just singular */
            goto out;
        }
    }
    if (attempt == MAX_ATTEMPTS) {
        rc = VOLEITH_EC_ERR_SINGULAR;
        goto out;
    }
    rc = 0;

out:
    voleith_prg_clear(&s.prg);
    voleith_secure_zero(s.buf, sizeof(s.buf));
    return rc;
}

int
voleith_confrlnc_validate_key(const voleith_confrlnc_params_t *p,
                              const uint16_t *L, const size_t *perm)
{
    int rc = voleith_confrlnc_params_check(p);
    if (rc != 0)
        return rc;
    if (!L || !perm)
        return VOLEITH_EC_ERR_PARAM;

    size_t n = voleith_confrlnc_grid_size(p);

    /* perm must be a permutation of [0, n): in range and no repeats.  Checked
     * in constant time (no secret-indexed access, no secret-dependent branch)
     * so validation does not leak the permutation. */
    if (perm_is_valid_ct(perm, n) != 0)
        return VOLEITH_EC_ERR_PARAM;

    /* L must be invertible over the coding field. */
    voleith_ec_matrix_t Lm = wrap(L, p->m, p->m, p->coding_field);
    voleith_ec_matrix_t inv;
    memset(&inv, 0, sizeof(inv));
    /* L is secret: use the constant-time inverse (M-2). */
    int ir = voleith_ec_matrix_invert_ct(&Lm, &inv);
    if (ir == 0) {
        voleith_ec_matrix_free_secure(&inv); /* inverse of secret L */
        return 0;
    }
    return ir; /* VOLEITH_EC_ERR_SINGULAR or a real error */
}
