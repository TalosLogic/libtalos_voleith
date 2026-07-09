/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * rlnc_confidential.h - Confidential RLNC plaintext codec, paper 2 scheme 1
 * (P7 T7.2).
 *
 * Reference: Brahimi & Merazka, "Data confidentiality-preserving schemes for
 * random linear network coding-capable networks", J. Information Security and
 * Applications 66 (2022) 103136.  See docs/ERASURE_CODES_DESIGN.md section 6.11.
 *
 * SECURITY POSTURE (read before use): this is WEAK / COMPUTATIONAL security in
 * the permutation-cipher family (P-Coding / SPOC lineage), strictly weaker than
 * a standard cipher, and it AUTHENTICATES NOTHING.  It is NOT an AEAD and must
 * not be mistaken for one.  The robust deployment shape is an AEAD payload
 * (semantic security + integrity) composed with this codec for the
 * coding-structure / generation-linkage hiding it uniquely adds.  Pollution
 * resistance (a homomorphic MAC) is the consuming application's concern.
 *
 * Scheme 1 encrypts a generation by:
 *   1. RLNC precode  C = L . P over the coding field (secret matrix L), then
 *   2. T vectorization: split each coding element into t sub-symbols, then
 *   3. a secret partial permutation of the sub-symbol grid, then
 *   4. T^{-1}: rejoin sub-symbols into coding elements.
 * The transmitted matrix is [I_m | data] (the identity block stands in for the
 * coefficients, so L never travels).  Decryption is the exact inverse pipeline,
 * ending in the RLNC decode P = L^{-1} . C.
 *
 * The codec is FIELD-PARAMETRIC over (q1, q2, t): the coding field is GF(2^w1)
 * (w1 = 8 or 16), each element splits into t sub-symbols of w2 = w1 / t bits.
 * The shipped transport instantiation is coding_field = GF(2^16), t = 2 (byte
 * sub-symbols).  The paper's worked-figure instantiation is GF(2^8), t = 2
 * (nibble sub-symbols); the codec runs that too so the figures serve as KATs.
 *
 * This is a PLAINTEXT data layer (not constant-time): it operates on whole
 * generation matrices in the clear, not on a VOLE witness.  The matching ZK
 * proof is the separate in-circuit work (plan T7.5 / T7.6).
 *
 * SIDE-CHANNEL / TIMING POSTURE (read before deploying): this codec's inputs
 * ARE secret (the coefficient matrix L, its inverse L^{-1}, and the partial
 * permutation perm), so the whole secret-key path is constant-time: no secret
 * value is used as a memory index and no branch depends on a secret.
 *   - keygen derives the permutation with an oblivious Fisher-Yates shuffle
 *     (masked full-array swap) whose index draws consume a FIXED number of PRG
 *     bytes -- a Lemire multiply-shift reduction, no reject loop -- so total
 *     PRG consumption and thus timing do not depend on the seed; L is then
 *     rejection-sampled to full rank; the safe-default generation is
 *     deterministic in (seed, generation_id);
 *   - the permutation apply (voleith_confrlnc_permute / _permute_inverse) and
 *     the bring-your-own key validation (voleith_confrlnc_validate_key) use a
 *     masked O(n^2) scan, never turning a perm entry into a memory index;
 *   - the secret-matrix inverse in keygen / decode goes through
 *     voleith_ec_matrix_invert_ct (oblivious masked pivoting, unconditional
 *     elimination), not the variable-time voleith_ec_matrix_invert;
 *   - the SEPARATE in-circuit AS-Waksman routing gadget that derives switch
 *     control bits from perm at proof-construction time
 *     (circuits/permutation_gf16_circuit.c) is likewise constant-time (Euler-
 *     tour list-ranking, masked accesses throughout);
 *   - the underlying GF(2^w) mul / inv are already constant-time.
 * The secret-dependent observables that remain are the singular / non-singular
 * return code (one bit, unavoidable at the API) and the retry count of keygen's
 * L rejection sampler, which redraws only when a random matrix is singular
 * (~2^-16 over GF(2^16)); that is a genuinely negligible residual, not tied to
 * any single secret value, and independent of the seed's actual key value.
 * (The permutation index sampler no longer rejects -- see above.)  Note the
 * total-time timing tests bound access-COUNT and branch leaks but are largely
 * blind to access-ORDER leaks; the oblivious-access property above is
 * established by construction / code inspection, not by those tests alone.
 * Confidentiality against a network observer is COMPUTATIONAL regardless.
 * See docs/ERASURE_CODES_DESIGN.md section 6.11.
 *
 * Element representation: every coding element and sub-symbol is carried in a
 * uint16_t (low w1 / w2 bits used), matching erasure/matrix.c storage.  The
 * T split is high-part-first: element value v -> sub-symbols
 * part_i = (v >> (w2 * (t - 1 - i))) & ((1 << w2) - 1), confirmed against the
 * paper figures (byte 0xe7 -> nibbles 0xe, 0x7).
 */

#ifndef VOLEITH_ERASURE_RLNC_CONFIDENTIAL_H
#define VOLEITH_ERASURE_RLNC_CONFIDENTIAL_H

#include <stddef.h>
#include <stdint.h>

#include "erasure.h"

/*
 * Versioned key-derivation contract (see voleith_confrlnc_keygen).  The
 * seed -> (permutation, L) derivation is a WIRE CONTRACT both source and sink
 * must share; this byte pins the version.
 */
#define VOLEITH_CONFRLNC_KDF_VERSION 0x01

/*
 * Codec parameters.  coding_field selects w1 (GF8 -> 8, GF16 -> 16); t is the
 * number of sub-symbols a coding element splits into (w2 = w1 / t, requires
 * w1 % t == 0 and 1 <= w2 <= 8).  A generation is an m-by-l matrix over the
 * coding field: m source symbols (rows), l coding elements per symbol
 * (columns).  L is the m-by-m secret coefficient matrix; the sub-symbol grid
 * is m-by-(l*t), and the partial permutation acts on its n = m*l*t entries
 * read row-major.
 */
typedef struct {
    voleith_ec_field_t coding_field; /* GF8 (paper) or GF16 (shipped). */
    unsigned t;                      /* sub-symbols per coding element. */
    size_t m;                        /* generation size (rows). */
    size_t l;                        /* coding elements per symbol (columns). */
} voleith_confrlnc_params_t;

/* Number of sub-symbols in the permutation grid: n = m * l * t. */
static inline size_t
voleith_confrlnc_grid_size(const voleith_confrlnc_params_t *p)
{
    return p->m * p->l * (size_t)p->t;
}

/* Coding elements in the generation matrix: m * l. */
static inline size_t
voleith_confrlnc_matrix_size(const voleith_confrlnc_params_t *p)
{
    return p->m * p->l;
}

/*
 * Validate parameters: known coding field, t >= 1 dividing w1 with w2 in
 * [1, 8], and m, l > 0.  Returns 0 if valid, VOLEITH_EC_ERR_PARAM otherwise.
 */
int voleith_confrlnc_params_check(const voleith_confrlnc_params_t *p);

/* ========================================================================
 * Pipeline stages (exposed for stage-by-stage KAT checking, T7.3)
 *
 * All element / sub-symbol arrays are uint16_t, row-major.  Matrices are
 * m*l elements; grids are n = m*l*t sub-symbols.  Stages do not allocate.
 * ======================================================================== */

/* RLNC precode: C = L . P over the coding field.  L is m*m, P and C are m*l. */
int voleith_confrlnc_precode_encode(const voleith_confrlnc_params_t *p,
                                    const uint16_t *L, const uint16_t *P,
                                    uint16_t *C_out);

/* RLNC decode: P = L^{-1} . C.  Returns VOLEITH_EC_ERR_SINGULAR if L has no
 * inverse. */
int voleith_confrlnc_precode_decode(const voleith_confrlnc_params_t *p,
                                    const uint16_t *L, const uint16_t *C,
                                    uint16_t *P_out);

/* T vectorization: split the m*l element matrix into the m*(l*t) sub-symbol
 * grid, high-part-first. */
int voleith_confrlnc_split(const voleith_confrlnc_params_t *p,
                           const uint16_t *mat, uint16_t *grid_out);

/* T^{-1}: rejoin the m*(l*t) sub-symbol grid into the m*l element matrix. */
int voleith_confrlnc_join(const voleith_confrlnc_params_t *p,
                          const uint16_t *grid, uint16_t *mat_out);

/*
 * Apply the partial permutation forward: out[i] = in[perm[i]] for i in [0, n).
 * perm is n entries, a permutation of [0, n).  in and out must not alias.
 */
int voleith_confrlnc_permute(const voleith_confrlnc_params_t *p,
                             const uint16_t *in, const size_t *perm,
                             uint16_t *out);

/*
 * Apply the inverse permutation: out[perm[i]] = in[i] for i in [0, n).  The
 * exact inverse of voleith_confrlnc_permute with the same perm.
 */
int voleith_confrlnc_permute_inverse(const voleith_confrlnc_params_t *p,
                                     const uint16_t *in, const size_t *perm,
                                     uint16_t *out);

/* ========================================================================
 * Full encrypt / decrypt (scheme 1)
 * ======================================================================== */

/*
 * Encrypt a generation: data_out = T^{-1}(permute(T(L . P))).  P and data_out
 * are m*l coding elements.  Allocates internal scratch.  Returns 0 on success,
 * a negative VOLEITH_EC_ERR_* on bad arguments or allocation failure.
 */
int voleith_confrlnc_encrypt(const voleith_confrlnc_params_t *p,
                             const uint16_t *L, const size_t *perm,
                             const uint16_t *P, uint16_t *data_out);

/*
 * Decrypt a generation: P_out = L^{-1} . T^{-1}(permute_inverse(T(data))).
 * data and P_out are m*l coding elements.  Allocates internal scratch.
 * Returns 0 on success, VOLEITH_EC_ERR_SINGULAR if L is not invertible, or
 * another negative VOLEITH_EC_ERR_*.
 */
int voleith_confrlnc_decrypt(const voleith_confrlnc_params_t *p,
                             const uint16_t *L, const size_t *perm,
                             const uint16_t *data, uint16_t *P_out);

/* ========================================================================
 * Transmitted-matrix framing: M_C = [I_m | data]
 * ======================================================================== */

/* Columns of the transmitted matrix [I_m | data]: m + l. */
static inline size_t
voleith_confrlnc_transmitted_cols(const voleith_confrlnc_params_t *p)
{
    return p->m + p->l;
}

/*
 * Build M_C = [I_m | data] (m rows, m+l cols, row-major) from the m*l data
 * matrix.  The identity block stands in for the secret coefficients.
 */
int voleith_confrlnc_attach_identity(const voleith_confrlnc_params_t *p,
                                     const uint16_t *data, uint16_t *mc_out);

/*
 * Recover the m*l data matrix from M_C = [I_m | data] (m rows, m+l cols).
 * The identity block is not validated (it is structural framing, not a
 * security check).
 */
int voleith_confrlnc_strip_identity(const voleith_confrlnc_params_t *p,
                                    const uint16_t *mc, uint16_t *data_out);

/* ========================================================================
 * Scheme 2 (RREF precode + PRNG-sync symbol)
 *
 * Scheme 2 (paper 2 Figures 3-4) is a cost-redistribution variant of scheme 1:
 * identical guess probability and identical T / permutation / T^{-1} data path,
 * but the precode is moved to the source as a Gauss-elimination (RREF) step and
 * a per-generation PRNG-synchronization symbol n is appended to the transmitted
 * matrix.  Concretely the source RREF-reduces the augmented matrix [L | P] to
 * [I_m | C], so the precode output is C = L^{-1} . P (the figure labels this
 * first arrow "RLNC decoding").  Decryption recovers P by RLNC-ENCODING with L:
 * P = L . C.  This is exactly scheme 1 with L and L^{-1} swapping roles in the
 * precode; the split / permute / join stages are unchanged, so they reuse the
 * scheme-1 functions above.
 *
 * The n symbol synchronizes the source PRNG so the sink regenerates the same
 * coefficients; it is metadata (typically the generation counter), carried in
 * the transmitted matrix but OUT of the data path.  It is supplied / recovered
 * by the scheme-2 framing functions and never touched by encrypt/decrypt.
 *
 * Security posture is identical to scheme 1 (weak / computational, authenticates
 * nothing): re-read the header banner.
 * ======================================================================== */

/* RREF precode encode: C = L^{-1} . P (RREF of [L | P] -> [I_m | C]).  Returns
 * VOLEITH_EC_ERR_SINGULAR if L has no inverse.  L is m*m, P and C are m*l. */
int voleith_confrlnc_precode_encode_s2(const voleith_confrlnc_params_t *p,
                                       const uint16_t *L, const uint16_t *P,
                                       uint16_t *C_out);

/* RREF precode decode: P = L . C (RLNC encode with L).  L is m*m, C and P are
 * m*l. */
int voleith_confrlnc_precode_decode_s2(const voleith_confrlnc_params_t *p,
                                       const uint16_t *L, const uint16_t *C,
                                       uint16_t *P_out);

/*
 * Encrypt a generation, scheme 2: data_out = T^{-1}(permute(T(L^{-1} . P))).
 * P and data_out are m*l coding elements.  Allocates internal scratch.  Returns
 * 0 on success, VOLEITH_EC_ERR_SINGULAR if L is not invertible, or another
 * negative VOLEITH_EC_ERR_*.  The n sync symbol is handled by the framing
 * functions, not here.
 */
int voleith_confrlnc_encrypt_s2(const voleith_confrlnc_params_t *p,
                                const uint16_t *L, const size_t *perm,
                                const uint16_t *P, uint16_t *data_out);

/*
 * Decrypt a generation, scheme 2: P_out = L . T^{-1}(permute_inverse(T(data))).
 * data and P_out are m*l coding elements.  Allocates internal scratch.  Returns
 * 0 on success or a negative VOLEITH_EC_ERR_*.
 */
int voleith_confrlnc_decrypt_s2(const voleith_confrlnc_params_t *p,
                                const uint16_t *L, const size_t *perm,
                                const uint16_t *data, uint16_t *P_out);

/* Columns of the scheme-2 transmitted matrix [I_m | n | data]: m + 1 + l. */
static inline size_t
voleith_confrlnc_transmitted_cols_s2(const voleith_confrlnc_params_t *p)
{
    return p->m + 1u + p->l;
}

/*
 * Build M_C = [I_m | n | data] (m rows, m+1+l cols, row-major).  n is the m
 * per-row PRNG-sync column (n[r] is row r's sync symbol; typically all equal to
 * the generation counter).  data is the m*l encrypted data block.
 */
int voleith_confrlnc_attach_identity_s2(const voleith_confrlnc_params_t *p,
                                        const uint16_t *n, const uint16_t *data,
                                        uint16_t *mc_out);

/*
 * Recover the n sync column (m entries) and the m*l data block from
 * M_C = [I_m | n | data].  n_out or data_out may be NULL to skip that output.
 * The identity block is structural framing and is not validated.
 */
int voleith_confrlnc_strip_identity_s2(const voleith_confrlnc_params_t *p,
                                       const uint16_t *mc, uint16_t *n_out,
                                       uint16_t *data_out);

/* ========================================================================
 * Key material
 * ======================================================================== */

/*
 * SAFE-DEFAULT key generation (the misuse-resistant path).  Deterministically
 * derives a uniform partial permutation and a full-rank secret matrix L from a
 * caller seed and generation id:
 *
 *   seed + generation_id -> (perm[n], L[m*m]).
 *
 * The permutation is a uniform Fisher-Yates shuffle drawn from core/prg.c; L
 * is rejection-sampled until erasure/matrix.c confirms it is invertible.  The
 * caller cannot produce a biased permutation or a singular L this way.  The
 * derivation is deterministic and versioned (VOLEITH_CONFRLNC_KDF_VERSION): it
 * is a WIRE CONTRACT, so source and sink deriving from the same (seed,
 * generation_id) obtain the same key.
 *
 * MISUSE WARNING (the caller owns these; the library CANNOT detect a violation
 * because keygen is a pure deterministic function with no persistent state):
 *   1. SEED ENTROPY. Confidentiality rests entirely on the seed. It MUST be
 *      full-length output of a cryptographic RNG. A predictable or low-entropy
 *      seed yields a predictable key. As a cheap tripwire keygen rejects an
 *      all-zero seed (a forgotten / uninitialized buffer) with
 *      VOLEITH_EC_ERR_PARAM, but this is NOT an entropy check: a nonzero but
 *      weak seed passes.
 *   2. generation_id UNIQUENESS. The derivation is deterministic, so the same
 *      (seed, generation_id) always yields the same (L, perm). generation_id
 *      MUST be unique per generation under a given seed (e.g. a monotonic
 *      counter). Reusing one is key reuse, which for this permutation-plus-
 *      linear cipher family can expose plaintext across the two ciphertexts.
 *      (Re-deriving the SAME key on the receiver side from the same inputs is
 *      the intended wire contract and is expected; the hazard is reusing the
 *      pair for a NEW generation.)
 * The application also owns key distribution. See ERASURE_CODES_DESIGN section
 * 7.0.
 *
 *   seed:           lambda/8 bytes, lambda in {128, 192, 256} (seed_len in
 *                   {16, 24, 32}); the PRG seed.
 *   generation_id:  an OPAQUE freshness label, fed only into the PRG IV (it is
 *                   never structurally bound to L: this keeps the future
 *                   in-circuit generation-commitment unconstrained, plan T7.1).
 *   perm_out:       n = m*l*t entries (caller allocates).
 *   L_out:          m*m coding elements (caller allocates).
 *
 * Returns 0 on success, VOLEITH_EC_ERR_PARAM on bad arguments (including an
 * all-zero seed), or (only under astronomically improbable sampling failure)
 * VOLEITH_EC_ERR_SINGULAR.
 */
int voleith_confrlnc_keygen(const voleith_confrlnc_params_t *p,
                            const uint8_t *seed, size_t seed_len,
                            uint32_t generation_id, size_t *perm_out,
                            uint16_t *L_out);

/*
 * VALIDATED bring-your-own key check (the advanced path).  Validates an
 * explicit permutation and matrix:
 *   - perm must be a permutation of [0, n): every entry < n, no repeats.
 *   - L must be invertible (full rank) over the coding field.
 * Returns 0 if both are valid, VOLEITH_EC_ERR_PARAM for a non-permutation
 * table, VOLEITH_EC_ERR_SINGULAR for a singular L, or another negative
 * VOLEITH_EC_ERR_* on bad arguments / allocation failure.  Errors are never
 * silent: an invalid key is rejected, not silently accepted.
 */
int voleith_confrlnc_validate_key(const voleith_confrlnc_params_t *p,
                                  const uint16_t *L, const size_t *perm);

#endif /* VOLEITH_ERASURE_RLNC_CONFIDENTIAL_H */
