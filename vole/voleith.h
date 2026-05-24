/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * voleith.h - VOLEitH protocol layer (FAEST spec Section 5.3)
 *
 * This layer sits above the BAVC (vc.h) and ConvertToVOLE (convert.h) layers
 * and provides the structured prover/verifier API for the VOLEitH protocol:
 *
 *   1. Prover commits: voleith_commit() → (commitment, prover_state)
 *   2. Challenge: voleith_decode_challenge() → i_delta[0..tau)
 *   3. Prover opens: voleith_open() → opening
 *   4. Verifier reconstructs: voleith_reconstruct() → q[0..lambda), 0 if valid
 *
 * The commitment contains everything the verifier needs before the challenge:
 *   - hcom = bavc.com: the BAVC global commitment hash (2*lambda/8 bytes)
 *   - u:  VOLE summary vector (ellhat_bytes)
 *   - c:  correction values ((tau-1)*ellhat_bytes)
 *
 * The prover state retains the BAVC and v vectors for the open phase and
 * for the QuickSilver proof layer that follows.
 */

#ifndef VOLEITH_VOLEITH_H
#define VOLEITH_VOLEITH_H

#include <stdint.h>
#include <stddef.h>
#include "vc.h"
#include "convert.h"

/*
 * Commitment - what the prover sends before seeing the challenge.
 *
 * hcom is bavc.com: the global BAVC commitment hash.
 * u and c are the VOLE correlation outputs from ConvertToVOLE.
 */
typedef struct {
    uint8_t *hcom;       /* 2 * lambda/8 bytes: BAVC global commitment */
    uint8_t *u;          /* ellhat_bytes: VOLE summary vector */
    uint8_t *c;          /* (tau-1) * ellhat_bytes: correction values */
    unsigned int ellhat; /* total VOLE output bits */
    unsigned int lambda; /* security parameter */
    unsigned int tau;    /* number of VOLE instances */
} voleith_commitment_t;

/*
 * Prover state - internal state retained after commit, not sent to verifier.
 *
 * Holds the BAVC (for opening) and v vectors (for QuickSilver).
 */
typedef struct {
    voleith_bavc_t bavc; /* full BAVC: GGM tree, leaf coms, global com */
    uint8_t **v;         /* lambda pointers, each to ellhat_bytes */
    uint8_t *_v_buf;     /* backing buffer for v (lambda * ellhat_bytes) */
    unsigned int ellhat;
    unsigned int lambda;
} voleith_prover_t;

/*
 * Derive the VOLEitH decommitment challenge from the commitment material.
 *
 * Computes: delta = SHAKE-256(iv || hcom || u || c) → lambda/8 bytes
 *
 * This provides a standalone (non-interactive) Fiat-Shamir challenge for
 * the VOLE layer. In the full proof system (Phase 8), the Fiat-Shamir
 * transcript will additionally absorb public inputs, QuickSilver outputs,
 * and domain separation before squeezing this challenge.
 *
 * iv:    16-byte initialization vector (same as used in commit)
 * com:   commitment from voleith_commit (provides hcom, u, c, ellhat, tau)
 * delta: output, lambda/8 bytes of challenge material
 */
void voleith_challenge_from_commitment(const uint8_t iv[16],
                                       const voleith_commitment_t *com,
                                       uint8_t *delta);

/*
 * Decode a lambda-bit challenge into per-vector challenge indices.
 *
 * The challenge delta is a sequence of lambda bits packed into lambda/8 bytes
 * (little-endian bit order). Consecutive groups of k or k-1 bits are extracted
 * for each VOLE instance to form i_delta[0..tau).
 *
 * delta:    lambda/8 bytes of challenge material
 * params:   VC parameters
 * i_delta:  output array of tau indices; i_delta[i] in [0..N_i)
 */
void voleith_decode_challenge(const uint8_t *delta,
                              const voleith_vc_params_t *params,
                              size_t *i_delta);

/*
 * Prover commit phase.
 *
 * Runs BAVC.Commit + ConvertToVOLE for all tau instances, producing:
 *   - com->hcom = bavc.com (global commitment hash)
 *   - com->u    (VOLE summary vector)
 *   - com->c    (correction values)
 *   - state->bavc (full GGM tree, needed for voleith_open)
 *   - state->v    (VOLE tag vectors, needed for QuickSilver)
 *
 * params:     VC parameters
 * root_seed:  lambda/8 bytes, the root GGM seed
 * iv:         16-byte initialization vector
 * ellhat:     total VOLE output bits (= ell + 3*lambda + UNIVERSAL_HASH_B_BITS)
 * com:        output commitment (caller-allocated struct; contents malloc'd)
 * state:      output prover state (caller-allocated struct; contents malloc'd)
 *
 * Returns 0 on success, -1 on allocation failure.
 * Caller must call voleith_commitment_free() and voleith_prover_free().
 */
int voleith_commit(voleith_commitment_t *com, voleith_prover_t *state,
                   const voleith_vc_params_t *params, const uint8_t *root_seed,
                   const uint8_t iv[16], unsigned int ellhat);

/*
 * Prover open phase.
 *
 * Runs BAVC.Open at the challenged indices i_delta, producing the
 * decommitment that the verifier needs to reconstruct VOLE correlations.
 *
 * state:    prover state from voleith_commit
 * params:   VC parameters
 * i_delta:  tau challenge indices from voleith_decode_challenge
 * opening:  output BAVC opening (caller-allocated struct; contents malloc'd)
 *
 * Returns 0 on success, -1 on error.
 * Caller must call voleith_bavc_opening_free() on the opening.
 */
int voleith_open(voleith_bavc_opening_t *opening, const voleith_prover_t *state,
                 const voleith_vc_params_t *params, const size_t *i_delta);

/*
 * Verifier reconstruct phase.
 *
 * Runs BAVC.Reconstruct + ConvertToVOLE (verifier side) to produce q, then
 * checks that the reconstructed commitment matches com->hcom.
 *
 * com:      commitment from the prover (hcom, u, c, ellhat, lambda, tau)
 * opening:  BAVC opening from the prover
 * params:   VC parameters
 * i_delta:  tau challenge indices
 * iv:       16-byte initialization vector (same as used in commit)
 * q:        output array of lambda pointers, each to ellhat_bytes.
 *           Caller allocates all buffers.
 *
 * Returns 0 if the commitment check passes (hcom matches reconstructed com),
 *        -1 if the check fails or on error.
 */
int voleith_reconstruct(const voleith_commitment_t *com,
                        const voleith_bavc_opening_t *opening,
                        const voleith_vc_params_t *params,
                        const size_t *i_delta, const uint8_t iv[16],
                        uint8_t **q);

/*
 * Free all heap memory in a commitment.
 */
void voleith_commitment_free(voleith_commitment_t *com);

/*
 * Free all heap memory in a prover state.
 * Securely zeros the BAVC tree and v vectors before freeing.
 */
void voleith_prover_free(voleith_prover_t *state);

#endif /* VOLEITH_VOLEITH_H */
