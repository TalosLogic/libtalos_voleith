/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * convert.h - ConvertToVOLE (FAEST spec Section 5.2, Figure 5.2)
 *
 * Converts per-leaf seeds from a vector commitment into VOLE correlations.
 * Each vector i (of tau total) has N_i = 2^{k_i} seeds. The conversion
 * applies PRG to each seed, then performs a butterfly XOR reduction to
 * produce:
 *   - u:  the summary vector (outlen bytes), XOR of all PRG outputs
 *   - v:  depth vectors v[0..depth-1], each outlen bytes
 *
 * The VOLE correlation equation:
 *   q[j] = v[j] XOR delta_j * u   for all j in [0..depth)
 *
 * where delta is the binary decomposition of the hidden index.
 */

#ifndef VOLEITH_CONVERT_H
#define VOLEITH_CONVERT_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include "vc.h"

/*
 * ConvertToVOLE for a single vector instance.
 *
 * Given N_i seeds for vector i, applies PRG(sd_j, iv, tweak; outlen*8) to
 * each seed, then performs a butterfly XOR reduction across depth levels.
 *
 * iv:        128-bit initialization vector (16 bytes)
 * sd:        pointer to N_i consecutive seeds, each params->lambda/8 bytes
 *            For prover: all N_i seeds present.
 *            For verifier: seed at position 0 is absent (zeroed/skipped).
 * sd0_bot:   if true, the first seed (index 0 after XOR-permutation) is
 *            missing (verifier side). PRG for that seed is skipped.
 * vec_index: the vector index i in [0..tau)
 * outlen:    output length per PRG call in bytes (ellhat_bytes)
 * u:         output summary vector (outlen bytes), NULL if sd0_bot
 * v:         output array of depth pointers, each pointing to outlen bytes.
 *            v[0..depth-1] are written. Caller must allocate.
 * params:    VC parameters
 *
 * Returns the depth (k or k-1) = number of v vectors produced.
 */
int voleith_convert_to_vole(const uint8_t *iv, const uint8_t *sd, bool sd0_bot,
                            int vec_index, size_t outlen, uint8_t *u,
                            uint8_t **v, const voleith_vc_params_t *params);

/*
 * VOLE Commit - prover side.
 *
 * Runs BAVC.Commit, then ConvertToVOLE for each of the tau vectors,
 * producing the full VOLE correlation.
 *
 * params:    VC parameters
 * root_seed: lambda/8 bytes, the root seed
 * iv:        128-bit initialization vector (16 bytes)
 * ellhat:    total number of output bits for VOLE (determines outlen)
 * bavc:      output - the committed BAVC (caller-allocated struct)
 * c:         output - correction values, (tau-1) * ellhat_bytes bytes
 * u:         output - summary vector, ellhat_bytes bytes
 * v:         output - array of lambda pointers, each to ellhat_bytes bytes.
 *            Caller allocates the pointer array and the buffers.
 *
 * Returns 0 on success, -1 on error.
 */
int voleith_vole_commit(const voleith_vc_params_t *params,
                        const uint8_t *root_seed, const uint8_t iv[16],
                        unsigned int ellhat, voleith_bavc_t *bavc, uint8_t *c,
                        uint8_t *u, uint8_t **v);

/*
 * VOLE Reconstruct - verifier side.
 *
 * Given a BAVC opening and challenge indices, reconstructs the VOLE
 * correlation vectors q[0..lambda-1] on the verifier side.
 *
 * params:    VC parameters
 * opening:   the BAVC opening from the prover
 * i_delta:   array of tau challenge indices
 * iv:        128-bit initialization vector (16 bytes)
 * ellhat:    total number of output bits
 * c:         correction values from prover, (tau-1) * ellhat_bytes bytes
 * com:       output - reconstructed global commitment, 2*lambda/8 bytes
 * q:         output - array of lambda pointers, each to ellhat_bytes bytes.
 *            Caller allocates the pointer array and the buffers.
 *
 * Returns 0 on success, -1 on error.
 */
int voleith_vole_reconstruct(const voleith_vc_params_t *params,
                             const voleith_bavc_opening_t *opening,
                             const size_t *i_delta, const uint8_t iv[16],
                             unsigned int ellhat, const uint8_t *c,
                             uint8_t *com, uint8_t **q);

#endif /* VOLEITH_CONVERT_H */
