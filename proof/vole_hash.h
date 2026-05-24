/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * vole_hash.h - VOLEHash universal hash (FAEST spec Section 4.3.3, Figure 4.4)
 *
 * Compresses a VOLE vector x into lambda/8 + VOLEITH_VOLE_HASH_B bytes using
 * a two-polynomial Horner evaluation scheme parameterized by the seed sd.
 *
 * The seed sd is the output of H_2^1 (chall_1), 5*lambda/8 + 8 bytes:
 *   sd = r0 | r1 | r2 | r3 | s | t
 * where r0,r1,r2,r3,s are GF(2^lambda) elements (lambda/8 bytes each)
 * and t is a GF(2^64) element (8 bytes).
 *
 * The input x is the full VOLE vector (ellhat_bytes), split as:
 *   x0 = x[0 .. (ell + 2*lambda)/8 - 1]   (data portion: ell + 2*lambda bits)
 *   x1 = x[(ell + 2*lambda)/8 ..]          (blinding: lambda/8 + VOLEITH_VOLE_HASH_B bytes)
 *
 * Algorithm (from x0):
 *   h0 = Horner eval in GF(2^lambda) of lambda-bit chunks of x0 using key s
 *   h1 = Horner eval in GF(2^64) of 64-bit words of x0 using key t
 *   h2 = r0*h0 + r1*h1_ext   (h1 zero-extended to lambda bits)
 *   h3 = r2*h0 + r3*h1_ext
 *   output = (h2 || h3[0..VOLEITH_VOLE_HASH_B-1]) XOR x1
 */

#ifndef VOLEITH_VOLE_HASH_H
#define VOLEITH_VOLE_HASH_H

#include <stdint.h>
#include <stddef.h>

/* Blinding bytes appended to VOLEHash output (= UNIVERSAL_HASH_B in faest-ref) */
#define VOLEITH_VOLE_HASH_B 2

/*
 * VOLEHash: compress a VOLE vector into lambda/8 + VOLEITH_VOLE_HASH_B bytes.
 *
 * h_out:  output buffer, lambda/8 + VOLEITH_VOLE_HASH_B bytes
 * sd:     hash seed (= chall_1), 5*lambda/8 + 8 bytes
 * x:      input VOLE vector, ellhat_bytes = ceil((ell + 3*lambda + 16) / 8) bytes
 * ell:    QuickSilver ell = witness_count + and_gate_count (NOT ellhat)
 * lambda: security parameter: 128, 192, or 256
 */
void voleith_vole_hash(uint8_t *h_out, const uint8_t *sd, const uint8_t *x,
                       size_t ell, unsigned int lambda);

#endif /* VOLEITH_VOLE_HASH_H */
