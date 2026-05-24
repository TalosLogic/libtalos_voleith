/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * kdf_ctr_cmac_circuit.h - KDF in Counter Mode using AES-CMAC as PRF
 *
 * Implements NIST SP 800-108r1-upd1 Section 4.1 (KDF in Counter Mode)
 * with AES-CMAC as the pseudorandom function.
 *
 * Message format per iteration (r = 32, counter is 32-bit big-endian):
 *   K(i) = CMAC(K_IN, [i]_32 || fixed_input),  i = 1, 2, ..., n
 *   K_OUT = leftmost output_bits of K(1) || K(2) || ... || K(n)
 *
 * where:
 *   [i]_32      = 32-bit big-endian encoding of counter i (constant wires)
 *   fixed_input = caller-supplied FixedInputData: Label || 0x00 || Context
 *                 || [L]_r (or any subset thereof per the application
 *                 protocol); must be byte-aligned
 *
 * The FixedInputData is treated as an opaque blob, matching the NIST CAVS
 * test vector format exactly.  The caller is responsible for constructing
 * fixed_input with whatever fields the application protocol requires.
 *
 * When to include [L]_r in fixed_input:
 *   If the same (K_IN, Label, Context) tuple will ever be used to derive
 *   keying material of two different lengths, append a big-endian encoding
 *   of output_bits to fixed_input so that the two calls produce independent
 *   key streams rather than one being a prefix of the other.  For example,
 *   a protocol that sometimes derives 128-bit keys and sometimes derives
 *   256-bit keys from the same KDK and label should include [L]_32 to
 *   prevent the 128-bit output from being the first half of the 256-bit
 *   output.  If output length is fixed by the protocol, [L]_r adds no
 *   value and may be omitted.
 *
 * Security note - CMAC Key Control Issue (NIST SP 800-108r1 Appendix B):
 *   When CMAC is used as the PRF and a party both knows K_IN and controls
 *   a sufficiently large portion of fixed_input (spanning multiple CMAC
 *   input blocks), they may be able to force a derived key block K(i) to a
 *   preselected value.  The spec suggests an optional mitigation: prepend
 *   K(0) = CMAC(K_IN, fixed_input) to each iteration's message.
 *
 *   This implementation uses the base counter mode.  In VOLEitH ZK proof
 *   circuits the KDK (K_IN) is the prover's secret witness, so an adversary
 *   cannot simultaneously know K_IN and control fixed_input.  If deploying
 *   in a multi-party KDF scenario where an adversary knows K_IN and controls
 *   fixed_input content, prepend a K(0) CMAC call per Section 4.1.
 *
 * AND gate cost:
 *   n = ceil(output_bits / 128) CMAC calls.
 *   Each CMAC call costs (1 + ceil(msg_bytes / 16)) × AES_AND_gates,
 *   where msg_bytes = 4 + fixed_input_bytes (4-byte counter prefix),
 *   and AES_AND_gates = 7200 (AES-128) or 9936 (AES-256).
 *
 * Constraints:
 *   - key_bits must be 128 or 256.
 *   - fixed_input_bits must be a multiple of 8 (byte-aligned).
 *   - output_bits must be > 0 and a multiple of 8.
 *   - n = ceil(output_bits / 128) must be <= 2^32 - 1.
 */

#ifndef VOLEITH_KDF_CTR_CMAC_CIRCUIT_H
#define VOLEITH_KDF_CTR_CMAC_CIRCUIT_H

#include "circuit.h"
#include <stddef.h>

/*
 * kdf_ctr_cmac_circuit - KDF in Counter Mode using AES-CMAC as PRF.
 *
 * Appends gates to circuit c for NIST SP 800-108r1 Section 4.1.
 *
 * Parameters:
 *   c                  - circuit to append gates to
 *   key                - wire IDs for the KDK (key_bits = 128 or 256)
 *   key_bits           - 128 or 256
 *   fixed_input        - wire IDs for FixedInputData (byte-aligned);
 *                        may be NULL when fixed_input_bits = 0
 *   fixed_input_bits   - bit length of fixed_input (must be multiple of 8)
 *   output             - caller-allocated array of output_bits wire IDs;
 *                        receives wire IDs for derived keying material K_OUT
 *   output_bits        - requested output length in bits (multiple of 8, > 0)
 */
void kdf_ctr_cmac_circuit(voleith_circuit_t *c, const wire_id *key,
                          size_t key_bits, const wire_id *fixed_input,
                          size_t fixed_input_bits, wire_id *output,
                          size_t output_bits);

#endif /* VOLEITH_KDF_CTR_CMAC_CIRCUIT_H */
