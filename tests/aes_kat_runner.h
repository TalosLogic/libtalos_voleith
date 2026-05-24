/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * aes_kat_runner.h - Backend-agnostic NIST AES known-answer-test
 * runner.
 *
 * Used by test_aes (validating the dispatch backend in core/aes.c)
 * and test_aes_ct64 (validating the bitsliced backend in
 * core/aes_ct64.c).  Any AES encrypt implementation that conforms
 * to the aes_encrypt_block_fn callback can be exercised against
 * the full NIST KAT corpus by calling aes_kat_run_all().
 *
 * Vectors covered:
 *   - FIPS 197 Appendix B (AES-128).
 *   - NIST SP 800-38A Appendix F.1 ECB (AES-128/192/256, blocks 1+2).
 *   - All-zeros key + plaintext for AES-128/192/256.
 *   - NIST CAVP ECBGFSbox-128/256.
 *   - NIST CAVP ECBKeySbox-128/256.
 *   - NIST CAVP ECBVarKey-128/256 (selected COUNT=0/7/49/127 / 0/7/127/255).
 *   - NIST CAVP ECBVarTxt-128/256 (selected COUNT=0/7/49/127 / 0/7/64/127).
 */

#ifndef VOLEITH_TEST_AES_KAT_RUNNER_H
#define VOLEITH_TEST_AES_KAT_RUNNER_H

#include <stdint.h>

/*
 * Backend-agnostic single-block AES encrypt.
 *
 * key_bits: 128, 192, or 256.
 * key:      pointer to key_bits/8 key bytes.
 * out:      output ciphertext (16 bytes).
 * in:       input plaintext (16 bytes).
 *
 * Returns 0 on success, nonzero on backend error (e.g., invalid
 * key size).  Implementations should clear their key context
 * before returning. */
typedef int (*aes_encrypt_block_fn)(int key_bits, const uint8_t *key,
                                    uint8_t out[16], const uint8_t in[16]);

/*
 * Run the full NIST KAT suite against the supplied backend.
 *
 * backend_name:  short label printed in test output ("voleith_aes",
 *                "aes_ct64", etc.).
 * encrypt_block: backend callback.
 * tests_run:     incremented once per vector exercised.
 * tests_passed:  incremented once per vector that matched.
 *
 * Returns 0 if all KATs passed, nonzero on any failure. */
int aes_kat_run_all(const char *backend_name,
                    aes_encrypt_block_fn encrypt_block, int *tests_run,
                    int *tests_passed);

#endif /* VOLEITH_TEST_AES_KAT_RUNNER_H */
