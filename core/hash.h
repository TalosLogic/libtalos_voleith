/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * hash.h - alias shim over <ichor/hash.h>.
 *
 * SHA3-256 and SHAKE-128/256 (FIPS 202) moved to libtalos_ichor.  voleith's
 * Fiat-Shamir transcript and serialization call sites are kept
 * source-compatible by aliasing the voleith_* names to their ichor_*
 * originals.  See docs/private/ICHOR_MIGRATION_1_10_1.md.
 *
 * One deliberate signature change is adopted, not hidden: ichor's seven
 * *_absorb functions return int (0 on success, VOLEITH_HASH_ERR_FINALIZED if
 * called after squeeze/finalize) where voleith's returned void.  The aliases
 * therefore forward the int-returning form; voleith's absorb call sites check
 * the return so a mistaken absorb after squeeze is caught instead of silently
 * ignored.
 */

#ifndef VOLEITH_HASH_H
#define VOLEITH_HASH_H

#include <ichor/hash.h>

#define VOLEITH_HASH_ERR_FINALIZED ICHOR_HASH_ERR_FINALIZED

typedef ichor_hash_ctx_t voleith_hash_ctx_t;

#define voleith_sha3_256 ichor_sha3_256
#define voleith_sha3_256_init ichor_sha3_256_init
#define voleith_sha3_256_absorb ichor_sha3_256_absorb
#define voleith_sha3_256_finalize ichor_sha3_256_finalize

#define voleith_shake128_init ichor_shake128_init
#define voleith_shake128_absorb ichor_shake128_absorb
#define voleith_shake128_squeeze ichor_shake128_squeeze
#define voleith_shake128_absorb_u32_le ichor_shake128_absorb_u32_le
#define voleith_shake128_absorb_u64_le ichor_shake128_absorb_u64_le

#define voleith_shake256_init ichor_shake256_init
#define voleith_shake256_absorb ichor_shake256_absorb
#define voleith_shake256_squeeze ichor_shake256_squeeze
#define voleith_shake256_absorb_u32_le ichor_shake256_absorb_u32_le
#define voleith_shake256_absorb_u64_le ichor_shake256_absorb_u64_le

#define voleith_hash_ctx_clear ichor_hash_ctx_clear

#endif /* VOLEITH_HASH_H */
