/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * aes.h - alias shim over <ichor/aes.h>.
 *
 * The AES-128/192/256 block cipher (encrypt only) and its runtime backend
 * dispatch moved to libtalos_ichor.  voleith's internal call sites (the
 * AES-CTR PRG in core/prg.c, Hirose, the AES circuits' software oracles) are
 * kept source-compatible by aliasing the voleith_* names to their ichor_*
 * originals.  See docs/private/ICHOR_MIGRATION_1_10_1.md.
 *
 * The context type, storage size, backend enum, and all signatures are
 * identical (ichor is a straight fork).  ichor's aes.h additionally exposes
 * ichor_aes_ctr (nonce/counter split); voleith's PRG stays voleith-side and
 * does not use it, so it is not aliased here.
 *
 * voleith_aes_dispatch_reset is test-only in ichor: its alias resolves only
 * under ICHOR_ENABLE_FORCE_BACKEND (set on voleith's test / backend-sweep /
 * dudect builds), matching the guard on the ichor declaration.
 */

#ifndef VOLEITH_AES_H
#define VOLEITH_AES_H

#include <ichor/aes.h>

#define VOLEITH_AES_CTX_STORAGE_BYTES ICHOR_AES_CTX_STORAGE_BYTES

typedef ichor_aes_ctx_t voleith_aes_ctx_t;
typedef ichor_aes_backend_t voleith_aes_backend_t;

#define VOLEITH_AES_BACKEND_AESNI ICHOR_AES_BACKEND_AESNI
#define VOLEITH_AES_BACKEND_ARMV8 ICHOR_AES_BACKEND_ARMV8
#define VOLEITH_AES_BACKEND_BITSLICED ICHOR_AES_BACKEND_BITSLICED

#define voleith_aes_key_expand ichor_aes_key_expand
#define voleith_aes_encrypt ichor_aes_encrypt
#define voleith_aes_encrypt_x4 ichor_aes_encrypt_x4
#define voleith_aes_ctx_clear ichor_aes_ctx_clear
#define voleith_aes_backend ichor_aes_backend
#define voleith_aes_backend_name ichor_aes_backend_name
#define voleith_aes_dispatch_init ichor_aes_dispatch_init

#ifdef ICHOR_ENABLE_FORCE_BACKEND
#define voleith_aes_dispatch_reset ichor_aes_dispatch_reset
#endif

#endif /* VOLEITH_AES_H */
