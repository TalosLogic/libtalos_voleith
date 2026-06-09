/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * aes.c - AES-128/192/256 public forwarders and runtime dispatch init.
 *
 * On first call, voleith_aes_dispatch_init() reads voleith_cpu_features()
 * and selects the highest-priority compiled-in backend whose required
 * feature bits are present:
 *   1. AES-NI         (x86_64; VOLEITH_HAVE_AES_NI compiled in)
 *   2. ARMv8 Crypto   (aarch64; VOLEITH_HAVE_ARMV8_AES compiled in)
 *   3. Bitsliced      (portable constant-time; always compiled in)
 *
 * The selected ops pointer is stored with a release-store; subsequent
 * calls pay one load-acquire and one indirect branch.  All three
 * backends are constant-time; the dispatch decision is data-independent.
 */

#include "aes.h"
#include "aes_dispatch.h"
#include "cpu.h"
#include "util.h"

#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>

_Atomic(const voleith_aes_ops_t *) voleith_aes_ops = NULL;

static atomic_flag s_aes_warn_once = ATOMIC_FLAG_INIT;

void
voleith_aes_dispatch_init(void)
{
    if (atomic_load_explicit(&voleith_aes_ops, memory_order_acquire) != NULL)
        return;

    unsigned feat = voleith_cpu_features();
    const voleith_aes_ops_t *pick = NULL;

#ifdef VOLEITH_HAVE_AES_NI
    if (pick == NULL && (feat & VOLEITH_CPU_AES_NI))
        pick = &voleith_aes_ops_aesni;
#endif
#ifdef VOLEITH_HAVE_ARMV8_AES
    if (pick == NULL && (feat & VOLEITH_CPU_ARMV8_AES))
        pick = &voleith_aes_ops_armv8;
#endif
    if (pick == NULL)
        pick = &voleith_aes_ops_bitsliced;

#ifndef VOLEITH_HAVE_AES_NI
    if ((feat & VOLEITH_CPU_AES_NI) && getenv("VOLEITH_QUIET") == NULL &&
        !atomic_flag_test_and_set(&s_aes_warn_once))
        fputs("voleith: notice: host CPU has AES-NI but the aes-ni backend"
              " was not compiled in; running on bitsliced fallback"
              " (~30-50x slower). Rebuild with -DVOLEITH_AES_NI=ON."
              " Suppress with VOLEITH_QUIET=1.\n",
              stderr);
#endif
#ifndef VOLEITH_HAVE_ARMV8_AES
    if ((feat & VOLEITH_CPU_ARMV8_AES) && getenv("VOLEITH_QUIET") == NULL &&
        !atomic_flag_test_and_set(&s_aes_warn_once))
        fputs("voleith: notice: host CPU has ARMv8 AES but the armv8 backend"
              " was not compiled in; running on bitsliced fallback"
              " (~30-50x slower). Rebuild with -DVOLEITH_ARMV8_AES=ON."
              " Suppress with VOLEITH_QUIET=1.\n",
              stderr);
#endif

    const voleith_aes_ops_t *expected = NULL;
    atomic_compare_exchange_strong_explicit(&voleith_aes_ops, &expected, pick,
                                            memory_order_release,
                                            memory_order_acquire);
}

/* ========================================================================
 * Public forwarders
 * ======================================================================== */

int
voleith_aes_key_expand(voleith_aes_ctx_t *ctx, const uint8_t *key, int key_bits)
{
    const voleith_aes_ops_t *ops =
        atomic_load_explicit(&voleith_aes_ops, memory_order_acquire);
    if (ops == NULL) {
        voleith_aes_dispatch_init();
        ops = atomic_load_explicit(&voleith_aes_ops, memory_order_acquire);
    }
    return ops->key_expand(ctx, key, key_bits);
}

void
voleith_aes_encrypt(const voleith_aes_ctx_t *ctx, uint8_t out[16],
                    const uint8_t in[16])
{
    const voleith_aes_ops_t *ops =
        atomic_load_explicit(&voleith_aes_ops, memory_order_acquire);
    if (ops == NULL) {
        voleith_aes_dispatch_init();
        ops = atomic_load_explicit(&voleith_aes_ops, memory_order_acquire);
    }
    ops->encrypt(ctx, out, in);
}

void
voleith_aes_encrypt_x4(const voleith_aes_ctx_t *ctx, uint8_t out[64],
                       const uint8_t in[64])
{
    const voleith_aes_ops_t *ops =
        atomic_load_explicit(&voleith_aes_ops, memory_order_acquire);
    if (ops == NULL) {
        voleith_aes_dispatch_init();
        ops = atomic_load_explicit(&voleith_aes_ops, memory_order_acquire);
    }
    ops->encrypt_x4(ctx, out, in);
}

void
voleith_aes_ctx_clear(voleith_aes_ctx_t *ctx)
{
    voleith_secure_zero(ctx, sizeof(*ctx));
}

voleith_aes_backend_t
voleith_aes_backend(void)
{
    const voleith_aes_ops_t *ops =
        atomic_load_explicit(&voleith_aes_ops, memory_order_acquire);
    if (ops == NULL) {
        voleith_aes_dispatch_init();
        ops = atomic_load_explicit(&voleith_aes_ops, memory_order_acquire);
    }
    return ops->backend_tag;
}

const char *
voleith_aes_backend_name(void)
{
    switch (voleith_aes_backend()) {
    case VOLEITH_AES_BACKEND_AESNI:
        return "AES-NI (x86_64 hardware)";
    case VOLEITH_AES_BACKEND_ARMV8:
        return "ARMv8 Cryptography Extension (aarch64 hardware)";
    case VOLEITH_AES_BACKEND_BITSLICED:
        return "bitsliced (portable constant-time software)";
    }
    return "unknown";
}

void
voleith_aes_dispatch_reset(void)
{
    atomic_store_explicit(&voleith_aes_ops, NULL, memory_order_release);
}
