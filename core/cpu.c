/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * cpu.c - Cached CPU feature query and override hook.
 *
 * The bitmask is computed once on first use via a hand-rolled
 * compare-and-swap guard on a static atomic unsigned.  Sentinel value
 * 0x80000000u means "not yet initialized"; the high bit lies outside
 * the defined feature bits (all in bits 0-17), so post-init values
 * never collide with the sentinel.
 *
 * Per-architecture probing lives in cpu_x86.c, cpu_aarch64.c, and
 * cpu_generic.c; exactly one of those files defines voleith_cpu_probe()
 * for any given build target.
 *
 * VOLEITH_FORCE_BACKEND: comma-separated list of domain:value pairs
 * read once during the first call to voleith_cpu_features().  Used to
 * strip feature bits so the dispatch tables route to a specific backend.
 * Format example: "aes:bitsliced,field:scalar,grostl:sw".
 * Unknown domains or values cause a stderr message followed by abort().
 */

#include "cpu.h"

#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CPU_FEATURES_UNINIT 0x80000000u

static _Atomic(unsigned) g_features = CPU_FEATURES_UNINIT;

/* Provided by the per-arch TU compiled for this target. */
unsigned voleith_cpu_probe(void);

/* ========================================================================
 * VOLEITH_FORCE_BACKEND parser
 * ======================================================================== */

/*
 * Parse the VOLEITH_FORCE_BACKEND environment variable and return a
 * modified feature mask.  Unknown domains and values abort with a
 * diagnostic to stderr.
 */
static unsigned
apply_force_backend(unsigned mask)
{
    const char *env = getenv("VOLEITH_FORCE_BACKEND");
    if (env == NULL)
        return mask;

    /* Copy into a local buffer.  A value over 255 chars is malformed. */
    char buf[256];
    size_t len = strlen(env);
    if (len >= sizeof(buf)) {
        fprintf(stderr,
                "voleith: VOLEITH_FORCE_BACKEND value too long (max 255)\n");
        abort();
    }
    memcpy(buf, env, len + 1);

    const char *p = buf;
    while (*p != '\0') {
        /* Find the ':' separating domain from value. */
        const char *colon = p;
        while (*colon != ':' && *colon != ',' && *colon != '\0')
            colon++;
        if (*colon != ':') {
            fprintf(stderr,
                    "voleith: VOLEITH_FORCE_BACKEND: "
                    "expected domain:value, got: %.64s\n",
                    p);
            abort();
        }

        /* Find end of value (next comma or NUL). */
        const char *vstart = colon + 1;
        const char *vend = vstart;
        while (*vend != ',' && *vend != '\0')
            vend++;

        size_t dlen = (size_t)(colon - p);
        size_t vlen = (size_t)(vend - vstart);

#define DMATCH(s) (dlen == sizeof(s) - 1 && memcmp(p, (s), dlen) == 0)
#define VMATCH(s) (vlen == sizeof(s) - 1 && memcmp(vstart, (s), vlen) == 0)

        if (DMATCH("aes")) {
            if (VMATCH("bitsliced")) {
                mask &= ~(VOLEITH_CPU_AES_NI | VOLEITH_CPU_ARMV8_AES);
            } else if (VMATCH("aesni")) {
                if (!(mask & VOLEITH_CPU_AES_NI)) {
                    fprintf(stderr, "voleith: VOLEITH_FORCE_BACKEND=aes:aesni "
                                    "but AES-NI not detected on this CPU\n");
                    abort();
                }
                mask &= ~VOLEITH_CPU_ARMV8_AES;
            } else if (VMATCH("armv8")) {
                if (!(mask & VOLEITH_CPU_ARMV8_AES)) {
                    fprintf(stderr, "voleith: VOLEITH_FORCE_BACKEND=aes:armv8 "
                                    "but ARMv8 AES not detected on this CPU\n");
                    abort();
                }
                mask &= ~VOLEITH_CPU_AES_NI;
            } else {
                fprintf(stderr,
                        "voleith: VOLEITH_FORCE_BACKEND: "
                        "unknown aes value '%.*s' "
                        "(valid: aesni, armv8, bitsliced)\n",
                        (int)vlen, vstart);
                abort();
            }
        } else if (DMATCH("field")) {
            if (VMATCH("scalar")) {
                mask &= ~(VOLEITH_CPU_CLMUL | VOLEITH_CPU_PMULL);
            } else if (VMATCH("clmul")) {
                if (!(mask & VOLEITH_CPU_CLMUL)) {
                    fprintf(stderr,
                            "voleith: VOLEITH_FORCE_BACKEND=field:clmul "
                            "but CLMUL not detected on this CPU\n");
                    abort();
                }
                mask &= ~VOLEITH_CPU_PMULL;
            } else if (VMATCH("pmull")) {
                if (!(mask & VOLEITH_CPU_PMULL)) {
                    fprintf(stderr,
                            "voleith: VOLEITH_FORCE_BACKEND=field:pmull "
                            "but PMULL not detected on this CPU\n");
                    abort();
                }
                mask &= ~VOLEITH_CPU_CLMUL;
            } else {
                fprintf(stderr,
                        "voleith: VOLEITH_FORCE_BACKEND: "
                        "unknown field value '%.*s' "
                        "(valid: clmul, pmull, scalar)\n",
                        (int)vlen, vstart);
                abort();
            }
        } else if (DMATCH("grostl")) {
            if (VMATCH("soft")) {
                mask &= ~(VOLEITH_CPU_AES_NI | VOLEITH_CPU_ARMV8_AES);
            } else if (VMATCH("aesni")) {
                if (!(mask & VOLEITH_CPU_AES_NI)) {
                    fprintf(stderr,
                            "voleith: VOLEITH_FORCE_BACKEND=grostl:aesni "
                            "but AES-NI not detected on this CPU\n");
                    abort();
                }
                mask &= ~VOLEITH_CPU_ARMV8_AES;
            } else if (VMATCH("armv8")) {
                if (!(mask & VOLEITH_CPU_ARMV8_AES)) {
                    fprintf(stderr,
                            "voleith: VOLEITH_FORCE_BACKEND=grostl:armv8 "
                            "but ARMv8 AES not detected on this CPU\n");
                    abort();
                }
                mask &= ~VOLEITH_CPU_AES_NI;
            } else {
                fprintf(stderr,
                        "voleith: VOLEITH_FORCE_BACKEND: "
                        "unknown grostl value '%.*s' "
                        "(valid: aesni, armv8, soft)\n",
                        (int)vlen, vstart);
                abort();
            }
        } else {
            fprintf(stderr,
                    "voleith: VOLEITH_FORCE_BACKEND: "
                    "unknown domain '%.*s' "
                    "(valid: aes, field, grostl)\n",
                    (int)dlen, p);
            abort();
        }

#undef DMATCH
#undef VMATCH

        p = (*vend == ',') ? vend + 1 : vend;
    }
    return mask;
}

/* ========================================================================
 * Public API
 * ======================================================================== */

unsigned
voleith_cpu_features(void)
{
    unsigned cur;
    unsigned probed;
    unsigned expected;

    cur = atomic_load_explicit(&g_features, memory_order_acquire);
    if (cur != CPU_FEATURES_UNINIT)
        return cur;

    probed = apply_force_backend(voleith_cpu_probe());
    expected = CPU_FEATURES_UNINIT;

    /*
     * CAS: winner stores probed; loser's value is dropped.  Both
     * paths then re-read, returning the winner's value.  The probe
     * is deterministic so either result is identical.
     */
    atomic_compare_exchange_strong_explicit(&g_features, &expected, probed,
                                            memory_order_release,
                                            memory_order_acquire);
    return atomic_load_explicit(&g_features, memory_order_acquire);
}

void
voleith_cpu_features_override(unsigned mask)
{
    atomic_store_explicit(&g_features, mask, memory_order_release);
}
