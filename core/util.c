/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * util.c - Security-critical utility functions
 */

/* Request glibc POSIX.1-2008 + BSD extensions for explicit_bzero(3). */
#define _DEFAULT_SOURCE
/* Request the C11 Annex K bounds-checking interfaces (memset_s) on macOS. */
#define __STDC_WANT_LIB_EXT1__ 1

#include "util.h"
#include <stdint.h>
#include <string.h>

/* ================================================================
 * Secure memory zeroing
 * ================================================================ */

/*
 * Select a zeroing primitive that the compiler is not permitted to
 * optimize away (unlike a plain memset):
 *   - Linux (glibc >= 2.25) and OpenBSD / FreeBSD / NetBSD: explicit_bzero(3).
 *   - macOS: explicit_bzero is NOT provided by the SDK, but memset_s
 *     (C11 Annex K) is, and it carries the same no-elide guarantee.
 *   - Everything else: a volatile-pointer loop.
 */
#if defined(__linux__) || defined(__OpenBSD__) || defined(__FreeBSD__) ||      \
    defined(__NetBSD__)
#define VOLEITH_SECURE_ZERO_EXPLICIT_BZERO 1
#elif defined(__APPLE__)
#define VOLEITH_SECURE_ZERO_MEMSET_S 1
#endif

void
voleith_secure_zero(void *ptr, size_t len)
{
    if (!ptr || len == 0)
        return;
#if defined(VOLEITH_SECURE_ZERO_EXPLICIT_BZERO)
    explicit_bzero(ptr, len);
#elif defined(VOLEITH_SECURE_ZERO_MEMSET_S)
    memset_s(ptr, len, 0, len);
#else
    volatile uint8_t *vp = (volatile uint8_t *)ptr;
    while (len--)
        *vp++ = 0;
#endif
}

/* ================================================================
 * Constant-time comparison
 * ================================================================ */

int
voleith_const_memcmp(const void *a, const void *b, size_t len)
{
    const uint8_t *pa = (const uint8_t *)a;
    const uint8_t *pb = (const uint8_t *)b;
    /*
     * volatile prevents the compiler from short-circuiting the loop or
     * hoisting the early-exit optimization that a plain uint8_t would allow.
     */
    volatile uint8_t diff = 0;
    for (size_t i = 0; i < len; i++)
        diff = (uint8_t)(diff | (pa[i] ^ pb[i]));
    return (int)diff;
}
