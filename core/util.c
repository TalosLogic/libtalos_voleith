/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * util.c - Security-critical utility functions
 */

/* Request glibc POSIX.1-2008 + BSD extensions for explicit_bzero(3) */
#define _DEFAULT_SOURCE

#include "util.h"
#include <stdint.h>
#include <string.h>

/* ================================================================
 * Secure memory zeroing
 * ================================================================ */

/*
 * explicit_bzero(3) is available on:
 *   - Linux with glibc >= 2.25  (since Ubuntu 18.04)
 *   - macOS >= 10.12
 *   - OpenBSD, FreeBSD, NetBSD
 *
 * It is specifically designed to not be optimized away, unlike memset().
 * Fall back to a volatile-pointer loop on platforms that lack it.
 */
#if defined(__linux__) || defined(__OpenBSD__) || defined(__FreeBSD__) ||      \
    defined(__NetBSD__)
#define VOLEITH_HAVE_EXPLICIT_BZERO 1
#endif

void
voleith_secure_zero(void *ptr, size_t len)
{
    if (!ptr || len == 0)
        return;
#ifdef VOLEITH_HAVE_EXPLICIT_BZERO
    explicit_bzero(ptr, len);
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
