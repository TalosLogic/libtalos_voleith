/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * util.h - Security-critical utility functions
 *
 * Provides:
 *   voleith_secure_zero   - zero memory in a way the compiler cannot elide
 *   voleith_const_memcmp  - constant-time byte comparison (no data-dependent branches)
 */

#ifndef VOLEITH_UTIL_H
#define VOLEITH_UTIL_H

#include <stddef.h>

/*
 * Zero len bytes at ptr.  The zeroing is guaranteed not to be optimized away
 * by the compiler, making it safe for erasing key material and witness data.
 *
 * Uses explicit_bzero(3) on POSIX platforms (Linux glibc ≥ 2.25, macOS,
 * BSDs) and a volatile-pointer loop elsewhere.
 */
void voleith_secure_zero(void *ptr, size_t len);

/*
 * Compare len bytes at a and b in constant time.
 *
 * Returns 0 if all bytes are equal, non-zero otherwise.
 * Always reads all len bytes regardless of content - no early exit.
 *
 * PROJECT POLICY: library code uses this for EVERY byte comparison, never plain
 * memcmp -- so no one has to judge case by case whether a given buffer is
 * secret. Plain memcmp() is allowed only in tests and examples (e.g. comparing
 * expected vs actual outputs). Note this reports only equal / not-equal; if you
 * need ordering (memcmp's sign), write an explicit comparator instead.
 */
int voleith_const_memcmp(const void *a, const void *b, size_t len);

#endif /* VOLEITH_UTIL_H */
