/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * util.h - alias shim over <ichor/util.h>.
 *
 * The security-critical utilities (secure_zero, constant-time memcmp) moved
 * to libtalos_ichor, the shared layer-0 symmetric core.  This header keeps
 * voleith's internal call sites unchanged by aliasing the voleith_* names to
 * their ichor_* originals.  See docs/private/ICHOR_MIGRATION_1_10_1.md.
 *
 * voleith_secure_zero  -> ichor_secure_zero
 * voleith_const_memcmp -> ichor_const_memcmp
 */

#ifndef VOLEITH_UTIL_H
#define VOLEITH_UTIL_H

#include <ichor/util.h>

#define voleith_secure_zero ichor_secure_zero
#define voleith_const_memcmp ichor_const_memcmp

#endif /* VOLEITH_UTIL_H */
