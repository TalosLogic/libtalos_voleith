/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * ichor_compat.h - compile-time guard on the vendored libtalos_ichor version.
 *
 * voleith consumes the shared layer-0 symmetric core from libtalos_ichor (see
 * docs/private/ICHOR_MIGRATION_1_10_1.md).  The build enforces the supported
 * range at configure time by parsing <ichor/version.h>; this header is the
 * compile-time half, catching a header / library skew (a stale submodule
 * checkout, an injected mismatched ichor) at translation-unit compile with a
 * clear #error instead of a confusing downstream failure.
 *
 * Policy is semver SameMajorVersion: voleith 1.10.x accepts ichor 1.x
 * (>= 1.0.0, < 2.0.0).  A new ichor major requires porting voleith.
 */

#ifndef VOLEITH_ICHOR_COMPAT_H
#define VOLEITH_ICHOR_COMPAT_H

#include <ichor/version.h>

#if !defined(ICHOR_VERSION_MAJOR)
#error                                                                         \
    "ichor/version.h does not define ICHOR_VERSION_MAJOR; ichor predates 1.0.0 (update the submodule pin)"
#endif

#if ICHOR_VERSION_MAJOR != 1
#error                                                                         \
    "libtalos_ichor major version mismatch: voleith 1.10.x requires ichor 1.x (>= 1.0.0, < 2.0.0)"
#endif

#endif /* VOLEITH_ICHOR_COMPAT_H */
