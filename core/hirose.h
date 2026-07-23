/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * hirose.h - alias shim over <ichor/hirose.h>.
 *
 * The Hirose double-block-length compression iteration `f` moved to
 * libtalos_ichor (shared with libtalos_syndrome's Argus opener-KDF).  The
 * voleith Merkle-layer framing built on top of `f` stays voleith-side in
 * circuits/node_hash_hirose_gf8.c.  See docs/private/ICHOR_MIGRATION_1_10_1.md.
 *
 * voleith_hirose_iteration -> ichor_hirose_iteration
 */

#ifndef VOLEITH_HIROSE_H
#define VOLEITH_HIROSE_H

#include <ichor/hirose.h>

#define voleith_hirose_iteration ichor_hirose_iteration

#endif /* VOLEITH_HIROSE_H */
