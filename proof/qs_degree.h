/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * qs_degree.h - QuickSilver constraint-degree bound (shared by the base /
 * GF(2^8) / GF(2^16) prover+verifier stacks).
 *
 * A QuickSilver constraint of degree d opens d+1 coefficients a_0..a_d through
 * the zk_hash (see docs/private/QS_DEGREE_D_DESIGN.md).  d=2 is the AND-gate /
 * assert baseline; the degree-d syndrome gadget for the RSV5 designated opener
 * raises it (up to 17 at lambda256, n0=2).  VOLEITH_QS_D_MAX bounds the fixed-
 * size coefficient storage in the zk_hash contexts; 32 is headroom over 17.
 *
 * The value is a compile-time storage bound only, NOT a wire/format constant:
 * the actual degree in force is carried in each zk_hash context's `d` field and
 * is a per-circuit property, never transmitted.
 */
#ifndef VOLEITH_QS_DEGREE_H
#define VOLEITH_QS_DEGREE_H

#define VOLEITH_QS_D_MAX 32u
#define VOLEITH_QS_COEFFS_MAX (VOLEITH_QS_D_MAX + 1u) /* a_0..a_d */

#endif /* VOLEITH_QS_DEGREE_H */
