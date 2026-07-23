/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * cpu.h - alias shim over <ichor/cpu.h>.
 *
 * Runtime CPU feature detection moved to libtalos_ichor.  ichor now answers
 * "what CPU"; voleith keeps only the field-impl dispatch table
 * (core/field_dispatch.h), which reads the aliased detection unchanged.
 * See docs/private/ICHOR_MIGRATION_1_10_1.md.
 *
 * The feature bits are identical (ichor is a straight fork), so the flag
 * macros and the two entry points map 1:1.  voleith_cpu_features_override is
 * test-only in ichor: its alias resolves only under ICHOR_ENABLE_FORCE_BACKEND
 * (set on voleith's test / backend-sweep / dudect builds), matching the guard
 * on the ichor declaration.
 */

#ifndef VOLEITH_CPU_H
#define VOLEITH_CPU_H

#include <ichor/cpu.h>

#define VOLEITH_CPU_AES_NI ICHOR_CPU_AES_NI
#define VOLEITH_CPU_CLMUL ICHOR_CPU_CLMUL
#define VOLEITH_CPU_SSE41 ICHOR_CPU_SSE41
#define VOLEITH_CPU_SSSE3 ICHOR_CPU_SSSE3
#define VOLEITH_CPU_ARMV8_AES ICHOR_CPU_ARMV8_AES
#define VOLEITH_CPU_PMULL ICHOR_CPU_PMULL

#define voleith_cpu_features ichor_cpu_features

#ifdef ICHOR_ENABLE_FORCE_BACKEND
#define voleith_cpu_features_override ichor_cpu_features_override
#endif

#endif /* VOLEITH_CPU_H */
