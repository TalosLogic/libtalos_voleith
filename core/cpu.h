/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * cpu.h - Runtime CPU feature detection.
 *
 * Provides a one-shot bitmask describing the hardware acceleration
 * features available on the running CPU.  The mask is computed once
 * on first use and cached; subsequent calls pay a single atomic load.
 *
 * The detection layer is intentionally separate from the dispatch
 * tables in core/aes.c, core/field.c, and core/grostl.c.  Those
 * tables consume this mask; they are not referenced from here.
 */

#ifndef VOLEITH_CPU_H
#define VOLEITH_CPU_H

/* ========================================================================
 * Feature flags
 *
 * Bit assignments are stable across library versions.  Bits 0-15 are
 * reserved for x86_64 features; bits 16-31 for aarch64 features.
 * ======================================================================== */

#define VOLEITH_CPU_AES_NI (1u << 0)     /* x86_64: CPUID.01H:ECX[25] */
#define VOLEITH_CPU_CLMUL (1u << 1)      /* x86_64: CPUID.01H:ECX[1]  */
#define VOLEITH_CPU_SSE41 (1u << 2)      /* x86_64: CPUID.01H:ECX[19] */
#define VOLEITH_CPU_SSSE3 (1u << 3)      /* x86_64: CPUID.01H:ECX[9]  */
#define VOLEITH_CPU_ARMV8_AES (1u << 16) /* aarch64: HWCAP_AES        */
#define VOLEITH_CPU_PMULL (1u << 17)     /* aarch64: HWCAP_PMULL      */

/* ========================================================================
 * API
 * ======================================================================== */

/*
 * Return a bitmask of VOLEITH_CPU_* flags for the running CPU.
 *
 * Thread-safe.  The bitmask is computed on the first call via a
 * compare-and-swap guard; all subsequent calls return the cached value
 * with a single atomic load.
 */
unsigned voleith_cpu_features(void);

/*
 * Override the cached feature bitmask.
 *
 * Intended for tests and debugging.  Replaces the cached mask with
 * the supplied value; the next call to voleith_cpu_features() returns
 * that value instead of the probed hardware mask.
 *
 * Production use: setting this to a mask whose bits are a strict
 * subset of the probed hardware mask is valid (e.g., to force the
 * scalar fallback for A/B benchmarking).  Setting bits that the
 * running CPU does not support is a programming error and causes
 * subsequent dispatch-init calls to abort.
 */
void voleith_cpu_features_override(unsigned mask);

#endif /* VOLEITH_CPU_H */
