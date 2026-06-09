/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * test_cpu_features.c - Tests for the CPU feature detection layer.
 *
 * Validates:
 *   - voleith_cpu_features() returns the correct bitmask by cross-checking
 *     against compiler builtins (x86_64) or getauxval (aarch64).
 *   - voleith_cpu_features_override() replaces the cached mask.
 *   - The module is backend-agnostic: no aes.c / field.c / grostl.c
 *     reference to voleith_cpu_features() yet.
 */

#include "cpu.h"

#include <stdio.h>

#if defined(__aarch64__) && defined(__linux__)
#include <sys/auxv.h>
#ifndef HWCAP_AES
#define HWCAP_AES (1 << 3)
#endif
#ifndef HWCAP_PMULL
#define HWCAP_PMULL (1 << 4)
#endif
#endif

static int tests_run = 0;
static int tests_passed = 0;

#define TEST(name)                                                             \
    do {                                                                       \
        tests_run++;                                                           \
        printf("  [%2d] %-55s ", tests_run, name);                             \
    } while (0)

#define PASS()                                                                 \
    do {                                                                       \
        tests_passed++;                                                        \
        printf("PASS\n");                                                      \
    } while (0)

#define FAIL(msg)                                                              \
    do {                                                                       \
        printf("FAIL: %s\n", msg);                                             \
    } while (0)

/* ========================================================================
 * Test: basic probe returns a stable value
 * ======================================================================== */

static void
test_stable(void)
{
    TEST("voleith_cpu_features() stable across two calls");
    unsigned first = voleith_cpu_features();
    unsigned second = voleith_cpu_features();
    if (first == second)
        PASS();
    else
        FAIL("mask changed between calls");
}

/* ========================================================================
 * Test: x86_64 cross-check against __builtin_cpu_supports
 * ======================================================================== */

#if defined(__x86_64__) || defined(_M_X64)

static void
test_x86_aesni(void)
{
    TEST("x86_64: VOLEITH_CPU_AES_NI matches __builtin_cpu_supports(aes)");
    unsigned mask = voleith_cpu_features();
    int builtin_aes = __builtin_cpu_supports("aes");
    int our_aes = (mask & VOLEITH_CPU_AES_NI) != 0;
    if (our_aes == (builtin_aes != 0))
        PASS();
    else
        FAIL("AES-NI mismatch with compiler builtin");
}

static void
test_x86_clmul(void)
{
    TEST("x86_64: VOLEITH_CPU_CLMUL matches __builtin_cpu_supports(pclmul)");
    unsigned mask = voleith_cpu_features();
    int builtin = __builtin_cpu_supports("pclmul");
    int ours = (mask & VOLEITH_CPU_CLMUL) != 0;
    if (ours == (builtin != 0))
        PASS();
    else
        FAIL("CLMUL mismatch with compiler builtin");
}

static void
test_x86_ssse3(void)
{
    TEST("x86_64: VOLEITH_CPU_SSSE3 matches __builtin_cpu_supports(ssse3)");
    unsigned mask = voleith_cpu_features();
    int builtin = __builtin_cpu_supports("ssse3");
    int ours = (mask & VOLEITH_CPU_SSSE3) != 0;
    if (ours == (builtin != 0))
        PASS();
    else
        FAIL("SSSE3 mismatch with compiler builtin");
}

static void
test_x86_sse41(void)
{
    TEST("x86_64: VOLEITH_CPU_SSE41 matches __builtin_cpu_supports(sse4.1)");
    unsigned mask = voleith_cpu_features();
    int builtin = __builtin_cpu_supports("sse4.1");
    int ours = (mask & VOLEITH_CPU_SSE41) != 0;
    if (ours == (builtin != 0))
        PASS();
    else
        FAIL("SSE4.1 mismatch with compiler builtin");
}

#endif /* x86_64 */

/* ========================================================================
 * Test: aarch64 cross-check against getauxval
 * ======================================================================== */

#if defined(__aarch64__) && defined(__linux__)

static void
test_aarch64_aes(void)
{
    TEST("aarch64: VOLEITH_CPU_ARMV8_AES matches getauxval(AT_HWCAP)");
    unsigned mask = voleith_cpu_features();
    unsigned long hwcap = getauxval(AT_HWCAP);
    int our_aes = (mask & VOLEITH_CPU_ARMV8_AES) != 0;
    int hwcap_aes = (hwcap & HWCAP_AES) != 0;
    if (our_aes == hwcap_aes)
        PASS();
    else
        FAIL("ARMV8_AES mismatch with getauxval");
}

static void
test_aarch64_pmull(void)
{
    TEST("aarch64: VOLEITH_CPU_PMULL matches getauxval(AT_HWCAP)");
    unsigned mask = voleith_cpu_features();
    unsigned long hwcap = getauxval(AT_HWCAP);
    int our_pmull = (mask & VOLEITH_CPU_PMULL) != 0;
    int hwcap_pmull = (hwcap & HWCAP_PMULL) != 0;
    if (our_pmull == hwcap_pmull)
        PASS();
    else
        FAIL("PMULL mismatch with getauxval");
}

#endif /* aarch64 Linux */

/* ========================================================================
 * Test: override roundtrip
 * ======================================================================== */

static void
test_override_zero(void)
{
    TEST("override(0) then features() returns 0");
    unsigned original = voleith_cpu_features();
    voleith_cpu_features_override(0);
    unsigned after = voleith_cpu_features();
    /* Restore so later tests in the same process are not affected. */
    voleith_cpu_features_override(original);
    if (after == 0)
        PASS();
    else
        FAIL("features() did not return 0 after override(0)");
}

static void
test_override_restore(void)
{
    TEST("override then restore returns original mask");
    unsigned original = voleith_cpu_features();
    voleith_cpu_features_override(0);
    voleith_cpu_features_override(original);
    unsigned restored = voleith_cpu_features();
    if (restored == original)
        PASS();
    else
        FAIL("restored mask does not match original");
}

/* ========================================================================
 * Test: no arch flags set for a non-local arch
 * ======================================================================== */

static void
test_no_cross_arch_bits(void)
{
    TEST("no cross-architecture bits set");
    unsigned mask = voleith_cpu_features();
#if defined(__x86_64__) || defined(_M_X64)
    /* On x86_64, aarch64 bits must be clear. */
    if (mask & (VOLEITH_CPU_ARMV8_AES | VOLEITH_CPU_PMULL))
        FAIL("aarch64 bits set on x86_64 host");
    else
        PASS();
#elif defined(__aarch64__)
    /* On aarch64, x86_64 bits must be clear. */
    if (mask & (VOLEITH_CPU_AES_NI | VOLEITH_CPU_CLMUL | VOLEITH_CPU_SSE41 |
                VOLEITH_CPU_SSSE3))
        FAIL("x86_64 bits set on aarch64 host");
    else
        PASS();
#else
    /* Generic host: all bits should be zero. */
    if (mask != 0)
        FAIL("unexpected feature bits on generic host");
    else
        PASS();
#endif
}

/* ========================================================================
 * main
 * ======================================================================== */

int
main(void)
{
    printf("CPU feature detection tests\n");

    test_stable();
    test_no_cross_arch_bits();

#if defined(__x86_64__) || defined(_M_X64)
    test_x86_aesni();
    test_x86_clmul();
    test_x86_ssse3();
    test_x86_sse41();
#endif

#if defined(__aarch64__) && defined(__linux__)
    test_aarch64_aes();
    test_aarch64_pmull();
#endif

    test_override_zero();
    test_override_restore();

    printf("\n%d/%d tests passed\n", tests_passed, tests_run);
    return (tests_passed == tests_run) ? 0 : 1;
}
