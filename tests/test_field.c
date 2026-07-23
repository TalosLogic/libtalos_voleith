/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * test_field.c - Test suite for GF(2^k) field arithmetic
 *
 * GF(2^8) and GF(2^64) tests run once (single-implementation).
 * GF(2^128/192/256) and ByteCombine tests run against whatever field backend
 * is active.  CTest registers this binary twice -- once with the hardware
 * backend and once with ICHOR_FORCE_BACKEND=clmul:scalar (the voleith field
 * backend rides the CLMUL/PMULL feature bits) -- to cover both paths.
 */

#include "field.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int tests_run = 0;
static int tests_passed = 0;

#define TEST(name)                                                             \
    do {                                                                       \
        tests_run++;                                                           \
        printf("  %-50s ", name);                                              \
    } while (0)

#define PASS()                                                                 \
    do {                                                                       \
        tests_passed++;                                                        \
        printf("[PASS]\n");                                                    \
    } while (0)

#define FAIL(msg)                                                              \
    do {                                                                       \
        printf("[FAIL] %s\n", msg);                                            \
    } while (0)

#define ASSERT_EQ(a, b, msg)                                                   \
    do {                                                                       \
        if ((a) != (b)) {                                                      \
            FAIL(msg);                                                         \
            return;                                                            \
        }                                                                      \
    } while (0)

/* ========================================================================
 * GF(2^8) tests
 * ======================================================================== */

static void
test_gf8_add_basic(void)
{
    TEST("gf8: add identity (a+0=a)");
    for (int a = 0; a < 256; a++) {
        ASSERT_EQ(voleith_gf8_add((uint8_t)a, 0), (uint8_t)a, "a+0 != a");
    }
    PASS();
}

static void
test_gf8_add_self_inverse(void)
{
    TEST("gf8: add self-inverse (a+a=0)");
    for (int a = 0; a < 256; a++) {
        ASSERT_EQ(voleith_gf8_add((uint8_t)a, (uint8_t)a), 0, "a+a != 0");
    }
    PASS();
}

static void
test_gf8_mul_identity(void)
{
    TEST("gf8: mul identity (a*1=a)");
    for (int a = 0; a < 256; a++) {
        ASSERT_EQ(voleith_gf8_mul((uint8_t)a, 1), (uint8_t)a, "a*1 != a");
    }
    PASS();
}

static void
test_gf8_mul_zero(void)
{
    TEST("gf8: mul zero (a*0=0)");
    for (int a = 0; a < 256; a++) {
        ASSERT_EQ(voleith_gf8_mul((uint8_t)a, 0), 0, "a*0 != 0");
    }
    PASS();
}

static void
test_gf8_mul_commutative(void)
{
    TEST("gf8: mul commutative (a*b=b*a)");
    for (int a = 0; a < 256; a++) {
        for (int b = a; b < 256; b++) {
            uint8_t ab = voleith_gf8_mul((uint8_t)a, (uint8_t)b);
            uint8_t ba = voleith_gf8_mul((uint8_t)b, (uint8_t)a);
            ASSERT_EQ(ab, ba, "a*b != b*a");
        }
    }
    PASS();
}

static void
test_gf8_mul_aes_vectors(void)
{
    TEST("gf8: AES test vectors");
    ASSERT_EQ(voleith_gf8_mul(0x57, 0x83), 0xc1, "{57}*{83} != {c1}");
    ASSERT_EQ(voleith_gf8_mul(0x57, 0x13), 0xfe, "{57}*{13} != {fe}");
    ASSERT_EQ(voleith_gf8_mul(0x57, 0x02), 0xae, "{57}*{02} != {ae}");
    ASSERT_EQ(voleith_gf8_mul(0xae, 0x02), 0x47, "{ae}*{02} != {47}");
    PASS();
}

static void
test_gf8_mul_associative(void)
{
    TEST("gf8: mul associative (spot check)");
    uint8_t vals[] = {0x00, 0x01, 0x02, 0x53, 0xCA, 0xFF, 0x83, 0x57};
    int n = (int)(sizeof(vals) / sizeof(vals[0]));
    for (int i = 0; i < n; i++) {
        for (int j = 0; j < n; j++) {
            for (int k = 0; k < n; k++) {
                uint8_t ab = voleith_gf8_mul(vals[i], vals[j]);
                uint8_t ab_c = voleith_gf8_mul(ab, vals[k]);
                uint8_t bc = voleith_gf8_mul(vals[j], vals[k]);
                uint8_t a_bc = voleith_gf8_mul(vals[i], bc);
                ASSERT_EQ(ab_c, a_bc, "(a*b)*c != a*(b*c)");
            }
        }
    }
    PASS();
}

static void
test_gf8_mul_distributive(void)
{
    TEST("gf8: mul distributive (spot check)");
    uint8_t vals[] = {0x01, 0x02, 0x53, 0xCA, 0xFF, 0x83, 0x57};
    int n = (int)(sizeof(vals) / sizeof(vals[0]));
    for (int i = 0; i < n; i++) {
        for (int j = 0; j < n; j++) {
            for (int k = 0; k < n; k++) {
                uint8_t bpc = voleith_gf8_add(vals[j], vals[k]);
                uint8_t a_bpc = voleith_gf8_mul(vals[i], bpc);
                uint8_t ab = voleith_gf8_mul(vals[i], vals[j]);
                uint8_t ac = voleith_gf8_mul(vals[i], vals[k]);
                uint8_t ab_pac = voleith_gf8_add(ab, ac);
                ASSERT_EQ(a_bpc, ab_pac, "a*(b+c) != a*b+a*c");
            }
        }
    }
    PASS();
}

/* ========================================================================
 * GF(2^64) tests
 * ======================================================================== */

static void
test_gf64_mul_identity(void)
{
    TEST("gf64: mul identity (a*1=a)");
    uint64_t vals[] = {0, 1, 2, 0xDEADBEEFCAFEBABEULL, UINT64_MAX};
    for (int i = 0; i < 5; i++) {
        ASSERT_EQ(voleith_gf64_mul(vals[i], 1), vals[i], "a*1 != a");
    }
    PASS();
}

static void
test_gf64_mul_zero(void)
{
    TEST("gf64: mul zero (a*0=0)");
    uint64_t vals[] = {0, 1, 0xDEADBEEFCAFEBABEULL, UINT64_MAX};
    for (int i = 0; i < 4; i++) {
        ASSERT_EQ(voleith_gf64_mul(vals[i], 0), 0ULL, "a*0 != 0");
    }
    PASS();
}

static void
test_gf64_mul_commutative(void)
{
    TEST("gf64: mul commutative");
    uint64_t a = 0x123456789ABCDEF0ULL;
    uint64_t b = 0xFEDCBA9876543210ULL;
    ASSERT_EQ(voleith_gf64_mul(a, b), voleith_gf64_mul(b, a), "a*b != b*a");
    PASS();
}

static void
test_gf64_mul_associative(void)
{
    TEST("gf64: mul associative");
    uint64_t a = 0x0102030405060708ULL;
    uint64_t b = 0x1122334455667788ULL;
    uint64_t c_val = 0xAABBCCDDEEFF0011ULL;
    uint64_t ab = voleith_gf64_mul(a, b);
    uint64_t ab_c = voleith_gf64_mul(ab, c_val);
    uint64_t bc = voleith_gf64_mul(b, c_val);
    uint64_t a_bc = voleith_gf64_mul(a, bc);
    ASSERT_EQ(ab_c, a_bc, "(a*b)*c != a*(b*c)");
    PASS();
}

static void
test_gf64_mul_faest_ref(void)
{
    TEST("gf64: faest-ref known-answer vector");
    voleith_gf64_t lhs = UINT64_C(0xefcdab8967452301);
    voleith_gf64_t rhs = UINT64_C(0x0123456789abcdef);
    voleith_gf64_t expected = UINT64_C(0x490c13538cc9d696);
    ASSERT_EQ(voleith_gf64_mul(lhs, rhs), expected, "gf64 mul mismatch");
    PASS();
}

/* ========================================================================
 * GF(2^128) tests - run under each field backend
 * ======================================================================== */

static void
test_gf128_add_identity(void)
{
    TEST("gf128: add identity (a+0=a)");
    voleith_gf128_t a = {{0xDEADBEEFCAFEBABEULL, 0x0102030405060708ULL}};
    voleith_gf128_t zero = voleith_gf128_zero();
    voleith_gf128_t result;
    voleith_gf128_add(&result, &a, &zero);
    ASSERT_EQ(voleith_gf128_eq(&result, &a), 1, "a+0 != a");
    PASS();
}

static void
test_gf128_add_self_inverse(void)
{
    TEST("gf128: add self-inverse (a+a=0)");
    voleith_gf128_t a = {{0xDEADBEEFCAFEBABEULL, 0x0102030405060708ULL}};
    voleith_gf128_t zero = voleith_gf128_zero();
    voleith_gf128_t result;
    voleith_gf128_add(&result, &a, &a);
    ASSERT_EQ(voleith_gf128_eq(&result, &zero), 1, "a+a != 0");
    PASS();
}

static void
test_gf128_mul_identity(void)
{
    TEST("gf128: mul identity (a*1=a)");
    voleith_gf128_t a = {{0xDEADBEEFCAFEBABEULL, 0x0102030405060708ULL}};
    voleith_gf128_t one = voleith_gf128_one();
    voleith_gf128_t result;
    voleith_gf128_mul(&result, &a, &one);
    ASSERT_EQ(voleith_gf128_eq(&result, &a), 1, "a*1 != a");
    PASS();
}

static void
test_gf128_mul_zero(void)
{
    TEST("gf128: mul zero (a*0=0)");
    voleith_gf128_t a = {{0xDEADBEEFCAFEBABEULL, 0x0102030405060708ULL}};
    voleith_gf128_t zero = voleith_gf128_zero();
    voleith_gf128_t result;
    voleith_gf128_mul(&result, &a, &zero);
    ASSERT_EQ(voleith_gf128_eq(&result, &zero), 1, "a*0 != 0");
    PASS();
}

static void
test_gf128_mul_commutative(void)
{
    TEST("gf128: mul commutative (a*b=b*a)");
    voleith_gf128_t a = {{0x0102030405060708ULL, 0x090A0B0C0D0E0F10ULL}};
    voleith_gf128_t b = {{0x1112131415161718ULL, 0x191A1B1C1D1E1F20ULL}};
    voleith_gf128_t ab, ba;
    voleith_gf128_mul(&ab, &a, &b);
    voleith_gf128_mul(&ba, &b, &a);
    ASSERT_EQ(voleith_gf128_eq(&ab, &ba), 1, "a*b != b*a");
    PASS();
}

static void
test_gf128_mul_associative(void)
{
    TEST("gf128: mul associative ((a*b)*c=a*(b*c))");
    voleith_gf128_t a = {{0x0102030405060708ULL, 0x090A0B0C0D0E0F10ULL}};
    voleith_gf128_t b = {{0x1112131415161718ULL, 0x191A1B1C1D1E1F20ULL}};
    voleith_gf128_t c_val = {{0x2122232425262728ULL, 0x292A2B2C2D2E2F30ULL}};
    voleith_gf128_t ab, ab_c, bc, a_bc;
    voleith_gf128_mul(&ab, &a, &b);
    voleith_gf128_mul(&ab_c, &ab, &c_val);
    voleith_gf128_mul(&bc, &b, &c_val);
    voleith_gf128_mul(&a_bc, &a, &bc);
    ASSERT_EQ(voleith_gf128_eq(&ab_c, &a_bc), 1, "(a*b)*c != a*(b*c)");
    PASS();
}

static void
test_gf128_mul_distributive(void)
{
    TEST("gf128: mul distributive (a*(b+c)=a*b+a*c)");
    voleith_gf128_t a = {{0x0102030405060708ULL, 0x090A0B0C0D0E0F10ULL}};
    voleith_gf128_t b = {{0x1112131415161718ULL, 0x191A1B1C1D1E1F20ULL}};
    voleith_gf128_t c_val = {{0x2122232425262728ULL, 0x292A2B2C2D2E2F30ULL}};
    voleith_gf128_t bpc, a_bpc, ab, ac, ab_pac;
    voleith_gf128_add(&bpc, &b, &c_val);
    voleith_gf128_mul(&a_bpc, &a, &bpc);
    voleith_gf128_mul(&ab, &a, &b);
    voleith_gf128_mul(&ac, &a, &c_val);
    voleith_gf128_add(&ab_pac, &ab, &ac);
    ASSERT_EQ(voleith_gf128_eq(&a_bpc, &ab_pac), 1, "a*(b+c) != a*b+a*c");
    PASS();
}

static void
test_gf128_mul_squaring(void)
{
    TEST("gf128: a*a consistency");
    voleith_gf128_t a = {{0xDEADBEEFCAFEBABEULL, 0x0102030405060708ULL}};
    voleith_gf128_t aa;
    voleith_gf128_mul(&aa, &a, &a);
    voleith_gf128_t zero = voleith_gf128_zero();
    ASSERT_EQ(voleith_gf128_eq(&aa, &zero), 0, "a*a == 0 for non-zero a");
    voleith_gf128_t one = voleith_gf128_one();
    voleith_gf128_t aa1;
    voleith_gf128_mul(&aa1, &aa, &one);
    ASSERT_EQ(voleith_gf128_eq(&aa1, &aa), 1, "a^2*1 != a^2");
    PASS();
}

static void
test_gf128_bytes_roundtrip(void)
{
    TEST("gf128: bytes round-trip");
    uint8_t buf[16] = {0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
                       0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10};
    voleith_gf128_t a;
    uint8_t buf2[16];
    voleith_gf128_from_bytes(&a, buf);
    voleith_gf128_to_bytes(buf2, &a);
    ASSERT_EQ(memcmp(buf, buf2, 16), 0, "round-trip failed");
    PASS();
}

static void
test_gf128_mul_faest_ref(void)
{
    TEST("gf128: faest-ref known-answer vector");
    uint8_t lhs_bytes[16] = {0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
                             0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef};
    uint8_t rhs_bytes[16] = {0xef, 0xcd, 0xab, 0x89, 0x67, 0x45, 0x23, 0x01,
                             0xef, 0xcd, 0xab, 0x89, 0x67, 0x45, 0x23, 0x01};
    uint8_t exp_bytes[16] = {0xe2, 0x3d, 0x64, 0xab, 0xb2, 0x4c, 0x15, 0xda,
                             0x43, 0x9c, 0xc5, 0x0a, 0x13, 0xed, 0xb4, 0x7b};

    voleith_gf128_t lhs, rhs, result, expected;
    voleith_gf128_from_bytes(&lhs, lhs_bytes);
    voleith_gf128_from_bytes(&rhs, rhs_bytes);
    voleith_gf128_from_bytes(&expected, exp_bytes);
    voleith_gf128_mul(&result, &lhs, &rhs);
    ASSERT_EQ(voleith_gf128_eq(&result, &expected), 1, "gf128 mul mismatch");
    PASS();
}

/* ========================================================================
 * GF(2^192) tests - run under each field backend
 * ======================================================================== */

static void
test_gf192_mul_identity(void)
{
    TEST("gf192: mul identity (a*1=a)");
    voleith_gf192_t a = {
        {0xDEADBEEFCAFEBABEULL, 0x0102030405060708ULL, 0xAABBCCDDEEFF0011ULL}};
    voleith_gf192_t one = voleith_gf192_one();
    voleith_gf192_t result;
    voleith_gf192_mul(&result, &a, &one);
    ASSERT_EQ(voleith_gf192_eq(&result, &a), 1, "a*1 != a");
    PASS();
}

static void
test_gf192_mul_commutative(void)
{
    TEST("gf192: mul commutative (a*b=b*a)");
    voleith_gf192_t a = {
        {0x0102030405060708ULL, 0x090A0B0C0D0E0F10ULL, 0x1112131415161718ULL}};
    voleith_gf192_t b = {
        {0x191A1B1C1D1E1F20ULL, 0x2122232425262728ULL, 0x292A2B2C2D2E2F30ULL}};
    voleith_gf192_t ab, ba;
    voleith_gf192_mul(&ab, &a, &b);
    voleith_gf192_mul(&ba, &b, &a);
    ASSERT_EQ(voleith_gf192_eq(&ab, &ba), 1, "a*b != b*a");
    PASS();
}

static void
test_gf192_mul_associative(void)
{
    TEST("gf192: mul associative ((a*b)*c=a*(b*c))");
    voleith_gf192_t a = {{0x01, 0x02, 0x03}};
    voleith_gf192_t b = {{0x04, 0x05, 0x06}};
    voleith_gf192_t c_val = {{0x07, 0x08, 0x09}};
    voleith_gf192_t ab, ab_c, bc, a_bc;
    voleith_gf192_mul(&ab, &a, &b);
    voleith_gf192_mul(&ab_c, &ab, &c_val);
    voleith_gf192_mul(&bc, &b, &c_val);
    voleith_gf192_mul(&a_bc, &a, &bc);
    ASSERT_EQ(voleith_gf192_eq(&ab_c, &a_bc), 1, "(a*b)*c != a*(b*c)");
    PASS();
}

static void
test_gf192_mul_faest_ref(void)
{
    TEST("gf192: faest-ref known-answer vector");
    uint8_t lhs_bytes[24] = {0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
                             0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
                             0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef};
    uint8_t rhs_bytes[24] = {0xef, 0xcd, 0xab, 0x89, 0x67, 0x45, 0x23, 0x01,
                             0xef, 0xcd, 0xab, 0x89, 0x67, 0x45, 0x23, 0x01,
                             0xef, 0xcd, 0xab, 0x89, 0x67, 0x45, 0x23, 0x01};
    uint8_t exp_bytes[24] = {0x22, 0xdc, 0x85, 0x4a, 0x53, 0xad, 0xf4, 0x3b,
                             0xa2, 0x7d, 0x24, 0xeb, 0xf2, 0x0c, 0x55, 0x9a,
                             0x03, 0xdc, 0x85, 0x4a, 0x53, 0xad, 0xf4, 0x3b};

    voleith_gf192_t lhs, rhs, result, expected;
    voleith_gf192_from_bytes(&lhs, lhs_bytes);
    voleith_gf192_from_bytes(&rhs, rhs_bytes);
    voleith_gf192_from_bytes(&expected, exp_bytes);
    voleith_gf192_mul(&result, &lhs, &rhs);
    ASSERT_EQ(voleith_gf192_eq(&result, &expected), 1, "gf192 mul mismatch");
    PASS();
}

/* ========================================================================
 * GF(2^256) tests - run under each field backend
 * ======================================================================== */

static void
test_gf256_mul_identity(void)
{
    TEST("gf256: mul identity (a*1=a)");
    voleith_gf256_t a = {{0xDEADBEEFCAFEBABEULL, 0x0102030405060708ULL,
                          0xAABBCCDDEEFF0011ULL, 0x9988776655443322ULL}};
    voleith_gf256_t one = voleith_gf256_one();
    voleith_gf256_t result;
    voleith_gf256_mul(&result, &a, &one);
    ASSERT_EQ(voleith_gf256_eq(&result, &a), 1, "a*1 != a");
    PASS();
}

static void
test_gf256_mul_commutative(void)
{
    TEST("gf256: mul commutative (a*b=b*a)");
    voleith_gf256_t a = {{0x0102030405060708ULL, 0x090A0B0C0D0E0F10ULL,
                          0x1112131415161718ULL, 0x191A1B1C1D1E1F20ULL}};
    voleith_gf256_t b = {{0x2122232425262728ULL, 0x292A2B2C2D2E2F30ULL,
                          0x3132333435363738ULL, 0x393A3B3C3D3E3F40ULL}};
    voleith_gf256_t ab, ba;
    voleith_gf256_mul(&ab, &a, &b);
    voleith_gf256_mul(&ba, &b, &a);
    ASSERT_EQ(voleith_gf256_eq(&ab, &ba), 1, "a*b != b*a");
    PASS();
}

static void
test_gf256_mul_associative(void)
{
    TEST("gf256: mul associative ((a*b)*c=a*(b*c))");
    voleith_gf256_t a = {{0x01, 0x02, 0x03, 0x04}};
    voleith_gf256_t b = {{0x05, 0x06, 0x07, 0x08}};
    voleith_gf256_t c_val = {{0x09, 0x0A, 0x0B, 0x0C}};
    voleith_gf256_t ab, ab_c, bc, a_bc;
    voleith_gf256_mul(&ab, &a, &b);
    voleith_gf256_mul(&ab_c, &ab, &c_val);
    voleith_gf256_mul(&bc, &b, &c_val);
    voleith_gf256_mul(&a_bc, &a, &bc);
    ASSERT_EQ(voleith_gf256_eq(&ab_c, &a_bc), 1, "(a*b)*c != a*(b*c)");
    PASS();
}

static void
test_gf256_mul_faest_ref(void)
{
    TEST("gf256: faest-ref known-answer vector");
    uint8_t lhs_bytes[32] = {0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
                             0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
                             0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
                             0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef};
    uint8_t rhs_bytes[32] = {0xef, 0xcd, 0xab, 0x89, 0x67, 0x45, 0x23, 0x01,
                             0xef, 0xcd, 0xab, 0x89, 0x67, 0x45, 0x23, 0x01,
                             0xef, 0xcd, 0xab, 0x89, 0x67, 0x45, 0x23, 0x01,
                             0xef, 0xcd, 0xab, 0x89, 0x67, 0x45, 0x23, 0x01};
    uint8_t exp_bytes[32] = {0x33, 0x5e, 0x5c, 0xd5, 0x5b, 0x5f, 0x50, 0xd9,
                             0x57, 0x5a, 0x54, 0xdd, 0x53, 0x57, 0x58, 0xd1,
                             0x5f, 0x52, 0x5c, 0xd5, 0x5b, 0x5f, 0x50, 0xd9,
                             0x57, 0x5a, 0x54, 0xdd, 0x53, 0x57, 0x58, 0xd1};

    voleith_gf256_t lhs, rhs, result, expected;
    voleith_gf256_from_bytes(&lhs, lhs_bytes);
    voleith_gf256_from_bytes(&rhs, rhs_bytes);
    voleith_gf256_from_bytes(&expected, exp_bytes);
    voleith_gf256_mul(&result, &lhs, &rhs);
    ASSERT_EQ(voleith_gf256_eq(&result, &expected), 1, "gf256 mul mismatch");
    PASS();
}

/* ========================================================================
 * ByteCombine ring homomorphism tests - run under each field backend
 * ======================================================================== */

static void
test_byte_combine_ring_hom_128(void)
{
    TEST("byte_combine ring hom lambda=128 (all a, 8 basis b)");
    static const uint8_t bvals[8] = {0x01, 0x02, 0x04, 0x08,
                                     0x10, 0x20, 0x40, 0x80};
    for (int bi = 0; bi < 8; bi++) {
        uint8_t bv = bvals[bi];
        uint8_t xb[8];
        for (int k = 0; k < 8; k++)
            xb[k] = (bv >> k) & 1u;
        voleith_gf128_t eb;
        voleith_gf128_from_bytes(&eb, (uint8_t[16]){0});
        uint8_t tmp[16];
        voleith_byte_combine(tmp, xb, 128);
        voleith_gf128_from_bytes(&eb, tmp);

        for (int av = 0; av < 256; av++) {
            uint8_t av8 = (uint8_t)av;
            uint8_t cv = voleith_gf8_mul(av8, bv);
            uint8_t xa[8], xc[8];
            for (int k = 0; k < 8; k++)
                xa[k] = (av8 >> k) & 1u;
            for (int k = 0; k < 8; k++)
                xc[k] = (cv >> k) & 1u;
            uint8_t ta[16], tc[16];
            voleith_byte_combine(ta, xa, 128);
            voleith_byte_combine(tc, xc, 128);
            voleith_gf128_t ea, ec, prod;
            voleith_gf128_from_bytes(&ea, ta);
            voleith_gf128_from_bytes(&ec, tc);
            voleith_gf128_mul(&prod, &ea, &eb);
            ASSERT_EQ(voleith_gf128_eq(&prod, &ec), 1,
                      "embed(a)*embed(b) != embed(a*b) at lambda=128");
        }
    }
    PASS();
}

static void
test_byte_combine_ring_hom_192(void)
{
    TEST("byte_combine ring hom lambda=192 (all a, 8 basis b)");
    static const uint8_t bvals[8] = {0x01, 0x02, 0x04, 0x08,
                                     0x10, 0x20, 0x40, 0x80};
    for (int bi = 0; bi < 8; bi++) {
        uint8_t bv = bvals[bi];
        uint8_t xb[8];
        for (int k = 0; k < 8; k++)
            xb[k] = (bv >> k) & 1u;
        uint8_t tb[24];
        voleith_byte_combine(tb, xb, 192);
        voleith_gf192_t eb;
        voleith_gf192_from_bytes(&eb, tb);

        for (int av = 0; av < 256; av++) {
            uint8_t av8 = (uint8_t)av;
            uint8_t cv = voleith_gf8_mul(av8, bv);
            uint8_t xa[8], xc[8];
            for (int k = 0; k < 8; k++)
                xa[k] = (av8 >> k) & 1u;
            for (int k = 0; k < 8; k++)
                xc[k] = (cv >> k) & 1u;
            uint8_t ta[24], tc[24];
            voleith_byte_combine(ta, xa, 192);
            voleith_byte_combine(tc, xc, 192);
            voleith_gf192_t ea, ec, prod;
            voleith_gf192_from_bytes(&ea, ta);
            voleith_gf192_from_bytes(&ec, tc);
            voleith_gf192_mul(&prod, &ea, &eb);
            ASSERT_EQ(voleith_gf192_eq(&prod, &ec), 1,
                      "embed(a)*embed(b) != embed(a*b) at lambda=192");
        }
    }
    PASS();
}

static void
test_byte_combine_ring_hom_256(void)
{
    TEST("byte_combine ring hom lambda=256 (all a, 8 basis b)");
    static const uint8_t bvals[8] = {0x01, 0x02, 0x04, 0x08,
                                     0x10, 0x20, 0x40, 0x80};
    for (int bi = 0; bi < 8; bi++) {
        uint8_t bv = bvals[bi];
        uint8_t xb[8];
        for (int k = 0; k < 8; k++)
            xb[k] = (bv >> k) & 1u;
        uint8_t tb[32];
        voleith_byte_combine(tb, xb, 256);
        voleith_gf256_t eb;
        voleith_gf256_from_bytes(&eb, tb);

        for (int av = 0; av < 256; av++) {
            uint8_t av8 = (uint8_t)av;
            uint8_t cv = voleith_gf8_mul(av8, bv);
            uint8_t xa[8], xc[8];
            for (int k = 0; k < 8; k++)
                xa[k] = (av8 >> k) & 1u;
            for (int k = 0; k < 8; k++)
                xc[k] = (cv >> k) & 1u;
            uint8_t ta[32], tc[32];
            voleith_byte_combine(ta, xa, 256);
            voleith_byte_combine(tc, xc, 256);
            voleith_gf256_t ea, ec, prod;
            voleith_gf256_from_bytes(&ea, ta);
            voleith_gf256_from_bytes(&ec, tc);
            voleith_gf256_mul(&prod, &ea, &eb);
            ASSERT_EQ(voleith_gf256_eq(&prod, &ec), 1,
                      "embed(a)*embed(b) != embed(a*b) at lambda=256");
        }
    }
    PASS();
}

/* ========================================================================
 * Test suite entry point for dispatched operations
 * ======================================================================== */

static void
run_dispatched_tests(void)
{
    printf("  === GF(2^128) ===\n");
    test_gf128_add_identity();
    test_gf128_add_self_inverse();
    test_gf128_mul_identity();
    test_gf128_mul_zero();
    test_gf128_mul_commutative();
    test_gf128_mul_associative();
    test_gf128_mul_distributive();
    test_gf128_mul_squaring();
    test_gf128_bytes_roundtrip();
    test_gf128_mul_faest_ref();

    printf("  === GF(2^192) ===\n");
    test_gf192_mul_identity();
    test_gf192_mul_commutative();
    test_gf192_mul_associative();
    test_gf192_mul_faest_ref();

    printf("  === GF(2^256) ===\n");
    test_gf256_mul_identity();
    test_gf256_mul_commutative();
    test_gf256_mul_associative();
    test_gf256_mul_faest_ref();

    printf("  === ByteCombine Ring Homomorphism ===\n");
    test_byte_combine_ring_hom_128();
    test_byte_combine_ring_hom_192();
    test_byte_combine_ring_hom_256();
}

/* ========================================================================
 * main
 * ======================================================================== */

int
main(void)
{
    printf("=== GF(2^8) Tests ===\n");
    test_gf8_add_basic();
    test_gf8_add_self_inverse();
    test_gf8_mul_identity();
    test_gf8_mul_zero();
    test_gf8_mul_commutative();
    test_gf8_mul_aes_vectors();
    test_gf8_mul_associative();
    test_gf8_mul_distributive();

    printf("\n=== GF(2^64) Tests ===\n");
    test_gf64_mul_identity();
    test_gf64_mul_zero();
    test_gf64_mul_commutative();
    test_gf64_mul_associative();
    test_gf64_mul_faest_ref();

    printf("\n=== Dispatched field tests ===\n");
    run_dispatched_tests();

    printf("\n=== Results: %d/%d passed ===\n", tests_passed, tests_run);
    return (tests_passed == tests_run) ? 0 : 1;
}
