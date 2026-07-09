/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * test_field16.c - Test suite for GF(2^16) field arithmetic
 *
 * GF(2^16) is a single-implementation field (CLMUL / PMULL / software
 * selected at compile time), so these tests run once.  CTest registers the
 * binary twice (hardware and VOLEITH_FORCE_BACKEND=field:scalar); the
 * software fold path is exercised on accelerated hosts via the _sw profile
 * if the build compiled without the intrinsic paths.
 *
 * The known-answer products and inverses are computed independently (a
 * separate reference, not this implementation) over m16 = x^16 + x^12 +
 * x^3 + x + 1.
 */

#include "field16.h"

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
 * Add
 * ======================================================================== */

static void
test_gf16_add_identity(void)
{
    int a;

    TEST("gf16: add identity (a+0=a)");
    for (a = 0; a < 65536; a++)
        ASSERT_EQ(voleith_gf16_add((uint16_t)a, 0), (uint16_t)a, "a+0 != a");
    PASS();
}

static void
test_gf16_add_self_inverse(void)
{
    int a;

    TEST("gf16: add self-inverse (a+a=0)");
    for (a = 0; a < 65536; a++)
        ASSERT_EQ(voleith_gf16_add((uint16_t)a, (uint16_t)a), 0, "a+a != 0");
    PASS();
}

/* ========================================================================
 * Mul
 * ======================================================================== */

static void
test_gf16_mul_identity(void)
{
    int a;

    TEST("gf16: mul identity (a*1=a)");
    for (a = 0; a < 65536; a++)
        ASSERT_EQ(voleith_gf16_mul((uint16_t)a, 1), (uint16_t)a, "a*1 != a");
    PASS();
}

static void
test_gf16_mul_zero(void)
{
    int a;

    TEST("gf16: mul zero (a*0=0)");
    for (a = 0; a < 65536; a++)
        ASSERT_EQ(voleith_gf16_mul((uint16_t)a, 0), 0, "a*0 != 0");
    PASS();
}

static void
test_gf16_mul_commutative(void)
{
    uint32_t i;

    TEST("gf16: mul commutative (a*b=b*a)");
    /* Stride over the space rather than the full 2^32 pairs. */
    for (i = 0; i < 65536; i++) {
        uint16_t a = (uint16_t)(i * 2654435761u);
        uint16_t b = (uint16_t)((i * 40503u) ^ 0x9E37u);
        ASSERT_EQ(voleith_gf16_mul(a, b), voleith_gf16_mul(b, a), "a*b != b*a");
    }
    PASS();
}

static void
test_gf16_mul_distributive(void)
{
    uint32_t i;

    TEST("gf16: mul distributive (a*(b+c)=a*b+a*c)");
    for (i = 0; i < 65536; i++) {
        uint16_t a = (uint16_t)(i * 2654435761u);
        uint16_t b = (uint16_t)((i * 40503u) ^ 0x1357u);
        uint16_t c = (uint16_t)((i * 2246822519u) ^ 0xACE0u);
        uint16_t lhs = voleith_gf16_mul(a, voleith_gf16_add(b, c));
        uint16_t rhs =
            voleith_gf16_add(voleith_gf16_mul(a, b), voleith_gf16_mul(a, c));
        ASSERT_EQ(lhs, rhs, "a*(b+c) != a*b+a*c");
    }
    PASS();
}

static void
test_gf16_mul_associative(void)
{
    uint32_t i;

    TEST("gf16: mul associative ((a*b)*c=a*(b*c))");
    for (i = 0; i < 65536; i++) {
        uint16_t a = (uint16_t)(i * 2654435761u);
        uint16_t b = (uint16_t)((i * 40503u) ^ 0x2468u);
        uint16_t c = (uint16_t)((i * 2246822519u) ^ 0x1111u);
        uint16_t lhs = voleith_gf16_mul(voleith_gf16_mul(a, b), c);
        uint16_t rhs = voleith_gf16_mul(a, voleith_gf16_mul(b, c));
        ASSERT_EQ(lhs, rhs, "(a*b)*c != a*(b*c)");
    }
    PASS();
}

static void
test_gf16_mul_kat(void)
{
    /* Independently computed over m16 = x^16 + x^12 + x^3 + x + 1. */
    static const struct {
        uint16_t a, b, prod;
    } kat[] = {
        {0x0002, 0x8000, 0x100B}, /* x * x^15 = x^16 = reduction constant */
        {0x8000, 0x8000, 0x8EFA}, {0x1234, 0x5678, 0x6324},
        {0xABCD, 0xFFFF, 0xF2F6}, {0x0003, 0x0003, 0x0005},
    };
    size_t i;

    TEST("gf16: mul known-answer vectors");
    for (i = 0; i < sizeof(kat) / sizeof(kat[0]); i++)
        ASSERT_EQ(voleith_gf16_mul(kat[i].a, kat[i].b), kat[i].prod,
                  "KAT product mismatch");
    PASS();
}

/* ========================================================================
 * Inverse
 * ======================================================================== */

static void
test_gf16_inv_roundtrip(void)
{
    int a;

    TEST("gf16: inverse round-trip (a*inv(a)=1, all nonzero)");
    for (a = 1; a < 65536; a++)
        ASSERT_EQ(voleith_gf16_mul((uint16_t)a, voleith_gf16_inv((uint16_t)a)),
                  1, "a*inv(a) != 1");
    PASS();
}

static void
test_gf16_inv_zero(void)
{
    TEST("gf16: inverse of zero is zero");
    ASSERT_EQ(voleith_gf16_inv(0), 0, "inv(0) != 0");
    PASS();
}

/* ========================================================================
 * Byte conversion
 * ======================================================================== */

static void
test_gf16_bytes_roundtrip(void)
{
    int a;

    TEST("gf16: from_bytes/to_bytes round-trip");
    for (a = 0; a < 65536; a++) {
        uint8_t buf[2];
        voleith_gf16_to_bytes(buf, (uint16_t)a);
        ASSERT_EQ(voleith_gf16_from_bytes(buf), (uint16_t)a, "byte round-trip");
    }
    PASS();
}

static void
test_gf16_bytes_endianness(void)
{
    uint8_t buf[2];

    TEST("gf16: byte form is little-endian");
    voleith_gf16_to_bytes(buf, 0x1234);
    ASSERT_EQ(buf[0], 0x34, "low byte wrong");
    ASSERT_EQ(buf[1], 0x12, "high byte wrong");
    ASSERT_EQ(voleith_gf16_from_bytes(buf), 0x1234, "from_bytes LE wrong");
    PASS();
}

int
main(void)
{
    printf("=== GF(2^16) Tests ===\n");
    test_gf16_add_identity();
    test_gf16_add_self_inverse();
    test_gf16_mul_identity();
    test_gf16_mul_zero();
    test_gf16_mul_commutative();
    test_gf16_mul_distributive();
    test_gf16_mul_associative();
    test_gf16_mul_kat();
    test_gf16_inv_roundtrip();
    test_gf16_inv_zero();
    test_gf16_bytes_roundtrip();
    test_gf16_bytes_endianness();

    printf("\n=== Results: %d/%d passed ===\n", tests_passed, tests_run);
    return (tests_passed == tests_run) ? 0 : 1;
}
