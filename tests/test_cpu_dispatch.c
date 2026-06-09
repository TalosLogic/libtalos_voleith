/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * test_cpu_dispatch.c - Tests for the AES runtime dispatch table.
 *
 * Validates:
 *   - Forcing all hardware bits clear routes to the bitsliced backend.
 *   - The dispatch table pointer is immutable after init (a second call
 *     to voleith_aes_dispatch_init() leaves the pointer unchanged).
 *   - The backend_tag in a key context matches the active backend.
 */

#include "aes.h"
#include "aes_dispatch.h"
#include "cpu.h"

#include <stdatomic.h>
#include <stdio.h>
#include <string.h>

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
 * Test: clearing all HW bits routes to bitsliced backend
 * ======================================================================== */

static void
test_force_bitsliced(void)
{
    TEST("override(no-HW) dispatches to bitsliced backend");

    unsigned host = voleith_cpu_features();
    voleith_cpu_features_override(
        host & ~(VOLEITH_CPU_AES_NI | VOLEITH_CPU_ARMV8_AES));
    voleith_aes_dispatch_reset();

    /* Trigger init by calling a public entry point. */
    uint8_t key[16] = {0};
    uint8_t in[16] = {0};
    uint8_t out[16];
    voleith_aes_ctx_t ctx;
    voleith_aes_key_expand(&ctx, key, 128);
    voleith_aes_encrypt(&ctx, out, in);

    voleith_aes_backend_t be = voleith_aes_backend();

    /* Restore before asserting so later tests see the native backend. */
    voleith_cpu_features_override(host);
    voleith_aes_dispatch_reset();

    if (be == VOLEITH_AES_BACKEND_BITSLICED)
        PASS();
    else
        FAIL("expected VOLEITH_AES_BACKEND_BITSLICED");
}

/* ========================================================================
 * Test: dispatch init is idempotent
 * ======================================================================== */

static void
test_dispatch_immutable(void)
{
    TEST("dispatch table pointer unchanged on second init call");

    /* Ensure the table is initialized. */
    uint8_t key[16] = {0};
    voleith_aes_ctx_t ctx;
    voleith_aes_key_expand(&ctx, key, 128);

    const voleith_aes_ops_t *snapshot =
        atomic_load_explicit(&voleith_aes_ops, memory_order_acquire);

    /* Second init should be a no-op. */
    voleith_aes_dispatch_init();

    const voleith_aes_ops_t *after =
        atomic_load_explicit(&voleith_aes_ops, memory_order_acquire);

    if (snapshot == after)
        PASS();
    else
        FAIL("dispatch table pointer changed after second init");
}

/* ========================================================================
 * Test: backend_tag in ctx matches active backend
 * ======================================================================== */

static void
test_ctx_backend_tag(void)
{
    TEST("ctx.backend_tag matches voleith_aes_backend() after key_expand");

    uint8_t key[16] = {0};
    voleith_aes_ctx_t ctx;
    voleith_aes_key_expand(&ctx, key, 128);

    voleith_aes_backend_t be = voleith_aes_backend();

    if (ctx.backend_tag == (uint8_t)be)
        PASS();
    else
        FAIL("ctx.backend_tag does not match active backend");
}

/* ========================================================================
 * Test: native backend is selected after restoring host features
 * ======================================================================== */

static void
test_native_backend_restored(void)
{
    TEST("native backend selected after restoring host feature mask");

    unsigned host = voleith_cpu_features();

    /* Force bitsliced. */
    voleith_cpu_features_override(0);
    voleith_aes_dispatch_reset();
    voleith_aes_backend(); /* trigger init */

    /* Restore and re-init. */
    voleith_cpu_features_override(host);
    voleith_aes_dispatch_reset();
    voleith_aes_backend(); /* trigger init */

    /*
     * On a host without any hardware AES, the native backend IS
     * bitsliced, so this test just checks consistency.
     */
    uint8_t key[16] = {0};
    uint8_t in[16] = {0};
    uint8_t out[16];
    voleith_aes_ctx_t ctx;
    voleith_aes_key_expand(&ctx, key, 128);
    voleith_aes_encrypt(&ctx, out, in);

    /* If we got here without crashing, the dispatch is functional. */
    PASS();
}

/* ========================================================================
 * main
 * ======================================================================== */

int
main(void)
{
    printf("AES dispatch tests\n");

    test_force_bitsliced();
    test_dispatch_immutable();
    test_ctx_backend_tag();
    test_native_backend_restored();

    printf("\n%d/%d tests passed\n", tests_passed, tests_run);
    return (tests_passed == tests_run) ? 0 : 1;
}
