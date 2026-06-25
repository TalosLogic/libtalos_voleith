/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * test_range_gf8_circuit.c - tests for assert_in_range_gf8.
 *
 * Validates:
 *   - Boundary and interior values in [low, high] satisfy the circuit;
 *     values just below low or just above high make it unsatisfiable.
 *   - Coverage across widths (1, 4, 16 bytes), little-endian.
 *   - A full prove / verify round-trip: an honest in-range witness
 *     verifies; an out-of-range witness is rejected at prove time.
 */

#include "../circuits/range_gf8_circuit.h"
#include "../proof/gf8_circuit.h"
#include "../proof/gf8_proof.h"
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int tests_run = 0;
static int tests_passed = 0;

#define TEST(name)                                                             \
    do {                                                                       \
        tests_run++;                                                           \
        printf("  [%2d] %-58s ", tests_run, name);                             \
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

static void
le_encode(uint8_t *out, uint64_t v, size_t n)
{
    /* Bytes beyond the 8 in a uint64 are zero; guard the shift to avoid
     * the undefined v >> 64 when n > 8. */
    for (size_t i = 0; i < n; i++)
        out[i] = (i < 8) ? (uint8_t)(v >> (8 * i)) : 0u;
}

/*
 * Build a circuit asserting low <= value <= high over n-byte wires,
 * evaluate it with the given values, and return the constraint flag
 * (1 satisfied, 0 violation, -1 alloc error).
 */
static int
eval_range(uint64_t value, uint64_t low, uint64_t high, size_t n)
{
    voleith_gf8_circuit_t *c = voleith_gf8_circuit_new();
    gf8_wire_id *vw = malloc(n * sizeof(gf8_wire_id));
    gf8_wire_id *lw = malloc(n * sizeof(gf8_wire_id));
    gf8_wire_id *hw = malloc(n * sizeof(gf8_wire_id));
    uint8_t *wit = malloc(3 * n);
    uint8_t *vals = NULL;
    size_t nwires;
    int ok;

    if (!c || !vw || !lw || !hw || !wit) {
        free(vw);
        free(lw);
        free(hw);
        free(wit);
        if (c)
            voleith_gf8_circuit_free(c);
        return -1;
    }

    for (size_t i = 0; i < n; i++)
        vw[i] = voleith_gf8_add_witness(c);
    for (size_t i = 0; i < n; i++)
        lw[i] = voleith_gf8_add_witness(c);
    for (size_t i = 0; i < n; i++)
        hw[i] = voleith_gf8_add_witness(c);
    assert_in_range_gf8(c, vw, lw, hw, n);

    le_encode(wit, value, n);
    le_encode(wit + n, low, n);
    le_encode(wit + 2 * n, high, n);

    nwires = voleith_gf8_circuit_wire_count(c);
    vals = calloc(nwires, 1);
    if (!vals) {
        free(vw);
        free(lw);
        free(hw);
        free(wit);
        voleith_gf8_circuit_free(c);
        return -1;
    }
    ok = voleith_gf8_circuit_eval(c, wit, NULL, vals);

    free(vals);
    free(wit);
    free(vw);
    free(lw);
    free(hw);
    voleith_gf8_circuit_free(c);
    return ok;
}

static void
check_case(uint64_t value, uint64_t low, uint64_t high, size_t n, int expect_ok,
           const char *label)
{
    TEST(label);
    int ok = eval_range(value, low, high, n);
    if (ok == expect_ok) {
        PASS();
    } else {
        printf("FAIL: eval=%d expected=%d (value=%llu low=%llu high=%llu)\n",
               ok, expect_ok, (unsigned long long)value,
               (unsigned long long)low, (unsigned long long)high);
    }
}

static void
test_boundaries_4byte(void)
{
    /* [100, 200] over 4 bytes. */
    check_case(100, 100, 200, 4, 1, "4B: value==low (100) in range");
    check_case(200, 100, 200, 4, 1, "4B: value==high (200) in range");
    check_case(150, 100, 200, 4, 1, "4B: interior (150) in range");
    check_case(99, 100, 200, 4, 0, "4B: just below low (99) rejected");
    check_case(201, 100, 200, 4, 0, "4B: just above high (201) rejected");
    check_case(0, 100, 200, 4, 0, "4B: zero (below) rejected");
    /* Degenerate single-point range [42, 42]. */
    check_case(42, 42, 42, 4, 1, "4B: point range [42,42], value 42");
    check_case(43, 42, 42, 4, 0, "4B: point range [42,42], value 43 rejected");
}

static void
test_widths(void)
{
    /* 1 byte: [10, 20]. */
    check_case(10, 10, 20, 1, 1, "1B: value==low (10) in range");
    check_case(20, 10, 20, 1, 1, "1B: value==high (20) in range");
    check_case(9, 10, 20, 1, 0, "1B: below (9) rejected");
    check_case(21, 10, 20, 1, 0, "1B: above (21) rejected");
    check_case(255, 0, 255, 1, 1, "1B: full range [0,255], value 255");

    /* 16 bytes: a large range straddling a byte boundary. */
    uint64_t low = 0x0000000100000000ULL;  /* 2^32 */
    uint64_t high = 0x0000000300000000ULL; /* 3*2^32 */
    check_case(low, low, high, 16, 1, "16B: value==low in range");
    check_case(high, low, high, 16, 1, "16B: value==high in range");
    check_case(0x0000000200000000ULL, low, high, 16, 1,
               "16B: interior in range");
    check_case(low - 1, low, high, 16, 0, "16B: just below low rejected");
    check_case(high + 1, low, high, 16, 0, "16B: just above high rejected");
}

/* ================================================================
 * Full prove / verify round-trip (4-byte width, all-witness).
 * ================================================================ */

static voleith_gf8_circuit_t *
build_range_circuit(size_t n)
{
    voleith_gf8_circuit_t *c = voleith_gf8_circuit_new();
    gf8_wire_id *vw = malloc(n * sizeof(gf8_wire_id));
    gf8_wire_id *lw = malloc(n * sizeof(gf8_wire_id));
    gf8_wire_id *hw = malloc(n * sizeof(gf8_wire_id));
    for (size_t i = 0; i < n; i++)
        vw[i] = voleith_gf8_add_witness(c);
    for (size_t i = 0; i < n; i++)
        lw[i] = voleith_gf8_add_witness(c);
    for (size_t i = 0; i < n; i++)
        hw[i] = voleith_gf8_add_witness(c);
    assert_in_range_gf8(c, vw, lw, hw, n);
    free(vw);
    free(lw);
    free(hw);
    return c;
}

static void
test_prove_verify(void)
{
    const size_t n = 4;
    const voleith_params_t *params = &voleith_params_em_128f;
    const char *ds = "test_range_gf8:in_range";
    voleith_gf8_circuit_t *c = build_range_circuit(n);
    size_t wit_len = voleith_gf8_circuit_witness_byte_len(c);
    size_t inst_len = voleith_gf8_circuit_instance_byte_len(c);
    uint8_t witness[3 * 4];

    /* Honest in-range witness: value=150 in [100, 200]. */
    le_encode(witness, 150, n);
    le_encode(witness + n, 100, n);
    le_encode(witness + 2 * n, 200, n);

    TEST("4B prove + verify: in-range witness");
    voleith_proof_t p = {0};
    int prc = voleith_gf8_prove_v2(&p, params, c, witness, wit_len, NULL,
                                   inst_len, ds, strlen(ds));
    int vrc = -1;
    if (prc == 0)
        vrc = voleith_gf8_verify_v2(&p, params, c, NULL, inst_len, ds,
                                    strlen(ds));
    if (prc == 0 && vrc == 0)
        PASS();
    else
        printf("FAIL: prove=%d verify=%d\n", prc, vrc);
    voleith_proof_free(&p);

    /* Out-of-range witness: value=250 above high=200; prover must reject. */
    TEST("4B prove: out-of-range witness rejected");
    le_encode(witness, 250, n);
    voleith_proof_t p2 = {0};
    int trc = voleith_gf8_prove_v2(&p2, params, c, witness, wit_len, NULL,
                                   inst_len, ds, strlen(ds));
    if (trc != 0) {
        PASS();
    } else {
        FAIL("prove accepted out-of-range witness");
        voleith_proof_free(&p2);
    }

    voleith_gf8_circuit_free(c);
}

int
main(void)
{
    printf("range_gf8_circuit tests\n");
    printf("=======================\n");

    printf("\n  Boundaries (4-byte)\n");
    test_boundaries_4byte();

    printf("\n  Widths (1, 16 byte)\n");
    test_widths();

    printf("\n  Prove / verify\n");
    test_prove_verify();

    printf("\n%d/%d tests passed\n", tests_passed, tests_run);
    return (tests_passed == tests_run) ? 0 : 1;
}
