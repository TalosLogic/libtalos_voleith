/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * test_shipshape_registry_table.c - crypto-v1 registry freeze table tests
 * (the implementation plan W2.1).
 *
 * Tests:
 *   1: table compiles, links, and has the expected entry count (13)
 *   2: every entry is well-formed (FQN, kind, signature, bodies)
 *   3: FQNs are unique
 *   4: frozen table agrees with the live descriptors (FQN, kind,
 *      signature, parameter bounds, grid)
 *   5: re-derivation: each frozen body hash equals a fresh fingerprint
 *      of the standalone body built from the C builders (also flags the
 *      placeholder zeros in an un-frozen table)
 *   6: parametric grids cover the STDLIB §3.4 required points
 */

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "shipshape_registry.h"

static int test_count = 0;
static int pass_count = 0;

static void
check(const char *name, int cond)
{
    test_count++;
    if (cond) {
        pass_count++;
    } else {
        printf("  FAIL: %s\n", name);
    }
}

#define EXPECTED_ENTRIES 13
#define EXPECTED_MAX_VECTOR_LEN (1u << 20)

/* ================================================================
 * Test 1: count
 * ================================================================ */
static void
test_count_matches(void)
{
    check("registry count == 13",
          voleith_shipshape_registry_count == EXPECTED_ENTRIES);
    check("descriptor count == registry count",
          voleith_shipshape_registry_descriptor_count() ==
              voleith_shipshape_registry_count);
}

/* ================================================================
 * Test 2: every entry well-formed
 * ================================================================ */
static void
test_entries_well_formed(void)
{
    int all_ok = 1;
    for (size_t i = 0; i < voleith_shipshape_registry_count; i++) {
        const voleith_shipshape_reg_entry_t *e = &voleith_shipshape_registry[i];
        if (e->fqn == NULL || strncmp(e->fqn, "stdlib/crypto/", 14) != 0) {
            printf("  entry %zu: bad fqn\n", i);
            all_ok = 0;
        }
        if (e->signature == NULL || e->signature[0] == '\0') {
            printf("  entry %zu: empty signature\n", i);
            all_ok = 0;
        }
        if (e->bodies == NULL || e->n_bodies == 0) {
            printf("  entry %zu: no bodies\n", i);
            all_ok = 0;
        }
        if (e->kind == VOLEITH_SHIPSHAPE_REG_FIXED) {
            if (e->n_bodies != 1 || e->bodies[0].param != 0 ||
                e->param_min != 0 || e->param_max != 0) {
                printf("  entry %zu: malformed FIXED entry\n", i);
                all_ok = 0;
            }
        } else {
            if (e->param_min != 0 || e->param_max != EXPECTED_MAX_VECTOR_LEN) {
                printf("  entry %zu: bad PARAMETRIC bounds\n", i);
                all_ok = 0;
            }
        }
    }
    check("all entries well-formed", all_ok);
}

/* ================================================================
 * Test 3: FQN uniqueness
 * ================================================================ */
static void
test_fqn_unique(void)
{
    int unique = 1;
    for (size_t i = 0; i < voleith_shipshape_registry_count; i++)
        for (size_t j = i + 1; j < voleith_shipshape_registry_count; j++)
            if (strcmp(voleith_shipshape_registry[i].fqn,
                       voleith_shipshape_registry[j].fqn) == 0) {
                printf("  duplicate FQN: %s\n",
                       voleith_shipshape_registry[i].fqn);
                unique = 0;
            }
    check("FQNs are unique", unique);
}

/* ================================================================
 * Test 4: frozen table agrees with the live descriptors
 * ================================================================ */
static void
test_table_matches_descriptors(void)
{
    int ok = 1;
    for (size_t i = 0; i < voleith_shipshape_registry_count; i++) {
        const char *fqn = NULL, *sig = NULL;
        voleith_shipshape_reg_kind_t kind = VOLEITH_SHIPSHAPE_REG_FIXED;
        uint32_t pmin = 0, pmax = 0;
        if (voleith_shipshape_registry_descriptor(i, &fqn, &kind, &sig, &pmin,
                                                  &pmax) != 0) {
            printf("  entry %zu: no descriptor\n", i);
            ok = 0;
            continue;
        }
        const voleith_shipshape_reg_entry_t *e = &voleith_shipshape_registry[i];
        if (strcmp(fqn, e->fqn) != 0 || kind != e->kind ||
            strcmp(sig, e->signature) != 0 || pmin != e->param_min ||
            pmax != e->param_max) {
            printf("  entry %zu: descriptor/table mismatch (%s)\n", i, e->fqn);
            ok = 0;
        }

        uint32_t grid[64];
        size_t glen = voleith_shipshape_registry_grid(i, grid, 64);
        if (glen != e->n_bodies) {
            printf("  entry %zu: grid length %zu != n_bodies %zu\n", i, glen,
                   e->n_bodies);
            ok = 0;
        } else {
            for (size_t g = 0; g < glen; g++)
                if (grid[g] != e->bodies[g].param) {
                    printf("  entry %zu: grid[%zu] param mismatch\n", i, g);
                    ok = 0;
                }
        }
    }
    check("frozen table matches live descriptors", ok);
}

/* ================================================================
 * Test 5: re-derivation (the freeze guarantee)
 * ================================================================ */
static void
test_rederivation(void)
{
    int match = 1;
    int placeholders = 0;
    uint8_t zero[VOLEITH_SHIPSHAPE_REGISTRY_BODY_HASH_BYTES] = {0};

    for (size_t i = 0; i < voleith_shipshape_registry_count; i++) {
        const voleith_shipshape_reg_entry_t *e = &voleith_shipshape_registry[i];
        for (size_t g = 0; g < e->n_bodies; g++) {
            uint8_t got[VOLEITH_SHIPSHAPE_REGISTRY_BODY_HASH_BYTES];
            if (voleith_shipshape_registry_body_hash(i, e->bodies[g].param,
                                                     got) != 0) {
                printf("  entry %zu param %u: build failed\n", i,
                       e->bodies[g].param);
                match = 0;
                continue;
            }
            if (memcmp(e->bodies[g].hash, zero, sizeof(zero)) == 0)
                placeholders++;
            if (memcmp(got, e->bodies[g].hash, sizeof(got)) != 0)
                match = 0;
        }
    }

    if (placeholders > 0)
        printf("  NOTE: %d placeholder (zero) body hash(es); regenerate "
               "parsers/shipshape_registry_table.c with "
               "shipshape_registry_freeze.\n",
               placeholders);

    check("frozen body hashes match fresh derivation", match);
    check("no placeholder body hashes remain", placeholders == 0);
}

/* ================================================================
 * Test 6: parametric grids cover the STDLIB §3.4 required points
 * ================================================================ */
static const voleith_shipshape_reg_entry_t *
find_entry(const char *fqn)
{
    for (size_t i = 0; i < voleith_shipshape_registry_count; i++)
        if (strcmp(voleith_shipshape_registry[i].fqn, fqn) == 0)
            return &voleith_shipshape_registry[i];
    return NULL;
}

static int
grid_has(const voleith_shipshape_reg_entry_t *e, uint32_t p)
{
    for (size_t i = 0; i < e->n_bodies; i++)
        if (e->bodies[i].param == p)
            return 1;
    return 0;
}

static void
require_points(const char *fqn, const uint32_t *pts, size_t n, int *ok)
{
    const voleith_shipshape_reg_entry_t *e = find_entry(fqn);
    if (e == NULL) {
        printf("  missing entry %s\n", fqn);
        *ok = 0;
        return;
    }
    for (size_t i = 0; i < n; i++)
        if (!grid_has(e, pts[i])) {
            printf("  %s: grid missing required param %u\n", fqn, pts[i]);
            *ok = 0;
        }
}

static void
test_grid_coverage(void)
{
    /* §3.4: smallest (0), each block boundary, published vector sizes.
     * CMAC block boundary is 16 (no pad) / 17 (pad); RFC 4493 sizes are
     * 0, 16, 40, 64.  Grøstl 1->2 boundary: 55/56 (256), 119/120 (512). */
    static const uint32_t cmac_pts[] = {0, 16, 17, 40, 64};
    static const uint32_t g256_pts[] = {0, 55, 56, 119, 120};
    static const uint32_t g512_pts[] = {0, 119, 120, 247, 248};
    int ok = 1;

    require_points("stdlib/crypto/cmac/aes_128", cmac_pts, 5, &ok);
    require_points("stdlib/crypto/cmac/aes_256", cmac_pts, 5, &ok);
    require_points("stdlib/crypto/grostl/hash_256", g256_pts, 5, &ok);
    require_points("stdlib/crypto/grostl/hash_256_t27", g256_pts, 5, &ok);
    require_points("stdlib/crypto/grostl/hash_512", g512_pts, 5, &ok);
    require_points("stdlib/crypto/grostl/hash_512_t59", g512_pts, 5, &ok);

    check("parametric grids cover STDLIB §3.4 required points", ok);
}

/* ================================================================
 * main
 * ================================================================ */
int
main(void)
{
    printf("test_shipshape_registry_table: crypto-v1 registry freeze table\n");

    test_count_matches();
    test_entries_well_formed();
    test_fqn_unique();
    test_table_matches_descriptors();
    test_rederivation();
    test_grid_coverage();

    printf("  %d / %d passed\n", pass_count, test_count);
    return (pass_count == test_count) ? 0 : 1;
}
