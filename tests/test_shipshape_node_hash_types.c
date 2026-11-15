/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * test_shipshape_node_hash_types.c - node-hash type registry tests (MR1).
 *
 * Four test groups:
 *
 *   1. by_name for all surface names: returns the right type_id and a
 *      non-NULL vt whose node_bytes matches the DESIGN §2 table.
 *
 *   2. by_name for "grostl256", "aes-dm", "", and a truncated slice
 *      returns NULL (no prefix or fuzzy matching).
 *
 *   3. by_id round-trips 0..15; by_id(16) returns NULL.
 *
 *   4. GOLDEN ORDER: voleith_shipshape_node_hash_types[i].type_id == i
 *      and .name at each index equals the expected literal, so any
 *      reorder or insertion is caught (ids are frozen).
 *
 * See the crypto-v2 implementation plan MR1.
 */

#include "shipshape_node_hash_types.h"

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

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

/*
 * Expected surface names, in type_id order.  Index == type_id.
 */
static const char *expected_names[] = {
    "aes_dm",                /* 0 */
    "aes_cmac_128",          /* 1 */
    "grostl_256",            /* 2 */
    "grostl_256_t27",        /* 3 */
    "grostl_512",            /* 4 */
    "grostl_512_t59",        /* 5 */
    "hirose",                /* 6 */
    "hirose_fixed_32",       /* 7 */
    "grostl_256_fixed",      /* 8 */
    "grostl_512_fixed",      /* 9 */
    "aes_dm_norm",           /* 10 (crypto-v3) */
    "aes_cmac_128_norm",     /* 11 */
    "hirose_norm",           /* 12 */
    "hirose_fixed_32_norm",  /* 13 */
    "grostl_256_fixed_norm", /* 14 */
    "grostl_512_fixed_norm", /* 15 */
};

/*
 * Expected node_bytes per type_id, in the same order.
 * From DESIGN §2 table (aes_dm=16, aes_cmac_128=16, grostl_256=32,
 * grostl_256_t27=27, grostl_512=64, grostl_512_t59=59, hirose=32,
 * hirose_fixed_32=32).
 */
static const size_t expected_node_bytes[] = {
    16, /* aes_dm */
    16, /* aes_cmac_128 */
    32, /* grostl_256 */
    27, /* grostl_256_t27 */
    64, /* grostl_512 */
    59, /* grostl_512_t59 */
    32, /* hirose */
    32, /* hirose_fixed_32 */
    32, /* grostl_256_fixed */
    64, /* grostl_512_fixed */
    16, /* aes_dm_norm */
    16, /* aes_cmac_128_norm */
    32, /* hirose_norm */
    32, /* hirose_fixed_32_norm */
    32, /* grostl_256_fixed_norm */
    64, /* grostl_512_fixed_norm */
};

/* Minimum stdlib version: 0..9 are crypto-v2; 10..15 are crypto-v3 norm. */
static const uint8_t expected_version[] = {2, 2, 2, 2, 2, 2, 2, 2,
                                           2, 2, 3, 3, 3, 3, 3, 3};

#define N_TYPES 16

static void
test_by_name_all(void)
{
    const voleith_shipshape_node_hash_type_t *e;
    char label[64];
    size_t i;

    for (i = 0; i < N_TYPES; i++) {
        const char *n = expected_names[i];
        e = voleith_shipshape_node_hash_type_by_name(n, strlen(n));

        snprintf(label, sizeof(label), "by_name(%s) non-NULL", n);
        check(label, e != NULL);

        if (e == NULL)
            continue;

        snprintf(label, sizeof(label), "by_name(%s) type_id==%u", n,
                 (unsigned)i);
        check(label, e->type_id == (uint16_t)i);

        snprintf(label, sizeof(label), "by_name(%s) vt non-NULL", n);
        check(label, e->vt != NULL);

        if (e->vt == NULL)
            continue;

        snprintf(label, sizeof(label), "by_name(%s) node_bytes==%zu", n,
                 expected_node_bytes[i]);
        check(label, e->vt->node_bytes == expected_node_bytes[i]);
    }
}

static void
test_by_name_no_fuzzy(void)
{
    const voleith_shipshape_node_hash_type_t *e;

    /* "grostl256" is missing the underscore before "256" */
    e = voleith_shipshape_node_hash_type_by_name("grostl256", 9);
    check("by_name(grostl256) == NULL", e == NULL);

    /* "aes-dm" uses a hyphen, not underscore */
    e = voleith_shipshape_node_hash_type_by_name("aes-dm", 6);
    check("by_name(aes-dm) == NULL", e == NULL);

    /* empty string must not match anything */
    e = voleith_shipshape_node_hash_type_by_name("", 0);
    check("by_name(\"\") == NULL", e == NULL);

    /*
     * Truncated slice: "aes" (first 3 bytes of "aes_dm").  Passing the
     * full pointer but a shorter length exercises the exact-length check.
     */
    e = voleith_shipshape_node_hash_type_by_name("aes_dm", 3);
    check("by_name(\"aes\", 3) == NULL", e == NULL);
}

static void
test_by_id_roundtrip(void)
{
    const voleith_shipshape_node_hash_type_t *e;
    char label[64];
    size_t i;

    for (i = 0; i < N_TYPES; i++) {
        e = voleith_shipshape_node_hash_type_by_id((uint16_t)i);

        snprintf(label, sizeof(label), "by_id(%zu) non-NULL", i);
        check(label, e != NULL);

        if (e == NULL)
            continue;

        snprintf(label, sizeof(label), "by_id(%zu) type_id==%zu", i, i);
        check(label, e->type_id == (uint16_t)i);

        snprintf(label, sizeof(label), "by_id(%zu) name matches", i);
        check(label, strcmp(e->name, expected_names[i]) == 0);
    }

    /* id N_TYPES is out of range */
    e = voleith_shipshape_node_hash_type_by_id(N_TYPES);
    check("by_id(N_TYPES) == NULL", e == NULL);
}

static void
test_golden_order(void)
{
    char label[64];
    size_t i;

    check("count == 16", voleith_shipshape_node_hash_types_count == N_TYPES);

    for (i = 0; i < N_TYPES; i++) {
        snprintf(label, sizeof(label), "table[%zu].type_id == %zu", i, i);
        check(label,
              voleith_shipshape_node_hash_types[i].type_id == (uint16_t)i);

        snprintf(label, sizeof(label), "table[%zu].name == \"%s\"", i,
                 expected_names[i]);
        check(label, strcmp(voleith_shipshape_node_hash_types[i].name,
                            expected_names[i]) == 0);

        snprintf(label, sizeof(label), "table[%zu].introduced_version == %u", i,
                 expected_version[i]);
        check(label, voleith_shipshape_node_hash_types[i].introduced_version ==
                         expected_version[i]);
    }
}

int
main(void)
{
    printf("test_shipshape_node_hash_types: starting\n");

    test_by_name_all();
    test_by_name_no_fuzzy();
    test_by_id_roundtrip();
    test_golden_order();

    printf("test_shipshape_node_hash_types: %d/%d passed\n", pass_count,
           test_count);
    return (pass_count == test_count) ? 0 : 1;
}
