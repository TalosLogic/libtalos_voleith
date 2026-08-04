/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * test_node_hash_fixed_multiblock_gf8.c - focused checks for the
 * two-block fixed leaf-hash vts added for RSv5 (OP.VT):
 *
 *   voleith_node_hash_hirose_fixed96    (6 iterations, 96B leaf, 3000 slots)
 *   voleith_node_hash_grostl256_fixed128 (2 blocks, 128B leaf, 3200 slots)
 *   voleith_node_hash_grostl512_fixed256 (2 blocks, 256B leaf, 8960 slots)
 *
 * The circuit-vs-software leaf/inode equivalence, invin sizing, domain
 * separation, and full path e2e for these vts are covered uniformly by
 * test_node_hash_vt_conformance.c (they are entries in its CASES table).
 * This suite adds the checks that harness does NOT: the literal slot-
 * count pins, over-capacity rejection, the capacity extension over the
 * single-block fixed siblings, output determinism, and construction
 * distinctness (block-count domain separation).
 *
 * Note: absolute golden KAT vectors are not hard-pinned here.  The
 * independent-oracle equivalence (circuit witness path vs. ichor /
 * core-hirose software path) in the conformance suite is the anchor
 * against either implementation drifting; the digests are printed below
 * for the record.
 */

#include "node_hash_vt.h"
#include "grostl_gf8_circuit.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int total_tests = 0;
static int total_pass = 0;

static void
check(const char *what, int cond)
{
    total_tests++;
    if (cond)
        total_pass++;
    else
        printf("    FAIL: %s\n", what);
}

/* Deterministic non-trivial fill. */
static void
fill(uint8_t *buf, size_t n, uint8_t seed)
{
    for (size_t i = 0; i < n; i++)
        buf[i] = (uint8_t)(seed + i * 31u + (i >> 3));
}

static void
print_hex(const char *label, const uint8_t *d, size_t n)
{
    printf("    %s = ", label);
    for (size_t i = 0; i < n; i++)
        printf("%02x", d[i]);
    printf("\n");
}

/* ================================================================
 * 1. Attribute + literal slot-count pins.
 * ================================================================ */

static void
check_pins(void)
{
    const voleith_node_hash_vt *h96 = &voleith_node_hash_hirose_fixed96;
    const voleith_node_hash_vt *g128 = &voleith_node_hash_grostl256_fixed128;
    const voleith_node_hash_vt *g256 = &voleith_node_hash_grostl512_fixed256;

    check("hirose_fixed96 node_bytes==32", h96->node_bytes == 32);
    check("hirose_fixed96 cr_bits==128", h96->cr_bits == 128);
    check("hirose_fixed96 leaf_block_bytes==96", h96->leaf_block_bytes == 96);
    check("hirose_fixed96 leaf slots==3000", h96->leaf_invin_bytes(96) == 3000);

    check("grostl256_fixed128 node_bytes==32", g128->node_bytes == 32);
    check("grostl256_fixed128 cr_bits==128", g128->cr_bits == 128);
    check("grostl256_fixed128 leaf_block_bytes==128",
          g128->leaf_block_bytes == 128);
    check("grostl256_fixed128 leaf slots==3200",
          g128->leaf_invin_bytes(128) == 3200);
    check("grostl256 node2 invin==3200",
          grostl256_gf8_node2_invin_bytes() == 3200);

    check("grostl512_fixed256 node_bytes==64", g256->node_bytes == 64);
    check("grostl512_fixed256 cr_bits==256", g256->cr_bits == 256);
    check("grostl512_fixed256 leaf_block_bytes==256",
          g256->leaf_block_bytes == 256);
    check("grostl512_fixed256 leaf slots==8960",
          g256->leaf_invin_bytes(256) == 8960);
    check("grostl512 node2 invin==8960",
          grostl512_gf8_node2_invin_bytes() == 8960);

    /* Inode is the single-block compression (L||R = one block), so its
     * slot count matches the single-block fixed sibling. */
    check("grostl256_fixed128 inode slots==1920",
          g128->inode_invin_bytes() == 1920);
    check("grostl512_fixed256 inode slots==5376",
          g256->inode_invin_bytes() == 5376);
}

/* ================================================================
 * 2. Over-capacity rejection: leaf_hash / leaf_build_witness must
 * return -1 (not truncate) for a preimage wider than leaf_block_bytes.
 * ================================================================ */

static void
check_reject_over_capacity(const voleith_node_hash_vt *h, const char *label)
{
    size_t cap = h->leaf_block_bytes;
    uint8_t in[257];
    uint8_t out[64];
    uint8_t *inv = calloc(h->leaf_invin_bytes(cap), 1);
    char name[128];

    fill(in, cap + 1, 0x11);

    snprintf(name, sizeof(name), "[%s] leaf_hash rejects cap+1", label);
    check(name, h->leaf_hash(in, cap + 1, out) == -1);

    snprintf(name, sizeof(name), "[%s] leaf_build_witness rejects cap+1",
             label);
    check(name, h->leaf_build_witness(in, cap + 1, inv) == -1);

    /* At exactly capacity it must succeed. */
    snprintf(name, sizeof(name), "[%s] leaf_hash accepts cap", label);
    check(name, h->leaf_hash(in, cap, out) == 0);

    free(inv);
}

/* ================================================================
 * 3. Capacity extension: a >64B preimage that the single-block fixed
 * sibling rejects is accepted by the two-block vt.
 * ================================================================ */

static void
check_capacity_extension(const voleith_node_hash_vt *small,
                         const voleith_node_hash_vt *big, size_t wide_bytes,
                         const char *label)
{
    uint8_t in[256];
    uint8_t out[64];
    char name[160];

    fill(in, wide_bytes, 0x42);

    snprintf(name, sizeof(name), "[%s] single-block sibling rejects %zuB",
             label, wide_bytes);
    check(name, small->leaf_hash(in, wide_bytes, out) == -1);

    snprintf(name, sizeof(name), "[%s] two-block vt accepts %zuB", label,
             wide_bytes);
    check(name, big->leaf_hash(in, wide_bytes, out) == 0);
}

/* ================================================================
 * 4. Determinism + construction distinctness.
 * ================================================================ */

static void
check_determinism_and_distinctness(void)
{
    const voleith_node_hash_vt *h32 = &voleith_node_hash_hirose_fixed32;
    const voleith_node_hash_vt *h96 = &voleith_node_hash_hirose_fixed96;
    const voleith_node_hash_vt *g64 = &voleith_node_hash_grostl256_fixed;
    const voleith_node_hash_vt *g128 = &voleith_node_hash_grostl256_fixed128;

    uint8_t in[32];
    uint8_t a[32], b[32], c[32], d[32];
    fill(in, sizeof(in), 0x7c);

    /* Determinism: same input, same digest. */
    check("hirose_fixed96 deterministic", h96->leaf_hash(in, 32, a) == 0 &&
                                              h96->leaf_hash(in, 32, b) == 0 &&
                                              memcmp(a, b, 32) == 0);
    check("grostl256_fixed128 deterministic",
          g128->leaf_hash(in, 32, c) == 0 && g128->leaf_hash(in, 32, d) == 0 &&
              memcmp(c, d, 32) == 0);

    /* Block-count domain separation: the two-block vt and its single-
     * block sibling, on the SAME 32-byte input (both zero-pad it), must
     * differ (distinct IV / c constant per block count). */
    uint8_t s[32], w[32];
    h32->leaf_hash(in, 32, s);
    h96->leaf_hash(in, 32, w);
    check("hirose_fixed32 != hirose_fixed96 on same input",
          memcmp(s, w, 32) != 0);

    uint8_t gs[32], gw[32];
    g64->leaf_hash(in, 32, gs);
    g128->leaf_hash(in, 32, gw);
    check("grostl256_fixed != grostl256_fixed128 on same input",
          memcmp(gs, gw, 32) != 0);

    print_hex("hirose_fixed96(32B)", w, 32);
    print_hex("grostl256_fixed128(32B)", gw, 32);
}

int
main(void)
{
    printf("=== node_hash two-block fixed leaf vts (OP.VT) ===\n");

    check_pins();

    check_reject_over_capacity(&voleith_node_hash_hirose_fixed96,
                               "hirose_fixed96");
    check_reject_over_capacity(&voleith_node_hash_grostl256_fixed128,
                               "grostl256_fixed128");
    check_reject_over_capacity(&voleith_node_hash_grostl512_fixed256,
                               "grostl512_fixed256");

    check_capacity_extension(&voleith_node_hash_hirose_fixed32,
                             &voleith_node_hash_hirose_fixed96, 96,
                             "hirose 32->96");
    check_capacity_extension(&voleith_node_hash_grostl256_fixed,
                             &voleith_node_hash_grostl256_fixed128, 96,
                             "grostl256 64->128");
    check_capacity_extension(&voleith_node_hash_grostl512_fixed,
                             &voleith_node_hash_grostl512_fixed256, 256,
                             "grostl512 128->256");

    check_determinism_and_distinctness();

    printf("\n%d/%d checks passed\n", total_pass, total_tests);
    return (total_pass == total_tests) ? 0 : 1;
}
