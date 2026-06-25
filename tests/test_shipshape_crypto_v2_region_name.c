/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * test_shipshape_crypto_v2_region_name.c - MR5 W8 region-name contract test.
 *
 * Pins that the parsed region name for every crypto-v2 construction entry
 * is exactly the bracketed FQN `stdlib/crypto/<name>[<type>]`, across all
 * 10 node-hash types (the MR3 smoke test covers only one type per entry).
 * This ensures the bracket carries the type name verbatim and that W8
 * dispatch can key on `region.name` without any additional lookup.
 *
 * See: docs/private/SHIPSHAPE_CRYPTO_V2_SECRETDIR_IMPL_PLAN.md MR5
 * See: docs/private/SHIPSHAPE_CRYPTO_V2_SECRETDIR_DESIGN.md §7
 */

#include "shipshape.h"

#include <stddef.h>
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

#define HDR_V2                                                                 \
    ".shipshape 1\n"                                                           \
    "field GF(2^8) irreducible 0x11B\n"                                        \
    "stdlib crypto-v2\n"

/*
 * Parse a NUL-terminated buffer with default limits.  On success, fills *p
 * and returns 0.  On failure, *p is zeroed (parse contract) and a negative
 * error code is returned.  The caller must call voleith_shipshape_parsed_free
 * on success.
 */
static int
parse_into(const char *buf, voleith_shipshape_parsed_t *p)
{
    return voleith_shipshape_parse_buffer(p, buf, 0, NULL);
}

/* ================================================================
 * Group A: merkle/path_secret[<type>] region names.
 *
 * Signature: (leaf : byte[L], siblings : byte[depth*node], dirs : byte[depth])
 *            -> root
 * depth=2 throughout.  node_bytes per type:
 *   aes_dm=16, aes_cmac_128=16, grostl_256=32, grostl_256_t27=27,
 *   grostl_512=64, grostl_512_t59=59, hirose=32, hirose_fixed_32=32.
 * For hirose_fixed_32, fixed_leaf_bytes=32 so leaf must be byte[32]
 * (== node_bytes; consistent).
 * ================================================================ */

/*
 * Emit one merkle/path_secret region-name assertion for a given type.
 * node  = vt->node_bytes for the type.
 * label = short human label for check() messages.
 * type_name = the surface selector string, e.g. "grostl_256".
 * expected  = the expected region name, e.g.
 *             "stdlib/crypto/merkle/path_secret[grostl_256]".
 */
static void
check_merkle_path_name(const char *label, const char *type_name, size_t node,
                       const char *expected)
{
    char src[512];
    char cname_parse[128];
    char cname_n_regions[128];
    char cname_name[128];
    voleith_shipshape_parsed_t p;
    int r;

    /* leaf=node_bytes, sib=2*node_bytes, dirs=2 */
    snprintf(src, sizeof(src),
             HDR_V2 "WITNESS  -> %%leaf : byte[%zu]\n"
                    "WITNESS  -> %%sib  : byte[%zu]\n"
                    "WITNESS  -> %%dirs : byte[2]\n"
                    "stdlib/crypto/merkle/path_secret[%s]"
                    "(%%leaf, %%sib, %%dirs) -> %%root\n",
             node, 2 * node, type_name);

    snprintf(cname_parse, sizeof(cname_parse),
             "merkle/path_secret[%s]: parse returns 0", label);
    snprintf(cname_n_regions, sizeof(cname_n_regions),
             "merkle/path_secret[%s]: one region", label);
    snprintf(cname_name, sizeof(cname_name),
             "merkle/path_secret[%s]: region name == %s", label, expected);

    r = parse_into(src, &p);
    check(cname_parse, r == 0);
    check(cname_n_regions, r == 0 && p.n_regions == 1);
    check(cname_name, r == 0 && p.n_regions == 1 &&
                          strcmp(p.regions[0].name, expected) == 0);
    if (r == 0)
        voleith_shipshape_parsed_free(&p);
}

static void
test_merkle_path_region_names(void)
{
    check_merkle_path_name("aes_dm", "aes_dm", 16,
                           "stdlib/crypto/merkle/path_secret[aes_dm]");
    check_merkle_path_name("aes_cmac_128", "aes_cmac_128", 16,
                           "stdlib/crypto/merkle/path_secret[aes_cmac_128]");
    check_merkle_path_name("grostl_256", "grostl_256", 32,
                           "stdlib/crypto/merkle/path_secret[grostl_256]");
    check_merkle_path_name("grostl_256_t27", "grostl_256_t27", 27,
                           "stdlib/crypto/merkle/path_secret[grostl_256_t27]");
    check_merkle_path_name("grostl_512", "grostl_512", 64,
                           "stdlib/crypto/merkle/path_secret[grostl_512]");
    check_merkle_path_name("grostl_512_t59", "grostl_512_t59", 59,
                           "stdlib/crypto/merkle/path_secret[grostl_512_t59]");
    check_merkle_path_name("hirose", "hirose", 32,
                           "stdlib/crypto/merkle/path_secret[hirose]");
    /* hirose_fixed_32: fixed_leaf_bytes=32; leaf=32 == node_bytes */
    check_merkle_path_name("hirose_fixed_32", "hirose_fixed_32", 32,
                           "stdlib/crypto/merkle/path_secret[hirose_fixed_32]");
    /* grostl_256_fixed: fixed_leaf_bytes=32; leaf=32 == node_bytes */
    check_merkle_path_name(
        "grostl_256_fixed", "grostl_256_fixed", 32,
        "stdlib/crypto/merkle/path_secret[grostl_256_fixed]");
    /* grostl_512_fixed: fixed_leaf_bytes=64; leaf=64 == node_bytes */
    check_merkle_path_name(
        "grostl_512_fixed", "grostl_512_fixed", 64,
        "stdlib/crypto/merkle/path_secret[grostl_512_fixed]");
}

/* ================================================================
 * Group B: ring_sig/v1[<type>] region names.
 *
 * Signature: (sk : byte[skb], dirs : byte[depth],
 *             siblings : byte[depth*node], root : byte[node])
 * No outputs (assertion-only).  root is INSTANCE.
 * depth=2 throughout.  sk = node_bytes for all types so the
 * leaf-data width is consistent with node size.
 * hirose_fixed_32: fixed_leaf_bytes=32; skb=32 == node_bytes.
 * ================================================================ */

static void
check_ring_sig_name(const char *label, const char *type_name, size_t node,
                    const char *expected)
{
    char src[512];
    char cname_parse[128];
    char cname_n_regions[128];
    char cname_name[128];
    voleith_shipshape_parsed_t p;
    int r;

    /* sk=node, dirs=2, sib=2*node, root=node (INSTANCE) */
    snprintf(src, sizeof(src),
             HDR_V2
             "WITNESS  -> %%sk   : byte[%zu]\n"
             "WITNESS  -> %%dirs : byte[2]\n"
             "WITNESS  -> %%sib  : byte[%zu]\n"
             "INSTANCE -> %%root : byte[%zu]\n"
             "stdlib/crypto/ring_sig/v1[%s](%%sk, %%dirs, %%sib, %%root)\n",
             node, 2 * node, node, type_name);

    snprintf(cname_parse, sizeof(cname_parse),
             "ring_sig/v1[%s]: parse returns 0", label);
    snprintf(cname_n_regions, sizeof(cname_n_regions),
             "ring_sig/v1[%s]: one region", label);
    snprintf(cname_name, sizeof(cname_name),
             "ring_sig/v1[%s]: region name == %s", label, expected);

    r = parse_into(src, &p);
    check(cname_parse, r == 0);
    check(cname_n_regions, r == 0 && p.n_regions == 1);
    check(cname_name, r == 0 && p.n_regions == 1 &&
                          strcmp(p.regions[0].name, expected) == 0);
    if (r == 0)
        voleith_shipshape_parsed_free(&p);
}

static void
test_ring_sig_region_names(void)
{
    check_ring_sig_name("aes_dm", "aes_dm", 16,
                        "stdlib/crypto/ring_sig/v1[aes_dm]");
    check_ring_sig_name("aes_cmac_128", "aes_cmac_128", 16,
                        "stdlib/crypto/ring_sig/v1[aes_cmac_128]");
    check_ring_sig_name("grostl_256", "grostl_256", 32,
                        "stdlib/crypto/ring_sig/v1[grostl_256]");
    check_ring_sig_name("grostl_256_t27", "grostl_256_t27", 27,
                        "stdlib/crypto/ring_sig/v1[grostl_256_t27]");
    check_ring_sig_name("grostl_512", "grostl_512", 64,
                        "stdlib/crypto/ring_sig/v1[grostl_512]");
    check_ring_sig_name("grostl_512_t59", "grostl_512_t59", 59,
                        "stdlib/crypto/ring_sig/v1[grostl_512_t59]");
    check_ring_sig_name("hirose", "hirose", 32,
                        "stdlib/crypto/ring_sig/v1[hirose]");
    /* hirose_fixed_32: fixed_leaf_bytes=32; skb=32 == node_bytes */
    check_ring_sig_name("hirose_fixed_32", "hirose_fixed_32", 32,
                        "stdlib/crypto/ring_sig/v1[hirose_fixed_32]");
    /* grostl_256_fixed: fixed_leaf_bytes=32; skb=32 == node_bytes */
    check_ring_sig_name("grostl_256_fixed", "grostl_256_fixed", 32,
                        "stdlib/crypto/ring_sig/v1[grostl_256_fixed]");
    /* grostl_512_fixed: fixed_leaf_bytes=64; skb=64 == node_bytes */
    check_ring_sig_name("grostl_512_fixed", "grostl_512_fixed", 64,
                        "stdlib/crypto/ring_sig/v1[grostl_512_fixed]");
}

/* ================================================================
 * Group C: indexed_merkle/nonmember_secret[<type>] region names.
 *
 * Signature: (target : byte[tb], low : byte[tb], hi : byte[tb],
 *             nidx : byte[ib], siblings : byte[depth*node],
 *             dirs : byte[depth], root : byte[node])
 * No outputs (assertion-only).  root is INSTANCE.
 * depth=2, tb=8, ib=8 for all types.
 * hirose_fixed_32: fixed_leaf_bytes=32; leaf record = 2*tb+ib
 * = 2*8+8 = 24, which is != 32.  Use tb=12, ib=8 (2*12+8=32).
 * ================================================================ */

static void
check_indexed_name(const char *label, const char *type_name, size_t node,
                   size_t tb, size_t ib, const char *expected)
{
    char src[640];
    char cname_parse[128];
    char cname_n_regions[128];
    char cname_name[128];
    voleith_shipshape_parsed_t p;
    int r;

    /* target=tb, low=tb, hi=tb, nidx=ib, sib=2*node, dirs=2, root=node */
    snprintf(src, sizeof(src),
             HDR_V2 "WITNESS  -> %%target : byte[%zu]\n"
                    "WITNESS  -> %%low    : byte[%zu]\n"
                    "WITNESS  -> %%hi     : byte[%zu]\n"
                    "WITNESS  -> %%nidx   : byte[%zu]\n"
                    "WITNESS  -> %%sib    : byte[%zu]\n"
                    "WITNESS  -> %%dirs   : byte[2]\n"
                    "INSTANCE -> %%root   : byte[%zu]\n"
                    "stdlib/crypto/indexed_merkle/nonmember_secret[%s]"
                    "(%%target, %%low, %%hi, %%nidx, %%sib, %%dirs, %%root)\n",
             tb, tb, tb, ib, 2 * node, node, type_name);

    snprintf(cname_parse, sizeof(cname_parse),
             "indexed_merkle/nonmember_secret[%s]: parse returns 0", label);
    snprintf(cname_n_regions, sizeof(cname_n_regions),
             "indexed_merkle/nonmember_secret[%s]: one region", label);
    snprintf(cname_name, sizeof(cname_name),
             "indexed_merkle/nonmember_secret[%s]: region name == %s", label,
             expected);

    r = parse_into(src, &p);
    check(cname_parse, r == 0);
    check(cname_n_regions, r == 0 && p.n_regions == 1);
    check(cname_name, r == 0 && p.n_regions == 1 &&
                          strcmp(p.regions[0].name, expected) == 0);
    if (r == 0)
        voleith_shipshape_parsed_free(&p);
}

static void
test_indexed_merkle_region_names(void)
{
    check_indexed_name("aes_dm", "aes_dm", 16, 8, 8,
                       "stdlib/crypto/indexed_merkle/nonmember_secret[aes_dm]");
    check_indexed_name(
        "aes_cmac_128", "aes_cmac_128", 16, 8, 8,
        "stdlib/crypto/indexed_merkle/nonmember_secret[aes_cmac_128]");
    check_indexed_name(
        "grostl_256", "grostl_256", 32, 8, 8,
        "stdlib/crypto/indexed_merkle/nonmember_secret[grostl_256]");
    check_indexed_name(
        "grostl_256_t27", "grostl_256_t27", 27, 8, 8,
        "stdlib/crypto/indexed_merkle/nonmember_secret[grostl_256_t27]");
    check_indexed_name(
        "grostl_512", "grostl_512", 64, 8, 8,
        "stdlib/crypto/indexed_merkle/nonmember_secret[grostl_512]");
    check_indexed_name(
        "grostl_512_t59", "grostl_512_t59", 59, 8, 8,
        "stdlib/crypto/indexed_merkle/nonmember_secret[grostl_512_t59]");
    check_indexed_name("hirose", "hirose", 32, 8, 8,
                       "stdlib/crypto/indexed_merkle/nonmember_secret[hirose]");
    /*
     * hirose_fixed_32: fixed_leaf_bytes=32; leaf record = 2*tb+ib must
     * equal 32.  Use tb=12, ib=8 (2*12+8=32).
     */
    check_indexed_name(
        "hirose_fixed_32", "hirose_fixed_32", 32, 12, 8,
        "stdlib/crypto/indexed_merkle/nonmember_secret[hirose_fixed_32]");
    /* grostl_256_fixed: leaf record 2*12+8=32 = fixed_leaf_bytes */
    check_indexed_name(
        "grostl_256_fixed", "grostl_256_fixed", 32, 12, 8,
        "stdlib/crypto/indexed_merkle/nonmember_secret[grostl_256_fixed]");
    /* grostl_512_fixed: leaf record 2*28+8=64 = fixed_leaf_bytes */
    check_indexed_name(
        "grostl_512_fixed", "grostl_512_fixed", 64, 28, 8,
        "stdlib/crypto/indexed_merkle/nonmember_secret[grostl_512_fixed]");
}

int
main(void)
{
    printf("test_shipshape_crypto_v2_region_name\n");

    test_merkle_path_region_names();
    test_ring_sig_region_names();
    test_indexed_merkle_region_names();

    printf("%d/%d tests passed\n", pass_count, test_count);
    return pass_count == test_count ? 0 : 1;
}
