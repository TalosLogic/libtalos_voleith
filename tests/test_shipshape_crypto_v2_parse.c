/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * test_shipshape_crypto_v2_parse.c - MR3 smoke test: the parser accepts a
 * minimal `stdlib crypto-v2` file calling `merkle/path_secret[grostl_256]`
 * and produces the correct region name.
 *
 * Also checks that:
 *   - A v1 entry with a bracket is rejected (ERR_REGISTRY).
 *   - A v2 entry under `stdlib crypto-v1` is rejected (ERR_REGISTRY).
 *   - A v2 entry without a bracket is rejected (ERR_REGISTRY).
 *   - An unknown type name is rejected (ERR_REGISTRY).
 *   - A two-type bracket form is rejected (ERR_REGISTRY).
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

#define HDR_V1                                                                 \
    ".shipshape 1\n"                                                           \
    "field GF(2^8) irreducible 0x11B\n"                                        \
    "stdlib crypto-v1\n"

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

/*
 * Parse a buffer and immediately release on success; return the code.
 * Useful for error-path checks.
 */
static int
parse_str(const char *buf)
{
    voleith_shipshape_parsed_t p;
    int r;

    r = voleith_shipshape_parse_buffer(&p, buf, 0, NULL);
    voleith_shipshape_parsed_free(&p);
    return r;
}

/*
 * Group A: smoke roundtrip -- merkle/path_secret[grostl_256] under crypto-v2.
 *
 * grostl_256 has node_bytes=32.  depth=2 means:
 *   siblings : byte[2*32] = byte[64]
 *   dirs     : byte[2]
 *   leaf     : byte[32]  (L=32)
 */
static void
test_smoke(void)
{
    static const char src[] =
        HDR_V2 "WITNESS  -> %leaf : byte[32]\n"
               "WITNESS  -> %sib  : byte[64]\n"
               "WITNESS  -> %dirs : byte[2]\n"
               "stdlib/crypto/merkle/path_secret[grostl_256]"
               "(%leaf, %sib, %dirs) -> %root\n";
    voleith_shipshape_parsed_t p;
    int r;

    r = parse_into(src, &p);
    check("smoke: parse returns 0", r == 0);
    check("smoke: produces exactly one region", r == 0 && p.n_regions == 1);
    check("smoke: region name is stdlib/crypto/merkle/path_secret[grostl_256]",
          r == 0 && p.n_regions == 1 &&
              strcmp(p.regions[0].name,
                     "stdlib/crypto/merkle/path_secret[grostl_256]") == 0);
    voleith_shipshape_parsed_free(&p);
}

/*
 * Group B: ring_sig/v1[aes_dm] under crypto-v2.
 * aes_dm node_bytes=16.  sk=16, depth=2: sib=byte[32], dirs=byte[2].
 * root is INSTANCE (public root; assertion-only entry).
 */
static void
test_smoke_ring_sig(void)
{
    static const char src[] =
        HDR_V2 "WITNESS  -> %sk   : byte[16]\n"
               "WITNESS  -> %dirs : byte[2]\n"
               "WITNESS  -> %sib  : byte[32]\n"
               "INSTANCE -> %root : byte[16]\n"
               "stdlib/crypto/ring_sig/v1[aes_dm](%sk, %dirs, %sib, %root)\n";
    voleith_shipshape_parsed_t p;
    int r;

    r = parse_into(src, &p);
    check("smoke: ring_sig/v1[aes_dm] returns 0", r == 0);
    check("smoke: ring_sig produces one region", r == 0 && p.n_regions == 1);
    check("smoke: ring_sig region name is stdlib/crypto/ring_sig/v1[aes_dm]",
          r == 0 && p.n_regions == 1 &&
              strcmp(p.regions[0].name, "stdlib/crypto/ring_sig/v1[aes_dm]") ==
                  0);
    voleith_shipshape_parsed_free(&p);
}

/*
 * Group B: indexed_merkle/nonmember_secret[aes_dm] under crypto-v2.
 * aes_dm node_bytes=16.  tb=8, ib=8, depth=2.
 */
static void
test_smoke_indexed(void)
{
    static const char src[] =
        HDR_V2 "WITNESS  -> %target : byte[8]\n"
               "WITNESS  -> %low    : byte[8]\n"
               "WITNESS  -> %hi     : byte[8]\n"
               "WITNESS  -> %nidx   : byte[8]\n"
               "WITNESS  -> %sib    : byte[32]\n"
               "WITNESS  -> %dirs   : byte[2]\n"
               "INSTANCE -> %root   : byte[16]\n"
               "stdlib/crypto/indexed_merkle/nonmember_secret[aes_dm]"
               "(%target, %low, %hi, %nidx, %sib, %dirs, %root)\n";
    voleith_shipshape_parsed_t p;
    int r;

    r = parse_into(src, &p);
    check("smoke: indexed_merkle[aes_dm] returns 0", r == 0);
    check("smoke: indexed_merkle produces one region",
          r == 0 && p.n_regions == 1);
    check("smoke: indexed region name is "
          "stdlib/crypto/indexed_merkle/nonmember_secret[aes_dm]",
          r == 0 && p.n_regions == 1 &&
              strcmp(p.regions[0].name,
                     "stdlib/crypto/indexed_merkle/nonmember_secret[aes_dm]") ==
                  0);
    voleith_shipshape_parsed_free(&p);
}

/*
 * Group C: error paths.
 */
static void
test_errors(void)
{
    int r;

    /* v1 entry with a bracket: ERR_REGISTRY. */
    r = parse_str(HDR_V1 "WITNESS -> %a : byte\n"
                         "stdlib/crypto/aes/sbox[grostl_256](%a) -> %b\n");
    check("error: v1 entry + bracket => ERR_REGISTRY",
          r == VOLEITH_SHIPSHAPE_ERR_REGISTRY);

    /* v2 entry under stdlib crypto-v1: ERR_REGISTRY. */
    r = parse_str(HDR_V1 "WITNESS  -> %leaf : byte[32]\n"
                         "WITNESS  -> %sib  : byte[64]\n"
                         "WITNESS  -> %dirs : byte[2]\n"
                         "stdlib/crypto/merkle/path_secret[grostl_256]"
                         "(%leaf, %sib, %dirs) -> %root\n");
    check("error: v2 entry under crypto-v1 => ERR_REGISTRY",
          r == VOLEITH_SHIPSHAPE_ERR_REGISTRY);

    /* v2 entry without a bracket: ERR_REGISTRY. */
    r = parse_str(HDR_V2 "WITNESS  -> %leaf : byte[32]\n"
                         "WITNESS  -> %sib  : byte[64]\n"
                         "WITNESS  -> %dirs : byte[2]\n"
                         "stdlib/crypto/merkle/path_secret"
                         "(%leaf, %sib, %dirs) -> %root\n");
    check("error: v2 entry without bracket => ERR_REGISTRY",
          r == VOLEITH_SHIPSHAPE_ERR_REGISTRY);

    /* Unknown type name: ERR_REGISTRY. */
    r = parse_str(HDR_V2 "WITNESS  -> %leaf : byte[32]\n"
                         "WITNESS  -> %sib  : byte[64]\n"
                         "WITNESS  -> %dirs : byte[2]\n"
                         "stdlib/crypto/merkle/path_secret[blake3]"
                         "(%leaf, %sib, %dirs) -> %root\n");
    check("error: unknown type name => ERR_REGISTRY",
          r == VOLEITH_SHIPSHAPE_ERR_REGISTRY);

    /* Two-type bracket form: ERR_REGISTRY. */
    r = parse_str(HDR_V2 "WITNESS  -> %leaf : byte[32]\n"
                         "WITNESS  -> %sib  : byte[64]\n"
                         "WITNESS  -> %dirs : byte[2]\n"
                         "stdlib/crypto/merkle/path_secret[grostl_256, aes_dm]"
                         "(%leaf, %sib, %dirs) -> %root\n");
    check("error: two-type bracket => ERR_REGISTRY",
          r == VOLEITH_SHIPSHAPE_ERR_REGISTRY);

    /* siblings length != depth*node: ERR_TYPE. */
    r = parse_str(HDR_V2
                  "WITNESS  -> %leaf : byte[32]\n"
                  "WITNESS  -> %sib  : byte[48]\n" /* wrong: should be 64 */
                  "WITNESS  -> %dirs : byte[2]\n"
                  "stdlib/crypto/merkle/path_secret[grostl_256]"
                  "(%leaf, %sib, %dirs) -> %root\n");
    check("error: siblings wrong length => ERR_TYPE",
          r == VOLEITH_SHIPSHAPE_ERR_TYPE);
}

/*
 * Group D: MR4 error cases not already covered by Group C above.
 *
 * Cases already covered in test_errors() and NOT repeated here:
 *   - v1 entry + bracket => ERR_REGISTRY
 *   - hash entry under crypto-v1 => ERR_REGISTRY
 *   - hash entry without bracket => ERR_REGISTRY
 *   - unknown type name => ERR_REGISTRY
 *   - two-type bracket form => ERR_REGISTRY
 *   - siblings != depth*node => ERR_TYPE
 */
static void
test_errors_mr4(void)
{
    int r;

    /*
     * low length != tb: ERR_TYPE.
     * indexed_merkle/nonmember_secret[aes_dm] has tb=8 (inferred from
     * %target : byte[8]).  Supplying %low : byte[9] must trigger the
     * "low/hi must equal tb" PASS 1 check.
     */
    r = parse_str(HDR_V2 "WITNESS  -> %target : byte[8]\n"
                         "WITNESS  -> %low    : byte[9]\n" /* wrong: tb=8 */
                         "WITNESS  -> %hi     : byte[8]\n"
                         "WITNESS  -> %nidx   : byte[8]\n"
                         "WITNESS  -> %sib    : byte[32]\n"
                         "WITNESS  -> %dirs   : byte[2]\n"
                         "INSTANCE -> %root   : byte[16]\n"
                         "stdlib/crypto/indexed_merkle/nonmember_secret[aes_dm]"
                         "(%target, %low, %hi, %nidx, %sib, %dirs, %root)\n");
    check("error: low length != tb => ERR_TYPE",
          r == VOLEITH_SHIPSHAPE_ERR_TYPE);

    /*
     * hirose_fixed_32 with leaf width != 32: ERR_TYPE.
     * hirose_fixed_32 requires vt->fixed_leaf_bytes == 32; supplying L=16
     * triggers the fixed-leaf check in registry_call_hash.
     */
    r = parse_str(HDR_V2
                  "WITNESS  -> %leaf : byte[16]\n" /* wrong: must be 32 */
                  "WITNESS  -> %sib  : byte[64]\n"
                  "WITNESS  -> %dirs : byte[2]\n"
                  "stdlib/crypto/merkle/path_secret[hirose_fixed_32]"
                  "(%leaf, %sib, %dirs) -> %root\n");
    check("error: hirose_fixed_32 with leaf width != 32 => ERR_TYPE",
          r == VOLEITH_SHIPSHAPE_ERR_TYPE);

    /*
     * Depth above param_max: ERR_LIMIT.
     * For ring_sig/v1, param_max[RS_DEPTH] = 1<<16 = 65536.  Using
     * depth = 65537 = (1<<16)+1 exceeds the bound and is caught in PASS 1
     * before any gate is emitted.
     *
     * The sibling buffer must match depth*node = 65537*16 bytes, which
     * would be gigantic; instead we pass a mismatched length so the
     * ERR_LIMIT on depth fires BEFORE the DEPTH_TIMES_NODE check in PASS 2
     * (PASS 1 checks the PARAM bound first, then PASS 2 validates
     * DEPTH_TIMES_NODE lengths).  So we supply sib : byte[32] (valid for
     * depth=2) but dirs : byte[65537] to trigger the depth param_max check.
     *
     * Note: depth binds from %dirs (PARAM index RS_DEPTH) in ring_sig/v1.
     * Declaring %dirs : byte[65537] with sk=16 sets depth=65537 > param_max.
     */
    r = parse_str(
        HDR_V2 "WITNESS  -> %sk   : byte[16]\n"
               "WITNESS  -> %dirs : byte[65537]\n" /* depth=65537 > 65536 */
               "WITNESS  -> %sib  : byte[32]\n"
               "INSTANCE -> %root : byte[16]\n"
               "stdlib/crypto/ring_sig/v1[aes_dm](%sk, %dirs, %sib, %root)\n");
    check("error: depth above param_max => ERR_LIMIT",
          r == VOLEITH_SHIPSHAPE_ERR_LIMIT);
}

int
main(void)
{
    printf("test_shipshape_crypto_v2_parse\n");

    test_smoke();
    test_smoke_ring_sig();
    test_smoke_indexed();
    test_errors();
    test_errors_mr4();

    printf("%d/%d tests passed\n", pass_count, test_count);
    return pass_count == test_count ? 0 : 1;
}
