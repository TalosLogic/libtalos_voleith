/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * test_shipshape_crypto_v3.c - conformance for the crypto-v3 stdlib version
 * (the Shipshape spec 7.8): the norm S-box standalone entries and node-hash
 * types.
 *
 * Checks:
 *   - A crypto-v3 file calling a norm node-hash bracket
 *     (merkle/path_secret[aes_dm_norm]) parses and names its region.
 *   - A crypto-v3 file calling a norm standalone entry
 *     (aes/encrypt_128_norm) parses.
 *   - crypto-v3 is additive: a crypto-v1 kernel and a crypto-v2 bracket
 *     both parse under crypto-v3.
 *   - A norm node-hash type under crypto-v2 is ERR_REGISTRY.
 *   - A norm standalone entry under crypto-v2 and crypto-v1 is ERR_REGISTRY.
 *   - An unknown stdlib version (crypto-v4) is ERR_HEADER.
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

#define HDR_V3                                                                 \
    ".shipshape 1\n"                                                           \
    "field GF(2^8) irreducible 0x11B\n"                                        \
    "stdlib crypto-v3\n"

static int
parse_into(const char *buf, voleith_shipshape_parsed_t *p)
{
    return voleith_shipshape_parse_buffer(p, buf, 0, NULL);
}

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
 * merkle/path_secret[aes_dm_norm] under crypto-v3.
 * aes_dm_norm node_bytes=16 (variable leaf).  depth=2, L=16:
 *   leaf byte[16], siblings byte[32], dirs byte[2].
 */
static void
test_smoke_norm_bracket(void)
{
    static const char src[] =
        HDR_V3 "WITNESS  -> %leaf : byte[16]\n"
               "WITNESS  -> %sib  : byte[32]\n"
               "WITNESS  -> %dirs : byte[2]\n"
               "stdlib/crypto/merkle/path_secret[aes_dm_norm]"
               "(%leaf, %sib, %dirs) -> %root\n";
    voleith_shipshape_parsed_t p;
    int r;

    r = parse_into(src, &p);
    check("smoke: path_secret[aes_dm_norm] parses under crypto-v3", r == 0);
    check("smoke: one region", r == 0 && p.n_regions == 1);
    check("smoke: region name is path_secret[aes_dm_norm]",
          r == 0 && p.n_regions == 1 &&
              strcmp(p.regions[0].name,
                     "stdlib/crypto/merkle/path_secret[aes_dm_norm]") == 0);
    voleith_shipshape_parsed_free(&p);
}

/*
 * aes/encrypt_128_norm standalone entry under crypto-v3.
 * Signature: (key : byte[16], pt : byte[16]) -> (ct : byte[16]).
 */
static void
test_smoke_norm_standalone(void)
{
    static const char src[] =
        HDR_V3 "WITNESS  -> %key : byte[16]\n"
               "WITNESS  -> %pt  : byte[16]\n"
               "stdlib/crypto/aes/encrypt_128_norm(%key, %pt) -> %ct\n";
    int r = parse_str(src);

    check("smoke: aes/encrypt_128_norm parses under crypto-v3", r == 0);
}

/*
 * crypto-v3 is additive: a crypto-v1 kernel and a crypto-v2 bracket both
 * remain callable under crypto-v3.
 */
static void
test_additive(void)
{
    int r;

    r = parse_str(HDR_V3 "WITNESS -> %key : byte[16]\n"
                         "WITNESS -> %pt  : byte[16]\n"
                         "stdlib/crypto/aes/encrypt_128(%key, %pt) -> %ct\n");
    check("additive: crypto-v1 kernel under crypto-v3 parses", r == 0);

    r = parse_str(HDR_V3 "WITNESS  -> %leaf : byte[32]\n"
                         "WITNESS  -> %sib  : byte[64]\n"
                         "WITNESS  -> %dirs : byte[2]\n"
                         "stdlib/crypto/merkle/path_secret[grostl_256]"
                         "(%leaf, %sib, %dirs) -> %root\n");
    check("additive: crypto-v2 bracket under crypto-v3 parses", r == 0);
}

/*
 * Gating: norm constructions are absent from crypto-v1 / crypto-v2.
 */
static void
test_gating(void)
{
    int r;

    /* Norm node-hash type under crypto-v2: ERR_REGISTRY. */
    r = parse_str(HDR_V2 "WITNESS  -> %leaf : byte[16]\n"
                         "WITNESS  -> %sib  : byte[32]\n"
                         "WITNESS  -> %dirs : byte[2]\n"
                         "stdlib/crypto/merkle/path_secret[aes_dm_norm]"
                         "(%leaf, %sib, %dirs) -> %root\n");
    check("gating: norm node-hash type under crypto-v2 => ERR_REGISTRY",
          r == VOLEITH_SHIPSHAPE_ERR_REGISTRY);

    /* Norm standalone entry under crypto-v2: ERR_REGISTRY. */
    r = parse_str(HDR_V2
                  "WITNESS -> %key : byte[16]\n"
                  "WITNESS -> %pt  : byte[16]\n"
                  "stdlib/crypto/aes/encrypt_128_norm(%key, %pt) -> %ct\n");
    check("gating: norm standalone under crypto-v2 => ERR_REGISTRY",
          r == VOLEITH_SHIPSHAPE_ERR_REGISTRY);

    /* Norm standalone entry under crypto-v1: ERR_REGISTRY. */
    r = parse_str(HDR_V1
                  "WITNESS -> %key : byte[16]\n"
                  "WITNESS -> %pt  : byte[16]\n"
                  "stdlib/crypto/aes/encrypt_128_norm(%key, %pt) -> %ct\n");
    check("gating: norm standalone under crypto-v1 => ERR_REGISTRY",
          r == VOLEITH_SHIPSHAPE_ERR_REGISTRY);

    /* Unknown stdlib version: ERR_HEADER. */
    r = parse_str(".shipshape 1\n"
                  "field GF(2^8) irreducible 0x11B\n"
                  "stdlib crypto-v4\n"
                  "WITNESS -> %a : byte\n"
                  "stdlib/crypto/aes/sbox(%a) -> %b\n");
    check("gating: unknown stdlib crypto-v4 => ERR_HEADER",
          r == VOLEITH_SHIPSHAPE_ERR_HEADER);
}

int
main(void)
{
    printf("test_shipshape_crypto_v3\n");

    test_smoke_norm_bracket();
    test_smoke_norm_standalone();
    test_additive();
    test_gating();

    printf("%d/%d tests passed\n", pass_count, test_count);
    return pass_count == test_count ? 0 : 1;
}
