/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * test_shipshape_witgen_construction_handlers.c - equivalence tests for the
 * W8.5b native crypto-v2 CONSTRUCTION witness backends
 * (parsers/shipshape_witgen_construction.c).
 *
 * For each confirmed construction (merkle/path_secret, ring_sig/v1,
 * indexed_merkle/nonmember_secret), over at least aes_dm and one grostl type,
 * the full witness is generated twice over the same external inputs:
 *
 *   baseline:   no backend registered (generic Tier 1 evaluator).
 *   dispatched: voleith_shipshape_witgen_register_constructions() registered.
 *
 * The two MUST be byte-identical (same length, memcmp == 0).  This is the
 * STDLIB equivalence-oracle property: a Tier 2a construction backend is a pure
 * speed layer that must reproduce the generic witness exactly.
 *
 * No prove / verify is performed (W8.6 adds the prove grid).  A valid tree is
 * NOT required: both the generic and handler paths derive the inv bytes
 * deterministically from the same ext via the same node-hash primitive, so the
 * byte-equivalence holds regardless of whether the tree is consistent.  The
 * only ext constraint is that dir bytes must be in {0, 1} (the secret-dir mux /
 * booleanity require it); all other ext bytes are arbitrary deterministic
 * values.
 *
 * SELF_CHECK is intentionally NOT set: the circuit's ASSERT_EQUAL root
 * constraints would fail on an inconsistent tree, but the inv-witness span we
 * compare is independent of constraint satisfaction.
 */

#include "shipshape.h"
#include "shipshape_witgen_construction.h"
#include "shipshape_witgen_dispatch.h"
#include "shipshape_witness.h"

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
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

/* crypto-v2 header. */
#define HDR_V2                                                                 \
    ".shipshape 1\n"                                                           \
    "field GF(2^8) irreducible 0x11B\n"                                        \
    "stdlib crypto-v2\n"

/*
 * Fill buf[0..len-1] with deterministic non-trivial bytes.  The seed offsets
 * the pattern so distinct buffers do not collide trivially.
 */
static void
fill_pattern(uint8_t *buf, size_t len, uint8_t seed)
{
    size_t i;

    for (i = 0; i < len; i++)
        buf[i] = (uint8_t)((i * 7u + seed * 13u + 0x5Au) & 0xff);
}

/*
 * Run one equivalence case: parse `src`, build ext (the caller fills it),
 * generate witness without backends (baseline) and with the construction
 * backends registered (dispatched), assert the two are byte-identical.
 *
 * ext / ext_len: the external WITNESS bytes in declaration order.  The INSTANCE
 * root values do not affect the inv-witness span; we pass a deterministic
 * filler of the circuit's instance count.
 */
static void
run_case(const char *name, const char *src, const uint8_t *ext, size_t ext_len)
{
    voleith_shipshape_parsed_t p = {0};
    uint8_t *baseline = NULL, *dispatched = NULL;
    uint8_t *inst = NULL;
    size_t baseline_len = 0, dispatched_len = 0, inst_len = 0;
    int r;

    r = voleith_shipshape_parse_buffer(&p, src, 0, NULL);
    check(name, r == 0 && p.circuit != NULL);
    if (r != 0 || p.circuit == NULL) {
        voleith_shipshape_parsed_free(&p);
        return;
    }

    /* Sanity: ext_len must match the circuit's external witness length. */
    check(name, voleith_shipshape_external_witness_len(&p) == ext_len);

    /* Instance filler (root): deterministic, value-irrelevant to the span. */
    inst_len = voleith_gf8_circuit_instance_count(p.circuit);
    if (inst_len > 0) {
        inst = calloc(inst_len, 1);
        if (inst == NULL) {
            check(name, 0);
            voleith_shipshape_parsed_free(&p);
            return;
        }
        fill_pattern(inst, inst_len, 0xC3);
    }

    /* Baseline: no backend registered. */
    voleith_shipshape_witgen_reset();
    r = voleith_shipshape_witness_gen(&p, ext, ext_len, inst, inst_len, 0,
                                      &baseline, &baseline_len);
    check(name, r == 0 && baseline != NULL);

    /* Dispatched: construction backends registered. */
    voleith_shipshape_witgen_reset();
    r = voleith_shipshape_witgen_register_constructions();
    check(name, r == 0);
    r = voleith_shipshape_witness_gen(&p, ext, ext_len, inst, inst_len, 0,
                                      &dispatched, &dispatched_len);
    check(name, r == 0 && dispatched != NULL);

    /* Equivalence oracle: byte-for-byte identical. */
    check(name, baseline != NULL && dispatched != NULL &&
                    baseline_len == dispatched_len &&
                    memcmp(baseline, dispatched, baseline_len) == 0);

    free(baseline);
    free(dispatched);
    free(inst);
    voleith_shipshape_parsed_free(&p);
    voleith_shipshape_witgen_reset();
}

/* ================================================================
 * merkle/path_secret cases.  ext = leaf(L) | siblings(depth*node) | dirs(depth).
 * ================================================================ */

/* aes_dm: node=16, L=16, depth=2 -> ext = 16 + 32 + 2 = 50.  root is an
 * inferred OUTPUT wire (-> %root), not an INSTANCE; the path_secret signature
 * returns the root. */
static const char MERKLE_AESDM_SRC[] =
    HDR_V2 "WITNESS  -> %leaf : byte[16]\n"
           "WITNESS  -> %sib  : byte[32]\n"
           "WITNESS  -> %dirs : byte[2]\n"
           "stdlib/crypto/merkle/path_secret[aes_dm]"
           "(%leaf, %sib, %dirs) -> %root\n";

/* grostl_256: node=32, L=16, depth=2 -> ext = 16 + 64 + 2 = 82. */
static const char MERKLE_GROSTL_SRC[] =
    HDR_V2 "WITNESS  -> %leaf : byte[16]\n"
           "WITNESS  -> %sib  : byte[64]\n"
           "WITNESS  -> %dirs : byte[2]\n"
           "stdlib/crypto/merkle/path_secret[grostl_256]"
           "(%leaf, %sib, %dirs) -> %root\n";

static void
test_merkle_path_secret(void)
{
    uint8_t ext[128];

    /* aes_dm: leaf(16) | sib(32) | dirs(2). dirs in {0,1}. */
    fill_pattern(ext, 16 + 32, 0x01);
    ext[48] = 0x00;
    ext[49] = 0x01;
    run_case("merkle/path_secret[aes_dm] equivalence", MERKLE_AESDM_SRC, ext,
             50);

    /* grostl_256: leaf(16) | sib(64) | dirs(2). dirs in {0,1}. */
    fill_pattern(ext, 16 + 64, 0x02);
    ext[80] = 0x01;
    ext[81] = 0x00;
    run_case("merkle/path_secret[grostl_256] equivalence", MERKLE_GROSTL_SRC,
             ext, 82);
}

/* ================================================================
 * ring_sig/v1 cases.  ext = sk(skb) | dirs(depth) | siblings(depth*node) |
 * root(node).  The root is an INSTANCE wire, so it is NOT part of ext; ext =
 * sk | dirs | siblings.
 * ================================================================ */

/* aes_dm: node=16, skb=16, depth=2 -> ext = 16 + 2 + 32 = 50. */
static const char RING_AESDM_SRC[] = HDR_V2 "WITNESS  -> %sk   : byte[16]\n"
                                            "WITNESS  -> %dirs : byte[2]\n"
                                            "WITNESS  -> %sib  : byte[32]\n"
                                            "INSTANCE -> %root : byte[16]\n"
                                            "stdlib/crypto/ring_sig/v1[aes_dm]"
                                            "(%sk, %dirs, %sib, %root)\n";

/* grostl_256: node=32, skb=16, depth=2 -> ext = 16 + 2 + 64 = 82. */
static const char RING_GROSTL_SRC[] =
    HDR_V2 "WITNESS  -> %sk   : byte[16]\n"
           "WITNESS  -> %dirs : byte[2]\n"
           "WITNESS  -> %sib  : byte[64]\n"
           "INSTANCE -> %root : byte[32]\n"
           "stdlib/crypto/ring_sig/v1[grostl_256]"
           "(%sk, %dirs, %sib, %root)\n";

static void
test_ring_sig_v1(void)
{
    uint8_t ext[128];

    /* aes_dm: sk(16) | dirs(2) | sib(32). dirs in {0,1}. */
    fill_pattern(ext, 16, 0x03);
    ext[16] = 0x00;
    ext[17] = 0x00;
    fill_pattern(ext + 18, 32, 0x04);
    run_case("ring_sig/v1[aes_dm] equivalence", RING_AESDM_SRC, ext, 50);

    /* grostl_256: sk(16) | dirs(2) | sib(64). dirs in {0,1}. */
    fill_pattern(ext, 16, 0x05);
    ext[16] = 0x01;
    ext[17] = 0x01;
    fill_pattern(ext + 18, 64, 0x06);
    run_case("ring_sig/v1[grostl_256] equivalence", RING_GROSTL_SRC, ext, 82);
}

/* ================================================================
 * indexed_merkle/nonmember_secret cases.  ext = target(tb) | low(tb) | hi(tb) |
 * nidx(ib) | siblings(depth*node) | dirs(depth).  The root is an INSTANCE wire.
 * ================================================================ */

/* aes_dm: node=16, tb=4, ib=4, depth=2 ->
 *   ext = 4 + 4 + 4 + 4 + 32 + 2 = 50. */
static const char INDEXED_AESDM_SRC[] =
    HDR_V2 "WITNESS  -> %tgt  : byte[4]\n"
           "WITNESS  -> %low  : byte[4]\n"
           "WITNESS  -> %hi   : byte[4]\n"
           "WITNESS  -> %nidx : byte[4]\n"
           "WITNESS  -> %sib  : byte[32]\n"
           "WITNESS  -> %dirs : byte[2]\n"
           "INSTANCE -> %root : byte[16]\n"
           "stdlib/crypto/indexed_merkle/nonmember_secret[aes_dm]"
           "(%tgt, %low, %hi, %nidx, %sib, %dirs, %root)\n";

/* grostl_256: node=32, tb=4, ib=4, depth=2 ->
 *   ext = 4 + 4 + 4 + 4 + 64 + 2 = 82. */
static const char INDEXED_GROSTL_SRC[] =
    HDR_V2 "WITNESS  -> %tgt  : byte[4]\n"
           "WITNESS  -> %low  : byte[4]\n"
           "WITNESS  -> %hi   : byte[4]\n"
           "WITNESS  -> %nidx : byte[4]\n"
           "WITNESS  -> %sib  : byte[64]\n"
           "WITNESS  -> %dirs : byte[2]\n"
           "INSTANCE -> %root : byte[32]\n"
           "stdlib/crypto/indexed_merkle/nonmember_secret[grostl_256]"
           "(%tgt, %low, %hi, %nidx, %sib, %dirs, %root)\n";

static void
test_indexed_nonmember_secret(void)
{
    uint8_t ext[128];

    /* aes_dm: tgt(4)|low(4)|hi(4)|nidx(4)|sib(32)|dirs(2). dirs in {0,1}. */
    fill_pattern(ext, 16 + 32, 0x07);
    ext[48] = 0x00;
    ext[49] = 0x01;
    run_case("indexed_merkle/nonmember_secret[aes_dm] equivalence",
             INDEXED_AESDM_SRC, ext, 50);

    /* grostl_256: tgt(4)|low(4)|hi(4)|nidx(4)|sib(64)|dirs(2). dirs in {0,1}. */
    fill_pattern(ext, 16 + 64, 0x08);
    ext[80] = 0x01;
    ext[81] = 0x00;
    run_case("indexed_merkle/nonmember_secret[grostl_256] equivalence",
             INDEXED_GROSTL_SRC, ext, 82);
}

/* ================================================================
 * Fallback: with nothing registered, witness_gen succeeds and equals the
 * no-backend baseline trivially.  This is the production default path: the
 * generic evaluator carries every construction.
 * ================================================================ */
static void
test_fallback_no_backend(void)
{
    voleith_shipshape_parsed_t p = {0};
    uint8_t *wit = NULL, *inst = NULL;
    size_t wit_len = 0, inst_len = 0;
    uint8_t ext[50];
    int r;

    fill_pattern(ext, 16 + 32, 0x09);
    ext[48] = 0x00;
    ext[49] = 0x01;

    r = voleith_shipshape_parse_buffer(&p, MERKLE_AESDM_SRC, 0, NULL);
    check("fallback: parse ok", r == 0 && p.circuit != NULL);
    if (r != 0 || p.circuit == NULL) {
        voleith_shipshape_parsed_free(&p);
        return;
    }

    inst_len = voleith_gf8_circuit_instance_count(p.circuit);
    if (inst_len > 0) {
        inst = calloc(inst_len, 1);
        if (inst == NULL) {
            check("fallback: inst alloc", 0);
            voleith_shipshape_parsed_free(&p);
            return;
        }
        fill_pattern(inst, inst_len, 0xC3);
    }

    /* No backend registered: the generic evaluator must still succeed. */
    voleith_shipshape_witgen_reset();
    r = voleith_shipshape_witness_gen(&p, ext, sizeof(ext), inst, inst_len, 0,
                                      &wit, &wit_len);
    check("fallback: generic witness gen ok", r == 0 && wit != NULL);

    free(wit);
    free(inst);
    voleith_shipshape_parsed_free(&p);
    voleith_shipshape_witgen_reset();
}

/* ================================================================
 * register_constructions() returns 0.
 * ================================================================ */
static void
test_register_returns_zero(void)
{
    int r;

    voleith_shipshape_witgen_reset();
    r = voleith_shipshape_witgen_register_constructions();
    check("register_constructions returns 0", r == 0);
    voleith_shipshape_witgen_reset();
}

int
main(void)
{
    printf("test_shipshape_witgen_construction_handlers\n");

    test_register_returns_zero();
    test_merkle_path_secret();
    test_ring_sig_v1();
    test_indexed_nonmember_secret();
    test_fallback_no_backend();

    printf("%d/%d tests passed\n", pass_count, test_count);
    return pass_count == test_count ? 0 : 1;
}
