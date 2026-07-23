/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * test_shipshape_conformance.c - Fingerprint conformance + alias corpus for
 * the Shipshape (.ship) parser.
 *
 * Covers W3.8 of the implementation plan: the hand-curated
 * cross-parser corpus mandated by ISA design §5.5 (and §8.4 item 12, second
 * half).  Every input here is checked against the 16-byte canonical
 * fingerprint of the equivalent hand-built GF(2^8) circuit
 * (voleith_gf8_circuit_fingerprint, proof/gf8_circuit_fingerprint.h).
 * Per ISA §5.5 any disagreement is a release-blocker.
 *
 * The corpus is organized by the axes §5.5 enumerates:
 *
 *   Group A: parse-then-reparse fingerprint idempotence.  The same source,
 *            parsed twice, yields byte-identical fingerprints (the lowering
 *            is deterministic; canonical order is emission order, §5.4).
 *   Group B: every sugar form lowers to its desugared C-built equivalent
 *            (SUM, FROBENIUS_K, CONST_BIT, ASSERT_BIT, ASSERT_CONST, MUX,
 *            INV, LINEAR_MAP squaring-matrix canonicalization, the bit
 *            refinement on WITNESS).
 *   Group C: every byte-literal encoding.  Hex digit case is an alias: two
 *            spellings of the same byte produce the identical fingerprint
 *            at every literal site (CONST, ADD_CONST, ASSERT_CONST,
 *            LINEAR_MAP matrix), including the 0x00 / 0xff boundaries.
 *   Group D: every region-marker placement.  Regions are a side table
 *            (ISA §2.8) and never enter the fingerprint: a subcircuit call
 *            and the equivalent inlined gates hash identically while their
 *            region tables differ; placement does not perturb the hash.
 *   Group E: gate-ordering edge cases.  Independent gates emitted in
 *            different source order lower to differently-ordered wire
 *            tables and MUST hash differently (§5.4); the redundant-
 *            constraint example (§5.4) likewise hashes differently.
 */

#include "aes_gf8_circuit.h"
#include "gf8_circuit.h"
#include "gf8_circuit_fingerprint.h"
#include "shipshape.h"

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

/* Header prefix shared by every corpus source. */
#define HDR                                                                    \
    ".shipshape 1\n"                                                           \
    "field GF(2^8) irreducible 0x11B\n"                                        \
    "stdlib crypto-v1\n"

/* Parse `src` with default limits into *p; returns the code. */
static int
parse(const char *src, voleith_shipshape_parsed_t *p)
{
    return voleith_shipshape_parse_buffer(p, src, 0, NULL);
}

/*
 * Write the canonical fingerprint of *c into out.  Returns 1 on success, 0
 * if c is NULL or the fingerprint call fails.
 */
static int
fp_of(const voleith_gf8_circuit_t *c,
      uint8_t out[VOLEITH_GF8_CIRCUIT_FINGERPRINT_BYTES])
{
    if (c == NULL)
        return 0;
    return voleith_gf8_circuit_fingerprint(c, out) == 0;
}

/* True iff two circuits share the same canonical fingerprint (ISA §5.3). */
static int
fp_eq(const voleith_gf8_circuit_t *a, const voleith_gf8_circuit_t *b)
{
    uint8_t fa[VOLEITH_GF8_CIRCUIT_FINGERPRINT_BYTES];
    uint8_t fb[VOLEITH_GF8_CIRCUIT_FINGERPRINT_BYTES];

    if (!fp_of(a, fa) || !fp_of(b, fb))
        return 0;
    return memcmp(fa, fb, sizeof(fa)) == 0;
}

/*
 * Parse `src`, compare the resulting circuit's fingerprint to `ref` built by
 * the hand-written gf8 builders, record one check named `name`, and free
 * both the parsed result and `ref`.
 */
static void
lowers_to(const char *name, const char *src, voleith_gf8_circuit_t *ref)
{
    voleith_shipshape_parsed_t p;
    int r;

    r = parse(src, &p);
    check(name, r == 0 && fp_eq(p.circuit, ref));
    voleith_shipshape_parsed_free(&p);
    voleith_gf8_circuit_free(ref);
}

/*
 * Parse the two sources, record one check named `name` asserting both parse
 * and lower to the identical fingerprint, and free both results.  Used for
 * alias pairs: two spellings that MUST agree.
 */
static void
same_fp(const char *name, const char *src_a, const char *src_b)
{
    voleith_shipshape_parsed_t pa, pb;
    int ra, rb;

    ra = parse(src_a, &pa);
    rb = parse(src_b, &pb);
    check(name, ra == 0 && rb == 0 && fp_eq(pa.circuit, pb.circuit));
    voleith_shipshape_parsed_free(&pa);
    voleith_shipshape_parsed_free(&pb);
}

/*
 * Parse the two sources, record one check named `name` asserting both parse
 * but lower to DIFFERENT fingerprints, and free both results.  Used for the
 * §5.4 distinctness cases.
 */
static void
diff_fp(const char *name, const char *src_a, const char *src_b)
{
    voleith_shipshape_parsed_t pa, pb;
    int ra, rb;

    ra = parse(src_a, &pa);
    rb = parse(src_b, &pb);
    check(name, ra == 0 && rb == 0 && pa.circuit != NULL &&
                    pb.circuit != NULL && !fp_eq(pa.circuit, pb.circuit));
    voleith_shipshape_parsed_free(&pa);
    voleith_shipshape_parsed_free(&pb);
}

/* ================================================================
 * Group A: parse-then-reparse fingerprint idempotence.
 * ================================================================ */

/*
 * Parse `src` twice and assert the two fingerprints are byte-identical: the
 * lowering is fully deterministic, so re-parsing the same text reproduces
 * the same canonical circuit (ISA §5.2-§5.4).
 */
static void
idempotent(const char *name, const char *src)
{
    voleith_shipshape_parsed_t p1, p2;
    uint8_t f1[VOLEITH_GF8_CIRCUIT_FINGERPRINT_BYTES];
    uint8_t f2[VOLEITH_GF8_CIRCUIT_FINGERPRINT_BYTES];
    int r1, r2, ok;

    r1 = parse(src, &p1);
    r2 = parse(src, &p2);
    ok = r1 == 0 && r2 == 0 && fp_of(p1.circuit, f1) && fp_of(p2.circuit, f2) &&
         memcmp(f1, f2, sizeof(f1)) == 0;
    check(name, ok);
    voleith_shipshape_parsed_free(&p1);
    voleith_shipshape_parsed_free(&p2);
}

static void
test_idempotence(void)
{
    /* A mixed gate / assertion body. */
    idempotent("idem: gates and assertions", HDR "WITNESS -> %a : byte\n"
                                                 "WITNESS -> %b : byte\n"
                                                 "ADD %a %b -> %s\n"
                                                 "MUL %a %b -> %p\n"
                                                 "ADD_CONST %a 0x1b -> %t\n"
                                                 "SQUARE %b -> %q\n"
                                                 "ASSERT_EQUAL %s %t\n");

    /* Every sugar form in one source. */
    idempotent("idem: full sugar set", HDR "WITNESS -> %a : byte\n"
                                           "WITNESS -> %b : byte\n"
                                           "WITNESS -> %c : byte\n"
                                           "SUM %a %b %c -> %d\n"
                                           "FROBENIUS_K 3 %a -> %e\n"
                                           "CONST_BIT 1 -> %one\n"
                                           "INV %a -> %ai\n"
                                           "ASSERT_BIT %one -> %ob : bit\n"
                                           "ASSERT_CONST %a 0x00\n");

    /* A user subcircuit call (regions exercised). */
    idempotent("idem: subcircuit call", HDR
               "subcircuit user/mac (%x : byte, %y : byte) -> (%z : byte) {\n"
               "MUL %x %y -> %z\n"
               "}\n"
               "WITNESS -> %a : byte\n"
               "WITNESS -> %b : byte\n"
               "user/mac(%a, %b) -> %c\n");

    /* A Tier 2a registry call. */
    idempotent("idem: registry sbox call",
               HDR "WITNESS -> %x : byte\n"
                   "stdlib/crypto/aes/sbox(%x) -> %y\n");
}

/* ================================================================
 * Group B: every sugar form lowers to its desugared C equivalent.
 * ================================================================ */

static void
test_sugar_forms(void)
{
    voleith_gf8_circuit_t *c;
    gf8_wire_id a, b, cc, sel;

    /* SUM -> chained ADD (n-1 XOR). */
    c = voleith_gf8_circuit_new();
    a = voleith_gf8_add_witness(c);
    b = voleith_gf8_add_witness(c);
    cc = voleith_gf8_add_witness(c);
    {
        gf8_wire_id acc = voleith_gf8_add_xor(c, a, b);
        voleith_gf8_add_xor(c, acc, cc);
    }
    lowers_to("sugar: SUM -> chained ADD",
              HDR "WITNESS -> %a : byte\n"
                  "WITNESS -> %b : byte\n"
                  "WITNESS -> %c : byte\n"
                  "SUM %a %b %c -> %d\n",
              c);

    /* FROBENIUS_K 1 -> a single SQUARE (k == 1 boundary). */
    c = voleith_gf8_circuit_new();
    a = voleith_gf8_add_witness(c);
    voleith_gf8_add_square(c, a);
    lowers_to("sugar: FROBENIUS_K 1 -> SQUARE",
              HDR "WITNESS -> %a : byte\n"
                  "FROBENIUS_K 1 %a -> %c\n",
              c);

    /* CONST_BIT 1 -> CONST 0x01. */
    c = voleith_gf8_circuit_new();
    voleith_gf8_add_const(c, 0x01);
    lowers_to("sugar: CONST_BIT 1 -> CONST 0x01", HDR "CONST_BIT 1 -> %one\n",
              c);

    /* CONST_BIT 0 -> CONST 0x00. */
    c = voleith_gf8_circuit_new();
    voleith_gf8_add_const(c, 0x00);
    lowers_to("sugar: CONST_BIT 0 -> CONST 0x00", HDR "CONST_BIT 0 -> %zero\n",
              c);

    /* ASSERT_BIT a -> a' : bit  desugars to ASSERT_PRODUCT(a, a, a); no new
     * wire is introduced (the name aliases the same wire). */
    c = voleith_gf8_circuit_new();
    a = voleith_gf8_add_witness(c);
    voleith_gf8_assert_product(c, a, a, a);
    lowers_to("sugar: ASSERT_BIT -> ASSERT_PRODUCT(a,a,a)",
              HDR "WITNESS -> %a : byte\n"
                  "ASSERT_BIT %a -> %ab : bit\n",
              c);

    /* ASSERT_CONST a k  desugars to ASSERT_ZERO(ADD_CONST(a, k)). */
    c = voleith_gf8_circuit_new();
    a = voleith_gf8_add_witness(c);
    {
        gf8_wire_id t = voleith_gf8_add_xor_const(c, a, 0x63);
        voleith_gf8_assert_zero(c, t);
    }
    lowers_to("sugar: ASSERT_CONST -> ADD_CONST + ASSERT_ZERO",
              HDR "WITNESS -> %a : byte\n"
                  "ASSERT_CONST %a 0x63\n",
              c);

    /* MUX sel a b -> c  desugars to diff = b^a; prod = sel*diff; out = a^prod
     * (one MUL slot).  The selector must carry the bit refinement, so the
     * `: bit` WITNESS first emits its booleanity ASSERT_PRODUCT(sel,sel,sel)
     * (see lower_input_decl); the hand-built reference must include it. */
    c = voleith_gf8_circuit_new();
    sel = voleith_gf8_add_witness(c);
    voleith_gf8_assert_product(c, sel, sel, sel);
    a = voleith_gf8_add_witness(c);
    b = voleith_gf8_add_witness(c);
    voleith_gf8_add_mux(c, a, b, sel);
    lowers_to("sugar: MUX -> diff/prod/out three-gate expansion",
              HDR "WITNESS -> %sel : bit\n"
                  "WITNESS -> %a : byte\n"
                  "WITNESS -> %b : byte\n"
                  "MUX %sel %a %b -> %c\n",
              c);

    /* INV a -> c  desugars to the canonical witness + two ASSERT_PRODUCT
     * gadget (Step 4). */
    c = voleith_gf8_circuit_new();
    a = voleith_gf8_add_witness(c);
    {
        gf8_wire_id ci = voleith_gf8_add_witness(c);
        gf8_wire_id a2 = voleith_gf8_add_square(c, a);
        voleith_gf8_assert_product(c, a2, ci, a);
        gf8_wire_id c2 = voleith_gf8_add_square(c, ci);
        voleith_gf8_assert_product(c, a, c2, ci);
    }
    lowers_to("sugar: INV -> witness + 2x ASSERT_PRODUCT gadget",
              HDR "WITNESS -> %a : byte\n"
                  "INV %a -> %ai\n",
              c);

    /* LINEAR_MAP with the squaring matrix canonicalizes to SQUARE. */
    c = voleith_gf8_circuit_new();
    a = voleith_gf8_add_witness(c);
    voleith_gf8_add_square(c, a);
    lowers_to("sugar: LINEAR_MAP squaring matrix -> SQUARE",
              HDR "WITNESS -> %a : byte\n"
                  "LINEAR_MAP [0x51 0xD0 0x22 0xF0 0x94 0x60 0x28 0xC0] "
                  "%a -> %c\n",
              c);

    /* The `: bit` refinement on a WITNESS is NOT free: it emits a booleanity
     * ASSERT_PRODUCT(a,a,a) alongside the WITNESS wire (lower_input_decl), so
     * it lowers to one WITNESS wire plus that constraint. */
    c = voleith_gf8_circuit_new();
    a = voleith_gf8_add_witness(c);
    voleith_gf8_assert_product(c, a, a, a);
    voleith_gf8_add_square(c, a);
    lowers_to("sugar: WITNESS : bit -> WITNESS + booleanity ASSERT_PRODUCT",
              HDR "WITNESS -> %a : bit\n"
                  "SQUARE %a -> %b\n",
              c);
}

/* ================================================================
 * Group C: every byte-literal encoding (hex digit case is an alias).
 * ================================================================ */

static void
test_literal_encodings(void)
{
    voleith_gf8_circuit_t *c;
    gf8_wire_id a;

    /* CONST: 0x1b and 0x1B are the same byte. */
    same_fp("lit: CONST hex case alias", HDR "CONST 0x1b -> %c\n",
            HDR "CONST 0x1B -> %c\n");

    /* ADD_CONST: mixed-case alias on a non-trivial byte. */
    same_fp("lit: ADD_CONST hex case alias",
            HDR "WITNESS -> %a : byte\n"
                "ADD_CONST %a 0xaB -> %c\n",
            HDR "WITNESS -> %a : byte\n"
                "ADD_CONST %a 0xAb -> %c\n");

    /* ASSERT_CONST: the 0xff / 0xFF boundary. */
    same_fp("lit: ASSERT_CONST 0xff boundary alias",
            HDR "WITNESS -> %a : byte\n"
                "ASSERT_CONST %a 0xff\n",
            HDR "WITNESS -> %a : byte\n"
                "ASSERT_CONST %a 0xFF\n");

    /* LINEAR_MAP matrix: an all-lowercase squaring matrix still
     * canonicalizes to SQUARE (and equals the C-built SQUARE). */
    c = voleith_gf8_circuit_new();
    a = voleith_gf8_add_witness(c);
    voleith_gf8_add_square(c, a);
    lowers_to("lit: LINEAR_MAP lowercase squaring matrix -> SQUARE",
              HDR "WITNESS -> %a : byte\n"
                  "LINEAR_MAP [0x51 0xd0 0x22 0xf0 0x94 0x60 0x28 0xc0] "
                  "%a -> %c\n",
              c);

    /* The 0x00 boundary lowers to CONST 0x00 regardless of spelling. */
    c = voleith_gf8_circuit_new();
    voleith_gf8_add_const(c, 0x00);
    lowers_to("lit: CONST 0x00 boundary", HDR "CONST 0x00 -> %z\n", c);
}

/* ================================================================
 * Group D: every region-marker placement (regions are a side table).
 * ================================================================ */

static void
test_region_placement(void)
{
    voleith_shipshape_parsed_t p;
    voleith_gf8_circuit_t *c;
    gf8_wire_id a;
    int r;

    /*
     * A user/<...> call and the equivalent inlined gates produce the identical
     * fingerprint: the region table (1 entry vs 0) does not enter the hash.
     */
    same_fp("region: subcircuit call hashes as inlined gates",
            HDR "subcircuit user/sq (%x : byte) -> (%y : byte) {\n"
                "SQUARE %x -> %y\n"
                "}\n"
                "WITNESS -> %a : byte\n"
                "user/sq(%a) -> %b\n",
            HDR "WITNESS -> %a : byte\n"
                "SQUARE %a -> %b\n");

    /* That call carries exactly one region; the inlined form carries none. */
    r = parse(HDR "subcircuit user/sq (%x : byte) -> (%y : byte) {\n"
                  "SQUARE %x -> %y\n"
                  "}\n"
                  "WITNESS -> %a : byte\n"
                  "user/sq(%a) -> %b\n",
              &p);
    check("region: call records one region", r == 0 && p.n_regions == 1);
    voleith_shipshape_parsed_free(&p);
    r = parse(HDR "WITNESS -> %a : byte\n"
                  "SQUARE %a -> %b\n",
              &p);
    check("region: inlined form records no region", r == 0 && p.n_regions == 0);
    voleith_shipshape_parsed_free(&p);

    /*
     * Region placement: a call at the FIRST body statement vs the LAST body
     * statement, with the same surrounding gate, lowers to the same wire
     * table only when the emission order is the same.  Here the call is the
     * first statement after the witness in both; the region's first_witness
     * tracks where its witnesses land, not where it sits in the hash.
     *
     * Build the reference: witness %a, then the sbox gadget (one inv
     * witness + two products), then a SQUARE of the original witness.
     */
    c = voleith_gf8_circuit_new();
    a = voleith_gf8_add_witness(c);
    (void)aes_gf8_sbox(c, a);
    voleith_gf8_add_square(c, a);
    lowers_to("region: registry call then gate lowers to C builder",
              HDR "WITNESS -> %a : byte\n"
                  "stdlib/crypto/aes/sbox(%a) -> %s\n"
                  "SQUARE %a -> %q\n",
              c);

    /* The region for that call spans its single inv witness (slot 1). */
    r = parse(HDR "WITNESS -> %a : byte\n"
                  "stdlib/crypto/aes/sbox(%a) -> %s\n"
                  "SQUARE %a -> %q\n",
              &p);
    check("region: registry region spans its inv witness",
          r == 0 && p.n_regions == 1 &&
              strcmp(p.regions[0].name, "stdlib/crypto/aes/sbox") == 0 &&
              p.regions[0].first_witness == 1 && p.regions[0].n_witness == 1);
    voleith_shipshape_parsed_free(&p);

    /*
     * Two calls in one file: regions are recorded in inlining order and the
     * fingerprint matches the hand-built two-sbox circuit.
     */
    c = voleith_gf8_circuit_new();
    a = voleith_gf8_add_witness(c);
    (void)aes_gf8_sbox(c, a);
    (void)aes_gf8_sbox(c, a);
    r = parse(HDR "WITNESS -> %a : byte\n"
                  "stdlib/crypto/aes/sbox(%a) -> %s1\n"
                  "stdlib/crypto/aes/sbox(%a) -> %s2\n",
              &p);
    check("region: two calls hash to two-sbox circuit",
          r == 0 && fp_eq(p.circuit, c));
    check("region: two calls record two regions in order",
          r == 0 && p.n_regions == 2 && p.regions[0].first_witness == 1 &&
              p.regions[1].first_witness == 2);
    voleith_shipshape_parsed_free(&p);
    voleith_gf8_circuit_free(c);
}

/* ================================================================
 * Group E: gate-ordering edge cases (§5.4 distinctness).
 * ================================================================ */

static void
test_gate_ordering(void)
{
    /*
     * Independent gates in different source order lower to differently
     * ordered wire tables and MUST hash differently: canonical order is
     * emission order, content-based re-sorting is forbidden (§5.4).
     */
    diff_fp("order: ADD-then-SQUARE differs from SQUARE-then-ADD",
            HDR "WITNESS -> %a : byte\n"
                "WITNESS -> %b : byte\n"
                "ADD %a %b -> %s\n"
                "SQUARE %a -> %q\n",
            HDR "WITNESS -> %a : byte\n"
                "WITNESS -> %b : byte\n"
                "SQUARE %a -> %q\n"
                "ADD %a %b -> %s\n");

    /* Declaration order matters too: swapping two witnesses reorders the
     * input slots and changes the hash. */
    diff_fp("order: swapped WITNESS declarations differ",
            HDR "WITNESS -> %a : byte\n"
                "WITNESS -> %b : byte\n"
                "MUL %a %b -> %p\n",
            HDR "WITNESS -> %b : byte\n"
                "WITNESS -> %a : byte\n"
                "MUL %a %b -> %p\n");

    /*
     * §5.4 redundant-constraint example: CONST 0x01 + ASSERT_BIT carries an
     * extra (always-true) PRODUCT constraint relative to CONST_BIT 1 and
     * hashes differently, even though both pin the wire to the bit 1.
     */
    diff_fp("order: CONST+ASSERT_BIT differs from CONST_BIT",
            HDR "CONST 0x01 -> %x\n"
                "ASSERT_BIT %x -> %y : bit\n",
            HDR "CONST_BIT 1 -> %x\n");
}

int
main(void)
{
    printf("test_shipshape_conformance: starting\n");
    test_idempotence();
    test_sugar_forms();
    test_literal_encodings();
    test_region_placement();
    test_gate_ordering();
    printf("test_shipshape_conformance: %d/%d passed\n", pass_count,
           test_count);
    return (pass_count == test_count) ? 0 : 1;
}
