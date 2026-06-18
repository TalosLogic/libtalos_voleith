/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * test_shipshape_registry_equiv.c - Registry equivalence tests, FIXED entries
 * (W5.1 of docs/SHIPSHAPE_IMPLEMENTATION_PLAN.md; ISA design §6 validation
 * plan; STDLIB D2, D3, §2).
 *
 * For each crypto-v1 FIXED Tier 2a entry, a minimal `.ship` file calling the
 * entry is parsed and its lowered circuit is compared BYTE-FOR-BYTE against
 * the same circuit built by the hand-written C builder: wire-table and
 * constraint-table counts, then every entry's kind / inputs / constant /
 * matrix in order, then the 16-byte fingerprint.  This is the structural
 * (not merely hash) half of the §6 plan; test_shipshape_parser.c already
 * covers fingerprint equality, and this pins the tables that back it.
 *
 * The seven FIXED entries are the AES family (sbox, keyschedule_128/256,
 * encrypt_rounds_128/256, encrypt_128/256).  The PARAMETRIC entries (CMAC,
 * Grøstl) and their grids are W5.2.
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

#define HDR                                                                    \
    ".shipshape 1\n"                                                           \
    "field GF(2^8) irreducible 0x11B\n"                                        \
    "stdlib crypto-v1\n"

/* Equal wire-, witness-, instance-, gate-, mul-, and constraint-counts. */
static int
counts_equal(const voleith_gf8_circuit_t *a, const voleith_gf8_circuit_t *b)
{
    return voleith_gf8_circuit_wire_count(a) ==
               voleith_gf8_circuit_wire_count(b) &&
           voleith_gf8_circuit_witness_count(a) ==
               voleith_gf8_circuit_witness_count(b) &&
           voleith_gf8_circuit_instance_count(a) ==
               voleith_gf8_circuit_instance_count(b) &&
           voleith_gf8_circuit_gate_count(a) ==
               voleith_gf8_circuit_gate_count(b) &&
           voleith_gf8_circuit_mul_count(a) ==
               voleith_gf8_circuit_mul_count(b) &&
           voleith_gf8_circuit_constraint_count(a) ==
               voleith_gf8_circuit_constraint_count(b) &&
           voleith_gf8_circuit_assert_product_count(a) ==
               voleith_gf8_circuit_assert_product_count(b);
}

/* Every wire entry equal in order: kind, both inputs, constant, matrix. */
static int
wires_equal(const voleith_gf8_circuit_t *a, const voleith_gf8_circuit_t *b)
{
    const gf8_wire_entry_t *wa = voleith_gf8_circuit_wires(a);
    const gf8_wire_entry_t *wb = voleith_gf8_circuit_wires(b);
    size_t n = voleith_gf8_circuit_wire_count(a);

    if (n != voleith_gf8_circuit_wire_count(b))
        return 0;
    for (size_t i = 0; i < n; i++) {
        if (wa[i].kind != wb[i].kind || wa[i].a != wb[i].a ||
            wa[i].b != wb[i].b || wa[i].const_val != wb[i].const_val ||
            memcmp(wa[i].matrix, wb[i].matrix, sizeof(wa[i].matrix)) != 0)
            return 0;
    }
    return 1;
}

/* Every constraint entry equal in order: kind, a, b, c. */
static int
constraints_equal(const voleith_gf8_circuit_t *a,
                  const voleith_gf8_circuit_t *b)
{
    const gf8_constraint_entry_t *ca = voleith_gf8_circuit_constraints(a);
    const gf8_constraint_entry_t *cb = voleith_gf8_circuit_constraints(b);
    size_t n = voleith_gf8_circuit_constraint_count(a);

    if (n != voleith_gf8_circuit_constraint_count(b))
        return 0;
    for (size_t i = 0; i < n; i++) {
        if (ca[i].kind != cb[i].kind || ca[i].a != cb[i].a ||
            ca[i].b != cb[i].b || ca[i].c != cb[i].c)
            return 0;
    }
    return 1;
}

static int
fp_equal(const voleith_gf8_circuit_t *a, const voleith_gf8_circuit_t *b)
{
    uint8_t fa[VOLEITH_GF8_CIRCUIT_FINGERPRINT_BYTES];
    uint8_t fb[VOLEITH_GF8_CIRCUIT_FINGERPRINT_BYTES];

    if (voleith_gf8_circuit_fingerprint(a, fa) != 0 ||
        voleith_gf8_circuit_fingerprint(b, fb) != 0)
        return 0;
    return memcmp(fa, fb, sizeof(fa)) == 0;
}

/*
 * Parse `src`, then deep-compare its circuit against `ref` (the C builder's
 * output): counts, wire table, constraint table, and fingerprint, each as a
 * separate named check.  Frees both the parsed result and `ref`.
 */
static void
compare_entry(const char *name, const char *src, voleith_gf8_circuit_t *ref)
{
    voleith_shipshape_parsed_t p;
    char label[96];
    int r;

    r = voleith_shipshape_parse_buffer(&p, src, 0, NULL);

    snprintf(label, sizeof(label), "%s: parses", name);
    check(label, r == 0 && p.circuit != NULL);

    if (r == 0 && p.circuit != NULL) {
        snprintf(label, sizeof(label), "%s: counts", name);
        check(label, counts_equal(p.circuit, ref));
        snprintf(label, sizeof(label), "%s: wire table", name);
        check(label, wires_equal(p.circuit, ref));
        snprintf(label, sizeof(label), "%s: constraint table", name);
        check(label, constraints_equal(p.circuit, ref));
        snprintf(label, sizeof(label), "%s: fingerprint", name);
        check(label, fp_equal(p.circuit, ref));
    }

    voleith_shipshape_parsed_free(&p);
    voleith_gf8_circuit_free(ref);
}

/* Append `n` witness wires to `c`, writing their ids into `out`. */
static void
add_witnesses(voleith_gf8_circuit_t *c, gf8_wire_id *out, size_t n)
{
    for (size_t i = 0; i < n; i++)
        out[i] = voleith_gf8_add_witness(c);
}

static void
test_fixed_entries(void)
{
    voleith_gf8_circuit_t *c;
    gf8_wire_id key[32], pt[16], rkflat[240], ct[16];
    gf8_wire_id rk128[11][16], rk256[15][16];
    gf8_wire_id a;

    /* sbox: one input wire. */
    c = voleith_gf8_circuit_new();
    a = voleith_gf8_add_witness(c);
    (void)aes_gf8_sbox(c, a);
    compare_entry("sbox",
                  HDR "WITNESS -> %x : byte\n"
                      "stdlib/crypto/aes/sbox(%x) -> %y\n",
                  c);

    /* keyschedule_128: 16-byte key. */
    c = voleith_gf8_circuit_new();
    add_witnesses(c, key, 16);
    aes128_gf8_expand_key(c, key, rk128);
    compare_entry("keyschedule_128",
                  HDR "WITNESS -> %key : byte[16]\n"
                      "stdlib/crypto/aes/keyschedule_128(%key) -> %rk\n",
                  c);

    /* encrypt_rounds_128: 176-byte round keys then 16-byte plaintext (the
     * declaration order the parser flattens). */
    c = voleith_gf8_circuit_new();
    add_witnesses(c, rkflat, 176);
    add_witnesses(c, pt, 16);
    memcpy(rk128, rkflat, sizeof(rk128)); /* round-major flat -> rk[r][b] */
    aes128_gf8_encrypt_rk(c, rk128, pt, ct);
    compare_entry("encrypt_rounds_128",
                  HDR "WITNESS -> %rk : byte[176]\n"
                      "WITNESS -> %pt : byte[16]\n"
                      "stdlib/crypto/aes/encrypt_rounds_128(%rk, %pt) -> %ct\n",
                  c);

    /* encrypt_128: 16-byte key then 16-byte plaintext. */
    c = voleith_gf8_circuit_new();
    add_witnesses(c, key, 16);
    add_witnesses(c, pt, 16);
    aes128_gf8_circuit(c, key, pt, ct);
    compare_entry("encrypt_128",
                  HDR "WITNESS -> %key : byte[16]\n"
                      "WITNESS -> %pt : byte[16]\n"
                      "stdlib/crypto/aes/encrypt_128(%key, %pt) -> %ct\n",
                  c);

    /* keyschedule_256: 32-byte key. */
    c = voleith_gf8_circuit_new();
    add_witnesses(c, key, 32);
    aes256_gf8_expand_key(c, key, rk256);
    compare_entry("keyschedule_256",
                  HDR "WITNESS -> %key : byte[32]\n"
                      "stdlib/crypto/aes/keyschedule_256(%key) -> %rk\n",
                  c);

    /* encrypt_rounds_256: 240-byte round keys then 16-byte plaintext. */
    c = voleith_gf8_circuit_new();
    add_witnesses(c, rkflat, 240);
    add_witnesses(c, pt, 16);
    memcpy(rk256, rkflat, sizeof(rk256));
    aes256_gf8_encrypt_rk(c, rk256, pt, ct);
    compare_entry("encrypt_rounds_256",
                  HDR "WITNESS -> %rk : byte[240]\n"
                      "WITNESS -> %pt : byte[16]\n"
                      "stdlib/crypto/aes/encrypt_rounds_256(%rk, %pt) -> %ct\n",
                  c);

    /* encrypt_256: 32-byte key then 16-byte plaintext. */
    c = voleith_gf8_circuit_new();
    add_witnesses(c, key, 32);
    add_witnesses(c, pt, 16);
    aes256_gf8_circuit(c, key, pt, ct);
    compare_entry("encrypt_256",
                  HDR "WITNESS -> %key : byte[32]\n"
                      "WITNESS -> %pt : byte[16]\n"
                      "stdlib/crypto/aes/encrypt_256(%key, %pt) -> %ct\n",
                  c);
}

int
main(void)
{
    printf("test_shipshape_registry_equiv: starting\n");
    test_fixed_entries();
    printf("test_shipshape_registry_equiv: %d/%d passed\n", pass_count,
           test_count);
    return (pass_count == test_count) ? 0 : 1;
}
