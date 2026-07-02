/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * test_shipshape_registry_grid.c - Registry equivalence tests, PARAMETRIC
 * entries (W5.2 of the implementation plan; ISA design §6;
 * STDLIB D1, §3.4).
 *
 * The same byte-for-byte table comparison as the FIXED-entry test, run over
 * the §3.4 parameter grid for each PARAMETRIC crypto-v1 entry (CMAC and the
 * four Grøstl variants).  For each grid point: parse a minimal `.ship` file
 * calling the entry with a length-n message, build the same circuit via the
 * hand-written C builder (mirroring inl_* in shipshape_registry_build.c),
 * and compare wire- and constraint-table counts, every entry in order, and
 * the 16-byte fingerprint.
 *
 * The grids below partition the frozen §3.4 grids (grid_cmac,
 * grid_grostl_256, grid_grostl_512 in shipshape_registry_build.c) into a
 * small set run by default and a large set run only with the `slow` label
 * (`<binary> slow`, registered as test_shipshape_registry_grid_slow):
 *
 *   cmac        {0,16,17}      + slow {40,64}
 *   grostl_256  {0,55,56}      + slow {64,119,120}
 *   grostl_512  {0,119,120}    + slow {200,247,248}
 *
 * The t27 / t59 truncated entries share their base builder (truncation is an
 * output-width concern only, not a wire- or constraint-table one), so their
 * circuits are compared against the same grostl256 / grostl512 builders.
 */

#include "aes_cmac_gf8_circuit.h"
#include "gf8_circuit.h"
#include "gf8_circuit_fingerprint.h"
#include "grostl_gf8_circuit.h"
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
 * Parse `src`, deep-compare against `ref` (counts, wires, constraints,
 * fingerprint) under the label `name`, and free both.
 */
static void
compare_entry(const char *name, const char *src, voleith_gf8_circuit_t *ref)
{
    voleith_shipshape_parsed_t p;
    char label[128];
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

static void
add_witnesses(voleith_gf8_circuit_t *c, gf8_wire_id *out, size_t n)
{
    for (size_t i = 0; i < n; i++)
        out[i] = voleith_gf8_add_witness(c);
}

/* CMAC over a length-n message with a key_bytes-byte key. */
static void
grid_cmac(const char *fqn, size_t key_bytes, const uint32_t *grid, size_t ng)
{
    gf8_wire_id w[32 + 64];
    gf8_wire_id tag[16];
    voleith_gf8_circuit_t *c;
    char src[256];
    char name[96];

    for (size_t g = 0; g < ng; g++) {
        uint32_t n = grid[g];

        c = voleith_gf8_circuit_new();
        add_witnesses(c, w, key_bytes + n);
        aes_cmac_gf8_circuit(c, w, key_bytes, n > 0 ? w + key_bytes : NULL, n,
                             tag);

        snprintf(src, sizeof(src),
                 HDR "WITNESS -> %%key : byte[%zu]\n"
                     "WITNESS -> %%msg : byte[%u]\n"
                     "%s(%%key, %%msg) -> %%tag\n",
                 key_bytes, n, fqn);
        snprintf(name, sizeof(name), "%s n=%u", fqn, n);
        compare_entry(name, src, c);
    }
}

/* Grøstl-256 (and its t27 truncation) over a length-n message. */
static void
grid_grostl256(const char *fqn, const uint32_t *grid, size_t ng)
{
    gf8_wire_id w[256];
    gf8_wire_id out[32];
    voleith_gf8_circuit_t *c;
    char src[256];
    char name[96];

    for (size_t g = 0; g < ng; g++) {
        uint32_t n = grid[g];

        c = voleith_gf8_circuit_new();
        add_witnesses(c, w, n);
        grostl256_gf8_circuit(c, n > 0 ? w : NULL, n, out);

        snprintf(src, sizeof(src),
                 HDR "WITNESS -> %%msg : byte[%u]\n"
                     "%s(%%msg) -> %%h\n",
                 n, fqn);
        snprintf(name, sizeof(name), "%s n=%u", fqn, n);
        compare_entry(name, src, c);
    }
}

/* Grøstl-512 (and its t59 truncation) over a length-n message. */
static void
grid_grostl512(const char *fqn, const uint32_t *grid, size_t ng)
{
    gf8_wire_id w[256];
    gf8_wire_id out[64];
    voleith_gf8_circuit_t *c;
    char src[256];
    char name[96];

    for (size_t g = 0; g < ng; g++) {
        uint32_t n = grid[g];

        c = voleith_gf8_circuit_new();
        add_witnesses(c, w, n);
        grostl512_gf8_circuit(c, n > 0 ? w : NULL, n, out);

        snprintf(src, sizeof(src),
                 HDR "WITNESS -> %%msg : byte[%u]\n"
                     "%s(%%msg) -> %%h\n",
                 n, fqn);
        snprintf(name, sizeof(name), "%s n=%u", fqn, n);
        compare_entry(name, src, c);
    }
}

/* The §3.4 grids, split into a default subset and a slow (large) subset. */
static const uint32_t cmac_small[] = {0, 16, 17};
static const uint32_t cmac_slow[] = {40, 64};
static const uint32_t g256_small[] = {0, 55, 56};
static const uint32_t g256_slow[] = {64, 119, 120};
static const uint32_t g512_small[] = {0, 119, 120};
static const uint32_t g512_slow[] = {200, 247, 248};

#define LEN(a) (sizeof(a) / sizeof((a)[0]))

int
main(int argc, char **argv)
{
    int slow = argc > 1 && strcmp(argv[1], "slow") == 0;

    printf("test_shipshape_registry_grid: starting (%s grid)\n",
           slow ? "slow" : "default");

    if (slow) {
        grid_cmac("stdlib/crypto/cmac/aes_128", 16, cmac_slow, LEN(cmac_slow));
        grid_cmac("stdlib/crypto/cmac/aes_256", 32, cmac_slow, LEN(cmac_slow));
        grid_grostl256("stdlib/crypto/grostl/hash_256", g256_slow,
                       LEN(g256_slow));
        grid_grostl256("stdlib/crypto/grostl/hash_256_t27", g256_slow,
                       LEN(g256_slow));
        grid_grostl512("stdlib/crypto/grostl/hash_512", g512_slow,
                       LEN(g512_slow));
        grid_grostl512("stdlib/crypto/grostl/hash_512_t59", g512_slow,
                       LEN(g512_slow));
    } else {
        grid_cmac("stdlib/crypto/cmac/aes_128", 16, cmac_small,
                  LEN(cmac_small));
        grid_cmac("stdlib/crypto/cmac/aes_256", 32, cmac_small,
                  LEN(cmac_small));
        grid_grostl256("stdlib/crypto/grostl/hash_256", g256_small,
                       LEN(g256_small));
        grid_grostl256("stdlib/crypto/grostl/hash_256_t27", g256_small,
                       LEN(g256_small));
        grid_grostl512("stdlib/crypto/grostl/hash_512", g512_small,
                       LEN(g512_small));
        grid_grostl512("stdlib/crypto/grostl/hash_512_t59", g512_small,
                       LEN(g512_small));
    }

    printf("test_shipshape_registry_grid: %d/%d passed\n", pass_count,
           test_count);
    return (pass_count == test_count) ? 0 : 1;
}
