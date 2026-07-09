/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * gen_rlnc_kat.c - RLNC encode known-answer-vector emitter (oracle tool).
 *
 * Generates byte-exact RLNC encode KATs for tests/test_erasure_rlnc.c using
 * GF-Complete (via Jerasure's galois layer) as an independent oracle for the
 * GF(2^16) arithmetic.  Run ONCE; redirect stdout to tests/rlnc_kat.inc and
 * check that in.  GF-Complete / Jerasure are NEVER linked into the library or
 * its tests (same posture as faest-ref): this tool only emits vectors.
 *
 * The oracle-able surface of RLNC is GF(2^16) linear algebra: a coded
 * symbol's payload is Y[i] = sum_j C[i][j] * X[j], for source symbols X and
 * a coefficient matrix C.  This tool fixes deterministic sources and
 * coefficients and computes the payloads, which voleith_rlnc_encode must
 * reproduce.  The RLNC wire format, recoding, and rank decode are our design
 * and are covered by self-consistency tests, not by this oracle.
 *
 * Matching our field:
 *   - GF(2^16), primitive polynomial 0x1100B (= our m16, and also
 *     GF-Complete's default w=16 polynomial), forced via galois_init_field +
 *     galois_change_technique.
 *   - GF_MULT_SHIFT (plain shift-and-reduce), not GF_MULT_DEFAULT: the same
 *     reason as gen_rs_kat, avoids the table-init path entirely.
 *
 * Build (static libs as built for gen_rs_kat; see that tool's README):
 *   gcc -O2 -I../../third_party/Jerasure/include \
 *       -I../../third_party/gf-complete/include \
 *       gen_rlnc_kat.c \
 *       ../../third_party/Jerasure/src/.libs/libJerasure.a \
 *       ../../third_party/gf-complete/src/.libs/libgf_complete.a \
 *       -o gen_rlnc_kat
 *   ./gen_rlnc_kat > ../../tests/rlnc_kat.inc
 */

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#include <gf_complete.h>

#include "galois.h"

#define GF_W 16
#define PRIM_POLY 0x1100B

/* One KAT case: num_coded coded symbols over a generation of k sources. */
struct kat_case {
    int k;
    int symbol_bytes; /* must be even; symbol = symbol_bytes/2 GF(2^16) elems */
    int num_coded;
};

static const struct kat_case cases[] = {
    {3, 8, 4},
    {4, 4, 5},
    {2, 6, 3},
};

/* Deterministic GF(2^16) source element for source j, element position s. */
static uint16_t
src_elem(int j, int s)
{
    uint32_t v = (uint32_t)(j * 2654435761u + s * 40503u + 0x1234u);
    return (uint16_t)(v >> 13);
}

/* Deterministic GF(2^16) coefficient for coded symbol i, source j. */
static uint16_t
coeff_elem(int i, int j)
{
    uint32_t v = (uint32_t)(i * 2246822519u + j * 3266489917u + 0x9E37u);
    uint16_t c = (uint16_t)(v >> 11);
    return c == 0 ? 1 : c; /* keep coefficients nonzero for a livelier KAT */
}

static void
emit_u16_bytes(const char *indent, const uint16_t *v, int n)
{
    int i;

    printf("%s", indent);
    for (i = 0; i < n; i++) {
        /* Little-endian byte pair per GF(2^16) element. */
        printf("0x%02X, 0x%02X,%s", v[i] & 0xff, (v[i] >> 8) & 0xff,
               ((i + 1) % 6 == 0) ? "\n" : " ");
    }
    if (n % 6 != 0)
        printf("\n");
}

static void
emit_u16(const char *indent, const uint16_t *v, int n)
{
    int i;

    printf("%s", indent);
    for (i = 0; i < n; i++)
        printf("0x%04X,%s", v[i], ((i + 1) % 8 == 0) ? "\n" : " ");
    if (n % 8 != 0)
        printf("\n");
}

static void
emit_case(const struct kat_case *c)
{
    uint16_t *sources, *coeffs, *coded;
    int k, sb, nc, elems, i, j, s;

    k = c->k;
    sb = c->symbol_bytes;
    nc = c->num_coded;
    elems = sb / 2;

    sources = malloc(sizeof(uint16_t) * (size_t)k * elems);
    coeffs = malloc(sizeof(uint16_t) * (size_t)nc * k);
    coded = malloc(sizeof(uint16_t) * (size_t)nc * elems);

    for (j = 0; j < k; j++)
        for (s = 0; s < elems; s++)
            sources[j * elems + s] = src_elem(j, s);
    for (i = 0; i < nc; i++)
        for (j = 0; j < k; j++)
            coeffs[i * k + j] = coeff_elem(i, j);

    /* Coded payloads: Y[i][s] = sum_j C[i][j] * X[j][s] over GF(2^16). */
    for (i = 0; i < nc; i++)
        for (s = 0; s < elems; s++) {
            int acc = 0;
            for (j = 0; j < k; j++)
                acc ^= galois_single_multiply(coeffs[i * k + j],
                                              sources[j * elems + s], GF_W);
            coded[i * elems + s] = (uint16_t)acc;
        }

    printf("    /* k=%d, symbol_bytes=%d, num_coded=%d; GF(2^16) poly 0x1100B "
           "*/\n",
           k, sb, nc);
    printf("    {\n");
    printf("        .k = %d, .symbol_bytes = %d, .num_coded = %d,\n", k, sb,
           nc);
    printf("        .sources = {\n");
    emit_u16_bytes("            ", sources, k * elems);
    printf("        },\n");
    printf("        .coeffs = {\n");
    emit_u16("            ", coeffs, nc * k);
    printf("        },\n");
    printf("        .coded = {\n");
    emit_u16_bytes("            ", coded, nc * elems);
    printf("        },\n");
    printf("    },\n");

    free(sources);
    free(coeffs);
    free(coded);
}

int
main(void)
{
    gf_t *gf;
    size_t i;

    /* Force GF(2^16) to poly 0x1100B with the shift multiplier (see header). */
    gf = galois_init_field(GF_W, GF_MULT_SHIFT, GF_REGION_DEFAULT,
                           GF_DIVIDE_DEFAULT, PRIM_POLY, 0, 0);
    galois_change_technique(gf, GF_W);

    printf("/* Auto-generated by tools/gen_rlnc_kat. Do not edit.\n");
    printf(" * Oracle: GF-Complete (via Jerasure galois layer), GF(2^16)\n");
    printf(" * poly 0x1100B; coded payload Y = C . X. */\n");
    printf("static const struct rlnc_kat rlnc_kats[] = {\n");
    for (i = 0; i < sizeof(cases) / sizeof(cases[0]); i++)
        emit_case(&cases[i]);
    printf("};\n");
    return 0;
}
