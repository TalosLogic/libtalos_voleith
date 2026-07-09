/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * gen_rs_kat.c - Reed-Solomon known-answer-vector emitter (oracle tool).
 *
 * Generates byte-exact RS KATs for tests/test_erasure_rs.c using Jerasure
 * 2.0 + GF-Complete as an independent oracle.  Run ONCE; redirect stdout to
 * tests/rs_kat.inc and check that in.  Jerasure/GF-Complete are NEVER linked
 * into the library or its tests (same posture as faest-ref): this tool only
 * emits vectors.
 *
 * Matching our construction exactly:
 *   - Field: GF(2^8) with primitive polynomial 0x11B (the AES/FAEST poly the
 *     library uses), forced via galois_init_field + galois_change_technique.
 *     Jerasure/GF-Complete default to 0x11d, which would NOT match, so this
 *     override is mandatory.
 *   - Construction: systematic Cauchy.  cauchy_xy_coding_matrix computes
 *     coding[i][j] = 1 / (X[i] ^ Y[j]); we pass X[i] = k + i (parity points)
 *     and Y[j] = j (data points), identical to voleith_ec_matrix_generator's
 *     CAUCHY case.  The full generator is [I_k ; coding]; encode is
 *     codeword = [data ; coding . data].
 *
 * Build (adjust paths to your third_party layout):
 *   gcc -O2 -I../../third_party/Jerasure/include \
 *       -I../../third_party/gf-complete/include \
 *       gen_rs_kat.c \
 *       ../../third_party/Jerasure/src/.libs/libJerasure.a \
 *       ../../third_party/gf-complete/src/.libs/libgf_complete.a \
 *       -o gen_rs_kat
 *   ./gen_rs_kat > ../../tests/rs_kat.inc
 */

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <gf_complete.h>

#include "cauchy.h"
#include "galois.h"

#define GF_W 8
#define PRIM_POLY 0x11B

/* One KAT case: a systematic (n, k) Cauchy RS over chunk_bytes-symbol chunks. */
struct kat_case {
    int n;
    int k;
    int chunk_bytes;
};

static const struct kat_case cases[] = {
    {6, 3, 4},
    {5, 2, 3},
    {7, 4, 8},
};

/* Deterministic message bytes so the emitter is reproducible. */
static uint8_t
msg_byte(int chunk, int pos)
{
    uint32_t s = (uint32_t)(chunk * 131 + pos * 7 + 0x5A) * 2654435761u;
    return (uint8_t)(s >> 24);
}

static void
emit_bytes(const char *indent, const uint8_t *p, int len)
{
    int i;

    printf("%s", indent);
    for (i = 0; i < len; i++)
        printf("0x%02X,%s", p[i], ((i + 1) % 12 == 0) ? "\n" : " ");
    if (len % 12 != 0)
        printf("\n");
}

static void
emit_case(const struct kat_case *c, int idx)
{
    uint8_t *message, *codeword;
    int *x, *y, *matrix;
    int i, j, p, m, k, cb, n;

    k = c->k;
    n = c->n;
    m = n - k;
    cb = c->chunk_bytes;

    /* Our exact Cauchy points: data Y[j] = j, parity X[i] = k + i. */
    x = malloc(sizeof(int) * m);
    y = malloc(sizeof(int) * k);
    for (i = 0; i < m; i++)
        x[i] = k + i;
    for (j = 0; j < k; j++)
        y[j] = j;
    matrix = cauchy_xy_coding_matrix(k, m, GF_W, x, y);

    message = malloc((size_t)k * cb);
    codeword = malloc((size_t)n * cb);

    /* Systematic: first k chunks are the data, passed through unchanged. */
    for (j = 0; j < k; j++)
        for (i = 0; i < cb; i++) {
            uint8_t b = msg_byte(j, i);
            message[j * cb + i] = b;
            codeword[j * cb + i] = b;
        }

    /*
     * Parity = coding-matrix . data, computed scalar (per byte) with
     * Jerasure's galois_single_multiply over the 0x11B field set above.
     * Scalar avoids GF-Complete's SIMD region-multiply alignment
     * requirements; for a once-run KAT emitter speed is irrelevant.
     */
    for (p = 0; p < m; p++)
        for (i = 0; i < cb; i++) {
            int acc = 0;
            for (j = 0; j < k; j++)
                acc ^= galois_single_multiply(matrix[p * k + j],
                                              message[j * cb + i], GF_W);
            codeword[(k + p) * cb + i] = (uint8_t)acc;
        }

    /* Emit a C initializer for one KAT. */
    printf("    /* (n=%d, k=%d, chunk_bytes=%d) systematic Cauchy, GF(2^8) "
           "poly 0x11B */\n",
           n, k, cb);
    printf("    {\n");
    printf("        .n = %d, .k = %d, .chunk_bytes = %d,\n", n, k, cb);
    printf("        .message = {\n");
    emit_bytes("            ", message, k * cb);
    printf("        },\n");
    printf("        .codeword = {\n");
    emit_bytes("            ", codeword, n * cb);
    printf("        },\n");
    printf("    },\n");

    free(x);
    free(y);
    free(matrix);
    free(message);
    free(codeword);
    (void)idx;
}

int
main(void)
{
    gf_t *gf;
    size_t i;

    /*
     * Force the global GF(2^8) to poly 0x11B so the matrix and encode match
     * the library's field (GF-Complete defaults to 0x11d otherwise).
     *
     * Use GF_MULT_SHIFT (plain shift-and-reduce), NOT GF_MULT_DEFAULT: the
     * default w=8 method builds a log/antilog table that assumes a
     * primitive polynomial, and 0x11B (irreducible but with a non-default
     * generator) makes gf_w8_table_init overrun its scratch and crash.
     * Shift-reduce works for any irreducible poly and matches how
     * core/field.c multiplies.
     */
    gf = galois_init_field(GF_W, GF_MULT_SHIFT, GF_REGION_DEFAULT,
                           GF_DIVIDE_DEFAULT, PRIM_POLY, 0, 0);
    galois_change_technique(gf, GF_W);

    printf("/* Auto-generated by tools/gen_rs_kat. Do not edit.\n");
    printf(" * Oracle: Jerasure 2.0 + GF-Complete, GF(2^8) poly 0x11B,\n");
    printf(" * systematic Cauchy (X[i]=k+i, Y[j]=j). */\n");
    printf("static const struct rs_kat rs_kats[] = {\n");
    for (i = 0; i < sizeof(cases) / sizeof(cases[0]); i++)
        emit_case(&cases[i], (int)i);
    printf("};\n");
    return 0;
}
