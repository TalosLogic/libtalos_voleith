/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * rlnc_confidential_gf16_circuit.c - GF(2^16) confidential-RLNC proof wrapper
 * (P7 T7.6).  See rlnc_confidential_gf16_circuit.h for the relation and cost.
 */

#include "rlnc_confidential_gf16_circuit.h"

#include "permutation_gf16_circuit.h" /* T7.5 routing gadget */
#include "rlnc_gf16_cert_circuit.h"   /* T7.1 decodability certificate */
#include "matrix.h"                   /* voleith_ec_matrix_* for Linv */
#include "erasure.h"                  /* VOLEITH_EC_* */
#include "field16.h"                  /* voleith_gf16_mul */
#include "util.h"                     /* voleith_secure_zero */

#include <stdlib.h>
#include <string.h>

size_t
voleith_rlnc_confidential_gf16_n_ctrl(size_t m, size_t l)
{
    return voleith_perm_gf16_n_switches(m * l *
                                        VOLEITH_RLNC_CONFIDENTIAL_GF16_T);
}

/* ========================================================================
 * Free GF(2)-linear maps
 * ======================================================================== */

/* result = k * wire in GF(2^16), as a free LINEAR_MAP gate.  Column j of the
 * map is k * x^j; bit i of that product sets row i, bit j of M. */
static gf16_wire_id
const_mul(voleith_gf16_circuit_t *c, gf16_wire_id w, voleith_gf16_t k)
{
    uint16_t M[16];
    for (int i = 0; i < 16; i++)
        M[i] = 0;
    for (int j = 0; j < 16; j++) {
        voleith_gf16_t t = voleith_gf16_mul(k, (voleith_gf16_t)(1u << j));
        for (int i = 0; i < 16; i++)
            if ((t >> i) & 1u)
                M[i] |= (uint16_t)(1u << j);
    }
    return voleith_gf16_add_linear_map(c, w, M);
}

/* High byte of a GF(2^16) wire as a byte-valued wire (bits 8..15 -> 0..7). */
static gf16_wire_id
split_hi(voleith_gf16_circuit_t *c, gf16_wire_id w)
{
    uint16_t M[16];
    for (int i = 0; i < 16; i++)
        M[i] = (i < 8) ? (uint16_t)(1u << (i + 8)) : 0;
    return voleith_gf16_add_linear_map(c, w, M);
}

/* Low byte of a GF(2^16) wire as a byte-valued wire (bits 0..7 kept). */
static gf16_wire_id
split_lo(voleith_gf16_circuit_t *c, gf16_wire_id w)
{
    uint16_t M[16];
    for (int i = 0; i < 16; i++)
        M[i] = (i < 8) ? (uint16_t)(1u << i) : 0;
    return voleith_gf16_add_linear_map(c, w, M);
}

/* Join two byte sub-symbols: (hi << 8) | lo, high-part-first. */
static gf16_wire_id
join_bytes(voleith_gf16_circuit_t *c, gf16_wire_id hi, gf16_wire_id lo)
{
    uint16_t M[16];
    for (int i = 0; i < 16; i++)
        M[i] =
            (i >= 8) ? (uint16_t)(1u << (i - 8)) : 0; /* shift low byte up 8 */
    gf16_wire_id hi_shifted = voleith_gf16_add_linear_map(c, hi, M);
    return voleith_gf16_add_xor(c, hi_shifted, lo);
}

/* ========================================================================
 * Circuit
 * ======================================================================== */

void
voleith_rlnc_confidential_gf16_circuit(voleith_gf16_circuit_t *c,
                                       const voleith_gf16_t *source,
                                       const gf16_wire_id *coeff_wires,
                                       const gf16_wire_id *coeff_inv_wires,
                                       const gf16_wire_id *ctrl_wires,
                                       const gf16_wire_id *data_wires, size_t m,
                                       size_t l)
{
    if (!c || !source || !coeff_wires || !ctrl_wires || !data_wires || m == 0 ||
        l == 0)
        return;

    unsigned t = VOLEITH_RLNC_CONFIDENTIAL_GF16_T;
    size_t n = m * l * t;
    size_t lt = l * t;

    gf16_wire_id *grid = calloc(n, sizeof(gf16_wire_id));
    gf16_wire_id *permuted = calloc(n, sizeof(gf16_wire_id));
    if (!grid || !permuted) {
        free(grid);
        free(permuted);
        return; /* allocation failure -> circuit_ok() stays false downstream */
    }

    /*
     * 1. Encode C = L . P (free): C[r][e] = XOR_j L[r][j] * P[j][e].  Each P
     *    element is a public constant, so the product is a free const-multiply
     *    of the secret coefficient wire.  2. Split C[r][e] into its two byte
     *    sub-symbols (free), high-part-first, into the grid.
     */
    for (size_t r = 0; r < m; r++) {
        for (size_t e = 0; e < l; e++) {
            gf16_wire_id acc = GF16_WIRE_ID_INVALID;
            for (size_t j = 0; j < m; j++) {
                voleith_gf16_t pk = source[j * l + e];
                if (pk == 0)
                    continue; /* 0 * anything contributes nothing */
                gf16_wire_id term = const_mul(c, coeff_wires[r * m + j], pk);
                acc = (acc == GF16_WIRE_ID_INVALID)
                          ? term
                          : voleith_gf16_add_xor(c, acc, term);
            }
            if (acc == GF16_WIRE_ID_INVALID)
                acc =
                    voleith_gf16_add_const(c, 0); /* whole row of P was zero */

            grid[r * lt + e * t + 0] = split_hi(c, acc);
            grid[r * lt + e * t + 1] = split_lo(c, acc);
        }
    }

    /* 3. Secret partial permutation of the grid (the only costly stage). */
    voleith_perm_gf16_circuit(c, grid, ctrl_wires, permuted, n);

    /* 4. Join the permuted grid (free) and 5. assert it equals the public
     *    coded packet. */
    for (size_t r = 0; r < m; r++) {
        for (size_t e = 0; e < l; e++) {
            gf16_wire_id hi = permuted[r * lt + e * t + 0];
            gf16_wire_id lo = permuted[r * lt + e * t + 1];
            gf16_wire_id joined = join_bytes(c, hi, lo);
            voleith_gf16_assert_equal(c, joined, data_wires[r * l + e]);
        }
    }

    /* Optional: prove L is full rank (decodable) via L . Linv = I. */
    if (coeff_inv_wires)
        voleith_rlnc_gf16_cert_circuit(c, coeff_wires, coeff_inv_wires, m);

    free(grid);
    free(permuted);
}

int
voleith_rlnc_confidential_gf16_build_witness(const voleith_gf16_t *L, size_t m,
                                             size_t l, const size_t *perm,
                                             int with_cert, voleith_gf16_t *out)
{
    if (!L || !perm || !out || m == 0 || l == 0)
        return VOLEITH_EC_ERR_PARAM;

    size_t n = m * l * VOLEITH_RLNC_CONFIDENTIAL_GF16_T;
    size_t pos = 0;

    /* 1. L (row-major). */
    for (size_t i = 0; i < m * m; i++)
        out[pos++] = L[i];

    /* 2. Linv (row-major), only with the certificate. */
    if (with_cert) {
        voleith_ec_matrix_t a = {
            .e = (uint16_t *)(uintptr_t)L,
            .rows = m,
            .cols = m,
            .field = VOLEITH_EC_FIELD_GF16,
        };
        voleith_ec_matrix_t inv;
        memset(&inv, 0, sizeof(inv));
        /* L is secret: constant-time inverse (M-3 posture for the proving
         * path), and zero L^{-1} on release. */
        int rc = voleith_ec_matrix_invert_ct(&a, &inv);
        if (rc != 0)
            return rc; /* VOLEITH_EC_ERR_SINGULAR if L has no inverse */
        for (size_t i = 0; i < m * m; i++)
            out[pos++] = (voleith_gf16_t)inv.e[i];
        voleith_ec_matrix_free_secure(&inv);
    }

    /* 3. Permutation control bits. */
    size_t s = voleith_perm_gf16_n_switches(n);
    uint16_t *bits = calloc(s ? s : 1, sizeof(uint16_t));
    if (!bits)
        return VOLEITH_EC_ERR_NOMEM;
    if (voleith_perm_gf16_route(perm, n, bits) != 0) {
        voleith_secure_zero(bits, (s ? s : 1) * sizeof(uint16_t));
        free(bits);
        return VOLEITH_EC_ERR_PARAM; /* not a valid permutation */
    }
    for (size_t i = 0; i < s; i++)
        out[pos++] = (voleith_gf16_t)bits[i];
    /* Control bits are secret witness material; wipe the scratch copy. */
    voleith_secure_zero(bits, (s ? s : 1) * sizeof(uint16_t));
    free(bits);

    return 0;
}
