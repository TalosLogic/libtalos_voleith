/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * rlnc_gf16_cert_circuit.c - GF(2^16) RLNC decodability / sufficiency
 * certificate circuit (P7 T7.1).
 *
 * See rlnc_gf16_cert_circuit.h for the relation and cost model.
 */

#include "rlnc_gf16_cert_circuit.h"

#include "matrix.h"  /* voleith_ec_matrix_*, VOLEITH_EC_ERR_* */
#include "erasure.h" /* VOLEITH_EC_FIELD_GF16, error codes */

#include <stdlib.h>
#include <string.h>

void
voleith_rlnc_gf16_cert_circuit(voleith_gf16_circuit_t *c,
                               const gf16_wire_id *c_wires,
                               const gf16_wire_id *cinv_wires, size_t m)
{
    if (!c || !c_wires || !cinv_wires || m == 0)
        return;

    /*
     * (C . Cinv)[i][j] = sum_{l} C[i][l] * Cinv[l][j].  Each scalar product is
     * a witness-by-witness GF(2^16) multiply (one add_mul / VOLE slot); the
     * sum is free XOR.  The result is asserted equal to the identity entry,
     * 1 on the diagonal and 0 off it.
     */
    gf16_wire_id zero = voleith_gf16_add_const(c, 0);
    gf16_wire_id one = voleith_gf16_add_const(c, 1);

    for (size_t i = 0; i < m; i++) {
        for (size_t j = 0; j < m; j++) {
            gf16_wire_id acc = GF16_WIRE_ID_INVALID;

            for (size_t l = 0; l < m; l++) {
                gf16_wire_id prod = voleith_gf16_add_mul(c, c_wires[i * m + l],
                                                         cinv_wires[l * m + j]);
                acc = (acc == GF16_WIRE_ID_INVALID)
                          ? prod
                          : voleith_gf16_add_xor(c, acc, prod);
            }

            /* m == 0 is rejected above, so acc is always assigned here. */
            voleith_gf16_assert_equal(c, acc, (i == j) ? one : zero);
        }
    }
}

int
voleith_rlnc_gf16_cert_build_witness(const voleith_gf16_t *c_mat, size_t m,
                                     voleith_gf16_t *out)
{
    if (!c_mat || !out || m == 0)
        return VOLEITH_EC_ERR_PARAM;

    /*
     * Wrap the caller's row-major C in an ec_matrix descriptor and invert it
     * with the validated plaintext Gauss-Jordan routine.  Cast away const on
     * the element pointer: voleith_ec_matrix_invert() does not modify its
     * input (documented in matrix.h), and the descriptor is local.
     */
    voleith_ec_matrix_t a = {
        .e = (uint16_t *)(uintptr_t)c_mat,
        .rows = m,
        .cols = m,
        .field = VOLEITH_EC_FIELD_GF16,
    };
    voleith_ec_matrix_t inv;
    memset(&inv, 0, sizeof(inv));

    int rc = voleith_ec_matrix_invert(&a, &inv);
    if (rc != 0)
        return rc; /* VOLEITH_EC_ERR_SINGULAR for a non-full-rank C. */

    /* Witness layout: C (row-major) then Cinv (row-major). */
    for (size_t idx = 0; idx < m * m; idx++)
        out[idx] = c_mat[idx];
    for (size_t idx = 0; idx < m * m; idx++)
        out[m * m + idx] = (voleith_gf16_t)inv.e[idx];

    voleith_ec_matrix_free(&inv);
    return 0;
}
