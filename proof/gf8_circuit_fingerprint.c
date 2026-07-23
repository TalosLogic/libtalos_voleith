/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * gf8_circuit_fingerprint.c - Compute the 16-byte SHAKE-128 fingerprint over
 *                             a GF(2^8) element-level circuit.
 *
 * See gf8_circuit_fingerprint.h for the canonical serialization spec.
 */

#include "gf8_circuit_fingerprint.h"

#include "../core/hash.h"
#include "../core/util.h"

#include <string.h>

/* Returns the underlying absorb status (0, or VOLEITH_HASH_ERR_FINALIZED). */
static int
absorb_u8(voleith_hash_ctx_t *ctx, uint8_t v)
{
    return voleith_shake128_absorb(ctx, &v, 1);
}

/*
 * Normalize an operand: GF8_WIRE_ID_INVALID maps to 0 on the wire so the
 * fingerprint does not depend on which sentinel a producer uses for
 * "unused".  Valid wire ids pass through unchanged.
 */
static uint32_t
normalize_operand(gf8_wire_id w)
{
    return (w == GF8_WIRE_ID_INVALID) ? 0u : (uint32_t)w;
}

int
voleith_gf8_circuit_fingerprint(
    const voleith_gf8_circuit_t *circuit,
    uint8_t out[VOLEITH_GF8_CIRCUIT_FINGERPRINT_BYTES])
{
    voleith_hash_ctx_t ctx;
    const gf8_wire_entry_t *wires;
    const gf8_constraint_entry_t *constraints;
    size_t n_wires, n_constraints, i;
    int rc = 0;
    /*
     * Domain tag plus the spec's 0x00 terminator.  sizeof() includes
     * the compiler-appended implicit '\0' on the string literal, so
     * subtract 1 to absorb only the 25-byte tag + the explicit 0x00.
     */
    static const uint8_t domain_tag[] =
        VOLEITH_GF8_CIRCUIT_FINGERPRINT_DOMAIN_TAG "\x00";

    if (circuit == NULL || out == NULL)
        return -1;

    n_wires = voleith_gf8_circuit_wire_count(circuit);
    n_constraints = voleith_gf8_circuit_constraint_count(circuit);
    wires = voleith_gf8_circuit_wires(circuit);
    constraints = voleith_gf8_circuit_constraints(circuit);

    voleith_shake128_init(&ctx);

    rc |= voleith_shake128_absorb(&ctx, domain_tag, sizeof(domain_tag) - 1);

    rc |= voleith_shake128_absorb_u32_le(&ctx, (uint32_t)n_wires);
    rc |= voleith_shake128_absorb_u32_le(
        &ctx, (uint32_t)voleith_gf8_circuit_witness_count(circuit));
    rc |= voleith_shake128_absorb_u32_le(
        &ctx, (uint32_t)voleith_gf8_circuit_instance_count(circuit));
    rc |= voleith_shake128_absorb_u32_le(
        &ctx, (uint32_t)voleith_gf8_circuit_mul_count(circuit));
    rc |= voleith_shake128_absorb_u32_le(&ctx, (uint32_t)n_constraints);

    for (i = 0; i < n_wires; i++) {
        rc |= absorb_u8(&ctx, (uint8_t)wires[i].kind);
        rc |=
            voleith_shake128_absorb_u32_le(&ctx, normalize_operand(wires[i].a));
        rc |=
            voleith_shake128_absorb_u32_le(&ctx, normalize_operand(wires[i].b));
        /*
         * const_val is meaningful only for CONST and XOR_CONST; the
         * builder leaves it at 0 for other kinds, so absorbing it
         * unconditionally is safe and keeps the encoding fixed-width.
         */
        rc |= absorb_u8(&ctx, wires[i].const_val);
        /*
         * matrix is populated only for LINEAR_MAP; zero-filled for
         * other kinds.  Always absorb the full 8 bytes for fixed-width
         * encoding.
         */
        rc |= voleith_shake128_absorb(&ctx, wires[i].matrix,
                                      sizeof(wires[i].matrix));
    }

    for (i = 0; i < n_constraints; i++) {
        rc |= absorb_u8(&ctx, (uint8_t)constraints[i].kind);
        rc |= voleith_shake128_absorb_u32_le(
            &ctx, normalize_operand(constraints[i].a));
        rc |= voleith_shake128_absorb_u32_le(
            &ctx, normalize_operand(constraints[i].b));
        rc |= voleith_shake128_absorb_u32_le(
            &ctx, normalize_operand(constraints[i].c));
    }

    /* nonzero only on absorb-after-squeeze (unreachable here, single squeeze
     * below); propagated defensively rather than silently dropped. */
    if (rc != 0) {
        voleith_hash_ctx_clear(&ctx);
        return -1;
    }

    voleith_shake128_squeeze(&ctx, out, VOLEITH_GF8_CIRCUIT_FINGERPRINT_BYTES);
    voleith_hash_ctx_clear(&ctx);

    return 0;
}
