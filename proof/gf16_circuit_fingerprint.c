/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * gf16_circuit_fingerprint.c - Compute the 16-byte SHAKE-128 fingerprint over
 *                              a GF(2^16) element-level circuit.
 *
 * See gf16_circuit_fingerprint.h for the canonical serialization spec.
 */

#include "gf16_circuit_fingerprint.h"

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
 * Normalize an operand: GF16_WIRE_ID_INVALID maps to 0 on the wire so the
 * fingerprint does not depend on which sentinel a producer uses for "unused".
 */
static uint32_t
normalize_operand(gf16_wire_id w)
{
    return (w == GF16_WIRE_ID_INVALID) ? 0u : (uint32_t)w;
}

int
voleith_gf16_circuit_fingerprint(
    const voleith_gf16_circuit_t *circuit,
    uint8_t out[VOLEITH_GF16_CIRCUIT_FINGERPRINT_BYTES])
{
    voleith_hash_ctx_t ctx;
    const gf16_wire_entry_t *wires;
    const gf16_constraint_entry_t *constraints;
    size_t n_wires, n_constraints, i;
    int rc = 0;
    /*
     * Domain tag plus the spec's 0x00 terminator.  sizeof() includes the
     * compiler-appended implicit '\0', so subtract 1 to absorb only the
     * 26-byte tag + the explicit 0x00.
     */
    static const uint8_t domain_tag[] =
        VOLEITH_GF16_CIRCUIT_FINGERPRINT_DOMAIN_TAG "\x00";

    if (circuit == NULL || out == NULL)
        return -1;

    n_wires = voleith_gf16_circuit_wire_count(circuit);
    n_constraints = voleith_gf16_circuit_constraint_count(circuit);
    wires = voleith_gf16_circuit_wires(circuit);
    constraints = voleith_gf16_circuit_constraints(circuit);

    voleith_shake128_init(&ctx);

    rc |= voleith_shake128_absorb(&ctx, domain_tag, sizeof(domain_tag) - 1);

    rc |= voleith_shake128_absorb_u32_le(&ctx, (uint32_t)n_wires);
    rc |= voleith_shake128_absorb_u32_le(
        &ctx, (uint32_t)voleith_gf16_circuit_witness_count(circuit));
    rc |= voleith_shake128_absorb_u32_le(
        &ctx, (uint32_t)voleith_gf16_circuit_instance_count(circuit));
    rc |= voleith_shake128_absorb_u32_le(
        &ctx, (uint32_t)voleith_gf16_circuit_mul_count(circuit));
    rc |= voleith_shake128_absorb_u32_le(&ctx, (uint32_t)n_constraints);

    for (i = 0; i < n_wires; i++) {
        rc |= absorb_u8(&ctx, (uint8_t)wires[i].kind);
        rc |=
            voleith_shake128_absorb_u32_le(&ctx, normalize_operand(wires[i].a));
        rc |=
            voleith_shake128_absorb_u32_le(&ctx, normalize_operand(wires[i].b));
        /*
         * const_val is meaningful only for CONST and XOR_CONST; the builder
         * leaves it at 0 otherwise, so absorbing it unconditionally is safe
         * and keeps the encoding fixed-width.  Absorbed as u32_le (a uint16
         * value, zero-extended) for an endian-stable encoding.
         */
        rc |=
            voleith_shake128_absorb_u32_le(&ctx, (uint32_t)wires[i].const_val);
        /*
         * matrix is populated only for LINEAR_MAP; zero-filled otherwise.
         * Each 16-bit row is absorbed little-endian (not as a raw byte
         * block) so the fingerprint is identical across host endianness.
         */
        for (int r = 0; r < 16; r++)
            rc |= voleith_shake128_absorb_u32_le(&ctx,
                                                 (uint32_t)wires[i].matrix[r]);
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

    voleith_shake128_squeeze(&ctx, out, VOLEITH_GF16_CIRCUIT_FINGERPRINT_BYTES);
    voleith_hash_ctx_clear(&ctx);

    return 0;
}
