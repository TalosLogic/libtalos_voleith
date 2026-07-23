/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * circuit_fingerprint.c - Compute the 16-byte SHAKE-128 circuit fingerprint.
 *
 * See circuit_fingerprint.h for the canonical serialization spec.
 */

#include "circuit_fingerprint.h"

#include "../core/hash.h"
#include "../core/util.h"

#include <string.h>

/* ================================================================
 * Helpers
 * ================================================================ */

/* Returns the underlying absorb status (0, or VOLEITH_HASH_ERR_FINALIZED). */
static int
absorb_u8(voleith_hash_ctx_t *ctx, uint8_t v)
{
    return voleith_shake128_absorb(ctx, &v, 1);
}

/*
 * Normalize an operand: WIRE_ID_INVALID maps to 0 on the wire so the
 * fingerprint does not depend on which sentinel value a producer
 * happens to use for "unused".  Any valid wire id passes through
 * unchanged.
 */
static uint32_t
normalize_operand(wire_id w)
{
    return (w == WIRE_ID_INVALID) ? 0u : (uint32_t)w;
}

/* ================================================================
 * Public API
 * ================================================================ */

int
voleith_circuit_fingerprint(const voleith_circuit_t *circuit,
                            uint8_t out[VOLEITH_CIRCUIT_FINGERPRINT_BYTES])
{
    voleith_hash_ctx_t ctx;
    const wire_entry_t *wires;
    const constraint_entry_t *constraints;
    size_t n_wires, n_constraints, i;
    int rc = 0;
    /* Domain tag plus the explicit 0x00 terminator from the spec. */
    static const uint8_t domain_tag[] =
        VOLEITH_CIRCUIT_FINGERPRINT_DOMAIN_TAG "\x00";

    if (circuit == NULL || out == NULL)
        return -1;

    n_wires = voleith_circuit_wire_count(circuit);
    n_constraints = voleith_circuit_constraint_count(circuit);
    wires = voleith_circuit_wires(circuit);
    constraints = voleith_circuit_constraints(circuit);

    voleith_shake128_init(&ctx);

    /*
     * sizeof(domain_tag) includes the implicit '\0' terminator that
     * the compiler appends to the string literal, plus the explicit
     * 0x00 we glued on - so the final absorbed length is the
     * 21-character tag + the spec's 0x00, totaling 22 bytes.  Subtract
     * 1 to avoid double-absorbing the implicit terminator.
     */
    rc |= voleith_shake128_absorb(&ctx, domain_tag, sizeof(domain_tag) - 1);

    rc |= voleith_shake128_absorb_u32_le(&ctx, (uint32_t)n_wires);
    rc |= voleith_shake128_absorb_u32_le(
        &ctx, (uint32_t)voleith_circuit_witness_count(circuit));
    rc |= voleith_shake128_absorb_u32_le(
        &ctx, (uint32_t)voleith_circuit_instance_count(circuit));
    rc |= voleith_shake128_absorb_u32_le(
        &ctx, (uint32_t)voleith_circuit_and_gate_count(circuit));
    rc |= voleith_shake128_absorb_u32_le(&ctx, (uint32_t)n_constraints);

    for (i = 0; i < n_wires; i++) {
        rc |= absorb_u8(&ctx, (uint8_t)wires[i].kind);
        rc |=
            voleith_shake128_absorb_u32_le(&ctx, normalize_operand(wires[i].a));
        rc |=
            voleith_shake128_absorb_u32_le(&ctx, normalize_operand(wires[i].b));
        /* const_bit is meaningful only for WIRE_KIND_CONST; for other
         * wire kinds the builder leaves it at 0 so this is a no-op. */
        rc |= absorb_u8(&ctx, wires[i].const_bit);
    }

    for (i = 0; i < n_constraints; i++) {
        rc |= absorb_u8(&ctx, (uint8_t)constraints[i].kind);
        rc |= voleith_shake128_absorb_u32_le(
            &ctx, normalize_operand(constraints[i].a));
        rc |= voleith_shake128_absorb_u32_le(
            &ctx, normalize_operand(constraints[i].b));
    }

    /* nonzero only on absorb-after-squeeze (unreachable here, single squeeze
     * below); propagated defensively rather than silently dropped. */
    if (rc != 0) {
        voleith_hash_ctx_clear(&ctx);
        return -1;
    }

    voleith_shake128_squeeze(&ctx, out, VOLEITH_CIRCUIT_FINGERPRINT_BYTES);
    voleith_hash_ctx_clear(&ctx);

    return 0;
}
