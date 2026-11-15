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
        /*
         * The fourth operand `d` exists only for PRODUCT3 and is absorbed
         * only for that kind, appended after `c`.  ZERO/EQUAL/PRODUCT
         * constraints absorb exactly as before, so their fingerprints stay
         * byte-identical to pre-PRODUCT3 circuits.
         */
        if (constraints[i].kind == GF8_CONSTRAINT_PRODUCT3)
            rc |= voleith_shake128_absorb_u32_le(
                &ctx, normalize_operand(constraints[i].d));
    }

    /*
     * AES norm round-pair table (paired-round norm S-box).  Appended only when
     * the circuit has at least one norm entry, so circuits without them (every
     * frozen circuit) are byte-identical to the pre-norm encoding, exactly as
     * the PRODUCT3 fourth operand is appended only for that kind.  Each entry
     * binds nst, the last_pair flag, and its 4*nst wire ids.
     */
    {
        size_t n_norm = voleith_gf8_circuit_norm_count(circuit);
        if (n_norm > 0) {
            const gf8_norm_entry_t *norms =
                voleith_gf8_circuit_norm_constraints(circuit);
            const gf8_wire_id *nw = voleith_gf8_circuit_norm_wires(circuit);
            size_t j, k;
            rc |= voleith_shake128_absorb_u32_le(&ctx, (uint32_t)n_norm);
            for (j = 0; j < n_norm; j++) {
                size_t cnt = (size_t)4 * norms[j].nst;
                rc |= voleith_shake128_absorb_u32_le(&ctx,
                                                     (uint32_t)norms[j].nst);
                rc |= absorb_u8(&ctx, (uint8_t)(norms[j].last_pair ? 1 : 0));
                for (k = 0; k < cnt; k++)
                    rc |= voleith_shake128_absorb_u32_le(
                        &ctx, normalize_operand(nw[norms[j].wires_off + k]));
            }
        }
    }

    /*
     * Grostl norm round-pair table (sibling of the AES norm table).  Appended
     * only when the circuit has at least one Grostl norm entry, so circuits
     * without them stay byte-identical to the pre-Grostl-norm encoding.  Each
     * entry binds nst, cols, is_q, odd_round, the 8 ShiftBytes row shifts, and
     * its 3*nst wire ids.
     */
    {
        size_t n_gn = voleith_gf8_circuit_grostl_norm_count(circuit);
        if (n_gn > 0) {
            const gf8_grostl_norm_entry_t *gn =
                voleith_gf8_circuit_grostl_norm_constraints(circuit);
            const gf8_wire_id *gw =
                voleith_gf8_circuit_grostl_norm_wires(circuit);
            size_t j, k;
            rc |= voleith_shake128_absorb_u32_le(&ctx, (uint32_t)n_gn);
            for (j = 0; j < n_gn; j++) {
                size_t cnt = (size_t)3 * gn[j].nst;
                rc |= voleith_shake128_absorb_u32_le(&ctx, (uint32_t)gn[j].nst);
                rc |=
                    voleith_shake128_absorb_u32_le(&ctx, (uint32_t)gn[j].cols);
                rc |= absorb_u8(&ctx, gn[j].is_q);
                rc |= absorb_u8(&ctx, gn[j].odd_round);
                for (k = 0; k < 8; k++)
                    rc |= absorb_u8(&ctx, gn[j].shift[k]);
                for (k = 0; k < cnt; k++)
                    rc |= voleith_shake128_absorb_u32_le(
                        &ctx, normalize_operand(gw[gn[j].wires_off + k]));
            }
        }
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
