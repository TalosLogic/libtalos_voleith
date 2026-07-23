/* Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * Grøstl witness-builder timing target.
 *
 * Witness-builder target (grostl256_gf8_build_witness_msg):
 *    Exercises the witness construction path in
 *    circuits/grostl_gf8_circuit.c, including the constant-time
 *    Fermat-based GF(2^8) inverse (voleith_gf8_inv) used to compute
 *    every S-box inv_in value.  This is the prover-side code that
 *    operates on secret witness data; constant-time discipline here
 *    is load-bearing because timing leaks would compromise the ZK
 *    secrecy the proof is meant to protect.
 *
 * The primitive Grøstl-256 / Grøstl-512 software-hash timing targets
 * moved to ichor along with the Grøstl primitive itself; ichor owns
 * that evidence trail now.  This voleith-side target validates only
 * the in-circuit witness builder, which stays voleith-side.
 *
 * Classes vary only the message content (all-zero vs all-one);
 * message length and call shape are public across classes.
 */
#include "dudect_target.h"

#include "grostl_gf8_circuit.h"

#include <stdint.h>
#include <string.h>

static volatile uint8_t grostl_target_sink;

/* ----- Grøstl-256 witness-builder target ------------------------------ */

/* Message length for the witness-builder target.  32 bytes fits in
 * one Grøstl-256 compression block, giving the minimum non-trivial
 * witness: 32 (message bytes) + 1*1280 (compression inv_in) + 640
 * (output transform inv_in) = 1952 bytes. */
#define WB_MSG_BYTES 32
#define WB_WITNESS_BYTES (WB_MSG_BYTES + 1280 + 640)

typedef struct {
    uint8_t msg[WB_MSG_BYTES];
} grostl_wb_state_t;

static void
grostl_wb_setup(int cls, void *state)
{
    grostl_wb_state_t *s = (grostl_wb_state_t *)state;
    memset(s->msg, cls ? 0xFF : 0x00, sizeof(s->msg));
}

static void
grostl256_wb_run(const void *state)
{
    const grostl_wb_state_t *s = (const grostl_wb_state_t *)state;
    /* Stack-local witness buffer, same pattern as the AES targets'
     * stack-local `out` buffer.  Avoids casting away const on the
     * harness state. */
    uint8_t witness[WB_WITNESS_BYTES];
    grostl256_gf8_build_witness(s->msg, WB_MSG_BYTES, witness);
    /* Visible side effect to defeat dead-code elimination. */
    grostl_target_sink ^= witness[0] ^ witness[WB_WITNESS_BYTES - 1];
}

const dudect_target_t target_voleith_grostl256_gf8_build_witness_msg = {
    .name = "voleith_grostl256_gf8_build_witness_msg",
    .setup_class = grostl_wb_setup,
    .run = grostl256_wb_run,
    .state_size = sizeof(grostl_wb_state_t),
    .reps_per_trial = 1,
};
