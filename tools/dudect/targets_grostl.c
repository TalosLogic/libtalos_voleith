/* Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * Grøstl-256 and Grøstl-512 timing targets.  Two families:
 *
 * 1. Software-hash targets (_msg):
 *    Exercise the software Grøstl path in core/grostl.c, including
 *    its use of the bitsliced AES S-box via
 *    aes_ct64_sbox_inplace_4blocks().  Cover the Grøstl-specific
 *    state-management, GF(2^8) MixBytes arithmetic, padding, and
 *    per-round AddRoundConstant / ShiftBytes operations that the AES
 *    targets do not.
 *
 * 2. Witness-builder target (grostl256_gf8_build_witness_msg):
 *    Exercises the witness construction path in
 *    circuits/grostl_gf8_circuit.c, including the constant-time
 *    Fermat-based GF(2^8) inverse (voleith_gf8_inv) used to compute
 *    every S-box inv_in value.  This is the prover-side code that
 *    operates on secret witness data; constant-time discipline here
 *    is load-bearing because timing leaks would compromise the ZK
 *    secrecy the proof is meant to protect.
 *
 * For each target, classes vary only the message content
 * (all-zero vs all-one); message length and call shape are public
 * across classes.
 */
#include "dudect_target.h"

#include "grostl.h"
#include "grostl_gf8_circuit.h"

#include <stdint.h>
#include <string.h>

/* 128-byte messages: for Grøstl-256 this is 2 message blocks plus a
 * dedicated padding block (3 compressions per hash); for Grøstl-512
 * this is 1 message block plus a dedicated padding block (2
 * compressions per hash).  Both cases exercise multi-block absorb
 * plus the finalize / padding path. */
#define GROSTL_DUDECT_MSG_BYTES 128

typedef struct {
    uint8_t msg[GROSTL_DUDECT_MSG_BYTES];
} grostl_state_t;

static volatile uint8_t grostl_target_sink;

/* ----- shared setup: message bytes vary across classes --------------- */

static void
grostl_msg_setup(int cls, void *state)
{
    grostl_state_t *s = (grostl_state_t *)state;
    memset(s->msg, cls ? 0xFF : 0x00, sizeof(s->msg));
}

/* ----- Grøstl-256 ---------------------------------------------------- */

static void
grostl256_msg_run(const void *state)
{
    const grostl_state_t *s = (const grostl_state_t *)state;
    uint8_t out[32];
    voleith_grostl256(out, s->msg, sizeof(s->msg));
    grostl_target_sink ^= out[0] ^ out[31];
}

const dudect_target_t target_voleith_grostl256_msg = {
    .name = "voleith_grostl256_msg",
    .setup_class = grostl_msg_setup,
    .run = grostl256_msg_run,
    .state_size = sizeof(grostl_state_t),
    .reps_per_trial = 50,
};

/* ----- Grøstl-512 ---------------------------------------------------- */

static void
grostl512_msg_run(const void *state)
{
    const grostl_state_t *s = (const grostl_state_t *)state;
    uint8_t out[64];
    voleith_grostl512(out, s->msg, sizeof(s->msg));
    grostl_target_sink ^= out[0] ^ out[63];
}

const dudect_target_t target_voleith_grostl512_msg = {
    .name = "voleith_grostl512_msg",
    .setup_class = grostl_msg_setup,
    .run = grostl512_msg_run,
    .state_size = sizeof(grostl_state_t),
    .reps_per_trial = 50,
};

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
