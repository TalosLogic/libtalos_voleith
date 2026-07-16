/* Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * Constant-time targets for the V6 forward-secure epoch key schedule
 * (RSV6 security review Q11).  Three secret-input entry points from
 * proof/rs_epoch_gf8.c are validated, all at harness depth_e = 8
 * (T = 256 epochs), epoch_sk_bytes = 16 (lambda = 128):
 *
 *   - voleith_rs_epoch_keygen: GGM-expands the SECRET identity master
 *     seed to 2^depth_e leaf seeds, hashes each, and builds the epoch
 *     Merkle tree.  Class A/B vary the master seed; a data-dependent
 *     branch or a seed-dependent PRG-consumption count in the expansion
 *     would show as a timing difference (the class of leak the erasure
 *     keygen sampler hit before the Lemire fixed-consumption fix).
 *   - voleith_rs_epoch_state_advance: recomputes the puncturable cover to
 *     tile [target_t, T) and zeroizes the retired seeds.  The public
 *     target epoch is FIXED across classes; only the SECRET cover seeds
 *     differ (via the master seed), so a pass shows the forward walk's
 *     time is seed-independent at a fixed t.
 *   - voleith_rs_epoch_derive_sk: PRG-walks the covering block down to the
 *     leaf seed sk_t.  Public t is FIXED; the SECRET cover seeds differ
 *     across classes.
 *
 * Class A (cls 0): a single FIXED master seed, reused every trial.
 * Class B (cls 1): a fresh RANDOM master seed each trial.  Canonical
 * dudect fixed-vs-random; a constant-time schedule yields statistically
 * indistinguishable timing.
 *
 * The advance / derive targets seed the cover with voleith_rs_epoch_state_
 * init (cover only, no epoch tree, no heap), so their run() copies the
 * cover cheaply and allocates nothing.  keygen necessarily builds and
 * frees the public-node tree inside run(), so its state stays run-local
 * and each build is released to bound memory.
 *
 * EVIDENCE BOUNDARY (read before trusting a pass): these targets measure
 * TOTAL execution time under a Welch t-test, sensitive to access-COUNT and
 * data-dependent-branch leaks but largely blind to access-ORDER leaks that
 * keep a fixed instruction count.  The cover walk and the GGM expansion are
 * oblivious by construction (fixed passes, PRG-driven, no secret-indexed
 * access); a pass here is necessary corroboration, not sole proof.
 */
#include "dudect_target.h"

#include "node_hash_vt.h"
#include "rs_epoch_gf8.h"
#include "rs_gf8.h"

#include <stdint.h>
#include <string.h>

static volatile uint8_t rs_epoch_ct_sink;

/* xorshift64 PRNG for the random (class B) master seeds.  Deterministic
 * initial state keeps runs reproducible; only the value spread matters. */
static uint64_t rs_epoch_ct_prng = 0x9e3779b97f4a7c15ULL;

static uint8_t
prng8(void)
{
    uint64_t x = rs_epoch_ct_prng;
    x ^= x << 13;
    x ^= x >> 7;
    x ^= x << 17;
    rs_epoch_ct_prng = x;
    return (uint8_t)x;
}

/* Shared harness shape.  depth_e = 8 gives a 256-epoch tree, small enough
 * to keygen many times yet deep enough to exercise the cover arithmetic. */
#define RS_EPOCH_CT_DEPTH_E 8u
#define RS_EPOCH_CT_SK_BYTES 16u
#define RS_EPOCH_CT_DEPTH_M 3u
#define RS_EPOCH_CT_ADVANCE_T 128u /* fixed public target epoch */
#define RS_EPOCH_CT_DERIVE_T 100u  /* fixed public epoch to derive */

/* Fill a canonical V6 config (hirose tree, no salt) matching the shape
 * above.  All fields are public; only the master seed varies by class. */
static void
rs_epoch_ct_fill_cfg(voleith_rs_config_t *cfg)
{
    memset(cfg, 0, sizeof(*cfg));
    cfg->membership.tree_hash = &voleith_node_hash_hirose;
    cfg->membership.sk_bytes = 0; /* V6: leaf = epoch root, no static sk */
    cfg->membership.depth_m = RS_EPOCH_CT_DEPTH_M;
    cfg->depth_e = RS_EPOCH_CT_DEPTH_E;
    cfg->epoch_sk_bytes = RS_EPOCH_CT_SK_BYTES;
}

/* Fill an epoch_sk_bytes-wide master seed: fixed 0x5a for class A, fresh
 * random for class B. */
static void
rs_epoch_ct_fill_master(int cls, uint8_t *master)
{
    size_t i;

    for (i = 0; i < RS_EPOCH_CT_SK_BYTES; i++)
        master[i] = (cls == 0) ? 0x5au : prng8();
}

/* ----- voleith_rs_epoch_keygen (secret master seed) ------------------ */

typedef struct {
    voleith_rs_config_t cfg;
    uint8_t master[RS_EPOCH_CT_SK_BYTES];
} keygen_state_t;

static void
keygen_setup(int cls, void *state)
{
    keygen_state_t *s = (keygen_state_t *)state;

    rs_epoch_ct_fill_cfg(&s->cfg);
    rs_epoch_ct_fill_master(cls, s->master);
}

static void
keygen_run(const void *state)
{
    const keygen_state_t *s = (const keygen_state_t *)state;
    voleith_rs_epoch_state_t out;
    uint8_t root[MERKLE_VT_MAX_NODE_BYTES];

    memset(&out, 0, sizeof(out));
    if (voleith_rs_epoch_keygen(&s->cfg, s->master, NULL, &out, root) == 0) {
        rs_epoch_ct_sink ^= root[0];
        voleith_rs_epoch_state_clear(&out); /* release the built tree */
    } else {
        rs_epoch_ct_sink ^= 0xffu;
    }
}

const dudect_target_t target_voleith_rs_epoch_keygen = {
    .name = "voleith_rs_epoch_keygen",
    .setup_class = keygen_setup,
    .run = keygen_run,
    .state_size = sizeof(keygen_state_t),
    .reps_per_trial = 1,
};

/* ----- voleith_rs_epoch_state_advance (secret cover seeds) ----------- */

/* Both advance and derive seed the cover with state_init, which allocates
 * nothing (public_nodes stays NULL), so run() may shallow-copy the state
 * and mutate / read the cover without touching or freeing heap memory. */
typedef struct {
    voleith_rs_epoch_state_t base; /* seeded at epoch 0, cover only */
} epoch_cover_state_t;

static void
epoch_cover_setup(int cls, void *state)
{
    epoch_cover_state_t *s = (epoch_cover_state_t *)state;
    uint8_t master[RS_EPOCH_CT_SK_BYTES];

    rs_epoch_ct_fill_master(cls, master);
    memset(&s->base, 0, sizeof(s->base));
    (void)voleith_rs_epoch_state_init(&s->base, RS_EPOCH_CT_DEPTH_E,
                                      RS_EPOCH_CT_SK_BYTES, master);
}

static void
advance_run(const void *state)
{
    const epoch_cover_state_t *s = (const epoch_cover_state_t *)state;
    voleith_rs_epoch_state_t tmp = s->base; /* cover-only copy; no heap alias */

    if (voleith_rs_epoch_state_advance(&tmp, RS_EPOCH_CT_ADVANCE_T) == 0)
        rs_epoch_ct_sink ^= tmp.cover_seed[0];
    else
        rs_epoch_ct_sink ^= 0xffu;
}

const dudect_target_t target_voleith_rs_epoch_state_advance = {
    .name = "voleith_rs_epoch_state_advance",
    .setup_class = epoch_cover_setup,
    .run = advance_run,
    .state_size = sizeof(epoch_cover_state_t),
    .reps_per_trial = 40,
};

/* ----- voleith_rs_epoch_derive_sk (secret cover seeds) --------------- */

static void
derive_run(const void *state)
{
    const epoch_cover_state_t *s = (const epoch_cover_state_t *)state;
    uint8_t sk[VOLEITH_RS_EPOCH_SEED_MAX_BYTES];

    if (voleith_rs_epoch_derive_sk(&s->base, RS_EPOCH_CT_DERIVE_T, sk) == 0)
        rs_epoch_ct_sink ^= sk[0];
    else
        rs_epoch_ct_sink ^= 0xffu;
}

const dudect_target_t target_voleith_rs_epoch_derive_sk = {
    .name = "voleith_rs_epoch_derive_sk",
    .setup_class = epoch_cover_setup,
    .run = derive_run,
    .state_size = sizeof(epoch_cover_state_t),
    .reps_per_trial = 40,
};
