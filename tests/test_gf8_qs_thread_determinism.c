/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * test_gf8_qs_thread_determinism.c - QuickSilver accumulate threading (T3.1).
 *
 * The threaded QuickSilver accumulate splits the ordered zk_hash update stream
 * into contiguous blocks hashed in parallel and folded back in order.  It must
 * be bit-identical to the serial fold, so a proof produced with N workers must
 * equal, byte for byte, the serial (1-worker) proof, and still verify.
 *
 * The existing thread-invariance check in test_gf8_proof uses a one-MUL-gate
 * circuit; with a single accumulate item the block count collapses to 1 and the
 * threaded path never runs.  These circuits are large enough that the accumulate
 * is genuinely partitioned into more than one block:
 *   - a long MUL chain (exercises the MUL segment + the segmented combine), and
 *   - the AES-128 norm S-box circuit (adds the PRODUCT3 / norm / EQUAL dispatch).
 *
 * On a software-only (non-threaded) ichor the pool is size 1, so the threaded
 * runs degrade to the serial path and the equality holds trivially; the test is
 * meaningful on a threaded build, where N > 1 workers actually split the stream.
 */

#include "aes_norm_gf8_circuit.h"
#include "gf8_circuit.h"
#include "gf8_proof.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int g_pass = 0;
static int g_fail = 0;

#define CHECK(cond, msg)                                                       \
    do {                                                                       \
        if (cond) {                                                            \
            g_pass++;                                                          \
        } else {                                                               \
            g_fail++;                                                          \
            printf("  FAIL: %s\n", (msg));                                     \
        }                                                                      \
    } while (0)

static const uint8_t KEY[32] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                                0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
                                0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
                                0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f};
static const uint8_t PT[16] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
                               0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff};

/* Worker counts to sweep against the serial baseline (0 = physical cores). */
static const unsigned int NTHREADS[] = {2, 4, 8, 0};

/*
 * Prove the circuit serially, then at each worker count, and assert every
 * threaded proof is byte-identical to the serial one and verifies.
 */
static void
run_invariance(const char *label, const voleith_gf8_circuit_t *c,
               const uint8_t *witness, const uint8_t *instance)
{
    const voleith_params_t *params = &voleith_params_em_128f;
    uint8_t fs_seed[16];
    voleith_proof_t base;

    printf("\n[QS accumulate thread invariance: %s]\n", label);
    memset(fs_seed, 0xCD, sizeof(fs_seed));
    memset(&base, 0, sizeof(base));

    int bret = voleith_gf8_prove(&base, params, c, witness, instance, fs_seed,
                                 sizeof(fs_seed));
    CHECK(bret == 0, "serial baseline prove succeeds");
    if (bret != 0)
        return;

    for (size_t t = 0; t < sizeof(NTHREADS) / sizeof(*NTHREADS); t++) {
        voleith_threading_opts_t opts = {.nthreads = NTHREADS[t], .pool = NULL};
        voleith_proof_t mt;
        char msg[96];

        memset(&mt, 0, sizeof(mt));
        int mret = voleith_gf8_prove_ex(&mt, params, c, witness, instance,
                                        fs_seed, sizeof(fs_seed), &opts);
        snprintf(msg, sizeof(msg), "threaded(n=%u) prove succeeds",
                 NTHREADS[t]);
        CHECK(mret == 0, msg);
        if (mret != 0)
            continue;

        snprintf(msg, sizeof(msg),
                 "threaded(n=%u) proof byte-identical to serial", NTHREADS[t]);
        CHECK(mt.len == base.len && memcmp(mt.data, base.data, base.len) == 0,
              msg);

        snprintf(msg, sizeof(msg), "threaded(n=%u) proof verifies",
                 NTHREADS[t]);
        CHECK(voleith_gf8_verify(&mt, params, c, instance, fs_seed,
                                 sizeof(fs_seed)) == 0,
              msg);
        voleith_proof_free(&mt);
    }
    voleith_proof_free(&base);
}

/* A chain of n_mul MUL gates: c_0 = a, c_{i+1} = c_i * b.  n_mul accumulate
 * items with no constraints, so the MUL segment alone is split across blocks.
 * The n_mul MUL output wires are all level-0 sources in the bit-tag pass, so
 * level 0 is n_mul+2 wide: large enough to trip the wavefront dispatch
 * threshold (width >= 4*workers) at every tested thread count. */
static void
test_mul_chain(void)
{
    const int n_mul = 512;
    voleith_gf8_circuit_t *c = voleith_gf8_circuit_new();
    if (!c) {
        printf("  SKIP: circuit alloc failed\n");
        return;
    }
    gf8_wire_id a = voleith_gf8_add_witness(c);
    gf8_wire_id b = voleith_gf8_add_witness(c);
    gf8_wire_id cur = a;
    for (int i = 0; i < n_mul; i++)
        cur = voleith_gf8_add_mul(c, cur, b);
    (void)cur;

    uint8_t witness[2] = {0x03, 0x05};
    run_invariance("MUL chain (512 gates)", c, witness, NULL);
    voleith_gf8_circuit_free(c);
}

/* AES-128 norm S-box circuit: MUL + PRODUCT3/norm + EQUAL constraints, thousands
 * of accumulate items spanning several segments. */
static void
test_aes128_norm(void)
{
    voleith_gf8_circuit_t *c = voleith_gf8_circuit_new();
    gf8_wire_id key_wires[16], pt_wires[16], ct_computed[16];
    uint8_t ct_ref[16], instance[32];
    uint8_t *witness = NULL;
    size_t wlen;

    if (!c) {
        printf("  SKIP: circuit alloc failed\n");
        return;
    }
    for (int i = 0; i < 16; i++)
        key_wires[i] = voleith_gf8_add_witness(c);
    for (int i = 0; i < 16; i++)
        pt_wires[i] = voleith_gf8_add_instance(c);
    aes128_norm_gf8_circuit(c, key_wires, pt_wires, ct_computed);
    for (int i = 0; i < 16; i++) {
        gf8_wire_id ct_inst = voleith_gf8_add_instance(c);
        voleith_gf8_assert_equal(c, ct_computed[i], ct_inst);
    }

    wlen = voleith_gf8_circuit_witness_byte_len(c);
    witness = calloc(wlen, 1);
    if (!witness) {
        printf("  SKIP: witness alloc failed\n");
        voleith_gf8_circuit_free(c);
        return;
    }
    aes128_norm_gf8_build_witness(KEY, PT, witness, ct_ref);
    memcpy(instance, PT, 16);
    memcpy(instance + 16, ct_ref, 16);

    run_invariance("AES-128 norm S-box", c, witness, instance);
    free(witness);
    voleith_gf8_circuit_free(c);
}

int
main(void)
{
    printf("=== test_gf8_qs_thread_determinism ===\n");

    test_mul_chain();
    test_aes128_norm();

    printf("\n=== Results: %d passed, %d failed ===\n", g_pass, g_fail);
    return (g_fail > 0) ? 1 : 0;
}
