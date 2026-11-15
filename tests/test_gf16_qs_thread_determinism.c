/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * test_gf16_qs_thread_determinism.c - QuickSilver accumulate threading (T3.1),
 * GF(2^16) mirror of test_gf8_qs_thread_determinism.
 *
 * The threaded GF(2^16) accumulate splits the ordered zk_hash update stream into
 * contiguous blocks hashed in parallel and folded back in order; it must be
 * bit-identical to the serial fold, so an N-worker proof must equal the serial
 * proof byte for byte and still verify.
 *
 * A GF(2^16) MUL chain is used because the native gf16 workloads (RLNC) are
 * free linear maps with no MUL gates and a trivial accumulate; the chain gives
 * enough accumulate items that the block count exceeds one and the threaded
 * path (and its segmented combine) actually runs.  On a software-only ichor the
 * pool is size 1 and the runs degrade to the serial path, so the equality holds
 * trivially; the test bites on a threaded build.
 */

#include "gf16_circuit.h"
#include "gf16_proof.h"

#include <stdio.h>
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

static const unsigned int NTHREADS[] = {2, 4, 8, 0};

int
main(void)
{
    const voleith_params_t *params = &voleith_params_em_128f;
    const int n_mul = 512;
    voleith_gf16_circuit_t *c = voleith_gf16_circuit_new();
    voleith_gf16_t witness[2] = {0x0003, 0x0005};
    uint8_t fs_seed[16];
    voleith_proof_t base;

    printf("=== test_gf16_qs_thread_determinism ===\n");
    printf(
        "\n[QS accumulate thread invariance: GF(2^16) MUL chain (%d gates)]\n",
        n_mul);

    if (!c) {
        printf("  SKIP: circuit alloc failed\n");
        return 0;
    }
    gf16_wire_id a = voleith_gf16_add_witness(c);
    gf16_wire_id b = voleith_gf16_add_witness(c);
    gf16_wire_id cur = a;
    for (int i = 0; i < n_mul; i++)
        cur = voleith_gf16_add_mul(c, cur, b);
    (void)cur;

    memset(fs_seed, 0xCD, sizeof(fs_seed));
    memset(&base, 0, sizeof(base));

    int bret = voleith_gf16_prove(&base, params, c, witness, NULL, fs_seed,
                                  sizeof(fs_seed));
    CHECK(bret == 0, "serial baseline prove succeeds");

    if (bret == 0) {
        for (size_t t = 0; t < sizeof(NTHREADS) / sizeof(*NTHREADS); t++) {
            voleith_threading_opts_t opts = {.nthreads = NTHREADS[t],
                                             .pool = NULL};
            voleith_proof_t mt;
            char msg[96];

            memset(&mt, 0, sizeof(mt));
            int mret = voleith_gf16_prove_ex(&mt, params, c, witness, NULL,
                                             fs_seed, sizeof(fs_seed), &opts);
            snprintf(msg, sizeof(msg), "threaded(n=%u) prove succeeds",
                     NTHREADS[t]);
            CHECK(mret == 0, msg);
            if (mret != 0)
                continue;

            snprintf(msg, sizeof(msg),
                     "threaded(n=%u) proof byte-identical to serial",
                     NTHREADS[t]);
            CHECK(mt.len == base.len &&
                      memcmp(mt.data, base.data, base.len) == 0,
                  msg);

            snprintf(msg, sizeof(msg), "threaded(n=%u) proof verifies",
                     NTHREADS[t]);
            CHECK(voleith_gf16_verify(&mt, params, c, NULL, fs_seed,
                                      sizeof(fs_seed)) == 0,
                  msg);
            voleith_proof_free(&mt);
        }
        voleith_proof_free(&base);
    }
    voleith_gf16_circuit_free(c);

    printf("\n=== Results: %d passed, %d failed ===\n", g_pass, g_fail);
    return (g_fail > 0) ? 1 : 0;
}
