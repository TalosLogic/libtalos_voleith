/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * test_params_fingerprint.c - Tests for voleith_params_fingerprint().
 *
 * Tests:
 *   1: Determinism - same params twice produces the same 16 bytes.
 *   2: All six named EM-* parameter sets produce distinct fingerprints.
 *   3: Each numeric field is bound - perturbing any field changes the
 *      fingerprint.
 *   4: fs_kind and bavc_kind are bound.
 *   5: voleith_params_build agrees with the named const struct for
 *      (SHAKE, STANDARD); produces different fingerprints across all
 *      four (fs, bavc) corners.
 *   6: NULL args rejected.
 */

#include "params_fingerprint.h"
#include "proof.h"

#include <stdint.h>
#include <stdio.h>
#include <string.h>

static int test_count = 0;
static int pass_count = 0;

static void
check(const char *name, int cond)
{
    test_count++;
    if (cond) {
        pass_count++;
    } else {
        printf("  FAIL: %s\n", name);
    }
}

/* ================================================================
 * Test 1: Determinism.
 * ================================================================ */
static void
test_determinism(void)
{
    uint8_t fp1[VOLEITH_PARAMS_FINGERPRINT_BYTES];
    uint8_t fp2[VOLEITH_PARAMS_FINGERPRINT_BYTES];

    check("determinism: em_128f fingerprint succeeds",
          voleith_params_fingerprint(&voleith_params_em_128f, fp1) == 0);
    check("determinism: em_128f fingerprint succeeds (again)",
          voleith_params_fingerprint(&voleith_params_em_128f, fp2) == 0);
    check("determinism: repeated calls identical",
          memcmp(fp1, fp2, sizeof(fp1)) == 0);
}

/* ================================================================
 * Test 2: All six named EM-* parameter sets produce distinct fingerprints.
 *
 * This is the M-N2 params-binding contract: the fingerprint must
 * distinguish every shipped parameter set, otherwise the verifier
 * cannot reject a 128f proof presented under 256f params.
 * ================================================================ */
static void
test_em_sets_all_distinct(void)
{
    const voleith_params_t *sets[] = {
        &voleith_params_em_128f, &voleith_params_em_128s,
        &voleith_params_em_192f, &voleith_params_em_192s,
        &voleith_params_em_256f, &voleith_params_em_256s,
    };
    const char *names[] = {"em_128f", "em_128s", "em_192f",
                           "em_192s", "em_256f", "em_256s"};
    const size_t n = sizeof(sets) / sizeof(sets[0]);
    uint8_t fps[6][VOLEITH_PARAMS_FINGERPRINT_BYTES];
    size_t i, j;
    int ok = 1;

    for (i = 0; i < n; i++) {
        if (voleith_params_fingerprint(sets[i], fps[i]) != 0) {
            ok = 0;
            break;
        }
    }
    check("em-sets: all six fingerprints compute", ok);

    if (!ok)
        return;

    for (i = 0; i < n && ok; i++) {
        for (j = i + 1; j < n; j++) {
            if (memcmp(fps[i], fps[j], VOLEITH_PARAMS_FINGERPRINT_BYTES) == 0) {
                printf("  collision: %s == %s\n", names[i], names[j]);
                ok = 0;
                break;
            }
        }
    }
    check("em-sets: every pair of fingerprints differs", ok);
}

/* ================================================================
 * Test 3: Each field is bound.
 *
 * Start from em_128f, mutate one field at a time, confirm the
 * fingerprint changes.  This is the custom-params contract: a
 * caller-built voleith_params_t cannot impersonate another by
 * tweaking any field.
 * ================================================================ */
static void
test_each_field_bound(void)
{
    voleith_params_t base = voleith_params_em_128f;
    voleith_params_t mut;
    uint8_t fp_base[VOLEITH_PARAMS_FINGERPRINT_BYTES];
    uint8_t fp_mut[VOLEITH_PARAMS_FINGERPRINT_BYTES];

    (void)voleith_params_fingerprint(&base, fp_base);

    /* lambda */
    mut = base;
    mut.lambda = 256;
    (void)voleith_params_fingerprint(&mut, fp_mut);
    check("field bound: lambda", memcmp(fp_base, fp_mut, sizeof(fp_base)) != 0);

    /* tau */
    mut = base;
    mut.tau = base.tau + 1;
    (void)voleith_params_fingerprint(&mut, fp_mut);
    check("field bound: tau", memcmp(fp_base, fp_mut, sizeof(fp_base)) != 0);

    /* w_grind */
    mut = base;
    mut.w_grind = base.w_grind + 1;
    (void)voleith_params_fingerprint(&mut, fp_mut);
    check("field bound: w_grind",
          memcmp(fp_base, fp_mut, sizeof(fp_base)) != 0);

    /* T_open */
    mut = base;
    mut.T_open = base.T_open + 1;
    (void)voleith_params_fingerprint(&mut, fp_mut);
    check("field bound: T_open", memcmp(fp_base, fp_mut, sizeof(fp_base)) != 0);

    /* n_leafcom */
    mut = base;
    mut.n_leafcom = (base.n_leafcom == 2) ? 3u : 2u;
    (void)voleith_params_fingerprint(&mut, fp_mut);
    check("field bound: n_leafcom",
          memcmp(fp_base, fp_mut, sizeof(fp_base)) != 0);
}

/* ================================================================
 * Test 4: fs_kind and bavc_kind are bound.
 * ================================================================ */
static void
test_fs_bavc_bound(void)
{
    voleith_params_t base = voleith_params_em_128f;
    voleith_params_t mut;
    uint8_t fp_base[VOLEITH_PARAMS_FINGERPRINT_BYTES];
    uint8_t fp_mut[VOLEITH_PARAMS_FINGERPRINT_BYTES];

    (void)voleith_params_fingerprint(&base, fp_base);

    mut = base;
    mut.fs_kind = VOLEITH_FS_GROSTL;
    (void)voleith_params_fingerprint(&mut, fp_mut);
    check("field bound: fs_kind",
          memcmp(fp_base, fp_mut, sizeof(fp_base)) != 0);

    mut = base;
    mut.bavc_kind = VOLEITH_BAVC_HALF_TREE;
    (void)voleith_params_fingerprint(&mut, fp_mut);
    check("field bound: bavc_kind",
          memcmp(fp_base, fp_mut, sizeof(fp_base)) != 0);
}

/* ================================================================
 * Test 5: voleith_params_build behavior.
 *
 *   - Build (EM_128F, SHAKE, STANDARD) and confirm it fingerprints
 *     identically to the named const voleith_params_em_128f.  This is
 *     the backward-compatibility contract: existing callers using the
 *     named symbols must produce the same proofs / fingerprints as
 *     callers using the new builder with default variants.
 *   - Across all four (fs, bavc) corners for the same parameter set,
 *     fingerprints must be pairwise distinct.
 *   - An out-of-range param_set_id produces a zero-initialized struct
 *     that voleith_params_validate rejects.
 * ================================================================ */
static void
test_params_build(void)
{
    voleith_params_t built;
    voleith_params_t bad;
    uint8_t fp_named[VOLEITH_PARAMS_FINGERPRINT_BYTES];
    uint8_t fp_built[VOLEITH_PARAMS_FINGERPRINT_BYTES];
    uint8_t fps[4][VOLEITH_PARAMS_FINGERPRINT_BYTES];
    size_t i, j;
    int ok = 1;

    built = voleith_params_build(VOLEITH_PARAM_EM_128F, VOLEITH_FS_SHAKE,
                                 VOLEITH_BAVC_STANDARD);
    (void)voleith_params_fingerprint(&voleith_params_em_128f, fp_named);
    (void)voleith_params_fingerprint(&built, fp_built);
    check("build (EM_128F, SHAKE, STANDARD) matches named em_128f",
          memcmp(fp_named, fp_built, sizeof(fp_named)) == 0);

    /* Four corners over (fs, bavc) for the same EM set must all differ. */
    {
        const voleith_fs_kind_t fss[] = {VOLEITH_FS_SHAKE, VOLEITH_FS_GROSTL};
        const voleith_bavc_kind_t bavcs[] = {VOLEITH_BAVC_STANDARD,
                                             VOLEITH_BAVC_HALF_TREE};
        size_t idx = 0;
        for (i = 0; i < 2; i++) {
            for (j = 0; j < 2; j++) {
                built = voleith_params_build(VOLEITH_PARAM_EM_256S, fss[i],
                                             bavcs[j]);
                (void)voleith_params_fingerprint(&built, fps[idx++]);
            }
        }
    }
    for (i = 0; i < 4 && ok; i++) {
        for (j = i + 1; j < 4; j++) {
            if (memcmp(fps[i], fps[j], VOLEITH_PARAMS_FINGERPRINT_BYTES) == 0) {
                ok = 0;
                break;
            }
        }
    }
    check("build: all four (fs, bavc) corners produce distinct fingerprints",
          ok);

    /* Out-of-range param_set_id -> zero struct -> validate rejects. */
    bad = voleith_params_build((voleith_param_set_id_t)99, VOLEITH_FS_SHAKE,
                               VOLEITH_BAVC_STANDARD);
    check("build: out-of-range set returns zero struct (lambda == 0)",
          bad.lambda == 0);
    check("build: out-of-range set fails validate",
          voleith_params_validate(&bad) != 0);

    /* All six named param sets reachable through the builder, each
     * validates. */
    {
        const voleith_param_set_id_t ids[] = {
            VOLEITH_PARAM_EM_128F, VOLEITH_PARAM_EM_128S, VOLEITH_PARAM_EM_192F,
            VOLEITH_PARAM_EM_192S, VOLEITH_PARAM_EM_256F, VOLEITH_PARAM_EM_256S,
        };
        int all_valid = 1;
        for (i = 0; i < sizeof(ids) / sizeof(ids[0]); i++) {
            voleith_params_t p = voleith_params_build(ids[i], VOLEITH_FS_SHAKE,
                                                      VOLEITH_BAVC_STANDARD);
            if (voleith_params_validate(&p) != 0) {
                all_valid = 0;
                break;
            }
        }
        check("build: all six param sets produce valid params", all_valid);
    }
}

/* ================================================================
 * Test 6: NULL args rejected.
 * ================================================================ */
static void
test_null_args(void)
{
    uint8_t fp[VOLEITH_PARAMS_FINGERPRINT_BYTES];

    check("null: params == NULL rejected",
          voleith_params_fingerprint(NULL, fp) != 0);
    check("null: out == NULL rejected",
          voleith_params_fingerprint(&voleith_params_em_128f, NULL) != 0);
}

int
main(void)
{
    printf("test_params_fingerprint: starting\n");
    test_determinism();
    test_em_sets_all_distinct();
    test_each_field_bound();
    test_fs_bavc_bound();
    test_params_build();
    test_null_args();
    printf("test_params_fingerprint: %d/%d passed\n", pass_count, test_count);
    return (pass_count == test_count) ? 0 : 1;
}
