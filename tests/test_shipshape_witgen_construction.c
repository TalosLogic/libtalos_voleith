/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * test_shipshape_witgen_construction.c - mechanism tests for the W8.5a Tier 2a
 * crypto-v2 CONSTRUCTION witness-backend dispatch substrate
 * (parsers/shipshape_witgen_dispatch.c + the region cv2_* fields in
 * parsers/shipshape.{h,c}).
 *
 * The substrate routes REG_HASH_PARAM construction calls (bracketed
 * "fqn[type]" names like stdlib/crypto/ring_sig/v1[aes_dm]) to a backend
 * registered under the exact bracketed name.  W8.5a adds NO real handler; this
 * suite uses a sentinel backend that deliberately returns -1 to observe that
 * dispatch reached the construction region (fail-closed), and asserts the
 * substrate is inert when nothing matching is registered.
 *
 * Vehicle: RING_SIG_SRC (ring_sig/v1[aes_dm], depth 2, sk 16), the known-good
 * crypto-v2 source mirrored from test_shipshape_crypto_v2_proof.c.
 */

#include "field.h"
#include "shipshape.h"
#include "shipshape_node_hash_types.h"
#include "shipshape_registry.h"
#include "shipshape_witgen_dispatch.h"
#include "shipshape_witness.h"
#include "util.h"

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
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

/* crypto-v2 header. */
#define HDR_V2                                                                 \
    ".shipshape 1\n"                                                           \
    "field GF(2^8) irreducible 0x11B\n"                                        \
    "stdlib crypto-v2\n"

/* ring_sig/v1[aes_dm]: sk=16, depth=2, sib=32, root(inst)=16. */
static const char RING_SIG_SRC[] =
    HDR_V2 "WITNESS  -> %sk   : byte[16]\n"
           "WITNESS  -> %dirs : byte[2]\n"
           "WITNESS  -> %sib  : byte[32]\n"
           "INSTANCE -> %root : byte[16]\n"
           "stdlib/crypto/ring_sig/v1[aes_dm](%sk, %dirs, %sib, %root)\n";

/* ext layout = sk[16] | dirs[2] | sib[32] = 50 bytes; instance = root[16]. */
#define RING_SIG_EXT_LEN 50u
#define RING_SIG_INST_LEN 16u

/* Static invocation counter for the sentinel construction backend. */
static int s_backend_call_count = 0;

/* Zero a secret witness buffer before releasing it. */
static void
zfree(uint8_t *buf, size_t len)
{
    if (buf != NULL && len > 0)
        voleith_secure_zero(buf, len);
    free(buf);
}

/*
 * Sentinel construction backend.  W8.5a ships no real handler, so this only
 * records that it was invoked and returns -1: a deliberate "I ran" signal that
 * needs no crypto.  A nonzero return aborts witness generation (fail-closed),
 * which is exactly how the test observes that dispatch reached the region.
 */
static int
test_construction_backend(const voleith_shipshape_region_t *region,
                          const uint8_t *ext, size_t ext_len, uint8_t *full)
{
    (void)region;
    (void)ext;
    (void)ext_len;
    (void)full;
    s_backend_call_count++;
    return -1;
}

/* Parse RING_SIG_SRC into *p.  Returns 0 on success. */
static int
parse_ring_sig(voleith_shipshape_parsed_t *p)
{
    return voleith_shipshape_parse_buffer(p, RING_SIG_SRC, 0, NULL);
}

/*
 * Run witness_gen on RING_SIG_SRC with arbitrary (non-crypto) ext + instance
 * bytes, no self-check.  *out is freed by the caller via zfree.  Returns the
 * witness_gen return code.
 */
static int
run_ring_sig_witness_gen(uint8_t **out, size_t *out_len)
{
    voleith_shipshape_parsed_t p = {0};
    uint8_t ext[RING_SIG_EXT_LEN];
    uint8_t inst[RING_SIG_INST_LEN];
    size_t i;
    int r;

    for (i = 0; i < RING_SIG_EXT_LEN; i++)
        ext[i] = (uint8_t)(i + 1);
    for (i = 0; i < RING_SIG_INST_LEN; i++)
        inst[i] = (uint8_t)(0x40 + i);

    r = parse_ring_sig(&p);
    if (r != 0) {
        voleith_shipshape_parsed_free(&p);
        return r;
    }
    r = voleith_shipshape_witness_gen(&p, ext, RING_SIG_EXT_LEN, inst,
                                      RING_SIG_INST_LEN, 0, out, out_len);
    voleith_shipshape_parsed_free(&p);
    return r;
}

/* ================================================================
 * Case 1: region recording.
 * ================================================================ */

static void
test_region_recording(void)
{
    voleith_shipshape_parsed_t p = {0};
    const voleith_shipshape_reg_hash_entry_t *e = NULL;
    size_t i;
    int r;

    voleith_shipshape_witgen_reset();

    r = parse_ring_sig(&p);
    check("recording: parse succeeds", r == 0);
    if (r != 0) {
        voleith_shipshape_parsed_free(&p);
        return;
    }

    check("recording: exactly one region", p.n_regions == 1);
    if (p.n_regions != 1) {
        voleith_shipshape_parsed_free(&p);
        return;
    }

    check("recording: cv2_valid set", p.regions[0].cv2_valid == 1);
    check("recording: cv2_type_id is aes_dm",
          p.regions[0].cv2_type_id == VOLEITH_SHIPSHAPE_NHT_AES_DM);

    /* Look up the ring_sig/v1 reg_hash entry for the expected param shape. */
    for (i = 0; i < voleith_shipshape_reg_hash_count; i++) {
        if (strcmp(voleith_shipshape_reg_hash[i].fqn,
                   "stdlib/crypto/ring_sig/v1") == 0) {
            e = &voleith_shipshape_reg_hash[i];
            break;
        }
    }
    check("recording: ring_sig/v1 reg_hash entry found", e != NULL);
    if (e != NULL) {
        check("recording: cv2_n_params matches entry",
              p.regions[0].cv2_n_params == e->n_params);
        check("recording: cv2_depth_param matches entry",
              p.regions[0].cv2_depth_param == e->depth_param);
        check("recording: cv2_leaf_param matches entry",
              p.regions[0].cv2_leaf_param == e->leaf_param);
    }

    /* The recorded depth param value must equal the source depth (2). */
    check("recording: depth param value == 2",
          p.regions[0].cv2_params[p.regions[0].cv2_depth_param] == 2);

    voleith_shipshape_parsed_free(&p);
}

/* ================================================================
 * Case 2: dispatch fires for the correct bracketed name.
 * ================================================================ */

static void
test_dispatch_fires(void)
{
    uint8_t *full = NULL;
    size_t full_len = 0;
    int r;

    voleith_shipshape_witgen_reset();
    s_backend_call_count = 0;

    r = voleith_shipshape_witgen_register_construction(
        "stdlib/crypto/ring_sig/v1[aes_dm]", test_construction_backend);
    check("dispatch: register_construction succeeds", r == 0);

    r = run_ring_sig_witness_gen(&full, &full_len);
    check("dispatch: witness_gen returns nonzero (backend failure propagated)",
          r != 0);
    check("dispatch: backend was invoked", s_backend_call_count > 0);

    zfree(full, full_len);
    voleith_shipshape_witgen_reset();
}

/* ================================================================
 * Case 3: wrong bracketed name does NOT dispatch.
 * ================================================================ */

static void
test_wrong_name_no_dispatch(void)
{
    uint8_t *full = NULL;
    size_t full_len = 0;
    int r;

    voleith_shipshape_witgen_reset();
    s_backend_call_count = 0;

    /* A different valid bracketed name: must not match the ring_sig region. */
    r = voleith_shipshape_witgen_register_construction(
        "stdlib/crypto/merkle/path_secret[aes_dm]", test_construction_backend);
    check("wrong name: register_construction succeeds", r == 0);

    r = run_ring_sig_witness_gen(&full, &full_len);
    check("wrong name: witness_gen succeeds (no matching backend)", r == 0);
    check("wrong name: backend was NOT invoked", s_backend_call_count == 0);

    zfree(full, full_len);
    voleith_shipshape_witgen_reset();
}

/* ================================================================
 * Case 4: nothing registered (generic baseline; substrate inert).
 * ================================================================ */

static void
test_nothing_registered(void)
{
    uint8_t *full = NULL;
    size_t full_len = 0;
    int r;

    voleith_shipshape_witgen_reset();
    s_backend_call_count = 0;

    r = run_ring_sig_witness_gen(&full, &full_len);
    check("empty: witness_gen succeeds (generic path)", r == 0);
    check("empty: backend was NOT invoked", s_backend_call_count == 0);

    zfree(full, full_len);
    voleith_shipshape_witgen_reset();
}

/* ================================================================
 * Case 5: register_construction validation.
 * ================================================================ */

static void
test_register_validation(void)
{
    voleith_shipshape_witgen_reset();

    /* NULL args. */
    check("validate: NULL fqn returns negative",
          voleith_shipshape_witgen_register_construction(
              NULL, test_construction_backend) < 0);
    check("validate: NULL fn returns negative",
          voleith_shipshape_witgen_register_construction(
              "stdlib/crypto/ring_sig/v1[aes_dm]", NULL) < 0);

    /* Non-bracketed (no type): a bare crypto-v2 entry name. */
    check("validate: non-bracketed name returns negative",
          voleith_shipshape_witgen_register_construction(
              "stdlib/crypto/ring_sig/v1", test_construction_backend) < 0);

    /* Unknown node-hash type. */
    check("validate: unknown type returns negative",
          voleith_shipshape_witgen_register_construction(
              "stdlib/crypto/ring_sig/v1[bogus]", test_construction_backend) <
              0);

    /* Malformed: missing trailing ']'. */
    check("validate: malformed (no closing bracket) returns negative",
          voleith_shipshape_witgen_register_construction(
              "stdlib/crypto/ring_sig/v1[aes_dm", test_construction_backend) <
              0);

    /* Valid name. */
    check("validate: valid bracketed name returns 0",
          voleith_shipshape_witgen_register_construction(
              "stdlib/crypto/ring_sig/v1[aes_dm]", test_construction_backend) ==
              0);

    voleith_shipshape_witgen_reset();
}

int
main(void)
{
    printf("Running shipshape Tier 2a construction-dispatch tests (W8.5a)\n");

    test_region_recording();
    test_dispatch_fires();
    test_wrong_name_no_dispatch();
    test_nothing_registered();
    test_register_validation();

    printf("%d/%d tests passed\n", pass_count, test_count);
    return pass_count == test_count ? 0 : 1;
}
