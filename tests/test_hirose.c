/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * test_hirose.c - Tests for the Hirose DBL compression primitive.
 *
 * Tests:
 *   1: Output matches the spec formula computed independently via
 *      voleith_aes_encrypt (in-test reference).
 *   2: In-place call (G_out == G) produces the same result as a
 *      non-aliasing call.
 *   3: Changing c_const changes the output (c is actually consumed).
 *   4: Changing M changes K (and therefore both outputs).
 *   5: Different (G,H) inputs produce different outputs (sanity).
 *   6: G_next and H_next are not equal in a generic case (the c-tweak
 *      genuinely differentiates the two halves of the output).
 *   7: G_next matches a value derived by hand from FIPS 197 Appendix
 *      C.3 (AES-256 KAT) - third-party anchor for the G_out path.
 *      No canonical Hirose-AES-256 KAT exists in NIST/ISO/IETF
 *      publications or in the original Hirose FSE 2006 paper (which
 *      is a theoretical security analysis without numerical
 *      vectors), so this is the strongest external grounding
 *      available.
 */

#include "../core/hirose.h"
#include "../core/aes.h"
#include <stdio.h>
#include <string.h>
#include <stdint.h>

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

/* In-test reference: directly apply the spec equations using the
 * voleith AES API.  Independent of voleith_hirose_iteration so it
 * actually validates the primitive. */
static void
hirose_iteration_ref(const uint8_t G[16], const uint8_t H[16],
                     const uint8_t M[16], const uint8_t c_const[16],
                     uint8_t G_out[16], uint8_t H_out[16])
{
    uint8_t key[32];
    memcpy(key, H, 16);
    memcpy(key + 16, M, 16);

    voleith_aes_ctx_t ctx;
    voleith_aes_key_expand(&ctx, key, 256);

    uint8_t E_G[16];
    voleith_aes_encrypt(&ctx, E_G, G);
    for (int i = 0; i < 16; i++)
        G_out[i] = E_G[i] ^ G[i];

    uint8_t Gxc[16];
    for (int i = 0; i < 16; i++)
        Gxc[i] = G[i] ^ c_const[i];
    uint8_t E_Gxc[16];
    voleith_aes_encrypt(&ctx, E_Gxc, Gxc);
    for (int i = 0; i < 16; i++)
        H_out[i] = E_Gxc[i] ^ Gxc[i];

    voleith_aes_ctx_clear(&ctx);
}

/* Standard test vectors used across cases. */
static const uint8_t G_IN[16] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55,
                                 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb,
                                 0xcc, 0xdd, 0xee, 0xff};
static const uint8_t H_IN[16] = {0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54,
                                 0x32, 0x10, 0x01, 0x23, 0x45, 0x67,
                                 0x89, 0xab, 0xcd, 0xef};
static const uint8_t M_IN[16] = {0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe,
                                 0xba, 0xbe, 0x01, 0x23, 0x45, 0x67,
                                 0x89, 0xab, 0xcd, 0xef};
static const uint8_t C_IN[16] = {'V', 'O', 'L', 'E', 'i', 'T', 'H', '-',
                                 'H', 'i', 'r', 'o', 's', 'e', '-', 'N'};

static void
test_matches_reference(void)
{
    uint8_t G_ref[16], H_ref[16];
    hirose_iteration_ref(G_IN, H_IN, M_IN, C_IN, G_ref, H_ref);

    uint8_t G_out[16], H_out[16];
    voleith_hirose_iteration(G_IN, H_IN, M_IN, C_IN, G_out, H_out);

    check("Hirose: G_next matches independent reference",
          memcmp(G_out, G_ref, 16) == 0);
    check("Hirose: H_next matches independent reference",
          memcmp(H_out, H_ref, 16) == 0);
}

static void
test_in_place_safe(void)
{
    uint8_t G_ref[16], H_ref[16];
    voleith_hirose_iteration(G_IN, H_IN, M_IN, C_IN, G_ref, H_ref);

    /* G_out aliases G; H_out aliases H. */
    uint8_t G_alias[16], H_alias[16];
    memcpy(G_alias, G_IN, 16);
    memcpy(H_alias, H_IN, 16);
    voleith_hirose_iteration(G_alias, H_alias, M_IN, C_IN, G_alias, H_alias);

    check("Hirose: in-place G_out=G yields the same G_next",
          memcmp(G_alias, G_ref, 16) == 0);
    check("Hirose: in-place H_out=H yields the same H_next",
          memcmp(H_alias, H_ref, 16) == 0);
}

static void
test_c_is_consumed(void)
{
    uint8_t G_a[16], H_a[16];
    voleith_hirose_iteration(G_IN, H_IN, M_IN, C_IN, G_a, H_a);

    uint8_t c_alt[16];
    memcpy(c_alt, C_IN, 16);
    c_alt[0] ^= 0x01;
    uint8_t G_b[16], H_b[16];
    voleith_hirose_iteration(G_IN, H_IN, M_IN, c_alt, G_b, H_b);

    /* G_next does not depend on c, so it should be unchanged. */
    check("Hirose: G_next is independent of c", memcmp(G_a, G_b, 16) == 0);
    /* H_next depends on c, so it must change. */
    check("Hirose: H_next changes when c changes", memcmp(H_a, H_b, 16) != 0);
}

static void
test_m_changes_key(void)
{
    uint8_t G_a[16], H_a[16];
    voleith_hirose_iteration(G_IN, H_IN, M_IN, C_IN, G_a, H_a);

    uint8_t M_alt[16];
    memcpy(M_alt, M_IN, 16);
    M_alt[7] ^= 0x80;
    uint8_t G_b[16], H_b[16];
    voleith_hirose_iteration(G_IN, H_IN, M_alt, C_IN, G_b, H_b);

    /* K = H || M, so flipping a bit of M reshapes the key for both
     * encryptions.  Both halves of the output must change. */
    check("Hirose: G_next changes when M changes", memcmp(G_a, G_b, 16) != 0);
    check("Hirose: H_next changes when M changes", memcmp(H_a, H_b, 16) != 0);
}

static void
test_inputs_differentiate(void)
{
    uint8_t G_a[16], H_a[16];
    voleith_hirose_iteration(G_IN, H_IN, M_IN, C_IN, G_a, H_a);

    uint8_t G_alt[16];
    memcpy(G_alt, G_IN, 16);
    G_alt[0] ^= 0x01;
    uint8_t G_b[16], H_b[16];
    voleith_hirose_iteration(G_alt, H_IN, M_IN, C_IN, G_b, H_b);

    check("Hirose: G_next changes when G changes", memcmp(G_a, G_b, 16) != 0);
    check("Hirose: H_next changes when G changes", memcmp(H_a, H_b, 16) != 0);

    uint8_t H_alt[16];
    memcpy(H_alt, H_IN, 16);
    H_alt[15] ^= 0x40;
    voleith_hirose_iteration(G_IN, H_alt, M_IN, C_IN, G_b, H_b);

    check("Hirose: G_next changes when H changes", memcmp(G_a, G_b, 16) != 0);
    check("Hirose: H_next changes when H changes", memcmp(H_a, H_b, 16) != 0);
}

static void
test_halves_differ(void)
{
    uint8_t G_out[16], H_out[16];
    voleith_hirose_iteration(G_IN, H_IN, M_IN, C_IN, G_out, H_out);
    check("Hirose: G_next != H_next (c-tweak actually differentiates halves)",
          memcmp(G_out, H_out, 16) != 0);
}

/* ================================================================
 * Test 7: G_next anchored to FIPS 197 Appendix C.3 (AES-256 KAT).
 *
 * Construction:
 *   H_FIPS = K_FIPS[ 0..15] = 00 01 02 ... 0e 0f
 *   M_FIPS = K_FIPS[16..31] = 10 11 12 ... 1e 1f
 *   G_FIPS = P_FIPS         = 00 11 22 33 44 55 66 77
 *                              88 99 aa bb cc dd ee ff
 *
 * Then K = H_FIPS || M_FIPS = K_FIPS, and by FIPS 197 Appendix C.3:
 *   AES_K(G_FIPS) = C_FIPS  = 8e a2 b7 ca 51 67 45 bf
 *                              ea fc 49 90 4b 49 60 89
 *
 * The Hirose spec gives G_out = AES_K(G) XOR G, so:
 *   G_OUT_EXPECTED = C_FIPS XOR P_FIPS
 *                  = 8e b3 95 f9 15 32 23 c8
 *                    62 65 e3 2b 87 94 8e 76
 *
 * Any reader can verify G_OUT_EXPECTED independently from FIPS 197
 * without computing any AES themselves.  Matching this value
 * confirms three things at once: the H||M -> K assembly order, the
 * "G as plaintext" plaintext assignment, and the "AES_K(G) XOR G"
 * output formula.  H_next is still checked against the in-test
 * reference because FIPS 197 publishes only one (key, pt, ct)
 * triple per key and so cannot directly pin the second encryption
 * AES_K(G XOR c).
 * ================================================================ */
static void
test_g_next_matches_fips197_c3(void)
{
    static const uint8_t K_FIPS[32] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a,
        0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15,
        0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f};
    static const uint8_t P_FIPS[16] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55,
                                       0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb,
                                       0xcc, 0xdd, 0xee, 0xff};
    static const uint8_t G_OUT_EXPECTED[16] = {
        0x8e, 0xb3, 0x95, 0xf9, 0x15, 0x32, 0x23, 0xc8,
        0x62, 0x65, 0xe3, 0x2b, 0x87, 0x94, 0x8e, 0x76};

    /* c can be anything nonzero; choose a distinct test value so this
     * test is independent of the inode/leaf constants chosen later
     * for the vt.  This c is local to this test only. */
    static const uint8_t c_local[16] = {0xa5, 0x5a, 0x01, 0x02, 0x03, 0x04,
                                        0x05, 0x06, 0x07, 0x08, 0x09, 0x0a,
                                        0x0b, 0x0c, 0x0d, 0x0e};

    const uint8_t *H_in = &K_FIPS[0];
    const uint8_t *M_in = &K_FIPS[16];
    const uint8_t *G_in = P_FIPS;

    uint8_t G_out[16], H_out[16];
    voleith_hirose_iteration(G_in, H_in, M_in, c_local, G_out, H_out);

    /* Load-bearing assertion: G_out matches the value derived by
     * hand from FIPS 197 + spec equation. */
    check("Hirose: G_next matches FIPS 197 C.3 (C_FIPS XOR P_FIPS)",
          memcmp(G_out, G_OUT_EXPECTED, 16) == 0);

    /* Cross-check: H_next still agrees with the in-test reference. */
    uint8_t G_ref[16], H_ref[16];
    hirose_iteration_ref(G_in, H_in, M_in, c_local, G_ref, H_ref);
    check("Hirose: G_next FIPS-derived value agrees with in-test reference",
          memcmp(G_ref, G_OUT_EXPECTED, 16) == 0);
    check("Hirose: H_next matches in-test reference (FIPS inputs)",
          memcmp(H_out, H_ref, 16) == 0);
}

int
main(void)
{
    printf("test_hirose: Hirose DBL compression primitive\n");

    test_matches_reference();
    test_in_place_safe();
    test_c_is_consumed();
    test_m_changes_key();
    test_inputs_differentiate();
    test_halves_differ();
    test_g_next_matches_fips197_c3();

    printf("  %d / %d passed\n", pass_count, test_count);
    return (pass_count == test_count) ? 0 : 1;
}
