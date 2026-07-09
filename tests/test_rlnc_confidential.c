/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * test_rlnc_confidential.c - Confidential RLNC codec tests, paper 2 scheme 1
 * (P7 T7.3).
 *
 * Tiers:
 *   ORACLE   - reproduce the paper's Figure 1 stages (docs/private/
 *              CONFIDENTIAL_RLNC_PAPER2_KAT.md).  The coding field poly is
 *              determined empirically (0x11D); the field-independent data path
 *              (T / permutation / T^{-1}) is reproduced byte-exact by the real
 *              codec.
 *   SELF     - shipped GF(2^16) self-consistency: encrypt/decrypt round-trip,
 *              precode reduces to the P3 RLNC encoder, T then T^{-1} identity,
 *              wrong perm / wrong L fail decryption.
 *   KEYGEN   - safe-default generation yields a valid permutation and a
 *              full-rank L; the validated bring-your-own path rejects a
 *              non-permutation table and a singular matrix.
 */

#include "rlnc_confidential.h"
#include "rlnc.h" /* P3 oracle: voleith_rlnc_encode + packet accessors */
#include "field16.h"
#include "erasure.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include "confrlnc_kat.inc"

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

/* Deterministic splitmix16 sample stream for the GF(2^16) self-consistency
 * tests. */
static uint64_t sm_state = UINT64_C(0xC0FFEE123);

static uint16_t
sm_next16(void)
{
    uint64_t z = (sm_state += UINT64_C(0x9E3779B97F4A7C15));
    z = (z ^ (z >> 30)) * UINT64_C(0xBF58476D1CE4E5B9);
    z = (z ^ (z >> 27)) * UINT64_C(0x94D049BB133111EB);
    z = z ^ (z >> 31);
    return (uint16_t)(z & 0xffff);
}

/* ---- test-local GF(2^8) multiply with a selectable reduction poly ---- */
static uint8_t
gf8_mul_poly(uint8_t a, uint8_t b, unsigned poly)
{
    uint8_t r = 0;
    for (int i = 0; i < 8; i++) {
        if (b & 1)
            r ^= a;
        uint8_t hi = (uint8_t)(a & 0x80);
        a = (uint8_t)(a << 1);
        if (hi)
            a ^= (uint8_t)(poly & 0xff);
        b >>= 1;
    }
    return r;
}

/* C[i][j] = sum_k L[i][k] * P[k][j] over GF(2^8) with the given poly. */
static void
gf8_matmul(const uint16_t *L, const uint16_t *P, uint16_t *C, size_t m,
           size_t l, unsigned poly)
{
    for (size_t i = 0; i < m; i++) {
        for (size_t j = 0; j < l; j++) {
            uint8_t acc = 0;
            for (size_t k = 0; k < m; k++)
                acc ^= gf8_mul_poly((uint8_t)L[i * m + k],
                                    (uint8_t)P[k * l + j], poly);
            C[i * l + j] = acc;
        }
    }
}

/* Greedily recover a permutation with out[i] = in[perm[i]] (the figures have
 * repeated nibbles, so any representative reproduces the stage). */
static int
recover_perm(const uint16_t *in, const uint16_t *out, size_t *perm, size_t n)
{
    uint8_t *used = calloc(n, 1);
    if (!used)
        return -1;
    for (size_t i = 0; i < n; i++) {
        size_t j;
        for (j = 0; j < n; j++)
            if (!used[j] && in[j] == out[i])
                break;
        if (j == n) {
            free(used);
            return -1; /* not a rearrangement: no source for out[i] */
        }
        used[j] = 1;
        perm[i] = j;
    }
    free(used);
    return 0;
}

/* =====================================================================
 * ORACLE 1: coding-field poly determination
 * ===================================================================== */
static void
test_poly_determination(void)
{
    uint16_t C[KAT1_M * KAT1_L_COLS];
    size_t n = KAT1_M * KAT1_L_COLS;

    /*
     * kat1_C is the CORRECT L.P (cell (row 2, col 0) holds 0x3F, the value the
     * paper misprints as 0x5F; see confrlnc_kat.inc).  Under the paper field
     * poly 0x11D, L.P reproduces it EXACTLY, in every cell.
     */
    gf8_matmul(kat1_L, kat1_P, C, KAT1_M, KAT1_L_COLS, 0x11D);
    int mismatch = 0;
    for (size_t i = 0; i < n; i++)
        if (C[i] != kat1_C[i])
            mismatch++;
    check("0x11D reproduces C = L.P exactly (paper field)", mismatch == 0);

    /* 0x11B (Rijndael) is not the paper field: it mismatches in many cells. */
    gf8_matmul(kat1_L, kat1_P, C, KAT1_M, KAT1_L_COLS, 0x11B);
    int mismatch_b = 0;
    for (size_t i = 0; i < n; i++)
        if (C[i] != kat1_C[i])
            mismatch_b++;
    check("0x11B (Rijndael) is not the paper field (many mismatches)",
          mismatch_b > 1);
}

/* =====================================================================
 * ORACLE 2: field-independent data path reproduces Fig 1 byte-exact
 * ===================================================================== */
static void
test_oracle_datapath(void)
{
    voleith_confrlnc_params_t p = {
        VOLEITH_EC_FIELD_GF8,
        KAT1_T,
        KAT1_M,
        KAT1_L_COLS,
    };

    uint16_t grid[KAT1_GRID];
    uint16_t mat[KAT1_M * KAT1_L_COLS];
    size_t perm[KAT1_GRID];

    /* T: split(C) == post-T. */
    check("split(C) == Fig 1 post-T",
          voleith_confrlnc_split(&p, kat1_C, grid) == 0 &&
              memcmp(grid, kat1_postT, sizeof(grid)) == 0);

    /* T^{-1}: join(post-T) == C. */
    check("join(post-T) == C",
          voleith_confrlnc_join(&p, kat1_postT, mat) == 0 &&
              memcmp(mat, kat1_C, sizeof(mat)) == 0);

    /* Permutation: a representative reproduces post-perm, multiset-preserving. */
    int rec = recover_perm(kat1_postT, kat1_postperm, perm, KAT1_GRID);
    check("post-T is a rearrangement of post-perm (multiset preserved)",
          rec == 0);
    if (rec == 0) {
        /* perm validity directly: in range and no repeats.  (validate_key is
         * not used here: it would also invert kat1_L under the library's
         * 0x11B, but the figure's field is 0x11D.) */
        int perm_valid = 1;
        uint8_t seen[KAT1_GRID] = {0};
        for (size_t i = 0; i < KAT1_GRID; i++) {
            if (perm[i] >= KAT1_GRID || seen[perm[i]]) {
                perm_valid = 0;
                break;
            }
            seen[perm[i]] = 1;
        }
        check("recovered perm is valid (permutation of [0,n))", perm_valid);
        check("permute(post-T, perm) == post-perm",
              voleith_confrlnc_permute(&p, kat1_postT, perm, grid) == 0 &&
                  memcmp(grid, kat1_postperm, sizeof(grid)) == 0);
        /* Decrypt direction: inverse permutation returns post-T. */
        check("permute_inverse(post-perm, perm) == post-T",
              voleith_confrlnc_permute_inverse(&p, kat1_postperm, perm, grid) ==
                      0 &&
                  memcmp(grid, kat1_postT, sizeof(grid)) == 0);
    }

    /* Final T^{-1}: join(post-perm) == data (M_C data block). */
    check("join(post-perm) == Fig 1 data block",
          voleith_confrlnc_join(&p, kat1_postperm, mat) == 0 &&
              memcmp(mat, kat1_data, sizeof(mat)) == 0);
}

/* =====================================================================
 * ORACLE 3 (scheme 2): precode self-consistency + Fig 3 data path
 * ===================================================================== */
static void
test_scheme2_oracle(void)
{
    voleith_confrlnc_params_t p = {
        VOLEITH_EC_FIELD_GF8,
        KAT1_T,
        KAT1_M,
        KAT1_L_COLS,
    };

    /* Precode transcription: the Fig 3 precode is C = L^{-1}.P, so the L
     * multiply recovers P.  Multiply-only (no custom-poly inverse needed):
     * L . kat2_precode == kat1_P over GF(2^8)/0x11D. */
    uint16_t P_back[KAT1_M * KAT1_L_COLS];
    gf8_matmul(kat1_L, kat2_precode, P_back, KAT1_M, KAT1_L_COLS, 0x11D);
    int precode_ok = (memcmp(P_back, kat1_P, sizeof(P_back)) == 0);
    check("scheme 2: L . Fig3-precode == P over 0x11D (precode = L^{-1}.P)",
          precode_ok);

    /* Field-independent data path: split(precode) -> permute -> join == data. */
    uint16_t grid[KAT1_GRID];
    uint16_t mat[KAT1_M * KAT1_L_COLS];
    size_t perm[KAT1_GRID];

    check("scheme 2: split(precode) == Fig 3 post-T",
          voleith_confrlnc_split(&p, kat2_precode, grid) == 0 &&
              memcmp(grid, kat2_postT, sizeof(grid)) == 0);

    int rec = recover_perm(kat2_postT, kat2_postperm, perm, KAT1_GRID);
    check("scheme 2: post-T is a rearrangement of post-perm", rec == 0);
    if (rec == 0) {
        check("scheme 2: permute(post-T) == Fig 3 post-perm",
              voleith_confrlnc_permute(&p, kat2_postT, perm, grid) == 0 &&
                  memcmp(grid, kat2_postperm, sizeof(grid)) == 0);
        check("scheme 2: permute_inverse(post-perm) == post-T",
              voleith_confrlnc_permute_inverse(&p, kat2_postperm, perm, grid) ==
                      0 &&
                  memcmp(grid, kat2_postT, sizeof(grid)) == 0);
    }

    check("scheme 2: join(post-perm) == Fig 3 data block",
          voleith_confrlnc_join(&p, kat2_postperm, mat) == 0 &&
              memcmp(mat, kat2_data, sizeof(mat)) == 0);
}

/* =====================================================================
 * SELF: shipped GF(2^16) self-consistency
 * ===================================================================== */
#define G_M 5u
#define G_L 7u
#define G_T 2u

static void
fill_random_matrix(uint16_t *mat, size_t n)
{
    for (size_t i = 0; i < n; i++)
        mat[i] = sm_next16();
}

static void
test_selfconsistency_gf16(void)
{
    voleith_confrlnc_params_t p = {VOLEITH_EC_FIELD_GF16, G_T, G_M, G_L};
    size_t n = voleith_confrlnc_grid_size(&p);
    size_t ms = voleith_confrlnc_matrix_size(&p);

    uint8_t seed[16];
    memset(seed, 0x5a, sizeof(seed));
    size_t *perm = calloc(n, sizeof(size_t));
    uint16_t *L = calloc(G_M * G_M, sizeof(uint16_t));
    uint16_t P[G_M * G_L], data[G_M * G_L], P2[G_M * G_L];

    int kg =
        voleith_confrlnc_keygen(&p, seed, sizeof(seed), 0xA1B2C3D4u, perm, L);
    check("keygen succeeds", kg == 0);

    fill_random_matrix(P, ms);

    /* encrypt then decrypt is the identity. */
    check("encrypt succeeds",
          voleith_confrlnc_encrypt(&p, L, perm, P, data) == 0);
    check("decrypt succeeds",
          voleith_confrlnc_decrypt(&p, L, perm, data, P2) == 0);
    check("decrypt(encrypt(P)) == P", memcmp(P, P2, sizeof(P)) == 0);

    /* T then T^{-1} is the identity. */
    uint16_t *grid = calloc(n, sizeof(uint16_t));
    uint16_t back[G_M * G_L];
    check("T then T^{-1} is identity",
          voleith_confrlnc_split(&p, P, grid) == 0 &&
              voleith_confrlnc_join(&p, grid, back) == 0 &&
              memcmp(P, back, sizeof(P)) == 0);
    free(grid);

    /* The precode (perm = identity) reduces to the P3 RLNC encoder row-wise:
     * row r of C = L.P equals voleith_rlnc_encode with coeffs = L row r. */
    uint16_t C[G_M * G_L];
    check("precode_encode succeeds",
          voleith_confrlnc_precode_encode(&p, L, P, C) == 0);

    size_t symbol_bytes = 2 * G_L;
    uint8_t sources[G_M * 2 * G_L];
    for (size_t r = 0; r < G_M; r++)
        for (size_t c = 0; c < G_L; c++)
            voleith_gf16_to_bytes(sources + r * symbol_bytes + 2 * c,
                                  P[r * G_L + c]);

    int precode_matches = 1;
    uint8_t packet[VOLEITH_RLNC_GEN_ID_BYTES + 2 * G_M + 2 * G_L];
    for (size_t r = 0; r < G_M; r++) {
        voleith_gf16_t coeffs[G_M];
        for (size_t j = 0; j < G_M; j++)
            coeffs[j] = L[r * G_M + j];
        if (voleith_rlnc_encode(1u, sources, G_M, symbol_bytes, coeffs,
                                packet) != 0) {
            precode_matches = 0;
            break;
        }
        const uint8_t *pay = voleith_rlnc_packet_payload(packet, G_M);
        for (size_t c = 0; c < G_L; c++) {
            if (voleith_gf16_from_bytes(pay + 2 * c) != C[r * G_L + c]) {
                precode_matches = 0;
                break;
            }
        }
    }
    check("precode row r == P3 voleith_rlnc_encode(L row r)", precode_matches);

    /* Wrong permutation fails to recover P. */
    size_t *perm2 = calloc(n, sizeof(size_t));
    uint16_t Lw[G_M * G_M];
    int kg2 =
        voleith_confrlnc_keygen(&p, seed, sizeof(seed), 0x99999999u, perm2, Lw);
    uint16_t Pbad[G_M * G_L];
    check("decrypt with wrong perm != P",
          kg2 == 0 && voleith_confrlnc_decrypt(&p, L, perm2, data, Pbad) == 0 &&
              memcmp(P, Pbad, sizeof(P)) != 0);

    /* Wrong L fails to recover P. */
    check("decrypt with wrong L != P",
          voleith_confrlnc_decrypt(&p, Lw, perm, data, Pbad) == 0 &&
              memcmp(P, Pbad, sizeof(P)) != 0);

    free(perm);
    free(perm2);
    free(L);
}

/* =====================================================================
 * SELF (scheme 2): GF(2^16) round-trip, precode inverse, framing with n
 * ===================================================================== */
static void
test_scheme2_selfconsistency_gf16(void)
{
    voleith_confrlnc_params_t p = {VOLEITH_EC_FIELD_GF16, G_T, G_M, G_L};
    size_t n = voleith_confrlnc_grid_size(&p);
    size_t ms = voleith_confrlnc_matrix_size(&p);

    uint8_t seed[16];
    memset(seed, 0x3c, sizeof(seed));
    size_t *perm = calloc(n, sizeof(size_t));
    uint16_t *L = calloc(G_M * G_M, sizeof(uint16_t));
    uint16_t P[G_M * G_L], data[G_M * G_L], P2[G_M * G_L];

    int kg =
        voleith_confrlnc_keygen(&p, seed, sizeof(seed), 0x0BADF00Du, perm, L);
    check("scheme 2: keygen succeeds", kg == 0);
    fill_random_matrix(P, ms);

    /* encrypt_s2 then decrypt_s2 is the identity. */
    check("scheme 2: encrypt_s2 succeeds",
          voleith_confrlnc_encrypt_s2(&p, L, perm, P, data) == 0);
    check("scheme 2: decrypt_s2 succeeds",
          voleith_confrlnc_decrypt_s2(&p, L, perm, data, P2) == 0);
    check("scheme 2: decrypt_s2(encrypt_s2(P)) == P",
          memcmp(P, P2, sizeof(P)) == 0);

    /* precode_encode_s2 (C = L^{-1}.P) then precode_decode_s2 (P = L.C) is the
     * identity, and the roles are inverted vs scheme 1. */
    uint16_t C[G_M * G_L], Pr[G_M * G_L], C1[G_M * G_L];
    check("scheme 2: precode_encode_s2 succeeds",
          voleith_confrlnc_precode_encode_s2(&p, L, P, C) == 0);
    check("scheme 2: precode_decode_s2(precode_encode_s2(P)) == P",
          voleith_confrlnc_precode_decode_s2(&p, L, C, Pr) == 0 &&
              memcmp(P, Pr, sizeof(P)) == 0);
    /* scheme-2 encode == scheme-1 decode (both multiply by L^{-1}). */
    uint16_t Cs1[G_M * G_L];
    check("scheme 2 precode_encode_s2 == scheme 1 precode_decode",
          voleith_confrlnc_precode_decode(&p, L, P, Cs1) == 0 &&
              memcmp(C, Cs1, sizeof(C)) == 0);
    /* scheme-2 decode == scheme-1 encode (both multiply by L). */
    check("scheme 2 precode_decode_s2 == scheme 1 precode_encode",
          voleith_confrlnc_precode_encode(&p, L, C, C1) == 0 &&
              voleith_confrlnc_precode_decode_s2(&p, L, C, Pr) == 0 &&
              memcmp(C1, Pr, sizeof(Pr)) == 0);

    /* Framing with the n sync column round-trips. */
    size_t cols2 = voleith_confrlnc_transmitted_cols_s2(&p);
    check("scheme 2: transmitted_cols_s2 == m + 1 + l",
          cols2 == G_M + 1u + G_L);
    uint16_t nsync[G_M];
    for (size_t r = 0; r < G_M; r++)
        nsync[r] = (uint16_t)(0x1000u + r);
    uint16_t *mc = calloc(G_M * cols2, sizeof(uint16_t));
    uint16_t n_back[G_M], data_back[G_M * G_L];
    check("scheme 2: attach_identity_s2 succeeds",
          voleith_confrlnc_attach_identity_s2(&p, nsync, data, mc) == 0);
    /* Identity block in place. */
    int ident_ok = 1;
    for (size_t r = 0; r < G_M; r++)
        for (size_t cc = 0; cc < G_M; cc++)
            if (mc[r * cols2 + cc] != (cc == r ? 1u : 0u))
                ident_ok = 0;
    check("scheme 2: M_C identity block correct", ident_ok);
    check("scheme 2: strip_identity_s2 recovers n and data",
          voleith_confrlnc_strip_identity_s2(&p, mc, n_back, data_back) == 0 &&
              memcmp(nsync, n_back, sizeof(nsync)) == 0 &&
              memcmp(data, data_back, sizeof(data)) == 0);

    /* singular L is rejected by the s2 precode. */
    uint16_t Lsing[G_M * G_M];
    memcpy(Lsing, L, sizeof(Lsing));
    for (size_t j = 0; j < G_M; j++)
        Lsing[0 * G_M + j] = 0; /* zero row -> singular */
    check("scheme 2: encrypt_s2 rejects singular L",
          voleith_confrlnc_encrypt_s2(&p, Lsing, perm, P, data) ==
              VOLEITH_EC_ERR_SINGULAR);

    free(mc);
    free(perm);
    free(L);
}

/* =====================================================================
 * KEYGEN: safe-default generation and validated bring-your-own
 * ===================================================================== */
static void
test_keygen_and_validate(void)
{
    voleith_confrlnc_params_t p = {VOLEITH_EC_FIELD_GF16, G_T, G_M, G_L};
    size_t n = voleith_confrlnc_grid_size(&p);

    uint8_t seed[16];
    memset(seed, 0x77, sizeof(seed));
    size_t *perm = calloc(n, sizeof(size_t));
    uint16_t *L = calloc(G_M * G_M, sizeof(uint16_t));

    /* Derived key is always valid: permutation + full-rank L. */
    int all_valid = 1;
    int image0_varies = 0;
    size_t first_image0 = 0;
    for (uint32_t g = 0; g < 32; g++) {
        if (voleith_confrlnc_keygen(&p, seed, sizeof(seed), g, perm, L) != 0 ||
            voleith_confrlnc_validate_key(&p, L, perm) != 0) {
            all_valid = 0;
            break;
        }
        if (g == 0)
            first_image0 = perm[0];
        else if (perm[0] != first_image0)
            image0_varies = 1;
    }
    check("safe keygen always yields a valid permutation + full-rank L",
          all_valid);
    check("derived permutation is not fixed across generation ids (uniformity "
          "sanity)",
          image0_varies);

    /* Determinism (wire contract): the same (seed, generation_id) must yield a
     * byte-identical permutation + L.  This guards the constant-time shuffle
     * against an accidental change in the generated key. */
    {
        size_t *perm2 = calloc(n, sizeof(size_t));
        uint16_t *L2 = calloc(G_M * G_M, sizeof(uint16_t));
        int kg1 = voleith_confrlnc_keygen(&p, seed, sizeof(seed), 7u, perm, L);
        int kg2 =
            voleith_confrlnc_keygen(&p, seed, sizeof(seed), 7u, perm2, L2);
        int same = (kg1 == 0 && kg2 == 0);
        for (size_t i = 0; same && i < n; i++)
            same &= (perm[i] == perm2[i]);
        for (size_t i = 0; same && i < (size_t)(G_M * G_M); i++)
            same &= (L[i] == L2[i]);
        check("keygen is deterministic for a fixed (seed, generation_id)",
              same);
        free(perm2);
        free(L2);
    }

    /* Validated bring-your-own rejects a non-permutation table. */
    voleith_confrlnc_keygen(&p, seed, sizeof(seed), 1u, perm, L);
    size_t saved = perm[1];
    perm[1] = perm[0]; /* duplicate -> not a permutation */
    check("validate rejects a non-permutation table",
          voleith_confrlnc_validate_key(&p, L, perm) == VOLEITH_EC_ERR_PARAM);
    perm[1] = saved;

    /* Validated bring-your-own rejects an out-of-range entry (perm[i] >= n). */
    perm[1] = SIZE_MAX;
    check("validate rejects an out-of-range permutation entry",
          voleith_confrlnc_validate_key(&p, L, perm) == VOLEITH_EC_ERR_PARAM);
    perm[1] = saved;

    /* Validated bring-your-own rejects a singular L (all-zero row). */
    for (size_t j = 0; j < G_M; j++)
        L[0 * G_M + j] = 0;
    check("validate rejects a singular L",
          voleith_confrlnc_validate_key(&p, L, perm) ==
              VOLEITH_EC_ERR_SINGULAR);

    /* Misuse tripwire: keygen rejects an all-zero seed (uninitialized buffer). */
    {
        uint8_t zero_seed[16];
        memset(zero_seed, 0, sizeof(zero_seed));
        check("keygen rejects an all-zero seed",
              voleith_confrlnc_keygen(&p, zero_seed, sizeof(zero_seed), 0u,
                                      perm, L) == VOLEITH_EC_ERR_PARAM);
    }

    free(perm);
    free(L);
}

int
main(void)
{
    printf("=== Confidential RLNC codec, schemes 1 + 2 (T7.3 / T7.4) ===\n");
    test_poly_determination();
    test_oracle_datapath();
    test_scheme2_oracle();
    test_selfconsistency_gf16();
    test_scheme2_selfconsistency_gf16();
    test_keygen_and_validate();
    printf("%d/%d tests passed\n", pass_count, test_count);
    return pass_count == test_count ? 0 : 1;
}
