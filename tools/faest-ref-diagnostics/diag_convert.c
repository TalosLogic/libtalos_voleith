/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * Diagnostic: print u/c/vs/qs from vole_commit+reconstruct for FAEST_EM_128F
 * Build: gcc -DFAEST_TESTS -DHAVE_CONFIG_H -I. -Ibuild -Isha3 diag_convert.c \
 *        -o build/diag_convert build/libfaest_no_random.a build/libfaest.a
 */

#include "vole.h"
#include "bavc.h"
#include "instances.h"
#include "aes.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define UNIVERSAL_HASH_B_BITS 16

static void
print_hex(const char *label, const uint8_t *data, size_t len)
{
    printf("%s: ", label);
    for (size_t i = 0; i < len; i++)
        printf("%02x", data[i]);
    printf("\n");
}

int
main(void)
{
    const faest_paramset_t *params = faest_get_paramset(FAEST_EM_128F);
    if (!params) {
        fprintf(stderr, "bad params\n");
        return 1;
    }

    unsigned int lambda = params->lambda;
    unsigned int lambda_bytes = lambda / 8;
    unsigned int ell_hat = params->l + lambda * 3 + UNIVERSAL_HASH_B_BITS;
    unsigned int ell_hat_bytes = (ell_hat + 7) / 8;
    unsigned int tau = params->tau;

    printf(
        "lambda=%u tau=%u k=%u tau1=%u L=%u l=%u ell_hat=%u ell_hat_bytes=%u\n",
        lambda, tau, params->k, params->tau1, params->L, params->l, ell_hat,
        ell_hat_bytes);

    uint8_t root_key[16];
    for (int i = 0; i < 16; i++)
        root_key[i] = (uint8_t)i;
    uint8_t iv[16] = {0};

    uint8_t *c = calloc((tau - 1) * ell_hat_bytes, 1);
    uint8_t *u = calloc(ell_hat_bytes, 1);
    uint8_t **v = calloc(lambda, sizeof(uint8_t *));
    uint8_t *vs = calloc(lambda * ell_hat_bytes, 1);
    for (unsigned int i = 0; i < lambda; i++)
        v[i] = vs + i * ell_hat_bytes;

    bavc_t bavc_com;
    vole_commit(root_key, iv, ell_hat, params, &bavc_com, c, u, v);

    print_hex("u[0..15]", u, 16);
    print_hex("bavc->sd[0]", bavc_com.sd, 16);

    /* Full hex for external hashing */
    printf("\nFULL_U=");
    for (unsigned int i = 0; i < ell_hat_bytes; i++)
        printf("%02x", u[i]);
    printf("\n");

    printf("FULL_C=");
    for (unsigned int i = 0; i < (tau - 1) * ell_hat_bytes; i++)
        printf("%02x", c[i]);
    printf("\n");

    printf("FULL_VS=");
    for (unsigned int i = 0; i < lambda * ell_hat_bytes; i++)
        printf("%02x", vs[i]);
    printf("\n");

    /* Reconstruct with challenge from vole_tvs.hpp */
    static const uint8_t chall[16] = {
        0x3a, 0x1f, 0x5b, 0x13, 0x14, 0x24, 0x53, 0xe3,
        0x06, 0x11, 0x8d, 0x26, 0x67, 0x09, 0xc1, 0x00,
    };

    const unsigned int com_size = 2 * lambda_bytes;
    uint8_t *decom_i =
        calloc(com_size * tau + params->T_open * lambda_bytes, 1);
    uint16_t i_delta[MAX_TAU];

    if (!decode_all_chall_3(i_delta, chall, params)) {
        fprintf(stderr, "decode_all_chall_3 failed\n");
        goto done;
    }
    if (!bavc_open(decom_i, &bavc_com, i_delta, params)) {
        fprintf(stderr, "bavc_open failed for this challenge\n");
        goto done;
    }

    {
        uint8_t *hcom = calloc(lambda_bytes * 2, 1);
        uint8_t **q = calloc(lambda, sizeof(uint8_t *));
        uint8_t *qs = calloc(lambda * ell_hat_bytes, 1);
        for (unsigned int i = 0; i < lambda; i++)
            q[i] = qs + i * ell_hat_bytes;

        bool ok =
            vole_reconstruct(hcom, q, iv, chall, decom_i, c, ell_hat, params);
        printf("vole_reconstruct: %s\n", ok ? "OK" : "FAIL");

        printf("FULL_QS=");
        for (unsigned int i = 0; i < lambda * ell_hat_bytes; i++)
            printf("%02x", qs[i]);
        printf("\n");

        free(hcom);
        free(q);
        free(qs);
    }

done:
    free(decom_i);
    bavc_clear(&bavc_com);
    free(c);
    free(u);
    free(v);
    free(vs);
    return 0;
}
