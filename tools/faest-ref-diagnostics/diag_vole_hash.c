/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * Diagnostic: print VOLEHash test vectors for λ=128, 192, 256
 * Build (from faest-ref directory):
 *   gcc -DFAEST_TESTS -DHAVE_CONFIG_H -I. -Ibuild -Isha3 diag_vole_hash.c \
 *       -o build/diag_vole_hash build/libfaest_no_random.a build/libfaest.a
 * Run:
 *   ./build/diag_vole_hash
 */

#include "universal_hashing.h"
#include <stdio.h>
#include <stdint.h>
#include <string.h>

#define UNIVERSAL_HASH_B 2 /* bytes */

static void
print_c_array(const char *name, const uint8_t *data, size_t len)
{
    printf("    static const uint8_t %s[] = {", name);
    for (size_t i = 0; i < len; i++) {
        if (i % 12 == 0)
            printf("\n        ");
        printf("0x%02x,", data[i]);
        if (i % 12 != 11 && i + 1 < len)
            printf(" ");
    }
    printf("\n    };\n");
}

static void
run(unsigned int lambda, unsigned int ell, const uint8_t *sd, const uint8_t *x)
{
    unsigned int nb = lambda / 8;
    unsigned int h_size = nb + UNIVERSAL_HASH_B;
    size_t sd_len = 5 * nb + 8;
    size_t x_len =
        (ell + 3 * lambda) / 8 + UNIVERSAL_HASH_B; /* = ellhat_bytes */
    uint8_t h[32 + UNIVERSAL_HASH_B] = {0};

    vole_hash(h, sd, x, ell, lambda);

    printf("    /* lambda=%u, ell=%u */\n", lambda, ell);
    printf("    {\n");
    print_c_array("sd", sd, sd_len);
    print_c_array("x", x, x_len);
    print_c_array("expected_h", h, h_size);
    printf("    }\n\n");
}

int
main(void)
{
    /*
     * Fixed, deterministic inputs:
     *   sd: 0x00, 0x01, 0x02, ...
     *   x:  0xaa, 0xab, 0xac, ...
     * ell = 200 bits (exercises multi-chunk Horner path for all λ)
     */
    const unsigned int ell = 200;

    /* x_size = ellhat_bytes = (ell + 3*lambda + 16) / 8 = (ell + 3*lambda)/8 + 2
     * λ=128: (200+384)/8+2 = 75 bytes;  sd=88 bytes;  h=18 bytes */
    {
        uint8_t sd[5 * 16 + 8];
        uint8_t x[(200 + 3 * 128) / 8 + UNIVERSAL_HASH_B];
        for (size_t i = 0; i < sizeof(sd); i++)
            sd[i] = (uint8_t)i;
        for (size_t i = 0; i < sizeof(x); i++)
            x[i] = (uint8_t)(0xaa + i);
        run(128, ell, sd, x);
    }

    /* λ=192: (200+576)/8+2 = 99 bytes;  sd=128 bytes;  h=26 bytes */
    {
        uint8_t sd[5 * 24 + 8];
        uint8_t x[(200 + 3 * 192) / 8 + UNIVERSAL_HASH_B];
        for (size_t i = 0; i < sizeof(sd); i++)
            sd[i] = (uint8_t)i;
        for (size_t i = 0; i < sizeof(x); i++)
            x[i] = (uint8_t)(0xaa + i);
        run(192, ell, sd, x);
    }

    /* λ=256: (200+768)/8+2 = 123 bytes;  sd=168 bytes;  h=34 bytes */
    {
        uint8_t sd[5 * 32 + 8];
        uint8_t x[(200 + 3 * 256) / 8 + UNIVERSAL_HASH_B];
        for (size_t i = 0; i < sizeof(sd); i++)
            sd[i] = (uint8_t)i;
        for (size_t i = 0; i < sizeof(x); i++)
            x[i] = (uint8_t)(0xaa + i);
        run(256, ell, sd, x);
    }

    return 0;
}
