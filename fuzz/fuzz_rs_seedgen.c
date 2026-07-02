/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * fuzz_rs_seedgen.c - regenerate the seed inputs for the ring-signature
 * fuzz harnesses.  A composable ring signature is binary and cannot be
 * hand-written like the .ship / Bristol text seeds, so this small program
 * produces them from the same fixed configuration the harnesses use
 * (fuzz_rs_common.h): it builds the reference ring, signs the fixed message
 * as member #FUZZ_RS_SIGNER, and writes
 *
 *   <outdir>/rs_unpack/valid_seed   the packed "VRSC" envelope
 *   <outdir>/rs_verify/valid_seed   the raw inner proof bytes
 *
 * Because the harnesses rebuild the identical ring (same sks, depth, hash,
 * params), these seeds verify / unpack cleanly and steer the fuzzer past
 * the cheap header rejections into the deep parse / verify paths.
 *
 * Usage: fuzz_rs_seedgen [outdir]   (default outdir: fuzz/corpus-work)
 *
 * The seeds are binary and regenerable, so they live under the gitignored
 * corpus-work/ tree rather than the committed text seed corpus.  Built only
 * under -DVOLEITH_FUZZ=ON; see fuzz/README.md.
 */

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "fuzz_rs_common.h"

static int
write_file(const char *path, const uint8_t *buf, size_t len)
{
    FILE *f = fopen(path, "wb");
    if (f == NULL) {
        fprintf(stderr, "seedgen: cannot open %s for writing\n", path);
        return -1;
    }
    if (len != 0 && fwrite(buf, 1, len, f) != len) {
        fprintf(stderr, "seedgen: short write to %s\n", path);
        fclose(f);
        return -1;
    }
    fclose(f);
    printf("seedgen: wrote %zu bytes to %s\n", len, path);
    return 0;
}

int
main(int argc, char **argv)
{
    const char *outdir = (argc > 1) ? argv[1] : "fuzz/corpus-work";
    char path[1024];

    voleith_rs_config_t cfg;
    voleith_params_t params = voleith_params_em_128f;
    uint8_t sks[FUZZ_RS_N_MEMBERS * FUZZ_RS_SK_BYTES];
    uint8_t sib[FUZZ_RS_N_MEMBERS * FUZZ_RS_DEPTH_M * MERKLE_VT_MAX_NODE_BYTES];
    voleith_rs_path_t paths[FUZZ_RS_N_MEMBERS];
    uint8_t root[MERKLE_VT_MAX_NODE_BYTES];
    voleith_rs_public_t pub;
    voleith_rs_sig_t sig = {NULL, 0};
    uint8_t *packed = NULL;
    size_t packed_len;
    int rc = 1;

    fuzz_rs_make_cfg(&cfg);
    fuzz_rs_fill_sks(sks);

    if (voleith_rs_ring_build(&cfg, sks, NULL, FUZZ_RS_N_MEMBERS, root, paths,
                              sib) != 0) {
        fprintf(stderr, "seedgen: ring_build failed\n");
        return 1;
    }

    memset(&pub, 0, sizeof(pub));
    pub.membership_root = root;

    if (voleith_rs_sign(
            &sig, &cfg, &params, sks + FUZZ_RS_SIGNER * FUZZ_RS_SK_BYTES, NULL,
            &paths[FUZZ_RS_SIGNER], &pub, (const uint8_t *)FUZZ_RS_MESSAGE,
            FUZZ_RS_MESSAGE_LEN) != 0) {
        fprintf(stderr, "seedgen: sign failed\n");
        return 1;
    }

    /* Sanity: the seed must verify, or it would not steer the verify fuzzer. */
    if (voleith_rs_verify(&sig, &cfg, &params, &pub,
                          (const uint8_t *)FUZZ_RS_MESSAGE,
                          FUZZ_RS_MESSAGE_LEN) != 0) {
        fprintf(stderr, "seedgen: self-verify failed\n");
        goto out;
    }

    /* Raw proof -> rs_verify seed. */
    snprintf(path, sizeof(path), "%s/rs_verify/valid_seed", outdir);
    if (write_file(path, sig.data, sig.len) != 0)
        goto out;

    /* Packed "VRSC" envelope -> rs_unpack seed. */
    packed_len = voleith_rs_sig_packed_len(&sig);
    packed = malloc(packed_len != 0 ? packed_len : 1);
    if (packed == NULL) {
        fprintf(stderr, "seedgen: alloc failed\n");
        goto out;
    }
    if (voleith_rs_sig_pack(packed, packed_len, NULL, &sig, &cfg, &params) !=
        0) {
        fprintf(stderr, "seedgen: pack failed\n");
        goto out;
    }
    snprintf(path, sizeof(path), "%s/rs_unpack/valid_seed", outdir);
    if (write_file(path, packed, packed_len) != 0)
        goto out;

    rc = 0;
out:
    free(packed);
    voleith_rs_sig_free(&sig);
    return rc;
}
