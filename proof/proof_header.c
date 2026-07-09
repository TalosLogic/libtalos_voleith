/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * proof_header.c - Parse and serialize the 48-byte proof metadata header.
 *
 * Only the statically-constrained fixed prefix (bytes 0..15) is validated
 * here.  The two trailing 16-byte fingerprints are opaque blobs at this
 * layer; their meaning is established by the fingerprint helpers and the
 * identity check that arrive in a later step.
 */

#include "proof_header.h"

#include "../core/util.h"
#include "circuit_fingerprint.h"
#include "gf8_circuit_fingerprint.h"
#include "gf16_circuit_fingerprint.h"
#include "params_fingerprint.h"

#include <string.h>

/* ================================================================
 * Helpers
 * ================================================================ */

/*
 * Returns 1 if every field of the fixed prefix is in range, 0 otherwise.
 * Encapsulates the constraints shared by parse and serialize so the two
 * paths cannot disagree.
 */
static int
fixed_prefix_valid(const uint8_t magic[4], uint8_t format_version,
                   uint8_t fs_kind, uint8_t bavc_kind, uint8_t param_set_id,
                   uint16_t flags, const uint8_t reserved[6])
{
    size_t i;

    if (magic[0] != VOLEITH_PROOF_MAGIC_0 ||
        magic[1] != VOLEITH_PROOF_MAGIC_1 ||
        magic[2] != VOLEITH_PROOF_MAGIC_2 || magic[3] != VOLEITH_PROOF_MAGIC_3)
        return 0;
    if (format_version != VOLEITH_PROOF_FORMAT_VERSION)
        return 0;
    if (fs_kind > (uint8_t)VOLEITH_FS_GROSTL)
        return 0;
    if (bavc_kind > (uint8_t)VOLEITH_BAVC_HALF_TREE)
        return 0;
    if (param_set_id > (uint8_t)VOLEITH_PARAM_EM_256S)
        return 0;
    if (flags != 0)
        return 0;
    for (i = 0; i < 6; i++) {
        if (reserved[i] != 0)
            return 0;
    }
    return 1;
}

/* ================================================================
 * Public API
 * ================================================================ */

int
voleith_proof_header_parse(voleith_proof_header_t *out, const uint8_t *bytes,
                           size_t len)
{
    uint16_t flags;

    if (out == NULL || bytes == NULL)
        return -1;
    if (len < VOLEITH_PROOF_HEADER_BYTES)
        return -1;

    /*
     * Decode flags before validation so we can pass the host-order value
     * to fixed_prefix_valid.  Little-endian wire encoding per spec.
     */
    flags = (uint16_t)bytes[8] | ((uint16_t)bytes[9] << 8);

    if (!fixed_prefix_valid(bytes, bytes[4], bytes[5], bytes[6], bytes[7],
                            flags, bytes + 10))
        return -1;

    /* Zero the entire struct first so any tail padding is well-defined. */
    memset(out, 0, sizeof(*out));

    memcpy(out->magic, bytes, 4);
    out->format_version = bytes[4];
    out->fs_kind = bytes[5];
    out->bavc_kind = bytes[6];
    out->param_set_id = bytes[7];
    out->flags = flags;
    memcpy(out->reserved, bytes + 10, 6);
    memcpy(out->circuit_fp, bytes + 16, VOLEITH_PROOF_FINGERPRINT_BYTES);
    memcpy(out->params_fp, bytes + 32, VOLEITH_PROOF_FINGERPRINT_BYTES);

    return 0;
}

int
voleith_proof_header_serialize(uint8_t *out, size_t *len,
                               const voleith_proof_header_t *h)
{
    if (len == NULL || h == NULL)
        return -1;

    /*
     * Size-query mode: caller wants to know how large a buffer to
     * allocate.  Struct contents are not inspected here - the header
     * size is constant.
     */
    if (out == NULL) {
        *len = VOLEITH_PROOF_HEADER_BYTES;
        return 0;
    }

    /* Write mode: require enough room before doing any validation. */
    if (*len < VOLEITH_PROOF_HEADER_BYTES)
        return -1;

    if (!fixed_prefix_valid(h->magic, h->format_version, h->fs_kind,
                            h->bavc_kind, h->param_set_id, h->flags,
                            h->reserved))
        return -1;

    memcpy(out, h->magic, 4);
    out[4] = h->format_version;
    out[5] = h->fs_kind;
    out[6] = h->bavc_kind;
    out[7] = h->param_set_id;
    out[8] = (uint8_t)(h->flags & 0xff);
    out[9] = (uint8_t)((h->flags >> 8) & 0xff);
    memcpy(out + 10, h->reserved, 6);
    memcpy(out + 16, h->circuit_fp, VOLEITH_PROOF_FINGERPRINT_BYTES);
    memcpy(out + 32, h->params_fp, VOLEITH_PROOF_FINGERPRINT_BYTES);

    *len = VOLEITH_PROOF_HEADER_BYTES;
    return 0;
}

int
voleith_proof_header_check_identity(const voleith_proof_header_t *h,
                                    const voleith_circuit_t *circuit,
                                    const voleith_params_t *params)
{
    uint8_t expected_circuit_fp[VOLEITH_PROOF_FINGERPRINT_BYTES];
    uint8_t expected_params_fp[VOLEITH_PROOF_FINGERPRINT_BYTES];
    int rv;

    if (h == NULL || circuit == NULL || params == NULL)
        return -1;

    if (voleith_circuit_fingerprint(circuit, expected_circuit_fp) != 0)
        return -1;
    if (voleith_params_fingerprint(params, expected_params_fp) != 0)
        return -1;

    /*
     * Constant-time over the 32 fingerprint bytes.  Both fingerprints
     * are public values, so timing leakage of a match/mismatch is not
     * a confidentiality issue; const_memcmp is used as defense-in-depth
     * to keep timing behavior trivial to reason about across all call
     * paths into the verifier.
     */
    rv = voleith_const_memcmp(h->circuit_fp, expected_circuit_fp,
                              VOLEITH_PROOF_FINGERPRINT_BYTES) |
         voleith_const_memcmp(h->params_fp, expected_params_fp,
                              VOLEITH_PROOF_FINGERPRINT_BYTES);

    voleith_secure_zero(expected_circuit_fp, sizeof(expected_circuit_fp));
    voleith_secure_zero(expected_params_fp, sizeof(expected_params_fp));

    return (rv == 0) ? 0 : -1;
}

int
voleith_proof_inspect(const voleith_proof_t *proof,
                      voleith_proof_header_t *header_out)
{
    voleith_proof_header_t scratch;
    voleith_proof_header_t *target =
        (header_out != NULL) ? header_out : &scratch;

    if (proof == NULL || proof->data == NULL)
        return -1;

    return voleith_proof_header_parse(target, proof->data, proof->len);
}

int
voleith_proof_header_check_identity_gf8(const voleith_proof_header_t *h,
                                        const voleith_gf8_circuit_t *circuit,
                                        const voleith_params_t *params)
{
    uint8_t expected_circuit_fp[VOLEITH_PROOF_FINGERPRINT_BYTES];
    uint8_t expected_params_fp[VOLEITH_PROOF_FINGERPRINT_BYTES];
    int rv;

    if (h == NULL || circuit == NULL || params == NULL)
        return -1;

    if (voleith_gf8_circuit_fingerprint(circuit, expected_circuit_fp) != 0)
        return -1;
    if (voleith_params_fingerprint(params, expected_params_fp) != 0)
        return -1;

    rv = voleith_const_memcmp(h->circuit_fp, expected_circuit_fp,
                              VOLEITH_PROOF_FINGERPRINT_BYTES) |
         voleith_const_memcmp(h->params_fp, expected_params_fp,
                              VOLEITH_PROOF_FINGERPRINT_BYTES);

    voleith_secure_zero(expected_circuit_fp, sizeof(expected_circuit_fp));
    voleith_secure_zero(expected_params_fp, sizeof(expected_params_fp));

    return (rv == 0) ? 0 : -1;
}

int
voleith_proof_header_check_identity_gf16(const voleith_proof_header_t *h,
                                         const voleith_gf16_circuit_t *circuit,
                                         const voleith_params_t *params)
{
    uint8_t expected_circuit_fp[VOLEITH_PROOF_FINGERPRINT_BYTES];
    uint8_t expected_params_fp[VOLEITH_PROOF_FINGERPRINT_BYTES];
    int rv;

    if (h == NULL || circuit == NULL || params == NULL)
        return -1;

    if (voleith_gf16_circuit_fingerprint(circuit, expected_circuit_fp) != 0)
        return -1;
    if (voleith_params_fingerprint(params, expected_params_fp) != 0)
        return -1;

    rv = voleith_const_memcmp(h->circuit_fp, expected_circuit_fp,
                              VOLEITH_PROOF_FINGERPRINT_BYTES) |
         voleith_const_memcmp(h->params_fp, expected_params_fp,
                              VOLEITH_PROOF_FINGERPRINT_BYTES);

    voleith_secure_zero(expected_circuit_fp, sizeof(expected_circuit_fp));
    voleith_secure_zero(expected_params_fp, sizeof(expected_params_fp));

    return (rv == 0) ? 0 : -1;
}
