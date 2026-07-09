/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * proof_header.h - Fixed 48-byte metadata header at the start of every
 *                  serialized proof.
 *
 * The header encodes the variants the proof was minted under (FS backend,
 * BAVC construction, parameter set) and binds the proof to a specific
 * circuit and params struct via two 16-byte SHAKE-128 fingerprints.  It
 * is mixed into the Fiat-Shamir seed before any other proof material is
 * absorbed, so any modification to the header bytes invalidates the
 * final chall_3 check.
 *
 * Layout (little-endian for the multi-byte flags field):
 *
 *   offset  size  field
 *   ------  ----  -----
 *      0     4    MAGIC          = 'T','L','O','S'
 *      4     1    FORMAT_VERSION = 0x01
 *      5     1    FS_KIND        VOLEITH_FS_SHAKE | VOLEITH_FS_GROSTL
 *      6     1    BAVC_KIND      VOLEITH_BAVC_STANDARD | VOLEITH_BAVC_HALF_TREE
 *      7     1    PARAM_SET_ID   VOLEITH_PARAM_EM_*  (0..5)
 *      8     2    FLAGS          must be 0
 *     10     6    RESERVED       must be 0
 *     16    16    CIRCUIT_FP     SHAKE-128 of canonical circuit bytes
 *     32    16    PARAMS_FP      SHAKE-128 of canonical params bytes
 *     48   ...    proof body
 *
 * See docs/PROOF_METADATA_HEADER_DESIGN.md for the full specification.
 *
 * This file implements the fixed-prefix (bytes 0..15) parse + serialize
 * only.  Fingerprint generation and the identity equality check land in
 * a later step; until then voleith_proof_header_check_identity is a stub
 * that returns 0.
 */

#ifndef VOLEITH_PROOF_HEADER_H
#define VOLEITH_PROOF_HEADER_H

#include <stddef.h>
#include <stdint.h>

#include "proof.h" /* voleith_params_t (transitively voleith_circuit_t) */

/* ================================================================
 * Constants
 * ================================================================ */

#define VOLEITH_PROOF_HEADER_BYTES 48
#define VOLEITH_PROOF_FINGERPRINT_BYTES 16

#define VOLEITH_PROOF_MAGIC_0 ((uint8_t)'T')
#define VOLEITH_PROOF_MAGIC_1 ((uint8_t)'L')
#define VOLEITH_PROOF_MAGIC_2 ((uint8_t)'O')
#define VOLEITH_PROOF_MAGIC_3 ((uint8_t)'S')

#define VOLEITH_PROOF_FORMAT_VERSION ((uint8_t)0x01)

/*
 * The variant identifier enums (voleith_fs_kind_t, voleith_bavc_kind_t,
 * voleith_param_set_id_t) are declared in proof.h, which is already
 * included above, so they are visible here.  They are referenced in the
 * header struct below and in the check_identity API at the bottom.
 */

/* ================================================================
 * Header struct
 * ================================================================ */

typedef struct {
    uint8_t magic[4];
    uint8_t format_version;
    uint8_t fs_kind;
    uint8_t bavc_kind;
    uint8_t param_set_id;
    uint16_t flags;
    uint8_t reserved[6];
    uint8_t circuit_fp[VOLEITH_PROOF_FINGERPRINT_BYTES];
    uint8_t params_fp[VOLEITH_PROOF_FINGERPRINT_BYTES];
} voleith_proof_header_t;

/* ================================================================
 * Parse / serialize
 * ================================================================ */

/*
 * Parse VOLEITH_PROOF_HEADER_BYTES bytes into *out.
 *
 * Validates the statically-constrained fixed prefix (bytes 0..15):
 * magic, format version, enum ranges, zero flags, zero reserved bytes.
 * Fingerprint bytes (16..47) are copied verbatim without validation;
 * their correctness against a specific circuit / params is the job of
 * voleith_proof_header_check_identity.
 *
 * Returns 0 on success, -1 if the input is too short or any constrained
 * field is malformed.  When -1 is returned the contents of *out are
 * unspecified.
 *
 * Accepts len >= VOLEITH_PROOF_HEADER_BYTES so callers may pass the
 * full proof length without slicing.
 */
int voleith_proof_header_parse(voleith_proof_header_t *out,
                               const uint8_t *bytes, size_t len);

/*
 * Serialize *h into the buffer at out, using *len as input + output.
 *
 * Two calling modes, distinguished by `out`:
 *
 *  1. Size query (out == NULL): write the required buffer size
 *     (VOLEITH_PROOF_HEADER_BYTES) into *len and return 0.  Useful for
 *     allocating a correctly-sized buffer before serializing.  The
 *     contents of *h are not inspected in this mode.
 *
 *  2. Write (out != NULL): *len is the caller-supplied buffer capacity.
 *     If *len < VOLEITH_PROOF_HEADER_BYTES the call fails (returns -1)
 *     without writing.  Otherwise the header is validated and serialized,
 *     *len is updated to the number of bytes actually written
 *     (VOLEITH_PROOF_HEADER_BYTES), and 0 is returned.
 *
 * Validates the same fixed-prefix constraints as parse before writing,
 * so a malformed struct is rejected rather than silently producing
 * unparseable bytes.
 *
 * Returns 0 on success, -1 on any of: NULL len, NULL h, insufficient
 * buffer (*len too small in write mode), or out-of-range struct field.
 * On failure no bytes are written and *len is unchanged.
 */
int voleith_proof_header_serialize(uint8_t *out, size_t *len,
                                   const voleith_proof_header_t *h);

/* ================================================================
 * Identity binding
 * ================================================================ */

/*
 * Check that *h's circuit_fp and params_fp match fingerprints computed
 * over the caller-supplied (bit-level) circuit and params.  Constant-
 * time comparison.  Returns 0 on match, -1 on mismatch or NULL args.
 */
int voleith_proof_header_check_identity(const voleith_proof_header_t *h,
                                        const voleith_circuit_t *circuit,
                                        const voleith_params_t *params);

/*
 * GF(2^8) variant of check_identity.  Forward-declares the circuit
 * type via the struct tag so this header does not need to drag in
 * gf8_circuit.h; the implementation includes it.
 */
struct voleith_gf8_circuit;

int voleith_proof_header_check_identity_gf8(
    const voleith_proof_header_t *h, const struct voleith_gf8_circuit *circuit,
    const voleith_params_t *params);

/*
 * GF(2^16) variant of check_identity.  Forward-declares the circuit type via
 * the struct tag so this header does not need to drag in gf16_circuit.h; the
 * implementation includes it.
 */
struct voleith_gf16_circuit;

int voleith_proof_header_check_identity_gf16(
    const voleith_proof_header_t *h, const struct voleith_gf16_circuit *circuit,
    const voleith_params_t *params);

/* ================================================================
 * Public inspection helper
 * ================================================================ */

/*
 * Read and validate the metadata header of a proof.  Does NOT verify
 * the proof contents or check identity against any circuit / params;
 * use voleith_proof_header_check_identity for that.
 *
 * Intended use: routing proofs to the appropriate verifier
 * configuration before invoking voleith_verify - e.g., picking a
 * params struct based on header_out->param_set_id, or deciding
 * whether a build that lacks Grostl-FS can even attempt verification.
 *
 * If header_out is non-NULL, the parsed header is written there on
 * success.  If header_out is NULL, the header is parsed and validated
 * without being stored - useful for a fast "is this a v1 proof?"
 * check, or for skipping past the header in a proof multiplexer.
 *
 * Returns:
 *   0  - proof->data starts with a well-formed v1 header.  When
 *        header_out != NULL, *header_out has been populated.
 *  -1  - proof is NULL, has no data, is shorter than the header, or
 *        the header bytes are malformed (bad magic, wrong version,
 *        out-of-range enum, nonzero flags / reserved).  Legacy
 *        pre-header proofs return -1 here; the verifier handles them
 *        through its own dual-path dispatch.
 */
int voleith_proof_inspect(const voleith_proof_t *proof,
                          voleith_proof_header_t *header_out);

#endif /* VOLEITH_PROOF_HEADER_H */
