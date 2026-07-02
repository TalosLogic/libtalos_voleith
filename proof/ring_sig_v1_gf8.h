/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * ring_sig_v1_gf8.h - RSv1 signature layer (V1-specific wrappers over
 * the shared membership core).
 *
 * This header declares only the voleith_rsv1_* / voleith_ring_sig_*
 * surface: the V1 cfg-fingerprint (binds V1's identity into the
 * signature's fs_seed; see design §5), the ring builder, fs_seed
 * construction, sign/verify, and the "VRS1" serialization envelope.
 *
 * The reusable membership core (voleith_rs_membership_* cfg, layout,
 * path, validate, canonical absorber, witness packer) moved to
 * proof/rs_membership_gf8.h, which this header re-includes so existing
 * V1 includers compile unchanged.  The membership circuit builder lives
 * in circuits/rs_membership_gf8_circuit.h.
 *
 * See docs/RSV1_DESIGN.md for the V1 protocol and docs/RING_SIGNATURE_DESIGN.md
 * for the V1-V7 variant matrix.
 */

#ifndef VOLEITH_RING_SIG_V1_GF8_H
#define VOLEITH_RING_SIG_V1_GF8_H

#include "rs_membership_gf8.h"  /* membership core: cfg, layout, path, etc. */
#include "params_fingerprint.h" /* VOLEITH_PARAMS_FINGERPRINT_BYTES */
#include "proof.h"              /* voleith_params_t, voleith_proof_t */

#include <stddef.h>
#include <stdint.h>

/* ================================================================
 * V1-specific helpers (built on the membership core above).
 * ================================================================ */

/*
 * Sentinel byte used to fill unfilled leaf-node slots in a sub-capacity
 * ring.  Each unused slot becomes node_bytes copies of this byte (i.e.
 * an all-zero leaf node when this is 0x00).
 *
 * Rationale: an OWF output of all-zero bytes is vanishingly unlikely
 * for any sk under any of the wrapped node-hash vts, so a sentinel slot
 * cannot collide with a real member's leaf node.  This means the ring
 * can be built once at capacity 2^depth_m and sub-capacity rings still
 * yield a well-defined root; downstream verifiers see only the root
 * and need not know the ring is sub-capacity.
 */
#define VOLEITH_RSV1_SENTINEL_LEAF_BYTE 0x00

/*
 * voleith_rsv1_ring_build - build a membership Merkle ring from
 * n_members raw secrets and emit per-member path bundles.
 *
 * For each member i, owf_vt->leaf_hash(sks + i * sk_bytes, sk_bytes)
 * is taken as the leaf node.  Unused slots [n_members .. 2^depth_m)
 * are filled with the documented sentinel (see
 * VOLEITH_RSV1_SENTINEL_LEAF_BYTE).  The membership root and each
 * member's sibling path are then produced by voleith_merkle_vt_build
 * and voleith_merkle_vt_compute_path (see
 * circuits/merkle_vt_gf8_helpers.h).
 *
 * Ownership / lifetime: siblings_storage is caller-owned, of length
 *
 *   n_members * cfg->depth_m * cfg->tree_hash->node_bytes
 *
 * bytes.  This function fills it and assigns
 *
 *   paths_out[i].siblings = siblings_storage + i * cfg->depth_m
 *                           * cfg->tree_hash->node_bytes
 *
 * so each path's sibling buffer points into the caller-managed block.
 * Freeing siblings_storage invalidates every paths_out[i].siblings.
 *
 * cfg              - validated via voleith_rs_membership_validate.
 * sks              - n_members * cfg->sk_bytes bytes, member 0 first.
 * n_members        - 1..2^cfg->depth_m.  Exceeding capacity returns -1.
 * root_out         - cfg->tree_hash->node_bytes bytes, written iff 0.
 * paths_out        - n_members entries; on success .leaf_index[i] = i
 *                    and .siblings[i] is wired into siblings_storage.
 * siblings_storage - as documented above.
 *
 * Returns 0 on success, -1 on NULL argument, cfg validation failure,
 * n_members == 0 or > ring capacity, propagated vt callback failure,
 * or allocation failure.  On failure root_out, paths_out, and
 * siblings_storage are left in an unspecified state.
 */
int voleith_rsv1_ring_build(const voleith_rs_membership_config_t *cfg,
                            const uint8_t *sks, size_t n_members,
                            uint8_t *root_out,
                            voleith_rs_membership_path_t *paths_out,
                            uint8_t *siblings_storage);

/* SHAKE-256 fingerprint width.  Matches params_fingerprint and
 * circuit_fingerprint for cross-layer convention consistency. */
#define VOLEITH_RSV1_CONFIG_FINGERPRINT_BYTES 16

/*
 * Canonical encoding domain tag absorbed first by V1's fingerprint
 * function.  The "-v1" suffix pins the V1 fingerprint layout; future
 * Vx fingerprints use their own domain tags so their outputs never
 * collide with V1's.
 */
#define VOLEITH_RSV1_CONFIG_FINGERPRINT_DOMAIN_TAG "voleith-rsv1-cf-v1"

/*
 * voleith_rsv1_config_fingerprint - 16-byte SHAKE-256 fingerprint
 * binding the V1 cfg identity.
 *
 * Internally: SHAKE-256(init) || absorb(VOLEITH_RSV1_CONFIG_FINGERPRINT_DOMAIN_TAG
 * || 0x00) || voleith_rs_membership_absorb_canonical(ctx, cfg) ||
 * squeeze(16).
 *
 * V1's cfg is exactly the membership cfg, so this fingerprint takes a
 * voleith_rs_membership_config_t directly.  V2's voleith_rsv2_config_t
 * will embed the membership cfg and add nullifier-PRF fields; its
 * fingerprint will absorb a V2 domain tag, then call
 * voleith_rs_membership_absorb_canonical on the embedded mem cfg, then
 * absorb the V2 extension, then squeeze.  Same canonical-membership
 * source of truth shared across variants.
 *
 * Both tree_hash and the effective owf vt (= owf_hash ?: tree_hash)
 * must have non-NULL .name.  Returns 0 on success, -1 if cfg is NULL,
 * out is NULL, cfg->tree_hash is NULL, or either name is NULL.
 *
 * Note: this function does not run voleith_rs_membership_validate.
 * Callers that need both invariants and a fingerprint should call
 * validate first.
 */
int voleith_rsv1_config_fingerprint(
    const voleith_rs_membership_config_t *cfg,
    uint8_t out[VOLEITH_RSV1_CONFIG_FINGERPRINT_BYTES]);

/* ================================================================
 * Sign / verify (T6).
 * ================================================================ */

/* Byte length of the fs_seed produced by voleith_rsv1_compute_fs_seed
 * and consumed by voleith_rsv1_sign / _verify. */
#define VOLEITH_RSV1_FS_SEED_BYTES 16

/* Single-byte version tag locking the §5 absorb layout to "RSv1 fs_seed
 * format 1".  Bump if the construction in voleith_rsv1_compute_fs_seed
 * ever changes; old verifiers reject the new value loudly. */
#define VOLEITH_RSV1_FS_SEED_FMT_VERSION 0x01

/* Width of the 16-byte ASCII domain tag absorbed by the fs_seed
 * construction.  Distinct from every other domain tag in the project. */
#define VOLEITH_RSV1_DOMAIN_TAG_BYTES 16

/* 16-byte ASCII domain tag absorbed second by the fs_seed construction
 * (right after the version byte).  "VOLEitH-RSv1" is 12 visible bytes;
 * the trailing four bytes pad to 16. */
extern const uint8_t voleith_rsv1_domain_tag[VOLEITH_RSV1_DOMAIN_TAG_BYTES];

/*
 * voleith_rsv1_compute_fs_seed - construct the §5 Fiat-Shamir seed.
 *
 * Absorbs, in order:
 *   FS_SEED_FMT_VERSION                          (1 byte)
 *   voleith_rsv1_domain_tag                      (16 bytes)
 *   voleith_rsv1_config_fingerprint(cfg)         (16 bytes)
 *   membership_root                              (tree_hash->node_bytes)
 *   revocation_root_or_null,
 *     else node_bytes zero bytes                 (tree_hash->node_bytes)
 *   m_len as 8-byte big-endian                   (8 bytes)
 *   m                                            (m_len bytes)
 *
 * Squeezes VOLEITH_RSV1_FS_SEED_BYTES bytes into out.  Exposed publicly
 * so the T6a KAT can pin its byte stream directly without going through
 * voleith_rsv1_sign.
 *
 * Returns 0 on success, -1 if any required pointer arg is NULL (cfg,
 * membership_root, out; m may be NULL only if m_len == 0; revocation
 * may be NULL, which means "absorb node_bytes zeros") or if cfg fails
 * voleith_rs_membership_validate / fingerprinting.
 */
int voleith_rsv1_compute_fs_seed(const voleith_rs_membership_config_t *cfg,
                                 const uint8_t *membership_root,
                                 const uint8_t *revocation_root_or_null,
                                 const uint8_t *m, size_t m_len,
                                 uint8_t out[VOLEITH_RSV1_FS_SEED_BYTES]);

/*
 * voleith_ring_sig_t - on-the-wire ring signature.
 *
 * In T6 (this ticket) the .data buffer is the raw gf8_proof bytes
 * emitted by voleith_gf8_prove_v2.  T7 wraps these bytes with the
 * versioned "VRS1" envelope (magic | version | cfg_fp | params_fp |
 * proof_len | proof).
 *
 * Allocated by voleith_rsv1_sign; freed with voleith_ring_sig_free.
 */
typedef struct {
    uint8_t *data;
    size_t len;
} voleith_ring_sig_t;

/* Free sig->data and zero the struct.  Safe to call on a zeroed or
 * already-freed sig (NULL data). */
void voleith_ring_sig_free(voleith_ring_sig_t *sig);

/*
 * voleith_rsv1_sign - produce an RSv1 ring signature.
 *
 * Steps (per design §4.2 + §5):
 *   1. Validate cfg.
 *   2. Build the membership circuit + layout via
 *      voleith_rs_membership_build_circuit.
 *   3. Pack the witness from (sk, membership) via
 *      voleith_rs_membership_pack_witness.
 *   4. Pack the instance: caller-supplied membership_root.
 *   5. Compute fs_seed via voleith_rsv1_compute_fs_seed.
 *   6. Call voleith_gf8_prove_v2.  If (sk, path) does NOT walk to
 *      membership_root, the assert_equal_root constraint fires inside
 *      the QuickSilver eval pass and prove returns -1 up-front (X-10
 *      discipline).
 *   7. Move the resulting proof bytes into *sig_out.
 *
 * cfg              - validated.
 * params           - voleith_params_validate'd by the prover.
 * sk               - cfg->sk_bytes bytes.
 * membership_root  - the ring's published root (tree_hash->node_bytes).
 *                    The caller obtained this from voleith_rsv1_ring_build
 *                    (or from the ring authority) and committed to it
 *                    out-of-band.  The signer does NOT recompute it from
 *                    (sk, path); supplying the real R here is what makes
 *                    wrong-sk / wrong-sibling fail at sign time.
 * membership       - signer's path bundle (leaf_index + sibling bytes).
 * revocation_root  - the published revocation IMT root (V).  Required
 *                    iff cfg->depth_r > 0; must be NULL when
 *                    cfg->depth_r == 0.
 * revocation       - signer's non-membership bundle for the revocation
 *                    IMT (rev_* fields of the path struct).  Required
 *                    iff cfg->depth_r > 0; must be NULL when
 *                    cfg->depth_r == 0.  The signer typically obtains
 *                    this by calling voleith_imt_vt_lookup_nonmember on
 *                    the published revocation record set with their
 *                    own leaf node as target.
 * m                - message to bind via Fiat-Shamir.  May be NULL only
 *                    when m_len == 0.
 * m_len            - up to 2^64 - 1.
 * sig_out          - on success, sig_out->data is malloc'd; caller frees
 *                    with voleith_ring_sig_free.  On failure sig_out is
 *                    zeroed.
 *
 * Returns 0 on success, -1 on validation failure, packing failure,
 * proof-system failure (incl. witness that doesn't satisfy the
 * circuit), or any NULL argument.
 */
int voleith_rsv1_sign(voleith_ring_sig_t *sig_out,
                      const voleith_rs_membership_config_t *cfg,
                      const voleith_params_t *params, const uint8_t *sk,
                      const uint8_t *membership_root,
                      const voleith_rs_membership_path_t *membership,
                      const uint8_t *revocation_root,
                      const voleith_rs_membership_path_t *revocation,
                      const uint8_t *m, size_t m_len);

/*
 * voleith_rsv1_verify - verify an RSv1 ring signature.
 *
 * Steps:
 *   1. Validate cfg.
 *   2. Build the membership circuit + layout (deterministic in cfg).
 *   3. Pack the instance from membership_root.
 *   4. Compute fs_seed via voleith_rsv1_compute_fs_seed.
 *   5. Call voleith_gf8_verify_v2 on the raw proof bytes in sig.
 *
 * cfg                       - validated.
 * params                    - same params used at sign time.
 * membership_root           - tree_hash->node_bytes bytes.
 * revocation_root_or_null   - required iff cfg->depth_r > 0; must be
 *                             NULL when cfg->depth_r == 0.
 * m, m_len                  - message bytes the signer committed to.
 *
 * Returns 0 if the signature verifies, -1 otherwise.
 */
int voleith_rsv1_verify(const voleith_ring_sig_t *sig,
                        const voleith_rs_membership_config_t *cfg,
                        const voleith_params_t *params,
                        const uint8_t *membership_root,
                        const uint8_t *revocation_root_or_null,
                        const uint8_t *m, size_t m_len);

/* ================================================================
 * Serialization (T7).
 *
 * Wire envelope wrapping the raw gf8_proof bytes inside sig->data with
 * a versioned, self-describing header.  Per design §7:
 *
 *   offset  size  field
 *   ------  ----  -----
 *        0     4  magic = "VRS1"
 *        4     1  format_version = 1
 *        5    16  cfg_fingerprint  (voleith_rsv1_config_fingerprint)
 *       21    16  params_fingerprint (voleith_params_fingerprint)
 *       37     4  gf8_proof_len, big-endian uint32
 *       41   ...  gf8_proof bytes
 *
 * Header overhead is VOLEITH_RING_SIG_HEADER_BYTES (= 41); total packed
 * length is 41 + gf8_proof_len.  Endianness on the length field matches
 * the project's other length-encoding conventions (m_len in §5,
 * proof_header lengths) which use big-endian.
 *
 * The magic separates RSv1 signatures from raw VOLEitH proofs in mixed
 * bytestreams; cfg_fingerprint and params_fingerprint make unpack fail
 * loudly when a caller supplies a different cfg or params than the one
 * the signature was produced under.  Inner gf8_proof bytes are not
 * re-validated by unpack; they are validated by voleith_rsv1_verify on
 * the unpacked sig.
 * ================================================================ */

/* Magic bytes at offset 0: 'V', 'R', 'S', '1'. */
#define VOLEITH_RING_SIG_MAGIC_0 'V'
#define VOLEITH_RING_SIG_MAGIC_1 'R'
#define VOLEITH_RING_SIG_MAGIC_2 'S'
#define VOLEITH_RING_SIG_MAGIC_3 '1'

/* Current on-the-wire format version.  Bumped if the envelope changes
 * shape; old unpackers reject the new value loudly. */
#define VOLEITH_RING_SIG_FORMAT_VERSION 1u

/* Fixed header bytes (magic + version + cfg_fp + params_fp + len) preceding
 * the gf8_proof body. */
#define VOLEITH_RING_SIG_HEADER_BYTES                                          \
    (4u + 1u + VOLEITH_RSV1_CONFIG_FINGERPRINT_BYTES +                         \
     VOLEITH_PARAMS_FINGERPRINT_BYTES + 4u)

/*
 * voleith_ring_sig_packed_len - total packed buffer length for an
 * unpacked sig.
 *
 * Equals VOLEITH_RING_SIG_HEADER_BYTES + sig->len.  Returned as a
 * size_t to avoid the uint32 cap inside the helpers; pack rejects any
 * sig.len that does not fit in a uint32_t.
 *
 * Returns 0 if sig is NULL.
 */
size_t voleith_ring_sig_packed_len(const voleith_ring_sig_t *sig);

/*
 * voleith_ring_sig_pack - serialize sig into out_buf.
 *
 * Computes cfg_fingerprint and params_fingerprint internally; the caller
 * must supply the same cfg / params they passed to voleith_rsv1_sign,
 * since those identities bind the signature.
 *
 * Caller provides out_buf of length out_len.  out_len must equal
 * voleith_ring_sig_packed_len(sig); pack rejects mismatches rather than
 * silently truncating.  written_out, if non-NULL, receives the number
 * of bytes written on success (same as voleith_ring_sig_packed_len).
 *
 * Returns 0 on success, -1 on:
 *   any NULL pointer arg (out_buf, sig, cfg, params; sig->data may be
 *     NULL only if sig->len is 0)
 *   sig->data == NULL with sig->len != 0 or vice versa
 *   sig->len > UINT32_MAX (cannot encode in the 4-byte length field)
 *   out_len != voleith_ring_sig_packed_len(sig)
 *   fingerprint computation failure (NULL .name on the cfg's vts, etc.)
 */
int voleith_ring_sig_pack(uint8_t *out_buf, size_t out_len, size_t *written_out,
                          const voleith_ring_sig_t *sig,
                          const voleith_rs_membership_config_t *cfg,
                          const voleith_params_t *params);

/*
 * voleith_ring_sig_unpack - parse buf into sig_out.
 *
 * Validates magic, format version, cfg_fingerprint (against the caller's
 * cfg), params_fingerprint (against the caller's params), and that
 * buf_len == VOLEITH_RING_SIG_HEADER_BYTES + encoded_proof_len.  On
 * success sig_out->data is malloc'd and holds the inner gf8_proof
 * bytes; caller frees with voleith_ring_sig_free.
 *
 * Returns 0 on success.  Returns -1 on:
 *   any NULL pointer arg
 *   buf_len < VOLEITH_RING_SIG_HEADER_BYTES
 *   magic mismatch
 *   format version mismatch
 *   cfg_fingerprint mismatch (constant-time comparison via
 *     voleith_const_memcmp)
 *   params_fingerprint mismatch (constant-time)
 *   length-field mismatch (truncated or oversized buffer)
 *   allocation failure for sig_out->data
 *
 * On failure sig_out is zeroed.
 */
int voleith_ring_sig_unpack(voleith_ring_sig_t *sig_out, const uint8_t *buf,
                            size_t buf_len,
                            const voleith_rs_membership_config_t *cfg,
                            const voleith_params_t *params);

#endif /* VOLEITH_RING_SIG_V1_GF8_H */
