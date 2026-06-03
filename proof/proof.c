/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * proof.c - Full VOLEitH non-interactive proof system
 *
 * Integrates VOLEitH commitment, Fiat-Shamir transcript, VOLEHash,
 * and the QuickSilver prover/verifier into a single prove/verify API.
 */

#include "proof.h"
#include "circuit_fingerprint.h"
#include "fiat_shamir.h"
#include "params_fingerprint.h"
#include "proof_header.h"
#include "prover.h"
#include "verifier.h"
#include "vole_hash.h"
#include "../vole/voleith.h"
#include "../vole/convert.h"
#include "../vole/vc.h"

#include "../core/util.h"
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

/* ================================================================
 * Parameter sets (from FAEST v2.0 spec / faest-ref meson.build)
 * ================================================================ */

/*
 * Numeric fields per FAEST v2.0 spec (faest-ref meson.build).
 * fs_kind / bavc_kind are explicit at SHAKE / STANDARD - the only
 * combination the library currently supports.  Listing them
 * explicitly rather than relying on zero-init from trailing-field
 * elision makes the wire-format binding obvious and breaks loudly if
 * the enum numbering ever changes.
 *
 * Layout matches voleith_params_t: {lambda, tau, w_grind, T_open,
 * n_leafcom, fs_kind, bavc_kind}.
 */
const voleith_params_t voleith_params_em_128s = {
    128, 11, 7, 103, 2, VOLEITH_FS_SHAKE, VOLEITH_BAVC_STANDARD};
const voleith_params_t voleith_params_em_128f = {
    128, 16, 8, 112, 2, VOLEITH_FS_SHAKE, VOLEITH_BAVC_STANDARD};
const voleith_params_t voleith_params_em_192s = {
    192, 16, 8, 162, 2, VOLEITH_FS_SHAKE, VOLEITH_BAVC_STANDARD};
const voleith_params_t voleith_params_em_192f = {
    192, 24, 8, 176, 2, VOLEITH_FS_SHAKE, VOLEITH_BAVC_STANDARD};
const voleith_params_t voleith_params_em_256s = {
    256, 22, 6, 218, 2, VOLEITH_FS_SHAKE, VOLEITH_BAVC_STANDARD};
const voleith_params_t voleith_params_em_256f = {
    256, 32, 8, 234, 2, VOLEITH_FS_SHAKE, VOLEITH_BAVC_STANDARD};

/*
 * Lookup table backing voleith_params_build().  Index by
 * voleith_param_set_id_t.  Holds only the numeric fields; fs_kind and
 * bavc_kind come from the caller's arguments.
 */
struct voleith_params_numeric {
    unsigned int lambda;
    unsigned int tau;
    unsigned int w_grind;
    unsigned int T_open;
    unsigned int n_leafcom;
};
static const struct voleith_params_numeric voleith_params_table[] = {
    [VOLEITH_PARAM_EM_128F] = {128, 16, 8, 112, 2},
    [VOLEITH_PARAM_EM_128S] = {128, 11, 7, 103, 2},
    [VOLEITH_PARAM_EM_192F] = {192, 24, 8, 176, 2},
    [VOLEITH_PARAM_EM_192S] = {192, 16, 8, 162, 2},
    [VOLEITH_PARAM_EM_256F] = {256, 32, 8, 234, 2},
    [VOLEITH_PARAM_EM_256S] = {256, 22, 6, 218, 2},
};
#define VOLEITH_PARAMS_TABLE_LEN                                               \
    (sizeof(voleith_params_table) / sizeof(voleith_params_table[0]))

voleith_params_t
voleith_params_build(voleith_param_set_id_t set, voleith_fs_kind_t fs,
                     voleith_bavc_kind_t bavc)
{
    voleith_params_t p = {0};
    const struct voleith_params_numeric *row;

    if ((unsigned int)set >= VOLEITH_PARAMS_TABLE_LEN)
        return p; /* zero-initialized; validate() will reject. */

    row = &voleith_params_table[set];
    p.lambda = row->lambda;
    p.tau = row->tau;
    p.w_grind = row->w_grind;
    p.T_open = row->T_open;
    p.n_leafcom = row->n_leafcom;
    p.fs_kind = fs;
    p.bavc_kind = bavc;
    return p;
}

/*
 * Map a voleith_params_t to a param_set_id for the metadata header byte.
 * Matches on (lambda, tau) against the six named EM-* sets; for custom
 * params returns the closest same-lambda default.  The header's
 * param_set_id byte is informational only - the real params binding is
 * via the 16-byte PARAMS_FP that follows it - so this just needs to
 * return a value in the legal range 0..5.
 */
static voleith_param_set_id_t
params_to_id(const voleith_params_t *p)
{
    if (p->lambda == 128)
        return (p->tau == 11) ? VOLEITH_PARAM_EM_128S : VOLEITH_PARAM_EM_128F;
    if (p->lambda == 192)
        return (p->tau == 16) ? VOLEITH_PARAM_EM_192S : VOLEITH_PARAM_EM_192F;
    /* lambda == 256 (validate() rejects anything else) */
    return (p->tau == 22) ? VOLEITH_PARAM_EM_256S : VOLEITH_PARAM_EM_256F;
}

/*
 * Build the 48-byte v1 proof header into `out`.  Computes circuit and
 * params fingerprints, fills magic/version/variant bytes, and zeros
 * flags + reserved.  Returns 0 on success, -1 if any fingerprint or
 * serialize step fails.
 */
static int
build_header_bytes(uint8_t out[VOLEITH_PROOF_HEADER_BYTES],
                   const voleith_circuit_t *circuit,
                   const voleith_params_t *params)
{
    voleith_proof_header_t h;
    size_t len = VOLEITH_PROOF_HEADER_BYTES;

    memset(&h, 0, sizeof(h));
    h.magic[0] = VOLEITH_PROOF_MAGIC_0;
    h.magic[1] = VOLEITH_PROOF_MAGIC_1;
    h.magic[2] = VOLEITH_PROOF_MAGIC_2;
    h.magic[3] = VOLEITH_PROOF_MAGIC_3;
    h.format_version = VOLEITH_PROOF_FORMAT_VERSION;
    h.fs_kind = (uint8_t)params->fs_kind;
    h.bavc_kind = (uint8_t)params->bavc_kind;
    h.param_set_id = (uint8_t)params_to_id(params);

    if (voleith_circuit_fingerprint(circuit, h.circuit_fp) != 0)
        return -1;
    if (voleith_params_fingerprint(params, h.params_fp) != 0)
        return -1;

    return voleith_proof_header_serialize(out, &len, &h);
}

/* ================================================================
 * Two-phase API: opaque context structs
 * ================================================================ */

struct voleith_prover_commit_t {
    voleith_params_t params;
    voleith_vc_params_t vcp;
    voleith_commitment_t com; /* hcom, u, c - from voleith_commit() */
    voleith_prover_t state;   /* V matrix + opening state */
    size_t ell;
    size_t ellhat_bytes;
    size_t ell_bytes;
    size_t n_instance;
    size_t utilde_bytes;
    size_t decom_size;
    size_t proof_size;
    uint8_t *pbuf; /* proof buffer (c and iv already written) */
};

struct voleith_verifier_reconstruct_t {
    voleith_params_t params;
    voleith_vc_params_t vcp;
    uint8_t **Q; /* lambda rows × ellhat_bytes */
    uint8_t *u_tilde_copy;
    uint8_t *d_copy;
    uint8_t *a1_tilde_copy;
    uint8_t *a2_tilde_copy;
    uint8_t chall_3[32]; /* lambda/8 bytes max */
    uint32_t ctr_val;
    size_t ell;
    size_t ellhat_bytes;
    size_t ell_bytes;
    size_t n_instance;
    size_t utilde_bytes;
};

/* ================================================================
 * Internal helpers
 * ================================================================ */

#define IV_SIZE 16

static inline unsigned int
get_bit(const uint8_t *buf, size_t pos)
{
    return (buf[pos / 8] >> (pos % 8)) & 1u;
}

/*
 * Check that the top w_grind bits of chall_3 are zero.
 * chall_3 is lambda/8 bytes. Bit i is at byte i/8, bit i%8.
 * Top bits = bits [lambda - w_grind .. lambda - 1].
 */
static int
check_grinding(const uint8_t *chall_3, unsigned int lambda,
               unsigned int w_grind)
{
    for (unsigned int i = lambda - w_grind; i < lambda; i++) {
        if (get_bit(chall_3, i))
            return 0;
    }
    return 1;
}

/*
 * Validate a voleith_params_t at the public API boundary.  All fields
 * are `unsigned int`, so the relevant checks differ from the signed-int
 * checks in voleith_vc_params_init (no `>= 0` is meaningful).  See
 * docs/SECURITY_REVIEW.md X-7.
 */
int
voleith_params_validate(const voleith_params_t *params)
{
    if (!params)
        return -1;
    if (params->lambda != 128 && params->lambda != 192 && params->lambda != 256)
        return -1;
    /* tau == 0 is rejected by voleith_vc_params_init's signed `<= 0` check
     * after an unsigned-to-signed cast, but we check it cleanly here.
     * Upper bound 32 mirrors the stack `i_delta[32]` array used by both
     * proof.c and gf8_proof.c (see P-6, V-8). */
    if (params->tau == 0 || params->tau > 32)
        return -1;
    /* w_grind == lambda would make effective = lambda - w_grind = 0;
     * w_grind > lambda would underflow into a huge unsigned value. */
    if (params->w_grind >= params->lambda)
        return -1;
    if (params->n_leafcom != 2 && params->n_leafcom != 3)
        return -1;
    if (params->T_open == 0)
        return -1;
    /*
     * Range-check the variant enums.  An out-of-range value here
     * indicates the struct was either uninitialized or constructed
     * outside voleith_params_build, both of which should be rejected
     * at the API boundary.
     */
    if ((unsigned int)params->fs_kind > (unsigned int)VOLEITH_FS_GROSTL)
        return -1;
    if ((unsigned int)params->bavc_kind > (unsigned int)VOLEITH_BAVC_HALF_TREE)
        return -1;
    /* C-N1: bound the per-vector depth k = (lambda - w_grind) / tau + 1.
     * vole/convert.c sizes a `v_ptrs[VOLEITH_MAX_K]` stack array and
     * computes `(int)1 << k` (UB at k >= 32) on the verifier-side
     * reconstruct path.  All shipping parameter sets satisfy this with
     * margin (k <= 12); the check exists for custom voleith_params_t
     * structs with tau small relative to lambda. */
    unsigned int k = (params->lambda - params->w_grind) / params->tau + 1;
    if (k > VOLEITH_MAX_K)
        return -1;
    return 0;
}

/*
 * Derive vc_params from proof params.
 * Returns 0 on success, -1 on invalid params.
 */
static int
make_vc_params(voleith_vc_params_t *vcp, const voleith_params_t *p)
{
    return voleith_vc_params_init(vcp, (int)p->lambda, (int)p->tau,
                                  (int)p->w_grind, (int)p->n_leafcom,
                                  (int)p->T_open);
}

/*
 * Compute proof layout offsets from a base pointer.
 * All pointer arguments are set by this function.
 * Pass NULL for any you don't need.
 */
static void
proof_layout(const uint8_t *base, const voleith_params_t *params,
             size_t ellhat_bytes, size_t ell_bytes, size_t decom_size,
             const uint8_t **c_out, const uint8_t **u_tilde_out,
             const uint8_t **d_out, const uint8_t **a1_tilde_out,
             const uint8_t **a2_tilde_out, const uint8_t **decom_i_out,
             const uint8_t **chall_3_out, const uint8_t **iv_out,
             const uint8_t **ctr_out)
{
    unsigned int nb = params->lambda / 8;
    size_t utilde_bytes = nb + VOLEITH_VOLE_HASH_B;
    const uint8_t *p = base;

    if (c_out)
        *c_out = p;
    p += (params->tau - 1) * ellhat_bytes;
    if (u_tilde_out)
        *u_tilde_out = p;
    p += utilde_bytes;
    if (d_out)
        *d_out = p;
    p += ell_bytes;
    if (a1_tilde_out)
        *a1_tilde_out = p;
    p += nb;
    if (a2_tilde_out)
        *a2_tilde_out = p;
    p += nb;
    if (decom_i_out)
        *decom_i_out = p;
    p += decom_size;
    if (chall_3_out)
        *chall_3_out = p;
    p += nb;
    if (iv_out)
        *iv_out = p;
    p += IV_SIZE;
    if (ctr_out)
        *ctr_out = p;
}

/* Same as proof_layout but with writable pointers */
static void
proof_layout_w(uint8_t *base, const voleith_params_t *params,
               size_t ellhat_bytes, size_t ell_bytes, size_t decom_size,
               uint8_t **c_out, uint8_t **u_tilde_out, uint8_t **d_out,
               uint8_t **a1_tilde_out, uint8_t **a2_tilde_out,
               uint8_t **decom_i_out, uint8_t **chall_3_out, uint8_t **iv_out,
               uint8_t **ctr_out)
{
    proof_layout((const uint8_t *)base, params, ellhat_bytes, ell_bytes,
                 decom_size, (const uint8_t **)c_out,
                 (const uint8_t **)u_tilde_out, (const uint8_t **)d_out,
                 (const uint8_t **)a1_tilde_out, (const uint8_t **)a2_tilde_out,
                 (const uint8_t **)decom_i_out, (const uint8_t **)chall_3_out,
                 (const uint8_t **)iv_out, (const uint8_t **)ctr_out);
}

/* ================================================================
 * Proof size
 * ================================================================ */

/*
 * Body-only size: the layout sections from c through ctr.  Used
 * internally everywhere the body offset matters (allocation strides,
 * verify expected-size check).  The public voleith_proof_byte_size
 * wraps this and adds VOLEITH_PROOF_HEADER_BYTES.
 */
static size_t
proof_body_byte_size(const voleith_params_t *params, size_t ell)
{
    unsigned int nb = params->lambda / 8;
    size_t ellhat_bits = ell + 3u * params->lambda + 16u;
    size_t ellhat_bytes = (ellhat_bits + 7u) / 8u;
    size_t ell_bytes = (ell + 7u) / 8u;
    size_t utilde_bytes = nb + VOLEITH_VOLE_HASH_B;

    /* decom_i: n_leafcom * tau * nb  +  T_open * nb */
    size_t decom_size =
        ((size_t)params->n_leafcom * params->tau + (size_t)params->T_open) * nb;

    return (params->tau - 1u) * ellhat_bytes /* c */
           + utilde_bytes                    /* u_tilde */
           + ell_bytes                       /* d */
           + nb                              /* a1_tilde */
           + nb                              /* a2_tilde */
           + decom_size                      /* decom_i */
           + nb                              /* chall_3 */
           + IV_SIZE                         /* iv */
           + 4u;                             /* ctr */
}

size_t
voleith_proof_byte_size(const voleith_params_t *params, size_t ell)
{
    return VOLEITH_PROOF_HEADER_BYTES + proof_body_byte_size(params, ell);
}

/* ================================================================
 * Two-phase API: implementation
 * ================================================================ */

size_t
voleith_commit_blob_size(const voleith_params_t *params,
                         const voleith_circuit_t *circuit)
{
    unsigned int nb = params->lambda / 8;
    size_t ellhat = voleith_qs_ellhat(circuit, params->lambda);
    size_t ellhat_bytes = (ellhat + 7) / 8;
    /*
     * Blob layout for the v1 metadata header design:
     *   header (48 bytes) || hcom (2*nb) || c ((tau-1)*ellhat_bytes) || iv
     * Header rides inside the blob so two-phase callers' derive_chall_1
     * absorbs it transitively without needing header-specific code.
     */
    return VOLEITH_PROOF_HEADER_BYTES + 2u * nb +
           (params->tau - 1u) * ellhat_bytes + IV_SIZE;
}

int
voleith_prove_commit(voleith_prover_commit_t **ctx_out,
                     const voleith_params_t *params,
                     const voleith_circuit_t *circuit, const uint8_t *witness,
                     const uint8_t *instance, const uint8_t *fs_seed,
                     size_t fs_seed_len, uint8_t *commitment_out)
{
    if (!ctx_out || !params || !circuit || !witness || !fs_seed ||
        !commitment_out)
        return -1;
    /* X-7: full parameter validation at the public API boundary. */
    if (voleith_params_validate(params) != 0)
        return -1;
    /* H-N1 / M-N1: reject circuits whose construction silently dropped
     * wires or constraints under OOM. */
    if (!voleith_circuit_ok(circuit))
        return -1;
    /* L-N2: validate every wire-id reference at the public boundary so
     * a malformed circuit fails fast instead of OOB-reading wire / tag
     * buffers in the QS hot loop. */
    if (voleith_circuit_validate(circuit) != 0)
        return -1;

    unsigned int lambda = params->lambda;
    unsigned int nb = lambda / 8;
    unsigned int tau = params->tau;

    size_t ell = voleith_qs_ell(circuit);
    size_t ellhat = voleith_qs_ellhat(circuit, lambda);
    size_t ellhat_bytes = (ellhat + 7) / 8;
    size_t ell_bytes = (ell + 7) / 8;
    size_t utilde_bytes = nb + VOLEITH_VOLE_HASH_B;
    size_t n_instance = voleith_circuit_instance_count(circuit);

    voleith_prover_commit_t *ctx = calloc(1, sizeof(*ctx));
    if (!ctx)
        return -1;

    ctx->params = *params;
    ctx->ell = ell;
    ctx->ellhat_bytes = ellhat_bytes;
    ctx->ell_bytes = ell_bytes;
    ctx->n_instance = n_instance;
    ctx->utilde_bytes = utilde_bytes;

    if (make_vc_params(&ctx->vcp, params) != 0) {
        free(ctx);
        return -1;
    }

    ctx->decom_size = voleith_bavc_opening_size(&ctx->vcp);
    ctx->proof_size = voleith_proof_byte_size(params, ell);

    ctx->pbuf = calloc(ctx->proof_size, 1);
    if (!ctx->pbuf) {
        free(ctx);
        return -1;
    }

    /* Step 0: build and write the v1 metadata header into pbuf[0..47].
     * The body follows at pbuf + VOLEITH_PROOF_HEADER_BYTES, so every
     * subsequent offset is biased by HEADER_BYTES.  The header bytes
     * also get mixed into the Fiat-Shamir transcript (root_seed
     * derivation below and chall_1 derivation in voleith_prove) so
     * that any change to the header invalidates the chall_3 check.
     */
    if (build_header_bytes(ctx->pbuf, circuit, params) != 0) {
        voleith_prover_commit_free(ctx);
        return -1;
    }
    const uint8_t *header_bytes = ctx->pbuf;
    uint8_t *body_base = ctx->pbuf + VOLEITH_PROOF_HEADER_BYTES;

    /* Map proof component pointers into the body region */
    uint8_t *c_ptr, *u_tilde_ptr, *d_ptr, *a1_ptr, *a2_ptr;
    uint8_t *decom_ptr, *chall3_ptr, *iv_ptr, *ctr_ptr;
    proof_layout_w(body_base, params, ellhat_bytes, ell_bytes, ctx->decom_size,
                   &c_ptr, &u_tilde_ptr, &d_ptr, &a1_ptr, &a2_ptr, &decom_ptr,
                   &chall3_ptr, &iv_ptr, &ctr_ptr);

    /* Step 1: Derive root_seed || iv via H_3(fs_seed' = header ‖ fs_seed).
     *
     * Header bytes are mixed in first so the prover and verifier
     * derive matching seeds only when the verifier reconstructs the
     * same fs_seed' (the v1 verify path does, the legacy path does
     * not).
     *
     * P-1: `root_seed` is the most secret value in the protocol -
     * recovery reveals every leaf seed, the VOLE mask, and (through
     * those) the witness.  The wrapping `buf` carries the same bytes.
     * Both must be zeroed on every exit, including the commit-failure
     * path below. */
    uint8_t root_seed[32];
    {
        uint8_t buf[48]; /* max nb + IV_SIZE = 32 + 16 */
        voleith_transcript_t t;
        voleith_transcript_init(&t, lambda, VOLEITH_FS_H3);
        voleith_transcript_absorb(&t, header_bytes, VOLEITH_PROOF_HEADER_BYTES);
        voleith_transcript_absorb(&t, fs_seed, fs_seed_len);
        voleith_transcript_squeeze(&t, buf, nb + IV_SIZE);
        voleith_transcript_clear(&t);
        memcpy(root_seed, buf, nb);
        memcpy(iv_ptr, buf + nb, IV_SIZE);
        voleith_secure_zero(buf, sizeof(buf));
    }

    /* Step 2: VOLEitH commit */
    int commit_rc = voleith_commit(&ctx->com, &ctx->state, &ctx->vcp, root_seed,
                                   iv_ptr, (unsigned int)ellhat);
    voleith_secure_zero(root_seed, sizeof(root_seed));
    if (commit_rc != 0) {
        voleith_prover_commit_free(ctx);
        return -1;
    }

    /* Copy c[0..tau-2] into proof buffer */
    memcpy(c_ptr, ctx->com.c, (tau - 1) * ellhat_bytes);

    /*
     * Fill commitment blob: header (48 bytes) || hcom || c || iv.
     * Header bytes come from pbuf[0..47] (written above by
     * build_header_bytes), so absorbing the blob in derive_chall_1
     * binds the proof to the variant choice and circuit / params
     * identity.
     */
    memcpy(commitment_out, header_bytes, VOLEITH_PROOF_HEADER_BYTES);
    memcpy(commitment_out + VOLEITH_PROOF_HEADER_BYTES, ctx->com.hcom, 2 * nb);
    memcpy(commitment_out + VOLEITH_PROOF_HEADER_BYTES + 2 * nb, c_ptr,
           (tau - 1) * ellhat_bytes);
    memcpy(commitment_out + VOLEITH_PROOF_HEADER_BYTES + 2 * nb +
               (tau - 1) * ellhat_bytes,
           iv_ptr, IV_SIZE);

    *ctx_out = ctx;
    return 0;
}

int
voleith_prove_respond(voleith_proof_t *proof_out, voleith_prover_commit_t *ctx,
                      const voleith_circuit_t *circuit, const uint8_t *witness,
                      const uint8_t *instance, const uint8_t *chall_1)
{
    if (!proof_out || !ctx || !ctx->pbuf || !circuit || !witness || !chall_1)
        return -1;

    const voleith_params_t *params = &ctx->params;
    unsigned int lambda = params->lambda;
    unsigned int nb = lambda / 8;
    size_t ell = ctx->ell;
    size_t ell_bytes = ctx->ell_bytes;
    size_t ellhat_bytes = ctx->ellhat_bytes;
    size_t utilde_bytes = ctx->utilde_bytes;
    const uint8_t *inst = instance ? instance : (const uint8_t *)"";

    /* Map proof component pointers (c and iv already filled by commit).
     * The body starts at pbuf + VOLEITH_PROOF_HEADER_BYTES; the
     * preceding 48 bytes hold the v1 metadata header written by
     * voleith_prove_commit. */
    uint8_t *c, *u_tilde, *d, *a1_tilde, *a2_tilde, *decom_i, *chall_3, *iv,
        *ctr;
    proof_layout_w(ctx->pbuf + VOLEITH_PROOF_HEADER_BYTES, params, ellhat_bytes,
                   ell_bytes, ctx->decom_size, &c, &u_tilde, &d, &a1_tilde,
                   &a2_tilde, &decom_i, &chall_3, &iv, &ctr);

    /* Step 4: u_tilde = VOLEHash(chall_1, u, ell) */
    voleith_vole_hash(u_tilde, chall_1, ctx->com.u, ell, lambda);

    /* Step 5: d = circuit_eval XOR u_slots */
    if (voleith_qs_compute_d(circuit, witness, inst, ctx->com.u, d) != 0)
        return -1;

    /* Step 6: chall_2 = H_2^2(chall_1 || u_tilde || V_tilde[0..λ-1] || d) */
    uint8_t chall_2[3 * 32 + 8];
    {
        voleith_transcript_t t;
        voleith_transcript_init(&t, lambda, VOLEITH_FS_H2_2);
        voleith_transcript_absorb(&t, chall_1, 5 * nb + 8);
        voleith_transcript_absorb(&t, u_tilde, utilde_bytes);

        uint8_t v_tilde[32 + VOLEITH_VOLE_HASH_B];
        for (unsigned int i = 0; i < lambda; i++) {
            voleith_vole_hash(v_tilde, chall_1, ctx->state.v[i], ell, lambda);
            voleith_transcript_absorb(&t, v_tilde, utilde_bytes);
        }

        voleith_transcript_absorb(&t, d, ell_bytes);
        voleith_transcript_squeeze(&t, chall_2, 3 * nb + 8);
        voleith_transcript_clear(&t);
    }

    /* Step 7: QuickSilver prove */
    uint8_t a0_tilde[32];
    {
        uint8_t d_tmp_stack[VOLEITH_STACK_BUF_MAX];
        uint8_t *d_tmp_heap = NULL;
        uint8_t *d_dyn;
        if (ell_bytes > sizeof(d_tmp_stack)) {
            d_tmp_heap = calloc(ell_bytes, 1);
            if (!d_tmp_heap)
                return -1;
            d_dyn = d_tmp_heap;
        } else
            d_dyn = d_tmp_stack;

        int ret = voleith_qs_prove(circuit, witness, inst, lambda, ctx->com.u,
                                   (const uint8_t **)ctx->state.v, chall_2,
                                   d_dyn, a0_tilde, a1_tilde, a2_tilde);
        /* X-9: d_dyn carries `witness ⊕ u_slots` (qs_prove writes d
         * here).  On a memory-disclosure attack combined with u_slots
         * recovery, this would reveal witness bits.  Zero before free
         * / before the stack buffer goes out of scope. */
        if (d_tmp_heap) {
            voleith_secure_zero(d_tmp_heap, ell_bytes);
            free(d_tmp_heap);
        } else {
            voleith_secure_zero(d_tmp_stack, ell_bytes);
        }
        if (ret != 0)
            return -1;
    }

    /* Steps 8-9: chall_3 grinding loop + BAVC open */
    uint32_t ctr_val = 0;
    for (;; ctr_val++) {
        voleith_transcript_t t;
        voleith_transcript_init(&t, lambda, VOLEITH_FS_H2_3);
        voleith_transcript_absorb(&t, chall_2, 3 * nb + 8);
        voleith_transcript_absorb(&t, a0_tilde, nb);
        voleith_transcript_absorb(&t, a1_tilde, nb);
        voleith_transcript_absorb(&t, a2_tilde, nb);
        uint8_t ctr_bytes[4];
        memcpy(ctr_bytes, &ctr_val, 4);
        voleith_transcript_absorb(&t, ctr_bytes, 4);
        voleith_transcript_squeeze(&t, chall_3, nb);
        voleith_transcript_clear(&t);

        if (!check_grinding(chall_3, lambda, params->w_grind))
            continue;

        size_t i_delta[32];
        voleith_decode_challenge(chall_3, &ctx->vcp, i_delta);

        voleith_bavc_opening_t opening;
        memset(&opening, 0, sizeof(opening));
        if (voleith_open(&opening, &ctx->state, &ctx->vcp, i_delta) != 0)
            continue;

        memcpy(decom_i, opening.data, opening.data_len);
        voleith_bavc_opening_free(&opening);
        break;
    }

    memcpy(ctr, &ctr_val, 4);

    /* Transfer pbuf ownership to proof_out */
    proof_out->data = ctx->pbuf;
    proof_out->len = ctx->proof_size;
    ctx->pbuf = NULL; /* prevent double-free in voleith_prover_commit_free() */
    return 0;
}

void
voleith_prover_commit_free(voleith_prover_commit_t *ctx)
{
    if (!ctx)
        return;
    voleith_commitment_free(&ctx->com);
    voleith_prover_free(&ctx->state);
    if (ctx->pbuf) {
        voleith_secure_zero(ctx->pbuf, ctx->proof_size);
        free(ctx->pbuf);
    }
    free(ctx);
}

/*
 * Body-only reconstruction core.  Takes a body-view proof (no v1 header
 * at the front), processes it, and writes hcom_rec || c || iv (no
 * header) to body_blob_out.  See gf8_proof.c's gf8_verify_reconstruct_body
 * for the analogous helper on the GF(2^8) side.
 */
static int
verify_reconstruct_body(voleith_verifier_reconstruct_t **ctx_out,
                        const voleith_proof_t *body_proof,
                        const voleith_params_t *params,
                        const voleith_circuit_t *circuit,
                        uint8_t *body_blob_out)
{
    if (!ctx_out || !body_proof || !body_proof->data || !params || !circuit ||
        !body_blob_out)
        return -1;
    if (voleith_params_validate(params) != 0)
        return -1;
    if (!voleith_circuit_ok(circuit))
        return -1;
    if (voleith_circuit_validate(circuit) != 0)
        return -1;

    unsigned int lambda = params->lambda;
    unsigned int nb = lambda / 8;
    unsigned int tau = params->tau;

    size_t ell = voleith_qs_ell(circuit);
    size_t ellhat = voleith_qs_ellhat(circuit, lambda);
    size_t ellhat_bytes = (ellhat + 7) / 8;
    size_t ell_bytes = (ell + 7) / 8;
    size_t utilde_bytes = nb + VOLEITH_VOLE_HASH_B;
    size_t n_instance = voleith_circuit_instance_count(circuit);

    voleith_vc_params_t vcp;
    if (make_vc_params(&vcp, params) != 0)
        return -1;

    size_t decom_size = voleith_bavc_opening_size(&vcp);
    size_t expected_body_size = proof_body_byte_size(params, ell);

    if (body_proof->len != expected_body_size)
        return -1;

    /* Rebind parameter names for the rest of the function body, which
     * was the original voleith_verify_reconstruct logic. */
    const voleith_proof_t *proof = body_proof;
    uint8_t *commitment_out = body_blob_out;

    /* Parse proof components */
    const uint8_t *c, *u_tilde, *d, *a1_tilde, *a2_tilde, *decom_i_ptr,
        *chall_3_ptr, *iv, *ctr_ptr;
    proof_layout(proof->data, params, ellhat_bytes, ell_bytes, decom_size, &c,
                 &u_tilde, &d, &a1_tilde, &a2_tilde, &decom_i_ptr, &chall_3_ptr,
                 &iv, &ctr_ptr);

    /* Step 1: Check grinding condition */
    if (!check_grinding(chall_3_ptr, lambda, params->w_grind))
        return -1;

    /* Step 2: Decode i_delta */
    size_t i_delta[32];
    voleith_decode_challenge(chall_3_ptr, &vcp, i_delta);

    /* Allocate context */
    voleith_verifier_reconstruct_t *ctx = calloc(1, sizeof(*ctx));
    if (!ctx)
        return -1;

    ctx->params = *params;
    ctx->vcp = vcp;
    ctx->ell = ell;
    ctx->ellhat_bytes = ellhat_bytes;
    ctx->ell_bytes = ell_bytes;
    ctx->n_instance = n_instance;
    ctx->utilde_bytes = utilde_bytes;
    memcpy(ctx->chall_3, chall_3_ptr, nb);
    memcpy(&ctx->ctr_val, ctr_ptr, 4);

    /* Copy small proof fields into context (so caller may free proof after reconstruct) */
    ctx->u_tilde_copy = malloc(utilde_bytes);
    ctx->d_copy = malloc(ell_bytes);
    ctx->a1_tilde_copy = malloc(nb);
    ctx->a2_tilde_copy = malloc(nb);
    if (!ctx->u_tilde_copy || !ctx->d_copy || !ctx->a1_tilde_copy ||
        !ctx->a2_tilde_copy) {
        voleith_verifier_reconstruct_free(ctx);
        return -1;
    }
    memcpy(ctx->u_tilde_copy, u_tilde, utilde_bytes);
    memcpy(ctx->d_copy, d, ell_bytes);
    memcpy(ctx->a1_tilde_copy, a1_tilde, nb);
    memcpy(ctx->a2_tilde_copy, a2_tilde, nb);

    /* Allocate Q matrix: lambda rows × ellhat_bytes */
    ctx->Q = calloc(lambda, sizeof(uint8_t *));
    if (!ctx->Q) {
        voleith_verifier_reconstruct_free(ctx);
        return -1;
    }
    ctx->Q[0] = calloc(lambda, ellhat_bytes);
    if (!ctx->Q[0]) {
        voleith_verifier_reconstruct_free(ctx);
        return -1;
    }
    for (unsigned int i = 1; i < lambda; i++)
        ctx->Q[i] = ctx->Q[0] + (size_t)i * ellhat_bytes;

    /* Wrap proof's decom_i bytes for reconstruct (not freed by us) */
    voleith_bavc_opening_t opening;
    opening.data = (uint8_t *)decom_i_ptr;
    opening.data_len = decom_size;
    opening.n_revealed = 0;

    /* Step 3: VOLEitH reconstruct → hcom_rec, Q */
    uint8_t hcom_rec[64];
    if (voleith_vole_reconstruct(&ctx->vcp, &opening, i_delta, iv,
                                 (unsigned int)ellhat, c, hcom_rec,
                                 ctx->Q) != 0) {
        voleith_verifier_reconstruct_free(ctx);
        return -1;
    }

    /* Fill commitment blob: hcom_rec || c || iv */
    memcpy(commitment_out, hcom_rec, 2 * nb);
    memcpy(commitment_out + 2 * nb, c, (tau - 1) * ellhat_bytes);
    memcpy(commitment_out + 2 * nb + (tau - 1) * ellhat_bytes, iv, IV_SIZE);

    *ctx_out = ctx;
    return 0;
}

/*
 * Public verify_reconstruct: requires a v1 proof (header at start).
 * Validates the header, copies it to commitment_out[0..47], and routes
 * the body to verify_reconstruct_body for the actual reconstruction.
 * Returns -1 on header malformation, identity mismatch, or downstream
 * reconstruction failure.  Legacy proofs are NOT accepted through this
 * entry point; the one-phase voleith_verify handles legacy via the
 * body helper directly.
 */
int
voleith_verify_reconstruct(voleith_verifier_reconstruct_t **ctx_out,
                           const voleith_proof_t *proof,
                           const voleith_params_t *params,
                           const voleith_circuit_t *circuit,
                           uint8_t *commitment_out)
{
    voleith_proof_header_t h;
    voleith_proof_t body_view;

    if (!ctx_out || !proof || !proof->data || !params || !circuit ||
        !commitment_out)
        return -1;

    if (voleith_proof_header_parse(&h, proof->data, proof->len) != 0)
        return -1;
    if (voleith_proof_header_check_identity(&h, circuit, params) != 0)
        return -1;

    memcpy(commitment_out, proof->data, VOLEITH_PROOF_HEADER_BYTES);

    body_view.data = proof->data + VOLEITH_PROOF_HEADER_BYTES;
    body_view.len = proof->len - VOLEITH_PROOF_HEADER_BYTES;

    return verify_reconstruct_body(ctx_out, &body_view, params, circuit,
                                   commitment_out + VOLEITH_PROOF_HEADER_BYTES);
}

int
voleith_verify_respond(voleith_verifier_reconstruct_t *ctx,
                       const voleith_circuit_t *circuit,
                       const uint8_t *instance, const uint8_t *chall_1)
{
    if (!ctx || !circuit || !chall_1)
        return -1;

    const voleith_params_t *params = &ctx->params;
    unsigned int lambda = params->lambda;
    unsigned int nb = lambda / 8;
    size_t ell = ctx->ell;
    size_t ell_bytes = ctx->ell_bytes;
    size_t utilde_bytes = ctx->utilde_bytes;
    const uint8_t *inst = instance ? instance : (const uint8_t *)"";

    /* Steps 5-6: chall_2 = H_2^2(chall_1 || u_tilde || D[0..λ-1] || d)
     * where D[i] = VOLEHash(chall_1, Q[i]) XOR (delta_i ? u_tilde : 0) */
    uint8_t chall_2[3 * 32 + 8];
    {
        voleith_transcript_t t;
        voleith_transcript_init(&t, lambda, VOLEITH_FS_H2_2);
        voleith_transcript_absorb(&t, chall_1, 5 * nb + 8);
        voleith_transcript_absorb(&t, ctx->u_tilde_copy, utilde_bytes);

        uint8_t q_tilde[32 + VOLEITH_VOLE_HASH_B];
        for (unsigned int i = 0; i < lambda; i++) {
            voleith_vole_hash(q_tilde, chall_1, ctx->Q[i], ell, lambda);
            if (get_bit(ctx->chall_3, i)) {
                for (unsigned int k = 0; k < utilde_bytes; k++)
                    q_tilde[k] ^= ctx->u_tilde_copy[k];
            }
            voleith_transcript_absorb(&t, q_tilde, utilde_bytes);
        }

        voleith_transcript_absorb(&t, ctx->d_copy, ell_bytes);
        voleith_transcript_squeeze(&t, chall_2, 3 * nb + 8);
        voleith_transcript_clear(&t);
    }

    /* Step 7: QuickSilver verify → a0_tilde_out */
    uint8_t a0_tilde_out[32];
    if (voleith_qs_verify(circuit, inst, lambda, (const uint8_t **)ctx->Q,
                          ctx->d_copy, ctx->chall_3, /* delta = chall_3 */
                          chall_2, ctx->a1_tilde_copy, ctx->a2_tilde_copy,
                          a0_tilde_out) != 0)
        return -1;

    /* Step 8: Recompute chall_3' and compare */
    uint8_t chall_3_check[32];
    {
        voleith_transcript_t t;
        voleith_transcript_init(&t, lambda, VOLEITH_FS_H2_3);
        voleith_transcript_absorb(&t, chall_2, 3 * nb + 8);
        voleith_transcript_absorb(&t, a0_tilde_out, nb);
        voleith_transcript_absorb(&t, ctx->a1_tilde_copy, nb);
        voleith_transcript_absorb(&t, ctx->a2_tilde_copy, nb);
        uint8_t ctr_bytes[4];
        memcpy(ctr_bytes, &ctx->ctr_val, 4);
        voleith_transcript_absorb(&t, ctr_bytes, 4);
        voleith_transcript_squeeze(&t, chall_3_check, nb);
        voleith_transcript_clear(&t);
    }

    return voleith_const_memcmp(chall_3_check, ctx->chall_3, nb) ? -1 : 0;
}

void
voleith_verifier_reconstruct_free(voleith_verifier_reconstruct_t *ctx)
{
    if (!ctx)
        return;
    if (ctx->Q) {
        if (ctx->Q[0]) {
            voleith_secure_zero(ctx->Q[0],
                                (size_t)ctx->params.lambda * ctx->ellhat_bytes);
            free(ctx->Q[0]);
        }
        free(ctx->Q);
    }
    if (ctx->u_tilde_copy) {
        voleith_secure_zero(ctx->u_tilde_copy, ctx->utilde_bytes);
        free(ctx->u_tilde_copy);
    }
    if (ctx->d_copy) {
        voleith_secure_zero(ctx->d_copy, ctx->ell_bytes);
        free(ctx->d_copy);
    }
    if (ctx->a1_tilde_copy) {
        voleith_secure_zero(ctx->a1_tilde_copy, ctx->params.lambda / 8);
        free(ctx->a1_tilde_copy);
    }
    if (ctx->a2_tilde_copy) {
        voleith_secure_zero(ctx->a2_tilde_copy, ctx->params.lambda / 8);
        free(ctx->a2_tilde_copy);
    }
    free(ctx);
}

/* ================================================================
 * Prove
 * ================================================================ */

int
voleith_prove(voleith_proof_t *proof, const voleith_params_t *params,
              const voleith_circuit_t *circuit, const uint8_t *witness,
              const uint8_t *instance, const uint8_t *fs_seed,
              size_t fs_seed_len)
{
    if (!proof || !params || !circuit || !witness || !fs_seed)
        return -1;

    unsigned int lambda = params->lambda;
    unsigned int nb = lambda / 8;
    size_t n_instance = voleith_circuit_instance_count(circuit);
    size_t instance_bytes = (n_instance + 7) / 8;
    const uint8_t *inst = instance ? instance : (const uint8_t *)"";

    size_t blob_size = voleith_commit_blob_size(params, circuit);
    uint8_t *blob = malloc(blob_size);
    if (!blob)
        return -1;

    voleith_prover_commit_t *ctx = NULL;
    if (voleith_prove_commit(&ctx, params, circuit, witness, instance, fs_seed,
                             fs_seed_len, blob) != 0) {
        free(blob);
        return -1;
    }

    /*
     * chall_1 = H_2^1(fs_seed ‖ instance ‖ blob).
     *
     * blob = header ‖ hcom ‖ c ‖ iv (the v1 blob layout written by
     * voleith_prove_commit).  The header bytes ride along inside the
     * blob, so absorbing the blob binds the proof to the variant
     * choice and circuit / params identity carried in the header
     * without needing a separate absorb call here.  This is the same
     * format used by two-phase shared-transcript callers.
     */
    uint8_t chall_1[5 * 32 + 8];
    {
        voleith_transcript_t t;
        voleith_transcript_init(&t, lambda, VOLEITH_FS_H2_1);
        voleith_transcript_absorb(&t, fs_seed, fs_seed_len);
        if (n_instance > 0)
            voleith_transcript_absorb(&t, inst, instance_bytes);
        voleith_transcript_absorb(&t, blob, blob_size);
        voleith_transcript_squeeze(&t, chall_1, 5 * nb + 8);
        voleith_transcript_clear(&t);
    }
    free(blob);

    int ret =
        voleith_prove_respond(proof, ctx, circuit, witness, instance, chall_1);
    voleith_prover_commit_free(ctx);
    return ret;
}

/* ================================================================
 * Verify
 * ================================================================ */

int
voleith_verify(const voleith_proof_t *proof, const voleith_params_t *params,
               const voleith_circuit_t *circuit, const uint8_t *instance,
               const uint8_t *fs_seed, size_t fs_seed_len)
{
    if (!proof || !proof->data || !params || !circuit || !fs_seed)
        return -1;

    unsigned int lambda = params->lambda;
    unsigned int nb = lambda / 8;
    size_t n_instance = voleith_circuit_instance_count(circuit);
    size_t instance_bytes = (n_instance + 7) / 8;
    const uint8_t *inst = instance ? instance : (const uint8_t *)"";

    /*
     * Full-parse-as-dispatch.  v1 path uses the public
     * verify_reconstruct (which validates the header and writes it
     * verbatim to the front of the blob).  Legacy path goes through
     * verify_reconstruct_body directly with a smaller, header-less
     * blob.  Either way the downstream chall_1 derivation absorbs
     * blob verbatim, so the absorbed bytes match what the
     * corresponding prover produced.
     */
    voleith_proof_header_t h_unused;
    int has_header =
        (voleith_proof_header_parse(&h_unused, proof->data, proof->len) == 0);

    size_t blob_size;
    uint8_t *blob;
    voleith_verifier_reconstruct_t *ctx = NULL;
    int rec_rc;

    if (has_header) {
        blob_size = voleith_commit_blob_size(params, circuit);
        blob = malloc(blob_size);
        if (!blob)
            return -1;
        rec_rc = voleith_verify_reconstruct(&ctx, proof, params, circuit, blob);
    } else {
#ifdef VOLEITH_LEGACY_VERIFY
        /* Legacy blob: hcom_rec || c || iv, no header prefix. */
        size_t ellhat = voleith_qs_ellhat(circuit, lambda);
        size_t ellhat_bytes = (ellhat + 7) / 8;
        blob_size =
            2u * nb + (params->tau - 1u) * ellhat_bytes + (size_t)IV_SIZE;
        blob = malloc(blob_size);
        if (!blob)
            return -1;
        rec_rc = verify_reconstruct_body(&ctx, proof, params, circuit, blob);
#else
        return -1;
#endif
    }

    if (rec_rc != 0) {
        free(blob);
        return -1;
    }

    /*
     * chall_1 = H_2^1(fs_seed ‖ instance ‖ blob).  For v1 the blob
     * starts with the metadata header; for legacy the blob is the
     * pre-header format.  Either way absorption matches the prover.
     */
    uint8_t chall_1[5 * 32 + 8];
    {
        voleith_transcript_t t;
        voleith_transcript_init(&t, lambda, VOLEITH_FS_H2_1);
        voleith_transcript_absorb(&t, fs_seed, fs_seed_len);
        if (n_instance > 0)
            voleith_transcript_absorb(&t, inst, instance_bytes);
        voleith_transcript_absorb(&t, blob, blob_size);
        voleith_transcript_squeeze(&t, chall_1, 5 * nb + 8);
        voleith_transcript_clear(&t);
    }
    free(blob);

    int ret = voleith_verify_respond(ctx, circuit, instance, chall_1);
    voleith_verifier_reconstruct_free(ctx);
    return ret;
}

/* ================================================================
 * Length-validated entry points (M-N3, 1.3.0)
 * ================================================================ */

size_t
voleith_circuit_witness_byte_len(const voleith_circuit_t *circuit)
{
    if (circuit == NULL)
        return 0;
    return (voleith_circuit_witness_count(circuit) + 7u) / 8u;
}

size_t
voleith_circuit_instance_byte_len(const voleith_circuit_t *circuit)
{
    if (circuit == NULL)
        return 0;
    return (voleith_circuit_instance_count(circuit) + 7u) / 8u;
}

int
voleith_prove_v2(voleith_proof_t *proof, const voleith_params_t *params,
                 const voleith_circuit_t *circuit, const uint8_t *witness,
                 size_t witness_len, const uint8_t *instance,
                 size_t instance_len, const uint8_t *fs_seed,
                 size_t fs_seed_len)
{
    /*
     * Validate lengths at the public boundary before any reads.
     * voleith_prove rejects NULL params/circuit/witness/fs_seed itself;
     * we duplicate the circuit check here because we dereference it
     * for the byte-len helpers.
     */
    if (circuit == NULL)
        return -1;
    if (witness_len != voleith_circuit_witness_byte_len(circuit))
        return -1;
    if (instance_len != voleith_circuit_instance_byte_len(circuit))
        return -1;

    return voleith_prove(proof, params, circuit, witness, instance, fs_seed,
                         fs_seed_len);
}

int
voleith_verify_v2(const voleith_proof_t *proof, const voleith_params_t *params,
                  const voleith_circuit_t *circuit, const uint8_t *instance,
                  size_t instance_len, const uint8_t *fs_seed,
                  size_t fs_seed_len)
{
    if (circuit == NULL)
        return -1;
    if (instance_len != voleith_circuit_instance_byte_len(circuit))
        return -1;

    return voleith_verify(proof, params, circuit, instance, fs_seed,
                          fs_seed_len);
}

/* ================================================================
 * Free
 * ================================================================ */

void
voleith_proof_free(voleith_proof_t *proof)
{
    if (proof && proof->data) {
        voleith_secure_zero(proof->data, proof->len);
        free(proof->data);
        proof->data = NULL;
        proof->len = 0;
    }
}
