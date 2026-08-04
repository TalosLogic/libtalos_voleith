/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * rs_opener_argus_gf8.h - Argus (QC-MDPC code-based) opener backend.
 *
 * The one opener scheme shipped today (VOLEITH_RS_OPENER_SCHEME_ARGUS): a
 * designated opener over the QC-MDPC syndrome PKE.  The signer encrypts its
 * identity with a fresh weight-t error e: the tag carries s = M*e^T and a DEM
 * ciphertext ct = identity XOR pad, where pad comes from K = H(support(e)); the
 * opener recovers e by decoding and recomputes K to trace.  This header is the
 * software side both the signer and the opener-verify path need: the parameter
 * tables, the (M, s, ct) byte layout, the constant-time syndrome recompute, the
 * KDF and DEM, and the backend's ops instance.
 *
 * CLEAN-ROOM reimplementation of libtalos_syndrome's byte-exact contract
 * (docs/private/VOLEITH_CONTRACT.md, rows A0-A7), NOT a port of syndrome's
 * opener/argus.c.  The two libraries share no source dependency: only this byte
 * layout and the shared Argus KAT vectors, which are the ground truth both sides
 * diff against.  The circulant arithmetic is ichor's shared F_2[x]/(x^p-1) ring
 * (<ichor/gf2x.h>); the KDF primitives are ichor's AES-DM (lambda128) /
 * Grostl-256 (lambda256).
 *
 * Every routine that touches the support (indices / e) is constant-time over
 * that secret: the support is the de-anonymizing identity K = H(support(e))
 * (contract A3; DESIGN.md §6.2, §7).
 */

#ifndef VOLEITH_RS_OPENER_ARGUS_GF8_H
#define VOLEITH_RS_OPENER_ARGUS_GF8_H

#include "rs_opener_gf8.h" /* scheme vtable, witness ref, status, scheme id */

#include <stddef.h>
#include <stdint.h>

/*
 * Shipped opener parameter sets, (lambda, n0).  All 12 of the planned space
 * (lambda in {128,192,256} x n0 in {2,3,4,5}) have a STABLE id reserved so the
 * numbering never churns (the id may reach the wire via OP.SER).  Only the four
 * sets pinned in contract A7 are parameterized in this build; the other eight are
 * reserved ids whose params() returns NULL (the generic layer maps that to
 * VOLEITH_RS_OPENER_ESET).  Adding a set fills a reserved row; it never
 * renumbers.
 */
typedef enum {
    VOLEITH_RS_OPENER_ARGUS_SET_128_2 = 0,
    VOLEITH_RS_OPENER_ARGUS_SET_128_3 = 1, /* reserved */
    VOLEITH_RS_OPENER_ARGUS_SET_128_4 = 2, /* reserved */
    VOLEITH_RS_OPENER_ARGUS_SET_128_5 = 3,
    VOLEITH_RS_OPENER_ARGUS_SET_192_2 = 4, /* reserved */
    VOLEITH_RS_OPENER_ARGUS_SET_192_3 = 5, /* reserved */
    VOLEITH_RS_OPENER_ARGUS_SET_192_4 = 6, /* reserved */
    VOLEITH_RS_OPENER_ARGUS_SET_192_5 = 7, /* reserved */
    VOLEITH_RS_OPENER_ARGUS_SET_256_2 = 8,
    VOLEITH_RS_OPENER_ARGUS_SET_256_3 = 9,  /* reserved */
    VOLEITH_RS_OPENER_ARGUS_SET_256_4 = 10, /* reserved */
    VOLEITH_RS_OPENER_ARGUS_SET_256_5 = 11,
    VOLEITH_RS_OPENER_ARGUS_SET_COUNT = 12
} voleith_rs_opener_argus_set_t;

/*
 * Primitive registry ids for the KDF hash (contract A5), carried as the tag's
 * leading hash_id (prim_id) byte so the tag is self-describing.  Distinct from
 * scheme_id (which PKE) and from the set (which params).
 */
#define VOLEITH_RS_OPENER_ARGUS_PRIM_AESDM 0x01u /* AES-128 Davies-Meyer   */
#define VOLEITH_RS_OPENER_ARGUS_PRIM_GROSTL256                                 \
    0x02u                                         /* Grostl-256             */
#define VOLEITH_RS_OPENER_ARGUS_PRIM_HIROSE 0x03u /* reserved, not compiled */
#define VOLEITH_RS_OPENER_ARGUS_PRIM_GROSTL512                                 \
    0x04u /* reserved, not compiled */

/* Domain-separation IV core width (contract A5); zero-padded to 64 B internally
 * for the Grostl KDF. */
#define VOLEITH_RS_OPENER_ARGUS_DS_IV_BYTES 16u

/*
 * Resolved per-set values (contract A7): the byte-exact diff target against
 * syndrome's opener/argus.c + sets/set_params.h and the shared KAT vectors.
 *
 *   p            circulant prime; ring is F_2[x]/(x^p-1).
 *   n0           block count (identity block implicit in M).
 *   t            error weight (one set bit per one-hot chunk).
 *   n            code length n0*p; support indices live in [0, n).
 *   block_bytes  ceil(p/8): one circulant block, LSB-first, canonical zero pad;
 *                also the s wire width (SYNDROME_CT_BYTES).
 *   idx_bits     ceil(log2 n): KDF support-index packing width (A3).
 *   msg_bytes    ceil(t*idx_bits/8): packed KDF message length (A3).
 *   key_bytes    lambda/8: K width, and the no-CTR DEM cutoff (A6).
 *   id_max       3*lambda/8: max wrapped identity length (A2).
 *   prim_default the per-lambda default primitive id (A5); 1.11.0 emits only it.
 *   ds_iv        the 16-byte (lambda, prim, n0) set-identity IV (A5/A7).
 */
typedef struct {
    voleith_rs_opener_argus_set_t set;
    unsigned lambda;
    uint32_t p;
    uint32_t n0;
    uint32_t t;
    uint32_t n;
    size_t block_bytes;
    uint32_t idx_bits;
    size_t msg_bytes;
    size_t key_bytes;
    size_t id_max;
    uint8_t prim_default;
    uint8_t ds_iv[VOLEITH_RS_OPENER_ARGUS_DS_IV_BYTES];
} voleith_rs_opener_argus_params_t;

/*
 * The Argus backend ops instance, registered under
 * VOLEITH_RS_OPENER_SCHEME_ARGUS.  Use through the generic
 * voleith_rs_opener_* entry points, or the typed helpers below directly.
 */
extern const voleith_rs_opener_scheme_t voleith_rs_opener_argus;

/*
 * Typed parameter lookup: the pinned row for a set, or NULL if `set` is out of
 * range or a reserved-but-unparameterized set in this build.  (The generic
 * voleith_rs_opener_scheme_t::params wraps this and takes a uint32_t.)
 */
const voleith_rs_opener_argus_params_t *
voleith_rs_opener_argus_params(voleith_rs_opener_argus_set_t set);

/*
 * Stamp a generic witness reference for the Argus scheme over the caller's
 * ascending support index list (`indices`, length t, kept live by the caller).
 */
void voleith_rs_opener_argus_witness(voleith_rs_opener_witness_t *w,
                                     const uint32_t *indices);

/* ---- (M, s, ct) tag layout (contract A0/A2) -------------------------------
 * tag = hash_id(1) || s(block_bytes) || ct(id_len).  M is (n0-1) circulant
 * blocks of block_bytes (leading identity block implicit).  All blocks are
 * length-p ring elements, LSB-first, top pad bits zero (A0).
 */

/* Total tag length: 1 + block_bytes + id_len.  0 if params is NULL. */
size_t voleith_rs_opener_argus_tag_bytes(
    const voleith_rs_opener_argus_params_t *params, size_t id_len);

/*
 * Split a tag into parts: writes *hash_id_out and points *s_out / *ct_out into
 * `tag` (no copy).  Returns EARGS on a null argument, a bad `id_len` (0 or
 * > id_max), or a `tag_len` that is not voleith_rs_opener_argus_tag_bytes(...).
 */
int voleith_rs_opener_argus_tag_parse(
    const voleith_rs_opener_argus_params_t *params, const uint8_t *tag,
    size_t tag_len, size_t id_len, uint8_t *hash_id_out, const uint8_t **s_out,
    const uint8_t **ct_out);

/* ---- software syndrome layer (sign + opener-verify) ------------------------ */

/*
 * s_out = M*e^T (systematic form s = M0*e0 + ... + e_{n0-1}, contract A1), with e
 * given as its t ascending global support positions in [0, n).  Scatters the
 * support into the n0 dense blocks obliviously and accumulates over the ichor
 * ring, so it is CONSTANT-TIME over the secret support.  M is (n0-1) blocks of
 * block_bytes; s_out is block_bytes.  Returns EARGS on a null argument or an
 * index >= n.
 */
int
voleith_rs_opener_argus_syndrome(const voleith_rs_opener_argus_params_t *params,
                                 uint8_t *s_out, const uint8_t *M,
                                 const uint32_t *indices);

/*
 * K_out = H(support(e)) (contract A3-A5): bit-pack the t ascending `indices`
 * LSB-first at idx_bits each, absorb through the primitive named by `hash_id`
 * under the set's DS IV, finalize fixed-input.  K_out is key_bytes.  Returns
 * EUNSUPPORTED if `hash_id` is not this build's compiled primitive for the set's
 * lambda (A5 staging).  Constant-time over the support.
 */
int voleith_rs_opener_argus_kdf(const voleith_rs_opener_argus_params_t *params,
                                uint8_t *K_out, uint8_t hash_id,
                                const uint32_t *indices);

/*
 * Fill pad_out[0:pad_len] with the DEM one-time-pad keystream from K (contract
 * A6): K truncated when pad_len <= key_bytes, else K keys AES-CTR (AES-128 @
 * lambda128 / AES-256 @ lambda256) under the fixed label.  pad_len (== id_len) is
 * public.  Returns EARGS on a null argument or pad_len > id_max.
 */
int
voleith_rs_opener_argus_dem_pad(const voleith_rs_opener_argus_params_t *params,
                                uint8_t *pad_out, size_t pad_len,
                                const uint8_t *K);

/*
 * Typed verify (the concrete op behind voleith_rs_opener_argus.verify): recompute
 * s' = M*e^T from `indices` and require s' == `s` (ESYNDROME); derive K under
 * `hash_id` (EUNSUPPORTED if not compiled); require `id` == `tag_ct` XOR
 * DEM-pad(K) (EIDENTITY).  Byte comparisons use voleith_const_memcmp.  Returns
 * VOLEITH_RS_OPENER_OK iff all three hold.
 *
 *   M       (n0-1) circulant blocks, block_bytes each.
 *   s       one block (block_bytes), the tag's syndrome field.
 *   tag_ct  id_len bytes, the tag's DEM ciphertext field.
 *   hash_id the tag's leading prim_id byte.
 *   indices t ascending global support positions in [0, n).
 *   id      id_len bytes, the claimed identity.
 */
int voleith_rs_opener_argus_verify(
    const voleith_rs_opener_argus_params_t *params, const uint8_t *M,
    const uint8_t *s, const uint8_t *tag_ct, uint8_t hash_id,
    const uint32_t *indices, const uint8_t *id, size_t id_len);

#endif /* VOLEITH_RS_OPENER_ARGUS_GF8_H */
