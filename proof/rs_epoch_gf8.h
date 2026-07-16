/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * rs_epoch_gf8.h - V6 forward-secure epoch key schedule (out of circuit).
 *
 * The GGM binary tree that backs the V6 epoch module (design Q7).  Leaves
 * 0 .. 2^depth_e - 1 are epochs; the leaf seed sk_t is the per-epoch
 * secret fed to the in-circuit epoch subtree (rs_gf8_circuit.c stage A0)
 * and, when V2 is on, keyed directly by the nullifier CMAC (Q5).
 *
 * Forward security comes from a puncturable cover: the state holds the
 * minimal set of subtree-root seeds tiling the range [t, T) of not-yet-
 * retired epochs.  voleith_rs_epoch_state_advance walks the cover forward
 * to a later epoch and zeroizes every seed that could reach an earlier
 * one, so a state captured at epoch t cannot recompute sk_{t'} for any
 * t' < t.  The tree is expanded with the AES-CTR PRG under a V6-specific
 * IV (VOLEITH_RS_EPOCH_PRG_IV_TAG), distinct from the FAEST/BAVC
 * expansion in vole/vc.c so the two schedules never collide.
 *
 * This translation unit owns only the key schedule (expand, cover,
 * advance, derive, zeroize).  Keygen (the epoch tree build and public
 * node store) and versioned serialization arrive in later tickets
 * (EP.KEYGEN, EP.STATE), which extend the state defined here.
 */

#ifndef VOLEITH_RS_EPOCH_GF8_H
#define VOLEITH_RS_EPOCH_GF8_H

#include <stddef.h>
#include <stdint.h>

#include "rs_gf8.h" /* VOLEITH_RS_EPOCH_MAX_DEPTH */

/* Widest epoch seed (epoch_sk_bytes) this module carries: AES-256 key. */
#define VOLEITH_RS_EPOCH_SEED_MAX_BYTES 32u

/*
 * Inline cap on the V6 leaf salt.  The salt rides into the leaf OWF
 * preimage (epoch_root || attrs || salt), bounded by the OWF block
 * capacity minus the node width; the widest fixed-input block is
 * grostl-512-fixed at 128 with a 64-byte node, so 64 is a safe ceiling.
 */
#define VOLEITH_RS_EPOCH_SALT_MAX_BYTES 64u

/*
 * 16-byte AES-CTR PRG IV that domain-separates the V6 epoch GGM
 * expansion from every other PRG use in the library (in particular the
 * FAEST/BAVC GGM in vole/vc.c, which uses the per-signature IV).  Exactly
 * 16 visible bytes, so a char-array initializer stores it without a NUL.
 */
#define VOLEITH_RS_EPOCH_PRG_IV_TAG "VOLEitH-RSv6-GGM"

/*
 * voleith_rs_epoch_state_t - the puncturable forward-secure key state.
 *
 * The cover is `n_cover` subtree-root seeds tiling [t, T) with T =
 * 2^depth_e.  cover_heap[i] is the node's heap index (root = 1, node H
 * has children 2H and 2H+1); cover_seed holds the seed_bytes-wide seed
 * for block i at offset i * seed_bytes.  Only the first n_cover slots are
 * meaningful; advance zeroizes the rest.
 *
 * The struct holds secret material (the cover seeds); zeroize with
 * voleith_rs_epoch_state_clear before it goes out of scope.
 */
typedef struct {
    size_t depth_e;    /* tree depth; 1 .. VOLEITH_RS_EPOCH_MAX_DEPTH */
    size_t seed_bytes; /* epoch_sk_bytes; 16 or 32 */
    int lambda;        /* seed_bytes * 8 (128 or 256) */
    uint64_t T;        /* 1 << depth_e (epoch count) */
    uint64_t t;        /* current epoch; the cover tiles [t, T) */
    size_t n_cover;    /* number of live cover blocks */
    uint64_t cover_heap[VOLEITH_RS_EPOCH_MAX_DEPTH + 1];
    uint8_t cover_seed[(VOLEITH_RS_EPOCH_MAX_DEPTH + 1) *
                       VOLEITH_RS_EPOCH_SEED_MAX_BYTES];

    /*
     * EP.KEYGEN additions.  The epoch tree (public) plus the leaf salt
     * (secret).  A state produced by voleith_rs_epoch_state_init alone
     * (EP.GGM key schedule only) leaves these zero/NULL; voleith_rs_epoch_
     * keygen populates them.
     */
    const voleith_node_hash_vt *epoch_hash; /* leaf/inode hash for the tree */
    size_t node_bytes;                      /* epoch_hash->node_bytes */
    uint8_t *public_nodes;   /* heap: (2T-1) * node_bytes, level-major,
                              * leaves first, root last (public, not secret) */
    size_t public_nodes_len; /* byte length of public_nodes */
    uint8_t epoch_root[MERKLE_VT_MAX_NODE_BYTES];       /* node_bytes wide */
    size_t leaf_salt_bytes;                             /* 0 = no salt */
    uint8_t leaf_salt[VOLEITH_RS_EPOCH_SALT_MAX_BYTES]; /* secret */

    /* cfg binding: the config fingerprint this state was built under
     * (voleith_rs_config_fingerprint), set by keygen / load. */
    uint8_t cfg_fingerprint[VOLEITH_RS_CONFIG_FINGERPRINT_BYTES];
} voleith_rs_epoch_state_t;

/*
 * voleith_rs_epoch_state_init - seed the schedule at epoch 0.
 *
 * The caller supplies the identity master seed (the library never
 * generates keys, RSV1 convention); it becomes the root cover block, so
 * the initial cover tiles the whole range [0, T).
 *
 * depth_e in [1, VOLEITH_RS_EPOCH_MAX_DEPTH]; epoch_sk_bytes in {16, 32};
 * master_seed is epoch_sk_bytes wide.
 *
 * Returns 0 on success, -1 on NULL argument or out-of-range parameter.
 */
int voleith_rs_epoch_state_init(voleith_rs_epoch_state_t *st, size_t depth_e,
                                size_t epoch_sk_bytes,
                                const uint8_t *master_seed);

/*
 * voleith_rs_epoch_state_advance - retire epochs before target_t.
 *
 * Recomputes the cover to tile [target_t, T) and zeroizes every seed that
 * could reach an earlier epoch, so the state can no longer derive sk_{t'}
 * for t' < target_t (forward security).  Strictly forward-only:
 * target_t <= st->t or target_t >= T is rejected.
 *
 * Returns 0 on success, -1 on NULL / out-of-range target_t.
 */
int voleith_rs_epoch_state_advance(voleith_rs_epoch_state_t *st,
                                   uint64_t target_t);

/*
 * voleith_rs_epoch_derive_sk - derive the epoch seed sk_t.
 *
 * t must be covered (st->t <= t < T); the seed is produced by a PRG walk
 * down from the covering block to leaf t.  sk_out is seed_bytes wide.
 *
 * Returns 0 on success, -1 on NULL argument or an uncovered t (already
 * retired, i.e. t < st->t, or t >= T).
 */
int voleith_rs_epoch_derive_sk(const voleith_rs_epoch_state_t *st, uint64_t t,
                               uint8_t *sk_out);

/*
 * voleith_rs_epoch_state_clear - free the public-node store and zeroize
 * the whole secret state.  Safe on a zeroed / already-cleared state.
 */
void voleith_rs_epoch_state_clear(voleith_rs_epoch_state_t *st);

/* ================================================================
 * EP.KEYGEN: epoch tree build + public-node store.
 * ================================================================ */

/*
 * voleith_rs_epoch_keygen - build an identity's epoch tree (design 8.1).
 *
 * The caller supplies the identity master seed (the library never
 * generates keys) and, when the config enables the salt, the random leaf
 * salt.  Keygen:
 *   1. GGM-expands master_seed to T = 2^depth_e leaf seeds sk_0..sk_{T-1},
 *   2. hashes each h_t = epoch_hash->leaf_hash(sk_t),
 *   3. builds the epoch Merkle tree over h_0..h_{T-1}, keeping ALL 2T-1
 *      public node hashes in state_out (so sign-time sibling extraction is
 *      O(depth) index arithmetic; see voleith_rs_epoch_path),
 *   4. writes the root to epoch_root_out (the member's ring leaf value),
 *   5. initializes the forward-secure state at epoch 0 (cover = root seed,
 *      public nodes, leaf salt when configured, cfg binding),
 *   6. zeroizes the transient full seed expansion.
 *
 * cfg must validate (voleith_rs_config_validate) with the epoch module on
 * (depth_e > 0).  epoch_hash is cfg->epoch_hash, or membership.tree_hash
 * when NULL.  master_seed is epoch_sk_bytes wide.  leaf_salt is
 * cfg->leaf_salt_bytes wide (NULL iff leaf_salt_bytes == 0).
 * epoch_root_out is epoch_hash->node_bytes wide.
 *
 * On success state_out owns a heap allocation; release it with
 * voleith_rs_epoch_state_clear.  Returns 0 on success, -1 on NULL / invalid
 * argument, config validation failure, salt over
 * VOLEITH_RS_EPOCH_SALT_MAX_BYTES, a propagated vt hash failure, or
 * allocation failure.  On failure state_out is cleared.
 */
int voleith_rs_epoch_keygen(const voleith_rs_config_t *cfg,
                            const uint8_t *master_seed,
                            const uint8_t *leaf_salt,
                            voleith_rs_epoch_state_t *state_out,
                            uint8_t *epoch_root_out);

/*
 * voleith_rs_epoch_path - extract the epoch authentication path for epoch
 * t from the stored public nodes.
 *
 * Writes depth_e * node_bytes sibling bytes to siblings_out, leaf level
 * first, matching the secret-dir / public-dir Merkle path convention
 * (sibling at level k is the node at position (t >> k) ^ 1 within level
 * k).  Directions are the bits of t; the caller derives them (the sign
 * layer does this internally).  Pure O(depth) index arithmetic over the
 * public node store; t may be any epoch in [0, T).
 *
 * Returns 0 on success, -1 on NULL argument, a state without a built tree
 * (public_nodes == NULL), or t >= T.
 */
int voleith_rs_epoch_path(const voleith_rs_epoch_state_t *st, uint64_t t,
                          uint8_t *siblings_out);

/* ================================================================
 * EP.STATE: versioned on-disk serialization (design 8.3).
 *
 * V6's state MUST survive process restarts across epochs or the scheme is
 * unusable, so a versioned format ships with the feature.  On-wire layout:
 *
 *   offset  size            field
 *   ------  --------------  -----
 *        0  4               magic = "VRSE"
 *        4  1               format version = 1
 *        5  16              cfg_fingerprint (voleith_rs_config_fingerprint)
 *       21  8               t, big-endian (current epoch)
 *       29  8               cover_count, big-endian
 *       37  cover_count *   (node_index_be8 || seed[seed_bytes])
 *           (8+seed_bytes)
 *          ...  leaf_salt_bytes   leaf salt (present iff cfg configures it)
 *          ...  (2T-1)*node_bytes public node hashes (level-major)
 *
 * seed_bytes, leaf_salt_bytes, node_bytes, and T are recovered from the
 * caller-supplied cfg at load time (the cfg_fingerprint pins them), so
 * they are not stored again.  The epoch root is the last public node, so
 * it is not stored separately either.
 *
 * WARNING (backup semantics): every copy of a serialized state is a copy
 * of the keys.  A restored backup silently reverts erasure and voids
 * forward security from the backup point onward: an attacker who obtains
 * an old backup can sign for every epoch that was still live when the
 * backup was taken.  Treat the state file like a private key and do not
 * keep stale copies.
 * ================================================================ */

#define VOLEITH_RS_EPOCH_STATE_MAGIC "VRSE"
#define VOLEITH_RS_EPOCH_STATE_VERSION 0x01u

/* Fixed header bytes preceding the variable sections (magic + version +
 * cfg_fingerprint + t_be8 + cover_count_be8). */
#define VOLEITH_RS_EPOCH_STATE_HEADER_BYTES                                    \
    (4u + 1u + VOLEITH_RS_CONFIG_FINGERPRINT_BYTES + 8u + 8u)

/*
 * voleith_rs_epoch_state_serialized_len - exact serialized byte length for
 * st (which depends on the current cover size).  Returns 0 if st is NULL
 * or carries no built tree (public_nodes == NULL).
 */
size_t
voleith_rs_epoch_state_serialized_len(const voleith_rs_epoch_state_t *st);

/*
 * voleith_rs_epoch_state_serialize - write st to out.
 *
 * out_len must equal voleith_rs_epoch_state_serialized_len(st).
 * written_out (if non-NULL) receives the byte count written.
 *
 * Returns 0 on success, -1 on NULL argument, a state without a built tree,
 * or out_len mismatch.
 */
int voleith_rs_epoch_state_serialize(const voleith_rs_epoch_state_t *st,
                                     uint8_t *out, size_t out_len,
                                     size_t *written_out);

/*
 * voleith_rs_epoch_state_load - parse buf into state_out under cfg.
 *
 * Validates magic, version, the embedded cfg_fingerprint (constant-time
 * against cfg), the cover structure (must match the tiling implied by the
 * stored t), and the exact buffer length (rejects truncation and trailing
 * bytes).  seed_bytes / node_bytes / T / leaf_salt_bytes are taken from
 * cfg; the epoch root is recovered from the last public node.
 *
 * On success state_out owns a heap allocation; release it (and zeroize the
 * loaded secret sections) with voleith_rs_epoch_state_clear.  Returns 0 on
 * success, -1 on NULL / invalid cfg, short or mismatched buffer, magic /
 * version / fingerprint / cover mismatch, or allocation failure.
 * state_out is cleared on failure.
 */
int voleith_rs_epoch_state_load(voleith_rs_epoch_state_t *state_out,
                                const voleith_rs_config_t *cfg,
                                const uint8_t *buf, size_t buf_len);

/* ================================================================
 * EP.SIGN: convenience signer that derives the epoch secrets from state.
 * ================================================================ */

/*
 * voleith_rs_epoch_sign - sign at the state's covered epoch pub->epoch,
 * deriving sk_t, the epoch siblings, and the leaf salt from the state.
 *
 * A thin wrapper over voleith_rs_sign: it fills a copy of `path` with the
 * epoch-derived fields (epoch_sk = derive_sk(state, pub->epoch),
 * epoch_siblings = the stored epoch path, epoch_salt = the state salt when
 * configured, epoch = pub->epoch) and forwards everything else.  The caller
 * still supplies the membership path and any other module inputs in `path`,
 * the attributes, and the public inputs (including pub->epoch).
 *
 * state must have been built under cfg (its cfg_fingerprint must match) and
 * must cover pub->epoch (state->t <= pub->epoch < 2^depth_e); the explicit
 * voleith_rs_sign entry stays primary.  sk is NULL (V6 has no static
 * membership sk).
 *
 * Returns 0 on success, -1 on NULL / invalid argument, a state/cfg
 * mismatch, an uncovered epoch, or a propagated sign failure.
 */
int voleith_rs_epoch_sign(voleith_rs_sig_t *sig_out,
                          const voleith_rs_epoch_state_t *state,
                          const voleith_rs_config_t *cfg,
                          const voleith_params_t *params, const uint8_t *attrs,
                          const voleith_rs_path_t *path,
                          const voleith_rs_public_t *pub, const uint8_t *m,
                          size_t m_len);

#endif /* VOLEITH_RS_EPOCH_GF8_H */
