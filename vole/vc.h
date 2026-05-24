/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * vc.h - Vector commitment via GGM tree (FAEST spec Section 5)
 *
 * Implements the Batch All-but-One Vector Commitment (BAVC) scheme from
 * FAEST v2.0. The core data structure is a GGM tree: a complete binary tree
 * where each internal node's seed is expanded via PRG to produce two child
 * seeds.
 *
 * Tree indexing (0-based):
 *   - Root:            node 0
 *   - Children of α:   nodes 2α+1 and 2α+2
 *   - Internal nodes:  0 .. L-2
 *   - Leaves:          L-1 .. 2L-2
 *   - Total nodes:     2L-1
 *
 * Each node stores a lambda-bit seed (lambda/8 bytes).
 *
 * The GGM tree expansion rule (FAEST spec Figure 5.4, line 7):
 *   (k_{2α+1}, k_{2α+2}) ← PRG(k_α, iv, α; 2λ)
 */

#ifndef VOLEITH_VC_H
#define VOLEITH_VC_H

#include <stdint.h>
#include <stddef.h>

/*
 * VOLE parameters derived from the FAEST parameter set.
 * See FAEST spec Table 5.1 for definitions.
 */
typedef struct {
    int lambda;    /* security parameter: 128, 192, or 256 */
    int tau;       /* number of VOLE instances */
    int tau1;      /* number of larger (k-bit) instances */
    int tau0;      /* number of smaller (k-1 bit) instances */
    int k;         /* bit-length of larger instances */
    size_t L;      /* total number of leaves in the GGM tree */
    int n_leafcom; /* lambda-bit blocks per leaf commitment (2=EM, 3=FAEST) */
    int w_grind;   /* grinding parameter */
    int T_open; /* max number of revealed seeds in opening (FAEST spec Table 3.2) */
} voleith_vc_params_t;

/*
 * Initialize VC parameters from the FAEST main parameters.
 *
 * lambda:    security parameter (128, 192, or 256)
 * tau:       number of VOLE instances
 * w_grind:   grinding parameter
 * n_leafcom: lambda-bit blocks per leaf commitment (2 for FAEST-EM, 3 for FAEST)
 * T_open:    max number of revealed seeds in opening (from FAEST spec Table 3.2)
 *
 * Computes k, tau1, tau0, L per FAEST spec Table 5.1.
 * Returns 0 on success, -1 on invalid parameters.
 */
int voleith_vc_params_init(voleith_vc_params_t *params, int lambda, int tau,
                           int w_grind, int n_leafcom, int T_open);

/*
 * Compute N_i - the field size (number of leaves) for the i-th VOLE instance.
 *
 * N_i = 2^k if i < tau1, else 2^{k-1}
 */
size_t voleith_vc_N(const voleith_vc_params_t *params, int i);

/*
 * PosInTree(i, j) - Map (vector index, position) to GGM tree leaf index.
 *
 * FAEST spec Figure 5.2.
 * Input:  i ∈ [0..τ), j ∈ [0..N_i)
 * Output: α ∈ [L-1 .. 2L-2]
 */
size_t voleith_pos_in_tree(const voleith_vc_params_t *params, int i, size_t j);

/*
 * GGM tree - stores seeds for all 2L-1 nodes.
 */
typedef struct {
    uint8_t *nodes;    /* flat array: node α at offset α * seed_bytes */
    size_t L;          /* number of leaves */
    int lambda;        /* security parameter */
    size_t seed_bytes; /* lambda / 8 */
} voleith_ggm_tree_t;

/*
 * Allocate a GGM tree for L leaves at security level lambda.
 *
 * Returns 0 on success, -1 on allocation failure.
 */
int voleith_ggm_tree_alloc(voleith_ggm_tree_t *tree, size_t L, int lambda);

/*
 * Free a GGM tree. Securely zeros all seed material before freeing.
 */
void voleith_ggm_tree_free(voleith_ggm_tree_t *tree);

/*
 * Expand a GGM tree from a root seed.
 *
 * Sets node 0 to root_seed, then for each internal node α ∈ [0..L-2]:
 *   (k_{2α+1}, k_{2α+2}) ← PRG(k_α, iv, α; 2λ)
 *
 * root_seed: lambda/8 bytes
 * iv:        128-bit initialization vector (16 bytes)
 */
void voleith_ggm_tree_expand(voleith_ggm_tree_t *tree, const uint8_t *root_seed,
                             const uint8_t iv[16]);

/*
 * Get a pointer to the seed for tree node α.
 *
 * Returns pointer to lambda/8 bytes within the tree's node array.
 * The pointer is valid until the tree is freed.
 */
static inline const uint8_t *
voleith_ggm_tree_node(const voleith_ggm_tree_t *tree, size_t alpha)
{
    return tree->nodes + alpha * tree->seed_bytes;
}

/*
 * Get a pointer to the seed for leaf index i (0-based).
 *
 * Leaf i corresponds to tree node (L-1+i).
 */
static inline const uint8_t *
voleith_ggm_tree_leaf(const voleith_ggm_tree_t *tree, size_t i)
{
    return voleith_ggm_tree_node(tree, tree->L - 1 + i);
}

/* ================================================================
 * BAVC Commit - Batch All-but-One Vector Commitment
 * FAEST spec Section 5.2, Figure 5.4
 * ================================================================ */

/*
 * Result of BAVC.Commit.
 *
 * Contains the global commitment, the GGM tree (for later opening),
 * per-leaf commitments, and per-vector hashes.
 */
typedef struct {
    voleith_ggm_tree_t tree; /* full GGM tree with all node seeds */
    uint8_t *leaf_coms;  /* per-leaf commitments: L entries, each com_bytes */
    uint8_t *leaf_seeds; /* per-leaf seeds: L entries, each seed_bytes */
                         /* for EM: leaf_seeds[α] = k_α (same as tree leaf) */
                         /* for FAEST: first λ bits of PRG(k_α,...) */
    uint8_t com[64];   /* global commitment H_1(h_0‖...‖h_{τ-1}), 2λ/8 bytes */
    size_t com_bytes;  /* bytes per leaf commitment: n_leafcom * lambda/8 */
    size_t seed_bytes; /* lambda / 8 */
} voleith_bavc_t;

/*
 * Run BAVC.Commit: expand GGM tree, compute leaf commitments, hash them.
 *
 * params:    VC parameters (from voleith_vc_params_init)
 * root_seed: lambda/8 bytes, the root seed r
 * iv:        128-bit initialization vector (16 bytes)
 * result:    output structure (caller-allocated, contents will be malloc'd)
 *
 * Returns 0 on success, -1 on error.
 * Caller must call voleith_bavc_free() to release allocated memory.
 */
int voleith_bavc_commit(voleith_bavc_t *result,
                        const voleith_vc_params_t *params,
                        const uint8_t *root_seed, const uint8_t iv[16]);

/*
 * Free all memory in a BAVC commit result.
 * Securely zeros sensitive material before freeing.
 */
void voleith_bavc_free(voleith_bavc_t *result);

/*
 * Get the leaf seed sd_{i,j} from a BAVC commit result.
 *
 * The returned pointer is valid until voleith_bavc_free() is called.
 */
const uint8_t *voleith_bavc_leaf_seed(const voleith_bavc_t *result,
                                      const voleith_vc_params_t *params, int i,
                                      size_t j);

/*
 * Get the leaf commitment com_{i,j} from a BAVC commit result.
 */
const uint8_t *voleith_bavc_leaf_com(const voleith_bavc_t *result,
                                     const voleith_vc_params_t *params, int i,
                                     size_t j);

/* ================================================================
 * BAVC Open - Reveal all-but-one decommitment
 * FAEST spec Section 5.2, Figure 5.4 (Open)
 * ================================================================ */

/*
 * Result of BAVC.Open.
 *
 * Contains the decommitment data needed by the verifier:
 *   - τ hidden leaf commitments (com_{i,Δ_i})
 *   - Revealed sibling seeds from the GGM tree
 *
 * Stored as a flat byte buffer matching the spec's decom_I format:
 *   [com_{0,Δ_0} | ... | com_{τ-1,Δ_{τ-1}} | seed_1 | ... | seed_n | zero_padding]
 *
 * Total size: n_leafcom * τ * (λ/8) + T_open * (λ/8) bytes.
 */
typedef struct {
    uint8_t *data;     /* flat decom_I buffer */
    size_t data_len;   /* total length in bytes */
    size_t n_revealed; /* number of revealed sibling seeds */
} voleith_bavc_opening_t;

/*
 * Run BAVC.Open: given challenge indices Δ_i, produce the decommitment.
 *
 * bavc:     committed BAVC result (from voleith_bavc_commit)
 * params:   VC parameters
 * i_delta:  array of τ challenge indices, i_delta[i] ∈ [0..N_i)
 * opening:  output structure (caller-allocated, contents will be malloc'd)
 *
 * Returns 0 on success, -1 on error (allocation failure or too many marked nodes).
 * Caller must call voleith_bavc_opening_free() to release allocated memory.
 */
int voleith_bavc_open(voleith_bavc_opening_t *opening,
                      const voleith_bavc_t *bavc,
                      const voleith_vc_params_t *params, const size_t *i_delta);

/*
 * Free all memory in a BAVC opening result.
 */
void voleith_bavc_opening_free(voleith_bavc_opening_t *opening);

/*
 * Get the total serialized size of a BAVC opening in bytes.
 *
 * This is a fixed size determined by the parameters:
 *   n_leafcom * τ * (λ/8) + T_open * (λ/8)
 */
size_t voleith_bavc_opening_size(const voleith_vc_params_t *params);

/* ================================================================
 * BAVC Reconstruct - Verifier reconstructs all-but-hidden leaves
 * FAEST spec Section 5.2, Figure 5.4 (Reconstruct)
 * ================================================================ */

/*
 * Result of BAVC.Reconstruct.
 *
 * Contains the reconstructed global commitment (for verification)
 * and the leaf seeds for all non-hidden leaves.
 */
typedef struct {
    uint8_t *leaf_seeds; /* L entries × seed_bytes; hidden leaves are zeroed */
    uint8_t *leaf_coms;  /* L entries × com_bytes; hidden leaves from opening */
    uint8_t com[64];     /* reconstructed global commitment, 2λ/8 bytes */
    size_t seed_bytes;   /* lambda / 8 */
    size_t com_bytes;    /* n_leafcom * lambda/8 */
    size_t L;            /* number of leaves */
} voleith_bavc_reconstruct_t;

/*
 * Run BAVC.Reconstruct: recover leaf seeds and recompute commitment.
 *
 * The verifier uses this to reconstruct all leaves except the hidden ones
 * from the opening, then recomputes the global commitment. If the
 * reconstructed commitment matches the prover's commitment, the opening
 * is valid.
 *
 * opening:  the decommitment from BAVC.Open
 * params:   VC parameters
 * i_delta:  array of τ challenge indices (same as used in Open)
 * iv:       128-bit initialization vector (same as used in Commit)
 * rec:      output structure (caller-allocated, contents will be malloc'd)
 *
 * Returns 0 on success, -1 on error (allocation failure or invalid opening).
 * Caller must call voleith_bavc_reconstruct_free() to release allocated memory.
 */
int voleith_bavc_reconstruct(voleith_bavc_reconstruct_t *rec,
                             const voleith_bavc_opening_t *opening,
                             const voleith_vc_params_t *params,
                             const size_t *i_delta, const uint8_t iv[16]);

/*
 * Free all memory in a BAVC reconstruct result.
 * Securely zeros sensitive material before freeing.
 */
void voleith_bavc_reconstruct_free(voleith_bavc_reconstruct_t *rec);

/*
 * Get the reconstructed leaf seed sd_{i,j}.
 *
 * Returns NULL if (i, j) is a hidden leaf (j == i_delta[i]).
 * Otherwise returns pointer to seed_bytes data, valid until free is called.
 */
const uint8_t *
voleith_bavc_reconstruct_leaf_seed(const voleith_bavc_reconstruct_t *rec,
                                   const voleith_vc_params_t *params, int i,
                                   size_t j, const size_t *i_delta);

#endif /* VOLEITH_VC_H */
