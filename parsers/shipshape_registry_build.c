/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * shipshape_registry_build.c - live crypto-v1 registry descriptors, the
 * call-site body inliner, and the D3 standalone-body builder.
 *
 * This is the hand-written source of truth that the freeze tool reads
 * to regenerate parsers/shipshape_registry_table.c.  Each descriptor names a
 * registry entry, records its signature layout and cost formulas, and
 * points at the inline function that emits its canonical body over
 * caller-supplied wires (the gate sequence of the hand-written
 * circuits/ builder; Goal 2(iii) / STDLIB D2 structural identity).
 * The parser lowers a `stdlib/crypto/*` call by handing the call
 * arguments' wires to voleith_shipshape_registry_inline(); the
 * standalone-body builder (D3) adds the signature's input wires as
 * WITNESS wires in signature order and then emits the same body, so the
 * resulting circuit's fingerprint is the entry's frozen body hash.
 *
 * Entry order here is canonical and MUST match the frozen table order
 * (SHIPSHAPE_SPEC.md §7.2).
 */

#include <stdlib.h>
#include <string.h>

#include "shipshape_registry.h"

#include "aes_cmac_gf8_circuit.h"
#include "aes_gf8_circuit.h"
#include "grostl_gf8_circuit.h"
#include "indexed_merkle_vt_gf8_circuit.h"
#include "merkle_vt_gf8_circuit.h"
#include "node_hash_vt.h"
#include "shipshape_node_hash_types.h"

/*
 * Maximum inferred length parameter, from SHIPSHAPE_SPEC.md §3.7
 * (MAX_VECTOR_LEN = 2^20).  The parser layer owns the canonical limit
 * constant (parsers/shipshape.h); duplicated here so the frozen table
 * records the bound without a forward dependency on the parser.
 */
#define SHIPSHAPE_REG_MAX_VECTOR_LEN (1u << 20)

/* Shorthand for the inferred-parameter slot in the signature tables. */
#define PARAM_LEN VOLEITH_SHIPSHAPE_REGISTRY_PARAM_LEN

/* ================================================================
 * Body inliners: each emits the entry's canonical body into the given
 * circuit over the caller's wires.  `in` is the signature inputs'
 * wires concatenated in signature order; the output's wires are
 * written to `out`.  Return 0 on success, -1 on allocation failure
 * (partial circuit; caller discards it).
 * ================================================================ */

static int
inl_aes_sbox(voleith_gf8_circuit_t *c, const gf8_wire_id *in, uint32_t param,
             gf8_wire_id *out)
{
    (void)param;
    out[0] = aes_gf8_sbox(c, in[0]);
    return 0;
}

static int
inl_aes_keyschedule_128(voleith_gf8_circuit_t *c, const gf8_wire_id *in,
                        uint32_t param, gf8_wire_id *out)
{
    gf8_wire_id rk[11][16];

    (void)param;
    aes128_gf8_expand_key(c, in, rk);
    memcpy(out, rk, sizeof(rk)); /* round-major flatten (STDLIB §2) */
    return 0;
}

static int
inl_aes_encrypt_rounds_128(voleith_gf8_circuit_t *c, const gf8_wire_id *in,
                           uint32_t param, gf8_wire_id *out)
{
    gf8_wire_id rk[11][16];

    (void)param;
    memcpy(rk, in, sizeof(rk)); /* flat round-major -> rk[round][byte] */
    aes128_gf8_encrypt_rk(c, rk, in + 176, out);
    return 0;
}

static int
inl_aes_encrypt_128(voleith_gf8_circuit_t *c, const gf8_wire_id *in,
                    uint32_t param, gf8_wire_id *out)
{
    (void)param;
    aes128_gf8_circuit(c, in, in + 16, out);
    return 0;
}

static int
inl_aes_keyschedule_256(voleith_gf8_circuit_t *c, const gf8_wire_id *in,
                        uint32_t param, gf8_wire_id *out)
{
    gf8_wire_id rk[15][16];

    (void)param;
    aes256_gf8_expand_key(c, in, rk);
    memcpy(out, rk, sizeof(rk)); /* round-major flatten (STDLIB §2) */
    return 0;
}

static int
inl_aes_encrypt_rounds_256(voleith_gf8_circuit_t *c, const gf8_wire_id *in,
                           uint32_t param, gf8_wire_id *out)
{
    gf8_wire_id rk[15][16];

    (void)param;
    memcpy(rk, in, sizeof(rk)); /* flat round-major -> rk[round][byte] */
    aes256_gf8_encrypt_rk(c, rk, in + 240, out);
    return 0;
}

static int
inl_aes_encrypt_256(voleith_gf8_circuit_t *c, const gf8_wire_id *in,
                    uint32_t param, gf8_wire_id *out)
{
    (void)param;
    aes256_gf8_circuit(c, in, in + 32, out);
    return 0;
}

/* CMAC: key wires (16 or 32) then param message wires (RFC 4493; the
 * empty message, param == 0, passes msg == NULL). */
static int
inl_cmac(voleith_gf8_circuit_t *c, const gf8_wire_id *in, size_t key_bytes,
         uint32_t param, gf8_wire_id *out)
{
    aes_cmac_gf8_circuit(c, in, key_bytes, param > 0 ? in + key_bytes : NULL,
                         param, out);
    return 0;
}

static int
inl_cmac_aes_128(voleith_gf8_circuit_t *c, const gf8_wire_id *in,
                 uint32_t param, gf8_wire_id *out)
{
    return inl_cmac(c, in, 16, param, out);
}

static int
inl_cmac_aes_256(voleith_gf8_circuit_t *c, const gf8_wire_id *in,
                 uint32_t param, gf8_wire_id *out)
{
    return inl_cmac(c, in, 32, param, out);
}

static int
inl_grostl_256(voleith_gf8_circuit_t *c, const gf8_wire_id *in, uint32_t param,
               gf8_wire_id *out)
{
    grostl256_gf8_circuit(c, param > 0 ? in : NULL, param, out);
    return 0;
}

/* T27: identical gate sequence; only the first 27 of 32 output wires
 * are exposed (SHIPSHAPE_SPEC.md §7.3). */
static int
inl_grostl_256_t27(voleith_gf8_circuit_t *c, const gf8_wire_id *in,
                   uint32_t param, gf8_wire_id *out)
{
    gf8_wire_id full[32];

    grostl256_gf8_circuit(c, param > 0 ? in : NULL, param, full);
    memcpy(out, full, 27 * sizeof(full[0]));
    return 0;
}

static int
inl_grostl_512(voleith_gf8_circuit_t *c, const gf8_wire_id *in, uint32_t param,
               gf8_wire_id *out)
{
    grostl512_gf8_circuit(c, param > 0 ? in : NULL, param, out);
    return 0;
}

/* T59: first 59 of 64 output wires (SHIPSHAPE_SPEC.md §7.3). */
static int
inl_grostl_512_t59(voleith_gf8_circuit_t *c, const gf8_wire_id *in,
                   uint32_t param, gf8_wire_id *out)
{
    gf8_wire_id full[64];

    grostl512_gf8_circuit(c, param > 0 ? in : NULL, param, full);
    memcpy(out, full, 59 * sizeof(full[0]));
    return 0;
}

/* ================================================================
 * Cost formulas (SHIPSHAPE_SPEC.md §7.2): blocks is the derived block
 * count, invs the INV count == witness slots the body adds.  FIXED
 * entries carry their constant invs in the descriptor instead.
 * ================================================================ */

typedef void (*shipshape_reg_cost_fn)(uint32_t, size_t *, size_t *);

static void
cost_cmac_aes_128(uint32_t param, size_t *blocks, size_t *invs)
{
    size_t n_aes = aes_cmac_gf8_n_aes_calls(param);

    *blocks = n_aes;
    *invs = 200 * n_aes;
}

static void
cost_cmac_aes_256(uint32_t param, size_t *blocks, size_t *invs)
{
    size_t n_aes = aes_cmac_gf8_n_aes_calls(param);

    *blocks = n_aes;
    *invs = 276 * n_aes;
}

static void
cost_grostl_256(uint32_t param, size_t *blocks, size_t *invs)
{
    size_t b = ((size_t)param + 9 + 63) / 64; /* ceil((n + 9) / 64) */

    *blocks = b;
    *invs = 1280 * b + 640;
}

static void
cost_grostl_512(uint32_t param, size_t *blocks, size_t *invs)
{
    size_t b = ((size_t)param + 9 + 127) / 128; /* ceil((n + 9) / 128) */

    *blocks = b;
    *invs = 3584 * b + 1792;
}

/* ================================================================
 * Freeze grids (STDLIB §3.4).  FIXED entries use grid_fixed ({0}).
 * Each PARAMETRIC grid covers: the smallest legal instantiation (n=0),
 * one mid-size, each of the first two block boundaries (the value just
 * inside a block and the value that spills into the next), and the
 * published test-vector sizes.
 *
 *   CMAC (16-byte block): RFC 4493 Examples 1-4 are 0, 16, 40, 64 bytes;
 *   16 is exactly one block (subkey K1, no padding) and 17 spills to two
 *   (subkey K2, padded), so {0, 16, 17, 40, 64} hits both subkey paths,
 *   both block boundaries, and every RFC vector.  (NIST CAVS 14.4
 *   lengths return with the kdf/* entries in crypto-v2; SHIPSHAPE §7.5.)
 *
 *   Grøstl block count is ceil((n + 9) / block_size) for both variants
 *   (8-byte length field; circuits/grostl_gf8_circuit.c n_blocks_for).
 *   256 (64-byte block): 1->2 at 55/56, 2->3 at 119/120.
 *   512 (128-byte block): 1->2 at 119/120, 2->3 at 247/248.
 * ================================================================ */

static const uint32_t grid_fixed[] = {0};
static const uint32_t grid_cmac[] = {0, 16, 17, 40, 64};
static const uint32_t grid_grostl_256[] = {0, 55, 56, 64, 119, 120};
static const uint32_t grid_grostl_512[] = {0, 119, 120, 200, 247, 248};

/* ================================================================
 * Descriptor table (canonical order; matches the frozen table).
 * ================================================================ */

typedef int (*shipshape_reg_inline_fn)(voleith_gf8_circuit_t *,
                                       const gf8_wire_id *, uint32_t,
                                       gf8_wire_id *);

typedef struct {
    const char *fqn;
    voleith_shipshape_reg_kind_t kind;
    const char *signature;
    uint32_t param_min;
    uint32_t param_max;
    const uint32_t *grid;
    size_t grid_len;
    uint8_t n_inputs; /* signature input argument count */
    uint32_t in_len[VOLEITH_SHIPSHAPE_REGISTRY_MAX_INPUTS];
    uint32_t out_len;           /* single output's element count */
    uint8_t out_is_vector;      /* 0 only for the scalar sbox output */
    uint32_t fixed_invs;        /* FIXED: invs; PARAMETRIC: 0 (cost fn) */
    shipshape_reg_cost_fn cost; /* PARAMETRIC only; NULL for FIXED */
    shipshape_reg_inline_fn inl;
} shipshape_reg_descriptor_t;

#define GRID(arr) (arr), (sizeof(arr) / sizeof((arr)[0]))

static const shipshape_reg_descriptor_t DESCRIPTORS[] = {
    {"stdlib/crypto/aes/sbox",
     VOLEITH_SHIPSHAPE_REG_FIXED,
     "(in : byte) -> (out : byte)",
     0,
     0,
     GRID(grid_fixed),
     1,
     {1, 0},
     1,
     0,
     1,
     NULL,
     inl_aes_sbox},
    {"stdlib/crypto/aes/keyschedule_128",
     VOLEITH_SHIPSHAPE_REG_FIXED,
     "(key : byte[16]) -> (rk : byte[176])",
     0,
     0,
     GRID(grid_fixed),
     1,
     {16, 0},
     176,
     1,
     40,
     NULL,
     inl_aes_keyschedule_128},
    {"stdlib/crypto/aes/encrypt_rounds_128",
     VOLEITH_SHIPSHAPE_REG_FIXED,
     "(rk : byte[176], pt : byte[16]) -> (ct : byte[16])",
     0,
     0,
     GRID(grid_fixed),
     2,
     {176, 16},
     16,
     1,
     160,
     NULL,
     inl_aes_encrypt_rounds_128},
    {"stdlib/crypto/aes/encrypt_128",
     VOLEITH_SHIPSHAPE_REG_FIXED,
     "(key : byte[16], pt : byte[16]) -> (ct : byte[16])",
     0,
     0,
     GRID(grid_fixed),
     2,
     {16, 16},
     16,
     1,
     200,
     NULL,
     inl_aes_encrypt_128},
    {"stdlib/crypto/aes/keyschedule_256",
     VOLEITH_SHIPSHAPE_REG_FIXED,
     "(key : byte[32]) -> (rk : byte[240])",
     0,
     0,
     GRID(grid_fixed),
     1,
     {32, 0},
     240,
     1,
     52,
     NULL,
     inl_aes_keyschedule_256},
    {"stdlib/crypto/aes/encrypt_rounds_256",
     VOLEITH_SHIPSHAPE_REG_FIXED,
     "(rk : byte[240], pt : byte[16]) -> (ct : byte[16])",
     0,
     0,
     GRID(grid_fixed),
     2,
     {240, 16},
     16,
     1,
     224,
     NULL,
     inl_aes_encrypt_rounds_256},
    {"stdlib/crypto/aes/encrypt_256",
     VOLEITH_SHIPSHAPE_REG_FIXED,
     "(key : byte[32], pt : byte[16]) -> (ct : byte[16])",
     0,
     0,
     GRID(grid_fixed),
     2,
     {32, 16},
     16,
     1,
     276,
     NULL,
     inl_aes_encrypt_256},
    {"stdlib/crypto/cmac/aes_128",
     VOLEITH_SHIPSHAPE_REG_PARAMETRIC,
     "(key : byte[16], msg : byte[n]) -> (tag : byte[16])",
     0,
     SHIPSHAPE_REG_MAX_VECTOR_LEN,
     GRID(grid_cmac),
     2,
     {16, PARAM_LEN},
     16,
     1,
     0,
     cost_cmac_aes_128,
     inl_cmac_aes_128},
    {"stdlib/crypto/cmac/aes_256",
     VOLEITH_SHIPSHAPE_REG_PARAMETRIC,
     "(key : byte[32], msg : byte[n]) -> (tag : byte[16])",
     0,
     SHIPSHAPE_REG_MAX_VECTOR_LEN,
     GRID(grid_cmac),
     2,
     {32, PARAM_LEN},
     16,
     1,
     0,
     cost_cmac_aes_256,
     inl_cmac_aes_256},
    {"stdlib/crypto/grostl/hash_256",
     VOLEITH_SHIPSHAPE_REG_PARAMETRIC,
     "(msg : byte[n]) -> (out : byte[32])",
     0,
     SHIPSHAPE_REG_MAX_VECTOR_LEN,
     GRID(grid_grostl_256),
     1,
     {PARAM_LEN, 0},
     32,
     1,
     0,
     cost_grostl_256,
     inl_grostl_256},
    {"stdlib/crypto/grostl/hash_256_t27",
     VOLEITH_SHIPSHAPE_REG_PARAMETRIC,
     "(msg : byte[n]) -> (out : byte[27])",
     0,
     SHIPSHAPE_REG_MAX_VECTOR_LEN,
     GRID(grid_grostl_256),
     1,
     {PARAM_LEN, 0},
     27,
     1,
     0,
     cost_grostl_256,
     inl_grostl_256_t27},
    {"stdlib/crypto/grostl/hash_512",
     VOLEITH_SHIPSHAPE_REG_PARAMETRIC,
     "(msg : byte[n]) -> (out : byte[64])",
     0,
     SHIPSHAPE_REG_MAX_VECTOR_LEN,
     GRID(grid_grostl_512),
     1,
     {PARAM_LEN, 0},
     64,
     1,
     0,
     cost_grostl_512,
     inl_grostl_512},
    {"stdlib/crypto/grostl/hash_512_t59",
     VOLEITH_SHIPSHAPE_REG_PARAMETRIC,
     "(msg : byte[n]) -> (out : byte[59])",
     0,
     SHIPSHAPE_REG_MAX_VECTOR_LEN,
     GRID(grid_grostl_512),
     1,
     {PARAM_LEN, 0},
     59,
     1,
     0,
     cost_grostl_512,
     inl_grostl_512_t59},
};

#define N_DESCRIPTORS (sizeof(DESCRIPTORS) / sizeof(DESCRIPTORS[0]))

/* ================================================================
 * Public accessors
 * ================================================================ */

size_t
voleith_shipshape_registry_descriptor_count(void)
{
    return N_DESCRIPTORS;
}

int
voleith_shipshape_registry_descriptor(size_t idx, const char **fqn,
                                      voleith_shipshape_reg_kind_t *kind,
                                      const char **signature,
                                      uint32_t *param_min, uint32_t *param_max)
{
    if (idx >= N_DESCRIPTORS)
        return -1;
    if (fqn)
        *fqn = DESCRIPTORS[idx].fqn;
    if (kind)
        *kind = DESCRIPTORS[idx].kind;
    if (signature)
        *signature = DESCRIPTORS[idx].signature;
    if (param_min)
        *param_min = DESCRIPTORS[idx].param_min;
    if (param_max)
        *param_max = DESCRIPTORS[idx].param_max;
    return 0;
}

size_t
voleith_shipshape_registry_grid(size_t idx, uint32_t *out, size_t max)
{
    if (idx >= N_DESCRIPTORS)
        return 0;
    const shipshape_reg_descriptor_t *d = &DESCRIPTORS[idx];
    if (out) {
        size_t n = (d->grid_len < max) ? d->grid_len : max;
        for (size_t i = 0; i < n; i++)
            out[i] = d->grid[i];
    }
    return d->grid_len;
}

int
voleith_shipshape_registry_signature(
    size_t idx, size_t *n_inputs,
    uint32_t in_len[VOLEITH_SHIPSHAPE_REGISTRY_MAX_INPUTS], uint32_t *out_len,
    int *out_is_vector)
{
    if (idx >= N_DESCRIPTORS)
        return -1;
    const shipshape_reg_descriptor_t *d = &DESCRIPTORS[idx];
    if (n_inputs)
        *n_inputs = d->n_inputs;
    if (in_len)
        for (size_t i = 0; i < VOLEITH_SHIPSHAPE_REGISTRY_MAX_INPUTS; i++)
            in_len[i] = d->in_len[i];
    if (out_len)
        *out_len = d->out_len;
    if (out_is_vector)
        *out_is_vector = d->out_is_vector;
    return 0;
}

int
voleith_shipshape_registry_cost(size_t idx, uint32_t param, size_t *blocks,
                                size_t *invs)
{
    size_t b, v;

    if (idx >= N_DESCRIPTORS)
        return -1;
    const shipshape_reg_descriptor_t *d = &DESCRIPTORS[idx];
    if (d->cost != NULL) {
        d->cost(param, &b, &v);
    } else {
        b = 1;
        v = d->fixed_invs;
    }
    if (blocks)
        *blocks = b;
    if (invs)
        *invs = v;
    return 0;
}

int
voleith_shipshape_registry_inline(size_t idx, voleith_gf8_circuit_t *c,
                                  const gf8_wire_id *in, uint32_t param,
                                  gf8_wire_id *out)
{
    if (idx >= N_DESCRIPTORS)
        return -1;
    return DESCRIPTORS[idx].inl(c, in, param, out);
}

voleith_gf8_circuit_t *
voleith_shipshape_registry_build_standalone(size_t idx, uint32_t param)
{
    voleith_gf8_circuit_t *c;
    gf8_wire_id *in, *out;
    size_t n_in = 0;
    int rc;

    if (idx >= N_DESCRIPTORS)
        return NULL;
    const shipshape_reg_descriptor_t *d = &DESCRIPTORS[idx];
    for (size_t i = 0; i < d->n_inputs; i++)
        n_in += (d->in_len[i] == PARAM_LEN) ? param : d->in_len[i];

    c = voleith_gf8_circuit_new();
    if (c == NULL)
        return NULL;
    in = calloc(n_in ? n_in : 1, sizeof(*in));
    out = calloc(d->out_len ? d->out_len : 1, sizeof(*out));
    if (in == NULL || out == NULL) {
        free(in);
        free(out);
        voleith_gf8_circuit_free(c);
        return NULL;
    }
    for (size_t i = 0; i < n_in; i++)
        in[i] = voleith_gf8_add_witness(c);
    rc = d->inl(c, in, param, out);
    free(in);
    free(out);
    if (rc != 0) {
        voleith_gf8_circuit_free(c);
        return NULL;
    }
    return c;
}

int
voleith_shipshape_registry_body_hash(
    size_t idx, uint32_t param,
    uint8_t out[VOLEITH_SHIPSHAPE_REGISTRY_BODY_HASH_BYTES])
{
    voleith_gf8_circuit_t *c =
        voleith_shipshape_registry_build_standalone(idx, param);
    if (c == NULL)
        return -1;
    int rc = voleith_gf8_circuit_fingerprint(c, out);
    voleith_gf8_circuit_free(c);
    return rc;
}

/* ================================================================
 * Crypto-v2 hash-parametric descriptors (REG_HASH_PARAM).
 *
 * Three entries: merkle/path_secret, indexed_merkle/nonmember_secret,
 * ring_sig/v1.  Each admits all node-hash type ids (all_type_ids) and carries a
 * multi-dimensional parameter grid whose body hashes are frozen by the
 * regenerated parsers/shipshape_registry_table.c.
 *
 * See docs/private/SHIPSHAPE_CRYPTO_V2_SECRETDIR_IMPL_PLAN.md MR2.
 * ================================================================ */

/* ---- fn-pointer typedefs for the hash-parametric inliner/cost ---- */

typedef int (*ss_reg_hash_inline_fn)(voleith_gf8_circuit_t *,
                                     const voleith_node_hash_vt *,
                                     const uint32_t *, const gf8_wire_id *,
                                     gf8_wire_id *);

typedef void (*ss_reg_hash_cost_fn)(const voleith_node_hash_vt *,
                                    const uint32_t *, size_t *, size_t *);

/* ---- grid point type: (type_id, params[]) ---- */

typedef struct {
    uint16_t type_id;
    uint32_t params[VOLEITH_SHIPSHAPE_REG_MAX_PARAMS];
    uint8_t n_params;
} ss_reg_hash_grid_pt_t;

/* ---- live descriptor struct (mirrors shipshape_reg_descriptor_t) ---- */

typedef struct {
    const char *fqn;
    const char *signature;
    const uint16_t *types;
    size_t n_types;
    uint8_t n_params;
    uint8_t depth_param;
    uint8_t leaf_param;
    uint32_t param_min[VOLEITH_SHIPSHAPE_REG_MAX_PARAMS];
    uint32_t param_max[VOLEITH_SHIPSHAPE_REG_MAX_PARAMS];
    uint8_t n_inputs;
    ss_arglen_t in[VOLEITH_SHIPSHAPE_REGISTRY_MAX_INPUTS];
    uint8_t out_is_node_vec;
    const ss_reg_hash_grid_pt_t *grid;
    size_t grid_len;
    ss_reg_hash_inline_fn inl;
    ss_reg_hash_cost_fn cost;
} ss_reg_hash_descriptor_t;

/* ---- param-index constants per entry ---- */

/* merkle/path_secret: params[0]=depth, params[1]=L */
#define PSEC_DEPTH 0
#define PSEC_L 1

/* indexed_merkle/nonmember_secret: params[0]=tb, params[1]=ib, params[2]=depth */
#define IDX_TB 0
#define IDX_IB 1
#define IDX_DEPTH 2

/* ring_sig/v1: params[0]=skb, params[1]=depth */
#define RS_SKB 0
#define RS_DEPTH 1

/* ---- all 10 type ids admitted by every hash-parametric entry ---- */

static const uint16_t all_type_ids[] = {
    VOLEITH_SHIPSHAPE_NHT_AES_DM,
    VOLEITH_SHIPSHAPE_NHT_AES_CMAC_128,
    VOLEITH_SHIPSHAPE_NHT_GROSTL_256,
    VOLEITH_SHIPSHAPE_NHT_GROSTL_256_T27,
    VOLEITH_SHIPSHAPE_NHT_GROSTL_512,
    VOLEITH_SHIPSHAPE_NHT_GROSTL_512_T59,
    VOLEITH_SHIPSHAPE_NHT_HIROSE,
    VOLEITH_SHIPSHAPE_NHT_HIROSE_FIXED_32,
    VOLEITH_SHIPSHAPE_NHT_GROSTL_256_FIXED,
    VOLEITH_SHIPSHAPE_NHT_GROSTL_512_FIXED,
};

/* ================================================================
 * Body inliners
 * ================================================================ */

/*
 * merkle/path_secret: in = leaf[L] | siblings[depth*node] | dirs[depth]
 * Outputs: root[node].
 */
static int
inl_merkle_path_secret(voleith_gf8_circuit_t *c, const voleith_node_hash_vt *vt,
                       const uint32_t *p, const gf8_wire_id *in,
                       gf8_wire_id *out)
{
    size_t node;
    uint32_t L, depth;
    const gf8_wire_id *leaf, *sib, *dirs;

    node = vt->node_bytes;
    L = p[PSEC_L];
    depth = p[PSEC_DEPTH];
    leaf = in;
    sib = in + L;
    dirs = in + L + (size_t)depth * node;
    return merkle_vt_gf8_path_circuit_secret_dir(c, vt, L > 0 ? leaf : NULL, L,
                                                 sib, dirs, depth, out);
}

/*
 * indexed_merkle/nonmember_secret:
 * in = target[tb] | low[tb] | hi[tb] | nidx[ib] |
 *      siblings[depth*node] | dirs[depth] | root_in[node]
 * (low=low_value, hi=low_next).  No outputs: asserts root internally.
 */
static int
inl_indexed_nonmember_secret(voleith_gf8_circuit_t *c,
                             const voleith_node_hash_vt *vt, const uint32_t *p,
                             const gf8_wire_id *in, gf8_wire_id *out)
{
    size_t node, k;
    uint32_t tb, ib, depth;
    const gf8_wire_id *target, *low, *hi, *nidx, *sib, *dirs, *root_in;
    gf8_wire_id computed[MERKLE_VT_MAX_NODE_BYTES];
    int rc;

    node = vt->node_bytes;
    tb = p[IDX_TB];
    ib = p[IDX_IB];
    depth = p[IDX_DEPTH];
    target = in;
    low = target + tb;
    hi = low + tb;
    nidx = hi + tb;
    sib = nidx + ib;
    dirs = sib + (size_t)depth * node;
    root_in = dirs + depth;
    rc = merkle_vt_gf8_indexed_nonmember_circuit_secret_dir(
        c, vt, target, tb, low, hi, nidx, ib, sib, dirs, depth, computed);
    if (rc != 0)
        return rc;
    for (k = 0; k < node; k++)
        voleith_gf8_assert_equal(c, computed[k], root_in[k]);
    (void)out;
    return 0;
}

/*
 * ring_sig/v1: in = sk[skb] | dirs[depth] | siblings[depth*node] | root_in[node]
 * No outputs: asserts root internally.
 */
static int
inl_ring_sig_v1(voleith_gf8_circuit_t *c, const voleith_node_hash_vt *vt,
                const uint32_t *p, const gf8_wire_id *in, gf8_wire_id *out)
{
    size_t node, k;
    uint32_t skb, depth;
    const gf8_wire_id *sk, *dirs, *sib, *root_in;
    gf8_wire_id leaf_node[MERKLE_VT_MAX_NODE_BYTES];
    gf8_wire_id computed[MERKLE_VT_MAX_NODE_BYTES];
    int rc;

    node = vt->node_bytes;
    skb = p[RS_SKB];
    depth = p[RS_DEPTH];
    sk = in;
    dirs = sk + skb;
    sib = dirs + depth;
    root_in = sib + (size_t)depth * node;
    vt->leaf_circuit(c, skb > 0 ? sk : NULL, skb, leaf_node);
    rc = merkle_vt_gf8_path_from_leaf_node_secret_dir(c, vt, leaf_node, sib,
                                                      dirs, depth, computed);
    if (rc != 0)
        return rc;
    for (k = 0; k < node; k++)
        voleith_gf8_assert_equal(c, computed[k], root_in[k]);
    (void)out;
    return 0;
}

/* ================================================================
 * Cost functions
 * ================================================================ */

static void
cost_merkle_path_secret(const voleith_node_hash_vt *vt, const uint32_t *p,
                        size_t *blocks, size_t *invs)
{
    *blocks = (size_t)1 + p[PSEC_DEPTH];
    *invs = vt->leaf_invin_bytes(p[PSEC_L]) +
            (size_t)p[PSEC_DEPTH] * vt->inode_invin_bytes();
}

/* indexed: leaf record is low_value || low_next || next_index = 2*tb + ib */
static void
cost_indexed_nonmember_secret(const voleith_node_hash_vt *vt, const uint32_t *p,
                              size_t *blocks, size_t *invs)
{
    *blocks = (size_t)1 + p[IDX_DEPTH];
    *invs = vt->leaf_invin_bytes((size_t)2 * p[IDX_TB] + p[IDX_IB]) +
            (size_t)p[IDX_DEPTH] * vt->inode_invin_bytes();
}

static void
cost_ring_sig_v1(const voleith_node_hash_vt *vt, const uint32_t *p,
                 size_t *blocks, size_t *invs)
{
    *blocks = (size_t)1 + p[RS_DEPTH];
    *invs = vt->leaf_invin_bytes(p[RS_SKB]) +
            (size_t)p[RS_DEPTH] * vt->inode_invin_bytes();
}

/* ================================================================
 * Freeze grids (DESIGN §6.1 representative points).
 *
 * Each grid entry is (type_id, params[n_params]).
 * node_bytes per type: aes_dm=16, aes_cmac_128=16, grostl_256=32,
 *   grostl_256_t27=27, grostl_512=64, grostl_512_t59=59,
 *   hirose=32, hirose_fixed_32=32, grostl_256_fixed=32, grostl_512_fixed=64.
 *
 * Fixed-leaf types (hirose_fixed_32, grostl_256_fixed, grostl_512_fixed)
 * require the leaf width to equal fixed_leaf_bytes (= node_bytes): 32 for the
 * two 32-byte ones, 64 for grostl_512_fixed.  For the variable-leaf and
 * truncated types the representative leaf widths are 0 and node_bytes.
 *
 * merkle/path_secret params: [depth, L].
 *   Variable/truncated types: depth in {2, 8}, L in {0, node_bytes}.
 *   Fixed-leaf types: depth in {2, 8}, L = fixed_leaf_bytes only.
 * indexed_merkle/nonmember_secret params: [tb, ib, depth]; leaf record =
 *   2*tb + ib must equal fixed_leaf_bytes for the fixed-leaf types
 *   (2*12+8=32, 2*28+8=64).
 * ring_sig/v1 params: [skb, depth]; skb = fixed_leaf_bytes for fixed-leaf types.
 * All grids stay within MAX_GRID=64.
 * ================================================================ */

#define GHASH_GRID(arr) (arr), (sizeof(arr) / sizeof((arr)[0]))

/*
 * merkle/path_secret grid: params = {depth, L}.
 * For hirose_fixed_32 (type_id=7), L must be 32 (fixed_leaf_bytes=32).
 */
static const ss_reg_hash_grid_pt_t grid_merkle_path[] = {
    /* aes_dm (node=16) */
    {VOLEITH_SHIPSHAPE_NHT_AES_DM, {2, 0}, 2},
    {VOLEITH_SHIPSHAPE_NHT_AES_DM, {2, 16}, 2},
    {VOLEITH_SHIPSHAPE_NHT_AES_DM, {8, 0}, 2},
    {VOLEITH_SHIPSHAPE_NHT_AES_DM, {8, 16}, 2},
    /* aes_cmac_128 (node=16) */
    {VOLEITH_SHIPSHAPE_NHT_AES_CMAC_128, {2, 0}, 2},
    {VOLEITH_SHIPSHAPE_NHT_AES_CMAC_128, {2, 16}, 2},
    {VOLEITH_SHIPSHAPE_NHT_AES_CMAC_128, {8, 0}, 2},
    {VOLEITH_SHIPSHAPE_NHT_AES_CMAC_128, {8, 16}, 2},
    /* grostl_256 (node=32) */
    {VOLEITH_SHIPSHAPE_NHT_GROSTL_256, {2, 0}, 2},
    {VOLEITH_SHIPSHAPE_NHT_GROSTL_256, {2, 32}, 2},
    {VOLEITH_SHIPSHAPE_NHT_GROSTL_256, {8, 0}, 2},
    {VOLEITH_SHIPSHAPE_NHT_GROSTL_256, {8, 32}, 2},
    /* grostl_256_t27 (node=27) */
    {VOLEITH_SHIPSHAPE_NHT_GROSTL_256_T27, {2, 0}, 2},
    {VOLEITH_SHIPSHAPE_NHT_GROSTL_256_T27, {2, 27}, 2},
    {VOLEITH_SHIPSHAPE_NHT_GROSTL_256_T27, {8, 0}, 2},
    {VOLEITH_SHIPSHAPE_NHT_GROSTL_256_T27, {8, 27}, 2},
    /* grostl_512 (node=64) */
    {VOLEITH_SHIPSHAPE_NHT_GROSTL_512, {2, 0}, 2},
    {VOLEITH_SHIPSHAPE_NHT_GROSTL_512, {2, 64}, 2},
    {VOLEITH_SHIPSHAPE_NHT_GROSTL_512, {8, 0}, 2},
    {VOLEITH_SHIPSHAPE_NHT_GROSTL_512, {8, 64}, 2},
    /* grostl_512_t59 (node=59) */
    {VOLEITH_SHIPSHAPE_NHT_GROSTL_512_T59, {2, 0}, 2},
    {VOLEITH_SHIPSHAPE_NHT_GROSTL_512_T59, {2, 59}, 2},
    {VOLEITH_SHIPSHAPE_NHT_GROSTL_512_T59, {8, 0}, 2},
    {VOLEITH_SHIPSHAPE_NHT_GROSTL_512_T59, {8, 59}, 2},
    /* hirose (node=32, variable leaf) */
    {VOLEITH_SHIPSHAPE_NHT_HIROSE, {2, 0}, 2},
    {VOLEITH_SHIPSHAPE_NHT_HIROSE, {2, 32}, 2},
    {VOLEITH_SHIPSHAPE_NHT_HIROSE, {8, 0}, 2},
    {VOLEITH_SHIPSHAPE_NHT_HIROSE, {8, 32}, 2},
    /* hirose_fixed_32 (node=32, fixed_leaf_bytes=32): L must be 32 */
    {VOLEITH_SHIPSHAPE_NHT_HIROSE_FIXED_32, {2, 32}, 2},
    {VOLEITH_SHIPSHAPE_NHT_HIROSE_FIXED_32, {8, 32}, 2},
    /* grostl_256_fixed (node=32, fixed_leaf_bytes=32): L must be 32 */
    {VOLEITH_SHIPSHAPE_NHT_GROSTL_256_FIXED, {2, 32}, 2},
    {VOLEITH_SHIPSHAPE_NHT_GROSTL_256_FIXED, {8, 32}, 2},
    /* grostl_512_fixed (node=64, fixed_leaf_bytes=64): L must be 64 */
    {VOLEITH_SHIPSHAPE_NHT_GROSTL_512_FIXED, {2, 64}, 2},
    {VOLEITH_SHIPSHAPE_NHT_GROSTL_512_FIXED, {8, 64}, 2},
};

/*
 * indexed_merkle/nonmember_secret grid: params = {tb, ib, depth}.
 * hirose_fixed_32: leaf record = 2*tb + ib; fixed_leaf_bytes=32 requires
 * 2*tb+ib == 32.  Use tb=12, ib=8 (12+12+8=32).
 */
static const ss_reg_hash_grid_pt_t grid_indexed_nonmember[] = {
    /* aes_dm (node=16) */
    {VOLEITH_SHIPSHAPE_NHT_AES_DM, {8, 8, 2}, 3},
    {VOLEITH_SHIPSHAPE_NHT_AES_DM, {8, 8, 8}, 3},
    /* aes_cmac_128 (node=16) */
    {VOLEITH_SHIPSHAPE_NHT_AES_CMAC_128, {8, 8, 2}, 3},
    {VOLEITH_SHIPSHAPE_NHT_AES_CMAC_128, {8, 8, 8}, 3},
    /* grostl_256 (node=32) */
    {VOLEITH_SHIPSHAPE_NHT_GROSTL_256, {8, 8, 2}, 3},
    {VOLEITH_SHIPSHAPE_NHT_GROSTL_256, {8, 8, 8}, 3},
    /* grostl_256_t27 (node=27) */
    {VOLEITH_SHIPSHAPE_NHT_GROSTL_256_T27, {8, 8, 2}, 3},
    {VOLEITH_SHIPSHAPE_NHT_GROSTL_256_T27, {8, 8, 8}, 3},
    /* grostl_512 (node=64) */
    {VOLEITH_SHIPSHAPE_NHT_GROSTL_512, {8, 8, 2}, 3},
    {VOLEITH_SHIPSHAPE_NHT_GROSTL_512, {8, 8, 8}, 3},
    /* grostl_512_t59 (node=59) */
    {VOLEITH_SHIPSHAPE_NHT_GROSTL_512_T59, {8, 8, 2}, 3},
    {VOLEITH_SHIPSHAPE_NHT_GROSTL_512_T59, {8, 8, 8}, 3},
    /* hirose (node=32, variable leaf) */
    {VOLEITH_SHIPSHAPE_NHT_HIROSE, {8, 8, 2}, 3},
    {VOLEITH_SHIPSHAPE_NHT_HIROSE, {8, 8, 8}, 3},
    /* hirose_fixed_32: leaf record 2*12+8=32 = fixed_leaf_bytes */
    {VOLEITH_SHIPSHAPE_NHT_HIROSE_FIXED_32, {12, 8, 2}, 3},
    {VOLEITH_SHIPSHAPE_NHT_HIROSE_FIXED_32, {12, 8, 8}, 3},
    /* grostl_256_fixed: leaf record 2*12+8=32 = fixed_leaf_bytes */
    {VOLEITH_SHIPSHAPE_NHT_GROSTL_256_FIXED, {12, 8, 2}, 3},
    {VOLEITH_SHIPSHAPE_NHT_GROSTL_256_FIXED, {12, 8, 8}, 3},
    /* grostl_512_fixed: leaf record 2*28+8=64 = fixed_leaf_bytes */
    {VOLEITH_SHIPSHAPE_NHT_GROSTL_512_FIXED, {28, 8, 2}, 3},
    {VOLEITH_SHIPSHAPE_NHT_GROSTL_512_FIXED, {28, 8, 8}, 3},
};

/*
 * ring_sig/v1 grid: params = {skb, depth}.
 * hirose_fixed_32: fixed_leaf_bytes=32, so skb must be 32.
 */
static const ss_reg_hash_grid_pt_t grid_ring_sig[] = {
    /* aes_dm (node=16) */
    {VOLEITH_SHIPSHAPE_NHT_AES_DM, {16, 2}, 2},
    {VOLEITH_SHIPSHAPE_NHT_AES_DM, {16, 8}, 2},
    /* aes_cmac_128 (node=16) */
    {VOLEITH_SHIPSHAPE_NHT_AES_CMAC_128, {16, 2}, 2},
    {VOLEITH_SHIPSHAPE_NHT_AES_CMAC_128, {16, 8}, 2},
    /* grostl_256 (node=32) */
    {VOLEITH_SHIPSHAPE_NHT_GROSTL_256, {32, 2}, 2},
    {VOLEITH_SHIPSHAPE_NHT_GROSTL_256, {32, 8}, 2},
    /* grostl_256_t27 (node=27) */
    {VOLEITH_SHIPSHAPE_NHT_GROSTL_256_T27, {27, 2}, 2},
    {VOLEITH_SHIPSHAPE_NHT_GROSTL_256_T27, {27, 8}, 2},
    /* grostl_512 (node=64) */
    {VOLEITH_SHIPSHAPE_NHT_GROSTL_512, {64, 2}, 2},
    {VOLEITH_SHIPSHAPE_NHT_GROSTL_512, {64, 8}, 2},
    /* grostl_512_t59 (node=59) */
    {VOLEITH_SHIPSHAPE_NHT_GROSTL_512_T59, {59, 2}, 2},
    {VOLEITH_SHIPSHAPE_NHT_GROSTL_512_T59, {59, 8}, 2},
    /* hirose (node=32, variable leaf) */
    {VOLEITH_SHIPSHAPE_NHT_HIROSE, {32, 2}, 2},
    {VOLEITH_SHIPSHAPE_NHT_HIROSE, {32, 8}, 2},
    /* hirose_fixed_32: skb must equal fixed_leaf_bytes=32 */
    {VOLEITH_SHIPSHAPE_NHT_HIROSE_FIXED_32, {32, 2}, 2},
    {VOLEITH_SHIPSHAPE_NHT_HIROSE_FIXED_32, {32, 8}, 2},
    /* grostl_256_fixed: skb must equal fixed_leaf_bytes=32 */
    {VOLEITH_SHIPSHAPE_NHT_GROSTL_256_FIXED, {32, 2}, 2},
    {VOLEITH_SHIPSHAPE_NHT_GROSTL_256_FIXED, {32, 8}, 2},
    /* grostl_512_fixed: skb must equal fixed_leaf_bytes=64 */
    {VOLEITH_SHIPSHAPE_NHT_GROSTL_512_FIXED, {64, 2}, 2},
    {VOLEITH_SHIPSHAPE_NHT_GROSTL_512_FIXED, {64, 8}, 2},
};

/* ================================================================
 * Hash descriptor table (canonical order)
 * ================================================================ */

static const ss_reg_hash_descriptor_t HASH_DESCRIPTORS[] = {
    /*
     * merkle/path_secret
     * params[PSEC_DEPTH=0]=depth, params[PSEC_L=1]=L
     * in: leaf[L], siblings[depth*node], dirs[depth]
     * out: root[node]
     */
    {
        "stdlib/crypto/merkle/path_secret",
        "(leaf : byte[L], siblings : byte[depth*node], dirs : byte[depth])"
        " -> (root : byte[node])",
        all_type_ids,
        sizeof(all_type_ids) / sizeof(all_type_ids[0]),
        2,          /* n_params */
        PSEC_DEPTH, /* depth_param */
        PSEC_L,     /* leaf_param */
        {1, 0, 0},  /* param_min: depth>=1, L>=0 */
        {1u << 16, SHIPSHAPE_REG_MAX_VECTOR_LEN, 0}, /* param_max */
        3,                                           /* n_inputs */
        {
            {SS_ARGLEN_PARAM, PSEC_L},
            {SS_ARGLEN_DEPTH_TIMES_NODE, 0},
            {SS_ARGLEN_PARAM, PSEC_DEPTH},
        },
        1, /* out_is_node_vec */
        GHASH_GRID(grid_merkle_path),
        inl_merkle_path_secret,
        cost_merkle_path_secret,
    },
    /*
     * indexed_merkle/nonmember_secret
     * params[IDX_TB=0]=tb, params[IDX_IB=1]=ib, params[IDX_DEPTH=2]=depth
     * in: target[tb], low[tb], hi[tb], nidx[ib],
     *     siblings[depth*node], dirs[depth], root_in[node]
     * out: none (assertion only)
     */
    {
        "stdlib/crypto/indexed_merkle/nonmember_secret",
        "(target : byte[tb], low : byte[tb], hi : byte[tb],"
        " nidx : byte[ib], siblings : byte[depth*node],"
        " dirs : byte[depth], root : byte[node])",
        all_type_ids,
        sizeof(all_type_ids) / sizeof(all_type_ids[0]),
        3,         /* n_params */
        IDX_DEPTH, /* depth_param */
        IDX_TB,    /* leaf_param (leaf record = 2*tb+ib; validate per entry) */
        {1, 1, 1}, /* param_min: tb>=1, ib>=1, depth>=1 */
        {SHIPSHAPE_REG_MAX_VECTOR_LEN, SHIPSHAPE_REG_MAX_VECTOR_LEN,
         1u << 16}, /* param_max */
        7,          /* n_inputs */
        {
            {SS_ARGLEN_PARAM, IDX_TB},
            {SS_ARGLEN_PARAM, IDX_TB},
            {SS_ARGLEN_PARAM, IDX_TB},
            {SS_ARGLEN_PARAM, IDX_IB},
            {SS_ARGLEN_DEPTH_TIMES_NODE, 0},
            {SS_ARGLEN_PARAM, IDX_DEPTH},
            {SS_ARGLEN_NODE, 0}, /* root_in[node]: exactly node_bytes */
        },
        0, /* out_is_node_vec: assertion-only */
        GHASH_GRID(grid_indexed_nonmember),
        inl_indexed_nonmember_secret,
        cost_indexed_nonmember_secret,
    },
    /*
     * ring_sig/v1
     * params[RS_SKB=0]=skb, params[RS_DEPTH=1]=depth
     * in: sk[skb], dirs[depth], siblings[depth*node], root_in[node]
     * out: none (assertion only)
     */
    {
        "stdlib/crypto/ring_sig/v1",
        "(sk : byte[skb], dirs : byte[depth], siblings : byte[depth*node],"
        " root : byte[node])",
        all_type_ids,
        sizeof(all_type_ids) / sizeof(all_type_ids[0]),
        2,         /* n_params */
        RS_DEPTH,  /* depth_param */
        RS_SKB,    /* leaf_param */
        {0, 1, 0}, /* param_min: skb>=0, depth>=1 */
        {SHIPSHAPE_REG_MAX_VECTOR_LEN, 1u << 16, 0}, /* param_max */
        4,                                           /* n_inputs */
        {
            {SS_ARGLEN_PARAM, RS_SKB},
            {SS_ARGLEN_PARAM, RS_DEPTH},
            {SS_ARGLEN_DEPTH_TIMES_NODE, 0},
            {SS_ARGLEN_NODE, 0}, /* root_in[node]: exactly node_bytes */
        },
        0, /* out_is_node_vec: assertion-only */
        GHASH_GRID(grid_ring_sig),
        inl_ring_sig_v1,
        cost_ring_sig_v1,
    },
};

#define N_HASH_DESCRIPTORS                                                     \
    (sizeof(HASH_DESCRIPTORS) / sizeof(HASH_DESCRIPTORS[0]))

/* ================================================================
 * Public hash-parametric accessors
 * ================================================================ */

size_t
voleith_shipshape_reg_hash_descriptor_count(void)
{
    return N_HASH_DESCRIPTORS;
}

int
voleith_shipshape_reg_hash_descriptor(
    size_t idx, const char **fqn, const char **signature,
    const uint16_t **types, size_t *n_types, uint8_t *n_params,
    uint8_t *depth_param, uint8_t *leaf_param,
    uint32_t param_min[VOLEITH_SHIPSHAPE_REG_MAX_PARAMS],
    uint32_t param_max[VOLEITH_SHIPSHAPE_REG_MAX_PARAMS], uint8_t *n_inputs,
    ss_arglen_t in[VOLEITH_SHIPSHAPE_REGISTRY_MAX_INPUTS],
    uint8_t *out_is_node_vec)
{
    size_t i;

    if (idx >= N_HASH_DESCRIPTORS)
        return -1;
    const ss_reg_hash_descriptor_t *d = &HASH_DESCRIPTORS[idx];
    if (fqn)
        *fqn = d->fqn;
    if (signature)
        *signature = d->signature;
    if (types)
        *types = d->types;
    if (n_types)
        *n_types = d->n_types;
    if (n_params)
        *n_params = d->n_params;
    if (depth_param)
        *depth_param = d->depth_param;
    if (leaf_param)
        *leaf_param = d->leaf_param;
    if (param_min)
        for (i = 0; i < VOLEITH_SHIPSHAPE_REG_MAX_PARAMS; i++)
            param_min[i] = d->param_min[i];
    if (param_max)
        for (i = 0; i < VOLEITH_SHIPSHAPE_REG_MAX_PARAMS; i++)
            param_max[i] = d->param_max[i];
    if (n_inputs)
        *n_inputs = d->n_inputs;
    if (in)
        for (i = 0; i < VOLEITH_SHIPSHAPE_REGISTRY_MAX_INPUTS; i++)
            in[i] = d->in[i];
    if (out_is_node_vec)
        *out_is_node_vec = d->out_is_node_vec;
    return 0;
}

size_t
voleith_shipshape_reg_hash_grid(size_t idx,
                                voleith_shipshape_reg_hash_body_t *out,
                                size_t max)
{
    size_t n, i;

    if (idx >= N_HASH_DESCRIPTORS)
        return 0;
    const ss_reg_hash_descriptor_t *d = &HASH_DESCRIPTORS[idx];
    if (out != NULL) {
        n = (d->grid_len < max) ? d->grid_len : max;
        for (i = 0; i < n; i++) {
            out[i].type_id = d->grid[i].type_id;
            out[i].n_params = d->grid[i].n_params;
            for (size_t j = 0; j < VOLEITH_SHIPSHAPE_REG_MAX_PARAMS; j++)
                out[i].params[j] = d->grid[i].params[j];
            /* hash field left uninitialised; callers that need it call
             * voleith_shipshape_reg_hash_body_hash. */
        }
    }
    return d->grid_len;
}

int
voleith_shipshape_reg_hash_cost(size_t idx, const voleith_node_hash_vt *vt,
                                const uint32_t *params, size_t *blocks,
                                size_t *invs)
{
    size_t b, v;

    if (idx >= N_HASH_DESCRIPTORS)
        return -1;
    HASH_DESCRIPTORS[idx].cost(vt, params, &b, &v);
    if (blocks)
        *blocks = b;
    if (invs)
        *invs = v;
    return 0;
}

int
voleith_shipshape_reg_hash_inline(size_t idx, voleith_gf8_circuit_t *c,
                                  const voleith_node_hash_vt *vt,
                                  const uint32_t *params, const gf8_wire_id *in,
                                  gf8_wire_id *out)
{
    if (idx >= N_HASH_DESCRIPTORS)
        return -1;
    return HASH_DESCRIPTORS[idx].inl(c, vt, params, in, out);
}

/*
 * Compute the total number of input wires for entry idx at (vt, params).
 * Returns the wire count, or 0 on error (idx out of range or unknown
 * arglen kind; kind SS_ARGLEN_DEPTH_TIMES_NODE requires depth_param to
 * be resolved before use, which is always true in our three entries).
 */
static size_t
hash_total_in_wires(size_t idx, const voleith_node_hash_vt *vt,
                    const uint32_t *params)
{
    size_t n, i;
    const ss_reg_hash_descriptor_t *d;

    if (idx >= N_HASH_DESCRIPTORS)
        return 0;
    d = &HASH_DESCRIPTORS[idx];
    n = 0;
    for (i = 0; i < d->n_inputs; i++) {
        switch (d->in[i].kind) {
        case SS_ARGLEN_FIXED:
            n += d->in[i].value;
            break;
        case SS_ARGLEN_PARAM:
            n += params[d->in[i].value];
            break;
        case SS_ARGLEN_DEPTH_TIMES_NODE:
            n += (size_t)params[d->depth_param] * vt->node_bytes;
            break;
        case SS_ARGLEN_NODE:
            n += vt->node_bytes;
            break;
        }
    }
    return n;
}

voleith_gf8_circuit_t *
voleith_shipshape_reg_hash_build_standalone(size_t idx, uint16_t type_id,
                                            const uint32_t *params)
{
    const ss_reg_hash_descriptor_t *d;
    const voleith_shipshape_node_hash_type_t *nht;
    const voleith_node_hash_vt *vt;
    voleith_gf8_circuit_t *c;
    gf8_wire_id *in, *out;
    size_t n_in, n_out;
    int rc;

    if (idx >= N_HASH_DESCRIPTORS)
        return NULL;
    d = &HASH_DESCRIPTORS[idx];

    nht = voleith_shipshape_node_hash_type_by_id(type_id);
    if (nht == NULL)
        return NULL;
    vt = nht->vt;

    /*
     * Validate: if the vt has a fixed leaf width (fixed_leaf_bytes != 0),
     * the effective leaf data bytes for this entry must match it.
     *
     * For merkle/path_secret and ring_sig/v1, the leaf data is the single
     * width param (L or skb).  For indexed_merkle/nonmember_secret, the
     * leaf record is low_value || low_next || next_index = 2*tb + ib, so
     * a compound check is needed.  We identify indexed by n_params == 3
     * (the only entry with three params).
     */
    if (vt->fixed_leaf_bytes != 0) {
        size_t eff_leaf;

        if (d->n_params == 3) {
            /* indexed_merkle: leaf record = 2*tb + ib */
            eff_leaf = (size_t)2 * params[IDX_TB] + params[IDX_IB];
        } else {
            eff_leaf = params[d->leaf_param];
        }
        if (eff_leaf != vt->fixed_leaf_bytes)
            return NULL;
    }

    n_in = hash_total_in_wires(idx, vt, params);
    n_out = d->out_is_node_vec ? vt->node_bytes : 1;

    c = voleith_gf8_circuit_new();
    if (c == NULL)
        return NULL;
    in = calloc(n_in > 0 ? n_in : 1, sizeof(*in));
    out = calloc(n_out, sizeof(*out));
    if (in == NULL || out == NULL) {
        free(in);
        free(out);
        voleith_gf8_circuit_free(c);
        return NULL;
    }
    for (size_t i = 0; i < n_in; i++)
        in[i] = voleith_gf8_add_witness(c);
    rc = d->inl(c, vt, params, in, out);
    free(in);
    free(out);
    if (rc != 0) {
        voleith_gf8_circuit_free(c);
        return NULL;
    }
    return c;
}

int
voleith_shipshape_reg_hash_body_hash(
    size_t idx, uint16_t type_id, const uint32_t *params,
    uint8_t out[VOLEITH_SHIPSHAPE_REGISTRY_BODY_HASH_BYTES])
{
    voleith_gf8_circuit_t *c;
    int rc;

    c = voleith_shipshape_reg_hash_build_standalone(idx, type_id, params);
    if (c == NULL)
        return -1;
    rc = voleith_gf8_circuit_fingerprint(c, out);
    voleith_gf8_circuit_free(c);
    return rc;
}
