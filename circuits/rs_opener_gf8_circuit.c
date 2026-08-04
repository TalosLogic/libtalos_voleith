/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * rs_opener_gf8_circuit.c - V5 designated-opener in-circuit relation (OP.CIRC.2:
 * the syndrome + well-formedness half).  See rs_opener_gf8_circuit.h.
 */

#include "rs_opener_gf8_circuit.h"

#include "aes_gf8_circuit.h"
#include "grostl_gf8_circuit.h"

#include <stdlib.h>
#include <string.h>

#define GROSTL256_BLOCK 64u

/* Number of Grostl-256 compressions for an msg_bytes-long support under the
 * ichor_grostl_finalize_fixed rule: full 64-byte blocks, plus one for a partial
 * tail; an exact block multiple adds none; an empty message compresses one zero
 * block. */
static size_t
grostl256_kdf_nblocks(size_t msg_bytes)
{
    size_t full = msg_bytes / GROSTL256_BLOCK;
    size_t rem = msg_bytes % GROSTL256_BLOCK;
    if (msg_bytes == 0)
        return 1; /* single zero block */
    return full + (rem != 0 ? 1u : 0u);
}

int
voleith_rs_opener_syndrome_gf8(voleith_gf8_circuit_t *c,
                               const gf8_wire_id *support_wires,
                               const gf8_wire_id *s_bit_wires, uint32_t t,
                               uint32_t idx_bits, uint32_t p, uint32_t n0,
                               const uint8_t *M)
{
    gf8_wire_id *idx_w = NULL; /* t*idx_bits MSB-first index bit wires */
    gf8_wire_id *n_w = NULL;   /* idx_bits const bits of n = n0*p       */
    uint32_t n;
    int rc = -1;
    uint32_t k;
    uint32_t b;

    if (c == NULL || support_wires == NULL || s_bit_wires == NULL)
        return -1;
    if (t == 0u || idx_bits == 0u || p == 0u || n0 == 0u)
        return -1;
    if (n0 > 1u && M == NULL)
        return -1;
    n = n0 * p;

    idx_w = calloc((size_t)t * idx_bits, sizeof(*idx_w));
    n_w = calloc(idx_bits, sizeof(*n_w));
    if (idx_w == NULL || n_w == NULL)
        goto out;

    /*
     * Extract MSB-first index bit wires from the LSB-first packed support.
     * Index k occupies packed bits [k*idx_bits, (k+1)*idx_bits) with its LSB at
     * the lowest position (ichor_bitpack_le32).  assert_syndrome wants
     * idx_w[k*idx_bits + b] = MSB-first bit b = integer bit (idx_bits-1-b) =
     * the packed bit at global position P = k*idx_bits + (idx_bits-1-b).  Each
     * extraction is a free linear map selecting that bit into byte bit 0, so
     * the result is auto-boolean and carries the support's (secret) VOLE tag.
     */
    for (k = 0; k < t; k++) {
        for (b = 0; b < idx_bits; b++) {
            size_t pos = (size_t)k * idx_bits + (idx_bits - 1u - b);
            uint8_t sel[8] = {0};
            sel[0] = (uint8_t)(1u << (pos % 8u));
            idx_w[(size_t)k * idx_bits + b] =
                voleith_gf8_add_linear_map(c, support_wires[pos / 8u], sel);
        }
    }

    /* Baked constant n as MSB-first idx_bits const bits (zero VOLE slots). */
    for (b = 0; b < idx_bits; b++)
        n_w[b] = voleith_gf8_add_const(
            c, (uint8_t)((n >> (idx_bits - 1u - b)) & 1u));

    /* Syndrome relation s = M * e^T over the committed support. */
    voleith_gf8_assert_syndrome(c, idx_w, s_bit_wires, t, idx_bits, p, n0, M);

    /*
     * UNIFORM weight-t well-formedness (QS_DEGREE_D section 18): the strict-
     * ascending chain assert_lt(idx[k], idx[k+1]) enforces distinct + ascending
     * + canonical in one shot; the range check assert_lt(idx[t-1], n) forces
     * every index < n.  Both are zero-slot degree-(idx_bits+1) constraints
     * batched into the syndrome zk_hash.
     */
    for (k = 0; k + 1u < t; k++)
        voleith_gf8_assert_lt(c, idx_w + (size_t)k * idx_bits,
                              idx_w + (size_t)(k + 1u) * idx_bits, idx_bits);
    voleith_gf8_assert_lt(c, idx_w + (size_t)(t - 1u) * idx_bits, n_w,
                          idx_bits);

    rc = 0;
out:
    free(idx_w);
    free(n_w);
    return rc;
}

/*
 * K = AES-DM(ds_iv, support): standard message-keyed Davies-Meyer, byte-exact to
 * ichor_aesdm_init_iv/absorb/finalize_fixed.  h seeded at ds_iv; each 16-byte
 * support block is the AES KEY, h the plaintext; h = AES_block(h) XOR h.  A final
 * partial block is zero-padded and run once more; an exact block multiple adds
 * nothing (msg_bytes == 0 leaves K = ds_iv).
 */
static void
opener_kdf_aesdm_gf8(voleith_gf8_circuit_t *c, const uint8_t ds_iv[16],
                     const gf8_wire_id *support_wires, size_t msg_bytes,
                     gf8_wire_id out_k[16])
{
    gf8_wire_id h[16];
    size_t full = msg_bytes / 16u;
    size_t rem = msg_bytes % 16u;
    size_t blk, k;

    for (k = 0; k < 16; k++)
        h[k] = voleith_gf8_add_const(c, ds_iv[k]);

    for (blk = 0; blk < full; blk++) {
        const gf8_wire_id *M = support_wires + blk * 16u;
        gf8_wire_id cipher[16];
        aes128_gf8_circuit(c, M, h, cipher); /* AES_M(h): block = key */
        for (k = 0; k < 16; k++)
            h[k] = voleith_gf8_add_xor(c, cipher[k], h[k]); /* XOR h */
    }

    if (rem > 0) {
        gf8_wire_id padded[16];
        gf8_wire_id cipher[16];
        for (k = 0; k < rem; k++)
            padded[k] = support_wires[full * 16u + k];
        for (k = rem; k < 16; k++)
            padded[k] = voleith_gf8_add_const(c, 0x00);
        aes128_gf8_circuit(c, padded, h, cipher);
        for (k = 0; k < 16; k++)
            h[k] = voleith_gf8_add_xor(c, cipher[k], h[k]);
    }

    for (k = 0; k < 16; k++)
        out_k[k] = h[k];
}

int
voleith_rs_opener_dem_aesdm_gf8(voleith_gf8_circuit_t *c,
                                const gf8_wire_id *support_wires,
                                size_t msg_bytes, const uint8_t ds_iv[16],
                                const gf8_wire_id *id_wires,
                                const gf8_wire_id *tag_ct_wires,
                                size_t key_bytes)
{
    gf8_wire_id K[16];
    size_t j;

    if (c == NULL || ds_iv == NULL || id_wires == NULL || tag_ct_wires == NULL)
        return -1;
    if (msg_bytes > 0 && support_wires == NULL)
        return -1;
    if (key_bytes != 16u) /* AES-DM K width; Grostl-256 (32) is OP.CIRC.3b */
        return -1;

    opener_kdf_aesdm_gf8(c, ds_iv, support_wires, msg_bytes, K);

    /* XOR-OTP DEM: assert tag_ct == K XOR id (free XOR + equality). */
    for (j = 0; j < key_bytes; j++) {
        gf8_wire_id x = voleith_gf8_add_xor(c, K[j], id_wires[j]);
        voleith_gf8_assert_equal(c, x, tag_ct_wires[j]);
    }
    return 0;
}

size_t
voleith_rs_opener_kdf_aesdm_invin_bytes(size_t msg_bytes)
{
    size_t full = msg_bytes / 16u;
    size_t n_aes = full + ((msg_bytes % 16u) != 0u ? 1u : 0u);
    return n_aes * 200u;
}

void
voleith_rs_opener_kdf_aesdm_build_witness(const uint8_t ds_iv[16],
                                          const uint8_t *msg, size_t msg_bytes,
                                          uint8_t *out_invin)
{
    uint8_t h[16];
    uint8_t block[16];
    uint8_t w[216];
    uint8_t ct[16];
    size_t full = msg_bytes / 16u;
    size_t rem = msg_bytes % 16u;
    size_t blk, k, off = 0;

    memcpy(h, ds_iv, 16);
    for (blk = 0; blk < full; blk++) {
        memcpy(block, msg + blk * 16u, 16);
        aes128_gf8_build_witness(block, h, w, ct); /* key = block, pt = h */
        memcpy(out_invin + off, w + 16, 200);      /* inv_in only (KS+data) */
        off += 200;
        for (k = 0; k < 16; k++)
            h[k] = (uint8_t)(ct[k] ^ h[k]); /* Davies-Meyer feed-forward */
    }
    if (rem > 0) {
        memcpy(block, msg + full * 16u, rem);
        memset(block + rem, 0, 16 - rem);
        aes128_gf8_build_witness(block, h, w, ct);
        memcpy(out_invin + off, w + 16, 200);
        off += 200;
        for (k = 0; k < 16; k++)
            h[k] = (uint8_t)(ct[k] ^ h[k]);
    }
}

/* ds_iv (16 bytes) zero-padded to the 64-byte Grostl-256 chaining IV. */
static void
grostl256_kdf_iv(const uint8_t ds_iv[16], uint8_t iv64[64])
{
    memset(iv64, 0, 64);
    memcpy(iv64, ds_iv, 16);
}

int
voleith_rs_opener_dem_grostl256_gf8(voleith_gf8_circuit_t *c,
                                    const gf8_wire_id *support_wires,
                                    size_t msg_bytes, const uint8_t ds_iv[16],
                                    const gf8_wire_id *id_wires,
                                    const gf8_wire_id *tag_ct_wires,
                                    size_t key_bytes)
{
    uint8_t iv64[64];
    size_t n_blocks = grostl256_kdf_nblocks(msg_bytes);
    size_t nb_wires = n_blocks * GROSTL256_BLOCK;
    gf8_wire_id *blocks = NULL;
    gf8_wire_id K[32];
    size_t i, j;

    if (c == NULL || ds_iv == NULL || id_wires == NULL || tag_ct_wires == NULL)
        return -1;
    if (msg_bytes > 0 && support_wires == NULL)
        return -1;
    if (key_bytes != 32u) /* Grostl-256 K width; AES-DM (16) is OP.CIRC.3a */
        return -1;

    grostl256_kdf_iv(ds_iv, iv64);

    /* Block wires: the support bytes, then zero-const padding to n_blocks * 64
     * (matching finalize_fixed's zero-fill of the final partial / empty block). */
    blocks = calloc(nb_wires, sizeof(*blocks));
    if (blocks == NULL)
        return -1;
    for (i = 0; i < msg_bytes; i++)
        blocks[i] = support_wires[i];
    for (i = msg_bytes; i < nb_wires; i++)
        blocks[i] = voleith_gf8_add_const(c, 0x00);

    grostl256_gf8_nodeN_circuit(c, iv64, blocks, n_blocks, K);
    free(blocks);

    /* XOR-OTP DEM: assert tag_ct == K XOR id. */
    for (j = 0; j < key_bytes; j++) {
        gf8_wire_id x = voleith_gf8_add_xor(c, K[j], id_wires[j]);
        voleith_gf8_assert_equal(c, x, tag_ct_wires[j]);
    }
    return 0;
}

size_t
voleith_rs_opener_kdf_grostl256_invin_bytes(size_t msg_bytes)
{
    return grostl256_gf8_nodeN_invin_bytes(grostl256_kdf_nblocks(msg_bytes));
}

void
voleith_rs_opener_kdf_grostl256_build_witness(const uint8_t ds_iv[16],
                                              const uint8_t *msg,
                                              size_t msg_bytes,
                                              uint8_t *out_invin)
{
    uint8_t iv64[64];
    size_t n_blocks = grostl256_kdf_nblocks(msg_bytes);
    size_t nb = n_blocks * GROSTL256_BLOCK;
    uint8_t *blockbuf = calloc(nb, 1);

    if (blockbuf == NULL)
        return; /* caller pre-sizes; OOM here leaves inv unwritten */
    if (msg_bytes > 0)
        memcpy(blockbuf, msg, msg_bytes);
    grostl256_kdf_iv(ds_iv, iv64);
    grostl256_gf8_nodeN_build_witness(iv64, blockbuf, n_blocks, out_invin);
    free(blockbuf);
}
