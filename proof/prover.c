/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * prover.c - QuickSilver prover (FAEST spec Section 6)
 *
 * Bit-level QuickSilver: one VOLE slot per witness wire and per AND gate.
 *   ell = witness_count + and_gate_count
 *   ellhat = ell + 3*lambda + 16
 *
 * For each AND gate (a AND b = c):
 *   Prover sends degree-0, degree-1, degree-2 coefficients of:
 *     key[a]*key[b] + key[c]  (a polynomial of degree 2 in delta)
 *   where key[w] = tag[w] + delta*bit[w]
 *
 * Degree-0 coefficient: tag[a]*tag[b] + tag[c]
 * Degree-1 coefficient: tag[a]*bit[b] + tag[b]*bit[a] + bit[c]
 * Degree-2 coefficient: bit[a]*bit[b]
 *
 * These are accumulated across all gates using the zk_hash_3 Horner scheme
 * (same as FAEST universal_hashing.c zk_hash_128_3), parameterized by chall_2.
 *
 * For assert_zero(w): prover adds (tag[w], 0, 0) to the accumulator.
 *
 * x1 corrections at finalization (from VOLE bits beyond ell):
 *   x1_0 = v_star_0 = sum_poly(V columns ell..ell+lambda-1)
 *   x1_1 = u_star_0 + v_star_1
 *   x1_2 = u_star_1
 * where u_star_0 = sum_poly_bits(u bits ell..ell+lambda-1),
 *       v_star_1 = sum_poly(V columns ell+lambda..ell+2*lambda-1),
 *       u_star_1 = sum_poly_bits(u bits ell+lambda..ell+2*lambda-1).
 */

#include "prover.h"
#include "circuit.h"
#include "../core/field.h"
#include "../core/util.h"

#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#define UNIVERSAL_HASH_B_BITS 16u

/* =====================================================================
 * Internal GF(2^lambda) helpers
 * ===================================================================== */

/*
 * Transpose the VOLE matrix from row-major (lambda rows × row_bytes each)
 * to a flat column-major bit format: V_T[col * nb .. col * nb + nb - 1]
 * holds the nb-byte packed representation of column col, where bit j is
 * stored at bit position j of V_T (i.e., byte j/8, bit j%8).
 *
 * Only the first n_cols columns are transposed (callers pass ell + 2*lambda).
 * Returns a calloc'd buffer of n_cols * nb bytes, or NULL on OOM.
 */
static uint8_t *
transpose_matrix(const uint8_t **V, unsigned int lambda, unsigned int nb,
                 size_t n_cols)
{
    uint8_t *V_T = calloc(n_cols * nb, 1);
    if (!V_T)
        return NULL;
    size_t row_bytes = (n_cols + 7) / 8;
    for (unsigned int j = 0; j < lambda; j++) {
        for (size_t byte_idx = 0; byte_idx < row_bytes; byte_idx++) {
            uint8_t byte = V[j][byte_idx];
            for (int b = 0; b < 8; b++) {
                size_t col = byte_idx * 8 + (size_t)b;
                if (col >= n_cols)
                    break;
                if ((byte >> b) & 1u)
                    V_T[col * nb + j / 8] |= (uint8_t)(1u << (j % 8));
            }
        }
    }
    return V_T;
}

/*
 * Get bit pos from a byte array (LE bit order: bit 0 = LSbit of byte 0).
 */
static inline unsigned int
get_bit(const uint8_t *buf, size_t pos)
{
    return (buf[pos / 8] >> (pos % 8)) & 1u;
}

/*
 * Multiply a GF(2^lambda) element by alpha (the generator).
 * in and out may alias (handled via a temporary).
 * lambda must be 128, 192, or 256.
 */
static void
gf_mul_alpha(uint8_t *out, const uint8_t *in, unsigned int lambda)
{
    unsigned int nb = lambda / 8;
    uint8_t carry = (in[nb - 1] >> 7) & 1u;
    /* Shift left by one bit (little-endian byte and bit ordering) */
    for (unsigned int i = nb - 1; i > 0; i--)
        out[i] = (uint8_t)((in[i] << 1) | (in[i - 1] >> 7));
    out[0] = (uint8_t)(in[0] << 1);
    /* Reduce by irreducible polynomial */
    if (carry) {
        if (lambda == 128 || lambda == 192) {
            out[0] ^= 0x87u; /* x^7+x^2+x+1 */
        } else {             /* lambda == 256 */
            out[0] ^= 0x25u; /* x^5+x^2+x^0 */
            out[1] ^= 0x04u; /* x^10 */
        }
    }
}

/*
 * Compute sum_poly of `count` GF(2^lambda) column elements from V_T.
 * V_T is the column-major transposed matrix (each column = nb contiguous bytes).
 * Processes columns start_col .. start_col+count-1 using Horner's rule:
 *   result = alpha^{count-1}*col[0] + ... + alpha^0*col[count-1]
 *     (= col[count-1] + alpha*(col[count-2] + alpha*(...)))
 * out and tmp must be nb bytes wide.
 */
static void
sum_poly_cols(uint8_t *out, uint8_t *tmp, const uint8_t *V_T,
              unsigned int lambda, unsigned int nb, size_t start_col,
              unsigned int count)
{
    memcpy(out, V_T + (start_col + count - 1) * nb, nb);
    for (int i = (int)count - 2; i >= 0; i--) {
        gf_mul_alpha(tmp, out, lambda);
        memcpy(out, tmp, nb);
        memcpy(tmp, V_T + (start_col + (size_t)i) * nb, nb);
        for (unsigned int k = 0; k < nb; k++)
            out[k] ^= tmp[k];
    }
}

/*
 * Compute sum_poly_bits: interpret `count` bits of `buf` starting at
 * bit offset `start_bit` as GF(2^lambda) polynomial coefficients, using
 * the same Horner's rule as sum_poly (processes from bit start_bit+count-1
 * down to start_bit):
 *   result = alpha^{count-1}*bit[0] + ... + alpha^0*bit[count-1]
 *
 * count must equal lambda.
 * out and tmp must be lambda_bytes wide.
 */
static void
sum_poly_bits_at(uint8_t *out, uint8_t *tmp, const uint8_t *buf,
                 size_t start_bit, unsigned int lambda)
{
    unsigned int nb = lambda / 8;
    /* Start with the last bit (bit start_bit + lambda - 1) */
    uint8_t b = (uint8_t)get_bit(buf, start_bit + lambda - 1);
    memset(out, 0, nb);
    out[0] = b;
    /* Horner: out = alpha*out + bit[i] for i from lambda-2 down to 0 */
    for (int i = (int)lambda - 2; i >= 0; i--) {
        gf_mul_alpha(tmp, out, lambda);
        memcpy(out, tmp, nb);
        b = (uint8_t)get_bit(buf, start_bit + (size_t)i);
        out[0] ^= b;
    }
}

/* =====================================================================
 * zk_hash_3 context (prover side): three separate Horner accumulators
 *
 * For each gate, prover calls update(v0, v1, v2):
 *   h0[i] = h0[i]*s + v_i
 *   h1[i] = h1[i]*t + v_i    (t is a GF(2^64) element, treated as GF(2^lambda))
 *
 * Finalize: h_i = r0*h0[i] + r1*h1[i] + x1_i
 * ===================================================================== */

typedef struct {
    uint8_t h0[3][32]; /* 3 GF(2^lambda) accumulators for h0 */
    uint8_t h1[3][32]; /* 3 GF(2^lambda) accumulators for h1 */
    uint8_t s[32];     /* GF(2^lambda) Horner key for h0 */
    uint8_t t[32];     /* GF(2^64) key for h1, zero-padded to lambda_bytes */
    unsigned int lambda;
} zk_hash_3_ctx;

static void
zk_hash_3_init(zk_hash_3_ctx *ctx, const uint8_t *chall_2, unsigned int lambda)
{
    unsigned int nb = lambda / 8;
    ctx->lambda = lambda;
    memset(ctx->h0, 0, sizeof(ctx->h0));
    memset(ctx->h1, 0, sizeof(ctx->h1));
    /* r0 = chall_2[0..nb-1]
     * r1 = chall_2[nb..2*nb-1]
     * s  = chall_2[2*nb..3*nb-1]
     * t  = chall_2[3*nb..3*nb+7] (8 bytes, GF(2^64)) */
    memcpy(ctx->s, chall_2 + 2 * nb, nb);
    memset(ctx->t, 0, nb);
    /* t is only 8 bytes (GF(2^64)), zero-padded to nb bytes */
    unsigned int t_bytes = (nb < 8) ? nb : 8;
    memcpy(ctx->t, chall_2 + 3 * nb, t_bytes);
}

/*
 * Multiply two GF(2^lambda) elements (byte-level dispatch to field.h functions).
 * out = a * b in GF(2^lambda).
 * All pointers are lambda_bytes wide.
 */
static void
gf_mul(uint8_t *out, const uint8_t *a, const uint8_t *b, unsigned int lambda)
{
    if (lambda == 128) {
        voleith_gf128_t A, B, C;
        voleith_gf128_from_bytes(&A, a);
        voleith_gf128_from_bytes(&B, b);
        voleith_gf128_mul(&C, &A, &B);
        voleith_gf128_to_bytes(out, &C);
    } else if (lambda == 192) {
        voleith_gf192_t A, B, C;
        voleith_gf192_from_bytes(&A, a);
        voleith_gf192_from_bytes(&B, b);
        voleith_gf192_mul(&C, &A, &B);
        voleith_gf192_to_bytes(out, &C);
    } else { /* lambda == 256 */
        voleith_gf256_t A, B, C;
        voleith_gf256_from_bytes(&A, a);
        voleith_gf256_from_bytes(&B, b);
        voleith_gf256_mul(&C, &A, &B);
        voleith_gf256_to_bytes(out, &C);
    }
}

/*
 * Accumulate one AND gate (or assert_zero) into the zk_hash_3 context.
 * v0, v1, v2 are degree-2, degree-1, degree-0 coefficients respectively.
 * All are lambda_bytes wide.
 *
 * h0[i] = h0[i]*s + v_i
 * h1[i] = h1[i]*t + v_i
 */
static void
zk_hash_3_update(zk_hash_3_ctx *ctx, const uint8_t *v0, /* degree-2 */
                 const uint8_t *v1,                     /* degree-1 */
                 const uint8_t *v2,                     /* degree-0 */
                 uint8_t *tmp1, uint8_t *tmp2)
{
    unsigned int nb = ctx->lambda / 8;
    const uint8_t *vs[3] = {v0, v1, v2};

    for (int i = 0; i < 3; i++) {
        /* h0[i] = h0[i]*s + v_i */
        gf_mul(tmp1, ctx->h0[i], ctx->s, ctx->lambda);
        for (unsigned int k = 0; k < nb; k++)
            ctx->h0[i][k] = tmp1[k] ^ vs[i][k];

        /* h1[i] = h1[i]*t + v_i */
        gf_mul(tmp2, ctx->h1[i], ctx->t, ctx->lambda);
        for (unsigned int k = 0; k < nb; k++)
            ctx->h1[i][k] = tmp2[k] ^ vs[i][k];
    }
}

/*
 * Finalize the zk_hash_3 context.
 * h_i = r0*h0[i] + r1*h1[i] + x1_i
 * Outputs a0_tilde (from h_0), a1_tilde (h_1), a2_tilde (h_2).
 */
static void
zk_hash_3_finalize(uint8_t *a0_tilde, uint8_t *a1_tilde, uint8_t *a2_tilde,
                   const zk_hash_3_ctx *ctx, const uint8_t *x1_0,
                   const uint8_t *x1_1, const uint8_t *x1_2,
                   const uint8_t *chall_2, uint8_t *tmp1, uint8_t *tmp2)
{
    unsigned int nb = ctx->lambda / 8;
    const uint8_t *r0 = chall_2;
    const uint8_t *r1 = chall_2 + nb;
    uint8_t *outputs[3] = {a0_tilde, a1_tilde, a2_tilde};
    const uint8_t *x1s[3] = {x1_0, x1_1, x1_2};

    for (int i = 0; i < 3; i++) {
        /* tmp1 = r0 * h0[i] */
        gf_mul(tmp1, r0, ctx->h0[i], ctx->lambda);
        /* tmp2 = r1 * h1[i] */
        gf_mul(tmp2, r1, ctx->h1[i], ctx->lambda);
        /* output = tmp1 + tmp2 + x1[i] */
        for (unsigned int k = 0; k < nb; k++)
            outputs[i][k] = tmp1[k] ^ tmp2[k] ^ x1s[i][k];
    }
}

/* =====================================================================
 * Main prover
 * ===================================================================== */

size_t
voleith_qs_ell(const voleith_circuit_t *circuit)
{
    return voleith_circuit_witness_count(circuit) +
           voleith_circuit_and_gate_count(circuit);
}

size_t
voleith_qs_ellhat(const voleith_circuit_t *circuit, unsigned int lambda)
{
    return voleith_qs_ell(circuit) + 3u * lambda + UNIVERSAL_HASH_B_BITS;
}

int
voleith_qs_prove(const voleith_circuit_t *circuit, const uint8_t *witness,
                 const uint8_t *instance, unsigned int lambda, const uint8_t *u,
                 const uint8_t **V, const uint8_t *chall_2, uint8_t *d_out,
                 uint8_t *a0_tilde, uint8_t *a1_tilde, uint8_t *a2_tilde)
{
    if (!circuit || !witness || !instance || !u || !V || !chall_2 || !d_out ||
        !a0_tilde || !a1_tilde || !a2_tilde)
        return -1;
    if (lambda != 128 && lambda != 192 && lambda != 256)
        return -1;

    unsigned int nb = lambda / 8;
    size_t n_wires = voleith_circuit_wire_count(circuit);
    size_t n_witness = voleith_circuit_witness_count(circuit);
    size_t n_and = voleith_circuit_and_gate_count(circuit);
    size_t ell = n_witness + n_and;
    size_t ell_bytes = (ell + 7) / 8;

    const wire_entry_t *wires = voleith_circuit_wires(circuit);
    const constraint_entry_t *constraints =
        voleith_circuit_constraints(circuit);
    size_t n_constraints = voleith_circuit_constraint_count(circuit);

    /* Declare all heap pointers before any goto to keep oom: cleanup safe */
    uint8_t *bits_heap = NULL;
    uint8_t *tags = NULL;
    uint8_t *V_T = NULL;

    /* Allocate per-wire bit values (stack for small circuits, heap otherwise) */
    size_t wire_bytes = (n_wires + 7) / 8;
    uint8_t bits_stack[VOLEITH_STACK_BUF_MAX];
    uint8_t *bits;
    if (wire_bytes > sizeof(bits_stack)) {
        bits_heap = calloc(wire_bytes, 1);
        if (!bits_heap)
            goto oom;
        bits = bits_heap;
    } else {
        memset(bits_stack, 0, wire_bytes);
        bits = bits_stack;
    }

    tags = calloc(n_wires * nb, 1); /* tag[w] = lambda_bytes each */
    if (!tags)
        goto oom;

    /* Transpose V to column-major so each column is a contiguous nb-byte block */
    size_t vt_cols = ell + 2 * (size_t)lambda;
    V_T = transpose_matrix(V, lambda, nb, vt_cols);
    if (!V_T)
        goto oom;

    /* Working buffers - fixed max size (lambda/8 ≤ 32 bytes for all parameter sets) */
    uint8_t tmp1[32] = {0};
    uint8_t tmp2[32] = {0};
    uint8_t tmp3[32] = {0};

    /* ------------------------------------------------------------------
     * Step 1: Evaluate the circuit to get bit[w] for all wires.
     * voleith_circuit_eval() handles all wire types and returns:
     *   1  - all constraints satisfied
     *   0  - some constraint violated (invalid witness)
     *   -1 - error (bad circuit / args)
     *
     * X-10 / P-14: reject != 1, matching the GF(2⁸) prover's
     * discipline.  Refusing to publish coefficients for an invalid
     * witness avoids leaking derived data and gives the caller a
     * fail-fast error instead of an unverifiable proof.
     * ------------------------------------------------------------------ */
    {
        size_t nbits = (n_wires + 7) / 8;
        if (voleith_circuit_eval(circuit, witness, instance, bits) != 1)
            goto err;
        (void)nbits;
    }

    /* ------------------------------------------------------------------
     * Step 2: Compute tag[w] for each wire.
     *
     * VOLE slot assignment:
     *   Witness wire with witness index wi → VOLE slot wi
     *   AND gate with AND index ai → VOLE slot n_witness + ai
     *   All other wires: tag derived via linear homomorphism.
     *
     * Process in topological order (wires[0..n_wires-1]).
     * Track witness_index and and_index as we scan.
     * ------------------------------------------------------------------ */
    {
        size_t witness_idx = 0;
        size_t and_idx = 0;

        for (size_t w = 0; w < n_wires; w++) {
            uint8_t *tag_w = tags + w * nb;
            const wire_entry_t *e = &wires[w];

            switch (e->kind) {
            case WIRE_KIND_WITNESS: {
                /* VOLE slot = witness_idx */
                memcpy(tag_w, V_T + witness_idx * nb, nb);
                witness_idx++;
                break;
            }
            case WIRE_KIND_INSTANCE:
            case WIRE_KIND_CONST:
                /* Public values: tag = 0 */
                memset(tag_w, 0, nb);
                break;

            case WIRE_KIND_XOR: {
                /* tag[out] = tag[a] XOR tag[b] */
                const uint8_t *ta = tags + e->a * nb;
                const uint8_t *tb = tags + e->b * nb;
                for (unsigned int k = 0; k < nb; k++)
                    tag_w[k] = ta[k] ^ tb[k];
                break;
            }
            case WIRE_KIND_AND: {
                /* tag[out] comes from VOLE slot n_witness + and_idx */
                memcpy(tag_w, V_T + (n_witness + and_idx) * nb, nb);
                and_idx++;
                break;
            }
            case WIRE_KIND_NOT: {
                /* NOT a = a XOR 1; tag is same as a (XOR with const_1 is free) */
                const uint8_t *ta = tags + e->a * nb;
                memcpy(tag_w, ta, nb);
                break;
            }
            }
        }
    }

    /* ------------------------------------------------------------------
     * Step 3: Compute d[w] = bit[w] XOR bit(u, slot[w])
     * Only for wires with VOLE slots (witness wires and AND gate outputs).
     * ------------------------------------------------------------------ */
    memset(d_out, 0, ell_bytes);
    {
        size_t witness_idx = 0;
        size_t and_idx = 0;

        for (size_t w = 0; w < n_wires; w++) {
            const wire_entry_t *e = &wires[w];
            size_t slot;
            int is_slotted = 0;

            if (e->kind == WIRE_KIND_WITNESS) {
                slot = witness_idx++;
                is_slotted = 1;
            } else if (e->kind == WIRE_KIND_AND) {
                slot = n_witness + and_idx++;
                is_slotted = 1;
            }

            if (is_slotted) {
                unsigned int bit_w = get_bit(bits, w);
                unsigned int bit_u = get_bit(u, slot);
                unsigned int d = bit_w ^ bit_u;
                if (d)
                    d_out[slot / 8] |= (uint8_t)(1u << (slot % 8));
            }
        }
    }

    /* ------------------------------------------------------------------
     * Step 4: Accumulate AND gate checks into zk_hash_3.
     *
     * For AND gate (a AND b = c):
     *   v0 = tag[a]*tag[b] + tag[c]  (degree-0 coefficient in delta)
     *   v1 = tag[a]*bit[b] + tag[b]*bit[a] + bit[c]  (degree-1)
     *   v2 = bit[a]*bit[b]  (degree-2)
     * ------------------------------------------------------------------ */
    zk_hash_3_ctx hasher;
    zk_hash_3_init(&hasher, chall_2, lambda);

    {
        uint8_t v0[32], v1[32], v2[32], prod[32], zero[32];
        memset(zero, 0, nb);

        for (size_t w = 0; w < n_wires; w++) {
            const wire_entry_t *e = &wires[w];
            if (e->kind != WIRE_KIND_AND)
                continue;

            wire_id wa = e->a, wb = e->b, wc = (wire_id)w;
            const uint8_t *ta = tags + wa * nb;
            const uint8_t *tb = tags + wb * nb;
            const uint8_t *tc = tags + wc * nb;
            unsigned int ba = get_bit(bits, wa);
            unsigned int bb = get_bit(bits, wb);
            unsigned int bc = get_bit(bits, wc);

            /* v0 = tag[a]*tag[b] + tag[c] */
            gf_mul(prod, ta, tb, lambda);
            for (unsigned int k = 0; k < nb; k++)
                v0[k] = prod[k] ^ tc[k];

            /* v1 = tag[a]*bit[b] + tag[b]*bit[a] + bit[c] */
            /* tag[a]*bit[b]: if bit[b]=0 → 0, else tag[a] */
            memset(v1, 0, nb);
            if (bb)
                for (unsigned int k = 0; k < nb; k++)
                    v1[k] ^= ta[k];
            if (ba)
                for (unsigned int k = 0; k < nb; k++)
                    v1[k] ^= tb[k];
            /* + bit[c]: if bit[c]=1 → XOR with 1 (= XOR byte 0 bit 0) */
            v1[0] ^= (uint8_t)bc;

            /* v2 = bit[a]*bit[b] */
            memset(v2, 0, nb);
            v2[0] = (uint8_t)(ba & bb);

            zk_hash_3_update(&hasher, v0, v1, v2, tmp1, tmp2);
        }

        /* P-3: zero per-gate working buffers at end of scope.
         * v0/v1/v2 carry secret QuickSilver coefficients; prod is the
         * tag·tag product. */
        voleith_secure_zero(v0, sizeof(v0));
        voleith_secure_zero(v1, sizeof(v1));
        voleith_secure_zero(v2, sizeof(v2));
        voleith_secure_zero(prod, sizeof(prod));
        voleith_secure_zero(zero, sizeof(zero));
    }

    /* ------------------------------------------------------------------
     * Step 5: Accumulate assert_zero constraints.
     *
     * For assert_zero(w): prover adds (tag[w], 0, 0).
     * For assert_equal(a, b): encoded as assert_zero(a XOR b), so the
     * underlying XOR wire (whose tag = tag[a]+tag[b]) gets the check.
     * ------------------------------------------------------------------ */
    {
        uint8_t zero[32];
        memset(zero, 0, nb);

        for (size_t ci = 0; ci < n_constraints; ci++) {
            const constraint_entry_t *c = &constraints[ci];
            if (c->kind == CONSTRAINT_ZERO) {
                zk_hash_3_update(&hasher, tags + c->a * nb, zero, zero, tmp1,
                                 tmp2);
            }
            /* CONSTRAINT_EQUAL is expressed as assert_zero(a XOR b)
             * which creates a XOR gate output as the constrained wire.
             * The circuit builder handles this, so we only see ZERO here. */
        }
        /* `zero` is a public zero constant - no security need to clear,
         * done for hygiene-bar consistency with the other per-block
         * buffers. */
        voleith_secure_zero(zero, sizeof(zero));
    }

    /* ------------------------------------------------------------------
     * Step 6: Compute x1 corrections from VOLE bits beyond ell.
     *
     * x1_0 = sum_poly(V columns ell..ell+lambda-1)
     * x1_1 = sum_poly(V columns ell+lambda..ell+2*lambda-1) + u_star_0
     *       where u_star_0 = sum_poly_bits(u bits ell..ell+lambda-1)
     * x1_2 = u_star_1 = sum_poly_bits(u bits ell+lambda..ell+2*lambda-1)
     * ------------------------------------------------------------------ */
    uint8_t x1_0[32], x1_1[32], x1_2[32];
    {
        /* v_star_0 = sum_poly(V cols ell..ell+lambda-1) */
        sum_poly_cols(x1_0, tmp1, V_T, lambda, nb, ell, lambda);

        /* u_star_0 = sum_poly_bits(u, ell..ell+lambda-1) */
        sum_poly_bits_at(tmp3, tmp1, u, ell, lambda);

        /* v_star_1 = sum_poly(V cols ell+lambda..ell+2*lambda-1) */
        sum_poly_cols(x1_1, tmp1, V_T, lambda, nb, ell + lambda, lambda);

        /* x1_1 = u_star_0 + v_star_1 */
        for (unsigned int k = 0; k < nb; k++)
            x1_1[k] ^= tmp3[k];

        /* x1_2 = u_star_1 = sum_poly_bits(u, ell+lambda..ell+2*lambda-1) */
        sum_poly_bits_at(x1_2, tmp1, u, ell + lambda, lambda);
    }

    /* ------------------------------------------------------------------
     * Step 7: Finalize zk_hash_3 to get a0_tilde, a1_tilde, a2_tilde.
     * ------------------------------------------------------------------ */
    zk_hash_3_finalize(a0_tilde, a1_tilde, a2_tilde, &hasher, x1_0, x1_1, x1_2,
                       chall_2, tmp1, tmp2);

    {
        /*
         * P-2: heap buffers that carried witness-derived material -
         * `bits_heap` (every wire value), `tags` (per-wire VOLE
         * tags), `V_T` (transposed VOLE mask matrix) - are zeroed
         * before free on every exit path.  An attacker recovering
         * any of them learns the witness directly or the tags
         * needed to forge.  `bits_heap` may be NULL when the
         * circuit fit in the stack buffer; NULL-guarded.
         *
         * P-3, P-4: zero function-scoped stack buffers that hold
         * secret-derived material.  bits_stack mirrors bits_heap
         * (used when wire_bytes fits the inline buffer); tmp1/2/3
         * carry intermediate field multiplications; x1_0/1/2 are
         * VOLE corrections folded into the final ZK hash; hasher
         * carries Horner accumulators over witness-derived tags.
         */
        if (V_T)
            voleith_secure_zero(V_T, vt_cols * nb);
        if (tags)
            voleith_secure_zero(tags, n_wires * nb);
        if (bits_heap)
            voleith_secure_zero(bits_heap, wire_bytes);
        voleith_secure_zero(bits_stack, sizeof(bits_stack));
        voleith_secure_zero(tmp1, sizeof(tmp1));
        voleith_secure_zero(tmp2, sizeof(tmp2));
        voleith_secure_zero(tmp3, sizeof(tmp3));
        voleith_secure_zero(x1_0, sizeof(x1_0));
        voleith_secure_zero(x1_1, sizeof(x1_1));
        voleith_secure_zero(x1_2, sizeof(x1_2));
        voleith_secure_zero(&hasher, sizeof(hasher));
        free(V_T);
        free(bits_heap);
        free(tags);
    }
    return 0;

oom:
err:
    /* Same cleanup as the success path.  At each goto site, at
     * least one of V_T/tags/bits_heap has been written to (the OOM
     * from transpose_matrix happens after `tags` is populated; the
     * err: from voleith_circuit_eval has `tags` and `bits_heap` or
     * `bits_stack` populated).  We unconditionally zero every
     * function-scoped buffer that could carry secret material -
     * some are guaranteed-uninitialized on early gotos (tmp1/2/3,
     * x1_*, hasher all live below where the OOM sites fire), but
     * zeroing them is harmless (writes only) and avoids drift if
     * the goto sites later move past their declarations. */
    if (V_T)
        voleith_secure_zero(V_T, vt_cols * nb);
    if (tags)
        voleith_secure_zero(tags, n_wires * nb);
    if (bits_heap)
        voleith_secure_zero(bits_heap, wire_bytes);
    voleith_secure_zero(bits_stack, sizeof(bits_stack));
    voleith_secure_zero(tmp1, sizeof(tmp1));
    voleith_secure_zero(tmp2, sizeof(tmp2));
    voleith_secure_zero(tmp3, sizeof(tmp3));
    voleith_secure_zero(x1_0, sizeof(x1_0));
    voleith_secure_zero(x1_1, sizeof(x1_1));
    voleith_secure_zero(x1_2, sizeof(x1_2));
    voleith_secure_zero(&hasher, sizeof(hasher));
    free(V_T);
    free(bits_heap);
    free(tags);
    return -1;
}

int
voleith_qs_compute_d(const voleith_circuit_t *circuit, const uint8_t *witness,
                     const uint8_t *instance, const uint8_t *u, uint8_t *d_out)
{
    if (!circuit || !witness || !instance || !u || !d_out)
        return -1;

    size_t n_wires = voleith_circuit_wire_count(circuit);
    size_t n_witness = voleith_circuit_witness_count(circuit);
    size_t n_and = voleith_circuit_and_gate_count(circuit);
    size_t ell = n_witness + n_and;
    size_t ell_bytes = (ell + 7) / 8;

    const wire_entry_t *wires = voleith_circuit_wires(circuit);

    size_t wire_bytes = (n_wires + 7) / 8;
    uint8_t bits_stack[VOLEITH_STACK_BUF_MAX];
    uint8_t *bits_heap = NULL;
    uint8_t *bits;
    if (wire_bytes > sizeof(bits_stack)) {
        bits_heap = calloc(wire_bytes, 1);
        if (!bits_heap)
            return -1;
        bits = bits_heap;
    } else {
        memset(bits_stack, 0, wire_bytes);
        bits = bits_stack;
    }

    /* X-10 / P-14: reject != 1, treating a constraint violation
     * (return value 0) the same as an error.  Matches the GF(2⁸)
     * variant and the qs_prove discipline. */
    if (voleith_circuit_eval(circuit, witness, instance, bits) != 1) {
        /* P-2: bits_heap may already hold partial wire values from
         * voleith_circuit_eval before it returned an error. */
        if (bits_heap)
            voleith_secure_zero(bits_heap, wire_bytes);
        free(bits_heap);
        return -1;
    }

    memset(d_out, 0, ell_bytes);
    {
        size_t witness_idx = 0;
        size_t and_idx = 0;

        for (size_t w = 0; w < n_wires; w++) {
            const wire_entry_t *e = &wires[w];
            size_t slot = 0;
            int is_slotted = 0;

            if (e->kind == WIRE_KIND_WITNESS) {
                slot = witness_idx++;
                is_slotted = 1;
            } else if (e->kind == WIRE_KIND_AND) {
                slot = n_witness + and_idx++;
                is_slotted = 1;
            }

            if (is_slotted) {
                unsigned int bit_w = (bits[w / 8] >> (w % 8)) & 1u;
                unsigned int bit_u = (u[slot / 8] >> (slot % 8)) & 1u;
                if (bit_w ^ bit_u)
                    d_out[slot / 8] |= (uint8_t)(1u << (slot % 8));
            }
        }
    }

    /* P-2: bits_heap holds every wire value (a direct function of the
     * witness).  Zero before free. */
    if (bits_heap)
        voleith_secure_zero(bits_heap, wire_bytes);
    free(bits_heap);
    return 0;
}
