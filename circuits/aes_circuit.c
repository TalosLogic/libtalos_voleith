/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * aes_circuit.c - AES S-box and AES-128/256 as Boolean circuits
 *
 * S-box inversion uses the Canright (2005) tower field decomposition:
 *   GF(2^2) = GF(2)[xi]  / (xi^2  + xi  + 1)
 *   GF(2^4) = GF(2^2)[eta]  / (eta^2 + eta + xi)
 *   GF(2^8) = GF(2^4)[theta] / (theta^2 + theta + phi)  where phi = xi*eta
 *
 * The change-of-basis matrices between AES GF(2^8) (polynomial basis for
 * x^8+x^4+x^3+x+1) and this tower field were computed by finding the roots
 * of the defining polynomials inside AES GF(2^8):
 *   xi=0xbc, eta=0x5c, phi=0xb0, theta=0xf2  (AES polynomial representation)
 *
 * B     (AES poly → tower): rows {0x73,0x38,0x42,0xc8,0x70,0x0c,0xde,0xa0}
 * B_inv (tower → AES poly): rows {0xe1,0xf0,0xc6,0xe6,0x7e,0x9a,0xf4,0x1a}
 *
 * All of B, B_inv, and the AES affine transform are linear over GF(2),
 * so they contribute only XOR/NOT gates (zero AND gates).
 *
 * AND gate accounting:
 *   GF(2^2) multiplication: 3 AND gates (Karatsuba)
 *   GF(2^4) multiplication: 9 AND gates (3 × GF(2^2) mults via Karatsuba)
 *   GF(2^8) inversion:     36 AND gates (4 × GF(2^4) operations at 9 each)
 *   AES S-box:             36 AND gates total
 */

#include "aes_circuit.h"
#include "circuit.h"
#include <string.h>
#include <stdint.h>

/* ================================================================
 * Tower field helpers - all operate on wire IDs in a circuit
 * ================================================================ */

/* GF(2^2) element: coefficient of xi (h) and constant term (l). */
typedef struct {
    wire_id h, l;
} gf2_wires;

/* GF(2^4) element: high GF(2^2) (coefficient of eta) and low GF(2^2). */
typedef struct {
    gf2_wires H, L;
} gf4_wires;

/* GF(2^8) element: high GF(2^4) (coefficient of theta) and low GF(2^4). */
typedef struct {
    gf4_wires H, L;
} gf8_wires;

/* ------ GF(2^2) operations ------ */

/* Addition: component-wise XOR - free. */
static gf2_wires
gf2_add(voleith_circuit_t *c, gf2_wires a, gf2_wires b)
{
    return (gf2_wires){
        voleith_circuit_add_xor(c, a.h, b.h),
        voleith_circuit_add_xor(c, a.l, b.l),
    };
}

/* Squaring in GF(2^2): sq(h,l) = (h, h XOR l) - free (one XOR). */
static gf2_wires
gf2_sq(voleith_circuit_t *c, gf2_wires a)
{
    return (gf2_wires){a.h, voleith_circuit_add_xor(c, a.h, a.l)};
}

/* Inversion in GF(2^2): inv = sq (since x^{-1} = x^2 for x in GF(2^2)*) - free. */
static gf2_wires
gf2_inv(voleith_circuit_t *c, gf2_wires a)
{
    return gf2_sq(c, a);
}

/* Multiplication by xi in GF(2^2): xi*(h,l) = (h XOR l, h) - free. */
static gf2_wires
gf2_mul_xi(voleith_circuit_t *c, gf2_wires a)
{
    return (gf2_wires){
        voleith_circuit_add_xor(c, a.h, a.l),
        a.h,
    };
}

/* Multiplication by xi+1 in GF(2^2): (xi+1)*(h,l) = (l, h XOR l) - free. */
static gf2_wires
gf2_mul_xi1(voleith_circuit_t *c, gf2_wires a)
{
    return (gf2_wires){
        a.l,
        voleith_circuit_add_xor(c, a.h, a.l),
    };
}

/*
 * GF(2^2) multiplication - 3 AND gates.
 *
 * (a.h*xi + a.l) * (b.h*xi + b.l):
 *   p1 = a.h & b.h,  p2 = a.l & b.l,  p3 = (a.h^a.l) & (b.h^b.l)
 *   result.h = p3 ^ p2
 *   result.l = p1 ^ p2
 */
static gf2_wires
gf2_mul(voleith_circuit_t *c, gf2_wires a, gf2_wires b)
{
    wire_id ah_xl = voleith_circuit_add_xor(c, a.h, a.l);
    wire_id bh_xl = voleith_circuit_add_xor(c, b.h, b.l);
    wire_id p1 = voleith_circuit_add_and(c, a.h, b.h);
    wire_id p2 = voleith_circuit_add_and(c, a.l, b.l);
    wire_id p3 = voleith_circuit_add_and(c, ah_xl, bh_xl);
    return (gf2_wires){
        voleith_circuit_add_xor(c, p3, p2),
        voleith_circuit_add_xor(c, p1, p2),
    };
}

/* ------ GF(2^4) = GF(2^2)[eta]/(eta^2+eta+xi) operations ------ */

/* Addition - component-wise, free. */
static gf4_wires
gf4_add(voleith_circuit_t *c, gf4_wires a, gf4_wires b)
{
    return (gf4_wires){gf2_add(c, a.H, b.H), gf2_add(c, a.L, b.L)};
}

/*
 * Squaring in GF(2^4) - free.
 *
 * (A.H*eta + A.L)^2 = A.H^2 * (eta+xi) + A.L^2
 *   result.H = sq2(A.H)
 *   result.L = xi * sq2(A.H)  XOR  sq2(A.L)
 */
static gf4_wires
gf4_sq(voleith_circuit_t *c, gf4_wires a)
{
    gf2_wires sq_H = gf2_sq(c, a.H);
    gf2_wires sq_L = gf2_sq(c, a.L);
    return (gf4_wires){sq_H, gf2_add(c, gf2_mul_xi(c, sq_H), sq_L)};
}

/*
 * Multiplication by phi = xi*eta in GF(2^4) - free.
 *
 * phi = xi*eta, so (phi.H = xi, phi.L = 0).
 * (A.H*eta + A.L) * xi*eta:
 *   result.H = (A.H XOR A.L) * xi
 *   result.L = A.H * (xi+1)
 */
static gf4_wires
gf4_mul_phi(voleith_circuit_t *c, gf4_wires a)
{
    gf2_wires sum = gf2_add(c, a.H, a.L);
    return (gf4_wires){gf2_mul_xi(c, sum), gf2_mul_xi1(c, a.H)};
}

/*
 * GF(2^4) multiplication - 9 AND gates (Karatsuba via 3 GF(2^2) mults).
 *
 * (A.H*eta + A.L) * (B.H*eta + B.L):
 *   P1 = A.H * B.H,  P2 = A.L * B.L,  P3 = (A.H^A.L) * (B.H^B.L)
 *   result.H = P3 ^ P2
 *   result.L = xi*P1 ^ P2
 */
static gf4_wires
gf4_mul(voleith_circuit_t *c, gf4_wires a, gf4_wires b)
{
    gf2_wires P1 = gf2_mul(c, a.H, b.H);
    gf2_wires P2 = gf2_mul(c, a.L, b.L);
    gf2_wires aHL = gf2_add(c, a.H, a.L);
    gf2_wires bHL = gf2_add(c, b.H, b.L);
    gf2_wires P3 = gf2_mul(c, aHL, bHL);
    return (gf4_wires){
        gf2_add(c, P3, P2),
        gf2_add(c, gf2_mul_xi(c, P1), P2),
    };
}

/*
 * GF(2^4) inversion - 9 AND gates.
 *
 * For b = (B.H, B.L):
 *   N4 = xi * B.H^2  XOR  B.H*B.L  XOR  B.L^2   (in GF(2^2))
 *   N4^{-1} = sq2(N4)                             (free)
 *   result.H = B.H * N4^{-1}                      (3 ANDs)
 *   result.L = (B.L XOR B.H) * N4^{-1}            (3 ANDs)
 */
static gf4_wires
gf4_inv(voleith_circuit_t *c, gf4_wires a)
{
    gf2_wires sq_H = gf2_sq(c, a.H);
    gf2_wires sq_L = gf2_sq(c, a.L);
    gf2_wires prod = gf2_mul(c, a.H, a.L);
    gf2_wires N4 = gf2_add(c, gf2_mul_xi(c, sq_H), gf2_add(c, prod, sq_L));
    gf2_wires N4_inv = gf2_inv(c, N4);
    gf2_wires sumHL = gf2_add(c, a.L, a.H);
    return (gf4_wires){
        gf2_mul(c, a.H, N4_inv),
        gf2_mul(c, sumHL, N4_inv),
    };
}

/*
 * GF(2^8) inversion - 36 AND gates.
 *
 * For a = (a.H, a.L) in GF(2^4) × GF(2^4):
 *   N    = phi * a.H^2  XOR  a.H*a.L  XOR  a.L^2   (in GF(2^4), 9 ANDs)
 *   N^{-1}: GF(2^4) inversion                       (9 ANDs)
 *   result.H = a.H * N^{-1}                          (9 ANDs)
 *   result.L = (a.H XOR a.L) * N^{-1}               (9 ANDs)
 */
static gf8_wires
gf8_inv(voleith_circuit_t *c, gf8_wires a)
{
    gf4_wires sq_H = gf4_sq(c, a.H);
    gf4_wires sq_L = gf4_sq(c, a.L);
    gf4_wires prod = gf4_mul(c, a.H, a.L);
    gf4_wires N = gf4_add(c, gf4_mul_phi(c, sq_H), gf4_add(c, prod, sq_L));
    gf4_wires N_inv = gf4_inv(c, N);
    gf4_wires sumHL = gf4_add(c, a.H, a.L);
    return (gf8_wires){
        gf4_mul(c, a.H, N_inv),
        gf4_mul(c, sumHL, N_inv),
    };
}

/* ================================================================
 * Change-of-basis matrices (computed for xi=0xbc, eta=0x5c,
 * phi=0xb0, theta=0xf2 in AES GF(2^8)).
 *
 * B[i] is the i-th row of the AES→tower matrix.
 * Output bit i = XOR of input bits j where bit j of B[i] is set.
 *
 * B_INV[i] is the i-th row of the tower→AES matrix.
 * ================================================================ */

static const uint8_t B[8] = {0x73, 0x38, 0x42, 0xc8, 0x70, 0x0c, 0xde, 0xa0};
static const uint8_t B_INV[8] = {0xe1, 0xf0, 0xc6, 0xe6,
                                 0x7e, 0x9a, 0xf4, 0x1a};

/*
 * apply_linear8 - apply an 8×8 GF(2) matrix to 8 wire IDs.
 *
 * M[i] is the i-th row (as a byte bitmask over the 8 input wires).
 * out[i] = XOR of in[j] for each j where bit j of M[i] is set.
 * Produces at most 7 XOR gates per output bit.
 */
static void
apply_linear8(voleith_circuit_t *c, const uint8_t M[8], const wire_id in[8],
              wire_id out[8])
{
    for (int i = 0; i < 8; i++) {
        uint8_t row = M[i];
        wire_id acc = WIRE_ID_INVALID;
        for (int j = 0; j < 8; j++) {
            if (!((row >> j) & 1))
                continue;
            if (acc == WIRE_ID_INVALID)
                acc = in[j];
            else
                acc = voleith_circuit_add_xor(c, acc, in[j]);
        }
        /* If row is all-zero, output is the zero constant wire. */
        if (acc == WIRE_ID_INVALID)
            acc = voleith_circuit_add_const(c, 0);
        out[i] = acc;
    }
}

/*
 * aes_affine - AES S-box affine transform (applied after inversion).
 *
 * out[i] = in[i] XOR in[(i+4)%8] XOR in[(i+5)%8] XOR in[(i+6)%8]
 *                XOR in[(i+7)%8] XOR const[i]
 * where const = 0x63 (bits 0,1,5,6 set).
 *
 * This is an affine map over GF(2): entirely XOR + optional NOT, zero ANDs.
 */
static void
aes_affine(voleith_circuit_t *c, const wire_id in[8], wire_id out[8])
{
    static const uint8_t C = 0x63; /* affine constant */
    for (int i = 0; i < 8; i++) {
        wire_id acc = in[i];
        acc = voleith_circuit_add_xor(c, acc, in[(i + 4) % 8]);
        acc = voleith_circuit_add_xor(c, acc, in[(i + 5) % 8]);
        acc = voleith_circuit_add_xor(c, acc, in[(i + 6) % 8]);
        acc = voleith_circuit_add_xor(c, acc, in[(i + 7) % 8]);
        if ((C >> i) & 1)
            acc = voleith_circuit_add_xor(c, acc,
                                          voleith_circuit_add_const(c, 1));
        out[i] = acc;
    }
}

/* ================================================================
 * Public API: AES S-box circuit
 * ================================================================ */

void
aes_sbox_circuit(voleith_circuit_t *c, const wire_id in[8], wire_id out[8])
{
    /* Step 1: Change basis AES poly → tower. */
    wire_id tower_in[8];
    apply_linear8(c, B, in, tower_in);

    /* Step 2: Pack into gf8_wires tower representation.
     * Bit layout after the basis change:
     *   bits 0,1: a_L.L = (t[1], t[0])   (h, l of GF(2^2) constant part of a_L)
     *   bits 2,3: a_L.H = (t[3], t[2])   (h, l of GF(2^2) leading part of a_L)
     *   bits 4,5: a_H.L = (t[5], t[4])
     *   bits 6,7: a_H.H = (t[7], t[6])
     */
    gf8_wires a = {
        .H =
            {
                .H = {tower_in[7], tower_in[6]}, /* a_H.H: h=t[7], l=t[6] */
                .L = {tower_in[5], tower_in[4]}, /* a_H.L: h=t[5], l=t[4] */
            },
        .L =
            {
                .H = {tower_in[3], tower_in[2]}, /* a_L.H: h=t[3], l=t[2] */
                .L = {tower_in[1], tower_in[0]}, /* a_L.L: h=t[1], l=t[0] */
            },
    };

    /* Step 3: Invert in GF(2^8) via tower field - 36 AND gates. */
    gf8_wires inv = gf8_inv(c, a);

    /* Step 4: Unpack inversion result back to flat bit array. */
    wire_id tower_out[8] = {
        inv.L.L.l, inv.L.L.h, inv.L.H.l, inv.L.H.h,
        inv.H.L.l, inv.H.L.h, inv.H.H.l, inv.H.H.h,
    };

    /* Step 5: Change basis tower → AES poly. */
    wire_id aes_inv[8];
    apply_linear8(c, B_INV, tower_out, aes_inv);

    /* Step 6: AES affine transform. */
    aes_affine(c, aes_inv, out);
}

/* ================================================================
 * AES building blocks: xtime, MixColumns, ShiftRows, SubBytes,
 * AddRoundKey, key schedule
 * ================================================================ */

/*
 * xtime - multiply a byte by x in AES GF(2^8) - free (all XOR).
 *
 * xtime(b)[0] = b[7]
 * xtime(b)[1] = b[0] XOR b[7]
 * xtime(b)[2] = b[1]
 * xtime(b)[3] = b[2] XOR b[7]
 * xtime(b)[4] = b[3] XOR b[7]
 * xtime(b)[5] = b[4]
 * xtime(b)[6] = b[5]
 * xtime(b)[7] = b[6]
 */
static void
xtime_byte(voleith_circuit_t *c, const wire_id b[8], wire_id out[8])
{
    out[0] = b[7];
    out[1] = voleith_circuit_add_xor(c, b[0], b[7]);
    out[2] = b[1];
    out[3] = voleith_circuit_add_xor(c, b[2], b[7]);
    out[4] = voleith_circuit_add_xor(c, b[3], b[7]);
    out[5] = b[4];
    out[6] = b[5];
    out[7] = b[6];
}

/*
 * xor_bytes - XOR two 8-wire bytes - free.
 */
static void
xor_bytes(voleith_circuit_t *c, const wire_id a[8], const wire_id b[8],
          wire_id out[8])
{
    for (int i = 0; i < 8; i++)
        out[i] = voleith_circuit_add_xor(c, a[i], b[i]);
}

/* AES state: 16 bytes × 8 bits = 128 wire IDs.
 * State layout: state[b] = bit b%8 of byte b/8, byte k = state[k%4][k/4].
 * The flat array maps directly to plaintext/ciphertext bit arrays. */
typedef wire_id aes_state[128];

/* Pointer into state for byte (row, col), bit b. */
#define STATE_BIT(row, col, b) ((4 * (col) + (row)) * 8 + (b))

/* Access byte (row, col) of state as a pointer to 8 wire IDs. */
static void
state_get_byte(const aes_state s, int row, int col, wire_id out[8])
{
    const wire_id *p = &s[STATE_BIT(row, col, 0)];
    for (int b = 0; b < 8; b++)
        out[b] = p[b];
}

static void
state_set_byte(aes_state s, int row, int col, const wire_id in[8])
{
    wire_id *p = &s[STATE_BIT(row, col, 0)];
    for (int b = 0; b < 8; b++)
        p[b] = in[b];
}

/* SubBytes: apply S-box to each byte of the state - 16 × 36 = 576 AND gates. */
static void
sub_bytes(voleith_circuit_t *c, aes_state s)
{
    for (int row = 0; row < 4; row++) {
        for (int col = 0; col < 4; col++) {
            wire_id in[8], out[8];
            state_get_byte(s, row, col, in);
            aes_sbox_circuit(c, in, out);
            state_set_byte(s, row, col, out);
        }
    }
}

/* ShiftRows: row r is shifted left by r positions - free (permutation). */
static void
shift_rows(aes_state s)
{
    aes_state tmp;
    for (int row = 0; row < 4; row++) {
        for (int col = 0; col < 4; col++) {
            wire_id src[8];
            state_get_byte(s, row, (col + row) % 4, src);
            /* Compute destination after shift into tmp. */
            wire_id *dst = &tmp[STATE_BIT(row, col, 0)];
            for (int b = 0; b < 8; b++)
                dst[b] = src[b];
        }
    }
    memcpy(s, tmp, sizeof(aes_state));
}

/*
 * mix_column - apply AES MixColumns to one column - free (all XOR).
 *
 * [b0]   [2 3 1 1] [a0]
 * [b1] = [1 2 3 1] [a1]
 * [b2]   [1 1 2 3] [a2]
 * [b3]   [3 1 1 2] [a3]
 *
 * 2*a = xtime(a), 3*a = xtime(a) XOR a.
 */
static void
mix_column(voleith_circuit_t *c, const wire_id a0[8], const wire_id a1[8],
           const wire_id a2[8], const wire_id a3[8], wire_id b0[8],
           wire_id b1[8], wire_id b2[8], wire_id b3[8])
{
    wire_id x0[8], x1[8], x2[8], x3[8]; /* xtime of each input */
    xtime_byte(c, a0, x0);
    xtime_byte(c, a1, x1);
    xtime_byte(c, a2, x2);
    xtime_byte(c, a3, x3);

    /* t[k] = xtime(a[k]) XOR a[k] = 3*a[k] */
    wire_id t0[8], t1[8], t2[8], t3[8];
    xor_bytes(c, x0, a0, t0);
    xor_bytes(c, x1, a1, t1);
    xor_bytes(c, x2, a2, t2);
    xor_bytes(c, x3, a3, t3);

    /* b0 = 2*a0 XOR 3*a1 XOR a2 XOR a3 */
    wire_id tmp[8];
    xor_bytes(c, x0, t1, tmp);
    xor_bytes(c, tmp, a2, tmp);
    xor_bytes(c, tmp, a3, b0);

    /* b1 = a0 XOR 2*a1 XOR 3*a2 XOR a3 */
    xor_bytes(c, a0, x1, tmp);
    xor_bytes(c, tmp, t2, tmp);
    xor_bytes(c, tmp, a3, b1);

    /* b2 = a0 XOR a1 XOR 2*a2 XOR 3*a3 */
    xor_bytes(c, a0, a1, tmp);
    xor_bytes(c, tmp, x2, tmp);
    xor_bytes(c, tmp, t3, b2);

    /* b3 = 3*a0 XOR a1 XOR a2 XOR 2*a3 */
    xor_bytes(c, t0, a1, tmp);
    xor_bytes(c, tmp, a2, tmp);
    xor_bytes(c, tmp, x3, b3);
}

/* MixColumns: apply mix_column to each of the 4 columns - free. */
static void
mix_columns(voleith_circuit_t *c, aes_state s)
{
    for (int col = 0; col < 4; col++) {
        wire_id a0[8], a1[8], a2[8], a3[8];
        wire_id b0[8], b1[8], b2[8], b3[8];
        state_get_byte(s, 0, col, a0);
        state_get_byte(s, 1, col, a1);
        state_get_byte(s, 2, col, a2);
        state_get_byte(s, 3, col, a3);
        mix_column(c, a0, a1, a2, a3, b0, b1, b2, b3);
        state_set_byte(s, 0, col, b0);
        state_set_byte(s, 1, col, b1);
        state_set_byte(s, 2, col, b2);
        state_set_byte(s, 3, col, b3);
    }
}

/* AddRoundKey: XOR state with a 128-bit round key - free. */
static void
add_round_key(voleith_circuit_t *c, aes_state s, const wire_id rk[128])
{
    for (int i = 0; i < 128; i++)
        s[i] = voleith_circuit_add_xor(c, s[i], rk[i]);
}

/*
 * sub_word - apply S-box to each of 4 bytes in a 32-bit word.
 * in[0..31]: 4 bytes × 8 bits (byte 0 = bits 0..7).
 * out[0..31]: S-box applied to each byte.
 */
static void
sub_word(voleith_circuit_t *c, const wire_id in[32], wire_id out[32])
{
    for (int byte = 0; byte < 4; byte++) {
        wire_id bin[8], bout[8];
        for (int b = 0; b < 8; b++)
            bin[b] = in[byte * 8 + b];
        aes_sbox_circuit(c, bin, bout);
        for (int b = 0; b < 8; b++)
            out[byte * 8 + b] = bout[b];
    }
}

/*
 * rot_word - rotate a 32-bit word left by 8 bits (one byte) - free.
 * Byte 0 → byte 1, byte 1 → byte 2, byte 2 → byte 3, byte 3 → byte 0.
 */
static void
rot_word(const wire_id in[32], wire_id out[32])
{
    /* out byte 0 = in byte 1, ..., out byte 3 = in byte 0 */
    for (int b = 0; b < 8; b++) {
        out[0 * 8 + b] = in[1 * 8 + b];
        out[1 * 8 + b] = in[2 * 8 + b];
        out[2 * 8 + b] = in[3 * 8 + b];
        out[3 * 8 + b] = in[0 * 8 + b];
    }
}

/*
 * xor_word - XOR two 32-bit words - free.
 */
static void
xor_word(voleith_circuit_t *c, const wire_id a[32], const wire_id b[32],
         wire_id out[32])
{
    for (int i = 0; i < 32; i++)
        out[i] = voleith_circuit_add_xor(c, a[i], b[i]);
}

/* ================================================================
 * AES-128 round constant words (FIPS 197 Table 5).
 * Only byte 0 (bits 0..7) is nonzero; bytes 1..3 are zero.
 * Rcon[0] corresponds to round 1.
 * ================================================================ */
static const uint8_t RCON128[10] = {0x01, 0x02, 0x04, 0x08, 0x10,
                                    0x20, 0x40, 0x80, 0x1b, 0x36};

/*
 * aes128_key_schedule - expand a 128-bit key to 11 round keys.
 *
 * key[0..127]: wire IDs for key bytes 0..15 (bit b of byte k = key[8*k+b]).
 * rk[round][0..127]: wire IDs for round key `round` (round 0 = original key).
 *
 * Each of 10 key-expansion steps calls SubWord (4 S-box calls = 144 ANDs total).
 */
static void
aes128_key_schedule(voleith_circuit_t *c, const wire_id key[128],
                    wire_id rk[11][128])
{
    /* Round 0: copy key verbatim. */
    for (int i = 0; i < 128; i++)
        rk[0][i] = key[i];

    /* Words of current round key as 4×32-bit arrays. */
    wire_id w[4][32];
    for (int word = 0; word < 4; word++)
        for (int b = 0; b < 32; b++)
            w[word][b] = key[word * 32 + b];

    for (int round = 1; round <= 10; round++) {
        /* temp = RotWord(w[3]) */
        wire_id temp[32];
        rot_word(w[3], temp);

        /* temp = SubWord(temp) */
        wire_id temp2[32];
        sub_word(c, temp, temp2);

        /* temp = temp XOR Rcon[round-1] (XOR first word's byte 0 only) */
        uint8_t rcon = RCON128[round - 1];
        for (int b = 0; b < 8; b++) {
            if ((rcon >> b) & 1)
                temp2[b] = voleith_circuit_add_xor(
                    c, temp2[b], voleith_circuit_add_const(c, 1));
        }

        /* w[0] = w[0] XOR temp */
        wire_id new_w[4][32];
        xor_word(c, w[0], temp2, new_w[0]);

        /* w[1] = w[1] XOR new_w[0], etc. */
        xor_word(c, w[1], new_w[0], new_w[1]);
        xor_word(c, w[2], new_w[1], new_w[2]);
        xor_word(c, w[3], new_w[2], new_w[3]);

        /* Pack new round key. */
        for (int word = 0; word < 4; word++) {
            for (int b = 0; b < 32; b++)
                rk[round][word * 32 + b] = new_w[word][b];
            for (int b = 0; b < 32; b++)
                w[word][b] = new_w[word][b];
        }
    }
}

/* ================================================================
 * Public API: AES-128 circuit
 * ================================================================ */

void
aes128_circuit(voleith_circuit_t *c, const wire_id key[128],
               const wire_id plaintext[128], wire_id output[128])
{
    /* Expand key schedule: 11 round keys. */
    wire_id rk[11][128];
    aes128_key_schedule(c, key, rk);

    /* Initialize state from plaintext. */
    aes_state state;
    for (int i = 0; i < 128; i++)
        state[i] = plaintext[i];

    /* Round 0: AddRoundKey. */
    add_round_key(c, state, rk[0]);

    /* Rounds 1-9: SubBytes + ShiftRows + MixColumns + AddRoundKey. */
    for (int round = 1; round <= 9; round++) {
        sub_bytes(c, state);
        shift_rows(state);
        mix_columns(c, state);
        add_round_key(c, state, rk[round]);
    }

    /* Round 10: SubBytes + ShiftRows + AddRoundKey (no MixColumns). */
    sub_bytes(c, state);
    shift_rows(state);
    add_round_key(c, state, rk[10]);

    /* Copy state to output. */
    for (int i = 0; i < 128; i++)
        output[i] = state[i];
}

/* ================================================================
 * AES-256 round constants (14 rounds, 7 SubWord calls per expansion).
 * Rcon[k] is used when i/8 - 1 == k (i.e., i = 8*(k+1)).
 * ================================================================ */
static const uint8_t RCON256[7] = {0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40};

/*
 * aes256_key_schedule - expand a 256-bit key to 15 round keys.
 *
 * key[0..255]: wire IDs for key bytes 0..31.
 * rk[round][0..127]: round key for round `round`.
 *
 * AES-256 key schedule generates 60 32-bit words (w[0..59]).
 * w[i] for i >= 8:
 *   if i % 8 == 0: w[i] = w[i-8] XOR SubWord(RotWord(w[i-1])) XOR Rcon[i/8-1]
 *   if i % 8 == 4: w[i] = w[i-8] XOR SubWord(w[i-1])
 *   else:          w[i] = w[i-8] XOR w[i-1]
 * Round key n = w[4n..4n+3].
 */
static void
aes256_key_schedule(voleith_circuit_t *c, const wire_id key[256],
                    wire_id rk[15][128])
{
    /* Store all 60 key-schedule words: w[word][bit 0..31]. */
    wire_id w[60][32];

    /* w[0..7] come directly from the key. */
    for (int word = 0; word < 8; word++)
        for (int b = 0; b < 32; b++)
            w[word][b] = key[word * 32 + b];

    /* Generate w[8..59]. */
    for (int i = 8; i < 60; i++) {
        wire_id temp[32];
        for (int b = 0; b < 32; b++)
            temp[b] = w[i - 1][b];

        if (i % 8 == 0) {
            wire_id rot[32];
            rot_word(temp, rot);
            wire_id sw[32];
            sub_word(c, rot, sw);
            /* XOR Rcon into byte 0 (bits 0..7) of sw. */
            uint8_t rcon = RCON256[i / 8 - 1];
            for (int b = 0; b < 8; b++) {
                if ((rcon >> b) & 1)
                    sw[b] = voleith_circuit_add_xor(
                        c, sw[b], voleith_circuit_add_const(c, 1));
            }
            for (int b = 0; b < 32; b++)
                temp[b] = sw[b];
        } else if (i % 8 == 4) {
            wire_id sw[32];
            sub_word(c, temp, sw);
            for (int b = 0; b < 32; b++)
                temp[b] = sw[b];
        }

        xor_word(c, w[i - 8], temp, w[i]);
    }

    /* Extract 15 round keys from the 60 words. */
    for (int n = 0; n < 15; n++)
        for (int word = 0; word < 4; word++)
            for (int b = 0; b < 32; b++)
                rk[n][word * 32 + b] = w[n * 4 + word][b];
}

void
aes256_circuit(voleith_circuit_t *c, const wire_id key[256],
               const wire_id plaintext[128], wire_id output[128])
{
    wire_id rk[15][128];
    aes256_key_schedule(c, key, rk);

    aes_state state;
    for (int i = 0; i < 128; i++)
        state[i] = plaintext[i];

    add_round_key(c, state, rk[0]);

    for (int round = 1; round <= 13; round++) {
        sub_bytes(c, state);
        shift_rows(state);
        mix_columns(c, state);
        add_round_key(c, state, rk[round]);
    }

    /* Round 14: no MixColumns. */
    sub_bytes(c, state);
    shift_rows(state);
    add_round_key(c, state, rk[14]);

    for (int i = 0; i < 128; i++)
        output[i] = state[i];
}
