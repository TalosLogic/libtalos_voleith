#!/usr/bin/env python3
# Copyright (c) 2026 Jason Crawford
# SPDX-License-Identifier: AGPL-3.0-only
#
# gen_vole_hash_kats.py - Independent, clean-room VOLEHash known-answer
# vector generator.
#
# Derived solely from the FAEST v2.0 specification, Figure 4.4 (Section
# 4.3.3, "VOLE Universal Hash"), NOT from faest-ref. Its purpose is to
# provide a second, independent oracle for proof/vole_hash.c so that the
# library's VOLEHash tests no longer trace their authority exclusively to
# faest-ref.
#
# Field conventions are pinned from core/field.h:
#   - Little-endian bit ordering: bit 0 of byte 0 is the coefficient of
#     alpha^0 (the constant term).  An element is therefore the integer
#     int.from_bytes(buf, 'little').
#   - Irreducible polynomials (low part, x^k term implicit):
#       P_64  = x^64  + x^4 + x^3 + x + 1     -> 0x1b
#       P_128 = x^128 + x^7 + x^2 + x + 1     -> 0x87
#       P_192 = x^192 + x^7 + x^2 + x + 1     -> 0x87
#       P_256 = x^256 + x^10 + x^5 + x^2 + 1  -> 0x425
#
# VOLEHash, from Figure 4.4 (x0 in {0,1}^{ell+2*lambda}, x1 in {0,1}^{lambda+B}):
#   parse sd = (r0 || r1 || r2 || r3 || s || t),  r_i,s in F(2^lambda), t in F(2^64)
#   l'  = lambda * ceil((ell + 2*lambda)/lambda)         # pad x0 to a multiple of lambda
#   h0  = sum_{i=0}^{l'/lambda - 1}  s^{l'/lambda-1-i} * x0_chunk[i]   in F(2^lambda)
#   h1  = sum_{i=0}^{l'/64 - 1}      t^{l'/64-1-i}     * x0_word[i]    in F(2^64)
#   h1' = h1 zero-extended to lambda bits
#   h2  = r0*h0 + r1*h1' ;  h3 = r2*h0 + r3*h1'
#   h   = (ToBits(h2) || ToBits(h3)[0..B)) XOR x1
#
# The Horner orderings (last chunk first for h0; high 64-bit word of the
# last chunk first, then remaining chunks backward, for h1) follow directly
# from the descending exponents s^{...-i} / t^{...-i} in the summations.

import argparse

# Blinding-byte output width, = VOLEITH_VOLE_HASH_B in vole_hash.h.
B = 2

# Full irreducible polynomials, including the x^k term.
POLY = {
    64: (1 << 64) | 0x1B,
    128: (1 << 128) | 0x87,
    192: (1 << 192) | 0x87,
    256: (1 << 256) | 0x425,
}


def gf_mul(a, b, k):
    """Multiply a*b in GF(2^k) with the irreducible polynomial POLY[k]."""
    mod = POLY[k]
    r = 0
    while b:
        if b & 1:
            r ^= a
        b >>= 1
        a <<= 1
        if (a >> k) & 1:
            a ^= mod
    return r


def gf_pow_into_horner(coeffs, key, k):
    """Horner evaluation sum_i key^{n-1-i} * coeffs[i] in GF(2^k).

    Equivalent to: acc = coeffs[0]; for c in coeffs[1:]: acc = acc*key + c.
    """
    acc = 0
    for c in coeffs:
        acc = gf_mul(acc, key, k) ^ c
    return acc


def vole_hash(sd, x, ell, lam):
    nb = lam // 8

    r0 = int.from_bytes(sd[0 * nb:1 * nb], "little")
    r1 = int.from_bytes(sd[1 * nb:2 * nb], "little")
    r2 = int.from_bytes(sd[2 * nb:3 * nb], "little")
    r3 = int.from_bytes(sd[3 * nb:4 * nb], "little")
    s = int.from_bytes(sd[4 * nb:5 * nb], "little")
    t = int.from_bytes(sd[5 * nb:5 * nb + 8], "little")

    # x splits into x0 (ell+2*lambda bits) and x1 (lambda+B bytes).
    x1_off = (ell + 2 * lam) // 8
    x1 = x[x1_off:x1_off + nb + B]

    # Number of lambda-bit chunks covering the (ell+2*lambda)-bit x0 region.
    n_chunks = (ell + 2 * lam + lam - 1) // lam
    # Meaningful bytes in the final (possibly partial) chunk.
    partial_bits = (ell + 2 * lam) % lam
    last_bytes = nb if partial_bits == 0 else partial_bits // 8

    last = bytearray(nb)
    last[:last_bytes] = x[(n_chunks - 1) * nb:(n_chunks - 1) * nb + last_bytes]

    # h0: Horner in GF(2^lambda), most-significant chunk first.
    # chunks in index order 0..n_chunks-1; the descending exponent means
    # we feed them in order chunk[0], chunk[1], ..., chunk[n_chunks-1].
    chunks = []
    for i in range(n_chunks - 1):
        chunks.append(int.from_bytes(x[i * nb:i * nb + nb], "little"))
    chunks.append(int.from_bytes(last, "little"))
    h0 = gf_pow_into_horner(chunks, s, lam)

    # h1: Horner in GF(2^64) over the 64-bit words of the same padded x0
    # region, with the most-significant word receiving exponent t^0 (and so
    # fed last in a descending-exponent Horner -- the same orientation as h0,
    # where the most-significant chunk receives s^0).  Build the word list in
    # ascending significance: chunk 0 low word first, padded last chunk high
    # word last.
    words = []
    # Chunks 0 .. n_chunks-2 (full chunks from x), each low word -> high word.
    for ci in range(n_chunks - 1):
        base = ci * nb
        for off in range(0, nb, 8):
            words.append(int.from_bytes(x[base + off:base + off + 8], "little"))
    # Padded last chunk, low word -> high word.
    for off in range(0, nb, 8):
        words.append(int.from_bytes(last[off:off + 8], "little"))
    h1 = gf_pow_into_horner(words, t, 64)

    # h1 zero-extended to lambda bits is just the same integer (< 2^64).
    h2 = gf_mul(r0, h0, lam) ^ gf_mul(r1, h1, lam)
    h3 = gf_mul(r2, h0, lam) ^ gf_mul(r3, h1, lam)

    h2b = h2.to_bytes(nb, "little")
    h3b = h3.to_bytes(nb, "little")

    out = bytearray(nb + B)
    for j in range(nb):
        out[j] = h2b[j] ^ x1[j]
    for j in range(B):
        out[nb + j] = h3b[j] ^ x1[nb + j]
    return bytes(out)


def patterned(start, length):
    """Byte string b[i] = (start + i) & 0xff -- matches the test fixtures."""
    return bytes((start + i) & 0xFF for i in range(length))


def make_inputs(lam, ell):
    """Reproduce the test_proof.c fixture shapes: sd = 0x00.., x = 0xaa.."""
    nb = lam // 8
    sd_len = 5 * nb + 8
    x_len = ((ell + 2 * lam) // 8) + nb + B
    return patterned(0x00, sd_len), patterned(0xAA, x_len)


def c_array(name, data, width):
    lines = [f"        static const uint8_t {name}[] = {{"]
    for i in range(0, len(data), width):
        row = ", ".join(f"0x{b:02x}" for b in data[i:i + width])
        lines.append(f"            {row},")
    lines.append("        };")
    return "\n".join(lines)


def main():
    ap = argparse.ArgumentParser(
        description="Independent VOLEHash KAT generator (FAEST v2.0 Fig 4.4).")
    ap.add_argument("--ell", type=int, default=200,
                    help="VOLE length ell (default 200, matches fixtures). "
                         "Ignored when --ell-list is given.")
    ap.add_argument("--ell-list", default=None,
                    help="Comma-separated ell values to emit per lambda, e.g. "
                         "'8,lambda,1000'.  The token 'lambda' expands to the "
                         "current security level (the exact-multiple boundary). "
                         "Overrides --ell.")
    ap.add_argument("--emit", choices=["digest", "c"], default="digest",
                    help="digest: print hex outputs; c: emit C test arrays.")
    ap.add_argument("--lambdas", default="128,256",
                    help="Comma-separated security levels (default '128,256'; "
                         "the library's currently supported set). 192 is also "
                         "valid math and cross-validates, but is not a current "
                         "support target.")
    args = ap.parse_args()

    def ells_for(lam):
        if args.ell_list is None:
            return [args.ell]
        out = []
        for tok in args.ell_list.split(","):
            tok = tok.strip()
            out.append(lam if tok == "lambda" else int(tok))
        return out

    for lam in (int(v) for v in args.lambdas.split(",")):
        for ell in ells_for(lam):
            sd, x = make_inputs(lam, ell)
            h = vole_hash(sd, x, ell, lam)
            if args.emit == "digest":
                print(f"lambda={lam} ell={ell}: {h.hex()}")
            else:
                print(f"    /* lambda={lam}, ell={ell} */")
                print("    {")
                print(c_array("sd", sd, 11))
                print(c_array("x", x, 11))
                print(c_array("expected_h", h, 9))
                print("    }")


if __name__ == "__main__":
    main()
