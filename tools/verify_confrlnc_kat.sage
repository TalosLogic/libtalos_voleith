#!/usr/bin/env sage
# Copyright (c) 2026 Jason Crawford
# SPDX-License-Identifier: AGPL-3.0-only
#
# verify_confrlnc_kat.sage - Independent (SageMath) confirmation of the
# confidential-RLNC paper-2 Figure 1 coding stage, in particular that cell
# C[2][0] = 0x3F (not the paper's printed 0x5F).
#
# This is a THIRD-PARTY check of the hand computation behind the KAT correction
# in tests/confrlnc_kat.inc.  It uses Sage's own GF(2^8) matrix arithmetic, with
# no code shared with the C library.  GPL/Sage stays an external oracle (run
# once to confirm); it is never linked into the library, same posture as
# faest-ref.
#
# Run:   sage verify_confrlnc_kat.sage
#
# It computes C = L . P over GF(2^8) under TWO reduction polynomials:
#   - 0x11D = x^8 + x^4 + x^3 + x^2 + 1   (the paper's field, determined
#                                          empirically)
#   - 0x11B = x^8 + x^4 + x^3 + x   + 1   (Rijndael, for contrast)
# and reports C[2][0] under each, plus whether the full matrix matches the
# CORRECTED KAT (C[2][0] = 0x3F) or the AS-PRINTED figure (C[2][0] = 0x5F).

# ---- inputs (Figure 1), bytes as integers -------------------------------
L = [
    [0x9a, 0x4c, 0x16, 0xed],
    [0xb6, 0x52, 0x43, 0xbb],
    [0x39, 0x6d, 0xcd, 0x7d],
    [0x1e, 0x82, 0x08, 0x94],
]
P = [
    [0x3d, 0x85, 0xae, 0x0a, 0x1a, 0x23],
    [0x76, 0x3c, 0x65, 0xe2, 0x43, 0xb8],
    [0xf6, 0x7d, 0x5e, 0xe9, 0x56, 0x1c],
    [0x8c, 0xa0, 0xfc, 0xcc, 0xae, 0xa7],
]

# C as the paper PRINTS it (the disputed cell is [2][0] = 0x5F).
C_printed = [
    [0xe7, 0x07, 0x29, 0xc3, 0x12, 0x1c],
    [0x86, 0xf1, 0x90, 0x72, 0x3b, 0xd7],
    [0x5f, 0x23, 0x71, 0xe2, 0xbb, 0x2c],
    [0x79, 0xb7, 0x4b, 0xdb, 0x1a, 0x77],
]

# C as CORRECTED in the KAT ([2][0] = 0x3F = the true L.P).
C_corrected = [row[:] for row in C_printed]
C_corrected[2][0] = 0x3f

R.<x> = PolynomialRing(GF(2), 'x')

# Field reduction polynomials, named by their byte encoding.
FIELDS = {
    0x11D: x^8 + x^4 + x^3 + x^2 + 1,
    0x11B: x^8 + x^4 + x^3 + x + 1,
}


def to_int(e):
    """Integer encoding of a GF(2^8) element (LSB = constant term)."""
    return sum((int(c) << i) for i, c in enumerate(e.polynomial().list()))


def to_elem(K, n):
    """GF(2^8) element from an integer byte (LSB = constant term)."""
    return K(R([(n >> i) & 1 for i in range(8)]))


def compute_C(modulus):
    K = GF(2**8, name='a', modulus=modulus)
    Lm = Matrix(K, [[to_elem(K, v) for v in row] for row in L])
    Pm = Matrix(K, [[to_elem(K, v) for v in row] for row in P])
    Cm = Lm * Pm
    return [[to_int(Cm[i, j]) for j in range(Cm.ncols())]
            for i in range(Cm.nrows())]


def fmt(M):
    return "\n".join("  " + " ".join("%02x" % v for v in row) for row in M)


print("=== Confidential-RLNC Figure 1: C = L . P (SageMath) ===\n")

for code, modulus in FIELDS.items():
    C = compute_C(modulus)
    matches_corrected = (C == C_corrected)
    matches_printed = (C == C_printed)
    print("poly 0x%X  (%s):" % (code, modulus))
    print(fmt(C))
    print("  C[2][0]            = 0x%02x" % C[2][0])
    print("  == corrected KAT   : %s" % matches_corrected)
    print("  == printed figure  : %s" % matches_printed)
    print("")

C_11d = compute_C(FIELDS[0x11D])
print("--- conclusion ---")
print("Under the paper field 0x11D, C[2][0] = 0x%02x." % C_11d[2][0])
assert C_11d[2][0] == 0x3f, "expected 0x3F under 0x11D"
assert C_11d[2][0] != 0x5f, "0x5F would contradict the typo finding"
assert C_11d == C_corrected, "0x11D must reproduce the corrected KAT exactly"
print("CONFIRMED: the true L.P is 0x3F; the figure's printed 0x5F is a typo.")
print("CONFIRMED: 0x11D reproduces the entire corrected C exactly.")
