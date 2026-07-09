# Copyright (c) 2026 Jason Crawford
# SPDX-License-Identifier: AGPL-3.0-only
#
# crosscheck.sage - independent oracle for the alpha16 subfield-embedding
# tables (T5.1).  Reproduces tools/gen_alpha16's output via SageMath and
# prints it in the same paste-ready core/field.c format, so a plain `diff`
# against the C generator's stdout confirms agreement.
#
# SageMath is GPL and is used only as a generation-time cross-check (the
# faest-ref posture): it is NEVER a build dependency of the library.
#
# Run:  sage crosscheck.sage > sage_tables.txt
#       ./gen_alpha16 > c_tables.txt 2>/dev/null
#       diff <(grep UINT64_C sage_tables.txt) <(grep UINT64_C c_tables.txt)
#
# CRITICAL matching conditions (must equal core/field.c exactly, else the
# limb encodings will not match even when the maths is right):
#   * GF(2^lambda) is built with the SAME reduction polynomial the library
#     uses: P_128 = P_192 = 0x87 (x^7+x^2+x+1), P_256 = 0x425
#     (x^10+x^5+x^2+1), with the x^lambda term implicit.
#   * The element encoding is the polynomial-basis integer (bit i = the
#     coefficient of x^i), which is Sage's integer_representation() and the
#     library's little-endian to_bytes().
#   * The root is selected by the same deterministic rule: smallest such
#     encoding integer among the 16 roots of m16.

R.<x> = GF(2)[]

def lib_modulus(lam):
    if lam in (128, 192):
        return x^lam + x^7 + x^2 + x + 1
    if lam == 256:
        return x^256 + x^10 + x^5 + x^2 + 1
    raise ValueError(lam)

def limbs(n, lam):
    out = []
    for _ in range(lam // 64):
        out.append(n & ((1 << 64) - 1))
        n >>= 64
    return out

def emit(lam, beta):
    L = lam // 64
    print("static const voleith_gf%d_t gf%d_alpha16[15] = {" % (lam, lam))
    p = beta
    for _ in range(1, 16):
        ls = limbs(p.integer_representation(), lam)
        inner = ", ".join("UINT64_C(0x%016x)" % v for v in ls)
        print("    {{%s}}," % inner)
        p = p * beta
    print("};")
    print("")

for lam in (128, 192, 256):
    Flam = GF(2^lam, name='z', modulus=lib_modulus(lam))
    S.<y> = Flam[]
    m16 = y^16 + y^12 + y^3 + y + 1
    roots = [r for (r, _mult) in m16.roots()]
    assert len(roots) == 16, "lambda %d: found %d roots" % (lam, len(roots))
    beta = min(roots, key=lambda e: e.integer_representation())
    emit(lam, beta)
