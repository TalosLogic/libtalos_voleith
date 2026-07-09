# gen_rlnc_kat - RLNC encode KAT emitter

`gen_rlnc_kat` generates byte-exact RLNC **encode** known-answer vectors
(`tests/rlnc_kat.inc`) for `tests/test_erasure_rlnc.c`, using **GF-Complete**
(through Jerasure's galois layer) as an independent oracle for the GF(2^16)
arithmetic.

It is run by hand, once, when the vectors need to be (re)generated. The
oracle libraries are **never linked into libtalos_voleith or its test
suite**: this tool only emits a checked-in C include. Same posture as
`gen_rs_kat` and the faest-ref oracle.

## What it does and does not cover

The oracle-able surface of RLNC is GF(2^16) linear algebra. A coded symbol's
payload is `Y[i] = sum_j C[i][j] * X[j]` for source symbols `X` and a
coefficient matrix `C`. This tool fixes deterministic sources and
coefficients and computes the payloads; `voleith_rlnc_encode` must reproduce
them byte-for-byte.

It does **not** cover the RLNC wire/header format, recoding, or rank-tracking
decode. Those are our own design, shared by no external library, and are
validated by the self-consistency tests in `test_erasure_rlnc.c` (encode then
decode round-trips, rank progress, recode-then-decode equals direct decode,
generation-id handling).

## Matching our field

Two things must line up or the vectors silently will not match:

1. **Field polynomial.** GF(2^16) with primitive polynomial `0x1100B`, which
   is our `m16` and also GF-Complete's default w=16 polynomial. The emitter
   forces it via `galois_init_field(... 0x1100B ...)` +
   `galois_change_technique`.

2. **Multiply method.** Use `GF_MULT_SHIFT`, not `GF_MULT_DEFAULT`, for the
   same reason as `gen_rs_kat`: the shift multiplier is plain shift-and-reduce
   and avoids the table-init path. Parity is computed with scalar
   `galois_single_multiply(..., 16)`.

## Building the oracle libraries

Identical to `gen_rs_kat`: build GF-Complete, then Jerasure (static) against
it. See `tools/gen_rs_kat/README.md` for the exact commands. The same two
static archives are reused here:

- `third_party/gf-complete/src/.libs/libgf_complete.a`
- `third_party/Jerasure/src/.libs/libJerasure.a`

(Only the galois layer from Jerasure is used, but linking the whole archive is
simplest.)

## Building and running the emitter

```sh
cd tools/gen_rlnc_kat
gcc -O2 \
    -I../../third_party/Jerasure/include \
    -I../../third_party/gf-complete/include \
    gen_rlnc_kat.c \
    ../../third_party/Jerasure/src/.libs/libJerasure.a \
    ../../third_party/gf-complete/src/.libs/libgf_complete.a \
    -o gen_rlnc_kat
./gen_rlnc_kat > ../../tests/rlnc_kat.inc
```

If you only have shared objects, link by name with an rpath as shown in the
`gen_rs_kat` README.

## Output format

`rlnc_kat.inc` is a C array consumed by `tests/test_erasure_rlnc.c`, which
defines the matching `struct rlnc_kat`:

```c
struct rlnc_kat {
    int k, symbol_bytes, num_coded;
    uint8_t sources[64];   /* k * symbol_bytes bytes used (LE GF(2^16)) */
    uint16_t coeffs[64];   /* num_coded * k coefficients used */
    uint8_t coded[128];    /* num_coded * symbol_bytes bytes used (LE) */
};
```

Sources and coded payloads are little-endian GF(2^16) byte pairs; coefficients
are emitted as `uint16_t` values.

## Adding or changing KAT cases

Edit the `cases[]` array in `gen_rlnc_kat.c`:

```c
static const struct kat_case cases[] = {
    {3, 8, 4},   /* {k, symbol_bytes, num_coded} */
    {4, 4, 5},
    {2, 6, 3},
};
```

`symbol_bytes` must be even. Add rows, rebuild, and rerun the emitter,
redirecting to `tests/rlnc_kat.inc`. If a new case exceeds the
`sources[64]` / `coeffs[64]` / `coded[128]` fixed buffers in `struct
rlnc_kat`, bump those sizes in `tests/test_erasure_rlnc.c` to match. Sources
and coefficients are deterministic functions of position, so regenerating with
the same `cases[]` reproduces identical vectors.
