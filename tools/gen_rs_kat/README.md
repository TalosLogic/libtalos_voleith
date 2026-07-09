# gen_rs_kat - Reed-Solomon KAT emitter

`gen_rs_kat` generates byte-exact Reed-Solomon known-answer vectors
(`tests/rs_kat.inc`) for `tests/test_erasure_rs.c`, using **Jerasure 2.0 +
GF-Complete** as an independent oracle.

It is run by hand, once, when the vectors need to be (re)generated. The
oracle libraries are **never linked into libtalos_voleith or its test
suite**: this tool only emits a checked-in C include. That is the same
posture as the faest-ref test oracle. The library remains clean-room.

## Why Jerasure (and not, say, libcorrect)

Our RS code is the **matrix family**: a systematic generator matrix `G` with
codeword `C = G . M`, Cauchy-constructed. Jerasure is the same family, so its
output can be made to match ours byte-for-byte.

libcorrect and similar comms RS libraries are the **BCH / generator-
polynomial family** (consecutive roots, syndrome / Berlekamp-Massey decode).
That is a different code; its parity bytes are unrelated to ours, so it cannot
serve as an oracle here.

## Matching our construction exactly

Three things must line up or the vectors silently will not match
`voleith_rs_encode`:

1. **Field polynomial.** We use the AES/FAEST primitive polynomial `0x11B`
   (`core/field.c`). GF-Complete defaults to `0x11d`. The emitter forces
   `0x11B` via `galois_init_field(... 0x11B ...)` + `galois_change_technique`.

2. **Multiply method.** The emitter must use `GF_MULT_SHIFT`, not
   `GF_MULT_DEFAULT`. The default w=8 method builds a log/antilog table that
   assumes a primitive polynomial; `0x11B` is irreducible but not the
   generator GF-Complete's table init expects, so `gf_w8_table_init` overruns
   its scratch and crashes (SIGSEGV in memset). `GF_MULT_SHIFT` is plain
   shift-and-reduce, valid for any irreducible polynomial, and matches how
   `core/field.c` multiplies.

3. **Cauchy points.** The emitter calls
   `cauchy_xy_coding_matrix(k, m, 8, X, Y)` with `X[i] = k + i` (parity points)
   and `Y[j] = j` (data points), identical to
   `voleith_ec_matrix_generator`'s CAUCHY case (`coding[i][j] = 1/(X[i]^Y[j])`).

Parity is computed with scalar `galois_single_multiply`, not
`jerasure_matrix_encode`: the SIMD region-multiply path requires 16-byte
aligned regions and crashes on small / odd chunk sizes. Scalar is plenty for
a run-once tool.

## Building the oracle libraries

Both live in `third_party/`. GF-Complete first (Jerasure links it):

```sh
cd third_party/gf-complete
./autogen.sh && ./configure && make
```

Then Jerasure, pointed at the GF-Complete build, built **static** so the
emitter links cleanly:

```sh
cd ../Jerasure
autoreconf --force --install
./configure --enable-static \
            CFLAGS="-I$(pwd)/../gf-complete/include" \
            LDFLAGS="-L$(pwd)/../gf-complete/src/.libs"
make
```

This produces:

- `third_party/gf-complete/src/.libs/libgf_complete.a`
- `third_party/Jerasure/src/.libs/libJerasure.a`

(If your archives land elsewhere, find them with
`find third_party -name 'libJerasure*' -o -name 'libgf_complete*'`.)

## Building and running the emitter

```sh
cd tools/gen_rs_kat
gcc -O2 \
    -I../../third_party/Jerasure/include \
    -I../../third_party/gf-complete/include \
    gen_rs_kat.c \
    ../../third_party/Jerasure/src/.libs/libJerasure.a \
    ../../third_party/gf-complete/src/.libs/libgf_complete.a \
    -o gen_rs_kat
./gen_rs_kat > ../../tests/rs_kat.inc
```

If you only have the shared objects, link by name and set an rpath instead:

```sh
JER="$(cd ../../third_party/Jerasure/src/.libs && pwd)"
GFC="$(cd ../../third_party/gf-complete/src/.libs && pwd)"
gcc -O2 \
    -I../../third_party/Jerasure/include \
    -I../../third_party/gf-complete/include \
    gen_rs_kat.c \
    -L"$JER" -lJerasure -L"$GFC" -lgf_complete \
    -Wl,-rpath,"$JER" -Wl,-rpath,"$GFC" \
    -o gen_rs_kat
./gen_rs_kat > ../../tests/rs_kat.inc
```

## Output format

`rs_kat.inc` is a C array consumed by `tests/test_erasure_rs.c`, which defines
the matching `struct rs_kat`:

```c
struct rs_kat {
    int n, k, chunk_bytes;
    uint8_t message[256];    /* k * chunk_bytes bytes used */
    uint8_t codeword[512];   /* n * chunk_bytes bytes used */
};
```

Because the code is systematic, the first `k * chunk_bytes` bytes of each
`codeword` equal its `message` (data passthrough); the rest is parity.

## Adding or changing KAT cases

Edit the `cases[]` array in `gen_rs_kat.c`:

```c
static const struct kat_case cases[] = {
    {6, 3, 4},   /* {n, k, chunk_bytes} */
    {5, 2, 3},
    {7, 4, 8},
};
```

Add rows, rebuild, and rerun the emitter, redirecting to `tests/rs_kat.inc`.
Keep `n <= 256` (GF(2^8) point budget) and `k <= n`. If a new case exceeds the
`message[256]` / `codeword[512]` fixed buffers in `struct rs_kat`, bump those
sizes in `tests/test_erasure_rs.c` to match.

The message bytes are deterministic (a fixed pseudo-random function of chunk
and position), so regenerating with the same `cases[]` reproduces identical
vectors.
