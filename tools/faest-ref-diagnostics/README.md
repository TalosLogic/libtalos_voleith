# faest-ref diagnostic tools

These files were used to extract test vectors from the faest-ref reference
implementation for use in libtalos_voleith's test suite.  They must be built
against the faest-ref tree in `../../third_party/faest-ref/`.

## Files

- **`diag_convert.c`** - Prints `u`, `c`, `vs`, `qs` arrays from
  `vole_commit` + `vole_reconstruct` for `FAEST_EM_128F`.  Used to derive the
  ConvertToVOLE known-answer vectors in `tests/test_convert.c`.

- **`diag_vole_hash.c`** - Prints VOLEHash test vectors for λ = 128, 192, 256.
  Used to derive the VOLEHash known-answer vectors in `tests/test_vole_hash.c`.

- **`compute_hashes.py`** - Post-processes the output of `diag_convert` by
  computing SHAKE-256 hashes of the raw `u`/`c`/`vs`/`qs` buffers and
  formatting them as C array literals.
  Usage: `./build/diag_convert | python3 compute_hashes.py`

- **`diag_norm_constraints.c`** - Prints the FAEST norm S-box constraint
  coefficients (spec Fig 6.19, `y * a^2 * a^16 = a`) for lambda = 128, 192,
  256: the three prover streams `a0`/`a1`/`a2` from
  `aes_SSS_inv_norm_constraints_prover` and the verifier value from
  `aes_SSS_inv_norm_constraints_verifier`.  Used to pin the one-shot PRODUCT3
  compat gate in `tests/test_product3_compat.c`.  The `IN_*` input arrays in
  that test MUST stay byte-identical to the ones here.

- **`diag_norm_basis.c`** - Recovers FAEST's GF(2^4) norm-nibble basis as
  GF(2^8) bytes by inverting `bf##W##_byte_combine_bits` on the basis images
  (`bfSSS_beta_squares[0..1]`, `bfSSS_beta_cubes[0]`).  Asserts the basis is
  identical across lambda = 128/192/256 and that the inversion is exact (which
  confirms voleith's `embed` == FAEST's `byte_combine`), then prints the four
  basis bytes and the beta images as lambda byte-arrays.  Used to pin the
  nibble basis in `proof/gf8_circuit.c` and the companion gate
  `tests/test_norm_basis_compat.c`.

## Building

From the `third_party/faest-ref/` directory (after building faest-ref with
meson):

```sh
# Copy or symlink the diagnostic source next to the faest-ref headers
cp tools/faest-ref-diagnostics/diag_convert.c   third_party/faest-ref/
cp tools/faest-ref-diagnostics/diag_vole_hash.c third_party/faest-ref/

cd third_party/faest-ref

gcc -DFAEST_TESTS -DHAVE_CONFIG_H -I. -Ibuild -Isha3 diag_convert.c \
    -o build/diag_convert build/libfaest_no_random.a build/libfaest.a

gcc -DFAEST_TESTS -DHAVE_CONFIG_H -I. -Ibuild -Isha3 diag_vole_hash.c \
    -o build/diag_vole_hash build/libfaest_no_random.a build/libfaest.a

cp tools/faest-ref-diagnostics/diag_norm_constraints.c third_party/faest-ref/
gcc -DFAEST_TESTS -DHAVE_CONFIG_H -I. -Ibuild -Isha3 diag_norm_constraints.c \
    -o build/diag_norm_constraints build/libfaest_no_random.a build/libfaest.a

cp tools/faest-ref-diagnostics/diag_norm_basis.c third_party/faest-ref/
gcc -DFAEST_TESTS -DHAVE_CONFIG_H -I. -Ibuild -Isha3 diag_norm_basis.c \
    -o build/diag_norm_basis build/libfaest_no_random.a build/libfaest.a
```

## Running

```sh
# ConvertToVOLE vectors
./build/diag_convert | python3 ../../tools/faest-ref-diagnostics/compute_hashes.py

# VOLEHash vectors
./build/diag_vole_hash

# PRODUCT3 norm-constraint compat vectors (paste into tests/test_product3_compat.c)
./build/diag_norm_constraints

# Norm-nibble basis + beta images (paste into tests/test_norm_basis_compat.c)
./build/diag_norm_basis
```
