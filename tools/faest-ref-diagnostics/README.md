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
```

## Running

```sh
# ConvertToVOLE vectors
./build/diag_convert | python3 ../../tools/faest-ref-diagnostics/compute_hashes.py

# VOLEHash vectors
./build/diag_vole_hash
```
