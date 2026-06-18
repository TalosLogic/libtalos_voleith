# Parser fuzz harnesses

libFuzzer harnesses for the two untrusted-input parsers, per ISA 1.5 (the
last parser invariant: "ships with a libFuzzer harness exercising the parser
entry point ... runs in CI on every commit that touches parser code") and
docs/GF8_CIRCUIT_ISA_DESIGN.md 8.4 item 11. This is W4.1 of
docs/SHIPSHAPE_IMPLEMENTATION_PLAN.md; the CI jobs (W4.2) and the
deterministic adversarial regression corpus (W4.3) build on it.

| Harness | Entry point | Source |
|---------|-------------|--------|
| `fuzz_shipshape` | `voleith_shipshape_parse_buffer` | `fuzz_shipshape.c` |
| `fuzz_bristol` | `voleith_bristol_parse_buffer` | `fuzz_bristol.c` |

Both copy the fuzzer input into a `size + 1` NUL-terminated buffer (the
invariant the file entry points guarantee via `calloc(sz + 1, 1)`) and pass
the explicit length, so the `len == 0 => strlen` path never reads past the
input.

## Build (Clang only)

libFuzzer is a Clang feature. The build is opt-in behind `-DVOLEITH_FUZZ=ON`,
which instruments the whole library with
`-fsanitize=fuzzer-no-link,address,undefined`; the harness executables add
the libFuzzer runtime at link.

```sh
CC=clang cmake -S . -B build-fuzz -DVOLEITH_FUZZ=ON
cmake --build build-fuzz --target fuzz_shipshape fuzz_bristol
```

Configuring with a non-Clang compiler and `-DVOLEITH_FUZZ=ON` is a hard
configure error.

## Run

libFuzzer uses its **first** directory argument as the corpus it both reads
and **writes** to, and any further directories as read-only seed inputs. Keep
the committed seeds read-only by pointing the first argument at a separate,
gitignored working dir:

```sh
mkdir -p fuzz/corpus-work/shipshape fuzz/corpus-work/bristol
./build-fuzz/fuzz/fuzz_shipshape fuzz/corpus-work/shipshape fuzz/corpus/shipshape
./build-fuzz/fuzz/fuzz_bristol   fuzz/corpus-work/bristol   fuzz/corpus/bristol
```

`fuzz/corpus-work/` is gitignored; the SHA1-named inputs libFuzzer discovers
go there, not into the committed seed corpus. (Do not pass `fuzz/corpus/...`
as the first argument, or the fuzzer pollutes the seed dir with hundreds of
generated files.)

A crash is written to `crash-<sha1>` in the working directory; reproduce with
`./fuzz_shipshape crash-<sha1>`. Crash artifacts are gitignored; promote a
real one to a deterministic regression test under W4.3 rather than committing
the raw artifact.

### ASLR on new kernels

On kernels that default `vm.mmap_rnd_bits` to 32 (Debian Trixie, Linux 6.x+),
an AddressSanitizer binary can die with a bare `Segmentation fault` at startup
(no sanitizer output, before any input is read): the shadow-memory mapping
collides with the high-entropy ASLR layout. Run the harness with ASLR off:

```sh
setarch -R ./build-fuzz/fuzz/fuzz_shipshape fuzz/corpus-work/shipshape \
    fuzz/corpus/shipshape
```

Or lower the host entropy once: `sudo sysctl -w vm.mmap_rnd_bits=28`. The CI
jobs already wrap the harnesses in `setarch -R`.

### Bounding resource use

The Shipshape harness passes tight `voleith_shipshape_limits_t` values, so no
single input drives a large allocation. The Bristol parser has no
resource-limit struct: the header counts `n_wires` and `n_output_values` each
drive an unbounded `calloc` (out-of-scope-by-policy, see
docs/SECURITY_REVIEW_1_5_0.md), so the harness caps them to 2^20 and skips any
input that exceeds the cap before parsing. Without that cap the fuzzer
trivially finds a giant-header input and reports a spurious out-of-memory.
Keep `-rss_limit_mb` as defense in depth:

```sh
./build-fuzz/fuzz/fuzz_bristol -rss_limit_mb=4096 fuzz/corpus/bristol
```

A short, bounded run for CI smoke (W4.2 wires this into the pipeline):

```sh
./build-fuzz/fuzz/fuzz_shipshape -max_total_time=60 fuzz/corpus/shipshape
```

## Seed corpus

`corpus/shipshape/` holds valid `.ship` files (header only, a gate/sugar mix,
and a Tier 2a registry call). `corpus/bristol/` holds small valid Bristol
Fashion circuits (a single XOR and a single INV). The Bristol harness reads
the file's declared input-value count from the header and presents a matching
WITNESS/INSTANCE role array, so a well-formed seed clears the
`ROLE_MISMATCH` gate and reaches the gate parser.
