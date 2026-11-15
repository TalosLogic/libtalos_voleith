# Benchmarks (1.12.0)

This document is the reproduction recipe and the results record for the 1.12.0
performance story: what multi-threading buys on prove and verify, and what the
FAEST norm S-box saves on proof size. The harness is
`examples/example_bench_release.c`; the result tables below are filled by
running it (numbers are host-specific, so each host gets its own block).

## What is measured

Four frozen (non-norm) proofs, chosen to span the range of real workloads:

1. **AES-128** (`em_128f`): the basic key-knowledge proof, 1:1 with FAEST.
2. **AES-256** (`em_256f`): the larger basic proof.
3. **Merkle membership, depth 10, Hirose** (`em_128f`): `hirose_fixed32` leaf and
   node. The cheapest 128-bit-CR node hash for inputs up to 32 bytes.
4. **Merkle membership, depth 10, Grostl-256** (`em_128f`): `grostl256_fixed`
   leaf and node. The 128-bit-CR choice once inputs exceed 32 bytes, with no
   keyed cipher and so no Hirose-style quantum surface.

Two tables come out of this:

- **Speed**: prove and verify wall-clock (min and median ms) for the four frozen
  circuits, at a sweep of worker counts. The 1-worker row is single-threaded.
- **Size**: the same four circuits built frozen and with the norm S-box,
  reporting VOLE slots (ell) and proof bytes, so the per-circuit saving is
  visible. Size is deterministic (one measurement, any host, no timing).

Three speed columns tell the release story:

| column | where it comes from |
| --- | --- |
| v1.11.0, 1 thread | the baseline binary built in a v1.11.0 worktree (serial; no threading API, and ichor 1.1.0 so no 1.3.0 SIMD) |
| v1.12.0, 1 thread | the current binary, `serial` row (the plain `_v2` path, the 1:1 match for the v1.11.0 entry point) |
| v1.12.0, N threads | the current binary, the best `_ex` row in the worker sweep |

The single-thread 1.11.0 -> 1.12.0 delta is expected to be small on prove/verify:
the ichor 1.3.0 SIMD work (gf256/gf16/Grostl) is off the prove/verify hot path,
and AES-NI/CLMUL (which do drive it) were already present in 1.11.0. The
threading columns are where the win is, and it is byte-identical, not a
micro-optimization that trades away determinism.

## Build and run: current tree (threaded + size table)

Build the examples as usual, then run the harness pinned to physical cores:

```sh
# configure + build however you normally do; the binary lands at
#   build/examples/example_bench_release
cmake -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j

# pin to physical cores (avoid SMT siblings), performance governor on
sudo cpupower frequency-set -g performance    # optional, steadies the clock
taskset -c 0-15 ./build/examples/example_bench_release
```

The current build auto-detects the threading API (via `<ichor/pool.h>`). It
first prints a `serial` row (the plain `_v2` path, the true single-thread
reference the sweep speedups are measured against), then sweeps
`1, 2, 4, 8, 16, cap` workers through the `_ex` path, where
`cap = min(VOLEITH_BENCH_MAX_WORKERS, physical cores)` (default max 16, shown as
the `cap(N)` row; sweep counts above `cap` are skipped), and prints the size
table at the end. On a multi-socket host the core query counts the whole
machine, so pin the run to one socket (taskset) and set
`VOLEITH_BENCH_MAX_WORKERS` to that socket's core count, so the sweep never
oversubscribes the pinned set. The `_ex` `1`-worker row is kept in the output so
the small pool-setup cost at one worker is visible; it is not the speedup
baseline.

## Build and run: v1.11.0 baseline (serial)

The baseline must be built from the v1.11.0 source with its own pinned ichor, so
it carries no threading API and the older (ichor 1.1.0) primitives. A git
worktree gives you a second checkout at the v1.11.0 tag in a sibling directory,
sharing one clone, without disturbing your current 1.12.0 checkout.

```sh
# 1. Create a second working tree checked out at the v1.11.0 release tag, in a
#    sibling directory. Your current checkout is left exactly as it is.
git worktree add ../voleith-v1_11_0 v1.11.0
cd ../voleith-v1_11_0

# 2. v1.11.0 pins a specific ichor commit (1.1.0). Fetch and check it out into
#    this tree's submodule, so the baseline builds against 1.11.0's ichor
#    (the older SIMD) rather than the current one.
git submodule update --init --recursive

# 3. The benchmark harness is new in 1.12.0, so it does not exist in this tree.
#    Copy it in from your current checkout (adjust the path if your 1.12.0
#    directory is named differently):
cp ../libtalos_voleith/examples/example_bench_release.c examples/

# 4. Register it so CMake compiles it: open examples/CMakeLists.txt in THIS
#    tree and add one line, `example_bench_release`, to the EXAMPLE_NAMES list
#    (the same list the other examples are in). No other change is needed; the
#    harness detects it is in an old tree (no <ichor/pool.h>) and compiles its
#    serial baseline path automatically.

# 5. Build and run, pinned the same way as the current-tree run above.
cmake -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j
taskset -c 0-15 ./build/examples/example_bench_release

# 6. When done, remove the worktree (from your main checkout):
#    cd ../libtalos_voleith && git worktree remove ../voleith-v1_11_0
```

It prints one serial row per circuit (and no size table): that row is the
v1.11.0 column. To force baseline mode in any tree, define
`VOLEITH_BENCH_BASELINE` at compile time.

It uses only the frozen circuit builders, which are byte-identical across
versions by the library's own frozen-circuit invariant, so the v1.11.0 and
v1.12.0 rows prove exactly the same statement over exactly the same gate stream.

## Measurement hygiene

Timing noise on a loaded OS is one-sided slow, so **min** is the intrinsic-cost
estimate and median is the typical run; the fast tail is never trimmed. For a
fair cross-version comparison:

- Same compiler and flags for both trees, same host, runs back-to-back.
- Pin to a fixed set of physical cores (`taskset -c 0-15`, or as many physical
  cores as the host has); disable or note Turbo and keep the governor in
  `performance`.
- On a multi-socket (NUMA) host, pin to a single socket and set
  `VOLEITH_BENCH_MAX_WORKERS` to that socket's physical-core count, so the
  comparison stays on one memory domain and the worker pool never spills across
  sockets.
- Quiesce the host (no other CPU-heavy work).
- Compare on min across the two binaries; do not mix numbers from different
  hosts or different build configs in one row.

## Results

One Speed block per host; the Size block is host-independent. Record CPU, core
count, compiler, and flags in each host header.

### Speed, host: Intel Core i9-13950HX (8 P-cores + 16 E-cores, 24 physical), governor min=max 100%, Turbo off

`v1.12.0 1T` is the `serial` row (plain `_v2`, the same entry point the v1.11.0
column uses, so the two are a 1:1 comparison). `v1.12.0 best` is the fastest
worker count in the `1, 2, 4, 8, 16` `_ex` sweep (the count is in parentheses);
`speedup` is `v1.12.0 best` over `v1.12.0 1T`. All figures are min ms over 10
iterations with the clock pinned flat (governor min=max 100%, Turbo disabled).
The worker sweep is capped at 16; the chip has only 8 performance cores, which
bounds the compute-bound prove scaling (see below).

Prove (min ms):

| circuit | v1.11.0 1T | v1.12.0 1T | v1.12.0 best | speedup |
| --- | --- | --- | --- | --- |
| AES-128 | 5.86 | 6.56 | 2.79 (8) | 2.35x |
| AES-256 | 17.96 | 18.80 | 6.69 (16) | 2.81x |
| Merkle d10 Hirose | 141.70 | 147.07 | 70.42 (8) | 2.09x |
| Merkle d10 Grostl-256 | 328.15 | 339.10 | 169.99 (8) | 2.00x |

Verify (min ms):

| circuit | v1.11.0 1T | v1.12.0 1T | v1.12.0 best | speedup |
| --- | --- | --- | --- | --- |
| AES-128 | 5.57 | 5.95 | 2.54 (16) | 2.34x |
| AES-256 | 16.42 | 17.13 | 5.22 (16) | 3.28x |
| Merkle d10 Hirose | 136.19 | 140.35 | 59.80 (16) | 2.35x |
| Merkle d10 Grostl-256 | 310.20 | 317.36 | 130.74 (16) | 2.43x |

Reading the table:

- **Threading is the win.** Prove is 2.0x to 2.8x faster, verify 2.3x to 3.3x,
  all measured within the one v1.12.0 binary against the plain-`_v2` `serial`
  row (so free of cross-build variance). AES-256 verify reaches 3.3x because its
  tau is 32 (more independent VOLE repetitions to spread), while the tau=16
  circuits plateau around 2x. Prove tops out around 8 workers and dips at 16:
  this host has 8 performance cores, so workers past 8 fall onto efficiency
  cores or hyper-thread siblings and the slowest worker gates the segmented
  reduction, on top of the heavy circuits being memory-bandwidth-bound. Verify,
  lighter per rep, keeps gaining to 16.
- **The `_ex` path adds no measurable cost at one worker.** The `serial` (plain
  `_v2`) and `_ex` `1`-worker rows match to within noise (AES-128: 6.56 vs
  6.59 ms prove), so routing through the threaded entry point with one worker is
  free; the earlier apparent gap was run-to-run variance on a tiny proof.
- **Single-thread, version to version, is a small consistent cost.** Comparing
  like for like (plain `_v2` in both versions), v1.12.0 is about 3% to 5% slower
  single-threaded on the heavy circuits (a bit more on the tiny AES-128), from
  the threading context plumbed through the serial commit chain plus cross-build
  variance. It is dwarfed by the threading gain, and the ichor 1.3.0 SIMD work
  is off the prove/verify hot path as expected, so there is no large serial
  swing either way.
- **Net gain over v1.11.0.** Against the old serial baseline, threaded v1.12.0
  is about 1.9x to 2.7x (prove) and 2.2x to 3.2x (verify) faster.

**Is 8 a ceiling? No, it is this laptop's performance-core count.** The
i9-13950HX has 8 performance cores plus 16 slower efficiency cores, so the prove
plateau at 8 is where the fast cores run out, not a limit of the threading.
Prove's commit phase parallelizes across the tau VOLE repetitions (16 at
em_128f, 32 at em_256f) and its QuickSilver phase across wider work, so on a
machine with more than 8 equal-performance cores prove keeps scaling past 8.
Verify already shows this on the same chip, gaining through 16 workers. A run on
one homogeneous socket (a single 14-core Broadwell socket, pinned to avoid
cross-socket NUMA) would show the prove curve continuing past 8 toward 14
directly; that host block is still to be filled in.

### Speed, host: Apple M1 (4 performance + 4 efficiency cores, 8 physical), macOS 15.8.1, Apple clang 17, Release

`v1.12.0 1T` is the `serial` row (plain `_v2`, the same entry point the v1.11.0
column uses). `v1.12.0 best` is the fastest worker count in the `1, 2, 4, 8`
`_ex` sweep (the count is in parentheses; the sweep caps at this host's 8
physical cores); `speedup` is `v1.12.0 best` over `v1.12.0 1T`. All figures are
min ms. Apple Silicon has no governor or Turbo knob to pin, so the run is a
quiesced Release build and min is the intrinsic-cost estimate.

Prove (min ms):

| circuit | v1.11.0 1T | v1.12.0 1T | v1.12.0 best | speedup |
| --- | --- | --- | --- | --- |
| AES-128 | 11.39 | 11.45 | 5.76 (8) | 1.99x |
| AES-256 | 34.15 | 34.34 | 15.38 (8) | 2.23x |
| Merkle d10 Hirose | 129.27 | 130.22 | 62.11 (4) | 2.10x |
| Merkle d10 Grostl-256 | 261.37 | 262.43 | 131.38 (4) | 2.00x |

Verify (min ms):

| circuit | v1.11.0 1T | v1.12.0 1T | v1.12.0 best | speedup |
| --- | --- | --- | --- | --- |
| AES-128 | 11.11 | 11.11 | 5.01 (8) | 2.22x |
| AES-256 | 32.89 | 33.09 | 13.17 (8) | 2.51x |
| Merkle d10 Hirose | 121.52 | 123.15 | 44.53 (8) | 2.77x |
| Merkle d10 Grostl-256 | 238.67 | 235.05 | 79.03 (8) | 2.97x |

Reading the table:

- **Threading is the win, same as the i9.** Prove is 2.0x to 2.2x faster, verify
  2.2x to 3.0x, all measured within the one v1.12.0 binary against the
  plain-`_v2` `serial` row.
- **Prove peaks at 4 workers on the heavy circuits and regresses past it**
  (Hirose 62.11 ms at 4 to 68.30 at 8; Grostl-256 131.38 at 4 to 135.66 at 8):
  the M1 has 4 performance cores, so workers 5 to 8 fall onto the efficiency
  cores and the slowest worker gates the segmented reduction. Verify, lighter
  per rep, keeps gaining through 8. This is the same plateau the i9 shows, now
  reproduced on a second heterogeneous performance-plus-efficiency part, so it
  is the fast-core count talking, not a threading ceiling.
- **Single-thread, version to version, is nearly free here.** Comparing like for
  like (plain `_v2` both versions), v1.12.0 is 0.4% to 0.7% slower
  single-threaded across all four circuits, smaller than the i9's 3% to 5%.
- **Net gain over v1.11.0.** Against the old serial baseline, threaded v1.12.0 is
  about 2.0x to 2.2x (prove) and 2.2x to 3.0x (verify) faster.

### Size (host-independent)

| circuit | frozen ell | norm ell | frozen proof B | norm proof B | saved |
| --- | --- | --- | --- | --- | --- |
| AES-128 (em_128f) | 216 | 176 | 6644 | 6004 | 9.6% |
| AES-256 (em_256f) | 308 | 252 | 22628 | 20836 | 7.9% |
| Merkle d10 Hirose (em_128f) | 11682 | 9218 | 190100 | 150676 | 20.7% |
| Merkle d10 Grostl-256 (em_128f) | 21802 | 16522 | 352020 | 267540 | 24.0% |

The saving grows with how S-box-dominated the circuit is, exactly as the
construction predicts: smallest on AES-128 and AES-256 (only the data-path
S-boxes norm; the key schedule stays frozen, and fixed proof overhead is a
larger fraction of a small proof), largest on the Grostl-256 depth-10 tree
(no key schedule, almost all S-boxes, negligible fixed overhead) at 24.0%, right
up against the clean 25% ceiling.
