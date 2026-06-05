# Changelog

All notable changes to libtalos_voleith are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.4.0] 2026-06-05

Adds RSv1 ring signatures: a non-interactive, publicly verifiable ring
signature with optional revocation, parameterised over any wrapped
node-hash vt.  Built on top of the existing vt-driven Merkle / IMT
stack with one new circuit entry point and a handful of software
helpers.  Inner GF(2⁸) proof format is unchanged; existing proofs
verify unchanged.  See DESIGN.md "Ring Signatures (RSv1)" for the
full design.

### Added

- `proof/ring_sig_v1_gf8.{c,h}`: data layer.  Membership cfg, validate,
  canonical-encoding absorber (reusable across future linkable /
  claimable / threshold variants), V1 cfg fingerprint, witness packer,
  `voleith_rsv1_ring_build`, sign / verify, fs_seed construction.
- `circuits/ring_sig_v1_gf8_circuit.{c,h}`:
  `voleith_rs_membership_build_circuit`, composing the OWF circuit,
  the secret-dir vt-driven Merkle path, and (when `depth_r > 0`) the
  secret-dir vt-driven IMT non-member branch.
- `merkle_vt_gf8_path_from_leaf_node_secret_dir`: new entry point on
  the vt-driven Merkle circuit that walks the inode chain from a
  pre-computed leaf-node wire array (instead of re-hashing leaf
  data).  Used to feed the OWF output into the path.  Bit-exact
  per-vt equivalence with the existing secret-dir entry is pinned in
  `test_merkle_vt_gf8_equivalence.c`.
- Software helpers `voleith_merkle_vt_build`,
  `voleith_merkle_vt_compute_path`
  (`circuits/merkle_vt_gf8_helpers.{c,h}`) and `voleith_imt_vt_build`,
  `voleith_imt_vt_lookup_nonmember`
  (`circuits/indexed_merkle_vt_gf8_helpers.{c,h}`): library-level
  tree / IMT construction and lookup, lifting the inline tree code
  previously open-coded in KVAC fixtures.
- On-the-wire envelope: `voleith_ring_sig_pack`,
  `voleith_ring_sig_unpack`, `voleith_ring_sig_packed_len`,
  `voleith_ring_sig_free`.  41-byte header ("VRS1" magic + version
  + cfg fingerprint + params fingerprint + big-endian proof length),
  constant-time fingerprint checks on unpack.
- `include/voleith_gf8.h` now pulls in the vt-driven Merkle / IMT
  stack and the RSv1 API; a complete RSv1 program can be written
  against the single umbrella header.
- Examples `example_ring_sig_v1_gf8.c` and
  `example_ring_sig_v1_revocable_gf8.c`: full sign-pack-unpack-verify
  demos, with and without revocation.  Both are parameterised over
  the cfg struct so swapping in a different node-hash vt or depth is
  a one-field edit.
- Tests `tests/test_ring_sig_v1_gf8.c`: cfg validate + fingerprint
  KAT pin, build_circuit + witness packer, ring_build, fs_seed KAT
  pin, sign / verify roundtrip on AES-DM and Hirose, asymmetric OWF /
  tree-hash pairing, anonymity smoke (two members signing the same
  message produce distinct proofs with no leaf-node embedded under
  memcmp), revocation positive and negative, wire envelope tamper
  rejections (magic, version, both fingerprints, length).

### Changed

- `voleith_node_hash_vt` (`circuits/node_hash_vt.h`) gains two fields:
  `cr_bits` (the vt's collision-resistance bound, used by
  `voleith_rs_membership_validate` to enforce the OWF-not-weaker-than-
  tree relationship) and `fixed_leaf_bytes` (non-zero for fixed-leaf
  vts such as `hirose_fixed32`, zero for variable-leaf vts).
  Source-compatible: in-tree vts use C99 designated initializers, so
  the added fields default-zero on any consumer that does not set
  them; out-of-tree vts that want the new strength / fixed-width
  enforcement must set them explicitly.

### Security

- `voleith_imt_vt_validate_records`
  (`circuits/indexed_merkle_vt_gf8_helpers.{c,h}`): rejects record
  arrays with sort-order, wrap-around-interval, or overlap violations
  before any hashing.  Wired into `voleith_imt_vt_build` and
  `voleith_imt_vt_lookup_nonmember` at the public boundary; catches
  the "forgot to update predecessor's next_value" foot-gun that
  would otherwise let an adversarial prover forge non-membership for
  an actual revoked member.  Accepts the degenerate "max sentinel"
  padding pattern used by the revocable example.

## [1.3.0] 2026-06-03

Adds a 48-byte v1 metadata header at the start of every proof, binding
each proof to the variant choice (FS backend, BAVC construction, param
set) and to the specific circuit and params via two 16-byte SHAKE-128
fingerprints.  The header is mixed into the Fiat-Shamir transcript so
any tampering breaks the final chall_3 check.  Pre-header proofs are
still accepted via a compile-time-gated legacy fallback in the
verifier.  Resolves the circuit/params identity-binding half of the
security review.

### Added

- `proof/proof_header.{c,h}`: 48-byte header (4-byte `"TLOS"` magic +
  version + fs_kind + bavc_kind + param_set_id + flags + reserved +
  16-byte circuit_fp + 16-byte params_fp).  Parse, serialize
  (size-query API), and constant-time identity check.
- `proof/circuit_fingerprint.{c,h}` and
  `proof/gf8_circuit_fingerprint.{c,h}`: canonical SHAKE-128
  fingerprint over the bit-level and GF(2⁸) circuit structures.
  Domain tags `voleith-{,gf8-}circuit-cf-v1` pin the encoding.
- `proof/params_fingerprint.{c,h}`: canonical SHAKE-128 fingerprint
  over `voleith_params_t` (domain tag `voleith-params-cf-v1`).
- `voleith_params_build(set, fs, bavc)`: unified params constructor;
  the existing `voleith_params_em_*` named symbols are explicit-init
  copies of the corresponding `(set, SHAKE, STANDARD)` row.
- `voleith_proof_inspect(proof, header_out)`: public helper for
  routing proofs to the right verifier configuration before
  invocation.  Supports `header_out == NULL` for a fast "is this v1?"
  check.
- `VOLEITH_LEGACY_VERIFY` CMake option (default `ON`): gates the
  legacy fallback verifier.  Disabling shrinks attack surface for
  deployments that have re-minted all proofs.
- `voleith_fs_kind_t`, `voleith_bavc_kind_t`, `voleith_param_set_id_t`
  enums (currently `SHAKE`/`STANDARD` only; `GROSTL` and `HALF_TREE`
  reserved for future backend work).
- `voleith_shake128_absorb_u32_le`: small SHAKE absorb helper used by
  the canonical serializers.
- `tests/test_legacy_verify.c`: header-strip, fingerprint-corruption,
  and fixed-prefix tampering coverage of the dual-path verifier.
- `voleith_{,gf8_}prove_v2` and `voleith_{,gf8_}verify_v2`:
  length-validated entry points that reject `witness_len` /
  `instance_len` mismatches at the public API boundary. Existing
  entry points stay source-compatible and are documented as
  deprecated for removal in 2.0.0.

### Changed

- Proof wire format adds 48 bytes at the start of every proof; the
  body layout is unchanged.  `voleith_proof_byte_size` and
  `voleith_gf8_proof_byte_size` reflect the new total.
- `voleith_{,gf8_}commit_blob_size` grows by 48 bytes; the
  commitment blob is now `header ‖ hcom ‖ c ‖ iv` so a caller-driven
  `chall_1` absorption naturally binds the header without
  header-specific code in the caller (shared-transcript / two-phase
  consumers gain the binding for free).
- `voleith_params_t` gains `fs_kind` and `bavc_kind` fields;
  `voleith_params_validate` range-checks them.
- `voleith_{,gf8_}verify` now dispatches statically: leading 48 bytes
  parse as v1 header → v1 path with identity check; otherwise → legacy
  path (when `VOLEITH_LEGACY_VERIFY=ON`) or rejection.

## [1.2.0] 2026-06-01

Adds Hirose-AES-256 as a hash primitive and GF(2⁸) circuit, the
`voleith_node_hash_vt` hash-agnostic interface, and generic vt-driven
Merkle path / indexed-non-member circuits that carry Hirose and the
existing hash families uniformly.  No wire-format or proof-format
change; existing proofs verify unchanged.  Existing fixed-hash entry
points (`merkle_gf8_path_circuit`, `merkle_grostl_gf8_path_circuit`,
their secret-dir and indexed counterparts) are unchanged: the
vt-driven additions are purely additive and produce bit-exact gate
streams.  See DESIGN.md "Hirose-AES-256 double-block-length hash" and
"Generic vt-driven Merkle path and indexed-non-member circuits".

### Added

- `core/hirose.{c,h}`: Hirose DBL compression (FSE 2006) over AES-256.
  Naive two-encrypt software form serves as an independent oracle for
  the KS-shared in-circuit form.
- `circuits/node_hash_hirose_gf8.{c,h}`: Hirose iteration as a GF(2⁸)
  circuit (KS-shared, 500 S-boxes / iteration, the structural floor at
  2¹²⁸ CR), plus fixed-32-leaf / variable-leaf / inode wrappers,
  witness builders, and software helpers.  Iteration emit is
  aliasing-safe for in-place chaining.
- `circuits/node_hash_vt.h`: `voleith_node_hash_vt` interface, the
  hash-agnostic bridge consumed by the generic vt-driven Merkle / IMT
  circuits.
- Hirose vt instances `voleith_node_hash_hirose_fixed32` (32-byte
  leaves, no padding) and `voleith_node_hash_hirose` (variable-length
  leaves, `10*` always-pad, Merkle-internal only).  Both share inode
  dispatch.
- `circuits/node_hash_aes_gf8.{c,h}` and `circuits/node_hash_grostl_gf8.{c,h}`:
  vt instances wrapping the existing AES-DM, AES-128-CMAC, and four
  Grøstl variants.  Eight vts ship in total.
- `circuits/merkle_vt_gf8_circuit.{c,h}`: generic vt-driven Merkle
  path circuit, public-dir and secret-dir.  Secret-dir enforces
  per-level `assert_product(dir, dir, dir)` booleanity structurally.
- `circuits/indexed_merkle_vt_gf8_circuit.{c,h}`: generic vt-driven
  indexed Merkle non-membership circuit, public-dir and secret-dir.
- Conformance / equivalence tests: `tests/test_merkle_vt_gf8_equivalence.c`,
  `tests/test_indexed_merkle_vt_gf8_equivalence.c` (bit-exact match
  against the fixed-hash entries for every wrapped vt), and
  `tests/test_node_hash_vt_conformance.c` (per-vt invin sizing, leaf /
  inode circuit-vs-software, domain separation, depth-3 end-to-end,
  booleanity rejection), uniform across all eight vts.
- AES-256 key-schedule sharing refactor (`aes256_gf8_expand_key`,
  `aes256_gf8_encrypt_rk`, matching witness builders).
  `aes256_gf8_circuit` becomes a thin wrapper that is byte-identical
  for all existing AES-256 callers.
- Examples: `example_hirose_gf8`, `example_hirose_leaf_gf8`,
  `example_hirose_inode_gf8`: three concrete cost points for the
  iteration primitive, the fixed-32 leaf, and the inode.
- `examples/example_merkle_hirose_gf8.c`: depth-5 Merkle path proof
  through the vt-driven `merkle_vt_gf8_path_circuit` with the
  Hirose-AES-256 fixed-32 leaf vt, mirroring `example_merkle_gf8`
  (AES-DM) and `example_merkle_grostl_gf8` (Grøstl) so the three node-
  hash families can be benchmarked apples-to-apples on the same host.
- Prove / verify benchmarking helpers (`examples/bench_util.h`) and
  `taskset(1)` workflow documented in README and DESIGN.md
  "Performance Benchmarking".

### Changed

- `tests/test_aes.c` FIPS 197 Appendix A round-key inspection tests
  now also run under the ARMv8 Crypto Extension backend (gate widened
  from `VOLEITH_HAVE_AES_NI` to `VOLEITH_HAVE_AES_NI ||
  VOLEITH_HAVE_ARMV8_AES`).  ARMv8 stores `ctx->rk` in the same flat
  byte layout as AES-NI, so the existing assertions apply unchanged.
  Previously these tests were skipped on aarch64 hosts.

### Removed

- The variable-time table-lookup AES backend and the variable-time
  software field-multiplication path have been removed entirely,
  along with their CMake gates (`-DVOLEITH_ALLOW_VARIABLE_TIME_AES`,
  `-DVOLEITH_ALLOW_VARIABLE_TIME_FIELD`).  Both were already gated
  OFF by default since 1.0.1 and unused by any shipping
  configuration; they survived only as in-tree reference oracles,
  but that role is covered by NIST AES KATs and the faest-ref oracle
  for field arithmetic, so deletion is a strict reduction of the
  side-channel surface and the maintenance burden.  Affected:
  `core/aes.{c,h}` (the FIPS 197 table-lookup path,
  `VOLEITH_AES_BACKEND_VARIABLE_TIME` enum value, and dispatch
  fallbacks), `core/field.c` (the variable-time arms of
  `voleith_gf8_mul`, `clmul64_soft`, `voleith_gf{128,192,256}_mul`,
  and `voleith_byte_combine`; the orphaned `limbs_xor` /
  `limbs_test_bit` helpers), `CMakeLists.txt` (option blocks, loud
  warnings, dispatch propagation, the `sw_vartime` test variant, and
  the `FORCE_VARTIME_FIELD` parameter of `voleith_add_variant`).
  Builds previously passing `-DVOLEITH_ALLOW_VARIABLE_TIME_*=ON`
  will fail with an "unknown CMake option" warning; the gates are
  no longer recognised.  All other build options behave unchanged.

### Security

- **Bounded the per-vector tree depth `k` in `voleith_params_validate`**.
  Prevents a stack-buffer overflow on the verifier-side reconstruct
  path for custom `voleith_params_t` with tau small relative to
  lambda; all six predefined `em_*` sets are well under the bound.
- **Reject circuits with silent allocation failures at the prove /
  verify boundary**.  Added `alloc_ok` flag + `voleith_circuit_ok()`
  to `voleith_circuit_t`; prove / verify entry points (bit-level and
  GF(2⁸)) now check it.
- **Auto-check `voleith_gf8_circuit_ok()` in the GF(2⁸) prove /
  verify entry points**. Previously only tested by callers; closes
  H-N2.
- **Validate wire-id references at the prove / verify boundary**.
  Added `voleith_circuit_validate` / `voleith_gf8_circuit_validate`,
  called from the prove / verify entry points after `*_circuit_ok`.
  One-shot topological + bounds check; closes L-N2.
- **Zero verifier-side reconstructed seed and qtmp buffers before
  free** in `voleith_vole_reconstruct`. Aligns with the prover-side
  V-5 discipline; closes L-N3.
- **Document the `fs_seed` caller-binding obligation** on every
  prove / verify entry point in `proof/proof.h` and
  `proof/gf8_proof.h`. Doc-only mitigation for M-N2; structural
  auto-binding deferred to 1.3.0.

### Performance

Depth-5 Merkle path, GF(2⁸) circuit, EM-128f parameters (the proof
system's smallest fast-variant set).  Measured with the
`example_merkle_*_gf8` programs: 25 prove and 100 verify iterations
after 2 warmup runs, pinned to a single core with `taskset -c 0`.
Reported as min: the cleanest estimate of intrinsic cost since prove
variance is dominated by the grinding loop (see `examples/bench_util.h`).

x86_64 (Intel Xeon E5-2690 0 @ 2.90GHz, Sandy Bridge-EP; CLMUL + AES-NI;
`taskset -c 0`):

| Node hash         | CR    | Proof size | Prove (min) | Verify (min) |
|---|---|---|---|---|
| AES-DM (16 B)     | 2⁶⁴  | 24 KB      | 45 ms       | 13 ms        |
| Hirose-AES-256    | 2¹²⁸ | 102 KB     | 63 ms       | 58 ms        |
| Grøstl-256_T27    | 2¹⁰⁸ | 190 KB     | 139 ms      | 134 ms       |

aarch64 (Apple M1, macOS 15.7.7; ARMv8 Crypto Extension; no CPU pinning):

| Node hash         | CR    | Proof size | Prove (min) | Verify (min) |
|---|---|---|---|---|
| AES-DM (16 B)     | 2⁶⁴  | 24 KB      | 19 ms       | 17 ms        |
| Hirose-AES-256    | 2¹²⁸ | 102 KB     | 64 ms       | 59 ms        |
| Grøstl-256_T27    | 2¹⁰⁸ | 190 KB     | 124 ms      | 111 ms       |

At the 2¹²⁸ CR floor, the new Hirose-AES-256 node hash produces 1.86×
smaller proofs and is ~2× faster (x86: 2.3×, M1: 1.9×) to verify than
Grøstl-256_T27, which is at the strictly weaker 2¹⁰⁸ CR - confirming
Hirose as the 2¹²⁸ option on both hardware families.

## [1.1.0] - 2026-05-28

Adds the Grøstl hash family and wide-node Grøstl Merkle circuits. No
wire-format or API breakage; existing proofs verify unchanged.

### Added

- Grøstl-256 / Grøstl-512 hash (`core/grostl.{c,h}`), constant-time,
  with x86 AES-NI and ARMv8 AES hardware paths for SubBytes.
- `circuits/grostl_gf8_circuit.{c,h}`: Grøstl as a GF(2⁸) circuit
  (reuses the AES S-box gadget).
- `circuits/merkle_grostl_gf8_circuit.{c,h}`: wide-node Grøstl Merkle
  path, four node variants (`GROSTL_256`, `_256_T27`, `_512`, `_512_T59`),
  public-dir and secret-dir. See DESIGN.md "Grøstl wide-node Merkle
  hashing".
- `circuits/indexed_merkle_grostl_gf8_circuit.{c,h}`: Grøstl indexed
  non-membership, public-dir and secret-dir.
- `voleith_gf8_inv()` (`core/field.c`): constant-time GF(2⁸) inverse
  (Fermat); shared by every AES-S-box witness builder, ~20× faster than
  the prior scan and dudect-validatable.
- Reusable bitsliced S-box primitives in `core/aes_ct64` for Grøstl's
  SubBytes.
- NIST Grøstl KAT and Monte Carlo test harnesses; vectors vendored
  in-repo (MCT tagged slow).
- dudect timing targets for the software Grøstl path and witness
  builder.
- Examples: `example_merkle_grostl_gf8`, `example_indexed_merkle_grostl_gf8`,
  Grøstl KVAC (`example_kvac_pq_grostl_gf8`, `..._depth12`), and shared
  `bench_util.h`.

### Fixed

- Secret-dir Merkle / indexed-Merkle circuits now enforce direction-bit
  booleanity in-circuit (`assert_product(dir, dir, dir)`); an
  unconstrained mux selector was a soundness break. See DESIGN.md
  "Merkle path direction bits".

### Changed

- CMake AES-NI flags now include `-mssse3` (Grøstl `pshufb`).
- README proof-size table refreshed to byte-exact GF(2⁸) AES-128
  figures; "EM" naming clarified.
- README and `docs/DESIGN.md` document the public-dir vs secret-dir
  Merkle distinction.

## [1.0.2] - 2026-05-26

### Added

- ARMv8 AES hardware backend (`core/aes.c`): AArch64 Crypto Extension
  (`AESE` / `AESD` / `AESMC` / `AESIMC` via `<arm_neon.h>`) for
  AES-128 / AES-256 encryption, key expansion, and the
  `voleith_aes_encrypt_x4()` batched path. Dispatched alongside the
  existing x86 AES-NI and constant-time bitsliced backends.
- ARMv8 PMULL / PMULL2 hardware backend (`core/field.c`): carry-less
  GF(2^k) multiplication via `vmull_p64` / `vmull_high_p64` for
  k ∈ {64, 128, 192, 256}, the AArch64 analogue of the existing x86
  CLMUL path. Gated behind the new `VOLEITH_HAVE_PMULL` define.
- CMake now detects AArch64 AES and PMULL extensions in addition to
  the existing x86 AES-NI / CLMUL detection, and only builds the
  test variants whose required hardware extension was detected on
  the host.
- dudect-style empirical timing-validation harness under
  `tools/dudect/`, gated behind `VOLEITH_BUILD_DUDECT` (default OFF).
  Welch's two-sample t-test with symmetric percentile cropping per
  Reparaz, Balasch, Verbauwhede (NDSS 2017). RDTSCP timer on x86_64,
  inline-asm `CNTVCT_EL0` with ISB barrier on aarch64,
  `clock_gettime` fallback. CPU pinning via `sched_setaffinity` on
  Linux and `thread_policy_set` + `QOS_CLASS_USER_INTERACTIVE` on
  macOS. Ten real targets (`aes_ct64_encrypt[_x4]_key`,
  `aes_ct64_encrypt[_x4]_pt`, `voleith_gf{128,192,256}_mul`,
  `voleith_byte_combine_{128,192,256}`) plus two self-validation
  sentinels. Cross-platform evidence on Sandy Bridge, Gracemont, and
  Apple M1 under `docs/dudect-runs/`.

### Fixed

- `voleith_aes_ctx_t::rk` now declared with `_Alignas(16)`. The
  AES-NI key-expand and encrypt paths cast `rk` to `__m128i *` and
  emit `MOVDQA` (aligned-only); without an explicit annotation the
  struct's natural alignment was 4 bytes, so a stack-local context
  could land on an unaligned offset and `#GP`. Latent in v1.0.1 but
  masked on gcc-14 (which over-aligns stack locals when it sees
  `__m128i` activity); reproducible on clang-14.
- `rotl64` in `core/hash.c` no longer relies on `(64 - n) % 64` for
  the reverse shift, which is undefined behaviour when `n == 0` and
  was miscompiled on Apple Clang / Xcode 26.2. Replaced with the
  `(-n) & 63` idiom.
- `voleith_secure_zero()` on Apple targets falls back to the
  volatile-pointer loop rather than calling `explicit_bzero`, which
  is no longer exposed in recent macOS SDKs.

## [1.0.1] - 2026-05-23

Security-hardening release. Every change in this version stems from a
comprehensive internal security review of the v1.0.0 codebase. No
protocol-level or wire-format changes: v1.0.0 proofs verify under v1.0.1
and vice versa.

One behaviour change at the API level: the bit-level prover now rejects
invalid witnesses upfront rather than producing a proof the verifier
would later reject. Callers that previously inspected the return value
of `voleith_prove` only after attempting verification are unaffected;
callers that ignored the prove return value should review their flow.

### Added

- `LICENSE` file: GNU Affero General Public License v3.0 (AGPL-3.0-only).
- SPDX-License-Identifier headers on all source files.
- Constant-time bitsliced AES backend (`core/aes_ct64.c`), always built as the
  portable side-channel-resistant fallback when AES-NI hardware is absent.
- `voleith_aes_encrypt_x4()` batched-encrypt API; the AES-CTR PRG
  (`core/prg.c`) now uses it for parallel block expansion.
- Build-time AES backend reporter (`voleith_report_aes_backend()`) printing
  the active backend at CMake configure time so CI/CD pipelines can detect
  software-fallback builds before deployment.
- One-time runtime stderr warning when a software-AES binary is executed on
  a host whose CPU advertises AES-NI, so users are not silently paying the
  ~30-50x slowdown.
- `-DVOLEITH_ALLOW_VARIABLE_TIME_AES` CMake gate (default OFF). When OFF,
  the legacy variable-time table-lookup AES path is not compiled in.
- `-DVOLEITH_ALLOW_VARIABLE_TIME_FIELD` CMake gate (default OFF). When OFF,
  no variable-time GF(2^k) multiplication paths are compiled in.
- `voleith_params_validate()` at every public API entry point
  (`voleith_prove`, `voleith_verify`, `voleith_prove_commit`,
  `voleith_verify_reconstruct`, and the GF(2^8) equivalents). Rejects
  malformed parameter structs (invalid λ, τ = 0, τ > 32, w_grind ≥ λ,
  n_leafcom not in {2, 3}, T_open = 0) before any allocation or
  cryptographic work.
- `docs/DESIGN.md` - design-rationale document covering the five-layer
  architecture, the two-variant proof-system rationale, the circuit API as
  the core abstraction, VOLEitH versus interactive VOLE, two-phase
  Fiat-Shamir composition, parameter-set sizing trade-offs, the FAEST
  norm-trick analysis, the indexed-Merkle trust assumption, and the
  future-work roadmap.
- README.md trust-assumption disclosure for the indexed-Merkle
  non-membership circuit: the adjacency invariant (each leaf's `next_value`
  / `next_index` correctly identifies the next-larger leaf actually present
  in the tree) is an external assumption on the tree builder, not verified
  by the circuit.
- Shared AES KAT test runner (`tests/aes_kat_runner.{c,h}`) for re-using
  NIST AES test vectors across AES-NI and bitsliced backends in all four
  build variants (sw, clmul, aesni, clmul_aesni).
- Regression tests for the VOLE-layer bounds-check findings (V-1, V-2,
  V-12) in `tests/test_vc.c`.
- `voleith_const_memcmp()` constant-time byte-array comparison (volatile
  XOR accumulator) for use at every secret-dependent equality-check site.
- `voleith_secure_zero()` memory-clear helper (backed by `explicit_bzero`
  on POSIX, volatile pointer loop otherwise) for use on every buffer that
  holds key material, VOLE correlations, or witness bytes.

### Changed

- All software-path GF(2^k) multiplications rewritten to be constant-time.
  No secret-dependent branches remain in `core/field.c` for k ∈ {8, 64,
  128, 192, 256}. The CLMUL hardware paths were already constant-time by
  hardware definition.
- `voleith_byte_combine()` rewritten to be constant-time (C-3): no
  secret-dependent branches; uses bitmask-conditional XOR with the
  `ct_barrier_u64` inline-asm optimiser barrier to prevent the compiler
  from re-introducing a branch.
- Bit-level QuickSilver prover (`voleith_qs_prove` in `proof/prover.c`)
  now calls `voleith_circuit_eval` and returns an error upfront for any
  invalid witness, matching the GF(2^8) prover's discipline.
  Previously the prover would produce coefficients that the verifier
  would later catch via the QuickSilver `a0_tilde` check, leaving a
  buggy caller unable to distinguish "my witness is wrong" from "my
  proof was tampered with in transit."
- Indexed-Merkle and KDF-CTR-CMAC circuits now return integer error codes
  when their input would exceed the internal stack-guard limits, rather
  than silently truncating and producing an invalid circuit.
- README.md restructured for the public release: high-level overview,
  consolidated "Standards and specifications implemented" table,
  minimal-example getting-started, examples directory inventory, and a
  References section with linked spec and paper sources.

### Security

This release closes every Medium-and-above finding from the internal
security review. The findings and their resolutions:

- **Software AES was variable-time** (cache-timing side channel via S-box
  table lookups). Resolved by shipping a constant-time bitsliced backend
  as the always-built default fallback, gating the variable-time path
  behind an opt-in CMake flag (default OFF), and adding compile-time and
  runtime warnings for software-AES builds.
- **Software field multiplications used secret-dependent branches**
  (timing side channel proportional to operand bit-length). Resolved by
  rewriting all five software multiplication paths to bitmask-conditional
  XOR with optimiser barriers; CLMUL hardware paths unchanged.
- **`voleith_byte_combine` used secret-dependent branches** (C-3).
  Resolved by rewriting to constant-time form using bitmask conditional
  selection.
- **Missing bounds checks in the VOLE layer** (V-1, V-2, V-12). Resolved
  by adding range validation in `vole/vc.c` for previously unchecked
  indexes that could be driven out of range by an attacker-controlled
  proof byte. Regression tests added.
- **Missing secure-zero before free** across the prover, verifier, VOLE,
  and proof-handling code paths. Resolved by a comprehensive sweep
  applying `voleith_secure_zero()` to every buffer holding key material,
  VOLE correlations, witness data, or transient cryptographic state.
  Affected modules: `core/aes.c`, `core/hash.c`, `core/prg.c`,
  `proof/fiat_shamir.c`, `proof/prover.c`, `proof/gf8_prover.c`,
  `proof/verifier.c`, `proof/gf8_verifier.c`, `proof/proof.c`,
  `proof/gf8_proof.c`, `vole/vc.c`, `vole/voleith.c`, `vole/convert.c`.
- **`memcmp` used for secret-dependent equality checks** at multiple
  sites. Resolved by replacing every secret-dependent comparison with
  `voleith_const_memcmp()` (volatile XOR accumulator). Affected sites
  include the commitment-equality check in the VOLEitH commitment phase
  and the `chall_3` comparison in the proof-verification path.
- **Silent stack-overflow guards in indexed-Merkle and KDF circuits**
  (CIR-2). Resolved by changing these stack-guard sites to return
  integer error codes rather than silently truncating.
- **No parameter validation at the API boundary** (X-7). Resolved by
  centralising validation in `voleith_params_validate()` and calling it
  from every public entry point before any work begins.
- **Bit-level prover did not reject invalid witnesses upfront** (X-10).
  Resolved by adding a `voleith_circuit_eval` check at the top of
  `voleith_qs_prove`, bringing the bit-level discipline in line with the
  existing GF(2^8) discipline.
- **Alloc-failure and mid-prove respond gaps** (X-9). Resolved by
  cleaning up secure-zero of `d_tmp` (both heap and stack variants) in
  the prove-respond functions of both proof-system variants.

### Removed

- The variable-time GF(2^k) multiplication paths are no longer compiled
  in default builds (gated behind `-DVOLEITH_ALLOW_VARIABLE_TIME_FIELD`).
- The variable-time table-lookup AES path is no longer compiled in
  default builds (gated behind `-DVOLEITH_ALLOW_VARIABLE_TIME_AES`).

## [1.0.0] - 2026-03-22

Initial release. General-purpose VOLE-in-the-Head (VOLEitH) zero-knowledge
proof library in C, clean-room implementation from the FAEST v2.0
specification.

### Added

- Two parallel proof-system variants:
  - Bit-level (GF(2)) QuickSilver: XOR / AND / NOT gates; one VOLE slot
    per AND gate.
  - Element-level (GF(2^8)) QuickSilver: XOR / affine linear map /
    squaring / GF(2^8) multiply; one VOLE slot per multiply gate.
- Six FAEST-EM parameter sets (`em_128f`, `em_128s`, `em_192f`,
  `em_192s`, `em_256f`, `em_256s`) covering 128-, 192-, and 256-bit
  security levels with fast / small trade-offs.
- Layer 1 primitives: GF(2^k) arithmetic for k ∈ {8, 64, 128, 192, 256}
  with CLMUL acceleration and software fallback; AES-CTR PRG;
  SHAKE-128 / SHAKE-256 / SHA3-256; AES-128 / AES-256 standard encrypt
  with AES-NI dispatch.
- Layer 2-3 VOLE-in-the-Head protocol: GGM-tree vector commitment,
  ConvertToVOLE (FAEST Figure 5.2), full VOLEitH commit / open /
  reconstruct phases.
- Layer 4 QuickSilver proof system: protocol-neutral circuit definition
  API, prover, verifier, VOLEHash (FAEST Figure 4.4), and a
  non-interactive Fiat-Shamir wrapper. Two-phase split
  (`prove_commit` / `prove_respond` at `chall_1`) for hybrid protocols
  that share a Fiat-Shamir transcript with an outer classical scheme.
- Layer 5 reusable circuit building blocks:
  - `aes_circuit` / `aes_gf8_circuit`: AES-128 and AES-256 encryption
    (Canright tower-field S-box, 36 AND gates per S-box in the bit-level
    variant; one inversion witness per S-box in the GF(2^8) variant).
  - `aes_cmac_circuit` / `aes_cmac_gf8_circuit`: AES-CMAC per RFC 4493.
  - `kdf_ctr_cmac_circuit` / `kdf_ctr_cmac_gf8_circuit`: KDF-CTR(AES-CMAC)
    per NIST SP 800-108r1 Section 4.1.
  - `merkle_circuit` / `merkle_gf8_circuit`: Merkle path verification
    with two selectable internal-node-hash constructions (Davies-Meyer
    and CMAC).
  - `indexed_merkle_circuit` / `indexed_merkle_gf8_circuit`: indexed
    Merkle non-membership.
- 14 runnable example programs in `examples/` covering every circuit
  building block in both proof-system variants, including a Signal-style
  anonymous group membership credential at depth 12 (4,096 members).
- Test suite cross-validated against `faest-ref` known-answer vectors
  for the GGM tree / vector commitment, PRG, GF(2^k) field arithmetic,
  and AES circuit; plus FIPS 197 AES vectors, NIST SP 800-38A AES-ECB,
  NIST CAVP AESVS (GFSbox, KeySbox, VarKey, VarTxt), RFC 4493 AES-CMAC
  Examples 1-4, NIST CAVP CMAC vectors, and NIST CAVS 14.4 KDF-CTR
  vectors.

[1.1.0]: https://github.com/TalosLogic/libtalos_voleith/releases/tag/v1.1.0
[1.0.1]: https://github.com/TalosLogic/libtalos_voleith/releases/tag/v1.0.1
