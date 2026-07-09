# Changelog

All notable changes to libtalos_voleith are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.9.0] 2026-07-09

Erasure coding: Reed-Solomon storage and RLNC transport codecs over a new
GF(2^16) core field, plus the native GF(2^16) prover, the in-circuit RLNC
membership and rank-certificate statements, the confidential-RLNC codec and
encoding proof, and the RS chunk membership certificates / storage use case.

### Added

GF(2^16) core field

- `core/field16.{c,h}`: GF(2^16) element arithmetic over poly `0x1100B`
  (x^16 + x^12 + x^3 + x + 1). `voleith_gf16_mul` with CLMUL / PMULL / constant-
  time software paths; `voleith_gf16_inv` via a fixed Fermat addition chain;
  2-byte little-endian byte conversions. Validated by `tests/test_field16.c`
  (exhaustive inverse sweep, distributivity, KATs).

Shared linear-algebra core and plaintext codecs

- `erasure/` module (sibling to `vole/`), `erasure/erasure.h` common types and
  field selector (`GF8` / `GF16`).
- `erasure/matrix.{c,h}`: systematic Vandermonde and Cauchy generator matrices
  over GF(2^8) and GF(2^16), submatrix select, and Gaussian-elimination solve
  (singular submatrices return an error code, not a crash).
- `erasure/rs.{c,h}`: systematic `(n, k)` Reed-Solomon encode and decode /
  repair over GF(2^8) from any k of n chunks. KATs from a Jerasure 2.0 +
  GF-Complete oracle (poly 0x11B, Cauchy), generated once and checked in, never
  linked (`tests/test_erasure_rs.c`, `tools/gen_rs_kat/`).
- `erasure/rlnc.{c,h}`: RLNC encode / recode / decode over GF(2^16); coded
  symbols carry their coefficient vector and a generation id; decode once the
  coefficient matrix reaches rank k, with rank-progress reporting. Oracle KATs
  at w=16 (`tests/test_erasure_rlnc.c`, `tools/gen_rlnc_kat/`).

Native GF(2^16) prover and in-circuit RLNC

- alpha16 subfield-embedding tables for lambda in {128, 192, 256} in
  `core/field.{c,h}`, derived clean-room by an in-repo generator
  (`tools/gen_alpha16/`) with a SageMath cross-check; homomorphism-validated
  (`tests/test_gf16_embed.c`).
- `proof/gf16_prover.c` / `gf16_verifier.c` / `gf16_circuit.c` /
  `gf16_proof.{c,h}` (+ `gf16_circuit_fingerprint.{c,h}`): native element-level
  GF(2^16) QuickSilver prover / verifier (one GF(2^16) element per VOLE slot)
  and the non-interactive Fiat-Shamir wrapper with the two-phase commit /
  respond split at chall_1, ported from the GF(2^8) stack.
- `circuits/rlnc_gf16_circuit.{c,h}`: in-circuit generation-membership statement
  `y = c . X` (public coefficients `c`, witnessed source matrix `X`) plus a
  rank / sufficiency assertion, on the native gf16 prover. Examples
  `example_rlnc_gf16` and `example_rlnc_gf16_private_vector`.

RS chunk membership certificates and storage use case

- `erasure/rs_dataset.{c,h}`: dataset metadata, its canonical serializer /
  parser (design 6.10), and the metadata-to-`R` binding
  `R = H(merkle_root || H(serialize(metadata)))` with `compute_R` / `verify_R`.
- `circuits/rs_chunk_cert_circuit.{c,h}`: FWK-blinded chunk membership circuit,
  public-index and secret-index (indexed-consistency) variants.
- `proof/rs_chunk_cert_proof.{c,h}`: non-interactive membership certificate
  (Fiat-Shamir wrapper) with the two-layer dataset check (recompute `R`, then
  verify against `merkle_root`); `prove` / `verify` and `_secret_dir` forms.
- `erasure/rs_membership.{c,h}`: plaintext leaf / tree / sibling-path / digest
  helpers for the FWK-blinded chunk tree.
- `erasure/rs_retriever.{c,h}`: retriever sufficiency flow (verify, dedup by
  recovered index, "have I `k` distinct yet", decode); index-recovery-by-trial.
- `erasure/rs_consistency.{c,h}`: capability-3 plaintext consistency check
  (re-encode and compare digests + whole-file digest).
- `erasure/rs.{c,h}`: healer decode-once / encode-specific-rows entry points
  (`voleith_rs_encode_row` / `voleith_rs_encode_indices`).
- `erasure/rs_wire.{c,h}`: dataset descriptor and per-chunk header wire
  serializers (design 6.10). Descriptor = `merkle_root || serialize(metadata)`;
  chunk header = `version || flags || R || cert_len || certificate ||
  [possession_tag]`. The certificate is length-prefixed (4-byte BE) so the
  reserved possession tail stays parseable; the reserved tail is defined and
  skipped (forward-compat). Header parse takes `cr_profile` as an input (a 32-
  vs 64-byte `R` is indistinguishable from the bytes; the descriptor pins it).
- Examples: `example_rs_chunk_membership`, `example_rs_heal`, `example_rs_wire`.

Confidential RLNC and the rank certificate

- `circuits/rlnc_gf16_cert_circuit.{c,h}`: knowledge-of-inverse rank certificate
  (`C . C^{-1} = I`, witness `C` and `C^{-1}`), the in-circuit counterpart of
  `voleith_rlnc_gf16_coeffs_full_rank`.
- `erasure/rlnc_confidential.{c,h}` (`voleith_confrlnc_*`): paper-2
  confidential-RLNC codec (secret-coefficient encode, `T` split/join, secret
  partial permutation); weak/computational security, documented as such. The
  secret-input path (matrix inverse, permutation apply, key generation) is
  constant-time, verified with the dudect timing harness (`docs/dudect-runs/`).
- `circuits/permutation_gf16_circuit.{c,h}` (`voleith_perm_gf16_circuit`):
  AS-Waksman secret-permutation gadget, one mul gate per 2x2 switch.
- `circuits/rlnc_confidential_gf16_circuit.{c,h}`: confidential-encoding
  correctness statement on the native gf16 prover. Example
  `example_rlnc_confidential`.
- `circuits/rlnc_gf16_circuit.{c,h}`: both-secret (data-blind) membership
  orientation `Y = c . X`.

## [1.8.0] 2026-07-02

Composable ring signatures (V2/V3/V4). One `voleith_rs_*` superset config
where the linkable nullifier, attribute predicates, and claimable commitment
are independently-enableable modules over the shared membership core. V1
(`voleith_rsv1_*`, `"VRS1"`) stays frozen.

### Added

- `proof/rs_gf8.{c,h}`: composable `voleith_rs_config_t` (embeds the V1
  membership config + V2 nullifier/spent-set, V3 attribute schema, V4
  commitment), module bitmap, validator, and the composable cfg-fingerprint
  (`"VOLEitH-RSc-cf"` domain tag).
- `circuits/rs_gf8_circuit.{c,h}`: `voleith_rs_build_circuit` superset builder
  emitting each enabled module in canonical wire order; `voleith_rs_layout_t`.
- `circuits/rs_leaf_gf8_circuit.{c,h}`: leaf = OWF(sk || attributes).
- V2 nullifier: in-circuit `T = AES-CMAC(sk, scope)`; optional spent-set IMT
  non-membership on `T`. V2.LINK helpers `voleith_rs_nullifier_equal` /
  `voleith_rs_nullifier`.
- V2 nullifier width tracks the tree's collision-resistance strength
  (`voleith_rs_nullifier_bytes`): 16-byte AES-CMAC for <= 128-bit-CR trees,
  32-byte SP 800-108 KDF-CTR-CMAC (L = 256) for 256-bit-CR trees, so the
  nullifier is never the weakest link (RS-3).
- V3 attributes: per-field `EQ` / `RANGE` predicates (public per-signature
  bounds) plus a `custom_predicate` escape hatch.
- V4 commitment: claimable `C = H(id || rand)`; `voleith_rs_claim_produce` /
  `voleith_rs_claim_verify`.
- Composed Fiat-Shamir seed (`voleith_rs_compute_fs_seed`, version-tagged
  module-bitmap absorb) and sign/verify (`voleith_rs_sign` / `_verify`).
- `"VRSC"` serialization envelope (`voleith_rs_sig_pack` / `_unpack`, 41-byte
  header binding cfg + params fingerprints).
- Four examples: `example_rs_{v2_linkable,v3_attribute,v4_claimable,composite}_gf8`.
- `voleith_node_hash_vt.leaf_block_bytes`: single-compression leaf-preimage
  capacity, so fixed-input OWF vts carry sk || attributes up to the block
  boundary (hirose-fixed32 = 32, grostl256_fixed = 64, grostl512_fixed = 128).
- Docs: `docs/RING_SIGNATURES_DESIGN.md` (RSv1 + composable V2/V3/V4 design).
- `tools/gen_vole_hash_kats.py`: independent VOLEHash KAT generator derived from
  FAEST v2.0 Fig 4.4; reproduces the existing faest-ref vectors plus nine new
  boundary-case vectors (ell = 8 / λ / 1000) for λ = 128/192/256.
- `test_assert_product_forgery` plus a test-only prover seam
  (`proof/gf8_prover_internal.h`, `*_unchecked`) that drives the verifier with
  an inconsistent witness, regression-pinning the `assert_product`
  `embed(val_c)` soundness invariant (S-6).
- Docs: DESIGN.md security sections expanded (constant-time compiler boundary,
  legacy-verify trade-off, vc-params bounds, GF(2^8)-verifier defense-in-depth,
  assert_product forgery test).
- `test_rs_revoked`: dedicated revocation-branch negative (non-revoked signer
  accepted; tampered revocation root, wrong adjacent record, and a revoked
  member rejected at lookup), closing the optional gap noted in RSV234_ASSESSMENT.
- `VOLEITH_SANITIZE` CMake option: build the library, tests, and examples with
  AddressSanitizer + UndefinedBehaviorSanitizer (GCC or Clang); see README
  "Sanitizer builds".

### Changed

- Two-phase API: `chall_1` length single-sourced through `voleith_chall1_bytes()`
  (was a hardcoded `5*nb+8` in eight call sites); the respond-function headers
  now state the exact-length / out-of-bounds-read contract (H-5).
- dudect harness: x86_64 timer now issues `_mm_lfence()` after `__rdtscp()`,
  matching the aarch64 ISB serialisation and removing a sub-cycle measurement
  bias that produced marginal `byte_combine_192/256` false positives on
  uncontrolled hosts; documented the quiesced-host requirement for
  release-quality x86_64 verdicts.

### Security

- (High): fixed-input node-hash leaves (`hirose_fixed32`,
  `grostl256_fixed`, `grostl512_fixed`; present since their respective
  releases, the last in 1.7.0) silently consumed only their single-compression
  block, dropping any higher bytes of the preimage. For an indexed-Merkle
  record (`value || next_value || next_index`, value = node_bytes) this left
  `next_value` unbound by the leaf hash, so a prover could substitute it to
  forge a non-membership proof (non-revocation / non-spent). Reachable in
  released configurations: `example_ring_sig_v1_revocable_gf8` shipped with
  `hirose_fixed32` over a revocation IMT. Fixed: `leaf_hash` /
  `leaf_build_witness` now return -1 over capacity (`hirose_fixed32` 32,
  `grostl256_fixed` 64, `grostl512_fixed` 128) instead of truncating;
  wide-record IMTs require a variable-leaf vt, and the revocable example
  switched to variable-leaf Hirose.
- (Clean-room): reimplemented `proof/vole_hash.c` (VOLEHash) from FAEST v2.0
  Figure 4.4, removing a labeled port of MIT `faest-ref/universal_hashing.c`
  that violated the clean-room-only rule. No wire-format change (S-1).
- (Hardening): the GF(2^8) QuickSilver verifier now bounds every wire /
  constraint reference and sizes its key buffers with the overflow-checked
  two-argument `calloc`, staying memory-safe on malformed circuits and 32-bit
  size overflow even if the boundary validator is bypassed (H-3).
- (Hardening): `voleith_vc_params_init` rejects `w_grind` outside `[0, λ)` and
  per-vector depth `k > VOLEITH_MAX_K`, mirroring `voleith_params_validate`, so
  direct callers cannot reach a negative shift or oversized allocation (S-3).
- (Portability): `voleith_secure_zero` uses `memset_s` on macOS (which lacks
  `explicit_bzero`) instead of degrading to the volatile-loop fallback (H-1).
- Documented `VOLEITH_LEGACY_VERIFY` as security-relevant (the legacy verify
  path skips header circuit/params identity binding) and the GCC/Clang-only
  scope of constant-time field arithmetic, in the README, DESIGN.md, and the
  CMake option help string (H-2, H-4).

## [1.7.0] 2026-06-25

### Added

- `voleith_node_hash_grostl256_fixed` / `_grostl512_fixed`: fixed-input
  single-compression Grøstl node-hash vts (32B/2^128 CR, 64B/2^256 CR). Full
  collision resistance at single-compression cost (1,920 / 5,376 inode
  S-boxes): drops Merkle-Damgård padding, with IV-based leaf/inode domain
  separation instead of a prefix byte.
- `core/grostl.{c,h}`: `voleith_grostl{256,512}_compress_node`, the single-block
  compression-plus-output-transform oracle backing the new vts.
- `circuits/grostl_gf8_circuit.{c,h}`: `grostl{256,512}_gf8_node_circuit` plus
  `*_node_invin_bytes` / `*_node_build_witness`, siblings of the full-hash
  builders (the frozen full-hash entry points are unchanged).
- Shipshape crypto-v2: registered `grostl_256_fixed` (type id 8) and
  `grostl_512_fixed` (type id 9) as node-hash types, usable as the bracket
  selector in all three parametric constructions (`merkle/path_secret`,
  `indexed_merkle/nonmember_secret`, `ring_sig/v1`). Append-only; ids 0-7
  unchanged. Regenerates the frozen `parsers/shipshape_registry_table.c`.
- `circuits/range_gf8_circuit.{c,h}`: `assert_in_range_gf8(value, low, high,
  n_bytes)`, a bounded-range primitive (`low <= value <= high`, inclusive,
  little-endian byte vectors) composed of existing Tier 1 gates. Layer 4 C
  builder, no Shipshape opcode; pre-positions ring-sig V3.

### Deprecated

- Grøstl node-hash vts `grostl256`, `grostl256_t27`, `grostl512`,
  `grostl512_t59`: superseded by `grostl*_fixed` (same-or-lower cost at full
  CR). Retained as frozen wire-format commitments, not recommended for new
  circuits.

## [1.6.0] 2026-06-18

Adds the Shipshape (`.ship`) native GF(2^8) circuit toolchain: a text format
for arithmetic circuits that lowers directly to `voleith_gf8_circuit_t`, a
generic witness generator, and the parse to witness to prove to verify
pipeline. Self-describing inputs (named WITNESS / INSTANCE / CONST wires),
Tier 1 gate set with sugar, `user/*` subcircuit inlining, and a frozen Tier
2a `stdlib/crypto/*` registry. See docs/specs/SHIPSHAPE_SPEC.md and
docs/DESIGN.md.

### Added

- `circuits/aes_gf8_circuit.{c,h}`: split AES-128 GF(2^8) builders
  `aes128_gf8_expand_key` / `aes128_gf8_encrypt_rk` (plus witness helpers and
  the `AES128_GF8_KS_INVIN_BYTES` / `AES128_GF8_ENC_INVIN_BYTES` constants),
  bringing AES-128 to parity with AES-256. `aes128_gf8_circuit` is now a thin
  wrapper; its fingerprint is unchanged (regression-pinned).
- `proof/gf8_circuit.{c,h}`: `voleith_gf8_circuit_gate_count` (produced,
  non-input wires); the Shipshape parser enforces `MAX_GATES` against it via a
  new `budget_gates` check at each gate-emission site. `voleith_gf8_circuit_set_limits`
  arms optional incremental wire/gate ceilings (0 = unlimited, default) that
  abort a bulk emitter the moment a ceiling is crossed; the parser uses it so
  Tier 2a registry bodies are bounded as they emit, not after.
- `tools/shipshape_registry_freeze`: regenerates the checked-in
  `parsers/shipshape_registry_table.c` (FQN, kind, signature, parameter
  bounds, body hashes) from the C builders; output is deterministic. A fresh
  checkout builds without running it.
- `parsers/shipshape.{c,h}`: Shipshape v1 parser. `voleith_shipshape_parse_file`
  / `voleith_shipshape_parse_buffer` / `voleith_shipshape_parsed_free`,
  returning the built circuit, a file-order declaration table, and a region
  side table. Validates the `.shipshape 1` magic on every parse; the
  filename is never trusted.
- Tier 2a registry: `stdlib/crypto/*` calls inline the hand-written C
  builders (AES, CMAC, Grostl) with byte-identical structure, gated by the
  exact `stdlib crypto-v1` header line.
- `tests/test_shipshape_parser.c`: entry / limit / lexer / header /
  declaration / gate / subcircuit / registry coverage, one malformed input
  per error code.
- `tests/test_shipshape_conformance.c`: ISA 5.5 cross-parser corpus. Every
  sugar form, literal encoding, region placement, and gate-ordering edge
  case checked against the fingerprint of the hand-built circuit, plus
  parse-then-reparse idempotence. Disagreement is a release-blocker.
- `parsers/shipshape_witness.{c,h}`: generic Tier 1 witness generator.
  `voleith_shipshape_witness_gen` completes the full witness array from the
  external input alone, evaluating the lowered circuit and filling
  gadget-internal `INV` inverses; reproduces `circuits/*_build_witness`
  byte-for-byte. See docs/specs/SHIPSHAPE_SPEC.md §2.4.
- `fuzz/`: libFuzzer harnesses for the Shipshape and Bristol parser entry
  points (`-DVOLEITH_FUZZ=ON`, Clang) with a seed corpus.
- `tests/data/shipshape/` + `examples/example_shipshape_parse_prove.c`:
  example `.ship` corpus (AES / CMAC key knowledge, public- and
  secret-direction Merkle paths) and an end-to-end parse / witness / prove /
  verify program.
- Equivalence and regression suites: adversarial corpus, registry
  equivalence (FIXED entries and the parametric grid), witness-vs-builder
  equivalence, and a prove/verify round-trip on parsed circuits.
- `stdlib crypto-v2` registry (additive over crypto-v1): adds a bracket
  node-hash-type selector and the node-hash-type registry
  (`parsers/shipshape_node_hash_types.{c,h}`), supporting `aes_dm`,
  `aes_cmac_128`, four Grostl variants, and Hirose as selector values.
- Three hash-parametric secret-direction crypto extensions (phase 1):
  `stdlib/crypto/merkle/path_secret[H]`,
  `stdlib/crypto/indexed_merkle/nonmember_secret[H]`, and
  `stdlib/crypto/ring_sig/v1[H]`; each inlines the existing C vt builders
  selected by node-hash type, with the region name serving as the
  witness-backend dispatch key. See docs/specs/SHIPSHAPE_SPEC.md §7.7 and
  docs/DESIGN.md.
- Tier 2a witness dispatch: opt-in native witness backends for the crypto-v1
  AES / CMAC / Grostl entries and the three crypto-v2 constructions
  (`voleith_shipshape_witgen_register_*`), filling a region's internal
  inverses in one `circuits/*_build_witness` call instead of the per-wire
  scan. Prover-side, fail-closed, byte-identical to the generic evaluator.
- `.ship` crypto-v2 examples over `hirose_fixed_32`:
  `example_shipshape_anon_membership` (secret-dir Merkle membership),
  `example_shipshape_kvac` (membership + indexed-Merkle revocation lifecycle),
  and `example_shipshape_ring_sig` (`ring_sig/v1` with Fiat-Shamir message
  binding).

### Changed

- `.gitlab-ci.yml`: new `registry-diff` job rebuilds the freeze tool,
  regenerates the table, and fails on any divergence from the checked-in
  copy; `fuzz-short` (MR pipelines) and a scheduled `fuzz-long` run the
  parser fuzz harnesses.
- `CMakeLists.txt`: parser, registry, and witness-generator sources compiled
  into `voleith_core`; the freeze tool and fuzz harnesses build as opt-in
  targets.
- `docs/DESIGN.md`: reviews the published quantum collision attacks on
  Hirose-AES-256 (Baek/Cho/Kim 2022 full-round free-start; round-reduced ToSC
  2021/2024) and why `cr_bits = 128` holds as a classical bound. See
  "Hirose-AES-256 double-block-length hash".

## [1.5.0] 2026-06-11

Adds a Bristol Fashion circuit parser: load boolean circuits in the
standard MPC/ZK file format and prove/verify them through the existing
bit-level pipeline. New `parsers/` subdirectory; no public API or
wire-format change to the proof system. See DESIGN.md "Bristol Fashion
Circuit Parser" for the format, role model, parse algorithm, and error
codes.

### Added

- `parsers/bristol.{c,h}`: Bristol Fashion parser building a bit-level
  `voleith_circuit_t`. `voleith_bristol_parse_file` /
  `voleith_bristol_parse_buffer` / `voleith_bristol_parsed_free`, with a
  per-input-value `WITNESS`/`INSTANCE` role array and returned input/output
  wire-id arrays. Supports XOR/AND/INV/EQ/EQW; rejects MAND and the older
  pre-Fashion format.
- `tests/test_bristol_parser.c`: synthetic round-trip, per-gate sweep,
  one malformed buffer per error code, role-count mismatch, AES-128/256
  AND-gate-count and FIPS-197 evaluation parity, neg64 and mult2_64
  arithmetic circuits, and a full prove/verify on the parsed AES-128 circuit.
- `examples/example_bristol_aes128.c`: AES-128 key-knowledge proof from a
  parsed Bristol circuit under FAEST-EM-128f.
- `tests/data/bristol/`: vendored Bristol Fashion corpus (AES-128, AES-256,
  neg64, mult2_64) with attribution README for cross-validation.

### Changed

- `CMakeLists.txt`: new `VOLEITH_PARSERS_SOURCES`, `parsers/` added to the
  core include path and compiled unconditionally into `voleith_core`. No
  new build option.

## [1.4.1] 2026-06-09

Collapses the previous per-ISA library variants (`libvoleith_sw.a`,
`libvoleith_aesni.a`, `libvoleith_clmul.a`, `libvoleith_aesni_clmul.a`,
and the parallel ARMv8 set) into a single `libtalos_voleith` artefact
that detects host CPU features at first use and routes through a
function-pointer dispatch table to the highest-priority compiled-in
backend. No public API or wire-format change; existing proofs verify
unchanged. See DESIGN.md "Runtime Hardware Dispatch (Single-Binary Fat
Builds)" for the full design, lean-build opt-outs, and test profile.

### Added

- `core/cpu.{c,h}`, `core/cpu_x86.c`, `core/cpu_aarch64.c`,
  `core/cpu_generic.c`: per-architecture CPU feature probe with cached
  bitmask, exposed via `voleith_cpu_features()`. Bits are stable across
  versions. `voleith_cpu_features_override()` is provided for tests.
- `VOLEITH_FORCE_BACKEND` environment variable: comma-separated
  `domain:value` list that strips feature bits so dispatch routes to a
  specific backend. Recognised values cover all three domains. Unknown
  values abort with a diagnostic.
- `VOLEITH_QUIET=1` suppresses the lean-build mismatch notice.
- `core/aes_dispatch.h`, `core/field_dispatch.h`, `core/grostl_dispatch.h`:
  internal ops-table types and per-backend extern declarations.
- `core/aes_aesni.{c,h}`, `core/aes_armv8.{c,h}`, `core/aes_ct64_ops.c`,
  `core/field_clmul.c`, `core/field_pmull.c`, `core/field_scalar.c`,
  `core/grostl_aesni.c`, `core/grostl_armv8.c`, `core/grostl_soft.c`,
  `core/grostl_core.h`: per-backend translation units, each gated by
  `VOLEITH_HAVE_*` macros and compiled with ISA flags scoped to the
  single TU via `set_source_files_properties`.
- `voleith_aes_backend()`, `voleith_aes_backend_name()`,
  `voleith_grostl_backend_name()`: diagnostic introspection of which
  backend the dispatcher selected.
- `tests/test_cpu_dispatch.c`, `tests/test_cpu_features.c`,
  `tests/test_lean_build_warning.c`: coverage for the probe, dispatch
  tables, override parsing, and mismatch-notice path.

### Changed

- `core/aes.c`, `core/field.c`, `core/grostl.c` reduced to public
  forwarders + dispatch-init only. Per-backend implementations moved
  to their own TUs. The forwarder branch on the atomic ops-table
  pointer adds one acquire load + one indirect call per public call.
- `CMakeLists.txt`: drops the variant matrix; builds one
  `voleith_core` (static) + optional `voleith_core_shared` containing
  every compiled-in backend. Build options `VOLEITH_AES_NI`,
  `VOLEITH_CLMUL`, `VOLEITH_ARMV8_AES`, `VOLEITH_PMULL` are now
  lean-build opt-outs (omit the corresponding backend TU); the
  bitsliced AES and scalar field backends are always compiled as the
  unconditional dispatch floor.
- `tests/CMakeLists.txt`: every `voleith_add_test` registration now
  produces two ctest entries, `<NAME>` (hardware-dispatched) and
  `<NAME>_sw` (`VOLEITH_FORCE_BACKEND=aes:bitsliced,field:scalar,grostl:soft`
  in the environment). Validates both paths on every host without
  rebuilds.
- `include/voleith.h` pulls in `cpu.h` so the feature probe is part
  of the public umbrella header.
- `proof/proof_header.h` documents the AES backend selection priority
  in the `aes.h` header comment for cross-reference.

### Security

- All three compiled-in AES backends and both field backends remain
  constant-time. The dispatch decision is made on a data-independent
  feature bitmask; the function pointer selected is invariant for
  process lifetime, so secret data never influences which backend
  handles it.
- On a lean build deployed to a hardware-capable host, the dispatch
  init emits a one-shot stderr notice naming the missing backend, the
  expected slowdown, and the configure flag that re-enables it.
  Intended as a misconfiguration backstop for accidental lean-build
  releases.

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
