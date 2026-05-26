# Changelog

All notable changes to libtalos_voleith are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
  Apple M1 under `docs/dudect-runs/`. Issue #86.

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
  `(-n) & 63` idiom. Issue #85.
- `voleith_secure_zero()` on Apple targets falls back to the
  volatile-pointer loop rather than calling `explicit_bzero`, which
  is no longer exposed in recent macOS SDKs. Issue #83.

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

[1.0.1]: https://github.com/TalosLogic/libtalos_voleith/releases/tag/v1.0.1
