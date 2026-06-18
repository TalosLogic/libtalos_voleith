# libtalos_voleith

A general-purpose VOLE-in-the-Head (VOLEitH) zero-knowledge proof library in C.

libtalos_voleith lets you prove knowledge of a private witness satisfying any
Boolean or byte-oriented circuit, producing non-interactive proofs that any
party can verify with the public inputs alone.  Security rests entirely on
symmetric-key primitives (AES, SHAKE-128/256), giving post-quantum security
with no elliptic curve assumptions.

The underlying protocol is extracted and generalized from the FAEST v2.0
specification (NIST PQC Round 2 additional signatures submission).  FAEST uses
VOLEitH to prove knowledge of an AES key; this library exposes the same
machinery for arbitrary circuits.

### What is a VOLEitH proof?

A VOLE-in-the-Head proof lets a prover demonstrate that they know a private
witness `w` such that `C(w, x) = 0` for some public circuit `C` and public
instance `x`, without revealing anything about `w` beyond that fact.  The
protocol works by having the prover simulate a VOLE (Vector Oblivious Linear
Evaluation) correlation "in their head", commit to it via a GGM tree, and then
run the QuickSilver line-point zero-knowledge protocol over the committed
correlation.  The Fiat-Shamir transform (instantiated with SHAKE) compresses
the resulting interactive protocol into a single non-interactive proof blob.

The result is:

- **Non-interactive**: no back-and-forth with the verifier.
- **Publicly verifiable**: anyone with the circuit and public instance can
  verify.
- **Post-quantum**: security relies only on AES and SHAKE, not on number-theoretic
  assumptions that fall to Shor's algorithm.
- **General-purpose**: any circuit expressible in XOR/AND (bit-level) or
  XOR/affine/square/multiply (GF(2^8)) can be proved.  Unlike SNARK systems, no
  trusted setup is required.

The trade-off vs. SNARKs is proof size: VOLEitH proofs are kilobytes (5-17 KB
depending on circuit and security level), not hundreds of bytes.  The benefits
are no trusted setup, post-quantum security, and prover times measured in
milliseconds.

---

## Standards and specifications implemented

| Standard | Used for |
|----------|----------|
| FAEST v2.0 (NIST PQC Round 2 additional signatures) | VOLEitH protocol, QuickSilver proof system, GGM vector commitment, ConvertToVOLE, parameter sets |
| FIPS 197 (AES) | AES-128 and AES-256 encryption - both as standard-eval primitive (for the PRG) and as Boolean / GF(2^8) circuit |
| FIPS 202 (SHA-3 / SHAKE) | SHAKE-128 and SHAKE-256 for Fiat-Shamir transform, commitment hashing, and challenge derivation |
| NIST SP 800-38A | AES-ECB validation vectors |
| NIST SP 800-108r1 | KDF in Counter Mode (KDF-CTR) using AES-CMAC as PRF |
| RFC 4493 | AES-CMAC subkey derivation, padding, and CBC-MAC chaining |
| Grøstl (SHA-3 finalist) | Grøstl-256 / Grøstl-512 hash, as standard-eval primitive and as a wide-node Merkle hash circuit |
| Hirose double-block-length (FSE 2006) | AES-256-keyed Hirose iteration, as a 32-byte / 2¹²⁸-CR Merkle node hash |
| RFC 6962 | Leaf / internal-node domain-separation prefix for the Grøstl Merkle circuit |

All protocol code is a clean-room implementation from the FAEST v2.0
specification.  No source from the FAEST reference implementation (`faest-ref`)
or any other VOLEitH library was copied; `faest-ref` is used only as a test
oracle for known-answer cross-validation.

---

## Security properties

- **Post-quantum secure.** No discrete log, no pairing, no elliptic curves.
  Security reduces to the difficulty of breaking AES and SHAKE.
- **Non-interactive.** Proofs are produced without any interaction with the
  verifier.  The Fiat-Shamir transform (instantiated with SHAKE) converts the
  interactive protocol into a standalone proof blob.
- **Publicly verifiable.** Anyone with the circuit description and public
  instance values can verify a proof.
- **Zero-knowledge.** The proof reveals nothing about the witness beyond the
  fact that a satisfying assignment exists.
- **Clean-room implementation.** All protocol code is derived from the FAEST
  v2.0 specification.  No faest-ref code was copied.

---

## Two proof system variants

The library offers two views of the same underlying protocol, suited to
different circuit styles.

- **Bit-level GF(2) QuickSilver** (`include/voleith.h`).  Each wire carries
  one bit; gates are XOR / AND / NOT.  XOR and NOT are free (linear in the
  VOLE correlation); AND gates determine proof cost.  Natural representation
  for circuits that are inherently bitwise (bitfield manipulation, comparison
  logic, custom Boolean functions).  See `examples/example_aes.c` for a
  minimal usage example.
- **Element-level GF(2⁸) QuickSilver** (`include/voleith_gf8.h`).  Each wire
  carries one byte; gates are XOR / affine linear map / squaring (all free)
  and GF(2⁸) multiply (one VOLE slot).  Byte-oriented computations (AES,
  CMAC, KDF, Merkle hashing) are about 8× more compact here than in the
  bit-level variant because witness and multiplication-gate counts shrink by
  a factor of 8.

**Use the GF(2⁸) variant for any circuit built from AES, CMAC, KDF, or
Merkle hashing.**  The bit-level variant is appropriate when the
computation is inherently bitwise and does not compose with the
byte-oriented building blocks.

A minimal GF(2⁸) usage sketch:

```c
#include "voleith_gf8.h"

voleith_gf8_circuit_t *c = voleith_gf8_circuit_new();

gf8_wire_id key_byte = voleith_gf8_add_witness(c);   // private
gf8_wire_id pub_byte = voleith_gf8_add_instance(c);  // public

gf8_wire_id xored = voleith_gf8_add_xor(c, key_byte, pub_byte); // free
gf8_wire_id prod  = voleith_gf8_add_mul(c, key_byte, pub_byte); // 1 VOLE slot
voleith_gf8_assert_zero(c, xored);

voleith_proof_t proof;
voleith_gf8_prove(&proof, &voleith_params_em_128f,
                  c, witness_bytes, instance_bytes, fs_seed, fs_seed_len);

voleith_gf8_verify(&proof, &voleith_params_em_128f,
                   c, instance_bytes, fs_seed, fs_seed_len);
```

For the parallel bit-level form (`voleith_circuit_*`,
`voleith_prove` / `voleith_verify`) and runnable side-by-side examples
exercising both variants over the same statement (AES-128 key knowledge),
see `examples/example_aes.c` and `examples/example_aes_gf8.c`.

---

## Circuit gate types and costs

| Gate | Bit-level cost | GF(2^8) cost |
|------|----------------|--------------|
| XOR / NOT | 0 AND gates | 0 mul gates |
| Affine linear map (MixColumns, basis change, etc.) | -- | 0 mul gates |
| Squaring in GF(2^8) | -- | 0 mul gates |
| AND | **1 AND gate** | -- |
| GF(2^8) multiply | -- | **1 mul gate** |

Only AND gates (bit-level) or GF(2^8) multiply gates (element-level) contribute
to proof size and prover computation.  All other operations are absorbed into
the VOLE linear homomorphism at no cost.

---

## Pre-built circuit building blocks

Both variants ship ready-to-compose sub-circuits for the common building
blocks.  Each appends gates to a caller-supplied circuit and returns wire IDs
for further composition.

| Building block | Functions | Notes |
|----------------|-----------|-------|
| AES-128 / AES-256 encryption | `aes128_circuit` / `aes256_circuit` (bit-level), `aes128_gf8_circuit` / `aes256_gf8_circuit` (GF(2⁸)) | Canright (2005) tower-field S-box. |
| AES-CMAC (RFC 4493) | `aes_cmac_circuit` / `aes_cmac_gf8_circuit` | 128- or 256-bit key. |
| KDF-CTR (NIST SP 800-108r1 §4.1) | `kdf_ctr_cmac_circuit` / `kdf_ctr_cmac_gf8_circuit` | AES-CMAC as PRF; 32-bit BE counter wired as circuit constants. |
| Merkle path (Davies-Meyer / CMAC nodes, 16-byte, 2⁶⁴ CR) | `merkle_circuit` / `merkle_gf8_circuit` | Public-dir and secret-dir variants. |
| Merkle path (Grøstl wide nodes) | `merkle_grostl_gf8_circuit` | Four node variants (`GROSTL_{256, 256_T27, 512, 512_T59}`) covering 2¹⁰⁸ to 2²⁵⁶ CR.  Public-dir and secret-dir. |
| Merkle path (any hash, hash-agnostic) | `merkle_vt_gf8_path_circuit` (+ `_secret_dir`) | Generic body parameterised by `voleith_node_hash_vt`; ships with vts for AES-DM, AES-128-CMAC, the four Grøstl variants, and Hirose-AES-256. |
| Indexed Merkle non-membership | `indexed_merkle_circuit` / `indexed_merkle_gf8_nonmember_circuit` / `indexed_merkle_grostl_gf8_nonmember_circuit` | DM/CMAC or Grøstl-node; public-dir and secret-dir. |
| Indexed Merkle non-membership (any hash, hash-agnostic) | `merkle_vt_gf8_indexed_nonmember_circuit` (+ `_secret_dir`) | Same vt coverage as the generic Merkle path. |
| Ring signatures (RSv1) | `voleith_rsv1_sign` / `_verify`, `voleith_rs_membership_build_circuit`, `voleith_ring_sig_pack` / `_unpack` | Anonymous-member signature over a published ring with optional revocation.  Parameterised over any `voleith_node_hash_vt`; composes the OWF leaf hash, the secret-dir Merkle path, and the secret-dir indexed-Merkle non-member branch into one circuit. |

For each building block, see [`docs/DESIGN.md`](docs/DESIGN.md): concrete
AND-gate / mul-slot cost formulas, the public-dir-vs-secret-dir choice,
the Grøstl `_T27` / `_T59` truncation rationale, the Hirose-AES-256
construction, the `voleith_node_hash_vt` interface, the indexed-Merkle
non-membership trust assumption (and the record-array validator that
catches the common operational foot-guns), the RSv1 protocol and
Fiat-Shamir message-binding construction, and worked gate-count
examples.

Each building block has at least one runnable example in `examples/` (see
the Examples table below).

---

## Loading external circuits (Bristol Fashion)

Besides circuits built programmatically through the API, the library can
parse circuits in **Bristol Fashion**, the boolean-circuit file format used
as the standard comparison baseline across the MPC/ZK ecosystem (AES, DES,
SHA-256, adders, comparators, multipliers, etc.).  `parsers/bristol.h`
exposes `voleith_bristol_parse_file` / `voleith_bristol_parse_buffer`, which
read a Bristol file and build a bit-level `voleith_circuit_t` that feeds
directly into `voleith_prove` / `voleith_verify`.

Because Bristol has no witness-vs-instance distinction, the caller supplies a
per-input-value role array (`WITNESS` or `INSTANCE`); outputs are returned as
bare wire IDs for the caller to constrain.  Supported gates are XOR, AND,
INV, EQ, and EQW; `MAND` and the older pre-Fashion format are detected and
rejected.  A small corpus of canonical circuits (AES-128, AES-256, 64-bit
negate, 64×64 multiply) is vendored under `tests/data/bristol/` for
cross-validation, and `examples/example_bristol_aes128.c` proves AES-128 key
knowledge from the parsed Bristol circuit.

See [`docs/DESIGN.md` → "Bristol Fashion Circuit Parser"](docs/DESIGN.md#bristol-fashion-circuit-parser)
for the format, the role-assignment and ownership model, the single-pass
parse algorithm and its validation invariants, the full error-code list, and
the test corpus.

---

## Loading native circuits (Shipshape)

For GF(2⁸) element-level circuits the library also reads **Shipshape**
(`.ship`), a native text format designed for this proof system.  Unlike
Bristol, a Shipshape file is self-describing: it declares its own `WITNESS` /
`INSTANCE` / `CONST` wires, offers the full Tier 1 gate set with sugar
(`SUM`, `FROBENIUS_K`, `MUX`, `INV`, `ASSERT_*`), supports `user/*`
subcircuit definitions and inlining, and calls a frozen Tier 2a
`stdlib/crypto/*` registry of cryptographic primitives (AES-128/256, AES-CMAC,
Grøstl-256/512) that lower to the hand-written C builders byte-for-byte.

`parsers/shipshape.h` exposes `voleith_shipshape_parse_file` /
`voleith_shipshape_parse_buffer`, which build a `voleith_gf8_circuit_t`.
`parsers/shipshape_witness.h` then generates the full witness from just the
external input (the generic Tier 1 evaluator completes gadget-internal
witnesses such as the `INV` inverses), and the result feeds
`voleith_gf8_prove_v2` / `voleith_gf8_verify_v2`.  Circuit identity is the
16-byte `voleith_gf8_circuit_fingerprint`: any two conformant parsers lower a
file to a byte-identical circuit and the same fingerprint, so a proof binds
to its `.ship` source through the metadata header with no extra machinery.

A worked corpus lives under `tests/data/shipshape/` (AES and CMAC key
knowledge, public- and secret-direction Merkle paths), and
`examples/example_shipshape_parse_prove.c` runs the full parse to witness to
prove to verify pipeline on one of them.

The additive `stdlib crypto-v2` registry extends crypto-v1 with three
hash-parametric crypto extensions (secret-direction Merkle path, indexed-Merkle
non-membership, and ring-signature membership), each selectable by node-hash
type via a bracket selector (`path_secret[H]`, `nonmember_secret[H]`,
`ring_sig/v1[H]`).  See [`docs/specs/SHIPSHAPE_SPEC.md` §7.7](docs/specs/SHIPSHAPE_SPEC.md)
for the format and [`docs/DESIGN.md`](docs/DESIGN.md) for the rationale.

Three runnable `.ship` examples exercise these constructions over the 128-bit
`hirose_fixed_32` node hash: `example_shipshape_anon_membership` (anonymous
group membership), `example_shipshape_kvac` (a membership plus indexed-Merkle
revocation credential lifecycle), and `example_shipshape_ring_sig` (a ring
signature with Fiat-Shamir message binding).  A registered witness backend can
fill each construction's witness natively: an opt-in, fail-closed prover-side
speed-up over the generic evaluator (see [`docs/DESIGN.md`](docs/DESIGN.md)).

See [`docs/specs/SHIPSHAPE_SPEC.md`](docs/specs/SHIPSHAPE_SPEC.md) for the
format and witness layout (§2.4), and [`docs/DESIGN.md`](docs/DESIGN.md) for
the design rationale.

---

## Fiat-Shamir transform

`voleith_prove` / `voleith_verify` and `voleith_gf8_prove` /
`voleith_gf8_verify` run the complete Fiat-Shamir non-interactive protocol in
one call.  The `fs_seed` parameter is a caller-supplied domain separator that
binds the proof to its application context.

A **two-phase (shared-transcript) API** is also exposed in the GF(2⁸) variant
(`voleith_gf8_prove_commit` / `_respond`, `voleith_gf8_verify_reconstruct` /
`_respond`) for hybrid protocols that interleave a VOLEitH proof with a
classical credential scheme on a shared Fiat-Shamir transcript. The split
point is at `chall_1`, the first FS challenge derived from the BAVC (GGM
tree) commitment, so the challenge can incorporate elements from an outer
protocol (e.g. a Pedersen commitment) before the proof responds to it.  See
[`docs/DESIGN.md` → "Two-Phase Fiat-Shamir"](docs/DESIGN.md#two-phase-fiat-shamir-shared-transcript-composition)
for the rationale and protocol-level pseudocode.

---

## Parameter sets

Six FAEST-EM parameter sets at three security levels (128 / 192 / 256-bit)
with two GGM-tree depth choices each: `f` ("fast", shallower tree, optimised
for prover speed) and `s` ("small", deeper tree, ~25% smaller proof at
roughly 7× more PRG work during GGM expansion).  `voleith_params_em_128f`
through `voleith_params_em_256s`.

The `f` variants are strongly recommended for most applications; pick `s`
only when proof bytes on the wire are the binding constraint.

Concrete proof sizes by parameter set (GF(2⁸) AES-128 circuit, ℓ = 216),
the `f`-vs-`s` trade-off in detail, and what "EM" names (the
leaf-commitment parameter family, not an Even-Mansour OWF; the AES-128
example proves *standard* AES-128, the FAEST-128f statement): see
[`docs/DESIGN.md` → "Parameter Sets"](docs/DESIGN.md#parameter-sets).

---

## Design and architecture

See [`docs/DESIGN.md`](docs/DESIGN.md) for the full technical design,
including protocol layering, two-variant rationale, soundness-critical paths,
parameter-set sizing trade-offs, the FAEST norm-trick analysis, the indexed
Merkle trust model, and the future-work roadmap.

## Security practices

- **Constant-time comparisons.** All secret-dependent equality checks use
  `voleith_const_memcmp()`, never `memcmp`.
- **Secure zeroing.** All contexts holding key material, VOLE correlations,
  witness data, or transient cryptographic state are zeroed on free with
  `voleith_secure_zero()` (`explicit_bzero` on POSIX, volatile loop otherwise).
- **No secret-dependent branches or table lookups** in any circuit path.  The
  AES S-box uses a purely algebraic tower-field decomposition.
- **Soundness-critical paths implemented exactly per spec.** The QuickSilver
  multiplication check, VOLEHash, and Fiat-Shamir transcript composition are
  not optimised in any way that deviates from the FAEST v2.0 specification.
- **Parameter validation at the API boundary.** Every public entry point calls
  `voleith_params_validate()` before any work.
- **Provers reject invalid witnesses upfront.** Both proof-system variants
  fail fast when the witness violates a circuit constraint, rather than
  publishing a proof the verifier would later catch.

See [`docs/DESIGN.md`](docs/DESIGN.md#design-decisions-and-non-features) for
the full security-architecture write-up.

---

## Correctness testing

One library binary contains every compiled-in backend; `ctest` runs each test
twice on every host, once with hardware dispatch (`<NAME>`) and once with the
software floor forced via `VOLEITH_FORCE_BACKEND` (`<NAME>_sw`). Both paths
are validated against the same known-answer vectors from multiple independent
sources:

- **AES primitive:** FIPS 197 (Appendices A and B), NIST SP 800-38A
  Appendix F.1, NIST CAVP AESVS (GFSbox, KeySbox, VarKey, VarTxt).
- **AES-CMAC:** RFC 4493 Examples 1-4, NIST CAVP CMAC vectors (partial /
  complete blocks, K1 / K2 paths, truncated tags).
- **KDF-CTR(AES-CMAC):** NIST CAVS 14.4 (4 vectors, AES-128 / AES-256).
- **Grøstl-256 / Grøstl-512:** NIST Grøstl ShortMsgKAT and LongMsgKAT
  known-answer vectors plus the Monte Carlo Test; the GF(2⁸) circuit is
  cross-checked against the software hash on every test run.
- **GF(2^k) arithmetic:** `faest-ref` Appendix A.1 known-answer vectors for
  every field size from GF(2^8) to GF(2^256).
- **PRG / GGM tree / vector commitment / AES circuit:** cross-validated
  against `faest-ref` test vectors at FAEST-EM-128F.
- **Proof system:** round-trip valid proofs, invalid-witness rejection,
  per-section tamper detection, cross-seed replay protection, instance
  binding, two-phase commit/respond consistency.

The full test-vector inventory is in
[`docs/DESIGN.md`](docs/DESIGN.md#correctness-testing).

---

## Getting started

### Build

Requirements: CMake 3.16+, a C17 compiler (GCC or Clang), Linux or macOS
(x86_64 or aarch64). The default build is a single-binary fat library that
compiles every available backend (AES-NI, ARMv8 Crypto, CLMUL, PMULL, plus
portable constant-time fallbacks) and selects among them at runtime based on
the host CPU. There is no per-host build step.

```sh
cmake -B build
cmake --build build -j$(nproc)
ctest --test-dir build/tests --output-on-failure
```

Build options. The first four are *lean-build opt-outs*: omit a hardware
backend to shrink the binary or target a deployment that will never see the
corresponding ISA. The portable bitsliced AES backend and constant-time
scalar field backend are always compiled as the unconditional dispatch
floor.

| Option | Default | Description |
|--------|---------|-------------|
| `VOLEITH_AES_NI`       | ON  | Compile the x86_64 AES-NI backend |
| `VOLEITH_ARMV8_AES`    | ON  | Compile the aarch64 ARMv8 Crypto AES backend |
| `VOLEITH_CLMUL`        | ON  | Compile the x86_64 CLMUL field-multiply backend |
| `VOLEITH_PMULL`        | ON  | Compile the aarch64 PMULL field-multiply backend |
| `VOLEITH_BUILD_SHARED` | OFF | Build shared library (`libtalos_voleith.so`/`.dylib`) in addition to the static library |

A lean build deployed to a hardware-capable host emits a one-shot stderr
notice naming the missing backend and the configure flag that re-enables
it (suppressible with `VOLEITH_QUIET=1` in the environment). The dispatch
machinery, lean-build trade-offs, the `VOLEITH_FORCE_BACKEND` testing
override, and the constant-time guarantees across every compiled-in
backend are documented in
[`docs/DESIGN.md` → Runtime Hardware Dispatch](docs/DESIGN.md#runtime-hardware-dispatch-single-binary-fat-builds).

### Minimal example

Prove and verify knowledge of an AES-128 key satisfying `AES(k, plaintext) = ciphertext`:

```c
#include "voleith_gf8.h"
#include "circuits/aes_gf8_circuit.h"

int main(void) {
    voleith_gf8_circuit_t *c = voleith_gf8_circuit_new();

    gf8_wire_id key[16], pt[16], ct_expected[16], ct[16];
    for (int i = 0; i < 16; i++) key[i]         = voleith_gf8_add_witness(c);
    for (int i = 0; i < 16; i++) pt[i]          = voleith_gf8_add_instance(c);
    for (int i = 0; i < 16; i++) ct_expected[i] = voleith_gf8_add_instance(c);

    aes128_gf8_circuit(c, key, pt, ct);
    for (int i = 0; i < 16; i++)
        voleith_gf8_assert_equal(c, ct[i], ct_expected[i]);

    uint8_t witness[16 + 200];   /* key + AES inversion witnesses */
    uint8_t instance[32];        /* plaintext || ciphertext */
    /* ... populate witness and instance ... */

    voleith_proof_t proof;
    const uint8_t fs_seed[] = "my-application-domain-v1";
    voleith_gf8_prove(&proof, &voleith_params_em_128f, c,
                      witness, instance, fs_seed, sizeof(fs_seed) - 1);

    int ok = voleith_gf8_verify(&proof, &voleith_params_em_128f, c,
                                instance, fs_seed, sizeof(fs_seed) - 1);

    voleith_proof_free(&proof);
    voleith_gf8_circuit_free(c);
    return ok == 0 ? 0 : 1;
}
```

See `examples/example_aes_gf8.c` for the complete runnable version including
witness construction with `aes_gf8_build_witness`.

---

## Examples

Runnable example programs in `examples/` exercise every circuit building
block in both proof-system variants, plus the Bristol Fashion parser:

| Example | What it proves |
|---------|----------------|
| `example_aes.c` / `example_aes_gf8.c`             | Knowledge of an AES-128 / AES-256 key |
| `example_aes_cmac.c` / `example_aes_cmac_gf8.c`   | Knowledge of a CMAC key producing a given tag |
| `example_kdf.c` / `example_kdf_gf8.c`             | Correct KDF-CTR(AES-CMAC) derivation from a secret key |
| `example_merkle.c` / `example_merkle_gf8.c`       | Membership of a secret leaf at a public position in a Merkle tree (AES-DM / CMAC node hash) |
| `example_merkle_grostl_gf8.c`                     | The same, with a wide-node Grøstl hash, plus prove/verify timing |
| `example_merkle_hirose_gf8.c`                     | The same at 2¹²⁸ CR via Hirose-AES-256 fixed-32 leaf through the vt-driven `merkle_vt_gf8_path_circuit`, plus prove/verify timing - direct apples-to-apples cost comparison against the AES-DM and Grøstl Merkle examples |
| `example_indexed_merkle.c` / `example_indexed_merkle_gf8.c` | Non-membership of a value in an indexed Merkle tree |
| `example_indexed_merkle_grostl_gf8.c`             | Non-membership with wide-node Grøstl-256 T27 nodes (2¹⁰⁸ collision resistance) |
| `example_kvac_pq.c` / `example_kvac_pq_gf8.c`     | Signal-style anonymous group membership credential (AES-DM trees) |
| `example_kvac_pq_gf8_depth12.c`                   | The above at depth 12 (4,096 group members) |
| `example_kvac_pq_grostl_gf8.c`                    | The same KVAC statement over Grøstl-256 T27 trees with a hidden leaf index (secret-dir) |
| `example_kvac_pq_grostl_gf8_depth12.c`            | The Grøstl KVAC at depth 12, with prove/verify timing |
| `example_hirose_gf8.c`                            | Knowledge of (G, H, M) producing a given Hirose-AES-256 iteration output (the bare iteration primitive) |
| `example_hirose_leaf_gf8.c`                       | Knowledge of a 32-byte preimage under the Hirose-AES-256 fixed-32 leaf hash (the leaf side of the Hirose Merkle node vt) |
| `example_hirose_inode_gf8.c`                      | Knowledge of children (L, R) under the Hirose-AES-256 inode hash (the inode side of the Hirose Merkle node vt) |
| `example_bristol_aes128.c`                        | AES-128 key knowledge from a circuit loaded via the Bristol Fashion parser |

Each example builds the circuit, generates a valid witness, produces a proof,
verifies it, and prints circuit statistics (AND-gate count, ell, proof size)
plus PASS/FAIL.  After building, run them from the build directory:

```sh
./build/examples/example_aes_gf8
./build/examples/example_kvac_pq_gf8_depth12
```

### Prove / verify benchmarking

Three examples (`example_merkle_gf8`, `example_merkle_hirose_gf8`, and
`example_merkle_grostl_gf8`) include a small wall-clock benchmark in addition
to the correctness check.  They run a few warmup iterations, then time 25
prove and 100 verify calls, and report min / median / mean / max in
milliseconds.  All three use the same depth, leaf index, and benchmark
methodology, so running all three on the same host gives a direct
apples-to-apples cost comparison across the three node-hash families.
To minimise scheduler noise, pin the run to a single core with `taskset(1)`:

```sh
taskset -c 0 ./build/examples/example_merkle_gf8
taskset -c 0 ./build/examples/example_merkle_hirose_gf8
taskset -c 0 ./build/examples/example_merkle_grostl_gf8
```

The minimum is the cleanest estimate of intrinsic cost (timing noise on a
loaded OS is one-sided slow); the median is the typical run.  Quiesce other
CPU-heavy processes first.  Disabling CPU frequency scaling
(`cpupower frequency-set -g performance` on Linux) and SMT/Hyper-Threading
sibling load further reduces variance if you need it.

See [docs/DESIGN.md → Performance Benchmarking](docs/DESIGN.md#performance-benchmarking)
for the methodology and for the pattern to instrument your own circuits the
same way.

---

## References

Protocol specification (FAEST v2.0), academic papers (VOLEitH, QuickSilver,
half-tree, Hirose, Grøstl), standards documents (FIPS 197, FIPS 202, NIST SP
800-38A / 800-108r1, RFC 4493, RFC 6962), and reference implementations
(`faest-ref`, used as a test oracle only): see
[`docs/DESIGN.md` → References](docs/DESIGN.md#references).

The "Standards and specifications implemented" table near the top of this
README lists every standard the library implements, with a one-line role
description per standard.

---

## License

This project is licensed under the GNU Affero General Public License,
version 3.0 (AGPL-3.0-only). See [LICENSE](LICENSE) for the full text.

This library is a clean-room implementation derived from the FAEST v2.0
specification.  The FAEST reference implementation (`faest-ref`, MIT licensed)
was used only as a test oracle to generate known-answer vectors; no source code
was copied from it.

---

## Contributing and Issues

Bug reports and security issues should be filed on the project repository.
Security-sensitive reports should be sent privately to the maintainers before
public disclosure.
