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

### Bit-level: GF(2) QuickSilver  (`include/voleith.h`)

Each wire carries one bit.  Gates are XOR, AND, and NOT.  XOR and NOT gates
are free (linear in the VOLE correlation); AND gates determine proof cost.
This is the natural representation for bit-manipulation circuits.

```c
#include "voleith.h"

voleith_circuit_t *c = voleith_circuit_new();

wire_id key_bit  = voleith_circuit_add_witness(c);  // private
wire_id pub_bit  = voleith_circuit_add_instance(c); // public

wire_id a = voleith_circuit_add_and(c, key_bit, pub_bit); // costs 1 AND slot
wire_id x = voleith_circuit_add_xor(c, a, key_bit);       // free
voleith_circuit_assert_zero(c, x);

voleith_proof_t proof;
voleith_prove(&proof, &voleith_params_em_128f,
              c, witness_bits, instance_bits, fs_seed, fs_seed_len);

voleith_verify(&proof, &voleith_params_em_128f,
               c, instance_bits, fs_seed, fs_seed_len);

voleith_proof_free(&proof);
voleith_circuit_free(c);
```

### Element-level: GF(2^8) QuickSilver  (`include/voleith_gf8.h`)

Each wire carries one byte (an element of GF(2^8)).  Gates are XOR (free),
affine linear maps (free), squaring (free), and GF(2^8) multiplication (costs
one VOLE slot).  Byte-oriented computations -- AES, CMAC, KDF, Merkle hashing
-- are approximately 8x more compact here than in the bit-level variant because
witness and multiplication-gate counts shrink by a factor of 8.

**Use the GF(2^8) variant for any circuit built from AES, CMAC, KDF, or Merkle
hashing.**  The bit-level variant is appropriate for circuits that are
inherently bitwise (bitfield manipulation, comparison logic, custom Boolean
functions) and do not compose with the byte-oriented building blocks.

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

Both variants include ready-to-compose sub-circuits for the following
operations.  Each appends gates to a caller-supplied circuit and returns wire
IDs for further composition.

### AES encryption

| Function | Key | Output | Bit-level AND gates | GF(2^8) mul slots |
|----------|-----|--------|---------------------|-------------------|
| `aes128_circuit` / `aes128_gf8_circuit` | 128 bits | 128 bits | 7,200 | 200 |
| `aes256_circuit` / `aes256_gf8_circuit` | 256 bits | 128 bits | 9,936 | 276 |

The S-box is implemented using the Canright (2005) tower-field decomposition
over GF(((2^2)^2)^2), giving 36 AND gates per S-box in the bit-level variant
and one inversion witness per S-box in the GF(2^8) variant.  Key schedule S-box
calls are included in the counts above (160 + 40 for AES-128; 224 + 52 for
AES-256).

### AES-CMAC (RFC 4493)

| Function | Key |
|----------|-----|
| `aes_cmac_circuit` / `aes_cmac_gf8_circuit` | 128 or 256 bits |

Cost: `(n_cbc_blocks + 1) * AES_cost` AND/mul gates.  Subkey derivation uses a
linear shift and conditional XOR at zero gate cost; only the CBC-MAC AES
encrypt calls contribute to proof cost.  Both K1 (complete final block) and K2
(padded final block, or empty message) paths are supported.

### NIST SP 800-108 KDF in Counter Mode

| Function | Key |
|----------|-----|
| `kdf_ctr_cmac_circuit` / `kdf_ctr_cmac_gf8_circuit` | 128 or 256 bits |

Implements KDF-CTR(AES-CMAC) per NIST SP 800-108r1-upd1 Section 4.1.  The
32-bit big-endian counter is wired as circuit constants (zero proof cost).
`fixed_input` is the caller-defined FixedInputData; appending `[L]_r` is the
caller's responsibility if required by the application.

### Merkle path verification

Two internal hash constructions are available, selectable per circuit:

- **Davies-Meyer (DM):** leaf hash uses a Merkle-Damgard chain with a
  domain-separated IV; internal node hash is `AES_L(R XOR C) XOR (R XOR C)`.
- **CMAC:** leaf hash is `CMAC(K_leaf, data)`; internal node hash is
  `CMAC(K_node, L || R)`.  Fixed keys are domain-separated at circuit-build time.

Both variants domain-separate leaf and internal node hashes to prevent
second-preimage attacks.

| Variant | Bit-level AND gates | GF(2^8) mul slots |
|---------|---------------------|-------------------|
| DM,       depth d | 7,200 leaf + d * 7,328 path | 200 leaf + d * 216 path |
| CMAC-128, depth d | 14,400 leaf + d * 21,728 path | 400 leaf + d * 616 path |
| CMAC-256, depth d | 19,872 leaf + d * 29,936 path | 552 leaf + d * 844 path |

Path direction bits are supplied as public instance values, so the left/right
swap is resolved at circuit-build time with zero additional gates.  A
secret-leaf-index variant (where the leaf index is itself a witness) would
require one `add_mul` per byte per level; add a new circuit function rather
than modifying the public-dir API if that use case arises.

### Indexed Merkle non-membership

`indexed_merkle_nonmember_circuit` / `indexed_merkle_gf8_nonmember_circuit`
proves that a target value is absent from an indexed Merkle tree by
demonstrating an adjacent leaf `(value, next_value, next_index)` such that
`value < target < next_value`, along with a valid Merkle path for that leaf.

Additional gate cost beyond the Merkle path: `2 * 3 * 8 * target_bytes`
GF(2^8) mul gates for the two byte-wise less-than comparisons.

**Trust assumption (important for integrators):** the non-membership statement
is sound *only* if the tree builder maintains the adjacency invariant, namely
that each leaf's `next_value` / `next_index` correctly identifies the
next-larger leaf actually present in the tree.  The circuit cannot verify this; it binds
the prover to a real leaf record and enforces `value < target < next_value`,
but the linked-list invariant is an external assumption on the protocol that
produces the signed tree root.  See [`docs/DESIGN.md`](docs/DESIGN.md#indexed-merkle-non-membership-trust-assumption-on-the-tree-builder)
for the full threat-model analysis.

---

## Fiat-Shamir transform

### Single-phase (standard)

`voleith_prove` / `voleith_verify` and `voleith_gf8_prove` /
`voleith_gf8_verify` run the complete Fiat-Shamir non-interactive protocol in
one call.  The `fs_seed` parameter is a caller-supplied domain separator that
binds the proof to its application context.

### Two-phase (shared transcript)

For hybrid protocols that interleave a VOLEitH proof with a classical
credential scheme on a shared Fiat-Shamir transcript, the GF(2^8) API exposes
split commit/respond phases:

```
Prover:
  voleith_gf8_prove_commit()    ->  commitment blob
  <incorporate blob into shared transcript, derive chall_1>
  voleith_gf8_prove_respond()   ->  complete proof

Verifier:
  voleith_gf8_verify_reconstruct()  ->  reconstructed blob
  <incorporate blob into shared transcript, derive chall_1>
  voleith_gf8_verify_respond()      ->  accept / reject
```

The split point is at `chall_1`, the first Fiat-Shamir challenge derived from
the BAVC (GGM tree) commitment.  This allows the challenge to incorporate
elements from an outer protocol -- for example, a Pedersen commitment in an
anonymous credential scheme -- before the proof responds to it.

---

## Parameter sets

Six parameter sets are provided, matching the FAEST security levels.  The `f`
(fast) variants use a shallower GGM tree and are optimized for prover speed;
the `s` (small) variants optimize proof size at some prover cost.

| Parameter | Security | Proof size (AES-128 circuit) |
|-----------|----------|------------------------------|
| `voleith_params_em_128f` | 128-bit | ~5.5 KB |
| `voleith_params_em_128s` | 128-bit | ~4.3 KB |
| `voleith_params_em_192f` | 192-bit | ~10 KB |
| `voleith_params_em_192s` | 192-bit | ~8 KB |
| `voleith_params_em_256f` | 256-bit | ~17 KB |
| `voleith_params_em_256s` | 256-bit | ~14 KB |

Proof size scales with AND/mul gate count; the figures above are for the
canonical AES-128-key-knowledge circuit from the FAEST specification.

The `f` variants are strongly recommended for most applications.  The `s`
variants reduce proof size by roughly 20% but use a much deeper GGM tree: for
128-bit security, `em_128s` (τ=11, N=65536) requires approximately 22× more
PRG calls during GGM expansion than `em_128f` (τ=16, N=2048), with no other
benefit.

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

Tests run in four build configurations (software-only, CLMUL, AES-NI, combined
CLMUL+AES-NI) and validate every layer against known-answer vectors from
multiple independent sources:

- **AES primitive:** FIPS 197 (Appendices A and B), NIST SP 800-38A
  Appendix F.1, NIST CAVP AESVS (GFSbox, KeySbox, VarKey, VarTxt).
- **AES-CMAC:** RFC 4493 Examples 1-4, NIST CAVP CMAC vectors (partial /
  complete blocks, K1 / K2 paths, truncated tags).
- **KDF-CTR(AES-CMAC):** NIST CAVS 14.4 (4 vectors, AES-128 / AES-256).
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

Requirements: CMake 3.16+, a C17 compiler (GCC or Clang), Linux or macOS.
AES-NI and CLMUL are detected automatically; software fallbacks are always
built.

```sh
cmake -B build
cmake --build build -j$(nproc)
ctest --test-dir build/tests --output-on-failure
```

Build options:

| Option | Default | Description |
|--------|---------|-------------|
| `VOLEITH_AES_NI`      | ON  | Enable AES-NI intrinsics (`-maes -msse2`) |
| `VOLEITH_CLMUL`       | ON  | Enable CLMUL carry-less multiply (`-mpclmul -msse2 -msse4.1`) |
| `VOLEITH_BUILD_SHARED` | OFF | Build shared library (`libtalos_voleith.so`/`.dylib`) in addition to the static library |

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

Fourteen runnable example programs in `examples/` exercise every circuit
building block in both proof-system variants:

| Example | What it proves |
|---------|----------------|
| `example_aes.c` / `example_aes_gf8.c`             | Knowledge of an AES-128 / AES-256 key |
| `example_aes_cmac.c` / `example_aes_cmac_gf8.c`   | Knowledge of a CMAC key producing a given tag |
| `example_kdf.c` / `example_kdf_gf8.c`             | Correct KDF-CTR(AES-CMAC) derivation from a secret key |
| `example_merkle.c` / `example_merkle_gf8.c`       | Membership of a secret leaf at a public position in a Merkle tree |
| `example_indexed_merkle.c` / `example_indexed_merkle_gf8.c` | Non-membership of a value in an indexed Merkle tree |
| `example_kvac_pq.c` / `example_kvac_pq_gf8.c`     | Signal-style anonymous group membership credential |
| `example_kvac_pq_gf8_depth12.c`                   | The above at depth 12 (4,096 group members) |

Each example builds the circuit, generates a valid witness, produces a proof,
verifies it, and prints circuit statistics (AND-gate count, ell, proof size)
plus PASS/FAIL.  After building, run them from the build directory:

```sh
./build/examples/example_aes_gf8
./build/examples/example_kvac_pq_gf8_depth12
```

---

## References

### Primary specification

- [FAEST v2.0](https://faest.info/): NIST PQC Round 2 additional signatures
  submission.  The complete protocol specification including VOLEitH, GGM
  vector commitments, ConvertToVOLE, QuickSilver, and Fiat-Shamir transform.
  Local copy: [`docs/specs/`](docs/specs/) if vendored.

### Academic papers

- Baum, Braun, de Saint Guilhem, Klooß, Orsini, Roy, Scholl.
  [Publicly Verifiable Zero-Knowledge and Post-Quantum Signatures from
  VOLE-in-the-Head](https://eprint.iacr.org/2023/996) (CRYPTO 2023).
  The VOLEitH construction.
- Yang, Sarkar, Weng, Wang.
  [QuickSilver: Efficient and Affordable Zero-Knowledge Proofs for Circuits
  and Polynomials over Any Field](https://eprint.iacr.org/2021/076)
  (CCS 2021).  The line-point zero-knowledge proof system used over the
  VOLEitH-committed correlation.
- Baum, Beck, Delpech de Saint Guilhem, Klooß, Orsini, Roy, Scholl.
  [Faster VOLEitH Signatures from All-but-One Vector Commitments and Half
  Trees](https://eprint.iacr.org/2024/097) (2024).  The half-tree GGM
  optimization referenced in the future work section.

### Standards documents

- [FIPS 197](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.197-upd1.pdf):
  Advanced Encryption Standard (AES).
- [FIPS 202](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.202.pdf):
  SHA-3 Standard: Permutation-Based Hash and Extendable-Output Functions.
- [NIST SP 800-38A](https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38a.pdf):
  Recommendation for Block Cipher Modes of Operation: Methods and Techniques.
- [NIST SP 800-108r1-upd1](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-108r1-upd1.pdf):
  Recommendation for Key Derivation Using Pseudorandom Functions.
- [RFC 4493](https://www.rfc-editor.org/rfc/rfc4493): The AES-CMAC
  Algorithm.

### Reference implementations (test oracles only)

- [faest-ref](https://github.com/faest-sign/faest-ref): the reference FAEST
  implementation (MIT licensed).  Used as a test oracle to generate
  known-answer vectors for cross-validation; no source code was copied.

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
