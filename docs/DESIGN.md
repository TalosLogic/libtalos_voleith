# libtalos_voleith: Design Rationale

## Overview

libtalos_voleith implements the FAEST v2.0 VOLE-in-the-Head (VOLEitH) zero-knowledge proof system as a general-purpose library: any circuit expressible in the supported gate model can be proven, not only the canonical FAEST AES-key-knowledge circuit. The library exposes two parallel proof-system variants that share the underlying VOLEitH protocol stack but differ in their circuit gate model:

- **Bit-level (GF(2)) QuickSilver**: each wire carries one bit; gates are XOR, AND, NOT. AND gates are the only proof-cost contributor.
- **Element-level (GF(2^8)) QuickSilver**: each wire carries one byte (an element of GF(2^8)); gates are XOR, affine linear map, squaring, and GF(2^8) multiply. Only multiply gates contribute proof cost.

Both variants use the same VOLE-in-the-Head commitment phase, the same GGM tree vector commitment, the same Fiat-Shamir transcript construction (SHAKE-128 / SHAKE-256), and the same parameter sets (the six FAEST-EM levels: 128f/s, 192f/s, 256f/s).

All protocol code is a clean-room implementation derived from the FAEST v2.0 specification. The FAEST reference implementation (`faest-ref`, MIT) was used only as a test oracle to generate known-answer vectors. No source code was copied.

---

## Five-Layer Architecture

The library is organised into five layers, each independently testable and each consuming only the layer below it:

```
Layer 5: circuits/                 Reusable circuit building blocks
  aes_circuit / aes_gf8_circuit         AES-128 and AES-256 encryption
  grostl_gf8_circuit                    Grøstl-256 / Grøstl-512 hash
  hirose_gf8_circuit                    Hirose-AES-256 DBL iteration
  aes_cmac_circuit / gf8 variant        AES-CMAC (RFC 4493)
  kdf_ctr_cmac_circuit / gf8 variant    NIST SP 800-108 KDF-CTR(AES-CMAC)
  merkle_circuit / merkle_gf8_circuit   Merkle path verification (AES-DM / CMAC)
  merkle_grostl_gf8_circuit             Wide-node Grøstl Merkle path
  indexed_merkle_circuit / gf8 variant  Indexed Merkle non-membership
  node_hash_vt                          Hash-agnostic node-hash interface (vt)
  node_hash_{aes,grostl,hirose}_gf8     Per-family vt instances
  merkle_vt_gf8_circuit                 Generic vt-driven Merkle path
  indexed_merkle_vt_gf8_circuit         Generic vt-driven indexed non-member

Layer 4: proof/                    QuickSilver proof system
  circuit / gf8_circuit                 Circuit definition API
  prover / gf8_prover                   QuickSilver prover (AND / mul check)
  verifier / gf8_verifier               QuickSilver verifier
  proof / gf8_proof                     Fiat-Shamir wrapper (non-interactive)
  vole_hash                             VOLEHash (FAEST Figure 4.4)

Layer 3: vole/ (VOLEitH)           VOLE-in-the-Head protocol
  convert                               ConvertToVOLE (FAEST Figure 5.2)
  voleith                               VOLEitH commitment and reconstruction

Layer 2: vole/ (vector commitment) GGM-tree vector commitment
  vc                                    Commit, Open, Reconstruct (BAVC)

Layer 1: core/                     Symmetric-key primitives
  field                                 GF(2^k) arithmetic, k in {8,64,128,192,256}
  prg                                   AES-CTR PRG
  hash                                  SHAKE-128 / SHAKE-256 / SHA3-256
  aes                                   AES-128 / AES-256 standard encrypt
  grostl                                Grøstl-256 / Grøstl-512 (software + HW)
  util                                  Secure zero, constant-time compare
```

### Why five layers, not one monolithic build

The conventional FAEST and faest-ref codebases fuse the proof layer to a single circuit (AES key knowledge), with the circuit definition itself implicit in the prover and verifier code. That fusion is acceptable for a fixed signature scheme but is the wrong abstraction for a general-purpose library: any new application would require rewriting the prover and verifier.

The five-layer split puts the circuit definition (`proof/circuit.h`, `proof/gf8_circuit.h`) at the boundary between the proof system and any specific application. **The prover and verifier never know what the circuit "means."** They process gates topologically and check constraints. This makes adding a new application (a new Merkle hash variant, a new MAC, a new protocol-specific assertion) a Layer 5 task that touches no protocol-critical code.

The circuit-builder building blocks in Layer 5 are pure wire-graph construction: they call only the Layer 4 circuit API and return wire IDs for further composition. A consumer combines them to express their statement:

```c
voleith_gf8_circuit_t *c = voleith_gf8_circuit_new();
gf8_wire_id key[16]  = { ... witness ... };
gf8_wire_id pt[16]   = { ... instance ... };
gf8_wire_id ct[16];
aes128_gf8_circuit(c, key, pt, ct);                        /* Layer 5 building block */
aes_cmac_gf8_circuit(c, key_K2, /* params */, tag_out);    /* Layer 5 building block */
voleith_gf8_assert_equal(c, ct[0], some_other_wire);       /* Layer 4 circuit API */
voleith_gf8_prove(&proof, params, c, witness, instance, ...);
```

---

## Why Two Proof-System Variants

The bit-level (GF(2)) and element-level (GF(2^8)) variants both exist because they have a roughly 8× difference in witness and proof size for byte-oriented circuits, but neither dominates in all cases.

### Bit-level (GF(2)): natural for bitwise statements

Each wire carries one bit. XOR and NOT gates are free (linear in the VOLE correlation). AND gates contribute one VOLE slot each. This is the natural model for:
- Circuits that operate inherently on bits (bitfield extraction, comparison logic, custom Boolean predicates).
- Direct ports of any Boolean circuit description.
- Statements where the proof's per-bit auditing structure is a feature.

The AES-128 circuit in this variant has 7,200 AND gates (200 S-boxes × 36 AND gates per Canright tower-field S-box).

### GF(2^8): compact for byte-oriented circuits

Each wire carries one byte. XOR, affine linear maps (MixColumns, change-of-basis, byte rotations), and squaring in GF(2^8) are all free (linear in the VOLE correlation). Only GF(2^8) multiply gates contribute proof cost. The S-box uses one `inv_in` witness byte and two free `assert_product` constraints per S-box.

The AES-128 circuit in this variant has 200 mul gates (one inversion per S-box, with no separate output commit because the S-box affine is a free linear map).

### Choosing between them

| Use case | Use this variant |
|----------|------------------|
| Any circuit built from AES, CMAC, KDF, or Merkle hashing | GF(2^8) |
| Bitwise comparison or bit-extraction with no byte-level structure | GF(2) |
| Mix of both | Currently requires two proofs or expressing bitwise logic in GF(2^8); a unified field is future work |

The GF(2^8) variant is approximately 8× more compact than the bit-level variant for byte-oriented workloads. Both variants are first-class: every circuit building block ships in both versions, and the same parameter sets and Fiat-Shamir construction are used for both.

---

## Circuit API as the Core Abstraction

The circuit definition API (`proof/circuit.h` for bit-level, `proof/gf8_circuit.h` for GF(2^8)) is the most important boundary in the library. It must remain protocol-neutral so that consumers in different application domains can use it without modification.

### Wire declarations

```c
wire_id  voleith_circuit_add_witness(c);     /* private input */
wire_id  voleith_circuit_add_instance(c);    /* public input */
wire_id  voleith_circuit_add_internal(c);    /* intermediate */
wire_id  voleith_circuit_add_const(c, bit);  /* compile-time constant */
```

Witness wires are private to the prover; instance wires are part of the verifier's input. Constants are resolved at circuit-build time and have zero proof cost.

### Gate construction

```c
wire_id voleith_circuit_add_xor(c, a, b);    /* free */
wire_id voleith_circuit_add_and(c, a, b);    /* 1 AND slot */
wire_id voleith_circuit_add_not(c, a);       /* free */

gf8_wire_id voleith_gf8_add_xor(c, a, b);                         /* free */
gf8_wire_id voleith_gf8_add_linear_map(c, in[8], coeffs[8]);      /* free */
gf8_wire_id voleith_gf8_add_square(c, a);                         /* free */
gf8_wire_id voleith_gf8_add_mul(c, a, b);                         /* 1 mul slot */
```

The asymmetry between free and costly gates is the central economic fact of QuickSilver. The library's circuit-builder building blocks (AES, CMAC, KDF, Merkle) are designed to minimise costly gates: AES S-boxes use Canright tower-field decomposition specifically because it lets all field-multiply work go through one inversion witness and free linear maps; CMAC subkey derivation uses a free shift-XOR; the half-tree GGM optimisation (future work) recovers nearly half the GGM PRG calls into the free side of the VOLE correlation.

### Constraints

```c
voleith_circuit_assert_zero(c, w);
voleith_circuit_assert_equal(c, a, b);

voleith_gf8_assert_zero(c, w);
voleith_gf8_assert_equal(c, a, b);
voleith_gf8_assert_product(c, a, b, c);    /* asserts a · b == c in GF(2^8) */
```

Constraints are what make the circuit a *statement*, not just a computation. The prover succeeds iff every constraint holds under the witness.

### Soundness invariant: assert_product

In the GF(2^8) variant, `assert_product(a, b, c)` is the soundness-critical constraint that anchors the S-box inversion. The prover MUST commit to `c = a · b` computed in GF(2^8); committing instead to some other value (even one the prover knows is correct in some other arithmetic) breaks soundness because the ZK hash check would become tautologically consistent. This is documented in the prover code and tested directly in `tests/test_gf8_quicksilver.c`.

---

## VOLEitH, Not Interactive VOLE

A common alternative design, used by emp-zk and the original QuickSilver implementations, runs an *interactive* VOLE between prover and verifier, with the verifier contributing to the VOLE correlation. This produces shorter proofs but requires both parties to be online during proof generation and prevents public verification of past proofs.

libtalos_voleith uses VOLE-in-the-Head: the prover simulates the VOLE protocol "in their head", commits to all simulated verifier randomness via a GGM tree, and then opens a single random path. The verifier reconstructs the VOLE correlation from the opened path and runs QuickSilver against it. The Fiat-Shamir transform (instantiated with SHAKE-128 / SHAKE-256) makes the protocol non-interactive.

**Properties this design enables:**
- The verifier need not be online when the proof is generated.
- Anyone with the circuit description and public instance can verify a past proof.
- Proofs can be stored, forwarded, and re-verified.
- The proof binds to a caller-supplied Fiat-Shamir domain separator (`fs_seed`), which provides cross-protocol replay protection.

**Cost:** proofs are larger (~5-17 KB depending on circuit size and security level) than interactive VOLE-ZK (~hundreds of bytes). For applications that need publicly verifiable non-interactive proofs and post-quantum security, this is an acceptable trade-off; for applications that are happy with interactive ZK and short proofs, an interactive VOLE library would be a better fit.

---

## Two-Phase Fiat-Shamir (Shared-Transcript Composition)

The standard `voleith_prove` / `voleith_verify` and `voleith_gf8_prove` / `voleith_gf8_verify` functions run the complete Fiat-Shamir protocol in a single call. The GF(2^8) API additionally exposes a split commit/respond pair:

```
Prover:
  voleith_gf8_prove_commit()     -> commitment blob (BAVC commitment + IV)
  <caller incorporates blob into outer transcript, derives chall_1>
  voleith_gf8_prove_respond()    -> complete proof

Verifier:
  voleith_gf8_verify_reconstruct() -> reconstructed blob
  <caller incorporates blob into outer transcript, derives chall_1>
  voleith_gf8_verify_respond()      -> accept / reject
```

### Why this exists

Hybrid protocols frequently need to bind a VOLEitH proof to a classical credential scheme on a *shared* Fiat-Shamir transcript. Concretely, Signal's KVAC anonymous credential scheme runs an outer Schnorr-style proof over Ristretto255; integrating a VOLEitH proof of "I know an AES-CMAC key that produces this tag on a committed value" requires both proofs to derive their challenges from the same transcript, otherwise an adversary could mix-and-match commitments between the two halves.

### Where the split point is

The split is at `chall_1`, the first Fiat-Shamir challenge in the VOLEitH protocol, derived from the BAVC (GGM tree) commitment. This is the earliest point at which the outer protocol's contribution can be incorporated: the prover has already committed to its VOLE correlation, but the verifier's first challenge has not yet been used to drive the QuickSilver protocol.

After `chall_1` is derived (either by the standalone wrapper or by the caller using a shared transcript), the rest of the protocol is identical: VOLE challenge, QuickSilver responses, BAVC opening with grinding.

### Why only the GF(2^8) API exposes the split

The bit-level API does not currently expose the two-phase variant because the use case that motivated it (Signal KVAC) operates exclusively on byte-oriented witnesses. Adding the split to the bit-level API is a mechanical mirror of the GF(2^8) work and would be done if a consumer needed it.

---

## Proof Metadata Header

Every serialized proof produced from 1.3.0 onward begins with a fixed 48-byte
metadata header that binds the proof cryptographically to the variant choices,
parameter set, circuit, and params struct it was minted under. The header is
identical in shape across the bit-level and GF(2⁸) proof systems.

### Layout

```
offset  size  field
------  ----  -----
   0     4    MAGIC          = 'T','L','O','S'
   4     1    FORMAT_VERSION = 0x01
   5     1    FS_KIND        VOLEITH_FS_SHAKE | VOLEITH_FS_GROSTL
   6     1    BAVC_KIND      VOLEITH_BAVC_STANDARD | VOLEITH_BAVC_HALF_TREE
   7     1    PARAM_SET_ID   VOLEITH_PARAM_EM_* (0..5)
   8     2    FLAGS          must be 0
  10     6    RESERVED       must be 0
  16    16    CIRCUIT_FP     SHAKE-128 of canonical circuit bytes
  32    16    PARAMS_FP      SHAKE-128 of canonical params bytes
  48   ...    proof body (existing c | u_tilde | d | ... | iv | ctr layout)
```

The first 16 bytes are statically constrained: every legal value is known up
front, giving the parser ~123 bits of disambiguation against random byte
strings. The trailing 32 bytes are caller-constrained: their validity depends
on a runtime comparison against fingerprints the verifier computes over its
own circuit and params.

### What the fingerprints bind

- **`CIRCUIT_FP`** = `SHAKE-128(canonical_circuit_bytes)` truncated to 16
  bytes. The canonical serialization writes wire kinds, operand wire-ids, and
  constraint operands in declaration order under a versioned domain tag
  (`voleith-circuit-cf-v1` for bit-level, `voleith-gf8-circuit-cf-v1` for the
  GF(2⁸) variant). Reordering wires, swapping operands, or changing a
  constant changes the fingerprint.

- **`PARAMS_FP`** = `SHAKE-128(canonical_params_bytes)` truncated to 16 bytes,
  domain tag `voleith-params-cf-v1`. Covers `lambda`, `tau`, `w_grind`,
  `n_leafcom`, `T_open`, plus `fs_kind`, `bavc_kind`, and a 6-byte
  zero-padded reserved region.

Both fingerprints are deterministic and order-sensitive: the same logical
circuit built in a different declaration order produces a different
fingerprint, by design. This forces an exact-structural match between the
prover's and verifier's circuits, not a semantic-equivalence-class match.

### How the header enters the transcript

The 48 header bytes are prepended to the commitment blob the
prover/verifier both produce:

```
blob = header || hcom || c || iv     (was: hcom || c || iv)
```

The Fiat-Shamir derivation absorbs the blob:

```
chall_1 = H_2^1(fs_seed ‖ instance ‖ blob)
```

so absorbing the blob automatically incorporates the header. Any change to a
header byte (variant downgrade, swapped param-set-id, tampered fingerprint)
propagates through `chall_1`, then `chall_2`, then `chall_3`, and the final
`chall_3` equality check fails. No caller-side header awareness is required,
which is what makes the two-phase shared-transcript API work without test
changes.

### Verifier dispatch and identity check

`voleith_verify` and `voleith_gf8_verify` dispatch statically on the leading
48 bytes:

1. If they parse as a well-formed v1 header (magic match, valid version,
   valid enums, zero reserved/flags), the verifier runs
   `voleith_proof_header_check_identity[_gf8]`: re-computes
   `CIRCUIT_FP` and `PARAMS_FP` over its own circuit and params and compares
   constant-time against the header. Mismatch returns -1 *before any
   crypto runs*, eliminating wasted work on cross-circuit / cross-params
   attacks.
2. Otherwise (parse fails) the proof is treated as a pre-v1 legacy proof and
   verified via a body-only fallback path. The fallback is gated by the
   `VOLEITH_LEGACY_VERIFY` CMake option (default `ON`); when `OFF`,
   non-v1 proofs are rejected immediately.

Both paths share the same body-reconstruction code; only the blob layout and
header absorption differ. Accidental dispatch (random legacy bytes parsing
as a v1 header) is ~2⁻¹²³, well below the construction's 128-bit floor.

### `voleith_proof_inspect`

Callers that need to route a proof to the right verifier configuration
(picking a `voleith_params_t` based on `param_set_id`, or rejecting variants
the build doesn't support) can use the public inspection helper:

```c
voleith_proof_header_t h;
if (voleith_proof_inspect(&proof, &h) == 0) {
    /* v1 proof: h.fs_kind, h.bavc_kind, h.param_set_id all readable */
} else {
    /* legacy or malformed - route accordingly */
}
```

Passing `NULL` for `header_out` does a validate-only check, useful as a
fast "is this v1?" detector.

### Variant identifier reserved space

`FS_KIND`, `BAVC_KIND`, and `PARAM_SET_ID` each carry single-byte enum
values. Currently only `(SHAKE, STANDARD)` is supported across the six
param sets; `GROSTL` (1) and `HALF_TREE` (1) reserve namespace for future
backends, namely the Grøstl Fiat-Shamir transform and the half-tree BAVC
construction. The verifier currently rejects out-of-range values via
`voleith_params_validate`; full dispatch will be wired when those backends
land.

### Length-validated entry points

Alongside the header, 1.3.0 introduces `voleith_prove_v2` /
`voleith_verify_v2` (and the GF(2⁸) equivalents) which take explicit
`witness_len` and `instance_len` parameters and reject mismatches at the
public API boundary before any reads. The original entry points are
preserved for source-compatibility and documented as deprecated for
removal in 2.0.0. New code should prefer the `_v2` forms.

---

## Parameter Sets

Six parameter sets are provided. They use the FAEST-EM leaf-commitment
parameter line (`n_leafcom = 2`); see "What 'EM' refers to" below.

| Parameter | λ | τ | Leaves/instance | w_grind | T_open | Proof size¹ |
|-----------|---|---|-----------------|---------|--------|-------------|
| `em_128f` | 128 | 16 | 128-256 | 8 | 112 | 6,644 B |
| `em_128s` | 128 | 11 | 2,048 | 7 | 103 | 5,010 B |
| `em_192f` | 192 | 24 | 128-256 | 8 | 176 | 12,428 B |
| `em_192s` | 192 | 16 | 2,048-4,096 | 8 | 162 | 9,388 B |
| `em_256f` | 256 | 32 | 128-256 | 8 | 234 | 19,684 B |
| `em_256s` | 256 | 22 | 2,048-4,096 | 6 | 218 | 15,392 B |

¹ GF(2⁸) AES-128 circuit (ℓ = 216 elements: 16 key bytes + 200 S-box
inverses), computed from `voleith_gf8_proof_byte_size`, which includes the
48-byte v1 metadata header at the start of every proof (see "Proof Metadata
Header" above). The `em_128f` row is cross-checked against the measured
proof. The bit-level GF(2) variant of the same circuit is ~2.7× larger
(`em_128f`: 17,844 B) because each S-box costs
36 AND-gate slots instead of a single mul slot.

The τ, w_grind, and T_open values are the parameter-set definitions in
`proof/proof.c`; T_open follows the FAEST-EM `meson.build` of the reference
implementation. Leaves/instance is the per-instance GGM leaf count from
`voleith_vc_N`: each vector commitment splits into τ₁ instances of 2^k leaves
and τ₀ of 2^(k-1) (FAEST spec Table 5.1), so the count is a range, not a
single power of two.

### Constructing a params struct

The recommended forward API is `voleith_params_build`:

```c
voleith_params_t p = voleith_params_build(VOLEITH_PARAM_EM_128F,
                                          VOLEITH_FS_SHAKE,
                                          VOLEITH_BAVC_STANDARD);
```

The three enum arguments select the named parameter set (table above),
the Fiat-Shamir transform, and the BAVC construction. The returned struct
has `lambda`, `tau`, `w_grind`, `T_open`, and `n_leafcom` drawn from the
named set, plus the `fs_kind` and `bavc_kind` fields added in 1.3.0 set
to the caller's choices. Both new fields are covered by the params
fingerprint, so two params structs that differ only in `fs_kind` or
`bavc_kind` produce different `PARAMS_FP` values and therefore
non-interoperable proofs.

Currently only `(VOLEITH_FS_SHAKE, VOLEITH_BAVC_STANDARD)` is supported.
`VOLEITH_FS_GROSTL` and `VOLEITH_BAVC_HALF_TREE` reserve namespace for
future backends and are rejected by `voleith_params_validate` until
those backends land.

The existing `voleith_params_em_128f`, `voleith_params_em_128s`, etc.
named symbols continue to work for source compatibility. Each is now an
explicit-init copy of `voleith_params_build(set, VOLEITH_FS_SHAKE,
VOLEITH_BAVC_STANDARD)` for the corresponding set. New code should
prefer `voleith_params_build` since the variant choices are visible at
the call site rather than implicit in the named symbol.

### What "EM" refers to

"EM" here denotes the **leaf-commitment parameter family** (`n_leafcom = 2`,
the FAEST-EM line), *not* the circuit being proven. This library is
general-purpose: it proves arbitrary circuits under these parameters, and the
`n_leafcom = 2` leaf commitment is a valid (and smaller) choice for any
circuit, independent of the OWF.

In particular, the AES-128 example circuit proves *standard* AES-128: secret
key, full key schedule, 200 S-boxes (160 data path + 40 key schedule). That is
the **FAEST-128f** statement, not the Even-Mansour OWF that FAEST-EM-128f
proves (public key, 160 S-boxes, no key schedule). So our AES-128 proof size
tracks FAEST-128f (≈ 6,336 B reference), not FAEST-EM-128f (≈ 5,696 B); the
~260 B gap vs. FAEST-128f is the 16 final-round S-box inverses we commit
explicitly but FAEST derives from the public ciphertext.

### f vs s trade-off

The `f` ("fast") variants use a shallower GGM tree (τ instances of N = 2^(λ/τ)) and are optimised for prover speed. The `s` ("small") variants use a deeper GGM tree (fewer instances, much larger N each) and trade prover speed for ~20% smaller proofs.

The `f` variants are strongly recommended for most applications. The factor between `f` and `s` is significant: for 128-bit security, `em_128s` (τ=11) expands ~22,528 total GGM leaves versus ~3,072 for `em_128f` (τ=16), roughly 7× more PRG work during GGM expansion, with no other benefit. A ~7× slowdown in prover time to save ~1.6 KB of proof is rarely the right trade-off.

### Why six, not more

The library currently implements only the FAEST-EM (Even-Mansour) variant, which corresponds to `n_leafcom = 2` in the FAEST taxonomy. The non-EM FAEST variants (with `n_leafcom = 3` and a different leaf commitment construction) are not implemented in the initial release. Two `TODO` comments in `vole/vc.c` mark the two code paths that would need to change. The six EM parameter sets cover all use cases known to the maintainers; the non-EM variants would offer slightly different size / speed trade-offs but no new security properties.

---

## Design Decisions and Non-Features

### Canright (2005) tower-field S-box, not Boyar-Peralta

The AES S-box circuit uses the Canright tower-field decomposition over GF(((2^2)^2)^2). This gives 36 AND gates per S-box in the bit-level variant.

The Boyar-Peralta (2012) computer-searched S-box reduces AND gate count to 32 per S-box (an 11% reduction for the bit-level variant: 7,200 → 6,400 AND gates for AES-128). It is used by faest-ref and other VOLEitH implementations.

**Why this library uses Canright anyway:**

1. **GF(2^8) variant unaffected.** In the element-level QuickSilver variant, S-box cost is one `inv_in` witness byte per S-box regardless of internal AND gate count. The inversion is expressed as two free `assert_product` constraints. The AND gate count inside the inversion is irrelevant to proof size or VOLE slot count. Boyar-Peralta provides no benefit to the GF(2^8) circuit, which is the recommended path for AES-containing circuits.

2. **Clean-room hand-derivable.** Canright's decomposition can be derived from first principles from the GF(2^8) tower-field identity. Boyar-Peralta is a computer-search result; clean-room reimplementation requires either re-running the search (impractical) or carefully transcribing the published optimised circuit (which raises clean-room provenance questions).

3. **Drop-in replacement available if needed.** If proof size in the bit-level variant becomes a concern, replacing `gf8_inv` in `circuits/aes_circuit.c` with the Boyar-Peralta circuit (32 AND gates) is a contained, protocol-neutral change with no API impact.

### FAEST "norm trick" not implemented

The FAEST v2.0 specification (Section 6) describes an "InvNorm" optimisation for the AES S-box: instead of committing to the full 8-bit inverse witness `x⁻¹`, the prover commits only to a 4-bit element `c = x¹⁷ ∈ GF(2⁴)`. This reduces the raw inversion witness from 1 byte to 0.5 bytes per S-box.

The norm trick is part of the FAEST-EM extended witness model and applies only to the **bit-level circuit variant**. In that model the S-box *output* is also separately committed as an additional witness element (1 byte per S-box), because `ZK.SBoxAffine` must verify the affine output transformation using the committed Galois conjugates of `c`. The net cost per S-box is therefore 0.5 + 1 = **1.5 bytes**, compared to this library's current **1 byte** (a single `inv_in` witness).

In the GF(2^8) element-level variant, each S-box already costs exactly one `inv_in` witness byte regardless of how the inversion is decomposed internally. The norm trick has no meaning in this model: there is no separate "output wire" to commit to, and `assert_product` checks are free. The GF(2^8) variant is already at the minimum achievable cost of 1 byte per S-box.

The norm trick therefore does not apply to the general-purpose circuit model used here and would *increase* witness size by 50% in the bit-level variant if naively adopted.

The correct interpretation of FAEST Figure 6.6 `InvNormToConjugates` is that the 0.5-byte norm element `c = x¹⁷` and the 1-byte separately committed S-box output `y` are two parts of the same per-S-box witness package. The FAEST signature scheme can use this split because its S-box is specifically the AES-128 SubBytes and its bit-level circuit is hand-tailored to the FAEST-EM extended witness model. A general-purpose bit-level circuit library that does not pre-commit S-box outputs separately cannot capture the norm-trick saving without re-architecting its entire witness layout, at which point the saving (relative to the GF(2^8) variant's 1 byte per S-box) is negative.

### AES-CMAC for KDF, not raw AES-CTR or Keccak

The KDF circuit building block (`kdf_ctr_cmac_circuit` / `kdf_ctr_cmac_gf8_circuit`) implements NIST SP 800-108r1-upd1 Section 4.1: KDF in Counter Mode with AES-CMAC as the PRF.

Three alternatives were considered and rejected:

| Construction | Why rejected |
|--------------|--------------|
| Raw AES-CTR as PRF | Not NIST SP 800-108 approved. The PRP-PRF switching lemma gives a birthday bound at 2^64, which is below the FAEST-EM-128 security level. |
| Keccak / SHAKE as PRF | ~920,000 AND gates per Keccak permutation vs AES-128's 7,200. Prohibitive in circuit. |
| HMAC-SHA256 as PRF | SHA-256 is ~25,000 AND gates per compression; HMAC-SHA256 is two compressions. Far more expensive than AES-CMAC (~800 AND gates per CMAC of a short input). |

AES-CMAC in KDF Counter Mode is NIST SP 800-108 compliant, post-quantum secure (because it's symmetric-key only), and approximately 30× cheaper in circuit than HMAC-SHA256.

The library does not include HMAC-SHA256 or SHAKE-based PRFs as circuit building blocks because their circuit cost is prohibitive for VOLEitH workloads. SHAKE is used extensively *outside* circuits (Fiat-Shamir, commitment hashing, challenge derivation), where AES-NI / hardware crypto extensions are not available and SHAKE's portability matters.

### Merkle path direction bits: public-dir and secret-dir variants

The library provides both forms. `merkle_gf8_path_circuit` (and the bit-level equivalent) takes `path_dirs` as a plain `const uint8_t *` (0/1 values resolved at circuit-build time), so the left/right swap is static and costs zero gates per level, the right choice when the leaf *index* is genuinely public (e.g. the `example_merkle_gf8.c` demo: membership of a secret leaf *value* at a known position). `merkle_gf8_path_circuit_secret_dir` takes `path_dirs` as `const gf8_wire_id *` (committed witness wires) and muxes each node byte, costing `node_bytes` mul-gates per level, the right choice when the index itself must be hidden.

**Signal KVAC uses the secret-dir variant.** It is an *anonymous* group-membership credential, so the prover must not reveal which leaf is theirs: publishing the position would identify the member and defeat anonymity. Both the leaf value *and* the direction bits (the leaf index) are witness; only the Merkle root is a public instance value. These secret-dir variants are the foundation for ring-signature circuits in general.

Current coverage is complete across all three hash families: the DM/CMAC, the wide-node Grøstl, and the Hirose-AES-256 Merkle path and indexed non-membership circuits all exist in both public-dir and secret-dir forms (`merkle_grostl_gf8_path_circuit` / `_secret_dir`, `indexed_merkle_grostl_gf8_nonmember_circuit` / `_secret_dir`, and the generic vt-driven `merkle_vt_gf8_path_circuit` / `_secret_dir` and `merkle_vt_gf8_indexed_nonmember_circuit` / `_secret_dir` parameterised by `voleith_node_hash_vt`, which is how Hirose ships). Every secret-dir circuit, fixed-hash or vt-driven, enforces direction-bit booleanity in-circuit.

The secret-dir variant adds `node_bytes` mul-slots plus one direction-bit witness per level (≈ 8% over a DM level's ~216 slots; proportionally far less for the wide Grøstl nodes). **Do not collapse the two into one API**: keeping the public-dir path gate-free avoids silently inflating proof size for the public-index case. **Every secret-dir circuit must constrain each direction wire to `{0,1}` inside the circuit** via `assert_product(dir, dir, dir)` (free: zero mul-slots, zero witnesses). This is soundness-critical: an unconstrained mux selector lets the prover make neither mux output equal the carried-up value, erasing it and forging a path, so booleanity must never be left to the caller.

### Indexed Merkle non-membership: trust assumption on the tree builder

`indexed_merkle_nonmember_circuit` and the GF(2^8) variant prove that a target value is absent from an indexed Merkle tree by demonstrating an adjacent leaf `(value, next_value, next_index)` such that `value < target < next_value`, along with a valid Merkle path for that leaf.

The non-membership statement is sound under one **external** assumption that is **not** verified by the circuit: the tree builder maintains the adjacency invariant, namely that for every leaf `L` in the tree, `L.next_value` is the value of the leaf with the smallest value strictly greater than `L.value`, and `L.next_index` is that leaf's tree index. The circuit cryptographically binds the prover to a real leaf record via the leaf hash and the Merkle path, and enforces the ordering relation `value < target < next_value`, but it cannot verify that `L.next_value` is in fact the next-larger value present in the tree.

Concretely, a deployment using `indexed_merkle_nonmember_circuit` is sound exactly when the protocol that produces the signed/agreed tree root is itself sound, i.e., the tree builder honestly maintains the linked-list invariant when inserting, updating, and deleting leaves. This is the standard model for indexed Merkle trees (the same assumption used by Aztec, Polygon Hermez, and similar deployments) and is satisfied by construction when a single trusted issuer (or a verifiable tree-update protocol) is responsible for tree maintenance.

If your threat model includes a fully malicious tree builder, this circuit is not sufficient on its own. Two mitigations are possible but not provided by this library:

1. An in-proof binding of `next_index` to the leaf actually stored at that index. This roughly doubles the circuit size and still cannot prevent a builder from omitting a leaf entirely.
2. A different data structure (e.g., a sparse Merkle tree keyed by value) with no linked list and no adjacency invariant.

The trust assumption is documented in the README's Pre-built circuit building blocks section so that integrators see it at the API surface and not only in the design document.

#### Software validator at the helper boundary

For the common case of an honest-but-buggy tree builder (the usual operational reality), `circuits/indexed_merkle_vt_gf8_helpers.{c,h}` ships a public `voleith_imt_vt_validate_records` that catches the soundness-critical record-array patterns at the public-API boundary. It is invoked automatically by both `voleith_imt_vt_build` and `voleith_imt_vt_lookup_nonmember`, so the malformed cases below are rejected loudly with `-1` instead of silently producing a verifying-but-false non-membership proof. Callers may also pre-validate once before a batch of lookups.

The validator enforces three invariants in one O(n) lsb-first pass:

1. **Sort order.** `records[i].value <= records[i+1].value`. Equality is permitted so that trailing "max sentinel" records (`value == next_value == MAX`) can be repeated to pad `n_records` to a power of two: the pattern used by `examples/example_ring_sig_v1_revocable_gf8.c`.
2. **Well-formed intervals.** `records[i].value <= records[i].next_value`. Rules out wrap-around intervals that would otherwise let an adversarial prover `assert_lt` on a target outside the IMT's value range.
3. **No overlap.** For every non-degenerate record (`value < next_value`), if `i < n_records - 1` then `next_value[i] <= value[i+1]`. This is the soundness-critical check: an overlap (`next_value[i] > value[i+1]`) lets an adversary use `records[i]` as their witness to `assert_lt` on `target = records[i+1].value`, forging a non-membership proof for an actual member. The most common operational foot-gun (inserting a new record without updating the predecessor's `next_value`) produces exactly this overlap and is caught here. Degenerate records (empty intervals, `value == next_value`) are exempt from this check because the circuit's strict `assert_lt(v, target, v)` can never hold for any `target`, so they cannot drive an attack.

What the validator deliberately does **not** check is **completeness** at the extremes of the value range: that is the application's sentinel policy (explicit `(0, first_real)` and `(last_real, MAX)` sentinels, wrap-around, or some other convention). A target outside any record's interval simply returns `-1` from `voleith_imt_vt_lookup_nonmember`. No verifying-but-false non-membership proof can be produced for a member by any caller whose record array passes the validator.

The validator does **not** lift the external trust assumption above: it cannot, since it sees only one record array, not the history of inserts / updates / deletes a tree builder ran to produce it. A fully malicious builder can still omit a leaf entirely or build a structurally well-formed but semantically wrong tree. The validator's contribution is purely defense-in-depth against the operational class of bugs (sort-order violations, broken linked-list consistency, forgotten predecessor updates) that arise from hand-maintained record arrays.

### DM vs CMAC Merkle hash trade-off

`merkle_gf8_circuit` supports two internal hash constructions, selectable per circuit:

- **Davies-Meyer (DM):** internal node hash is `AES_L(R ⊕ C_node) ⊕ (R ⊕ C_node)`. Leaf hash is a Merkle-Damgård chain with a domain-separated IV.
- **CMAC:** internal node hash is `CMAC(K_node, L || R)`. Leaf hash is `CMAC(K_leaf, data)`. `K_leaf ≠ K_node` (domain-separated at circuit-build time).

| Variant | Cost per internal node | When to use |
|---------|------------------------|-------------|
| DM | 1 × AES (~7,200 AND gates / 200 mul slots) | Fastest. Recommended default for new applications where compatibility with an external hash is not required. |
| CMAC-128 | 3 × AES (~21,600 AND gates / 600 mul slots) | When the application protocol externally specifies CMAC-based Merkle hashing for compatibility with non-circuit code. |
| CMAC-256 | 3 × AES-256 (~29,808 AND gates / 828 mul slots) | Same as CMAC-128 but with 256-bit security on the Merkle hash. |

Both DM and CMAC variants domain-separate leaf hashes from internal node hashes (different IVs / keys) to prevent second-preimage attacks across levels.

**Collision-resistance ceiling.** Both DM and CMAC produce a 128-bit node digest (the AES block width). Their collision resistance is therefore the birthday bound of 2^64, regardless of the chosen security level λ. This is adequate when the tree contents are fixed by a trusted party and the adversary cannot choose colliding leaves, but it is *below* the 128-bit floor whenever an adversary can grind leaf or subtree values to forge membership, exactly the threat model of an anonymous-credential or ring-signature tree, where the prover is the adversary. For those uses the node hash must offer collision resistance at the full security level, which a 128-bit-output hash cannot. This is what motivates the Grøstl wide-node variants below.

### Grøstl wide-node Merkle hashing, and why a 27-byte truncation

`merkle_grostl_gf8_circuit` provides a Merkle path whose internal-node hash is Grøstl (the SHA-3 finalist), used specifically to lift the node-digest collision resistance above the 2^64 ceiling that AES-DM / CMAC impose. Grøstl is the natural choice here for one structural reason: **its S-box is the AES S-box.** The entire Grøstl SubBytes step reuses the same inversion gadget already built for AES (one `inv_in` witness byte per S-box, with free `assert_product` constraints), and every other Grøstl operation (AddRoundConstant, ShiftBytes, MixBytes, and the wide-pipe compression XOR) is GF(2)-linear and therefore free in the GF(2^8) variant. Adopting Grøstl adds no new costly gate type and no new constant-time primitive: the same S-box, the same `voleith_gf8_inv`, the same hardware-accelerated SubBytes path. A non-AES-based wide hash (e.g. SHA-256, ~25,000 AND gates per compression) would have been far more expensive and would have required a second S-box implementation.

Three variants are exposed, differing only in node width and hence collision resistance:

| Variant | Node width | Collision resistance | S-boxes / internal node |
|---------|-----------|----------------------|-------------------------|
| `VOLEITH_MERKLE_GROSTL_256` | 32 B (256-bit) | 2^128 | 3,200 (2 compressions + Ω) |
| `VOLEITH_MERKLE_GROSTL_256_T27` | 27 B (216-bit) | 2^108 | 1,920 (1 compression + Ω) |
| `VOLEITH_MERKLE_GROSTL_512` | 64 B (512-bit) | 2^256 | 8,960 (2 compressions + Ω) |
| `VOLEITH_MERKLE_GROSTL_512_T59` | 59 B (472-bit) | 2^236 | 5,376 (1 compression + Ω) |

Leaf and internal-node hashes are domain-separated with a single RFC 6962-style prefix byte (`0x00` for leaves, `0x01` for internal nodes), added as a constant wire: public structural data, not witness.

**Why the 27-byte truncated variant exists.** The internal-node hash computes `Grøstl(0x01 ‖ L ‖ R)`, so for a node width of `n` bytes the compression input is `1 + 2n` bytes. Grøstl-256 has a 64-byte block and its padding consumes at least 9 bytes (the `0x80` marker plus an 8-byte block count). A single Grøstl compression therefore covers the inode iff `1 + 2n + 9 ≤ 64`, i.e. `n ≤ 27`. At the full 32-byte width the inode input is `1 + 64 = 65` bytes and spills into a *second* block, doubling the compression count from one to two. Truncating Grøstl-256 to its first 27 output bytes is the largest node size that keeps the inode at a single compression, cutting the per-level S-box count from 3,200 to 1,920, roughly a 40% reduction in both proof size and verify time at every level of the tree. Because VOLEitH verification is linear in circuit size (not succinct), that per-level saving compounds across the whole path.

The cost of the truncation is collision resistance: a 216-bit digest gives the birthday bound 2^108 instead of 2^128. Truncating a wide hash to a shorter digest is a standard, sound construction (the same pattern as SHA-512/256 and SHA-512/t); internally the function is still full Grøstl-256, only the output is shortened. So `_T27` is the right choice for applications that need collision resistance well above AES-DM's 2^64 and find 2^108 acceptable while wanting minimum proof size; `_256` is the choice when the full 2^128 is required; `_512` when a 256-bit security margin is wanted on the tree hash itself.

`_T59` applies the identical single-block trick one tier up, for the >2^128 regime that only Grøstl-512 can reach (Grøstl-256's 32-byte output caps at 2^128). The full Grøstl-512 inode (`1 + 2·64 = 129` bytes + 9 padding) already spans two 128-byte blocks; `1 + 2n + 9 ≤ 128` gives `n ≤ 59`, so a 59-byte node is the largest whose inode stays a single compression, halving it to 5,376 S-boxes (1 compression + Ω) from the full 8,960 at 2^236 instead of 2^256 CR. A single Grøstl-512 block is one compression regardless of how full it is, so 59 maximises collision resistance at no extra per-level proof cost; a smaller truncation (e.g. 48 bytes for a clean 2^192 / NIST-L3 label) costs the same in S-boxes and only saves a handful of sibling/mux bytes per level. The software `core/grostl.c` is validated against the published NIST Grøstl KAT and Monte Carlo test vectors, and the circuit is cross-checked against it on every test run.

### Hirose-AES-256 double-block-length hash (primitive + circuit)

This section documents Hirose-AES-256: the iteration primitive, the leaf / inode framing built on top of it, and how that framing plugs into the generic vt-driven Merkle path / indexed-non-member circuits described in the next subsection.  Unlike DM/CMAC and Grøstl, Hirose has no fixed-hash Merkle path entry point of its own: it ships *only* as `voleith_node_hash_vt` instances consumed by the generic vt-driven Merkle circuits.  That choice is structural: Hirose was the first new hash family added after the vt interface existed, so there was no benefit to building a hash-specific path circuit alongside it.

**Why a double-block-length construction at all.**  A single-block-length AES hash (Davies-Meyer-style) produces a 128-bit digest and is capped at 2^64 collision resistance by the birthday bound on the block size.  Any AES-based hash that needs to go above 2^64 CR therefore has to output ≥200 bits, which a 128-bit-block cipher cannot do in a single compression call; it requires a *double-block-length* (DBL) construction that emits a 2n-bit chaining value from two cipher calls per message block.  Of the published DBL constructions over a 2n-bit-key block cipher, Hirose (FSE 2006) is the one with a *tight* collision bound of ≈2^n in the ideal-cipher model (birthday-optimal for a 2n-bit output).  Earlier DBL families (MDC-2, Tandem-DM, Abreast-DM) have weaker bounds: MDC-2-AES-128 admits a 2^77 collision attack (Knudsen et al., below the 2^100 line), and naïve counter-widening of AES-128 hits the Joux multicollision bound at ~2^70.  Instantiated over AES-256 (n=128), Hirose lands cleanly at 2^128 CR.

**The compression function `f`.**  With block cipher `E` of n-bit block and 2n-bit key, a 2n-bit chaining value `(G, H)`, an n-bit message block `M`, and a fixed nonzero n-bit constant `c`:

```
K       = H ‖ M                    (256-bit AES-256 key)
G_next  = E(K, G)        XOR  G
H_next  = E(K, G XOR c)  XOR  G XOR c
```

Both encryptions use the same key `K = H ‖ M` and differ only in plaintext (`G` vs. `G ⊕ c`).  `c ≠ 0` is required by the security argument: a zero `c` collapses the two encryptions to the same call and breaks the collision bound.  Hirose's reduction (FSE 2006) proves CR ≈ 2^n in the ideal-cipher model, and crucially holds with an *adversarially chosen* IV: the chaining-value slot can carry attacker-controlled bytes without weakening the bound.

**Why this matters at the circuit-cost level.**  AES-256's key-schedule produces 15 round keys and consumes 52 S-boxes in the GF(2^8) circuit; the data-path encryption consumes 224 S-boxes; a full encrypt is 276.  A naïve "two independent AES-256 calls" Hirose iteration is 2·276 = 552 S-boxes.  Because the two calls inside `f` use the *same key*, the key schedule can be computed once and fed into both data-path encryptions.  That saving of 52 S-boxes per iteration is realised structurally by splitting `aes256_gf8_circuit` (`circuits/aes_gf8_circuit.c`) into two public entry points:

```c
void aes256_gf8_expand_key(c, key[32], rk[15][16]);     /* 52 S-boxes  */
void aes256_gf8_encrypt_rk(c, rk[15][16], pt[16], ct[16]);   /* 224 S-boxes */
```

with matching witness builders.  `aes256_gf8_circuit` becomes a thin wrapper that calls both in sequence, so all existing AES-256 callers (CMAC, the FIPS-197 / faest-ref-OWF KATs, the existing 308-byte witness layout) are byte-identical after the refactor.  One Hirose iteration then emits `aes256_gf8_expand_key` once over `H ‖ M` and `aes256_gf8_encrypt_rk` twice (once on `G`, once on `G ⊕ c`), giving 52 + 2·224 = **500 S-boxes per iteration**, the structural floor for any AES-256-based Hirose iteration at 2^128 CR.

**Linear glue is free.**  The remaining work in one iteration is `K = H ‖ M` (a wire-ID array reshape, no gates), one `add_xor_const` per byte for `G ⊕ c` (16 free ops), one `add_xor` per byte for `G_next = AES_K(G) ⊕ G` (16 free ops), and one `add_xor` per byte for `H_next = AES_K(G ⊕ c) ⊕ G ⊕ c` (16 free ops).  All 48 glue operations are `add_xor` / `add_xor_const` / `add_linear_map` (or wire reshape) and contribute zero VOLE slots and zero `assert_product` constraints.  So the full per-iteration cost in the GF(2^8) variant is exactly 500 inv_in witness bytes and 1000 `assert_product` constraints, both pure consequences of the AES S-boxes inside the two `encrypt_rk` emits.

**Software primitive as independent oracle.**  `core/hirose.c` exposes a single function, `voleith_hirose_iteration(G, H, M, c, G_out, H_out)`, that implements `f` over `voleith_aes_encrypt`.  It deliberately does *not* share the key schedule across the two encryptions: it builds one `voleith_aes_ctx_t` over `H ‖ M` and calls `voleith_aes_encrypt` twice.  Sharing or not sharing the schedule changes only gate-count cost, not output, so the software form is functionally equivalent to the in-circuit KS-shared form.  Two consequences: (a) the software primitive serves as an **independent oracle**, since any divergence between in-circuit output and software output is by construction a circuit-side bug, never a shared-spec-misreading bug; (b) the primitive is genuinely standalone, since `core/hirose.c` exports `voleith_hirose_iteration` only and does not expose leaf / inode framing, so it cannot be used as a general-purpose hash by accident.

**Test vector grounding.**  No canonical Hirose-AES-256 KAT exists: the original FSE 2006 paper is theoretical and the construction is not in any NIST / ISO / IETF standard.  The strongest external anchor available is **FIPS 197 Appendix C.3** (AES-256 KAT): constructing a Hirose input with `H ‖ M = K_FIPS` and `G = P_FIPS` produces `G_out = C_FIPS XOR P_FIPS`, a value derivable from NIST's published triple plus the spec equation.  `tests/test_hirose.c` checks this byte-for-byte; it grounds the `G_out` path of one iteration in a citable third-party vector.  The `H_out` path falls back to the in-test reference (FIPS 197 publishes only one `(P, C)` triple per key), but a shared-misreading bug in the spec equations is ruled out by the FIPS-anchored `G_out` half: a typo like `AES_K(G XOR c) XOR G` instead of `AES_K(G XOR c) XOR (G XOR c)` would fail the FIPS-anchored equality even though the in-test reference would still pass.

**Aliasing-safe in-circuit semantics.**  `hirose_gf8_iteration_circuit` supports `G_out` aliasing `G` (and `H_out` aliasing `H`) so callers can chain iterations in-place:

```c
hirose_gf8_iteration_circuit(c, G, H, M, k_const, G, H);
hirose_gf8_iteration_circuit(c, G, H, M2, k_const, G, H);
```

Internally the function snapshots `G`'s wire IDs at the start (16 integer copies, no gates) before any write to `G_out`. `G` is read three times during emission (once by `encrypt_rk` for the first AES gates, once for the `G_out` feed-forward XOR, once for the `G ⊕ c` XOR), and without the snapshot an `in-place` chaining call corrupts the wire-ID array between reads.  `H` and `M` are each read exactly once (into the `K = H ‖ M` array at the top), so they need no snapshot.  A regression test (`tests/test_node_hash_hirose_gf8.c::test_iteration_in_place_aliasing`) pins this contract: a future refactor that drops the snapshot fails that test directly, before any downstream wrapper test would.

**Why no truncated Hirose variant.**  Unlike Grøstl, where the truncation trick (T27 / T59) saves a compression by keeping the inode input inside a single block, Hirose has **no analogous saving**.  Truncation in Grøstl is justified by *block-padding economics* (one Grøstl compression covers the entire `0x01 ‖ L ‖ R` if and only if `1 + 2n + 9 ≤ block_size`).  Hirose has no padding inside the iteration (every iteration consumes exactly one 16-byte message block), so truncating the 32-byte node would not eliminate any S-boxes.  A 200-bit Hirose variant would have to drop iterations, and 2-iter is already the floor (R = ≥200 bits ⇒ ≥2 message blocks).  So Hirose ships as a single-variant primitive: 256-bit node, 2^128 CR, 500 S-boxes / iteration.

**Leaf and inode framing.**  Two ways to compose the iteration into a hash are shipped, both as wrappers in `circuits/node_hash_hirose_gf8.c`:

- **Fixed-32 leaf** (`voleith_node_hash_hirose_fixed32`).  Assumes a 32-byte input; no padding.  Two iterations: the first chains from `HIROSE_IV_LEAF` with the first 16 input bytes as the message block, the second uses the iteration-1 output `(G, H)` as the chaining value and the next 16 input bytes as the message block.  Output is `G ‖ H` (32 bytes).  Per-leaf cost: 1,000 S-boxes.
- **Variable-length leaf** (`voleith_node_hash_hirose`).  Accepts arbitrary input length; uses `10*` always-pad (append `0x80`, then zero-pad to the next 16-byte boundary; if input is already block-aligned, append a full block of `0x80 ‖ 0x00·15`); **no length suffix**.  Iteration count is `n_iter = ⌈(len + 1) / 16⌉`.  `10*` alone suffices for CR via Merkle's strengthening theorem (injective padding + iteration-count derivable from padded length); length-extension defense is a MAC concern that doesn't apply to Merkle-internal hashing.  **Scope constraint:** this leaf hash is Merkle-internal only, not exposed as a general-purpose hash.  Per-leaf cost: `n_iter × 500` S-boxes.
- **Inode** (shared between both vts).  The left child `L = (L_G, L_H)` is loaded into the chaining state as the IV, and the right child `R` is absorbed as two 16-byte message blocks across two iterations.  Output is the final `G ‖ H`.  The "L as IV" trick is what keeps an inode at exactly 2 iterations (1,000 S-boxes); using a fixed IV and absorbing `L ‖ R` as message would cost 4 message blocks = 4 iterations = 2,000 S-boxes.  Hirose's collision-resistance proof holds with an adversarially chosen IV, so this is safe.

Two iterations is the structural floor for any AES-based Hirose hash over a ≥256-bit input at >2⁶⁴ CR (R = ≥200 bits ⇒ ≥2 message blocks).  Both the fixed-32 leaf and the inode hit it; the variable-length leaf reaches it for inputs up to 15 bytes and grows linearly beyond that.

**Domain-separation constants.**  Four hard-coded constants encode the per-hash identity:

| Constant                | Size | Value                                  | Role                                  |
|-------------------------|------|----------------------------------------|---------------------------------------|
| `HIROSE_IV_LEAF`        | 32 B | `"VOLEitH-Hirose-IV"` + zero-pad        | leaf chaining IV (both vts)           |
| `HIROSE_C_LEAF_FIXED32` | 16 B | `"VOLEitH-Hirose-L"` (exactly 16 bytes) | `c` for the fixed-32 leaf vt          |
| `HIROSE_C_LEAF_VAR`     | 16 B | `"VOLEitH-Hirose-V"` (exactly 16 bytes) | `c` for the variable-length leaf vt   |
| `HIROSE_C_INODE`        | 16 B | `"VOLEitH-Hirose-N"` (exactly 16 bytes) | `c` for the inode (shared by both vts) |

All `c` values are 16 bytes (the AES block size: `c` is an n-bit half-block tweak XORed into the second encryption's plaintext, not a key-side input), nonzero (`c = 0` collapses the two encryptions to the same call and breaks the CR bound), and pairwise distinct.  Distinctness gives **structural** rather than probabilistic separation: a leaf-vs-inode collision would have to be a collision *across two genuinely different compression families* (not merely a near-miss on the same compression), because the `c` constant participates in every iteration's H-side encryption.  The same argument forces `HIROSE_C_LEAF_FIXED32 ≠ HIROSE_C_LEAF_VAR`: a 32-byte input fed to the fixed-32 vt and the same bytes fed to the variable-leaf vt would otherwise collide (the variable vt would emit a different gate stream because of `10*` padding, but the H-side encryption would land in the same compression family, and distinct `c_leaf` closes that).  The inode `c` is shared between the two vts because the inode hash is identical between them: children are always exactly 32 bytes, no padding ambiguity, and leaf-vs-inode separation is already guaranteed by `c_leaf_* ≠ c_inode`.  All four constants are pure circuit constants (`add_const` / `add_xor_const`) and contribute zero VOLE slots.

**`IV_LEAF` is 32 bytes by design** while the three `c` constants are 16 bytes by design: they occupy different slots in the compression.  `IV_LEAF` is the full 2n-bit initial chaining value `(G₀, H₀)` (must be 32 bytes, since a 256-bit state cannot be seeded with fewer bits); `c` is an n-bit half-block tweak XORed into the plaintext `G ⊕ c` (must be 16 bytes).  They never interchange.

**The vt bridge.**  The `voleith_node_hash_vt` interface (`circuits/node_hash_vt.h`) is a struct of function pointers (`leaf_circuit`, `inode_circuit`, the matching `*_build_witness` and software helpers, plus `name` / `node_bytes` / `cr_bits` / `*_invin_bytes` identity fields) that lets higher layers (the generic vt-driven Merkle path circuit `merkle_vt_gf8_path_circuit`, its secret-dir form, the indexed-non-member counterparts, ring signatures, any future tree-shaped consumer) operate on a hash without knowing which one.  The two Hirose vts both have `node_bytes = 32`, `cr_bits = 128`, and share the inode-side fields; they differ only in their leaf-side dispatch.  The vt is consumed during circuit *construction*: indirect calls happen at build time only.  The prover and verifier never see the vt; they process the resulting gate stream, identical to what a hand-written hash-specific circuit would have produced.  Hash agnosticism is therefore a structural property of the codebase at zero proof-time cost.

### Generic vt-driven Merkle path and indexed-non-member circuits

The hash-agnostic Merkle refactor lifts the per-hash path and indexed-non-member bodies into two generic entry points parameterised by `const voleith_node_hash_vt *h`:

```c
void merkle_vt_gf8_path_circuit            (c, h, leaf, leaf_bytes, path_nodes, path_dirs_uint8,    depth, root);
void merkle_vt_gf8_path_circuit_secret_dir (c, h, leaf, leaf_bytes, path_nodes, path_dirs_wire,     depth, root);

int  merkle_vt_gf8_indexed_nonmember_circuit            (c, h, target, target_bytes, low_value, low_next, low_next_index, index_bytes, path_nodes, path_dirs_uint8, depth, root);
int  merkle_vt_gf8_indexed_nonmember_circuit_secret_dir (c, h, target, target_bytes, low_value, low_next, low_next_index, index_bytes, path_nodes, path_dirs_wire,  depth, root);
```

The body owns only the path traversal, the direction handling (static swap for public-dir; per-byte mux with `assert_product(dir, dir, dir)` booleanity for secret-dir), and, for the indexed variant, the `low_value < target < low_next` comparison.  All hash-specific gates live in `h->leaf_circuit` and `h->inode_circuit`.  Eight vt instances ship: AES-DM, AES-128-CMAC, Grøstl-{256, 256_T27, 512, 512_T59}, and Hirose-{fixed32, variable-leaf}.

**Bit-exact gate-stream equivalence with the fixed-hash entries.**  For every hash that has both forms (AES-DM, AES-128-CMAC, all four Grøstl variants), the generic vt-driven body produces a circuit byte-identical to the hand-written fixed-hash entry point: same `witness_count`, same `mul_count`, same `assert_product_count`, same `constraint_count`, same root wire values on every input.  The equivalence is checked in `tests/test_merkle_vt_gf8_equivalence.c` and `tests/test_indexed_merkle_vt_gf8_equivalence.c` across 12 path × hash × dir-flavour pairings each.  Per-vt conformance (invin sizing matches circuit emission, leaf and inode circuits match the software helpers, domain separation between leaf and inode, depth-3 end-to-end through the generic path, secret-dir non-{0,1} direction-bit rejection) is verified in `tests/test_node_hash_vt_conformance.c` uniformly across all eight vts.

**Existing fixed-hash entry points are unchanged.**  `merkle_gf8_path_circuit`, `merkle_grostl_gf8_path_circuit`, and their secret-dir / indexed counterparts stay in place; the vt-driven additions are purely additive.  Collapsing the fixed-hash entries to thin wrappers around the generic body is a future-work item that has no observable effect on the proof system (the gate streams are already identical).

### Constant-time field arithmetic and AES

All field-multiplication paths in `core/field.c` are constant-time: the CLMUL (x86_64) and PMULL (ARMv8) hardware paths by ISA definition, and the software fallback by construction (bitmask-conditional XOR routed through an inline-asm optimiser barrier). No variable-time table-lookup or branch-on-secret path ships in the library; the previous opt-in `-DVOLEITH_ALLOW_VARIABLE_TIME_FIELD` gate was removed in 1.2.0.

AES follows the same design. A constant-time bitsliced backend (`core/aes_ct64.c`) is always built as the universal fallback; AES-NI (x86_64) and ARMv8 Crypto Extension (aarch64) hardware paths are constant-time by ISA definition. No variable-time table-lookup AES path ships; the previous opt-in `-DVOLEITH_ALLOW_VARIABLE_TIME_AES` gate was removed in 1.2.0.

The constant-time discipline is verified two ways. Structurally, by source review (no secret-dependent branches, no secret-indexed memory access, all conditional XORs routed through bitmask AND with the `ct_barrier_u64` optimiser barrier). Empirically, by a dudect-style timing harness (`tools/dudect/`) that runs Welch's t-test on the bitsliced AES, the software field-multiplication paths, `voleith_byte_combine`, the software Grøstl path, and the GF(2^8) Grøstl witness builder (whose `voleith_gf8_inv` is a fixed Fermat addition chain, hence data-independent; the prior brute-force inverse scan was not) under fix-vs-fix input distributions on real hardware. Release-gate evidence files live under `docs/dudect-runs/`, currently covering x86_64 (Sandy Bridge and Gracemont) and aarch64 (Apple M1).

### Parameter validation at the API boundary

Every public API entry point (`voleith_prove`, `voleith_verify`, `voleith_prove_commit`, `voleith_gf8_prove`, etc.) calls `voleith_params_validate(params)` before doing any work. This rejects:

- NULL `params`.
- `λ` not in {128, 192, 256}.
- `τ = 0` or `τ > 32`.
- `w_grind ≥ λ`.
- `n_leafcom` not in {2, 3}.
- `T_open = 0`.

The validation is centralised in `voleith_params_validate` (in `proof/proof.c`) rather than scattered across each entry point. This both deduplicates the checks and makes the contract explicit: "any caller-supplied `voleith_params_t` is validated; out-of-range fields are rejected before any allocation or cryptographic operation."

This is defense-in-depth: the library ships only six well-formed parameter sets, but a caller could construct a `voleith_params_t` directly with garbage fields, and the API boundary must reject that case rather than relying on internal code to fail downstream.

### Circuit validation at the API boundary

The `voleith_circuit_t` (and its GF(2^8) twin `voleith_gf8_circuit_t`) is the second caller-supplied input that flows into every prove / verify entry point, and the same boundary-rejection discipline applies. Two checks run before any cryptographic work:

1. **Construction-completeness check** via `voleith_circuit_ok` / `voleith_gf8_circuit_ok`. The builder functions (`add_xor`, `add_and`, `add_mul`, `assert_zero`, `assert_product`, etc.) cannot signal OOM through their return value, so on `realloc` failure they set an internal `alloc_ok` flag and continue. A circuit with silently dropped wires or constraints would be a soundness break (the application's assertions are no longer enforced), so prove / verify reject when this flag is clear.

2. **Reference-bounds check** via `voleith_circuit_validate` / `voleith_gf8_circuit_validate`. A one-shot O(n_wires + n_constraints) pass that enforces the topological-order invariant on gate inputs (for every gate at index *i*, its input wire ids are strictly less than *i*) and bounds every constraint's referenced wire ids against `n_wires`. Catches malformed circuits before they OOB-read wire / tag buffers in the QS hot loop.

Both checks run at the public boundary (`voleith_prove_commit`, `voleith_verify_reconstruct`, and the GF(2^8) equivalents); the one-shot `voleith_prove` / `voleith_verify` flow through them. The validators are also public so callers that ever accept circuits from a less-trusted source (a future deserialize path, for instance) can run the same check up front. Neither check imposes any per-gate cost in the QS hot loop.

### Witness-correctness rejection at the prover

Both the bit-level prover (`voleith_qs_prove`) and the GF(2^8) prover (`voleith_gf8_qs_prove`) reject an invalid witness *upfront*, before publishing any QuickSilver coefficients. The check is `voleith_circuit_eval(circuit, witness, instance, bits) != 1`; on violation, the prover returns an error rather than producing a proof that the verifier would later catch.

**Why upfront rejection.** The naive design lets the prover produce a proof for an invalid witness and relies on the verifier to catch it via the QuickSilver `a0_tilde` check. This is sound (the verifier does catch it) but operationally awkward: a buggy caller cannot distinguish "my witness is wrong" from "my proof was tampered with in transit." Upfront rejection makes prover-side bugs fail fast.

The GF(2^8) prover has done upfront rejection from the start (the `assert_product` constraints are checked during witness evaluation). The bit-level prover was brought to the same discipline so that prover-side bugs surface immediately rather than as opaque downstream verifier rejections.

### Memory hygiene: secure-zero discipline

All contexts holding key material, VOLE correlations, witness data, or transient cryptographic state are zeroed on free using `voleith_secure_zero()` (backed by `explicit_bzero` on POSIX, volatile pointer loop otherwise). This applies to:

| Location | Why |
|----------|-----|
| Expanded AES round keys (`core/aes.c`) | Key material is sensitive even after use; cold-boot and DMA attacks can extract it from process memory. |
| Keccak sponge state (`core/hash.c`) | Sponge state contains absorbed input including possibly secret material. |
| PRG contexts (`core/prg.c`) | Hold expanded AES keys derived from the FAEST seed. |
| Fiat-Shamir transcript state (`proof/fiat_shamir.c`) | Contains absorbed witness-derived material. |
| VOLE commitment buffers (`vole/voleith.c`, `vole/convert.c`) | Hold u, v, V_rows correlations linear in the witness. |
| Prover scratch buffers (`proof/prover.c`, `proof/gf8_prover.c`) | Hold Q[0], u_tilde, d, a1_tilde, a2_tilde; all witness-dependent. |
| `d_tmp` (prove-respond) | Holds witness ⊕ u_slots; must be zeroed even when the buffer is on the stack. |
| Serialised proof data (`proof/proof.c`) | Cleared on `voleith_proof_free` for defense-in-depth, even though the proof itself is public. |
| Reconstructed verifier-side bitstream context (`proof/verifier.c`) | Cleared after `zk_hash_finalize` to avoid leaving derived state in scope. |

All secret-dependent equality checks use `voleith_const_memcmp()` (volatile XOR accumulator), never `memcmp`. This applies to commitment-equality checks in the VOLEitH commitment phase and to `chall_3` comparison in the full proof verification path.

### No secret-dependent table lookups inside circuits

The AES S-box circuit uses a purely algebraic tower-field decomposition; no lookup tables are accessed inside the proof circuit. This is required for soundness in the proof model (table lookups are not expressible in the QuickSilver gate language) and for constant-time guarantees outside it.

The standard-eval AES used by the PRG and by test code is either the hardware AES-NI / ARMv8 backend or the constant-time bitsliced backend (`core/aes_ct64.c`). Neither is accessible to the proof circuit's prover or verifier.

### Soundness-critical paths: implemented exactly per spec

The QuickSilver multiplication check in `proof/prover.c` and `proof/gf8_prover.c` is the central soundness mechanism. It is implemented exactly per the FAEST v2.0 specification with no optimisations that deviate from the spec. The same discipline applies to:

- The VOLEHash construction (`proof/vole_hash.c`, FAEST Figure 4.4).
- The ConvertToVOLE algorithm (`vole/convert.c`, FAEST Figure 5.2).
- The Fiat-Shamir challenge derivation order and transcript composition.

Performance optimisations are applied only to operations that do not affect soundness: PRG block batching, GF(2^k) CLMUL / PMULL acceleration, AES-NI and ARMv8 Crypto Extension dispatch. Anything that touches the multiplication check, the VOLEHash, or the challenge derivation is left exactly as the spec dictates.

---

## Ring Signatures (RSv1)

RSv1 is the library's first end-user signature capability built on top of the layered proof stack. It packages the hash-agnostic Merkle path circuit, the OWF circuit, and the GF(2^8) Fiat-Shamir prover into a non-interactive, publicly verifiable ring signature with optional revocation. The public API lives under two prefixes: `voleith_rs_membership_*` for the reusable membership baseline (intended to be shared with future linkable / claimable / threshold variants) and `voleith_rsv1_*` for V1-specific wiring (the cfg fingerprint, the ring builder, sign / verify, the on-the-wire envelope).

### Statement proven

```
PUBLIC inputs (instance):
    membership_root R       (tree_hash.node_bytes bytes)
    revocation_root V       (tree_hash.node_bytes bytes; only when depth_r > 0)
    m                       (message bound via Fiat-Shamir, not a wire)

PRIVATE inputs (witness):
    sk                                          (sk_bytes)
    membership path direction bits              (depth_m bytes, one per level)
    membership sibling node values              (depth_m * node_bytes bytes)
    OWF inv_in                                  (owf leaf circuit internals)
    per-level inode inv_in                      (depth_m * inode_invin_bytes)
    [iff depth_r > 0:]
        revocation adjacent record:
            low_value, low_next                 (node_bytes each)
            next_index                          (8 bytes)
        revocation path direction bits          (depth_r bytes)
        revocation sibling node values          (depth_r * node_bytes bytes)
        revocation IMT-leaf inv_in              (tree_hash leaf circuit)
        per-level revocation inode inv_in       (depth_r * inode_invin_bytes)

CONSTRAINTS:
    leaf  = OWF_circuit(sk)
    root  = secret_dir_merkle_path(leaf, siblings, dirs)
    assert_equal(root, R)
    [optional revocation:]
        rec_leaf  = tree_hash.leaf_circuit(low_value || low_next || next_index)
        rec_root  = secret_dir_merkle_path(rec_leaf, rev_siblings, rev_dirs)
        assert_equal(rec_root, V)
        assert_lt(low_value, leaf)
        assert_lt(leaf,      low_next)
```

The Fiat-Shamir transcript binds `m` (see "Message binding" below). Tampering any byte of `m`, `R`, `V`, or the config struct desynchronises the verifier's challenges from the prover's commitments and `voleith_gf8_verify` returns -1.

### Why VOLEitH for ring signatures

The same properties that make VOLEitH attractive as a general proof system carry over to the ring-signature setting:

- **Post-quantum.** Soundness relies only on symmetric-key primitives (AES and SHAKE). No discrete-log or RSA hardness assumptions.
- **Public verifiability.** A signature is a self-contained byte sequence; verification needs only the published roots and config, not interaction with the signer.
- **Reuses the shipped stack.** The OWF, the Merkle path, the IMT non-membership check, and the GF(2^8) prover / verifier all already ship and are pinned by their own test vectors. RSv1 is composition glue plus message binding.
- **Anonymity by construction.** Secret-dir Merkle paths and witness-held sibling values keep the signer's leaf index private. The verifier learns "some ring member signed" and nothing about which.

The trade-off versus DL-based ring signatures is signature size: RSv1 at depth 3 with the FAEST-EM-128f parameter set produces ~5 to 6 KB of proof bytes plus 41 bytes of envelope. For permissioned rings up to a few thousand members this is acceptable; for very large anonymity sets the per-signature size dominates.

### Circuit shape and the membership baseline

The membership branch composes three circuit primitives in order:

1. `owf_vt.leaf_circuit(sk_wires, sk_bytes, leaf_node_wires)` produces the signer's leaf node from the secret. `owf_vt` is whichever node-hash vt is named as the OWF in the config; the vt's leaf circuit is preimage-resistant on its input, so it serves directly as the one-way function. There is no separate "OWF primitive": the existing leaf-hash circuit is the OWF.

2. `merkle_vt_gf8_path_from_leaf_node_secret_dir(c, tree_vt, leaf_node_wires, sibling_wires, dir_wires, depth_m, computed_root_wires)` walks `depth_m` inode levels starting from `leaf_node_wires`. At each level the (left, right) inputs to `tree_vt.inode_circuit` are selected by a per-byte mux on the level's direction wire. Direction-wire booleanity is enforced inside the path body via `assert_product(dir, dir, dir)` per level (one mul gate per level), which is free in the soundness sense (the mul slot exists regardless) and is the only thing that prevents a malicious prover from picking a non-{0, 1} dir value to fold an arbitrary chain value into the root.

3. `assert_equal_byte(computed_root[i], R_instance[i])` for each of the `node_bytes` bytes of the computed root vs the public R instance wires.

This baseline lives behind `voleith_rs_membership_build_circuit` and is the surface intended for sharing with future variants (V2 linkable, V4 claimable, V5 traceable, V7 threshold). Variants extend the baseline by appending more witness wires, more instance wires, and more constraints; the membership shape itself does not change.

### Revocation branch

When `cfg->depth_r > 0`, the builder additionally declares the revocation witness section, the revocation root V as instance, and calls the hash-agnostic indexed-non-member circuit on `tree_vt`. The revocation tree stores revoked leaf-node values (the same value type the OWF emits) as IMT records, sorted by value, with each record carrying its successor's index. To prove "leaf is not revoked", the signer supplies:

- An adjacent record (low_value, low_next, next_index) whose value is strictly less than the signer's leaf and whose next_value is strictly greater.
- A secret-dir Merkle path from that record's IMT leaf to V.

The circuit hashes `low_value || low_next || next_index` via `tree_vt.leaf_circuit`, walks the IMT path to recompute V, and `assert_equal`s the recomputation against the public V. Two `assert_lt` calls then constrain `low_value < leaf < low_next` byte-wise via the shared comparison routine. The comparison uses byte 0 as the LSB and adds 3 mul gates per bit of `value_bytes` per assert.

The revocation `next_index` width is fixed at 8 bytes (`VOLEITH_RSV1_REV_INDEX_BYTES`), enough to address up to `2^64` records. Smaller `depth_r` values still encode `next_index` in 8 bytes with the upper bytes zero-padded; this keeps the witness layout deterministic in `(cfg, vt)` alone.

### Anonymity model

The signature is anonymous over the ring set, in the standard "the verifier learns *some* member signed" sense. Specifically:

- The signer's leaf index is a witness, recovered from `cfg->depth_m` secret direction wires that the verifier never sees.
- The sibling node values along the signer's path are witness, not instance, because each member's path has different siblings and publishing them would identify the signer.
- The revocation adjacent record (low_value, low_next, next_index) is witness for the same reason: it depends on where the signer falls in the sorted revocation set.
- Only R, V (when revocation is enabled), and `cfg_fingerprint` go through the public Fiat-Shamir absorb. Two signatures from different members over the same `m` produce distinct proof bytestreams (different witnesses give different VOLE commitments) but neither leaks `leaf_index` or any other member-distinguishing field.

### Configuration surface

A single config struct fixes the ring's identity:

```c
typedef struct {
    const voleith_node_hash_vt *tree_hash;   /* Merkle path; required.  */
    const voleith_node_hash_vt *owf_hash;    /* sk -> leaf; NULL = tree_hash. */
    size_t                       sk_bytes;   /* secret-key byte length. */
    size_t                       depth_m;    /* membership tree depth.  */
    size_t                       depth_r;    /* 0 disables revocation.  */
} voleith_rs_membership_config_t;
```

`voleith_rs_membership_validate` rejects malformed configs at the API boundary. It enforces:

- `cfg != NULL` and `cfg->tree_hash != NULL`.
- `1 <= depth_m <= VOLEITH_RS_MEMBERSHIP_MAX_DEPTH` (= 64).
- `depth_r <= VOLEITH_RS_MEMBERSHIP_MAX_DEPTH`.
- `sk_bytes >= 1`.
- When `owf_hash != NULL`: `owf_hash->node_bytes == tree_hash->node_bytes` (the OWF output is the Merkle leaf node), and `owf_hash->cr_bits >= tree_hash->cr_bits` (the OWF must not be the system's weak link).
- For fixed-leaf vts (currently only `voleith_node_hash_hirose_fixed32`, which has `fixed_leaf_bytes = 32`): `sk_bytes == fixed_leaf_bytes`. Variable-leaf vts accept any `sk_bytes >= 1`.

The "OWF cr_bits >= tree cr_bits" check is intentionally conservative. The OWF's relevant attack is preimage resistance (roughly twice CR for the wrapped vts) while the tree's is collision resistance (= CR), so configs with `owf.cr_bits < tree.cr_bits` are sometimes safe in absolute terms. The conservative rule never gives false security and is the cleanest invariant to explain.

### Message binding (Fiat-Shamir)

This is the V1-specific work that turns a membership proof into a signature. The signer chooses `m` and binds it into the proof's Fiat-Shamir transcript via the `fs_seed` argument to `voleith_gf8_prove`. The seed is constructed as:

```
fs_seed = SHAKE256-16( FS_SEED_FMT_VERSION       (1 byte, = 0x01)
                    || DOMAIN_TAG_RSV1           (16 bytes, "VOLEitH-RSv1\0\0\0\0")
                    || cfg_fingerprint            (16 bytes)
                    || membership_root R          (tree_hash.node_bytes bytes)
                    || revocation_root V or zero  (tree_hash.node_bytes bytes)
                    || m_len_be8                  (8 bytes, big-endian)
                    || m                          (m_len bytes) )
```

Field roles:

- **`FS_SEED_FMT_VERSION`.** Single byte `0x01`. Pins the absorb layout. If the construction ever changes in a future release (added field, reordered, etc.) the new format bumps this byte and old verifiers reject loudly. Cheap insurance against unknown-unknowns; one byte forever.
- **`DOMAIN_TAG_RSV1`.** Fixed 16-byte ASCII tag distinct from every other domain tag in the project. The "RSv1" embedded in the tag is the protocol-level version; if a future variant supersedes V1 it gets a new tag, while in-protocol format revisions of V1 itself bump only the version byte.
- **`cfg_fingerprint`.** A 16-byte SHAKE-256 fingerprint over the canonical encoding of the config struct. Canonical encoding: `u32_le(owf_name_len) || owf_name || u32_le(tree_name_len) || tree_name || u64_le(sk_bytes) || u64_le(depth_m) || u64_le(depth_r)`. The vt is identified by `->name` rather than pointer address so the fingerprint is portable across processes and library builds. Two configs that differ in any of these fields produce different fingerprints, distinct fs_seeds, and verify-failure across configs.
- **`revocation_root V or zero`.** When `depth_r == 0`, `node_bytes` of zero bytes are absorbed instead. The placeholder is safe because cfg_fingerprint already pins `depth_r`; a depth_r=0 config and a depth_r>0 config can never collide on the fingerprint.
- **`m_len_be8`.** 8-byte big-endian message length. Prevents the ambiguity between `m = "foo" || "bar"` and `m = "foobar"` that would arise if only `m` were absorbed. The 8-byte width supports messages up to 2^64 - 1 bytes; big-endian matches the length-encoding convention used elsewhere in the project (proof header lengths and the wire envelope's proof_len).

Field ordering follows the convention "public / derivable bytes before caller-supplied bytes": version, domain tag, cfg fingerprint, and roots (all values the verifier reconstructs from cfg and policy) absorb first; the message length and message itself absorb last.

The output is exactly 16 bytes and is what gets handed to `voleith_gf8_prove(..., fs_seed, 16)`. The existing proof machinery absorbs the metadata header, params fingerprint, circuit fingerprint, and the proof's own internal commitment blob on top of the seed; no changes to the GF(2^8) prover are needed.

Once a release tags this construction, the format is a compatibility boundary: breaking changes require bumping `FS_SEED_FMT_VERSION` rather than redefining `0x01`. A byte-exact known-answer test pins the construction against silent format drift.

### Enrollment and keygen

Out of band (the ring authority decides):

1. **Sample sk.** `cfg->sk_bytes` cryptographically uniform random per member. The library does not generate keys.
2. **Derive leaf.** `leaf = owf_vt.leaf_hash(sk, sk_bytes, leaf_out)` where `owf_vt = cfg.owf_hash` or `cfg.tree_hash` if owf_hash is NULL. The vt's software `leaf_hash` is the out-of-circuit counterpart of the in-circuit `leaf_circuit`.
3. **Build ring.** Authority collects N leaf-node values and walks them up via `tree_hash.inode_hash` to a balanced Merkle root. Publishes `membership_root`. The library helper `voleith_rsv1_ring_build` does this in one call.
4. **Persist path.** Each member keeps `(sk, leaf_index)` plus the sibling nodes along their path. Direction bits are derived from `leaf_index` at sign time.
5. **Revocation (optional).** Maintain a separate indexed Merkle tree of revoked leaves; on revocation, insert; at sign time the member uses the published IMT records to compute their adjacent-record witness via `voleith_imt_vt_lookup_nonmember`.

Sub-capacity rings (fewer than `2^depth_m` members) pad unused leaf slots with an all-zero sentinel. An OWF output of all-zero bytes is vanishingly unlikely (~`2^-128` for any wrapped vt), so a sentinel slot cannot collide with a real member's leaf. The ring can therefore be built once at capacity `2^depth_m` and sub-capacity rings still yield a well-defined root; downstream verifiers see only the root and need not know the ring is sub-capacity.

Ring mutation (add / remove / replace a member) is supported by re-running `voleith_rsv1_ring_build` with the updated leaf list. The root changes (new epoch), affected members get refreshed path bundles. Old-root signatures and new-root signatures are automatically distinguishable through the `cfg_fingerprint` + R binding in `fs_seed`. Incremental ring updates (patching only the siblings on the path of one inserted leaf) are deferred; for rings up to ~10K members the O(N) full rebuild finishes in milliseconds.

### Signature serialization

The on-the-wire envelope wraps the raw GF(2^8) proof bytes with a versioned, self-describing header:

```
offset  size  field
------  ----  -----
     0     4  magic = "VRS1"
     4     1  format_version = 1
     5    16  cfg_fingerprint        (binds the config to the proof)
    21    16  params_fingerprint     (binds the VOLEitH params)
    37     4  gf8_proof_len          (big-endian uint32)
    41   ...  gf8_proof bytes
```

Header overhead is 41 bytes; total packed length is `41 + gf8_proof_len`. The big-endian length field matches the length-encoding convention used elsewhere in the project.

Pack and unpack helpers (`voleith_ring_sig_pack`, `voleith_ring_sig_unpack`) compute both fingerprints internally and reject mismatches on unpack with a constant-time comparison. A consumer who hands the wrong cfg or wrong params to unpack gets `-1` without ever touching the inner proof bytes. The inner GF(2^8) proof itself is not re-validated by unpack; that is `voleith_rsv1_verify`'s job on the unpacked sig.

### Software helpers

The data-layer helpers expose the same Merkle and IMT machinery the prover uses, so applications can build and maintain rings without re-implementing the tree walk:

- `voleith_merkle_vt_build(vt, leaf_nodes, n_leaves, root_out)`: compute the Merkle root from `n_leaves` leaf-node values (must be a power of two). Walks `vt->inode_hash` level by level.
- `voleith_merkle_vt_compute_path(vt, leaf_nodes, n_leaves, leaf_index, siblings_out)`: emit the sibling path from leaf `leaf_index` to the root.
- `voleith_imt_vt_build(vt, records, n_records, value_bytes, index_bytes, root_out)`: compute the IMT root from sort-ordered records.
- `voleith_imt_vt_lookup_nonmember(vt, records, n_records, value_bytes, index_bytes, target, adj_idx_out, path_out)`: locate the adjacent record straddling `target` and emit its sibling path. Returns -1 when `target` matches any record's value (target is a member, no non-membership proof possible).
- `voleith_rsv1_ring_build(cfg, sks, n_members, root_out, paths_out, siblings_storage)`: one-call ring construction. Computes per-member leaves via `owf_vt.leaf_hash`, pads sub-capacity slots with the all-zero sentinel, calls `voleith_merkle_vt_build`, and emits per-member path bundles.

### Tests and examples

Test coverage for `tests/test_ring_sig_v1_gf8.c` includes: sign / verify roundtrip on AES-DM and on Hirose; rejection of wrong sk, wrong sibling, wrong root, tampered message, mismatched cfg; revocation-positive (leaf not in V accepts), revocation-negative (leaf in V rejects at the lookup helper, so no witness can be produced); asymmetric OWF / tree-hash pairings (`owf_hash != tree_hash` with matching `node_bytes`); strength-relationship rejection (weaker OWF rejected by validate); fingerprint determinism and per-field binding; the fs_seed byte-exact KAT; the wire envelope's pack / unpack roundtrip plus magic / version / fingerprint / length-mismatch rejections; an anonymity smoke test that two distinct members signing the same `m` produce distinct proof bytestreams with no leaf node embedded in either proof under a memcmp scan.

Two example programs (`examples/example_ring_sig_v1_gf8.c`, `examples/example_ring_sig_v1_revocable_gf8.c`) drive the full sign-pack-unpack-verify path end-to-end. Both are parameterised over the cfg struct: changing the `tree_hash` vt, `sk_bytes`, and depths propagates through all downstream buffer sizing automatically, so a consumer can swap AES-DM (16-byte node, 2^64 CR) for Hirose (32-byte node, 2^128 CR) or Grøstl-256 (32-byte node, 2^128 CR) without further edits.

### Out of scope for V1

The plan deliberately ships V1 first as the smallest useful surface, with explicit hooks for follow-on variants:

- **V2 (linkable).** A per-(signer, tag) nullifier that lets a verifier detect when the same member signs twice under the same tag, without revealing identity.
- **V3 (attribute predicates).** Each member's leaf binds attributes; the signer proves a predicate over them.
- **V4 (claimable / accountable).** The signer can later, optionally, prove they were the signer; or an authority can.
- **V5 (traceable line-reveal).** Two signatures by the same member under the same context reveal the member.
- **V6 (forward-secure key evolution).** Per-epoch key derivation so past signatures stay valid after key compromise.
- **V7 (threshold t-of-n).** A signature requires t of n authorised members to cooperate.

The `voleith_rs_membership_*` layer is named separately from `voleith_rsv1_*` precisely so V2 / V4 / V5 / V7 can share the membership baseline without copy-paste. V3 and V6 deviate from the baseline shape and will get their own builders. None of these variants ship in the V1 release.

Also deferred: a public-dir companion to the `from_leaf_node` secret-dir entry (would mirror the secret-dir variant for the rare public-leaf-index use case); incremental ring-update helpers (path-only update vs full rebuild); an on-disk path-bundle format.

---

## Runtime Hardware Dispatch (Single-Binary Fat Builds)

One library binary serves every supported host. At first use, each of three independent dispatch domains (AES, GF(2^k) field multiplication, Grøstl compression) probes the running CPU and routes subsequent calls through a function-pointer table to the highest-priority backend whose required instruction-set features are present. There is no per-host build, no per-CPU library variant, and no caller-visible API change between hardware and software paths.

Earlier releases produced separate static libraries per ISA variant (`libvoleith_sw.a`, `libvoleith_aesni.a`, `libvoleith_clmul.a`, `libvoleith_aesni_clmul.a` on x86_64, plus parallel ARMv8 variants); consumers had to match the binary to the deployment target. 1.4.1 collapses that matrix into one `libtalos_voleith.a` / `.so` artefact that compiles every available backend and selects among them at runtime.

### Three independent dispatch domains

Each domain has its own ops table, init function, and per-backend translation unit. They share the CPU-feature probe but are otherwise independent.

| Domain | Public forwarders | Selection priority (highest first) |
|---|---|---|
| AES block cipher | `voleith_aes_key_expand`, `voleith_aes_encrypt`, `voleith_aes_encrypt_x4` | AES-NI (x86_64) → ARMv8 Crypto (aarch64) → bitsliced ct64 (portable) |
| GF(2^k) field multiply (k=64,128,192,256) | `voleith_gf{64,128,192,256}_mul` | CLMUL/PCLMULQDQ (x86_64) → PMULL (aarch64) → constant-time scalar |
| Grøstl compression | `voleith_grostl{256,512}_compress` | AES-NI (x86_64) → ARMv8 Crypto (aarch64) → software |

Each public forwarder is a one-line indirect call: load the atomic ops-table pointer, branch on `if (ops == NULL) dispatch_init()`, then call through the selected function pointer. The init cost is paid once per process; the per-call overhead is one acquire load and one indirect branch.

### CPU feature probe

`core/cpu.h` exposes `voleith_cpu_features()`, which returns a stable `unsigned` bitmask of feature flags (`VOLEITH_CPU_AES_NI`, `VOLEITH_CPU_CLMUL`, `VOLEITH_CPU_SSE41`, `VOLEITH_CPU_SSSE3`, `VOLEITH_CPU_ARMV8_AES`, `VOLEITH_CPU_PMULL`). The probe is implemented per-architecture in `core/cpu_x86.c` (CPUID-based), `core/cpu_aarch64.c` (`getauxval(AT_HWCAP)`-based), or `core/cpu_generic.c` (returns zero on unknown architectures). Exactly one of those translation units is compiled for any given target.

The bitmask is computed on the first call via a compare-and-swap guard, cached in an atomic, and returned by all subsequent calls with a single acquire load. Bit assignments are stable across library versions (bits 0–15 for x86_64 features, 16–31 for aarch64 features), so consumers may persist or compare masks across builds.

### Dispatch tables and atomic init

Each domain follows the same shape (illustrated for AES):

```
core/aes.c              Public forwarders + voleith_aes_dispatch_init().
                        Holds _Atomic(const voleith_aes_ops_t *) voleith_aes_ops.
core/aes_dispatch.h     Internal ops-table type, extern declarations for each
                        backend's ops, declaration of voleith_aes_ops.
core/aes_aesni.c        x86_64 AES-NI backend (compiled iff VOLEITH_HAVE_AES_NI).
core/aes_armv8.c        ARMv8 Crypto backend (compiled iff VOLEITH_HAVE_ARMV8_AES).
core/aes_ct64.c         Portable bitsliced ct64 engine (always compiled).
core/aes_ct64_ops.c     Bitsliced ops-table adapter (always compiled).
```

`voleith_aes_dispatch_init()` reads the feature bitmask, walks the compiled-in backends in priority order, picks the first one whose feature bits are present, and publishes the chosen ops table with a release store + CAS so concurrent first-callers converge on the same selection. Field-multiply and Grøstl follow the identical pattern (`field_dispatch.h` / `grostl_dispatch.h`).

### Compile-time gating and per-TU instruction flags

Backend translation units that need ISA-specific intrinsics (`-maes -mssse3` for AES-NI, `-mpclmul -msse4.1` for CLMUL, `-march=armv8-a+crypto` for ARMv8 Crypto and PMULL) compile with those flags scoped to the file via `set_source_files_properties(... COMPILE_FLAGS ...)`. The flags do not propagate to any other translation unit, so consumers do not need to compile their own code with `-maes` and the library does not accidentally emit AES-NI in unrelated functions.

CMake probes the toolchain for each instruction set at configure time. If a probe succeeds, the corresponding `VOLEITH_HAVE_*` macro is defined as a public compile definition on the library target; the backend TU's contents are then enabled by an `#ifdef` at the file top. If the probe fails (older toolchain, missing intrinsics header), the TU compiles to an empty object and the dispatcher falls through to the next backend in priority order.

### Lean-build opt-outs

Operators who want to strip the library to the smallest possible footprint, or who target a deployment that will never see hardware acceleration, can disable any backend at configure time:

```
-DVOLEITH_AES_NI=OFF       # omit core/aes_aesni.c
-DVOLEITH_ARMV8_AES=OFF    # omit core/aes_armv8.c
-DVOLEITH_CLMUL=OFF        # omit core/field_clmul.c
-DVOLEITH_PMULL=OFF        # omit core/field_pmull.c
```

The portable bitsliced AES backend (`aes_ct64`) and the constant-time scalar field backend are always compiled; they are the unconditional floor of the dispatch table. A lean build that omits every hardware backend produces a fully functional binary that runs the portable paths on every host.

### Lean-build mismatch notice

When `voleith_aes_dispatch_init()` selects the bitsliced fallback because a hardware backend was *opted out at compile time* on a CPU that *does* support the corresponding ISA, it emits a one-line notice to stderr the first time it runs:

```
voleith: notice: host CPU has AES-NI but the aes-ni backend was not compiled
in; running on bitsliced fallback (~30-50x slower). Rebuild with
-DVOLEITH_AES_NI=ON. Suppress with VOLEITH_QUIET=1.
```

Analogous notices exist for ARMv8 AES, CLMUL, and PMULL. The notice is fired through an `atomic_flag_test_and_set` once-guard so it appears at most once per process per domain. It is intended as a misconfiguration backstop: a lean-build artefact accidentally shipped to hardware-capable production should be loud enough about the performance loss that operators notice before users do. Setting `VOLEITH_QUIET=1` in the environment suppresses every variant of the notice (useful in test harnesses that deliberately exercise the fallback).

A run on a host that genuinely lacks the hardware (e.g., a generic x86_64 VM without AES-NI) produces no notice: the bitsliced backend is the correct, only available choice in that case.

### Backend override for testing

`VOLEITH_FORCE_BACKEND` is a comma-separated `domain:value` list parsed once during the first call to `voleith_cpu_features()`. Recognised values:

```
aes:aesni      aes:armv8      aes:bitsliced
field:clmul    field:pmull    field:scalar
grostl:aesni   grostl:armv8   grostl:soft
```

The parser strips the corresponding feature bits from the cached bitmask so subsequent dispatch-init calls route to the requested backend. Forcing a backend that the host does not support (e.g., `aes:aesni` on aarch64) prints a diagnostic and `abort()`s; forcing a backend that the build did not compile in falls through to the next-priority backend with no error. Forcing the scalar/bitsliced/software path on a hardware-capable host is the supported A/B-benchmarking mode.

The override is not part of the supported public API; production deployments should not set it. Its sole purpose is the test profile described in the next subsection.

### Constant-time guarantee preserved across backends

Every compiled-in backend is constant-time:

- AES-NI and ARMv8 Crypto use hardware AES instructions whose latency is data-independent on every architecturally compliant implementation.
- The portable AES backend is bitsliced (`aes_ct64`); no S-box table lookup.
- The CLMUL and PMULL field backends use the corresponding carry-less multiply instruction (data-independent on every architecturally compliant implementation).
- The scalar field backend is constant-time scalar code (no secret-indexed memory access, no secret-dependent branches).
- Grøstl AES-NI / ARMv8 backends drive the AES round instructions over Grøstl's 64-byte / 128-byte state; the software backend is straight-line table-free Grøstl.

The dispatch decision itself is made on the CPU feature bitmask, which is data-independent. The function-pointer selected by dispatch is invariant for the remainder of the process, so secret data never influences which backend handles it.

### Test methodology: every test runs in both profiles

`ctest` registers every test twice. The default registration (`<NAME>`) runs the binary as the operator would, so the dispatcher selects whichever hardware backend the host actually has. A second registration (`<NAME>_sw`) runs the same binary with `VOLEITH_FORCE_BACKEND=aes:bitsliced,field:scalar,grostl:soft` in the environment, exercising the software floor on the same host. This means every CI run validates both paths on every supported architecture without separate build configurations.

A dedicated test (`tests/test_lean_build_warning.c`) covers the mismatch-notice path: it captures stderr while triggering `voleith_aes_dispatch_init()` on a build that omitted the hardware backend, asserts the expected notice text appears, and confirms that `VOLEITH_QUIET=1` suppresses it. On a fat build the test exits immediately with PASS because the warning code path is not reached.

### Public introspection

Three symbols let a consumer ask which backend a built library will actually use:

```c
voleith_aes_backend_t   voleith_aes_backend(void);     /* AESNI | ARMV8 | BITSLICED */
const char             *voleith_aes_backend_name(void);
const char             *voleith_grostl_backend_name(void);
unsigned                voleith_cpu_features(void);    /* raw bitmask */
```

The first call to any of these triggers `voleith_aes_dispatch_init()` (or the corresponding Grøstl init) if it has not already run. These are intended for diagnostic logging and for verifying the expected backend in a deployment health check; the protocol layer never consults them.

---

## Correctness Testing

The library is tested against known-answer vectors from multiple independent sources. A single library binary contains every available backend; `ctest` runs every test in two profiles (hardware-dispatched and software-forced via `VOLEITH_FORCE_BACKEND`) so both the hardware path and the constant-time software floor are exercised against the same vectors on every run. The dispatch machinery itself is covered above in "Runtime Hardware Dispatch".

### Primitives (Layer 1)

| Standard | Test type | Coverage |
|----------|-----------|----------|
| FIPS 197 Appendix B | AES-128 cipher example | 1 known-answer vector |
| FIPS 197 Appendix A.1, A.3 | AES-128 / AES-256 last round key | 2 vectors |
| NIST SP 800-38A Appendix F.1 | AES-128 / AES-192 / AES-256 ECB | 2 blocks each (6 vectors) |
| NIST CAVP AESVS GFSbox | Walking all-zero key | 7 (AES-128) + 5 (AES-256) vectors |
| NIST CAVP AESVS KeySbox | Walking key, zero plaintext | 21 (AES-128) + 16 (AES-256) vectors |
| NIST CAVP AESVS VarKey | Walking bit through key | full bit positions |
| NIST CAVP AESVS VarTxt | Walking bit through plaintext | full bit positions |

### CMAC (Layer 5 building block)

| Source | Coverage |
|--------|----------|
| RFC 4493 Examples 1-4 | empty, 16B (K1 path), 40B (K2 path), 64B (K1 path) |
| NIST CAVP CMAC | Partial first block: AES-128 Mlen={10,20}, AES-256 Mlen={10,15}. Complete single block: AES-128 Mlen=32, AES-256 Mlen=16. Multi-block partial final: AES-128 Mlen=33. Multi-block complete final: AES-256 Mlen=48. Truncated tag lengths: Tlen={8,15} (AES-128), Tlen=10 (AES-256) |

### KDF (Layer 5 building block)

NIST CAVS 14.4 KDF-CTR vectors: AES-128 and AES-256 keys, derived output lengths 128 and 256 bits (4 vectors).

### FAEST reference cross-validation

The FAEST-EM-128F parameter set is used to cross-validate against the FAEST reference implementation (`faest-ref`) at multiple layers:

| Layer | What is cross-validated |
|-------|-------------------------|
| GF(2^k) arithmetic | All field sizes from GF(2^8) to GF(2^256). Known-answer vectors from `faest-ref` Appendix A.1 validate `ByteCombine` and the embed / ring-homomorphism operations used by the QuickSilver proof system. |
| PRG (AES-CTR) | Output compared against `faest-ref/prg_tvs.hpp`. |
| GGM tree / vector commitment | Commit, Open, Reconstruct cross-validated against `faest-ref/bavc_tvs.hpp` for FAEST-EM-128F (GGM expansion, LeafCommit, global commitment hash). |
| AES circuit | `faest-ref` one-way-function vectors used to validate the full AES-128 and AES-256 circuit evaluation end-to-end. |

### Property tests (proof system)

Beyond known-answer vectors:

- **Valid witness, valid proof:** verifier accepts.
- **Invalid witness:** prover rejects upfront (X-10).
- **Modified proof bytes:** verifier rejects (every section: c, u_tilde, d, a1_tilde, a2_tilde, decom_i, chall_3, iv, ctr; each tested by single-byte tamper).
- **Wrong Fiat-Shamir seed:** verifier rejects (cross-seed replay protection).
- **Wrong instance:** verifier rejects (instance binding into the transcript).
- **Two-phase round-trip:** `prove_commit` / `prove_respond` produces the same proof bytes as one-shot `prove`, and `chall_1` mismatches between the two phases are detected.

The complete test suite runs once per built variant (up to seven: sw, clmul, aesni, clmul_aesni on x86_64; armv8_aes, pmull, armv8 on aarch64; the CMake configuration step omits variants whose required hardware extension was not detected on the host). It currently includes 96 tests (memory safety regression suite) plus per-module tests for each circuit building block and proof variant.

---

## Performance Benchmarking

### Scope: in `examples/`, not in the library

The library exposes no benchmarking surface of its own: `voleith_prove` and
`voleith_verify` are the only entry points needed to measure prove / verify
cost.  Benchmarking helpers live alongside the example programs in
[`examples/bench_util.h`](../examples/bench_util.h) so that the public API
stays focused on the proof system, and so that consumers can copy the same
pattern into their own application code without depending on a measurement
API that would otherwise have to be supported as part of the ABI.

Two examples are wired up out of the box: `example_merkle_gf8` (AES-DM
nodes) and `example_merkle_grostl_gf8` (wide-node Grøstl).  They were the
first targets because the prove / verify cost trade-off between the two
hash families (cheap-but-2⁶⁴ vs. expensive-but-2¹²⁸) is the most
load-bearing per-application choice in the library, and the only one where
"how much does that actually cost?" needs to be answered with numbers, not
just gate-count algebra.

### `bench_util.h` API

Header-only, three functions:

- `bench_now_ns()`: `clock_gettime(CLOCK_MONOTONIC)` wrapped to a `uint64_t`
  nanosecond timestamp.  Requires `_POSIX_C_SOURCE >= 199309L` defined
  before any include.
- `bench_compute(samples, n)`: sorts the samples in place and returns
  `{min, median, mean, max, n}` over a millisecond-sample array.
- `bench_print(label, stats)`: prints the four statistics on one line.

The examples define `BENCH_WARMUP`, `BENCH_PROVE_ITERS`, and
`BENCH_VERIFY_ITERS` (2 / 25 / 100 by default) at the top of `main` so that
consumers cribbing the pattern can adjust them in one place.  Sample arrays
are stack-allocated; no allocation in the timed region.

### Methodology

Timing noise on a loaded OS is **one-sided slow**: preemption, cache
misses, page faults, frequency dips can only ever make a sample slower, not
faster.  Two consequences shape the methodology:

- **The minimum is the cleanest estimate of intrinsic cost.**  It is the
  sample least contaminated by the noise floor.  Report it as the floor for
  "how fast can this code run on this host."
- **The fast tail is never trimmed.**  Symmetric percentile cropping
  (e.g. dudect's 5th/95th percentile crop) exists to stabilise the
  two-sample t-test that dudect runs for leakage detection, not to estimate
  runtime.  For runtime estimation, trimming the fast tail throws away the
  cleanest signal.

`bench_util.h` therefore reports min / median / mean / max and lets the
caller pick the right statistic for the question being asked.  Median is
the typical-run number to compare against a budget; mean is sensitive to
outliers and usually less useful than median here; max bounds the
preemption tail and is useful for "could this miss a latency target."

Warmup iterations fill caches, settle frequency scaling, and (on the
prover side) let the grinding loop's random hit-rate stabilise.  The
default of 2 is enough for the existing examples but is exposed as a
`#define` so it can be raised for noisier hosts.

The `example_merkle_*` benchmarks generate a fresh proof per `prove`
iteration (the grinding loop's variance is a real prover cost and should be
visible in the spread) and run the verify loop against one fixed proof
(valid-proof verify cost does not depend on which valid proof, so pinning to
one removes a confound).

### Why `taskset -c 0`

`taskset(1)` pins the process to a single logical core.  This eliminates
two large sources of variance:

1. **Cross-core migration.**  Unpinned processes move between cores at the
   scheduler's discretion, and a migration costs a full cold-cache restart
   on the destination core, visible as a long-tail spike in the samples.
2. **Frequency-domain churn.**  Even with the governor in `performance`
   mode, the package-level boost decision is per-core; pinning makes the
   per-iteration frequency stable.

Core 0 is the conventional pick because it is the boot CPU and is normally
the lowest-numbered logical core (with no SMT sibling on single-socket
configurations).  Any specific core works; the important properties are
"the same one each iteration" and "not shared with another CPU-heavy
process."  Disabling Hyper-Threading or pinning to one logical CPU per
physical core (`taskset -c 0,2,4,...` on most x86 layouts) removes
sibling-contention variance on top of that.

Other hygiene that helps when the noise floor matters:

- `sudo cpupower frequency-set -g performance` (Linux): keeps the
  governor from down-clocking between samples.
- Disable Intel Turbo / AMD Boost via `/sys/devices/system/cpu/cpufreq/`
  if you want a flat clock; otherwise the boost will be active during the
  benchmark (often what you want, but variable).
- Run on a host that is not doing anything else.  The fast tail will
  reflect the host's idle floor; the slow tail will reflect whatever else
  is contending.

### Adapting the pattern to a consumer circuit

Users instrumenting their own circuit can follow the same shape in their
own program:

```c
#define _POSIX_C_SOURCE 199309L
#include "bench_util.h"   /* copied or vendored from examples/ */

#define WARMUP 2
#define PROVE_ITERS 25

double prove_ms[PROVE_ITERS];

for (int w = 0; w < WARMUP; w++) {
    voleith_proof_t p = {0};
    voleith_gf8_prove(&p, params, c, witness, instance, ds, ds_len);
    voleith_proof_free(&p);
}

for (int i = 0; i < PROVE_ITERS; i++) {
    voleith_proof_t p = {0};
    uint64_t t0 = bench_now_ns();
    voleith_gf8_prove(&p, params, c, witness, instance, ds, ds_len);
    uint64_t t1 = bench_now_ns();
    prove_ms[i] = (double)(t1 - t0) / 1e6;
    voleith_proof_free(&p);
}

bench_print("prove", bench_compute(prove_ms, PROVE_ITERS));
```

Run with `taskset -c 0 ./your_program`.  The same shape applies for verify;
keep the witness-build work outside the timed region so it does not pollute
the prove samples (the verify loop has no witness, so no equivalent
concern).

`bench_util.h` is intentionally a header-only file with no `voleith_`
prefix; it is not part of the library's ABI surface and is meant to be
copied into consumer projects (or vendored as-is) rather than depended on
across a library version boundary.

---

## References

### Primary specification

- FAEST v2.0. NIST PQC Round 2 additional signatures submission. The complete protocol specification.

### Academic papers

- Baum, Braun, de Saint Guilhem, Klooß, Orsini, Roy, Scholl. *Publicly Verifiable Zero-Knowledge and Post-Quantum Signatures from VOLE-in-the-Head*. CRYPTO 2023. ePrint 2023/996.
- Yang, Sarkar, Weng, Wang. *QuickSilver: Efficient and Affordable Zero-Knowledge Proofs for Circuits and Polynomials over Any Field*. CCS 2021. ePrint 2021/076.
- Baum, Beck, Delpech de Saint Guilhem, Klooß, Orsini, Roy, Scholl. *Faster VOLEitH Signatures from All-but-One Vector Commitments and Half Trees*. ePrint 2024/097.
- Canright. *A Very Compact S-Box for AES*. CHES 2005.
- Gauravaram, Knudsen, Matusiewicz, Mendel, Rechberger, Schläffer, Thomsen. *Grøstl: a SHA-3 candidate*. SHA-3 competition finalist (Round 3 specification).
- Hirose. *Some Plausible Constructions of Double-Block-Length Hash Functions*. FSE 2006, LNCS 4047 pp. 210-225. The Hirose-DBL compression and its ideal-cipher collision-resistance proof; instantiated here over AES-256 for the 2¹²⁸-CR Merkle node hash.
- Reparaz, Balasch, Verbauwhede. *Dude, is my code constant time?* NDSS 2017. (dudect methodology)

### Standards

- FIPS 197: Advanced Encryption Standard (AES).
- FIPS 202: SHA-3 Standard.
- NIST SP 800-38A: Block cipher modes of operation.
- NIST SP 800-108r1-upd1: Key derivation using PRFs.
- RFC 4493: AES-CMAC.
- RFC 6962: Certificate Transparency (source of the 0x00 / 0x01 leaf / internal-node domain-separation prefix used by the Grøstl Merkle circuit).

### Reference implementations (test oracles only)

- `faest-ref` (MIT): reference FAEST implementation used as test oracle for known-answer cross-validation. No source code copied.
