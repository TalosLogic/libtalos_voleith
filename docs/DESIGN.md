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
  aes_cmac_circuit / gf8 variant        AES-CMAC (RFC 4493)
  kdf_ctr_cmac_circuit / gf8 variant    NIST SP 800-108 KDF-CTR(AES-CMAC)
  merkle_circuit / merkle_gf8_circuit   Merkle path verification (AES-DM / CMAC)
  merkle_grostl_gf8_circuit             Wide-node Grøstl Merkle path
  indexed_merkle_circuit / gf8 variant  Indexed Merkle non-membership

Layer 4: proof/                    QuickSilver proof system
  circuit / gf8_circuit                 Circuit definition API
  prover / gf8_prover                   QuickSilver prover (AND / mul check)
  verifier / gf8_verifier               QuickSilver verifier
  proof / gf8_proof                     Fiat-Shamir wrapper (non-interactive)
  vole_hash                             VOLEHash (FAEST Figure 4.4)

Layer 2-3: vole/                   VOLE-in-the-Head protocol
  vc                                    GGM tree vector commitment
  convert                               ConvertToVOLE (FAEST Figure 5.2)
  voleith                               VOLEitH commitment and reconstruction

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

## Parameter Sets

Six parameter sets are provided. They use the FAEST-EM leaf-commitment
parameter line (`n_leafcom = 2`); see "What 'EM' refers to" below.

| Parameter | λ | τ | Leaves/instance | w_grind | T_open | Proof size¹ |
|-----------|---|---|-----------------|---------|--------|-------------|
| `em_128f` | 128 | 16 | 128–256 | 8 | 112 | 6,596 B |
| `em_128s` | 128 | 11 | 2,048 | 7 | 103 | 4,962 B |
| `em_192f` | 192 | 24 | 128–256 | 8 | 176 | 12,380 B |
| `em_192s` | 192 | 16 | 2,048–4,096 | 8 | 162 | 9,340 B |
| `em_256f` | 256 | 32 | 128–256 | 8 | 234 | 19,636 B |
| `em_256s` | 256 | 22 | 2,048–4,096 | 6 | 218 | 15,344 B |

¹ GF(2⁸) AES-128 circuit (ℓ = 216 elements: 16 key bytes + 200 S-box
inverses), computed from `voleith_gf8_proof_byte_size`. The `em_128f` row is
cross-checked against the measured proof. The bit-level GF(2) variant of the
same circuit is ~2.7× larger (`em_128f`: 17,796 B) because each S-box costs
36 AND-gate slots instead of a single mul slot.

The τ, w_grind, and T_open values are the parameter-set definitions in
`proof/proof.c`; T_open follows the FAEST-EM `meson.build` of the reference
implementation. Leaves/instance is the per-instance GGM leaf count from
`voleith_vc_N`: each vector commitment splits into τ₁ instances of 2^k leaves
and τ₀ of 2^(k-1) (FAEST spec Table 5.1), so the count is a range, not a
single power of two.

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

Current coverage is complete across both hash families: the DM/CMAC and the wide-node Grøstl Merkle path and indexed non-membership circuits all exist in both public-dir and secret-dir forms (`merkle_grostl_gf8_path_circuit` / `_secret_dir`, `indexed_merkle_grostl_gf8_nonmember_circuit` / `_secret_dir`). Every secret-dir circuit enforces direction-bit booleanity in-circuit.

The secret-dir variant adds `node_bytes` mul-slots plus one direction-bit witness per level (≈ 8% over a DM level's ~216 slots; proportionally far less for the wide Grøstl nodes). **Do not collapse the two into one API**: keeping the public-dir path gate-free avoids silently inflating proof size for the public-index case. **Every secret-dir circuit must constrain each direction wire to `{0,1}` inside the circuit** via `assert_product(dir, dir, dir)` (free: zero mul-slots, zero witnesses). This is soundness-critical: an unconstrained mux selector lets the prover make neither mux output equal the carried-up value, erasing it and forging a path, so booleanity must never be left to the caller.

### Indexed Merkle non-membership: trust assumption on the tree builder

`indexed_merkle_nonmember_circuit` and the GF(2^8) variant prove that a target value is absent from an indexed Merkle tree by demonstrating an adjacent leaf `(value, next_value, next_index)` such that `value < target < next_value`, along with a valid Merkle path for that leaf.

The non-membership statement is sound under one **external** assumption that is **not** verified by the circuit: the tree builder maintains the adjacency invariant, namely that for every leaf `L` in the tree, `L.next_value` is the value of the leaf with the smallest value strictly greater than `L.value`, and `L.next_index` is that leaf's tree index. The circuit cryptographically binds the prover to a real leaf record via the leaf hash and the Merkle path, and enforces the ordering relation `value < target < next_value`, but it cannot verify that `L.next_value` is in fact the next-larger value present in the tree.

Concretely, a deployment using `indexed_merkle_nonmember_circuit` is sound exactly when the protocol that produces the signed/agreed tree root is itself sound, i.e., the tree builder honestly maintains the linked-list invariant when inserting, updating, and deleting leaves. This is the standard model for indexed Merkle trees (the same assumption used by Aztec, Polygon Hermez, and similar deployments) and is satisfied by construction when a single trusted issuer (or a verifiable tree-update protocol) is responsible for tree maintenance.

If your threat model includes a fully malicious tree builder, this circuit is not sufficient on its own. Two mitigations are possible but not provided by this library:

1. An in-proof binding of `next_index` to the leaf actually stored at that index. This roughly doubles the circuit size and still cannot prevent a builder from omitting a leaf entirely.
2. A different data structure (e.g., a sparse Merkle tree keyed by value) with no linked list and no adjacency invariant.

The trust assumption is documented in the README's Pre-built circuit building blocks section so that integrators see it at the API surface and not only in the design document.

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

### Constant-time field arithmetic, with a gated variable-time path

All software paths in `core/field.c` are constant-time. The CLMUL (x86_64) and PMULL (ARMv8) hardware paths are constant-time by ISA definition. There is no variable-time table-lookup path enabled by default.

A `-DVOLEITH_ALLOW_VARIABLE_TIME_FIELD=ON` CMake flag exists to enable a variable-time path (faster for some operations, exposes a small timing side-channel on secret-dependent field elements). It is OFF by default and tests must opt in to use it. This gate exists for performance experiments and benchmarking; production deployments should leave it OFF.

The same design applies to AES: a constant-time bitsliced AES backend is always built, and the AES-NI (x86_64) and ARMv8 Crypto Extension (aarch64) hardware paths are constant-time by ISA definition. A variable-time table-lookup AES path is gated behind `-DVOLEITH_ALLOW_VARIABLE_TIME_AES=ON` and is OFF by default.

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

The standard-eval AES used by the PRG and by test code does use S-box tables (in the variable-time path) or bitsliced AES (in the constant-time fallback). Neither is accessible to the proof circuit's prover or verifier.

### Soundness-critical paths: implemented exactly per spec

The QuickSilver multiplication check in `proof/prover.c` and `proof/gf8_prover.c` is the central soundness mechanism. It is implemented exactly per the FAEST v2.0 specification with no optimisations that deviate from the spec. The same discipline applies to:

- The VOLEHash construction (`proof/vole_hash.c`, FAEST Figure 4.4).
- The ConvertToVOLE algorithm (`vole/convert.c`, FAEST Figure 5.2).
- The Fiat-Shamir challenge derivation order and transcript composition.

Performance optimisations are applied only to operations that do not affect soundness: PRG block batching, GF(2^k) CLMUL / PMULL acceleration, AES-NI and ARMv8 Crypto Extension dispatch. Anything that touches the multiplication check, the VOLEHash, or the challenge derivation is left exactly as the spec dictates.

---

## Correctness Testing

The library is tested against known-answer vectors from multiple independent sources. CMake auto-detects the host's hardware extensions and builds every relevant variant: software-only (always), x86 CLMUL, AES-NI, and combined CLMUL+AES-NI on x86_64; ARMv8 AES, PMULL, and combined ARMv8 (AES+PMULL) on aarch64. Each variant runs the full test suite against the same vectors, ensuring backend dispatch does not affect correctness.

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

The complete test suite runs once per built variant (up to eight: sw, clmul, aesni, clmul_aesni, sw_vartime on x86_64; armv8_aes, pmull, armv8 on aarch64; the CMake configuration step omits variants whose required hardware extension was not detected on the host). It currently includes 96 tests (memory safety regression suite) plus per-module tests for each circuit building block and proof variant.

---

## Future Enhancements

These items are intentionally scoped for future releases.

### Runtime hardware detection and dispatch (single-binary fat builds)

The library currently selects its AES and field-multiplication backends at compile time based on CMake feature probes. This produces a binary that is fast on its build target but suboptimal everywhere else: a binary built without AES-NI runs at bitsliced speed on a host that has AES-NI; a generic distro-package build targeting "any aarch64" cannot use Apple Silicon's hardware AES even when present.

The fix is a fat-binary build that compiles every backend the toolchain can produce, then chooses the best one at first use via runtime CPU-feature detection. The pattern is well-established in audio / video codec libraries; the cleanest reference implementation to study is FFmpeg (`libavutil/cpu.c`, `libavutil/aarch64/cpu.c`, `libavutil/x86/cpu.c`, and the per-codec `_init` dispatchers in `libavcodec/`). FFmpeg's design factors cleanly into "detect features once" plus "per-function dispatch table populated from those features" - the same shape libtalos_voleith needs.

**Design.** A new `core/dispatch.c` exposes `voleith_cpu_features()` returning a bitmask populated once at first call via:

- x86_64: `__get_cpuid_count` / `__cpuid_count` (GCC, Clang) for AES-NI (`CPUID.01H:ECX[25]`), CLMUL (`CPUID.01H:ECX[1]`), AVX2 if useful (`CPUID.07H:EBX[5]`).
- aarch64 Linux: `getauxval(AT_HWCAP)` for `HWCAP_AES`, `HWCAP_PMULL`, `HWCAP_SHA2`.
- aarch64 macOS: `sysctlbyname("hw.optional.arm.FEAT_AES", ...)`, `FEAT_PMULL`, etc.
- RISC-V Linux: `getauxval(AT_HWCAP)` once the kernel exposes the relevant bits; `riscv_hwprobe` syscall as fallback.

The `voleith_aes_*` and `voleith_field_*` entry points become thin dispatchers that select the best available backend on first call and cache the choice in a `static atomic` function-pointer table. Subsequent calls pay one indirect-branch cost, which is negligible relative to AES round latency.

**Build impact.** CMake compiles every backend the toolchain can target, regardless of the build host's CPU. The single resulting binary picks the right backend at runtime. Lean builds (size-constrained embedded targets) opt out per-backend with `-DVOLEITH_AES_NI=OFF`, `-DVOLEITH_ARMV8_AES=OFF`, etc. The default is fat.

**Cost.** Binary size grows by approximately 30-50 KB per additional AES backend and 10-20 KB per field backend. For a 200-300 KB library, that is a 20-30% size increase in exchange for "works fast everywhere out of the box." On hosts where size matters, the per-backend opt-out flags keep the lean-build option available.

**Test impact.** Each backend is currently validated under its own build configuration in the four-variant CI matrix (sw, clmul, aesni, clmul_aesni). With runtime dispatch the matrix collapses: one fat binary runs every backend its hardware supports, on every test host. A `VOLEITH_FORCE_BACKEND=<name>` environment variable lets tests pin a specific backend regardless of available hardware, preserving per-backend coverage on a single host.

### Runtime backend-mismatch detection (lean builds only)

Once runtime dispatch (above) is in place, the default fat binary always picks the best available backend, and the deployment-mistake case largely disappears. It remains relevant only for **lean builds** that explicitly compile out a backend (e.g., `-DVOLEITH_AES_NI=OFF` for an embedded target with size constraints) and are then deployed to a host that has that hardware. The binary silently uses the bitsliced fallback at ~30-50× the speed it could be running at. This is functionally correct (bitsliced is constant-time and produces identical outputs) but operationally a pitfall.

**Implementation scope.** A one-shot probe at first `voleith_aes_*` call using the same `voleith_cpu_features()` machinery. If the running CPU advertises a hardware path that this binary was not built with, print a single stderr warning suggesting either a rebuild with the relevant `-D...=ON` flag or a default (fat) build. Suppressed by `VOLEITH_QUIET=1`. Idempotent via a single `static atomic_flag`. No security implication; purely a deployment-mistake aid.

### RISC-V cryptography extensions (gated on hardware availability)

RISC-V is finalising scalar and vector cryptography extensions (`Zkn*`, `Zvbb`, `Zvbc`, `Zvkg`, `Zvkned`, `Zvksh`) that include AES round instructions (`AES32ESI`, `AES32ESMI`, `AES64ES`, `AES64ESM`, plus vector forms), GF(2) multiplication (`CLMUL`, `CLMULH`, vector `vclmul.vv`), and SHA-2 / SHA-3 acceleration. Linux distributions for RISC-V SoCs with these extensions are emerging; volume commercial silicon is still rare as of this writing.

**Implementation scope.** A new `core/aes_riscv.c` and (eventually) `core/field_riscv.c` matching the existing dispatch surface alongside the AES-NI / ARMv8 / bitsliced backends. CMake probe based on the `-march` extension string (e.g., `-march=rv64gc_zkn`). This work is **deferred until validation hardware is available**: a hardware-accelerated backend that has not been run on real silicon is a liability, not an asset. Target hardware: a SiFive HiFive Premier P550 dev board, the Milk-V Jupiter / Megrez class, or any equivalent Zkn-capable SBC once they ship in volume and a constant-time validation host (including dudect) can be sourced.

### Half-tree GGM optimisation

The "Faster VOLEitH Signatures" paper (ePrint 2024/097) describes a half-tree construction for the GGM vector commitment. Instead of expanding a full binary tree of depth log₂(N), one half of the tree is derived from the VOLE correlation, halving the number of PRG calls during commitment and cutting the `c` component of the proof by approximately 50%.

This is the single highest-priority optimisation for large-circuit workloads such as the Signal KVAC anonymous credential circuit (ell = 7,808, τ = 16, 128–256 leaves per instance, ~3,072 total): the GGM tree commitment currently dominates both proving time (~3,072 leaf expansions) and proof size, so halving it would deliver a roughly 2× improvement in both. The optimisation is protocol-level (it benefits all parameter sets and both proof variants equally) and is a drop-in replacement for the GGM expansion in `vole/vc.c` with no API changes required.

**Implementation scope.** The change is contained to `vole/vc.c` (GGM expansion and opening) and the corresponding verifier reconstruction path. The Fiat-Shamir transcript composition, QuickSilver gates, and parameter-set numerics are unchanged. The principal subtlety is that the half-tree construction introduces a correlation-robust hash (H_ccr) over GGM nodes that must be domain-separated from the existing leaf-commit hash; getting that domain separation wrong would silently weaken soundness, so the implementation must include faest-ref half-tree cross-validation vectors before being trusted.

### `n_leafcom = 3` FAEST variant

The non-EM FAEST variants use `n_leafcom = 3` with a different leaf commitment construction. Two `TODO` comments in `vole/vc.c` mark the code paths that would need to change. The six FAEST-EM parameter sets cover all use cases known to the maintainers; the non-EM variants would be added if a consumer needed them.

### Boyar-Peralta S-box for bit-level AES circuit

If proof size in the bit-level variant becomes a concern, replacing the Canright `gf8_inv` in `circuits/aes_circuit.c` with the Boyar-Peralta circuit (32 AND gates per S-box, down from 36) is a contained change that does not affect the GF(2^8) variant (already at the minimum cost of 1 byte per S-box).

---

## References

### Primary specification

- FAEST v2.0. NIST PQC Round 2 additional signatures submission. The complete protocol specification.

### Academic papers

- Baum, Braun, de Saint Guilhem, Klooß, Orsini, Roy, Scholl. *Publicly Verifiable Zero-Knowledge and Post-Quantum Signatures from VOLE-in-the-Head*. CRYPTO 2023. ePrint 2023/996.
- Yang, Sarkar, Weng, Wang. *QuickSilver: Efficient and Affordable Zero-Knowledge Proofs for Circuits and Polynomials over Any Field*. CCS 2021. ePrint 2021/076.
- Baum, Beck, Delpech de Saint Guilhem, Klooß, Orsini, Roy, Scholl. *Faster VOLEitH Signatures from All-but-One Vector Commitments and Half Trees*. ePrint 2024/097.
- Canright. *A Very Compact S-Box for AES*. CHES 2005.
- Gauravaram, Knudsen, Matusiewicz, Mendel, Rechberger, Schläffer, Thomsen. *Grøstl – a SHA-3 candidate*. SHA-3 competition finalist (Round 3 specification).
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
