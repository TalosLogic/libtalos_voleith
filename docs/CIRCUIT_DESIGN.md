# Circuit and Hash-Construction Design

This document collects the per-circuit and per-hash construction design
rationale: the AES S-box choice, the KDF/CMAC choice, the Merkle path and
indexed-non-membership circuits, the node-hash families (DM/CMAC, Grøstl,
Hirose), and the generic `voleith_node_hash_vt` bridge. These are the
building blocks the higher-level capabilities compose.

For the proof system, layered architecture, and library-level invariants
(constant-time discipline, API-boundary validation, memory hygiene,
soundness-exact paths) see [`docs/DESIGN.md`](DESIGN.md). For the
ring-signature capabilities built on these circuits see
[`docs/RING_SIGNATURES_DESIGN.md`](RING_SIGNATURES_DESIGN.md). Cross-references
below to "the Shipshape section" or "the verify-scaling discussion" point into
`docs/DESIGN.md`.

## Canright (2005) tower-field S-box, not Boyar-Peralta

The AES S-box circuit uses the Canright tower-field decomposition over GF(((2^2)^2)^2). This gives 36 AND gates per S-box in the bit-level variant.

The Boyar-Peralta (2012) computer-searched S-box reduces AND gate count to 32 per S-box (an 11% reduction for the bit-level variant: 7,200 → 6,400 AND gates for AES-128). It is used by faest-ref and other VOLEitH implementations.

**Why this library uses Canright anyway:**

1. **GF(2^8) variant unaffected.** In the element-level QuickSilver variant, S-box cost is one `inv_in` witness byte per S-box regardless of internal AND gate count. The inversion is expressed as two free `assert_product` constraints. The AND gate count inside the inversion is irrelevant to proof size or VOLE slot count. Boyar-Peralta provides no benefit to the GF(2^8) circuit, which is the recommended path for AES-containing circuits.

2. **Clean-room hand-derivable.** Canright's decomposition can be derived from first principles from the GF(2^8) tower-field identity. Boyar-Peralta is a computer-search result; clean-room reimplementation requires either re-running the search (impractical) or carefully transcribing the published optimised circuit (which raises clean-room provenance questions).

3. **Drop-in replacement available if needed.** If proof size in the bit-level variant becomes a concern, replacing `gf8_inv` in `circuits/aes_circuit.c` with the Boyar-Peralta circuit (32 AND gates) is a contained, protocol-neutral change with no API impact.

## FAEST "norm trick" not implemented

The FAEST v2.0 specification (Section 6) describes an "InvNorm" optimisation for the AES S-box: instead of committing to the full 8-bit inverse witness `x⁻¹`, the prover commits only to a 4-bit element `c = x¹⁷ ∈ GF(2⁴)`. This reduces the raw inversion witness from 1 byte to 0.5 bytes per S-box.

The norm trick is part of the FAEST-EM extended witness model and applies only to the **bit-level circuit variant**. In that model the S-box *output* is also separately committed as an additional witness element (1 byte per S-box), because `ZK.SBoxAffine` must verify the affine output transformation using the committed Galois conjugates of `c`. The net cost per S-box is therefore 0.5 + 1 = **1.5 bytes**, compared to this library's current **1 byte** (a single `inv_in` witness).

In the GF(2^8) element-level variant, each S-box already costs exactly one `inv_in` witness byte regardless of how the inversion is decomposed internally. The norm trick has no meaning in this model: there is no separate "output wire" to commit to, and `assert_product` checks are free. The GF(2^8) variant is already at the minimum achievable cost of 1 byte per S-box.

The norm trick therefore does not apply to the general-purpose circuit model used here and would *increase* witness size by 50% in the bit-level variant if naively adopted.

The correct interpretation of FAEST Figure 6.6 `InvNormToConjugates` is that the 0.5-byte norm element `c = x¹⁷` and the 1-byte separately committed S-box output `y` are two parts of the same per-S-box witness package. The FAEST signature scheme can use this split because its S-box is specifically the AES-128 SubBytes and its bit-level circuit is hand-tailored to the FAEST-EM extended witness model. A general-purpose bit-level circuit library that does not pre-commit S-box outputs separately cannot capture the norm-trick saving without re-architecting its entire witness layout, at which point the saving (relative to the GF(2^8) variant's 1 byte per S-box) is negative.

## AES-CMAC for KDF, not raw AES-CTR or Keccak

The KDF circuit building block (`kdf_ctr_cmac_circuit` / `kdf_ctr_cmac_gf8_circuit`) implements NIST SP 800-108r1-upd1 Section 4.1: KDF in Counter Mode with AES-CMAC as the PRF.

Three alternatives were considered and rejected:

| Construction | Why rejected |
|--------------|--------------|
| Raw AES-CTR as PRF | Not NIST SP 800-108 approved. The PRP-PRF switching lemma gives a birthday bound at 2^64, which is below the FAEST-EM-128 security level. |
| Keccak / SHAKE as PRF | ~920,000 AND gates per Keccak permutation vs AES-128's 7,200. Prohibitive in circuit. |
| HMAC-SHA256 as PRF | SHA-256 is ~25,000 AND gates per compression; HMAC-SHA256 is two compressions. Far more expensive than AES-CMAC (~800 AND gates per CMAC of a short input). |

AES-CMAC in KDF Counter Mode is NIST SP 800-108 compliant, post-quantum secure (because it's symmetric-key only), and approximately 30× cheaper in circuit than HMAC-SHA256.

The library does not include HMAC-SHA256 or SHAKE-based PRFs as circuit building blocks because their circuit cost is prohibitive for VOLEitH workloads. SHAKE is used extensively *outside* circuits (Fiat-Shamir, commitment hashing, challenge derivation), where AES-NI / hardware crypto extensions are not available and SHAKE's portability matters.

## Merkle path direction bits: public-dir and secret-dir variants

The library provides both forms. `merkle_gf8_path_circuit` (and the bit-level equivalent) takes `path_dirs` as a plain `const uint8_t *` (0/1 values resolved at circuit-build time), so the left/right swap is static and costs zero gates per level, the right choice when the leaf *index* is genuinely public (e.g. the `example_merkle_gf8.c` demo: membership of a secret leaf *value* at a known position). `merkle_gf8_path_circuit_secret_dir` takes `path_dirs` as `const gf8_wire_id *` (committed witness wires) and muxes each node byte, costing `node_bytes` mul-gates per level, the right choice when the index itself must be hidden.

**Signal KVAC uses the secret-dir variant.** It is an *anonymous* group-membership credential, so the prover must not reveal which leaf is theirs: publishing the position would identify the member and defeat anonymity. Both the leaf value *and* the direction bits (the leaf index) are witness; only the Merkle root is a public instance value. These secret-dir variants are the foundation for ring-signature circuits in general.

Current coverage is complete across all three hash families: the DM/CMAC, the wide-node Grøstl, and the Hirose-AES-256 Merkle path and indexed non-membership circuits all exist in both public-dir and secret-dir forms (`merkle_grostl_gf8_path_circuit` / `_secret_dir`, `indexed_merkle_grostl_gf8_nonmember_circuit` / `_secret_dir`, and the generic vt-driven `merkle_vt_gf8_path_circuit` / `_secret_dir` and `merkle_vt_gf8_indexed_nonmember_circuit` / `_secret_dir` parameterised by `voleith_node_hash_vt`, which is how Hirose ships). Every secret-dir circuit, fixed-hash or vt-driven, enforces direction-bit booleanity in-circuit.

The secret-dir variant adds `node_bytes` mul-slots plus one direction-bit witness per level (≈ 8% over a DM level's ~216 slots; proportionally far less for the wide Grøstl nodes). **Do not collapse the two into one API**: keeping the public-dir path gate-free avoids silently inflating proof size for the public-index case. **Every secret-dir circuit must constrain each direction wire to `{0,1}` inside the circuit** via `assert_product(dir, dir, dir)` (free: zero mul-slots, zero witnesses). This is soundness-critical: an unconstrained mux selector lets the prover make neither mux output equal the carried-up value, erasing it and forging a path, so booleanity must never be left to the caller.

## Per-proof public directions: the free scale-by-instance gate

The static public-dir path above resolves its directions at *circuit-build* time: one fingerprint per direction pattern. That is wrong for a case that arose with forward-secure ring signatures (V6): a path whose directions are public but *vary per proof* (the bits of a public epoch `t`). Building a distinct circuit per `t` would give a distinct fingerprint per epoch, so a verifier could not pin one circuit for the identity. Muxing on `t` as witness would work but pay `node_bytes` mul-slots per level, and it would be a lie, `t` is public.

The fix is a gate that multiplies a wire by a **public instance wire** for free: `GF8_WIRE_SCALE_INSTANCE`, `c = a · b` with `b` constrained to be an INSTANCE wire (`voleith_gf8_add_scale_instance`). Because `b` is public, `x -> b·x` is a per-proof GF(2)-linear map on `a`, so it costs zero VOLE slots (the same reason XOR and the fixed linear maps are free): the prover and verifier both derive the 8×8 multiply-by-`b` matrix from the public byte at proof time. This is unlike `MUL`, which multiplies two committed wires and costs a slot. From it, `voleith_gf8_add_mux_instance(a, b, sel) = a XOR sel·(b XOR a)` is a slot-free public-selector mux, and a public-dir path built from it has **one circuit fingerprint independent of the direction values**, so V6 gets one epoch-tree circuit per identity regardless of `t`.

Two soundness points: (1) the instance-only constraint on `b` is enforced at gate-build time *and* re-checked by `voleith_gf8_circuit_validate`, since a secret `b` would need a VOLE slot the free path does not allocate; and (2) the circuit fingerprint absorbs the gate kind and operand wire ids, not the runtime matrix, which is exactly why the fingerprint is stable across differing instance byte values. The gate is exposed to `.ship` as the `SCALE_INSTANCE` opcode (the first `.shipshape 1.1` Tier 1 addition; see `docs/specs/SHIPSHAPE_SPEC.md` §4.2.5).

## Indexed Merkle non-membership: trust assumption on the tree builder

`indexed_merkle_nonmember_circuit` and the GF(2^8) variant prove that a target value is absent from an indexed Merkle tree by demonstrating an adjacent leaf `(value, next_value, next_index)` such that `value < target < next_value`, along with a valid Merkle path for that leaf.

The non-membership statement is sound under one **external** assumption that is **not** verified by the circuit: the tree builder maintains the adjacency invariant, namely that for every leaf `L` in the tree, `L.next_value` is the value of the leaf with the smallest value strictly greater than `L.value`, and `L.next_index` is that leaf's tree index. The circuit cryptographically binds the prover to a real leaf record via the leaf hash and the Merkle path, and enforces the ordering relation `value < target < next_value`, but it cannot verify that `L.next_value` is in fact the next-larger value present in the tree.

Concretely, a deployment using `indexed_merkle_nonmember_circuit` is sound exactly when the protocol that produces the signed/agreed tree root is itself sound, i.e., the tree builder honestly maintains the linked-list invariant when inserting, updating, and deleting leaves. This is the standard model for indexed Merkle trees (the same assumption used by Aztec, Polygon Hermez, and similar deployments) and is satisfied by construction when a single trusted issuer (or a verifiable tree-update protocol) is responsible for tree maintenance.

If your threat model includes a fully malicious tree builder, this circuit is not sufficient on its own. Two mitigations are possible but not provided by this library:

1. An in-proof binding of `next_index` to the leaf actually stored at that index. This roughly doubles the circuit size and still cannot prevent a builder from omitting a leaf entirely.
2. A different data structure (e.g., a sparse Merkle tree keyed by value) with no linked list and no adjacency invariant.

The trust assumption is documented in the README's Pre-built circuit building blocks section so that integrators see it at the API surface and not only in the design document.

### Software validator at the helper boundary

For the common case of an honest-but-buggy tree builder (the usual operational reality), `circuits/indexed_merkle_vt_gf8_helpers.{c,h}` ships a public `voleith_imt_vt_validate_records` that catches the soundness-critical record-array patterns at the public-API boundary. It is invoked automatically by both `voleith_imt_vt_build` and `voleith_imt_vt_lookup_nonmember`, so the malformed cases below are rejected loudly with `-1` instead of silently producing a verifying-but-false non-membership proof. Callers may also pre-validate once before a batch of lookups.

The validator enforces three invariants in one O(n) lsb-first pass:

1. **Sort order.** `records[i].value <= records[i+1].value`. Equality is permitted so that trailing "max sentinel" records (`value == next_value == MAX`) can be repeated to pad `n_records` to a power of two: the pattern used by `examples/example_ring_sig_v1_revocable_gf8.c`.
2. **Well-formed intervals.** `records[i].value <= records[i].next_value`. Rules out wrap-around intervals that would otherwise let an adversarial prover `assert_lt` on a target outside the IMT's value range.
3. **No overlap.** For every non-degenerate record (`value < next_value`), if `i < n_records - 1` then `next_value[i] <= value[i+1]`. This is the soundness-critical check: an overlap (`next_value[i] > value[i+1]`) lets an adversary use `records[i]` as their witness to `assert_lt` on `target = records[i+1].value`, forging a non-membership proof for an actual member. The most common operational foot-gun (inserting a new record without updating the predecessor's `next_value`) produces exactly this overlap and is caught here. Degenerate records (empty intervals, `value == next_value`) are exempt from this check because the circuit's strict `assert_lt(v, target, v)` can never hold for any `target`, so they cannot drive an attack.

What the validator deliberately does **not** check is **completeness** at the extremes of the value range: that is the application's sentinel policy (explicit `(0, first_real)` and `(last_real, MAX)` sentinels, wrap-around, or some other convention). A target outside any record's interval simply returns `-1` from `voleith_imt_vt_lookup_nonmember`. No verifying-but-false non-membership proof can be produced for a member by any caller whose record array passes the validator.

The validator does **not** lift the external trust assumption above: it cannot, since it sees only one record array, not the history of inserts / updates / deletes a tree builder ran to produce it. A fully malicious builder can still omit a leaf entirely or build a structurally well-formed but semantically wrong tree. The validator's contribution is purely defense-in-depth against the operational class of bugs (sort-order violations, broken linked-list consistency, forgotten predecessor updates) that arise from hand-maintained record arrays.

## Bounded-range assertion (`assert_in_range_gf8`)

`assert_in_range_gf8(value, low, high, n_bytes)` (`circuits/range_gf8_circuit.{c,h}`) constrains `low <= value <= high` (inclusive) for `n_bytes`-wide unsigned little-endian byte-vector wires, packaging the common "value in an interval" pattern (timestamp validity windows, version-number floors, numeric attribute thresholds) that otherwise has every caller hand-wire two comparisons. It is the same comparison machinery used by the indexed-Merkle non-membership check above, exposed as a reusable primitive; it underpins the attribute / selective-disclosure ring-signature predicates, whose `RANGE` checks are range checks over hidden attributes.

Two design points are load-bearing:

- **Inclusive bounds without overflow.** The underlying comparator is *strict* (`a < b`). Inclusive bounds are expressed as `value >= low` ≡ `NOT(value < low)` and `value <= high` ≡ `NOT(high < value)`, asserting that each strict comparison wire is `0`. Encoding `<=` as `< (bound ± 1)` would underflow at `0` or overflow at the max value of the width; the `NOT(strict)` formulation has no such edge case and the two boundaries `value == low` and `value == high` are accepted by construction.
- **A separate module, not a call into the indexed-Merkle comparator.** The strict-less-than core is reproduced here as a small helper that *returns* the comparison-result wire (rather than asserting on it, as `indexed_merkle_gf8_assert_lt` does). This keeps the range primitive in a neutral home and leaves the indexed-Merkle gate stream byte-identical, so its frozen Shipshape body hash is unaffected. Both share the byte-0-is-LSB convention and the 3-mul-gates-per-bit cost; a range assertion is two such comparisons (6 mul gates per bit, two `assert_zero`, no witness slots).

Like the comparator it builds on, `assert_in_range_gf8` is a Layer 4 C circuit builder composed of existing Tier 1 gates, not a Shipshape opcode (the Tier 1 set is closed); a `.ship` consumer reaches range logic only inside a Tier 2a construction body, never as a standalone op.

## DM vs CMAC Merkle hash trade-off

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

## Grøstl wide-node Merkle hashing, and why a 27-byte truncation

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

## Grøstl fixed-input node hashes (single compression, full collision resistance)

The `_T27` / `_T59` truncations buy a single-compression inode by *shrinking the node*, paying collision resistance (2^108 / 2^236) for the smaller digest. The fixed-input variants `voleith_node_hash_grostl256_fixed` (32-byte nodes, 2^128 CR) and `voleith_node_hash_grostl512_fixed` (64-byte nodes, 2^256 CR) reach the same single-compression cost while keeping the *full* node width and *full* collision resistance, by removing the padding instead of the digest bytes.

The construction is `H(L, R) = Ω(f(IV_inode, L ‖ R))` and `H_leaf(x) = Ω(f(IV_leaf, x ‖ 0-pad-to-block))`, where `f(h, m) = P(h ⊕ m) ⊕ Q(m) ⊕ h` is the Grøstl compression and `Ω(x) = trunc_n(P(x) ⊕ x)` is the Grøstl output transformation. Two changes versus the full-hash variants above:

- **No Merkle-Damgård padding.** The padding (`0x80` marker, zero fill, 64-bit length block) exists only to make the hash safe across *variable-length* messages. A node hash always consumes a fixed-length input (`L ‖ R` is exactly `2·node_bytes`), so the padding does no security work and is dropped. For a node width equal to half the Grøstl block (32 bytes for Grøstl-256, 64 for Grøstl-512), `L ‖ R` fills exactly one block, so the inode is a single compression: 1,920 S-boxes for `grostl256_fixed` (vs 3,200 for the full-hash `grostl256`), 5,376 for `grostl512_fixed` (vs 8,960). This is the same per-inode cost as `_T27` / `_T59`, at the full digest width.

- **IV-based domain separation, not a prefix byte.** Leaf vs internal-node separation is carried by distinct chaining values `IV_leaf ≠ IV_inode` (the fixed public value in the compression's chaining slot), not by the `0x00` / `0x01` in-message prefix the full-hash variants use. The prefix would push the inode message to `1 + 2·node_bytes` bytes, spilling into a second block and reintroducing the very cost this construction removes; moving domain separation into the IV keeps `L ‖ R` at exactly one block. The four IVs are distinct ASCII labels zero-padded to the block width.

- **The output transformation Ω is kept.** Dropping the padding is sound; dropping Ω would not be. Ω applies a full `P` permutation and a feed-forward before truncating, doing the wide-to-narrow compression the bare compression output does not. The construction is `Ω` of a full Grøstl compression, so its collision resistance rests on the same two standard facts the truncated variants rely on: collision resistance of the Grøstl compression function (full rounds; rebound attacks reach only round-reduced versions) and the soundness of wide-pipe truncation (the SHA-512/t pattern). Min over the two is 2^128 (`grostl256_fixed`) / 2^256 (`grostl512_fixed`). Dropping the length block is sound precisely because cross-length collisions cannot exist for a fixed-length input.

These two variants dominate all four prefix-padded Grøstl node hashes above: `grostl256_fixed` matches `_T27`'s 1,920 S-boxes at full 2^128 (vs `_T27`'s 2^108) and is 40% under `grostl256`; `grostl512_fixed` matches `_T59`'s 5,376 at full 2^256 (vs `_T59`'s 2^236) and is 40% under `grostl512`. They are the cheapest fully-Grøstl node hashes at each collision-resistance tier and supersede the older four, which remain only as frozen wire-format commitments (existing proofs and `.ship` selectors keep working). At the 2^128 tier Hirose-AES-256 (~1,000 S-boxes/inode) is still cheaper overall; `grostl256_fixed` is the strongest fully-Grøstl 2^128 option. The software side reuses `core/grostl.c` (`voleith_grostl{256,512}_compress_node`) and the circuit side reuses the existing Grøstl permutation builders; both are cross-checked against each other on every test run.

**Single-compression leaf capacity: reject, never clamp.** A fixed-input leaf consumes exactly one compression block, so its preimage has a hard byte ceiling (`leaf_block_bytes`): **32 bytes for `hirose_fixed32`, 64 bytes for `grostl256_fixed`, 128 bytes for `grostl512_fixed`** (`2·node_bytes` for the Grøstl pair, the two-iteration input width for Hirose). A shorter preimage is zero-padded into the block (this is what lets a V3 leaf pack `sk ‖ attributes` up to the ceiling); a preimage *over* the ceiling is **rejected**: `leaf_hash` and `leaf_build_witness` return `-1`. They do not silently clamp to the block and drop the high bytes. Clamping is a security bug, not a convenience: the dropped bytes are simply *not bound* by the hash, with no error to the caller. The motivating case is an indexed-Merkle record `value ‖ next_value ‖ next_index` (`2·node_bytes + index_bytes`): when the value width equals `node_bytes` (the revocation / spent-by-leaf shape) the record exceeds every fixed vt's block, so a clamp would silently hash only its prefix and leave the tail unauthenticated, yet proofs would still verify (prover and verifier clamp identically), masking the lost binding. Failing loud forces such wide-record IMTs onto a variable-leaf vt (`leaf_block_bytes == 0`: Hirose-variable, or the full-hash Grøstl vts), which absorbs any length by iterating. `leaf_circuit` is `void` and cannot signal, so it retains a buffer-bounding clamp; the matching `leaf_hash` / `leaf_build_witness` rejection guarantees no valid proof is ever built over a truncated leaf.

## Hirose-AES-256 double-block-length hash (primitive + circuit)

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

- **Fixed-32 leaf** (`voleith_node_hash_hirose_fixed32`).  Assumes an input of at most 32 bytes (zero-padded into the two iterations; a preimage over 32 bytes is rejected, never clamped, see "Single-compression leaf capacity" above).  Two iterations: the first chains from `HIROSE_IV_LEAF` with the first 16 input bytes as the message block, the second uses the iteration-1 output `(G, H)` as the chaining value and the next 16 input bytes as the message block.  Output is `G ‖ H` (32 bytes).  Per-leaf cost: 1,000 S-boxes.
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

**Quantum cryptanalysis (considered).**  Because this library is advertised as post-quantum, the dedicated *quantum* collision attacks published against this exact construction were reviewed.  Three papers target it directly:

- Chauhan, Kumar, Sanadhya, "Quantum Free-Start Collision Attacks on Double Block Length Hashing with Round-Reduced AES-256", IACR ToSC 2021(1), pp. 316-336 (DOI 10.46586/tosc.v2021.i1.316-336).  They name the target HCF-AES-256: Hirose's DBL compression function instantiated with AES-256, byte-identical to the `f` defined above (`g = E_{h‖m}(g) ⊕ g`, `h = E_{h‖m}(g ⊕ c) ⊕ g ⊕ c`, nonzero `c`).  A free-start rebound collision on at most 10 of 14 rounds.
- Lee, Hong, "Improved Quantum Rebound Attacks on Double Block Length Hashing with Round-Reduced AES-256 and ARIA-256", IACR ToSC 2024(3), pp. 238-265 (DOI 10.46586/tosc.v2024.i3.238-265).  Corrects errors in the 2021 complexity analysis (some 2021 figures are flawed, and once corrected fall below the generic bound) and improves the attack with nested quantum amplitude amplification.  Still round-reduced: 10 of 14 rounds.
- Baek, Cho, Kim, "Quantum cryptanalysis of the full AES-256-based Davies-Meyer, Hirose and MJH hash functions", Quantum Information Processing 21:163 (2022) (DOI 10.1007/s11128-022-03499-5).  Reaches **full 14-round** AES-256 by refining Biryukov et al.'s [BKN09] chosen-key differential trail: a full-round quantum collision on DM-AES-256, and full-round quantum **free-start** collisions on Hirose-AES-256 and MJH-AES-256.

The two round-reduced papers do not reach this implementation, for either of two independent reasons:

1. **Round count.**  They cover at most 10 of 14 rounds (the 2024 paper measures cost in "10-round AES-256 encryption" units), and extending past 10 is left open.  This library uses full 14-round AES-256 (`aes256_gf8_expand_key` emits all 15 round keys; see the cost discussion above), which the rebound trail does not touch.
2. **Constant `c` density.**  Their rebound trail requires a *sparse* `c`: the best classical 9-round attack needs 4 nonzero bytes, the 2024 quantum 10-round attack 8 nonzero bytes at specific positions.  The `c` constants here (`"VOLEitH-Hirose-N"` and the leaf variants) are 16 nonzero ASCII bytes, the *densest* possible `c`, which that trail cannot use.  This keeps the dense-`c` choice load-bearing against the round-reduced rebound attacks: a future "optimization" to a sparse or low-Hamming-weight `c` would reintroduce their precondition and must not be made.

The Baek et al. (2022) full-round attack is the realization of a related-key free-start collision the 2021 conclusion only sketched, so the round-count defense does not apply to it, and the dense-`c` argument does not cover it either: its chosen-key trail is valid for about 2^77 values of `c` (up from 2^34 and 2^64 in the round-reduced papers, a set that has grown paper over paper and whose condition is not simply "sparse"), and the paper gives no closed form that places this library's specific dense `c` outside it.  Two other facts bound its reach instead:

- **It is free-start.**  The adversary chooses the chaining value, so leaf hashing (seeded by the fixed `HIROSE_IV_LEAF`) is unaffected.  At an inode the "L as IV" framing (above) nominally puts the chaining value under a tree-forging adversary, but only nominally: the inode chaining value is `L`, the *left child's hash output*, not a free parameter the adversary sets directly.  Turning an attack-chosen chaining value into a tree collision then additionally requires exhibiting a left child that hashes to that exact value, a (second-)preimage on the child node hash (and at the leaf level, on a hash whose fixed IV the adversary cannot touch), which the construction's generic ~2^256 preimage resistance blocks.  So the free-start freedom does not compose into a realizable tree collision; the conservative `cr_bits = 128` classical-collision posture below is kept independently of this, not on the strength of it.
- **It does not beat the generic quantum bound by a meaningful margin.**  The full-round Hirose-AES-256 free-start collision costs 2^100.3 in the CNS model (large classical memory, no large qRAM) with negligible memory, only about 4x below the generic CNS bound of 2^102.4, and far *above* the generic BHT bound of 2^85.33 when large qRAM exists.  So even for an inode with a vulnerable `c`, the construction's quantum collision resistance stays at the generic ~2^85 to ~2^102 that any 256-bit hash already has.

The DM-AES-256 result in that paper (a full-round quantum collision at 2^48.5 vs the generic 2^51.2) rides entirely on AES-256's chosen-key key-schedule weakness and does **not** apply to this library's AES-DM node hash, which keys AES-128 with the sibling (no AES-128 related-key analogue) and is a deliberately-cheap 2^64-CR option regardless.

The load-bearing conclusion: a 256-bit DBL output has *generic* quantum collision cost of about 2^85.3 (BHT, large qRAM) down to about 2^102.4 (CNS, no large qRAM), both below 128 bits.  This is a property of any 256-bit hash, not of this construction, so `cr_bits = 128` is a *classical* collision bound (the bar NIST treats as meaningful for collision resistance, since the quantum generic attacks need impractical qRAM or parallelism).  No dedicated attack, round-reduced or full, lowers the quantum collision resistance below that generic level.

**The vt bridge.**  The `voleith_node_hash_vt` interface (`circuits/node_hash_vt.h`) is a struct of function pointers (`leaf_circuit`, `inode_circuit`, the matching `*_build_witness` and software helpers, plus `name` / `node_bytes` / `cr_bits` / `*_invin_bytes` identity fields) that lets higher layers (the generic vt-driven Merkle path circuit `merkle_vt_gf8_path_circuit`, its secret-dir form, the indexed-non-member counterparts, ring signatures, any future tree-shaped consumer) operate on a hash without knowing which one.  The two Hirose vts both have `node_bytes = 32`, `cr_bits = 128`, and share the inode-side fields; they differ only in their leaf-side dispatch.  The vt is consumed during circuit *construction*: indirect calls happen at build time only.  The prover and verifier never see the vt; they process the resulting gate stream, identical to what a hand-written hash-specific circuit would have produced.  Hash agnosticism is therefore a structural property of the codebase at zero proof-time cost.

## Hirose vs fixed-input Grøstl: the quantum-surface trade-off

The quantum analysis above leaves Hirose-AES-256 with a residual *structural* surface, the inode free-start case, that is bounded on every axis examined (it is free-start so it does not compose into a tree collision without a child preimage break, and it does not beat the generic quantum bound) but is conservatively kept at `cr_bits = 128` as a classical bound. The fixed-input Grøstl node hashes (above) sidestep that surface class entirely, at a cost. They are the structural alternative when an application would rather not carry the keyed-cipher attack surface at all.

**Why fixed-input Grøstl is immune to the Hirose attack class.** Every full-round and round-reduced quantum collision result against the AES-256 double-block-length hashes (Baek/Cho/Kim on Hirose, DM, and MJH; Chauhan et al.; Lee/Hong) rides AES-256's *chosen-key / related-key key-schedule* structure, the BKN09 differential trail with `c` in a key role. Grøstl has no keyed cipher: its compression `f(h, m) = P(h ⊕ m) ⊕ Q(m) ⊕ h` runs two *fixed public permutations* `P` and `Q`, and the node hash feeds the children as the *message* (`L ‖ R` for an inode, the leaf bytes for a leaf) with a *fixed public IV* in the chaining slot. There is no cipher key and no attacker-chosen IV-in-a-key-role anywhere in the construction, so the entire chosen-key / free-start rebound class that the Hirose papers exploit has nothing to attach to. The leaf hash in particular consumes only data, never a key or an attacker-controlled chaining value. (Grøstl carries its own reduced-round rebound literature, which is why its collision resistance rests on full-round compression-CR, see the fixed-input section above; that is a different and far weaker lever than the AES key-schedule attacks, and the truncation argument is the standard SHA-512/t one.)

**The cost of buying that out, and the 256-bit tier.** The immunity is not free: a fixed-input Grøstl inode costs roughly double a Hirose inode at the same 2^128 tier, and because VOLEitH verification is linear in circuit size (not succinct, see the verify-scaling discussion), that doubling is a roughly 2x proof-size and verify-time premium at every level of the tree.

| Node hash | Node bytes | CR | S-boxes / inode (= VOLE slots) | Keyed-cipher attack surface |
|---|---|---|---|---|
| Hirose-AES-256 | 32 | 2^128 | ~1,000 | AES-DBL free-start (bounded above; `cr_bits = 128` classical) |
| `grostl256_fixed` | 32 | 2^128 | 1,920 | none (permutation-based, data-only inputs) |
| `grostl512_fixed` | 64 | 2^256 | 5,376 | none (permutation-based, data-only inputs) |

At the 2^128 tier the choice is a security-surface-vs-cost trade: Hirose is the cheapest node hash and its quantum surface is conservatively bounded, while `grostl256_fixed` removes the keyed-cipher surface class entirely (data-only inputs) at about twice the per-inode slot count. At the 2^256 tier there is no contest, and that is the second milestone this release lands: Hirose-AES-256 *cannot* reach 2^256 at all (its 256-bit double-block output caps collision resistance at 2^128), so `grostl512_fixed` is the only construction in the library for a true 256-bit-CR tree, at 5,376 slots per inode (and the corresponding linear verify cost, roughly 5.4x a Hirose inode).

## Generic vt-driven Merkle path and indexed-non-member circuits

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

**Shipshape exposure.**  The secret-direction vt-driven path and indexed-non-member circuits are also reachable from `.ship` files through the crypto-v2 Tier 2a registry (see "Hash-parametric crypto extensions (crypto-v2)" in `docs/DESIGN.md`).  The registry inlines these same C vt builders by reference; a `.ship` call and a direct C call produce a byte-identical gate stream.
