# Ring Signatures

This document covers the library's ring-signature capabilities: the RSv1
baseline (anonymous membership with optional revocation) and the composable
V2 / V3 / V4 superset shipped in 1.8.0 (linkable nullifier, hidden-attribute
predicates, claimable commitment). Both build on the layered GF(2^8) proof
stack; for the per-circuit and per-hash construction rationale they compose
(OWF leaf, secret-dir Merkle path, indexed non-membership, the node-hash vt
interface), see [`docs/CIRCUIT_DESIGN.md`](CIRCUIT_DESIGN.md). For the proof
system itself see [`docs/DESIGN.md`](DESIGN.md).

## Ring Signatures (RSv1)

RSv1 is the library's first end-user signature capability built on top of the layered proof stack. It packages the hash-agnostic Merkle path circuit, the OWF circuit, and the GF(2^8) Fiat-Shamir prover into a non-interactive, publicly verifiable ring signature with optional revocation.  The underlying C vt circuits (`ring_sig_v1_gf8_circuit.c`, `merkle_vt_gf8_circuit.c`, `indexed_merkle_vt_gf8_circuit.c`) are also exposed by reference through the crypto-v2 Shipshape registry; see "Hash-parametric crypto extensions (crypto-v2)" in the Shipshape section of `docs/DESIGN.md` for the rationale. The public API lives under two prefixes: `voleith_rs_membership_*` for the reusable membership baseline (shared with the composable variants below) and `voleith_rsv1_*` for V1-specific wiring (the cfg fingerprint, the ring builder, sign / verify, the on-the-wire envelope).

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

This baseline lives behind `voleith_rs_membership_build_circuit` and is the surface shared with the composable variants (V2 linkable, V4 claimable, and the future V5 traceable / V7 threshold). Variants extend the baseline by appending more witness wires, more instance wires, and more constraints; the membership shape itself does not change.

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

### Variant roadmap

V1 shipped first as the smallest useful surface, with explicit hooks for follow-on variants. The composable V2 / V3 / V4 superset below shipped in 1.8.0 over the same `voleith_rs_membership_*` baseline; V6 (forward-secure key evolution) shipped in 1.10.0 and the designated opener (V5) shipped in 1.11.0, both as additional modules (see "Forward-secure key evolution (V6)" and "Designated opener (V5)" below). Still on the roadmap:

- **V7 (threshold t-of-n).** A signature requires t of n authorised members to cooperate.

The `voleith_rs_membership_*` layer is named separately from `voleith_rsv1_*` precisely so V2 / V4 / V5 / V7 can share the membership baseline without copy-paste. V3 and V6 deviate from the baseline shape and get their own builders.

Also deferred: a public-dir companion to the `from_leaf_node` secret-dir entry (would mirror the secret-dir variant for the rare public-leaf-index use case); incremental ring-update helpers (path-only update vs full rebuild); an on-disk path-bundle format.

## Composable ring signatures (V2 / V3 / V4)

Status: shipped in 1.8.0. The composable API is strictly additive over RSv1 and lives in `proof/rs_gf8.{c,h}` + `circuits/rs_gf8_circuit.{c,h}` + `circuits/rs_leaf_gf8_circuit.{c,h}`, reusing the relocated membership core (`proof/rs_membership_gf8.{c,h}`).

### Model

1.8.0 ships a single composable superset, not three separate APIs. The V1 secret-dir Merkle membership proof (with the optional revocation IMT branch) is the spine; V2 / V3 / V4 are independently-enableable modules over it. "V2", "V3", "V4" are named presets of enabled modules, not separate codebases. V1's public surface (`voleith_rsv1_*`, the V1 fs_seed construction, the `"VRS1"` wire format) stays frozen and untouched.

`voleith_rs_module_bitmap(cfg)` returns a single byte self-describing the enabled set, absorbed into both the cfg-fingerprint and the fs_seed so no field-shift ambiguity between combinations is possible:

| bit | macro | enabled when |
|---|---|---|
| 0 | `VOLEITH_RS_MODULE_REVOCATION` | `membership.depth_r > 0` |
| 1 | `VOLEITH_RS_MODULE_NULLIFIER` | `scope_bytes > 0` |
| 2 | `VOLEITH_RS_MODULE_PREDICATE` | `attr_schema != NULL` and some field `pred != NONE` |
| 3 | `VOLEITH_RS_MODULE_COMMITMENT` | `enable_commitment != 0` |
| 4 | `VOLEITH_RS_MODULE_SPENT_SET` | `depth_s > 0` |

### Config (`voleith_rs_config_t`)

Embeds `voleith_rs_membership_config_t` (tree_hash, owf_hash, sk_bytes, depth_m, depth_r) and adds:

- V3: `const voleith_rs_attr_schema_t *attr_schema` (NULL = leaf is OWF(sk)), `custom_predicate` callback + ctx (escape hatch, not in the config fingerprint; its gates are bound by the proof's circuit fingerprint).
- V2: `scope_bytes` (PRF input width; `T = AES-CMAC(sk, scope)`), `depth_s` (in-circuit spent-set IMT depth, 0 = none).
- V4: `enable_commitment`, `commit_id_bytes` (= lambda; shared with the future V5 opener), `commit_rand_bytes`.

`voleith_rs_config_validate` runs the width-independent membership structural checks (NOT the V1 `sk == fixed_leaf_bytes` check, since the composable leaf is `OWF(sk || attributes)`), validates the attribute schema, then bounds the OWF preimage `sk_bytes + sum(attr widths)`:

- `leaf_block_bytes != 0` (fixed-input OWF): preimage `<= leaf_block_bytes` (single compression; the leaf circuit zero-pads the shortfall). Concrete capacities: hirose-fixed32 = 32, grostl256_fixed = 64, grostl512_fixed = 128.
- `leaf_block_bytes == 0, fixed_leaf_bytes != 0`: preimage `== fixed_leaf_bytes`.
- both 0 (variable-leaf): no upper bound beyond the attribute cap.

Spent-set requires a nullifier (`depth_s > 0` implies `scope_bytes > 0`). Commitment requires `commit_id_bytes >= 1` and `commit_rand_bytes >= 1` (and guards their sum against `size_t` overflow). `leaf_block_bytes` is a `voleith_node_hash_vt` field added this release; see the "Single-compression leaf capacity" discussion in [`docs/CIRCUIT_DESIGN.md`](CIRCUIT_DESIGN.md).

### cfg-fingerprint

`voleith_rs_config_fingerprint(cfg, out16)`, 16-byte SHAKE-256, domain tag `"VOLEitH-RSc-cf\x00\x00"` (distinct from V1's `-cf-v1`). Absorbs:

```
domain_tag(16) || membership_absorb_canonical || module_bitmap(1)
  [if nullifier]  scope_bytes_le8 || depth_s_le8
  [if commitment] commit_id_bytes_le8 || commit_rand_bytes_le8
  [if predicate]  n_fields_le8 || (width_bytes_le8 || pred_byte)*
```

`custom_predicate` is NOT absorbed into fs_seed (function pointers are not portable, so `voleith_rs_config_fingerprint` excludes it). Its emitted gates are bound instead by the proof's circuit fingerprint: `voleith_gf8_circuit_fingerprint` is computed into the proof header and the verifier re-derives the circuit from the same cfg and runs `voleith_proof_header_check_identity_gf8`, rejecting any gate-stream divergence. The custom predicate therefore cannot be dropped or altered.

### Circuit (`voleith_rs_build_circuit`)

Emits wires/gates in canonical order:

- witness: sk, attributes, membership dirs, siblings, [id, rand], leaf inv_in (over sk||attrs), path inv_in, [commit inv_in], [nullifier CMAC inv_in], [revocation inv_in], [spent-set inv_in].
- instance: membership_root, [C], [scope, T], [predicate bounds], [rev_root], [spent_root].
- gates (emission order A-H): leaf = OWF(sk||attrs); merkle path; assert computed root == membership_root; [D] C = tree_hash(id||rand), assert == C; [E] T = AES-CMAC(sk, scope), assert == T; [F] per-field predicates; [G] revocation non-membership; [H] spent-set non-membership on T.

`voleith_rs_layout_t` (named tag `struct voleith_rs_layout`, forward-declared in `rs_gf8.h`) records byte offsets for the packer. A config with all modules off emits a V1-compatible layout (still a distinct protocol via the composed fingerprint).

Predicates: `EQ` asserts byte-equality to a public target; `RANGE` calls `assert_in_range_gf8(attr, low, high)`. Bounds are per-signature public inputs, so one ring supports varying thresholds. Predicate gates add mul gates but no witnesses. The nullifier `T` is fixed 16 bytes (`VOLEITH_RS_NULLIFIER_BYTES`) and requires `sk_bytes in {16, 32}` (the AES-CMAC key width).

#### Nullifier width vs tree collision-resistance strength

`T = AES-CMAC(sk, scope)` is 128 bits. Its security rests on two bounds that are *not* output-width-limited: linkability (one member, one `T` per scope) is enforced exactly by the in-circuit constraint `T == AES-CMAC(sk, scope)`, and non-frameability (producing a target victim's `T` without their `sk`) is keyed second-preimage resistance at ~2^128. The only output-width-limited bound is *accidental* cross-signer collision: two honest members happening to share a `T` under one scope, a birthday event at ~2^64. That is non-adversarial (an attacker cannot steer it without other members' `sk`); its only effect is a benign false-positive double-spend flag.

Policy: **nullifier output width tracks the node-hash collision-resistance strength of the tree.** The width is derived automatically from the membership node-hash vt's `cr_bits`: the nullifier is `cr_bits / 8` bytes (16 for a 128-bit-CR tree, 32 for a 256-bit-CR tree). This matches the nullifier's second-preimage bound (~2^cr_bits) to the tree and places accidental cross-signer collision at the 2^(cr_bits/2) floor.

- **128-bit-CR trees (Hirose-AES-256 / Grøstl-256, 2^128).** 16-byte nullifier via `T = AES-CMAC(sk, scope)`, unchanged. The ~2^64 accidental bound is matched to the rest of the system and negligible at any realistic ring/scope scale.
- **256-bit-CR trees (Grøstl-512, 2^256).** 32-byte nullifier. The correct lever is output *width* from a PRF, not the collision resistance of a hash (the nullifier never needs adversarial collision resistance), so the construction is the NIST SP 800-108r1 §4.1 KDF in Counter Mode with AES-CMAC as the PRF, at `L = 256`. This reuses the existing `kdf_ctr_cmac_gf8` circuit (validated against NIST CAVS vectors): two counter iterations, `K(i) = AES-CMAC(sk, [i]_32be || FixedInputData)` for `i = 1, 2`. A 256-bit output places accidental collision at the 2^128 floor and second-preimage at ~2^256, both matched to the tree. Cost is one extra in-circuit CMAC call (plus wider spent-set IMT comparisons when the spent-set is enabled), proportionate to having opted into a 2^256 tree.

The 128-bit (raw AES-CMAC) and wider (KDF-CTR-CMAC) paths are distinct constructions, not a uniform one: the 128-bit nullifier bytes and its V2 KAT stay frozen; only `cr_bits >= 256` trees take the KDF path.

`FixedInputData` layout (drives the 256-bit nullifier KAT): `Label || 0x00 || scope || [L]_2`, where `Label = "VOLEitH-Nullifier"`, `0x00` is the SP 800-108 separator, `scope` is the Context, and `[L]_2` is the 32-bit big-endian output length. The Label domain-separates this PRF use of `sk` from the leaf OWF; `[L]_2` is appended explicitly because the `kdf_ctr_cmac_gf8` circuit does not add it. Using the standardized KDF rather than an ad-hoc two-block CMAC concatenation keeps the wide nullifier a citable NIST-approved construction.

Width selection is automatic today (derived from `cr_bits`, always the `cr_bits / 8` minimum). A planned `voleith_rs_config_t` field will let a caller request a wider nullifier, bounded `[cr_bits / 8, 2 * cr_bits / 8]`: the lower bound matches second-preimage resistance to the tree (the enforced minimum), and the upper bound `2 * cr_bits / 8` lets a caller raise *accidental*-collision resistance to the tree's full `cr_bits` level (birthday over `2 * cr_bits` output = 2^cr_bits) when their deployment scale warrants it. A request below the minimum is rejected.

### fs_seed (`voleith_rs_compute_fs_seed`)

16-byte output. Version byte `0x01`, domain tag `"VOLEitH-RSc-fs\x00\x00"`. Absorbs:

```
FMT_VERSION(1) || DOMAIN_TAG(16) || cfg_fingerprint(16) || module_bitmap(1) ||
membership_root || revocation_root_or_zero ||
  [commitment] C ||
  [nullifier]  scope_len_be8 || scope || T(16) ||
  [spent_set]  spent_root ||
  [predicate]  n_pred_be8 || (field_idx_be8 || pred_kind ||
               EQ: width_be8 || target;  RANGE: width_be8 || low || width_be8 || high)* ||
  m_len_be8 || m
```

revocation_root_or_zero is absorbed unconditionally (node_bytes zeros when disabled). All length prefixes are 8-byte big-endian.

### sign / verify / serialize / helpers

- `voleith_rs_ring_build` / `voleith_rs_pack_witness`: ring construction and the unified superset witness packer.
- `voleith_rs_sign` / `voleith_rs_verify`: build circuit, fill instance from `voleith_rs_public_t`, compose fs_seed, call `voleith_gf8_{prove,verify}_v2`. Because prove_v2 runs `circuit_eval` first, a wrong sk / sibling / attribute / out-of-range predicate / wrong T fails at sign time (X-10 discipline).
- `voleith_rs_sig_{pack,unpack}`: `"VRSC"` envelope, 41-byte header `magic(4) | version(1) | cfg_fp(16) | params_fp(16) | proof_len_be(4)`, then the gf8_proof bytes. Mirrors V1's `"VRS1"` but binds the composable cfg fingerprint, so a VRSC blob never unpacks under a V1 or mismatched config.
- V2.LINK: `voleith_rs_nullifier_equal(t1, t2, t_bytes)` (constant-time) and `voleith_rs_nullifier(cfg, pub)` (extractor). Consensus rule: accept a signature iff verify passes AND its T has not been seen before in this scope. The library proves unlinkable-unless-same-scope; enforcing one-time use is the application's seen-set, keyed on T per scope.
- V4.CLAIM: `voleith_rs_claim_produce(cfg, id, rand, claim_out)` and `voleith_rs_claim_verify(cfg, C, id, rand)`. A claim is meaningful only because C is bound into fs_seed (non-transferable across signatures); losing rand loses the ability to claim.

### Tests and examples

`tests/test_rs_gf8.c`: per-module circuit-eval tests, sign/verify roundtrips, KAT pins (cfg-fingerprint, composed fs_seed), `"VRSC"` roundtrip + tamper, V2 linkability, V3 sign-level (predicate-violated fails at sign, attribute-bound-to-leaf, mismatched `bounds_len` rejected), V4 claim roundtrip + non-transferability, composite per-section tamper sweep, anonymity smoke (proof length independent of signer index), and layout/fingerprint determinism.

Examples: `example_rs_v2_linkable_gf8`, `example_rs_v3_attribute_gf8`, `example_rs_v4_claimable_gf8`, `example_rs_composite_gf8` (8-member depth-3 ring, sign + verify + headline property, CI smoke return code). All default to Hirose-AES-256 (2^128) with a documented one-edit switch to Grøstl-256 / Grøstl-512 (2^256) and the matching parameter set.

The two attacker-controlled entry points (`voleith_rs_sig_unpack`, the `"VRSC"` envelope parser, and `voleith_rs_verify`) have libFuzzer harnesses under `fuzz/` (`fuzz_rs_unpack`, `fuzz_rs_verify`, seeded by `fuzz_rs_seedgen`).

## Forward-secure key evolution (V6)

V6 (shipped in 1.10.0) adds per-identity key evolution: an enrolled member holds a signing key that changes every epoch, and advancing past an epoch destroys the key material for it. It is a composable module (enabled by `depth_e > 0`) and combines with V2 / V3 / V4 and revocation like the other modules.

### Two guarantees

Against an adversary that steals the signer's complete secret state at some epoch `t_c` (the signer having been honest up to `t_c`, including honest key erasure on every advance):

1. **Forward unforgeability.** The thief cannot produce a signature that verifies for any earlier epoch `tau < t_c`.
2. **Forward anonymity.** The thief cannot deanonymize the signer's already-published signatures, and (with the V2 nullifier enabled) cannot recompute the signer's past nullifier tags to link them.

The thief does hold everything needed to sign for the current and future epochs, and can advance the state itself. V6 is not recovery-from-compromise: revoke the member's ring leaf (the revocation module) to cut off future signing. What V6 protects is the past.

### Key lifecycle

Each identity carries a tree of `2^depth_e` one-time epoch seeds, expanded from a single master seed with the AES-CTR PRG (a GGM tree, kept entirely out of the circuit). The per-epoch seed `sk_t` is hashed to a leaf, and the leaves are Merkle-hashed into an **epoch root**; that root is the value enrolled as the member's ring leaf. There is no separate static per-member key: with V3 off the ring leaf is the epoch root directly; with V3 on it is `OWF(epoch_root || attributes || salt)`.

- **Keygen** (`voleith_rs_epoch_keygen`) builds the epoch tree, returns the epoch root, and initializes the forward-secure state at epoch 0. The signer keeps a compact cover (`O(depth_e)` seeds) plus the public epoch-node hashes.
- **Signing at epoch t** (`voleith_rs_epoch_sign`) proves in-circuit that `sk_t` hashes into the enrolled epoch root **at position t**, where the epoch-path directions are the public bits of `t`, then continues into the ordinary secret-direction membership path that hides which member signed. Making the position public is what ties a signature's claimed epoch to the leaf actually used; if it were secret, a thief holding a current seed could sign while claiming any past epoch.
- **Advancing** (`voleith_rs_epoch_state_advance`) recomputes the cover for `[target_t, T)` and zeroizes every seed that could reach an earlier epoch. After advancing past `t`, the signer API refuses to sign for `t` (the seed no longer exists).

`t` is public and bound both into Fiat-Shamir and as the epoch-path direction wires, so a signature for one epoch cannot be replayed as another. The library verifies "valid for epoch t"; it does not know the current time. **Applications must enforce their own epoch-acceptance window** (reject `t` outside what they currently accept) exactly as they enforce V2 scope policy; the example demonstrates a checked window.

### Caveats

- **Erasure and backups.** Forward security holds only if expended seeds are actually gone. The library zeroizes on advance, but it cannot control operational copies: a restored backup, VM snapshot, or swap image of an old state silently reverts erasure and lets the holder sign for every epoch that was live when the copy was taken. Treat the serialized state like a private key and keep no stale copies.
- **Per-epoch nullifier semantics (with V2).** The V2 nullifier is keyed with `sk_t`, so linkability is per (scope, epoch): two signatures link only within the same scope and the same epoch. This is deliberate, it is what keeps past tags uncomputable after erasure. Cross-epoch linkability is out of scope, because any key enabling it would survive compromise and let the thief link past signatures. Applications wanting per-epoch uniqueness put `t` in their scope.
- **External same-hash reuse.** The in-circuit statement fixes the tree roles, but it cannot protect an application's own external constructions that hash related values (for example, epoch roots) with the same node hash. Domain-separating those is the application's responsibility, as with every variant.
- **Public-state size.** The signer stores all `2T - 1` public epoch-node hashes, `(2T-1) * node_bytes`, which grows with `depth_e` (roughly 32 KB / 2 MB / 512 MB at `depth_e` 10 / 16 / 24 for 16-byte nodes). This is the current-version cost; XMSS/BDS-style `O(log T)` traversal storage is a planned future enhancement for constrained signers or routine deep-tree use.

### Strength and cost

The epoch tree is an honestly-built Merkle tree over one-time keys, so its forgery resistance reduces to preimage / second-preimage resistance of the node hash, not collision resistance. That lets deployments optionally use a cheaper epoch hash than the membership tree hash (`epoch_hash`, with the `epoch_hash_preimage_ok` opt-in relaxing the default strength rule). Signing adds one epoch leaf hash plus `depth_e` inode hashes over the membership circuit; verification stays linear in circuit size, as everywhere in this library.

### Tests and examples

`tests/test_rs_gf8.c` covers the epoch config fingerprint and layout, keygen determinism (epoch-root KAT), sign/verify at several epochs, the forward-security properties (retired-epoch derivation refused; a thief-simulated wrong-epoch proof rejected at sign and verify), state serialize / deserialize with version and tamper rejection, and V6 composition with V2 / V4 / revocation. `example_rs_v6_forward_secure_gf8` runs an 8-member ring: sign at epoch 0, advance, sign at epoch 5, the retired-epoch refusal, and a verifier epoch-window policy check. Three dudect release-gate targets (`voleith_rs_epoch_keygen`, `voleith_rs_epoch_state_advance`, `voleith_rs_epoch_derive_sk`) validate that the key schedule is constant-time in the secret seeds.

## Designated opener (V5)

V5 (shipped in 1.11.0) adds a **designated opener**: a party holding an opener key can trace a signature back to the signer's enrolled identity, while every other verifier still learns only that some ring member signed. It is a composable module (enabled by `enable_opener` plus a public opener key `opener_pk`) and combines with V2 / V3 / V4 / V6 like the other modules. The traceability is code-based and post-quantum: it rests on a QC-MDPC syndrome, not on any number-theoretic trapdoor.

### Trust model and split custody

The opener is a single designated role: whoever holds the opener secret key (a QC-MDPC private key) can open any signature made under the matching public key. The library provides the tracing mechanism, not a policy for who may invoke it. **The default deployment narrative is split custody:** hold the opener key under threshold or multi-party control so no single operator can unilaterally deanonymize, and gate opening behind an out-of-band authorization (a court order, an abuse-review quorum). The opener key is independent of every signer's key: signers do not trust the opener with their secrets, and compromise of the opener key does not let it forge, only trace.

Opening is **reveal-based**. The opener recovers the signer's identity and can publish it together with the evidence (the recovered support re-encrypts to the public tag), which anyone can check. A trace the opener keeps to itself has weaker standing: it is the opener's private claim until revealed, because the opener could in principle assert an opening without publishing the checkable witness. Deployments that need accountable opening should require the opener to publish the reveal.

### How a tag traces

Each signature carries an opener **tag** `prim_id || s || tag_ct` in its own serialization section:

- The signer draws a fresh per-signature fixed-weight error `e` (weight `t`, the QC-MDPC error weight) and computes the public syndrome `s = M * e^T` under the opener public parity block `M = opener_pk`.
- The signer's identity `id` (a fixed lambda-bit value, the same wire the V4 claimable commitment uses) is one-time-pad wrapped: `tag_ct = id XOR KDF(support(e))`, where the KDF hashes the sparse support of `e`. `prim_id` names the KDF hash so an opener knows how to reproduce it.

In circuit, the signature proves three things bind together: (1) the committed support is a genuine weight-`t` distinct in-range set (the ascending less-than chain and range check); (2) its syndrome equals the public `s` (the syndrome relation); and (3) the same `id` sits inside the membership leaf preimage that the anonymity proof already hides. The syndrome relation, the less-than well-formedness chain, the KDF, and the OTP DEM are described in [`docs/CIRCUIT_DESIGN.md`](CIRCUIT_DESIGN.md) ("Designated-opener gadgets"); the degree-d opening mechanism they use is in [`docs/DESIGN.md`](DESIGN.md).

To open, the opener runs its companion code-based KEM decapsulation on `s`, recovering the unique weight-`t` error `e`, recomputes `K = KDF(support(e))`, and unwraps `id = tag_ct XOR K`. Authentication is **re-encryption, not a MAC**: the opener accepts the recovered `id` only when `M * e'^T == s` and `weight(e') == t`, which unique bounded-distance decoding satisfies for exactly one `e'`. A decode failure returns "unopenable" rather than a wrong identity, and the OTP therefore needs no separate tag (its integrity is the enclosing VOLEitH proof plus this re-encryption check).

### Security separation: what the opener cannot do

- **No forgery.** The opener key is a tracing key, not a signing key. It grants no ability to produce a signature for any member.
- **No framing.** Unique decoding forbids a second valid weight-`t` preimage of `s`, and constructing two colliding weight-`t` errors would be a low-weight codeword of the opener code, i.e. key recovery. So the identity a tag traces to is the one the signer committed, and the opener cannot make a signature open to a member who did not make it.
- **No spillover.** Confidentiality of non-traced signatures and unforgeability of all signatures do not depend on the opener key at all; they hold even against an opener-key holder.
- **Honest-error assumption.** A proof certifies `wt(e) = t` and `s = M * e^T`, but it cannot certify that a signer sampled `e` honestly. The only thing a malicious signer buys by choosing `e` adversarially is self-denial of tracing (deliberately picking a decode-failure syndrome so its own signature is unopenable); it cannot frame anyone or touch confidentiality. This residual is bounded by the code's decoding-failure rate (`<= 2^-lambda`) and by key-recovery hardness (the failure-inducing errors are functions of the secret opener key), so an opener-key-blind signer cannot construct one except at negligible rate. The library takes this honest-error posture deliberately rather than pay the extra gates to derive `e` from a bound seed in circuit.

### Parameters and leaf capacity

The opener commits `e` as its sparse support (`t` indices of `idx_bits` bits), never the dense `n`-bit vector, so the witness is the packed support, not the error. Four parameter sets ship, matched to the companion KEM (libtalos_syndrome), which is authoritative for the QC-MDPC parameters `p`, `n0`, and `t` (its `docs/DESIGN.md`); the table reproduces those alongside the voleith circuit view (`idx_bits`, key/id bytes, and the opening degree and gate cost below):

| Opener set | p | n0 | t | n = n0·p | idx_bits | id / key bytes | KDF hash |
|------------|-----|----|-----|----------|----------|----------------|----------|
| 128_2 | 13613 | 2 | 130 | 27226 | 15 | 16 | AES-DM |
| 128_5 | 7829 | 5 | 57 | 39145 | 16 | 16 | AES-DM |
| 256_2 | 43451 | 2 | 261 | 86902 | 17 | 32 | Grøstl-256 |
| 256_5 | 24733 | 5 | 113 | 123665 | 17 | 32 | Grøstl-256 |

The `n0 = 2` sets minimize the opener public-key size; the `n0 = 5` sets minimize the in-circuit cost (fewer support indices). The opening degree is `idx_bits + 1` (16 to 18), and the opener adds roughly 3k to 17k multiply gates depending on the set, hash-dominated once the sparse syndrome relation removes the dense error. Verification stays linear in circuit size, as everywhere in this library.

Because the opener `id` lives inside the membership leaf preimage (`OWF(sk || attributes || id)`), the leaf hash must have capacity for it. The multi-block fixed-input node hashes cover the range: `hirose_fixed96` (96-byte capacity, 2^128 CR), `grostl256_fixed128` (128-byte, 2^128 CR), and `grostl512_fixed256` (256-byte, 2^256 CR). The config validator rejects a leaf preimage wider than the chosen vt's capacity before circuit construction.

### Tag wire contract

The opener tag is byte-exact and self-describing, but voleith is not its source of truth. The companion code-based KEM (libtalos_syndrome) produces the tag, and its `docs/DESIGN.md` §6 is the single authority for the byte recipe: the `prim_id || s || tag_ct` layout and the `prim_id` hash registry (§6.2), the `M` / syndrome systematic form, the `K = H(support(e))` KDF and its per-set domain-separation IV (§6.1), the one-time-pad DEM, the re-encryption open check, and the parameter-set id space. The bytes are deliberately not restated here: keeping the recipe in one repo is what stops the two implementations from drifting.

voleith reproduces that recipe in-circuit as a clean-room implementation sharing no source with the KEM. The shared Argus known-answer vectors are the cross-library ground truth both sides diff against; the small KDF / DEM-framing subset voleith cannot obtain from the shared ichor primitives is pinned by those vectors (see "Tests and examples" below). What is voleith-owned is the in-circuit reproduction and the degree-`d` opening it rides (see "Parameters and leaf capacity" above and [`docs/DESIGN.md`](DESIGN.md)); the wire bytes themselves belong to syndrome.

### Serialization (VRSC v2) and the v1 downgrade

The opener tag rides in a tagged, length-prefixed section of the version-2 `"VRSC"` envelope. The v2 format is a superset: a signature with the opener module off packs a v2 envelope byte-identical in its other sections, and the one-shot `voleith_rs_sig_pack` still emits v1 byte-identical to 1.8.0. **Opting a signature down to the v1 format drops the opener section:** a v1 envelope of an opener-enabled signature is no longer traceable, because the tag it needs is gone. Pack v1 only for signatures whose opener module is off; keep opener-enabled signatures in v2.

### Tests and examples

`tests/test_rs_opener_*` cover the opener config fingerprint and witness layout, the seal (support draw, syndrome, tag), sign/verify with the opener module on, the VRSC v2 opener section round-trip and the v1 opt-down, and composition with V4 (shared `id`), V2, V3 (leaf capacity), and V6 (opener id inside the epoch leaf). A syndrome-backed end-to-end test links the companion code-based KEM as the decap oracle and checks that a signature traces to the enrolled identity through the real opener, that an unverified signature is refused at the opener gate, and that the software cross-check agrees with the KEM decap. `example_rs_v5_designated_opener_gf8` runs an 8-member ring with a split-custody narrative: enroll with the opener id in the leaf, sign, verify anonymously, then open the trace.
