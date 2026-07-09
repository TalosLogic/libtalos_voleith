# Erasure Codes Design (v1.9.0)

Status: planning. No implementation has begun. This document is the
markable artifact agreed before any code is written.

## 1. Goal

Add erasure coding to libtalos_voleith for two complementary use cases:

- Reed-Solomon (RS) for a storage layer: fixed (n, k) systematic codes
  providing durability and repair.
- Random Linear Network Coding (RLNC) for a transport layer: rateless
  recoding at intermediate nodes.

The two compose: RLNC can transport RS-encoded chunks, so a storage system
built on RS can move and repair its chunks over an RLNC transport. Both ship
in v1.9.0.

Three downstream capabilities motivate the work, in increasing order of
difficulty (only the first is in v1.9.0 scope as plaintext; the rest are
sequenced after):

1. Plaintext RS/RLNC encode, decode, and recode as a data-layer library.
2. Prove a chunk belongs to a dataset: that its bytes are a chunk the owner
   committed under a public root `R`. As built in section 6 this is Merkle-leaf
   membership (an FWK-blinded leaf under `R`), an authenticity statement, NOT an
   arithmetic claim that the chunk equals a particular `G . M` coordinate.
3. Prove a dataset was correctly and specifically encoded: that the committed
   chunks satisfy the codeword relation `C = G . M` for the public generator
   `G` (the encoding-correctness / consistency layer).

These are two different guarantees, not two sizes of the same one. Capability 2
(membership, section 6.1) says the owner blessed these bytes at this position;
capability 3 (consistency, section 6.9) says the bytes are arithmetically the
right encoding. A row of `C = G . M` ("chunk `i` really equals `(G . M)[i]`")
is the per-row slice of capability 3, a stronger statement than the Merkle
membership of capability 2, so capability 2 is not simply one row of capability
3; the two prove different things and compose (section 6.9). For storage-scale
public data capability 3 is a plaintext check rather than a circuit; see
section 6.9 for when it is in-circuit and when it is not.

### 1.1 Erasures vs corruption, and the integrity bridge

These are erasure codes, not error-correcting codes. The decoder is told
which chunk indices it holds and trusts those bytes are correct: it corrects
erasures (loss at known positions), not errors (silent corruption at an
unknown position). Feeding a corrupted chunk in as if valid yields wrong
output with no warning. Correcting unknown errors would need syndrome
decoding (the BCH/generator-polynomial family), which is deliberately out of
scope.

Corruption is therefore handled by detecting it out of band and then treating
a bad chunk as an erasure: drop it from the index set and let the remaining k
good chunks reconstruct. Two detection tiers exist, picked by threat model:

- Cheap tier (per-chunk hash or MAC). For non-adversarial integrity (bit-rot,
  a flaky link) a hash or MAC per chunk is the right tool and is far cheaper
  than a proof. In many distribution systems this is already present and
  automatic: a torrent-like swarm hashes every piece as part of transfer, so
  a corrupted piece fails its piece hash and is simply re-requested or marked
  missing. No proof is involved; the erasure layer then absorbs the loss.
- Verifiable tier (in-circuit membership proof, capability 2). When detection
  must be verifiable to a third party, zero-knowledge, or bound to a public
  commitment of the dataset, a hash is not enough. The membership proof asserts
  the chunk is a committed member of the dataset (for RS, a leaf of the tree
  under `R`, section 6.1; for RLNC, a valid combination of the committed
  generation), so a corrupted chunk, whose digest differs, is not a member, has
  no valid proof (soundness), and fails verification, after which it is marked
  missing exactly as above. The commitment is load-bearing: a proof of
  "membership in some dataset" is meaningless without binding to one committed
  dataset (`R`).

In both tiers the pattern is identical: detect, mark missing, decode. The
plaintext layer (capabilities 1) recovers from known loss; the detection tier
(a hash, or the capability-2 proof) is the gatekeeper that converts corruption
into loss the recovery layer can absorb. This is why the plaintext codes and
the in-circuit proofs are complementary rather than redundant.

### 1.2 RS over RLNC: the transport composition

RS and RLNC are not alternatives; the intended deployment composes them. RS
provides the durable storage code (fixed (n, k), parity, repair). RLNC is the
transport that moves those chunks between nodes: an intermediate node recodes
the RS chunks it has received into fresh linear combinations without first
decoding them, which is what makes the transport rateless and repair-friendly
over lossy or churning links. A storage system built on RS therefore ships
and heals its chunks over an RLNC transport, and that is precisely why both
codes are in v1.9.0 rather than only one.

The composition is also where the integrity bridge of section 1.1 earns its
keep. Chunks crossing an RLNC transport arrive from peers, possibly recoded
several times, so a receiver needs to answer two questions before trusting an
incoming coded symbol:

- Does it belong to the generation / code set I am trying to rebuild? This is
  capability 2 in its RLNC form: prove the coded symbol is a valid combination
  `y = c . X` of the committed generation `X`. A corrupted or foreign symbol
  has no valid proof and is dropped, exactly the detect-then-erase pattern.
- Do I yet have enough to rebuild? RLNC decode reports rank progress (P3), so
  the receiver knows when k linearly independent symbols have accumulated.

The cheap tier still applies underneath: where the transport already hashes
what it moves (a torrent-like swarm, or any content-addressed link), routine
corruption is caught for free and the symbol is re-requested, leaving the
membership proof for the cases that need to be verifiable or zero-knowledge.

## 2. Field choice

| Scheme | Field | Rationale |
|---|---|---|
| RS (storage) | GF(2^8) | n <= 255 covers practical stripe sizes; reuses the existing constant-time `core/field.c` GF(2^8), so no new field code and no representation mismatch when proving later. |
| RLNC (transport) | GF(2^16) | Avoids the coupon-collector wall that makes GF(2^8) unusable for RLNC at scale. New field, `core/field16.c`. |

### 2.1 GF(2^16) construction

- Reduction polynomial: `0x1100B` (x^16 + x^12 + x^3 + x + 1), the standard
  RS choice (gf-complete, ISA-L), so externally generated test vectors are
  reproducible.
- Built like the existing large fields: `CLMUL` / `PMULL` hardware fast path
  plus a constant-time software fallback (branchless shift-and-reduce).
- Constant-time from day one. This keeps private coefficients possible
  without a rewrite, and costs almost nothing: carryless multiply handles
  16-bit operands trivially and the software fallback is small. Speed only
  degrades on the software fallback, which only fires on architectures
  outside the two supported targets (x86_64 with CLMUL, ARMv8 with PMULL),
  both of which have hardware acceleration.

### 2.2 Why GF(2^8) is not made variable-time

The existing `voleith_gf8_mul` is constant-time and must stay that way: in
the proof system its inputs are secret witness bytes. The erasure data layer
and the proof system are two different consumers with opposite requirements.
They do not share a multiply. If erasure ever needs a faster GF(2^8) region
multiply, it is a separate function in `erasure/`, never a modification of
the core primitive.

### 2.3 RS shard-count bound and minimum chunk size

The field size caps the total shard count. Our Cauchy construction draws code
points from the field elements `0..n-1`, so for the GF(2^8) RS:

    n <= 256

(`erasure/matrix.c` rejects `n > 256`. Textbook "255" excludes the zero
element; our Cauchy uses 0 as a valid data point, so the full 256 is
available. Treat 255 as a safe round number.)

This bounds how finely a file may be sharded. With `k = ceil(file_size /
chunk_size)` data chunks and redundancy expressed as the overhead factor
`R = n / k` (total / data), the constraint `n <= 256` is:

    ceil(file_size / chunk_size) * R  <=  256

Smaller chunks mean more chunks, so the smallest usable chunk size is the
point where `n` reaches the cap:

    k_max     = floor(256 / R)
    chunk_min = ceil(file_size / k_max)   ~=  file_size * R / 256

Equivalently, in terms of a target loss-tolerance fraction `f` (survive losing
up to `f` of the shards), `R = 1 / (1 - f)` and `k_max = floor(256 * (1 - f))`.
The original file length must be stored alongside the shards, since the last
data chunk is zero-padded to `chunk_size`.

Worked example: a 2 GB file, tolerate losing 80% (`f = 0.8`, so `R = 5`):
`k_max = floor(256 / 5) = 51`, `chunk_min = ceil(2 GB / 51) ~= 42 MB`, giving
`n = 255`. Chunks smaller than ~42 MB are not expressible in GF(2^8) at that
redundancy. The absolute floor for a 2 GB file (R = 1, no redundancy) is
`2 GB / 256 = 8 MB`; any real redundancy pushes it higher.

When `chunk_min` is too coarse (small files needing many shards, or very high
redundancy), the only remedy is a larger field. A GF(2^16) RS would raise the
cap to `n <= 65536`, two orders of magnitude finer sharding. That is not built
in v1.9.0 (RS is GF(2^8) by decision above); see the future enhancements
section for when it would be worth adding.

## 3. Constant-time posture

"Constant-time" here means no secret-dependent branch and no secret-indexed
memory. It is achieved by branchless shift-reduce or hardware carryless
multiply. It is not achieved by bitslicing; bitslicing is used only for the
AES S-box (`core/aes_ct64.c`), where a 256-entry secret-indexed table would
otherwise leak.

Erasure payload is public. The constant-time hardware multiply is fast enough
that v1.9.0 uses it everywhere, including any future in-proof coding circuit.
A variable-time region-multiply engine is therefore NOT built in v1.9.0; see
the future enhancements section.

## 4. Module layout and layers

Plaintext erasure coding is a data-layer library, not one of the five proof
layers. It consumes only `core/`.

```
core/field16.{c,h}            Layer 1: GF(2^16) element arithmetic
erasure/rs.{c,h}              new module above core: RS encode/decode (GF(2^8))
erasure/rlnc.{c,h}            new module above core: RLNC recode/decode (GF(2^16))
erasure/matrix.{c,h}          shared generator-matrix + Gaussian elimination core
circuits/rs_chunk_cert_circuit.{c,h}  Layer 5: RS chunk membership certificate (6.1, P6)
circuits/rlnc_*_circuit.{c,h}         Layer 5: in-circuit RLNC (after plaintext, P5)
circuits/rs_*_circuit.{c,h}           Layer 5: in-circuit RS coordinate / C=G.M (deferred, 6.9)
```

- `core/field16.*` is Layer 1, a core primitive alongside the existing fields.
- `erasure/` is a new top-level module, sibling to `vole/`, depending only on
  `core/`. It does not touch the proof stack.
- In-circuit coding, when it lands, is Layer 5 circuits built on the Layer 4
  QuickSilver prover/verifier, exactly like `aes_gf8_circuit` and
  `merkle_gf8_circuit` today.

## 5. In-circuit field representation

The proof system today has bit-level and GF(2^8) element-level QuickSilver.
There is no GF(2^16) element-level prover.

- **RS in-circuit** is over GF(2^8) and proves natively on the existing
  GF(2^8) QuickSilver. No new field-proving code.
- **RLNC in-circuit** is over GF(2^16) and proves on a NEW native GF(2^16)
  element-level QuickSilver (`proof/gf16_prover.c` / `gf16_verifier.c` /
  `gf16_circuit.c`, parallel to the GF(2^8) stack).

### 5.1 Native GF(2^16) is primary; the tower is a scoped secondary

A single QuickSilver proof is over one element-level field. The gf8 prover
carries one GF(2^8) byte per VOLE slot; the gf16 prover carries one GF(2^16)
element per slot, with a different embedding. GF(2^8) and GF(2^16) element
wires cannot be natively mixed in the same proof. So the representation choice
is not "which is faster in isolation," it is "which field dominates the
circuit the GF(2^16) arithmetic lives inside."

Primary path (native GF(2^16)): a standalone RLNC membership proof is entirely
GF(2^16). Verify in this library is linear in circuit size, so the fastest
verification matters most here: the motivating use case (prove an incoming
chunk belongs to the correct generation, and whether enough chunks exist to
rebuild) must keep pace with high-throughput networking. A native GF(2^16)
prover is the planned path for it. RS, being over GF(2^8), proves natively on
the existing GF(2^8) prover. So in the standalone cases neither scheme needs
the tower.

Secondary path (the GF(2^8)^2 tower), for cross-field composition: when a
circuit is predominantly GF(2^8) and needs only a minority of GF(2^16)
arithmetic, the whole proof cannot flip to gf16. The choice is then between
(a) emulating the GF(2^16) part as the tower GF(2^8)^2 inside the gf8 proof,
at 3x cost but only on that minority of gates, or (b) running a separate gf16
proof cross-bound to the gf8 proof via a shared transcript and consistency
constraints. When GF(2^16) is a small fraction of a gf8-dominated statement,
the tower is cheaper and simpler than a second bound proof. Example
statements: an RLNC chunk whose decoded data also carries an AES/Merkle
commitment proven in the same statement; RLNC or RS membership composed with
a gf8 ring-signature or KVAC membership (the existing ring-sig stack is gf8);
a GF(2^16) generation tag checked against an otherwise-gf8 circuit.

- Tower representation: each GF(2^16) element is two GF(2^8) wires; GF(2^16)
  multiply is a small GF(2^8) sub-circuit (Karatsuba: 3 GF(2^8) multiplies
  plus linear maps); a change-of-basis (the AES `B` / `B_inv` matrix pattern)
  maps between the canonical plaintext GF(2^16) poly `0x1100B` and the tower
  basis. The two are isomorphic, so the plaintext field is unconstrained.

Build decision: the tower is NOT built in v1.9.0 (no composed gf8+gf16
statement is in scope yet). It is documented here as the chosen mechanism for
that case, with a clear trigger: it is built when a concrete cross-field
composition consumer appears. This is recorded so that case is a known,
planned gadget rather than a re-opened decision. See future enhancements.

### 5.2 Native GF(2^16) QuickSilver: feasibility and the new work

Feasible because 16 divides 128, 192, and 256, so GF(2^16) is a subfield of
every VOLE field GF(2^lambda) and the `embed()` construction generalizes: a
GF(2^16) element embeds as `sum_i val_bit_i * alpha16^i` in GF(2^lambda).

The one genuinely new cryptographic task: the GF(2^8) prover's alpha tables
came from faest-ref Appendix A.1 (FAEST generated them in SageMath). There is
no faest-ref source for GF(2^16), so the alpha16 subfield-embedding tables must
be derived in-house. Same construction as A.1: the table is the powers
`beta^1 .. beta^15` of a root `beta` of the canonical GF(2^16) defining
polynomial `m16 = x^16 + x^12 + x^3 + x + 1` (poly `0x1100B`) inside each
GF(2^lambda) (`beta^0 = 1` implicit, so 15 elements per lambda). Deriving
rather than transcribing keeps it clean-room. The root is non-unique (16
conjugates); a deterministic rule fixes it (smallest integer encoding in
GF(2^lambda)), documented for reproducibility.

Generation is an in-repo C tool under `tools/gen_alpha16/` that links the
project's `core/field.c` GF(2^lambda) arithmetic, so no external dependency
and no factoring of `2^lambda - 1`: it projects elements into the GF(2^16)
subfield via the Frobenius sum, finds a generator of the order-65535 subgroup
(factoring only `65535 = 3 * 5 * 17 * 257`), enumerates the subfield, and picks
the `m16` root. A SageMath script (Sage is GPL open-source) computes the same
tables independently as a cross-check oracle, the faest-ref posture: used to
validate, never linked. Final correctness is the subfield-homomorphism test
(`embed(a*b) == embed(a)*embed(b)`, `embed(a+b) == embed(a)+embed(b)`) against
`core/field16.c`. This is a discrete planned task, not a research risk.

This decision does not block plaintext work: `field16.c` picks the canonical
RS polynomial now; the alpha16 embedding is derived later when the gf16 prover
is built.

## 6. RS proof use cases: membership, retrieval, and encoding correctness

This section specifies the RS proof use cases: the chunk membership certificate
(requirement 1, section 6.1), the owner-specified node-attribute restriction
(sections 6.3 / 6.5), the two index modes and leaf layout (section 6.6), the
dataset metadata binding and wire format (sections 6.7 / 6.10), the
retriever-side sufficiency check (requirement 2, section 6.8), and encoding
correctness (capability 3, section 6.9). It sits
on a firm boundary: RS chunk data is public to the proof system, and
confidentiality is the caller's responsibility, handled by encrypting before
encoding (see section 2 and the encrypt-then-encode rule). The proof never
witnesses bulk payload; the only secrets it witnesses are small (a key, an
index, a selector). Within that boundary, plain membership of a public chunk
is just a plaintext Merkle path and needs no zero-knowledge; the cases below
are the ones that do.

### 6.1 The chunk membership certificate (requirement 1)

The owner is the controller of a per-file witness key, the FWK. The owner
secures the data externally, feeds it into the library for RS encoding, and
uses the FWK to generate membership certificates. "Who owns a dataset" is
defined as who controls its FWK.

Each chunk's Merkle leaf is blinded by the FWK:

    leaf_i = node_hash(FWK || chunk_digest_i || pad)

so the leaf cannot be recomputed by anyone who does not hold the FWK. The
certificate is the zero-knowledge statement:

- Claim: `chunk_digest` is the leaf at index `i` of root `R`, that is,
  there exists an FWK such that `node_hash(FWK || chunk_digest || pad)` is the
  leaf at index `i` under `R`.
- Public (instance): `R`, `chunk_digest`, `index i`. The circuit actually
  proves against `merkle_root` and a verifier checks `R` commits to it and the
  metadata; "against `R`" is shorthand for that two-layer check (section 6.7).
- Secret (witness): `FWK`, the sibling path.
- Prover: the owner (FWK holder), once per chunk, at distribution time.
- Verifier: anyone with `R` (storage nodes, the ledger); no secret needed.

Properties, and why each holds:

- Forces a zero-knowledge proof. Because the leaf is FWK-blinded, a verifier
  holding the chunk can compute `chunk_digest` but cannot recompute the leaf,
  so a plaintext Merkle path cannot express membership. The owner attests it
  in zero knowledge, with the FWK as witness.
- Hides the owner. The FWK is the witness and is never revealed, so "who owns
  R" stays private even from the verifier. This is requirement 1's anonymity,
  and it comes from FWK secrecy, not from hiding anything else.
- Only the owner can produce it. Producing the proof requires the FWK, so no
  node or outside party can fabricate a membership certificate. Storage nodes
  verify and relay certificates; they never produce them and never hold the
  FWK.
- Unforgeable. No FWK means no valid leaf preimage, so members cannot be
  invented; collision resistance plus proof soundness means a non-member
  cannot be passed off as a member.

Free-floating, not node-bound. The certificate deliberately does NOT bind
which node holds the chunk. The owner does not control distribution (the
ledger places chunks as it sees fit), and binding a node would force the owner
to regenerate certificates every time the network heals or redistributes,
making the network more fragile. So the certificate is a transferable
statement "this chunk is a member of R" that any holder can present.

Direction profile. The durability-monitoring use case (section 6.2) defaults to
public-dir: the chunk index is public so the ledger can deduplicate distinct
chunks and count coverage directly. Secret-index is also supported over the same
tree (section 6.6) for deployments that need chunk anonymity, at a small added
cost and with the ledger falling back to `chunk_digest` for dedup. The owner is
hidden by the FWK in either mode, so the index choice is about chunk anonymity
and dedup convenience, not owner anonymity. Public-dir is the default here, not
the only option.

### 6.2 Motivating use case: ledger-driven durability monitoring

Three roles. The design separates three roles by job, regardless of whether one
physical system plays several of them (that is an implementation choice, not a
design constraint):

- Node: holds chunk bytes. Its sole job is storage (and, in a future
  enhancement, proving possession). It does not reconstruct.
- Healer: reconstructs missing chunks on the ledger's command and sends them
  where the ledger directs. A healer needs enough surviving chunks to decode
  (see below); it does not coordinate.
- Ledger: the coordinator, a tracker in the BitTorrent sense. It holds metadata
  for every chunk of every dataset, decides placement and healing, and verifies
  certificates. It stores no bulk data itself.

What the ledger tracks. The ledger records every published root `R` and, per
chunk, indexes the chunk by its membership certificate and its `chunk_digest`,
and tags which node it sent that chunk to. So the ledger's per-chunk row is
roughly `(R, chunk_digest, certificate, assigned_node)`. For public-dir
datasets the chunk index is public, so the ledger records it too,
`(R, index, chunk_digest, certificate, assigned_node)`: the index is the natural
dedup and coverage key (counting distinct indices toward `k`) and makes "which
positions are currently covered, which are missing" a direct lookup rather than
a digest comparison. For secret-dir datasets the index is not available to the
ledger, so it falls back to `chunk_digest` as the dedup key. This is what lets
it answer "who should have what" and detect divergence.

Monitoring loop. Periodically the ledger asks each node which chunks of `R` the
node holds; the node answers by presenting the membership certificates for those
chunks. The ledger verifies each certificate against `R`, deduplicates by index
(public-dir) or `chunk_digest`, counts the distinct indices covered, and
assesses whether `R` can still survive its target loss (e.g. 80%, meaning at
least `k` distinct indices remain recoverable, with replication margin).
Membership certificates ensure the counted chunks are genuine members of `R` (a
node cannot pad its count with garbage, since a non-member has no valid
certificate), and dedup ensures copies of the same chunk are not double-counted.

Healing mechanics. When coverage falls (a node is down, or a rebuilt node lost
some or all of its chunks across however many datasets), the ledger commands a
healer to regenerate the missing chunks and place them on healthy nodes. Three
properties govern how this works:

- Repair needs `k` chunks, so the healer reconstructs the file. To regenerate
  one lost chunk the healer decodes `M` from any `k` surviving chunks and
  re-encodes the missing row (the RS `repair` operation). It therefore
  temporarily reconstructs the whole file. Under encrypt-then-encode that `M` is
  ciphertext, so confidentiality holds (the healer never sees plaintext), but
  the healer is a point that aggregates enough to assemble the ciphertext file.
  Avoiding even that aggregation would require locally-repairable or
  regenerating codes (repair from a subset without full decode), a different
  code family and out of scope; plain MDS RS always needs `k` to repair one.
- No FWK at heal time, and the bytes come back bit-identical. Re-encoding is
  public linear algebra with the public generator `G`, so the healer needs no
  FWK. Because RS is deterministic, the regenerated chunk is bit-identical to
  the lost one, so its `chunk_digest` and its membership certificate are
  unchanged and still verify against `R`. For MDS the healer may regenerate the
  specific lost index or any currently-absent index; all are equivalent for
  recoverability.
- The certificate must be archived, because it cannot be regenerated. The chunk
  bytes are reproducible without FWK, but the certificate is a zero-knowledge
  proof that requires the FWK to produce. If the only copy of a chunk's
  certificate died with its node, the bytes can be rebuilt but the certificate
  cannot. So the owner generates all `n` certificates once at publish time and
  the ledger archives them (they are small, alongside the per-chunk metadata it
  already keeps); at heal time the healer re-encodes the bytes and the
  ledger re-attaches the stored certificate, valid because the bytes are
  identical. FWK is used exactly once, at setup, never during healing.

Healer recipe and the primitives it needs. Healing reconstructs by re-encoding
(RS is deterministic: decode `M`, recompute the missing rows, bit-identical
output), NOT by recoding (the RLNC random-combination operation does not
reproduce a specific missing chunk). The healer's orchestration lives in the
application (section 7.0); the primitives it composes live in the library:

1. Deserialize the descriptor for `(n, k)`, the generator, and the profile.
2. Validate the survivors: verify each survivor's membership certificate, and
   run the capability-3 plaintext consistency check (section 6.9) so the healer
   does not reconstruct a wrong `M` from an inconsistent codeword and propagate
   it. The decode path also reports an undecodable / singular `k`-subset.
3. Decode `M` once from any `k` distinct survivors, then re-encode the missing
   rows. For a public-dir dataset the ledger names the missing index directly,
   so the healer re-encodes that row. For a secret-dir dataset the ledger tracks
   by `chunk_digest` (no index), so the healer re-encodes candidate rows and
   matches digests (or recovers the index first, then re-encodes directly).
4. Post-heal check: hash each regenerated chunk and assert it equals the
   archived certificate's `chunk_digest`. Equality confirms the re-encode is
   bit-identical, which is exactly what makes the archived certificate valid for
   it.
5. Re-attach and place: the healer does NOT generate the certificate (no FWK);
   it takes the archived certificate from the ledger and packages
   `(R, certificate, bytes)` with the chunk-header serializer. The ledger
   directs placement.

The one primitive this needs beyond plaintext RS encode/decode is a public
decode-once / encode-specific-rows entry point, so healing several missing
chunks of one dataset decodes `M` a single time rather than once per chunk (the
RS `repair` helper bundles decode plus a single row).

The possession gap. A membership certificate proves a chunk is a valid member
of `R`; it does not by itself prove that a node currently holds that chunk's
bytes. A node holding only the certificate, which travels with the chunk and
may be copyable, must not be able to inflate the health estimate. Durability
monitoring therefore ultimately needs a possession/liveness guarantee (Proof
of Retrievability / Provable Data Possession in spirit). That is requirement 2
(sufficiency and possession), of which the retriever-side check is specified in
section 6.8 and the node-side possession proof is a future enhancement (section
10). Requirement 1 is the integrity layer underneath it: it makes the counted
chunks genuine and dedupable, which possession then makes live.

### 6.3 Owner-specified node-attribute restrictions

The owner may restrict which TYPES of node are allowed to hold a dataset, and
it does so by binding an attribute restriction into the membership certificate
(or into the dataset metadata the certificate commits to), not by relying on
nodes to assert their own eligibility. The ledger then distributes chunks of
`R` only to nodes whose attributes satisfy the owner's restriction.

- The owner specifies, per dataset `R`, an allowed node-attribute predicate
  (for example, a set of permitted geographic regions), bound to `R` so it
  cannot be altered by a node or by the transport.
- The ledger, which manages placement and knows node attributes, matches the
  owner's restriction against candidate nodes and places chunks only where the
  predicate is satisfied.
- The predicate is expressed and verified with the attribute /
  selective-disclosure machinery from v1.8.0 (the RS V2/V3/V4 composable
  ring-signature modules; RS V3 is the attribute module), so node attributes
  can be checked and, where desired, matched without revealing the exact
  attribute, only that it lies in the allowed set.

Example: export-controlled data is restricted by the owner to approved
geographic regions. The restriction travels bound to `R`; the ledger places
chunks of `R` only on nodes in the approved regions. Placement is the ledger's
responsibility, but the policy is the owner's and is cryptographically tied to
the dataset, so the ledger cannot widen it and a node cannot be given data its
type is not permitted to hold.

This stays composable with the chunk membership certificate of 6.1: the
certificate remains free-floating and node-agnostic (it never binds a specific
node), while the attribute restriction it carries constrains the SET of node
types the ledger may place it on.

### 6.4 Public vs secret, at a glance

| Element | Chunk membership certificate (6.1) | Node-attribute restriction (6.3) |
|---|---|---|
| Specified by | owner (FWK holder) | owner (bound to `R`) |
| Enforced by | anyone with `R` verifies (nodes, ledger) | ledger (placement) |
| Public | `R`, `chunk_digest`, index (public-dir; index hidden in secret-index, 6.6) | allowed attribute set / predicate |
| Secret | `FWK`, sibling path | node's exact attribute (if selective disclosure) |
| Hides | the owner | the node's exact attribute (optional) |
| Unforgeability from | FWK secrecy + collision resistance + soundness | restriction bound to `R` + credential unforgeability + soundness |

Requirement 2 (sufficiency and possession), the retriever's side, is specified
in section 6.8.

### 6.5 Confidential attribute values (metadata confidentiality)

The attribute restriction of 6.3 can carry its allowed-value set in the clear
or keep it secret. Keeping it secret is supported, and it buys exactly one
thing: metadata confidentiality. It does NOT, on its own, harden placement
against a misbehaving node. That distinction is the whole of this section,
because the two are easy to conflate.

What secrecy is for. The mere classification of a dataset is often sensitive:
"restricted to NATO regions" leaks that the data is defense-relevant,
"PCI-DSS scope only" leaks that it is cardholder data. An observer scanning a
ledger of public roots could otherwise catalogue every dataset by its
regulatory tier and target accordingly. Committing the allowed-attribute set
rather than publishing it (and, with selective disclosure, not revealing a
node's exact attribute either) closes that leak. This is a confidentiality
property over the policy metadata, and it is in scope now: the v1.8.0 RS V3
selective-disclosure machinery already proves "attribute lies in the allowed
set" while revealing neither the attribute nor, optionally, the set.

What secrecy is NOT. Hiding the allowed value does not stop a node from
holding a chunk it should not. If a node's own attribute is self-asserted (the
node simply supplies a region value at check time), secrecy is actively
defeated by an oracle attack: the node tries candidate values and watches for
which one verifies, learning the hidden policy and finding a passing value in
the same step. The property that actually prevents the spoof is that the
node's attribute is a non-forgeable credential (a region attestation signed by
an issuing authority), checked against the policy. Credential unforgeability is
the integrity guarantee; secret value is a separate confidentiality guarantee
layered on top. Enforcing that, end to end on the network, additionally turns
the node into a prover of its own eligibility rather than a passive verifier,
which is a structural change beyond v1.9.0 scope; see section 10.

In scope for the design now, therefore: the allowed-attribute set MAY be
secret (committed, not published) for metadata confidentiality, expressed with
the existing selective-disclosure machinery. The active, credential-checked,
ledger-compromise-resistant enforcement of that policy on the network is
recorded as a future enhancement, not built here.

### 6.6 Two index modes (public and secret) over one tree

A dataset's tree supports both a public-index and a secret-index membership
proof from the SAME committed root `R` and the SAME leaf layout. The mode is a
per-proof choice of circuit variant, not a property of the tree:

- Public-index (public-dir): the Merkle path directions are compile-time
  constants. The L/R swap at each level is a static build-time reorder (zero
  multiplication gates) and the index travels as public instance data into
  Fiat-Shamir. Used when no one cares which chunk a node holds: the ledger can
  read the index directly for dedup and coverage counting (section 6.2).
- Secret-index (secret-dir): the path directions are witnessed. Each level adds
  a booleanity check `assert_product(dir, dir, dir)` (~1 multiply) and an L/R
  conditional-swap MUX (`node_bytes` multiplies), so the index is never
  revealed. Used when chunk anonymity must be enforced: a node proves it holds
  some chunk of `R` without revealing which one.

Cost asymmetry is small because the per-level node hash dominates. For the
GF(2^8) RS tree the depth is always `<= 8` (n `<=` 256), so on the 128-bit
profile (32-byte nodes, grostl256_fixed inode at 1920 multiplies per level):
the secret-dir machinery adds `~ (node_bytes + 1)` multiplies per level,
`~264` over depth 8, against `~15,360` for the path hashing itself. Hiding the
index therefore costs on the order of 1-2% over revealing it; revealing it
costs nothing. Both variants are worth shipping.

Leaf layout. The leaf preimage binds the FWK, the chunk digest, and a 1-byte
index (sufficient because `n <= 256`), padded to the hash block:

    128-bit CR: FWK(16) || chunk_digest(32) || index(1) || pad(15)  = 64 B (one grostl256/SHAKE block)
    256-bit CR: FWK(32) || chunk_digest(64) || index(1) || pad(31)  = 128 B (one grostl512/SHAKE block)

The index field widens to 2 bytes (the pad shrinks by 1) for the future
GF(2^16) RS, where `n` can reach 65535 and the tree depth 16; the index width
is `1` byte while depth `<= 8` and `2` for depth `9..16`. The tree depth itself
is per-dataset, `ceil(log2(n))`, recomputable by a verifier from the
`R`-bound `n`, so a shallower tree (a smaller dataset) costs one fewer
inode-hash level per proof and a prover cannot misrepresent the depth.

Indexed-consistency constraint (mandatory once the index is in the leaf and the
secret-dir variant is offered): the circuit must assert that the witnessed path
directions equal the bits of the committed index byte, or a prover could commit
index `i` in the leaf while routing the secret path to a different position,
decoupling the committed index from the actual tree position. This is the
existing `indexed_merkle_gf8` pattern: bit extraction from the index byte is a
free linear map and the per-bit equality is ~1 multiply, so ~8 multiplies at
depth 8. The public-dir variant does not strictly need the index in the
preimage (the public path already pins the position), but binding it lets one
tree serve both modes, which is the point.

Attributes are NOT a leaf field. The node-attribute restriction of section 6.3
is per-dataset, bound once to `R`, not carried per chunk: there is no use case
for one chunk of a dataset being placeable outside the dataset's own policy. So
the restriction stays bound to the root and the leaf preimage carries no
attribute bytes; the pad in the layout above is just padding.

### 6.7 Dataset metadata bound to R

Several values are per-dataset constants rather than per-chunk data, and the
sections above refer to them piecemeal. They are collected here as one small
structure committed once and bound to the root `R` (the binding is what stops a
party from reinterpreting a dataset under different parameters). What travels
with `R`:

- `chunk_size`: the fixed length of every chunk (data and parity), needed to
  lay out and read shards.
- `file_len`: the original file length, needed to strip the final data chunk's
  zero padding (section 2.3).
- `(n, k)`: the RS parameters, so a verifier knows how many distinct indices
  constitute a recoverable dataset (the `k` threshold the ledger counts toward
  in section 6.2).
- Hash profile / CR level: which node-hash and digest sizes the tree uses
  (128-bit = SHAKE128/32-byte digest + grostl256_fixed; 256-bit =
  SHAKE256/64-byte digest + grostl512_fixed), so the leaf and node hashes are
  unambiguous to a verifier.
- Node-attribute restriction (section 6.3): the per-dataset allowed-node
  predicate, optionally with a secret (committed) allowed-value set for metadata
  confidentiality (section 6.5).
- Whole-file digest (optional): a hash over the full encoded message, letting a
  retriever make one end-to-end check that the rebuilt file matches what the
  owner committed (section 6.8). Independent of the per-chunk digests.

None of these is a leaf field; binding them to `R` once is both cheaper than
repeating them per leaf and the reason they cannot be altered per chunk or in
transit. The FWK is NOT part of this metadata: it is the owner's secret witness
(section 6.1) and never travels with the public root.

Binding mechanism. The metadata is bound to `R` by making `R` itself a
commitment over both the tree and the metadata, rather than a tree leaf (a leaf
would steal a slot from the 256-chunk budget or force a ninth tree level for one
extra leaf):

    metadata_digest = H(canonical_serialize(metadata))
    R               = H(merkle_root || metadata_digest)

`H` here is the plaintext per-profile hash (SHAKE128 squeezed to 32 bytes for
128-bit CR, SHAKE256 to 64 bytes for 256-bit), domain-separated from the
in-circuit node hashes so this top-level commitment can never be confused with
an internal tree node. The published, ledger-anchored identifier is this `R`;
the bare Merkle root is now an inner value.

This costs nothing in the tree (the tree is still just the dataset's chunk
leaves, at depth ceil(log2(n)) <= 8 for GF(2^8) RS) and nothing in the
circuit. The membership proof's in-circuit statement is unchanged: it proves a
leaf is on the path to `merkle_root`, with `merkle_root` a public input. The
metadata binding is a single plaintext hash the verifier computes OUTSIDE the
circuit. A certificate therefore travels as `(membership_proof, merkle_root,
metadata)`, with `merkle_root` and `metadata` carried in the once-fetched
dataset descriptor and the `membership_proof` in the per-chunk header (the
concrete byte layout is section 6.10), and a verifier:

1. recomputes `R = H(merkle_root || H(metadata))` and checks it against the
   authoritative `R` it trusts (ledger-published or signed);
2. verifies the membership proof against `merkle_root`.

Consequence for terminology: "the root" now has two layers, `merkle_root` (what
the circuit proves against) and `R` (what the ledger publishes and what binds
the metadata). Where sections 6.1 and 6.8 say "membership proof against `R`,"
that is shorthand for "proof against `merkle_root`, plus the plaintext check
that `R` commits to that `merkle_root` and the metadata." Owner-tying is
preserved: `merkle_root` still has FWK-blinded leaves, so only the FWK owner can
construct an `R` of this form.

### 6.8 Retriever-side sufficiency (requirement 2)

Requirement 2 is the retriever's side: a client downloading a dataset needs to
know when it holds enough distinct chunks to rebuild, and how many more to
request when it does not. In the form that matters for the ledger deployment
this is the client's OWN local check, not a proof presented to a third party.
Proving sufficiency or live possession TO another party is a separate, heavier
statement; see the scope note at the end.

The target count is public. From the section 6.7 metadata bound to `R` the
client reads `k`, the number of distinct chunks needed (MDS: any `k` distinct
indices rebuild). For the worked example, 64MB chunks of a 2GB file, `k = 32`.

Mechanism:

1. Request. The client asks the ledger for `k` distinct chunks of root `R`
   ("give me 32 chunks for `R`"). The ledger directs it to nodes holding chunks
   of `R`.
2. Collect and dedup. The client pulls chunks from those nodes. Duplicates can
   arise: node churn or stale ledger placement state can hand back two copies
   of the same chunk. (Distinctness from the ledger is best-effort in any case:
   under secret-index the ledger does not know the indices, so it cannot
   guarantee distinct service and the client-side dedup is the real arbiter.)
   The client deduplicates by the chunk's identity:
   - public-index: by the revealed index.
   - secret-index: by `chunk_digest`, which the client computes from the bytes
     it holds. The digest is inherently public (section 6.6), so duplicate
     content is detected without learning the index. An authorized rebuilder
     can do better: since it must recover each chunk's index to decode anyway
     (step 5), it can dedup by the recovered index, which avoids a corner case
     where two different indices with identical bytes (repeated blocks in
     plaintext data) collide to one digest and undercount. That undercount is
     safe (it only ever requests more, never rebuilds with too few) and is
     negligible under encrypt-then-encode (pseudorandom ciphertext chunks do
     not collide), but dedup-by-recovered-index sidesteps it entirely.
   Only the distinct count advances toward `k`; duplicates do not.
3. Top up. Finding it has, say, 24 distinct and 8 duplicates, the client
   requests more chunks from the ledger and repeats until it holds `k` distinct.
   Over the RLNC transport this is the rank-based loop of section 1.2: ask for
   more recoded packets, linearly dependent ones are free no-ops, stop at
   rank `k`.
4. Verify. The client verifies each chunk's membership proof against `R` (the
   two-layer check of section 6.7: proof against `merkle_root`, plus confirming
   `R` commits to that `merkle_root` and the metadata) and checks that the chunk
   bytes hash to the `chunk_digest` the proof commits to.
   A chunk failing either check is not a genuine member of `R` (garbage,
   corruption, or a malicious node), is dropped, and is not counted toward `k`.
   This is the detect-then-erase pattern of section 1.1.
5. Decode. With `k` verified distinct chunks the client rebuilds. RS decode
   needs the indices to select generator rows: in public-index mode the client
   has them; in secret-index mode it must be authorized to recover them (an FWK
   holder recovers the 1-byte index by trial against the tree, or the owner
   furnishes an index token), consistent with index secrecy being aimed at the
   network, not at the legitimate rebuilder.

What the client gains. After step 4 it trusts that every counted chunk is a
correctly downloaded, genuine member of `R`; after step 5 it knows the decoded
data is exactly what the FWK owner encoded under `R`, because each chunk was
proven to be a leaf of `R` and its bytes matched the committed digest.
Integrity chains from the authenticity of `R` (ledger-published or signed)
through per-chunk membership to the rebuilt file.

Membership proves authenticity, not codeword consistency. The membership proof
attests that each chunk's bytes are what the owner placed at its leaf of `R`.
It does NOT prove the chunks form a consistent RS codeword (that decoding any
`k`-subset yields the same message); that cross-chunk property is capability 3
(`C = G . M`), not the per-chunk capability 2 used here. The flow is sound
because the client trusts the owner encoded `R` consistently: an honest owner
ran the encoder, so all `n` chunks agree and any `k` distinct decode to the
same message, and a malicious node cannot substitute bytes that still pass
membership (no FWK, collision resistance). A client that needs to distrust the
owner's encoding itself, rather than take `R` as authoritative, needs the
capability-3 encoding proof.

Optional end-to-end check. Per-chunk membership already guarantees a correct
decode under an honest owner, but a whole-file digest in the section 6.7
metadata bound to `R` lets the client make one final check after decode and
decrypt: confirm the rebuilt file matches what the owner committed. This is
cheap insurance against a buggy decode or a wrong `file_len` and gives the
downloader a single unambiguous "this is the file" assertion.

The two checks stay independent. Membership verification is the integrity gate
(genuine vs junk); dedup-by-digest is the counting (distinct vs duplicate).
Neither subsumes the other: a genuine chunk can be a duplicate, and a
unique-looking blob can be junk.

Scope note: proving to a third party. The mechanism above is the client
convincing ITSELF. Proving to someone else is a different and heavier
requirement, recorded here so the boundary is explicit and out of v1.9.0 scope:

- Sufficiency as a third-party statement ("I hold `k` distinct members of
  `R`") is a zero-knowledge statement over `k` membership witnesses, where the
  public/secret index choice becomes the distinctness-revelation knob: reveal
  indices to show distinctness, or prove distinctness in zero knowledge.
- Live possession ("I currently hold these bytes") needs freshness (an
  unpredictable challenge the prover could not precompute) and verifier-
  efficient tags (proof of retrievability / provable data possession), because
  a static Fiat-Shamir proof is replayable: it proves possession at generation
  time, not at validation time. The freshness source is the challenger (the
  ledger or a public beacon), never the data owner, and needs no FWK, since
  possession is about bytes, not ownership. The owner contributes only
  setup-time tags bound to `R`.

Neither is required by the ledger durability use case as described; both are
recorded as future enhancements in section 10.

### 6.9 Capability 3: encoding correctness

Capability 3 is the consistency layer: it asserts the committed chunks form a
valid codeword `C = G . M` for the public generator `G` (fixed by `(n, k)` in
the section 6.7 metadata). It is a different statement from the section 6.1
membership cert: membership proves the owner blessed these bytes at this
position; capability 3 proves the bytes are arithmetically the correct
encoding. The two compose, and capability 3 is the downloader's defense against
a buggy or malicious owner that committed an inconsistent codeword under an
otherwise valid `R` (section 6.8).

How it is proved depends on whether the data is public and on who the verifier
is. There are three forms, only the first of which applies to RS storage:

- Plaintext re-encode (RS storage, the default). The chunk data is public
  (encrypt-then-encode), and verify in this library is linear in circuit size,
  so an in-circuit `C = G . M` over a multi-gigabyte file is both infeasible and
  pointless: there is nothing to hide. Instead any party holding `k` chunks
  decodes `M`, re-encodes all `n` with the public `G`, and checks the parity
  chunks against the digests committed under `R`. That IS capability 3, done in
  plaintext, and the downloader gets it almost for free as the final step of
  section 6.8 (it is the same computation as the optional whole-file digest
  check). No circuit, no witness.
- In-circuit ZK `C = G . M` (small secret data only). A zero-knowledge encoding
  proof earns its keep only when `M` is small AND must stay secret from the
  verifier, for example the RLNC generation-membership statement `y = c . X`
  over a small generation (one row, mostly XOR plus a thin row of multiplies,
  section 7). It does NOT help storage: the data is public, and linear verify
  means the proof costs about what re-encoding costs, so even a chunk-less
  auditor saves nothing over plaintext re-encode at scale.
- Homomorphic-tag consistency (chunk-less, sublinear, future work). The only
  way to let a party verify `C = G . M` WITHOUT the bulk data and sublinearly is
  a linearly-homomorphic commitment: commit each chunk so that
  `commit(C[i]) = G . commit(M)` holds by homomorphism, and check consistency
  over the small commitments. This is the same machinery family as the
  possession tags of section 6.8 and is separate from the hash-Merkle leaf
  (hashes are not linear, so `G . M` cannot be pushed through a plain digest).
  It would replace, not extend, the Merkle leaf for this purpose, and is
  recorded as future work in section 10, not a v1.9.0 deliverable.

Forgeability and owner-tying. Capability 3 has no forgeable artifact in its
plaintext form: it is a self-checked public predicate, the verifier recomputes
the truth, so there is no "yes it is consistent" to forge or replay. And it
needs no owner-binding of its own, it inherits `R`'s: the leaves of `R` are
FWK-blinded, so only the FWK holder can construct the authoritative `R` (section
6.1), and the ledger or a signature anchors which `R` is canonical. Consistency
checked against that `R` is therefore consistency of the OWNER's committed
codeword. Membership (capability 2) plus consistency (capability 3) together
state that the FWK owner committed a set of chunks that are arithmetically a
valid encoding. Anyone may re-encode the public data under their OWN root, but
that is a different dataset with a different owner, not a forgery, ownership is
FWK control of the anchored `R`.

The two non-plaintext forms reattach owner-tying through the same FWK anchor:
the in-circuit ZK proof witnesses the FWK / binds to the FWK-blinded commitment
exactly as section 6.1 does (forgery-resistance from proof soundness); the
homomorphic-tag form derives its tag key from the FWK with verification material
bound to `R` (forgery-resistance from tag / homomorphic-signature
unforgeability). In every form, owner-tying routes through the FWK and
forgery-resistance comes from the mechanism appropriate to that form:
self-checking, soundness, or tag unforgeability.

### 6.10 Metadata serialization and wire format

Section 6.7 binds the metadata to `R` by `R = H(merkle_root || H(canonical_
serialize(metadata)))`. For that digest to be reproducible by anyone, the
serialization must be canonical: exactly one byte encoding per metadata value.
This section pins it.

Canonical metadata byte string (the input to `metadata_digest = H(...)`). Fixed
field order, big-endian integers, explicit flags and lengths for optional
fields, no padding:

```
off  size  field
0    1     version            0x01
1    1     cr_profile         0x01 = 128-bit CR, 0x02 = 256-bit CR
2    4     chunk_size         uint32 BE (caps a chunk at 4 GB - 1; never the
                              binding constraint in the GF(2^8) regime, see 2.3)
6    8     file_len           uint64 BE
14   2     n                  uint16 BE (room for a future GF(2^16) RS up to
                              n = 65535 without a format change)
16   2     k                  uint16 BE
18   1     flags              bit0 = whole_file_digest present
                              bit1 = attribute_restriction present
                              bit2 = por_params present (RESERVED for the future
                                     possession proof; always 0 in v1.9.0)
19   ...   whole_file_digest  present iff flags.bit0; 32 B (128-CR) or 64 B (256-CR)
...  ...   attr_restriction   present iff flags.bit1; 2-byte BE length L, then L
                              bytes (opaque: the predicate, or a commitment to it
                              when the value is secret, section 6.5)
...  ...   por_params         present iff flags.bit2; 2-byte BE length L, then L
                              bytes (PoR public verification parameters + scheme
                              id). RESERVED: the flag and field are defined now so
                              enabling possession later is a populate step, not a
                              format change (forward-compat note below).
```

Tail fields appear in flag-bit order (whole_file_digest, attr_restriction,
por_params), each present only if its flag is set. So a fixed 19-byte head plus
up to three optional length-determined tail fields.
`metadata_digest` is `H` over this entire string, with `H` the per-profile
plaintext hash (SHAKE128 squeezed to 32 bytes for 128-bit CR, SHAKE256 to 64
bytes for 256-bit).

`cr_profile` is redundant with `len(R)` (32 vs 64 bytes) but is kept: the
in-circuit verification needs the explicit enum to select the node hash, and
`metadata_digest` is computed before a party necessarily holds `R`. A verifier
MUST assert the two agree (`len(R) == 32` iff `cr_profile == 0x01`) as a cheap
malformed-input check. The `version` byte lets the format evolve without
ambiguity, which matters because this string is hashed into the dataset
identity.

Dataset descriptor (the metainfo, fetched once). The metadata travels in a
per-dataset descriptor, a tracker metainfo in the BitTorrent sense, not in every
chunk:

    descriptor = merkle_root (32 or 64 B) || canonical_serialize(metadata)

`merkle_root` is the other operand of `R` (not part of `metadata_digest`), so it
sits alongside the metadata here. A retriever fetches the descriptor once,
recomputes `R = H(merkle_root || H(metadata))`, and checks it against the
authoritative `R` it was given.

Per-chunk wire format (what circulates in the swarm). Each chunk references the
dataset by `R` rather than restating the metadata, and the header is versioned
and flagged so the possession plumbing exists now (see forward-compat note):

    chunk_packet = chunk_header || chunk_bytes
    chunk_header = header_version  (1 B, 0x01)
                || header_flags    (1 B; bit0 = possession_tag present)
                || R               (32 or 64 B, length from cr_profile)
                || cert_len        (4 B, uint32 BE: length of the certificate)
                || membership_certificate (cert_len bytes)
                || possession_tag  (present iff header_flags.bit0; 2-byte BE
                                    length L, then L bytes; RESERVED, always
                                    absent / flag 0 in v1.9.0)

The membership certificate is a variable-length blob (the gf8 proof) followed by
the optional `possession_tag` tail, so the header length-prefixes it with a
4-byte BE `cert_len` to stay parseable. The certificate's public instance
already carries `merkle_root`, `chunk_digest`, and (public-dir) the `index`
(section 6.1), so those are not restated; `chunk_digest` is recomputable from
`chunk_bytes`, so storing it is optional convenience for dedup. The full metadata
is NOT duplicated per chunk: the chunk points at `R` and the retriever already
holds the descriptor. An optional standalone mode may embed the descriptor in a
chunk header (about 50-100 extra bytes) so a chunk is verifiable with nothing
pre-fetched; the swarm default is reference-by-`R`.

Parsing the two envelopes (who knows `len(R)`). The descriptor is
self-describing: `merkle_root` precedes the metadata, but the metadata's
`cr_profile` byte fixes `len(R)`, so the parser recovers the split by trying both
candidate widths (32, 64) and accepting the one whose trailing metadata parses,
consumes the buffer exactly, and whose `cr_profile` agrees with the split point.
The chunk header is NOT self-describing: a 32- and a 64-byte `R` are
indistinguishable from the header bytes alone, so the parser takes `cr_profile`
as an input. This is sound because a party processing a chunk has always already
fetched the descriptor (hence the profile); the chunk references the dataset by
`R`, and `R`'s width is part of the dataset identity the descriptor pins.

Forward-compatibility for possession (plumbing now, populated later). The
node-side possession proof is a future enhancement (section 10), but its
plumbing is reserved in this format as of v1.9.0 so that turning it on is a
populate step, never a format break:

- Descriptor side (what the verifier needs): the PoR public verification
  parameters ride in the `por_params` metadata field gated by `flags.bit2`.
  Because they are part of the metadata that `R` commits to, they are
  tamper-bound to the dataset and cannot be swapped in transit.
- Per-chunk side (what the node needs): the per-chunk homomorphic tag rides in
  the `possession_tag` header field gated by `header_flags.bit0`. So a chunk
  delivered to a node becomes `bytes + certificate + tag`, and the node has
  everything it needs to answer a freshness challenge without any further
  format change.

In v1.9.0 both flags are 0 and both fields absent; a serializer and the wire
parser still define and skip them, so a future possession-enabled dataset is
read by the same code path. What is NOT in the format, by design, is the
freshness nonce: it is generated fresh per challenge by the challenger (ledger
or beacon) and never stored or pre-sent (section 10). The FWK never travels to
the node either; the node holds only its tag, not the tag key.

This makes concrete the "travels as `(membership_proof, merkle_root, metadata)`"
shorthand of section 6.7: `merkle_root` and `metadata` live in the descriptor,
the `membership_proof` (certificate) rides in the per-chunk header, and `R` ties
them together.

### 6.11 Confidential RLNC (paper 2) as a ZK statement

The rest of section 6 assumes encrypt-then-encode: the owner enciphers the data
with a standard cipher, then RS/RLNC-codes the ciphertext, and the proofs are
about membership and decodability of pseudorandom chunks. Two papers in
`docs/specs` instead push confidentiality INTO the coding layer, making the
linear combination itself the cipher. Of the two, only Brahimi and Merazka 2022
("Data confidentiality-preserving schemes for RLNC", paper 2) is relevant here;
Noura/Martin/Al Agha 2014 (paper 1) reduces to "secure the coefficient matrix"
(already covered below) and bolts on HMAC-SHA-512 and RSA, which are off-strategy
for this symmetric/PQ library. This section pins the design for a PLANNED,
general-purpose library capability: paper 2's confidential-RLNC codec plus a ZK
proof over it. The motivation is that this library is general (paper 2 is a real,
citable construction worth supporting in its own right), NOT the ledger, whose
encrypt-then-encode posture does not need it (see "Relationship to the ledger"
at the end). The build sub-sequence, smallest-first, is in section 9.1.

What paper 2 is. Two encryption schemes, both resting on two levers:

1. Securing the coding coefficient matrix. The local encoding matrix `L` is
   secret and NOT transmitted (the packet carries an identity/unit-vector block
   in place of coefficients), so a wiretapper cannot decode. Scheme 1 RLNC-encodes
   under secret `L`; scheme 2 uses Gauss elimination (RREF) plus an extra symbol
   for PRNG synchronization in place of the precoding.
2. A partial permutation of the data symbols after a `T` transformation. `T` is
   the vectorization isomorphism `F_{q1} -> F_{q2}^t` (their example splits a
   GF(2^8) symbol into two GF(2^4) sub-symbols). `T` enlarges the alphabet so the
   secret partial permutation has more symbols to act on; `T^{-1}` reassembles.

Threat model is weak/computational security against a wiretapper with access to
up to `C_m` channels, NOT semantic security. The permutation-cipher family
(P-Coding, SPOC, and this work) is known to be weaker than a standard cipher; a
ZK proof of correct encoding neither strengthens nor weakens that.

Implementation side-channel posture. The network-observer threat model above
bounds what a wiretapper learns from the transmitted symbols; it does not, by
itself, cover a local or co-tenant adversary observing this host's timing or
cache. The codec's inputs are secret (the coefficient matrix `L`, its inverse
`L^{-1}`, and the partial permutation `perm`), and this library holds a
project-wide constant-time requirement (no secret-dependent branches, no
secret-indexed memory), so the plaintext codec data path is constant-time:

- keygen derives the permutation with an oblivious Fisher-Yates shuffle: the
  random draw index is secret, so each swap reads and writes the target slot with
  a masked full-array scan rather than a secret index. Each index is drawn from a
  FIXED number of PRG bytes and reduced into range by a Lemire multiply-shift
  (`(v * bound) >> 64`, bias `<= bound / 2^64`), with no reject loop, so total PRG
  consumption -- and thus keygen's block-refill count and total time -- is
  independent of the seed. The draw sequence is otherwise deterministic in
  `(seed, generation_id)`;
- the permutation apply (`voleith_confrlnc_permute` / `_permute_inverse`) and the
  bring-your-own key validation (`voleith_confrlnc_validate_key`, and the routing
  gadget's own input validation) check and apply `perm` with a masked O(n^2)
  scan, so a secret `perm` entry is never used as a memory index and no reject
  branches on the permutation; it is a per-generation, data-owner-side step, not
  the hot proving path, so the O(n^2) cost is acceptable (a Benes/Waksman
  O(n log n) oblivious apply is a possible future optimization);
- the secret-matrix inverse in keygen and decode uses
  `voleith_ec_matrix_invert_ct` (oblivious masked pivoting, unconditional
  elimination) instead of the variable-time `voleith_ec_matrix_invert`, which is
  kept only for the public RS data;
- the underlying GF(2^w) multiply and inverse are constant-time.

The secret-dependent observables that remain on the data path are the one-bit
singular / non-singular return code (unavoidable at the API, and already revealed
by keygen's L acceptance) and the retry count of keygen's L rejection sampler,
which redraws only when a random matrix happens to be singular (~2^-16 over
GF(2^16)) -- a genuinely negligible residual, not tied to any single secret value
and independent of the seed's key value. (The permutation index sampler no longer
rejects; see above.) These constant-time paths carry empirical timing evidence:
`tools/dudect/targets_erasure_ct.c` registers fixed-vs-random dudect targets for
`voleith_ec_matrix_invert_ct`, `voleith_confrlnc_permute`, `_permute_inverse`,
`voleith_perm_gf16_route`, `voleith_confrlnc_validate_key`, and
`voleith_confrlnc_keygen`, run pre-release from the explicitly-built `dudect`
harness. Note those targets measure TOTAL time, which
bounds access-count and branch leaks but is largely blind to access-ORDER (cache
address-pattern) leaks; the oblivious-access property of the shuffle, validation,
and routing above is established by construction and code inspection, not by the
total-time tests alone.

This extends to the proving path. The AS-Waksman gadget derives its switch
control bits from `perm` at proof-construction time
(`voleith_perm_gf16_route`), and that routing is also constant-time: the memory
access pattern and control flow depend only on the network size `n` (public),
never on the permutation values. The coloring that the classical routing
algorithm does with a data-dependent breadth-first search is replaced by an
Euler-tour list-ranking (pointer doubling) in which every secret-indexed access
is a masked O(n) scan, giving O(n^2 log n) work; the network recursion structure
was already a function of `n` alone. A variable-time reference router is retained
only as a test oracle and is never run on a secret permutation. The rest of the
proving path is constant-time by construction: the QuickSilver prover iterates
the public circuit shape with public wire indices and constant-time field
arithmetic, and the arithmetic witness generators (e.g. the AES / CMAC S-box
inverse inputs) are composed from the constant-time field inverse. Timing
evidence for the routing is a dudect target
(`tools/dudect/targets_erasure_ct.c`, `voleith_perm_gf16_route`, fixed-vs-random
permutation).

What is free in our circuits. Both levers land mostly on existing machinery:

- Secret coefficient matrix = the secret-coefficient orientation already built
  (`voleith_rlnc_gf16_coded_vector_circuit`): multiply-by-a-coefficient is
  GF(2)-linear, so with public data and secret coefficients the whole encode is
  zero mul gates, `ell = k`. This is the in-circuit form of lever 1.
- The `T` split and `T^{-1}` are GF(2)-linear (a bit-regrouping), hence free.
  For our GF(2^16) coding field the natural split is `F_{2^16} -> F_{2^8}^2`
  (`r=8, t=2`). The whole P7 proof is HOSTED ON THE NATIVE GF(2^16) PROVER
  (`proof/gf16_*`, the P5 stack), NOT a gf8 stack: byte sub-symbols are carried
  as gf16 wires (value in the low 8 bits), and `T` / `T^{-1}` are free 16x16
  GF(2) linear maps. (This supersedes an earlier "host on the mature gf8 stack /
  GF(2^8)^2 tower" design: once the native gf16 prover landed in P5 it became the
  better substrate, because it lets the wrapper compose the secret-coefficient
  encode, the permutation gadget, and the decodability certificate in ONE prover
  and ONE VOLE instance, and keeps the cheapest gf16 arithmetic on the
  verify-linear path. The GF(2^8)^2 tower stays deferred, section 10.) Critically,
  `T` is a representation/permutation device only: the coding stays in GF(2^16),
  so the full-rank-at-scale reason for GF(2^16) (section 2, RLNC) is preserved.
  Do NOT reinterpret the split as coding over GF(2^8).

The one new costly primitive. Lever 2's permutation is SECRET (key-derived,
stored as a lookup table). A public permutation is free wire relabeling; a secret
one is not. Proving in zero knowledge that a secret partial permutation was
applied requires proving the table is a genuine permutation (each index used once)
and that it was applied, i.e. a routing/sorting-network argument, roughly
`O(n log n)` constrained gates over the (gf16-carried) byte sub-symbol wires.
This gadget is built as an AS-Waksman routing network
(`voleith_perm_gf16_circuit`): one mul gate per 2x2 switch, control-bit
booleanity by `assert_product(s, s, s)`, and permutation-validity that is
STRUCTURAL (any control bits yield a rearrangement), at the optimal switch count
`S(n) = n*log2(n) - n + 1`. The permutation acts on byte-granular sub-symbols
that are already first-class wires after the `T` split.

The decodability/sufficiency certificate. Independent of confidentiality, a
recipient can be convinced that the packets it holds are enough to rebuild
WITHOUT being able to rebuild them. Decodability is exactly "the (hidden)
coefficient matrix of the held packets is full rank". The clean ZK certificate
is knowledge of the inverse: witness `C` and `C^{-1}`, assert `C . C^{-1} = I_m`.
Existence of an inverse is equivalent to full rank, and the verifier sees only
that the relation holds, never `C` or `C^{-1}`, so it cannot compute
`X = C^{-1} . Y`. Cost is an `m x m` matrix-multiply-equals-identity,
witness x witness, about `m^3` mul gates (m=16 -> ~4k, AES-circuit scale).
This is the in-circuit counterpart of `voleith_rlnc_gf16_coeffs_full_rank` (the
plaintext oracle), shipped as `voleith_rlnc_gf16_cert_circuit` (P7 T7.1). Role
constraints (mirrors the 6.8 scope note): the prover must hold the secrets
(typically the source), the verifying recipient must NOT be the decryptor (else
decodability assurance is moot). It certifies decodability, not semantic
correctness of the plaintext, unless a commitment to `X` is bound as instance.

Generation binding (out of scope). The `C . C^{-1} = I` relation certifies that
SOME matrix the prover knows is full rank, but does not by itself pin `C` to the
packets a holder actually received. Binding `C` to a specific received set across
independently finalized per-packet proofs is deliberately NOT provided, for two
reasons. First, it is unnecessary in the intended trust model: with the source
trusted for cross-packet consistency, such a rank binding would defend only
against a source honest about consistency yet lying about rank (an incoherent
adversary), while an honest source's random coefficients make any k held packets
full rank with probability about `1 - 2^-16`, so counting k integrity-checked
packets already suffices. Any party able to build the certificate holds the
coefficients and can therefore decode, so that necessarily-trusted party's plain
signature over the held set conveys the same assurance at zero circuit cost.
Second, the recommended transport posture is encrypt-then-encode (this section's
preamble), under which coefficients are public, rank checks are free plaintext
computations, and per-hop recoding (RLNC's defining flexibility, which per-packet
emit-time proofs forbid) is restored. A naive cross-proof binding would in any
case be unsound: a single post-commit challenge cannot land inside the
chall_1..chall_3 window of proofs finalized at different times, and the sound
alternatives (fold each opening into its own proof's pre-challenge transcript)
conflict with the shared cross-set challenge that would be the point of the
feature.

What is provided: the standalone rank certificate (T7.1, above, no instance
wires) and the data-blind membership circuit (`Y = c . X`, both secret, in
`rlnc_gf16_circuit`), each individually sound. The codec guardrail stands on its
own merits: `generation_id` remains OPAQUE (never `generation_id = H(C)`).

Forwarding and recoding (relation to the RLNC transport, section 1.2). A keyless
relay forwarding the SAME packets plus the SAME proof transfers the guarantee:
the proof is non-interactive and publicly verifiable, bound to the packet values,
so any downstream host re-verifies decodability and learns no plaintext (and is
protected against the relay tampering, since the proof validates exactly those
bytes). The genuine RLNC behavior, recoding `Y' = R . Y` at an intermediate node,
does NOT carry the proof: `Y'` is a different instance, and a keyless relay cannot
re-prove (it lacks the witness). The practical resolution does not need a
malleable proof, because RLNC recoding `R` is PUBLIC and decodability composes:
`Y' = (R . C) . X`, and `R . C` is invertible iff `R` is. So carry the original
proof on the original generation plus the public recoding matrix (or its running
product), and the verifier publicly checks `Y' = R . Y` and `rank(R) = m`. This
is an auditable transform (it carries `Y` and `R`, so it keeps decodability and
confidentiality but not RLNC's bandwidth gain), and it only covers the linear
coding layer: the secret permutation cannot be made public, so a keyless relay
can recode the coding layer but cannot touch the permutation layer.

Why malleable proofs are a non-goal. Literal proof malleability (transform a
proof to a new instance without the witness) is structurally blocked by this
library's design: VOLEitH under Fiat-Shamir derives every challenge by hashing
the transcript including the instance, so `Y -> Y'` changes `chall_1` and
cascades, and patching requires the witness and GGM seeds. That instance-binding
is the same property that gives soundness; it is not a missing feature.
Algebraic malleability would need a homomorphic-commitment proof system
(lattice/pairing), a different foundation than this symmetric/PQ-hash stack.
Recursive proof composition (verifying a VOLEitH proof inside a VOLEitH circuit
via the in-circuit AES/SHAKE primitives) is expressible in principle but
practically infeasible. The public-`R` construction above is the recommended
route and needs no new cryptography beyond the invertibility certificate.

Security notion is an API-honesty requirement, not a blocker. Confidential RLNC
provides weak/computational security only (the permutation-cipher family, weaker
than AEAD), and it authenticates nothing. The codec and proof APIs MUST document
this so a consumer does not mistake the coding layer for a semantically-secure
authenticated cipher. The robust deployment shape is AEAD payload (semantic
security plus integrity) composed with confidential RLNC for the coding-structure
(generation-linkage) hiding it uniquely adds. Pollution resistance (active packet
injection survives recoding) is a separate, mandatory transport concern (a
homomorphic MAC), and is the consuming application's job, not this codec's.

Key material is a split responsibility. A security library must own SAMPLING
CORRECTNESS (a uniform permutation, a full-rank coefficient matrix, a correct
CSPRNG) even though it does NOT own KEY DISTRIBUTION (getting the secret to the
legitimate decryptor: KDC, sync, freshness), which stays the application's job
(section 7.0). So the codec exposes two paths. The DEFAULT (misuse-resistant)
path takes a high-entropy seed plus a generation id and deterministically derives
a uniform permutation (Fisher-Yates over `core/prg.c`) and a full-rank matrix
(rejection-sampled until `erasure/matrix.c` confirms invertibility); the caller
cannot produce a biased permutation or a singular matrix this way. This matches
paper 2's own PRNG-derived, KDC-synced model (source and sink derive the same
secret from the same seed), so the `seed -> (permutation, coefficients)`
derivation is a VERSIONED WIRE CONTRACT both ends must share. The ADVANCED path
takes an explicit matrix and permutation table, each VALIDATED (a non-permutation
table and a singular matrix are rejected with an error, never silently accepted);
it also drives the paper-figure KATs (which use a specific permutation, not a
seed-derived one), so it is a tested first-class path. The `generation_id` is an
OPAQUE freshness label fed only into the PRG IV; it is deliberately NOT bound to
`C` structurally (see the retired generation-binding discussion above), so any
future binding scheme stays unconstrained.

Keygen is a pure deterministic function of `(seed, generation_id)` with no
persistent state, so it CANNOT detect the two caller mistakes that would break
confidentiality, and the application owns both:

- Seed entropy. The seed MUST be full-length cryptographic-RNG output;
  confidentiality rests entirely on it, and a predictable or low-entropy seed
  yields a predictable key. Keygen rejects an all-zero seed (the fingerprint of
  a forgotten / uninitialized buffer) with `VOLEITH_EC_ERR_PARAM` as a cheap
  misuse tripwire, but this is explicitly NOT an entropy check: a nonzero but
  weak seed passes.
- `generation_id` uniqueness. Because the derivation is deterministic, the same
  `(seed, generation_id)` always yields the same `(L, permutation)`. The
  `generation_id` MUST be unique per generation under a given seed (e.g. a
  monotonic counter); reusing it is key reuse, which for this permutation-plus-
  linear cipher family can expose plaintext across the two ciphertexts.
  Re-deriving the same key on the receiver from the same inputs is the intended
  wire contract; the hazard is reusing the pair for a NEW generation.

The application also owns key distribution.

Build ordering. The decodability/sufficiency certificate (`C . C^{-1} = I`) is
independent of the permutation gadget and lands first: it is a self-contained
rank primitive useful beyond paper 2 (keyless verifiable relay of any coded
generation). The secret-permutation routing-network gadget is the largest piece
and gates the full paper-2 proof. See section 9.1 for the smallest-first
sequence.

Relationship to the ledger. The ledger does NOT consume this: its encrypt-then-
encode posture (a standard cipher, then code the ciphertext) is simpler, achieves
semantic security, and is the section 6 default. Confidential RLNC is a library
capability for OTHER consumers (e.g. a confidential transport that unifies FEC
and coding-structure privacy in one layer, over any datagram or stream carrier),
not a ledger feature. Even there,
it is the easy half of traffic-analysis resistance: it hides packet CONTENT and
the coding vectors, but the metadata channel (endpoints, sizes, timing) remains
and is closed by framing/padding/cover traffic, independent of the codec.

## 7. API surface (sketch)

### 7.0 Library boundary: codec, proofs, and serialization only

This library is a codec plus proof system plus serialization toolkit. It does no
I/O and runs no distributed-system logic. The transport (moving chunks) and the
ledger / tracker (who-holds-what state, placement, health scheduling, healer
orchestration, certificate archival) are OUT of scope and live in a consuming
application built on this library, the same way interactive VOLE-ZK and the
Shipshape IR are scoped as separate efforts rather than folded in here.

In scope (this library provides):

- Plaintext codec: RS encode / decode / repair, RLNC encode / recode / decode.
- Proof system: membership-certificate prove / verify, and the capability-3
  plaintext consistency helper (section 6.9).
- Three serializable types, each with a canonical serialize and a matching
  deserialize, so the application moves bytes without knowing their structure:
  - dataset metadata (sections 6.7 / 6.10), and the descriptor
    `merkle_root || serialize(metadata)`;
  - the chunk header (section 6.10: version, flags, `R`, certificate reference,
    reserved possession-tag slot);
  - the membership certificate / proof itself.
- Crypto helpers: `chunk_digest`, the FWK-blinded leaf builder, tree build to
  `merkle_root`, `compute_R` / `verify_R`, and index-recovery-by-trial.
- Local decision primitives (pure functions the application calls): dedup,
  distinct-count, RLNC rank, "do I have `k` distinct yet".

Out of scope (the consuming application provides):

- Transmission and networking (the swarm, transfers, retries).
- The ledger / tracker: per-chunk who-holds-what state, placement decisions,
  health-check scheduling, healer orchestration, and certificate archival
  storage (section 6.2).
- Policy: redundancy level, when to heal, node selection, attribute matching.
- Encryption (encrypt-then-encode is the caller's job), key management (FWK,
  future possession tag keys, attribute credentials), and the publishing,
  anchoring, or signing of `R`.

Three boundary nuances, so a helper is not mistaken for an orchestrator:

- Retriever sufficiency (section 6.8): the library exposes the decision
  functions (dedup, distinct-count, "am I done", decode, certificate verify,
  index recovery) and reports "you have 24 of 32, here are the gaps." The
  request-more loop is the application's networking; the library does not fetch.
- Healing (section 6.2): the library provides the RS `repair` primitive (decode
  plus re-encode the missing row); certificate re-attach is plain byte handling.
  Commanding a healer and placing chunks is the application.
- Capability-3 check (section 6.9): a library helper (re-encode and compare);
  when to run it is the application's call.

The `examples/` programs demonstrate the end-to-end flow but are illustrations,
not a shipped transport or ledger layer.

### 7.1 Detailed sketch

Plaintext, exposed for the data layer:

- RS: systematic `(n, k)` encode producing parity chunks; decode/repair from
  any k of n chunks. Generator via Vandermonde or Cauchy matrix (selected in
  the matrix core). A public decode-once / encode-specific-rows entry point
  (section 6.2 healer recipe) lets a healer regenerate several missing chunks
  from a single decode of `M`.
- RLNC: encode source symbols into coded symbols with coefficient vectors;
  recode coded symbols at intermediate nodes; decode a generation once rank
  k is reached. Generation identity and coding coefficients travel in the
  chunk header.

In-circuit (after plaintext is validated):

- Capability 2 (chunk membership). For RS this is the FWK-blinded Merkle
  membership certificate of section 6.1 (an authenticity statement, a leaf under
  `R`), built on the existing gf8 prover; it is NOT a `G . M` coordinate proof.
  For RLNC it is the generation-membership statement `y = c . X` for a committed
  source matrix `X` and public coefficients `c` (one row, mostly XOR plus a thin
  row of multiplies), on the native gf16 prover.
- Capability 3 (encoding correctness, `C = G . M`). For RS storage this is a
  PLAINTEXT re-encode-and-compare, not a circuit (section 6.9): public data plus
  linear verify make an in-circuit encoding proof infeasible and pointless. An
  in-circuit `C = G . M` is reserved for the small-secret-data case (the RLNC
  `y = c . X` form above); a general in-circuit RS encoding proof is deferred
  (see the implementation plan). Where built, cost scales with k . n
  multiply-adds and verify is linear in circuit size, so encoder size shapes
  verify cost.

## 8. Test oracle strategy

There is no faest-ref equivalent for erasure codes. Use an external reference
library (with a clearly stated GF(2^16) polynomial and matrix construction,
Cauchy vs Vandermonde) purely as an oracle: generate fixed known-answer
vectors once and check them into `tests/`. Do not link the reference library
at test time. We use it to produce vectors, we do not depend on it. This
mirrors how faest-ref is treated: oracle only, never a build dependency, never
ported.

The chosen oracle is **Jerasure 2.0 + GF-Complete** (both in `third_party/`,
never linked). It is the matrix family, matching our `C = G . M` construction,
and GF-Complete supports both fields we need:

- RS at w=8 with primitive polynomial 0x11B (our AES/FAEST field). Emitter:
  `tools/gen_rs_kat/` producing `tests/rs_kat.inc`. See that tool's README for
  the exact build and the gotchas (force 0x11B, use `GF_MULT_SHIFT`, scalar
  `galois_single_multiply`, match Cauchy points X[i]=k+i, Y[j]=j).
- RLNC at w=16 with primitive polynomial 0x1100B, which is already
  GF-Complete's default w=16 polynomial and is exactly our `m16`. The
  oracle-able surface of RLNC is GF(2^16) linear algebra: encode `Y = C . X`
  for fixed deterministic coefficient matrices C, and the decode inverse
  `C^-1`. A `tools/gen_rlnc_kat/` emitter (analogous to `gen_rs_kat`) produces
  `tests/rlnc_kat.inc`.

What is deliberately NOT oracled against a third party, because it is our own
design rather than a standard: the RLNC wire/header format (generation id plus
coefficient vector) and the rank-progress API. No external RLNC library shares
our packet layout, and dedicated RLNC stacks (e.g. Kodo) are license-
encumbered and only re-validate the same field algebra. Those RLNC-specific
behaviors are covered by self-consistency property tests: recode-then-decode
equals direct decode, decode succeeds exactly at rank k, and generation-id
handling.

Validation targets:

- `tests/test_field16.c`: GF(2^16) multiply / inverse round-trips,
  distributivity, known-answer vectors.
- RS encode/decode known-answer vectors from the oracle; repair from every
  k-subset for small parameters.
- RLNC encode known-answer vectors from the w=16 oracle; recode/decode by
  self-consistency: rank-completion decode, recoding associativity,
  generation-identity handling.

## 9. Build sequence (smallest first)

1. `core/field16.{c,h}` element arithmetic (CLMUL/PMULL + constant-time
   software fallback) and `tests/test_field16.c`.
2. `erasure/matrix.*` shared generator-matrix and Gaussian-elimination core.
3. `erasure/rs.*` RS encode/decode over GF(2^8) with oracle KATs.
4. `erasure/rlnc.*` RLNC recode/decode over GF(2^16) with oracle KATs.
5. After plaintext is validated: Layer 5 in-circuit RS/RLNC circuits using
   the GF(2^8)^2 tower representation from section 5.

A validated, tested, correct plaintext layer is the prerequisite for the
in-circuit work: it is the reference the circuits are checked against.

### 9.1 Confidential RLNC build sub-sequence

This is the smallest-first order for the section 6.11 capability. It sequences
AFTER step 4 above (plaintext RLNC codec validated), since the confidential codec
is the same recode/decode with secret coefficients and a permutation stage, and
the plaintext path is its oracle. Steps 1 and 2 are independently useful and can
land before the later ones.

1. Decodability/sufficiency certificate (`C . C^{-1} = I`). Self-contained rank
   primitive, independent of everything below. Plaintext oracle already exists
   (`voleith_rlnc_gf16_coeffs_full_rank`); add the in-circuit
   `m x m` matrix-multiply-equals-identity check (witness `C`, `C^{-1}`) with
   prove/verify tests. Shipped as `voleith_rlnc_gf16_cert_circuit`. Generation
   binding (pinning `C` to a received packet set) is deliberately out of scope
   (section 6.11 "Generation binding"). The cert ships standalone here, useful on
   its own for keyless verifiable relay.
2. Plaintext confidential-RLNC codec in `erasure/rlnc_confidential.*` (its own
   translation unit, not a mode flag on the plaintext codec): secret-coefficient
   encode/decode, the `T` split `F_{2^16} -> F_{2^8}^2` and `T^{-1}`, and the
   secret partial-permutation stage over the byte sub-symbols, validated against a
   paper-2 KAT oracle (scheme 1 first; scheme 2's RREF variant after). No proofs
   yet: this is the reference the circuit is checked against, same discipline as
   step 4.
3. Secret-permutation routing-network gadget (Layer 5). The one new costly
   primitive: prove a secret partial permutation is a genuine permutation and was
   applied, ~`O(n log n)` constrained gates over the byte sub-symbol wires.
   Hosted on the native GF(2^16) prover (the byte sub-symbols are gf16 wires after
   the step-2 `T` split), shipped as `voleith_perm_gf16_circuit` (AS-Waksman).
   Largest piece; gates the full proof.
4. Confidential-RLNC proof wrapper: compose the (free) secret-coefficient encode,
   the (free) `T` maps, and the step-3 permutation gadget into a prove/verify over
   a confidential packet, with the step-1 certificate available for the
   decodability statement. Tamper and soundness tests per the existing proof-test
   pattern.

The codec (steps 1, 2) lives in this library; any transport that would consume
it does not (section 7.0 boundary, and the section 6.11 ledger note).

## 10. Future enhancements (out of v1.9.0 scope)

These are recorded so the v1.9.0 design does not foreclose them. None is built
in v1.9.0; each lands only if a use case arises.

- Variable-time fast region-multiply engine. A `PSHUFB` (x86) / `TBL` (ARMv8)
  split-nibble region multiply for bulk encode throughput. Its only use case
  is public coding outside a proof, so it lives entirely in `erasure/`, never
  in the proving layers. The constant-time hardware multiply is faster than
  the software fallback anyway and is allowed in the proving layers because it
  is constant-time; the variable-time engine is a throughput optimization for
  the plaintext path only, added if and when a use case demands it. Note: the
  `PSHUFB`/`TBL` split-table method is itself constant-time (register-resident
  table, fixed-latency shuffle); only a memory-resident log/antilog scalar
  fallback is genuinely variable-time.

- Streaming RS encode / decode / repair. The v1.9.0 codec operates on whole
  chunk buffers, which is correct but holds `k` chunks resident to decode (e.g.
  32 x 64MB = 2GB to repair one chunk), and worse under large chunks, the
  GF(2^16) large-file regime, or concurrent heals. Because `C = G . M` is
  symbol-wise independent (the encode core is already per-symbol), a streaming
  API is a thin wrapper: process a symbol window across the `k` inputs and emit
  output symbols incrementally, dropping peak memory from `k * chunk_size` to
  `k * window`. This is a memory / scalability concern, not a correctness one,
  and nothing in the proof or metadata design depends on it: `chunk_digest`
  already streams (the Keccak sponge in `core/hash.c` absorbs incrementally),
  and the membership proof is over the small digest, not the bulk bytes. The
  healer is the heaviest beneficiary (section 6.2). Deferred, but the buffer API
  is kept per-symbol so the streaming version wraps it rather than rewriting it.
  Trigger: large-chunk or memory-constrained deployments; pairs naturally with
  the GF(2^16) RS large-file item below.

(The native GF(2^16) element-level QuickSilver prover, previously listed here
as a future enhancement, is now a planned v1.9.0 in-circuit deliverable; see
section 5.)

- GF(2^8)^2 tower gadget for cross-field composition (see section 5.1). Not
  built in v1.9.0. Trigger: a concrete proof statement that is GF(2^8)
  dominated but needs a minority of GF(2^16) arithmetic in the same proof
  (e.g. RLNC/RS membership composed with the gf8 ring-sig or KVAC stack). When
  that consumer appears, build the tower multiply (Karatsuba over GF(2^8)) and
  the plaintext-to-tower change-of-basis as a Layer 5 gadget on the existing
  gf8 prover. This is the documented mechanism for the composition case; it is
  preferred there over a separate cross-bound gf16 proof when GF(2^16) is a
  small fraction of the circuit.

- Node-side possession proof (the possession half of requirement 2). The
  section 6.2 monitoring loop counts a node's chunks by the certificates it
  presents, but a certificate proves membership, not current possession of the
  bytes (it travels with the chunk and is copyable), so a node can inflate the
  health estimate by presenting certificates for chunks it no longer holds. A
  node-side possession proof closes this: a freshness challenge from the
  challenger (the ledger or a public beacon, never the owner, needing no FWK)
  over the actual stored bytes, verifier-efficient via setup-time homomorphic
  tags bound to `R` (Proof of Retrievability / Provable Data Possession in
  spirit). This is the integrity guarantee the healing loop's accuracy depends
  on. Out of v1.9.0 scope; the retriever-side half of requirement 2 is built
  (section 6.8), this node-side half is deferred. See the section 6.8 scope
  note for why a static Fiat-Shamir proof is insufficient (replayable). The wire
  plumbing is already reserved as of v1.9.0 (section 6.10): the PoR public
  parameters land in the descriptor's `por_params` metadata field
  (`flags.bit2`), and the per-chunk homomorphic tag lands in the chunk header's
  `possession_tag` field (`header_flags.bit0`). So delivering possession is a
  matter of populating reserved fields and adding the tag scheme, not a format
  change; a chunk header already carries everything a node needs (`bytes +
  certificate + tag`) once the scheme ships.

- Third-party sufficiency and live-possession proofs. The section 6.8
  self-check convinces the client ITSELF; proving to another party is heavier
  and unbuilt. Sufficiency ("I hold `k` distinct members of `R`") is a
  zero-knowledge statement over `k` membership witnesses, with the public/secret
  index choice as the distinctness-revelation knob (reveal indices to show
  distinctness, or prove distinctness in zero knowledge). Live possession ("I
  currently hold these bytes") is the same freshness-challenged Proof-of-
  Retrievability machinery as the node-side possession proof above: a static
  Fiat-Shamir proof is replayable (it proves possession at generation time, not
  validation time), so it needs an unpredictable challenge from the challenger
  (ledger or public beacon), never the owner. Trigger: a deployment that must
  prove its holdings to a third party or auditor, not only self-audit.

- Homomorphic-tag sublinear encoding verification. Verifying `C = G . M`
  WITHOUT the bulk data and sublinearly needs a linearly-homomorphic commitment:
  commit each chunk so `commit(C[i]) = G . commit(M)` holds by homomorphism,
  then check consistency over the small commitments. This is distinct from the
  hash-Merkle leaf (hashes are not linear, so `G . M` cannot be pushed through a
  plain digest) and would replace it for this purpose; it is the same machinery
  family as the section 6.8 possession tags. Trigger: a party that must verify
  encoding correctness sublinearly without holding the data.

- Active network policy enforcement (credentialed, ledger-compromise-
  resistant placement). Section 6.3 has the owner specify a node-attribute
  restriction and the ledger enforce placement by matching it against node
  attributes it already knows; section 6.5 lets the allowed-attribute set be
  secret for metadata confidentiality. Neither makes placement robust against
  a misbehaving node or a compromised ledger. Doing that requires: (a) node
  attributes carried as non-forgeable credentials (region attestations signed
  by an issuing authority) rather than self-asserted, so a node cannot lie
  about its type; (b) the policy committed and bound to `R` so any party, not
  only the original ledger, can re-check placement and an auditor can verify it
  after the fact; (c) the node proving its own eligibility ("I hold a
  credential whose attribute satisfies the policy bound to `R`," revealing
  neither attribute nor policy), which makes the node a prover, not just a
  verifier. This is the integrity counterpart to the confidentiality of 6.5
  and reuses the v1.8.0 attribute machinery, but the node-as-prover flow and
  the credential-issuance trust model are out of v1.9.0 scope. Trigger: a
  deployment whose placement policy must survive a wrong or hostile ledger,
  not merely an honest one.

- GF(2^16) Reed-Solomon for shard counts above 256. The GF(2^8) RS caps total
  shards at `n <= 256` (section 2.3), which sets a floor on chunk size for a
  given file and redundancy. A GF(2^16) RS raises the cap to `n <= 65536`, two
  orders of magnitude finer sharding, at the cost of 2 bytes per symbol and a
  larger generator matrix. Not built in v1.9.0: the matrix and Gaussian-
  elimination core (`erasure/matrix.*`) is already field-generic over GF(2^8)
  and GF(2^16), so the missing piece is mainly an `rs.*` variant that selects
  the GF(2^16) field and packs 2-byte symbols. Trigger: a use case needing
  more than 256 shards, or chunks finer than `file_size / 256` allows (small
  files split into many shards, or very high redundancy). RLNC already uses
  GF(2^16) for exactly the scale reason, so the field and most of the
  machinery exist; this is a packaging task, not new cryptography.
