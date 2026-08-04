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
Layer 5: circuits/ + parsers/      Reusable circuit building blocks + format parsers
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
  bristol (parsers/)                    Bristol Fashion boolean-circuit parser

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
  hash                                  SHAKE-128 / SHAKE-256 / SHA3-256  (libtalos_ichor)
  aes                                   AES-128 / AES-256 standard encrypt  (libtalos_ichor)
  grostl                                Grøstl-256 / Grøstl-512 (software + HW)  (libtalos_ichor)
  util                                  Secure zero, constant-time compare  (libtalos_ichor)
```

Since 1.10.1 the AES, SHAKE/SHA3, Grøstl, Hirose, CPU-dispatch, and secure-zero
primitives are supplied by **libtalos_ichor**, a shared layer-0 core extracted
from this codebase and vendored as a submodule under `third_party/`. ichor is
first-party Talos code derived from voleith's own forked primitives, not a
foreign third-party dependency: the two are a straight fork, so the `voleith_*`
primitive names are thin aliases over the identical `ichor_*` entry points and
no behavior changed at the swap. The `core/{aes,cpu,hash,hirose,util,grostl}.h`
headers are alias shims; `field.{c,h}` / `field16.{c,h}` / `prg.{c,h}` stay
voleith-side (field arithmetic and the AES-CTR PRG are voleith-specific). ichor
carries its own KAT and dudect timing evidence for the primitives it owns.

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

### A specialized third prover: native GF(2^16)

The two variants above are the general-purpose choice for any circuit. A third, specialized element-level prover carries one GF(2^16) element per VOLE slot (`proof/gf16_prover.c` / `gf16_verifier.c` / `gf16_circuit.c` / `gf16_proof.{c,h}`). It mirrors the GF(2^8) element-level structure and Fiat-Shamir construction (including the two-phase commit/respond split), with alpha16 subfield-embedding tables for lambda in {128, 192, 256}. It exists for the high-throughput network-coding statements whose symbols are naturally GF(2^16) elements, where a native wide-field prover verifies faster than the GF(2^8) tower equivalent; it is not a general-purpose replacement for the GF(2^8) building-block library. Its construction and the erasure-coding statements built on it (RLNC membership, the rank certificate, confidential RLNC, and the RS chunk membership certificate) are documented in [`docs/ERASURE_CODES_DESIGN.md`](ERASURE_CODES_DESIGN.md).

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

In the GF(2^8) variant, `assert_product(a, b, c)` is the soundness-critical constraint that anchors the S-box inversion. The prover MUST commit to `c = a · b` computed in GF(2^8); committing instead to some other value (even one the prover knows is correct in some other arithmetic) breaks soundness because the ZK hash check would become tautologically consistent. Concretely, the prover's degree-2 term for the PRODUCT constraint uses `v2 = embed(val_c)` (the committed value), never `embed(val_a · val_b)`; the latter would make the verifier's check pass regardless of whether `c = a · b`.

This is documented in the prover code and guarded by two tests in `tests/test_gf8_quicksilver.c`: an end-to-end check that a witness with `c != a · b` is rejected, and a forgery check (`test_assert_product_forgery`) that drives the verifier with such a witness through a test-only unchecked prover seam (`proof/gf8_prover_internal.h`), confirming the verifier rejects it even when the prover's upfront witness check is bypassed. The forgery test isolates the `embed(val_c)` invariant from the upfront rejection, so it fails if either guard regresses.

### Degree-d QuickSilver openings

An AND gate / `assert_product` is a degree-2 constraint: QuickSilver opens three coefficients `a_0, a_1, a_2` of the masked line, the verifier recomputes `a_0` and the proof transmits `a_1, a_2`. Some statements are naturally higher degree, so the opening count is generalized: a constraint of degree `d` opens `d+1` coefficients `a_0..a_d`, `a_0` is recomputed by the verifier, and `a_1..a_d` are transmitted. The opening count `d` sets `ellhat`, the size of the QuickSilver mask region (one mask block per opened degree), and the `a_tilde` serialization.

`d` is a *derived per-circuit* property: the prover and verifier each compute it as the maximum constraint degree in the circuit (`voleith_*_circuit_qs_degree`), and it is never transmitted. A circuit whose constraints are all degree 2 keeps `d = 2` and produces a proof byte-identical to the pre-generalization format, so the degree-2 path (AES, CMAC, KDF, Merkle, every shipped ring-signature module except the opener) is unchanged. The value is bounded at compile time by `VOLEITH_QS_D_MAX` (32), which sizes the fixed coefficient storage; it is a storage ceiling, not a wire-format constant.

The only shipped consumer above degree 2 is the designated-opener syndrome gadget: it opens at `idx_bits + 1` (the index-bit width, raised one by the strict-ascending less-than chain), which is 16 to 18 across the four shipped parameter sets (the less-than and syndrome constructions are in [`docs/CIRCUIT_DESIGN.md`](CIRCUIT_DESIGN.md), the V5 protocol in [`docs/RING_SIGNATURES_DESIGN.md`](RING_SIGNATURES_DESIGN.md), and the opener tag and KEM byte contract in the companion libtalos_syndrome, its `docs/DESIGN.md` §6). Soundness degrades only logarithmically in `d`: the opening-check error is `d / 2^lambda` (about 4 bits of the 2^-lambda margin at these degrees), while the batched-constraint term `~C / 2^lambda` dominates (the syndrome relation appends about `p` constraints, `log2(p) ~= 13.7`). The overall QuickSilver soundness error stays in the `~(C + d) / 2^lambda` class the library already accepts for its largest circuits (about 2^-114 at lambda128, 2^-242 at lambda256), so it is the constraint count, not the opening degree, that sets the margin. The shipped opener degrees (16 to 18) sit well below the `VOLEITH_QS_D_MAX` ceiling of 32.

---

## Bristol Fashion Circuit Parser

The library can ingest circuits described in **Bristol Fashion**, the boolean-circuit file format maintained by Nigel Smart's group and used as the standard comparison baseline across the MPC/ZK ecosystem (AES, DES, SHA-256, adders, comparators, multipliers, etc.). The parser lives in `parsers/bristol.{c,h}` and is a Layer 5 consumer of the bit-level circuit API: it reads a file (or in-memory buffer) and builds a `voleith_circuit_t` that feeds directly into `voleith_prove` / `voleith_verify`.

The parser targets the **bit-level** (GF(2)) API only. Bristol is a pure-boolean format; projecting onto GF(2^8) wires would defeat the point, so the GF(2^8) layer gets nothing from this work.

### Why a `parsers/` subdirectory

The parser is structurally a peer of `circuits/`, not a member of it: a `circuits/` building block constructs gates from C, whereas a parser constructs gates from an external file. Giving format parsers their own directory keeps that distinction clean and means a future parser (SIEVE IR, ABY's circuit format) lands as a sibling rather than as a structural rework. The parser depends only on `proof/circuit.h`; it does not touch `vole/`, the prover/verifier, or `circuits/`. CMake compiles it unconditionally into `voleith_core` with no new build option.

### The format

Bristol Fashion is three header lines, a blank line, then one line per gate:

```
<n_gates> <n_wires>
<n_input_values> <input_1_bits> <input_2_bits> ... <input_k_bits>
<n_output_values> <output_1_bits> <output_2_bits> ... <output_m_bits>

<gate_1>
...
```

Wires are numbered `0 .. n_wires-1`. The first `sum(input_*_bits)` wires are the inputs (value 1's bits first, then value 2's, etc.), the **last** `sum(output_*_bits)` wires are the outputs, and the interior wires are gate outputs in topological order. Each gate line is `<n_in> <n_out> <in1> [in2] <out> <gate_type>`. The supported gate types and their mapping onto the circuit API:

| Gate | n_in | n_out | Semantics             | Maps to                     |
|------|------|-------|-----------------------|-----------------------------|
| XOR  | 2    | 1     | out = a ⊕ b           | `voleith_circuit_add_xor`   |
| AND  | 2    | 1     | out = a · b           | `voleith_circuit_add_and`   |
| INV  | 1    | 1     | out = ¬a              | `voleith_circuit_add_not`   |
| EQ   | 1    | 1     | out = constant 0 or 1 | `voleith_circuit_add_const` |
| EQW  | 1    | 1     | out = a               | reuse the input wire's id   |

The `EQ` line's "input" field is the literal `0` or `1` constant, not a wire id, a format quirk noted in the parser. `EQW` (wire copy) adds no gate; it aliases the output wire id to the input's mapped circuit wire. `MAND` (multi-input AND) and any other gate type are **rejected** in v1 with a specific error; `MAND` is desugarable into a tree of binary ANDs but is added only when a real consumer needs it. The older pre-Fashion "Bristol Format" is detected by its different header arity and rejected with a distinct error.

### Witness / instance role assignment

Bristol has no witness-vs-instance distinction: all inputs are just "value 1 bits, value 2 bits, ...". The proof system requires the split, so the caller supplies a **per-input-value role array** (`voleith_bristol_config_t`) of `WITNESS` or `INSTANCE`, one entry per input value declared in the header. The parser validates that the array length matches the file's `n_input_values` (returning `VOLEITH_BRISTOL_ERR_ROLE_MISMATCH` otherwise) and allocates each input value's bits via `add_witness` or `add_instance` accordingly. For the canonical Bristol AES-128 circuit (two 128-bit input values, key and plaintext), a "prove I know the key" use case passes `{WITNESS, INSTANCE}`.

Bristol outputs are bare wires; the format has no `assert_zero` / `assert_equal` concept. The parser returns the output wire ids in a `voleith_bristol_parsed_t`, and the caller attaches whatever constraints the use case demands (e.g. `assert_equal` against expected-ciphertext constant bits for an AES-key-knowledge proof, or leave them unconstrained for free composition into a larger circuit).

### Parse result and ownership

```c
typedef struct {
    voleith_circuit_t *circuit;        /* parser-built, caller frees */
    wire_id  *input_wires;             /* flattened, file order */
    size_t    n_input_wires;
    wire_id  *output_wires;            /* flattened, file order */
    size_t    n_output_wires;
    size_t   *input_value_sizes;       /* bit-counts per input value */
    size_t    n_input_values;
    size_t   *output_value_sizes;      /* bit-counts per output value */
    size_t    n_output_values;
} voleith_bristol_parsed_t;
```

`voleith_bristol_parse_file` and `voleith_bristol_parse_buffer` return 0 on success and a negative `voleith_bristol_error_t` on failure. On success the caller owns the circuit and the four arrays; `voleith_bristol_parsed_free` releases them all and is safe to call on a zero-initialised struct (so the standard cleanup pattern is `voleith_bristol_parsed_t p = {0};` plus an unconditional free on every exit path). On any failure the parser frees all partial allocations, including the partially-built circuit, and zeroes `*out`.

**Callers must validate the parsed shape before indexing the returned arrays or sizing fixed witness/instance buffers.** The parser makes no assumptions about what the circuit means: a file that does not match the caller's expected input/output layout would otherwise drive an out-of-bounds read in caller code. The AES-128 example demonstrates the guard (check `n_input_values == 2`, both `input_value_sizes` equal 128, and `n_output_wires >= 128` before proceeding).

### Algorithm and validation

The parser is single-pass. A flat `wire_id` array of size `n_wires` maps each dense Bristol wire id to the circuit wire id returned by the builder (no hash table needed). Inputs are allocated from the header; each gate line then looks up its input mappings, dispatches to the builder, and records the output mapping. Bristol Fashion files are topologically ordered by construction, so the parser does **not** sort: it instead enforces the format's invariants and rejects any file that violates them. For every gate it checks that each input wire id is strictly less than the output wire id (topological order), that no input wire is used before it is defined, and that no output wire id is reassigned (no SSA violation). After the gate loop it confirms that exactly `n_wires` entries were populated. The error codes (`VOLEITH_BRISTOL_ERR_IO`, `_HEADER`, `_ROLE_MISMATCH`, `_GATE_SYNTAX`, `_UNKNOWN_GATE`, `_WIRE_ORDER`, `_WIRE_REDEF`, `_WIRE_COUNT`, `_ALLOC`, `_OLD_FORMAT`) each have a single well-defined cause; there are no assertions and every error path propagates a code.

### Test corpus and cross-validation

A small set of canonical Bristol Fashion circuits is vendored under `tests/data/bristol/` (attribution and the upstream source in that directory's `README.md`):

| File           | Circuit                                                  |
|----------------|----------------------------------------------------------|
| `aes_128.txt`  | AES-128 (Boyar-Peralta S-box, 6,400 AND gates)           |
| `aes_256.txt`  | AES-256 (Boyar-Peralta S-box, 8,832 AND gates)           |
| `neg64.txt`    | 64-bit two's-complement negation                         |
| `mult2_64.txt` | 64×64 → 128-bit unsigned multiply                        |

These give independent cross-validation of the parser against real-world circuits. The AES files in this corpus encode 128-bit blocks with reversed byte order (wire 0 carries bit 0 of the last byte), while the arithmetic circuits (`neg64`, `mult2_64`) use the plain little-endian convention (wire 0 = LSB); the test and example code account for both. Note the AES AND-gate counts differ from this library's hand-built circuits (7,200 for AES-128, 9,936 for AES-256): the Bristol circuits use the Boyar-Peralta 32-AND S-box rather than the Canright 36-AND build, and that expected ratio is itself a sanity check.

`tests/test_bristol_parser.c` exercises: a synthetic 4-gate round-trip (XOR/AND/INV/EQW) evaluated against hand-computed outputs, a per-gate sweep, one minimal malformed buffer per error code, a role-count-mismatch rejection, AES-128 and AES-256 AND-gate-count and FIPS-197 evaluation-parity checks, the `neg64` and `mult2_64` arithmetic circuits over their little-endian convention, and a full `voleith_prove` / `voleith_verify` round-trip on the parsed AES-128 circuit. `examples/example_bristol_aes128.c` is the runnable form of that last test: it parses the vendored AES-128 circuit, marks the key as witness and the plaintext as instance, constrains each output wire to the expected FIPS-197 ciphertext bit via `add_const`, and proves/verifies under FAEST-EM-128f.

### Non-goals (v1)

Writing Bristol files (no consumer is asking), `MAND` desugaring, streaming/partial parsing (whole-file in-memory only; the largest standard Bristol circuit is well under 100 MB), GF(2^8) projection, and support for the older pre-Fashion format beyond detect-and-reject.

---

## Shipshape Native GF(2^8) Circuit Format

Where Bristol is an external boolean format projected onto the bit-level API, **Shipshape** (`.ship`) is a native text format for the **GF(2^8) element-level** circuit model. It is the byte-oriented counterpart to the Bristol path: `parsers/shipshape.{c,h}` reads a file or buffer and builds a `voleith_gf8_circuit_t`, `parsers/shipshape_witness.{c,h}` generates the full witness from the external input, and the result feeds `voleith_gf8_prove_v2` / `voleith_gf8_verify_v2`.

**The normative specification is [`docs/specs/SHIPSHAPE_SPEC.md`](specs/SHIPSHAPE_SPEC.md)**: the ISA and type system, the grammar and lexical rules, the resource bounds, the instruction reference, the witness and instance layout (§2.4), the Tier 2a registry table (§7), and the canonical fingerprint serialization all live there and are the single source of truth. This section records *why* the format exists and the design decisions behind it; it intentionally does not restate normative content, and where the two disagree the spec wins.

### Why a native format, not Bristol

Bristol is pure boolean, with no witness/instance distinction and no notion of a cryptographic primitive. The GF(2^8) prover's whole advantage is that an AES S-box is one inversion witness rather than 36 AND gates, so a format that forces everything through GF(2) bits would throw that away. Shipshape is therefore element-level (one wire is one GF(2^8) byte), self-describing (a file declares its own `WITNESS` / `INSTANCE` / `CONST` wires, so no caller-supplied role array is needed), and primitive-aware (it can name AES, CMAC, and Grøstl by reference instead of open-coding them). The two parsers are deliberate siblings under `parsers/`: same structural role, different circuit model and different trust model.

### The pipeline: parse, generate witness, prove

A Bristol caller owns witness construction; a Shipshape circuit can describe enough that the witness is *derived*, not hand-built. The split is the two-trust-level view of the witness array (spec §2.4): the **external input** is only the file-declared `WITNESS` bytes (keys, messages, tree nodes), while the **full witness array** the prover consumes also includes gadget-internal wires, in Tier 1, the `INV` inverse outputs. The generic Tier 1 evaluator in `shipshape_witness.c` walks the lowered circuit once and completes the full array, computing each internal inverse as the field inverse of its source wire. Crucially this is a generic circuit evaluator, not per-primitive code: it reproduces the hand-written `circuits/*_gf8_build_witness` output byte-for-byte for AES, CMAC, and Grøstl, which is what makes the format usable without shipping a bespoke witness builder per circuit. The fail-closed witness-backend dispatch interface and the Tier 2a fast-path (now implemented, see "Tier 2a witness dispatch" below) follow the registry rules in [`SHIPSHAPE_SPEC.md`](specs/SHIPSHAPE_SPEC.md) §2.5 and §7.

### Tier 2a hash-pinned crypto registry

The registry exists because of a soundness channel, not convenience. A wrong constant buried inside an open-coded AES body is *not AES*, and a counterparty verifying such a circuit would silently accept a proof of the wrong statement. Shipshape closes that channel by making `stdlib/crypto/*` calls by-reference only: the parser substitutes the registry-canonical body verbatim, so two conformant parsers agree byte-for-byte on what a Tier 2a call means, and the per-entry body hash lets a witness backend dispatch safely. The bundled `crypto-v1` set is frozen and regenerated from the same C builders the hand-written path uses (`tools/shipshape_registry_freeze`, gated in CI), so the parser's lowering of a registry call is byte-identical to calling the builder directly. The structural namespace (`stdlib/structural/*`) is empty in v1, which is forced rather than chosen (the structural signatures need a parameter type the v1 set does not have), so Merkle and similar compositions are written as `user/*` subcircuits, shipped as example text rather than bundled content.

### Hash-parametric crypto extensions (crypto-v2)

**The problem crypto-v2 solves.**  Crypto-v1 left the structural constructions (Merkle path, indexed-Merkle non-membership, ring-signature membership) to `user/*` hand-wiring.  That places the security-critical structural glue (leaf/inode domain separation, the DM wrap, the MMO leaf chain, the secret-direction MUX, the `assert_lt` comparator, direction-bit booleanity) in the file author's hands.  A wrong Merkle node hash or a missing domain separation is a SILENT soundness compromise, not a parameter choice: the verifier accepts a proof of the wrong statement, with no error.  This is exactly the failure mode hash-pinning exists to prevent, and the same argument that makes the AES kernel hash-pinned Tier 2a.  Deferring these constructions to `user/*` while pinning AES primitives was logically inconsistent.

**The decision.**  Promote the structural constructions to hash-pinned Tier 2a "crypto extensions" that inline the existing, reviewed C vt builders (`circuits/merkle_vt_gf8_circuit.c`, `circuits/indexed_merkle_vt_gf8_circuit.c`, `circuits/ring_sig_v1_gf8_circuit.c`) by reference, so a `.ship` file physically cannot emit a different construction.  A conformant parser substitutes the registry-canonical gate stream verbatim, and the per-entry body hash guarantees witness-backend dispatch safety on the same basis as the crypto-v1 primitives.

**Why hash-PARAMETRIC rather than monomorphized.**  The node-hash type is a compile-time parameter chosen by the file author from a closed, extensible set (aes_dm, aes_cmac_128, Grøstl-256, Grøstl-256-T27, Grøstl-512, Grøstl-512-T59, Hirose-fixed32, Hirose-variable, plus the fixed-input Grøstl-256-fixed and Grøstl-512-fixed added in 1.7.0; rijndael_256, whirlpool planned).  A monomorphized table would require a new entry per hash, growing the table quadratically in the (construction, hash) product and forcing downstream tooling to enumerate an ever-expanding list.  The parametric design adds one new hash type as a C vt plus one type-table entry, leaving the constructions and the Tier 1 opcode set untouched.  The Tier 1 opcode set stays closed: no new opcodes ship for crypto-v2.

**Why a bracket selector for the type (not a leading named argument).**  The node-hash selector is a compile-time TYPE, not a runtime value: it determines which gate stream the parser inlines, drives a different CI-frozen body hash, and participates in the circuit fingerprint.  A bracket syntax (`path[aes_dm](...)`) makes that boundary visible at every layer (grammar, type-checker, dispatch key) while keeping the wire argument list homogeneous, so integer-length inference and constraint checking are unaffected.  A positional leading argument would be parsed as a wire, conflating type dispatch with value routing.  The normative grammar and dispatch rules are in SHIPSHAPE_SPEC §7.7.

**Phase 1 scope: secret-direction constructions only.**  Crypto-v2 phase 1 ships the secret-direction variants (hidden leaf index) that enable the ring-signature and anonymous-membership use cases.  Public-direction path variants are unchanged `user/*` pattern (the path directions are public constants; there is no structural glue a registry entry could add over a well-written hand-wired subcircuit).  The immediate-constant parameter mechanism needed for `kdf/*` and direct-Hirose entries remains deferred to crypto-v2 phase 2 for the same reason those entries were deferred in crypto-v1 (spec §7.5, §7.6).

**Identity, dispatch, and fail-closed authentication.**  The body hash keys on (construction name, node-hash type, inferred integer params), frozen over the full type-x-param grid and CI-checked in the same harness as the crypto-v1 grid.  Witness-backend dispatch keys on the region name `stdlib/crypto/<name>[<type>]` and the registry version.  Authentication is structural: the crypto-v2 backend and the crypto-v2 body ship together, and a mismatch between backend version and parser version yields an invalid proof, never a verifier false-accept.  Dispatch is prover-side and fail-closed: a wrong backend is caught at prove time, not verify time.

For the normative format, grammar, entry table, and conformance requirements, see SHIPSHAPE_SPEC §7.7 ("crypto-v2 registry: hash-parametric crypto extensions (secret-direction)").

### Format versioning: semver on the format axis

The three version axes stay independent: the **format version** (`.shipshape` line, the Tier 1 ISA), the **stdlib version** (`crypto-vN`, the Tier 2a registry), and the editorial spec revision. The format axis is semver `MAJOR.MINOR`. A new Tier 1 opcode that leaves every prior-minor file valid and lowering to a byte-identical fingerprint is an *additive MINOR* bump, not a new major: existing files are unaffected (a bare `MAJOR` reads as `MAJOR.0`), and the frozen registry bodies and all KATs are untouched because the version header is not hashed. Removing or renaming an opcode, or changing any lowering, cost, or semantics, is a MAJOR bump with a successor spec. The scale-by-instance gate ships this way as `SCALE_INSTANCE`, the first `.shipshape 1.1` opcode: a file must declare `1.1` to use it (declaring `1.0` yields `ERR_OPCODE_VERSION`, distinct from `ERR_GATE` for a genuinely unknown opcode). This is what let the V6 gate reach the `.ship` toolchain at minor cost without reopening the frozen crypto registry. Normative rules in SHIPSHAPE_SPEC §1.4.

### Tier 2a witness dispatch (opt-in prover-side fast path)

The witness-backend dispatch interface (spec §2.5, §7) is implemented as an opt-in speed layer over the generic Tier 1 evaluator. A registered backend fills a registry region's internal inverse witnesses by running the primitive natively (the same `circuits/*_build_witness` the hand-written path uses) instead of the per-wire brute-force `voleith_gf8_inv` scan, and the single forward pass skips the inverse for the slots a backend covers. With no backend registered the generic evaluator carries every circuit unchanged: the layer is never a correctness requirement, only a speed-up where the dominant cost is a few large primitive calls.

It is prover-side and fail-closed (spec §2.5). A backend MUST reproduce the generic witness byte-for-byte, a property pinned per entry by the equivalence tests; a wrong backend can at worst produce a wrong witness, caught at witness-gen self-check or refused by the prover, never a verifier false-accept. Backends ship for the crypto-v1 FIXED (AES) and PARAMETRIC (CMAC, Grøstl) entries and the three crypto-v2 secret-direction constructions, each keyed on its region name (`stdlib/crypto/<name>[<type>]` for the constructions). The frozen backend interface and the interleaved forward-pass skip are pinned by the witness-equivalence tests.

### Circuit identity and proof binding

Shipshape adds no new identity machinery. A circuit's identity is the existing 16-byte `voleith_gf8_circuit_fingerprint` (`proof/gf8_circuit_fingerprint.{c,h}`, the same hash the 1.3.0 proof metadata header already binds to). The spec's conformance requirement is that any two conformant parsers lower a file to a byte-identical wire and constraint table, hence the same fingerprint; the cross-parser corpus (`tests/test_shipshape_conformance.c`) is the release gate for that property, and any disagreement is a release-blocker. Because identity is the gf8 fingerprint, a proof's metadata header binds to its `.ship` source with no extra work (see "Proof Metadata Header" below).

### Hardening and validation

The parser consumes attacker-controlled bytes (spec §2.7 trust boundary): no `assert` on input paths under `-DNDEBUG`, two-argument `calloc` for every count-times-size allocation, growth `realloc` guarded against `size_t` overflow, incremental wire/gate budgets checked before each allocation grows, bounded inline depth, and first-error-stop with no recovery. A libFuzzer harness (`fuzz/`, also covering the Bristol parser) runs in CI on parser-touching commits. The equivalence suites pin the two correctness claims that matter: each registry entry lowers to its C builder byte-for-byte (`test_shipshape_registry_equiv` / `_grid`), and the generic witness evaluator reproduces the C builders' witnesses and round-trips through prove/verify (`test_shipshape_witness` / `_witness_proof`).

### Non-goals (v1) and deferrals

Writing `.ship` files (the format is read-only here; producers are upstream tools), streaming parsing (whole-file in-memory, bounded by `MAX_FILE_BYTES`), and a non-GF(2^8) field instance (the IR is field-parametric but only GF(2^8) is specified). The `kdf/*` and direct-Hirose registry entries remain deferred to `crypto-v2` phase 2 (spec §7.5, §7.6): their immediate-constant parameters are not expressible at a v1 call site, and applications compose them from `cmac/*` at identical cost in the meantime.

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

**Security note (`VOLEITH_LEGACY_VERIFY`).** The step-2 legacy fallback does
not run the step-1 identity check, so it does not bind `CIRCUIT_FP` /
`PARAMS_FP`. A deployment that accepts v1 headered proofs should build with
`-DVOLEITH_LEGACY_VERIFY=OFF`, so that stripping the 48-byte header from a v1
proof cannot route it through the identity-unbound legacy path. The option is
`ON` by default only for backward compatibility with pre-header proofs; it is
security-relevant and is flagged as such in the README and the CMake option
help string.

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

The per-circuit and per-hash construction design rationale (the AES S-box choice, the AES-CMAC KDF, the Merkle path and indexed-non-membership circuits, the DM/CMAC, Grøstl, and Hirose node-hash families, and the generic `voleith_node_hash_vt` bridge) lives in [`docs/CIRCUIT_DESIGN.md`](CIRCUIT_DESIGN.md). The library-level invariants that apply across all circuits follow below.

### Constant-time field arithmetic and AES

All field-multiplication paths in `core/field.c` are constant-time: the CLMUL (x86_64) and PMULL (ARMv8) hardware paths by ISA definition, and the software fallback by construction (bitmask-conditional XOR routed through an inline-asm optimiser barrier). No variable-time table-lookup or branch-on-secret path ships in the library; the previous opt-in `-DVOLEITH_ALLOW_VARIABLE_TIME_FIELD` gate was removed in 1.2.0.

The software barrier (`ct_barrier_u64`) is a GCC/Clang inline-asm construct, so the constant-time scalar field path is available only under GCC or Clang: `core/field_scalar.c` raises `#error` on any other compiler (e.g. MSVC) rather than silently emitting a variable-time multiply. The library's constant-time guarantees therefore apply to GCC/Clang targets only; supporting another toolchain requires providing an equivalent optimiser barrier first.

AES follows the same design. A constant-time bitsliced backend (ichor's `src/aes_ct64.c`) is always built as the universal fallback; AES-NI (x86_64) and ARMv8 Crypto Extension (aarch64) hardware paths are constant-time by ISA definition. No variable-time table-lookup AES path ships; the previous opt-in `-DVOLEITH_ALLOW_VARIABLE_TIME_AES` gate was removed in 1.2.0.

The constant-time discipline is verified two ways. Structurally, by source review (no secret-dependent branches, no secret-indexed memory access, all conditional XORs routed through bitmask AND with the `ct_barrier_u64` optimiser barrier). Empirically, by a dudect-style timing harness (`tools/dudect/`) that runs Welch's t-test on the software field-multiplication paths, `voleith_byte_combine`, the GF(2^8) Grøstl witness builder (whose `voleith_gf8_inv` is a fixed Fermat addition chain, hence data-independent; the prior brute-force inverse scan was not), and the erasure / RS secret-input paths, under fix-vs-fix input distributions on real hardware. Since 1.10.1 the primitive AES and Grøstl timing targets moved to libtalos_ichor with the primitives themselves; ichor carries their evidence in its own dudect trail. Release-gate evidence files for the voleith-side targets live under `docs/dudect-runs/`, currently covering x86_64 (Sandy Bridge and Gracemont) and aarch64 (Apple M1).

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

The lower-level `voleith_vc_params_init` (the exported GGM / BAVC parameter initializer) mirrors the same `w_grind` and derived-depth bounds: it rejects `w_grind < 0`, `w_grind >= λ`, and a computed per-vector depth `k > VOLEITH_MAX_K`, computing `k` before any shift uses it. A caller that constructs vc params directly therefore cannot drive a negative shift (`1 << (k - 1)` with `k <= 0`) or an oversized GGM-tree allocation, independent of the higher-level `voleith_params_validate`.

### Circuit validation at the API boundary

The `voleith_circuit_t` (and its GF(2^8) twin `voleith_gf8_circuit_t`) is the second caller-supplied input that flows into every prove / verify entry point, and the same boundary-rejection discipline applies. Two checks run before any cryptographic work:

1. **Construction-completeness check** via `voleith_circuit_ok` / `voleith_gf8_circuit_ok`. The builder functions (`add_xor`, `add_and`, `add_mul`, `assert_zero`, `assert_product`, etc.) cannot signal OOM through their return value, so on `realloc` failure they set an internal `alloc_ok` flag and continue. A circuit with silently dropped wires or constraints would be a soundness break (the application's assertions are no longer enforced), so prove / verify reject when this flag is clear.

2. **Reference-bounds check** via `voleith_circuit_validate` / `voleith_gf8_circuit_validate`. A one-shot O(n_wires + n_constraints) pass that enforces the topological-order invariant on gate inputs (for every gate at index *i*, its input wire ids are strictly less than *i*) and bounds every constraint's referenced wire ids against `n_wires`. Catches malformed circuits before they OOB-read wire / tag buffers in the QS hot loop.

Both checks run at the public boundary (`voleith_prove_commit`, `voleith_verify_reconstruct`, and the GF(2^8) equivalents); the one-shot `voleith_prove` / `voleith_verify` flow through them. The validators are also public so callers that ever accept circuits from a less-trusted source (a future deserialize path, for instance) can run the same check up front. Neither check imposes any per-gate cost in the QS hot loop.

As additional defense in depth, the GF(2^8) QuickSilver verifier (`voleith_gf8_qs_verify`) does not rely solely on the boundary validator: it re-checks every wire and constraint reference against `n_wires` at the top of the routine and sizes its `bit_keys` / `Q_T` buffers with the overflow-checked two-argument `calloc(nmemb, size)` form. The verifier is the surface most exposed to attacker-influenced inputs, so it stays memory-safe (no OOB read, no `size_t` wrap on a 32-bit target) even if reached with a circuit that bypassed the boundary validators.

### Witness-correctness rejection at the prover

Both the bit-level prover (`voleith_qs_prove`) and the GF(2^8) prover (`voleith_gf8_qs_prove`) reject an invalid witness *upfront*, before publishing any QuickSilver coefficients. The check is `voleith_circuit_eval(circuit, witness, instance, bits) != 1`; on violation, the prover returns an error rather than producing a proof that the verifier would later catch.

This upfront rejection is convenient but also hides the verifier-side soundness check from black-box tests (the honest prover never emits a proof for a bad witness). To regression-test the verifier directly, a test-only seam (`proof/gf8_prover_internal.h`: `voleith_gf8_qs_prove_unchecked` / `voleith_gf8_qs_compute_d_unchecked`) proceeds when `voleith_gf8_circuit_eval` returns 0 (constraint violated, structure valid) while still rejecting structural errors. It has external linkage but is absent from the public headers and is never called by production code; the public entry points are thin wrappers that pass `reject_invalid = 1`.

**Why upfront rejection.** The naive design lets the prover produce a proof for an invalid witness and relies on the verifier to catch it via the QuickSilver `a0_tilde` check. This is sound (the verifier does catch it) but operationally awkward: a buggy caller cannot distinguish "my witness is wrong" from "my proof was tampered with in transit." Upfront rejection makes prover-side bugs fail fast.

The GF(2^8) prover has done upfront rejection from the start (the `assert_product` constraints are checked during witness evaluation). The bit-level prover was brought to the same discipline so that prover-side bugs surface immediately rather than as opaque downstream verifier rejections.

### Memory hygiene: secure-zero discipline

All contexts holding key material, VOLE correlations, witness data, or transient cryptographic state are zeroed on free using `voleith_secure_zero()` (backed by `explicit_bzero` on Linux/BSD, `memset_s` on macOS, and a volatile-pointer loop on any other platform; macOS does not ship `explicit_bzero`). This applies to:

| Location | Why |
|----------|-----|
| Expanded AES round keys (ichor's `src/aes.c`) | Key material is sensitive even after use; cold-boot and DMA attacks can extract it from process memory. |
| Keccak sponge state (ichor's `src/hash.c`) | Sponge state contains absorbed input including possibly secret material. |
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

The standard-eval AES used by the PRG and by test code is either the hardware AES-NI / ARMv8 backend or the constant-time bitsliced backend (ichor's `src/aes_ct64.c`). Neither is accessible to the proof circuit's prover or verifier.

### Soundness-critical paths: implemented exactly per spec

The QuickSilver multiplication check in `proof/prover.c` and `proof/gf8_prover.c` is the central soundness mechanism. It is implemented exactly per the FAEST v2.0 specification with no optimisations that deviate from the spec. The same discipline applies to:

- The VOLEHash construction (`proof/vole_hash.c`, FAEST Figure 4.4).
- The ConvertToVOLE algorithm (`vole/convert.c`, FAEST Figure 5.2).
- The Fiat-Shamir challenge derivation order and transcript composition.

Performance optimisations are applied only to operations that do not affect soundness: PRG block batching, GF(2^k) CLMUL / PMULL acceleration, AES-NI and ARMv8 Crypto Extension dispatch. Anything that touches the multiplication check, the VOLEHash, or the challenge derivation is left exactly as the spec dictates.

---

## Ring Signatures

The library's ring-signature capabilities (the RSv1 anonymous-membership baseline with optional revocation, the composable V2 / V3 / V4 superset shipped in 1.8.0: linkable nullifier, hidden-attribute predicates, claimable commitment, and the V6 forward-secure key-evolution module shipped in 1.10.0) are documented in [`docs/RING_SIGNATURES_DESIGN.md`](RING_SIGNATURES_DESIGN.md). They compose the OWF leaf, secret-dir Merkle path, and indexed non-membership circuits described in [`docs/CIRCUIT_DESIGN.md`](CIRCUIT_DESIGN.md) over the GF(2^8) proof stack. V6 adds a per-identity epoch tree whose in-circuit path uses public directions (the bits of a public epoch `t`), verified through the free scale-by-instance gate so one circuit fingerprint covers every epoch; the GGM key schedule that gives the forward-security erasure boundary stays out of circuit.

---

## Runtime Hardware Dispatch (Single-Binary Fat Builds)

One library binary serves every supported host. At first use, each of three independent dispatch domains (AES, GF(2^k) field multiplication, Grøstl compression) probes the running CPU and routes subsequent calls through a function-pointer table to the highest-priority backend whose required instruction-set features are present. There is no per-host build, no per-CPU library variant, and no caller-visible API change between hardware and software paths.

Since 1.10.1 the AES and Grøstl dispatch domains (and the shared CPU-feature probe) are owned by **libtalos_ichor**; the `voleith_aes_*` / `voleith_grostl*` forwarders below are alias shims over the identical `ichor_*` dispatchers, so the description holds unchanged from the consumer's view. The GF(2^k) **field** dispatch domain stays voleith-side (`core/field.c`, `field_dispatch.h`), since field arithmetic is voleith-specific.

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

Since 1.10.1 `core/cpu.h` is an alias shim over `<ichor/cpu.h>`: `voleith_cpu_features()` forwards to `ichor_cpu_features()` and the `VOLEITH_CPU_*` flag macros alias `ICHOR_CPU_*` 1:1. The probe returns a stable `unsigned` bitmask of feature flags (`VOLEITH_CPU_AES_NI`, `VOLEITH_CPU_CLMUL`, `VOLEITH_CPU_SSE41`, `VOLEITH_CPU_SSSE3`, `VOLEITH_CPU_ARMV8_AES`, `VOLEITH_CPU_PMULL`) and is implemented per-architecture in ichor's `src/cpu_x86.c` (CPUID-based), `src/cpu_aarch64.c` (`getauxval(AT_HWCAP)`-based), or `src/cpu_generic.c` (returns zero on unknown architectures). Exactly one of those translation units is compiled for any given target.

The bitmask is computed on the first call via a compare-and-swap guard, cached in an atomic, and returned by all subsequent calls with a single acquire load. Bit assignments are stable across library versions (bits 0-15 for x86_64 features, 16-31 for aarch64 features), so consumers may persist or compare masks across builds.

### Dispatch tables and atomic init

Each domain follows the same shape. Since 1.10.1 the GF(2^k) field-multiply domain is the one that stays voleith-side, so it illustrates the pattern:

```
core/field.c            Public forwarders + voleith_field_dispatch_init().
                        Holds _Atomic(const voleith_field_ops_t *) voleith_field_ops.
core/field_dispatch.h   Internal ops-table type, extern declarations for each
                        backend's ops, declaration of voleith_field_ops.
core/field_clmul.c      x86_64 CLMUL backend (compiled iff VOLEITH_HAVE_CLMUL).
core/field_pmull.c      aarch64 PMULL backend (compiled iff VOLEITH_HAVE_PMULL).
core/field_scalar.c     Portable constant-time scalar backend (always compiled).
```

`voleith_field_dispatch_init()` reads the feature bitmask, walks the compiled-in backends in priority order, picks the first one whose feature bits are present, and publishes the chosen ops table with a release store + CAS so concurrent first-callers converge on the same selection. The AES and Grøstl domains follow the identical pattern inside libtalos_ichor (`src/aes.c` + `src/aes_dispatch.h` over the `aes_aesni` / `aes_armv8` / `aes_ct64` backends; `src/grostl.c` + `src/grostl_dispatch.h`); voleith's `voleith_aes_*` / `voleith_grostl*` forwarders are alias shims over ichor's dispatchers.

### Compile-time gating and per-TU instruction flags

Backend translation units that need ISA-specific intrinsics (`-maes -mssse3` for AES-NI, `-mpclmul -msse4.1` for CLMUL, `-march=armv8-a+crypto` for ARMv8 Crypto and PMULL) compile with those flags scoped to the file via `set_source_files_properties(... COMPILE_FLAGS ...)`. The flags do not propagate to any other translation unit, so consumers do not need to compile their own code with `-maes` and the library does not accidentally emit AES-NI in unrelated functions.

CMake probes the toolchain for each instruction set at configure time. If a probe succeeds, the corresponding `VOLEITH_HAVE_*` macro is defined as a public compile definition on the library target; the backend TU's contents are then enabled by an `#ifdef` at the file top. If the probe fails (older toolchain, missing intrinsics header), the TU compiles to an empty object and the dispatcher falls through to the next backend in priority order.

Since 1.10.1 this gating is split by owner. The AES-NI / ARMv8 (and Grøstl) backends are gated inside libtalos_ichor by `ICHOR_HAVE_AES_NI` / `ICHOR_HAVE_ARMV8_AES`, which voleith drives by forwarding its `VOLEITH_AES_NI` / `VOLEITH_ARMV8_AES` lean-build options to ichor's sub-build (`ICHOR_AES_NI` / `ICHOR_ARMV8_AES`). The CLMUL / PMULL field backends stay voleith-side under `VOLEITH_HAVE_CLMUL` / `VOLEITH_HAVE_PMULL`. The mechanism is identical on both sides.

### Lean-build opt-outs

Operators who want to strip the library to the smallest possible footprint, or who target a deployment that will never see hardware acceleration, can disable any backend at configure time:

```
-DVOLEITH_AES_NI=OFF       # omit ichor's src/aes_aesni.c (forwarded to ICHOR_AES_NI)
-DVOLEITH_ARMV8_AES=OFF    # omit ichor's src/aes_armv8.c (forwarded to ICHOR_ARMV8_AES)
-DVOLEITH_CLMUL=OFF        # omit core/field_clmul.c
-DVOLEITH_PMULL=OFF        # omit core/field_pmull.c
```

The portable bitsliced AES backend (`aes_ct64`) and the constant-time scalar field backend are always compiled; they are the unconditional floor of the dispatch table. A lean build that omits every hardware backend produces a fully functional binary that runs the portable paths on every host.

### Lean-build mismatch notice

When the field dispatch init selects the scalar fallback because a hardware backend was *opted out at compile time* on a CPU that *does* support the corresponding ISA, it emits a one-line notice to stderr the first time it runs:

```
voleith: notice: host CPU has CLMUL but the clmul backend was not compiled
in; running on scalar fallback. Rebuild with -DVOLEITH_CLMUL=ON.
Suppress with VOLEITH_QUIET=1.
```

An analogous notice exists for PMULL. The notice is fired through a once-guard so it appears at most once per process per domain. It is intended as a misconfiguration backstop: a lean-build artefact accidentally shipped to hardware-capable production should be loud enough about the performance loss that operators notice before users do. Setting `VOLEITH_QUIET=1` in the environment suppresses every variant of the notice (useful in test harnesses that deliberately exercise the fallback).

This lazy field notice (`core/field.c`) covers the one dispatch domain that stays voleith-side. Since 1.10.1 the AES and Grøstl backends moved to libtalos_ichor, which does no I/O and reads no environment variable: it exposes backend health only through its query API (`<ichor/backend.h>`: `ichor_backend_report`, `ichor_aes_backend_health`, `ichor_grostl_backend_health`, returning `ICHOR_BACKEND_FALLBACK` when the host has an accelerated backend that was not compiled in). voleith preserves its pre-1.10.1 operator-facing behavior by turning that verdict back into the same one-shot stderr notice: the internal `voleith_backend_notice()` (`core/backend_notice.c`) queries ichor's AES and Grøstl health once per process and prints the matching notice, choosing the ISA / rebuild-flag wording from the host feature bits (ichor's Grøstl hardware backend rides the same `VOLEITH_AES_NI` / `VOLEITH_ARMV8_AES` build options as AES). It is fired from the public proof entry points (`voleith_{,gf8_}prove_commit` / `voleith_{,gf8_}verify_reconstruct`), honours `VOLEITH_QUIET`, and is not part of the public API. The notice behavior is therefore unchanged for consumers across the migration, keeping 1.10.1 a pure patch; a future release may instead route all three domains through ichor's query API for one report, but that would drop the stderr / `VOLEITH_QUIET` contract and so is a later, minor-versioned change.

A run on a host that genuinely lacks the hardware (e.g., a generic x86_64 VM without AES-NI) produces no notice: the bitsliced backend is the correct, only available choice in that case.

### Backend override for testing

Since 1.10.1 backend forcing is owned by libtalos_ichor: `ICHOR_FORCE_BACKEND` is a comma-separated `domain:value` list parsed once during the first call to `ichor_cpu_features()`, the same probe that backs `voleith_cpu_features()`. It has two domains, `aes` and `clmul`; the voleith-side field and Grøstl domains have no token of their own and instead follow the masked feature bits. Recognised values:

```
aes:aesni      aes:armv8      aes:bitsliced
clmul:pclmul   clmul:pmull    clmul:scalar
```

The parser strips the corresponding feature bits from the cached CPU-feature mask so subsequent dispatch-init calls route to a lower-priority backend. `aes:bitsliced` clears the AES-NI / ARMv8 bits, forcing both the AES cipher and Grøstl (Grøstl rides the AES S-box backend) onto software; `clmul:scalar` clears the CLMUL / PMULL bits, forcing voleith's GF(2^k) field multiply onto its constant-time scalar backend. A malformed pair, an unknown domain/value, or a backend the host lacks is silently ignored (the mask is left as probed for that token); the parser does no I/O and never aborts. Forcing the scalar/bitsliced/software path on a hardware-capable host is the supported A/B-benchmarking mode.

The parser (and its `getenv`) compiles in only under `ICHOR_ENABLE_FORCE_BACKEND`, which voleith's build enables for test / backend-sweep / dudect builds and leaves off for a release build, so a shipped consumer cannot reach it. The override is not part of the supported public API; production deployments should not set it. Its sole purpose is the test profile described in the next subsection.

### Constant-time guarantee preserved across backends

Every compiled-in backend is constant-time:

- AES-NI and ARMv8 Crypto use hardware AES instructions whose latency is data-independent on every architecturally compliant implementation.
- The portable AES backend is bitsliced (`aes_ct64`); no S-box table lookup.
- The CLMUL and PMULL field backends use the corresponding carry-less multiply instruction (data-independent on every architecturally compliant implementation).
- The scalar field backend is constant-time scalar code (no secret-indexed memory access, no secret-dependent branches).
- Grøstl AES-NI / ARMv8 backends drive the AES round instructions over Grøstl's 64-byte / 128-byte state; the software backend is straight-line table-free Grøstl.

The dispatch decision itself is made on the CPU feature bitmask, which is data-independent. The function-pointer selected by dispatch is invariant for the remainder of the process, so secret data never influences which backend handles it.

### Test methodology: every test runs in both profiles

`ctest` registers every test twice. The default registration (`<NAME>`) runs the binary as the operator would, so the dispatcher selects whichever hardware backend the host actually has. A second registration (`<NAME>_sw`) runs the same binary with `ICHOR_FORCE_BACKEND=aes:bitsliced,clmul:scalar` in the environment, exercising the software floor on the same host. This means every CI run validates both paths on every supported architecture without separate build configurations.

A dedicated test (`tests/test_lean_build_warning.c`) covers the mismatch-notice path: it captures stderr while calling `voleith_backend_notice()` on a build that omitted the hardware AES backend, asserts the expected notice text appears, that it fires at most once, and that `VOLEITH_QUIET=1` suppresses it. It detects the active fallback at runtime via `ichor_aes_backend_health()` rather than a compiled-in macro; on a fat build (hardware backend active) the notice path is not reachable and the test exits immediately with PASS.

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

The library is tested against known-answer vectors from multiple independent sources. A single library binary contains every available backend; `ctest` runs every test in two profiles (hardware-dispatched and software-forced via `ICHOR_FORCE_BACKEND`) so both the hardware path and the constant-time software floor are exercised against the same vectors on every run. The dispatch machinery itself is covered above in "Runtime Hardware Dispatch".

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
