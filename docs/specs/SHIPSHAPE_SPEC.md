# Shipshape v1 Specification: GF(2^8) Circuit ISA and Text Format

**Format name:** Shipshape. **File extension:** `.ship`
(RECOMMENDED; §1.1). **Format version:** `.shipshape 1.1`
(semver; §1.4). **Stdlib version:** `crypto-v1`.
**Spec revision:** 2026-07-12 (r4).

**Status: normative; draft until the first conformant parser
ships.** Draft revisions MAY change the language itself: r3 named
the format Shipshape and renamed the header magic from `.circ` (the
design-time working name) to `.shipshape`. r4 adopted semver on the
format axis and added the `SCALE_INSTANCE` opcode as the first
additive MINOR bump (`.shipshape 1.1`; §1.4, §4.2.5). After the first
parser release, a spec revision MUST NOT change which files parse (§1.4).
This is the single, self-contained normative specification of the
Shipshape circuit description language and the single source of truth
for it: the surface syntax and formal grammar (Appendix A, Appendix
B), the IR semantics, opcodes, costs, lowering, and fingerprint (§§2,
4, 5, 6, 8), the crypto-v1 registry table and its freeze/CI process
(§7), and the parser implementation-security invariants (§8.5) are
all consolidated here. Where any other document disagrees with this
one, this one wins.

The format's design-time working name was `.circ`; that name and
Shipshape denote the same format.

**Implementation status.** The Tier 1 parser is implemented: the
surface syntax, lexical rules, gate set with sugar, `user/*`
subcircuit inlining, the resource bounds (§3.7), and the canonical
fingerprint serialization (§8) all parse and lower to a
`voleith_gf8_circuit_t`, with the generic Tier 1 witness generator
completing the full witness array from the external input. The worked
examples in §9 are hand-checked against the Appendix A grammar and
MUST be promoted to parser conformance fixtures. The open issue
recorded in r1 (KDF output-length parameter)
was resolved on 2026-06-11 by deferring the `kdf/*` entries to
crypto-v2; §7.5 records the decision and the v1 hand-composition
pattern.

---

## 1. Introduction

### 1.1 What a Shipshape file is

**Name and lineage.** The format is named **Shipshape**, completing
the idiom that named its ancestor: the Bristol Fashion MPC circuit
corpus (itself the successor to the older Bristol Format, punning
on the nautical idiom "shipshape and Bristol fashion": everything
tidy and in good order). This library ships a Bristol Fashion
parser (`parsers/bristol.c`); Shipshape is its strongly-typed,
canonically-fingerprinted successor format.

**File naming.** Shipshape files conventionally use the `.ship`
extension. The convention is RECOMMENDED but non-normative: format
identification is the `.shipshape 1` header line (§3.4), which a
parser MUST validate in all cases. A parser MUST NOT condition any
behavior on the file name.

A Shipshape file describes a deterministic computation over a finite
field as a directed acyclic graph of gates, together with input
declarations and assertions. It is a circuit description language,
not a proof-system encoding: the file commits to a statement ("there
exists a witness such that every assertion holds"), not to a proving
strategy.

A conformant parser consumes a Shipshape file (untrusted input) and
produces:

1. a lowered in-memory circuit (`voleith_gf8_circuit_t`, the Tier 1
   wire and constraint tables),
2. its 16-byte canonical fingerprint (§8), and
3. advisory side-table metadata (region markers for witness-backend
   dispatch, external-witness wire flags; §6.4, §2.4).

The reference proof-system binding is QuickSilver over VOLEitH via
`proof/gf8_circuit.h` and `proof/gf8_proof.h`. Other bindings may
consume the same IR; every cost in this document is quoted in
circuit-intrinsic units (nonlinear multiplications, witness slots,
assertions), not in binding units such as VOLE slots or proof bytes.

### 1.2 Audience

Two audiences, with different obligations:

- **Circuit authors** write Shipshape files. They need §§2-7 and the
  examples in §9. Sections 8 and the appendices are reference
  material for them.
- **Parser implementers** build conformant parsers. For them every
  section is normative, including Appendix A (grammar), Appendix B
  (static semantics), §3.6 (error policy), §3.7 (resource bounds),
  and §8 (lowering and fingerprint conformance).

### 1.3 Conformance language

The key words MUST, MUST NOT, REQUIRED, SHALL, SHALL NOT, SHOULD,
SHOULD NOT, RECOMMENDED, MAY, and OPTIONAL are to be interpreted as
described in RFC 2119 and RFC 8174 when, and only when, they appear
in all capitals.

A Shipshape file is **well-formed** iff it matches the Appendix A
grammar AND satisfies every rule in Appendix B AND respects the §3.7
resource bounds. A parser is **conformant** iff it accepts exactly
the well-formed files, rejects everything else with a defined error
(§3.6), and meets the determinism requirements of §8.5.

### 1.4 Versioning

Three version identifiers move independently:

- The **format version** (`.shipshape MAJOR[.MINOR]` header line) names
  the language this document defines. It is semver on `(MAJOR, MINOR)`.
  A bare `MAJOR` means `MAJOR.0`, so `.shipshape 1` == `.shipshape 1.0`.
  A new Tier 1 opcode (§§4-5) that leaves every prior-minor file valid
  and fingerprint-identical is an additive MINOR bump (for example
  `SCALE_INSTANCE`, introduced in `1.1`, §4.2.5); such a change is a
  delta section in this same document. Removing or renaming an opcode,
  changing any lowering, cost, or semantics, or tightening a rule is a
  MAJOR bump, which gets a successor specification. A parser advertises,
  per supported MAJOR, the highest MINOR it accepts; it accepts a file
  iff the MAJOR is supported and the file's MINOR does not exceed that
  highest MINOR, and it dispatches solely to that MAJOR's opcode table
  (no cross-major substitution, mirroring the stdlib rule). An opcode
  whose introduced-minor exceeds the file's declared MINOR is rejected
  (`ERR_OPCODE_VERSION`), distinct from an unknown opcode (`ERR_GATE`).
  The declared version is the minimum required; under-declaring a
  newer opcode is an error, over-declaring is legal.
- The **stdlib version** (`stdlib crypto-v1` or `stdlib crypto-v2`
  header line) names the Tier 2a registry the file calls into (§7).
  Registry changes are always a new version, never an in-place edit.
  `crypto-v2` is ADDITIVE over `crypto-v1`: every crypto-v1 registry
  entry remains callable under crypto-v2, and crypto-v2 adds the
  hash-parametric crypto extension entries (§7.7). A parser that
  supports `crypto-v2` MUST also bundle the complete `crypto-v1`
  table. There is no cross-version substitution in either direction:
  a `crypto-v1` file parsed by a `crypto-v2`-only parser is rejected
  outright (§3.4).
- The **spec revision** (top of this document) tracks editorial
  changes to this text. A spec revision MUST NOT change which files
  parse or what they parse to; any such change is a new format or
  stdlib version.

---

## 2. Concepts

### 2.1 Circuit model

The IR is SSA over a single flat DAG: every wire is defined exactly
once, there is no mutation, no control flow, and no forward
reference. Every statement falls into exactly one of five classes:

1. **DECL.** Introduces a fresh input wire: witness (private),
   instance (public), or constant.
2. **LINEAR.** Linear in the field values it consumes. Zero
   nonlinear cost, zero witness slots.
3. **NONLINEAR.** Multiplication of two already-defined wires
   producing a third. One nonlinear-mul, one witness slot for the
   output. Exactly two opcodes: `MUL` and `MUX`.
4. **NONLINEAR-GADGET.** A fixed soundness-bearing pattern consuming
   witness slots and assertions without consuming a nonlinear-mul.
   `INV` is the only member (§4.5).
5. **ASSERT.** Predicate over already-defined wires. Verifier-side
   only; zero prover cost.

Nothing else is admissible. The following are rejected at parse, by
grammar or by static semantics: lookup tables indexed by witness
values, witness-dependent vector indexing, arbitrary-arity field
multiplication, witness-dependent control flow, and operations over
any field other than the declared one.

### 2.2 Types

A small refinement-type system over one base type:

| Type | Meaning |
| --- | --- |
| `byte` | Arbitrary element of the declared field. |
| `bit` | Refinement of `byte` provably in `{0, 1}`. |
| `byte[N]` | Vector of `N` byte wires. Pure syntactic grouping; no runtime cost. `N = 0` is legal. |
| `bit[N]` | Vector of `N` bit wires. |

A wire is `bit`-typed iff it is (a) a `CONST_BIT` constant, (b) the
output of an explicit `ASSERT_BIT` narrowing, or (c) declared
`WITNESS ... : bit` (which emits the booleanity constraint at parse;
§4.1).

Two rules complete the system:

- **Subtyping.** `bit <: byte`: a `bit` wire is usable anywhere a
  `byte` is expected. The refinement is parse-time metadata only; it
  is erased at lowering and never hashed (§8.3 Step 6).
- **Flow-sensitive narrowing.** The type of a wire at a use site is
  determined solely by statements strictly preceding that use in the
  post-inline statement stream. `ASSERT_BIT %a -> %a2 : bit` refines
  from its binding onward, under the new name only; a later
  `ASSERT_BIT` cannot retroactively legalize an earlier use. Typing
  is a single forward pass, so two conformant parsers agree on
  accept/reject by construction.

The refinement exists for one critical case: the `MUX` selector MUST
be typed `bit` (§4.4). A `MUX` over an unconstrained `byte` selector
is a parse error, not a documented invariant. This makes the silent
soundness break (an unbooleanized secret-direction selector erasing
the carried chain value in a Merkle path) statically impossible.

### 2.3 Cost model

Costs are circuit-intrinsic and additive:

- **nonlinear-muls:** count of `MUL` plus `MUX` operations after
  sugar expansion. Every binding's proof-size formula is monotone in
  this count.
- **witness slots:** one per `WITNESS` wire, one per `MUL`/`MUX`
  output, one per `INV` output.
- **assertions:** one per `ASSERT_*` statement (two per `INV`).

LINEAR operations and DECLs are free in this accounting. "Free" is
exact for proof size and prover time; a free wire still occupies a
wire-table entry and is still walked by the verifier.

`INV` is accounted separately (as `invs`) because it consumes a
witness slot and two assertions but no nonlinear-mul. Stdlib costs
in §7 are quoted in `invs`.

### 2.4 Witness and instance layout

The mapping from a circuit to its witness and instance byte arrays
is IR semantics; any two conformant implementations MUST agree on
what "a witness for this circuit" means.

- **Witness array.** One byte per `WITNESS` wire, in the order the
  `WITNESS` declarations appear in the canonical (post-inline,
  post-desugar) gate stream. Gadget-internal witness wires are
  included: the `INV` output occupies the position of its defining
  gate. A `WITNESS : bit` wire contributes one byte like any other.
- **Instance array.** One byte per `INSTANCE` wire, in canonical
  declaration order.
- **Nothing else is in either array.** `MUL` and `MUX` outputs are
  not witness-array entries; their values are derived by evaluating
  the circuit and are committed separately by the binding.

Subcircuit inlining preserves the rule with no special casing: an
inlined body's `WITNESS` declarations land at the call site, in body
order. This is the layout the hand-written
`circuits/*_gf8_build_witness` helpers already implement:
externally-declared wires (keys, messages, tree nodes) precede the
builders' internal inverse witnesses.

Two views of the same array, at two trust levels:

- The **full witness array** (every `WITNESS` wire, canonical order)
  is what the proof-system binding consumes. It is a property of the
  lowered circuit and is covered by the §8 identity: same
  fingerprint, same layout.
- The **external witness input** (only the `WITNESS` declarations
  written in the file, excluding wires introduced by gadget
  lowering) is what a witness generator consumes. Every
  gadget-internal witness is a deterministic function of
  earlier-defined wires (the `INV` output is the field inverse of
  its input), so a generic evaluator completes the full array from
  the external input. Which wires are external is parse-level
  side-table metadata, not part of the circuit identity.

### 2.5 Namespaces and tiers

Subcircuit names are fully-qualified `/`-separated paths in three
namespaces, tracking the security boundary:

| Namespace | Tier | Bodies | Hash-pinned | Witness-backend dispatch |
| --- | --- | --- | --- | --- |
| `stdlib/crypto/*` | 2a | Bundled with the parser; MUST NOT be defined in a file | Yes | Safe-by-default on `(name, body-hash)` |
| `stdlib/structural/*` | 2b | Bundled; **empty set in v1**, so every use is a parse error | No | Advisory only |
| `user/*` | 2b | Defined in the file | No | Advisory only |

Tier 1 is the primitive opcode set of §§4-5. It is closed within a
format major: a new primitive enters only by an additive MINOR bump
(§1.4). Tier 2a is the
hash-pinned cryptographic registry (§7): names are by-reference
only, and the parser substitutes the registry-canonical body
verbatim, so two parsers agree byte-for-byte on what a Tier 2a call
means. Tier 2b is ordinary subcircuit territory; a wrong Merkle
domain byte there is a parameter choice, not malformation.

The split tracks the threat model: a wrong constant inside an AES
body is not-AES, and a counterparty's application would silently
accept proofs of the wrong statement; hash-pinning closes that
channel.

crypto-v2 reclassification (decided 2026-06-13, implemented). The same
threat-model argument applies to the crypto CONSTRUCTIONS, not just the
kernels: a wrong Merkle node hash, a missing leaf/inode domain separation,
or a botched indexed-Merkle comparator is a silent soundness compromise,
not a parameter choice. crypto-v2 therefore makes the structural crypto
constructions (Merkle path, indexed-Merkle non-membership, ring-sig
membership) Tier 2a hash-pinned "crypto extensions", inlined by reference
from the proven C builders exactly like `aes`/`cmac`/`grostl`. They are
hash-parametric: the node-hash TYPE is a parameter (never pinned to a
specific hash), supplied by the bracketed selector described in §7.7.
Tier 1 (the §§4-5 opcode set) stays closed; nothing here adds an opcode.
The secret-direction variants of these three constructions are implemented
in crypto-v2 phase 1 and fully normative; see §7.7 for the complete entry
table, type set, bracket-selector rules, cost model, and grammar delta.

### 2.6 Regions

Subcircuit calls are inlined at parse time (§6.4). Each inlined call
site is recorded as a named **region** in the parser's side-table
output, covering exactly the gates the body expanded to. Regions are
implicit (there is no region syntax) and semantically transparent:
they are never represented in the lowered circuit and never hashed.
Their only consumers are witness-backend dispatch (Tier 2a, keyed on
`(canonical-name, canonical-body-hash)` and authenticated against the
backend's own bundled registry) and the certified-primitive
attestation digest, which is bound to the fingerprint but never
folded into it.

Tier 2a dispatch is fail-closed by construction: it is prover-side
only, so a wrong or malicious backend can at worst produce a wrong
witness, yielding an invalid proof. It can never cause a verifier to
accept a proof of a wrong statement.

### 2.7 Trust boundary

A Shipshape file is untrusted input. A conformant parser consumes
attacker-controlled bytes and produces a trusted Tier 1 IR plus a
canonical fingerprint. Downstream consumers (witness interpreter,
prover, verifier, region-dispatching backends) trust the parser's
output; nothing downstream re-validates structural or type
invariants the parser is responsible for. Parser-implementation
security invariants (incremental bound enforcement, allocation
discipline, fuzzing requirements) are specified in §8.5.

---

## 3. File structure

### 3.1 Character set, lines, comments

- Allowed bytes: 0x20-0x7E (printable ASCII), tab (0x09), and the
  newline bytes 0x0A / 0x0D. Any other byte anywhere in the file,
  including inside comments, is a parse error. ASCII-only is a
  security rule, not a style rule: subcircuit namespace strings feed
  Tier 2a dispatch, and Unicode-confusable identifiers are an attack
  channel.
- Newlines: `\n`, `\r`, and `\r\n` each count as exactly one
  newline. A `\r` immediately followed by `\n` is one newline; any
  other adjacency is two. The final line MAY omit its newline.
- One statement per line; the newline terminates it. No semicolons,
  no continuation lines.
- Spaces and tabs are interchangeable between tokens. Leading and
  trailing whitespace is ignored. Blank lines are ignored.
- `#` begins a comment running to end of line. No block comments.
  Comments and blank lines may appear anywhere, including before and
  between header lines.

### 3.2 Identifiers

- Wire names are sigil identifiers: `%` followed by
  `[A-Za-z_][A-Za-z0-9_]*`. The sigil makes wires lexically distinct
  from opcode mnemonics and subcircuit paths, so there are no
  reserved-word conflicts.
- Subcircuit paths: `[A-Za-z_][A-Za-z0-9_]*` segments joined by `/`,
  at least two segments (e.g. `stdlib/crypto/aes/encrypt_128`,
  `user/myapp/foo`). `user/*` permits sub-namespacing to any depth
  within `MAX_IDENT_LEN`.
- Everything is case-sensitive. Identifier length, including the
  sigil or path separators, is bounded by `MAX_IDENT_LEN` (§3.7).
- Opcode mnemonics are uppercase and form a closed set.

### 3.3 Literals

- **Byte literal:** `0x` followed by exactly two hex digits; upper
  and lower case digits both accepted. No decimal, octal, or binary
  byte forms: banning alternate bases removes the literal-encoding
  aliasing channel at the source level outright.
- **Integer literal** (vector lengths, `FROBENIUS_K` k): decimal
  only, no sign, no leading zeros (zero itself is `0`). The value
  MUST fit the relevant §3.7 bound, checked while lexing.

### 3.4 Header

Three mandatory lines, in this order, before any other statement:

```
.shipshape 1
field GF(2^8) irreducible 0x11B
stdlib crypto-v1
```

or, for files that use the hash-parametric crypto extensions (§7.7):

```
.shipshape 1
field GF(2^8) irreducible 0x11B
stdlib crypto-v2
```

Token spellings are exact and case-sensitive: `GF(2^8)`,
`irreducible`, `0x11B`, `crypto-v1`, `crypto-v2`. Each supported
field and stdlib version has exactly one accepted token sequence. A
duplicated header keyword is a parse error (enforced structurally by
the grammar).

- `.shipshape <version>` declares the format version (§1.4). The
  `<version>` token is `MAJOR` or `MAJOR.MINOR`: non-negative decimal
  components with no leading zeros (bare `0` excepted). A bare `MAJOR`
  is `MAJOR.0`. This parser accepts major 1 with minor up to 1; a
  higher major or minor is `ERR_HEADER`.
- `field <F> irreducible <poly>` declares the working field. The
  parser rejects any opcode whose semantics are not defined over the
  declared field, and the proof-system binding refuses to verify a
  proof whose committed field does not match. This document
  specifies only the GF(2^8) instance; the IR is field-parametric.
- `stdlib <id>` declares the Tier 2a registry version (§7). Two
  values are defined: `crypto-v1` (the original 13-entry table, §7.2)
  and `crypto-v2` (additive superset that adds the hash-parametric
  crypto extensions of §7.7). The parser MUST have the declared
  registry bundled or reject the file. There is no cross-version
  substitution: a `crypto-v1` file is always parsed against the v1
  table even when the parser also bundles `crypto-v2`; a `crypto-v2`
  file is rejected by a parser that bundles only `crypto-v1`.
  Bracketed type selectors (§7.7) are a parse error under
  `crypto-v1`.

### 3.5 Statements

After the header, a file is a sequence of top-level statements and
subcircuit definitions. The statement kinds and where each is legal:

| Statement | Top level | Subcircuit body |
| --- | --- | --- |
| `WITNESS`, `CONST`, `CONST_BIT` declarations | yes | yes |
| `INSTANCE` declarations | yes | **no** (parse error) |
| Gates (§4) and assertions (§5) | yes | yes |
| Subcircuit calls (§6.2) | yes | yes |
| Subcircuit definitions (§6.1) | yes | **no** (no nesting) |

`INSTANCE` is top-level only because inlining one body at two call
sites would mint duplicate public inputs; public values reach bodies
via parameters.

**Scalarity.** Gate and assertion operands are scalar: an unindexed
vector name in a gate or assertion operand position is a type error.
There is no element-wise vector form of any Tier 1 opcode in v1;
element-wise patterns are written as subcircuits or unrolled.

**Vector access.** A vector element is `%name[i]` with `i` a decimal
integer literal in `0..N-1`. Anything that is not a literal in the
index position is a syntax error: witness-dependent indexing is
inadmissible at the IR level and the grammar rejects it
syntactically, not just semantically.

**Whole vectors and concatenation.** A vector name may be passed
whole where a `byte[N]` parameter of matching length is expected;
length mismatch is a type error. `++` is infix concatenation,
allowed in subcircuit-call arguments only: `f(%H ++ %M)` passes a
`byte[a+b]`. A scalar wire is usable as a `byte[1]` operand of `++`
(e.g. a domain-separation constant: `%dom ++ %L ++ %R`). No other
expression context accepts `++`. There is no slicing in v1.

### 3.6 Error policy

The first error stops the parse: a conformant parser frees every
partial allocation (including the partially built circuit), zeroes
the caller's out-struct, and returns a defined negative error code.
There is no error recovery and no resynchronization: the format is
machine-consumed, and recovery logic on attacker-controlled input is
added attack surface for zero benefit. Error-code enum and
out-struct conventions mirror `parsers/bristol.h`.

### 3.7 Resource bounds

Every parser enforces the same upper bounds on the post-inline IR.
These bounds are part of this specification, not implementation
choices: a parser that accepts an input violating them is
non-conformant.

| Bound | Symbol | Value |
| --- | --- | --- |
| Maximum wire count | `MAX_WIRES` | `2^28` |
| Maximum gate count (post-inline) | `MAX_GATES` | `2^28` |
| Maximum subcircuit inlining depth | `MAX_INLINE_DEPTH` | `64` |
| Maximum identifier length (bytes) | `MAX_IDENT_LEN` | `256` |
| Maximum `LINEAR_MAP` matrix size (bytes) | `MAX_MATRIX_BYTES` | `8` |
| Maximum vector length | `MAX_VECTOR_LEN` | `2^20` |
| Maximum block count per variable-block stdlib entry | `MAX_BLOCKS_PER_OPCODE` | `2^20` |
| Maximum file size (bytes) | `MAX_FILE_BYTES` | `2^26` (64 MiB) |
| Maximum line length (bytes) | `MAX_LINE_BYTES` | `2^16` |

The **gate count** is the number of non-input wires in the canonical
post-inline wire table (§8.4): every wire whose kind is not `WITNESS`,
`INSTANCE`, or `CONST`. Equivalently,
`n_wires - n_witness - n_instance - n_const`. An `INV` gadget therefore
contributes 2 (its two `SQUARE`
wires); its inverse output is a `WITNESS` wire, counted toward witness
slots, not gates. Because the wire table is byte-identical across
conformant parsers (§8.5), the gate count, and hence the `MAX_GATES`
accept/reject decision, is identical too: a file whose post-inline gate
count exceeds `MAX_GATES` is rejected by every conformant parser, and one
within it is accepted by every parser configured with default limits.

These are hard ceilings, not working sizes. The parse API takes
caller-supplied limits for gate count, wire count, and input size,
clamped to the ceilings; applications that know their circuits are
small SHOULD pass small limits. Enforcement is incremental:
header-declared sizes are checked on sight, running counts are
checked during parsing and inlining before each allocation growth
step, and no allocation is ever sized by an attacker-declared count
that has not been validated against the active limit.
`MAX_FILE_BYTES` is checked at the entry point before any of the
file is buffered; `MAX_LINE_BYTES` is enforced during lexing against
a single fixed-size line buffer. The file bound is sized for
pre-inline text: the sanctioned path to the `MAX_GATES` ceiling is
subcircuit inlining and vector expansion, not flat text.

A future format revision MAY raise these bounds; raising them
changes which files parse, never the fingerprint of any circuit that
already parses. The bounds are conformance requirements on parsers,
not inputs to the fingerprint.

---

## 4. Instruction reference

Each entry uses a fixed template. **Class** is one of the §2.1
classes. **Cost** is quoted as (nonlinear-muls, witness slots,
assertions). **Lowered form** names the wire/constraint entries the
statement contributes to the canonical tables (§8.3), in terms of
the `proof/gf8_circuit.h` builder calls. **Errors** lists
statement-specific rejection conditions beyond the universal rules
(SSA, define-before-use, scalarity, bounds; Appendix B).

### 4.1 Declarations (class: DECL)

#### 4.1.1 WITNESS

```
WITNESS -> %w : byte
WITNESS -> %w : bit
WITNESS -> %v : byte[16]
```

- **Semantics.** Declares a private input wire (or, with a vector
  type, `N` wires under one name). The prover supplies one byte per
  wire in the witness array (§2.4).
- **Cost.** (0, 1 per wire, 0); the `bit` form adds 1 assertion.
- **Lowered form.** `voleith_gf8_add_witness` per wire. The `bit`
  form lowers to `WITNESS ... : byte` followed by
  `ASSERT_PRODUCT(%w, %w, %w)`, so booleanity is enforced at
  declaration.
- **Errors.** Type annotation REQUIRED (it is FORBIDDEN on all
  outputs except `ASSERT_BIT`).

#### 4.1.2 INSTANCE

```
INSTANCE -> %x : byte
INSTANCE -> %root : byte[32]
```

- **Semantics.** Declares a public input wire (or `N` wires). The
  verifier supplies one byte per wire in the instance array (§2.4).
- **Cost.** (0, 0, 0).
- **Lowered form.** `voleith_gf8_add_instance` per wire.
- **Errors.** Top level only; `INSTANCE` inside a subcircuit body is
  a parse error. Type annotation REQUIRED.

#### 4.1.3 CONST

```
CONST 0x63 -> %c
```

- **Semantics.** Declares a literal field element.
- **Cost.** (0, 0, 0).
- **Lowered form.** `voleith_gf8_add_const`; the byte lands in the
  wire entry's `const_val`.
- **Errors.** Byte literal MUST be `0x` plus exactly two hex digits.

#### 4.1.4 CONST_BIT

```
CONST_BIT 1 -> %one
```

- **Semantics.** Declares a literal `{0, 1}` constant with `bit`
  type. Sugar: booleanity follows from the literal, so no constraint
  is emitted.
- **Cost.** (0, 0, 0).
- **Lowered form.** `CONST 0x00` or `CONST 0x01`; the `bit` typing
  is parse-time metadata, erased at lowering.
- **Errors.** Literal MUST be `0` or `1`.

### 4.2 Linear opcodes (class: LINEAR)

#### 4.2.1 ADD

```
ADD %a %b -> %c
```

- **Semantics.** `c = a + b` in GF(2^8) (bytewise XOR).
- **Cost.** (0, 0, 0).
- **Lowered form.** `voleith_gf8_add_xor` (XOR wire kind).

#### 4.2.2 ADD_CONST

```
ADD_CONST %a 0x1B -> %c
```

- **Semantics.** `c = a + k` for the literal `k`.
- **Cost.** (0, 0, 0).
- **Lowered form.** `voleith_gf8_add_xor_const` (XOR_CONST wire
  kind; the byte lands in `const_val`).

#### 4.2.3 LINEAR_MAP

```
LINEAR_MAP [0x51 0xD0 0x22 0xF0 0x94 0x60 0x28 0xC0] %a -> %c
```

- **Semantics.** `c = M . a` for an 8x8 GF(2) matrix. Surface
  position `i` is row `M[i]`, row-major; output bit `i` =
  `popcount(M[i] & a) mod 2`. Subsumes basis change, MixColumns
  rows, the CMAC RB-shift, Frobenius maps, and bit extraction
  (`M = {1<<i, 0, ..., 0}`).
- **Cost.** (0, 0, 0).
- **Lowered form.** `voleith_gf8_add_linear_map`, EXCEPT when the
  matrix equals the squaring matrix
  `{0x51, 0xD0, 0x22, 0xF0, 0x94, 0x60, 0x28, 0xC0}`, in which case
  it MUST lower via `voleith_gf8_add_square` to the SQUARE wire kind
  (§8.3 Step 3).
- **Errors.** Matrix MUST be exactly 8 byte literals in square
  brackets (grammar-enforced).

#### 4.2.4 SQUARE

```
SQUARE %a -> %c
```

- **Semantics.** `c = a^2`. Squaring is GF(2)-linear in GF(2^8); the
  matrix is fixed by the field declared in the header.
- **Cost.** (0, 0, 0).
- **Lowered form.** `voleith_gf8_add_square` (SQUARE wire kind). A
  parser MUST NOT rewrite `SQUARE` as a `LINEAR_MAP`.

#### 4.2.5 SCALE_INSTANCE

```
SCALE_INSTANCE %a %b -> %c
```

- **Since.** Format `1.1` (introduced-minor 1). A file using this
  opcode MUST declare `.shipshape 1.1` or higher; declaring `1.0` (or a
  bare `1`) is `ERR_OPCODE_VERSION`.
- **Semantics.** `c = a . b` in GF(2^8), where `%b` MUST be an INSTANCE
  (public) wire. Because the multiplier is public, `x -> b . x` is a
  per-proof GF(2)-linear map on `a`, so the gate is free (no VOLE slot),
  unlike `MUL`.
- **Cost.** (0, 0, 0).
- **Lowered form.** `voleith_gf8_add_scale_instance` (SCALE_INSTANCE
  wire kind).
- **Errors.** `%b` not an INSTANCE wire is `ERR_TYPE` (re-checked by the
  builder and by `voleith_gf8_circuit_validate`).

### 4.3 Linear sugar

Sugar opcodes expand during lowering (§8.3 Step 2); each expansion
counts toward the incremental gate budget like hand-written gates.

#### 4.3.1 SUM

```
SUM %a %b %c -> %d        # variadic, >= 2 inputs
```

- **Semantics.** n-ary sum.
- **Cost.** (0, 0, 0).
- **Lowered form.** `n-1` chained `ADD` ops with parser-fresh
  intermediate wires.
- **Errors.** Fewer than 2 operands is a syntax error.

#### 4.3.2 FROBENIUS_K

```
FROBENIUS_K 3 %a -> %c
```

- **Semantics.** `c = a^(2^k)`.
- **Cost.** (0, 0, 0).
- **Lowered form.** `k` chained `SQUARE` ops.
- **Errors.** `k >= 1` REQUIRED: `k = 0` would make the output an
  alias of its input wire, which SSA cannot express.

### 4.4 Nonlinear opcodes (class: NONLINEAR)

There are exactly two. A circuit's nonlinear-mul count is the count
of `MUL` and `MUX` operations after sugar expansion.

#### 4.4.1 MUL

```
MUL %a %b -> %c
```

- **Semantics.** `c = a . b` in GF(2^8). The only field
  multiplication primitive.
- **Cost.** (1, 1, 0).
- **Lowered form.** `voleith_gf8_add_mul` (MUL wire kind).

#### 4.4.2 MUX

```
MUX %sel %a %b -> %c
```

- **Semantics.** `c = sel ? b : a`, computed as
  `sel . (b + a) + a`.
- **Cost.** (1, 1, 0).
- **Lowered form.** The three-gate sequence emitted by
  `voleith_gf8_add_mux`: `diff = ADD(b, a)`,
  `prod = MUL(sel, diff)`, `c = ADD(a, prod)`. The expansion is
  sound gate-by-gate, which is why `MUX` may expand while `INV` must
  not (§4.5).
- **Errors.** `%sel` MUST be typed `bit` at the use site (§2.2).
  `MUX` over a `byte` selector is a type error; this check happens
  BEFORE expansion, so the canonical form never contains a MUX over
  an unrefined selector.

### 4.5 Inverse (class: NONLINEAR-GADGET)

#### 4.5.1 INV

```
INV %a -> %c
```

- **Semantics.** Field inverse: `a -> a^-1` for `a != 0`, and
  `0 -> 0`. The prover supplies `c` as a witness; two product
  assertions pin it down exactly, including the zero case.
- **Cost.** (0, 1, 2): one witness slot, two assertions, zero
  nonlinear-muls.
- **Lowered form.** Atomically, the canonical gadget from
  `proof/gf8_circuit.h`:

  ```
  c  = add_witness()
  a2 = add_square(a);   assert_product(a2, c, a)
  c2 = add_square(c);   assert_product(a, c2, c)
  ```

  There is no INV wire kind in the lowered tables; `INV` appears as
  this expansion.
- **Errors.** None beyond the universal rules.

`INV` is a primitive, not sugar, because the witness pattern is only
sound as an atomic unit. A hand-written incomplete or reordered
expansion (omitting one assertion, swapping the `SQUARE` placement,
or reusing an existing committed wire for `c`) parses but is a
different circuit that silently fails soundness; atomizing the
pattern as `INV` closes that failure mode. A user who hand-writes
the complete pattern gets the same tables and the same fingerprint,
which is correct: it is the same circuit. Bindings MUST either lower
`INV` to a gadget proven equivalent to the canonical expansion or
reject circuits containing `INV`.

---

## 5. Assertions (class: ASSERT)

Assertions are verifier-side predicates over already-defined wires.
All have zero prover cost in the §2.3 accounting (`ASSERT_CONST`
adds one linear wire).

### 5.1 ASSERT_ZERO

```
ASSERT_ZERO %a
```

- **Semantics.** Verifier checks `a = 0`.
- **Lowered form.** `voleith_gf8_assert_zero` (ZERO constraint).

### 5.2 ASSERT_EQUAL

```
ASSERT_EQUAL %a %b
```

- **Semantics.** Verifier checks `a = b`.
- **Lowered form.** `voleith_gf8_assert_equal` (EQUAL constraint).

### 5.3 ASSERT_PRODUCT

```
ASSERT_PRODUCT %a %b %c
```

- **Semantics.** Verifier checks `a . b = c` on three already-
  defined wires. At the IR level it is just a three-wire predicate;
  under the VOLEitH binding it is the QuickSilver
  multiplication-check entry point.
- **Lowered form.** `voleith_gf8_assert_product` (PRODUCT
  constraint).

### 5.4 ASSERT_BIT

```
ASSERT_BIT %a -> %a2 : bit
```

- **Semantics.** Narrows `%a : byte` to `bit` by constraining
  `a . a = a` (true iff `a` is 0 or 1). Binds a NEW name to the SAME
  wire: `%a2` and `%a` are one wire, with the refined type attached
  to `%a2` from this statement onward (§2.2). The `: bit` annotation
  is REQUIRED.
- **Lowered form.** `ASSERT_PRODUCT(%a, %a, %a)`; no fresh wire.

### 5.5 ASSERT_CONST

```
ASSERT_CONST %a 0x63
```

- **Semantics.** Sugar: verifier checks `a = k`.
- **Lowered form.** `ASSERT_ZERO(ADD_CONST(%a, k))`: one fresh
  XOR_CONST wire plus one ZERO constraint.

---

## 6. Subcircuits

### 6.1 Definitions

```
subcircuit user/aes_keystream (%key : byte[16], %nonce : byte[16]) -> (%ks : byte[16]) {
    ...
}
```

- Definitions are top-level only: no nesting, no inline-at-call-site
  bodies.
- A subcircuit MUST be defined before its first call. Together with
  define-before-use this makes recursion (direct or mutual)
  unrepresentable; the parser additionally bounds inlining depth
  against `MAX_INLINE_DEPTH`.
- The top level and each body are separate scopes with no visibility
  between them. Bodies see only their parameters; there are no
  captures of top-level wires.
- Signature parameter types are wire types only: `byte`, `bit`,
  `byte[N]`, `bit[N]`. Type parameters (the node-hash type a
  Merkle/indexed-Merkle/ring-sig construction is built over) do NOT
  appear in subcircuit signatures. Under `crypto-v1`, a bracketed
  type selector anywhere in a call is a parse error. Under
  `crypto-v2`, a bracketed selector MAY appear between the path and
  the argument list on the three hash-parametric entries only (§7.7):
  `stdlib/crypto/merkle/path_secret[grostl_256](...)`. A bracket on
  any other call (a crypto-v1 kernel, a `user/*` call, or a call
  under `crypto-v1`) is a parse error. A hash-parametric entry called
  WITHOUT a bracket is also a parse error. The closed node-hash-type
  set and the full static rules for the selector are in §7.7.
- Body statements are wire declarations except `INSTANCE` (§3.5),
  gates, assertions, and calls.
- A subcircuit MAY have zero outputs (assertion-only bodies, e.g.
  range checks), written by OMITTING the `-> ( ... )` clause in the
  definition and the `-> %out` clause at the call site. An empty
  `-> ()` is not legal syntax: one spelling per construct. A
  zero-parameter subcircuit writes `()`.

### 6.2 Calls

```
stdlib/crypto/aes/encrypt_128(%key, %pt) -> %ct
user/split_state(%s) -> %lo, %hi
user/range_check(%x)
```

- Arguments are parenthesized and comma-separated; each argument is
  a scalar operand, a whole vector, or a `++` concatenation chain
  (§3.5). Arguments match the signature positionally; a `++` chain's
  length is the sum of its operands' lengths, a scalar counting as
  `byte[1]`. Length mismatch is a type error.
- The output `wire-list` length MUST equal the definition's output
  count; each output binds one fresh name of the declared output
  type (vector outputs bind one vector name). The output clause is
  present iff the definition has outputs.
- Zero-length vectors (`byte[0]`) are legal in signatures and at
  call sites (e.g. the empty CMAC message, RFC 4493 Example 1).

### 6.3 Namespace and hash-pinning rules

- A `subcircuit stdlib/crypto/...` definition is a parse error.
- A call to a `stdlib/crypto/*` name absent from the bundled
  registry for the declared `stdlib` version is a parse error. There
  is no fallback to "treat as `user/`", no partial-support handling,
  and no cross-version substitution.
- Every `stdlib/structural/*` call or definition is a parse error in
  v1 (the bundled structural set is empty; §7.4).
- Definitions MUST be in `user/*`.

The first two rules are the hash-pinning enforcement (§2.5): no
Shipshape file can cause a conformant parser to instantiate a gate
sequence for a `stdlib/crypto/*` name that differs from the bundled
registry's canonical body for that name at the declared version.

### 6.4 Inlining semantics

Every call site is replaced at parse time by the body's gate
sequence: the registry-canonical body for Tier 2a calls, the in-file
definition for `user/*` calls. Inlined `WITNESS` declarations land
at the call site in body order (§2.4). Each call site is recorded as
an implicit region marker in the parser's side-table output (§2.6);
regions never enter the lowered circuit and never affect the
fingerprint.

---

## 7. Standard library: the crypto-v1 registry

### 7.1 Registry model

Tier 2a entries come in two kinds:

- **FIXED.** Constant signature, single frozen body hash.
- **PARAMETRIC.** Takes one or more compile-time integer parameters
  (message length, output length). The body is the deterministic
  output of the bundled generator for the given parameter values;
  the body hash is a function of `(name, params)`, computed
  identically by any conformant implementation.

In v1, integer parameters are supplied only by inference from the
lengths of vector arguments at the call site (a `msg : byte[n]`
parameter takes `n` from the actual argument's length). Every
crypto-v1 integer parameter is inferable this way; the designed
`kdf/*` entries, whose output-length parameter is not, are deferred
to crypto-v2 (§7.5). Parameter values are bounded by
`MAX_VECTOR_LEN` and derived block counts by
`MAX_BLOCKS_PER_OPCODE`, checked during instantiation before any
gates are emitted.

The normative body of every entry is the gate sequence emitted by
the corresponding hand-written `circuits/*_gf8_circuit.c` builder.
The freeze and CI process is:

1. The registry freeze tool (`tools/shipshape_registry_freeze`)
   builds every FIXED body and a parameter grid of every PARAMETRIC
   body via the C builders, serializes each under the §8.4 rules, and
   emits the frozen table (FQN, kind, signature, parameter bounds,
   body hash(es)) as generated C source, checked in and human-reviewed
   at each version cut.
2. CI re-derives the table on every commit touching `circuits/` or
   the parser and compares it byte-for-byte; divergence is a
   release-blocker (§6.3, Tier 2a non-malleability).
3. Any change to a registered body is a new entry in `crypto-v(N+1)`,
   never an in-place edit. Files pinned to `crypto-v1` parse against
   the v1 table forever.
4. The PARAMETRIC CI grid covers at minimum the smallest legal
   instantiation, one mid-size, one at each block boundary (e.g. CMAC
   at 16 and 17 bytes), and the published test-vector sizes (RFC 4493
   Examples 1-4, NIST CAVS 14.4 lengths).

### 7.2 Entry table

All names abbreviate `stdlib/crypto/...`. Costs are in `invs` (each
`INV`: 1 witness slot, 2 product assertions, 0 nonlinear-muls). No
entry contains any `MUL` or `MUX`, so each entry's nonlinear-mul
count is 0 and its witness-slot count equals its `invs`.

| FQN | Kind | Signature | Cost (invs) |
| --- | --- | --- | --- |
| `aes/sbox` | FIXED | `(in : byte) -> (out : byte)` | 1 |
| `aes/keyschedule_128` | FIXED | `(key : byte[16]) -> (rk : byte[176])` | 40 |
| `aes/encrypt_rounds_128` | FIXED | `(rk : byte[176], pt : byte[16]) -> (ct : byte[16])` | 160 |
| `aes/encrypt_128` | FIXED | `(key : byte[16], pt : byte[16]) -> (ct : byte[16])` | 200 |
| `aes/keyschedule_256` | FIXED | `(key : byte[32]) -> (rk : byte[240])` | 52 |
| `aes/encrypt_rounds_256` | FIXED | `(rk : byte[240], pt : byte[16]) -> (ct : byte[16])` | 224 |
| `aes/encrypt_256` | FIXED | `(key : byte[32], pt : byte[16]) -> (ct : byte[16])` | 276 |
| `cmac/aes_128` | PARAMETRIC `n >= 0` | `(key : byte[16], msg : byte[n]) -> (tag : byte[16])` | `200 * n_aes` |
| `cmac/aes_256` | PARAMETRIC `n >= 0` | `(key : byte[32], msg : byte[n]) -> (tag : byte[16])` | `276 * n_aes` |
| `grostl/hash_256` | PARAMETRIC `n >= 0` | `(msg : byte[n]) -> (out : byte[32])` | `1280 * b + 640`, `b = ceil((n + 9) / 64)` |
| `grostl/hash_256_t27` | PARAMETRIC `n >= 0` | `(msg : byte[n]) -> (out : byte[27])` | same as `hash_256` |
| `grostl/hash_512` | PARAMETRIC `n >= 0` | `(msg : byte[n]) -> (out : byte[64])` | `3584 * b + 1792`, `b = ceil((n + 9) / 128)` |
| `grostl/hash_512_t59` | PARAMETRIC `n >= 0` | `(msg : byte[n]) -> (out : byte[59])` | same as `hash_512` |

Thirteen entries. `n_aes` for the CMAC entries is
`aes_cmac_gf8_n_aes_calls(n)`. (The two `kdf/*` entries originally
designed for this table are deferred to crypto-v2; §7.5. The
`hirose/aes256_iter` entry was also deferred to crypto-v2 on
2026-06-11; §7.6.)

### 7.3 Usage notes for circuit authors

- **Hoist the AES key schedule.** `encrypt_128` / `encrypt_256` are
  convenience forms that re-run the key schedule on every call. Any
  circuit encrypting more than once under the same key SHOULD call
  `keyschedule_*` once and `encrypt_rounds_*` per block. This is the
  reason the split exists: a double-block-length compression like
  Hirose (deferred to crypto-v2, §7.6) runs two encryptions per
  iteration under one shared schedule for 52 + 2 x 224 = 500 invs,
  versus 2 x 276 = 552 monolithic.
- **The v1 CMAC bodies are monolithic.** They re-derive the AES key
  schedule and CMAC subkeys per call, exactly as the shipped C
  builders do. The granular subkey/chain split, the hoisted KDF,
  and the `kdf/*` entries themselves land in crypto-v2 (§7.5).
- **Truncated Grøstl variants are free.** `hash_256_t27` and
  `hash_512_t59` have identical gate sequences to their parents;
  only the output signature narrows (first 27 of 32, first 59 of 64
  output wires). T27 exists for single-compression Merkle inodes:
  with 27-byte nodes, an inode input of 1 + 2 x 27 = 55 bytes fits
  one Grøstl block.
- **Domain separation is the caller's job.** Tier 2a hashes are raw;
  prefix domain bytes yourself (e.g. `%dom ++ %L ++ %R`), as the
  Merkle examples do.
- **`cmac/*` admits `n = 0`** (RFC 4493 Example 1); pass a declared
  `byte[0]` vector.

### 7.4 Structural stdlib: empty in v1; crypto extensions in v2

The bundled `stdlib/structural/*` set in Shipshape v1 is empty. This
is forced, not merely chosen: the designed structural entries
(Merkle path, indexed-Merkle non-membership, comparators) all take a
typed `<hash>` parameter, and the v1 parameter-type set is empty
(§6.1, no bracketed selector under `crypto-v1`), so none of those
signatures is expressible in v1. Under `crypto-v1`, applications
write structural compositions as `user/*` subcircuits; the project
ships them as example Shipshape text, not bundled registry content.
A v1 public-direction Merkle path is generated circuit text with the
directions statically resolved, exactly as the C builders do today;
secret-direction paths mux per node byte with a `bit`-typed selector
(§4.4, §9.3).

crypto-v2 resolution (decided 2026-06-13, implemented in phase 1).
The structural constructions are NOT left to `user/*` hand-wiring:
that puts the security-critical glue (domain separation, DM wrap,
leaf chain, `assert_lt`, direction booleanity) in the untrusted
author's hands, the exact failure mode hash-pinning exists to prevent
(§2.5). Under `stdlib crypto-v2`, three hash-parametric constructions
are registered as Tier 2a hash-pinned "crypto extensions" and are
fully normative: `stdlib/crypto/merkle/path_secret`,
`stdlib/crypto/indexed_merkle/nonmember_secret`, and
`stdlib/crypto/ring_sig/v1`. These are the secret-direction variants
(direction bits are witness); public-direction variants are deferred
to crypto-v2 phase 2. The full entry table, type set, bracket rules,
cost model, region names, body-hash CI model, and phase-2 deferred
items are in §7.7. The `stdlib/structural/*` namespace remains empty
in both v1 and v2; every call there is a parse error.

### 7.5 KDF-CTR-CMAC: deferred to crypto-v2 phase 2 (decided 2026-06-11)

crypto-v1 and crypto-v2 phase 1 register no `kdf/*` entries.
Revision r1 of this section recorded the underlying open issue: the
designed entries' output-length parameter `L` appears only in the
output signature (`out : byte[L]`), and neither v1 nor v2 phase 1
has surface syntax that can supply it. Call arguments are wires
(Appendix A `arg`), output bindings carry no type annotation (§3.5),
and inference reaches only input vector lengths (§7.1). Rather than
add syntax, the entries are deferred to crypto-v2 phase 2, which
plans both pieces they need: the immediate-constant parameter syntax
and the hoisted subkey/chain CMAC forms the granular KDF builds on.
(Note: crypto-v2 phase 1 -- the secret-direction constructions of
§7.7 -- has shipped; `kdf/*` is a phase-2 item only.) Parsers reject
`kdf/*` calls as unknown registry names, exactly like any other
unregistered `stdlib/crypto/*` name (§6.3).

Nothing is lost in v1 but convenience. SP 800-108 KDF-CTR is
hand-expressible from the `cmac/*` entries because the counter is a
compile-time constant: each iteration is one CMAC call over
`[i]_32be ++ fixed`, with the counter bytes as `CONST` wires:

```
# K(1) = CMAC(key, [1]_32be || fixed); repeat per 16-byte block,
# incrementing the counter constants. Fragment: %key and %fixed
# are declared earlier.
CONST 0x00 -> %c0
CONST 0x00 -> %c1
CONST 0x00 -> %c2
CONST 0x01 -> %c3
stdlib/crypto/cmac/aes_128(%key, %c0 ++ %c1 ++ %c2 ++ %c3 ++ %fixed) -> %k1
```

The cost is identical to the deferred monolithic entries: the v1
CMAC bodies re-derive the key schedule and subkeys per call (§7.3),
which is exactly what the monolithic KDF builders do. Two
consequences to be aware of: there is no KDF-level region, so
witness-backend dispatch and certified-primitive attestation
operate at CMAC granularity in v1; and the hand-composed KDF is a
caller-level pattern with no KDF-level hash-pinning, while each
embedded `cmac/*` call remains hash-pinned.

### 7.6 Hirose: deferred to crypto-v2 phase 2 (decided 2026-06-11)

crypto-v1 and crypto-v2 phase 1 register no `hirose/*` kernel entry.
Revision r3 of this section listed a single FIXED `hirose/aes256_iter`
(one Hirose compression iteration). It is deferred for the same
structural reason as `kdf/*`: its only consumer is node hashing for a
Hirose Merkle tree, and the C node-hash builders domain-separate leaf
from inode with a per-role 128-bit constant `c`
(`circuits/node_hash_hirose_gf8.c`: `-L` for leaf, `-N` for inode).
`c` is applied as a circuit constant (`ADD_CONST`), not a wire, and
is not part of the iteration's `(G, H, M)` signature; v1 and v2
phase 1 have no call-site syntax to supply it (the same
immediate-constant gap that defers `kdf/*`, §7.5). A single baked
`c` would force leaf and inode to share a constant, so a
Shipshape-authored Hirose Merkle would neither match the C
`merkle_hirose_*` circuits byte-for-byte nor preserve their leaf/inode
type-confusion separation.

Note: the `hirose` and `hirose_fixed_32` entries DO appear in the
crypto-v2 phase-1 node-hash-type table (§7.7), where they identify
which C builder to inline for the Merkle/IMT/ring-sig constructions.
What is deferred is only the standalone `hirose/*` kernel entry
(one isolated compression call). crypto-v2 phase 2 will add that
entry once the immediate-constant parameter mechanism exists. Hirose
is a leaf in the registry dependency graph (it composes
`aes/keyschedule_256` plus two `aes/encrypt_rounds_256`, and nothing
else consumes it), so the deferral removes no other entry. Parsers
reject `hirose/*` calls as unknown registry names (§6.3).

### 7.7 crypto-v2 registry: hash-parametric crypto extensions (secret-direction)

This section is normative under `stdlib crypto-v2`. All rules here
apply only when the file header declares `stdlib crypto-v2`; the
entries defined here are absent from the `crypto-v1` registry and
any reference to them under `crypto-v1` is a parse error (§6.3).

#### 7.7.1 Overview

Three entries are added to the Tier 2a registry in crypto-v2. They
are hash-parametric: each entry is instantiated for a specific
node-hash TYPE, supplied by the bracketed selector at the call site.
They are hash-pinned (Tier 2a) for the same reason the crypto-v1
kernels are: the security-critical glue (domain separation, leaf
chain construction, `assert_lt` comparator, direction-bit booleanity
enforcement) lives inside the bundled body, not in the caller's
`user/*` code. Putting that glue in untrusted author code is the
failure mode hash-pinning exists to prevent (§2.5).

All three entries in phase 1 are SECRET-DIRECTION: the direction bits
(one per Merkle level) are witness wires, selected per node byte with
a `MUX`, and direction-bit booleanity is enforced INSIDE the inlined
body via `ASSERT_PRODUCT` per level. The caller does NOT need to add
booleanity constraints separately. Public-direction variants and the
standalone `hirose/*` kernel are deferred to crypto-v2 phase 2 (§7.6,
§7.5).

#### 7.7.2 Node-hash-type set

The node-hash type is a compile-time TYPE supplied by the bracketed
selector, not a wire. The closed set of defined type names is:

| Type name | Node bytes | Notes |
| --- | --- | --- |
| `aes_dm` | 16 | Davies-Meyer / MMO construction |
| `aes_cmac_128` | 16 | AES-128 CMAC construction |
| `grostl_256` | 32 | |
| `grostl_256_t27` | 27 | Truncated to first 27 output bytes |
| `grostl_512` | 64 | |
| `grostl_512_t59` | 59 | Truncated to first 59 output bytes |
| `hirose` | 32 | Hirose double-block-length (variable leaf width) |
| `hirose_fixed_32` | 32 | Leaf-record width fixed to 32 bytes |
| `grostl_256_fixed` | 32 | Fixed-input single-compression Grøstl-256; leaf-record width fixed to 32 bytes |
| `grostl_512_fixed` | 64 | Fixed-input single-compression Grøstl-512; leaf-record width fixed to 64 bytes |

The set is closed as of this version and is extensible only by a
future registry version (planned additions: `rijndael_256`,
`whirlpool`). The type-name is also the segment under which a future
`stdlib/crypto/node_hash/<type>/...` callable could be added;
that namespace is reserved and registers nothing in phase 1.

An unknown type-name in a bracket selector is a parse error.

#### 7.7.3 Bracket-selector syntax and rules

A hash-parametric call carries exactly one bracket selector between
the path and the argument list:

```
stdlib/crypto/merkle/path_secret[grostl_256](%leaf, %sib, %dirs) -> %root
```

Normative rules:

- The bracket selector is REQUIRED on every call to a hash-parametric
  entry. A hash-parametric entry called without a bracket is a parse
  error.
- The bracket selector is PERMITTED ONLY on the three entries listed
  in §7.7.4, and only under `stdlib crypto-v2`. A bracket on any
  other call (any crypto-v1 kernel, any `user/*` call, or any call
  under `stdlib crypto-v1`) is a parse error.
- The selector contains exactly one type-name from the closed set
  (§7.7.2). A comma-separated multi-type selector is a parse error
  in phase 1.
- The type-name is a bare identifier. Leading and trailing whitespace
  inside the brackets is permitted. The type-name is case-sensitive.
- An unknown type-name is a parse error.

#### 7.7.4 Entry table

In all signatures: `node` is the selected type's node-byte width
(§7.7.2); `depth` is inferred from `len(dirs)`. The parameter `L`
(leaf-data width), `tb` (target/low/hi field width), `ib` (index
field width), and `skb` (secret-key width) are free length
parameters inferred from the corresponding argument vectors at the
call site (§7.1).

| FQN (abbreviated `stdlib/crypto/...`) | Kind | Signature |
| --- | --- | --- |
| `merkle/path_secret[H]` | PARAMETRIC `H`, `L`, `depth >= 1` | `(leaf : byte[L], siblings : byte[depth*node], dirs : byte[depth]) -> (root : byte[node])` |
| `indexed_merkle/nonmember_secret[H]` | PARAMETRIC `H`, `tb`, `ib`, `depth >= 1` | `(target : byte[tb], low : byte[tb], hi : byte[tb], nidx : byte[ib], siblings : byte[depth*node], dirs : byte[depth], root : byte[node])` (assertion-only, no outputs) |
| `ring_sig/v1[H]` | PARAMETRIC `H`, `skb`, `depth >= 1` | `(sk : byte[skb], dirs : byte[depth], siblings : byte[depth*node], root : byte[node])` (assertion-only, no outputs) |

Notes:

- `merkle/path_secret[H]`: `siblings` MUST have length `depth * node`
  (inferred from the argument vector's length; a mismatch is a type
  error). For `hirose_fixed_32`, `L` MUST equal 32; any other `L`
  is a type error.
- `indexed_merkle/nonmember_secret[H]`: assertion-only; the call
  site MUST omit the `-> (...)` clause (§6.1). `siblings` MUST have
  length `depth * node`. The entry asserts non-membership internally
  and asserts the recomputed root equals the `root` argument. For
  `hirose_fixed_32`, `2 * tb + ib` MUST equal 32; any other
  combination is a type error.
- `ring_sig/v1[H]`: assertion-only; the call site MUST omit the
  `-> (...)` clause. `siblings` MUST have length `depth * node`. The
  OWF hash and the tree hash are the same `H` in phase 1 (multi-type
  ring_sig is a phase-2 item). `root` is the public ring/group root
  (an `INSTANCE` or `CONST` wire at the call site). For
  `hirose_fixed_32`, `skb` MUST equal 32.

#### 7.7.5 Region names

Each call site records an implicit region (§2.6) named EXACTLY:

```
stdlib/crypto/<name>[<type>]
```

For example: `stdlib/crypto/merkle/path_secret[grostl_256]`. This
string, together with the registry version, is the Tier 2a
witness-backend dispatch key (§2.5, §2.6). The dispatch key is the
full bracketed form; dispatch on the unbracketed path alone is
insufficient and MUST NOT be used.

#### 7.7.6 Identity and body hash

Each `(entry, node-hash type, inferred integer params)` triple has
a deterministic frozen body hash, produced by the bundled generator
from the corresponding hash-parametric C vt builder
(`circuits/merkle_vt_gf8_circuit.c`,
`circuits/indexed_merkle_vt_gf8_circuit.c`, and
`circuits/ring_sig_v1_gf8_circuit.c`), each driven by the selected
node-hash `voleith_node_hash_vt`. The freeze and CI process follows the same model as
crypto-v1 PARAMETRIC entries (§7.1): the registry freeze tool
samples a representative (type, param) grid (covering each type at
small, mid-size, and boundary parameter values), serializes bodies
under §8.4 rules, and emits a frozen table checked in and
CI-verified on every commit that touches `circuits/` or the parser.

Off-grid (type, param) combinations parse, prove, and verify
normally; the grid is change-detection sampling only. This is the
same model as crypto-v1, where only a few CMAC message lengths are
frozen but all lengths are correct.

#### 7.7.7 Cost model

Unlike every crypto-v1 entry (which contains zero `MUL` or `MUX`
gates), these secret-direction entries DO contain nonlinear gates.
The sources of nonlinear cost are:

- One `MUX` per node byte per level (direction selection), giving
  `depth * node` MUX gates.
- One `ASSERT_PRODUCT` per level for direction-bit booleanity, giving
  `depth` additional assertion operations (these are on `bit`-typed
  wires inferred from the booleanity structure, handled inside the
  body).
- For `indexed_merkle/nonmember_secret`: the `assert_lt` non-membership
  comparator over the `tb`-byte fields, contributing additional `MUL`
  gates that scale with the comparison bit width. The exact per-bit
  factor is fixed by the `assert_lt_gf8` C implementation and frozen in
  the body hash.

The total nonlinear-mul count is therefore nonzero and is deterministic
in `(node-hash type, depth, data widths)`. The exact counts are fixed
by the bundled generator and frozen/CI-checked over the representative
grid (§7.7.6). The dominant cost term (by far) is the inlined hash
calls: one leaf hash plus `depth` inode hashes for
`merkle/path_secret`, with the same pattern for the other two entries
plus the comparator overhead. Exact counts are available via the
corresponding C `*_witness_bytes()` and circuit-stat helper functions.

#### 7.7.8 Phase-2 deferred items

The following items are deferred to crypto-v2 phase 2 and are NOT
part of phase 1:

- Public-direction variants of all three entries (where `dirs` is a
  vector of `CONST` or `INSTANCE` wires and the MUX overhead is
  absent).
- The standalone `hirose/*` kernel entry (§7.6).
- The `kdf/*` entries (§7.5).
- Multi-type `ring_sig/v1` (separate OWF hash and tree hash types).
- The `rijndael_256` and `whirlpool` node-hash types.

Phase 2 requires the immediate-constant parameter mechanism not yet
present in the grammar; no phase-2 item is parseable under the
current grammar.

---

## 8. Circuit identity

### 8.1 Fingerprint definition

This format defines no new hash. The fingerprint of a Shipshape file
is the fingerprint of the circuit it parses to:

```
fingerprint(file) := voleith_gf8_circuit_fingerprint(parse(file))
```

where `voleith_gf8_circuit_fingerprint()` is the existing identity
from `proof/gf8_circuit_fingerprint.h` (shipped in 1.3.0): a 16-byte
SHAKE-128 digest with domain tag `voleith-gf8-circuit-cf-v1`,
computed over the post-lowering wire and constraint tables (§8.4).
The proof metadata header (`proof/proof_header.h`) already binds
proofs to this digest, so Shipshape files get exactly the identity
proofs are verified against. A circuit built by the parser and the
same circuit built by a hand-written C builder produce the same
fingerprint.

Header strings are not hashed, and need not be: `field`, `stdlib`,
and format version select how a file is parsed; the meaning they
pin is the resulting gates, and the gates are what is hashed. Field
substitution is excluded by domain-tag disjointness across circuit
types (a bit-level `field GF(2)` parse would produce a
`voleith_circuit_t` under the separate `voleith-circuit-cf-v1` tag).

### 8.2 What changes the fingerprint (author's view)

Identical fingerprints, by construction:

- Renaming wires or subcircuits (names are discarded at lowering).
- Comment, whitespace, blank-line, and newline-style variation.
- Writing a sugar form versus its expansion (`SUM` vs chained `ADD`,
  `FROBENIUS_K` vs chained `SQUARE`, `CONST_BIT` vs `CONST`,
  `ASSERT_CONST` vs its expansion, `MUX` vs its three-gate
  expansion with the same wires, `INV` vs its complete hand-written
  gadget).
- `SQUARE` versus `LINEAR_MAP` carrying the squaring matrix.
- Literal case (`0xAB` vs `0xab`).
- Factoring gates into subcircuits differently, provided the
  post-inline gate sequence is identical (regions are transparent).
- Subcircuit definition order at top level (definitions emit no
  gates; only call sites do, in call order).

Different fingerprints, deliberately:

- Reordering independent gates. Canonical order is emission order;
  two files listing independent gates in different orders are
  different circuits. This is the safe direction: the attack the
  fingerprint excludes is two different circuits with one hash; one
  circuit with two hashes wastes an adversary's time but breaks
  nothing.
- Redundant constraints (e.g. `CONST 0x01` plus `ASSERT_BIT`
  carries an extra always-true PRODUCT constraint relative to
  `CONST_BIT 1`). Extra assertions only restrict the satisfying
  witness set; they can never widen it.
- Any Tier 2a body difference (a `stdlib` version whose registry
  changes a body changes the inlined gates, hence the hash).

### 8.3 Lowering normalization (normative)

The canonical form of a Shipshape file is the `voleith_gf8_circuit_t`
produced by lowering the parsed AST through these steps in order:

- **Step 0: no semantic rewrites.** No dead-code elimination, no
  CSE, no gate deduplication, no constant folding, no reordering.
  Gates are emitted in post-inline source appearance order and are
  never removed or merged. This is a conformance requirement: an
  "optimizing" parser produces wrong fingerprints, and eliminating
  gates can delete ASSERTs, which is a soundness break.
- **Step 1: subcircuit inlining.** Every call site is replaced by
  its body's gates (§6.4); call sites become side-table regions.
- **Step 2: sugar expansion.** `SUM`, `FROBENIUS_K`, `CONST_BIT`,
  `ASSERT_CONST`, `ASSERT_BIT`, `WITNESS : bit`, and `MUX` expand
  to their lowered forms (§§4-5). The `MUX` selector type check
  happens BEFORE expansion.
- **Step 3: distinguished special case.** A `LINEAR_MAP` whose
  matrix equals the squaring matrix lowers to the SQUARE wire kind.
  The direction is fixed by the C builders, which call
  `voleith_gf8_add_square`; a parser that emits a LINEAR_MAP-kind
  entry carrying the squaring matrix is non-conformant.
- **Step 4: INV lowering.** Atomic expansion to the §4.5 gadget; no
  INV wire kind exists in the tables.
- **Step 5: wire numbering and gate order.** Wire IDs are assigned
  in definition order during lowering; source names are discarded.
  Gates and constraints land in emission order, which Steps 0-4
  make deterministic. A parser MUST NOT re-sort gates by any
  criterion.
- **Step 6: type erasure.** The `bit`/`byte` refinement is enforced
  at parse time and then erased; the tables carry no type tags and
  none are hashed.
- **Step 7: regions stay outside.** Region markers and Tier 2a
  `(name, body-hash)` pairs exist only in side-table output; they
  are not part of the circuit and not part of the fingerprint.
- **Step 8: literal canonicalization.** Source encoding of literals
  is discarded; constants land as the `const_val` byte,
  `LINEAR_MAP` matrices as the row-major `uint8_t M[8]` array with
  the §4.2.3 bit convention.

### 8.4 Fingerprint serialization (reference)

The serialization and hash are owned by
`proof/gf8_circuit_fingerprint.h`; this section reproduces them for
convenience. Any change to the layout requires a new domain tag.

```
preimage :=
    "voleith-gf8-circuit-cf-v1" || 0x00                (26 bytes)
||  u32_le(n_wires)
||  u32_le(n_witness)
||  u32_le(n_instance)
||  u32_le(n_mul)
||  u32_le(n_constraints)
||  for each wire in declaration order:
        u8     kind        (WITNESS=0, INSTANCE=1, CONST=2, XOR=3,
                            XOR_CONST=4, LINEAR_MAP=5, SQUARE=6,
                            MUL=7)
        u32_le a           (0 if the kind has no first input)
        u32_le b           (0 if the kind has no second input)
        u8     const_val   (0 unless kind is CONST or XOR_CONST)
        u8[8]  matrix      (zero-filled unless kind is LINEAR_MAP)
||  for each constraint in declaration order:
        u8     kind        (ZERO=0, EQUAL=1, PRODUCT=2)
        u32_le a
        u32_le b           (0 if the kind has no second operand)
        u32_le c           (0 unless kind is PRODUCT)

fingerprint := SHAKE-128(preimage, 16 bytes)
```

`GF8_WIRE_ID_INVALID` in unused operand positions is normalized to 0
before hashing. Note what the table does NOT contain: no MUX or INV
kinds (lowered away), no type tags, no region or Tier 2a
information, no header strings, no bounds. Wire IDs fit in `u32`
because `MAX_WIRES = 2^28`.

### 8.5 Parser conformance

Any two conformant v1 parsers, given the same well-formed v1
Shipshape file, MUST produce byte-identical wire and constraint
tables under
the §8.4 serialization, and hence the identical 16-byte fingerprint.
For every Tier 2a registry entry, those tables MUST additionally be
byte-identical to the hand-written C builder's output; the
per-entry equivalence test doubles as the fingerprint-conformance
test. A hand-curated cross-parser corpus exercising every sugar
form, literal encoding, and gate-ordering edge case is part of the
parser's CI gates; disagreement on any input is a release-blocker.

A conformant parser also binds to the following
implementation-security invariants:

- **Defined rejection.** Every malformed or pathological input is
  rejected with a defined error and no undefined behaviour, OOB
  read/write, or silent acceptance of a different circuit than the
  bytes describe (§3.6).
- **Incremental bound enforcement.** The §3.7 resource limits are
  enforced incrementally: no allocation is ever sized by an
  attacker-declared count that has not been validated against the
  active limit. Header-declared sizes are checked on sight; running
  gate and wire counts are checked before each allocation-growth
  step, aborting the moment a limit is crossed. A tiny file can
  legally expand toward `MAX_GATES` through inlining and vector
  sugar, so limits are enforced as the expansion runs, not after.
- **Allocation discipline.** Every count-times-element-size
  allocation uses the two-argument `calloc(n, size)` form; the bound
  check plus the language-level overflow guard together close the
  parser-side surface for that bug class.
- **No `assert()` on file-byte paths.** The project builds with
  `-DNDEBUG`, so every check on a path that processes file bytes is a
  runtime `if (...) return error;`, never an `assert()`.
- **Fail-closed on first error.** The parser stops at the first parse
  error, frees every partial allocation (including the partially
  built circuit), zeroes the caller's out-struct, and returns a
  defined error code. There is no error recovery or
  resynchronization: recovery logic on attacker-controlled input is
  added attack surface for no benefit in a machine-consumed format.
- **No forward references.** Every operand wire ID is validated
  against the in-progress wire table at the point of use;
  wire-use-before-define is a parse error.
- **Bounded inlining.** Subcircuit inlining depth is bounded against
  `MAX_INLINE_DEPTH` (§3.7), with the incremental gate/wire discipline
  applied while expanding, so the post-inline gate array never grows
  past the active limit before a violation is detected.
- **Single pass or no TOCTOU gap.** The parser either validates in a
  single pass over the inlined gate stream, or specifies which
  validations happen at which pass and proves no TOCTOU gap can open
  between them.
- **Mandatory fuzz harness.** The parser ships with a libFuzzer (or
  equivalent) harness exercising its entry point on attacker-shaped
  inputs, run in CI on every commit that touches parser code.

---

## 9. Worked examples

Examples 9.1 and 9.2 are complete files; 9.3 is a fragment. All are
hand-checked against Appendix A and Appendix B; none has been run
through a parser, because none exists yet. They MUST become parser
conformance fixtures when the parser lands.

### 9.1 Knowledge of two private factors

```
.shipshape 1
field GF(2^8) irreducible 0x11B
stdlib crypto-v1

# Prove knowledge of bytes a, b with a * b = c for public c.
WITNESS -> %a : byte
WITNESS -> %b : byte
INSTANCE -> %c : byte
MUL %a %b -> %p
ASSERT_EQUAL %p %c
```

Witness array: 2 bytes (`a`, `b`). Instance array: 1 byte (`c`).
Cost: 1 nonlinear-mul, 3 witness slots total under the binding
(2 declared + 1 for the `MUL` output), 1 assertion.

### 9.2 Knowledge of an AES-128 key (the FAEST statement)

```
.shipshape 1
field GF(2^8) irreducible 0x11B
stdlib crypto-v1

# Prove knowledge of an AES-128 key mapping a public plaintext to a
# public ciphertext.

subcircuit user/assert_eq16 (%x : byte[16], %y : byte[16]) {
    ASSERT_EQUAL %x[0] %y[0]
    ASSERT_EQUAL %x[1] %y[1]
    ASSERT_EQUAL %x[2] %y[2]
    ASSERT_EQUAL %x[3] %y[3]
    ASSERT_EQUAL %x[4] %y[4]
    ASSERT_EQUAL %x[5] %y[5]
    ASSERT_EQUAL %x[6] %y[6]
    ASSERT_EQUAL %x[7] %y[7]
    ASSERT_EQUAL %x[8] %y[8]
    ASSERT_EQUAL %x[9] %y[9]
    ASSERT_EQUAL %x[10] %y[10]
    ASSERT_EQUAL %x[11] %y[11]
    ASSERT_EQUAL %x[12] %y[12]
    ASSERT_EQUAL %x[13] %y[13]
    ASSERT_EQUAL %x[14] %y[14]
    ASSERT_EQUAL %x[15] %y[15]
}

WITNESS -> %key : byte[16]
INSTANCE -> %pt : byte[16]
INSTANCE -> %ct : byte[16]

stdlib/crypto/aes/encrypt_128(%key, %pt) -> %out
user/assert_eq16(%out, %ct)
```

This demonstrates: an assertion-only `user/*` subcircuit (no output
clause at definition or call), a Tier 2a call, and the witness
layout rule. The witness array is 216 bytes: the 16 declared key
bytes, then the 200 `INV` output bytes the inlined `encrypt_128`
body's gadgets introduce at the call site (200 S-boxes, one `INV`
each), in gate order. The instance array is 32 bytes (`pt` then
`ct`). Cost: 0 nonlinear-muls, 200 invs, 416 assertions (2 per INV
plus 16 equality checks).

### 9.3 Merkle level over Grøstl-256-T27 (fragment)

```
# Public-direction inode: this level's direction bit was 0 at
# generation time, so the chain value is the left child. v1
# public-dir paths are generated text with directions statically
# resolved (no MUX cost).
CONST 0x01 -> %dom                  # RFC 6962 inode domain byte
stdlib/crypto/grostl/hash_256_t27(%dom ++ %cur ++ %sib) -> %parent

# Secret-direction level: the direction is a witness bit, and each
# of the 27 node bytes is selected with a MUX pair. The bit type on
# %dir is what makes this sound; a byte selector is a parse error.
WITNESS -> %dir : bit
MUX %dir %cur[0] %sib[0] -> %left0
MUX %dir %sib[0] %cur[0] -> %right0
# ... same MUX pair for bytes 1..26, then hash
# %dom ++ %left0 ++ ... ++ %right26 as above.
```

Here `%cur` and `%sib` are `byte[27]` wires declared earlier. The
`++` chain passes a `byte[55]` message (1 + 27 + 27), so the
PARAMETRIC `hash_256_t27` instantiates at `n = 55`: a single Grøstl
block, 1 compression, 1920 invs per inode. The secret-direction
variant costs `2 x 27 = 54` nonlinear-muls per level for the muxes;
`WITNESS -> %dir : bit` emits the booleanity constraint at
declaration, so no separate `ASSERT_BIT` is needed.

---

## Appendix A. Formal grammar (normative)

Notation: RFC 5234 ABNF with RFC 7405 `%s` (case-sensitive) string
literals. Core rules `ALPHA`, `DIGIT`, `SP`, `HTAB`, `CR`, `LF` are
RFC 5234 Appendix B.

The grammar is normative for token structure. The Appendix B
static-semantics rules are normative for everything a context-free
grammar cannot express; a file is well-formed iff it matches this
grammar AND satisfies every rule in Appendix B. Where this grammar
and the prose of §§3-6 disagree, the grammar wins for syntax and the
prose wins for semantics.

Whitespace convention: `ws` (required, 1 or more space/tab)
separates adjacent word-like tokens; `ows` (optional) is permitted
around punctuation (`->`, `:`, `,`, `(`, `)`, `]`, `{`, `}`, `++`,
the `[` of a matrix, and the `[` / `]` of a bracket type selector).
The `[` of a vector index or vector type binds tightly: no whitespace
before it. A `CR` immediately followed by `LF` is one newline (§3.1).
The final line of a file may omit its trailing newline.

```abnf
;; File structure ------------------------------------------------

shipshape-file = *skip-line version-line
                 *skip-line field-line
                 *skip-line stdlib-line
                 *( skip-line / top-line / subckt-def )

version-line  = ows %s".shipshape" ws %s"1" trail
field-line    = ows %s"field" ws %s"GF(2^8)" ws %s"irreducible"
                ws %s"0x11B" trail
stdlib-line   = ows %s"stdlib" ws stdlib-ver trail
stdlib-ver    = %s"crypto-v1" / %s"crypto-v2"

top-line      = ows top-stmt trail
top-stmt      = decl / gate / assertion / call
skip-line     = ows [ comment ] eol

;; Subcircuit definitions ----------------------------------------

subckt-def    = ows %s"subcircuit" ws path ows
                "(" ows [ param-list ows ] ")"
                [ ows arrow ows "(" ows param-list ows ")" ]
                ows "{" trail
                *body-line
                ows "}" trail

param-list    = param *( ows "," ows param )
param         = wire ows ":" ows type

body-line     = skip-line / ( ows body-stmt trail )
body-stmt     = witness-decl / const-decl / constbit-decl
              / gate / assertion / call

;; Statements ----------------------------------------------------

decl          = witness-decl / instance-decl / const-decl
              / constbit-decl
witness-decl  = %s"WITNESS" ows arrow ows wire ows ":" ows type
instance-decl = %s"INSTANCE" ows arrow ows wire ows ":" ows type
const-decl    = %s"CONST" ws byte-lit ows arrow ows wire
constbit-decl = %s"CONST_BIT" ws bit-lit ows arrow ows wire

gate          = add-g / add-const-g / linear-map-g / square-g
              / mul-g / mux-g / inv-g / sum-g / frobenius-g
add-g         = %s"ADD" ws operand ws operand out
add-const-g   = %s"ADD_CONST" ws operand ws byte-lit out
linear-map-g  = %s"LINEAR_MAP" ows matrix ws operand out
square-g      = %s"SQUARE" ws operand out
mul-g         = %s"MUL" ws operand ws operand out
mux-g         = %s"MUX" ws operand ws operand ws operand out
inv-g         = %s"INV" ws operand out
sum-g         = %s"SUM" ws operand 1*( ws operand ) out
frobenius-g   = %s"FROBENIUS_K" ws int-lit ws operand out

assertion     = assert-zero / assert-equal / assert-product
              / assert-bit / assert-const
assert-zero   = %s"ASSERT_ZERO" ws operand
assert-equal  = %s"ASSERT_EQUAL" ws operand ws operand
assert-product = %s"ASSERT_PRODUCT" ws operand ws operand
                 ws operand
assert-bit    = %s"ASSERT_BIT" ws operand ows arrow ows wire
                ows ":" ows %s"bit"
assert-const  = %s"ASSERT_CONST" ws operand ws byte-lit

call          = path [ ows "[" ows type-sel ows "]" ]
                ows "(" ows [ arg-list ows ] ")"
                [ ows arrow ows wire-list ]
type-sel      = ident              ; exactly one identifier; phase 1
arg-list      = arg *( ows "," ows arg )
arg           = operand *( ows "++" ows operand )
wire-list     = wire *( ows "," ows wire )

;; Operands, types, literals -------------------------------------

out           = ows arrow ows wire
arrow         = %s"->"
operand       = wire [ "[" ows int-lit ows "]" ]
wire          = "%" ident
path          = ident 1*( "/" ident )
ident         = id-start *id-char        ; length <= MAX_IDENT_LEN
id-start      = ALPHA / "_"
id-char       = ALPHA / DIGIT / "_"

type          = scalar-type [ "[" ows int-lit ows "]" ]
scalar-type   = %s"byte" / %s"bit"

matrix        = "[" ows byte-lit 7( ws byte-lit ) ows "]"
byte-lit      = %s"0x" 2hex
hex           = DIGIT / %x41-46 / %x61-66       ; 0-9 A-F a-f
bit-lit       = "0" / "1"
int-lit       = "0" / ( %x31-39 *DIGIT )  ; no sign, no leading 0

;; Lexical layer --------------------------------------------------

trail         = ows [ comment ] eol
comment       = "#" *cchar
cchar         = HTAB / %x20-7E
ws            = 1*( SP / HTAB )
ows           = *( SP / HTAB )
eol           = ( CR LF ) / CR / LF      ; may be absent at EOF
```

Notes on the grammar itself:

- A bare-identifier statement head cannot collide between gates and
  calls: opcode mnemonics contain no `/`, and `path` requires at
  least two segments, so `foo(...)` without a namespace is a syntax
  error.
- Header order and uniqueness are enforced structurally: the three
  header lines admit no alternatives and no repetition, so a
  duplicated header keyword fails as an unparseable statement.
- `LINEAR_MAP`'s matrix is exactly 8 byte literals (grammar), and
  `SUM` has at least 2 operands (grammar).

## Appendix B. Static semantics (normative)

A file matching Appendix A is well-formed iff all of the following
hold. Violations are parse errors under the §3.6 first-error-stop
policy.

- **S1 (SSA).** Every wire name is defined exactly once per scope;
  the top level and each subcircuit body are separate scopes with no
  visibility between them (§6.1). A vector declaration defines its
  name once, creating `N` element wires (`N = 0` legal). A
  definition's parameters and outputs are definitions in the body
  scope. `ASSERT_BIT` defines a new name for the same wire (§5.4).
- **S2 (define-before-use).** Every operand names a wire defined
  strictly earlier in its scope. Every call names a subcircuit
  already defined in the file (`user/*`) or present in the bundled
  registry for the declared `stdlib` version (`stdlib/crypto/*`).
  No forward references.
- **S3 (INSTANCE top-level).** Enforced by the grammar (`body-stmt`
  has no `instance-decl`); restated as a deliberate IR rule, not a
  grammar accident: public inputs enter bodies only via parameters
  (§3.5).
- **S4 (namespaces).** Definitions must be in `user/*`. A
  `subcircuit stdlib/...` definition is an error. Calls to
  `stdlib/crypto/*` names absent from the declared registry version
  are errors; calls to `stdlib/structural/*` are errors in v1
  (empty bundled set, §7.4).
- **S5 (scalarity and types).** Gate and assertion operands are
  scalar; an unindexed vector name there is a type error (§3.5).
  `MUX` selectors must be `bit`. `bit <: byte`; narrowing is
  flow-sensitive: the type at a use site is fixed by strictly
  preceding statements only (§2.2).
- **S6 (vector lengths).** Index literals lie in `0..N-1`. Call
  arguments match the signature positionally; a `++` chain's length
  is the sum of its operands' lengths, a scalar counting as
  `byte[1]`. Length mismatch is a type error.
- **S7 (call outputs).** The `wire-list` length equals the
  definition's output count; each output binds one fresh name of
  the declared output type (vector outputs bind one vector name).
  The output clause is present iff the definition has outputs
  (§6.1).
- **S8 (bounds).** `MAX_IDENT_LEN` per identifier, `MAX_LINE_BYTES`
  during lexing, `MAX_FILE_BYTES` at entry, `MAX_VECTOR_LEN` for
  every type bracket and `++` result, and the incremental
  `MAX_WIRES` / `MAX_GATES` / `MAX_INLINE_DEPTH` discipline of §3.7
  and §8.5.
- **S9 (sugar arity).** `FROBENIUS_K` requires `k >= 1` (§4.3.2);
  expansion counts toward the incremental gate budget like any
  sugar.
- **S10 (witness placement).** `WITNESS` in bodies is legal; on
  inlining, its wires land at the call site in body order (§2.4).
- **S11 (bracket type selector).** The `[ type-sel ]` production in a
  `call` is subject to the following rules, checked after S2
  (define-before-use on the path):
  1. Under `stdlib crypto-v1`, a bracket selector on any call is a
     parse error regardless of the path.
  2. Under `stdlib crypto-v2`, a bracket selector is REQUIRED on
     calls to the three hash-parametric entries
     (`stdlib/crypto/merkle/path_secret`,
     `stdlib/crypto/indexed_merkle/nonmember_secret`,
     `stdlib/crypto/ring_sig/v1`) and is a parse error on every
     other call (including all crypto-v1 kernels and all `user/*`
     calls).
  3. The type-name MUST be a member of the closed node-hash-type set
     in §7.7.2. An unknown name is a parse error.
  4. Exactly one type-name per bracket; a comma inside the bracket
     (multi-type) is a parse error.
  5. After the type-name resolves, `node` is bound to the
     corresponding node-byte width from §7.7.2. All vector-length
     checks in S6 then apply with `node` substituted. In particular:
     the `siblings` argument MUST have length `depth * node` where
     `depth = len(dirs)` (the length of the `dirs` argument); a
     mismatch is a type error.
  6. For `hirose_fixed_32`: the leaf-data width `L` MUST equal 32
     (for `merkle/path_secret`); `2 * tb + ib` MUST equal 32 (for
     `indexed_merkle/nonmember_secret`); `skb` MUST equal 32 (for
     `ring_sig/v1`). Any other value is a type error.
  7. `depth` MUST be >= 1. A zero-length `dirs` argument is a type
     error for all three entries.
