/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * gf8_circuit.h - GF(2⁸) element-level circuit definition API
 *
 * This is the element-level counterpart to circuit.h. Each wire carries a
 * single GF(2⁸) element (one byte) rather than a single bit. Operating at
 * element granularity reduces VOLE slot count dramatically:
 *
 *   Bit-level:   one VOLE slot per AND gate
 *   GF(2⁸)-level: one VOLE slot per GF(2⁸) multiplication (add_mul)
 *                  zero slots for all GF(2)-linear operations (XOR, squaring,
 *                  linear maps)
 *
 * In the AES S-box: 36 AND gates → 1 add_mul gate (via Proposition 6.4
 * from the FAEST spec: asserting x²·y = x and x·y² = y proves y = x⁻¹ or
 * x = y = 0, using two free assert_product checks and one inv_in witness).
 *
 * VOLE slot layout:
 *   Slots  0 .. n_witness-1       witness elements, in declaration order
 *   Slots  n_witness .. ell-1     add_mul gate outputs, in gate order
 *   (ell = n_witness + n_mul)
 *
 * Wire IDs are sequential non-negative integers assigned in order of
 * creation, so the wire table is always in topological order.
 *
 * Usage pattern:
 *   voleith_gf8_circuit_t *c = voleith_gf8_circuit_new();
 *   gf8_wire_id k  = voleith_gf8_add_witness(c);     // key byte
 *   gf8_wire_id k2 = voleith_gf8_add_square(c, k);   // k² (free)
 *   gf8_wire_id ki = voleith_gf8_add_witness(c);      // k⁻¹ (inv witness)
 *   // assert k² · ki == k  and  k · ki² == ki  (Proposition 6.4)
 *   voleith_gf8_assert_product(c, k2, ki, k);
 *   gf8_wire_id ki2 = voleith_gf8_add_square(c, ki);
 *   voleith_gf8_assert_product(c, k, ki2, ki);
 *   voleith_gf8_circuit_free(c);
 */

#ifndef VOLEITH_GF8_CIRCUIT_H
#define VOLEITH_GF8_CIRCUIT_H

#include <stdint.h>
#include <stddef.h>

/* Wire identifier - index into the circuit's wire table */
typedef uint32_t gf8_wire_id;

/* Sentinel for "no wire" / invalid wire */
#define GF8_WIRE_ID_INVALID UINT32_MAX

/*
 * Wire kinds - determines how the wire's GF(2⁸) value is computed.
 *
 * WITNESS and INSTANCE wires are primary inputs.
 * CONST wires carry a fixed element embedded in the circuit.
 * All operations below marked "free" cost zero VOLE slots because they
 * are GF(2)-linear: their VOLE tags are derived from input tags.
 * MUL wires cost one VOLE slot each (the QuickSilver multiplication check).
 */
typedef enum {
    GF8_WIRE_WITNESS,    /* private input: GF(2⁸) element from witness */
    GF8_WIRE_INSTANCE,   /* public input:  GF(2⁸) element from instance */
    GF8_WIRE_CONST,      /* constant element; value in const_val */
    GF8_WIRE_XOR,        /* output = a XOR b          (free: GF(2)-linear) */
    GF8_WIRE_XOR_CONST,  /* output = a XOR const_val  (free: GF(2)-linear) */
    GF8_WIRE_LINEAR_MAP, /* output = M·a for 8×8 GF(2) matrix M (free) */
    GF8_WIRE_SQUARE,     /* output = a² = Frobenius(a) (free: GF(2)-linear) */
    GF8_WIRE_MUL, /* output = a · b in GF(2⁸)  (costs one VOLE slot) */
    GF8_WIRE_SCALE_INSTANCE, /* output = a · b, b MUST be an instance wire
                              * (free: b is public, so a·b is GF(2)-linear
                              * in a via the runtime matrix of x -> b·x) */
} gf8_wire_kind_t;

/*
 * A single wire entry.
 *
 * For primary inputs (WITNESS/INSTANCE/CONST), the input wire fields are
 * unused (GF8_WIRE_ID_INVALID).
 *
 * For unary gates (LINEAR_MAP, SQUARE, XOR_CONST): a holds the input, b is
 * GF8_WIRE_ID_INVALID.
 *
 * For binary gates (XOR, MUL, SCALE_INSTANCE): both a and b hold input wire
 * IDs.  For SCALE_INSTANCE, b must reference an INSTANCE wire.
 *
 * const_val: for CONST and XOR_CONST, the embedded constant byte.
 *
 * matrix: for LINEAR_MAP, the 8×8 GF(2) matrix stored row-major.
 *         Row i is matrix[i]; bit j of matrix[i] is the (i,j) entry.
 *         Output bit i = inner product of matrix row i with input bits.
 *         (Column-vector convention: out = M · a_col, where a_col[j] = bit j
 *          of the input element.)
 */
typedef struct {
    gf8_wire_kind_t kind;
    gf8_wire_id a;     /* first input wire, or GF8_WIRE_ID_INVALID */
    gf8_wire_id b;     /* second input wire, or GF8_WIRE_ID_INVALID */
    uint8_t const_val; /* for CONST and XOR_CONST */
    uint8_t matrix[8]; /* for LINEAR_MAP: row i of the 8×8 GF(2) matrix */
} gf8_wire_entry_t;

/*
 * Constraint types - assertions that the verifier checks.
 *
 * ZERO:     wire a must equal 0x00.
 * EQUAL:    wire a must equal wire b.
 * PRODUCT:  wire a · wire b must equal wire c  (QuickSilver assert_product).
 *           PRODUCT costs zero VOLE slots - it checks existing committed values.
 * PRODUCT3: wire a · wire b · wire c must equal wire d  (three-way product).
 *           This is the FAEST norm S-box relation c · a² · a¹⁶ = a (spec Fig
 *           6.19): a relation of degree R = 3 whose target d is parked at the
 *           top (∆³) coefficient so that coefficient vanishes for an honest
 *           prover.  Only the three lower coefficients are opened, so PRODUCT3
 *           rides the same opening count d = 2 as PRODUCT (zero VOLE slots,
 *           unchanged a_tilde width).  The fourth operand uses field `d`.
 */
typedef enum {
    GF8_CONSTRAINT_ZERO,     /* assert wire a == 0x00 */
    GF8_CONSTRAINT_EQUAL,    /* assert wire a == wire b */
    GF8_CONSTRAINT_PRODUCT,  /* assert wire a · wire b == wire c */
    GF8_CONSTRAINT_PRODUCT3, /* assert wire a · wire b · wire c == wire d */
} gf8_constraint_kind_t;

/*
 * A single constraint entry.
 * For ZERO:     a is the checked wire; b, c, d are GF8_WIRE_ID_INVALID.
 * For EQUAL:    a and b are the checked wires; c, d are GF8_WIRE_ID_INVALID.
 * For PRODUCT:  a, b, c are used (a · b == c); d is GF8_WIRE_ID_INVALID.
 * For PRODUCT3: a, b, c, d are all used (a · b · c == d).
 *
 * The fourth operand `d` is meaningful only for PRODUCT3.  It is serialized
 * into the circuit fingerprint only for PRODUCT3 (gf8_circuit_fingerprint.c),
 * so ZERO/EQUAL/PRODUCT fingerprints remain byte-identical to pre-PRODUCT3
 * circuits.
 */
typedef struct {
    gf8_constraint_kind_t kind;
    gf8_wire_id a;
    gf8_wire_id b;
    gf8_wire_id c;
    gf8_wire_id d;
} gf8_constraint_entry_t;

/*
 * Less-than constraint (degree-(width+1) QuickSilver, zero VOLE slots).
 *
 * Asserts value(A) < value(B), where A and B are unsigned `width`-bit integers
 * given as MSB-first arrays of bit wires (each wire holds 0x00 or 0x01).  The
 * bit wires live in the circuit's shared LT bit pool: for this entry, the A
 * bits are pool[bits_off .. bits_off+width-1] and the B bits are
 * pool[bits_off+width .. bits_off+2*width-1].
 *
 * Kept in a table separate from gf8_constraint_entry_t so the fixed-degree
 * ZERO/EQUAL/PRODUCT accumulation path is unchanged (d=2 stays byte-identical).
 * A circuit with any LT constraint raises its QS opening degree to width+1
 * (voleith_gf8_circuit_qs_degree).
 */
typedef struct {
    size_t bits_off;
    unsigned int width;
} gf8_lt_entry_t;

/*
 * Syndrome constraint (degree-b QuickSilver, zero VOLE slots).
 *
 * Asserts the QC-MDPC syndrome relation s = M * e^T against a committed
 * weight-t support, in the global-bit equality-polynomial form (no dense e):
 *
 *     s_j  =  XOR_{k=0..t-1}  M[j, g_k]      for j = 0 .. p-1,
 *
 * where g_k is the k-th support index, committed as `idx_bits` MSB-first bit
 * wires, and M[j, g_k] as a function of g_k's bits is a degree-`idx_bits`
 * multilinear polynomial (the equality-polynomial demux, evaluated on the
 * Delta-polynomials, never materialized as a dense error vector).  This is a
 * zero-slot degree-`idx_bits` assert-zero constraint family (one per syndrome
 * bit j), batched into the same zk_hash accumulator as the gate constraints.
 *
 * Wire layout in the shared syndrome bit pool for this entry:
 *   pool[idx_off + k*idx_bits + b]      MSB-first bit b of support index g_k
 *   pool[s_off + j]                     syndrome bit s_j (public / instance)
 *
 * M is a private owned copy of the public circulant matrix: (n0-1) blocks of
 * block_bytes each (the first row of each circulant block), exactly the buffer
 * voleith_rs_opener_argus_syndrome() consumes.  The implicit-identity last
 * block (systematic form) is not stored.
 *
 * Kept in a table separate from gf8_constraint_entry_t and gf8_lt_entry_t so
 * the fixed-degree constraint path stays byte-identical (d=2 unchanged).  A
 * circuit with any syndrome constraint raises its QS opening degree to
 * idx_bits.
 */
typedef struct {
    size_t idx_off;    /* pool offset of the t*idx_bits support bit wires */
    size_t s_off;      /* pool offset of the p syndrome bit wires         */
    uint32_t t;        /* support weight                                  */
    uint32_t idx_bits; /* bits per global index = ceil(log2 n)            */
    uint32_t p;        /* circulant block length (syndrome bit count)     */
    uint32_t n0;       /* number of circulant blocks; n = n0 * p          */
    const uint8_t *M;  /* owned copy: (n0-1) * block_bytes                 */
    size_t m_bytes;    /* length of the M copy                            */
} gf8_syndrome_entry_t;

/*
 * AES norm S-box round-pair constraint (FAEST paired-round norm, opening count
 * d = 2, zero VOLE slots).
 *
 * This is the paired-round re-expression of two AES rounds (spec Section 6.2,
 * faest-ref aes_SSS_enc_constraints): the even round commits a 4-bit subfield
 * norm per S-box instead of the 8-bit inverse, and the odd round commits a full
 * intermediate state (`s_tilde`) so the linear layers can be run backward to
 * reset the degree chain.  Together this averages 6 bits per S-box (down from
 * 8) with no change to the opening count: the two folded per-byte constraints
 * (s_sq * st_0 - s and s * st_1 - st_0) are degree R = 3 parked to d = 2, pushed
 * through the same zk_hash_3 accumulator as PRODUCT / PRODUCT3, so a circuit
 * with norm round-pairs keeps qs_degree = 2.
 *
 * Kept in a table separate from gf8_constraint_entry_t (like the LT and
 * syndrome tables) so the fixed-degree ZERO/EQUAL/PRODUCT/PRODUCT3 path stays
 * byte-identical.  The per-byte isolated norm relation c * a^2 * a^16 = a is NOT
 * stored here: it is emitted through the ordinary PRODUCT3 builder.  This entry
 * carries only the paired-round reset relation that PRODUCT3 cannot express
 * (its degree-2 operand is a linear image of a product of committed wires).
 *
 * Wire layout in the shared norm bit pool for this entry (4 * nst ids):
 *   pool[wires_off + 0*nst + i]   state_in[i]: even-round input state byte wire
 *   pool[wires_off + 1*nst + i]   norm[i]:     embedded subfield norm c = a^-17
 *                                              (voleith_gf8_add_norm_embed out)
 *   pool[wires_off + 2*nst + i]   s_tilde[i]:  committed odd-round reset state
 *   pool[wires_off + 3*nst + i]   k0[i]:       round key added in the odd round
 *
 * The norm[i] wire carries the full GF(2^8) norm byte c (not the raw nibble):
 * the accumulate derives the four inverse-norm conjugates y[k] = c^(2^k) by
 * Frobenius squaring (the beta tables are Frobenius-generated).  The conjugates
 * of state_in and the conjugate-domain affine constants are likewise computed
 * inside the prover/verifier accumulate from these wires and fixed field
 * constants; they are not stored per entry.
 */
typedef struct {
    size_t wires_off; /* pool offset of the 4*nst wire ids for this pair */
    unsigned int nst; /* state bytes (16 for AES) */
    int last_pair;    /* 1 if the pair's second round is the final round
                           (no MixColumns), else 0 */
} gf8_norm_entry_t;

/*
 * Grostl norm S-box round-pair constraint (FAEST paired-round norm; sibling of
 * gf8_norm_entry_t for Grostl's linear layer).  Grostl's S-box IS the AES
 * S-box, so the inversion/affine math and the two folded degree-R=3/d=2
 * relations are identical; what differs is the linear layer (ShiftBytes +
 * MixBytes instead of ShiftRows + MixColumns) and the round add (a public
 * AddRoundConstant before SubBytes, so there is no secret round-key wire
 * group).  Kept in its own table so the AES norm path stays byte-identical.
 *
 * Wire layout in the Grostl norm bit pool for this entry (3 * nst ids):
 *   pool[wires_off + 0*nst + i]   state_in[i]: even-round S-box input byte wire
 *                                              (= state XOR the public even
 *                                              AddRoundConstant, applied free by
 *                                              the caller)
 *   pool[wires_off + 1*nst + i]   norm[i]:     embedded subfield norm c = a^-17
 *   pool[wires_off + 2*nst + i]   s_tilde[i]:  committed odd-round reset state
 *                                              (after odd SubBytes + ShiftBytes)
 *
 * The odd-round public AddRoundConstant is reconstructed from (is_q, odd_round,
 * cols) via grostl_norm_round_const; the ShiftBytes flat permutation and its
 * inverse (for the s recovery) from (shift, cols) via grostl_norm_build_shift.
 */
typedef struct {
    size_t wires_off;  /* pool offset of the 3*nst wire ids */
    unsigned int nst;  /* state bytes: 64 (Grostl-256) or 128 (-512) */
    unsigned int cols; /* state columns: 8 (Grostl-256) or 16 (-512) */
    uint8_t shift[8];  /* ShiftBytes row shifts for this permutation */
    uint8_t odd_round; /* round number of the pair's odd (second) round */
    uint8_t is_q;      /* 1 = Q permutation ARC, 0 = P */
} gf8_grostl_norm_entry_t;

/*
 * The GF(2⁸) circuit - opaque type, constructed via the builder API below.
 */
typedef struct voleith_gf8_circuit voleith_gf8_circuit_t;

/* ================================================================
 * Lifecycle
 * ================================================================ */

/*
 * Allocate an empty circuit. Returns NULL on allocation failure.
 * Must be freed with voleith_gf8_circuit_free().
 */
voleith_gf8_circuit_t *voleith_gf8_circuit_new(void);

/*
 * Free a circuit and all its allocated memory.
 */
void voleith_gf8_circuit_free(voleith_gf8_circuit_t *c);

/*
 * Set incremental resource ceilings on a circuit: at most `max_wires` total
 * wires and `max_gates` gate (non-input) wires.  A value of 0 means unlimited,
 * which is the default for a newly created circuit, so circuits built without
 * calling this behave exactly as before (identical wire/constraint tables and
 * fingerprint).  When a ceiling is set, the builder's add_* calls fail
 * (returning GF8_WIRE_ID_INVALID and clearing voleith_gf8_circuit_ok()) the
 * moment an append would cross it, bounding a bulk emitter's allocation rather
 * than detecting the overflow only after the fact.
 */
void voleith_gf8_circuit_set_limits(voleith_gf8_circuit_t *c, size_t max_wires,
                                    size_t max_gates);

/* ================================================================
 * Builder API - add wires and gates
 *
 * All functions returning gf8_wire_id return GF8_WIRE_ID_INVALID on
 * allocation failure. Void functions silently discard errors (callers
 * may check voleith_gf8_circuit_ok() after construction).
 * ================================================================ */

/*
 * Declare a witness (private input) wire.
 * Assigned VOLE slot index = (current witness count before this call).
 */
gf8_wire_id voleith_gf8_add_witness(voleith_gf8_circuit_t *c);

/*
 * Declare an instance (public input) wire.
 * Not assigned a VOLE slot - both prover and verifier know its value.
 */
gf8_wire_id voleith_gf8_add_instance(voleith_gf8_circuit_t *c);

/*
 * Add a constant wire carrying the fixed GF(2⁸) element `val`.
 */
gf8_wire_id voleith_gf8_add_const(voleith_gf8_circuit_t *c, uint8_t val);

/*
 * Add an XOR gate: output = a XOR b. Free in QuickSilver.
 */
gf8_wire_id voleith_gf8_add_xor(voleith_gf8_circuit_t *c, gf8_wire_id a,
                                gf8_wire_id b);

/*
 * Add an XOR-with-constant gate: output = a XOR k. Free in QuickSilver.
 */
gf8_wire_id voleith_gf8_add_xor_const(voleith_gf8_circuit_t *c, gf8_wire_id a,
                                      uint8_t k);

/*
 * Add a GF(2)-linear map gate: output = M · a for 8×8 GF(2) matrix M.
 * M is stored row-major: M[i] is row i (a byte); output bit i =
 * popcount(M[i] & a) mod 2.  Free in QuickSilver.
 *
 * Typical use: basis change (AES ↔ tower field) and Frobenius squaring as
 * an explicit matrix.
 */
gf8_wire_id voleith_gf8_add_linear_map(voleith_gf8_circuit_t *c, gf8_wire_id a,
                                       const uint8_t M[8]);

/*
 * Add a Frobenius squaring gate: output = a² in GF(2⁸). Free in QuickSilver.
 * Equivalent to add_linear_map with the squaring matrix for the AES field,
 * but provided as a dedicated primitive for clarity.
 */
gf8_wire_id voleith_gf8_add_square(voleith_gf8_circuit_t *c, gf8_wire_id a);

/*
 * Add a nibble-select gate: output is the low (which == 0) or high
 * (which == 1) 4-bit nibble of `packed`, as a GF(2⁸) byte whose top 4 bits
 * are zero.  Free GF(2)-linear mask/shift map (no VOLE slot).
 *
 * Used by the norm S-box builders, which pack two adjacent even-round 4-bit
 * subfield norms into one witness byte (FAEST's `(i % 2) * 4` layout).
 */
gf8_wire_id voleith_gf8_add_nibble(voleith_gf8_circuit_t *c, gf8_wire_id packed,
                                   unsigned int which);

/*
 * Add a norm-embed gate: map a 4-bit GF(2⁴) subfield norm (the low nibble of
 * `nib`) to its GF(2⁸) byte c in the AES field, via the fixed GF(2⁴) ⊂ GF(2⁸)
 * basis.  Free GF(2)-linear map (no VOLE slot).
 *
 * The four basis bytes match FAEST's norm-nibble basis (derived from faest-ref
 * bfSSS_beta_squares / bfSSS_beta_cubes; see
 * tools/faest-ref-diagnostics/diag_norm_basis.c), so the committed nibble bits
 * are the same GF(2⁴) coordinates FAEST uses.  The embedded byte feeds the
 * degree-3 norm relation c · a² · a¹⁶ = a (voleith_gf8_assert_product3), with
 * a² and a¹⁶ as free Frobenius images of the S-box input.
 */
gf8_wire_id voleith_gf8_add_norm_embed(voleith_gf8_circuit_t *c,
                                       gf8_wire_id nib);

/*
 * Add a multiplication gate: output = a · b in GF(2⁸).
 * Costs one VOLE slot - the QuickSilver prover commits to the output.
 * VOLE slot index = n_witness + (mul gate count before this call).
 */
gf8_wire_id voleith_gf8_add_mul(voleith_gf8_circuit_t *c, gf8_wire_id a,
                                gf8_wire_id b);

/*
 * Add a 2-to-1 MUX gate: output = (sel == 0x00) ? a : b.
 * Implemented as a XOR (b XOR a), one MUL (sel · diff), and a XOR (a XOR prod).
 * Costs one VOLE slot (the internal multiplication).
 * sel is a wire expected to carry 0x00 or 0x01 - the circuit does not
 * enforce this; the caller must constrain sel to be a bit if required.
 */
gf8_wire_id voleith_gf8_add_mux(voleith_gf8_circuit_t *c, gf8_wire_id a,
                                gf8_wire_id b, gf8_wire_id sel);

/*
 * Add a scale-by-instance gate: output = a · b in GF(2⁸), where b MUST be an
 * instance (public) wire.  Free in QuickSilver: because b is public, x -> b·x
 * is a GF(2)-linear map whose 8×8 matrix the prover/verifier build at runtime,
 * so no VOLE slot is consumed (unlike add_mul).
 *
 * a may be any wire.  If b does not reference an INSTANCE wire, the call fails
 * (returns GF8_WIRE_ID_INVALID and clears voleith_gf8_circuit_ok()); the same
 * kind check is re-run by voleith_gf8_circuit_validate() so a hand-forged wire
 * table cannot route a witness operand through the free path.
 */
gf8_wire_id voleith_gf8_add_scale_instance(voleith_gf8_circuit_t *c,
                                           gf8_wire_id a, gf8_wire_id b);

/*
 * Add a slot-free 2-to-1 MUX gate: output = (sel == 0x00) ? a : b, where sel
 * MUST be an instance (public) wire.  Emitted as a XOR scale_instance(a XOR b,
 * sel); costs zero VOLE slots (the scale gate is free).  If sel does not
 * reference an INSTANCE wire, the call fails like add_scale_instance.
 *
 * As with voleith_gf8_add_mux, sel is expected to carry 0x00 or 0x01 and the
 * circuit does not enforce this: a non-boolean public sel yields the algebraic
 * result a XOR sel·(b XOR a), not a selection.
 */
gf8_wire_id voleith_gf8_add_mux_instance(voleith_gf8_circuit_t *c,
                                         gf8_wire_id a, gf8_wire_id b,
                                         gf8_wire_id sel);

/*
 * Build the 8×8 GF(2) matrix (row-major, as consumed by add_linear_map and the
 * evaluator) of the GF(2⁸)-linear map x -> c·x for a fixed scalar c.  Column j
 * is c·αʲ; out[i] bit j is set iff bit i of c·αʲ is set.  Used by the scale-
 * instance gate's prover/verifier tag propagation, where c is the known public
 * value on the instance operand.
 */
void voleith_gf8_mul_matrix(uint8_t out[8], uint8_t c);

/* ================================================================
 * Constraints - assertions on wire values
 * ================================================================ */

/*
 * Assert that wire w evaluates to 0x00.
 */
void voleith_gf8_assert_zero(voleith_gf8_circuit_t *c, gf8_wire_id w);

/*
 * Assert that wire a equals wire b.
 */
void voleith_gf8_assert_equal(voleith_gf8_circuit_t *c, gf8_wire_id a,
                              gf8_wire_id b);

/*
 * Assert that a · b == c_expected in GF(2⁸).
 * This is the "free" multiplication check: it costs zero VOLE slots because
 * the QuickSilver verifier checks the polynomial relation on existing
 * committed wire values.
 *
 * Primary use: Proposition 6.4 inverse check for the AES S-box.
 *   assert_product(x², x⁻¹, x)   →  x² · x⁻¹ == x
 *   assert_product(x, (x⁻¹)², x⁻¹) → x · (x⁻¹)² == x⁻¹
 */
void voleith_gf8_assert_product(voleith_gf8_circuit_t *c, gf8_wire_id a,
                                gf8_wire_id b, gf8_wire_id c_expected);

/*
 * Assert that a · b · c == d_expected in GF(2⁸): a three-way (degree R = 3)
 * product constraint, costing zero VOLE slots.
 *
 * This is the FAEST v2 norm S-box relation (spec Section 6.2, Fig 6.19).  For
 * an S-box input a with committed inverse norm y = N_{F2⁸/F2⁴}(a⁻¹) = a⁻¹⁷, the
 * check y · a² · a¹⁶ == a certifies y is the inverse norm:
 *   assert_product3(y, a², a¹⁶, a)
 * where a² and a¹⁶ are free Frobenius (squaring) wires of a.
 *
 * The relation has degree 3, but the target d is parked at the top (∆³)
 * coefficient, which is then structurally zero for an honest prover.  Only the
 * three lower coefficients are opened, so the opening count stays d = 2 (same
 * a_tilde width as assert_product) and no VOLEITH_QS_D_MAX change is needed.
 * The primitive is layout-agnostic in a, b, c, d; it imposes no Frobenius
 * relationship among them (that is the caller's circuit's concern).
 */
void voleith_gf8_assert_product3(voleith_gf8_circuit_t *circuit, gf8_wire_id a,
                                 gf8_wire_id b, gf8_wire_id c,
                                 gf8_wire_id d_expected);

/* ================================================================
 * Introspection
 * ================================================================ */

/* Total number of wires (all kinds) */
size_t voleith_gf8_circuit_wire_count(const voleith_gf8_circuit_t *c);

/* Number of witness (private input) wires */
size_t voleith_gf8_circuit_witness_count(const voleith_gf8_circuit_t *c);

/* Number of instance (public input) wires */
size_t voleith_gf8_circuit_instance_count(const voleith_gf8_circuit_t *c);

/* Number of gate (produced, non-input) wires: wire_count minus the WITNESS,
 * INSTANCE, and CONST input wires. */
size_t voleith_gf8_circuit_gate_count(const voleith_gf8_circuit_t *c);

/* Number of MUL gates (add_mul calls; determines VOLE slot count) */
size_t voleith_gf8_circuit_mul_count(const voleith_gf8_circuit_t *c);

/*
 * Maximum QuickSilver constraint degree d in force for this circuit.  The
 * proof opens d+1 coefficients (a_0..a_d) and the QS mask region is d*lambda
 * bits.  All circuits built today are degree-2; d is derived per-circuit and
 * is NOT transmitted on the wire.
 */
unsigned int voleith_gf8_circuit_qs_degree(const voleith_gf8_circuit_t *c);

/* Number of assert_product constraints */
size_t voleith_gf8_circuit_assert_product_count(const voleith_gf8_circuit_t *c);

/* Number of constraints (all kinds) */
size_t voleith_gf8_circuit_constraint_count(const voleith_gf8_circuit_t *c);

/*
 * Number of VOLE slots: ell = n_witness + n_mul.
 * This is the ℓ in the FAEST spec (Table 5.1), measured in GF(2⁸) elements.
 */
size_t voleith_gf8_qs_ell(const voleith_gf8_circuit_t *c);

/*
 * Returns 1 if all builder operations succeeded (no allocation failure),
 * 0 if any operation failed silently.
 */
int voleith_gf8_circuit_ok(const voleith_gf8_circuit_t *c);

/*
 * Validate that every wire-id reference in the circuit is in range.
 *
 * For each gate wire at index i, requires that input wire ids (a, b
 * where applicable) are strictly less than i - the topological-order
 * property the evaluator relies on.  For each constraint, requires
 * referenced wire ids to be less than n_wires.  Primary input wires
 * (WITNESS, INSTANCE, CONST) carry no wire references and are
 * skipped.
 *
 * Returns 0 on success, -1 if any reference is out of range or c is
 * NULL.  Called automatically by the GF(2⁸) prove / verify entry
 * points to fail fast on a malformed circuit (covering L-N2 from the
 * 1.2.0 security review).  Available as a public function so callers
 * that accept circuits from less-trusted sources can validate
 * up-front.
 */
int voleith_gf8_circuit_validate(const voleith_gf8_circuit_t *c);

/*
 * Read-only access to the wire table (for QuickSilver and evaluation).
 * Returns pointer to the internal array of wire_count entries.
 * Valid until the next modification of the circuit.
 */
const gf8_wire_entry_t *
voleith_gf8_circuit_wires(const voleith_gf8_circuit_t *c);

/*
 * Read-only access to the constraint table.
 */
const gf8_constraint_entry_t *
voleith_gf8_circuit_constraints(const voleith_gf8_circuit_t *c);

/*
 * Assert value(A) < value(B) as unsigned width-bit integers.  a_bits and
 * b_bits are MSB-first arrays of `width` bit wires each, every wire holding
 * 0x00 or 0x01 (the builder does not enforce boolean-ness; extract bits via a
 * free linear map so they are auto-boolean).  Zero VOLE slots.  Raises the
 * circuit's QS opening degree to width+1.
 */
void voleith_gf8_assert_lt(voleith_gf8_circuit_t *c, const gf8_wire_id *a_bits,
                           const gf8_wire_id *b_bits, unsigned int width);

/*
 * Read-only access to the less-than constraint table and its shared bit pool
 * (for QuickSilver prove/verify and evaluation).
 */
size_t voleith_gf8_circuit_lt_count(const voleith_gf8_circuit_t *c);
const gf8_lt_entry_t *
voleith_gf8_circuit_lt_constraints(const voleith_gf8_circuit_t *c);
const gf8_wire_id *voleith_gf8_circuit_lt_bits(const voleith_gf8_circuit_t *c);

/*
 * Assert one AES norm S-box round-pair (FAEST paired-round norm; see
 * gf8_norm_entry_t).  Emits the paired-round reset relation for `nst` state
 * bytes as a zero-slot, d = 2 constraint family (qs_degree unchanged).  The
 * isolated per-byte norm relation c * a^2 * a^16 = a is emitted separately by
 * the caller through voleith_gf8_assert_product3.
 *
 *   state_in  nst even-round input state byte wires.
 *   norm      nst embedded subfield-norm wires c = a^-17, one per S-box
 *             (voleith_gf8_add_norm_embed output; the full GF(2^8) norm byte,
 *             not the raw nibble).
 *   s_tilde   nst committed odd-round reset-state wires.
 *   k0        nst round-key wires added in the odd round.
 *   nst       state size in bytes (16 for AES).
 *   last_pair 1 if this pair's second round is the final round (no MixColumns).
 */
void voleith_gf8_assert_aes_norm_roundpair(voleith_gf8_circuit_t *c,
                                           const gf8_wire_id *state_in,
                                           const gf8_wire_id *norm,
                                           const gf8_wire_id *s_tilde,
                                           const gf8_wire_id *k0,
                                           unsigned int nst, int last_pair);

/*
 * Read-only access to the norm round-pair constraint table and its shared wire
 * pool (for QuickSilver prove/verify and evaluation).
 */
size_t voleith_gf8_circuit_norm_count(const voleith_gf8_circuit_t *c);
const gf8_norm_entry_t *
voleith_gf8_circuit_norm_constraints(const voleith_gf8_circuit_t *c);
const gf8_wire_id *
voleith_gf8_circuit_norm_wires(const voleith_gf8_circuit_t *c);

/*
 * Assert one Grostl norm S-box round-pair (FAEST paired-round norm; sibling of
 * voleith_gf8_assert_aes_norm_roundpair for Grostl's linear layer).  Emits the
 * paired-round reset relation for `nst` state bytes as a zero-slot, d = 2
 * constraint family (qs_degree unchanged).  The isolated per-byte norm relation
 * c * a^2 * a^16 = a is emitted separately by the caller via
 * voleith_gf8_assert_product3.
 *
 *   state_in  nst even-round S-box input byte wires (the committed state with
 *             the public even-round AddRoundConstant already XORed in, free).
 *   norm      nst embedded subfield-norm wires c = a^-17, one per S-box.
 *   s_tilde   nst committed odd-round reset-state wires (after odd SubBytes and
 *             ShiftBytes; the caller applies the odd-round MixBytes afterward).
 *   nst       state size in bytes (64 Grostl-256, 128 Grostl-512).
 *   cols      state columns (8 Grostl-256, 16 Grostl-512).
 *   shift     the permutation's ShiftBytes row shifts (8 entries).
 *   is_q      1 for the Q permutation's AddRoundConstant, 0 for P.
 *   odd_round the round number of the pair's odd (second) round, selecting the
 *             public AddRoundConstant added before the odd SubBytes.
 */
void voleith_gf8_assert_grostl_norm_roundpair(
    voleith_gf8_circuit_t *c, const gf8_wire_id *state_in,
    const gf8_wire_id *norm, const gf8_wire_id *s_tilde, unsigned int nst,
    unsigned int cols, const uint8_t shift[8], int is_q,
    unsigned int odd_round);

/*
 * Read-only access to the Grostl norm round-pair constraint table and its
 * shared wire pool (for QuickSilver prove/verify and evaluation).
 */
size_t voleith_gf8_circuit_grostl_norm_count(const voleith_gf8_circuit_t *c);
const gf8_grostl_norm_entry_t *
voleith_gf8_circuit_grostl_norm_constraints(const voleith_gf8_circuit_t *c);
const gf8_wire_id *
voleith_gf8_circuit_grostl_norm_wires(const voleith_gf8_circuit_t *c);

/*
 * Assert the QC-MDPC syndrome relation s = M * e^T (global-bit
 * equality-polynomial form; see gf8_syndrome_entry_t).
 *
 *   idx_bit_wires  t*idx_bits MSB-first index bit wires (index k, bit b at
 *                  idx_bit_wires[k*idx_bits + b]); each wire holds 0x00/0x01
 *                  (extract via a free linear map so they are auto-boolean).
 *   s_bit_wires    p syndrome bit wires (public / instance), s_j at [j].
 *   M              (n0-1) circulant first-row blocks of block_bytes each,
 *                  the buffer voleith_rs_opener_argus_syndrome() consumes;
 *                  copied into the circuit.  NULL only if n0 == 1.
 *
 * block_bytes is derived as ceil(p/8).  Zero VOLE slots.  Raises the circuit's
 * QS opening degree to idx_bits.
 */
void voleith_gf8_assert_syndrome(voleith_gf8_circuit_t *c,
                                 const gf8_wire_id *idx_bit_wires,
                                 const gf8_wire_id *s_bit_wires, uint32_t t,
                                 uint32_t idx_bits, uint32_t p, uint32_t n0,
                                 const uint8_t *M);

/*
 * Read-only access to the syndrome constraint table and its shared bit pool.
 */
size_t voleith_gf8_circuit_syndrome_count(const voleith_gf8_circuit_t *c);
const gf8_syndrome_entry_t *
voleith_gf8_circuit_syndrome_constraints(const voleith_gf8_circuit_t *c);
const gf8_wire_id *
voleith_gf8_circuit_syndrome_bits(const voleith_gf8_circuit_t *c);

/* ================================================================
 * Circuit evaluation (for testing and witness checking)
 *
 * Inputs and outputs are byte arrays: one byte per wire element.
 * ================================================================ */

/*
 * Evaluate the circuit on the given witness and instance byte vectors.
 *
 * witness:    byte array, witness_count bytes (one byte per witness wire,
 *             in declaration order).
 * instance:   byte array, instance_count bytes (one byte per instance wire,
 *             in declaration order).
 * wire_vals:  output array, wire_count bytes (caller allocates).
 *             wire_vals[i] is the GF(2⁸) value of wire i.
 *
 * Returns 1 if all constraints are satisfied, 0 otherwise.
 * Returns -1 on error (NULL circuit or NULL output buffer).
 */
int voleith_gf8_circuit_eval(const voleith_gf8_circuit_t *c,
                             const uint8_t *witness, const uint8_t *instance,
                             uint8_t *wire_vals);

/*
 * Check whether all constraints are satisfied given a wire_vals buffer
 * produced by voleith_gf8_circuit_eval().
 *
 * Returns 1 if all constraints pass, 0 if any fail.
 */
int voleith_gf8_circuit_check_constraints(const voleith_gf8_circuit_t *c,
                                          const uint8_t *wire_vals);

#endif /* VOLEITH_GF8_CIRCUIT_H */
