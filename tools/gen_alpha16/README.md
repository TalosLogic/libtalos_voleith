# gen_alpha16 - GF(2^16) subfield-embedding table emitter

`gen_alpha16` generates the **alpha16** tables: the powers `beta^1 .. beta^15`
of a root `beta` of the canonical GF(2^16) defining polynomial

```
m16 = x^16 + x^12 + x^3 + x + 1        (0x1100B)
```

embedded in GF(2^lambda) for `lambda in {128, 192, 256}`. `beta^0 = 1` is
implicit, so each table has 15 entries (mirroring the gf8 `alpha` tables,
which carry `alpha^1 .. alpha^7`). They let the gf16 element-level prover
embed a GF(2^16) value `v` into GF(2^lambda):

```
embed(v) = sum_i v_bit_i * beta^i.
```

It is run by hand, once, when the tables need to be (re)generated. Redirect
stdout to a paste-ready block for `core/field.c`, placed alongside the
existing `gf{128,192,256}_alpha` tables. **The oracle (SageMath) is never
linked into libtalos_voleith or its test suite**: same posture as the
faest-ref, Jerasure, and GF-Complete oracles.

## Why two generators

`gen_alpha16.c` is the **canonical** generator. It links the project's own
`core/field.c` GF(2^lambda) arithmetic, so the emitted limb encoding matches
the library *by construction*: there is no second implementation of the field
to disagree about the modulus or the bit order. It needs no external
dependency and never factors `2^lambda - 1` (only `65535 = 3 * 5 * 17 * 257`,
which is trivial).

`crosscheck.sage` is an **independent oracle**. It recomputes the same tables
from first principles in SageMath and prints them in the identical format, so
a plain `diff` of the two outputs is the agreement check. Because Sage builds
GF(2^lambda) from scratch, the two only match when Sage uses the library's
exact reduction polynomial and encoding (documented below). The ultimate
correctness guarantee is the **T5.2 homomorphism test** against
`core/field16.c`, not the Sage byte-match; the cross-check is a strong
secondary signal that the derivation is right.

## The construction

GF(2^16) embeds in GF(2^lambda) because `16 | lambda` for all three sizes
(128/16 = 8, 192/16 = 12, 256/16 = 16). The subfield is the fixed field of
the Frobenius `x -> x^(2^16)`, i.e. the 2^16 elements satisfying
`x^(2^16) = x`.

For each lambda the C generator:

1. **Projects** random GF(2^lambda) elements into the subfield via the
   relative trace `P(x) = sum_{i=0}^{m-1} x^(2^(16 i))`, `m = lambda / 16`.
   `P` is GF(2^16)-linear and surjective onto the subfield.
2. **Finds a generator** `g` of the order-65535 subfield multiplicative group
   (a nonzero subfield element `s` with `s^(65535/p) != 1` for every prime
   `p | 65535`). A random nonzero subfield element qualifies with probability
   `phi(65535)/65535 ~ 0.43`, so this is immediate.
3. **Enumerates** the 65535 nonzero subfield elements `g^0 .. g^65534`,
   collects the 16 roots of `m16`, and selects `beta` by the deterministic
   root rule below. Zero is never a root (`m16(0) = 1`).
4. **Emits** `beta^1 .. beta^15`.

The set of 16 roots is fixed (the roots of `m16` in the field); `g` only
fixes the enumeration order, so the chosen `beta` is independent of `g`.

### Deterministic root rule

`m16` has 16 roots in GF(2^16) (the conjugates). We pin one:

> **`beta` is the root with the smallest encoding**, where an element's
> encoding is its `to_bytes()` little-endian serialization read as an unsigned
> integer (byte 0 least significant; equivalently bit `i` is the coefficient
> of `x^i` in the polynomial basis).

Any root of `m16` defines a valid field embedding GF(2^16) -> GF(2^lambda);
the rule just makes the choice reproducible. The three lambdas are chosen
independently (like the gf8 `alpha` tables), so the embeddings need not be
mutually compatible; each is validated as a homomorphism on its own in T5.2.

## Building and running the canonical generator

The tool links `core/field.c`, the scalar field backend, and the CPU-dispatch
sources. On x86_64:

```sh
cd tools/gen_alpha16
gcc -O2 -I../../core \
    gen_alpha16.c \
    ../../core/field.c ../../core/field_scalar.c \
    ../../core/cpu.c ../../core/cpu_x86.c \
    -o gen_alpha16
VOLEITH_QUIET=1 ./gen_alpha16 > alpha16_tables.inc   # progress on stderr
```

On aarch64 swap `core/cpu_x86.c` for `core/cpu_aarch64.c`; on other targets
use `core/cpu_generic.c`. Only the **scalar** backend is needed: the library
gates its CLMUL/PMULL backends behind `-DVOLEITH_CLMUL` / `-DVOLEITH_PMULL`,
so without those defines the dispatch runs the scalar fallback (hence the
`field_scalar.c` link and the harmless "running on scalar fallback" notice
that `VOLEITH_QUIET=1` suppresses). The field arithmetic result is identical
across backends, so the emitted tables do not depend on the host.

Paste the three `gf{128,192,256}_alpha16[15]` blocks into `core/field.c`
beside the existing `gf{128,192,256}_alpha` tables.

## Running the cross-check

```sh
sage crosscheck.sage > sage_tables.txt
diff <(grep -oE '0x[0-9a-f]{16}' sage_tables.txt) \
     <(grep -oE '0x[0-9a-f]{16}' alpha16_tables.inc)
```

Compare the **constants**, not the lines: the C emitter wraps the 192- and
256-bit entries across two lines to match the `field.c` style, while the Sage
emitter prints one entry per line, so a line-wise `diff` reports spurious
differences even when every value agrees. Extracting the `0x...` limbs first
(135 of them: 15 entries x (2 + 3 + 4) limbs) sidesteps that. A clean `diff`
means the canonical generator and the independent Sage oracle agree. If they diverge, the first suspect is the Sage GF(2^lambda) modulus or
bit order not matching the library (see the matching conditions at the top of
`crosscheck.sage`); the C output is authoritative because it uses the
library's own arithmetic.

## Acceptance (T5.1)

- The C generator reports 16 roots for each lambda and emits 3 tables.
- The Sage cross-check produces byte-identical tables.
- The T5.2 homomorphism validation passes against `core/field16.c`.
- Tables checked into `core/field.c`.
