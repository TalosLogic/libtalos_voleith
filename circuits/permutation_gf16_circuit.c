/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * permutation_gf16_circuit.c - GF(2^16) AS-Waksman secret-permutation gadget
 * (P7 T7.5).  See permutation_gf16_circuit.h for the construction and the gate
 * / switch cost model.
 *
 * The router (voleith_perm_gf16_route) and the circuit builder
 * (voleith_perm_gf16_circuit) are two recursions over the SAME network shape.
 * They MUST visit switches in the identical order so control-bit indices align:
 * at every block both emit, in order,
 *   1. the floor(n/2) input switches (p = 0 .. floor(n/2)-1),
 *   2. the top subnetwork (size ceil(n/2)),
 *   3. the bottom subnetwork (size floor(n/2)),
 *   4. the output switches.
 *
 * CONSTANT-TIME ROUTING.  The permutation is SECRET key material, so the
 * production router (voleith_perm_gf16_route) is constant-time: its memory
 * access pattern and control flow depend only on n (public), never on the
 * permutation values.  A variable-time reference router
 * (voleith_perm_gf16_route_reference) is kept for tests as a routing oracle
 * ONLY and must never run on a secret permutation.
 */

#include "permutation_gf16_circuit.h"

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "util.h" /* voleith_secure_zero */

/*
 * Zero `bytes` of secret-derived working storage, then free it.  The
 * constant-time router's per-block buffers all encode the secret permutation
 * (its inverse, the routing-graph adjacency, the 2-coloring, the sub-
 * permutations), so they are wiped on release per the project rule "zero
 * sensitive material on free".  Safe on NULL.  The zero length is fixed
 * (a function of the public block size n), so it adds no data dependence.
 */
static void
secure_free(void *p, size_t bytes)
{
    if (p != NULL) {
        voleith_secure_zero(p, bytes);
        free(p);
    }
}

size_t
voleith_perm_gf16_n_switches(size_t n)
{
    if (n <= 1)
        return 0;
    if (n == 2)
        return 1;
    size_t nin = n / 2;                      /* input switches */
    size_t nout = (n % 2 == 0) ? (n / 2 - 1) /* even: omit one */
                               : (n / 2);    /* odd: full floor(n/2) */
    return nin + nout + voleith_perm_gf16_n_switches((n + 1) / 2) +
           voleith_perm_gf16_n_switches(n / 2);
}

/* ========================================================================
 * Reference router (VARIABLE-TIME, test oracle only)
 *
 * Derives control bits from a permutation with a data-dependent BFS coloring.
 * Retained purely so tests can cross-check the constant-time router against an
 * independent implementation.  MUST NOT be called on a secret permutation.
 * ======================================================================== */

static int
route_block_reference(const size_t *perm, size_t n, uint16_t *bits, size_t *k)
{
    if (n <= 1)
        return 0;
    if (n == 2) {
        bits[(*k)++] = (uint16_t)(perm[0] & 1u);
        return 0;
    }

    size_t nin = n / 2;
    size_t top_n = (n + 1) / 2;
    size_t bot_n = n / 2;
    int odd = (int)(n & 1u);
    int rc = -1;

    size_t *inv = calloc(n, sizeof(size_t));
    int *color = calloc(n, sizeof(int));
    size_t *top_perm = calloc(top_n ? top_n : 1, sizeof(size_t));
    size_t *bot_perm = calloc(bot_n ? bot_n : 1, sizeof(size_t));
    size_t *queue = calloc(n, sizeof(size_t));
    if (!inv || !color || !top_perm || !bot_perm || !queue)
        goto out;

    for (size_t o = 0; o < n; o++)
        inv[perm[o]] = o;
    for (size_t o = 0; o < n; o++)
        color[o] = -1;

#define SET_COLOR(node, col)                                                   \
    do {                                                                       \
        if (color[(node)] == -1) {                                             \
            color[(node)] = (col);                                             \
            queue[qtail++] = (node);                                           \
        } else if (color[(node)] != (col)) {                                   \
            goto out;                                                          \
        }                                                                      \
    } while (0)

    size_t qhead = 0, qtail = 0;

    if (odd) {
        SET_COLOR(inv[n - 1], 0);
        SET_COLOR(n - 1, 0);
    } else {
        SET_COLOR(0, 0);
        SET_COLOR(1, 1);
    }

    size_t start = 0;
    for (;;) {
        while (qhead < qtail) {
            size_t o = queue[qhead++];
            int oc = color[o];

            size_t op = SIZE_MAX;
            if (odd) {
                if (o != n - 1)
                    op = o ^ 1u;
            } else {
                if (o >= 2)
                    op = o ^ 1u;
            }
            if (op != SIZE_MAX)
                SET_COLOR(op, oc ^ 1);

            size_t a = perm[o];
            if (!(odd && a == n - 1)) {
                size_t ip = inv[a ^ 1u];
                SET_COLOR(ip, oc ^ 1);
            }
        }

        while (start < n && color[start] != -1)
            start++;
        if (start == n)
            break;
        SET_COLOR(start, 0);
    }
#undef SET_COLOR

    for (size_t p = 0; p < nin; p++)
        bits[(*k)++] = (uint16_t)color[inv[2 * p]];

    for (size_t o = 0; o < n; o++) {
        if (color[o] == 0)
            top_perm[o / 2] = perm[o] / 2;
        else
            bot_perm[o / 2] = perm[o] / 2;
    }

    if (route_block_reference(top_perm, top_n, bits, k) != 0)
        goto out;
    if (route_block_reference(bot_perm, bot_n, bits, k) != 0)
        goto out;

    if (odd) {
        for (size_t q = 0; q < n / 2; q++)
            bits[(*k)++] = (uint16_t)color[2 * q];
    } else {
        for (size_t q = 1; q < n / 2; q++)
            bits[(*k)++] = (uint16_t)color[2 * q];
    }

    rc = 0;
out:
    free(inv);
    free(color);
    free(top_perm);
    free(bot_perm);
    free(queue);
    return rc;
}

int
voleith_perm_gf16_route_reference(const size_t *perm, size_t n,
                                  uint16_t *bits_out)
{
    if (!perm || n == 0 || !bits_out)
        return -1;

    uint8_t *seen = calloc(n, 1);
    if (!seen)
        return -1;
    for (size_t i = 0; i < n; i++) {
        if (perm[i] >= n || seen[perm[i]]) {
            free(seen);
            return -1;
        }
        seen[perm[i]] = 1;
    }
    free(seen);

    size_t k = 0;
    return route_block_reference(perm, n, bits_out, &k);
}

/* ========================================================================
 * Constant-time primitives
 *
 * Every access that would otherwise use a secret value as an index is done as
 * a masked scan over the whole array, so the memory-access pattern is fixed.
 * ======================================================================== */

static inline size_t
ct_barrier_sz(size_t x)
{
#if defined(__GNUC__) || defined(__clang__)
    __asm__ volatile("" : "+r"(x));
    return x;
#else
    volatile size_t v = x;
    return v;
#endif
}

/* ~0 if a == b, else 0. */
static inline size_t
ct_eq(size_t a, size_t b)
{
    size_t d = a ^ b;
    size_t nz = (d | (size_t)(0 - d)) >> (sizeof(size_t) * 8 - 1);
    return ct_barrier_sz((size_t)0 - (nz ^ (size_t)1));
}

/* ~0 if a < b, else 0.  The unsigned comparison compiles to a branchless
 * set-on-less-than on mainstream ISAs; the barrier keeps the compiler from
 * later re-deriving a data-dependent branch from the resulting mask. */
static inline size_t
ct_lt(size_t a, size_t b)
{
    size_t r = (size_t)(a < b); /* 0 or 1 */
    return ct_barrier_sz((size_t)0 - r);
}

static inline size_t
ct_min(size_t a, size_t b)
{
    size_t m = ct_lt(a, b); /* ~0 if a < b */
    return (a & m) | (b & ~m);
}

/* Select b if sel (0 or 1) else a, for size_t. */
static inline size_t
ct_sel_sz(size_t sel, size_t a, size_t b)
{
    size_t m = (size_t)0 - (sel & 1u);
    return (a & ~m) | (b & m);
}

/* Read arr[idx] (idx secret) by masked scan over count entries. */
static inline size_t
ct_gather(const size_t *arr, size_t count, size_t idx)
{
    size_t r = 0;
    for (size_t j = 0; j < count; j++)
        r |= arr[j] & ct_eq(idx, j);
    return r;
}

/*
 * Constant-time check that perm is a permutation of [0, n): every entry is in
 * range and each target occurs exactly once.  No secret-indexed access and no
 * secret-dependent branch: the range check ORs a mask across all entries, and
 * each target's occurrence count is accumulated by a masked scan.  O(n^2), in
 * line with the router's cost.  Returns 0 if valid, -1 otherwise.
 */
static int
voleith_perm_is_valid_ct(const size_t *perm, size_t n)
{
    size_t bad = 0;
    for (size_t i = 0; i < n; i++)
        bad |= ~ct_lt(perm[i], n); /* 0 iff perm[i] < n */
    for (size_t target = 0; target < n; target++) {
        size_t cnt = 0;
        for (size_t i = 0; i < n; i++)
            cnt += (ct_eq(perm[i], target) & 1u);
        bad |= ~ct_eq(cnt, 1u); /* 0 iff target appears exactly once */
    }
    return ct_barrier_sz(bad) == 0 ? 0 : -1;
}

/* ========================================================================
 * Constant-time router
 * ======================================================================== */

/* Number of pointer-doubling rounds to cover a walk of up to `count` states:
 * smallest r with 2^r >= count. */
static unsigned
doubling_rounds(size_t count)
{
    unsigned r = 0;
    size_t reach = 1;
    while (reach < count) {
        reach <<= 1;
        r++;
    }
    return r + 1; /* one extra round: cheap insurance against off-by-one */
}

/*
 * Constant-time coloring of the routing graph for a block of size n (n >= 3).
 * On return color[o] in {0,1} is the subnetwork (0 top, 1 bottom) for output o.
 * Returns 0 on success, -1 on allocation failure.
 *
 * Graph: output o has an output-partner edge to o^1 (except the anchored /
 * leftover boundary) and an input-partner edge to inv[perm[o]^1] (except the
 * odd-n leftover input).  A proper 2-coloring assigns opposite colors across
 * every edge; anchors pin the colors forced by the omitted / straight wires.
 */
static int
color_block_ct(const size_t *perm, size_t n, size_t *color_out)
{
    int odd = (int)(n & 1u);
    int rc = -1;

    size_t *inv = calloc(n, sizeof(size_t));
    size_t *opn = calloc(n, sizeof(size_t)); /* output-partner node */
    size_t *op_real = calloc(n, sizeof(size_t));
    size_t *ipn = calloc(n, sizeof(size_t)); /* input-partner node */
    size_t *ip_real = calloc(n, sizeof(size_t));
    size_t two_n = 2 * n;
    size_t *nxt = calloc(two_n, sizeof(size_t));
    size_t *cross =
        calloc(two_n, sizeof(size_t)); /* 1 iff a real edge crossed */
    size_t *jmp = calloc(two_n, sizeof(size_t));
    size_t *minnode =
        calloc(two_n, sizeof(size_t)); /* cycle-min node (comp id) */
    size_t *minstate =
        calloc(two_n, sizeof(size_t)); /* cycle-min state (head) */
    size_t *par = calloc(two_n, sizeof(size_t));
    size_t *jmp2 = calloc(two_n, sizeof(size_t));
    size_t *base = calloc(n, sizeof(size_t));
    size_t *tmp_a =
        calloc(two_n, sizeof(size_t)); /* double-buffer for doubling */
    size_t *tmp_b = calloc(two_n, sizeof(size_t));
    size_t *tmp_c = calloc(two_n, sizeof(size_t));
    if (!inv || !opn || !op_real || !ipn || !ip_real || !nxt || !cross ||
        !jmp || !minnode || !minstate || !par || !jmp2 || !base || !tmp_a ||
        !tmp_b || !tmp_c)
        goto out;

    /* inv[a] = o with perm[o] == a, built as an oblivious scatter. */
    for (size_t a = 0; a < n; a++) {
        size_t v = 0;
        for (size_t o = 0; o < n; o++)
            v |= o & ct_eq(perm[o], a);
        inv[a] = v;
    }

    /* Output-partner (public: depends only on n). */
    for (size_t o = 0; o < n; o++) {
        size_t real;
        if (odd)
            real =
                ct_eq(o, n - 1) ^ (size_t) ~(size_t)0; /* real iff o != n-1 */
        else
            real = ct_lt(o, 2) ^ (size_t) ~(size_t)0; /* real iff o >= 2 */
        op_real[o] = real & 1u;
        opn[o] = ct_sel_sz(op_real[o], o /* self */, o ^ 1u);
    }

    /* Input-partner: real iff perm[o] has an input-switch partner, i.e.
     * perm[o] < 2*floor(n/2).  ipn[o] = inv[perm[o]^1] when real, else self. */
    {
        size_t paired_inputs = 2 * (n / 2);
        for (size_t o = 0; o < n; o++) {
            size_t real = ct_lt(perm[o], paired_inputs) & 1u;
            size_t partner = ct_gather(inv, n, perm[o] ^ 1u);
            ip_real[o] = real;
            ipn[o] = ct_sel_sz(real, o /* self */, partner);
        }
    }

    /*
     * State graph: state s = 2*o + d.  d = 0 means "next hop leaves via the
     * output-partner edge"; d = 1 means "leaves via the input-partner edge".
     * At a missing (self) edge the walk reflects (flips d) without crossing a
     * real edge.  next is a permutation of the 2n states whose cycles are the
     * graph components (each traversed in both directions).
     */
    for (size_t o = 0; o < n; o++) {
        /* d = 0: leave via output edge. */
        {
            size_t s = 2 * o;
            size_t viareal = op_real[o];
            size_t target_real =
                2 * opn[o] + 1;             /* arrived via op -> leave ip */
            size_t target_refl = 2 * o + 1; /* reflect */
            nxt[s] = ct_sel_sz(viareal, target_refl, target_real);
            cross[s] = viareal;
        }
        /* d = 1: leave via input edge. */
        {
            size_t s = 2 * o + 1;
            size_t viareal = ip_real[o];
            size_t target_real = 2 * ipn[o]; /* arrived via ip -> leave op */
            size_t target_refl = 2 * o;      /* reflect */
            nxt[s] = ct_sel_sz(viareal, target_refl, target_real);
            cross[s] = viareal;
        }
    }

    /* Per state-cycle: minimum node index (component id) AND minimum state
     * index (the head that anchors the parity pass), via pointer doubling.
     * A graph-cycle component splits into two state-cycles (its forward and
     * reverse Euler tours); using the min STATE as head guarantees a head in
     * each tour, and that state's node is always the component-min node, so the
     * parity reference stays consistent across the whole component. */
    for (size_t s = 0; s < two_n; s++) {
        jmp[s] = nxt[s];
        minnode[s] = s / 2;
        minstate[s] = s;
    }
    {
        unsigned rounds = doubling_rounds(two_n);
        for (unsigned r = 0; r < rounds; r++) {
            /* Double-buffer: new values are computed from the round's OLD
             * arrays, then swapped in. */
            for (size_t s = 0; s < two_n; s++) {
                size_t j = jmp[s];
                tmp_a[s] = ct_min(minnode[s], ct_gather(minnode, two_n, j));
                tmp_b[s] = ct_gather(jmp, two_n, j);
                tmp_c[s] = ct_min(minstate[s], ct_gather(minstate, two_n, j));
            }
            memcpy(minnode, tmp_a, two_n * sizeof(size_t));
            memcpy(jmp, tmp_b, two_n * sizeof(size_t));
            memcpy(minstate, tmp_c, two_n * sizeof(size_t));
        }
    }

    /* Parity from each state to its cycle's head state (min node, d = 0).
     * Head is a fixed point so accumulation converges to it; even cycle parity
     * makes the direction irrelevant. */
    for (size_t s = 0; s < two_n; s++) {
        size_t is_head = ct_eq(s, minstate[s]); /* unique min state per cycle */
        jmp2[s] = ct_sel_sz(is_head & 1u, nxt[s], s);
        par[s] = ct_sel_sz(is_head & 1u, cross[s], 0);
    }
    {
        unsigned rounds = doubling_rounds(two_n);
        for (unsigned r = 0; r < rounds; r++) {
            for (size_t s = 0; s < two_n; s++) {
                size_t j = jmp2[s];
                tmp_a[s] = par[s] ^ ct_gather(par, two_n, j);
                tmp_b[s] = ct_gather(jmp2, two_n, j);
            }
            memcpy(par, tmp_a, two_n * sizeof(size_t));
            memcpy(jmp2, tmp_b, two_n * sizeof(size_t));
        }
    }

    for (size_t o = 0; o < n; o++)
        base[o] = par[2 * o] & 1u;

    /*
     * Anchor flips.  Up to two anchors force specific colors; flip the whole
     * component (identified by its min node index) so the anchor matches.
     *   even n: (0 -> 0), (1 -> 1)
     *   odd  n: (n-1 -> 0), (inv[n-1] -> 0)
     */
    {
        size_t a0 = ct_sel_sz((size_t)odd, 0, n - 1);
        size_t req0 = 0;
        size_t a1 = ct_sel_sz((size_t)odd, 1, inv[n - 1]);
        size_t req1 = (size_t)(odd ? 0 : 1);

        size_t comp0 = minnode[2 * a0];
        size_t comp1 = ct_gather(minnode, two_n, 2 * a1);
        size_t f0 = base[a0] ^ req0;
        size_t f1 = ct_gather(base, n, a1) ^ req1;

        for (size_t o = 0; o < n; o++) {
            size_t comp_o = minnode[2 * o];
            size_t m0 = ct_eq(comp_o, comp0) & 1u;
            size_t m1 = ct_eq(comp_o, comp1) & 1u;
            size_t flip = ct_sel_sz(m0, ct_sel_sz(m1, 0, f1), f0);
            color_out[o] = (base[o] ^ flip) & 1u;
        }
    }

    rc = 0;
out:
    secure_free(inv, n * sizeof(size_t));
    secure_free(opn, n * sizeof(size_t));
    secure_free(op_real, n * sizeof(size_t));
    secure_free(ipn, n * sizeof(size_t));
    secure_free(ip_real, n * sizeof(size_t));
    secure_free(nxt, two_n * sizeof(size_t));
    secure_free(cross, two_n * sizeof(size_t));
    secure_free(jmp, two_n * sizeof(size_t));
    secure_free(minnode, two_n * sizeof(size_t));
    secure_free(minstate, two_n * sizeof(size_t));
    secure_free(par, two_n * sizeof(size_t));
    secure_free(jmp2, two_n * sizeof(size_t));
    secure_free(base, n * sizeof(size_t));
    secure_free(tmp_a, two_n * sizeof(size_t));
    secure_free(tmp_b, two_n * sizeof(size_t));
    secure_free(tmp_c, two_n * sizeof(size_t));
    return rc;
}

static int
route_block_ct(const size_t *perm, size_t n, uint16_t *bits, size_t *k)
{
    if (n <= 1)
        return 0;
    if (n == 2) {
        /* Straight iff perm[0] == 0; oblivious (no secret index/branch). */
        bits[(*k)++] = (uint16_t)(perm[0] & 1u);
        return 0;
    }

    size_t nin = n / 2;
    size_t top_n = (n + 1) / 2;
    size_t bot_n = n / 2;
    int odd = (int)(n & 1u);
    int rc = -1;

    size_t *color = calloc(n, sizeof(size_t));
    size_t *icolor = calloc(n, sizeof(size_t)); /* icolor[a] = color[inv[a]] */
    size_t *top_perm = calloc(top_n, sizeof(size_t));
    size_t *bot_perm = calloc(bot_n, sizeof(size_t));
    if (!color || !icolor || !top_perm || !bot_perm)
        goto out;

    if (color_block_ct(perm, n, color) != 0)
        goto out;

    /* icolor[a] = color of the output fed by input a, via oblivious scatter:
     * icolor[perm[o]] = color[o]. */
    for (size_t a = 0; a < n; a++) {
        size_t v = 0;
        for (size_t o = 0; o < n; o++)
            v |= color[o] & ct_eq(perm[o], a);
        icolor[a] = v;
    }

    /* Input switch bits (p order): crosses iff input 2p routes to bottom. */
    for (size_t p = 0; p < nin; p++)
        bits[(*k)++] = (uint16_t)(icolor[2 * p] & 1u);

    /*
     * Sub-permutations.  Each output-switch pair (2j, 2j+1) has opposite
     * colors; the color-0 element joins the top subnetwork, color-1 the
     * bottom.  Indices are public; the color test is a masked select.
     */
    for (size_t j = 0; j < n / 2; j++) {
        size_t c0 = color[2 * j] & 1u; /* 1 iff output 2j goes bottom */
        size_t top_val = ct_sel_sz(c0, perm[2 * j] / 2, perm[2 * j + 1] / 2);
        size_t bot_val = ct_sel_sz(c0, perm[2 * j + 1] / 2, perm[2 * j] / 2);
        top_perm[j] = top_val;
        bot_perm[j] = bot_val;
    }
    if (odd)
        top_perm[top_n - 1] = perm[n - 1] / 2; /* leftover output -> top */

    if (route_block_ct(top_perm, top_n, bits, k) != 0)
        goto out;
    if (route_block_ct(bot_perm, bot_n, bits, k) != 0)
        goto out;

    /* Output switch bits: even n omits q == 0. */
    if (odd) {
        for (size_t q = 0; q < n / 2; q++)
            bits[(*k)++] = (uint16_t)(color[2 * q] & 1u);
    } else {
        for (size_t q = 1; q < n / 2; q++)
            bits[(*k)++] = (uint16_t)(color[2 * q] & 1u);
    }

    rc = 0;
out:
    secure_free(color, n * sizeof(size_t));
    secure_free(icolor, n * sizeof(size_t));
    secure_free(top_perm, top_n * sizeof(size_t));
    secure_free(bot_perm, bot_n * sizeof(size_t));
    return rc;
}

int
voleith_perm_gf16_route(const size_t *perm, size_t n, uint16_t *bits_out)
{
    if (!perm || n == 0 || !bits_out)
        return -1;

    /* Validate perm is a permutation of [0, n) in constant time: no secret
     * value is used as a memory index and no branch depends on the secret
     * permutation, so the reject path leaks nothing about a valid table. */
    if (voleith_perm_is_valid_ct(perm, n) != 0)
        return -1;

    size_t k = 0;
    return route_block_ct(perm, n, bits_out, &k);
}

/* ========================================================================
 * Circuit builder: emit the same network over wire ids.
 * ======================================================================== */

/* One 2x2 switch: out0 = MUX(a, b, s); out1 = a XOR b XOR out0.  Booleanity of
 * s is enforced (free).  Costs one mul gate. */
static void
emit_switch(voleith_gf16_circuit_t *c, gf16_wire_id a, gf16_wire_id b,
            gf16_wire_id s, gf16_wire_id *out0, gf16_wire_id *out1)
{
    voleith_gf16_assert_product(c, s, s, s); /* s in {0, 1} */
    gf16_wire_id o0 = voleith_gf16_add_mux(c, a, b, s);
    *out0 = o0;
    *out1 = voleith_gf16_add_xor(c, voleith_gf16_add_xor(c, a, b), o0);
}

/*
 * Build one block over wire ids.  in[0..n-1] are the block inputs; out[0..n-1]
 * are filled with the block outputs.  Consumes ctrl[] starting at *k in the
 * same order route_block emits bits.
 */
static void
build_block(voleith_gf16_circuit_t *c, const gf16_wire_id *in,
            gf16_wire_id *out, const gf16_wire_id *ctrl, size_t *k, size_t n)
{
    if (n == 1) {
        out[0] = in[0];
        return;
    }
    if (n == 2) {
        emit_switch(c, in[0], in[1], ctrl[(*k)++], &out[0], &out[1]);
        return;
    }

    size_t nin = n / 2;
    size_t top_n = (n + 1) / 2;
    size_t bot_n = n / 2;
    int odd = (int)(n & 1u);

    gf16_wire_id *top_in = calloc(top_n, sizeof(gf16_wire_id));
    gf16_wire_id *bot_in = calloc(bot_n, sizeof(gf16_wire_id));
    gf16_wire_id *top_out = calloc(top_n, sizeof(gf16_wire_id));
    gf16_wire_id *bot_out = calloc(bot_n, sizeof(gf16_wire_id));
    if (!top_in || !bot_in || !top_out || !bot_out)
        goto out; /* allocation failure surfaces via circuit_ok() downstream */

    for (size_t p = 0; p < nin; p++)
        emit_switch(c, in[2 * p], in[2 * p + 1], ctrl[(*k)++], &top_in[p],
                    &bot_in[p]);
    if (odd)
        top_in[top_n - 1] = in[n - 1];

    build_block(c, top_in, top_out, ctrl, k, top_n);
    build_block(c, bot_in, bot_out, ctrl, k, bot_n);

    if (odd) {
        for (size_t q = 0; q < n / 2; q++)
            emit_switch(c, top_out[q], bot_out[q], ctrl[(*k)++], &out[2 * q],
                        &out[2 * q + 1]);
        out[n - 1] = top_out[top_n - 1];
    } else {
        out[0] = top_out[0];
        out[1] = bot_out[0];
        for (size_t q = 1; q < n / 2; q++)
            emit_switch(c, top_out[q], bot_out[q], ctrl[(*k)++], &out[2 * q],
                        &out[2 * q + 1]);
    }

out:
    free(top_in);
    free(bot_in);
    free(top_out);
    free(bot_out);
}

void
voleith_perm_gf16_circuit(voleith_gf16_circuit_t *c,
                          const gf16_wire_id *in_wires,
                          const gf16_wire_id *ctrl_wires,
                          gf16_wire_id *out_wires, size_t n)
{
    if (!c || !in_wires || !out_wires || n == 0)
        return;
    if (n > 1 && !ctrl_wires)
        return;

    size_t k = 0;
    build_block(c, in_wires, out_wires, ctrl_wires, &k, n);
}
