/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * test_bristol_parser.c - Tests for the Bristol Fashion circuit parser.
 *
 * Tests:
 *   Group A: Synthetic round-trip (XOR + AND + INV + EQW circuit, eval check).
 *   Group B: Per-gate sweep (one minimal circuit per supported gate type).
 *   Group C: Error-code coverage (one malformed buffer per error code).
 *   Group D: AES-128 Bristol file (AND-gate count, FIPS-197 App B eval parity).
 *   Group E: AES-256 Bristol file (AND-gate count, FIPS-197 App C.3 eval parity).
 *   Group F: Prove/verify roundtrip (parsed AES-128, FIPS-197 App B, em_128f).
 *   Group G: neg64 Bristol file (real-circuit EQW exercise, two's complement).
 *   Group H: mult2_64 Bristol file (n_output_values > 1, 128-bit product split).
 */

#include "bristol.h"
#include "circuit.h"
#include "proof.h"

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int test_count = 0;
static int pass_count = 0;

static void
check(const char *name, int cond)
{
    test_count++;
    if (cond) {
        pass_count++;
    } else {
        printf("  FAIL: %s\n", name);
    }
}

/* Return bit w from a wire_vals (or similar bit-packed) array. */
static uint8_t
bit_at(const uint8_t *arr, wire_id w)
{
    return (arr[w / 8] >> (w % 8)) & 1;
}

/* ================================================================
 * Group A: Synthetic round-trip.
 *
 * Six-wire circuit:
 *   Wire 0: input a (1-bit witness, input value 0)
 *   Wire 1: input b (1-bit instance, input value 1)
 *   Wire 2: a XOR b
 *   Wire 3: a AND b
 *   Wire 4: NOT a
 *   Wire 5: alias of wire 1 (EQW)
 *   Output wires: 2,3,4,5 (last 4 of 6)
 * ================================================================ */

static const char ROUND_TRIP_BUF[] = "4 6\n"
                                     "2 1 1\n"
                                     "1 4\n"
                                     "\n"
                                     "2 1 0 1 2 XOR\n"
                                     "2 1 0 1 3 AND\n"
                                     "1 1 0 4 INV\n"
                                     "1 1 1 5 EQW\n";

static void
test_round_trip(void)
{
    voleith_bristol_input_role_t roles[2];
    voleith_bristol_config_t cfg;
    voleith_bristol_parsed_t p;
    uint8_t witness[1], instance[1], wire_vals[8];
    int r;

    roles[0] = VOLEITH_BRISTOL_WITNESS;
    roles[1] = VOLEITH_BRISTOL_INSTANCE;
    cfg.input_roles = roles;
    cfg.n_input_roles = 2;

    memset(&p, 0, sizeof(p));
    r = voleith_bristol_parse_buffer(&p, ROUND_TRIP_BUF,
                                     sizeof(ROUND_TRIP_BUF) - 1, &cfg);
    check("round_trip: parse ok", r == 0);
    if (r != 0)
        return;

    check("round_trip: n_input_wires", p.n_input_wires == 2);
    check("round_trip: n_output_wires", p.n_output_wires == 4);
    check("round_trip: n_input_values", p.n_input_values == 2);
    check("round_trip: n_output_values", p.n_output_values == 1);
    check("round_trip: input_value_sizes[0]", p.input_value_sizes[0] == 1);
    check("round_trip: input_value_sizes[1]", p.input_value_sizes[1] == 1);
    check("round_trip: output_value_sizes[0]", p.output_value_sizes[0] == 4);
    check("round_trip: and_gate_count",
          voleith_circuit_and_gate_count(p.circuit) == 1);
    check("round_trip: witness_count",
          voleith_circuit_witness_count(p.circuit) == 1);
    check("round_trip: instance_count",
          voleith_circuit_instance_count(p.circuit) == 1);

    /* Eval with a=1 (witness bit 0) and b=0 (instance bit 0). */
    witness[0] = 0x01;
    instance[0] = 0x00;
    memset(wire_vals, 0, sizeof(wire_vals));
    r = voleith_circuit_eval(p.circuit, witness, instance, wire_vals);
    check("round_trip: eval ok", r == 1);

    /* a XOR b = 1 XOR 0 = 1 */
    check("round_trip: out[0] XOR", bit_at(wire_vals, p.output_wires[0]) == 1);
    /* a AND b = 1 AND 0 = 0 */
    check("round_trip: out[1] AND", bit_at(wire_vals, p.output_wires[1]) == 0);
    /* NOT a = NOT 1 = 0 */
    check("round_trip: out[2] INV", bit_at(wire_vals, p.output_wires[2]) == 0);
    /* EQW(b) = b = 0 */
    check("round_trip: out[3] EQW", bit_at(wire_vals, p.output_wires[3]) == 0);

    voleith_bristol_parsed_free(&p);
}

/* ================================================================
 * Group B: Per-gate sweep.
 * ================================================================ */

/*
 * Evaluate a circuit that has exactly one 2-bit witness input and one
 * 1-bit output.  a is bit 0 of witness, b is bit 1.
 */
static uint8_t
eval_2w1o(const voleith_circuit_t *c, const wire_id *out_wires, uint8_t a,
          uint8_t b)
{
    uint8_t witness[1], wire_vals[8];

    witness[0] = (uint8_t)(a | (uint8_t)(b << 1));
    memset(wire_vals, 0, sizeof(wire_vals));
    if (voleith_circuit_eval(c, witness, NULL, wire_vals) < 0)
        return 0xFF;
    return bit_at(wire_vals, out_wires[0]);
}

/*
 * Evaluate a circuit that has exactly one 1-bit witness input and one
 * 1-bit output.
 */
static uint8_t
eval_1w1o(const voleith_circuit_t *c, const wire_id *out_wires, uint8_t a)
{
    uint8_t witness[1], wire_vals[8];

    witness[0] = a;
    memset(wire_vals, 0, sizeof(wire_vals));
    if (voleith_circuit_eval(c, witness, NULL, wire_vals) < 0)
        return 0xFF;
    return bit_at(wire_vals, out_wires[0]);
}

/* Evaluate a circuit with no inputs (constant output). */
static uint8_t
eval_0io(const voleith_circuit_t *c, const wire_id *out_wires)
{
    uint8_t wire_vals[8];

    memset(wire_vals, 0, sizeof(wire_vals));
    if (voleith_circuit_eval(c, NULL, NULL, wire_vals) < 0)
        return 0xFF;
    return bit_at(wire_vals, out_wires[0]);
}

static void
test_gate_sweep(void)
{
    /* One input value (2 bits, witness). Used for binary gates. */
    static const char XOR_BUF[] = "1 3\n"
                                  "1 2\n"
                                  "1 1\n"
                                  "\n"
                                  "2 1 0 1 2 XOR\n";
    static const char AND_BUF[] = "1 3\n"
                                  "1 2\n"
                                  "1 1\n"
                                  "\n"
                                  "2 1 0 1 2 AND\n";
    /* One input value (1 bit, witness). Used for unary gates and EQW. */
    static const char INV_BUF[] = "1 2\n"
                                  "1 1\n"
                                  "1 1\n"
                                  "\n"
                                  "1 1 0 1 INV\n";
    static const char EQW_BUF[] = "1 2\n"
                                  "1 1\n"
                                  "1 1\n"
                                  "\n"
                                  "1 1 0 1 EQW\n";
    /* No input values. Used for EQ constant-injection. */
    static const char EQ0_BUF[] = "1 1\n"
                                  "0\n"
                                  "1 1\n"
                                  "\n"
                                  "1 1 0 0 EQ\n";
    static const char EQ1_BUF[] = "1 1\n"
                                  "0\n"
                                  "1 1\n"
                                  "\n"
                                  "1 1 1 0 EQ\n";

    voleith_bristol_input_role_t role_w = VOLEITH_BRISTOL_WITNESS;
    voleith_bristol_config_t cfg_1v = {&role_w, 1};
    voleith_bristol_config_t cfg_0v = {NULL, 0};
    voleith_bristol_parsed_t p;
    int r;

    memset(&p, 0, sizeof(p));

    /* XOR: out = a XOR b */
    r = voleith_bristol_parse_buffer(&p, XOR_BUF, 0, &cfg_1v);
    check("gate_sweep: XOR(1,0)=1",
          r == 0 && eval_2w1o(p.circuit, p.output_wires, 1, 0) == 1);
    check("gate_sweep: XOR(1,1)=0",
          r == 0 && eval_2w1o(p.circuit, p.output_wires, 1, 1) == 0);
    if (r == 0)
        voleith_bristol_parsed_free(&p);

    /* AND: out = a AND b */
    r = voleith_bristol_parse_buffer(&p, AND_BUF, 0, &cfg_1v);
    check("gate_sweep: AND(1,0)=0",
          r == 0 && eval_2w1o(p.circuit, p.output_wires, 1, 0) == 0);
    check("gate_sweep: AND(1,1)=1",
          r == 0 && eval_2w1o(p.circuit, p.output_wires, 1, 1) == 1);
    if (r == 0)
        voleith_bristol_parsed_free(&p);

    /* INV: out = NOT a */
    r = voleith_bristol_parse_buffer(&p, INV_BUF, 0, &cfg_1v);
    check("gate_sweep: INV(0)=1",
          r == 0 && eval_1w1o(p.circuit, p.output_wires, 0) == 1);
    check("gate_sweep: INV(1)=0",
          r == 0 && eval_1w1o(p.circuit, p.output_wires, 1) == 0);
    if (r == 0)
        voleith_bristol_parsed_free(&p);

    /* EQ constant 0 */
    r = voleith_bristol_parse_buffer(&p, EQ0_BUF, 0, &cfg_0v);
    check("gate_sweep: EQ(0)=0",
          r == 0 && eval_0io(p.circuit, p.output_wires) == 0);
    if (r == 0)
        voleith_bristol_parsed_free(&p);

    /* EQ constant 1 */
    r = voleith_bristol_parse_buffer(&p, EQ1_BUF, 0, &cfg_0v);
    check("gate_sweep: EQ(1)=1",
          r == 0 && eval_0io(p.circuit, p.output_wires) == 1);
    if (r == 0)
        voleith_bristol_parsed_free(&p);

    /* EQW: output aliases input wire */
    r = voleith_bristol_parse_buffer(&p, EQW_BUF, 0, &cfg_1v);
    check("gate_sweep: EQW(0)=0",
          r == 0 && eval_1w1o(p.circuit, p.output_wires, 0) == 0);
    check("gate_sweep: EQW(1)=1",
          r == 0 && eval_1w1o(p.circuit, p.output_wires, 1) == 1);
    if (r == 0)
        voleith_bristol_parsed_free(&p);
}

/* ================================================================
 * Group C: Error-code coverage.
 * ================================================================ */

static void
test_error_codes(void)
{
    voleith_bristol_input_role_t role_w = VOLEITH_BRISTOL_WITNESS;
    voleith_bristol_config_t cfg_1v = {&role_w, 1};
    voleith_bristol_config_t cfg_0v = {NULL, 0};
    voleith_bristol_parsed_t p;
    int r;

    memset(&p, 0, sizeof(p));

    /* ERR_HEADER: n_wires missing on line 1 */
    r = voleith_bristol_parse_buffer(&p, "42\n1 1\n1 1\n\n1 1 0 1 INV\n", 0,
                                     &cfg_1v);
    check("err: ERR_HEADER", r == VOLEITH_BRISTOL_ERR_HEADER);

    /* ERR_OLD_FORMAT: three integers on line 1 */
    r = voleith_bristol_parse_buffer(&p, "1 2 3\n1 1\n1 1\n\n1 1 0 1 INV\n", 0,
                                     &cfg_1v);
    check("err: ERR_OLD_FORMAT", r == VOLEITH_BRISTOL_ERR_OLD_FORMAT);

    /* ERR_ROLE_MISMATCH: file has 2 input values, cfg supplies 1 role */
    r = voleith_bristol_parse_buffer(&p, ROUND_TRIP_BUF,
                                     sizeof(ROUND_TRIP_BUF) - 1, &cfg_1v);
    check("err: ERR_ROLE_MISMATCH", r == VOLEITH_BRISTOL_ERR_ROLE_MISMATCH);

    /* ERR_HEADER: sum_output_bits (2) > n_wires (1) */
    r = voleith_bristol_parse_buffer(&p, "1 1\n0\n1 2\n\n1 1 0 0 EQ\n", 0,
                                     &cfg_0v);
    check("err: ERR_HEADER bits>wires", r == VOLEITH_BRISTOL_ERR_HEADER);

    /* ERR_GATE_SYNTAX: n_out = 2 (only n_out = 1 is supported) */
    r = voleith_bristol_parse_buffer(&p, "1 2\n1 1\n1 1\n\n2 2 0 1 1 XOR\n", 0,
                                     &cfg_1v);
    check("err: ERR_GATE_SYNTAX", r == VOLEITH_BRISTOL_ERR_GATE_SYNTAX);

    /* ERR_UNKNOWN_GATE: unrecognised gate type */
    r = voleith_bristol_parse_buffer(&p, "1 2\n1 1\n1 1\n\n1 1 0 1 FOO\n", 0,
                                     &cfg_1v);
    check("err: ERR_UNKNOWN_GATE", r == VOLEITH_BRISTOL_ERR_UNKNOWN_GATE);

    /*
     * ERR_WIRE_ORDER: in0 (2) has not been defined yet when gate runs.
     * Gate: "2 1 2 0 1 XOR" -> n_in=2 n_out=1 in0=2 in1=0 out=1.
     * Wire 2 is never written by any earlier gate or input declaration.
     */
    r = voleith_bristol_parse_buffer(&p, "1 3\n1 1\n1 2\n\n2 1 2 0 1 XOR\n", 0,
                                     &cfg_1v);
    check("err: ERR_WIRE_ORDER", r == VOLEITH_BRISTOL_ERR_WIRE_ORDER);

    /* ERR_WIRE_REDEF: two gates both write to wire 1 */
    r = voleith_bristol_parse_buffer(
        &p, "2 3\n1 1\n1 2\n\n1 1 0 1 INV\n1 1 0 1 INV\n", 0, &cfg_1v);
    check("err: ERR_WIRE_REDEF", r == VOLEITH_BRISTOL_ERR_WIRE_REDEF);

    /* ERR_WIRE_COUNT: wire 2 declared but never assigned */
    r = voleith_bristol_parse_buffer(&p, "1 3\n1 1\n1 2\n\n1 1 0 1 INV\n", 0,
                                     &cfg_1v);
    check("err: ERR_WIRE_COUNT", r == VOLEITH_BRISTOL_ERR_WIRE_COUNT);
}

/* ================================================================
 * Group D: AES-128 Bristol file tests.
 *
 * Requires the vendored circuit at VOLEITH_BRISTOL_TEST_DATA_DIR/aes_128.txt.
 * The circuit uses the Boyar-Peralta 32-AND S-box: 200 S-boxes x 32 = 6400
 * AND gates.  FIPS-197 Appendix B key/plaintext/ciphertext are used for the
 * evaluation parity check.
 * ================================================================ */

/* FIPS-197 Appendix B */
static const uint8_t AES128_KEY[16] = {0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae,
                                       0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88,
                                       0x09, 0xcf, 0x4f, 0x3c};
static const uint8_t AES128_PT[16] = {0x32, 0x43, 0xf6, 0xa8, 0x88, 0x5a,
                                      0x30, 0x8d, 0x31, 0x31, 0x98, 0xa2,
                                      0xe0, 0x37, 0x07, 0x34};
static const uint8_t AES128_CT[16] = {0x39, 0x25, 0x84, 0x1d, 0x02, 0xdc,
                                      0x09, 0xfb, 0xdc, 0x11, 0x85, 0x97,
                                      0x19, 0x6a, 0x0b, 0x32};

static void
test_aes128_file(void)
{
    voleith_bristol_input_role_t roles[2];
    voleith_bristol_config_t cfg;
    voleith_bristol_parsed_t p;
    uint8_t *wire_vals;
    uint8_t instance[32]; /* key[16] || plaintext[16] */
    uint8_t ct_got[16];
    size_t wv_bytes;
    int r, i;

    roles[0] = VOLEITH_BRISTOL_INSTANCE; /* key */
    roles[1] = VOLEITH_BRISTOL_INSTANCE; /* plaintext */
    cfg.input_roles = roles;
    cfg.n_input_roles = 2;

    memset(&p, 0, sizeof(p));
    r = voleith_bristol_parse_file(
        &p, VOLEITH_BRISTOL_TEST_DATA_DIR "/aes_128.txt", &cfg);
    check("aes128: parse ok", r == 0);
    if (r != 0)
        return;

    /* Boyar-Peralta S-box: 200 S-boxes x 32 AND gates = 6400 */
    check("aes128: and_gate_count",
          voleith_circuit_and_gate_count(p.circuit) == 6400);
    check("aes128: n_input_wires", p.n_input_wires == 256);
    check("aes128: n_output_wires", p.n_output_wires == 128);
    check("aes128: n_input_values", p.n_input_values == 2);
    check("aes128: n_output_values", p.n_output_values == 1);
    check("aes128: input_value_sizes[0]", p.input_value_sizes[0] == 128);
    check("aes128: input_value_sizes[1]", p.input_value_sizes[1] == 128);
    check("aes128: output_value_sizes[0]", p.output_value_sizes[0] == 128);
    check("aes128: witness_count",
          voleith_circuit_witness_count(p.circuit) == 0);
    check("aes128: instance_count",
          voleith_circuit_instance_count(p.circuit) == 256);

    /*
     * Evaluation parity against FIPS-197 Appendix B.
     *
     * This Bristol AES-128 circuit uses reversed bit/byte ordering: wire 0
     * carries bit 0 of the LAST byte of each 128-bit value (byte 15), and
     * wire 127 carries bit 7 of the FIRST byte (byte 0).  Supply key and
     * plaintext bytes in reverse order and reconstruct the ciphertext in
     * the same way.
     */
    for (i = 0; i < 16; i++) {
        instance[i] = AES128_KEY[15 - i];
        instance[16 + i] = AES128_PT[15 - i];
    }

    wv_bytes = (voleith_circuit_wire_count(p.circuit) + 7) / 8;
    wire_vals = calloc(wv_bytes, 1);
    check("aes128: alloc wire_vals", wire_vals != NULL);
    if (wire_vals == NULL) {
        voleith_bristol_parsed_free(&p);
        return;
    }

    r = voleith_circuit_eval(p.circuit, NULL, instance, wire_vals);
    check("aes128: eval ok", r == 1);

    /* Output wires are also in reversed byte order: wire i carries bit i%8
     * of ciphertext byte (15 - i/8). */
    memset(ct_got, 0, sizeof(ct_got));
    for (i = 0; i < 128; i++)
        ct_got[15 - i / 8] |=
            (uint8_t)(bit_at(wire_vals, p.output_wires[i]) << (i % 8));
    if (memcmp(ct_got, AES128_CT, 16) != 0) {
        printf("  NOTE aes128: expected CT: ");
        for (i = 0; i < 16; i++)
            printf("%02x", AES128_CT[i]);
        printf("\n  NOTE aes128: got      CT: ");
        for (i = 0; i < 16; i++)
            printf("%02x", ct_got[i]);
        printf("\n");
    }
    check("aes128: ciphertext match", memcmp(ct_got, AES128_CT, 16) == 0);

    free(wire_vals);
    voleith_bristol_parsed_free(&p);
}

/* ================================================================
 * Group E: AES-256 Bristol file tests.
 *
 * Same reversed bit/byte ordering as the AES-128 file.
 * FIPS-197 Appendix C.3 key/plaintext/ciphertext are used for the
 * evaluation parity check.
 * Input value 1: 256-bit key (party 1).
 * Input value 2: 128-bit plaintext (party 2).
 * AND gates: 276 S-boxes x 32 (Boyar-Peralta) = 8832.
 * ================================================================ */

/* FIPS-197 Appendix C.3 */
static const uint8_t AES256_KEY[32] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a,
    0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15,
    0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f};
static const uint8_t AES256_PT[16] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55,
                                      0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb,
                                      0xcc, 0xdd, 0xee, 0xff};
static const uint8_t AES256_CT[16] = {0x8e, 0xa2, 0xb7, 0xca, 0x51, 0x67,
                                      0x45, 0xbf, 0xea, 0xfc, 0x49, 0x90,
                                      0x4b, 0x49, 0x60, 0x89};

static void
test_aes256_file(void)
{
    voleith_bristol_input_role_t roles[2];
    voleith_bristol_config_t cfg;
    voleith_bristol_parsed_t p;
    uint8_t *wire_vals;
    uint8_t instance[48]; /* key[32] reversed || plaintext[16] reversed */
    uint8_t ct_got[16];
    size_t wv_bytes;
    int r, i;

    roles[0] = VOLEITH_BRISTOL_INSTANCE; /* key (256 bits) */
    roles[1] = VOLEITH_BRISTOL_INSTANCE; /* plaintext (128 bits) */
    cfg.input_roles = roles;
    cfg.n_input_roles = 2;

    memset(&p, 0, sizeof(p));
    r = voleith_bristol_parse_file(
        &p, VOLEITH_BRISTOL_TEST_DATA_DIR "/aes_256.txt", &cfg);
    check("aes256: parse ok", r == 0);
    if (r != 0)
        return;

    /* Boyar-Peralta S-box: 276 S-boxes x 32 AND gates = 8832 */
    check("aes256: and_gate_count",
          voleith_circuit_and_gate_count(p.circuit) == 8832);
    check("aes256: n_input_wires", p.n_input_wires == 384);
    check("aes256: n_output_wires", p.n_output_wires == 128);
    check("aes256: n_input_values", p.n_input_values == 2);
    check("aes256: n_output_values", p.n_output_values == 1);
    check("aes256: input_value_sizes[0]", p.input_value_sizes[0] == 256);
    check("aes256: input_value_sizes[1]", p.input_value_sizes[1] == 128);
    check("aes256: output_value_sizes[0]", p.output_value_sizes[0] == 128);
    check("aes256: witness_count",
          voleith_circuit_witness_count(p.circuit) == 0);
    check("aes256: instance_count",
          voleith_circuit_instance_count(p.circuit) == 384);

    /* Reversed byte-order encoding (same convention as AES-128 file). */
    for (i = 0; i < 32; i++)
        instance[i] = AES256_KEY[31 - i];
    for (i = 0; i < 16; i++)
        instance[32 + i] = AES256_PT[15 - i];

    wv_bytes = (voleith_circuit_wire_count(p.circuit) + 7) / 8;
    wire_vals = calloc(wv_bytes, 1);
    check("aes256: alloc wire_vals", wire_vals != NULL);
    if (wire_vals == NULL) {
        voleith_bristol_parsed_free(&p);
        return;
    }

    r = voleith_circuit_eval(p.circuit, NULL, instance, wire_vals);
    check("aes256: eval ok", r == 1);

    memset(ct_got, 0, sizeof(ct_got));
    for (i = 0; i < 128; i++)
        ct_got[15 - i / 8] |=
            (uint8_t)(bit_at(wire_vals, p.output_wires[i]) << (i % 8));
    if (memcmp(ct_got, AES256_CT, 16) != 0) {
        printf("  NOTE aes256: expected CT: ");
        for (i = 0; i < 16; i++)
            printf("%02x", AES256_CT[i]);
        printf("\n  NOTE aes256: got      CT: ");
        for (i = 0; i < 16; i++)
            printf("%02x", ct_got[i]);
        printf("\n");
    }
    check("aes256: ciphertext match", memcmp(ct_got, AES256_CT, 16) == 0);

    free(wire_vals);
    voleith_bristol_parsed_free(&p);
}

/* ================================================================
 * Group F: Prove and verify with a parsed Bristol AES-128 circuit.
 *
 * Key is witness, plaintext is instance, expected ciphertext is
 * constrained via assert_equal against add_const wires.  Uses
 * FIPS-197 Appendix B test vector with FAEST-EM-128f parameters.
 * ================================================================ */

static const uint8_t PROVE_VERIFY_FS_SEED[] = "bristol_aes128_prove_verify";

static void
test_prove_verify(void)
{
    voleith_bristol_input_role_t roles[2];
    voleith_bristol_config_t cfg;
    voleith_bristol_parsed_t p;
    voleith_proof_t proof;
    uint8_t witness[16];
    uint8_t instance[16];
    wire_id cw;
    int bit, r, i;

    roles[0] = VOLEITH_BRISTOL_WITNESS;  /* key */
    roles[1] = VOLEITH_BRISTOL_INSTANCE; /* plaintext */
    cfg.input_roles = roles;
    cfg.n_input_roles = 2;

    memset(&p, 0, sizeof(p));
    r = voleith_bristol_parse_file(
        &p, VOLEITH_BRISTOL_TEST_DATA_DIR "/aes_128.txt", &cfg);
    check("prove_verify: parse ok", r == 0);
    if (r != 0)
        return;

    /*
     * Constrain each output wire against the expected ciphertext bit.
     * Bristol byte order: output wire i = bit (i%8) of CT byte (15 - i/8).
     */
    for (i = 0; i < 128; i++) {
        bit = (AES128_CT[15 - i / 8] >> (i % 8)) & 1;
        cw = voleith_circuit_add_const(p.circuit, (uint8_t)bit);
        voleith_circuit_assert_equal(p.circuit, p.output_wires[i], cw);
    }

    /* Key bytes in reversed byte order (wire 0 = bit 0 of KEY[15]). */
    for (i = 0; i < 16; i++)
        witness[i] = AES128_KEY[15 - i];

    /* Plaintext bytes in reversed byte order. */
    for (i = 0; i < 16; i++)
        instance[i] = AES128_PT[15 - i];

    memset(&proof, 0, sizeof(proof));
    r = voleith_prove_v2(&proof, &voleith_params_em_128f, p.circuit, witness,
                         voleith_circuit_witness_byte_len(p.circuit), instance,
                         voleith_circuit_instance_byte_len(p.circuit),
                         PROVE_VERIFY_FS_SEED,
                         sizeof(PROVE_VERIFY_FS_SEED) - 1);
    check("prove_verify: prove ok", r == 0);

    if (r == 0) {
        r = voleith_verify_v2(
            &proof, &voleith_params_em_128f, p.circuit, instance,
            voleith_circuit_instance_byte_len(p.circuit), PROVE_VERIFY_FS_SEED,
            sizeof(PROVE_VERIFY_FS_SEED) - 1);
        check("prove_verify: verify ok", r == 0);
    }

    voleith_proof_free(&proof);
    voleith_bristol_parsed_free(&p);
}

/* ================================================================
 * Group G: neg64 Bristol file.
 *
 * Two's-complement 64-bit negation. The only file in the standard
 * Bristol corpus we vendor that uses EQW (wire 0 aliased to output
 * wire 190: LSB of -x equals LSB of x). Confirms the parser handles
 * EQW correctly in a real circuit, not just synthetically.
 *
 * Bristol arithmetic convention: little-endian. Wire 0 = bit 0 (LSB)
 * of the 64-bit input value; output wires 0..63 carry bits 0..63 of
 * the result, LSB first. This matches a direct little-endian uint64
 * memcpy into the witness byte array.
 * ================================================================ */

static uint64_t
output_to_u64(const uint8_t *wire_vals, const wire_id *out_wires)
{
    uint64_t v = 0;
    int i;
    for (i = 0; i < 64; i++)
        v |= ((uint64_t)bit_at(wire_vals, out_wires[i])) << i;
    return v;
}

static void
test_neg64_file(void)
{
    voleith_bristol_input_role_t role = VOLEITH_BRISTOL_WITNESS;
    voleith_bristol_config_t cfg = {&role, 1};
    voleith_bristol_parsed_t p;
    uint8_t witness[8];
    uint8_t *wire_vals;
    size_t wv_bytes;
    int r;

    memset(&p, 0, sizeof(p));
    r = voleith_bristol_parse_file(
        &p, VOLEITH_BRISTOL_TEST_DATA_DIR "/neg64.txt", &cfg);
    check("neg64: parse ok", r == 0);
    if (r != 0)
        return;

    check("neg64: and_gate_count",
          voleith_circuit_and_gate_count(p.circuit) == 62);
    check("neg64: n_input_wires", p.n_input_wires == 64);
    check("neg64: n_output_wires", p.n_output_wires == 64);
    check("neg64: n_input_values", p.n_input_values == 1);
    check("neg64: n_output_values", p.n_output_values == 1);
    check("neg64: input_value_sizes[0]", p.input_value_sizes[0] == 64);
    check("neg64: output_value_sizes[0]", p.output_value_sizes[0] == 64);

    wv_bytes = (voleith_circuit_wire_count(p.circuit) + 7) / 8;
    wire_vals = calloc(wv_bytes, 1);
    check("neg64: alloc wire_vals", wire_vals != NULL);
    if (wire_vals == NULL) {
        voleith_bristol_parsed_free(&p);
        return;
    }

    /* -0 = 0 (baseline; also exercises the EQW LSB alias on 0). */
    memset(witness, 0, sizeof(witness));
    r = voleith_circuit_eval(p.circuit, witness, NULL, wire_vals);
    check("neg64: eval(0) ok", r == 1);
    check("neg64: -0 = 0", output_to_u64(wire_vals, p.output_wires) == 0);

    /* -1 = 0xFFFFFFFFFFFFFFFF in two's complement. LSB = 1, exercises EQW. */
    memset(witness, 0, sizeof(witness));
    witness[0] = 0x01;
    memset(wire_vals, 0, wv_bytes);
    r = voleith_circuit_eval(p.circuit, witness, NULL, wire_vals);
    check("neg64: eval(1) ok", r == 1);
    check("neg64: -1 = 0xFFFFFFFFFFFFFFFF",
          output_to_u64(wire_vals, p.output_wires) == 0xFFFFFFFFFFFFFFFFULL);

    /* -42 = 0xFFFFFFFFFFFFFFD6 (sanity: arbitrary nonzero, mixed bits). */
    memset(witness, 0, sizeof(witness));
    witness[0] = 42;
    memset(wire_vals, 0, wv_bytes);
    r = voleith_circuit_eval(p.circuit, witness, NULL, wire_vals);
    check("neg64: eval(42) ok", r == 1);
    check("neg64: -42 = 0xFFFFFFFFFFFFFFD6",
          output_to_u64(wire_vals, p.output_wires) == 0xFFFFFFFFFFFFFFD6ULL);

    free(wire_vals);
    voleith_bristol_parsed_free(&p);
}

/* ================================================================
 * Group H: mult2_64 Bristol file.
 *
 * 64x64 -> 128-bit unsigned multiply. The only file we vendor with
 * n_output_values > 1: outputs are split into two 64-bit values
 * (high and low halves of the 128-bit product). Confirms the
 * parser's output-suffix slicing handles multi-value outputs.
 *
 * Output layout (inferred from the file's final AND gate
 * `a_0 AND b_0 -> wire 28096`, which is the product LSB landing at
 * the first wire of output value 1): output value 0 = HI half,
 * output value 1 = LO half. Within each value, bits are LSB first
 * (matching the corpus little-endian convention used by neg64).
 *
 * To distinguish hi from lo we pick a = 2, b = 2^63 so the product
 * is exactly 2^64: hi = 1, lo = 0.
 * ================================================================ */

static void
test_mult2_64_file(void)
{
    voleith_bristol_input_role_t roles[2];
    voleith_bristol_config_t cfg;
    voleith_bristol_parsed_t p;
    uint8_t witness[16];
    uint8_t *wire_vals;
    size_t wv_bytes;
    uint64_t lo, hi;
    int r;

    roles[0] = VOLEITH_BRISTOL_WITNESS; /* a */
    roles[1] = VOLEITH_BRISTOL_WITNESS; /* b */
    cfg.input_roles = roles;
    cfg.n_input_roles = 2;

    memset(&p, 0, sizeof(p));
    r = voleith_bristol_parse_file(
        &p, VOLEITH_BRISTOL_TEST_DATA_DIR "/mult2_64.txt", &cfg);
    check("mult2_64: parse ok", r == 0);
    if (r != 0)
        return;

    check("mult2_64: and_gate_count",
          voleith_circuit_and_gate_count(p.circuit) == 8128);
    check("mult2_64: n_input_wires", p.n_input_wires == 128);
    check("mult2_64: n_output_wires", p.n_output_wires == 128);
    check("mult2_64: n_input_values", p.n_input_values == 2);
    check("mult2_64: n_output_values", p.n_output_values == 2);
    check("mult2_64: input_value_sizes[0]", p.input_value_sizes[0] == 64);
    check("mult2_64: input_value_sizes[1]", p.input_value_sizes[1] == 64);
    check("mult2_64: output_value_sizes[0]", p.output_value_sizes[0] == 64);
    check("mult2_64: output_value_sizes[1]", p.output_value_sizes[1] == 64);

    wv_bytes = (voleith_circuit_wire_count(p.circuit) + 7) / 8;
    wire_vals = calloc(wv_bytes, 1);
    check("mult2_64: alloc wire_vals", wire_vals != NULL);
    if (wire_vals == NULL) {
        voleith_bristol_parsed_free(&p);
        return;
    }

    /* 3 * 5 = 15. Both halves fit in lo; baseline correctness. */
    memset(witness, 0, sizeof(witness));
    witness[0] = 3;
    witness[8] = 5;
    r = voleith_circuit_eval(p.circuit, witness, NULL, wire_vals);
    check("mult2_64: eval(3,5) ok", r == 1);
    hi = output_to_u64(wire_vals, p.output_wires);
    lo = output_to_u64(wire_vals, p.output_wires + 64);
    check("mult2_64: 3*5 lo=15", lo == 15);
    check("mult2_64: 3*5 hi=0", hi == 0);

    /*
     * 2 * 2^63 = 2^64. hi = 1, lo = 0. Distinguishes which output
     * value is which, so a parser bug that swapped output_value 0
     * and 1 would surface here.
     */
    memset(witness, 0, sizeof(witness));
    witness[0] = 2;
    witness[8 + 7] = 0x80; /* bit 63 of b, little-endian */
    memset(wire_vals, 0, wv_bytes);
    r = voleith_circuit_eval(p.circuit, witness, NULL, wire_vals);
    check("mult2_64: eval(2, 2^63) ok", r == 1);
    hi = output_to_u64(wire_vals, p.output_wires);
    lo = output_to_u64(wire_vals, p.output_wires + 64);
    check("mult2_64: 2*2^63 lo=0", lo == 0);
    check("mult2_64: 2*2^63 hi=1", hi == 1);

    free(wire_vals);
    voleith_bristol_parsed_free(&p);
}

/* ================================================================
 * main
 * ================================================================ */

int
main(void)
{
    printf("test_bristol_parser: starting\n");
    test_round_trip();
    test_gate_sweep();
    test_error_codes();
    test_aes128_file();
    test_aes256_file();
    test_neg64_file();
    test_mult2_64_file();
    test_prove_verify();
    printf("test_bristol_parser: %d/%d passed\n", pass_count, test_count);
    return (pass_count == test_count) ? 0 : 1;
}
