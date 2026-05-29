/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * test_grostl_gf8_circuit.c - Tests for circuits/grostl_gf8_circuit.
 *
 * Validates:
 *   - Mul-gate count and witness-byte count match the design doc.
 *   - Witness builder + circuit-evaluation produces digests
 *     byte-identical to the NIST-KAT-validated software path in
 *     core/grostl.c.
 *   - All circuit constraints (the assert_product checks inside
 *     each aes_gf8_sbox) are satisfied by the constructed witness.
 *
 * Spot-checks at four message shapes (empty, sub-block, exact one
 * block, exact two blocks) for Grøstl-256, plus the analogous
 * shapes for Grøstl-512.  Plus a random-input differential against
 * core/grostl.c.
 */

#include "../circuits/grostl_gf8_circuit.h"
#include "../core/grostl.h"
#include "../proof/gf8_circuit.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int tests_run = 0;
static int tests_passed = 0;

#define TEST(name)                                                             \
    do {                                                                       \
        tests_run++;                                                           \
        printf("  [%2d] %-60s ", tests_run, name);                             \
    } while (0)

#define PASS()                                                                 \
    do {                                                                       \
        tests_passed++;                                                        \
        printf("PASS\n");                                                      \
    } while (0)

#define FAIL(msg)                                                              \
    do {                                                                       \
        printf("FAIL: %s\n", msg);                                             \
    } while (0)

static void
hex_print(const uint8_t *p, size_t n)
{
    for (size_t i = 0; i < n; i++)
        printf("%02x", p[i]);
}

/* Deterministic PRNG for reproducible random inputs. */
static uint64_t lcg_state = 0xC0FFEE1234567890ULL;

static uint8_t
lcg_byte(void)
{
    lcg_state = lcg_state * 6364136223846793005ULL + 1442695040888963407ULL;
    return (uint8_t)(lcg_state >> 56);
}

static void
fill_random(uint8_t *buf, size_t n)
{
    for (size_t i = 0; i < n; i++)
        buf[i] = lcg_byte();
}

/* ================================================================
 * Helpers: build, build-witness, evaluate.
 * ================================================================ */

/* Build a Grøstl-256 circuit hashing `msg_bytes` of caller-witness
 * message data; return the circuit and the 32 output wire IDs. */
static voleith_gf8_circuit_t *
build_grostl256_circuit(size_t msg_bytes, gf8_wire_id out[32])
{
    voleith_gf8_circuit_t *c = voleith_gf8_circuit_new();
    gf8_wire_id *msg_wires =
        (msg_bytes > 0) ? malloc(msg_bytes * sizeof(*msg_wires)) : NULL;
    for (size_t i = 0; i < msg_bytes; i++)
        msg_wires[i] = voleith_gf8_add_witness(c);
    grostl256_gf8_circuit(c, msg_wires, msg_bytes, out);
    free(msg_wires);
    return c;
}

static voleith_gf8_circuit_t *
build_grostl512_circuit(size_t msg_bytes, gf8_wire_id out[64])
{
    voleith_gf8_circuit_t *c = voleith_gf8_circuit_new();
    gf8_wire_id *msg_wires =
        (msg_bytes > 0) ? malloc(msg_bytes * sizeof(*msg_wires)) : NULL;
    for (size_t i = 0; i < msg_bytes; i++)
        msg_wires[i] = voleith_gf8_add_witness(c);
    grostl512_gf8_circuit(c, msg_wires, msg_bytes, out);
    free(msg_wires);
    return c;
}

/* Evaluate a Grøstl-256 circuit, returning the 32 output bytes and
 * a constraint-satisfaction flag.  Returns 1 on success, 0 on
 * constraint failure, -1 on alloc error. */
static int
eval_grostl256(const uint8_t *msg, size_t msg_bytes, uint8_t md[32])
{
    gf8_wire_id out[32];
    voleith_gf8_circuit_t *c = build_grostl256_circuit(msg_bytes, out);
    if (!c)
        return -1;

    size_t wbytes = grostl256_gf8_witness_bytes(msg_bytes);
    uint8_t *witness = malloc(wbytes);
    if (!witness) {
        voleith_gf8_circuit_free(c);
        return -1;
    }
    grostl256_gf8_build_witness(msg, msg_bytes, witness);

    size_t n_wires = voleith_gf8_circuit_wire_count(c);
    uint8_t *vals = calloc(n_wires, 1);
    if (!vals) {
        free(witness);
        voleith_gf8_circuit_free(c);
        return -1;
    }
    int ok = voleith_gf8_circuit_eval(c, witness, NULL, vals);

    for (int i = 0; i < 32; i++)
        md[i] = vals[out[i]];

    free(vals);
    free(witness);
    voleith_gf8_circuit_free(c);
    return ok;
}

static int
eval_grostl512(const uint8_t *msg, size_t msg_bytes, uint8_t md[64])
{
    gf8_wire_id out[64];
    voleith_gf8_circuit_t *c = build_grostl512_circuit(msg_bytes, out);
    if (!c)
        return -1;

    size_t wbytes = grostl512_gf8_witness_bytes(msg_bytes);
    uint8_t *witness = malloc(wbytes);
    if (!witness) {
        voleith_gf8_circuit_free(c);
        return -1;
    }
    grostl512_gf8_build_witness(msg, msg_bytes, witness);

    size_t n_wires = voleith_gf8_circuit_wire_count(c);
    uint8_t *vals = calloc(n_wires, 1);
    if (!vals) {
        free(witness);
        voleith_gf8_circuit_free(c);
        return -1;
    }
    int ok = voleith_gf8_circuit_eval(c, witness, NULL, vals);

    for (int i = 0; i < 64; i++)
        md[i] = vals[out[i]];

    free(vals);
    free(witness);
    voleith_gf8_circuit_free(c);
    return ok;
}

/* ================================================================
 * S-box / VOLE-slot count and witness-byte count tests.
 *
 * Grøstl's S-box gadget (via aes_gf8_sbox) uses Proposition 6.4:
 * one add_witness for inv_in plus two assert_product constraints -
 * no add_mul calls.  So voleith_gf8_circuit_mul_count() is 0; the
 * S-box slot count lives in the witness count.  voleith_gf8_qs_ell()
 * = n_witness + n_mul reports the formal proof-system "ell"; for
 * Grøstl that's just n_witness (= msg_bytes + n_sboxes).
 * ================================================================ */

static void
test_sbox_count_grostl256(void)
{
    /* Cover boundary shapes for padding (fits-in-one-block,
     * forces-second-block, exact-block-boundary). */
    struct {
        size_t msg_bytes;
        size_t expected_n_blocks;
    } cases[] = {
        {0, 1},   /* fits + length in one block */
        {3, 1},   /* fits + length in one block */
        {55, 1},  /* exactly fills one padded block */
        {56, 2},  /* needs second block for length */
        {64, 2},  /* full block + padding block */
        {128, 3}, /* 2 full blocks + padding block */
    };

    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        char name[80];
        snprintf(name, sizeof(name),
                 "Grøstl-256 S-box count: msg=%zuB -> %zu blocks",
                 cases[i].msg_bytes, cases[i].expected_n_blocks);
        TEST(name);

        gf8_wire_id out[32];
        voleith_gf8_circuit_t *c =
            build_grostl256_circuit(cases[i].msg_bytes, out);

        /* S-box gadget has no add_mul calls; n_mul must be 0. */
        size_t mul = voleith_gf8_circuit_mul_count(c);
        /* S-box count = total witness wires minus the msg wires the
         * caller declared up front. */
        size_t n_sboxes =
            voleith_gf8_circuit_witness_count(c) - cases[i].msg_bytes;
        size_t expected = cases[i].expected_n_blocks * 1280u + 640u;

        if (mul == 0 && n_sboxes == expected) {
            PASS();
        } else {
            printf("FAIL: n_mul=%zu n_sboxes=%zu expected sboxes=%zu\n", mul,
                   n_sboxes, expected);
        }

        voleith_gf8_circuit_free(c);
    }
}

static void
test_sbox_count_grostl512(void)
{
    struct {
        size_t msg_bytes;
        size_t expected_n_blocks;
    } cases[] = {
        {0, 1},   /* fits */
        {3, 1},   /* fits */
        {119, 1}, /* exactly fills one padded block */
        {120, 2}, /* needs second block for length */
        {128, 2}, /* full block + padding block */
    };

    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        char name[80];
        snprintf(name, sizeof(name),
                 "Grøstl-512 S-box count: msg=%zuB -> %zu blocks",
                 cases[i].msg_bytes, cases[i].expected_n_blocks);
        TEST(name);

        gf8_wire_id out[64];
        voleith_gf8_circuit_t *c =
            build_grostl512_circuit(cases[i].msg_bytes, out);

        size_t mul = voleith_gf8_circuit_mul_count(c);
        size_t n_sboxes =
            voleith_gf8_circuit_witness_count(c) - cases[i].msg_bytes;
        size_t expected = cases[i].expected_n_blocks * 3584u + 1792u;

        if (mul == 0 && n_sboxes == expected) {
            PASS();
        } else {
            printf("FAIL: n_mul=%zu n_sboxes=%zu expected sboxes=%zu\n", mul,
                   n_sboxes, expected);
        }

        voleith_gf8_circuit_free(c);
    }
}

static void
test_witness_bytes(void)
{
    /* witness_bytes(msg) must equal the total number of witness wires
     * the prover commits to: msg_bytes (caller-declared) + inv_in for
     * every S-box (added internally).  Same as qs_ell since the
     * S-box gadget contributes no add_mul gates. */
    TEST("witness_bytes formula matches qs_ell across message sizes");

    int fail = 0;
    size_t cases[] = {0, 1, 32, 55, 64, 100, 128, 200, 1024};
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        size_t mb = cases[i];

        size_t w256 = grostl256_gf8_witness_bytes(mb);
        gf8_wire_id out256[32];
        voleith_gf8_circuit_t *c256 = build_grostl256_circuit(mb, out256);
        size_t expected256 = voleith_gf8_qs_ell(c256);
        if (w256 != expected256) {
            fail = 1;
            printf("\n    Grøstl-256 msg=%zu: w=%zu expected=%zu", mb, w256,
                   expected256);
        }
        voleith_gf8_circuit_free(c256);

        size_t w512 = grostl512_gf8_witness_bytes(mb);
        gf8_wire_id out512[64];
        voleith_gf8_circuit_t *c512 = build_grostl512_circuit(mb, out512);
        size_t expected512 = voleith_gf8_qs_ell(c512);
        if (w512 != expected512) {
            fail = 1;
            printf("\n    Grøstl-512 msg=%zu: w=%zu expected=%zu", mb, w512,
                   expected512);
        }
        voleith_gf8_circuit_free(c512);
    }
    if (fail)
        FAIL("witness size mismatch");
    else
        PASS();
}

/* ================================================================
 * Direct NIST KAT validation of the circuit.
 *
 * Vectors hand-extracted from
 *   third_party/Groestl/KAT_MCT/ShortMsgKAT_{256,512}.txt.
 *
 * Compares circuit-eval output against the published NIST MD field
 * directly - independent of core/grostl.c.  Catches a class of bug
 * that the differential-vs-software tests cannot: a bug present in
 * BOTH the circuit and the software (e.g., a shared misreading of
 * the spec).  A full KAT-file parser is left to a follow-up; these
 * hand-picked vectors cover the same boundary shapes used in
 * test_grostl.c (empty, sub-block, exact-block-boundary).
 * ================================================================ */

static int
hex_nibble(char c)
{
    if (c >= '0' && c <= '9')
        return c - '0';
    if (c >= 'a' && c <= 'f')
        return c - 'a' + 10;
    if (c >= 'A' && c <= 'F')
        return c - 'A' + 10;
    return -1;
}

/* Decode a hex string into a fresh malloc'd byte buffer.  Returns
 * byte length on success, -1 on malformed input. */
static int
hex_decode(const char *s, uint8_t **out)
{
    size_t len = strlen(s);
    if (len % 2 != 0)
        return -1;
    size_t n = len / 2;
    uint8_t *buf = malloc(n > 0 ? n : 1);
    if (!buf)
        return -1;
    for (size_t i = 0; i < n; i++) {
        int hi = hex_nibble(s[2 * i]);
        int lo = hex_nibble(s[2 * i + 1]);
        if (hi < 0 || lo < 0) {
            free(buf);
            return -1;
        }
        buf[i] = (uint8_t)((hi << 4) | lo);
    }
    *out = buf;
    return (int)n;
}

/* Grøstl-256 NIST KAT vectors. */
static const char *NIST256_EMPTY_MD =
    "1A52D11D550039BE16107F9C58DB9EBCC417F16F736ADB2502567119F0083467";
static const uint8_t NIST256_3B_MSG[3] = {0x1F, 0x87, 0x7C};
static const char *NIST256_3B_MD =
    "05FE7DE2D8CE1770DF766739F788037D0CF2CA7C2B7620835CC34F45B3FCF919";
static const char *NIST256_64B_MSG_HEX =
    "E926AE8B0AF6E53176DBFFCC2A6B88C6BD765F939D3D178A9BDE9EF3AA131C61"
    "E31C1E42CDFAF4B4DCDE579A37E150EFBEF5555B4C1CB40439D835A724E2FAE7";
static const char *NIST256_64B_MD =
    "5ADEBBFDF6FD6178892B39A97A32B29FB605F97E1E5C3BBCF624A0E9CD72D145";

/* Grøstl-512 NIST KAT vectors. */
static const char *NIST512_EMPTY_MD =
    "6D3AD29D279110EEF3ADBD66DE2A0345A77BAEDE1557F5D099FCE0C03D6DC2BA"
    "8E6D4A6633DFBD66053C20FAA87D1A11F39A7FBE4A6C2F009801370308FC4AD8";
static const char *NIST512_3B_MD =
    "413907C17D8CA9E5477DE5491914DC4EB621F35C96267F8E807AFFC0335DD8F6"
    "781C053CED249FF3C8C5A4D4AC62FE3D9E6660B30CC09621DE7162E6C271D3C7";
static const char *NIST512_128B_MSG_HEX =
    "2B6DB7CED8665EBE9DEB080295218426BDAA7C6DA9ADD2088932CDFFBAA1C141"
    "29BCCDD70F369EFB149285858D2B1D155D14DE2FDB680A8B027284055182A0CA"
    "E275234CC9C92863C1B4AB66F304CF0621CD54565F5BFF461D3B461BD40DF281"
    "98E3732501B4860EADD503D26D6E69338F4E0456E9E9BAF3D827AE685FB1D817";
static const char *NIST512_128B_MD =
    "FF410B511135DBC0B8644C28EFA3EC632326FEB98E50EDC6390C441610D7C514"
    "ACDF0A61A0BF01AA9DC1F55D92E085248EBA1C24EE23978B4986AF41C13A6176";

static void
check_nist_kat_256(const uint8_t *msg, size_t msg_bytes,
                   const char *expected_md_hex, const char *label)
{
    char name[80];
    snprintf(name, sizeof(name), "Grøstl-256 circuit vs NIST MD: %s", label);
    TEST(name);

    uint8_t got[32];
    int ok = eval_grostl256(msg, msg_bytes, got);
    if (ok != 1) {
        printf("FAIL: circuit_eval returned %d\n", ok);
        return;
    }

    uint8_t *expected;
    int exp_len = hex_decode(expected_md_hex, &expected);
    if (exp_len != 32) {
        FAIL("expected hex malformed");
        return;
    }

    if (memcmp(got, expected, 32) == 0) {
        PASS();
    } else {
        printf("FAIL\n        got:      ");
        hex_print(got, 32);
        printf("\n        expected: ");
        hex_print(expected, 32);
        printf("\n");
    }
    free(expected);
}

static void
check_nist_kat_512(const uint8_t *msg, size_t msg_bytes,
                   const char *expected_md_hex, const char *label)
{
    char name[80];
    snprintf(name, sizeof(name), "Grøstl-512 circuit vs NIST MD: %s", label);
    TEST(name);

    uint8_t got[64];
    int ok = eval_grostl512(msg, msg_bytes, got);
    if (ok != 1) {
        printf("FAIL: circuit_eval returned %d\n", ok);
        return;
    }

    uint8_t *expected;
    int exp_len = hex_decode(expected_md_hex, &expected);
    if (exp_len != 64) {
        FAIL("expected hex malformed");
        return;
    }

    if (memcmp(got, expected, 64) == 0) {
        PASS();
    } else {
        printf("FAIL\n        got:      ");
        hex_print(got, 64);
        printf("\n        expected: ");
        hex_print(expected, 64);
        printf("\n");
    }
    free(expected);
}

static void
test_circuit_against_nist_kats(void)
{
    /* Grøstl-256 KATs. */
    check_nist_kat_256(NULL, 0, NIST256_EMPTY_MD, "empty");
    check_nist_kat_256(NIST256_3B_MSG, 3, NIST256_3B_MD, "3-byte (1F877C)");
    {
        uint8_t *msg;
        int n = hex_decode(NIST256_64B_MSG_HEX, &msg);
        if (n == 64) {
            check_nist_kat_256(msg, 64, NIST256_64B_MD,
                               "64-byte (forces 2-block padding)");
        }
        free(msg);
    }

    /* Grøstl-512 KATs. */
    check_nist_kat_512(NULL, 0, NIST512_EMPTY_MD, "empty");
    check_nist_kat_512(NIST256_3B_MSG, 3, NIST512_3B_MD, "3-byte (1F877C)");
    {
        uint8_t *msg;
        int n = hex_decode(NIST512_128B_MSG_HEX, &msg);
        if (n == 128) {
            check_nist_kat_512(msg, 128, NIST512_128B_MD,
                               "128-byte (forces 2-block padding)");
        }
        free(msg);
    }
}

/* ================================================================
 * Software cross-validation: circuit-eval result must match
 * core/grostl.c (itself NIST-KAT-validated) byte-identically.
 * ================================================================ */

static void
check_one_256(const uint8_t *msg, size_t msg_bytes, const char *label)
{
    char name[80];
    snprintf(name, sizeof(name), "Grøstl-256 circuit vs software: %s", label);
    TEST(name);

    uint8_t md_circuit[32];
    int ok = eval_grostl256(msg, msg_bytes, md_circuit);
    if (ok != 1) {
        printf("FAIL: circuit_eval returned %d (constraint failure)\n", ok);
        return;
    }

    uint8_t md_sw[32];
    voleith_grostl256(md_sw, msg, msg_bytes);

    if (memcmp(md_circuit, md_sw, 32) == 0) {
        PASS();
    } else {
        printf("FAIL\n        circuit: ");
        hex_print(md_circuit, 32);
        printf("\n        software:");
        hex_print(md_sw, 32);
        printf("\n");
    }
}

static void
check_one_512(const uint8_t *msg, size_t msg_bytes, const char *label)
{
    char name[80];
    snprintf(name, sizeof(name), "Grøstl-512 circuit vs software: %s", label);
    TEST(name);

    uint8_t md_circuit[64];
    int ok = eval_grostl512(msg, msg_bytes, md_circuit);
    if (ok != 1) {
        printf("FAIL: circuit_eval returned %d (constraint failure)\n", ok);
        return;
    }

    uint8_t md_sw[64];
    voleith_grostl512(md_sw, msg, msg_bytes);

    if (memcmp(md_circuit, md_sw, 64) == 0) {
        PASS();
    } else {
        printf("FAIL\n        circuit: ");
        hex_print(md_circuit, 64);
        printf("\n        software:");
        hex_print(md_sw, 64);
        printf("\n");
    }
}

static void
test_grostl256_vectors(void)
{
    check_one_256(NULL, 0, "empty");

    /* NIST KAT-style short input. */
    const uint8_t m3[] = {0x1F, 0x87, 0x7C};
    check_one_256(m3, 3, "3-byte (1F877C)");

    /* Exactly one block - triggers two-block padding branch. */
    uint8_t m55[55];
    for (int i = 0; i < 55; i++)
        m55[i] = (uint8_t)i;
    check_one_256(m55, 55, "55-byte (fits in 1 block)");

    uint8_t m56[56];
    for (int i = 0; i < 56; i++)
        m56[i] = (uint8_t)i;
    check_one_256(m56, 56, "56-byte (forces 2-block padding)");

    uint8_t m64[64];
    for (int i = 0; i < 64; i++)
        m64[i] = (uint8_t)i;
    check_one_256(m64, 64, "64-byte (1 full + padding block)");

    /* Multi-block. */
    uint8_t m200[200];
    fill_random(m200, 200);
    check_one_256(m200, 200, "200-byte random");
}

static void
test_grostl512_vectors(void)
{
    check_one_512(NULL, 0, "empty");

    const uint8_t m3[] = {0x1F, 0x87, 0x7C};
    check_one_512(m3, 3, "3-byte (1F877C)");

    /* Sub-block but close to threshold. */
    uint8_t m119[119];
    for (int i = 0; i < 119; i++)
        m119[i] = (uint8_t)i;
    check_one_512(m119, 119, "119-byte (fits in 1 block)");

    uint8_t m120[120];
    for (int i = 0; i < 120; i++)
        m120[i] = (uint8_t)i;
    check_one_512(m120, 120, "120-byte (forces 2-block padding)");

    /* Random multi-block. */
    uint8_t m256[256];
    fill_random(m256, 256);
    check_one_512(m256, 256, "256-byte random");
}

/* ================================================================
 * Differential vs software on random inputs.  Catches anything the
 * fixed vectors don't.
 * ================================================================ */

static void
test_differential_random(void)
{
    TEST("random differential vs voleith_grostl256 (16 trials, msg<=128)");

    int fail = 0;
    for (int t = 0; t < 16 && !fail; t++) {
        size_t msg_len = (size_t)(lcg_byte() & 0x7f); /* 0..127 */
        uint8_t msg[128];
        fill_random(msg, msg_len);

        uint8_t md_c[32], md_s[32];
        int ok = eval_grostl256(msg, msg_len, md_c);
        if (ok != 1) {
            fail = 1;
            printf("\n    trial %d: constraint failure (ok=%d)", t, ok);
            break;
        }
        voleith_grostl256(md_s, msg, msg_len);
        if (memcmp(md_c, md_s, 32) != 0) {
            fail = 1;
            printf("\n    trial %d (msg_len=%zu): mismatch", t, msg_len);
        }
    }
    if (fail)
        FAIL("differential mismatch");
    else
        PASS();
}

int
main(void)
{
    printf("grostl_gf8_circuit tests\n");
    printf("========================\n");

    printf("\n  S-box / VOLE-slot counts\n");
    test_sbox_count_grostl256();
    test_sbox_count_grostl512();
    test_witness_bytes();

    printf("\n  Direct NIST KAT validation\n");
    test_circuit_against_nist_kats();

    printf("\n  Grøstl-256: circuit vs software\n");
    test_grostl256_vectors();

    printf("\n  Grøstl-512: circuit vs software\n");
    test_grostl512_vectors();

    printf("\n  Random differential\n");
    test_differential_random();

    printf("\n%d/%d tests passed\n", tests_passed, tests_run);
    return (tests_passed == tests_run) ? 0 : 1;
}
