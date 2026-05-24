/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * aes_kat_runner.c - Backend-agnostic NIST AES known-answer-test
 * runner.  See aes_kat_runner.h for documentation.
 *
 * All vectors are stored as hex strings to keep the file compact
 * and to mirror the format used by NIST CAVP response files.
 */

#include "aes_kat_runner.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ================================================================
 * Vector representation.
 *
 * key_hex:  key bytes as hex (length = key_bits / 4).
 * pt_hex:   16-byte plaintext as 32 hex chars.
 * ct_hex:   16-byte expected ciphertext as 32 hex chars.
 *
 * For groups like "varied plaintext, zero key" we still spell out
 * the zero key - keeps the runner uniform.
 * ================================================================ */

struct aes_kat {
    const char *label;
    int key_bits;
    const char *key_hex;
    const char *pt_hex;
    const char *ct_hex;
};

/* ----- FIPS 197 Appendix B ----- */
static const struct aes_kat KATS_FIPS197[] = {
    {
        "FIPS 197 Appendix B",
        128,
        "2b7e151628aed2a6abf7158809cf4f3c",
        "3243f6a8885a308d313198a2e0370734",
        "3925841d02dc09fbdc118597196a0b32",
    },
};

/* ----- NIST SP 800-38A Appendix F.1 ECB ----- */
static const struct aes_kat KATS_SP800_38A[] = {
    {
        "SP 800-38A ECB-AES128 block 1",
        128,
        "2b7e151628aed2a6abf7158809cf4f3c",
        "6bc1bee22e409f96e93d7e117393172a",
        "3ad77bb40d7a3660a89ecaf32466ef97",
    },
    {
        "SP 800-38A ECB-AES128 block 2",
        128,
        "2b7e151628aed2a6abf7158809cf4f3c",
        "ae2d8a571e03ac9c9eb76fac45af8e51",
        "f5d3d58503b9699de785895a96fdbaaf",
    },
    {
        "SP 800-38A ECB-AES192 block 1",
        192,
        "8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b",
        "6bc1bee22e409f96e93d7e117393172a",
        "bd334f1d6e45f25ff712a214571fa5cc",
    },
    {
        "SP 800-38A ECB-AES192 block 2",
        192,
        "8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b",
        "ae2d8a571e03ac9c9eb76fac45af8e51",
        "974104846d0ad3ad7734ecb3ecee4eef",
    },
    {
        "SP 800-38A ECB-AES256 block 1",
        256,
        "603deb1015ca71be2b73aef0857d7781"
        "1f352c073b6108d72d9810a30914dff4",
        "6bc1bee22e409f96e93d7e117393172a",
        "f3eed1bdb5d2a03c064b5a7e3db181f8",
    },
    {
        "SP 800-38A ECB-AES256 block 2",
        256,
        "603deb1015ca71be2b73aef0857d7781"
        "1f352c073b6108d72d9810a30914dff4",
        "ae2d8a571e03ac9c9eb76fac45af8e51",
        "591ccb10d410ed26dc5ba74a31362870",
    },
};

/* ----- All-zeros key + plaintext ----- */
static const struct aes_kat KATS_ZERO[] = {
    {
        "AES-128 zero key, zero plaintext",
        128,
        "00000000000000000000000000000000",
        "00000000000000000000000000000000",
        "66e94bd4ef8a2c3b884cfa59ca342b2e",
    },
    {
        "AES-192 zero key, zero plaintext",
        192,
        "000000000000000000000000000000000000000000000000",
        "00000000000000000000000000000000",
        "aae06992acbf52a3e8f4a96ec9300bd7",
    },
    {
        "AES-256 zero key, zero plaintext",
        256,
        "00000000000000000000000000000000"
        "00000000000000000000000000000000",
        "00000000000000000000000000000000",
        "dc95c078a2408989ad48a21492842087",
    },
};

/* ----- NIST CAVP ECBGFSbox-128: zero key, varied plaintexts ----- */
static const struct aes_kat KATS_GFSBOX_128[] = {
    {"GFSbox-128 COUNT=0", 128, "00000000000000000000000000000000",
     "f34481ec3cc627bacd5dc3fb08f273e6", "0336763e966d92595a567cc9ce537f5e"},
    {"GFSbox-128 COUNT=1", 128, "00000000000000000000000000000000",
     "9798c4640bad75c7c3227db910174e72", "a9a1631bf4996954ebc093957b234589"},
    {"GFSbox-128 COUNT=2", 128, "00000000000000000000000000000000",
     "96ab5c2ff612d9dfaae8c31f30c42168", "ff4f8391a6a40ca5b25d23bedd44a597"},
    {"GFSbox-128 COUNT=3", 128, "00000000000000000000000000000000",
     "6a118a874519e64e9963798a503f1d35", "dc43be40be0e53712f7e2bf5ca707209"},
    {"GFSbox-128 COUNT=4", 128, "00000000000000000000000000000000",
     "cb9fceec81286ca3e989bd979b0cb284", "92beedab1895a94faa69b632e5cc47ce"},
    {"GFSbox-128 COUNT=5", 128, "00000000000000000000000000000000",
     "b26aeb1874e47ca8358ff22378f09144", "459264f4798f6a78bacb89c15ed3d601"},
    {"GFSbox-128 COUNT=6", 128, "00000000000000000000000000000000",
     "58c8e00b2631686d54eab84b91f0aca1", "08a4e2efec8a8e3312ca7460b9040bbf"},
};

/* ----- NIST CAVP ECBGFSbox-256 ----- */
static const struct aes_kat KATS_GFSBOX_256[] = {
    {"GFSbox-256 COUNT=0", 256,
     "00000000000000000000000000000000"
     "00000000000000000000000000000000",
     "014730f80ac625fe84f026c60bfd547d", "5c9d844ed46f9885085e5d6a4f94c7d7"},
    {"GFSbox-256 COUNT=1", 256,
     "00000000000000000000000000000000"
     "00000000000000000000000000000000",
     "0b24af36193ce4665f2825d7b4749c98", "a9ff75bd7cf6613d3731c77c3b6d0c04"},
    {"GFSbox-256 COUNT=2", 256,
     "00000000000000000000000000000000"
     "00000000000000000000000000000000",
     "761c1fe41a18acf20d241650611d90f1", "623a52fcea5d443e48d9181ab32c7421"},
    {"GFSbox-256 COUNT=3", 256,
     "00000000000000000000000000000000"
     "00000000000000000000000000000000",
     "8a560769d605868ad80d819bdba03771", "38f2c7ae10612415d27ca190d27da8b4"},
    {"GFSbox-256 COUNT=4", 256,
     "00000000000000000000000000000000"
     "00000000000000000000000000000000",
     "91fbef2d15a97816060bee1feaa49afe", "1bc704f1bce135ceb810341b216d7abe"},
};

/* ----- NIST CAVP ECBKeySbox-128: varied keys, zero plaintext ----- */
static const struct aes_kat KATS_KEYSBOX_128[] = {
    {"KeySbox-128 COUNT=0", 128, "10a58869d74be5a374cf867cfb473859",
     "00000000000000000000000000000000", "6d251e6944b051e04eaa6fb4dbf78465"},
    {"KeySbox-128 COUNT=1", 128, "caea65cdbb75e9169ecd22ebe6e54675",
     "00000000000000000000000000000000", "6e29201190152df4ee058139def610bb"},
    {"KeySbox-128 COUNT=2", 128, "a2e2fa9baf7d20822ca9f0542f764a41",
     "00000000000000000000000000000000", "c3b44b95d9d2f25670eee9a0de099fa3"},
    {"KeySbox-128 COUNT=3", 128, "b6364ac4e1de1e285eaf144a2415f7a0",
     "00000000000000000000000000000000", "5d9b05578fc944b3cf1ccf0e746cd581"},
    {"KeySbox-128 COUNT=4", 128, "64cf9c7abc50b888af65f49d521944b2",
     "00000000000000000000000000000000", "f7efc89d5dba578104016ce5ad659c05"},
    {"KeySbox-128 COUNT=5", 128, "47d6742eefcc0465dc96355e851b64d9",
     "00000000000000000000000000000000", "0306194f666d183624aa230a8b264ae7"},
    {"KeySbox-128 COUNT=6", 128, "3eb39790678c56bee34bbcdeccf6cdb5",
     "00000000000000000000000000000000", "858075d536d79ccee571f7d7204b1f67"},
    {"KeySbox-128 COUNT=7", 128, "64110a924f0743d500ccadae72c13427",
     "00000000000000000000000000000000", "35870c6a57e9e92314bcb8087cde72ce"},
    {"KeySbox-128 COUNT=8", 128, "18d8126516f8a12ab1a36d9f04d68e51",
     "00000000000000000000000000000000", "6c68e9be5ec41e22c825b7c7affb4363"},
    {"KeySbox-128 COUNT=9", 128, "f530357968578480b398a3c251cd1093",
     "00000000000000000000000000000000", "f5df39990fc688f1b07224cc03e86cea"},
    {"KeySbox-128 COUNT=10", 128, "da84367f325d42d601b4326964802e8e",
     "00000000000000000000000000000000", "bba071bcb470f8f6586e5d3add18bc66"},
    {"KeySbox-128 COUNT=11", 128, "e37b1c6aa2846f6fdb413f238b089f23",
     "00000000000000000000000000000000", "43c9f7e62f5d288bb27aa40ef8fe1ea8"},
    {"KeySbox-128 COUNT=12", 128, "6c002b682483e0cabcc731c253be5674",
     "00000000000000000000000000000000", "3580d19cff44f1014a7c966a69059de5"},
    {"KeySbox-128 COUNT=13", 128, "143ae8ed6555aba96110ab58893a8ae1",
     "00000000000000000000000000000000", "806da864dd29d48deafbe764f8202aef"},
    {"KeySbox-128 COUNT=14", 128, "b69418a85332240dc82492353956ae0c",
     "00000000000000000000000000000000", "a303d940ded8f0baff6f75414cac5243"},
    {"KeySbox-128 COUNT=15", 128, "71b5c08a1993e1362e4d0ce9b22b78d5",
     "00000000000000000000000000000000", "c2dabd117f8a3ecabfbb11d12194d9d0"},
    {"KeySbox-128 COUNT=16", 128, "e234cdca2606b81f29408d5f6da21206",
     "00000000000000000000000000000000", "fff60a4740086b3b9c56195b98d91a7b"},
    {"KeySbox-128 COUNT=17", 128, "13237c49074a3da078dc1d828bb78c6f",
     "00000000000000000000000000000000", "8146a08e2357f0caa30ca8c94d1a0544"},
    {"KeySbox-128 COUNT=18", 128, "3071a2a48fe6cbd04f1a129098e308f8",
     "00000000000000000000000000000000", "4b98e06d356deb07ebb824e5713f7be3"},
    {"KeySbox-128 COUNT=19", 128, "90f42ec0f68385f2ffc5dfc03a654dce",
     "00000000000000000000000000000000", "7a20a53d460fc9ce0423a7a0764c6cf2"},
    {"KeySbox-128 COUNT=20", 128, "febd9a24d8b65c1c787d50a4ed3619a9",
     "00000000000000000000000000000000", "f4a70d8af877f9b02b4c40df57d45b17"},
};

/* ----- NIST CAVP ECBKeySbox-256 ----- */
static const struct aes_kat KATS_KEYSBOX_256[] = {
    {"KeySbox-256 COUNT=0", 256,
     "c47b0294dbbbee0fec4757f22ffeee35"
     "87ca4730c3d33b691df38bab076bc558",
     "00000000000000000000000000000000", "46f2fb342d6f0ab477476fc501242c5f"},
    {"KeySbox-256 COUNT=1", 256,
     "28d46cffa158533194214a91e712fc2b"
     "45b518076675affd910edeca5f41ac64",
     "00000000000000000000000000000000", "4bf3b0a69aeb6657794f2901b1440ad4"},
    {"KeySbox-256 COUNT=2", 256,
     "c1cc358b449909a19436cfbb3f852ef8"
     "bcb5ed12ac7058325f56e6099aab1a1c",
     "00000000000000000000000000000000", "352065272169abf9856843927d0674fd"},
    {"KeySbox-256 COUNT=3", 256,
     "984ca75f4ee8d706f46c2d98c0bf4a45"
     "f5b00d791c2dfeb191b5ed8e420fd627",
     "00000000000000000000000000000000", "4307456a9e67813b452e15fa8fffe398"},
    {"KeySbox-256 COUNT=4", 256,
     "b43d08a447ac8609baadae4ff12918b9"
     "f68fc1653f1269222f123981ded7a92f",
     "00000000000000000000000000000000", "4663446607354989477a5c6f0f007ef4"},
    {"KeySbox-256 COUNT=5", 256,
     "1d85a181b54cde51f0e098095b2962fd"
     "c93b51fe9b88602b3f54130bf76a5bd9",
     "00000000000000000000000000000000", "531c2c38344578b84d50b3c917bbb6e1"},
    {"KeySbox-256 COUNT=6", 256,
     "dc0eba1f2232a7879ded34ed8428eeb8"
     "769b056bbaf8ad77cb65c3541430b4cf",
     "00000000000000000000000000000000", "fc6aec906323480005c58e7e1ab004ad"},
    {"KeySbox-256 COUNT=7", 256,
     "f8be9ba615c5a952cabbca24f68f8593"
     "039624d524c816acda2c9183bd917cb9",
     "00000000000000000000000000000000", "a3944b95ca0b52043584ef02151926a8"},
    {"KeySbox-256 COUNT=8", 256,
     "797f8b3d176dac5b7e34a2d539c4ef36"
     "7a16f8635f6264737591c5c07bf57a3e",
     "00000000000000000000000000000000", "a74289fe73a4c123ca189ea1e1b49ad5"},
    {"KeySbox-256 COUNT=9", 256,
     "6838d40caf927749c13f0329d331f448"
     "e202c73ef52c5f73a37ca635d4c47707",
     "00000000000000000000000000000000", "b91d4ea4488644b56cf0812fa7fcf5fc"},
    {"KeySbox-256 COUNT=10", 256,
     "ccd1bc3c659cd3c59bc437484e3c5c72"
     "4441da8d6e90ce556cd57d0752663bbc",
     "00000000000000000000000000000000", "304f81ab61a80c2e743b94d5002a126b"},
    {"KeySbox-256 COUNT=11", 256,
     "13428b5e4c005e0636dd338405d173ab"
     "135dec2a25c22c5df0722d69dcc43887",
     "00000000000000000000000000000000", "649a71545378c783e368c9ade7114f6c"},
    {"KeySbox-256 COUNT=12", 256,
     "07eb03a08d291d1b07408bf3512ab40c"
     "91097ac77461aad4bb859647f74f00ee",
     "00000000000000000000000000000000", "47cb030da2ab051dfc6c4bf6910d12bb"},
    {"KeySbox-256 COUNT=13", 256,
     "90143ae20cd78c5d8ebdd6cb9dc17624"
     "27a96c78c639bccc41a61424564eafe1",
     "00000000000000000000000000000000", "798c7c005dee432b2c8ea5dfa381ecc3"},
    {"KeySbox-256 COUNT=14", 256,
     "b7a5794d52737475d53d5a377200849b"
     "e0260a67a2b22ced8bbef12882270d07",
     "00000000000000000000000000000000", "637c31dc2591a07636f646b72daabbe7"},
    {"KeySbox-256 COUNT=15", 256,
     "fca02f3d5011cfc5c1e23165d413a049"
     "d4526a991827424d896fe3435e0bf68e",
     "00000000000000000000000000000000", "179a49c712154bbffbe6e7a84a18e220"},
};

/* ----- NIST CAVP ECBVarKey-128 (selected COUNT values) ----- */
static const struct aes_kat KATS_VARKEY_128[] = {
    {"VarKey-128 COUNT=0", 128, "80000000000000000000000000000000",
     "00000000000000000000000000000000", "0edd33d3c621e546455bd8ba1418bec8"},
    {"VarKey-128 COUNT=7", 128, "ff000000000000000000000000000000",
     "00000000000000000000000000000000", "b1d758256b28fd850ad4944208cf1155"},
    {"VarKey-128 COUNT=49", 128, "ffffffffffffc0000000000000000000",
     "00000000000000000000000000000000", "cb2f430383f9084e03a653571e065de6"},
    {"VarKey-128 COUNT=127", 128, "ffffffffffffffffffffffffffffffff",
     "00000000000000000000000000000000", "a1f6258c877d5fcd8964484538bfc92c"},
};

/* ----- NIST CAVP ECBVarKey-256 (selected COUNT values) ----- */
static const struct aes_kat KATS_VARKEY_256[] = {
    {"VarKey-256 COUNT=0", 256,
     "80000000000000000000000000000000"
     "00000000000000000000000000000000",
     "00000000000000000000000000000000", "e35a6dcb19b201a01ebcfa8aa22b5759"},
    {"VarKey-256 COUNT=7", 256,
     "ff000000000000000000000000000000"
     "00000000000000000000000000000000",
     "00000000000000000000000000000000", "ec52a212f80a09df6317021bc2a9819e"},
    {"VarKey-256 COUNT=127", 256,
     "ffffffffffffffffffffffffffffffff"
     "00000000000000000000000000000000",
     "00000000000000000000000000000000", "6825a347ac479d4f9d95c5cb8d3fd7e9"},
    {"VarKey-256 COUNT=255", 256,
     "ffffffffffffffffffffffffffffffff"
     "ffffffffffffffffffffffffffffffff",
     "00000000000000000000000000000000", "4bf85f1b5d54adbc307b0a048389adcb"},
};

/* ----- NIST CAVP ECBVarTxt-128 (selected COUNT values) ----- */
static const struct aes_kat KATS_VARTXT_128[] = {
    {"VarTxt-128 COUNT=0", 128, "00000000000000000000000000000000",
     "80000000000000000000000000000000", "3ad78e726c1ec02b7ebfe92b23d9ec34"},
    {"VarTxt-128 COUNT=7", 128, "00000000000000000000000000000000",
     "ff000000000000000000000000000000", "db4f1aa530967d6732ce4715eb0ee24b"},
    {"VarTxt-128 COUNT=49", 128, "00000000000000000000000000000000",
     "ffffffffffffc0000000000000000000", "ea2e6b5ef182b7dff3629abd6a12045f"},
    {"VarTxt-128 COUNT=127", 128, "00000000000000000000000000000000",
     "ffffffffffffffffffffffffffffffff", "3f5b8cc9ea855a0afa7347d23e8d664e"},
};

/* ----- NIST CAVP ECBVarTxt-256 (selected COUNT values) ----- */
static const struct aes_kat KATS_VARTXT_256[] = {
    {"VarTxt-256 COUNT=0", 256,
     "00000000000000000000000000000000"
     "00000000000000000000000000000000",
     "80000000000000000000000000000000", "ddc6bf790c15760d8d9aeb6f9a75fd4e"},
    {"VarTxt-256 COUNT=7", 256,
     "00000000000000000000000000000000"
     "00000000000000000000000000000000",
     "ff000000000000000000000000000000", "49af6b372135acef10132e548f217b17"},
    {"VarTxt-256 COUNT=64", 256,
     "00000000000000000000000000000000"
     "00000000000000000000000000000000",
     "ffffffffffffffff8000000000000000", "77f392089042e478ac16c0c86a0b5db5"},
    {"VarTxt-256 COUNT=127", 256,
     "00000000000000000000000000000000"
     "00000000000000000000000000000000",
     "ffffffffffffffffffffffffffffffff", "acdace8078a32b1a182bfa4987ca1347"},
};

/* ================================================================
 * Hex parsing and per-vector runner.
 * ================================================================ */

static int
hex_byte(const char *p)
{
    int hi = -1, lo = -1;
    char c;

    c = p[0];
    if (c >= '0' && c <= '9')
        hi = c - '0';
    else if (c >= 'a' && c <= 'f')
        hi = c - 'a' + 10;
    else if (c >= 'A' && c <= 'F')
        hi = c - 'A' + 10;

    c = p[1];
    if (c >= '0' && c <= '9')
        lo = c - '0';
    else if (c >= 'a' && c <= 'f')
        lo = c - 'a' + 10;
    else if (c >= 'A' && c <= 'F')
        lo = c - 'A' + 10;

    if (hi < 0 || lo < 0)
        return -1;
    return (hi << 4) | lo;
}

static int
hex2bytes(uint8_t *out, const char *hex, size_t out_len)
{
    if (strlen(hex) != out_len * 2)
        return -1;
    for (size_t i = 0; i < out_len; i++) {
        int b = hex_byte(hex + 2 * i);
        if (b < 0)
            return -1;
        out[i] = (uint8_t)b;
    }
    return 0;
}

static void
hex_print(const uint8_t *p, size_t n)
{
    for (size_t i = 0; i < n; i++)
        printf("%02x", p[i]);
}

static int
run_one(const struct aes_kat *kat, aes_encrypt_block_fn encrypt_block,
        int *tests_run, int *tests_passed)
{
    uint8_t key[32];
    uint8_t pt[16];
    uint8_t expected[16];
    uint8_t ct[16];
    int key_bytes = kat->key_bits / 8;

    (*tests_run)++;
    printf("  [%3d] %-50s ", *tests_run, kat->label);

    if (hex2bytes(key, kat->key_hex, (size_t)key_bytes) != 0 ||
        hex2bytes(pt, kat->pt_hex, 16) != 0 ||
        hex2bytes(expected, kat->ct_hex, 16) != 0) {
        printf("FAIL (bad hex)\n");
        return 1;
    }

    if (encrypt_block(kat->key_bits, key, ct, pt) != 0) {
        printf("FAIL (backend returned error)\n");
        return 1;
    }

    if (memcmp(ct, expected, 16) != 0) {
        printf("FAIL\n        expected: ");
        hex_print(expected, 16);
        printf("\n        got:      ");
        hex_print(ct, 16);
        printf("\n");
        return 1;
    }

    (*tests_passed)++;
    printf("PASS\n");
    return 0;
}

static int
run_group(const char *header, const struct aes_kat *kats, size_t n,
          aes_encrypt_block_fn encrypt_block, int *tests_run, int *tests_passed)
{
    int failures = 0;
    printf("\n  %s\n", header);
    for (size_t i = 0; i < n; i++) {
        if (run_one(&kats[i], encrypt_block, tests_run, tests_passed) != 0)
            failures++;
    }
    return failures;
}

#define RUN_GROUP(HEADER, ARR)                                                 \
    failures += run_group(HEADER, (ARR), sizeof(ARR) / sizeof((ARR)[0]),       \
                          encrypt_block, tests_run, tests_passed)

int
aes_kat_run_all(const char *backend_name, aes_encrypt_block_fn encrypt_block,
                int *tests_run, int *tests_passed)
{
    int failures = 0;

    printf("\nNIST AES KAT suite - backend: %s\n", backend_name);

    RUN_GROUP("FIPS 197 Appendix B", KATS_FIPS197);
    RUN_GROUP("NIST SP 800-38A Appendix F.1", KATS_SP800_38A);
    RUN_GROUP("All-zeros key+plaintext", KATS_ZERO);
    RUN_GROUP("NIST CAVP ECBGFSbox-128", KATS_GFSBOX_128);
    RUN_GROUP("NIST CAVP ECBGFSbox-256", KATS_GFSBOX_256);
    RUN_GROUP("NIST CAVP ECBKeySbox-128", KATS_KEYSBOX_128);
    RUN_GROUP("NIST CAVP ECBKeySbox-256", KATS_KEYSBOX_256);
    RUN_GROUP("NIST CAVP ECBVarKey-128", KATS_VARKEY_128);
    RUN_GROUP("NIST CAVP ECBVarKey-256", KATS_VARKEY_256);
    RUN_GROUP("NIST CAVP ECBVarTxt-128", KATS_VARTXT_128);
    RUN_GROUP("NIST CAVP ECBVarTxt-256", KATS_VARTXT_256);

    return failures;
}
