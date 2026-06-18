/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * test_shipshape_examples.c - the W7.1 example `.ship` corpus parses.
 *
 * Loads each shipped example from tests/data/shipshape/ through the public
 * file entry point and asserts it parses to a circuit (return 0).  This is
 * the build-time guard that the hand-written corpus stays valid as the
 * grammar evolves; the end-to-end prove/verify of one of them is W7.2.
 */

#include "gf8_circuit.h"
#include "shipshape.h"

#include <stddef.h>
#include <stdio.h>
#include <string.h>

#ifndef VOLEITH_TEST_SOURCE_DIR
#define VOLEITH_TEST_SOURCE_DIR "."
#endif

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

static const char *const EXAMPLES[] = {
    "aes128_key_knowledge.ship",
    "cmac_tag_verify.ship",
    "merkle_path_public.ship",
    "merkle_path_secret.ship",
};

static void
parse_example(const char *file)
{
    voleith_shipshape_parsed_t p;
    char path[512];
    int r;

    snprintf(path, sizeof(path), "%s/tests/data/shipshape/%s",
             VOLEITH_TEST_SOURCE_DIR, file);
    r = voleith_shipshape_parse_file(&p, path, NULL);
    check(file, r == 0 && p.circuit != NULL &&
                    voleith_gf8_circuit_wire_count(p.circuit) > 0);
    voleith_shipshape_parsed_free(&p);
}

int
main(void)
{
    printf("test_shipshape_examples: starting\n");
    for (size_t i = 0; i < sizeof(EXAMPLES) / sizeof(EXAMPLES[0]); i++)
        parse_example(EXAMPLES[i]);
    printf("test_shipshape_examples: %d/%d passed\n", pass_count, test_count);
    return (pass_count == test_count) ? 0 : 1;
}
