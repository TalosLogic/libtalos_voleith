/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * cpu_generic.c - CPU feature probing for architectures other than
 * x86_64 and aarch64.
 *
 * Returns 0: no hardware acceleration available; dispatch falls through
 * to the bitsliced/scalar software backends.
 *
 * Compiled on all targets but only produces non-empty code on hosts
 * that are neither x86_64 nor aarch64 (where cpu_x86.c and
 * cpu_aarch64.c both compile to empty objects).
 */

#if !defined(__x86_64__) && !defined(_M_X64) && !defined(__aarch64__)

#include "cpu.h"

unsigned
voleith_cpu_probe(void)
{
    return 0;
}

#endif
