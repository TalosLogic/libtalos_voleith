/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * cpu_x86.c - CPU feature probing for x86_64.
 *
 * Uses <cpuid.h> (shipped by GCC and Clang) rather than inline
 * assembly so the probe compiles without requiring per-feature ISA
 * flags on this translation unit.
 *
 * Compiled on all targets but only produces non-empty code on x86_64.
 */

#if defined(__x86_64__) || defined(_M_X64)

#include "cpu.h"

#include <cpuid.h>

unsigned
voleith_cpu_probe(void)
{
    unsigned eax, ebx, ecx, edx;
    unsigned mask = 0;

    if (__get_cpuid_count(1, 0, &eax, &ebx, &ecx, &edx)) {
        if (ecx & (1u << 25))
            mask |= VOLEITH_CPU_AES_NI;
        if (ecx & (1u << 1))
            mask |= VOLEITH_CPU_CLMUL;
        if (ecx & (1u << 19))
            mask |= VOLEITH_CPU_SSE41;
        if (ecx & (1u << 9))
            mask |= VOLEITH_CPU_SSSE3;
    }
    return mask;
}

#endif /* __x86_64__ || _M_X64 */
