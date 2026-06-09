/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * cpu_aarch64.c - CPU feature probing for aarch64.
 *
 * Linux: reads HWCAP bits via getauxval(AT_HWCAP).
 * macOS (Apple Silicon): reads hw.optional.arm.FEAT_* via sysctlbyname.
 * Other aarch64 OSes: returns 0 (bitsliced fallback).
 *
 * Compiled on all targets but only produces non-empty code on aarch64.
 */

#if defined(__aarch64__)

#include "cpu.h"

#if defined(__linux__)

#include <sys/auxv.h>

#ifndef HWCAP_AES
#define HWCAP_AES (1 << 3)
#endif
#ifndef HWCAP_PMULL
#define HWCAP_PMULL (1 << 4)
#endif

unsigned
voleith_cpu_probe(void)
{
    unsigned long hwcap = getauxval(AT_HWCAP);
    unsigned mask = 0;

    if (hwcap & HWCAP_AES)
        mask |= VOLEITH_CPU_ARMV8_AES;
    if (hwcap & HWCAP_PMULL)
        mask |= VOLEITH_CPU_PMULL;
    return mask;
}

#elif defined(__APPLE__)

#include <string.h>
#include <sys/sysctl.h>

static int
sysctl_int(const char *name)
{
    int v = 0;
    size_t sz = sizeof(v);

    if (sysctlbyname(name, &v, &sz, NULL, 0) != 0)
        return 0;
    return v;
}

unsigned
voleith_cpu_probe(void)
{
    unsigned mask = 0;

    if (sysctl_int("hw.optional.arm.FEAT_AES"))
        mask |= VOLEITH_CPU_ARMV8_AES;
    if (sysctl_int("hw.optional.arm.FEAT_PMULL"))
        mask |= VOLEITH_CPU_PMULL;
    return mask;
}

#else

/* Unknown aarch64 OS: assume no acceleration available. */
unsigned
voleith_cpu_probe(void)
{
    return 0;
}

#endif /* OS selection */

#endif /* __aarch64__ */
