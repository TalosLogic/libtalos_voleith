/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * backend_notice.c - lean-build fallback notice for ichor-owned primitives.
 *
 * See backend_notice.h.  ichor's <ichor/backend.h> tells us whether a
 * primitive selected its software fallback because the matching hardware
 * backend was absent from the build (ICHOR_BACKEND_FALLBACK) while the host
 * advertises the feature.  ichor names the situation but performs no I/O; we
 * turn a FALLBACK verdict into the voleith-branded stderr notice, choosing the
 * ISA / rebuild-flag wording from the host feature bits.  ichor's Grøstl
 * hardware backend rides the same VOLEITH_AES_NI / VOLEITH_ARMV8_AES options
 * as AES, so both notices name the same flag.
 */

#include "backend_notice.h"
#include "cpu.h"

#include <ichor/backend.h>

#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>

static atomic_flag s_notice_once = ATOMIC_FLAG_INIT;

static void
emit_aes_notice(unsigned feat)
{
    if (feat & VOLEITH_CPU_AES_NI)
        fputs("voleith: notice: host CPU has AES-NI but the aes-ni backend"
              " was not compiled in; running on software fallback."
              " Rebuild with -DVOLEITH_AES_NI=ON."
              " Suppress with VOLEITH_QUIET=1.\n",
              stderr);
    else if (feat & VOLEITH_CPU_ARMV8_AES)
        fputs("voleith: notice: host CPU has ARMv8 AES but the armv8-aes"
              " backend was not compiled in; running on software fallback."
              " Rebuild with -DVOLEITH_ARMV8_AES=ON."
              " Suppress with VOLEITH_QUIET=1.\n",
              stderr);
}

static void
emit_grostl_notice(unsigned feat)
{
    if (feat & VOLEITH_CPU_AES_NI)
        fputs("voleith: notice: host CPU has AES-NI but the grostl hardware"
              " backend was not compiled in; running on software fallback."
              " Rebuild with -DVOLEITH_AES_NI=ON."
              " Suppress with VOLEITH_QUIET=1.\n",
              stderr);
    else if (feat & VOLEITH_CPU_ARMV8_AES)
        fputs("voleith: notice: host CPU has ARMv8 AES but the grostl hardware"
              " backend was not compiled in; running on software fallback."
              " Rebuild with -DVOLEITH_ARMV8_AES=ON."
              " Suppress with VOLEITH_QUIET=1.\n",
              stderr);
}

void
voleith_backend_notice(void)
{
    /* Quiet check first so it does not consume the once-guard: a later
     * non-quiet call can still fire (matches core/field.c's notice). */
    if (getenv("VOLEITH_QUIET") != NULL)
        return;
    if (atomic_flag_test_and_set(&s_notice_once))
        return;

    unsigned feat = voleith_cpu_features();

    if (ichor_aes_backend_health() == ICHOR_BACKEND_FALLBACK)
        emit_aes_notice(feat);
    if (ichor_grostl_backend_health() == ICHOR_BACKEND_FALLBACK)
        emit_grostl_notice(feat);
}

#ifdef ICHOR_ENABLE_FORCE_BACKEND
void
voleith_backend_notice_reset(void)
{
    atomic_flag_clear(&s_notice_once);
}
#endif
