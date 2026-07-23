/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * backend_notice.h - lean-build fallback notice for ichor-owned primitives.
 *
 * The AES and Grøstl backends moved to libtalos_ichor (1.10.1), which does
 * no I/O of its own and reports backend health only through its query API
 * (<ichor/backend.h>).  This internal helper restores voleith's pre-1.10.1
 * operator-facing behavior: it queries ichor's per-primitive health once and,
 * when the running CPU has a hardware backend that was opted out at compile
 * time, emits the same one-shot stderr notice voleith used to print from its
 * own AES / Grøstl dispatch.  The GF(2^k) field notice stays lazy in field.c
 * (field dispatch remains voleith-side).
 *
 * Internal only: not part of the public API (include/voleith*.h).  Called from
 * the public proof entry points so the notice fires once per process on first
 * prove / verify.
 */

#ifndef VOLEITH_BACKEND_NOTICE_H
#define VOLEITH_BACKEND_NOTICE_H

/*
 * Emit the AES / Grøstl lean-build fallback notice(s) to stderr at most once
 * per process.  No-op when VOLEITH_QUIET is set, when the active backends are
 * optimal, or on a host lacking the relevant hardware.  Idempotent and
 * thread-safe; cheap to call from every entry point.
 */
void voleith_backend_notice(void);

#ifdef ICHOR_ENABLE_FORCE_BACKEND
/* Test-only: clear the once-guard so a test can re-trigger the notice.
 * Gated behind the same macro as the dispatch-reset hooks. */
void voleith_backend_notice_reset(void);
#endif

#endif /* VOLEITH_BACKEND_NOTICE_H */
