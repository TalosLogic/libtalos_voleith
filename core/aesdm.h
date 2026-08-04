/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * aesdm.h - alias shim over <ichor/aesdm.h>.
 *
 * AES-128 Davies-Meyer single-block-length compression lives in libtalos_ichor
 * (shared with libtalos_syndrome).  voleith's opener KDF (the lambda128 Argus
 * extractor, proof/rs_opener_argus_gf8.c) reaches only the public voleith_aesdm*
 * API here, which maps 1:1 to ichor_aesdm*.  Mirrors core/grostl.h: the full
 * multi-block hash surface (init_iv / absorb / finalize_fixed / clear) is aliased
 * so the KDF stays on voleith_* names; the bare single iteration is reached
 * through <ichor/aesdm.h> directly if ever needed.
 */

#ifndef VOLEITH_AESDM_H
#define VOLEITH_AESDM_H

#include <ichor/aesdm.h>

typedef ichor_aesdm_ctx_t voleith_aesdm_ctx_t;

#define voleith_aesdm_init_iv ichor_aesdm_init_iv
#define voleith_aesdm_absorb ichor_aesdm_absorb
#define voleith_aesdm_finalize_fixed ichor_aesdm_finalize_fixed
#define voleith_aesdm_clear ichor_aesdm_clear

#endif /* VOLEITH_AESDM_H */
