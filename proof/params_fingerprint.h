/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * params_fingerprint.h - 16-byte SHAKE-128 fingerprint over a params struct.
 *
 * Used by the proof metadata header (proof_header.h) to bind a proof to
 * a specific voleith_params_t value.  For the six named EM-* parameter
 * sets the fingerprint duplicates the information in the header's
 * PARAM_SET_ID byte; for caller-constructed (custom) params it is the
 * only binding.
 *
 * Canonical serialization (input to SHAKE-128):
 *
 *   domain_tag   = "voleith-params-cf-v1" || 0x00   (21 bytes)
 *   u32_le lambda
 *   u32_le tau
 *   u32_le w_grind
 *   u32_le n_leafcom
 *   u32_le T_open
 *   u8     fs_kind        (from params->fs_kind; matches header FS_KIND)
 *   u8     bavc_kind      (from params->bavc_kind; matches header BAVC_KIND)
 *   u8[6]  zero_padding   (reserved for future struct fields)
 *
 * The "-v1" suffix in the domain tag pins this layout.  Any future
 * change to the canonical encoding MUST come with a new tag.
 */

#ifndef VOLEITH_PARAMS_FINGERPRINT_H
#define VOLEITH_PARAMS_FINGERPRINT_H

#include <stddef.h>
#include <stdint.h>

#include "proof.h" /* voleith_params_t */

#define VOLEITH_PARAMS_FINGERPRINT_BYTES 16
#define VOLEITH_PARAMS_FINGERPRINT_DOMAIN_TAG "voleith-params-cf-v1"

/*
 * Compute SHAKE-128 of the canonical serialization of *params, truncated
 * to VOLEITH_PARAMS_FINGERPRINT_BYTES bytes.
 *
 * Returns 0 on success, -1 if params or out is NULL.  Does not modify
 * out on failure.  Does not validate params field ranges - that is
 * voleith_params_validate's job; callers should run it separately if
 * they need to reject malformed structs early.
 */
int voleith_params_fingerprint(const voleith_params_t *params,
                               uint8_t out[VOLEITH_PARAMS_FINGERPRINT_BYTES]);

#endif /* VOLEITH_PARAMS_FINGERPRINT_H */
