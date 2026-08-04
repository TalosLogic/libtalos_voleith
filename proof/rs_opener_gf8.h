/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * rs_opener_gf8.h - generic designated-opener dispatch layer.
 *
 * A designated opener lets a signer seal its identity to a tracing authority:
 * the signature carries a tag = Enc(opener_pk, identity; r), the circuit proves
 * (in a later ticket) that the tag encrypts the membership-committed identity
 * under the pinned opener key, and the opener later decrypts to trace.  The
 * *envelope* around that (parse tag, recompute the encryption relation, check it,
 * check the plaintext binds to the identity, return a trusted-caller status) is
 * PKE-independent; the encryption relation and its circuit gadget are not.
 *
 * This header is the PKE-independent layer: a frozen one-byte scheme registry, a
 * scheme interface (`voleith_rs_opener_scheme_t` ops vtable), a self-describing
 * witness reference, and generic entry points that dispatch to the selected
 * scheme.  Each concrete PKE opener is a backend implementing the ops vtable;
 * the only one today is the Argus / QC-MDPC code-based opener
 * (proof/rs_opener_argus_gf8.h).  Adding a backend (e.g. a code-based HQC opener)
 * is additive: a new `scheme_id`, a new ops instance, one registry row; no
 * signature here changes and no existing backend is touched.
 *
 * `scheme_id` is the frozen discriminator.  It is absorbed into the circuit
 * fingerprint, the Fiat-Shamir transcript, and the serialization envelope (OP.CFG
 * / OP.SIGN / OP.SER), so the very first frozen opener circuit is scheme-tagged:
 * a second scheme is a new registry value in an existing format, never a second
 * format.  It is orthogonal to a scheme's internal parameter axis (Argus's
 * (lambda, n0) set) and to the tag's KDF-hash byte (Argus's prim_id).
 */

#ifndef VOLEITH_RS_OPENER_GF8_H
#define VOLEITH_RS_OPENER_GF8_H

#include <stddef.h>
#include <stdint.h>

/*
 * Frozen opener-scheme registry (one byte, append-only, absorbed big-endian into
 * the circuit fingerprint / FS transcript / envelope).  A sequential counter,
 * not cryptographically meaningful; ids are stable once assigned.
 */
#define VOLEITH_RS_OPENER_SCHEME_ARGUS 0x01u /* QC-MDPC code-based (Argus) */

/* ---- typed status ---------------------------------------------------------
 * 0 on success; negative on failure.  The verify path distinguishes which check
 * failed for the trusted caller and the tamper KATs; this status is NOT an
 * openability oracle to expose to untrusted parties (contract D2).
 */
#define VOLEITH_RS_OPENER_OK 0
#define VOLEITH_RS_OPENER_EARGS (-1)        /* null / bad length              */
#define VOLEITH_RS_OPENER_EUNSUPPORTED (-2) /* hash_id not this build's prim  */
#define VOLEITH_RS_OPENER_ESYNDROME (-3)    /* encryption relation != tag     */
#define VOLEITH_RS_OPENER_EIDENTITY (-4)    /* recovered plaintext != id      */
#define VOLEITH_RS_OPENER_ESET (-5)         /* set reserved, not this build   */
#define VOLEITH_RS_OPENER_ESCHEME (-6)      /* witness tag != scheme          */
#define VOLEITH_RS_OPENER_ENOMEM (-7)       /* working-buffer allocation fail */

/*
 * Self-describing opening witness.  The witness contents are scheme-specific
 * (Argus: the weight-t support index list), so they cross the generic boundary
 * as an opaque pointer paired with the scheme tag that says how to read them.
 * The generic layer checks `scheme_id` before dispatch (ESCHEME on mismatch), so
 * a witness built for one scheme cannot be fed to another.  Backends provide a
 * typed constructor that stamps this (e.g. voleith_rs_opener_argus_witness), so
 * application code rarely writes `data` by hand.  This is a tagged reference, not
 * a union: the generic core never enumerates backend witness types, so a new
 * backend does not touch it.
 */
typedef struct {
    uint8_t scheme_id;
    const void *data; /* backend casts to its concrete witness type */
} voleith_rs_opener_witness_t;

/*
 * Opener scheme interface (ops vtable).  One static const instance per backend,
 * registered by `scheme_id`.  All buffer arguments are caller-owned.
 *
 *   scheme_id  the frozen registry id this backend implements.
 *   name       short human label (diagnostics only, not frozen).
 *   params     resolve the opaque per-set parameters for a scheme-internal
 *              selector `set`; returns NULL if `set` is out of range or reserved
 *              but not parameterized in this build.
 *   tag_bytes  total tag length for an identity of `id_len` bytes under `params`.
 *   verify     recompute the encryption relation from `witness`, check it equals
 *              the tag's relation field, derive the DEM key, and check the tag's
 *              ciphertext decrypts to `id`.  `pk` is the opener public key bytes,
 *              `tag` the full tag (relation field + ciphertext + any selector
 *              bytes).  Returns VOLEITH_RS_OPENER_OK or a typed negative.
 */
typedef struct voleith_rs_opener_scheme {
    uint8_t scheme_id;
    const char *name;
    const void *(*params)(uint32_t set);
    size_t (*tag_bytes)(const void *params, size_t id_len);
    int (*verify)(const void *params, const uint8_t *pk, const uint8_t *tag,
                  size_t tag_len, const void *witness_data, const uint8_t *id,
                  size_t id_len);
} voleith_rs_opener_scheme_t;

/*
 * Look up a registered scheme by its frozen id, or NULL if no backend for that
 * id is compiled in this build.
 */
const voleith_rs_opener_scheme_t *voleith_rs_opener_scheme(uint8_t scheme_id);

/*
 * Total tag length for `id_len` bytes of identity under (`scheme`, `set`).
 * Returns 0 if `scheme` is NULL or `set` is unsupported.
 */
size_t voleith_rs_opener_tag_bytes(const voleith_rs_opener_scheme_t *scheme,
                                   uint32_t set, size_t id_len);

/*
 * Generic verify: resolve params for `set`, check the witness scheme tag, and
 * dispatch to the backend.  Returns:
 *   EARGS       a null argument,
 *   ESCHEME     witness->scheme_id != scheme->scheme_id,
 *   ESET        `set` unsupported for this scheme in this build,
 *   otherwise   the backend's status (OK / EUNSUPPORTED / ESYNDROME / EIDENTITY).
 * The caller is trusted (contract D1/D2); the status must not be republished as
 * an openability oracle.
 */
int voleith_rs_opener_verify(const voleith_rs_opener_scheme_t *scheme,
                             uint32_t set, const uint8_t *pk,
                             const uint8_t *tag, size_t tag_len,
                             const voleith_rs_opener_witness_t *witness,
                             const uint8_t *id, size_t id_len);

#endif /* VOLEITH_RS_OPENER_GF8_H */
