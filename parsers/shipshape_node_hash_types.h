/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * shipshape_node_hash_types.h - frozen node-hash type-id registry for
 * the Shipshape crypto-v2 bracket selector.
 *
 * Type ids are FROZEN and APPEND-ONLY.  Never renumber existing entries.
 * Adding a new hash family requires a new id at the end of the table and
 * a matching VOLEITH_SHIPSHAPE_NHT_* macro below.
 *
 * See docs/private/SHIPSHAPE_CRYPTO_V2_DESIGN.md §2 for the design
 * rationale and docs/private/SHIPSHAPE_CRYPTO_V2_SECRETDIR_IMPL_PLAN.md
 * MR1 for the implementation plan this file satisfies.
 */

#ifndef VOLEITH_PARSERS_SHIPSHAPE_NODE_HASH_TYPES_H
#define VOLEITH_PARSERS_SHIPSHAPE_NODE_HASH_TYPES_H

#include <stddef.h>
#include <stdint.h>
#include "node_hash_vt.h" /* voleith_node_hash_vt + the 8 extern vts */

/* Frozen, append-only node-hash type ids (crypto-v2).  Never renumber. */
#define VOLEITH_SHIPSHAPE_NHT_AES_DM 0
#define VOLEITH_SHIPSHAPE_NHT_AES_CMAC_128 1
#define VOLEITH_SHIPSHAPE_NHT_GROSTL_256 2
#define VOLEITH_SHIPSHAPE_NHT_GROSTL_256_T27 3
#define VOLEITH_SHIPSHAPE_NHT_GROSTL_512 4
#define VOLEITH_SHIPSHAPE_NHT_GROSTL_512_T59 5
#define VOLEITH_SHIPSHAPE_NHT_HIROSE 6
#define VOLEITH_SHIPSHAPE_NHT_HIROSE_FIXED_32 7

typedef struct {
    const char *name; /* surface name, snake_case */
    uint16_t type_id;
    const voleith_node_hash_vt *vt;
} voleith_shipshape_node_hash_type_t;

extern const voleith_shipshape_node_hash_type_t
    voleith_shipshape_node_hash_types[];
extern const size_t voleith_shipshape_node_hash_types_count;

/* Resolve a name slice [name, name+len).  Returns the entry or NULL. */
const voleith_shipshape_node_hash_type_t *
voleith_shipshape_node_hash_type_by_name(const char *name, size_t len);

/* Resolve by id.  Returns the entry or NULL. */
const voleith_shipshape_node_hash_type_t *
voleith_shipshape_node_hash_type_by_id(uint16_t type_id);

#endif /* VOLEITH_PARSERS_SHIPSHAPE_NODE_HASH_TYPES_H */
