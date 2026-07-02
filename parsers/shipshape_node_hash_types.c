/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * shipshape_node_hash_types.c - frozen node-hash type-id registry for
 * the Shipshape crypto-v2 bracket selector.
 *
 * The table is ordered by type_id and MUST remain so.  Type ids are
 * frozen: never renumber, never remove, only append.  See
 * the crypto-v2 implementation plan MR1.
 */

#include "shipshape_node_hash_types.h"

#include <stddef.h>
#include <stdint.h>
#include <string.h>

/*
 * Frozen table.  Entries are in strict type_id order (0..9).
 * The .name field is the surface name used in .ship bracket selectors,
 * e.g. merkle/path_secret[aes_dm].  The .vt pointer references the
 * extern vt declared in node_hash_vt.h.
 */
const voleith_shipshape_node_hash_type_t voleith_shipshape_node_hash_types[] = {
    {"aes_dm", VOLEITH_SHIPSHAPE_NHT_AES_DM, &voleith_node_hash_aes_dm},
    {"aes_cmac_128", VOLEITH_SHIPSHAPE_NHT_AES_CMAC_128,
     &voleith_node_hash_aes_cmac128},
    {"grostl_256", VOLEITH_SHIPSHAPE_NHT_GROSTL_256,
     &voleith_node_hash_grostl256},
    {"grostl_256_t27", VOLEITH_SHIPSHAPE_NHT_GROSTL_256_T27,
     &voleith_node_hash_grostl256_t27},
    {"grostl_512", VOLEITH_SHIPSHAPE_NHT_GROSTL_512,
     &voleith_node_hash_grostl512},
    {"grostl_512_t59", VOLEITH_SHIPSHAPE_NHT_GROSTL_512_T59,
     &voleith_node_hash_grostl512_t59},
    {"hirose", VOLEITH_SHIPSHAPE_NHT_HIROSE, &voleith_node_hash_hirose},
    {"hirose_fixed_32", VOLEITH_SHIPSHAPE_NHT_HIROSE_FIXED_32,
     &voleith_node_hash_hirose_fixed32},
    {"grostl_256_fixed", VOLEITH_SHIPSHAPE_NHT_GROSTL_256_FIXED,
     &voleith_node_hash_grostl256_fixed},
    {"grostl_512_fixed", VOLEITH_SHIPSHAPE_NHT_GROSTL_512_FIXED,
     &voleith_node_hash_grostl512_fixed},
};

const size_t voleith_shipshape_node_hash_types_count =
    sizeof(voleith_shipshape_node_hash_types) /
    sizeof(voleith_shipshape_node_hash_types[0]);

/*
 * Resolve a name slice [name, name+len) to a registry entry.
 * Uses an exact-length compare: no prefix or fuzzy matching.
 * Returns the entry or NULL if not found.
 *
 * Mirrors registry_lookup() in parsers/shipshape.c.
 */
const voleith_shipshape_node_hash_type_t *
voleith_shipshape_node_hash_type_by_name(const char *name, size_t len)
{
    size_t i;

    for (i = 0; i < voleith_shipshape_node_hash_types_count; i++) {
        const char *entry_name = voleith_shipshape_node_hash_types[i].name;
        if (strlen(entry_name) == len && memcmp(entry_name, name, len) == 0)
            return &voleith_shipshape_node_hash_types[i];
    }
    return NULL;
}

/*
 * Resolve a type_id to a registry entry.
 * Returns the entry or NULL if type_id >= count.
 */
const voleith_shipshape_node_hash_type_t *
voleith_shipshape_node_hash_type_by_id(uint16_t type_id)
{
    size_t i;

    for (i = 0; i < voleith_shipshape_node_hash_types_count; i++) {
        if (voleith_shipshape_node_hash_types[i].type_id == type_id)
            return &voleith_shipshape_node_hash_types[i];
    }
    return NULL;
}
