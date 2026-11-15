/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * node_hash_grostl_norm_gf8.c - fixed-input Grostl node-hash vts with
 * the FAEST paired-round norm S-box.  See node_hash_grostl_norm_gf8.h.
 *
 * The construction bodies and IV constants are shared with the frozen
 * vts through node_hash_grostl_gf8_internal.h; this file is the norm
 * instantiation, driving the shared vt macros with norm = 1.  Same node
 * output as the frozen vts, smaller witness (a clean 0.75: Grostl has
 * no key schedule, so every S-box shrinks).  The software helpers
 * (leaf_hash / inode_hash) are reused unchanged: the node output is
 * identical, so they carry no norm flag.
 */

#include "node_hash_grostl_norm_gf8.h"
#include "node_hash_grostl_gf8_internal.h"

NH_GROSTL_FIXED_VT(256, 32, "grostl-256-fixed-norm", 128,
                   voleith_node_hash_grostl256_fixed_norm, 1, nh_g256_fixed_n);
NH_GROSTL_FIXED_VT(512, 64, "grostl-512-fixed-norm", 256,
                   voleith_node_hash_grostl512_fixed_norm, 1, nh_g512_fixed_n);
NH_GROSTL_FIXED2_VT(256, 32, "grostl-256-fixed128-norm", 128,
                    voleith_node_hash_grostl256_fixed128_norm, 1,
                    nh_g256_fixed2_n);
NH_GROSTL_FIXED2_VT(512, 64, "grostl-512-fixed256-norm", 256,
                    voleith_node_hash_grostl512_fixed256_norm, 1,
                    nh_g512_fixed2_n);
