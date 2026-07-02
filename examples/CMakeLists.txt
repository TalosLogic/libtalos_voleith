# Copyright (c) 2026 Jason Crawford
# SPDX-License-Identifier: AGPL-3.0-only

cmake_minimum_required(VERSION 3.16)

# Example programs - each demonstrates a ZK proof for one circuit type.
# All examples link against the production voleith_core library (with
# hardware acceleration when available).

set(EXAMPLE_NAMES
    example_aes
    example_aes_gf8
    example_aes_cmac
    example_aes_cmac_gf8
    example_kdf
    example_kdf_gf8
    example_merkle
    example_merkle_gf8
    example_merkle_grostl_gf8
    example_merkle_hirose_gf8
    example_grostl_fixed_merkle
    example_hirose_gf8
    example_hirose_leaf_gf8
    example_hirose_inode_gf8
    example_indexed_merkle
    example_indexed_merkle_gf8
    example_indexed_merkle_grostl_gf8
    example_kvac_pq
    example_kvac_pq_gf8
    example_kvac_pq_gf8_depth12
    example_kvac_pq_grostl_gf8
    example_kvac_pq_grostl_gf8_depth12
    example_ring_sig_v1_gf8
    example_ring_sig_v1_revocable_gf8
    example_rs_v2_linkable_gf8
    example_rs_v3_attribute_gf8
    example_rs_v4_claimable_gf8
    example_rs_composite_gf8
    example_bristol_aes128
    example_shipshape_parse_prove
    example_shipshape_anon_membership
    example_shipshape_kvac
    example_shipshape_ring_sig
)

foreach(EXAMPLE ${EXAMPLE_NAMES})
    add_executable(${EXAMPLE} ${EXAMPLE}.c)
    target_link_libraries(${EXAMPLE} PRIVATE voleith_core)
    set_target_properties(${EXAMPLE} PROPERTIES
        RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/examples)
endforeach()

# Default .ship path for the parse/prove example (overridable via argv[1]).
target_compile_definitions(example_shipshape_parse_prove PRIVATE
    VOLEITH_SHIPSHAPE_DATA_DIR="${CMAKE_SOURCE_DIR}/tests/data/shipshape")

# Default .ship path for the anonymous membership example (overridable via argv[1]).
target_compile_definitions(example_shipshape_anon_membership PRIVATE
    VOLEITH_SHIPSHAPE_DATA_DIR="${CMAKE_SOURCE_DIR}/tests/data/shipshape")

# .ship data dir for the KVAC credential lifecycle example.
target_compile_definitions(example_shipshape_kvac PRIVATE
    VOLEITH_SHIPSHAPE_DATA_DIR="${CMAKE_SOURCE_DIR}/tests/data/shipshape")

# Default .ship path for the RSv1 ring signature example (overridable via argv[1]).
target_compile_definitions(example_shipshape_ring_sig PRIVATE
    VOLEITH_SHIPSHAPE_DATA_DIR="${CMAKE_SOURCE_DIR}/tests/data/shipshape")
