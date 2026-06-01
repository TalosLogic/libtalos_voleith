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
)

foreach(EXAMPLE ${EXAMPLE_NAMES})
    add_executable(${EXAMPLE} ${EXAMPLE}.c)
    target_link_libraries(${EXAMPLE} PRIVATE voleith_core)
    set_target_properties(${EXAMPLE} PROPERTIES
        RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/examples)
endforeach()
