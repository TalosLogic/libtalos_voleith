# Copyright (c) 2026 Jason Crawford
# SPDX-License-Identifier: AGPL-3.0-only

# Test executables build into their own directory
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/tests)

# Helper function: create one test executable linked against the fat library and
# register it under two CTest names:
#   <TEST_NAME>     -- hardware profile: best backend selected at runtime
#   <TEST_NAME>_sw  -- software profile: all domains forced to fallback paths
#
# Additional source files (shared test helpers) may be supplied after the
# main TEST_SOURCE.
function(voleith_add_test TEST_NAME TEST_SOURCE)
    add_executable(${TEST_NAME} ${TEST_SOURCE} ${ARGN})
    target_link_libraries(${TEST_NAME} voleith_core)

    # Let tests that read fixtures (e.g. NIST KAT files under
    # third_party/) locate the repo root at runtime.
    target_compile_definitions(${TEST_NAME} PRIVATE
        VOLEITH_TEST_SOURCE_DIR="${CMAKE_SOURCE_DIR}")

    # The core shim headers gate the test-only dispatch-reset / cpu-features-
    # override aliases (voleith_aes_dispatch_reset, voleith_cpu_features_override)
    # behind ICHOR_ENABLE_FORCE_BACKEND.  ichor exports that macro PUBLIC on the
    # ichor target, but voleith_core links ichor PRIVATE, so it does not reach a
    # test TU that includes core/aes.h or core/cpu.h.  Define it directly on the
    # test target (the variable is ON whenever tests are configured).
    if(ICHOR_ENABLE_FORCE_BACKEND)
        target_compile_definitions(${TEST_NAME} PRIVATE ICHOR_ENABLE_FORCE_BACKEND)
    endif()

    # Add intrinsics compile flags for test source files that use them directly.
    get_target_property(LIB_DEFS voleith_core INTERFACE_COMPILE_DEFINITIONS)
    if(LIB_DEFS)
        if("VOLEITH_HAVE_CLMUL" IN_LIST LIB_DEFS)
            target_compile_options(${TEST_NAME} PRIVATE -mpclmul -msse2 -msse4.1)
        endif()
        if("VOLEITH_HAVE_AES_NI" IN_LIST LIB_DEFS)
            target_compile_options(${TEST_NAME} PRIVATE -maes -msse2 -mssse3)
        endif()
    endif()

    # Hardware profile: runtime dispatch selects the best compiled-in backend.
    add_test(NAME ${TEST_NAME} COMMAND $<TARGET_FILE:${TEST_NAME}>)

    # Software profile: forces all dispatch domains to their fallback paths so
    # the software backends are validated even on hardware-capable hosts.  All
    # backend forcing routes through ichor's ICHOR_FORCE_BACKEND (its
    # ichor_cpu_features() masks the probed feature word; voleith's field
    # dispatch reads that same masked word).  aes:bitsliced also forces Grostl
    # soft (it rides the AES S-box backend); clmul:scalar forces the voleith
    # field backend scalar (it rides the CLMUL/PMULL feature bits).
    add_test(NAME ${TEST_NAME}_sw COMMAND $<TARGET_FILE:${TEST_NAME}>)
    set_tests_properties(${TEST_NAME}_sw PROPERTIES
        ENVIRONMENT "ICHOR_FORCE_BACKEND=aes:bitsliced,clmul:scalar")
endfunction()

# Register a test that only runs in the hardware profile (no _sw variant).
# Use for tests that verify the detection layer itself rather than backend
# correctness.  The _sw profile's ICHOR_FORCE_BACKEND override makes
# hardware cross-check assertions trivially wrong for those tests.
function(voleith_add_hw_test TEST_NAME TEST_SOURCE)
    add_executable(${TEST_NAME} ${TEST_SOURCE} ${ARGN})
    target_link_libraries(${TEST_NAME} voleith_core)

    target_compile_definitions(${TEST_NAME} PRIVATE
        VOLEITH_TEST_SOURCE_DIR="${CMAKE_SOURCE_DIR}")

    get_target_property(LIB_DEFS voleith_core INTERFACE_COMPILE_DEFINITIONS)
    if(LIB_DEFS)
        if("VOLEITH_HAVE_CLMUL" IN_LIST LIB_DEFS)
            target_compile_options(${TEST_NAME} PRIVATE -mpclmul -msse2 -msse4.1)
        endif()
        if("VOLEITH_HAVE_AES_NI" IN_LIST LIB_DEFS)
            target_compile_options(${TEST_NAME} PRIVATE -maes -msse2 -mssse3)
        endif()
    endif()

    add_test(NAME ${TEST_NAME} COMMAND $<TARGET_FILE:${TEST_NAME}>)
endfunction()

# Apply a CTest label to both profiles of a registered test.
# Use the "slow" label for heavy tests (e.g. the Monte Carlo chains) so the
# default loop can skip them with `ctest -LE slow` and run them on demand
# with `ctest -L slow`.
function(voleith_label_test TEST_NAME)
    set_tests_properties(${TEST_NAME} ${TEST_NAME}_sw PROPERTIES LABELS "${ARGN}")
endfunction()

# Register tests
voleith_add_test(test_field test_field.c)
voleith_add_test(test_field16 test_field16.c)
voleith_add_test(test_gf16_embed test_gf16_embed.c)
voleith_add_test(test_erasure_matrix test_erasure_matrix.c)
voleith_add_test(test_erasure_rs test_erasure_rs.c)
voleith_add_test(test_erasure_rlnc test_erasure_rlnc.c)
voleith_add_test(test_rlnc_confidential test_rlnc_confidential.c)
voleith_add_test(test_erasure_rs_dataset test_erasure_rs_dataset.c)
voleith_add_test(test_erasure_rs_chunk_cert_circuit
                 test_erasure_rs_chunk_cert_circuit.c)
voleith_add_test(test_erasure_rs_chunk_cert test_erasure_rs_chunk_cert.c)
voleith_label_test(test_erasure_rs_chunk_cert slow)
voleith_add_test(test_erasure_rs_retriever test_erasure_rs_retriever.c)
voleith_add_test(test_rs_consistency test_rs_consistency.c)
voleith_add_test(test_rs_wire test_rs_wire.c)
voleith_add_test(test_node_hash_hirose_gf8 test_node_hash_hirose_gf8.c)
voleith_add_test(test_prg test_prg.c)
voleith_add_test(test_vc test_vc.c)
voleith_add_test(test_convert test_convert.c)
voleith_add_test(test_voleith test_voleith.c)
voleith_add_test(test_circuit test_circuit.c)
voleith_add_test(test_aes_circuit test_aes_circuit.c)
voleith_add_test(test_quicksilver test_quicksilver.c)
voleith_add_test(test_fiat_shamir test_fiat_shamir.c)
voleith_add_test(test_proof_header test_proof_header.c)
voleith_add_test(test_circuit_fingerprint test_circuit_fingerprint.c)
voleith_add_test(test_gf8_circuit_fingerprint test_gf8_circuit_fingerprint.c)
voleith_add_test(test_params_fingerprint test_params_fingerprint.c)
voleith_add_test(test_proof test_proof.c)
voleith_add_test(test_legacy_verify test_legacy_verify.c)
voleith_add_test(test_aes_cmac_circuit test_aes_cmac_circuit.c)
voleith_add_test(test_kdf_ctr_cmac_circuit test_kdf_ctr_cmac_circuit.c)
voleith_add_test(test_merkle_circuit test_merkle_circuit.c)
voleith_add_test(test_indexed_merkle_circuit test_indexed_merkle_circuit.c)
voleith_add_test(test_gf8_circuit test_gf8_circuit.c)
voleith_add_test(test_aes_gf8_circuit test_aes_gf8_circuit.c)
voleith_add_test(test_grostl_gf8_circuit test_grostl_gf8_circuit.c)
voleith_add_test(test_grostl_fixed_node_circuit test_grostl_fixed_node_circuit.c)
voleith_add_test(test_aes_cmac_gf8_circuit test_aes_cmac_gf8_circuit.c)
voleith_add_test(test_kdf_ctr_cmac_gf8_circuit test_kdf_ctr_cmac_gf8_circuit.c)
voleith_add_test(test_merkle_gf8_circuit test_merkle_gf8_circuit.c)
voleith_add_test(test_merkle_grostl_gf8_circuit test_merkle_grostl_gf8_circuit.c)
voleith_add_test(test_indexed_merkle_gf8_circuit test_indexed_merkle_gf8_circuit.c)
voleith_add_test(test_range_gf8_circuit test_range_gf8_circuit.c)
voleith_add_test(test_indexed_merkle_grostl_gf8_circuit test_indexed_merkle_grostl_gf8_circuit.c)
voleith_add_test(test_merkle_vt_gf8_equivalence test_merkle_vt_gf8_equivalence.c)
voleith_add_test(test_merkle_vt_gf8_helpers test_merkle_vt_gf8_helpers.c)
voleith_add_test(test_indexed_merkle_vt_gf8_helpers test_indexed_merkle_vt_gf8_helpers.c)
voleith_add_test(test_indexed_merkle_vt_gf8_equivalence test_indexed_merkle_vt_gf8_equivalence.c)
voleith_add_test(test_node_hash_vt_conformance test_node_hash_vt_conformance.c)
voleith_add_test(test_node_hash_fixed_multiblock_gf8 test_node_hash_fixed_multiblock_gf8.c)
voleith_add_test(test_gf8_quicksilver test_gf8_quicksilver.c)
voleith_add_test(test_syndrome_gf8 test_syndrome_gf8.c)
voleith_add_test(test_syndrome_opener_e2e_gf8 test_syndrome_opener_e2e_gf8.c)
voleith_label_test(test_syndrome_opener_e2e_gf8 slow)
voleith_add_test(test_gf16_quicksilver test_gf16_quicksilver.c)
voleith_add_test(test_syndrome_gf16 test_syndrome_gf16.c)
voleith_add_test(test_rlnc_gf16_circuit test_rlnc_gf16_circuit.c)
voleith_add_test(test_rlnc_gf16_cert_circuit test_rlnc_gf16_cert_circuit.c)
voleith_add_test(test_permutation_gf16_circuit test_permutation_gf16_circuit.c)
voleith_add_test(test_rlnc_confidential_gf16_circuit test_rlnc_confidential_gf16_circuit.c)
voleith_add_test(test_gf8_proof test_gf8_proof.c)
voleith_add_test(test_ring_sig_v1_gf8 test_ring_sig_v1_gf8.c)
voleith_add_test(test_rs_gf8 test_rs_gf8.c)
voleith_add_test(test_rs_epoch_gf8 test_rs_epoch_gf8.c)
voleith_add_test(test_rs_opener_gf8 test_rs_opener_gf8.c)
voleith_add_test(test_rs_opener_e2e_gf8 test_rs_opener_e2e_gf8.c)
voleith_label_test(test_rs_opener_e2e_gf8 slow)
voleith_add_test(test_rs_opener_sign_gf8 test_rs_opener_sign_gf8.c)
voleith_label_test(test_rs_opener_sign_gf8 slow)
# OP.TEST: V5 composition matrix (V5+V4 shared id, V5+V2 nullifier).
voleith_add_test(test_rs_opener_compose_gf8 test_rs_opener_compose_gf8.c)
voleith_label_test(test_rs_opener_compose_gf8 slow)

# OP.ORACLE: syndrome-backed opener end-to-end. libtalos_syndrome is an OPTIONAL
# test-only dependency (design Q1): when found the e2e links it as the real decap
# oracle; otherwise the test still builds and runs as a loud SKIP. It is REQUIRED
# at the 1.11.0 release gate. Point discovery at a checkout/install with
# -DVOLEITH_SYNDROME_ROOT=<path> (its include/ and the built libtalos_syndrome.a);
# the sibling ../libtalos_syndrome is searched by default.
voleith_add_test(test_rs_opener_oracle_gf8 test_rs_opener_oracle_gf8.c)
voleith_label_test(test_rs_opener_oracle_gf8 slow)

set(VOLEITH_SYNDROME_ROOT "" CACHE PATH
    "Path to a libtalos_syndrome checkout/install for the OP.ORACLE e2e test")
find_path(VOLEITH_SYNDROME_INCLUDE_DIR talos_syndrome.h
    HINTS "${VOLEITH_SYNDROME_ROOT}" "${CMAKE_SOURCE_DIR}/../libtalos_syndrome"
    PATH_SUFFIXES include)
find_library(VOLEITH_SYNDROME_LIB
    NAMES talos_syndrome libtalos_syndrome
    HINTS "${VOLEITH_SYNDROME_ROOT}" "${CMAKE_SOURCE_DIR}/../libtalos_syndrome"
    PATH_SUFFIXES build lib build/lib)
if(VOLEITH_SYNDROME_INCLUDE_DIR AND VOLEITH_SYNDROME_LIB)
    # Pin the compatible range (design Q1): syndrome major version 1.
    file(STRINGS "${VOLEITH_SYNDROME_INCLUDE_DIR}/talos_syndrome.h"
        _syn_ver_lines REGEX "#define SYNDROME_VERSION_(MAJOR|MINOR|PATCH)")
    string(REGEX MATCH "SYNDROME_VERSION_MAJOR ([0-9]+)" _ "${_syn_ver_lines}")
    set(_syn_major "${CMAKE_MATCH_1}")
    string(REGEX MATCH "SYNDROME_VERSION_MINOR ([0-9]+)" _ "${_syn_ver_lines}")
    set(_syn_minor "${CMAKE_MATCH_1}")
    string(REGEX MATCH "SYNDROME_VERSION_PATCH ([0-9]+)" _ "${_syn_ver_lines}")
    set(_syn_patch "${CMAKE_MATCH_1}")
    if(_syn_major STREQUAL "1")
        target_include_directories(test_rs_opener_oracle_gf8 PRIVATE
            "${VOLEITH_SYNDROME_INCLUDE_DIR}")
        target_link_libraries(test_rs_opener_oracle_gf8
            "${VOLEITH_SYNDROME_LIB}")
        target_compile_definitions(test_rs_opener_oracle_gf8 PRIVATE
            VOLEITH_HAVE_SYNDROME)
        message(STATUS "OP.ORACLE: libtalos_syndrome "
            "${_syn_major}.${_syn_minor}.${_syn_patch} found; opener e2e ENABLED")
    else()
        message(WARNING "OP.ORACLE: libtalos_syndrome "
            "${_syn_major}.${_syn_minor}.${_syn_patch} outside supported [1.0, 2.0); "
            "opener e2e will SKIP")
    endif()
else()
    message(WARNING "OP.ORACLE: libtalos_syndrome not found; opener e2e will SKIP "
        "(set -DVOLEITH_SYNDROME_ROOT). REQUIRED for the 1.11.0 release gate.")
endif()
voleith_add_test(test_lean_build_warning test_lean_build_warning.c)
voleith_add_test(test_bristol_parser test_bristol_parser.c)
target_compile_definitions(test_bristol_parser PRIVATE
    VOLEITH_BRISTOL_TEST_DATA_DIR="${CMAKE_SOURCE_DIR}/tests/data/bristol")
voleith_add_test(test_shipshape_node_hash_types test_shipshape_node_hash_types.c)
voleith_add_test(test_shipshape_registry_table test_shipshape_registry_table.c)
voleith_add_test(test_shipshape_parser test_shipshape_parser.c)
voleith_add_test(test_shipshape_conformance test_shipshape_conformance.c)
voleith_add_test(test_shipshape_adversarial test_shipshape_adversarial.c)
voleith_add_test(test_shipshape_registry_equiv test_shipshape_registry_equiv.c)
voleith_add_test(test_shipshape_witness test_shipshape_witness.c)
voleith_add_test(test_shipshape_witness_proof test_shipshape_witness_proof.c)
voleith_add_test(test_shipshape_examples test_shipshape_examples.c)
voleith_add_test(test_shipshape_registry_grid test_shipshape_registry_grid.c)
# Large §3.4 grid points: same binary with the `slow` argument, labelled slow
# so the default loop skips them (`ctest -LE slow`) and runs them on demand.
add_test(NAME test_shipshape_registry_grid_slow
    COMMAND $<TARGET_FILE:test_shipshape_registry_grid> slow)
set_tests_properties(test_shipshape_registry_grid_slow PROPERTIES LABELS slow)
# NOTE: test_shipshape_reg_hash_grid will not link until
# parsers/shipshape_registry_table.c is regenerated by the freeze tool
# after the MR2 source lands (see MR2 handoff instructions).
voleith_add_test(test_shipshape_reg_hash_grid test_shipshape_reg_hash_grid.c)
# MR3: crypto-v2 parser smoke test (also extended in MR4 with Group D cases).
voleith_add_test(test_shipshape_crypto_v2_parse test_shipshape_crypto_v2_parse.c)
# MR4: crypto-v2 equivalence and prove/verify soundness tests.
voleith_add_test(test_shipshape_crypto_v2_equiv test_shipshape_crypto_v2_equiv.c)
voleith_add_test(test_shipshape_crypto_v2_proof test_shipshape_crypto_v2_proof.c)
# MR5: W8 region-name contract -- bracketed FQN asserted across all 10 types.
voleith_add_test(test_shipshape_crypto_v2_region_name test_shipshape_crypto_v2_region_name.c)
# W8.2: Tier 2a dispatch registry + dispatch loop mechanism test.
voleith_add_test(test_shipshape_witgen_dispatch test_shipshape_witgen_dispatch.c)
# W8.3b: native AES witness backends, equivalence oracle vs generic evaluator.
voleith_add_test(test_shipshape_witgen_aes test_shipshape_witgen_aes.c)
# W8.3c: native PARAMETRIC cmac/grostl witness backends, structural name keying.
voleith_add_test(test_shipshape_witgen_cmac_grostl
    test_shipshape_witgen_cmac_grostl.c)
# W8.4: interleaved-skip fail-closed property (wrong backend yields invalid proof).
voleith_add_test(test_shipshape_witgen_failclosed
    test_shipshape_witgen_failclosed.c)
# W8.4: interleaved-skip performance sanity (byte-identical output, slow label).
voleith_add_test(test_shipshape_witgen_bench test_shipshape_witgen_bench.c)
voleith_label_test(test_shipshape_witgen_bench slow)
# W8.5a: crypto-v2 construction-dispatch substrate (no real handler).
voleith_add_test(test_shipshape_witgen_construction
    test_shipshape_witgen_construction.c)
# W8.5b: native crypto-v2 construction witness backends, equivalence oracle.
voleith_add_test(test_shipshape_witgen_construction_handlers
    test_shipshape_witgen_construction_handlers.c)
# W8.6: construction handler validation across the (entry, node-hash type) grid.
voleith_add_test(test_shipshape_witgen_construction_grid
    test_shipshape_witgen_construction_grid.c)
# W8.6: construction backend fail-closed property (wrong backend yields invalid proof).
voleith_add_test(test_shipshape_witgen_construction_failclosed
    test_shipshape_witgen_construction_failclosed.c)
# W8.6: construction backend performance sanity (byte-identical output, slow label).
voleith_add_test(test_shipshape_witgen_construction_bench
    test_shipshape_witgen_construction_bench.c)
voleith_label_test(test_shipshape_witgen_construction_bench slow)
