# Copyright (c) 2026 Jason Crawford
# SPDX-License-Identifier: AGPL-3.0-only

# Test executables build into their own directory
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/tests)

# Helper function: create one test executable per variant for a given test source.
# Additional source files (e.g., shared test helpers like aes_kat_runner.c) may be
# supplied after the main TEST_SOURCE; they are compiled into every per-variant
# build of the test binary.
function(voleith_add_test TEST_NAME TEST_SOURCE)
    foreach(VARIANT ${VOLEITH_TEST_VARIANTS})
        set(TARGET_NAME ${TEST_NAME}_${VARIANT})
        set(LIB_NAME voleith_core_${VARIANT})

        add_executable(${TARGET_NAME} ${TEST_SOURCE} ${ARGN})
        target_link_libraries(${TARGET_NAME} ${LIB_NAME})

        # Let tests that read fixtures (e.g. NIST KAT files under
        # third_party/) locate the repo root at runtime.
        target_compile_definitions(${TARGET_NAME} PRIVATE
            VOLEITH_TEST_SOURCE_DIR="${CMAKE_SOURCE_DIR}")

        # Add intrinsics compile flags for test source files that use them directly
        get_target_property(LIB_DEFS ${LIB_NAME} INTERFACE_COMPILE_DEFINITIONS)
        if(LIB_DEFS)
            if("VOLEITH_HAVE_CLMUL" IN_LIST LIB_DEFS)
                target_compile_options(${TARGET_NAME} PRIVATE -mpclmul -msse2 -msse4.1)
            endif()
            if("VOLEITH_HAVE_AES_NI" IN_LIST LIB_DEFS)
                target_compile_options(${TARGET_NAME} PRIVATE -maes -msse2 -mssse3)
            endif()
        endif()

        add_test(NAME ${TARGET_NAME} COMMAND $<TARGET_FILE:${TARGET_NAME}>)
    endforeach()
endfunction()

# Apply CTest labels to every per-variant instance of a registered test.
# Use the "slow" label for heavy tests (e.g. the Monte Carlo chains) so the
# default loop can skip them with `ctest -LE slow` and run them on demand
# with `ctest -L slow`.
function(voleith_label_test TEST_NAME)
    foreach(VARIANT ${VOLEITH_TEST_VARIANTS})
        set_tests_properties(${TEST_NAME}_${VARIANT} PROPERTIES LABELS "${ARGN}")
    endforeach()
endfunction()

# Register tests
voleith_add_test(test_field test_field.c)
voleith_add_test(test_aes test_aes.c aes_kat_runner.c)
voleith_add_test(test_aes_ct64 test_aes_ct64.c aes_kat_runner.c)
voleith_add_test(test_grostl test_grostl.c)
voleith_add_test(test_hirose test_hirose.c)
voleith_add_test(test_node_hash_hirose_gf8 test_node_hash_hirose_gf8.c)
voleith_add_test(test_grostl_kat test_grostl_kat.c)
voleith_add_test(test_grostl_mct test_grostl_mct.c)
voleith_label_test(test_grostl_mct slow)
voleith_add_test(test_prg test_prg.c)
voleith_add_test(test_hash test_hash.c)
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
voleith_add_test(test_aes_cmac_gf8_circuit test_aes_cmac_gf8_circuit.c)
voleith_add_test(test_kdf_ctr_cmac_gf8_circuit test_kdf_ctr_cmac_gf8_circuit.c)
voleith_add_test(test_merkle_gf8_circuit test_merkle_gf8_circuit.c)
voleith_add_test(test_merkle_grostl_gf8_circuit test_merkle_grostl_gf8_circuit.c)
voleith_add_test(test_indexed_merkle_gf8_circuit test_indexed_merkle_gf8_circuit.c)
voleith_add_test(test_indexed_merkle_grostl_gf8_circuit test_indexed_merkle_grostl_gf8_circuit.c)
voleith_add_test(test_merkle_vt_gf8_equivalence test_merkle_vt_gf8_equivalence.c)
voleith_add_test(test_indexed_merkle_vt_gf8_equivalence test_indexed_merkle_vt_gf8_equivalence.c)
voleith_add_test(test_node_hash_vt_conformance test_node_hash_vt_conformance.c)
voleith_add_test(test_gf8_quicksilver test_gf8_quicksilver.c)
voleith_add_test(test_gf8_proof test_gf8_proof.c)
