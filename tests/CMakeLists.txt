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

        # Add intrinsics compile flags for test source files that use them directly
        get_target_property(LIB_DEFS ${LIB_NAME} INTERFACE_COMPILE_DEFINITIONS)
        if(LIB_DEFS)
            if("VOLEITH_HAVE_CLMUL" IN_LIST LIB_DEFS)
                target_compile_options(${TARGET_NAME} PRIVATE -mpclmul -msse2 -msse4.1)
            endif()
            if("VOLEITH_HAVE_AES_NI" IN_LIST LIB_DEFS)
                target_compile_options(${TARGET_NAME} PRIVATE -maes -msse2)
            endif()
        endif()

        add_test(NAME ${TARGET_NAME} COMMAND $<TARGET_FILE:${TARGET_NAME}>)
    endforeach()
endfunction()

# Register tests
voleith_add_test(test_field test_field.c)
voleith_add_test(test_aes test_aes.c aes_kat_runner.c)
voleith_add_test(test_aes_ct64 test_aes_ct64.c aes_kat_runner.c)
voleith_add_test(test_prg test_prg.c)
voleith_add_test(test_hash test_hash.c)
voleith_add_test(test_vc test_vc.c)
voleith_add_test(test_convert test_convert.c)
voleith_add_test(test_voleith test_voleith.c)
voleith_add_test(test_circuit test_circuit.c)
voleith_add_test(test_aes_circuit test_aes_circuit.c)
voleith_add_test(test_quicksilver test_quicksilver.c)
voleith_add_test(test_fiat_shamir test_fiat_shamir.c)
voleith_add_test(test_proof test_proof.c)
voleith_add_test(test_aes_cmac_circuit test_aes_cmac_circuit.c)
voleith_add_test(test_kdf_ctr_cmac_circuit test_kdf_ctr_cmac_circuit.c)
voleith_add_test(test_merkle_circuit test_merkle_circuit.c)
voleith_add_test(test_indexed_merkle_circuit test_indexed_merkle_circuit.c)
voleith_add_test(test_gf8_circuit test_gf8_circuit.c)
voleith_add_test(test_aes_gf8_circuit test_aes_gf8_circuit.c)
voleith_add_test(test_aes_cmac_gf8_circuit test_aes_cmac_gf8_circuit.c)
voleith_add_test(test_kdf_ctr_cmac_gf8_circuit test_kdf_ctr_cmac_gf8_circuit.c)
voleith_add_test(test_merkle_gf8_circuit test_merkle_gf8_circuit.c)
voleith_add_test(test_indexed_merkle_gf8_circuit test_indexed_merkle_gf8_circuit.c)
voleith_add_test(test_gf8_quicksilver test_gf8_quicksilver.c)
voleith_add_test(test_gf8_proof test_gf8_proof.c)
