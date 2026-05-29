# Copyright (c) 2026 Jason Crawford
# SPDX-License-Identifier: AGPL-3.0-only

cmake_minimum_required(VERSION 3.16)
project(libvoleith VERSION 1.1.0 LANGUAGES C)

set(CMAKE_C_STANDARD 17)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)

# Build options
option(VOLEITH_AES_NI     "Enable x86 AES-NI intrinsics"                       ON)
option(VOLEITH_CLMUL      "Enable x86 CLMUL (PCLMULQDQ) intrinsics"            ON)
option(VOLEITH_ARMV8_AES  "Enable ARMv8 Crypto Extension AES instructions"     ON)
option(VOLEITH_PMULL      "Enable ARMv8 PMULL carry-less multiply instruction"  ON)
option(VOLEITH_BUILD_TESTS "Build test suite" ON)
option(VOLEITH_BUILD_EXAMPLES "Build example programs" ON)
option(VOLEITH_BUILD_SHARED "Build shared library (libvoleith.so/.dylib) in addition to static" OFF)
option(VOLEITH_BUILD_DUDECT "Build dudect timing-validation harness (tools/dudect)" OFF)

# Test/debug-only flag.  Compiles in the FIPS 197 table-lookup AES
# path, which has a cache-timing side channel on secret keys.  See
# docs/SECURITY_REVIEW.md C-1 and docs/AES_MIGRATION_PLAN.md §3.
option(VOLEITH_ALLOW_VARIABLE_TIME_AES
       "Enable the variable-time table-lookup AES backend (test/debug only)"
       OFF)

if(VOLEITH_ALLOW_VARIABLE_TIME_AES)
    message(WARNING
        "voleith: variable-time AES (table lookups indexed by secret bytes)\n"
        "is being compiled in.  This is a cache-timing side channel and is\n"
        "for TEST/DEBUG only.  Do NOT ship this configuration to production.\n"
        "See docs/SECURITY_REVIEW.md finding C-1 for context.")
endif()

# Test/debug-only flag.  Compiles in the variable-time software
# field-multiplication path (branches on secret bits of the
# multiplier).  See docs/SECURITY_REVIEW.md C-2 and
# docs/CONSTANT_TIME_FIELD_DESIGN.md.
option(VOLEITH_ALLOW_VARIABLE_TIME_FIELD
       "Enable the variable-time software field multiplication path (test/debug only)"
       OFF)

if(VOLEITH_ALLOW_VARIABLE_TIME_FIELD)
    message(WARNING
        "voleith: variable-time field multiplication (branches on secret\n"
        "bits of the multiplier) is being compiled in.  Cache/timing side\n"
        "channel.  For TEST/DEBUG only.  Do NOT ship this configuration\n"
        "to production.  See docs/SECURITY_REVIEW.md finding C-2 for context.")
endif()

# Report which AES backend will be active.  Done after the AES-NI
# detection probe (below) populates HAVE_AES_NI, so the report
# reflects the actually-selected backend.  Deferred via a helper:
function(voleith_report_aes_backend)
    if(HAVE_AES_NI)
        message(STATUS "voleith: AES backend = AES-NI (x86_64 hardware)")
    elseif(HAVE_ARMV8_AES)
        message(STATUS "voleith: AES backend = ARMv8 Crypto Extension (aarch64 hardware)")
    elseif(VOLEITH_ALLOW_VARIABLE_TIME_AES)
        # The WARNING above already announces this loudly.
    else()
        # NOTICE (CMake 3.15+) prints to stderr without the "-- " STATUS
        # prefix and is not suppressed by -Wno-dev - easy for CI/CD to
        # grep for "voleith: AES backend".
        message(NOTICE
            "voleith: AES backend = bitsliced software (no AES-NI / "
            "ARMv8 Crypto Extension detected). Constant-time but "
            "~30-50x slower than hardware AES. If targeting x86_64 "
            "use -DVOLEITH_AES_NI=ON; for aarch64 use -DVOLEITH_ARMV8_AES=ON.")
    endif()
endfunction()

# Report which field-multiplication backend will be active.
function(voleith_report_field_backend)
    if(HAVE_CLMUL)
        message(STATUS "voleith: field backend = CLMUL/PCLMULQDQ (x86_64 hardware)")
    elseif(HAVE_PMULL)
        message(STATUS "voleith: field backend = PMULL (aarch64 hardware)")
    elseif(VOLEITH_ALLOW_VARIABLE_TIME_FIELD)
        # The WARNING above already announces this loudly.
    else()
        message(NOTICE
            "voleith: field backend = constant-time scalar software "
            "(no CLMUL/PMULL detected). Constant-time but slower than hardware. "
            "For x86_64 use -DVOLEITH_CLMUL=ON; for aarch64 use -DVOLEITH_PMULL=ON.")
    endif()
endfunction()

# Compiler warnings
add_compile_options(-Wall -Wextra -Wpedantic -Wno-unused-parameter)

# Check for intrinsics support
if(VOLEITH_CLMUL)
    include(CheckCSourceCompiles)
    set(CMAKE_REQUIRED_FLAGS "-mpclmul -msse2 -msse4.1")
    check_c_source_compiles("
        #include <wmmintrin.h>
        int main(void) {
            __m128i a = _mm_setzero_si128();
            __m128i b = _mm_clmulepi64_si128(a, a, 0);
            (void)b;
            return 0;
        }
    " HAVE_CLMUL)
    unset(CMAKE_REQUIRED_FLAGS)
endif()

if(VOLEITH_AES_NI)
    include(CheckCSourceCompiles)
    set(CMAKE_REQUIRED_FLAGS "-maes -msse2 -mssse3")
    check_c_source_compiles("
        #include <wmmintrin.h>
        int main(void) {
            __m128i a = _mm_setzero_si128();
            __m128i b = _mm_aesenc_si128(a, a);
            (void)b;
            return 0;
        }
    " HAVE_AES_NI)
    unset(CMAKE_REQUIRED_FLAGS)
endif()

# ARMv8 Crypto Extension probe.  Try without explicit flags first
# (Apple Silicon / compilers that enable crypto by default); if that
# fails, try -march=armv8-a+crypto (Linux GCC/Clang on aarch64).
set(_ARMV8_AES_SRC "
    #include <arm_neon.h>
    int main(void) {
        uint8x16_t a = vdupq_n_u8(0);
        a = vaeseq_u8(a, a);
        a = vaesmcq_u8(a);
        (void)a;
        return 0;
    }
")
set(_ARMV8_PMULL_SRC "
    #include <arm_neon.h>
    int main(void) {
        poly128_t r = vmull_p64((poly64_t)0ULL, (poly64_t)0ULL);
        (void)r;
        return 0;
    }
")

if(VOLEITH_ARMV8_AES)
    include(CheckCSourceCompiles)
    check_c_source_compiles("${_ARMV8_AES_SRC}" HAVE_ARMV8_AES_NO_FLAG)
    if(HAVE_ARMV8_AES_NO_FLAG)
        set(HAVE_ARMV8_AES TRUE)
        set(ARMV8_CRYPTO_FLAGS "")
    else()
        set(CMAKE_REQUIRED_FLAGS "-march=armv8-a+crypto")
        check_c_source_compiles("${_ARMV8_AES_SRC}" HAVE_ARMV8_AES_WITH_FLAG)
        unset(CMAKE_REQUIRED_FLAGS)
        if(HAVE_ARMV8_AES_WITH_FLAG)
            set(HAVE_ARMV8_AES TRUE)
            set(ARMV8_CRYPTO_FLAGS "-march=armv8-a+crypto")
        endif()
    endif()
endif()

if(VOLEITH_PMULL)
    include(CheckCSourceCompiles)
    if(DEFINED ARMV8_CRYPTO_FLAGS)
        set(CMAKE_REQUIRED_FLAGS "${ARMV8_CRYPTO_FLAGS}")
    endif()
    check_c_source_compiles("${_ARMV8_PMULL_SRC}" HAVE_PMULL_PROBE)
    unset(CMAKE_REQUIRED_FLAGS)
    if(HAVE_PMULL_PROBE)
        set(HAVE_PMULL TRUE)
        if(NOT DEFINED ARMV8_CRYPTO_FLAGS)
            set(ARMV8_CRYPTO_FLAGS "")
        endif()
    endif()
endif()

unset(_ARMV8_AES_SRC)
unset(_ARMV8_PMULL_SRC)

# Tell the build engineer (and CI/CD log scrapers) which AES and
# field backends the production library will use.  Variants below
# each pick their own backend per variant configuration.
voleith_report_aes_backend()
voleith_report_field_backend()

# Source files for core library
set(VOLEITH_CORE_SOURCES
    core/field.c
    core/aes.c
    core/aes_ct64.c
    core/grostl.c
    core/prg.c
    core/hash.c
    core/util.c
    vole/vc.c
    vole/convert.c
    vole/voleith.c
    proof/circuit.c
    proof/gf8_circuit.c
    proof/prover.c
    proof/verifier.c
    proof/gf8_prover.c
    proof/gf8_verifier.c
    proof/fiat_shamir.c
    proof/vole_hash.c
    proof/proof.c
    proof/gf8_proof.c
    circuits/aes_circuit.c
    circuits/aes_gf8_circuit.c
    circuits/grostl_gf8_circuit.c
    circuits/aes_cmac_circuit.c
    circuits/aes_cmac_gf8_circuit.c
    circuits/kdf_ctr_cmac_circuit.c
    circuits/kdf_ctr_cmac_gf8_circuit.c
    circuits/merkle_circuit.c
    circuits/merkle_gf8_circuit.c
    circuits/merkle_grostl_gf8_circuit.c
    circuits/indexed_merkle_circuit.c
    circuits/indexed_merkle_gf8_circuit.c
    circuits/indexed_merkle_grostl_gf8_circuit.c
)

set(VOLEITH_CORE_INCLUDES
    ${CMAKE_CURRENT_SOURCE_DIR}/core
    ${CMAKE_CURRENT_SOURCE_DIR}/vole
    ${CMAKE_CURRENT_SOURCE_DIR}/proof
    ${CMAKE_CURRENT_SOURCE_DIR}/circuits
    ${CMAKE_CURRENT_SOURCE_DIR}/include
)

# Helper to apply hardware capability flags to a library target
function(voleith_apply_hw_flags TARGET)
    if(HAVE_CLMUL)
        target_compile_definitions(${TARGET} PUBLIC VOLEITH_HAVE_CLMUL)
        target_compile_options(${TARGET} PRIVATE -mpclmul -msse2 -msse4.1)
    endif()
    if(HAVE_AES_NI)
        target_compile_definitions(${TARGET} PUBLIC VOLEITH_HAVE_AES_NI)
        target_compile_options(${TARGET} PRIVATE -maes -msse2 -mssse3)
    endif()
    if(HAVE_ARMV8_AES)
        target_compile_definitions(${TARGET} PUBLIC VOLEITH_HAVE_ARMV8_AES)
        if(ARMV8_CRYPTO_FLAGS)
            target_compile_options(${TARGET} PRIVATE ${ARMV8_CRYPTO_FLAGS})
        endif()
    endif()
    if(HAVE_PMULL)
        target_compile_definitions(${TARGET} PUBLIC VOLEITH_HAVE_PMULL)
        if(ARMV8_CRYPTO_FLAGS AND NOT HAVE_ARMV8_AES)
            target_compile_options(${TARGET} PRIVATE ${ARMV8_CRYPTO_FLAGS})
        endif()
    endif()
    if(VOLEITH_ALLOW_VARIABLE_TIME_AES)
        target_compile_definitions(${TARGET} PUBLIC
                                   VOLEITH_ALLOW_VARIABLE_TIME_AES)
    endif()
    if(VOLEITH_ALLOW_VARIABLE_TIME_FIELD)
        target_compile_definitions(${TARGET} PUBLIC
                                   VOLEITH_ALLOW_VARIABLE_TIME_FIELD)
    endif()
endfunction()

# Production static library (libtalos_voleith.a)
add_library(voleith_core STATIC ${VOLEITH_CORE_SOURCES})
set_target_properties(voleith_core PROPERTIES OUTPUT_NAME talos_voleith)
target_include_directories(voleith_core PUBLIC ${VOLEITH_CORE_INCLUDES})
voleith_apply_hw_flags(voleith_core)

# Optional shared library (libtalos_voleith.so / .dylib)
if(VOLEITH_BUILD_SHARED)
    add_library(voleith_core_shared SHARED ${VOLEITH_CORE_SOURCES})
    set_target_properties(voleith_core_shared PROPERTIES
        OUTPUT_NAME talos_voleith
        VERSION     ${PROJECT_VERSION}
        SOVERSION   ${PROJECT_VERSION_MAJOR}
    )
    target_include_directories(voleith_core_shared PUBLIC ${VOLEITH_CORE_INCLUDES})
    voleith_apply_hw_flags(voleith_core_shared)
endif()

# Test variants: build all 4 combinations to test all code paths
if(VOLEITH_BUILD_TESTS)
    enable_testing()

    # Accumulated by voleith_add_variant.  Variants whose required
    # hardware feature was not detected on the build host are skipped
    # entirely (neither built nor added to the test-variant list).
    set(VOLEITH_TEST_VARIANTS "")

    # Helper function to create a library variant with specific intrinsics.
    # FORCE_VARTIME_FIELD: if ON, compile this variant's field-mul software
    # path as variable-time regardless of the top-level option.  Used by the
    # sw_vartime test variant so the reference path is exercised even when
    # the top-level VOLEITH_ALLOW_VARIABLE_TIME_FIELD is OFF.
    function(voleith_add_variant SUFFIX USE_CLMUL USE_AES_NI FORCE_VARTIME_FIELD
                                        USE_ARMV8_AES USE_PMULL)
        # Skip the variant when a required hardware feature is absent on
        # this host.  Building it would either fail (compiler rejects the
        # ISA flag) or silently degrade to the sw equivalent, neither of
        # which is useful.
        if(USE_CLMUL AND NOT HAVE_CLMUL)
            message(STATUS
                "voleith: skipping variant '${SUFFIX}' (CLMUL not detected)")
            return()
        endif()
        if(USE_AES_NI AND NOT HAVE_AES_NI)
            message(STATUS
                "voleith: skipping variant '${SUFFIX}' (AES-NI not detected)")
            return()
        endif()
        if(USE_ARMV8_AES AND NOT HAVE_ARMV8_AES)
            message(STATUS
                "voleith: skipping variant '${SUFFIX}' "
                "(ARMv8 AES not detected)")
            return()
        endif()
        if(USE_PMULL AND NOT HAVE_PMULL)
            message(STATUS
                "voleith: skipping variant '${SUFFIX}' (PMULL not detected)")
            return()
        endif()

        set(TARGET_NAME voleith_core_${SUFFIX})
        add_library(${TARGET_NAME} STATIC ${VOLEITH_CORE_SOURCES})
        target_include_directories(${TARGET_NAME}
            PUBLIC ${VOLEITH_CORE_INCLUDES}
        )

        if(USE_CLMUL AND HAVE_CLMUL)
            target_compile_definitions(${TARGET_NAME} PUBLIC VOLEITH_HAVE_CLMUL)
            target_compile_options(${TARGET_NAME} PRIVATE -mpclmul -msse2 -msse4.1)
        endif()

        if(USE_AES_NI AND HAVE_AES_NI)
            target_compile_definitions(${TARGET_NAME} PUBLIC VOLEITH_HAVE_AES_NI)
            target_compile_options(${TARGET_NAME} PRIVATE -maes -msse2 -mssse3)
        endif()

        if(USE_ARMV8_AES AND HAVE_ARMV8_AES)
            target_compile_definitions(${TARGET_NAME} PUBLIC VOLEITH_HAVE_ARMV8_AES)
            if(ARMV8_CRYPTO_FLAGS)
                target_compile_options(${TARGET_NAME} PRIVATE ${ARMV8_CRYPTO_FLAGS})
            endif()
        endif()

        if(USE_PMULL AND HAVE_PMULL)
            target_compile_definitions(${TARGET_NAME} PUBLIC VOLEITH_HAVE_PMULL)
            if(ARMV8_CRYPTO_FLAGS AND NOT (USE_ARMV8_AES AND HAVE_ARMV8_AES))
                target_compile_options(${TARGET_NAME} PRIVATE ${ARMV8_CRYPTO_FLAGS})
            endif()
        endif()

        if(VOLEITH_ALLOW_VARIABLE_TIME_AES)
            target_compile_definitions(${TARGET_NAME} PUBLIC
                                       VOLEITH_ALLOW_VARIABLE_TIME_AES)
        endif()

        if(FORCE_VARTIME_FIELD OR VOLEITH_ALLOW_VARIABLE_TIME_FIELD)
            target_compile_definitions(${TARGET_NAME} PUBLIC
                                       VOLEITH_ALLOW_VARIABLE_TIME_FIELD)
        endif()

        # Record this suffix so tests can iterate only over the variants
        # that were actually built.
        set(VOLEITH_TEST_VARIANTS ${VOLEITH_TEST_VARIANTS} ${SUFFIX}
            PARENT_SCOPE)
    endfunction()

    #                   suffix          CLMUL  AES_NI  VARTIME  ARMV8_AES  PMULL
    voleith_add_variant(sw              OFF    OFF     OFF      OFF        OFF)
    voleith_add_variant(clmul           ON     OFF     OFF      OFF        OFF)
    voleith_add_variant(aesni           OFF    ON      OFF      OFF        OFF)
    voleith_add_variant(clmul_aesni     ON     ON      OFF      OFF        OFF)
    voleith_add_variant(sw_vartime      OFF    OFF     ON       OFF        OFF)
    voleith_add_variant(armv8_aes       OFF    OFF     OFF      ON         OFF)
    voleith_add_variant(pmull           OFF    OFF     OFF      OFF        ON)
    voleith_add_variant(armv8           OFF    OFF     OFF      ON         ON)

    # VOLEITH_TEST_VARIANTS is now populated with only the suffixes
    # whose underlying hardware feature was detected on this host;
    # voleith_add_variant returned early and did not append for the
    # rest.  Surface the final list at configure time so a captured
    # CMake log explains why a given variant did or did not build.
    message(STATUS "voleith: enabled test variants: ${VOLEITH_TEST_VARIANTS}")

    add_subdirectory(tests)
endif()

if(VOLEITH_BUILD_EXAMPLES)
    add_subdirectory(examples)
endif()

if(VOLEITH_BUILD_DUDECT)
    add_subdirectory(tools/dudect)
endif()
