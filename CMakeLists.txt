# Copyright (c) 2026 Jason Crawford
# SPDX-License-Identifier: AGPL-3.0-only

cmake_minimum_required(VERSION 3.16)
project(libvoleith VERSION 1.11.0 LANGUAGES C)

set(CMAKE_C_STANDARD 17)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)

# Build options
option(VOLEITH_AES_NI     "Compile AES-NI backend (omit for lean build)"              ON)
option(VOLEITH_CLMUL      "Compile CLMUL (PCLMULQDQ) field backend (omit for lean build)" ON)
option(VOLEITH_ARMV8_AES  "Compile ARMv8 AES backend (omit for lean build)"         ON)
option(VOLEITH_PMULL      "Compile ARMv8 PMULL field backend (omit for lean build)"  ON)
option(VOLEITH_BUILD_TESTS "Build test suite" ON)
option(VOLEITH_BUILD_EXAMPLES "Build example programs" ON)
option(VOLEITH_BUILD_SHARED "Build shared library (libvoleith.so/.dylib) in addition to static" OFF)
option(VOLEITH_BUILD_DUDECT "Build dudect timing-validation harness (tools/dudect)" OFF)
option(VOLEITH_BUILD_BENCH "Build FS-hash microbenchmarks (tools/bench_fs_hash)" OFF)
option(VOLEITH_BUILD_REGISTRY_FREEZE "Build the crypto-v1 registry freeze tool (tools/shipshape_registry_freeze)" OFF)
option(VOLEITH_FUZZ "Build libFuzzer parser harnesses (clang only; fuzz/)" OFF)
option(VOLEITH_SANITIZE "Instrument the library, tests, and examples with AddressSanitizer + UndefinedBehaviorSanitizer (GCC or Clang; use a dedicated build dir)" OFF)
option(VOLEITH_LEGACY_VERIFY "Accept pre-header proofs in voleith_verify (legacy fallback; SECURITY: legacy path skips header circuit/params identity binding, set OFF if you also accept v1 headered proofs)" ON)

# Propagate VOLEITH_LEGACY_VERIFY as a compile definition for every
# target defined below.  The macro gates the dual-path verifier
# fallback in proof/proof.c and proof/gf8_proof.c.  See
# docs/PROOF_METADATA_HEADER_DESIGN.md.
if(VOLEITH_LEGACY_VERIFY)
    add_compile_definitions(VOLEITH_LEGACY_VERIFY=1)
    message(STATUS "voleith: legacy (pre-header) proof verification = ENABLED")
else()
    message(STATUS "voleith: legacy (pre-header) proof verification = DISABLED")
endif()

# When fuzzing is enabled, instrument the whole library (the parsers under
# test included) for coverage-guided fuzzing plus AddressSanitizer and
# UndefinedBehaviorSanitizer.  The fuzz/ executables additionally link the
# libFuzzer runtime (-fsanitize=fuzzer).  These directory-scoped options must
# be set before any target is defined so voleith_core picks them up.  Clang
# only.  See fuzz/README.md and the implementation plan W4.
if(VOLEITH_FUZZ)
    if(NOT CMAKE_C_COMPILER_ID MATCHES "Clang")
        message(FATAL_ERROR
            "VOLEITH_FUZZ requires Clang (libFuzzer). Re-run with CC=clang.")
    endif()
    add_compile_options(-fsanitize=fuzzer-no-link,address,undefined
        -fno-omit-frame-pointer -g -O1)
    add_link_options(-fsanitize=address,undefined)
    message(STATUS "voleith: libFuzzer parser harnesses = ENABLED (fuzz/)")
endif()

# Instrument the whole build (library, tests, examples) with AddressSanitizer
# + UndefinedBehaviorSanitizer.  Like the fuzz block above, these options must
# be set before any target is defined so every target picks them up.  Works
# with GCC or Clang.  Use a dedicated build directory: you never want
# sanitizer-instrumented binaries in a release artifact.  Skipped when
# VOLEITH_FUZZ is on (it already applies the same sanitizers plus libFuzzer).
# -fno-sanitize-recover=all makes UBSan abort on the first finding so ctest
# marks the offending test failed instead of merely printing a warning.
# See README.md "Sanitizer builds (ASan / UBSan)".
if(VOLEITH_SANITIZE AND NOT VOLEITH_FUZZ)
    add_compile_options(-fsanitize=address,undefined
        -fno-sanitize-recover=all -fno-omit-frame-pointer -g)
    add_link_options(-fsanitize=address,undefined)
    message(STATUS "voleith: ASan + UBSan instrumentation = ENABLED")
endif()

# Report which AES backend will be active.  Done after the AES-NI
# detection probe (below) populates HAVE_AES_NI, so the report
# reflects the actually-selected backend.  Deferred via a helper:
function(voleith_report_aes_backend)
    if(HAVE_AES_NI)
        message(STATUS "voleith: AES backend = AES-NI (x86_64 hardware)")
    elseif(HAVE_ARMV8_AES)
        message(STATUS "voleith: AES backend = ARMv8 Crypto Extension (aarch64 hardware)")
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

# Tell the build engineer (and CI/CD log scrapers) which backends
# the fat library will prefer at runtime.
voleith_report_aes_backend()
voleith_report_field_backend()

# ---------------------------------------------------------------------------
# libtalos_ichor: shared layer-0 symmetric core (AES, SHA-3/SHAKE, Grostl,
# carry-less multiply, AES-DM/Hirose, CPU dispatch, secure-zero), vendored as a
# git submodule under third_party/.  For 1.10.1 it is consumed via
# add_subdirectory: voleith owns the single ichor build.  The ExternalProject /
# dependency-injection model libtalos_syndrome uses is revisited only when
# voleith builds syndrome in-tree.  See docs/private/ICHOR_MIGRATION_1_10_1.md.
# ---------------------------------------------------------------------------

# Map voleith's four build variants (sw / clmul / aesni / clmul_aesni) onto
# ichor's matching backend options, so a lean voleith build yields a lean ichor
# and the same backend matrix is exercised on both sides.  These plain set()s
# take precedence over ichor's option() defaults (policy CMP0077, NEW under our
# 3.16 minimum).
set(ICHOR_AES_NI    ${VOLEITH_AES_NI})
set(ICHOR_ARMV8_AES ${VOLEITH_ARMV8_AES})
set(ICHOR_CLMUL     ${VOLEITH_CLMUL})
set(ICHOR_PMULL     ${VOLEITH_PMULL})

# ichor carries its own KAT / dudect suites in its own tree; do not build them
# inside voleith.
set(ICHOR_BUILD_TESTS  OFF)
set(ICHOR_BUILD_DUDECT OFF)

# voleith's dudect harness (tools/dudect) recompiles voleith's own core with no
# hardware flags and must likewise measure ichor's software primitive paths,
# independent of this configure's hardware backend selection.  Ask ichor for its
# software-only companion target (ichor_soft) so the harness links that instead
# of the possibly-hardware `ichor`; the main library and the hardware test
# profile keep the accelerated `ichor`.
if(VOLEITH_BUILD_DUDECT)
    set(ICHOR_BUILD_SOFT_LIB ON)
endif()

# The ICHOR_FORCE_BACKEND env override and the dispatch-reset / cpu-features-
# override hooks compile in only under ICHOR_ENABLE_FORCE_BACKEND.  voleith's
# backend-sweep and dudect builds need them (the voleith_*_dispatch_reset /
# voleith_cpu_features_override shims resolve to these); a release build carries
# neither the env parser nor the hooks.
if(VOLEITH_BUILD_TESTS OR VOLEITH_BUILD_DUDECT)
    set(ICHOR_ENABLE_FORCE_BACKEND ON)
endif()

# Enforce the supported ichor version range [MIN, MAX) (semver SameMajorVersion)
# against <ichor/version.h>.  That header is authoritative: ichor's own CMake
# fails to configure if it drifts from project(VERSION).  Parsing it here (rather
# than reading a subdirectory-scoped CMake variable) works regardless of how
# ichor is pulled in and fails fast if the submodule is not initialized.  A
# compile-time guard in core/ichor_compat.h re-checks the major at TU compile.
set(VOLEITH_ICHOR_VERSION_MIN 1.0.0)
set(VOLEITH_ICHOR_VERSION_MAX 2.0.0)
set(_voleith_ichor_version_h
    "${CMAKE_CURRENT_SOURCE_DIR}/third_party/libtalos_ichor/include/ichor/version.h")
if(NOT EXISTS "${_voleith_ichor_version_h}")
    message(FATAL_ERROR
        "ichor/version.h not found at '${_voleith_ichor_version_h}'. Initialize "
        "the submodule (git submodule update --init --recursive) or pin an ichor "
        ">= ${VOLEITH_ICHOR_VERSION_MIN}.")
endif()
file(STRINGS "${_voleith_ichor_version_h}" _voleith_ichor_ver_lines
    REGEX "#define ICHOR_VERSION_(MAJOR|MINOR|PATCH)")
string(REGEX MATCH "ICHOR_VERSION_MAJOR ([0-9]+)" _ "${_voleith_ichor_ver_lines}")
set(_voleith_ichor_major "${CMAKE_MATCH_1}")
string(REGEX MATCH "ICHOR_VERSION_MINOR ([0-9]+)" _ "${_voleith_ichor_ver_lines}")
set(_voleith_ichor_minor "${CMAKE_MATCH_1}")
string(REGEX MATCH "ICHOR_VERSION_PATCH ([0-9]+)" _ "${_voleith_ichor_ver_lines}")
set(_voleith_ichor_patch "${CMAKE_MATCH_1}")
if(_voleith_ichor_major STREQUAL "" OR _voleith_ichor_minor STREQUAL "" OR
   _voleith_ichor_patch STREQUAL "")
    message(FATAL_ERROR
        "could not parse ICHOR_VERSION_* from '${_voleith_ichor_version_h}'")
endif()
set(VOLEITH_ICHOR_VERSION
    "${_voleith_ichor_major}.${_voleith_ichor_minor}.${_voleith_ichor_patch}")
if(VOLEITH_ICHOR_VERSION VERSION_LESS VOLEITH_ICHOR_VERSION_MIN OR
   NOT VOLEITH_ICHOR_VERSION VERSION_LESS VOLEITH_ICHOR_VERSION_MAX)
    message(FATAL_ERROR
        "libtalos_ichor ${VOLEITH_ICHOR_VERSION} is outside the supported range "
        "[${VOLEITH_ICHOR_VERSION_MIN}, ${VOLEITH_ICHOR_VERSION_MAX}). Update the "
        "submodule pin or port voleith to the new ichor major.")
endif()
message(STATUS
    "voleith: libtalos_ichor ${VOLEITH_ICHOR_VERSION} "
    "(supported range [${VOLEITH_ICHOR_VERSION_MIN}, ${VOLEITH_ICHOR_VERSION_MAX}))")

add_subdirectory(third_party/libtalos_ichor)

# voleith's internal core/*.h are now thin shims over <ichor/*.h>, so every
# in-tree target that compiles a TU including a core header (tests, tools,
# examples) needs ichor's include directory.  Exposed below as a
# BUILD_INTERFACE usage requirement on voleith_core: it reaches build-tree
# dependents but is stripped from the installed / exported interface, so
# external consumers of voleith are NOT handed ichor's headers (the sibling
# QC-MDPC library pulls ichor on its own).  The link dependency itself still
# propagates via the PRIVATE ichor link (LINK_ONLY) so symbols resolve.
set(VOLEITH_ICHOR_INCLUDE_DIR
    "${CMAKE_CURRENT_SOURCE_DIR}/third_party/libtalos_ichor/include")

# Source files for core library
set(VOLEITH_CORE_SOURCES
    # AES / CPU-detect / hash / hirose / util / grostl primitives moved to
    # libtalos_ichor (linked target `ichor`); see
    # docs/private/ICHOR_MIGRATION_1_10_1.md.  Only the voleith-specific field
    # arithmetic and the tweakable AES-CTR PRG stay here.
    core/field.c
    core/field_clmul.c
    core/field_pmull.c
    core/field_scalar.c
    core/field16.c
    core/prg.c
    core/backend_notice.c
    vole/vc.c
    vole/convert.c
    vole/voleith.c
    proof/circuit.c
    proof/gf8_circuit.c
    proof/prover.c
    proof/verifier.c
    proof/gf8_prover.c
    proof/gf8_verifier.c
    proof/gf16_circuit.c
    proof/gf16_prover.c
    proof/gf16_verifier.c
    proof/fiat_shamir.c
    proof/proof_header.c
    proof/circuit_fingerprint.c
    proof/gf8_circuit_fingerprint.c
    proof/gf16_circuit_fingerprint.c
    proof/params_fingerprint.c
    proof/vole_hash.c
    proof/proof.c
    proof/gf8_proof.c
    proof/gf16_proof.c
    proof/rs_membership_gf8.c
    proof/rs_gf8.c
    proof/rs_epoch_gf8.c
    proof/ring_sig_v1_gf8.c
    proof/rs_chunk_cert_proof.c
    proof/rs_opener_gf8.c
    proof/rs_opener_argus_gf8.c
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
    circuits/range_gf8_circuit.c
    circuits/node_hash_hirose_gf8.c
    circuits/node_hash_aes_gf8.c
    circuits/node_hash_grostl_gf8.c
    circuits/merkle_vt_gf8_circuit.c
    circuits/merkle_vt_gf8_helpers.c
    circuits/indexed_merkle_vt_gf8_circuit.c
    circuits/indexed_merkle_vt_gf8_helpers.c
    circuits/rs_membership_gf8_circuit.c
    circuits/rs_leaf_gf8_circuit.c
    circuits/rs_gf8_circuit.c
    circuits/rs_opener_gf8_circuit.c
    circuits/rlnc_gf16_circuit.c
    circuits/rlnc_gf16_cert_circuit.c
    circuits/permutation_gf16_circuit.c
    circuits/rlnc_confidential_gf16_circuit.c
    circuits/rs_chunk_cert_circuit.c
)

set(VOLEITH_PARSERS_SOURCES
    parsers/bristol.c
    parsers/shipshape.c
    parsers/shipshape_node_hash_types.c
    parsers/shipshape_registry_build.c
    parsers/shipshape_registry_table.c
    parsers/shipshape_witness.c
    parsers/shipshape_witgen_dispatch.c
    parsers/shipshape_witgen_aes.c
    parsers/shipshape_witgen_cmac_grostl.c
    parsers/shipshape_witgen_construction.c
)
list(APPEND VOLEITH_CORE_SOURCES ${VOLEITH_PARSERS_SOURCES})

# Erasure-coding module (plaintext data layer; sibling to vole/, depends
# only on core/).  Sources are added as each phase lands (P1 matrix, P2 RS,
# P3 RLNC); the header-only scaffolding (erasure/erasure.h) needs no source.
set(VOLEITH_ERASURE_SOURCES
    erasure/matrix.c
    erasure/rs.c
    erasure/rlnc.c
    erasure/rlnc_confidential.c
    erasure/rs_dataset.c
    erasure/rs_wire.c
    erasure/rs_membership.c
    erasure/rs_retriever.c
    erasure/rs_consistency.c
)
list(APPEND VOLEITH_CORE_SOURCES ${VOLEITH_ERASURE_SOURCES})

set(VOLEITH_CORE_INCLUDES
    ${CMAKE_CURRENT_SOURCE_DIR}/core
    ${CMAKE_CURRENT_SOURCE_DIR}/vole
    ${CMAKE_CURRENT_SOURCE_DIR}/erasure
    ${CMAKE_CURRENT_SOURCE_DIR}/proof
    ${CMAKE_CURRENT_SOURCE_DIR}/circuits
    ${CMAKE_CURRENT_SOURCE_DIR}/parsers
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
endfunction()

# Per-TU compile flags for the field backend files.
#
# Only the respective backend TU needs the ISA instruction flags.  The
# flags are directory-scoped (CMake 3.16 compatible), so they apply to
# every target in this CMakeLists.txt that compiles these source files.
# For targets that do not define the corresponding VOLEITH_HAVE_* macro,
# the files compile to empty objects and the extra flags are harmless.
#
# The AES / Grøstl per-TU flags moved to libtalos_ichor along with those
# sources; only the voleith-owned field carryless-mul backends remain.
if(HAVE_CLMUL)
    set_source_files_properties(core/field_clmul.c PROPERTIES
        COMPILE_FLAGS "-mpclmul -msse2 -msse4.1")
endif()
if(HAVE_PMULL AND ARMV8_CRYPTO_FLAGS)
    set_source_files_properties(core/field_pmull.c PROPERTIES
        COMPILE_FLAGS "${ARMV8_CRYPTO_FLAGS}")
endif()

# Production static library (libtalos_voleith.a)
add_library(voleith_core STATIC ${VOLEITH_CORE_SOURCES})
set_target_properties(voleith_core PROPERTIES OUTPUT_NAME talos_voleith)
target_include_directories(voleith_core PUBLIC ${VOLEITH_CORE_INCLUDES})
voleith_apply_hw_flags(voleith_core)

# Link the shared layer-0 core.  PRIVATE: ichor's headers are an internal
# implementation detail and must not be re-exported to external consumers of
# voleith (the sibling QC-MDPC library pulls ichor on its own).  For the static
# archive CMake still propagates the ichor link dependency (LINK_ONLY) to final
# executables so symbols resolve; only the include directories stay private.
target_link_libraries(voleith_core PRIVATE ichor)
target_include_directories(voleith_core PUBLIC
    "$<BUILD_INTERFACE:${VOLEITH_ICHOR_INCLUDE_DIR}>")

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
    target_link_libraries(voleith_core_shared PRIVATE ichor)
    target_include_directories(voleith_core_shared PUBLIC
        "$<BUILD_INTERFACE:${VOLEITH_ICHOR_INCLUDE_DIR}>")
endif()

if(VOLEITH_BUILD_TESTS)
    enable_testing()
    add_subdirectory(tests)
endif()

if(VOLEITH_BUILD_EXAMPLES)
    add_subdirectory(examples)
endif()

if(VOLEITH_BUILD_DUDECT)
    add_subdirectory(tools/dudect)
endif()

if(VOLEITH_BUILD_BENCH)
    add_subdirectory(tools/bench_fs_hash)
endif()

if(VOLEITH_BUILD_REGISTRY_FREEZE)
    add_subdirectory(tools/shipshape_registry_freeze)
endif()

if(VOLEITH_FUZZ)
    add_subdirectory(fuzz)
endif()
