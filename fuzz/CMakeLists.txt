# Copyright (c) 2026 Jason Crawford
# SPDX-License-Identifier: AGPL-3.0-only
#
# libFuzzer harnesses for the parser entry points (W4.1).  Opt-in, Clang
# only; the root CMakeLists builds the whole library with
# -fsanitize=fuzzer-no-link,address,undefined when VOLEITH_FUZZ=ON, and these
# targets add the libFuzzer runtime at link:
#
#   CC=clang cmake -S . -B build-fuzz -DVOLEITH_FUZZ=ON
#   cmake --build build-fuzz --target fuzz_shipshape fuzz_bristol
#   ./build-fuzz/fuzz/fuzz_shipshape fuzz/corpus/shipshape
#   ./build-fuzz/fuzz/fuzz_bristol   fuzz/corpus/bristol
#
# See fuzz/README.md; the implementation plan W4.1; ISA 1.5,
# 8.4 item 11.

function(voleith_add_fuzzer NAME SRC)
    add_executable(${NAME} ${SRC})
    target_link_libraries(${NAME} PRIVATE voleith_core)
    target_include_directories(${NAME} PRIVATE ${VOLEITH_CORE_INCLUDES})
    target_link_options(${NAME} PRIVATE -fsanitize=fuzzer,address,undefined)
    set_target_properties(${NAME} PROPERTIES
        RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/fuzz)
endfunction()

voleith_add_fuzzer(fuzz_shipshape fuzz_shipshape.c)
voleith_add_fuzzer(fuzz_bristol fuzz_bristol.c)

# Composable ring-signature harnesses (1.8.0 security review follow-up:
# fuzz the two attacker-controlled entry points voleith_rs_sig_unpack and
# voleith_rs_verify).  Both share the fixed configuration in
# fuzz_rs_common.h.
voleith_add_fuzzer(fuzz_rs_unpack fuzz_rs_unpack.c)
voleith_add_fuzzer(fuzz_rs_verify fuzz_rs_verify.c)

# Seed generator: a plain executable (no libFuzzer runtime) that signs once
# and writes binary seeds for the two RS harnesses into corpus-work/.  RS
# proofs are binary and cannot be hand-written like the .ship / Bristol
# seeds, so they are regenerated rather than committed.
add_executable(fuzz_rs_seedgen fuzz_rs_seedgen.c)
target_link_libraries(fuzz_rs_seedgen PRIVATE voleith_core)
target_include_directories(fuzz_rs_seedgen PRIVATE ${VOLEITH_CORE_INCLUDES})
target_link_options(fuzz_rs_seedgen PRIVATE -fsanitize=address,undefined)
set_target_properties(fuzz_rs_seedgen PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/fuzz)
