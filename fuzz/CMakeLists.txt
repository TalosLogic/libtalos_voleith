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
# See fuzz/README.md; docs/SHIPSHAPE_IMPLEMENTATION_PLAN.md W4.1; ISA 1.5,
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
