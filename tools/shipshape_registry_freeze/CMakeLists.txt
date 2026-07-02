# Copyright (c) 2026 Jason Crawford
# SPDX-License-Identifier: AGPL-3.0-only
#
# shipshape_registry_freeze: regenerate the frozen crypto-v1 Tier 2a registry
# table (parsers/shipshape_registry_table.c) from the live builders in
# parsers/shipshape_registry_build.c.  Opt-in:
#
#   cmake -S . -B build -DVOLEITH_BUILD_REGISTRY_FREEZE=ON
#   cmake --build build --target shipshape_registry_freeze
#   ./build/tools/shipshape_registry_freeze/shipshape_registry_freeze \
#       > parsers/shipshape_registry_table.c
#
# the stdlib spec §3, D7; the implementation plan W2.1.

add_executable(shipshape_registry_freeze shipshape_registry_freeze.c)
target_link_libraries(shipshape_registry_freeze PRIVATE voleith_core)
target_include_directories(shipshape_registry_freeze PRIVATE ${VOLEITH_CORE_INCLUDES})
set_target_properties(shipshape_registry_freeze PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/tools/shipshape_registry_freeze)

# Determinism gate (D7): two runs produce byte-identical output.  Only
# meaningful when testing is enabled (VOLEITH_BUILD_TESTS).
add_test(NAME shipshape_registry_freeze_determinism
    COMMAND ${CMAKE_COMMAND}
        -DTOOL=$<TARGET_FILE:shipshape_registry_freeze>
        -P ${CMAKE_CURRENT_SOURCE_DIR}/determinism_check.cmake)
