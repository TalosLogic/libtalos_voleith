# Copyright (c) 2026 Jason Crawford
# SPDX-License-Identifier: AGPL-3.0-only
#
# dudect timing-validation harness.  Builds a dedicated static
# library copy of the core sources with no hardware-acceleration
# definitions, so the binary exercises the constant-time software
# paths (bitsliced AES, scalar field multiplication) that we want
# to validate.  The hardware paths (CLMUL, AES-NI, PMULL) are
# constant-time by ISA specification and do not need empirical
# validation here.

# Library copy of the core sources with zero hardware flags.
# VOLEITH_CORE_SOURCES uses paths relative to the top-level
# CMakeLists; re-anchor them to CMAKE_SOURCE_DIR so this subdirectory
# can find them.
set(_DUDECT_CORE_SOURCES "")
foreach(_src ${VOLEITH_CORE_SOURCES})
    list(APPEND _DUDECT_CORE_SOURCES "${CMAKE_SOURCE_DIR}/${_src}")
endforeach()

add_library(voleith_core_dudect STATIC ${_DUDECT_CORE_SOURCES})
target_include_directories(voleith_core_dudect
    PUBLIC ${VOLEITH_CORE_INCLUDES}
)
unset(_DUDECT_CORE_SOURCES)

# Harness executable.
set(DUDECT_SOURCES
    dudect_runner.c
    dudect_timer.c
    dudect_platform.c
    dudect_main.c
    targets_sentinel.c
    targets_aes.c
    targets_field.c
    targets_byte_combine.c
)

add_executable(dudect ${DUDECT_SOURCES})
target_include_directories(dudect PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(dudect voleith_core_dudect)

# libm for sqrt() in the t-statistic.  Linux requires -lm explicitly;
# macOS / BSD fold it into libc but tolerate the link line.
if(NOT APPLE)
    target_link_libraries(dudect m)
endif()

# Lives outside the test pipeline.  Run manually; see
# docs/DUDECT_TIMING_VALIDATION.md.
set_target_properties(dudect PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/tools/dudect
)
