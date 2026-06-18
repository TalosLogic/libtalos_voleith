# Copyright (c) 2026 Jason Crawford
# SPDX-License-Identifier: AGPL-3.0-only
#
# Run the freeze tool twice and assert byte-identical output (D7
# regeneration determinism, SHIPSHAPE_IMPLEMENTATION_PLAN.md W2.1).
# Invoked as: cmake -DTOOL=<path> -P determinism_check.cmake

execute_process(COMMAND ${TOOL} OUTPUT_VARIABLE out1 RESULT_VARIABLE r1)
if(NOT r1 EQUAL 0)
    message(FATAL_ERROR "shipshape_registry_freeze first run failed (exit ${r1})")
endif()

execute_process(COMMAND ${TOOL} OUTPUT_VARIABLE out2 RESULT_VARIABLE r2)
if(NOT r2 EQUAL 0)
    message(FATAL_ERROR "shipshape_registry_freeze second run failed (exit ${r2})")
endif()

if(NOT out1 STREQUAL out2)
    message(FATAL_ERROR "shipshape_registry_freeze output is not deterministic")
endif()

message(STATUS "shipshape_registry_freeze: deterministic across two runs")
