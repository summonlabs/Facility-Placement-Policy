# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Summon Software Labs.
#
# Facility Placement Policy - build, test, install and packaging rules.
#
# The primary product surface is the library target `facility_placement_policy`,
# exported as `dccp::facility_placement_policy`. The inspection CLI, the
# examples, the tests and the benchmarks are optional and are never installed
# except for the CLI. Nothing this project uses for itself (warning policy,
# sanitizer instrumentation, test support) leaks into the installed package.

cmake_minimum_required(VERSION 3.20)

# Keep in sync with include/dccp/facility_placement_policy/version.hpp; the test
# suite compares this value against the compiled-in library version so the two
# cannot drift apart silently.
project(facility_placement_policy
        VERSION 1.0.0
        DESCRIPTION "Deterministic evaluation of allowable physical placement"
        HOMEPAGE_URL "https://github.com/summonlabs/Facility-Placement-Policy"
        LANGUAGES CXX)

include(GNUInstallDirs)
include(CMakePackageConfigHelpers)

if(CMAKE_SOURCE_DIR STREQUAL CMAKE_CURRENT_SOURCE_DIR)
  set(FACILITY_PLACEMENT_POLICY_IS_TOP_LEVEL ON)
else()
  set(FACILITY_PLACEMENT_POLICY_IS_TOP_LEVEL OFF)
endif()

option(FACILITY_PLACEMENT_POLICY_BUILD_SHARED
       "Build facility_placement_policy as a shared library instead of a static one" OFF)
option(FACILITY_PLACEMENT_POLICY_BUILD_TESTS
       "Build the Facility Placement Policy test suite" ${FACILITY_PLACEMENT_POLICY_IS_TOP_LEVEL})
option(FACILITY_PLACEMENT_POLICY_BUILD_CLI
       "Build the fppctl inspection and evaluation tool" ON)
option(FACILITY_PLACEMENT_POLICY_BUILD_EXAMPLES
       "Build the Facility Placement Policy examples" ${FACILITY_PLACEMENT_POLICY_IS_TOP_LEVEL})
option(FACILITY_PLACEMENT_POLICY_BUILD_BENCHMARKS
       "Build the Facility Placement Policy benchmarks" ${FACILITY_PLACEMENT_POLICY_IS_TOP_LEVEL})
option(FACILITY_PLACEMENT_POLICY_WARNINGS_AS_ERRORS
       "Treat every first-party compiler warning as an error" ON)
option(FACILITY_PLACEMENT_POLICY_ENABLE_ASAN
       "Build first-party targets with AddressSanitizer" OFF)

if(NOT CMAKE_CONFIGURATION_TYPES AND NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE Release CACHE STRING "Build type" FORCE)
endif()

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

if(FACILITY_PLACEMENT_POLICY_BUILD_SHARED)
  set(FACILITY_PLACEMENT_POLICY_LIBRARY_TYPE SHARED)
else()
  set(FACILITY_PLACEMENT_POLICY_LIBRARY_TYPE STATIC)
endif()

# ---------------------------------------------------------------------------
# Warning policy
# ---------------------------------------------------------------------------
#
# The warning interface target is used with $<BUILD_INTERFACE:...> everywhere it
# is linked, so an installed consumer never inherits this project's warning
# policy and never fails to configure because the target is missing.

add_library(facility_placement_policy_warnings INTERFACE)
add_library(dccp::facility_placement_policy_warnings ALIAS facility_placement_policy_warnings)

if(MSVC)
  target_compile_options(facility_placement_policy_warnings INTERFACE
    /W4 /permissive- /utf-8 /Zc:__cplusplus /EHsc /MP)
  if(FACILITY_PLACEMENT_POLICY_WARNINGS_AS_ERRORS)
    target_compile_options(facility_placement_policy_warnings INTERFACE /WX)
  endif()
else()
  target_compile_options(facility_placement_policy_warnings INTERFACE
    -Wall -Wextra -Wpedantic -Wshadow -Wnon-virtual-dtor -Wcast-align
    -Wunused -Woverloaded-virtual -Wnull-dereference -Wdouble-promotion
    -Wformat=2 -Wimplicit-fallthrough)
  if(FACILITY_PLACEMENT_POLICY_WARNINGS_AS_ERRORS)
    target_compile_options(facility_placement_policy_warnings INTERFACE -Werror)
  endif()
endif()

# ---------------------------------------------------------------------------
# Sanitizer instrumentation
# ---------------------------------------------------------------------------

add_library(facility_placement_policy_sanitizers INTERFACE)
if(FACILITY_PLACEMENT_POLICY_ENABLE_ASAN)
  if(MSVC)
    target_compile_options(facility_placement_policy_sanitizers INTERFACE /fsanitize=address)
    target_link_options(facility_placement_policy_sanitizers INTERFACE /fsanitize=address)
  else()
    target_compile_options(facility_placement_policy_sanitizers INTERFACE
      -fsanitize=address -fno-omit-frame-pointer)
    target_link_options(facility_placement_policy_sanitizers INTERFACE
      -fsanitize=address -fno-omit-frame-pointer)
  endif()
endif()

# ---------------------------------------------------------------------------
# Library
# ---------------------------------------------------------------------------

set(FACILITY_PLACEMENT_POLICY_SOURCES
  src/result.cpp
  src/strong_id.cpp
  src/digest.cpp
  src/crc32.cpp
  src/time.cpp
  src/text_util.cpp
  src/facility.cpp
  src/policy.cpp
  src/request.cpp
  src/verdict.cpp
  src/canonical.cpp
  src/text.cpp
  src/evaluate.cpp
  src/json_out.cpp
  src/file_ops.cpp
  src/store.cpp)

add_library(facility_placement_policy ${FACILITY_PLACEMENT_POLICY_LIBRARY_TYPE}
  ${FACILITY_PLACEMENT_POLICY_SOURCES})
add_library(dccp::facility_placement_policy ALIAS facility_placement_policy)

target_compile_features(facility_placement_policy PUBLIC cxx_std_20)
target_include_directories(facility_placement_policy
  PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>
  PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/src)
target_link_libraries(facility_placement_policy
  PRIVATE
    $<BUILD_INTERFACE:facility_placement_policy_warnings>
    $<BUILD_INTERFACE:facility_placement_policy_sanitizers>)
set_target_properties(facility_placement_policy PROPERTIES
  CXX_EXTENSIONS OFF
  VERSION ${PROJECT_VERSION}
  SOVERSION ${PROJECT_VERSION_MAJOR}
  POSITION_INDEPENDENT_CODE ON
  EXPORT_NAME facility_placement_policy)

if(FACILITY_PLACEMENT_POLICY_BUILD_SHARED)
  if(MSVC)
    set_target_properties(facility_placement_policy PROPERTIES WINDOWS_EXPORT_ALL_SYMBOLS ON)
  endif()
endif()

# ---------------------------------------------------------------------------
# Command line tool
# ---------------------------------------------------------------------------

if(FACILITY_PLACEMENT_POLICY_BUILD_CLI)
  add_executable(fppctl apps/fppctl/main.cpp apps/fppctl/commands.cpp)
  target_link_libraries(fppctl
    PRIVATE
      dccp::facility_placement_policy
      $<BUILD_INTERFACE:facility_placement_policy_warnings>
      $<BUILD_INTERFACE:facility_placement_policy_sanitizers>)
  target_include_directories(fppctl PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src)
  set_target_properties(fppctl PROPERTIES CXX_EXTENSIONS OFF)
endif()

# ---------------------------------------------------------------------------
# Examples
# ---------------------------------------------------------------------------

if(FACILITY_PLACEMENT_POLICY_BUILD_EXAMPLES)
  foreach(example_name IN ITEMS
      evaluate_placements
      durable_policy_store
      consume_upstream_evidence)
    add_executable(facility_placement_policy_example_${example_name}
      examples/${example_name}.cpp)
    target_link_libraries(facility_placement_policy_example_${example_name}
      PRIVATE
        dccp::facility_placement_policy
        $<BUILD_INTERFACE:facility_placement_policy_warnings>
        $<BUILD_INTERFACE:facility_placement_policy_sanitizers>)
    set_target_properties(facility_placement_policy_example_${example_name}
      PROPERTIES CXX_EXTENSIONS OFF)
  endforeach()
endif()

# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

if(FACILITY_PLACEMENT_POLICY_BUILD_TESTS)
  enable_testing()

  # The suites are registered individually so a failure names the suite and the
  # suites can run in parallel. test_main fails when asked for a suite that does
  # not exist, so a typo here cannot silently reduce coverage.
  set(FACILITY_PLACEMENT_POLICY_TEST_SUITES
    result
    digest
    time
    text_util
    policy
    canonical
    evaluate
    override
    verdict
    store
    recovery
    property
    adversarial
    concurrency
    multiprocess
    crash
    cli)

  add_library(facility_placement_policy_test_support STATIC
    tests/test_main.cpp
    tests/test_support.cpp
    tests/child_process.cpp)
  target_link_libraries(facility_placement_policy_test_support
    PUBLIC
      dccp::facility_placement_policy
      $<BUILD_INTERFACE:facility_placement_policy_warnings>
      $<BUILD_INTERFACE:facility_placement_policy_sanitizers>)
  target_include_directories(facility_placement_policy_test_support
    PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/tests
    PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src)
  target_compile_definitions(facility_placement_policy_test_support
    PUBLIC
      FACILITY_PLACEMENT_POLICY_CMAKE_VERSION="${PROJECT_VERSION}"
      FACILITY_PLACEMENT_POLICY_SCRATCH_ROOT="${CMAKE_CURRENT_BINARY_DIR}/test-scratch"
      FACILITY_PLACEMENT_POLICY_CRASH_CHILD_PATH="$<TARGET_FILE:facility_placement_policy_crash_child>")
  set_target_properties(facility_placement_policy_test_support PROPERTIES CXX_EXTENSIONS OFF)

  add_executable(facility_placement_policy_tests
    tests/tests_result.cpp
    tests/tests_digest.cpp
    tests/tests_time.cpp
    tests/tests_text_util.cpp
    tests/tests_policy.cpp
    tests/tests_canonical.cpp
    tests/tests_evaluate.cpp
    tests/tests_override.cpp
    tests/tests_verdict.cpp
    tests/tests_store.cpp
    tests/tests_recovery.cpp
    tests/tests_property.cpp
    tests/tests_adversarial.cpp
    tests/tests_concurrency.cpp
    tests/tests_multiprocess.cpp
    tests/tests_crash.cpp
    tests/tests_cli.cpp)
  target_link_libraries(facility_placement_policy_tests
    PRIVATE facility_placement_policy_test_support)
  target_include_directories(facility_placement_policy_tests
    PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src)
  set_target_properties(facility_placement_policy_tests PROPERTIES CXX_EXTENSIONS OFF)

  # The crash sweeps and the independent-process tests need a helper that dies on
  # request, and the CLI tests run the real tool as an independent process.
  add_executable(facility_placement_policy_crash_child tests/crash_child.cpp)
  target_link_libraries(facility_placement_policy_crash_child
    PRIVATE
      dccp::facility_placement_policy
      $<BUILD_INTERFACE:facility_placement_policy_warnings>
      $<BUILD_INTERFACE:facility_placement_policy_sanitizers>)
  target_include_directories(facility_placement_policy_crash_child
    PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src)
  set_target_properties(facility_placement_policy_crash_child PROPERTIES CXX_EXTENSIONS OFF)

  add_dependencies(facility_placement_policy_tests facility_placement_policy_crash_child)
  add_dependencies(facility_placement_policy_test_support facility_placement_policy_crash_child)

  if(FACILITY_PLACEMENT_POLICY_BUILD_CLI)
    # The path is compiled into the support library, because that is where the
    # tests ask for it, and into the tests themselves for the same reason.
    target_compile_definitions(facility_placement_policy_test_support
      PUBLIC FACILITY_PLACEMENT_POLICY_CLI_PATH="$<TARGET_FILE:fppctl>")
    add_dependencies(facility_placement_policy_tests fppctl)
  endif()

  foreach(suite IN LISTS FACILITY_PLACEMENT_POLICY_TEST_SUITES)
    add_test(NAME facility_placement_policy_${suite}
             COMMAND facility_placement_policy_tests --suite ${suite})
    set_tests_properties(facility_placement_policy_${suite} PROPERTIES
      WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR})
  endforeach()

  # The complete suite in one process, to prove the suites do not interfere.
  add_test(NAME facility_placement_policy_all COMMAND facility_placement_policy_tests)
  set_tests_properties(facility_placement_policy_all PROPERTIES
    WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR})
endif()

# ---------------------------------------------------------------------------
# Benchmarks
# ---------------------------------------------------------------------------

if(FACILITY_PLACEMENT_POLICY_BUILD_BENCHMARKS)
  add_executable(facility_placement_policy_benchmarks benchmarks/benchmarks.cpp)
  target_link_libraries(facility_placement_policy_benchmarks
    PRIVATE
      dccp::facility_placement_policy
      $<BUILD_INTERFACE:facility_placement_policy_warnings>
      $<BUILD_INTERFACE:facility_placement_policy_sanitizers>)
  set_target_properties(facility_placement_policy_benchmarks PROPERTIES CXX_EXTENSIONS OFF)
endif()

# ---------------------------------------------------------------------------
# Install and export
# ---------------------------------------------------------------------------

install(TARGETS facility_placement_policy
  EXPORT facility_placement_policyTargets
  RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
  LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
  ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
  INCLUDES DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})

if(FACILITY_PLACEMENT_POLICY_BUILD_CLI)
  install(TARGETS fppctl RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
endif()

install(DIRECTORY include/ DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})

set(FACILITY_PLACEMENT_POLICY_CMAKE_INSTALL_DIR
    ${CMAKE_INSTALL_LIBDIR}/cmake/facility_placement_policy)

install(EXPORT facility_placement_policyTargets
  FILE facility_placement_policyTargets.cmake
  NAMESPACE dccp::
  DESTINATION ${FACILITY_PLACEMENT_POLICY_CMAKE_INSTALL_DIR})

configure_package_config_file(
  ${CMAKE_CURRENT_SOURCE_DIR}/cmake/facility_placement_policyConfig.cmake.in
  ${CMAKE_CURRENT_BINARY_DIR}/facility_placement_policyConfig.cmake
  INSTALL_DESTINATION ${FACILITY_PLACEMENT_POLICY_CMAKE_INSTALL_DIR})

write_basic_package_version_file(
  ${CMAKE_CURRENT_BINARY_DIR}/facility_placement_policyConfigVersion.cmake
  VERSION ${PROJECT_VERSION}
  COMPATIBILITY SameMajorVersion)

install(FILES
  ${CMAKE_CURRENT_BINARY_DIR}/facility_placement_policyConfig.cmake
  ${CMAKE_CURRENT_BINARY_DIR}/facility_placement_policyConfigVersion.cmake
  DESTINATION ${FACILITY_PLACEMENT_POLICY_CMAKE_INSTALL_DIR})

install(FILES
  ${CMAKE_CURRENT_SOURCE_DIR}/README.md
  ${CMAKE_CURRENT_SOURCE_DIR}/LICENSE
  ${CMAKE_CURRENT_SOURCE_DIR}/NOTICE
  DESTINATION ${CMAKE_INSTALL_DOCDIR})
