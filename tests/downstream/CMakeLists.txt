# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Summon Software Labs.
#
# An independent consumer of the installed Facility Placement Policy package.
#
# This project is deliberately not part of the main build: it is configured
# against an installed prefix only, with find_package, so it proves that the
# export set, the headers and the version file are enough for a downstream
# project that has never seen this source tree.

cmake_minimum_required(VERSION 3.20)

project(facility_placement_policy_downstream LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
  set(CMAKE_BUILD_TYPE Release CACHE STRING "Build type" FORCE)
endif()

find_package(facility_placement_policy CONFIG REQUIRED)

add_executable(fpp_downstream main.cpp)
target_link_libraries(fpp_downstream PRIVATE dccp::facility_placement_policy)
target_compile_options(fpp_downstream PRIVATE
  $<$<CXX_COMPILER_ID:MSVC>:/W4 /WX /permissive- /utf-8>
  $<$<NOT:$<CXX_COMPILER_ID:MSVC>>:-Wall -Wextra -Werror>)
