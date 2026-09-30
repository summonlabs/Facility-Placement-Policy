// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs.

#ifndef DCCP_FACILITY_PLACEMENT_POLICY_VERSION_HPP
#define DCCP_FACILITY_PLACEMENT_POLICY_VERSION_HPP

#include <cstdint>
#include <string_view>

namespace dccp::facility_placement_policy {

/// Semantic version of the library, kept in sync with the CMake project
/// version. The test suite asserts that the two never drift apart.
inline constexpr int kVersionMajor = 1;
inline constexpr int kVersionMinor = 0;
inline constexpr int kVersionPatch = 0;

/// "1.0.0"
inline constexpr std::string_view kVersionString = "1.0.0";

/// The library version as text, "major.minor.patch".
inline std::string_view version_string() noexcept { return kVersionString; }

/// Major component of the library version.
constexpr int version_major() noexcept { return kVersionMajor; }

}  // namespace dccp::facility_placement_policy

#endif  // DCCP_FACILITY_PLACEMENT_POLICY_VERSION_HPP
