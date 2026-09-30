// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs.
//
// Deterministic JSON rendering for the command line tool. Not installed.
//
// The renderer is deliberately a set of small pure functions over ordered
// vectors rather than a streaming writer with state: field order is the order
// the caller wrote, which is the order the documentation describes, and two runs
// over the same input therefore produce identical bytes.

#ifndef DCCP_FACILITY_PLACEMENT_POLICY_SRC_JSON_OUT_HPP
#define DCCP_FACILITY_PLACEMENT_POLICY_SRC_JSON_OUT_HPP

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "dccp/facility_placement_policy/digest.hpp"
#include "dccp/facility_placement_policy/generation.hpp"

namespace dccp::facility_placement_policy::internal {

using JsonField = std::pair<std::string, std::string>;

/// A JSON string literal, escaped and quoted.
std::string json_string(std::string_view text);

/// A JSON number. The unsigned overloads are distinct so that a 32-bit count
/// never has to choose between the signed and unsigned 64-bit forms.
std::string json_number(std::uint64_t value);
std::string json_number(std::uint32_t value);
std::string json_number(std::int64_t value);

/// A JSON boolean.
std::string json_bool(bool value);

/// JSON null.
std::string json_null();

/// An object whose fields appear in the order given.
std::string json_object(const std::vector<JsonField>& fields);

/// An array of already-rendered JSON values.
std::string json_array(const std::vector<std::string>& items);

/// An array of strings.
std::string json_string_array(const std::vector<std::string>& items);

/// "sha256:<hex>".
std::string json_digest(const Digest& digest);

/// Renders a counter, or JSON null when it is absent.
template <class Tag>
std::string json_counter(const Counter<Tag>& counter) {
  return counter.is_valid() ? json_number(counter.value()) : json_null();
}

/// Renders an optional counter, or JSON null when it is absent.
template <class Tag>
std::string json_optional_counter(const std::optional<Counter<Tag>>& counter) {
  return counter.has_value() ? json_counter(*counter) : json_null();
}

}  // namespace dccp::facility_placement_policy::internal

#endif  // DCCP_FACILITY_PLACEMENT_POLICY_SRC_JSON_OUT_HPP
