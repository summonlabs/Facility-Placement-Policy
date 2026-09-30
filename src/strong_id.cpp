// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs.

#include "dccp/facility_placement_policy/strong_id.hpp"

#include <cctype>

namespace dccp::facility_placement_policy {
namespace {

constexpr bool is_ascii_alphanumeric(char ch) noexcept {
  return (ch >= '0' && ch <= '9') || (ch >= 'A' && ch <= 'Z') || (ch >= 'a' && ch <= 'z');
}

constexpr bool is_interior_character(char ch) noexcept {
  return is_ascii_alphanumeric(ch) || ch == '.' || ch == ':' || ch == '-';
}

}  // namespace

bool is_valid_identifier_syntax(std::string_view raw) noexcept {
  if (raw.empty() || raw.size() > kMaxIdentifierBytes) {
    return false;
  }
  if (!is_ascii_alphanumeric(raw.front()) || !is_ascii_alphanumeric(raw.back())) {
    return false;
  }
  for (const char ch : raw) {
    if (!is_interior_character(ch)) {
      return false;
    }
  }
  return true;
}

std::string_view identifier_syntax_help() noexcept {
  return "identifier must be 1..128 bytes, start and end with an ASCII letter or digit, "
         "and contain only ASCII letters, digits, '.', ':' or '-' in between";
}

}  // namespace dccp::facility_placement_policy
