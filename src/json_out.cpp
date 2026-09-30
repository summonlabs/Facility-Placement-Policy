// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs.

#include "json_out.hpp"

#include <cstddef>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace dccp::facility_placement_policy::internal {
namespace {

void append_escaped(std::string& out, std::string_view text) {
  out.push_back('"');
  for (const char ch : text) {
    const auto byte = static_cast<unsigned char>(ch);
    switch (ch) {
      case '"':
        out.append("\\\"");
        break;
      case '\\':
        out.append("\\\\");
        break;
      case '\n':
        out.append("\\n");
        break;
      case '\r':
        out.append("\\r");
        break;
      case '\t':
        out.append("\\t");
        break;
      default:
        if (byte < 0x20u) {
          static constexpr char kHex[] = "0123456789abcdef";
          out.append("\\u00");
          out.push_back(kHex[(byte >> 4) & 0x0Fu]);
          out.push_back(kHex[byte & 0x0Fu]);
        } else {
          out.push_back(ch);
        }
        break;
    }
  }
  out.push_back('"');
}

}  // namespace

std::string json_string(std::string_view text) {
  std::string out;
  out.reserve(text.size() + 2);
  append_escaped(out, text);
  return out;
}

std::string json_number(std::uint64_t value) { return std::to_string(value); }

std::string json_number(std::uint32_t value) { return std::to_string(value); }

std::string json_number(std::int64_t value) { return std::to_string(value); }

std::string json_bool(bool value) { return value ? "true" : "false"; }

std::string json_null() { return "null"; }

std::string json_object(const std::vector<JsonField>& fields) {
  std::string out;
  out.push_back('{');
  bool first = true;
  for (const JsonField& field : fields) {
    if (!first) {
      out.push_back(',');
    }
    first = false;
    append_escaped(out, field.first);
    out.push_back(':');
    out.append(field.second);
  }
  out.push_back('}');
  return out;
}

std::string json_array(const std::vector<std::string>& items) {
  std::string out;
  out.push_back('[');
  bool first = true;
  for (const std::string& item : items) {
    if (!first) {
      out.push_back(',');
    }
    first = false;
    out.append(item);
  }
  out.push_back(']');
  return out;
}

std::string json_string_array(const std::vector<std::string>& items) {
  std::vector<std::string> rendered;
  rendered.reserve(items.size());
  for (const std::string& item : items) {
    rendered.push_back(json_string(item));
  }
  return json_array(rendered);
}

std::string json_digest(const Digest& digest) { return json_string(digest_tagged_hex(digest)); }

}  // namespace dccp::facility_placement_policy::internal
