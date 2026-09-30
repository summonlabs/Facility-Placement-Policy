// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs.

#include "dccp/facility_placement_policy/text_util.hpp"

#include <cstddef>
#include <string>

namespace dccp::facility_placement_policy {
namespace {

constexpr bool is_space(char ch) noexcept {
  return ch == ' ' || ch == '\t' || ch == '\n' || ch == '\r' || ch == '\v' || ch == '\f';
}

constexpr char hex_digit(unsigned value) noexcept {
  return static_cast<char>(value < 10u ? ('0' + value) : ('A' + (value - 10u)));
}

constexpr int hex_value(char ch) noexcept {
  if (ch >= '0' && ch <= '9') {
    return ch - '0';
  }
  if (ch >= 'A' && ch <= 'F') {
    return 10 + (ch - 'A');
  }
  if (ch >= 'a' && ch <= 'f') {
    return 10 + (ch - 'a');
  }
  return -1;
}

}  // namespace

bool is_valid_utf8(std::string_view text) noexcept {
  const auto* bytes = reinterpret_cast<const std::uint8_t*>(text.data());
  const std::size_t size = text.size();
  std::size_t index = 0;
  while (index < size) {
    const std::uint8_t lead = bytes[index];
    if (lead < 0x80u) {
      ++index;
      continue;
    }
    std::size_t continuation = 0;
    std::uint32_t code_point = 0;
    if ((lead & 0xE0u) == 0xC0u) {
      continuation = 1;
      code_point = lead & 0x1Fu;
    } else if ((lead & 0xF0u) == 0xE0u) {
      continuation = 2;
      code_point = lead & 0x0Fu;
    } else if ((lead & 0xF8u) == 0xF0u) {
      continuation = 3;
      code_point = lead & 0x07u;
    } else {
      return false;
    }
    if (size - index <= continuation) {
      return false;
    }
    for (std::size_t offset = 1; offset <= continuation; ++offset) {
      const std::uint8_t next = bytes[index + offset];
      if ((next & 0xC0u) != 0x80u) {
        return false;
      }
      code_point = (code_point << 6) | (next & 0x3Fu);
    }
    // Reject overlong encodings, code points above U+10FFFF and surrogates.
    if (continuation == 1 && code_point < 0x80u) {
      return false;
    }
    if (continuation == 2 && code_point < 0x800u) {
      return false;
    }
    if (continuation == 3 && code_point < 0x10000u) {
      return false;
    }
    if (code_point > 0x10FFFFu) {
      return false;
    }
    if (code_point >= 0xD800u && code_point <= 0xDFFFu) {
      return false;
    }
    index += continuation + 1;
  }
  return true;
}

Result<std::string> require_valid_utf8(std::string_view text, std::string_view what,
                                       std::size_t max_bytes) {
  if (text.size() > max_bytes) {
    return Error(ErrorCode::TextTooLong, "text field exceeds its maximum length")
        .with_subject(std::string(what))
        .with_detail("limit=" + std::to_string(max_bytes) +
                     " actual=" + std::to_string(text.size()));
  }
  if (!is_valid_utf8(text)) {
    return Error(ErrorCode::InvalidUtf8, "text field is not valid UTF-8")
        .with_subject(std::string(what));
  }
  return std::string(text);
}

bool is_ascii(std::string_view text) noexcept {
  for (const char ch : text) {
    if (static_cast<unsigned char>(ch) > 0x7Fu) {
      return false;
    }
  }
  return true;
}

bool is_ascii_printable(std::string_view text) noexcept {
  for (const char ch : text) {
    const auto value = static_cast<unsigned char>(ch);
    if (value < 0x20u || value > 0x7Eu) {
      return false;
    }
  }
  return true;
}

std::string text_escape(std::string_view text) {
  std::string out;
  out.reserve(text.size() + 8);
  for (const char ch : text) {
    switch (ch) {
      case '\\':
        out.append("\\\\");
        break;
      case '"':
        out.append("\\\"");
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
      default: {
        const auto byte = static_cast<unsigned char>(ch);
        if (byte < 0x20u || byte == 0x7Fu) {
          out.append("\\x");
          out.push_back(hex_digit(byte >> 4));
          out.push_back(hex_digit(byte & 0x0Fu));
        } else {
          out.push_back(ch);
        }
        break;
      }
    }
  }
  return out;
}

Result<std::string> text_unescape(std::string_view text) {
  std::string out;
  out.reserve(text.size());
  std::size_t index = 0;
  while (index < text.size()) {
    const char ch = text[index];
    if (ch != '\\') {
      out.push_back(ch);
      ++index;
      continue;
    }
    ++index;
    if (index >= text.size()) {
      return Error(ErrorCode::TruncatedInput, "text ends with an incomplete escape sequence")
          .with_subject(std::string(text.substr(0, 96)));
    }
    const char escape = text[index];
    ++index;
    switch (escape) {
      case '\\':
        out.push_back('\\');
        break;
      case '"':
        out.push_back('"');
        break;
      case 'n':
        out.push_back('\n');
        break;
      case 'r':
        out.push_back('\r');
        break;
      case 't':
        out.push_back('\t');
        break;
      case 'x': {
        if (text.size() - index < 2) {
          return Error(ErrorCode::TruncatedInput, "\\x escape needs two hexadecimal digits")
              .with_subject(std::string(text.substr(0, 96)));
        }
        const int high = hex_value(text[index]);
        const int low = hex_value(text[index + 1]);
        if (high < 0 || low < 0) {
          return Error(ErrorCode::MalformedDocument, "\\x escape needs two hexadecimal digits")
              .with_subject(std::string(text.substr(0, 96)));
        }
        const auto byte = static_cast<unsigned>((high << 4) | low);
        if (byte >= 0x20u && byte != 0x7Fu) {
          return Error(ErrorCode::MalformedDocument,
                       "\\x escape is reserved for control bytes; printable bytes are literal")
              .with_subject(std::string(text.substr(0, 96)));
        }
        out.push_back(static_cast<char>(byte));
        index += 2;
        break;
      }
      default:
        return Error(ErrorCode::UnknownEnumToken, "unknown escape sequence in text")
            .with_subject(std::string(text.substr(0, 96)));
    }
  }
  return out;
}

std::string_view trim_ascii(std::string_view text) noexcept {
  std::size_t begin = 0;
  std::size_t end = text.size();
  while (begin < end && is_space(text[begin])) {
    ++begin;
  }
  while (end > begin && is_space(text[end - 1])) {
    --end;
  }
  return text.substr(begin, end - begin);
}

bool ascii_iequals(std::string_view lhs, std::string_view rhs) noexcept {
  if (lhs.size() != rhs.size()) {
    return false;
  }
  for (std::size_t index = 0; index < lhs.size(); ++index) {
    char left = lhs[index];
    char right = rhs[index];
    if (left >= 'A' && left <= 'Z') {
      left = static_cast<char>(left - 'A' + 'a');
    }
    if (right >= 'A' && right <= 'Z') {
      right = static_cast<char>(right - 'A' + 'a');
    }
    if (left != right) {
      return false;
    }
  }
  return true;
}

std::string ascii_upper(std::string_view text) {
  std::string out(text);
  for (char& ch : out) {
    if (ch >= 'a' && ch <= 'z') {
      ch = static_cast<char>(ch - 'a' + 'A');
    }
  }
  return out;
}

std::string ascii_lower(std::string_view text) {
  std::string out(text);
  for (char& ch : out) {
    if (ch >= 'A' && ch <= 'Z') {
      ch = static_cast<char>(ch - 'A' + 'a');
    }
  }
  return out;
}

Result<std::uint64_t> parse_uint64_strict(std::string_view text, std::string_view what,
                                          bool allow_zero) {
  if (text.empty()) {
    return Error(ErrorCode::MissingField, "numeric field is empty")
        .with_subject(std::string(what));
  }
  if (text.size() > 1 && text[0] == '0') {
    return Error(ErrorCode::MalformedDocument,
                 "numeric field has a leading zero, which is not canonical")
        .with_subject(std::string(what));
  }
  std::uint64_t value = 0;
  for (const char ch : text) {
    if (ch < '0' || ch > '9') {
      return Error(ErrorCode::MalformedDocument, "numeric field must contain decimal digits only")
          .with_subject(std::string(what));
    }
    const auto digit = static_cast<std::uint64_t>(ch - '0');
    if (value > (UINT64_MAX - digit) / 10u) {
      return Error(ErrorCode::NumericOverflow, "numeric field does not fit in 64 bits")
          .with_subject(std::string(what));
    }
    value = value * 10u + digit;
  }
  if (value == 0 && !allow_zero) {
    return Error(ErrorCode::InvalidArgument, "numeric field must be greater than zero")
        .with_subject(std::string(what));
  }
  return value;
}

std::string to_decimal(std::uint64_t value) { return std::to_string(value); }

}  // namespace dccp::facility_placement_policy
