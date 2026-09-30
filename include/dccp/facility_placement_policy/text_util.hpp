// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs.

#ifndef DCCP_FACILITY_PLACEMENT_POLICY_TEXT_UTIL_HPP
#define DCCP_FACILITY_PLACEMENT_POLICY_TEXT_UTIL_HPP

#include <cstdint>
#include <string>
#include <string_view>

#include "dccp/facility_placement_policy/result.hpp"

namespace dccp::facility_placement_policy {

/// Strict UTF-8 validation: rejects overlong encodings, surrogate code points,
/// code points above U+10FFFF, truncated sequences and stray continuation
/// bytes. Untrusted text is validated before it reaches any other code.
bool is_valid_utf8(std::string_view text) noexcept;

/// Validates and copies, reporting ErrorCode::InvalidUtf8 or TextTooLong.
Result<std::string> require_valid_utf8(std::string_view text, std::string_view what,
                                       std::size_t max_bytes);

/// True when every byte is in 0x00..0x7F.
bool is_ascii(std::string_view text) noexcept;

/// True when every byte is in 0x20..0x7E.
bool is_ascii_printable(std::string_view text) noexcept;

/// Canonical escaping for the text document format, without the surrounding
/// quotes: backslash, double quote, newline, carriage return and tab have their
/// short forms; other bytes below 0x20 and 0x7F use \xHH. Every other byte,
/// including every byte of a multi-byte UTF-8 sequence, is emitted unchanged.
std::string text_escape(std::string_view text);

/// Inverse of text_escape. Rejects unknown escapes, truncated escapes and any
/// escape that would produce a byte outside the canonical set.
Result<std::string> text_unescape(std::string_view text);

/// Removes leading and trailing ASCII whitespace.
std::string_view trim_ascii(std::string_view text) noexcept;

/// Case-insensitive comparison over ASCII bytes only.
bool ascii_iequals(std::string_view lhs, std::string_view rhs) noexcept;

/// ASCII case folding; bytes outside A-Z/a-z are copied unchanged.
std::string ascii_upper(std::string_view text);
std::string ascii_lower(std::string_view text);

/// Strict unsigned decimal parse: digits only, no sign, no whitespace, no
/// leading zero unless the value is exactly zero (and zero only when allowed).
Result<std::uint64_t> parse_uint64_strict(std::string_view text, std::string_view what,
                                          bool allow_zero);

/// Decimal rendering of an unsigned value.
std::string to_decimal(std::uint64_t value);

}  // namespace dccp::facility_placement_policy

#endif  // DCCP_FACILITY_PLACEMENT_POLICY_TEXT_UTIL_HPP
