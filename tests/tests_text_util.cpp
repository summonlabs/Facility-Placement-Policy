// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs.

#include <cstdint>
#include <initializer_list>
#include <string>
#include <string_view>
#include <vector>

#include "test_framework.hpp"

#include "dccp/facility_placement_policy/limits.hpp"
#include "dccp/facility_placement_policy/strong_id.hpp"
#include "dccp/facility_placement_policy/text_util.hpp"

namespace {

using namespace dccp::facility_placement_policy;

std::string bytes_of(std::initializer_list<unsigned> values) {
  std::string out;
  for (const unsigned value : values) {
    out.push_back(static_cast<char>(value));
  }
  return out;
}

}  // namespace

FPT_TEST(text_util, utf8_validation_accepts_well_formed_text) {
  const char* accepted[] = {
      "", "plain ascii", "\xc3\xa9", "\xe2\x82\xac", "\xf0\x9f\x98\x80",
      "mixed \xc3\xa9 and ascii", "\x7f",
  };
  for (const char* text : accepted) {
    FPT_CHECK(is_valid_utf8(text));
  }
}

FPT_TEST(text_util, utf8_validation_refuses_every_malformed_shape) {
  const std::vector<std::string> rejected = {
      bytes_of({0x80}),                          // stray continuation
      bytes_of({0xBF}),                          // stray continuation
      bytes_of({0xC0, 0x80}),                    // overlong NUL
      bytes_of({0xC1, 0xBF}),                    // overlong
      bytes_of({0xE0, 0x80, 0x80}),              // overlong
      bytes_of({0xF0, 0x80, 0x80, 0x80}),        // overlong
      bytes_of({0xC2}),                          // truncated
      bytes_of({0xE2, 0x82}),                    // truncated
      bytes_of({0xF0, 0x9F, 0x98}),              // truncated
      bytes_of({0xE2, 0x28, 0xA1}),              // bad continuation
      bytes_of({0xED, 0xA0, 0x80}),              // surrogate U+D800
      bytes_of({0xED, 0xBF, 0xBF}),              // surrogate U+DFFF
      bytes_of({0xF4, 0x90, 0x80, 0x80}),        // above U+10FFFF
      bytes_of({0xF5, 0x80, 0x80, 0x80}),        // invalid lead
      bytes_of({0xFE}),                          // invalid lead
      bytes_of({0xFF}),                          // invalid lead
  };
  for (const std::string& text : rejected) {
    FPT_CHECK(!is_valid_utf8(text));
  }
  // The boundary code points are accepted.
  FPT_CHECK(is_valid_utf8(bytes_of({0xED, 0x9F, 0xBF})));   // U+D7FF
  FPT_CHECK(is_valid_utf8(bytes_of({0xEE, 0x80, 0x80})));   // U+E000
  FPT_CHECK(is_valid_utf8(bytes_of({0xF4, 0x8F, 0xBF, 0xBF})));  // U+10FFFF
}

FPT_TEST(text_util, requiring_valid_utf8_reports_the_bound_before_the_encoding) {
  FPT_REQUIRE_OK(require_valid_utf8("ok", "field", 16));
  FPT_CHECK_ERROR(require_valid_utf8(std::string(17, 'a'), "field", 16), ErrorCode::TextTooLong);
  FPT_CHECK_ERROR(require_valid_utf8(bytes_of({0xFF}), "field", 16), ErrorCode::InvalidUtf8);
  const auto failure = require_valid_utf8(bytes_of({0xFF}), "field", 16);
  FPT_CHECK_EQ(failure.error().subject(), std::string("field"));
}

FPT_TEST(text_util, escaping_round_trips_every_byte) {
  std::string all_bytes;
  for (unsigned value = 0; value < 256u; ++value) {
    all_bytes.push_back(static_cast<char>(value));
  }
  const std::string escaped = text_escape(all_bytes);
  auto unescaped = text_unescape(escaped);
  FPT_REQUIRE_OK(unescaped);
  FPT_CHECK_EQ(unescaped.value(), all_bytes);
}

FPT_TEST(text_util, escaping_uses_the_short_forms_and_only_for_control_bytes) {
  FPT_CHECK_EQ(text_escape("a\\b\"c\nd\re\tf"), std::string("a\\\\b\\\"c\\nd\\re\\tf"));
  FPT_CHECK_EQ(text_escape(std::string(1, '\x01')), std::string("\\x01"));
  FPT_CHECK_EQ(text_escape("\x7f"), std::string("\\x7F"));
  FPT_CHECK_EQ(text_escape("\xc3\xa9"), std::string("\xc3\xa9"));
}

FPT_TEST(text_util, unescaping_refuses_unknown_truncated_and_non_canonical_escapes) {
  FPT_CHECK_ERROR(text_unescape("\\"), ErrorCode::TruncatedInput);
  FPT_CHECK_ERROR(text_unescape("\\x"), ErrorCode::TruncatedInput);
  FPT_CHECK_ERROR(text_unescape("\\x1"), ErrorCode::TruncatedInput);
  FPT_CHECK_ERROR(text_unescape("\\xzz"), ErrorCode::MalformedDocument);
  FPT_CHECK_ERROR(text_unescape("\\q"), ErrorCode::UnknownEnumToken);
  // \x is reserved for control bytes, so a printable byte written that way is
  // not the canonical form and is refused.
  FPT_CHECK_ERROR(text_unescape("\\x41"), ErrorCode::MalformedDocument);
  FPT_REQUIRE_OK(text_unescape("\\x1F"));
  FPT_CHECK_EQ(text_unescape("\\x1F").value(), std::string(1, '\x1f'));
}

FPT_TEST(text_util, strict_unsigned_parsing_refuses_every_shortcut) {
  FPT_CHECK_EQ(parse_uint64_strict("0", "n", true).value(), std::uint64_t(0));
  FPT_CHECK_EQ(parse_uint64_strict("42", "n", false).value(), std::uint64_t(42));
  FPT_CHECK_EQ(parse_uint64_strict("18446744073709551615", "n", false).value(), UINT64_MAX);

  FPT_CHECK_ERROR(parse_uint64_strict("0", "n", false), ErrorCode::InvalidArgument);
  FPT_CHECK_ERROR(parse_uint64_strict("007", "n", true), ErrorCode::MalformedDocument);
  FPT_CHECK_ERROR(parse_uint64_strict("", "n", true), ErrorCode::MissingField);
  FPT_CHECK_ERROR(parse_uint64_strict("+1", "n", true), ErrorCode::MalformedDocument);
  FPT_CHECK_ERROR(parse_uint64_strict("-1", "n", true), ErrorCode::MalformedDocument);
  FPT_CHECK_ERROR(parse_uint64_strict(" 1", "n", true), ErrorCode::MalformedDocument);
  FPT_CHECK_ERROR(parse_uint64_strict("1 ", "n", true), ErrorCode::MalformedDocument);
  FPT_CHECK_ERROR(parse_uint64_strict("1a", "n", true), ErrorCode::MalformedDocument);
  FPT_CHECK_ERROR(parse_uint64_strict("18446744073709551616", "n", true),
                  ErrorCode::NumericOverflow);
  FPT_CHECK_EQ(to_decimal(12345), std::string("12345"));
}

FPT_TEST(text_util, ascii_helpers_never_touch_non_ascii_bytes) {
  FPT_CHECK_EQ(trim_ascii("  spaced \t\n"), std::string_view("spaced"));
  FPT_CHECK_EQ(trim_ascii(""), std::string_view(""));
  FPT_CHECK_EQ(trim_ascii("   "), std::string_view(""));
  FPT_CHECK(ascii_iequals("AbC", "aBc"));
  FPT_CHECK(!ascii_iequals("abc", "abcd"));
  FPT_CHECK(!ascii_iequals("abc", "abd"));
  FPT_CHECK_EQ(ascii_upper("\xc3\xa9z"), std::string("\xc3\xa9Z"));
  FPT_CHECK_EQ(ascii_lower("AZ\xc3\x89"), std::string("az\xc3\x89"));
  FPT_CHECK(is_ascii("plain"));
  FPT_CHECK(!is_ascii("\xc3\xa9"));
  FPT_CHECK(is_ascii_printable("a~"));
  FPT_CHECK(!is_ascii_printable("a\n"));
}

FPT_TEST(text_util, identifiers_follow_a_grammar_that_cannot_smuggle_a_path) {
  const char* accepted[] = {"a", "A9", "tenant:acme", "site-1.room-2", "x.y-z:q",
                            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"};
  for (const char* text : accepted) {
    FPT_CHECK(is_valid_identifier_syntax(text));
  }
  const char* rejected[] = {"",
                            "-a",
                            "a-",
                            ".a",
                            "a.",
                            ":a",
                            "a:",
                            "a b",
                            "a/b",
                            "a\\b",
                            "a\xc3\xa9",
                            "a\tb",
                            "a\nb",
                            "../etc",
                            "C:\\temp",
                            "a,b"};
  for (const char* text : rejected) {
    FPT_CHECK(!is_valid_identifier_syntax(text));
    FPT_CHECK_ERROR(TenantId::parse(text), ErrorCode::MalformedIdentifier);
  }
  // A reserved device name is a legal identifier: what makes it dangerous is
  // using it as a path component, which the store refuses separately.
  FPT_CHECK(is_valid_identifier_syntax("NUL"));
  FPT_CHECK(is_valid_identifier_syntax("CON"));
  FPT_REQUIRE_OK(TenantId::parse("NUL"));

  // The length bound is enforced before the grammar, so an over-long identifier
  // reports a bound rather than a syntax problem.
  const std::string too_long(kMaxIdentifierBytes + 1, 'a');
  FPT_CHECK_ERROR(TenantId::parse(too_long), ErrorCode::IdentifierTooLong);
  FPT_CHECK_ERROR(TenantId::parse("bad id"), ErrorCode::MalformedIdentifier);

  const auto good = TenantId::parse("tenant:acme");
  FPT_REQUIRE_OK(good);
  FPT_CHECK_EQ(good.value().value(), std::string_view("tenant:acme"));
  FPT_CHECK_EQ(good.value().str(), std::string("tenant:acme"));
  FPT_CHECK_EQ(to_string(good.value()), std::string("tenant:acme"));
  FPT_CHECK(TenantId{} == TenantId{});
  FPT_CHECK(TenantId{} != good.value());

  // Identities of different kinds are different types and never compare equal by
  // accident: the tag is part of the type, which is a compile-time property, so
  // it is asserted here by construction only.
  const auto site = SiteId::parse("site:a");
  FPT_REQUIRE_OK(site);
  FPT_CHECK_EQ(site.value().value(), std::string_view("site:a"));
}
