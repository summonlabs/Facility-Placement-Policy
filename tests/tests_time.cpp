// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs.

#include <cstdint>
#include <string>

#include "test_framework.hpp"

#include "dccp/facility_placement_policy/time.hpp"

namespace {

using namespace dccp::facility_placement_policy;

/// A non-canonical instant is refused, and the refusal is an argument error
/// rather than a silent normalisation.
void expect_instant_refused(const char* text) {
  const auto parsed = Instant::parse(text);
  FPT_CHECK(!parsed.has_value());
  if (!parsed.has_value()) {
    FPT_CHECK(parsed.error().category() == ErrorCategory::Argument);
  }
}

void expect_duration_refused(const char* text) {
  const auto parsed = Duration::parse(text);
  FPT_CHECK(!parsed.has_value());
  if (!parsed.has_value()) {
    FPT_CHECK(parsed.error().category() == ErrorCategory::Argument);
  }
}

}  // namespace

FPT_TEST(time, an_instant_that_is_not_set_is_not_the_epoch) {
  const Instant unset;
  FPT_CHECK(!unset.is_set());
  FPT_CHECK_EQ(unset.to_string(), std::string("unset"));
  FPT_REQUIRE_OK(Instant::parse("1970-01-01T00:00:00.000000Z"));
  const Instant epoch = Instant::parse("1970-01-01T00:00:00.000000Z").value();
  FPT_CHECK(epoch.is_set());
  FPT_CHECK_EQ(epoch.unix_micros(), std::int64_t(0));
  FPT_CHECK(unset != epoch);
  // A set instant sorts before an unset one, so ordering is total and stable.
  FPT_CHECK(epoch < unset);
}

FPT_TEST(time, canonical_text_round_trips_exactly) {
  const char* samples[] = {
      "0001-01-01T00:00:00.000000Z", "1969-12-31T23:59:59.999999Z",
      "1970-01-01T00:00:00.000000Z", "2000-02-29T12:34:56.789012Z",
      "2026-02-14T09:30:00.000001Z", "9999-12-31T23:59:59.999999Z",
  };
  for (const char* sample : samples) {
    auto parsed = Instant::parse(sample);
    FPT_REQUIRE_OK(parsed);
    FPT_CHECK_EQ(parsed.value().to_string(), std::string(sample));
    auto reparsed = Instant::parse(parsed.value().to_string());
    FPT_REQUIRE_OK(reparsed);
    FPT_CHECK(reparsed.value() == parsed.value());
  }
}

FPT_TEST(time, parsing_refuses_every_non_canonical_form) {
  const char* rejected[] = {
      "",
      "2026-02-14",
      "2026-02-14T09:30:00",
      "2026-02-14T09:30:00z",
      "2026-02-14t09:30:00Z",
      "2026-02-14T09:30:00+01:00",
      "2026-02-14 09:30:00Z",
      " 2026-02-14T09:30:00Z",
      "2026-02-14T09:30:00Z ",
      "2026-02-14T09:30:00.Z",
      "2026-02-14T09:30:00.1234567Z",
      "2026-02-14T09:30:60Z",
      "2026-02-14T24:00:00Z",
      "2026-13-01T00:00:00Z",
      "2026-00-01T00:00:00Z",
      "2026-02-30T00:00:00Z",
      "2025-02-29T00:00:00Z",
      "0000-01-01T00:00:00Z",
      "2026-02-14T09:30:0aZ",
      "2026-02-14T09:30:00Zextra",
  };
  for (const char* text : rejected) {
    expect_instant_refused(text);
  }
  // A leap second is not representable, so it is refused rather than folded.
  expect_instant_refused("2016-12-31T23:59:60Z");
}

FPT_TEST(time, the_representable_range_is_exactly_the_documented_bounds) {
  FPT_REQUIRE_OK(Instant::from_unix_micros(Instant::min_unix_micros()));
  FPT_REQUIRE_OK(Instant::from_unix_micros(Instant::max_unix_micros()));
  FPT_CHECK_EQ(Instant::from_unix_micros(Instant::min_unix_micros()).value().to_string(),
               std::string("0001-01-01T00:00:00.000000Z"));
  FPT_CHECK_EQ(Instant::from_unix_micros(Instant::max_unix_micros()).value().to_string(),
               std::string("9999-12-31T23:59:59.999999Z"));
  FPT_CHECK_ERROR(Instant::from_unix_micros(Instant::min_unix_micros() - 1),
                  ErrorCode::NumericUnderflow);
  FPT_CHECK_ERROR(Instant::from_unix_micros(Instant::max_unix_micros() + 1),
                  ErrorCode::NumericOverflow);
  FPT_CHECK_ERROR(Instant::from_civil(10000, 1, 1, 0, 0, 0, 0), ErrorCode::InvalidArgument);
  FPT_CHECK_ERROR(Instant::from_civil(0, 1, 1, 0, 0, 0, 0), ErrorCode::InvalidArgument);
  FPT_CHECK_ERROR(Instant::from_civil(2026, 2, 29, 0, 0, 0, 0), ErrorCode::InvalidArgument);
  FPT_REQUIRE_OK(Instant::from_civil(2024, 2, 29, 0, 0, 0, 0));
}

FPT_TEST(time, arithmetic_refuses_to_leave_the_representable_range) {
  const auto start = Instant::parse("2026-02-14T09:30:00.000000Z");
  FPT_REQUIRE_OK(start);
  const auto day = Duration::from_days(1);
  FPT_REQUIRE_OK(day);
  const auto later = checked_add(start.value(), day.value());
  FPT_REQUIRE_OK(later);
  FPT_CHECK_EQ(later.value().to_string(), std::string("2026-02-15T09:30:00.000000Z"));

  FPT_CHECK_ERROR(checked_add(start.value(), Duration::from_microseconds(INT64_MAX)),
                  ErrorCode::NumericOverflow);
  FPT_CHECK_ERROR(checked_add(start.value(), Duration::from_microseconds(INT64_MIN)),
                  ErrorCode::NumericUnderflow);
  FPT_CHECK_ERROR(checked_add(Instant{}, day.value()), ErrorCode::MissingField);

  const auto difference = checked_difference(later.value(), start.value());
  FPT_REQUIRE_OK(difference);
  FPT_CHECK_EQ(difference.value().microseconds(), std::int64_t(86400000000));
  FPT_CHECK_ERROR(checked_difference(Instant{}, start.value()), ErrorCode::MissingField);
}

FPT_TEST(time, durations_parse_and_render_canonically) {
  struct Sample {
    const char* text;
    const char* canonical;
  };
  const Sample samples[] = {
      {"0s", "0s"},
      {"1us", "1us"},
      {"999us", "999us"},
      {"1ms", "1ms"},
      {"1000ms", "1s"},
      {"45s", "45s"},
      {"90s", "90s"},
      {"60m", "1h"},
      {"1h30m", "90m"},
      {"1d", "1d"},
      {"2d3h4m5s6ms7us", "183845006007us"},
      {"-1d", "-1d"},
      {"-3h", "-3h"},
  };
  for (const Sample& sample : samples) {
    auto parsed = Duration::parse(sample.text);
    FPT_REQUIRE_OK(parsed);
    FPT_CHECK_EQ(parsed.value().to_string(), std::string(sample.canonical));
    auto reparsed = Duration::parse(parsed.value().to_string());
    FPT_REQUIRE_OK(reparsed);
    FPT_CHECK(reparsed.value() == parsed.value());
  }
}

FPT_TEST(time, duration_parsing_refuses_malformed_and_overflowing_forms) {
  const char* rejected[] = {
      "",       "-",      "1",      "s",       "1x",     "1s1s",   "1m1h",
      " 1s",    "1s ",    "1 s",    "1S",      "1us1ms", "1.5s",   "+1s",
      "1d2d",   "1ms1us1s", "1h1d",
  };
  for (const char* text : rejected) {
    expect_duration_refused(text);
  }
  FPT_CHECK_ERROR(Duration::parse("999999999999999999999d"), ErrorCode::NumericOverflow);
  FPT_CHECK_ERROR(Duration::parse("106751992d"), ErrorCode::NumericOverflow);
  // The smallest representable duration renders and parses back exactly.
  FPT_CHECK_EQ(Duration::from_microseconds(INT64_MIN).to_string(),
               std::string("-9223372036854775808us"));
  auto smallest = Duration::parse(Duration::from_microseconds(INT64_MIN).to_string());
  FPT_REQUIRE_OK(smallest);
  FPT_CHECK_EQ(smallest.value().microseconds(), std::int64_t(INT64_MIN));
}

FPT_TEST(time, scaled_constructors_refuse_to_wrap) {
  FPT_CHECK_ERROR(Duration::from_days(INT64_MAX), ErrorCode::NumericOverflow);
  FPT_CHECK_ERROR(Duration::from_seconds(INT64_MAX), ErrorCode::NumericOverflow);
  FPT_CHECK_ERROR(Duration::from_milliseconds(INT64_MIN), ErrorCode::NumericOverflow);
  FPT_REQUIRE_OK(Duration::from_seconds(1));
  FPT_CHECK_EQ(Duration::from_seconds(1).value().microseconds(), std::int64_t(1000000));
  FPT_CHECK(Duration::from_seconds(-1).value().is_negative());
}

FPT_TEST(time, the_calendar_self_check_passes) { FPT_CHECK(time_self_test()); }
