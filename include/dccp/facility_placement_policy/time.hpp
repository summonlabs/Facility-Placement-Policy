// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs.

#ifndef DCCP_FACILITY_PLACEMENT_POLICY_TIME_HPP
#define DCCP_FACILITY_PLACEMENT_POLICY_TIME_HPP

#include <compare>
#include <cstdint>
#include <string>
#include <string_view>

#include "dccp/facility_placement_policy/result.hpp"

/// Absolute time and signed durations.
///
/// Instants are UTC with microsecond resolution and are never "now" by default:
/// every API that needs a time takes it from the caller, so an evaluation is a
/// pure function of its inputs and two runs over the same request produce the
/// same verdict. There is no clock call anywhere in the library.
///
/// An instant carries its own "not set" state rather than overloading a value:
/// the Unix epoch is a real and meaningful instant, so it is never the marker for
/// absence. is_set() distinguishes the two. A default-constructed instant is not
/// set, exactly as a default-constructed identifier is empty, and every public
/// entry point that needs a real instant refuses an instant that is not set.
namespace dccp::facility_placement_policy {

/// A signed duration with microsecond resolution.
class Duration {
 public:
  constexpr Duration() noexcept = default;

  static constexpr Duration from_microseconds(std::int64_t micros) noexcept {
    return Duration(micros);
  }
  static Result<Duration> from_milliseconds(std::int64_t millis) noexcept;
  static Result<Duration> from_seconds(std::int64_t seconds) noexcept;
  static Result<Duration> from_minutes(std::int64_t minutes) noexcept;
  static Result<Duration> from_hours(std::int64_t hours) noexcept;
  static Result<Duration> from_days(std::int64_t days) noexcept;

  /// Parses a compound duration: an optional sign followed by one or more
  /// value/unit pairs in descending unit order, for example "-1d2h30m",
  /// "45s" or "250ms". Units are d, h, m, s, ms and us. Values exceed nothing:
  /// an overflowing component is rejected.
  static Result<Duration> parse(std::string_view text);

  static constexpr Duration zero() noexcept { return Duration(0); }

  constexpr std::int64_t microseconds() const noexcept { return micros_; }
  constexpr bool is_zero() const noexcept { return micros_ == 0; }
  constexpr bool is_negative() const noexcept { return micros_ < 0; }

  /// Canonical text: the largest unit that represents the value exactly, for
  /// example "1d", "90m", "45s", "250ms", "7us", "-3h".
  std::string to_string() const;

  friend constexpr bool operator==(const Duration& lhs, const Duration& rhs) noexcept = default;
  friend constexpr auto operator<=>(const Duration& lhs, const Duration& rhs) noexcept = default;

 private:
  explicit constexpr Duration(std::int64_t micros) noexcept : micros_(micros) {}
  std::int64_t micros_ = 0;
};

/// An absolute UTC instant with microsecond resolution.
class Instant {
 public:
  /// Not set. The value is meaningless until it is assigned a set instant.
  constexpr Instant() noexcept = default;

  /// Strict RFC 3339 UTC: "YYYY-MM-DDThh:mm:ss[.ffffff]Z". No offsets other than
  /// Z, no lower-case t or z, no leap second, no surrounding whitespace.
  static Result<Instant> parse(std::string_view text);

  /// Adopts a count of microseconds since 1970-01-01T00:00:00Z, which must fall
  /// inside the representable range.
  static Result<Instant> from_unix_micros(std::int64_t micros) noexcept;

  /// Builds an instant from civil UTC fields, validating the calendar.
  static Result<Instant> from_civil(int year, unsigned month, unsigned day, unsigned hour,
                                    unsigned minute, unsigned second,
                                    unsigned micros) noexcept;

  static constexpr std::int64_t min_unix_micros() noexcept { return -62135596800000000LL; }
  static constexpr std::int64_t max_unix_micros() noexcept { return 253402300799999999LL; }

  /// True when this instant holds a value. Meaningless otherwise.
  constexpr bool is_set() const noexcept { return set_; }

  /// Microseconds since the Unix epoch. Zero when the instant is not set.
  constexpr std::int64_t unix_micros() const noexcept { return micros_; }

  /// Canonical text, always with six fractional digits:
  /// "2026-02-14T09:30:00.000000Z". An instant that is not set renders as
  /// "unset".
  std::string to_string() const;

  friend constexpr bool operator==(const Instant& lhs, const Instant& rhs) noexcept {
    return lhs.set_ == rhs.set_ && (!lhs.set_ || lhs.micros_ == rhs.micros_);
  }

  /// A set instant sorts before every unset one, and set instants order by
  /// time. The ordering is total, which keeps any container that holds instants
  /// deterministic.
  friend constexpr std::strong_ordering operator<=>(const Instant& lhs,
                                                    const Instant& rhs) noexcept {
    if (lhs.set_ != rhs.set_) {
      return lhs.set_ ? std::strong_ordering::less : std::strong_ordering::greater;
    }
    if (!lhs.set_) {
      return std::strong_ordering::equal;
    }
    return lhs.micros_ < rhs.micros_
               ? std::strong_ordering::less
               : (lhs.micros_ > rhs.micros_ ? std::strong_ordering::greater
                                            : std::strong_ordering::equal);
  }

 private:
  explicit constexpr Instant(std::int64_t micros) noexcept : micros_(micros), set_(true) {}
  std::int64_t micros_ = 0;
  bool set_ = false;
};

/// instant + delta, refusing to leave the representable range.
Result<Instant> checked_add(Instant instant, Duration delta) noexcept;

/// later - earlier, refusing to overflow.
Result<Duration> checked_difference(Instant later, Instant earlier) noexcept;

/// Runs the calendar and range self-checks: the representable bounds agree with
/// the civil conversion, and the round trips at the extremes are exact. Not
/// noexcept: it renders instants as text, so it allocates.
bool time_self_test();

}  // namespace dccp::facility_placement_policy

#endif  // DCCP_FACILITY_PLACEMENT_POLICY_TIME_HPP
