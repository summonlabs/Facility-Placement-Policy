// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs.

#include "dccp/facility_placement_policy/time.hpp"

#include <cstdint>
#include <string>

namespace dccp::facility_placement_policy {
namespace {

constexpr std::int64_t kMicrosPerMilli = 1000;
constexpr std::int64_t kMicrosPerSecond = 1000000;
constexpr std::int64_t kMicrosPerMinute = 60 * kMicrosPerSecond;
constexpr std::int64_t kMicrosPerHour = 60 * kMicrosPerMinute;
constexpr std::int64_t kMicrosPerDay = 24 * kMicrosPerHour;

/// Days from 1970-01-01 to the given proleptic Gregorian civil date.
/// Howard Hinnant's algorithm; exact for the whole representable range and free
/// of any dependence on the host C library or the host time zone.
constexpr std::int64_t days_from_civil(std::int64_t year, unsigned month, unsigned day) noexcept {
  const std::int64_t adjusted_year = year - (month <= 2u ? 1 : 0);
  const std::int64_t era = (adjusted_year >= 0 ? adjusted_year : adjusted_year - 399) / 400;
  const unsigned year_of_era = static_cast<unsigned>(adjusted_year - era * 400);
  const unsigned day_of_year =
      (153u * (month + (month > 2u ? static_cast<unsigned>(-3) : 9u)) + 2u) / 5u + day - 1u;
  const unsigned day_of_era =
      year_of_era * 365u + year_of_era / 4u - year_of_era / 100u + day_of_year;
  return era * 146097 + static_cast<std::int64_t>(day_of_era) - 719468;
}

constexpr void civil_from_days(std::int64_t days, std::int64_t& year, unsigned& month,
                               unsigned& day) noexcept {
  const std::int64_t shifted = days + 719468;
  const std::int64_t era = (shifted >= 0 ? shifted : shifted - 146096) / 146097;
  const unsigned day_of_era = static_cast<unsigned>(shifted - era * 146097);
  const unsigned year_of_era =
      (day_of_era - day_of_era / 1460u + day_of_era / 36524u - day_of_era / 146096u) / 365u;
  const std::int64_t base_year = static_cast<std::int64_t>(year_of_era) + era * 400;
  const unsigned day_of_year =
      day_of_era - (365u * year_of_era + year_of_era / 4u - year_of_era / 100u);
  const unsigned month_prime = (5u * day_of_year + 2u) / 153u;
  day = day_of_year - (153u * month_prime + 2u) / 5u + 1u;
  month = month_prime + (month_prime < 10u ? 3u : static_cast<unsigned>(-9));
  year = base_year + (month <= 2u ? 1 : 0);
}

constexpr bool is_leap_year(std::int64_t year) noexcept {
  return (year % 4 == 0 && year % 100 != 0) || year % 400 == 0;
}

constexpr unsigned days_in_month(std::int64_t year, unsigned month) noexcept {
  switch (month) {
    case 1u:
    case 3u:
    case 5u:
    case 7u:
    case 8u:
    case 10u:
    case 12u:
      return 31u;
    case 4u:
    case 6u:
    case 9u:
    case 11u:
      return 30u;
    case 2u:
      return is_leap_year(year) ? 29u : 28u;
    default:
      return 0u;
  }
}

void append_two_digits(std::string& out, unsigned value) {
  out.push_back(static_cast<char>('0' + (value / 10u) % 10u));
  out.push_back(static_cast<char>('0' + value % 10u));
}

void append_four_digits(std::string& out, unsigned value) {
  out.push_back(static_cast<char>('0' + (value / 1000u) % 10u));
  out.push_back(static_cast<char>('0' + (value / 100u) % 10u));
  out.push_back(static_cast<char>('0' + (value / 10u) % 10u));
  out.push_back(static_cast<char>('0' + value % 10u));
}

void append_six_digits(std::string& out, unsigned value) {
  out.push_back(static_cast<char>('0' + (value / 100000u) % 10u));
  out.push_back(static_cast<char>('0' + (value / 10000u) % 10u));
  out.push_back(static_cast<char>('0' + (value / 1000u) % 10u));
  out.push_back(static_cast<char>('0' + (value / 100u) % 10u));
  out.push_back(static_cast<char>('0' + (value / 10u) % 10u));
  out.push_back(static_cast<char>('0' + value % 10u));
}

Result<std::int64_t> checked_multiply(std::int64_t value, std::int64_t factor,
                                      std::string_view unit) {
  if (value > INT64_MAX / factor || value < INT64_MIN / factor) {
    return Error(ErrorCode::NumericOverflow, "duration component does not fit in 64 bits")
        .with_detail(std::string(unit));
  }
  return value * factor;
}

/// Reads the magnitude of one component. The value is unsigned because the
/// magnitude of INT64_MIN is one greater than INT64_MAX; the caller applies the
/// bound, which is what lets the smallest representable duration round trip.
Result<std::uint64_t> parse_digits(std::string_view text, std::size_t& offset) {
  const std::size_t start = offset;
  std::uint64_t value = 0;
  while (offset < text.size() && text[offset] >= '0' && text[offset] <= '9') {
    if (value > (UINT64_MAX - static_cast<std::uint64_t>(text[offset] - '0')) / 10u) {
      return Error(ErrorCode::NumericOverflow, "duration component does not fit in 64 bits")
          .with_subject(std::string(text));
    }
    value = value * 10u + static_cast<std::uint64_t>(text[offset] - '0');
    ++offset;
  }
  if (offset == start) {
    return Error(ErrorCode::MalformedDocument, "a duration component needs a value")
        .with_subject(std::string(text));
  }
  return value;
}

}  // namespace

Result<Duration> Duration::from_milliseconds(std::int64_t millis) noexcept {
  const auto scaled = checked_multiply(millis, kMicrosPerMilli, "ms");
  if (!scaled.has_value()) {
    return scaled.error();
  }
  return Duration(scaled.value());
}

Result<Duration> Duration::from_seconds(std::int64_t seconds) noexcept {
  const auto scaled = checked_multiply(seconds, kMicrosPerSecond, "s");
  if (!scaled.has_value()) {
    return scaled.error();
  }
  return Duration(scaled.value());
}

Result<Duration> Duration::from_minutes(std::int64_t minutes) noexcept {
  const auto scaled = checked_multiply(minutes, kMicrosPerMinute, "m");
  if (!scaled.has_value()) {
    return scaled.error();
  }
  return Duration(scaled.value());
}

Result<Duration> Duration::from_hours(std::int64_t hours) noexcept {
  const auto scaled = checked_multiply(hours, kMicrosPerHour, "h");
  if (!scaled.has_value()) {
    return scaled.error();
  }
  return Duration(scaled.value());
}

Result<Duration> Duration::from_days(std::int64_t days) noexcept {
  const auto scaled = checked_multiply(days, kMicrosPerDay, "d");
  if (!scaled.has_value()) {
    return scaled.error();
  }
  return Duration(scaled.value());
}

Result<Duration> Duration::parse(std::string_view text) {
  if (text.empty()) {
    return Error(ErrorCode::MissingField, "duration text is empty");
  }
  std::size_t offset = 0;
  bool negative = false;
  if (text[offset] == '-') {
    negative = true;
    ++offset;
  }
  if (offset == text.size()) {
    return Error(ErrorCode::MalformedDocument, "duration text has a sign but no value")
        .with_subject(std::string(text));
  }

  std::uint64_t total = 0;
  const std::uint64_t limit =
      negative ? static_cast<std::uint64_t>(INT64_MAX) + 1u : static_cast<std::uint64_t>(INT64_MAX);
  int last_unit = -1;

  while (offset < text.size()) {
    const auto magnitude = parse_digits(text, offset);
    if (!magnitude.has_value()) {
      return magnitude.error();
    }
    if (offset >= text.size()) {
      return Error(ErrorCode::MalformedDocument, "duration component is missing its unit")
          .with_subject(std::string(text));
    }

    int unit = -1;
    std::uint64_t factor = 0;
    if (text[offset] == 'd') {
      unit = 0;
      factor = static_cast<std::uint64_t>(kMicrosPerDay);
      ++offset;
    } else if (text[offset] == 'h') {
      unit = 1;
      factor = static_cast<std::uint64_t>(kMicrosPerHour);
      ++offset;
    } else if (text[offset] == 'm') {
      ++offset;
      if (offset < text.size() && text[offset] == 's') {
        unit = 4;
        factor = static_cast<std::uint64_t>(kMicrosPerMilli);
        ++offset;
      } else {
        unit = 2;
        factor = static_cast<std::uint64_t>(kMicrosPerMinute);
      }
    } else if (text[offset] == 's') {
      unit = 3;
      factor = static_cast<std::uint64_t>(kMicrosPerSecond);
      ++offset;
    } else if (text[offset] == 'u') {
      ++offset;
      if (offset >= text.size() || text[offset] != 's') {
        return Error(ErrorCode::UnknownEnumToken,
                     "duration unit must be one of d, h, m, s, ms, us")
            .with_subject(std::string(text));
      }
      ++offset;
      unit = 5;
      factor = 1u;
    } else {
      return Error(ErrorCode::UnknownEnumToken,
                   "duration unit must be one of d, h, m, s, ms, us")
          .with_subject(std::string(text));
    }

    if (unit <= last_unit) {
      return Error(ErrorCode::MalformedDocument,
                   "duration units must appear at most once, in descending order")
          .with_subject(std::string(text));
    }
    last_unit = unit;

    const std::uint64_t value = magnitude.value();
    if (value > (limit - total) / factor) {
      return Error(ErrorCode::NumericOverflow, "duration does not fit in 64 bits")
          .with_subject(std::string(text));
    }
    total += value * factor;
  }

  if (negative) {
    if (total == static_cast<std::uint64_t>(INT64_MAX) + 1u) {
      return Duration(INT64_MIN);
    }
    return Duration(-static_cast<std::int64_t>(total));
  }
  return Duration(static_cast<std::int64_t>(total));
}

std::string Duration::to_string() const {
  if (micros_ == 0) {
    return "0s";
  }
  std::string out;
  std::uint64_t magnitude = 0;
  if (micros_ < 0) {
    out.push_back('-');
    // INT64_MIN has no positive counterpart, so the magnitude is formed in
    // unsigned arithmetic where the negation is exact.
    magnitude = static_cast<std::uint64_t>(0) - static_cast<std::uint64_t>(micros_);
  } else {
    magnitude = static_cast<std::uint64_t>(micros_);
  }
  struct Unit {
    std::uint64_t micros;
    const char* suffix;
  };
  static constexpr Unit kUnits[] = {{static_cast<std::uint64_t>(kMicrosPerDay), "d"},
                                    {static_cast<std::uint64_t>(kMicrosPerHour), "h"},
                                    {static_cast<std::uint64_t>(kMicrosPerMinute), "m"},
                                    {static_cast<std::uint64_t>(kMicrosPerSecond), "s"},
                                    {static_cast<std::uint64_t>(kMicrosPerMilli), "ms"},
                                    {1u, "us"}};
  for (const Unit& unit : kUnits) {
    if (magnitude % unit.micros == 0) {
      out.append(std::to_string(magnitude / unit.micros));
      out.append(unit.suffix);
      return out;
    }
  }
  out.append(std::to_string(magnitude));
  out.append("us");
  return out;
}

Result<Instant> Instant::from_unix_micros(std::int64_t micros) noexcept {
  if (micros < min_unix_micros()) {
    return Error(ErrorCode::NumericUnderflow,
                 "instant is earlier than 0001-01-01T00:00:00Z, the earliest representable one")
        .with_detail("unix-micros=" + std::to_string(micros));
  }
  if (micros > max_unix_micros()) {
    return Error(ErrorCode::NumericOverflow,
                 "instant is later than 9999-12-31T23:59:59.999999Z, the latest representable one")
        .with_detail("unix-micros=" + std::to_string(micros));
  }
  return Instant(micros);
}

Result<Instant> Instant::from_civil(int year, unsigned month, unsigned day, unsigned hour,
                                    unsigned minute, unsigned second,
                                    unsigned micros) noexcept {
  if (year < 1 || year > 9999) {
    return Error(ErrorCode::InvalidArgument, "year must be in 1..9999")
        .with_detail("year=" + std::to_string(year));
  }
  if (month < 1u || month > 12u) {
    return Error(ErrorCode::InvalidArgument, "month must be in 1..12")
        .with_detail("month=" + std::to_string(month));
  }
  const std::int64_t signed_year = year;
  if (day < 1u || day > days_in_month(signed_year, month)) {
    return Error(ErrorCode::InvalidArgument, "day is outside the month")
        .with_detail("month=" + std::to_string(month) + " day=" + std::to_string(day));
  }
  if (hour > 23u || minute > 59u || second > 59u || micros > 999999u) {
    return Error(ErrorCode::InvalidArgument,
                 "time of day is out of range (hour 0..23, minute 0..59, second 0..59, "
                 "microsecond 0..999999)");
  }
  const std::int64_t days = days_from_civil(signed_year, month, day);
  const std::int64_t micros_of_day = static_cast<std::int64_t>(hour) * kMicrosPerHour +
                                     static_cast<std::int64_t>(minute) * kMicrosPerMinute +
                                     static_cast<std::int64_t>(second) * kMicrosPerSecond +
                                     static_cast<std::int64_t>(micros);
  const std::int64_t total = days * kMicrosPerDay + micros_of_day;
  if (total < min_unix_micros() || total > max_unix_micros()) {
    return Error(ErrorCode::NumericOverflow, "instant is outside the representable range")
        .with_detail("unix-micros=" + std::to_string(total));
  }
  return Instant(total);
}

Result<Instant> Instant::parse(std::string_view text) {
  const auto digits_at = [&text](std::size_t offset, std::size_t count,
                                 unsigned& out) -> bool {
    unsigned value = 0;
    for (std::size_t index = 0; index < count; ++index) {
      const char ch = text[offset + index];
      if (ch < '0' || ch > '9') {
        return false;
      }
      value = value * 10u + static_cast<unsigned>(ch - '0');
    }
    out = value;
    return true;
  };

  if (text.size() < 20) {
    return Error(ErrorCode::MalformedDocument,
                 "an instant is at least YYYY-MM-DDThh:mm:ssZ")
        .with_subject(std::string(text.substr(0, 64)));
  }
  if (text[4] != '-' || text[7] != '-' || text[10] != 'T' || text[13] != ':' ||
      text[16] != ':') {
    return Error(ErrorCode::MalformedDocument,
                 "an instant must have the shape YYYY-MM-DDThh:mm:ss[.ffffff]Z")
        .with_subject(std::string(text.substr(0, 64)));
  }

  unsigned year = 0;
  unsigned month = 0;
  unsigned day = 0;
  unsigned hour = 0;
  unsigned minute = 0;
  unsigned second = 0;
  unsigned micros = 0;
  if (!digits_at(0, 4, year) || !digits_at(5, 2, month) || !digits_at(8, 2, day) ||
      !digits_at(11, 2, hour) || !digits_at(14, 2, minute) || !digits_at(17, 2, second)) {
    return Error(ErrorCode::MalformedDocument,
                 "an instant must have decimal digits in every date and time field")
        .with_subject(std::string(text.substr(0, 64)));
  }

  std::size_t offset = 19;
  if (offset < text.size() && text[offset] == '.') {
    ++offset;
    const std::size_t fraction_start = offset;
    unsigned fraction = 0;
    while (offset < text.size() && text[offset] >= '0' && text[offset] <= '9') {
      fraction = fraction * 10u + static_cast<unsigned>(text[offset] - '0');
      ++offset;
    }
    const std::size_t fraction_digits = offset - fraction_start;
    if (fraction_digits == 0 || fraction_digits > 6) {
      return Error(ErrorCode::MalformedDocument,
                   "a fractional second has between 1 and 6 digits")
          .with_subject(std::string(text.substr(0, 64)));
    }
    for (std::size_t index = fraction_digits; index < 6; ++index) {
      fraction *= 10u;
    }
    micros = fraction;
  }

  if (offset >= text.size() || text[offset] != 'Z') {
    return Error(ErrorCode::MalformedDocument,
                 "an instant must end with an upper-case Z (UTC offset zero); no other "
                 "offset is accepted")
        .with_subject(std::string(text.substr(0, 64)));
  }
  ++offset;
  if (offset != text.size()) {
    return Error(ErrorCode::TrailingContent, "unexpected content after the instant")
        .with_subject(std::string(text.substr(0, 96)));
  }

  return from_civil(static_cast<int>(year), month, day, hour, minute, second, micros);
}

std::string Instant::to_string() const {
  if (!set_) {
    return "unset";
  }
  // Floor division, not truncation: an instant before 1970 must borrow a day
  // when its remainder is negative, or it renders one day late.
  std::int64_t days = micros_ / kMicrosPerDay;
  std::int64_t micros_of_day = micros_ % kMicrosPerDay;
  if (micros_of_day < 0) {
    micros_of_day += kMicrosPerDay;
    --days;
  }
  std::int64_t year = 1970;
  unsigned month = 1;
  unsigned day = 1;
  civil_from_days(days, year, month, day);

  const unsigned hour = static_cast<unsigned>(micros_of_day / kMicrosPerHour);
  const unsigned minute = static_cast<unsigned>((micros_of_day / kMicrosPerMinute) % 60);
  const unsigned second = static_cast<unsigned>((micros_of_day / kMicrosPerSecond) % 60);
  const unsigned micros = static_cast<unsigned>(micros_of_day % kMicrosPerSecond);

  std::string out;
  out.reserve(27);
  append_four_digits(out, static_cast<unsigned>(year));
  out.push_back('-');
  append_two_digits(out, month);
  out.push_back('-');
  append_two_digits(out, day);
  out.push_back('T');
  append_two_digits(out, hour);
  out.push_back(':');
  append_two_digits(out, minute);
  out.push_back(':');
  append_two_digits(out, second);
  out.push_back('.');
  append_six_digits(out, micros);
  out.push_back('Z');
  return out;
}

Result<Instant> checked_add(Instant instant, Duration delta) noexcept {
  if (!instant.is_set()) {
    return Error(ErrorCode::MissingField, "cannot add a duration to an instant that is not set");
  }
  const std::int64_t base = instant.unix_micros();
  const std::int64_t step = delta.microseconds();
  // Both operands are already inside the representable range, so the two
  // comparisons below cannot overflow even when the delta is INT64_MAX or
  // INT64_MIN, which is exactly the hostile case that has to be rejected.
  if (step > 0 && step > Instant::max_unix_micros() - base) {
    return Error(ErrorCode::NumericOverflow, "instant addition leaves the representable range")
        .with_detail("base=" + std::to_string(base) + " delta-us=" + std::to_string(step));
  }
  if (step < 0 && step < Instant::min_unix_micros() - base) {
    return Error(ErrorCode::NumericUnderflow, "instant subtraction leaves the representable range")
        .with_detail("base=" + std::to_string(base) + " delta-us=" + std::to_string(step));
  }
  return Instant::from_unix_micros(base + step);
}

Result<Duration> checked_difference(Instant later, Instant earlier) noexcept {
  if (!later.is_set() || !earlier.is_set()) {
    return Error(ErrorCode::MissingField,
                 "cannot subtract instants when either of them is not set");
  }
  // The representable range is far narrower than 64 bits, so the difference of
  // two representable instants always fits.
  return Duration::from_microseconds(later.unix_micros() - earlier.unix_micros());
}

bool time_self_test() {
  const auto start_probe = []() { return Instant::from_civil(1970, 1, 1, 0, 0, 0, 0).value(); };
  const auto min_instant = Instant::from_unix_micros(Instant::min_unix_micros());
  const auto max_instant = Instant::from_unix_micros(Instant::max_unix_micros());
  if (!min_instant.has_value() || !max_instant.has_value()) {
    return false;
  }
  if (min_instant.value().to_string() != "0001-01-01T00:00:00.000000Z") {
    return false;
  }
  if (max_instant.value().to_string() != "9999-12-31T23:59:59.999999Z") {
    return false;
  }
  const auto civil_min = Instant::from_civil(1, 1, 1, 0, 0, 0, 0);
  const auto civil_max = Instant::from_civil(9999, 12, 31, 23, 59, 59, 999999);
  if (!civil_min.has_value() || civil_min.value() != min_instant.value()) {
    return false;
  }
  if (!civil_max.has_value() || civil_max.value() != max_instant.value()) {
    return false;
  }

  // Every day from 1970-01-01 to 2100-01-01 must round trip exactly, which
  // exercises the leap year rules in both directions.
  // Every instant from the earliest representable one must render and parse
  // back exactly, including the whole pre-epoch range.
  {
    Instant cursor = min_instant.value();
    const auto step = Duration::from_hours(7).value();
    for (int index = 0; index < 4000; ++index) {
      const std::string text = cursor.to_string();
      const auto reparsed = Instant::parse(text);
      if (!reparsed.has_value() || reparsed.value() != cursor) {
        return false;
      }
      const auto next = checked_add(cursor, step);
      if (!next.has_value()) {
        return false;
      }
      cursor = next.value();
    }
    Instant backwards = start_probe();
    const Duration step_back = Duration::from_microseconds(-1);
    for (int index = 0; index < 5000; ++index) {
      const auto previous = checked_add(backwards, step_back);
      if (!previous.has_value()) {
        return false;
      }
      backwards = previous.value();
      const auto reparsed = Instant::parse(backwards.to_string());
      if (!reparsed.has_value() || reparsed.value() != backwards) {
        return false;
      }
    }
    if (backwards.to_string() != "1969-12-31T23:59:59.995000Z") {
      return false;
    }
  }

  const auto start = Instant::from_civil(1970, 1, 1, 0, 0, 0, 0);
  if (!start.has_value()) {
    return false;
  }
  const auto day = Duration::from_days(1).value();
  Instant cursor = start.value();
  for (int index = 0; index < 47482; ++index) {
    const std::string text = cursor.to_string();
    const auto reparsed = Instant::parse(text);
    if (!reparsed.has_value() || reparsed.value() != cursor) {
      return false;
    }
    const auto next = checked_add(cursor, day);
    if (!next.has_value()) {
      return false;
    }
    cursor = next.value();
  }
  if (cursor.to_string() != "2100-01-01T00:00:00.000000Z") {
    return false;
  }
  return true;
}

}  // namespace dccp::facility_placement_policy
