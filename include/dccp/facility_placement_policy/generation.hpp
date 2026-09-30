// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs.

#ifndef DCCP_FACILITY_PLACEMENT_POLICY_GENERATION_HPP
#define DCCP_FACILITY_PLACEMENT_POLICY_GENERATION_HPP

#include <compare>
#include <cstdint>
#include <string>
#include <string_view>

#include "dccp/facility_placement_policy/result.hpp"

/// Monotonic counters: policy revisions, authority epochs, store sequences and
/// the generations published by adjacent authorities.
///
/// Two rules are encoded in the type rather than left to discipline:
///
///  * a counter is never overloaded. Zero means "no value", exactly as an empty
///    identifier means "no identifier"; a real generation starts at one, so an
///    absent generation can never be mistaken for the first generation;
///  * a counter never wraps. Advancing one is a checked operation that reports
///    ErrorCode::GenerationOverflow instead of silently returning to zero.
namespace dccp::facility_placement_policy {

template <class Tag>
class Counter {
 public:
  using tag_type = Tag;

  /// Absent counter. is_valid() is false and the value is zero.
  constexpr Counter() noexcept = default;

  /// Adopts a value. Zero is not a valid counter value.
  static Result<Counter> from_value(std::uint64_t value) {
    if (value == 0) {
      return Error(ErrorCode::InvalidGeneration,
                   "a counter value of zero means absent and is never a published value");
    }
    return Counter(value);
  }

  /// Strict decimal parse: no sign, no leading zero (except "0", which is
  /// rejected as absent), no surrounding whitespace.
  static Result<Counter> parse(std::string_view text) {
    if (text.empty()) {
      return Error(ErrorCode::MissingField, "counter text is empty");
    }
    if (text.size() > 20) {
      return Error(ErrorCode::NumericOverflow, "counter text is longer than 20 digits")
          .with_subject(std::string(text.substr(0, 32)));
    }
    std::uint64_t value = 0;
    for (const char ch : text) {
      if (ch < '0' || ch > '9') {
        return Error(ErrorCode::MalformedDocument,
                     "counter text must contain decimal digits only")
            .with_subject(std::string(text));
      }
      const std::uint64_t digit = static_cast<std::uint64_t>(ch - '0');
      if (value > (UINT64_MAX - digit) / 10u) {
        return Error(ErrorCode::NumericOverflow, "counter value does not fit in 64 bits")
            .with_subject(std::string(text));
      }
      value = value * 10u + digit;
    }
    if (value == 0) {
      return Error(ErrorCode::InvalidGeneration,
                   "a counter value of zero means absent and is never a published value");
    }
    return Counter(value);
  }

  constexpr bool is_valid() const noexcept { return value_ != 0; }
  constexpr std::uint64_t value() const noexcept { return value_; }

  std::string to_string() const { return std::to_string(value_); }

  /// Next value in the sequence. Reports overflow rather than wrapping.
  Result<Counter> next() const {
    if (!is_valid()) {
      return Error(ErrorCode::InvalidGeneration,
                   "cannot advance an absent counter");
    }
    if (value_ == UINT64_MAX) {
      return Error(ErrorCode::GenerationOverflow,
                   "counter is at the maximum value and must not wrap")
          .with_detail("value=" + std::to_string(value_));
    }
    return Counter(value_ + 1u);
  }

  friend constexpr bool operator==(const Counter& lhs, const Counter& rhs) noexcept = default;

  friend constexpr std::strong_ordering operator<=>(const Counter& lhs,
                                                    const Counter& rhs) noexcept {
    if (lhs.value_ < rhs.value_) {
      return std::strong_ordering::less;
    }
    if (lhs.value_ > rhs.value_) {
      return std::strong_ordering::greater;
    }
    return std::strong_ordering::equal;
  }

 private:
  explicit constexpr Counter(std::uint64_t value) noexcept : value_(value) {}

  std::uint64_t value_ = 0;
};

struct PolicyRevisionTag {
  static constexpr std::string_view kind_name = "policy-revision";
};
struct AuthorityEpochTag {
  static constexpr std::string_view kind_name = "authority-epoch";
};
struct StoreSequenceTag {
  static constexpr std::string_view kind_name = "store-sequence";
};
struct TopologyGenerationTag {
  static constexpr std::string_view kind_name = "topology-generation";
};
struct FailureDomainGenerationTag {
  static constexpr std::string_view kind_name = "failure-domain-generation";
};
struct TenantGenerationTag {
  static constexpr std::string_view kind_name = "tenant-generation";
};
struct ServiceClassGenerationTag {
  static constexpr std::string_view kind_name = "service-class-generation";
};
struct MaintenanceGenerationTag {
  static constexpr std::string_view kind_name = "maintenance-generation";
};
struct OccupancyGenerationTag {
  static constexpr std::string_view kind_name = "occupancy-generation";
};
struct SchemaGenerationTag {
  static constexpr std::string_view kind_name = "schema-generation";
};

using PolicyRevision = Counter<PolicyRevisionTag>;
using AuthorityEpoch = Counter<AuthorityEpochTag>;
using StoreSequence = Counter<StoreSequenceTag>;
using TopologyGeneration = Counter<TopologyGenerationTag>;
using FailureDomainGeneration = Counter<FailureDomainGenerationTag>;
using TenantGeneration = Counter<TenantGenerationTag>;
using ServiceClassGeneration = Counter<ServiceClassGenerationTag>;
using MaintenanceGeneration = Counter<MaintenanceGenerationTag>;
using OccupancyGeneration = Counter<OccupancyGenerationTag>;
using SchemaGeneration = Counter<SchemaGenerationTag>;

/// The later of two counters, used to advance anti-rollback watermarks.
template <class Tag>
Counter<Tag> later_of(const Counter<Tag>& lhs, const Counter<Tag>& rhs) noexcept {
  if (!lhs.is_valid()) {
    return rhs;
  }
  if (!rhs.is_valid()) {
    return lhs;
  }
  return lhs.value() >= rhs.value() ? lhs : rhs;
}

}  // namespace dccp::facility_placement_policy

#endif  // DCCP_FACILITY_PLACEMENT_POLICY_GENERATION_HPP
