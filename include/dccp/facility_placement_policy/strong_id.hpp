// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs.

#ifndef DCCP_FACILITY_PLACEMENT_POLICY_STRONG_ID_HPP
#define DCCP_FACILITY_PLACEMENT_POLICY_STRONG_ID_HPP

#include <compare>
#include <cstddef>
#include <functional>
#include <string>
#include <string_view>
#include <utility>

#include "dccp/facility_placement_policy/limits.hpp"
#include "dccp/facility_placement_policy/result.hpp"

namespace dccp::facility_placement_policy {

/// Identifier syntax (canonical form):
///   - 1..128 bytes;
///   - the first and last byte are ASCII alphanumeric;
///   - interior bytes are ASCII alphanumeric or one of '.', ':', '-'.
///
/// The grammar deliberately excludes whitespace, quoting, path separators,
/// control characters and non-ASCII bytes, so canonical serialization needs no
/// escaping for identities and an identity cannot smuggle a path, a
/// bidirectional control character or a look-alike into durable state.
bool is_valid_identifier_syntax(std::string_view raw) noexcept;

/// Explains the identifier grammar, for diagnostics.
std::string_view identifier_syntax_help() noexcept;

/// Tag types selecting a distinct StrongId instantiation. Unrelated identities
/// are distinct C++ types and cannot be converted into one another by accident.
struct FacilityIdTag {
  static constexpr std::string_view kind_name = "facility";
};
struct SiteIdTag {
  static constexpr std::string_view kind_name = "site";
};
struct RoomIdTag {
  static constexpr std::string_view kind_name = "room";
};
struct RowIdTag {
  static constexpr std::string_view kind_name = "row";
};
struct RackIdTag {
  static constexpr std::string_view kind_name = "rack";
};
struct FailureDomainIdTag {
  static constexpr std::string_view kind_name = "failure-domain";
};
struct JurisdictionIdTag {
  static constexpr std::string_view kind_name = "jurisdiction";
};
struct TenantIdTag {
  static constexpr std::string_view kind_name = "tenant";
};
struct ServiceClassIdTag {
  static constexpr std::string_view kind_name = "service-class";
};
struct PrincipalIdTag {
  static constexpr std::string_view kind_name = "principal";
};
struct PolicyIdTag {
  static constexpr std::string_view kind_name = "policy";
};
struct RuleIdTag {
  static constexpr std::string_view kind_name = "rule";
};
struct EnvelopeIdTag {
  static constexpr std::string_view kind_name = "envelope";
};
struct RequestIdTag {
  static constexpr std::string_view kind_name = "request";
};
struct CandidateIdTag {
  static constexpr std::string_view kind_name = "candidate";
};
struct PlacementIdTag {
  static constexpr std::string_view kind_name = "placement";
};
struct StoreIdTag {
  static constexpr std::string_view kind_name = "store";
};
struct UsageIdTag {
  static constexpr std::string_view kind_name = "usage";
};
struct ExposureIdTag {
  static constexpr std::string_view kind_name = "exposure";
};

/// A validated, strongly typed identifier.
///
/// Construction only succeeds through parse() and from_trusted(); the
/// default-constructed value is empty and exists only so identifiers can live in
/// containers. An empty identifier is never written to durable state and is
/// rejected by every public entry point that requires one.
template <class Tag>
class StrongId {
 public:
  using tag_type = Tag;

  StrongId() noexcept = default;

  /// Parses and validates untrusted text.
  static Result<StrongId> parse(std::string_view raw) {
    if (raw.size() > kMaxIdentifierBytes) {
      return Error(ErrorCode::IdentifierTooLong,
                   "identifier exceeds the maximum length")
          .with_subject(bounded_echo(raw))
          .with_detail("limit=" + std::to_string(kMaxIdentifierBytes) +
                       " actual=" + std::to_string(raw.size()));
    }
    if (!is_valid_identifier_syntax(raw)) {
      return Error(ErrorCode::MalformedIdentifier, std::string(identifier_syntax_help()))
          .with_subject(bounded_echo(raw));
    }
    return StrongId(std::string(raw));
  }

  /// Adopts a value that the caller has already validated.
  ///
  /// This exists for values this library produced itself (parsed canonical
  /// state, identifiers echoed from a validated document). It validates anyway
  /// and reports failure rather than trusting the caller.
  static Result<StrongId> from_trusted(std::string_view value) { return parse(value); }

  bool empty() const noexcept { return value_.empty(); }
  std::string_view value() const noexcept { return value_; }
  const std::string& str() const noexcept { return value_; }

  friend bool operator==(const StrongId& lhs, const StrongId& rhs) noexcept = default;

  /// Ordering is byte-wise over the canonical identifier, so iteration order is
  /// identical on every platform.
  friend std::strong_ordering operator<=>(const StrongId& lhs, const StrongId& rhs) noexcept {
    const int cmp = lhs.value_.compare(rhs.value_);
    return cmp < 0 ? std::strong_ordering::less
                   : (cmp > 0 ? std::strong_ordering::greater : std::strong_ordering::equal);
  }

 private:
  explicit StrongId(std::string value) : value_(std::move(value)) {}

  static std::string bounded_echo(std::string_view raw) {
    constexpr std::size_t kEchoLimit = 64;
    std::string echo(raw.substr(0, kEchoLimit));
    if (raw.size() > kEchoLimit) {
      echo.append("...");
    }
    return echo;
  }

  std::string value_;
};

using FacilityId = StrongId<FacilityIdTag>;
using SiteId = StrongId<SiteIdTag>;
using RoomId = StrongId<RoomIdTag>;
using RowId = StrongId<RowIdTag>;
using RackId = StrongId<RackIdTag>;
using FailureDomainId = StrongId<FailureDomainIdTag>;
using JurisdictionId = StrongId<JurisdictionIdTag>;
using TenantId = StrongId<TenantIdTag>;
using ServiceClassId = StrongId<ServiceClassIdTag>;
using PrincipalId = StrongId<PrincipalIdTag>;
using PolicyId = StrongId<PolicyIdTag>;
using RuleId = StrongId<RuleIdTag>;
using EnvelopeId = StrongId<EnvelopeIdTag>;
using RequestId = StrongId<RequestIdTag>;
using CandidateId = StrongId<CandidateIdTag>;
using PlacementId = StrongId<PlacementIdTag>;
using StoreId = StrongId<StoreIdTag>;
using UsageId = StrongId<UsageIdTag>;
using ExposureId = StrongId<ExposureIdTag>;

/// Renders an identifier as its canonical text.
template <class Tag>
std::string to_string(const StrongId<Tag>& id) {
  return std::string(id.value());
}

}  // namespace dccp::facility_placement_policy

namespace std {

template <class Tag>
struct hash<dccp::facility_placement_policy::StrongId<Tag>> {
  std::size_t operator()(const dccp::facility_placement_policy::StrongId<Tag>& id) const noexcept {
    return std::hash<std::string_view>{}(id.value());
  }
};

}  // namespace std

#endif  // DCCP_FACILITY_PLACEMENT_POLICY_STRONG_ID_HPP
