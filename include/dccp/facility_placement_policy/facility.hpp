// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs.

#ifndef DCCP_FACILITY_PLACEMENT_POLICY_FACILITY_HPP
#define DCCP_FACILITY_PLACEMENT_POLICY_FACILITY_HPP

#include <array>
#include <compare>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <variant>
#include <vector>

#include "dccp/facility_placement_policy/generation.hpp"
#include "dccp/facility_placement_policy/result.hpp"
#include "dccp/facility_placement_policy/strong_id.hpp"
#include "dccp/facility_placement_policy/time.hpp"

/// Facility facts, occupancy facts and maintenance facts, as this runtime
/// consumes them.
///
/// Everything in this header is *evidence*: it is published by an adjacent
/// authority (Facility Topology, Failure Domain Registry, Physical Location
/// Registry, Tenant Registry, Service Class Registry, Maintenance Coordinator)
/// and is carried into an evaluation already bound to the generation it was
/// read at. This runtime never invents, derives or repairs any of it, and it
/// never treats an absent fact as a benign one.
namespace dccp::facility_placement_policy {

/// Resolves an enum token table entry. Both helpers are constexpr and linear in
/// the table, which is always tiny.
template <class Enum, std::size_t N>
constexpr std::string_view enum_token(
    const std::array<std::pair<Enum, std::string_view>, N>& table, Enum value) noexcept {
  for (const auto& entry : table) {
    if (entry.first == value) {
      return entry.second;
    }
  }
  return "?";
}

template <class Enum, std::size_t N>
Result<Enum> enum_from_token(const std::array<std::pair<Enum, std::string_view>, N>& table,
                             std::string_view text, std::string_view what) {
  for (const auto& entry : table) {
    if (entry.second == text) {
      return entry.first;
    }
  }
  return Error(ErrorCode::UnknownEnumToken, "unrecognised token")
      .with_subject(std::string(what) + "=" + std::string(text.substr(0, 64)));
}

/// The dimension along which two placements can share, or must not share, a
/// common failure point. Site, room, row and rack are the physical hierarchy;
/// failure domains are the overlapping electrical, thermal, network, control and
/// storage containment published by the failure-domain authority.
enum class PlacementDimension : std::uint8_t {
  Site = 0,
  Room = 1,
  Row = 2,
  Rack = 3,
  FailureDomain = 4,
};

inline constexpr std::array<std::pair<PlacementDimension, std::string_view>, 5>
    kPlacementDimensionTokens = {{{PlacementDimension::Site, "site"},
                                  {PlacementDimension::Room, "room"},
                                  {PlacementDimension::Row, "row"},
                                  {PlacementDimension::Rack, "rack"},
                                  {PlacementDimension::FailureDomain, "failure-domain"}}};

constexpr std::string_view placement_dimension_name(PlacementDimension value) noexcept {
  return enum_token(kPlacementDimensionTokens, value);
}

inline Result<PlacementDimension> parse_placement_dimension(std::string_view text) {
  return enum_from_token(kPlacementDimensionTokens, text, "dimension");
}

/// Kind of a published failure domain. The kind is part of the identity of the
/// dimension, so a power domain and a network domain are never compared.
enum class FailureDomainKind : std::uint8_t {
  Power = 0,
  Cooling = 1,
  Network = 2,
  Control = 3,
  Storage = 4,
  Custom = 5,
};

inline constexpr std::array<std::pair<FailureDomainKind, std::string_view>, 6>
    kFailureDomainKindTokens = {{{FailureDomainKind::Power, "power"},
                                 {FailureDomainKind::Cooling, "cooling"},
                                 {FailureDomainKind::Network, "network"},
                                 {FailureDomainKind::Control, "control"},
                                 {FailureDomainKind::Storage, "storage"},
                                 {FailureDomainKind::Custom, "custom"}}};

constexpr std::string_view failure_domain_kind_name(FailureDomainKind value) noexcept {
  return enum_token(kFailureDomainKindTokens, value);
}

inline Result<FailureDomainKind> parse_failure_domain_kind(std::string_view text) {
  return enum_from_token(kFailureDomainKindTokens, text, "failure-domain-kind");
}

/// A dimension together with the failure-domain kind it selects. The kind is
/// present if and only if the dimension is a failure domain; a document that
/// supplies it for a physical dimension, or omits it for a failure domain, is
/// rejected rather than silently normalised.
struct DimensionSelector {
  PlacementDimension dimension = PlacementDimension::Site;
  std::optional<FailureDomainKind> failure_domain_kind;

  friend bool operator==(const DimensionSelector& lhs, const DimensionSelector& rhs) noexcept {
    return lhs.dimension == rhs.dimension &&
           lhs.failure_domain_kind == rhs.failure_domain_kind;
  }

  friend std::strong_ordering operator<=>(const DimensionSelector& lhs,
                                          const DimensionSelector& rhs) noexcept {
    if (lhs.dimension != rhs.dimension) {
      return lhs.dimension < rhs.dimension ? std::strong_ordering::less
                                           : std::strong_ordering::greater;
    }
    const int left = lhs.failure_domain_kind ? static_cast<int>(*lhs.failure_domain_kind) : -1;
    const int right = rhs.failure_domain_kind ? static_cast<int>(*rhs.failure_domain_kind) : -1;
    return left < right ? std::strong_ordering::less
                        : (left > right ? std::strong_ordering::greater
                                        : std::strong_ordering::equal);
  }
};

/// Validates the selector's own shape (kind present exactly for failure domains).
Result<void> validate_dimension_selector(const DimensionSelector& selector);

/// The identity of one place in a dimension. The alternative that is active must
/// match the dimension the constraint selects, so a rack identity can never be
/// compared against a room identity even when the two spellings are identical.
using DimensionIdentity = std::variant<SiteId, RoomId, RowId, RackId, FailureDomainId>;

/// The dimension an identity belongs to.
constexpr PlacementDimension dimension_of_identity(const DimensionIdentity& identity) noexcept {
  switch (identity.index()) {
    case 0:
      return PlacementDimension::Site;
    case 1:
      return PlacementDimension::Room;
    case 2:
      return PlacementDimension::Row;
    case 3:
      return PlacementDimension::Rack;
    default:
      return PlacementDimension::FailureDomain;
  }
}

/// The identity's canonical text.
std::string_view dimension_identity_value(const DimensionIdentity& identity) noexcept;

/// Renders an identity for diagnostics.
std::string dimension_identity_text(const DimensionIdentity& identity);

/// Renders a selector, for example "rack" or "failure-domain:power".
std::string dimension_selector_name(const DimensionSelector& selector);

/// Which placed instances a constraint reasons about.
enum class PlacementScopeKind : std::uint8_t {
  Tenant = 0,        // the tenant named by the request
  ServiceClass = 1,  // the service class named by the request
  Any = 2,           // every placed instance in the occupancy evidence
};

inline constexpr std::array<std::pair<PlacementScopeKind, std::string_view>, 3>
    kPlacementScopeTokens = {{{PlacementScopeKind::Tenant, "tenant"},
                              {PlacementScopeKind::ServiceClass, "service-class"},
                              {PlacementScopeKind::Any, "any"}}};

constexpr std::string_view placement_scope_name(PlacementScopeKind value) noexcept {
  return enum_token(kPlacementScopeTokens, value);
}

inline Result<PlacementScopeKind> parse_placement_scope(std::string_view text) {
  return enum_from_token(kPlacementScopeTokens, text, "scope");
}

/// Typed facility attribute keys. A key is not a free-form string: adding a new
/// one is a code change with a value type attached, which is what keeps
/// jurisdiction and facility metadata from degrading into name matching.
enum class FacilityAttributeKey : std::uint8_t {
  PowerFeedCount = 0,
  PowerRedundancy = 1,
  CoolingMode = 2,
  CoolingRedundancy = 3,
  FloorLoadKgPerM2 = 4,
  RackWeightLimitKg = 5,
  SecurityTier = 6,
  FireSuppression = 7,
  NetworkIsolation = 8,
  EnvironmentalControl = 9,
  CommissionedAt = 10,
  DecommissionScheduledAt = 11,
};

inline constexpr std::array<std::pair<FacilityAttributeKey, std::string_view>, 12>
    kFacilityAttributeKeyTokens = {{{FacilityAttributeKey::PowerFeedCount, "power-feed-count"},
                                   {FacilityAttributeKey::PowerRedundancy, "power-redundancy"},
                                   {FacilityAttributeKey::CoolingMode, "cooling-mode"},
                                   {FacilityAttributeKey::CoolingRedundancy, "cooling-redundancy"},
                                   {FacilityAttributeKey::FloorLoadKgPerM2, "floor-load-kg-m2"},
                                   {FacilityAttributeKey::RackWeightLimitKg, "rack-weight-limit-kg"},
                                   {FacilityAttributeKey::SecurityTier, "security-tier"},
                                   {FacilityAttributeKey::FireSuppression, "fire-suppression"},
                                   {FacilityAttributeKey::NetworkIsolation, "network-isolation"},
                                   {FacilityAttributeKey::EnvironmentalControl,
                                    "environmental-control"},
                                   {FacilityAttributeKey::CommissionedAt, "commissioned-at"},
                                   {FacilityAttributeKey::DecommissionScheduledAt,
                                    "decommission-scheduled-at"}}};

constexpr std::string_view facility_attribute_key_name(FacilityAttributeKey value) noexcept {
  return enum_token(kFacilityAttributeKeyTokens, value);
}

inline Result<FacilityAttributeKey> parse_facility_attribute_key(std::string_view text) {
  return enum_from_token(kFacilityAttributeKeyTokens, text, "attribute");
}

/// Redundancy class of a power or cooling distribution path.
enum class RedundancyClass : std::uint8_t {
  None = 0,
  N = 1,
  N1 = 2,
  N2 = 3,
};

inline constexpr std::array<std::pair<RedundancyClass, std::string_view>, 4>
    kRedundancyClassTokens = {{{RedundancyClass::None, "none"},
                               {RedundancyClass::N, "n"},
                               {RedundancyClass::N1, "n+1"},
                               {RedundancyClass::N2, "2n"}}};

constexpr std::string_view redundancy_class_name(RedundancyClass value) noexcept {
  return enum_token(kRedundancyClassTokens, value);
}

inline Result<RedundancyClass> parse_redundancy_class(std::string_view text) {
  return enum_from_token(kRedundancyClassTokens, text, "redundancy");
}

/// Heat rejection method serving the space.
enum class CoolingModeClass : std::uint8_t {
  Air = 0,
  RearDoor = 1,
  DirectLiquid = 2,
  Immersion = 3,
};

inline constexpr std::array<std::pair<CoolingModeClass, std::string_view>, 4>
    kCoolingModeTokens = {{{CoolingModeClass::Air, "air"},
                           {CoolingModeClass::RearDoor, "rear-door"},
                           {CoolingModeClass::DirectLiquid, "direct-liquid"},
                           {CoolingModeClass::Immersion, "immersion"}}};

constexpr std::string_view cooling_mode_name(CoolingModeClass value) noexcept {
  return enum_token(kCoolingModeTokens, value);
}

inline Result<CoolingModeClass> parse_cooling_mode(std::string_view text) {
  return enum_from_token(kCoolingModeTokens, text, "cooling-mode");
}

/// Fixed suppression system serving the space.
enum class FireSuppressionClass : std::uint8_t {
  None = 0,
  Sprinkler = 1,
  CleanAgent = 2,
  WaterMist = 3,
};

inline constexpr std::array<std::pair<FireSuppressionClass, std::string_view>, 4>
    kFireSuppressionTokens = {{{FireSuppressionClass::None, "none"},
                               {FireSuppressionClass::Sprinkler, "sprinkler"},
                               {FireSuppressionClass::CleanAgent, "clean-agent"},
                               {FireSuppressionClass::WaterMist, "water-mist"}}};

constexpr std::string_view fire_suppression_name(FireSuppressionClass value) noexcept {
  return enum_token(kFireSuppressionTokens, value);
}

inline Result<FireSuppressionClass> parse_fire_suppression(std::string_view text) {
  return enum_from_token(kFireSuppressionTokens, text, "fire-suppression");
}

/// How strongly the space is separated from other tenants' traffic.
enum class NetworkIsolationClass : std::uint8_t {
  Shared = 0,
  TenantDedicated = 1,
  PhysicallySeparated = 2,
};

inline constexpr std::array<std::pair<NetworkIsolationClass, std::string_view>, 3>
    kNetworkIsolationTokens = {{{NetworkIsolationClass::Shared, "shared"},
                                {NetworkIsolationClass::TenantDedicated, "tenant-dedicated"},
                                {NetworkIsolationClass::PhysicallySeparated,
                                 "physically-separated"}}};

constexpr std::string_view network_isolation_name(NetworkIsolationClass value) noexcept {
  return enum_token(kNetworkIsolationTokens, value);
}

inline Result<NetworkIsolationClass> parse_network_isolation(std::string_view text) {
  return enum_from_token(kNetworkIsolationTokens, text, "network-isolation");
}

/// Degree of environmental control.
enum class EnvironmentalControlClass : std::uint8_t {
  None = 0,
  Basic = 1,
  Precision = 2,
};

inline constexpr std::array<std::pair<EnvironmentalControlClass, std::string_view>, 3>
    kEnvironmentalControlTokens = {{{EnvironmentalControlClass::None, "none"},
                                    {EnvironmentalControlClass::Basic, "basic"},
                                    {EnvironmentalControlClass::Precision, "precision"}}};

constexpr std::string_view environmental_control_name(EnvironmentalControlClass value) noexcept {
  return enum_token(kEnvironmentalControlTokens, value);
}

inline Result<EnvironmentalControlClass> parse_environmental_control(std::string_view text) {
  return enum_from_token(kEnvironmentalControlTokens, text, "environmental-control");
}

/// The typed value of a facility attribute. The alternative that is active must
/// match the value kind the key requires; anything else is rejected by
/// validation rather than compared.
using AttributeValue =
    std::variant<std::uint32_t, Instant, RedundancyClass, CoolingModeClass,
                 FireSuppressionClass, NetworkIsolationClass, EnvironmentalControlClass>;

/// The value kind expected by an attribute key.
enum class AttributeValueKind : std::uint8_t {
  Unsigned = 0,
  Instant = 1,
  Redundancy = 2,
  CoolingMode = 3,
  FireSuppression = 4,
  NetworkIsolation = 5,
  EnvironmentalControl = 6,
};

AttributeValueKind attribute_value_kind(FacilityAttributeKey key) noexcept;

/// True when the value's alternative matches the key's expected kind.
bool attribute_value_matches(FacilityAttributeKey key, const AttributeValue& value) noexcept;

/// Renders a value in the canonical token form for its kind.
std::string attribute_value_text(const AttributeValue& value);

/// Renders a key and value, for example "cooling-mode=direct-liquid".
std::string attribute_text(FacilityAttributeKey key, const AttributeValue& value);

/// A facility as the policy engine sees it: identity, jurisdiction and typed
/// attributes. Every field is what the owning authority published.
struct FacilityRecord {
  FacilityId facility;
  /// Absent means the jurisdiction is not known. A jurisdiction constraint
  /// refuses an unknown jurisdiction; it never treats it as a mismatch or a
  /// match by accident.
  std::optional<JurisdictionId> jurisdiction;
  /// Sorted by key, at most one entry per key.
  std::vector<std::pair<FacilityAttributeKey, AttributeValue>> attributes;

  const AttributeValue* attribute(FacilityAttributeKey key) const noexcept;
};

/// Where a candidate or a placed instance is.
struct FacilityLocation {
  FacilityId facility;
  std::optional<SiteId> site;
  std::optional<RoomId> room;
  std::optional<RowId> row;
  std::optional<RackId> rack;
  /// Sorted by (kind, identity); at most one entry per (kind, identity) pair.
  std::vector<std::pair<FailureDomainKind, FailureDomainId>> failure_domains;

  /// True when the dimension is present in this location.
  bool has_dimension(const DimensionSelector& selector) const noexcept;

  /// The identity that two locations share when they sit in the same place for
  /// this dimension, or an empty optional when the dimension is not known here.
  /// The returned view is valid for as long as this location is.
  std::optional<std::string_view> dimension_identity(const DimensionSelector& selector) const noexcept;
};

/// A placement that already exists, as published by the authority that owns it.
struct PlacedInstance {
  PlacementId placement_id;
  TenantId tenant;
  ServiceClassId service_class;
  FacilityLocation location;
};

/// Occupancy facts, bound to the generation they were read at.
///
/// An absent generation means no occupancy evidence was supplied at all, which
/// is different from a generation with an empty instance list. Constraints that
/// reason about what already exists refuse the former and accept the latter.
struct OccupancyEvidence {
  std::optional<OccupancyGeneration> generation;
  /// Sorted by placement identity.
  std::vector<PlacedInstance> instances;
};

/// What kind of event an exposure describes.
enum class MaintenanceKind : std::uint8_t {
  Planned = 0,
  Emergency = 1,
  Degradation = 2,
};

inline constexpr std::array<std::pair<MaintenanceKind, std::string_view>, 3>
    kMaintenanceKindTokens = {{{MaintenanceKind::Planned, "planned"},
                               {MaintenanceKind::Emergency, "emergency"},
                               {MaintenanceKind::Degradation, "degradation"}}};

constexpr std::string_view maintenance_kind_name(MaintenanceKind value) noexcept {
  return enum_token(kMaintenanceKindTokens, value);
}

inline Result<MaintenanceKind> parse_maintenance_kind(std::string_view text) {
  return enum_from_token(kMaintenanceKindTokens, text, "maintenance-kind");
}

/// How much of the space the exposure takes out of service.
enum class MaintenanceSeverity : std::uint8_t {
  Advisory = 0,   // recorded, but does not remove capability
  Degraded = 1,   // capability is reduced
  Blackout = 2,   // the space must not receive new placements
};

inline constexpr std::array<std::pair<MaintenanceSeverity, std::string_view>, 3>
    kMaintenanceSeverityTokens = {{{MaintenanceSeverity::Advisory, "advisory"},
                                   {MaintenanceSeverity::Degraded, "degraded"},
                                   {MaintenanceSeverity::Blackout, "blackout"}}};

constexpr std::string_view maintenance_severity_name(MaintenanceSeverity value) noexcept {
  return enum_token(kMaintenanceSeverityTokens, value);
}

inline Result<MaintenanceSeverity> parse_maintenance_severity(std::string_view text) {
  return enum_from_token(kMaintenanceSeverityTokens, text, "maintenance-severity");
}

/// The set of places an exposure applies to. Every field that is present must
/// agree with the candidate's location for the exposure to apply; an exposure
/// that names a field the candidate does not declare cannot be evaluated and is
/// refused rather than ignored.
struct MaintenanceScope {
  std::optional<FacilityId> facility;
  std::optional<SiteId> site;
  std::optional<RoomId> room;
  std::optional<RowId> row;
  std::optional<RackId> rack;
  std::optional<FailureDomainKind> failure_domain_kind;
  std::optional<FailureDomainId> failure_domain;

  bool is_empty() const noexcept;
};

/// One published exposure.
struct MaintenanceExposure {
  ExposureId exposure_id;
  MaintenanceKind kind = MaintenanceKind::Planned;
  MaintenanceSeverity severity = MaintenanceSeverity::Blackout;
  MaintenanceScope scope;
  Instant start;
  Instant end;
};

/// Maintenance facts, bound to the generation they were read at. An absent
/// generation means no maintenance evidence was supplied.
struct MaintenanceEvidence {
  std::optional<MaintenanceGeneration> generation;
  /// Sorted by exposure identity.
  std::vector<MaintenanceExposure> exposures;
};

/// The generations every evaluation binds to. An absent generation is a
/// refusal, never a default.
struct EvidenceGenerations {
  TopologyGeneration topology;
  FailureDomainGeneration failure_domain;
  TenantGeneration tenant;
  ServiceClassGeneration service_class;
};

/// True when every generation is present.
bool evidence_generations_complete(const EvidenceGenerations& generations) noexcept;

/// Names the first absent generation, for diagnostics. Empty when complete.
std::string_view first_absent_generation(const EvidenceGenerations& generations) noexcept;

}  // namespace dccp::facility_placement_policy

#endif  // DCCP_FACILITY_PLACEMENT_POLICY_FACILITY_HPP
