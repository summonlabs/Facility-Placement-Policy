// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs.

#include "dccp/facility_placement_policy/canonical.hpp"

#include <algorithm>
#include <cstring>
#include <string>
#include <string_view>
#include <type_traits>
#include <variant>
#include <vector>

#include "canonical_internal.hpp"
#include "dccp/facility_placement_policy/text_util.hpp"
#include "internal_util.hpp"

namespace dccp::facility_placement_policy {

namespace internal {

void write_instant(Writer& writer, Instant instant) {
  writer.boolean(instant.is_set());
  writer.i64(instant.unix_micros());
}

Instant read_instant(Reader& reader, std::string_view what) noexcept {
  const bool is_set = reader.flag();
  const std::int64_t micros = reader.i64();
  if (!reader.ok()) {
    return Instant{};
  }
  if (!is_set) {
    // A field that carries no meaning must be zero, so that a decode is the
    // exact inverse of an encode and a record cannot hide a value in a field the
    // reader is about to ignore.
    if (micros != 0) {
      reader.fail(Error(ErrorCode::ReservedFieldNotZero,
                        "an instant that is not set must encode a zero payload")
                      .with_subject(std::string(what)));
    }
    return Instant{};
  }
  auto parsed = Instant::from_unix_micros(micros);
  if (!parsed.has_value()) {
    reader.fail(std::move(parsed.error()).with_subject(std::string(what)));
    return Instant{};
  }
  return parsed.value();
}

void write_digest(Writer& writer, const Digest& digest) { writer.digest(digest); }

Digest read_digest(Reader& reader) { return reader.digest(); }

}  // namespace internal

namespace {

using internal::Reader;
using internal::read_counter;
using internal::read_digest;
using internal::read_enum;
using internal::read_id;
using internal::read_instant;
using internal::read_optional_counter;
using internal::read_optional_id;
using internal::sort_unique;
using internal::write_counter;
using internal::write_digest;
using internal::write_enum;
using internal::write_id;
using internal::write_instant;
using internal::write_optional_counter;
using internal::write_optional_id;
using internal::Writer;

template <class Id>
std::optional<Id> parse_identifier(Reader& reader, const std::string& raw,
                                   std::string_view what) noexcept {
  auto parsed = Id::from_trusted(raw);
  if (!parsed.has_value()) {
    reader.fail(std::move(parsed.error()).with_subject(std::string(what)));
    return std::nullopt;
  }
  return parsed.value();
}

std::string read_utf8_text(Reader& reader, std::size_t max_bytes, std::string_view what) {
  std::string raw = reader.text(max_bytes);
  if (!reader.ok()) {
    return raw;
  }
  auto checked = require_valid_utf8(raw, what, max_bytes);
  if (!checked.has_value()) {
    reader.fail(checked.error());
    return {};
  }
  return checked.value();
}

// ---------------------------------------------------------------------------
// Shared model fragments
// ---------------------------------------------------------------------------

void write_dimension_selector(Writer& writer, const DimensionSelector& selector) {
  write_enum(writer, selector.dimension);
  writer.boolean(selector.failure_domain_kind.has_value());
  if (selector.failure_domain_kind.has_value()) {
    write_enum(writer, *selector.failure_domain_kind);
  }
}

DimensionSelector read_dimension_selector(Reader& reader) {
  DimensionSelector selector;
  selector.dimension = read_enum<PlacementDimension>(reader, 4u, "dimension");
  if (reader.flag()) {
    selector.failure_domain_kind = read_enum<FailureDomainKind>(reader, 5u, "failure-domain-kind");
  }
  return selector;
}

void write_identity(Writer& writer, const DimensionIdentity& identity) {
  writer.u8(static_cast<std::uint8_t>(identity.index()));
  std::visit([&writer](const auto& concrete) { writer.blob(concrete.value()); }, identity);
}

DimensionIdentity read_identity(Reader& reader) noexcept {
  const std::uint8_t index = reader.u8();
  const std::string raw = reader.text(kMaxIdentifierBytes);
  if (!reader.ok()) {
    return SiteId{};
  }
  if (index > 4u) {
    reader.fail(Error(ErrorCode::UnknownEnumToken, "identity alternative is outside its range")
                    .with_detail("alternative=" + std::to_string(index)));
    return SiteId{};
  }
  switch (index) {
    case 0u: {
      auto parsed = parse_identifier<SiteId>(reader, raw, "site");
      return parsed.has_value() ? DimensionIdentity(*parsed) : DimensionIdentity(SiteId{});
    }
    case 1u: {
      auto parsed = parse_identifier<RoomId>(reader, raw, "room");
      return parsed.has_value() ? DimensionIdentity(*parsed) : DimensionIdentity(RoomId{});
    }
    case 2u: {
      auto parsed = parse_identifier<RowId>(reader, raw, "row");
      return parsed.has_value() ? DimensionIdentity(*parsed) : DimensionIdentity(RowId{});
    }
    case 3u: {
      auto parsed = parse_identifier<RackId>(reader, raw, "rack");
      return parsed.has_value() ? DimensionIdentity(*parsed) : DimensionIdentity(RackId{});
    }
    default: {
      auto parsed = parse_identifier<FailureDomainId>(reader, raw, "failure-domain");
      return parsed.has_value() ? DimensionIdentity(*parsed)
                                : DimensionIdentity(FailureDomainId{});
    }
  }
}

void write_selector(Writer& writer, const RuleSelector& selector) {
  writer.u32(static_cast<std::uint32_t>(selector.tenants.size()));
  for (const TenantId& id : selector.tenants) {
    write_id(writer, id);
  }
  writer.u32(static_cast<std::uint32_t>(selector.service_classes.size()));
  for (const ServiceClassId& id : selector.service_classes) {
    write_id(writer, id);
  }
  writer.u32(static_cast<std::uint32_t>(selector.facilities.size()));
  for (const FacilityId& id : selector.facilities) {
    write_id(writer, id);
  }
  writer.u32(static_cast<std::uint32_t>(selector.jurisdictions.size()));
  for (const JurisdictionId& id : selector.jurisdictions) {
    write_id(writer, id);
  }
}

RuleSelector read_selector(Reader& reader) {
  RuleSelector selector;
  const std::uint32_t tenants = reader.count(kMaxSelectorEntries, "selector tenants");
  selector.tenants.reserve(tenants);
  for (std::uint32_t index = 0; index < tenants && reader.ok(); ++index) {
    selector.tenants.push_back(read_id<TenantId>(reader, "selector tenant"));
  }
  const std::uint32_t service_classes = reader.count(kMaxSelectorEntries, "selector service classes");
  selector.service_classes.reserve(service_classes);
  for (std::uint32_t index = 0; index < service_classes && reader.ok(); ++index) {
    selector.service_classes.push_back(
        read_id<ServiceClassId>(reader, "selector service class"));
  }
  const std::uint32_t facilities = reader.count(kMaxSelectorEntries, "selector facilities");
  selector.facilities.reserve(facilities);
  for (std::uint32_t index = 0; index < facilities && reader.ok(); ++index) {
    selector.facilities.push_back(read_id<FacilityId>(reader, "selector facility"));
  }
  const std::uint32_t jurisdictions = reader.count(kMaxSelectorEntries, "selector jurisdictions");
  selector.jurisdictions.reserve(jurisdictions);
  for (std::uint32_t index = 0; index < jurisdictions && reader.ok(); ++index) {
    selector.jurisdictions.push_back(read_id<JurisdictionId>(reader, "selector jurisdiction"));
  }
  return selector;
}

void write_attribute_value(Writer& writer, const AttributeValue& value) {
  std::visit(
      [&writer](const auto& concrete) {
        using Concrete = std::decay_t<decltype(concrete)>;
        static_cast<void>(concrete);
        if constexpr (std::is_same_v<Concrete, std::uint32_t>) {
          write_enum(writer, AttributeValueKind::Unsigned);
        } else if constexpr (std::is_same_v<Concrete, Instant>) {
          write_enum(writer, AttributeValueKind::Instant);
        } else if constexpr (std::is_same_v<Concrete, RedundancyClass>) {
          write_enum(writer, AttributeValueKind::Redundancy);
        } else if constexpr (std::is_same_v<Concrete, CoolingModeClass>) {
          write_enum(writer, AttributeValueKind::CoolingMode);
        } else if constexpr (std::is_same_v<Concrete, FireSuppressionClass>) {
          write_enum(writer, AttributeValueKind::FireSuppression);
        } else if constexpr (std::is_same_v<Concrete, NetworkIsolationClass>) {
          write_enum(writer, AttributeValueKind::NetworkIsolation);
        } else {
          write_enum(writer, AttributeValueKind::EnvironmentalControl);
        }
      },
      value);
  std::visit(
      [&writer](const auto& concrete) {
        using Concrete = std::decay_t<decltype(concrete)>;
        if constexpr (std::is_same_v<Concrete, std::uint32_t>) {
          writer.u32(concrete);
        } else if constexpr (std::is_same_v<Concrete, Instant>) {
          write_instant(writer, concrete);
        } else {
          writer.u8(static_cast<std::uint8_t>(concrete));
        }
      },
      value);
}

AttributeValue read_attribute_value(Reader& reader) noexcept {
  const AttributeValueKind kind = read_enum<AttributeValueKind>(reader, 6u, "attribute-value-kind");
  if (!reader.ok()) {
    return std::uint32_t{0};
  }
  switch (kind) {
    case AttributeValueKind::Unsigned:
      return reader.u32();
    case AttributeValueKind::Instant:
      return read_instant(reader, "attribute instant");
    case AttributeValueKind::Redundancy:
      return read_enum<RedundancyClass>(reader, 3u, "redundancy");
    case AttributeValueKind::CoolingMode:
      return read_enum<CoolingModeClass>(reader, 3u, "cooling-mode");
    case AttributeValueKind::FireSuppression:
      return read_enum<FireSuppressionClass>(reader, 3u, "fire-suppression");
    case AttributeValueKind::NetworkIsolation:
      return read_enum<NetworkIsolationClass>(reader, 2u, "network-isolation");
    case AttributeValueKind::EnvironmentalControl:
      return read_enum<EnvironmentalControlClass>(reader, 2u, "environmental-control");
  }
  return std::uint32_t{0};
}

void write_location(Writer& writer, const FacilityLocation& location) {
  write_id(writer, location.facility);
  write_optional_id(writer, location.site);
  write_optional_id(writer, location.room);
  write_optional_id(writer, location.row);
  write_optional_id(writer, location.rack);
  writer.u32(static_cast<std::uint32_t>(location.failure_domains.size()));
  for (const auto& entry : location.failure_domains) {
    write_enum(writer, entry.first);
    write_id(writer, entry.second);
  }
}

FacilityLocation read_location(Reader& reader) {
  FacilityLocation location;
  location.facility = read_id<FacilityId>(reader, "facility");
  location.site = read_optional_id<SiteId>(reader, "site");
  location.room = read_optional_id<RoomId>(reader, "room");
  location.row = read_optional_id<RowId>(reader, "row");
  location.rack = read_optional_id<RackId>(reader, "rack");
  const std::uint32_t domains =
      reader.count(kMaxFailureDomainsPerPlacement, "placement failure domains");
  location.failure_domains.reserve(domains);
  for (std::uint32_t index = 0; index < domains && reader.ok(); ++index) {
    const FailureDomainKind kind = read_enum<FailureDomainKind>(reader, 5u, "failure-domain-kind");
    const FailureDomainId id = read_id<FailureDomainId>(reader, "failure-domain");
    location.failure_domains.emplace_back(kind, id);
  }
  return location;
}

// ---------------------------------------------------------------------------
// Policy
// ---------------------------------------------------------------------------

void write_constraint(Writer& writer, const Constraint& constraint) {
  write_enum(writer, constraint_kind_of(constraint));
  std::visit(
      [&writer](const auto& concrete) {
        using Concrete = std::decay_t<decltype(concrete)>;
        if constexpr (std::is_same_v<Concrete, JurisdictionConstraint>) {
          writer.u32(static_cast<std::uint32_t>(concrete.allow.size()));
          for (const JurisdictionId& id : concrete.allow) {
            write_id(writer, id);
          }
          writer.u32(static_cast<std::uint32_t>(concrete.deny.size()));
          for (const JurisdictionId& id : concrete.deny) {
            write_id(writer, id);
          }
        } else if constexpr (std::is_same_v<Concrete, FacilityAttributeConstraint>) {
          write_enum(writer, concrete.key);
          write_enum(writer, concrete.op);
          writer.boolean(concrete.operand.has_value());
          if (concrete.operand.has_value()) {
            write_attribute_value(writer, *concrete.operand);
          }
        } else if constexpr (std::is_same_v<Concrete, SeparationConstraint>) {
          write_dimension_selector(writer, concrete.dimension);
          writer.u32(static_cast<std::uint32_t>(concrete.allow.size()));
          for (const DimensionIdentity& identity : concrete.allow) {
            write_identity(writer, identity);
          }
          writer.u32(static_cast<std::uint32_t>(concrete.deny.size()));
          for (const DimensionIdentity& identity : concrete.deny) {
            write_identity(writer, identity);
          }
        } else if constexpr (std::is_same_v<Concrete, AntiAffinityConstraint>) {
          write_enum(writer, concrete.scope);
          write_dimension_selector(writer, concrete.dimension);
          writer.u32(concrete.max_shared);
        } else if constexpr (std::is_same_v<Concrete, RedundancyConstraint>) {
          write_enum(writer, concrete.scope);
          write_dimension_selector(writer, concrete.dimension);
          writer.u32(concrete.min_distinct_domains);
        } else if constexpr (std::is_same_v<Concrete, CoTenancyConstraint>) {
          write_dimension_selector(writer, concrete.dimension);
          writer.u32(static_cast<std::uint32_t>(concrete.forbidden_tenants.size()));
          for (const TenantId& id : concrete.forbidden_tenants) {
            write_id(writer, id);
          }
          writer.u32(static_cast<std::uint32_t>(concrete.forbidden_service_classes.size()));
          for (const ServiceClassId& id : concrete.forbidden_service_classes) {
            write_id(writer, id);
          }
          writer.u32(concrete.max_shared);
        } else {
          write_enum(writer, concrete.minimum_blocking_severity);
          writer.i64(concrete.horizon.microseconds());
        }
      },
      constraint);
}

Constraint read_constraint(Reader& reader) {
  const ConstraintKind kind = read_enum<ConstraintKind>(reader, 6u, "constraint-kind");
  switch (kind) {
    case ConstraintKind::JurisdictionMembership: {
      JurisdictionConstraint constraint;
      const std::uint32_t allow = reader.count(kMaxSetEntries, "jurisdiction allow");
      constraint.allow.reserve(allow);
      for (std::uint32_t index = 0; index < allow && reader.ok(); ++index) {
        constraint.allow.push_back(read_id<JurisdictionId>(reader, "jurisdiction"));
      }
      const std::uint32_t deny = reader.count(kMaxSetEntries, "jurisdiction deny");
      constraint.deny.reserve(deny);
      for (std::uint32_t index = 0; index < deny && reader.ok(); ++index) {
        constraint.deny.push_back(read_id<JurisdictionId>(reader, "jurisdiction"));
      }
      return Constraint(constraint);
    }
    case ConstraintKind::FacilityAttribute: {
      FacilityAttributeConstraint constraint;
      constraint.key = read_enum<FacilityAttributeKey>(reader, 11u, "attribute-key");
      constraint.op = read_enum<AttributeOperator>(reader, 5u, "attribute-operator");
      if (reader.flag()) {
        constraint.operand = read_attribute_value(reader);
      }
      return Constraint(constraint);
    }
    case ConstraintKind::Separation: {
      SeparationConstraint constraint;
      constraint.dimension = read_dimension_selector(reader);
      const std::uint32_t allow = reader.count(kMaxSetEntries, "separation allow");
      constraint.allow.reserve(allow);
      for (std::uint32_t index = 0; index < allow && reader.ok(); ++index) {
        constraint.allow.push_back(read_identity(reader));
      }
      const std::uint32_t deny = reader.count(kMaxSetEntries, "separation deny");
      constraint.deny.reserve(deny);
      for (std::uint32_t index = 0; index < deny && reader.ok(); ++index) {
        constraint.deny.push_back(read_identity(reader));
      }
      return Constraint(constraint);
    }
    case ConstraintKind::AntiAffinity: {
      AntiAffinityConstraint constraint;
      constraint.scope = read_enum<PlacementScopeKind>(reader, 2u, "scope");
      constraint.dimension = read_dimension_selector(reader);
      constraint.max_shared = reader.u32();
      return Constraint(constraint);
    }
    case ConstraintKind::Redundancy: {
      RedundancyConstraint constraint;
      constraint.scope = read_enum<PlacementScopeKind>(reader, 2u, "scope");
      constraint.dimension = read_dimension_selector(reader);
      constraint.min_distinct_domains = reader.u32();
      return Constraint(constraint);
    }
    case ConstraintKind::CoTenancy: {
      CoTenancyConstraint constraint;
      constraint.dimension = read_dimension_selector(reader);
      const std::uint32_t tenants = reader.count(kMaxSetEntries, "co-tenancy tenants");
      constraint.forbidden_tenants.reserve(tenants);
      for (std::uint32_t index = 0; index < tenants && reader.ok(); ++index) {
        constraint.forbidden_tenants.push_back(read_id<TenantId>(reader, "tenant"));
      }
      const std::uint32_t service_classes =
          reader.count(kMaxSetEntries, "co-tenancy service classes");
      constraint.forbidden_service_classes.reserve(service_classes);
      for (std::uint32_t index = 0; index < service_classes && reader.ok(); ++index) {
        constraint.forbidden_service_classes.push_back(
            read_id<ServiceClassId>(reader, "service-class"));
      }
      constraint.max_shared = reader.u32();
      return Constraint(constraint);
    }
    case ConstraintKind::MaintenanceExposure:
    default: {
      MaintenanceConstraint constraint;
      constraint.minimum_blocking_severity =
          read_enum<MaintenanceSeverity>(reader, 2u, "maintenance-severity");
      constraint.horizon = Duration::from_microseconds(reader.i64());
      return Constraint(constraint);
    }
  }
}

void write_rule(Writer& writer, const Rule& rule) {
  write_id(writer, rule.rule_id);
  write_selector(writer, rule.selector);
  writer.blob(rule.description);
  writer.u32(static_cast<std::uint32_t>(rule.constraints.size()));
  for (const Constraint& constraint : rule.constraints) {
    write_constraint(writer, constraint);
  }
}

Rule read_rule(Reader& reader) {
  Rule rule;
  rule.rule_id = read_id<RuleId>(reader, "rule");
  rule.selector = read_selector(reader);
  rule.description = read_utf8_text(reader, kMaxTextBytes, "rule description");
  const std::uint32_t constraints = reader.count(kMaxConstraintsPerRule, "rule constraints");
  rule.constraints.reserve(constraints);
  for (std::uint32_t index = 0; index < constraints && reader.ok(); ++index) {
    rule.constraints.push_back(read_constraint(reader));
  }
  return rule;
}

void write_envelope(Writer& writer, const OverrideEnvelope& envelope) {
  write_id(writer, envelope.envelope_id);
  write_selector(writer, envelope.scope);
  writer.u32(static_cast<std::uint32_t>(envelope.allowed_constraints.size()));
  for (const ConstraintKind kind : envelope.allowed_constraints) {
    write_enum(writer, kind);
  }
  writer.u32(static_cast<std::uint32_t>(envelope.authorized_principals.size()));
  for (const PrincipalId& id : envelope.authorized_principals) {
    write_id(writer, id);
  }
  writer.u32(envelope.max_uses);
  writer.i64(envelope.grant_validity.microseconds());
  write_instant(writer, envelope.not_before);
  write_instant(writer, envelope.expires_at);
}

OverrideEnvelope read_envelope(Reader& reader) {
  OverrideEnvelope envelope;
  envelope.envelope_id = read_id<EnvelopeId>(reader, "envelope");
  envelope.scope = read_selector(reader);
  const std::uint32_t kinds = reader.count(kConstraintKindCount, "envelope constraint kinds");
  envelope.allowed_constraints.reserve(kinds);
  for (std::uint32_t index = 0; index < kinds && reader.ok(); ++index) {
    envelope.allowed_constraints.push_back(
        read_enum<ConstraintKind>(reader, 6u, "constraint-kind"));
  }
  const std::uint32_t principals = reader.count(kMaxSetEntries, "envelope principals");
  envelope.authorized_principals.reserve(principals);
  for (std::uint32_t index = 0; index < principals && reader.ok(); ++index) {
    envelope.authorized_principals.push_back(read_id<PrincipalId>(reader, "principal"));
  }
  envelope.max_uses = reader.u32();
  envelope.grant_validity = Duration::from_microseconds(reader.i64());
  envelope.not_before = read_instant(reader, "envelope not-before");
  envelope.expires_at = read_instant(reader, "envelope expires-at");
  return envelope;
}

void write_policy(Writer& writer, const PolicyDocument& document) {
  writer.u32(kPayloadFormatVersion);
  write_id(writer, document.policy_id);
  write_counter(writer, document.revision);
  writer.u32(static_cast<std::uint32_t>(document.rules.size()));
  for (const Rule& rule : document.rules) {
    write_rule(writer, rule);
  }
  writer.u32(static_cast<std::uint32_t>(document.envelopes.size()));
  for (const OverrideEnvelope& envelope : document.envelopes) {
    write_envelope(writer, envelope);
  }
}

PolicyDocument read_policy(Reader& reader) {
  PolicyDocument document;
  const std::uint32_t version = reader.u32();
  if (version != kPayloadFormatVersion) {
    reader.fail(Error(ErrorCode::UnsupportedFormatVersion, "policy payload version is not supported")
                    .with_detail("version=" + std::to_string(version)));
    return document;
  }
  document.policy_id = read_id<PolicyId>(reader, "policy");
  document.revision = read_counter<PolicyRevisionTag>(reader, "policy-revision");
  const std::uint32_t rules = reader.count(kMaxRulesPerPolicy, "policy rules");
  document.rules.reserve(rules);
  for (std::uint32_t index = 0; index < rules && reader.ok(); ++index) {
    document.rules.push_back(read_rule(reader));
  }
  const std::uint32_t envelopes = reader.count(kMaxEnvelopesPerPolicy, "policy envelopes");
  document.envelopes.reserve(envelopes);
  for (std::uint32_t index = 0; index < envelopes && reader.ok(); ++index) {
    document.envelopes.push_back(read_envelope(reader));
  }
  return document;
}

// ---------------------------------------------------------------------------
// Request
// ---------------------------------------------------------------------------

void write_facility_record(Writer& writer, const FacilityRecord& record) {
  write_id(writer, record.facility);
  write_optional_id(writer, record.jurisdiction);
  writer.u32(static_cast<std::uint32_t>(record.attributes.size()));
  for (const auto& entry : record.attributes) {
    write_enum(writer, entry.first);
    write_attribute_value(writer, entry.second);
  }
}

FacilityRecord read_facility_record(Reader& reader) {
  FacilityRecord record;
  record.facility = read_id<FacilityId>(reader, "facility");
  record.jurisdiction = read_optional_id<JurisdictionId>(reader, "jurisdiction");
  const std::uint32_t attributes = reader.count(kMaxFacilityAttributes, "facility attributes");
  record.attributes.reserve(attributes);
  for (std::uint32_t index = 0; index < attributes && reader.ok(); ++index) {
    const FacilityAttributeKey key = read_enum<FacilityAttributeKey>(reader, 11u, "attribute-key");
    // AttributeValue is trivially copyable, so moving it would only obscure the
    // intent.
    record.attributes.emplace_back(key, read_attribute_value(reader));
  }
  return record;
}

void write_maintenance_scope(Writer& writer, const MaintenanceScope& scope) {
  write_optional_id(writer, scope.facility);
  write_optional_id(writer, scope.site);
  write_optional_id(writer, scope.room);
  write_optional_id(writer, scope.row);
  write_optional_id(writer, scope.rack);
  writer.boolean(scope.failure_domain_kind.has_value());
  if (scope.failure_domain_kind.has_value()) {
    write_enum(writer, *scope.failure_domain_kind);
  }
  write_optional_id(writer, scope.failure_domain);
}

MaintenanceScope read_maintenance_scope(Reader& reader) {
  MaintenanceScope scope;
  scope.facility = read_optional_id<FacilityId>(reader, "scope facility");
  scope.site = read_optional_id<SiteId>(reader, "scope site");
  scope.room = read_optional_id<RoomId>(reader, "scope room");
  scope.row = read_optional_id<RowId>(reader, "scope row");
  scope.rack = read_optional_id<RackId>(reader, "scope rack");
  if (reader.flag()) {
    scope.failure_domain_kind = read_enum<FailureDomainKind>(reader, 5u, "failure-domain-kind");
  }
  scope.failure_domain = read_optional_id<FailureDomainId>(reader, "scope failure-domain");
  return scope;
}

void write_request_body(Writer& writer, const PlacementRequest& request,
                        std::span<const CandidatePlacement> candidates) {
  write_id(writer, request.request_id);
  write_id(writer, request.tenant);
  write_id(writer, request.service_class);
  write_instant(writer, request.requested_at);
  write_counter(writer, request.generations.topology);
  write_counter(writer, request.generations.failure_domain);
  write_counter(writer, request.generations.tenant);
  write_counter(writer, request.generations.service_class);
  writer.u32(static_cast<std::uint32_t>(request.facilities.size()));
  for (const FacilityRecord& record : request.facilities) {
    write_facility_record(writer, record);
  }
  writer.u32(static_cast<std::uint32_t>(candidates.size()));
  for (const CandidatePlacement& candidate : candidates) {
    write_id(writer, candidate.candidate_id);
    write_location(writer, candidate.location);
  }
  write_optional_counter(writer, request.occupancy.generation);
  writer.u32(static_cast<std::uint32_t>(request.occupancy.instances.size()));
  for (const PlacedInstance& instance : request.occupancy.instances) {
    write_id(writer, instance.placement_id);
    write_id(writer, instance.tenant);
    write_id(writer, instance.service_class);
    write_location(writer, instance.location);
  }
  write_optional_counter(writer, request.maintenance.generation);
  writer.u32(static_cast<std::uint32_t>(request.maintenance.exposures.size()));
  for (const MaintenanceExposure& exposure : request.maintenance.exposures) {
    write_id(writer, exposure.exposure_id);
    write_enum(writer, exposure.kind);
    write_enum(writer, exposure.severity);
    write_maintenance_scope(writer, exposure.scope);
    write_instant(writer, exposure.start);
    write_instant(writer, exposure.end);
  }
}

PlacementRequest read_request_body(Reader& reader, std::vector<CandidatePlacement>& candidates) {
  PlacementRequest request;
  request.request_id = read_id<RequestId>(reader, "request");
  request.tenant = read_id<TenantId>(reader, "tenant");
  request.service_class = read_id<ServiceClassId>(reader, "service-class");
  request.requested_at = read_instant(reader, "requested-at");
  request.generations.topology = read_counter<TopologyGenerationTag>(reader, "topology-generation");
  request.generations.failure_domain =
      read_counter<FailureDomainGenerationTag>(reader, "failure-domain-generation");
  request.generations.tenant = read_counter<TenantGenerationTag>(reader, "tenant-generation");
  request.generations.service_class =
      read_counter<ServiceClassGenerationTag>(reader, "service-class-generation");
  const std::uint32_t facilities = reader.count(kMaxSetEntries, "request facilities");
  request.facilities.reserve(facilities);
  for (std::uint32_t index = 0; index < facilities && reader.ok(); ++index) {
    request.facilities.push_back(read_facility_record(reader));
  }
  const std::uint32_t candidate_count = reader.count(kMaxCandidatesPerRequest, "request candidates");
  candidates.reserve(candidate_count);
  for (std::uint32_t index = 0; index < candidate_count && reader.ok(); ++index) {
    CandidatePlacement candidate;
    candidate.candidate_id = read_id<CandidateId>(reader, "candidate");
    candidate.location = read_location(reader);
    candidates.push_back(std::move(candidate));
  }
  request.occupancy.generation =
      read_optional_counter<OccupancyGenerationTag>(reader, "occupancy-generation");
  const std::uint32_t instances = reader.count(kMaxPlacedInstances, "occupancy instances");
  request.occupancy.instances.reserve(instances);
  for (std::uint32_t index = 0; index < instances && reader.ok(); ++index) {
    PlacedInstance instance;
    instance.placement_id = read_id<PlacementId>(reader, "placement");
    instance.tenant = read_id<TenantId>(reader, "tenant");
    instance.service_class = read_id<ServiceClassId>(reader, "service-class");
    instance.location = read_location(reader);
    request.occupancy.instances.push_back(std::move(instance));
  }
  request.maintenance.generation =
      read_optional_counter<MaintenanceGenerationTag>(reader, "maintenance-generation");
  const std::uint32_t exposures = reader.count(kMaxMaintenanceExposures, "maintenance exposures");
  request.maintenance.exposures.reserve(exposures);
  for (std::uint32_t index = 0; index < exposures && reader.ok(); ++index) {
    MaintenanceExposure exposure;
    exposure.exposure_id = read_id<ExposureId>(reader, "exposure");
    exposure.kind = read_enum<MaintenanceKind>(reader, 2u, "maintenance-kind");
    exposure.severity = read_enum<MaintenanceSeverity>(reader, 2u, "maintenance-severity");
    exposure.scope = read_maintenance_scope(reader);
    exposure.start = read_instant(reader, "exposure start");
    exposure.end = read_instant(reader, "exposure end");
    request.maintenance.exposures.push_back(std::move(exposure));
  }
  return request;
}

// ---------------------------------------------------------------------------
// Verdicts
// ---------------------------------------------------------------------------

void write_binding(Writer& writer, const PolicyBinding& binding) {
  write_id(writer, binding.policy_id);
  write_counter(writer, binding.revision);
  write_digest(writer, binding.digest);
}

PolicyBinding read_binding(Reader& reader) {
  PolicyBinding binding;
  binding.policy_id = read_id<PolicyId>(reader, "policy");
  binding.revision = read_counter<PolicyRevisionTag>(reader, "policy-revision");
  binding.digest = read_digest(reader);
  return binding;
}

void write_generations(Writer& writer, const EvidenceGenerations& generations) {
  write_counter(writer, generations.topology);
  write_counter(writer, generations.failure_domain);
  write_counter(writer, generations.tenant);
  write_counter(writer, generations.service_class);
}

EvidenceGenerations read_generations(Reader& reader) {
  EvidenceGenerations generations;
  generations.topology = read_counter<TopologyGenerationTag>(reader, "topology-generation");
  generations.failure_domain =
      read_counter<FailureDomainGenerationTag>(reader, "failure-domain-generation");
  generations.tenant = read_counter<TenantGenerationTag>(reader, "tenant-generation");
  generations.service_class =
      read_counter<ServiceClassGenerationTag>(reader, "service-class-generation");
  return generations;
}

void write_candidate_verdict(Writer& writer, const CandidateVerdict& verdict,
                             bool include_identity_fields) {
  write_id(writer, verdict.candidate_id);
  write_enum(writer, verdict.decision);
  writer.u32(static_cast<std::uint32_t>(verdict.violations.size()));
  for (const Violation& violation : verdict.violations) {
    write_id(writer, violation.rule_id);
    write_enum(writer, violation.constraint_kind);
    writer.u32(violation.constraint_index);
    write_enum(writer, violation.code);
    writer.blob(violation.detail);
    write_optional_id(writer, violation.waived_by);
  }
  writer.u32(static_cast<std::uint32_t>(verdict.applied_rules.size()));
  for (const RuleId& id : verdict.applied_rules) {
    write_id(writer, id);
  }
  writer.u32(static_cast<std::uint32_t>(verdict.not_applicable_rules.size()));
  for (const RuleId& id : verdict.not_applicable_rules) {
    write_id(writer, id);
  }
  writer.boolean(verdict.constrained);
  writer.boolean(verdict.override_use.has_value());
  if (verdict.override_use.has_value()) {
    write_id(writer, verdict.override_use->envelope_id);
    write_id(writer, verdict.override_use->principal);
    write_id(writer, verdict.override_use->usage_id);
    write_digest(writer, verdict.override_use->grant_digest);
    writer.u32(verdict.override_use->waived_count);
  }
  write_digest(writer, verdict.evidence_digest);
  if (include_identity_fields) {
    write_digest(writer, verdict.verdict_digest);
    writer.boolean(verdict.replayed);
  }
}

CandidateVerdict read_candidate_verdict_body(Reader& reader, bool include_identity_fields) {
  CandidateVerdict verdict;
  verdict.candidate_id = read_id<CandidateId>(reader, "candidate");
  verdict.decision = read_enum<Decision>(reader, 1u, "decision");
  const std::uint32_t violations = reader.count(kMaxViolationsPerVerdict, "verdict violations");
  verdict.violations.reserve(violations);
  for (std::uint32_t index = 0; index < violations && reader.ok(); ++index) {
    Violation violation;
    violation.rule_id = read_id<RuleId>(reader, "rule");
    violation.constraint_kind = read_enum<ConstraintKind>(reader, 6u, "constraint-kind");
    violation.constraint_index = reader.u32();
    violation.code = read_enum<ViolationCode>(reader, 15u, "violation");
    violation.detail = read_utf8_text(reader, kMaxTextBytes, "violation detail");
    violation.waived_by = read_optional_id<EnvelopeId>(reader, "envelope");
    verdict.violations.push_back(std::move(violation));
  }
  const std::uint32_t applied = reader.count(kMaxRulesPerPolicy, "applied rules");
  verdict.applied_rules.reserve(applied);
  for (std::uint32_t index = 0; index < applied && reader.ok(); ++index) {
    verdict.applied_rules.push_back(read_id<RuleId>(reader, "rule"));
  }
  const std::uint32_t not_applicable = reader.count(kMaxRulesPerPolicy, "not applicable rules");
  verdict.not_applicable_rules.reserve(not_applicable);
  for (std::uint32_t index = 0; index < not_applicable && reader.ok(); ++index) {
    verdict.not_applicable_rules.push_back(read_id<RuleId>(reader, "rule"));
  }
  verdict.constrained = reader.boolean();
  if (reader.flag()) {
    OverrideUse use;
    use.envelope_id = read_id<EnvelopeId>(reader, "envelope");
    use.principal = read_id<PrincipalId>(reader, "principal");
    use.usage_id = read_id<UsageId>(reader, "usage");
    use.grant_digest = read_digest(reader);
    use.waived_count = reader.u32();
    verdict.override_use = std::move(use);
  }
  verdict.evidence_digest = read_digest(reader);
  if (include_identity_fields) {
    verdict.verdict_digest = read_digest(reader);
    verdict.replayed = reader.boolean();
  }
  return verdict;
}

void write_verdict_set(Writer& writer, const PlacementVerdictSet& verdicts) {
  writer.u32(kPayloadFormatVersion);
  write_id(writer, verdicts.request_id);
  write_binding(writer, verdicts.policy);
  write_counter(writer, verdicts.authority_epoch);
  write_generations(writer, verdicts.generations);
  write_optional_counter(writer, verdicts.occupancy_generation);
  write_optional_counter(writer, verdicts.maintenance_generation);
  write_instant(writer, verdicts.evaluated_at);
  write_digest(writer, verdicts.request_digest);
  writer.u32(static_cast<std::uint32_t>(verdicts.candidates.size()));
  for (const CandidateVerdict& candidate : verdicts.candidates) {
    write_candidate_verdict(writer, candidate, true);
  }
  writer.boolean(verdicts.replayed);
}

PlacementVerdictSet read_verdict_set(Reader& reader) {
  PlacementVerdictSet verdicts;
  const std::uint32_t version = reader.u32();
  if (version != kPayloadFormatVersion) {
    reader.fail(Error(ErrorCode::UnsupportedFormatVersion, "verdict payload version is not supported")
                    .with_detail("version=" + std::to_string(version)));
    return verdicts;
  }
  verdicts.request_id = read_id<RequestId>(reader, "request");
  verdicts.policy = read_binding(reader);
  verdicts.authority_epoch = read_counter<AuthorityEpochTag>(reader, "authority-epoch");
  verdicts.generations = read_generations(reader);
  verdicts.occupancy_generation =
      read_optional_counter<OccupancyGenerationTag>(reader, "occupancy-generation");
  verdicts.maintenance_generation =
      read_optional_counter<MaintenanceGenerationTag>(reader, "maintenance-generation");
  verdicts.evaluated_at = read_instant(reader, "evaluated-at");
  verdicts.request_digest = read_digest(reader);
  const std::uint32_t candidates = reader.count(kMaxCandidatesPerRequest, "verdict candidates");
  verdicts.candidates.reserve(candidates);
  for (std::uint32_t index = 0; index < candidates && reader.ok(); ++index) {
    verdicts.candidates.push_back(read_candidate_verdict_body(reader, true));
  }
  verdicts.replayed = reader.boolean();
  return verdicts;
}

// ---------------------------------------------------------------------------
// Grants
// ---------------------------------------------------------------------------

void write_grant_body(Writer& writer, const OverrideGrant& grant, bool include_digest) {
  write_id(writer, grant.envelope_id);
  write_digest(writer, grant.envelope_digest);
  write_id(writer, grant.principal);
  write_id(writer, grant.usage_id);
  write_binding(writer, grant.policy);
  write_counter(writer, grant.authority_epoch);
  write_id(writer, grant.tenant);
  write_id(writer, grant.service_class);
  write_id(writer, grant.facility);
  write_instant(writer, grant.issued_at);
  write_instant(writer, grant.expires_at);
  if (include_digest) {
    write_digest(writer, grant.grant_digest);
  }
}

OverrideGrant read_grant(Reader& reader) {
  OverrideGrant grant;
  grant.envelope_id = read_id<EnvelopeId>(reader, "envelope");
  grant.envelope_digest = read_digest(reader);
  grant.principal = read_id<PrincipalId>(reader, "principal");
  grant.usage_id = read_id<UsageId>(reader, "usage");
  grant.policy = read_binding(reader);
  grant.authority_epoch = read_counter<AuthorityEpochTag>(reader, "authority-epoch");
  grant.tenant = read_id<TenantId>(reader, "tenant");
  grant.service_class = read_id<ServiceClassId>(reader, "service-class");
  grant.facility = read_id<FacilityId>(reader, "facility");
  grant.issued_at = read_instant(reader, "issued-at");
  grant.expires_at = read_instant(reader, "expires-at");
  grant.grant_digest = read_digest(reader);
  return grant;
}

// ---------------------------------------------------------------------------
// Durable records
// ---------------------------------------------------------------------------

void write_record_ref(Writer& writer, const RecordRef& ref) {
  write_digest(writer, ref.digest);
  writer.u64(ref.bytes);
}

RecordRef read_record_ref(Reader& reader) {
  RecordRef ref;
  ref.digest = read_digest(reader);
  ref.bytes = reader.u64();
  return ref;
}

void write_retained_policy(Writer& writer, const RetainedPolicy& retained) {
  write_counter(writer, retained.revision);
  write_id(writer, retained.policy_id);
  write_record_ref(writer, retained.record);
}

RetainedPolicy read_retained_policy(Reader& reader) {
  RetainedPolicy retained;
  retained.revision = read_counter<PolicyRevisionTag>(reader, "policy-revision");
  retained.policy_id = read_id<PolicyId>(reader, "policy");
  retained.record = read_record_ref(reader);
  return retained;
}


// ---------------------------------------------------------------------------
// Manifest, ledger and evaluation payloads
// ---------------------------------------------------------------------------

void write_manifest_body(internal::Writer& writer, const ManifestRecord& manifest) {
  writer.u32(kPayloadFormatVersion);
  write_id(writer, manifest.store_id);
  write_counter(writer, manifest.sequence);
  write_counter(writer, manifest.authority_epoch);
  writer.boolean(manifest.has_active_policy);
  if (manifest.has_active_policy) {
    write_binding(writer, manifest.policy);
    write_retained_policy(writer, manifest.active);
    writer.u32(static_cast<std::uint32_t>(manifest.retained.size()));
    for (const RetainedPolicy& retained : manifest.retained) {
      write_retained_policy(writer, retained);
    }
  }
  write_record_ref(writer, manifest.ledger);
  internal::write_maybe_counter(writer, manifest.topology_floor);
  internal::write_maybe_counter(writer, manifest.failure_domain_floor);
  write_instant(writer, manifest.created_at);
  write_instant(writer, manifest.last_commit_at);
}

ManifestRecord read_manifest_body(internal::Reader& reader) {
  ManifestRecord manifest;
  const std::uint32_t version = reader.u32();
  if (version != kPayloadFormatVersion) {
    reader.fail(Error(ErrorCode::UnsupportedFormatVersion, "manifest payload version is not supported")
                    .with_detail("version=" + std::to_string(version)));
    return manifest;
  }
  manifest.store_id = read_id<StoreId>(reader, "store");
  manifest.sequence = read_counter<StoreSequenceTag>(reader, "store-sequence");
  manifest.authority_epoch = read_counter<AuthorityEpochTag>(reader, "authority-epoch");
  manifest.has_active_policy = reader.flag();
  if (manifest.has_active_policy) {
    manifest.policy = read_binding(reader);
    manifest.active = read_retained_policy(reader);
    const std::uint32_t retained = reader.count(kMaxRetainedPolicyRevisions, "retained policies");
    manifest.retained.reserve(retained);
    for (std::uint32_t index = 0; index < retained && reader.ok(); ++index) {
      manifest.retained.push_back(read_retained_policy(reader));
    }
  }
  manifest.ledger = read_record_ref(reader);
  manifest.topology_floor =
      internal::read_maybe_counter<TopologyGenerationTag>(reader, "topology-generation");
  manifest.failure_domain_floor =
      internal::read_maybe_counter<FailureDomainGenerationTag>(reader, "failure-domain-generation");
  manifest.created_at = read_instant(reader, "created-at");
  manifest.last_commit_at = read_instant(reader, "last-commit-at");
  return manifest;
}

void write_ledger_body(internal::Writer& writer, const LedgerRecord& ledger) {
  writer.u32(kPayloadFormatVersion);
  write_counter(writer, ledger.sequence);
  writer.u32(static_cast<std::uint32_t>(ledger.usage_counters.size()));
  for (const EnvelopeUsageCounter& counter : ledger.usage_counters) {
    write_id(writer, counter.envelope_id);
    writer.u32(counter.uses);
  }
  writer.u32(static_cast<std::uint32_t>(ledger.usage_records.size()));
  for (const OverrideUsageRecord& record : ledger.usage_records) {
    write_grant_body(writer, record.grant, true);
  }
  writer.u32(static_cast<std::uint32_t>(ledger.evaluations.size()));
  for (const RecordedEvaluationIndex& index : ledger.evaluations) {
    write_id(writer, index.request_id);
    write_digest(writer, index.request_digest);
    write_record_ref(writer, index.record);
    write_instant(writer, index.recorded_at);
  }
}

LedgerRecord read_ledger_body(internal::Reader& reader) {
  LedgerRecord ledger;
  const std::uint32_t version = reader.u32();
  if (version != kPayloadFormatVersion) {
    reader.fail(Error(ErrorCode::UnsupportedFormatVersion, "ledger payload version is not supported")
                    .with_detail("version=" + std::to_string(version)));
    return ledger;
  }
  ledger.sequence = read_counter<StoreSequenceTag>(reader, "store-sequence");
  const std::uint32_t counters = reader.count(kMaxSetEntries, "ledger usage counters");
  ledger.usage_counters.reserve(counters);
  for (std::uint32_t index = 0; index < counters && reader.ok(); ++index) {
    EnvelopeUsageCounter counter;
    counter.envelope_id = read_id<EnvelopeId>(reader, "envelope");
    counter.uses = reader.u32();
    ledger.usage_counters.push_back(std::move(counter));
  }
  const std::uint32_t records = reader.count(kMaxUsageRecords, "ledger usage records");
  ledger.usage_records.reserve(records);
  for (std::uint32_t index = 0; index < records && reader.ok(); ++index) {
    OverrideUsageRecord record;
    record.grant = read_grant(reader);
    ledger.usage_records.push_back(std::move(record));
  }
  const std::uint32_t evaluations = reader.count(kMaxEvaluationRecords, "ledger evaluations");
  ledger.evaluations.reserve(evaluations);
  for (std::uint32_t index = 0; index < evaluations && reader.ok(); ++index) {
    RecordedEvaluationIndex entry;
    entry.request_id = read_id<RequestId>(reader, "request");
    entry.request_digest = read_digest(reader);
    entry.record = read_record_ref(reader);
    entry.recorded_at = read_instant(reader, "recorded-at");
    ledger.evaluations.push_back(std::move(entry));
  }
  return ledger;
}

bool constraint_less(const Constraint& lhs, const Constraint& rhs) {
  return constraint_text(lhs) < constraint_text(rhs);
}

Digest digest_of_buffer(const ByteBuffer& buffer) noexcept {
  return digest_of(std::string_view(reinterpret_cast<const char*>(buffer.data()), buffer.size()));
}

}  // namespace

// ---------------------------------------------------------------------------
// Framing
// ---------------------------------------------------------------------------

Result<ByteBuffer> frame_record(std::uint64_t magic, std::span<const std::uint8_t> payload) {
  if (payload.size() > kMaxRecordBytes) {
    return Error(ErrorCode::LimitExceeded, "record payload exceeds the maximum size")
        .with_detail("limit=" + std::to_string(kMaxRecordBytes) +
                     " actual=" + std::to_string(payload.size()));
  }
  ByteBuffer out;
  out.reserve(kRecordFrameOverhead + payload.size());
  internal::Writer writer;
  writer.u64(magic);
  writer.u32(kStoreFormatVersion);
  writer.u32(0u);
  writer.u32(0u);
  writer.u64(static_cast<std::uint64_t>(payload.size()));
  writer.bytes(payload);
  const std::uint32_t checksum =
      crc32c(std::string_view(reinterpret_cast<const char*>(payload.data()), payload.size()));
  writer.u32(checksum);
  out = writer.take();
  const Digest digest = digest_of_buffer(out);
  out.insert(out.end(), digest.begin(), digest.end());
  return out;
}

Digest framed_record_digest(std::span<const std::uint8_t> bytes) noexcept {
  if (bytes.size() < kDigestBytes) {
    return Digest{};
  }
  return digest_of(std::string_view(reinterpret_cast<const char*>(bytes.data()),
                                    bytes.size() - kDigestBytes));
}

Result<FramedRecord> unframe_record(std::span<const std::uint8_t> bytes) {
  if (bytes.size() < kRecordFrameOverhead) {
    return Error(ErrorCode::TruncatedInput, "record is shorter than the frame overhead")
        .with_detail("bytes=" + std::to_string(bytes.size()));
  }
  internal::Reader reader(bytes);
  FramedRecord record;
  record.magic = reader.u64();
  record.format_version = reader.u32();
  const std::uint32_t kind = reader.u32();
  const std::uint32_t reserved = reader.u32();
  const std::uint64_t payload_bytes = reader.u64();
  if (!reader.ok()) {
    return reader.error();
  }

  const bool known_magic = record.magic == kManifestMagic || record.magic == kPolicyRecordMagic ||
                           record.magic == kLedgerRecordMagic ||
                           record.magic == kGrantRecordMagic ||
                           record.magic == kEvaluationRecordMagic;
  if (!known_magic) {
    return Error(ErrorCode::ManifestCorrupt, "record does not start with a known magic number")
        .with_detail("magic=" + std::to_string(record.magic));
  }
  if (record.format_version != kStoreFormatVersion) {
    return Error(ErrorCode::UnsupportedFormatVersion, "record format version is not supported")
        .with_detail("version=" + std::to_string(record.format_version));
  }
  if (kind != 0u || reserved != 0u) {
    return Error(ErrorCode::ReservedFieldNotZero,
                 "a reserved record field is not zero, so this reader does not understand the "
                 "record")
        .with_detail("kind=" + std::to_string(kind) + " reserved=" + std::to_string(reserved));
  }
  if (payload_bytes > kMaxRecordBytes) {
    return Error(ErrorCode::LimitExceeded, "record declares a payload larger than the limit")
        .with_detail("declared=" + std::to_string(payload_bytes) +
                     " limit=" + std::to_string(kMaxRecordBytes));
  }
  const std::uint64_t expected = kRecordFrameOverhead + payload_bytes;
  if (bytes.size() != expected) {
    return Error(bytes.size() < expected ? ErrorCode::TruncatedInput : ErrorCode::TrailingContent,
                 "record length does not match the length it declares")
        .with_detail("declared=" + std::to_string(expected) +
                     " actual=" + std::to_string(bytes.size()));
  }

  const auto payload = bytes.subspan(kRecordHeaderBytes, static_cast<std::size_t>(payload_bytes));
  const std::size_t checksum_offset =
      kRecordHeaderBytes + static_cast<std::size_t>(payload_bytes);
  const std::uint32_t stored_checksum =
      static_cast<std::uint32_t>(bytes[checksum_offset]) |
      (static_cast<std::uint32_t>(bytes[checksum_offset + 1]) << 8) |
      (static_cast<std::uint32_t>(bytes[checksum_offset + 2]) << 16) |
      (static_cast<std::uint32_t>(bytes[checksum_offset + 3]) << 24);
  const std::uint32_t computed_checksum =
      crc32c(std::string_view(reinterpret_cast<const char*>(payload.data()), payload.size()));
  if (stored_checksum != computed_checksum) {
    return Error(ErrorCode::ChecksumMismatch, "record checksum does not match its payload")
        .with_detail("stored=" + std::to_string(stored_checksum) +
                     " computed=" + std::to_string(computed_checksum));
  }

  Digest stored_digest{};
  for (std::size_t index = 0; index < stored_digest.size(); ++index) {
    stored_digest[index] = bytes[bytes.size() - stored_digest.size() + index];
  }
  const Digest computed_digest = framed_record_digest(bytes);
  if (!digest_equal(stored_digest, computed_digest)) {
    return Error(ErrorCode::DigestMismatch, "record digest does not match its contents");
  }

  record.payload.assign(payload.begin(), payload.end());
  record.digest = stored_digest;
  return record;
}

// ---------------------------------------------------------------------------
// Public codecs
// ---------------------------------------------------------------------------

Result<ByteBuffer> encode_policy(const PolicyDocument& document) {
  internal::Writer writer;
  write_policy(writer, document);
  return writer.take();
}

Result<PolicyDocument> decode_policy(std::span<const std::uint8_t> bytes) {
  internal::Reader reader(bytes);
  PolicyDocument document = read_policy(reader);
  const auto finished = reader.finish("policy");
  if (!finished.has_value()) {
    return finished.error();
  }
  // The digest is derived, not stored: a document never gets to assert its own
  // identity, and a decoded document is always exactly as canonical as an
  // encoded one.
  document.digest = digest_of(std::string_view(reinterpret_cast<const char*>(bytes.data()),
                                               bytes.size()));
  return document;
}

Result<ByteBuffer> encode_request(const PlacementRequest& request) {
  internal::Writer writer;
  writer.u32(kPayloadFormatVersion);
  write_request_body(writer, request, request.candidates);
  return writer.take();
}

Result<PlacementRequest> decode_request(std::span<const std::uint8_t> bytes) {
  internal::Reader reader(bytes);
  const std::uint32_t version = reader.u32();
  if (version != kPayloadFormatVersion) {
    reader.fail(Error(ErrorCode::UnsupportedFormatVersion, "request payload version is not supported")
                    .with_detail("version=" + std::to_string(version)));
  }
  std::vector<CandidatePlacement> candidates;
  PlacementRequest request = read_request_body(reader, candidates);
  request.candidates = std::move(candidates);
  const auto finished = reader.finish("request");
  if (!finished.has_value()) {
    return finished.error();
  }
  return request;
}

Result<ByteBuffer> encode_verdict_set(const PlacementVerdictSet& verdicts) {
  internal::Writer writer;
  write_verdict_set(writer, verdicts);
  return writer.take();
}

Result<PlacementVerdictSet> decode_verdict_set(std::span<const std::uint8_t> bytes) {
  internal::Reader reader(bytes);
  PlacementVerdictSet verdicts = read_verdict_set(reader);
  const auto finished = reader.finish("verdict-set");
  if (!finished.has_value()) {
    return finished.error();
  }
  return verdicts;
}

Result<ByteBuffer> encode_candidate_verdict(const CandidateVerdict& verdict) {
  internal::Writer writer;
  write_candidate_verdict(writer, verdict, true);
  return writer.take();
}

Result<CandidateVerdict> decode_candidate_verdict(std::span<const std::uint8_t> bytes) {
  internal::Reader reader(bytes);
  CandidateVerdict verdict = read_candidate_verdict_body(reader, true);
  const auto finished = reader.finish("candidate-verdict");
  if (!finished.has_value()) {
    return finished.error();
  }
  return verdict;
}

Result<ByteBuffer> encode_grant(const OverrideGrant& grant) {
  internal::Writer writer;
  write_grant_body(writer, grant, true);
  return writer.take();
}

Result<OverrideGrant> decode_grant(std::span<const std::uint8_t> bytes) {
  internal::Reader reader(bytes);
  OverrideGrant grant = read_grant(reader);
  const auto finished = reader.finish("grant");
  if (!finished.has_value()) {
    return finished.error();
  }
  return grant;
}

Result<ByteBuffer> encode_envelope(const OverrideEnvelope& envelope) {
  internal::Writer writer;
  write_envelope(writer, envelope);
  return writer.take();
}

Result<ByteBuffer> encode_manifest(const ManifestRecord& manifest) {
  internal::Writer writer;
  write_manifest_body(writer, manifest);
  return writer.take();
}

Result<ManifestRecord> decode_manifest(std::span<const std::uint8_t> bytes) {
  internal::Reader reader(bytes);
  ManifestRecord manifest = read_manifest_body(reader);
  const auto finished = reader.finish("manifest");
  if (!finished.has_value()) {
    return finished.error();
  }
  return manifest;
}

Result<ByteBuffer> encode_ledger(const LedgerRecord& ledger) {
  internal::Writer writer;
  write_ledger_body(writer, ledger);
  return writer.take();
}

Result<LedgerRecord> decode_ledger(std::span<const std::uint8_t> bytes) {
  internal::Reader reader(bytes);
  LedgerRecord ledger = read_ledger_body(reader);
  const auto finished = reader.finish("ledger");
  if (!finished.has_value()) {
    return finished.error();
  }
  return ledger;
}

Result<ByteBuffer> encode_evaluation_payload(const RecordedEvaluationPayload& payload) {
  internal::Writer writer;
  write_verdict_set(writer, payload.verdicts);
  return writer.take();
}

Result<RecordedEvaluationPayload> decode_evaluation_payload(std::span<const std::uint8_t> bytes) {
  internal::Reader reader(bytes);
  RecordedEvaluationPayload payload;
  payload.verdicts = read_verdict_set(reader);
  const auto finished = reader.finish("evaluation-payload");
  if (!finished.has_value()) {
    return finished.error();
  }
  return payload;
}

// ---------------------------------------------------------------------------
// Digests
// ---------------------------------------------------------------------------

Digest envelope_digest(const OverrideEnvelope& envelope) {
  internal::Writer writer;
  write_envelope(writer, envelope);
  return digest_of_buffer(writer.buffer());
}

Digest compute_grant_digest(const OverrideGrant& grant) {
  internal::Writer writer;
  write_grant_body(writer, grant, false);
  return digest_of_buffer(writer.buffer());
}

Digest compute_verdict_digest(const CandidateVerdict& verdict) {
  internal::Writer writer;
  write_candidate_verdict(writer, verdict, false);
  return digest_of_buffer(writer.buffer());
}

Digest compute_watermark_digest(TopologyGeneration topology, FailureDomainGeneration failure_domain) {
  internal::Writer writer;
  writer.u32(kPayloadFormatVersion);
  write_counter(writer, topology);
  write_counter(writer, failure_domain);
  return digest_of_buffer(writer.buffer());
}

Digest request_digest(const PlacementRequest& request) {
  internal::Writer writer;
  writer.u32(kPayloadFormatVersion);
  write_request_body(writer, request, request.candidates);
  return digest_of_buffer(writer.buffer());
}

Digest candidate_evidence_digest(const PlacementRequest& request,
                                 const CandidatePlacement& candidate) {
  internal::Writer writer;
  writer.u32(kPayloadFormatVersion);
  const std::span<const CandidatePlacement> single(&candidate, 1);
  write_request_body(writer, request, single);
  return digest_of_buffer(writer.buffer());
}

// ---------------------------------------------------------------------------
// Canonicalisation
// ---------------------------------------------------------------------------

Result<PolicyDocument> canonicalize_policy(PolicyDocument document) {
  // Bounds are checked on the document as it was written. Canonicalisation folds
  // semantically identical constraints together, so checking afterwards would
  // let a rule with more constraints than the limit pass by repeating one.
  const auto shape_before_sorting = validate_policy_shape(document);
  if (!shape_before_sorting.has_value()) {
    return shape_before_sorting.error();
  }

  for (Rule& rule : document.rules) {
    internal::sort_unique(rule.selector.tenants);
    internal::sort_unique(rule.selector.service_classes);
    internal::sort_unique(rule.selector.facilities);
    internal::sort_unique(rule.selector.jurisdictions);
    for (Constraint& constraint : rule.constraints) {
      std::visit(
          [](auto& concrete) {
            using Concrete = std::decay_t<decltype(concrete)>;
            if constexpr (std::is_same_v<Concrete, JurisdictionConstraint>) {
              internal::sort_unique(concrete.allow);
              internal::sort_unique(concrete.deny);
            } else if constexpr (std::is_same_v<Concrete, SeparationConstraint>) {
              internal::sort_unique(concrete.allow, [](const DimensionIdentity& lhs,
                                                       const DimensionIdentity& rhs) {
                return dimension_identity_text(lhs) < dimension_identity_text(rhs);
              });
              internal::sort_unique(concrete.deny, [](const DimensionIdentity& lhs,
                                                      const DimensionIdentity& rhs) {
                return dimension_identity_text(lhs) < dimension_identity_text(rhs);
              });
            } else if constexpr (std::is_same_v<Concrete, CoTenancyConstraint>) {
              internal::sort_unique(concrete.forbidden_tenants);
              internal::sort_unique(concrete.forbidden_service_classes);
            } else {
              static_cast<void>(concrete);
            }
          },
          constraint);
    }
    internal::sort_unique(rule.constraints, constraint_less);
  }
  // Rules and envelopes are sorted but never folded: two rules with the same
  // identity are an error the author has to see, not a duplicate to drop.
  std::sort(document.rules.begin(), document.rules.end(),
            [](const Rule& lhs, const Rule& rhs) { return lhs.rule_id < rhs.rule_id; });
  for (OverrideEnvelope& envelope : document.envelopes) {
    internal::sort_unique(envelope.scope.tenants);
    internal::sort_unique(envelope.scope.service_classes);
    internal::sort_unique(envelope.scope.facilities);
    internal::sort_unique(envelope.scope.jurisdictions);
    internal::sort_unique(envelope.allowed_constraints);
    internal::sort_unique(envelope.authorized_principals);
  }
  std::sort(document.envelopes.begin(), document.envelopes.end(),
            [](const OverrideEnvelope& lhs, const OverrideEnvelope& rhs) {
              return lhs.envelope_id < rhs.envelope_id;
            });

  const auto shape = validate_policy_shape(document);
  if (!shape.has_value()) {
    return shape.error();
  }
  const auto encoded = encode_policy(document);
  if (!encoded.has_value()) {
    return encoded.error();
  }
  document.digest = digest_of_buffer(encoded.value());
  return document;
}

Result<void> validate_canonical_policy(const PolicyDocument& document) {
  const auto shape = validate_policy_shape(document);
  if (!shape.has_value()) {
    return shape.error();
  }
  if (!internal::is_strictly_increasing(
          document.rules,
          [](const Rule& lhs, const Rule& rhs) { return lhs.rule_id < rhs.rule_id; })) {
    return Error(ErrorCode::MalformedDocument, "policy rules are not in canonical order");
  }
  for (const Rule& rule : document.rules) {
    if (!internal::is_strictly_increasing(rule.selector.tenants) ||
        !internal::is_strictly_increasing(rule.selector.service_classes) ||
        !internal::is_strictly_increasing(rule.selector.facilities) ||
        !internal::is_strictly_increasing(rule.selector.jurisdictions)) {
      return Error(ErrorCode::MalformedDocument, "a rule selector is not in canonical order")
          .with_detail("rule=" + std::string(rule.rule_id.value()));
    }
    if (!internal::is_strictly_increasing(rule.constraints, constraint_less)) {
      return Error(ErrorCode::MalformedDocument, "rule constraints are not in canonical order")
          .with_detail("rule=" + std::string(rule.rule_id.value()));
    }
  }
  if (!internal::is_strictly_increasing(
          document.envelopes, [](const OverrideEnvelope& lhs, const OverrideEnvelope& rhs) {
            return lhs.envelope_id < rhs.envelope_id;
          })) {
    return Error(ErrorCode::MalformedDocument, "policy envelopes are not in canonical order");
  }
  for (const OverrideEnvelope& envelope : document.envelopes) {
    if (!internal::is_strictly_increasing(envelope.allowed_constraints) ||
        !internal::is_strictly_increasing(envelope.authorized_principals)) {
      return Error(ErrorCode::MalformedDocument,
                   "an envelope's constraint kinds or principals are not in canonical order")
          .with_detail("envelope=" + std::string(envelope.envelope_id.value()));
    }
  }

  const auto encoded = encode_policy(document);
  if (!encoded.has_value()) {
    return encoded.error();
  }
  const Digest computed = digest_of_buffer(encoded.value());
  if (!digest_equal(computed, document.digest)) {
    return Error(ErrorCode::DigestMismatch, "policy digest does not match its contents")
        .with_detail("stored=" + digest_hex(document.digest) +
                     " computed=" + digest_hex(computed));
  }
  return success;
}

}  // namespace dccp::facility_placement_policy
