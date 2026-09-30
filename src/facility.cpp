// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs.

#include "dccp/facility_placement_policy/facility.hpp"

#include <string>
#include <type_traits>
#include <variant>

#include "internal_util.hpp"

namespace dccp::facility_placement_policy {

AttributeValueKind attribute_value_kind(FacilityAttributeKey key) noexcept {
  switch (key) {
    case FacilityAttributeKey::PowerFeedCount:
      return AttributeValueKind::Unsigned;
    case FacilityAttributeKey::PowerRedundancy:
      return AttributeValueKind::Redundancy;
    case FacilityAttributeKey::CoolingMode:
      return AttributeValueKind::CoolingMode;
    case FacilityAttributeKey::CoolingRedundancy:
      return AttributeValueKind::Redundancy;
    case FacilityAttributeKey::FloorLoadKgPerM2:
      return AttributeValueKind::Unsigned;
    case FacilityAttributeKey::RackWeightLimitKg:
      return AttributeValueKind::Unsigned;
    case FacilityAttributeKey::SecurityTier:
      return AttributeValueKind::Unsigned;
    case FacilityAttributeKey::FireSuppression:
      return AttributeValueKind::FireSuppression;
    case FacilityAttributeKey::NetworkIsolation:
      return AttributeValueKind::NetworkIsolation;
    case FacilityAttributeKey::EnvironmentalControl:
      return AttributeValueKind::EnvironmentalControl;
    case FacilityAttributeKey::CommissionedAt:
      return AttributeValueKind::Instant;
    case FacilityAttributeKey::DecommissionScheduledAt:
      return AttributeValueKind::Instant;
  }
  return AttributeValueKind::Unsigned;
}

bool attribute_value_matches(FacilityAttributeKey key, const AttributeValue& value) noexcept {
  switch (attribute_value_kind(key)) {
    case AttributeValueKind::Unsigned:
      return std::holds_alternative<std::uint32_t>(value);
    case AttributeValueKind::Instant:
      return std::holds_alternative<Instant>(value);
    case AttributeValueKind::Redundancy:
      return std::holds_alternative<RedundancyClass>(value);
    case AttributeValueKind::CoolingMode:
      return std::holds_alternative<CoolingModeClass>(value);
    case AttributeValueKind::FireSuppression:
      return std::holds_alternative<FireSuppressionClass>(value);
    case AttributeValueKind::NetworkIsolation:
      return std::holds_alternative<NetworkIsolationClass>(value);
    case AttributeValueKind::EnvironmentalControl:
      return std::holds_alternative<EnvironmentalControlClass>(value);
  }
  return false;
}

std::string attribute_value_text(const AttributeValue& value) {
  return std::visit(
      [](const auto& concrete) -> std::string {
        using Concrete = std::decay_t<decltype(concrete)>;
        if constexpr (std::is_same_v<Concrete, std::uint32_t>) {
          return std::to_string(concrete);
        } else if constexpr (std::is_same_v<Concrete, Instant>) {
          return concrete.to_string();
        } else if constexpr (std::is_same_v<Concrete, RedundancyClass>) {
          return std::string(redundancy_class_name(concrete));
        } else if constexpr (std::is_same_v<Concrete, CoolingModeClass>) {
          return std::string(cooling_mode_name(concrete));
        } else if constexpr (std::is_same_v<Concrete, FireSuppressionClass>) {
          return std::string(fire_suppression_name(concrete));
        } else if constexpr (std::is_same_v<Concrete, NetworkIsolationClass>) {
          return std::string(network_isolation_name(concrete));
        } else {
          return std::string(environmental_control_name(concrete));
        }
      },
      value);
}

std::string attribute_text(FacilityAttributeKey key, const AttributeValue& value) {
  std::string out(facility_attribute_key_name(key));
  out.push_back('=');
  out.append(attribute_value_text(value));
  return out;
}

const AttributeValue* FacilityRecord::attribute(FacilityAttributeKey key) const noexcept {
  for (const auto& entry : attributes) {
    if (entry.first == key) {
      return &entry.second;
    }
  }
  return nullptr;
}

Result<void> validate_dimension_selector(const DimensionSelector& selector) {
  const bool is_failure_domain = selector.dimension == PlacementDimension::FailureDomain;
  if (is_failure_domain != selector.failure_domain_kind.has_value()) {
    return Error(ErrorCode::InvalidConstraintOperand,
                 "a failure-domain dimension needs a failure domain kind, and no other "
                 "dimension may carry one")
        .with_detail("dimension=" + std::string(placement_dimension_name(selector.dimension)));
  }
  return success;
}

std::string dimension_selector_name(const DimensionSelector& selector) {
  std::string out(placement_dimension_name(selector.dimension));
  if (selector.failure_domain_kind.has_value()) {
    out.push_back(':');
    out.append(failure_domain_kind_name(*selector.failure_domain_kind));
  }
  return out;
}

std::string_view dimension_identity_value(const DimensionIdentity& identity) noexcept {
  return std::visit([](const auto& id) -> std::string_view { return id.value(); }, identity);
}

std::string dimension_identity_text(const DimensionIdentity& identity) {
  std::string out(placement_dimension_name(dimension_of_identity(identity)));
  out.push_back(':');
  out.append(dimension_identity_value(identity));
  return out;
}

bool FacilityLocation::has_dimension(const DimensionSelector& selector) const noexcept {
  switch (selector.dimension) {
    case PlacementDimension::Site:
      return site.has_value();
    case PlacementDimension::Room:
      return room.has_value();
    case PlacementDimension::Row:
      return row.has_value();
    case PlacementDimension::Rack:
      return rack.has_value();
    case PlacementDimension::FailureDomain: {
      if (!selector.failure_domain_kind.has_value()) {
        return false;
      }
      for (const auto& entry : failure_domains) {
        if (entry.first == *selector.failure_domain_kind) {
          return true;
        }
      }
      return false;
    }
  }
  return false;
}

std::optional<std::string_view> FacilityLocation::dimension_identity(
    const DimensionSelector& selector) const noexcept {
  switch (selector.dimension) {
    case PlacementDimension::Site:
      return site.has_value() ? std::optional<std::string_view>(site->value()) : std::nullopt;
    case PlacementDimension::Room:
      return room.has_value() ? std::optional<std::string_view>(room->value()) : std::nullopt;
    case PlacementDimension::Row:
      return row.has_value() ? std::optional<std::string_view>(row->value()) : std::nullopt;
    case PlacementDimension::Rack:
      return rack.has_value() ? std::optional<std::string_view>(rack->value()) : std::nullopt;
    case PlacementDimension::FailureDomain: {
      if (!selector.failure_domain_kind.has_value()) {
        return std::nullopt;
      }
      for (const auto& entry : failure_domains) {
        if (entry.first == *selector.failure_domain_kind) {
          return std::optional<std::string_view>(entry.second.value());
        }
      }
      return std::nullopt;
    }
  }
  return std::nullopt;
}

bool MaintenanceScope::is_empty() const noexcept {
  return !facility.has_value() && !site.has_value() && !room.has_value() && !row.has_value() &&
         !rack.has_value() && !failure_domain_kind.has_value() && !failure_domain.has_value();
}

bool evidence_generations_complete(const EvidenceGenerations& generations) noexcept {
  return generations.topology.is_valid() && generations.failure_domain.is_valid() &&
         generations.tenant.is_valid() && generations.service_class.is_valid();
}

std::string_view first_absent_generation(const EvidenceGenerations& generations) noexcept {
  if (!generations.topology.is_valid()) {
    return "topology-generation";
  }
  if (!generations.failure_domain.is_valid()) {
    return "failure-domain-generation";
  }
  if (!generations.tenant.is_valid()) {
    return "tenant-generation";
  }
  if (!generations.service_class.is_valid()) {
    return "service-class-generation";
  }
  return {};
}

}  // namespace dccp::facility_placement_policy
