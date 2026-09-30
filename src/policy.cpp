// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs.

#include "dccp/facility_placement_policy/policy.hpp"

#include <algorithm>
#include <cstdint>
#include <string>
#include <string_view>
#include <type_traits>
#include <variant>
#include <vector>

#include "dccp/facility_placement_policy/text_util.hpp"
#include "internal_util.hpp"

namespace dccp::facility_placement_policy {
namespace {

using internal::intersection;
using internal::shares_any_element;

std::string identity_list_text(const std::vector<DimensionIdentity>& identities) {
  return internal::join(identities, [](const DimensionIdentity& identity) {
    return dimension_identity_text(identity);
  });
}

std::string identifier_list_text(const std::vector<JurisdictionId>& ids) {
  return internal::join(ids, [](const JurisdictionId& id) { return std::string(id.value()); });
}

bool same_dimension(const DimensionSelector& lhs, const DimensionSelector& rhs) noexcept {
  return lhs == rhs;
}

/// True when two dimension identities address the same place: same dimension
/// alternative and same value.
bool same_identity(const DimensionIdentity& lhs, const DimensionIdentity& rhs) noexcept {
  return dimension_of_identity(lhs) == dimension_of_identity(rhs) &&
         dimension_identity_value(lhs) == dimension_identity_value(rhs);
}

std::vector<DimensionIdentity> intersect_identities(std::vector<DimensionIdentity> lhs,
                                                    const std::vector<DimensionIdentity>& rhs) {
  std::vector<DimensionIdentity> out;
  for (const DimensionIdentity& candidate : lhs) {
    for (const DimensionIdentity& other : rhs) {
      if (same_identity(candidate, other)) {
        out.push_back(candidate);
        break;
      }
    }
  }
  return out;
}

/// An ordered comparison value, used only for contradiction detection.
struct OrderedValue {
  bool is_instant = false;
  std::int64_t value = 0;
};

bool ordered_values_equal(const OrderedValue& lhs, const OrderedValue& rhs) noexcept {
  return lhs.is_instant == rhs.is_instant && lhs.value == rhs.value;
}

bool ordered_value_less(const OrderedValue& lhs, const OrderedValue& rhs) noexcept {
  if (lhs.is_instant != rhs.is_instant) {
    return !lhs.is_instant;
  }
  return lhs.value < rhs.value;
}

OrderedValue ordered_from_attribute(const AttributeValue& value) {
  OrderedValue out;
  if (const auto* number = std::get_if<std::uint32_t>(&value)) {
    out.is_instant = false;
    out.value = static_cast<std::int64_t>(*number);
  } else {
    out.is_instant = true;
    out.value = std::get<Instant>(value).unix_micros();
  }
  return out;
}

bool is_ordered_attribute_key(FacilityAttributeKey key) noexcept {
  const AttributeValueKind kind = attribute_value_kind(key);
  return kind == AttributeValueKind::Unsigned || kind == AttributeValueKind::Instant;
}

/// Detects a rule that can never be satisfied because two of its attribute
/// predicates for the same key have no common satisfying value.
Result<void> detect_attribute_contradiction(const Rule& rule) {
  for (std::size_t first = 0; first < rule.constraints.size(); ++first) {
    const auto* left = std::get_if<FacilityAttributeConstraint>(&rule.constraints[first]);
    if (left == nullptr) {
      continue;
    }
    bool present_seen = false;
    bool absent_seen = false;
    bool has_lower = false;
    bool has_upper = false;
    OrderedValue lower;
    OrderedValue upper;
    std::vector<OrderedValue> excluded;
    std::vector<AttributeValue> equal_values;
    std::vector<AttributeValue> not_equal_values;

    for (const Constraint& constraint : rule.constraints) {
      const auto* predicate = std::get_if<FacilityAttributeConstraint>(&constraint);
      if (predicate == nullptr || predicate->key != left->key) {
        continue;
      }
      switch (predicate->op) {
        case AttributeOperator::Present:
          present_seen = true;
          break;
        case AttributeOperator::Absent:
          absent_seen = true;
          break;
        case AttributeOperator::Equal:
          equal_values.push_back(*predicate->operand);
          break;
        case AttributeOperator::NotEqual:
          if (is_ordered_attribute_key(predicate->key)) {
            excluded.push_back(ordered_from_attribute(*predicate->operand));
          } else {
            not_equal_values.push_back(*predicate->operand);
          }
          break;
        case AttributeOperator::AtLeast: {
          const OrderedValue bound = ordered_from_attribute(*predicate->operand);
          if (!has_lower || ordered_value_less(lower, bound)) {
            lower = bound;
          }
          has_lower = true;
          break;
        }
        case AttributeOperator::AtMost: {
          const OrderedValue bound = ordered_from_attribute(*predicate->operand);
          if (!has_upper || ordered_value_less(bound, upper)) {
            upper = bound;
          }
          has_upper = true;
          break;
        }
      }
    }

    if (present_seen && absent_seen) {
      return Error(ErrorCode::ContradictoryConstraint,
                   "a rule requires one facility attribute to be both present and absent")
          .with_detail(std::string("attribute=") + std::string(facility_attribute_key_name(left->key)));
    }

    if (is_ordered_attribute_key(left->key)) {
      if (has_lower && has_upper && ordered_value_less(upper, lower)) {
        return Error(ErrorCode::ContradictoryConstraint,
                     "a rule requires one facility attribute to be at least a value and at "
                     "most a smaller one")
            .with_detail(std::string("attribute=") +
                         std::string(facility_attribute_key_name(left->key)));
      }
      for (const OrderedValue& value : excluded) {
        if (has_lower && ordered_value_less(value, lower)) {
          continue;
        }
        if (has_upper && ordered_value_less(upper, value)) {
          continue;
        }
        // The excluded value is inside the permitted interval. It is only a
        // contradiction when the interval holds nothing else.
        if (has_lower && has_upper && ordered_values_equal(lower, upper) &&
            ordered_values_equal(lower, value)) {
          return Error(ErrorCode::ContradictoryConstraint,
                       "a rule permits exactly one facility attribute value and excludes it")
              .with_detail(std::string("attribute=") +
                           std::string(facility_attribute_key_name(left->key)));
        }
      }
    } else {
      // Enum-valued keys only support equality, so two different required values
      // can never both hold.
      for (std::size_t index = 0; index < equal_values.size(); ++index) {
        for (std::size_t other = index + 1; other < equal_values.size(); ++other) {
          if (equal_values[index] != equal_values[other]) {
            return Error(ErrorCode::ContradictoryConstraint,
                         "a rule requires two different values of the same facility attribute")
                .with_detail(std::string("attribute=") +
                             std::string(facility_attribute_key_name(left->key)));
          }
        }
      }
      bool demanded = false;
      std::string demanded_value;
      for (const Constraint& constraint : rule.constraints) {
        const auto* predicate = std::get_if<FacilityAttributeConstraint>(&constraint);
        if (predicate == nullptr || predicate->key != left->key ||
            predicate->op != AttributeOperator::Equal) {
          continue;
        }
        demanded = true;
        demanded_value = attribute_value_text(*predicate->operand);
      }
      if (demanded) {
        for (const AttributeValue& excluded_value : not_equal_values) {
          if (attribute_value_text(excluded_value) == demanded_value) {
            return Error(ErrorCode::ContradictoryConstraint,
                         "a rule requires a facility attribute value and excludes the same value")
                .with_detail(std::string("attribute=") +
                             std::string(facility_attribute_key_name(left->key)));
          }
        }
      }
    }
  }
  return success;
}

/// Detects separation constraints on one dimension whose allow-lists have an
/// empty intersection: no candidate can satisfy both, so the rule is dead.
Result<void> detect_separation_contradiction(const Rule& rule) {
  for (std::size_t index = 0; index < rule.constraints.size(); ++index) {
    const auto* left = std::get_if<SeparationConstraint>(&rule.constraints[index]);
    if (left == nullptr || left->allow.empty()) {
      continue;
    }
    std::vector<DimensionIdentity> running = left->allow;
    for (std::size_t other = index + 1; other < rule.constraints.size(); ++other) {
      const auto* right = std::get_if<SeparationConstraint>(&rule.constraints[other]);
      if (right == nullptr || right->allow.empty() ||
          !same_dimension(left->dimension, right->dimension)) {
        continue;
      }
      running = intersect_identities(running, right->allow);
      if (running.empty()) {
        return Error(ErrorCode::ContradictoryConstraint,
                     "a rule allows disjoint sets of identities for the same dimension, so no "
                     "candidate can satisfy it")
            .with_detail("dimension=" + dimension_selector_name(left->dimension));
      }
    }
  }
  return success;
}

Result<void> detect_rule_contradictions(const Rule& rule) {
  for (const Constraint& constraint : rule.constraints) {
    const auto* jurisdiction = std::get_if<JurisdictionConstraint>(&constraint);
    if (jurisdiction != nullptr && shares_any_element(jurisdiction->allow, jurisdiction->deny)) {
      return Error(ErrorCode::ContradictoryConstraint,
                   "a rule allows and denies the same jurisdiction")
          .with_detail("rule=" + std::string(rule.rule_id.value()));
    }
    const auto* separation = std::get_if<SeparationConstraint>(&constraint);
    if (separation != nullptr) {
      std::vector<DimensionIdentity> overlap;
      for (const DimensionIdentity& allowed : separation->allow) {
        for (const DimensionIdentity& denied : separation->deny) {
          if (same_identity(allowed, denied)) {
            overlap.push_back(allowed);
          }
        }
      }
      if (!overlap.empty()) {
        return Error(ErrorCode::ContradictoryConstraint,
                     "a rule allows and denies the same identity")
            .with_detail("dimension=" + dimension_selector_name(separation->dimension) +
                         " identity=" + dimension_identity_text(overlap.front()));
      }
    }
  }

  const auto attribute_result = detect_attribute_contradiction(rule);
  if (!attribute_result.has_value()) {
    return attribute_result.error();
  }
  return detect_separation_contradiction(rule);
}

Result<void> validate_attribute_constraint(const FacilityAttributeConstraint& constraint) {
  const bool needs_operand = constraint.op == AttributeOperator::Equal ||
                             constraint.op == AttributeOperator::NotEqual ||
                             constraint.op == AttributeOperator::AtLeast ||
                             constraint.op == AttributeOperator::AtMost;
  if (needs_operand != constraint.operand.has_value()) {
    return Error(ErrorCode::InvalidConstraintOperand,
                 needs_operand ? "this operator needs an operand"
                               : "presence operators take no operand")
        .with_detail(std::string("attribute=") +
                     std::string(facility_attribute_key_name(constraint.key)));
  }
  if (!needs_operand) {
    return success;
  }
  if (!attribute_value_matches(constraint.key, *constraint.operand)) {
    return Error(ErrorCode::InvalidAttributeValue,
                 "the operand type does not match the attribute key")
        .with_detail(std::string("attribute=") +
                     std::string(facility_attribute_key_name(constraint.key)) + " value=" +
                     attribute_value_text(*constraint.operand));
  }
  const bool ordered_operator = constraint.op == AttributeOperator::AtLeast ||
                                constraint.op == AttributeOperator::AtMost;
  if (ordered_operator && !is_ordered_attribute_key(constraint.key)) {
    return Error(ErrorCode::InvalidOperatorForKey,
                 "at-least and at-most are only meaningful for numeric or instant attributes")
        .with_detail(std::string("attribute=") +
                     std::string(facility_attribute_key_name(constraint.key)));
  }
  return success;
}

Result<void> validate_separation_constraint(const SeparationConstraint& constraint) {
  const auto selector_result = validate_dimension_selector(constraint.dimension);
  if (!selector_result.has_value()) {
    return selector_result.error();
  }
  if (constraint.allow.empty() && constraint.deny.empty()) {
    return Error(ErrorCode::InvalidConstraintOperand,
                 "a separation constraint must allow or deny at least one identity")
        .with_detail("dimension=" + dimension_selector_name(constraint.dimension));
  }
  for (const DimensionIdentity& identity : constraint.allow) {
    if (dimension_of_identity(identity) != constraint.dimension.dimension) {
      return Error(ErrorCode::InvalidConstraintOperand,
                   "an allow-list identity belongs to a different dimension than the constraint")
          .with_detail("dimension=" + dimension_selector_name(constraint.dimension) +
                       " identity=" + dimension_identity_text(identity));
    }
  }
  for (const DimensionIdentity& identity : constraint.deny) {
    if (dimension_of_identity(identity) != constraint.dimension.dimension) {
      return Error(ErrorCode::InvalidConstraintOperand,
                   "a deny-list identity belongs to a different dimension than the constraint")
          .with_detail("dimension=" + dimension_selector_name(constraint.dimension) +
                       " identity=" + dimension_identity_text(identity));
    }
  }
  return success;
}

}  // namespace

bool constraint_kind_is_hard_interlock(ConstraintKind kind) noexcept {
  switch (kind) {
    case ConstraintKind::JurisdictionMembership:
    case ConstraintKind::Separation:
    case ConstraintKind::MaintenanceExposure:
      return true;
    case ConstraintKind::FacilityAttribute:
    case ConstraintKind::AntiAffinity:
    case ConstraintKind::Redundancy:
    case ConstraintKind::CoTenancy:
      return false;
  }
  return true;
}

const std::vector<ConstraintKind>& hard_interlock_kinds() {
  static const std::vector<ConstraintKind> kinds = {
      ConstraintKind::JurisdictionMembership, ConstraintKind::Separation,
      ConstraintKind::MaintenanceExposure};
  return kinds;
}

Result<void> validate_constraint(const Constraint& constraint) {
  return std::visit(
      [](const auto& concrete) -> Result<void> {
        using Concrete = std::decay_t<decltype(concrete)>;
        if constexpr (std::is_same_v<Concrete, JurisdictionConstraint>) {
          if (concrete.allow.empty() && concrete.deny.empty()) {
            return Error(ErrorCode::InvalidConstraintOperand,
                         "a jurisdiction constraint must allow or deny at least one jurisdiction");
          }
          if (shares_any_element(concrete.allow, concrete.deny)) {
            return Error(ErrorCode::ContradictoryConstraint,
                         "a jurisdiction constraint allows and denies the same jurisdiction");
          }
          return success;
        } else if constexpr (std::is_same_v<Concrete, FacilityAttributeConstraint>) {
          return validate_attribute_constraint(concrete);
        } else if constexpr (std::is_same_v<Concrete, SeparationConstraint>) {
          return validate_separation_constraint(concrete);
        } else if constexpr (std::is_same_v<Concrete, AntiAffinityConstraint>) {
          return validate_dimension_selector(concrete.dimension);
        } else if constexpr (std::is_same_v<Concrete, RedundancyConstraint>) {
          const auto selector_result = validate_dimension_selector(concrete.dimension);
          if (!selector_result.has_value()) {
            return selector_result.error();
          }
          if (concrete.min_distinct_domains == 0u) {
            return Error(ErrorCode::InvalidConstraintOperand,
                         "a redundancy constraint must require at least one distinct domain");
          }
          return success;
        } else if constexpr (std::is_same_v<Concrete, CoTenancyConstraint>) {
          const auto selector_result = validate_dimension_selector(concrete.dimension);
          if (!selector_result.has_value()) {
            return selector_result.error();
          }
          if (concrete.forbidden_tenants.empty() &&
              concrete.forbidden_service_classes.empty()) {
            return Error(ErrorCode::InvalidConstraintOperand,
                         "a co-tenancy constraint must name a tenant or a service class");
          }
          return success;
        } else {
          if (concrete.horizon.microseconds() <= 0) {
            return Error(ErrorCode::InvalidConstraintOperand,
                         "a maintenance exposure horizon must be greater than zero");
          }
          if (concrete.horizon.microseconds() > 365LL * 86400LL * 1000000LL) {
            return Error(ErrorCode::InvalidConstraintOperand,
                         "a maintenance exposure horizon may not exceed one year");
          }
          if (concrete.minimum_blocking_severity > MaintenanceSeverity::Blackout) {
            return Error(ErrorCode::UnknownEnumToken,
                         "maintenance severity is outside the defined range");
          }
          return success;
        }
      },
      constraint);
}

bool RuleSelector::is_empty() const noexcept {
  return tenants.empty() && service_classes.empty() && facilities.empty() &&
         jurisdictions.empty();
}

bool rule_selector_matches(const RuleSelector& selector, const TenantId& tenant,
                           const ServiceClassId& service_class, const FacilityId& facility,
                           const std::optional<JurisdictionId>& jurisdiction) noexcept {
  if (!selector.tenants.empty() &&
      std::find(selector.tenants.begin(), selector.tenants.end(), tenant) ==
          selector.tenants.end()) {
    return false;
  }
  if (!selector.service_classes.empty() &&
      std::find(selector.service_classes.begin(), selector.service_classes.end(), service_class) ==
          selector.service_classes.end()) {
    return false;
  }
  if (!selector.facilities.empty() &&
      std::find(selector.facilities.begin(), selector.facilities.end(), facility) ==
          selector.facilities.end()) {
    return false;
  }
  if (!selector.jurisdictions.empty()) {
    if (!jurisdiction.has_value()) {
      return false;
    }
    if (std::find(selector.jurisdictions.begin(), selector.jurisdictions.end(), *jurisdiction) ==
        selector.jurisdictions.end()) {
      return false;
    }
  }
  return true;
}

bool rule_applies(const Rule& rule, const TenantId& tenant,
                  const ServiceClassId& service_class, const FacilityId& facility,
                  const std::optional<JurisdictionId>& jurisdiction) noexcept {
  return rule_selector_matches(rule.selector, tenant, service_class, facility, jurisdiction);
}

const OverrideEnvelope* find_envelope(const PolicyDocument& document,
                                      const EnvelopeId& envelope_id) noexcept {
  for (const OverrideEnvelope& envelope : document.envelopes) {
    if (envelope.envelope_id == envelope_id) {
      return &envelope;
    }
  }
  return nullptr;
}

const Rule* find_rule(const PolicyDocument& document, const RuleId& rule_id) noexcept {
  for (const Rule& rule : document.rules) {
    if (rule.rule_id == rule_id) {
      return &rule;
    }
  }
  return nullptr;
}

Result<void> validate_policy_shape(const PolicyDocument& document) {
  if (document.policy_id.empty()) {
    return Error(ErrorCode::MissingField, "a policy needs an identity");
  }
  if (!document.revision.is_valid()) {
    return Error(ErrorCode::MissingField, "a policy needs a revision greater than zero");
  }
  if (document.rules.empty()) {
    return Error(ErrorCode::EmptyPolicy,
                 "a policy with no rules constrains nothing and is refused rather than "
                 "treated as an allow-all");
  }
  if (document.rules.size() > kMaxRulesPerPolicy) {
    return Error(ErrorCode::LimitExceeded, "policy has more rules than the limit allows")
        .with_detail("limit=" + std::to_string(kMaxRulesPerPolicy) +
                     " actual=" + std::to_string(document.rules.size()));
  }
  if (document.envelopes.size() > kMaxEnvelopesPerPolicy) {
    return Error(ErrorCode::LimitExceeded, "policy has more envelopes than the limit allows")
        .with_detail("limit=" + std::to_string(kMaxEnvelopesPerPolicy) +
                     " actual=" + std::to_string(document.envelopes.size()));
  }

  for (std::size_t index = 0; index < document.rules.size(); ++index) {
    const Rule& rule = document.rules[index];
    if (rule.rule_id.empty()) {
      return Error(ErrorCode::MissingField, "a rule needs an identity");
    }
    for (std::size_t other = index + 1; other < document.rules.size(); ++other) {
      if (document.rules[other].rule_id == rule.rule_id) {
        return Error(ErrorCode::DuplicateRuleId, "two rules share an identity")
            .with_detail("rule=" + std::string(rule.rule_id.value()));
      }
    }
    const auto description_result =
        require_valid_utf8(rule.description, "rule description", kMaxTextBytes);
    if (!description_result.has_value()) {
      return description_result.error();
    }
    if (rule.constraints.empty()) {
      return Error(ErrorCode::RuleWithoutConstraints,
                   "a rule that requires nothing would make an unconstrained policy look "
                   "constrained")
          .with_detail("rule=" + std::string(rule.rule_id.value()));
    }
    if (rule.constraints.size() > kMaxConstraintsPerRule) {
      return Error(ErrorCode::LimitExceeded, "rule has more constraints than the limit allows")
          .with_detail("rule=" + std::string(rule.rule_id.value()) +
                       " limit=" + std::to_string(kMaxConstraintsPerRule));
    }
    if (rule.selector.tenants.size() > kMaxSelectorEntries ||
        rule.selector.service_classes.size() > kMaxSelectorEntries ||
        rule.selector.facilities.size() > kMaxSelectorEntries ||
        rule.selector.jurisdictions.size() > kMaxSelectorEntries) {
      return Error(ErrorCode::LimitExceeded, "rule selector has more entries than the limit allows")
          .with_detail("rule=" + std::string(rule.rule_id.value()) +
                       " limit=" + std::to_string(kMaxSelectorEntries));
    }
    for (const Constraint& constraint : rule.constraints) {
      const auto constraint_result = validate_constraint(constraint);
      if (!constraint_result.has_value()) {
        return constraint_result.error();
      }
    }
    const auto contradiction_result = detect_rule_contradictions(rule);
    if (!contradiction_result.has_value()) {
      return contradiction_result.error();
    }
  }

  for (std::size_t index = 0; index < document.envelopes.size(); ++index) {
    const OverrideEnvelope& envelope = document.envelopes[index];
    if (envelope.envelope_id.empty()) {
      return Error(ErrorCode::MissingField, "an override envelope needs an identity");
    }
    for (std::size_t other = index + 1; other < document.envelopes.size(); ++other) {
      if (document.envelopes[other].envelope_id == envelope.envelope_id) {
        return Error(ErrorCode::DuplicateEnvelopeId, "two envelopes share an identity")
            .with_detail("envelope=" + std::string(envelope.envelope_id.value()));
      }
    }
    if (envelope.scope.is_empty()) {
      return Error(ErrorCode::SelectorEmpty,
                   "an override envelope that covers every request is not a scoped exception")
          .with_detail("envelope=" + std::string(envelope.envelope_id.value()));
    }
    if (envelope.authorized_principals.empty()) {
      return Error(ErrorCode::EnvelopeWithoutPrincipals,
                   "an override envelope must name at least one authorised principal")
          .with_detail("envelope=" + std::string(envelope.envelope_id.value()));
    }
    if (envelope.allowed_constraints.empty()) {
      return Error(ErrorCode::EnvelopeWithoutConstraintKinds,
                   "an override envelope must name at least one constraint kind it may waive")
          .with_detail("envelope=" + std::string(envelope.envelope_id.value()));
    }
    for (const ConstraintKind kind : envelope.allowed_constraints) {
      if (constraint_kind_is_hard_interlock(kind)) {
        return Error(ErrorCode::HardInterlockNotOverridable,
                     "a hard interlock can never be waived by an override")
            .with_detail("envelope=" + std::string(envelope.envelope_id.value()) +
                         " constraint=" + std::string(constraint_kind_name(kind)));
      }
    }
    if (envelope.max_uses == 0u || envelope.max_uses > kMaxOverrideUses) {
      return Error(ErrorCode::InvalidConstraintOperand,
                   "an override envelope's use limit is outside the permitted range")
          .with_detail("envelope=" + std::string(envelope.envelope_id.value()) +
                       " limit=" + std::to_string(kMaxOverrideUses));
    }
    if (envelope.grant_validity < kMinGrantValidity ||
        envelope.grant_validity > kMaxGrantValidity) {
      return Error(ErrorCode::InvalidConstraintOperand,
                   "an override envelope's grant validity is outside the permitted range")
          .with_detail("envelope=" + std::string(envelope.envelope_id.value()) + " min=" +
                       kMinGrantValidity.to_string() + " max=" + kMaxGrantValidity.to_string());
    }
    if (envelope.not_before.is_set() && envelope.expires_at.is_set() &&
        !(envelope.not_before < envelope.expires_at)) {
      return Error(ErrorCode::InvalidEnvelopeWindow,
                   "an override envelope's window is empty or inverted")
          .with_detail("envelope=" + std::string(envelope.envelope_id.value()));
    }
  }
  return success;
}

std::string constraint_text(const Constraint& constraint) {
  return std::visit(
      [](const auto& concrete) -> std::string {
        using Concrete = std::decay_t<decltype(concrete)>;
        std::string out;
        if constexpr (std::is_same_v<Concrete, JurisdictionConstraint>) {
          out = "jurisdiction allow=";
          out.append(identifier_list_text(concrete.allow));
          out.append(" deny=");
          out.append(identifier_list_text(concrete.deny));
        } else if constexpr (std::is_same_v<Concrete, FacilityAttributeConstraint>) {
          out = "facility-attribute key=";
          out.append(facility_attribute_key_name(concrete.key));
          out.append(" op=");
          out.append(attribute_operator_name(concrete.op));
          out.append(" value=");
          if (concrete.operand.has_value()) {
            out.append(attribute_value_text(*concrete.operand));
          }
        } else if constexpr (std::is_same_v<Concrete, SeparationConstraint>) {
          out = "separation dimension=";
          out.append(dimension_selector_name(concrete.dimension));
          out.append(" allow=");
          out.append(identity_list_text(concrete.allow));
          out.append(" deny=");
          out.append(identity_list_text(concrete.deny));
        } else if constexpr (std::is_same_v<Concrete, AntiAffinityConstraint>) {
          out = "anti-affinity scope=";
          out.append(placement_scope_name(concrete.scope));
          out.append(" dimension=");
          out.append(dimension_selector_name(concrete.dimension));
          out.append(" max-shared=");
          out.append(std::to_string(concrete.max_shared));
        } else if constexpr (std::is_same_v<Concrete, RedundancyConstraint>) {
          out = "redundancy scope=";
          out.append(placement_scope_name(concrete.scope));
          out.append(" dimension=");
          out.append(dimension_selector_name(concrete.dimension));
          out.append(" min-distinct-domains=");
          out.append(std::to_string(concrete.min_distinct_domains));
        } else if constexpr (std::is_same_v<Concrete, CoTenancyConstraint>) {
          out = "co-tenancy dimension=";
          out.append(dimension_selector_name(concrete.dimension));
          out.append(" tenants=");
          out.append(internal::join(concrete.forbidden_tenants,
                                    [](const TenantId& id) { return std::string(id.value()); }));
          out.append(" service-classes=");
          out.append(internal::join(
              concrete.forbidden_service_classes,
              [](const ServiceClassId& id) { return std::string(id.value()); }));
          out.append(" max-shared=");
          out.append(std::to_string(concrete.max_shared));
        } else {
          out = "maintenance-exposure min-severity=";
          out.append(maintenance_severity_name(concrete.minimum_blocking_severity));
          out.append(" horizon=");
          out.append(concrete.horizon.to_string());
        }
        return out;
      },
      constraint);
}

}  // namespace dccp::facility_placement_policy
