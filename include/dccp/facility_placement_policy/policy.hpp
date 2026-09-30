// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs.

#ifndef DCCP_FACILITY_PLACEMENT_POLICY_POLICY_HPP
#define DCCP_FACILITY_PLACEMENT_POLICY_POLICY_HPP

#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <variant>
#include <vector>

#include "dccp/facility_placement_policy/digest.hpp"
#include "dccp/facility_placement_policy/facility.hpp"
#include "dccp/facility_placement_policy/generation.hpp"
#include "dccp/facility_placement_policy/limits.hpp"
#include "dccp/facility_placement_policy/result.hpp"
#include "dccp/facility_placement_policy/strong_id.hpp"
#include "dccp/facility_placement_policy/time.hpp"

/// The policy model.
///
/// A policy is a set of rules. A rule applies to a candidate when its selector
/// matches, and it is satisfied when every one of its constraints holds. The
/// constraints of every applicable rule are conjoined, so a policy can only ever
/// narrow placement: there is no rule form that broadens, exempts or ranks. Two
/// rules that demand incompatible things make every affected candidate
/// ineligible, which is the intended fail-closed outcome.
///
/// Ordering is not part of the semantics. Rules are canonicalised by identity
/// and constraints by kind and content, so two documents that differ only in the
/// order in which they were written have the same digest and the same meaning.
namespace dccp::facility_placement_policy {

/// The closed set of constraint kinds.
enum class ConstraintKind : std::uint8_t {
  JurisdictionMembership = 0,
  FacilityAttribute = 1,
  Separation = 2,
  AntiAffinity = 3,
  Redundancy = 4,
  CoTenancy = 5,
  MaintenanceExposure = 6,
};

inline constexpr std::array<std::pair<ConstraintKind, std::string_view>, 7>
    kConstraintKindTokens = {{{ConstraintKind::JurisdictionMembership, "jurisdiction"},
                              {ConstraintKind::FacilityAttribute, "facility-attribute"},
                              {ConstraintKind::Separation, "separation"},
                              {ConstraintKind::AntiAffinity, "anti-affinity"},
                              {ConstraintKind::Redundancy, "redundancy"},
                              {ConstraintKind::CoTenancy, "co-tenancy"},
                              {ConstraintKind::MaintenanceExposure, "maintenance-exposure"}}};

constexpr std::string_view constraint_kind_name(ConstraintKind value) noexcept {
  return enum_token(kConstraintKindTokens, value);
}

inline Result<ConstraintKind> parse_constraint_kind(std::string_view text) {
  return enum_from_token(kConstraintKindTokens, text, "constraint");
}

/// A hard interlock is a constraint whose violation can never be waived by an
/// override, at any authority level, under any policy.
///
/// The set is fixed in code and reflects what an exception must not be able to
/// buy: physical containment (a shared failure domain), life-safety and
/// availability (an active maintenance blackout) and legal placement
/// (jurisdiction). A policy that tries to make one of these overridable is
/// rejected when it is loaded, not silently narrowed.
bool constraint_kind_is_hard_interlock(ConstraintKind kind) noexcept;

/// Every hard interlock kind, in canonical order.
const std::vector<ConstraintKind>& hard_interlock_kinds();

/// Jurisdiction membership. A candidate whose jurisdiction is unknown violates
/// this constraint; a policy that wants to permit an unknown jurisdiction must
/// say so by leaving the constraint out, which is a visible authoring decision.
struct JurisdictionConstraint {
  /// Sorted, unique. Empty means "no allow-list restriction".
  std::vector<JurisdictionId> allow;
  /// Sorted, unique. Empty means "no deny-list restriction".
  std::vector<JurisdictionId> deny;
};

/// How a typed attribute value is compared.
enum class AttributeOperator : std::uint8_t {
  Equal = 0,
  NotEqual = 1,
  AtLeast = 2,
  AtMost = 3,
  Present = 4,
  Absent = 5,
};

inline constexpr std::array<std::pair<AttributeOperator, std::string_view>, 6>
    kAttributeOperatorTokens = {{{AttributeOperator::Equal, "equal"},
                                 {AttributeOperator::NotEqual, "not-equal"},
                                 {AttributeOperator::AtLeast, "at-least"},
                                 {AttributeOperator::AtMost, "at-most"},
                                 {AttributeOperator::Present, "present"},
                                 {AttributeOperator::Absent, "absent"}}};

constexpr std::string_view attribute_operator_name(AttributeOperator value) noexcept {
  return enum_token(kAttributeOperatorTokens, value);
}

inline Result<AttributeOperator> parse_attribute_operator(std::string_view text) {
  return enum_from_token(kAttributeOperatorTokens, text, "operator");
}

/// A typed predicate over one facility attribute.
struct FacilityAttributeConstraint {
  FacilityAttributeKey key = FacilityAttributeKey::PowerFeedCount;
  AttributeOperator op = AttributeOperator::Present;
  /// Required for Equal, NotEqual, AtLeast and AtMost; forbidden for Present and
  /// Absent, which are about the presence of the attribute rather than its value.
  std::optional<AttributeValue> operand;
};

/// Membership in an explicit allow/deny set of identities for one dimension, for
/// example "only these racks" or "never this power domain". This is separate
/// from anti-affinity, which reasons about what already exists.
struct SeparationConstraint {
  DimensionSelector dimension;
  /// Sorted, unique. Empty means "no allow-list restriction".
  std::vector<DimensionIdentity> allow;
  /// Sorted, unique. Empty means "no deny-list restriction".
  std::vector<DimensionIdentity> deny;
};

/// Separation from placements that already exist.
struct AntiAffinityConstraint {
  PlacementScopeKind scope = PlacementScopeKind::Tenant;
  DimensionSelector dimension;
  /// The greatest number of existing in-scope placements that may share the
  /// candidate's identity in this dimension. Zero is the classic anti-affinity
  /// requirement: nothing else in scope may share the dimension at all.
  std::uint32_t max_shared = 0;
};

/// Distinctness across a dimension, counting the candidate and the existing
/// in-scope placements together.
struct RedundancyConstraint {
  PlacementScopeKind scope = PlacementScopeKind::Tenant;
  DimensionSelector dimension;
  /// At least one. The number of distinct identities in the dimension that the
  /// in-scope placements plus the candidate must span.
  std::uint32_t min_distinct_domains = 0;
};

/// Sharing with named tenants or service classes.
struct CoTenancyConstraint {
  /// Sorted, unique. Empty means no tenant is named by this constraint.
  std::vector<TenantId> forbidden_tenants;
  /// Sorted, unique. Empty means no service class is named.
  std::vector<ServiceClassId> forbidden_service_classes;
  DimensionSelector dimension;
  /// The greatest number of forbidden in-scope placements that may share the
  /// candidate's identity in this dimension.
  std::uint32_t max_shared = 0;
};

/// Exposure to published maintenance over a lookahead horizon.
struct MaintenanceConstraint {
  /// An exposure blocks the candidate when its severity is at least this great.
  /// Blackout is always included, whatever the threshold.
  MaintenanceSeverity minimum_blocking_severity = MaintenanceSeverity::Degraded;
  /// The lookahead window, measured from the evaluation instant. Must be greater
  /// than zero and no longer than a year.
  Duration horizon = Duration::zero();
};

/// A constraint is exactly one of the kinds above. The alternative order of the
/// variant is the enumerator order of ConstraintKind and is checked by the test
/// suite, so the kind of a constraint is its variant index.
using Constraint =
    std::variant<JurisdictionConstraint, FacilityAttributeConstraint, SeparationConstraint,
                 AntiAffinityConstraint, RedundancyConstraint, CoTenancyConstraint,
                 MaintenanceConstraint>;

constexpr std::size_t kConstraintKindCount = 7;

static_assert(std::variant_size_v<Constraint> == kConstraintKindCount,
              "every constraint kind needs exactly one alternative");

constexpr ConstraintKind constraint_kind_of(const Constraint& constraint) noexcept {
  return static_cast<ConstraintKind>(constraint.index());
}

/// Validates one constraint on its own terms: operand presence and type, set
/// emptiness, mutually exclusive fields, contradictory memberships.
Result<void> validate_constraint(const Constraint& constraint);

/// Renders a constraint in the canonical text form, for diagnostics and for the
/// canonical document.
std::string constraint_text(const Constraint& constraint);

/// Which candidates a rule applies to. Every field that is set must agree with
/// the candidate for the rule to apply. An empty field is not a restriction.
struct RuleSelector {
  /// Sorted, unique.
  std::vector<TenantId> tenants;
  /// Sorted, unique.
  std::vector<ServiceClassId> service_classes;
  /// Sorted, unique.
  std::vector<FacilityId> facilities;
  /// Sorted, unique. Matched against the candidate facility's jurisdiction; a
  /// facility whose jurisdiction is unknown matches no jurisdiction selector.
  std::vector<JurisdictionId> jurisdictions;

  bool is_empty() const noexcept;
};

/// True when the selector applies to a candidate in this context.
bool rule_selector_matches(const RuleSelector& selector, const TenantId& tenant,
                           const ServiceClassId& service_class, const FacilityId& facility,
                           const std::optional<JurisdictionId>& jurisdiction) noexcept;

/// A requirement. A rule is satisfied when every constraint holds.
struct Rule {
  RuleId rule_id;
  RuleSelector selector;
  /// Optional human-readable note. Bounded, validated UTF-8, and part of the
  /// canonical digest: a policy's explanation is part of its identity.
  std::string description;
  /// At least one. A rule that requires nothing is rejected, because it would
  /// make an unconstrained policy look constrained.
  std::vector<Constraint> constraints;
};

/// Default and maximum lifetime of a granted exception.
inline constexpr Duration kMinGrantValidity = Duration::from_microseconds(1000000);
inline constexpr Duration kMaxGrantValidity = Duration::from_microseconds(86400000000);

/// A policy-authored exception envelope.
///
/// The envelope is the *authority*; a grant is an *exercise* of it, issued by the
/// runtime for one scope, one principal and a bounded lifetime, and recorded in
/// durable state so that its use count cannot be reduced by a restart or a
/// replayed request.
struct OverrideEnvelope {
  EnvelopeId envelope_id;
  /// Which requests the envelope covers. Must not be empty: an envelope that
  /// covers everything is not a scoped exception.
  RuleSelector scope;
  /// At least one kind. Hard interlocks are rejected here when the policy is
  /// validated; a policy may narrow what an override reaches, never widen it.
  std::vector<ConstraintKind> allowed_constraints;
  /// At least one. Sorted, unique.
  std::vector<PrincipalId> authorized_principals;
  /// Between one and kMaxOverrideUses.
  std::uint32_t max_uses = 0;
  /// Between kMinGrantValidity and kMaxGrantValidity.
  Duration grant_validity = Duration::zero();
  /// When set, grants may not be issued before this instant.
  Instant not_before;
  /// When set, grants may not be issued at or after this instant.
  Instant expires_at;
};

/// A canonical policy revision.
struct PolicyDocument {
  PolicyId policy_id;
  PolicyRevision revision;
  /// At least one rule. Sorted by rule identity.
  std::vector<Rule> rules;
  /// Sorted by envelope identity.
  std::vector<OverrideEnvelope> envelopes;
  /// SHA-256 of the canonical encoding of every field above. Computed by
  /// canonicalize_policy() and recomputed by the decoder; never parsed from
  /// input, because a document must not be able to assert its own identity.
  Digest digest{};
};

/// The identity of the policy revision a decision was made under.
struct PolicyBinding {
  PolicyId policy_id;
  PolicyRevision revision;
  Digest digest;
};

/// Sorts every set and every list into canonical order, validates the document,
/// and computes its digest. The input is taken by value because canonicalisation
/// rewrites it.
Result<PolicyDocument> canonicalize_policy(PolicyDocument document);

/// Validates an already canonical document, including the digest it carries.
/// Used when reading durable state, where a document that is not canonical is a
/// corruption rather than a formatting difference.
Result<void> validate_canonical_policy(const PolicyDocument& document);

/// Structural validation that does not depend on canonical order.
Result<void> validate_policy_shape(const PolicyDocument& document);

/// Finds an envelope by identity.
const OverrideEnvelope* find_envelope(const PolicyDocument& document,
                                      const EnvelopeId& envelope_id) noexcept;

/// Finds a rule by identity.
const Rule* find_rule(const PolicyDocument& document, const RuleId& rule_id) noexcept;

/// True when the rule's selector applies to a candidate in this context.
bool rule_applies(const Rule& rule, const TenantId& tenant, const ServiceClassId& service_class,
                  const FacilityId& facility,
                  const std::optional<JurisdictionId>& jurisdiction) noexcept;

}  // namespace dccp::facility_placement_policy

#endif  // DCCP_FACILITY_PLACEMENT_POLICY_POLICY_HPP
