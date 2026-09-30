// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs.

#include "dccp/facility_placement_policy/evaluate.hpp"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <variant>
#include <vector>

#include "dccp/facility_placement_policy/canonical.hpp"
#include "internal_util.hpp"

namespace dccp::facility_placement_policy {
namespace {

/// Detail strings are built from identifiers, enum tokens and numbers only, and
/// are capped, so a hostile document cannot inflate a verdict.
std::string bound_detail(std::string detail) {
  if (detail.size() > kMaxTextBytes) {
    detail.resize(kMaxTextBytes);
  }
  return detail;
}

std::string number_u32(std::uint32_t value) { return std::to_string(value); }

/// How a maintenance scope relates to a candidate.
enum class ScopeRelation : std::uint8_t {
  Applies = 0,       // the exposure covers this candidate
  DoesNotApply = 1,  // the exposure provably covers somewhere else
  Unverifiable = 2,  // the candidate does not declare enough to decide
};

ScopeRelation relate_scope(const MaintenanceScope& scope, const FacilityLocation& location) {
  bool unknown = false;
  if (scope.facility.has_value() && location.facility != *scope.facility) {
    return ScopeRelation::DoesNotApply;
  }
  const auto compare_optional = [&unknown](const auto& bound, const auto& actual) {
    if (!actual.has_value()) {
      unknown = true;
      return true;
    }
    return *bound == *actual;
  };
  if (scope.site.has_value() && !compare_optional(scope.site, location.site)) {
    return ScopeRelation::DoesNotApply;
  }
  if (scope.room.has_value() && !compare_optional(scope.room, location.room)) {
    return ScopeRelation::DoesNotApply;
  }
  if (scope.row.has_value() && !compare_optional(scope.row, location.row)) {
    return ScopeRelation::DoesNotApply;
  }
  if (scope.rack.has_value() && !compare_optional(scope.rack, location.rack)) {
    return ScopeRelation::DoesNotApply;
  }
  if (scope.failure_domain_kind.has_value() && scope.failure_domain.has_value()) {
    bool found = false;
    for (const auto& entry : location.failure_domains) {
      if (entry.first != *scope.failure_domain_kind) {
        continue;
      }
      found = true;
      if (!(entry.second == *scope.failure_domain)) {
        return ScopeRelation::DoesNotApply;
      }
    }
    if (!found) {
      unknown = true;
    }
  }
  return unknown ? ScopeRelation::Unverifiable : ScopeRelation::Applies;
}

bool in_scope(PlacementScopeKind scope, const PlacedInstance& instance,
              const PlacementRequest& request) noexcept {
  switch (scope) {
    case PlacementScopeKind::Any:
      return true;
    case PlacementScopeKind::Tenant:
      return instance.tenant == request.tenant;
    case PlacementScopeKind::ServiceClass:
      return instance.service_class == request.service_class;
  }
  return false;
}

/// A dimension observation about a location: either the identity, or the fact
/// that the location does not publish one.
struct DimensionObservation {
  bool known = false;
  std::string_view identity;
};

DimensionObservation observe_dimension(const FacilityLocation& location,
                                       const DimensionSelector& selector) noexcept {
  const auto identity = location.dimension_identity(selector);
  DimensionObservation observation;
  observation.known = identity.has_value();
  if (identity.has_value()) {
    observation.identity = *identity;
  }
  return observation;
}

bool identity_matches(const DimensionIdentity& listed, const DimensionSelector& selector,
                      std::string_view value) noexcept {
  return dimension_of_identity(listed) == selector.dimension &&
         dimension_identity_value(listed) == value;
}

struct ViolationDraft {
  ViolationCode code = ViolationCode::AntiAffinityExceeded;
  std::string detail;
};

using Check = std::optional<ViolationDraft>;

std::optional<ViolationDraft> check_jurisdiction(const JurisdictionConstraint& constraint,
                                                 const FacilityRecord& facility) {
  if (!facility.jurisdiction.has_value()) {
    return ViolationDraft{
        ViolationCode::JurisdictionUnknown,
        "facility=" + std::string(facility.facility.value()) +
            " has no published jurisdiction, so jurisdiction membership cannot be established"};
  }
  const JurisdictionId& jurisdiction = *facility.jurisdiction;
  if (std::find(constraint.deny.begin(), constraint.deny.end(), jurisdiction) !=
      constraint.deny.end()) {
    return ViolationDraft{ViolationCode::JurisdictionDenied,
                          "jurisdiction=" + std::string(jurisdiction.value()) + " is denied"};
  }
  if (!constraint.allow.empty() &&
      std::find(constraint.allow.begin(), constraint.allow.end(), jurisdiction) ==
          constraint.allow.end()) {
    return ViolationDraft{ViolationCode::JurisdictionNotAllowed,
                          "jurisdiction=" + std::string(jurisdiction.value()) +
                              " is not in the allow list"};
  }
  return std::nullopt;
}

bool ordered_compare(const AttributeValue& actual, const AttributeValue& operand, bool at_least) {
  if (const auto* left = std::get_if<std::uint32_t>(&actual)) {
    const auto* right = std::get_if<std::uint32_t>(&operand);
    if (right == nullptr) {
      return false;
    }
    return at_least ? (*left >= *right) : (*left <= *right);
  }
  const auto* left = std::get_if<Instant>(&actual);
  const auto* right = std::get_if<Instant>(&operand);
  if (left == nullptr || right == nullptr || !left->is_set() || !right->is_set()) {
    return false;
  }
  return at_least ? (left->unix_micros() >= right->unix_micros())
                  : (left->unix_micros() <= right->unix_micros());
}

std::optional<ViolationDraft> check_attribute(const FacilityAttributeConstraint& constraint,
                                              const FacilityRecord& facility) {
  const std::string key(facility_attribute_key_name(constraint.key));
  const AttributeValue* actual = facility.attribute(constraint.key);
  if (actual == nullptr) {
    if (constraint.op == AttributeOperator::Absent) {
      return std::nullopt;
    }
    return ViolationDraft{ViolationCode::AttributeUnmeasured,
                          "facility=" + std::string(facility.facility.value()) + " does not publish " +
                              key + ", so the requirement cannot be established"};
  }
  switch (constraint.op) {
    case AttributeOperator::Present:
      return std::nullopt;
    case AttributeOperator::Absent:
      return ViolationDraft{ViolationCode::AttributeUnsatisfied,
                            "facility=" + std::string(facility.facility.value()) + " publishes " +
                                key + "=" + attribute_value_text(*actual) +
                                " but the rule requires it to be absent"};
    case AttributeOperator::Equal:
      if (attribute_value_text(*actual) == attribute_value_text(*constraint.operand)) {
        return std::nullopt;
      }
      return ViolationDraft{ViolationCode::AttributeUnsatisfied,
                            key + "=" + attribute_value_text(*actual) + " is not equal to " +
                                attribute_value_text(*constraint.operand)};
    case AttributeOperator::NotEqual:
      if (attribute_value_text(*actual) != attribute_value_text(*constraint.operand)) {
        return std::nullopt;
      }
      return ViolationDraft{ViolationCode::AttributeUnsatisfied,
                            key + "=" + attribute_value_text(*actual) + " is excluded"};
    case AttributeOperator::AtLeast:
      if (ordered_compare(*actual, *constraint.operand, true)) {
        return std::nullopt;
      }
      return ViolationDraft{ViolationCode::AttributeUnsatisfied,
                            key + "=" + attribute_value_text(*actual) + " is below " +
                                attribute_value_text(*constraint.operand)};
    case AttributeOperator::AtMost:
      if (ordered_compare(*actual, *constraint.operand, false)) {
        return std::nullopt;
      }
      return ViolationDraft{ViolationCode::AttributeUnsatisfied,
                            key + "=" + attribute_value_text(*actual) + " is above " +
                                attribute_value_text(*constraint.operand)};
  }
  return std::nullopt;
}

std::optional<ViolationDraft> check_separation(const SeparationConstraint& constraint,
                                               const CandidatePlacement& candidate) {
  const auto identity = candidate.location.dimension_identity(constraint.dimension);
  const std::string dimension = dimension_selector_name(constraint.dimension);
  if (!identity.has_value()) {
    return ViolationDraft{ViolationCode::DimensionUnmeasured,
                          "candidate=" + std::string(candidate.candidate_id.value()) +
                              " does not declare " + dimension +
                              ", so membership cannot be established"};
  }
  for (const DimensionIdentity& denied : constraint.deny) {
    if (identity_matches(denied, constraint.dimension, *identity)) {
      return ViolationDraft{ViolationCode::SeparationDenied,
                            "candidate is in " + dimension + ":" + std::string(*identity) +
                                ", which the rule denies"};
    }
  }
  if (!constraint.allow.empty()) {
    bool allowed = false;
    for (const DimensionIdentity& listed : constraint.allow) {
      if (identity_matches(listed, constraint.dimension, *identity)) {
        allowed = true;
        break;
      }
    }
    if (!allowed) {
      return ViolationDraft{ViolationCode::SeparationNotAllowed,
                            "candidate is in " + dimension + ":" + std::string(*identity) +
                                ", which the rule does not allow"};
    }
  }
  return std::nullopt;
}

struct OccupancyScan {
  std::uint32_t shared = 0;
  std::uint32_t unverifiable = 0;
  std::vector<std::string_view> distinct;
};

/// Counts the in-scope placements that share the candidate's identity in the
/// dimension, the in-scope placements whose identity in that dimension is not
/// published, and the distinct identities in scope.
Result<OccupancyScan> scan_occupancy(const PlacementRequest& request,
                                     const DimensionSelector& selector,
                                     PlacementScopeKind scope,
                                     std::string_view candidate_identity) {
  OccupancyScan scan;
  const auto generation = request.occupancy.generation;
  if (!generation.has_value()) {
    return Error(ErrorCode::EvidenceGenerationAbsent, "no occupancy evidence was supplied");
  }
  for (const PlacedInstance& instance : request.occupancy.instances) {
    if (!in_scope(scope, instance, request)) {
      continue;
    }
    const DimensionObservation observation = observe_dimension(instance.location, selector);
    if (!observation.known) {
      ++scan.unverifiable;
      continue;
    }
    if (observation.identity == candidate_identity) {
      ++scan.shared;
    }
    bool seen = false;
    for (const std::string_view existing : scan.distinct) {
      if (existing == observation.identity) {
        seen = true;
        break;
      }
    }
    if (!seen) {
      scan.distinct.push_back(observation.identity);
    }
  }
  return scan;
}

std::optional<ViolationDraft> check_anti_affinity(const AntiAffinityConstraint& constraint,
                                                  const PlacementRequest& request,
                                                  const CandidatePlacement& candidate) {
  const DimensionObservation observation =
      observe_dimension(candidate.location, constraint.dimension);
  const std::string dimension = dimension_selector_name(constraint.dimension);
  if (!observation.known) {
    return ViolationDraft{ViolationCode::DimensionUnmeasured,
                          "candidate=" + std::string(candidate.candidate_id.value()) +
                              " does not declare " + dimension};
  }
  auto scan = scan_occupancy(request, constraint.dimension, constraint.scope, observation.identity);
  if (!scan.has_value()) {
    return ViolationDraft{ViolationCode::OccupancyEvidenceAbsent,
                          std::string(scan.error().message())};
  }
  if (scan->unverifiable > 0) {
    return ViolationDraft{
        ViolationCode::DimensionUnmeasured,
        number_u32(scan->unverifiable) + " in-scope placement(s) do not declare " + dimension +
            ", so separation from them cannot be established"};
  }
  if (scan->shared > constraint.max_shared) {
    return ViolationDraft{ViolationCode::AntiAffinityExceeded,
                          number_u32(scan->shared) + " in-scope placement(s) already share " +
                              dimension + ":" + std::string(observation.identity) +
                              " (limit " + number_u32(constraint.max_shared) + ")"};
  }
  return std::nullopt;
}

std::optional<ViolationDraft> check_redundancy(const RedundancyConstraint& constraint,
                                               const PlacementRequest& request,
                                               const CandidatePlacement& candidate) {
  const DimensionObservation observation =
      observe_dimension(candidate.location, constraint.dimension);
  const std::string dimension = dimension_selector_name(constraint.dimension);
  if (!observation.known) {
    return ViolationDraft{ViolationCode::DimensionUnmeasured,
                          "candidate=" + std::string(candidate.candidate_id.value()) +
                              " does not declare " + dimension};
  }
  auto scan = scan_occupancy(request, constraint.dimension, constraint.scope, observation.identity);
  if (!scan.has_value()) {
    return ViolationDraft{ViolationCode::OccupancyEvidenceAbsent,
                          std::string(scan.error().message())};
  }
  if (scan->unverifiable > 0) {
    return ViolationDraft{
        ViolationCode::DimensionUnmeasured,
        number_u32(scan->unverifiable) + " in-scope placement(s) do not declare " + dimension +
            ", so the spread across it cannot be established"};
  }
  std::uint32_t distinct = 1;  // the candidate itself
  for (const std::string_view identity : scan->distinct) {
    if (identity != observation.identity) {
      ++distinct;
    }
  }
  if (distinct < constraint.min_distinct_domains) {
    return ViolationDraft{
        ViolationCode::RedundancyUnsatisfied,
        "placement set would span " + number_u32(distinct) + " distinct " + dimension +
            " value(s), below the required " + number_u32(constraint.min_distinct_domains)};
  }
  return std::nullopt;
}

std::optional<ViolationDraft> check_co_tenancy(const CoTenancyConstraint& constraint,
                                               const PlacementRequest& request,
                                               const CandidatePlacement& candidate) {
  const DimensionObservation observation =
      observe_dimension(candidate.location, constraint.dimension);
  const std::string dimension = dimension_selector_name(constraint.dimension);
  if (!observation.known) {
    return ViolationDraft{ViolationCode::DimensionUnmeasured,
                          "candidate=" + std::string(candidate.candidate_id.value()) +
                              " does not declare " + dimension};
  }
  if (!request.occupancy.generation.has_value()) {
    return ViolationDraft{ViolationCode::OccupancyEvidenceAbsent,
                          "no occupancy evidence was supplied"};
  }
  std::uint32_t shared = 0;
  std::uint32_t unverifiable = 0;
  for (const PlacedInstance& instance : request.occupancy.instances) {
    const bool forbidden =
        std::find(constraint.forbidden_tenants.begin(), constraint.forbidden_tenants.end(),
                  instance.tenant) != constraint.forbidden_tenants.end() ||
        std::find(constraint.forbidden_service_classes.begin(),
                  constraint.forbidden_service_classes.end(),
                  instance.service_class) != constraint.forbidden_service_classes.end();
    if (!forbidden) {
      continue;
    }
    const DimensionObservation other = observe_dimension(instance.location, constraint.dimension);
    if (!other.known) {
      ++unverifiable;
      continue;
    }
    if (other.identity == observation.identity) {
      ++shared;
    }
  }
  if (unverifiable > 0u) {
    return ViolationDraft{
        ViolationCode::DimensionUnmeasured,
        number_u32(unverifiable) + " forbidden placement(s) do not declare " + dimension +
            ", so co-tenancy cannot be established"};
  }
  if (shared > constraint.max_shared) {
    return ViolationDraft{ViolationCode::CoTenancyExceeded,
                          number_u32(shared) + " forbidden placement(s) share " + dimension + ":" +
                              std::string(observation.identity) + " (limit " +
                              number_u32(constraint.max_shared) + ")"};
  }
  return std::nullopt;
}

Result<Check> check_maintenance(const MaintenanceConstraint& constraint,
                                const PlacementRequest& request,
                                const CandidatePlacement& candidate) {
  if (!request.maintenance.generation.has_value()) {
    return Check{ViolationDraft{
        ViolationCode::MaintenanceEvidenceAbsent,
        "the rule requires maintenance exposure to be considered and no maintenance evidence "
        "was supplied"}};
  }
  const auto horizon_end = checked_add(request.requested_at, constraint.horizon);
  if (!horizon_end.has_value()) {
    return horizon_end.error();
  }

  const MaintenanceExposure* worst = nullptr;
  bool unverifiable = false;
  const MaintenanceExposure* unverifiable_exposure = nullptr;
  for (const MaintenanceExposure& exposure : request.maintenance.exposures) {
    if (exposure.severity < constraint.minimum_blocking_severity) {
      continue;
    }
    // The exposure intersects the lookahead window [requested_at, horizon_end).
    if (!(exposure.start < horizon_end.value() && request.requested_at < exposure.end)) {
      continue;
    }
    const ScopeRelation relation = relate_scope(exposure.scope, candidate.location);
    if (relation == ScopeRelation::DoesNotApply) {
      continue;
    }
    if (relation == ScopeRelation::Unverifiable) {
      if (!unverifiable) {
        unverifiable = true;
        unverifiable_exposure = &exposure;
      }
      continue;
    }
    if (worst == nullptr || exposure.severity > worst->severity ||
        (exposure.severity == worst->severity && exposure.exposure_id < worst->exposure_id)) {
      worst = &exposure;
    }
  }

  if (worst != nullptr) {
    const bool blackout = worst->severity == MaintenanceSeverity::Blackout;
    return Check{ViolationDraft{
        blackout ? ViolationCode::MaintenanceBlackout : ViolationCode::MaintenanceDegraded,
        "exposure=" + std::string(worst->exposure_id.value()) +
            " kind=" + std::string(maintenance_kind_name(worst->kind)) +
            " severity=" + std::string(maintenance_severity_name(worst->severity)) +
            " window=" + worst->start.to_string() + "/" + worst->end.to_string()}};
  }
  if (unverifiable && unverifiable_exposure != nullptr) {
    return Check{ViolationDraft{
        ViolationCode::MaintenanceScopeUnverifiable,
        "exposure=" + std::string(unverifiable_exposure->exposure_id.value()) +
            " is scoped to a place the candidate does not declare, so exposure cannot be "
            "ruled out"}};
  }
  return Check{std::nullopt};
}

/// One validated grant and the envelope it exercises.
///
/// The grant is held by value: the envelope points into the policy snapshot,
/// which outlives the evaluation, but the grant itself came from a local
/// canonicalisation and must be owned here rather than referenced.
struct PreparedGrant {
  OverrideGrant grant;
  const OverrideEnvelope* envelope = nullptr;
};

struct Prepared {
  const PolicySnapshot* snapshot = nullptr;
  PlacementRequest request;
  Digest request_digest_value{};
  std::vector<PreparedGrant> grants;  // sorted by facility, one per facility
};

Result<void> validate_grant_shape(const OverrideGrant& grant, bool require_digest = true) {
  if (grant.envelope_id.empty() || grant.principal.empty() || grant.usage_id.empty() ||
      grant.tenant.empty() || grant.service_class.empty() || grant.facility.empty()) {
    return Error(ErrorCode::MissingField, "a grant is missing an identity field");
  }
  if (grant.policy.policy_id.empty() || !grant.policy.revision.is_valid()) {
    return Error(ErrorCode::MissingField, "a grant is missing the policy revision it was "
                                          "issued against");
  }
  if (!grant.authority_epoch.is_valid()) {
    return Error(ErrorCode::MissingField, "a grant is missing its authority epoch");
  }
  if (!grant.issued_at.is_set() || !grant.expires_at.is_set()) {
    return Error(ErrorCode::MissingField, "a grant is missing its validity window");
  }
  if (!(grant.issued_at < grant.expires_at)) {
    return Error(ErrorCode::InvalidEnvelopeWindow, "a grant window is empty or inverted")
        .with_detail("usage=" + std::string(grant.usage_id.value()));
  }
  if (require_digest && !verify_grant_digest(grant)) {
    return Error(ErrorCode::DigestMismatch, "a grant's digest does not match its contents")
        .with_detail("usage=" + std::string(grant.usage_id.value()));
  }
  return success;
}

Result<Prepared> prepare(const PolicySnapshot& snapshot, const EvaluationInput& input,
                         EvaluationOptions options) {
  const auto policy_check = validate_canonical_policy(snapshot.policy);
  if (!policy_check.has_value()) {
    return policy_check.error();
  }
  if (!snapshot.authority_epoch.is_valid()) {
    return Error(ErrorCode::MissingField, "the policy snapshot has no authority epoch");
  }
  if (!snapshot.store_sequence.is_valid()) {
    return Error(ErrorCode::MissingField, "the policy snapshot has no store sequence");
  }

  auto canonical_input = canonicalize_evaluation_input(input);
  if (!canonical_input.has_value()) {
    return canonical_input.error();
  }

  Prepared prepared;
  prepared.snapshot = &snapshot;
  prepared.request = std::move(canonical_input.value().request);
  prepared.request_digest_value = request_digest(prepared.request);

  if (!prepared.request.requested_at.is_set()) {
    return Error(ErrorCode::MissingField, "the request has no evaluation instant");
  }

  if (options.enforce_generation_floor) {
    if (snapshot.topology_floor.is_valid() &&
        prepared.request.generations.topology < snapshot.topology_floor) {
      return Error(ErrorCode::StaleTopologyGeneration,
                   "the request binds a topology generation older than the newest this runtime "
                   "has already accepted")
          .with_detail("bound=" + prepared.request.generations.topology.to_string() +
                       " floor=" + snapshot.topology_floor.to_string());
    }
    if (snapshot.failure_domain_floor.is_valid() &&
        prepared.request.generations.failure_domain < snapshot.failure_domain_floor) {
      return Error(ErrorCode::StaleFailureDomainGeneration,
                   "the request binds a failure-domain generation older than the newest this "
                   "runtime has already accepted")
          .with_detail("bound=" + prepared.request.generations.failure_domain.to_string() +
                       " floor=" + snapshot.failure_domain_floor.to_string());
    }
  }

  for (const OverrideGrant& grant : canonical_input.value().grants) {
    const auto shape = validate_grant_shape(grant);
    if (!shape.has_value()) {
      return shape.error();
    }
    const OverrideEnvelope* envelope = find_envelope(snapshot.policy, grant.envelope_id);
    if (envelope == nullptr) {
      return Error(ErrorCode::OverrideUnknownEnvelope,
                   "the grant names an envelope the active policy does not declare")
          .with_detail("envelope=" + std::string(grant.envelope_id.value()));
    }
    if (!digest_equal(envelope_digest(*envelope), grant.envelope_digest)) {
      return Error(ErrorCode::OverrideGrantEnvelopeMismatch,
                   "the envelope changed after the grant was issued, so the grant is fenced")
          .with_detail("envelope=" + std::string(grant.envelope_id.value()));
    }
    if (!(grant.policy.revision == snapshot.policy.revision) ||
        !digest_equal(grant.policy.digest, snapshot.policy.digest)) {
      return Error(ErrorCode::OverrideBindingMismatch,
                   "the grant was issued against a different policy revision")
          .with_detail("grant-revision=" + grant.policy.revision.to_string() +
                       " active-revision=" + snapshot.policy.revision.to_string());
    }
    if (!(grant.authority_epoch == snapshot.authority_epoch)) {
      return Error(ErrorCode::StaleAuthorityEpoch,
                   "the grant belongs to a superseded authority epoch and is fenced")
          .with_detail("grant-epoch=" + grant.authority_epoch.to_string() +
                       " current-epoch=" + snapshot.authority_epoch.to_string());
    }
    if (!(grant.tenant == prepared.request.tenant) ||
        !(grant.service_class == prepared.request.service_class)) {
      return Error(ErrorCode::OverrideScopeMismatch,
                   "the grant was issued for a different tenant or service class")
          .with_detail("grant-tenant=" + std::string(grant.tenant.value()) +
                       " request-tenant=" + std::string(prepared.request.tenant.value()));
    }
    // The envelope's tenant, service-class and facility scope is checked here.
    // Its jurisdiction scope is checked per candidate, where the facility's
    // jurisdiction is known; an envelope that restricts jurisdictions therefore
    // waives nothing for a candidate outside them rather than failing the whole
    // evaluation.
    const bool facility_scope_ok =
        (envelope->scope.tenants.empty() ||
         std::find(envelope->scope.tenants.begin(), envelope->scope.tenants.end(),
                   grant.tenant) != envelope->scope.tenants.end()) &&
        (envelope->scope.service_classes.empty() ||
         std::find(envelope->scope.service_classes.begin(), envelope->scope.service_classes.end(),
                   grant.service_class) != envelope->scope.service_classes.end()) &&
        (envelope->scope.facilities.empty() ||
         std::find(envelope->scope.facilities.begin(), envelope->scope.facilities.end(),
                   grant.facility) != envelope->scope.facilities.end());
    if (!facility_scope_ok) {
      return Error(ErrorCode::OverrideScopeMismatch,
                   "the grant's scope is outside the envelope's scope")
          .with_detail("envelope=" + std::string(envelope->envelope_id.value()) +
                       " facility=" + std::string(grant.facility.value()));
    }
    if (std::find(envelope->authorized_principals.begin(), envelope->authorized_principals.end(),
                  grant.principal) == envelope->authorized_principals.end()) {
      return Error(ErrorCode::OverridePrincipalNotAuthorized,
                   "the principal is not authorised by this envelope")
          .with_detail("envelope=" + std::string(envelope->envelope_id.value()) +
                       " principal=" + std::string(grant.principal.value()));
    }
    if (envelope->not_before.is_set() && grant.issued_at < envelope->not_before) {
      return Error(ErrorCode::OverrideNotYetValid,
                   "the grant was issued before the envelope opens")
          .with_detail("envelope=" + std::string(envelope->envelope_id.value()));
    }
    if (envelope->expires_at.is_set() && !(grant.issued_at < envelope->expires_at)) {
      return Error(ErrorCode::OverrideExpired, "the grant was issued after the envelope closed")
          .with_detail("envelope=" + std::string(envelope->envelope_id.value()));
    }
    if (!(prepared.request.requested_at < grant.expires_at)) {
      return Error(ErrorCode::OverrideExpired, "the grant has expired")
          .with_detail("usage=" + std::string(grant.usage_id.value()) + " expires=" +
                       grant.expires_at.to_string());
    }
    for (const PreparedGrant& existing : prepared.grants) {
      if (existing.grant.facility == grant.facility) {
        return Error(ErrorCode::OverrideUsageConflict,
                     "more than one grant applies to the same facility")
            .with_detail("facility=" + std::string(grant.facility.value()));
      }
    }
    prepared.grants.push_back(PreparedGrant{grant, envelope});
  }

  std::sort(prepared.grants.begin(), prepared.grants.end(),
            [](const PreparedGrant& lhs, const PreparedGrant& rhs) {
              return lhs.grant.facility < rhs.grant.facility;
            });
  return prepared;
}

Result<CandidateVerdict> evaluate_one(const Prepared& prepared, const CandidatePlacement& candidate) {
  const FacilityRecord* facility = find_facility(prepared.request, candidate.location.facility);
  if (facility == nullptr) {
    return Error(ErrorCode::NotFound, "the candidate names a facility the request does not describe")
        .with_detail("candidate=" + std::string(candidate.candidate_id.value()));
  }

  const PreparedGrant* prepared_grant = nullptr;
  for (const PreparedGrant& entry : prepared.grants) {
    if (entry.grant.facility == candidate.location.facility) {
      prepared_grant = &entry;
      break;
    }
  }

  CandidateVerdict verdict;
  verdict.candidate_id = candidate.candidate_id;

  for (const Rule& rule : prepared.snapshot->policy.rules) {
    if (!rule_applies(rule, prepared.request.tenant, prepared.request.service_class,
                      candidate.location.facility, facility->jurisdiction)) {
      verdict.not_applicable_rules.push_back(rule.rule_id);
      continue;
    }
    verdict.applied_rules.push_back(rule.rule_id);

    for (std::size_t index = 0; index < rule.constraints.size(); ++index) {
      const Constraint& constraint = rule.constraints[index];
      Check check;
      bool fatal = false;
      Result<Check> fatal_result{std::nullopt};
      std::visit(
          [&](const auto& concrete) {
            using Concrete = std::decay_t<decltype(concrete)>;
            if constexpr (std::is_same_v<Concrete, JurisdictionConstraint>) {
              check = check_jurisdiction(concrete, *facility);
            } else if constexpr (std::is_same_v<Concrete, FacilityAttributeConstraint>) {
              check = check_attribute(concrete, *facility);
            } else if constexpr (std::is_same_v<Concrete, SeparationConstraint>) {
              check = check_separation(concrete, candidate);
            } else if constexpr (std::is_same_v<Concrete, AntiAffinityConstraint>) {
              check = check_anti_affinity(concrete, prepared.request, candidate);
            } else if constexpr (std::is_same_v<Concrete, RedundancyConstraint>) {
              check = check_redundancy(concrete, prepared.request, candidate);
            } else if constexpr (std::is_same_v<Concrete, CoTenancyConstraint>) {
              check = check_co_tenancy(concrete, prepared.request, candidate);
            } else {
              fatal_result = check_maintenance(concrete, prepared.request, candidate);
              fatal = true;
            }
          },
          constraint);
      if (fatal) {
        if (!fatal_result.has_value()) {
          return fatal_result.error();
        }
        check = fatal_result.value();
      }
      if (!check.has_value()) {
        continue;
      }
      Violation violation;
      violation.rule_id = rule.rule_id;
      violation.constraint_kind = constraint_kind_of(constraint);
      violation.constraint_index = static_cast<std::uint32_t>(index);
      violation.code = check->code;
      violation.detail = bound_detail(std::move(check->detail));
      verdict.violations.push_back(std::move(violation));
    }
  }
  verdict.constrained = !verdict.applied_rules.empty();

  const bool override_in_scope =
      prepared_grant != nullptr &&
      rule_selector_matches(prepared_grant->envelope->scope, prepared.request.tenant,
                            prepared.request.service_class, candidate.location.facility,
                            facility->jurisdiction);
  if (prepared_grant != nullptr && override_in_scope) {
    const OverrideEnvelope& envelope = *prepared_grant->envelope;
    const OverrideGrant& grant = prepared_grant->grant;
    std::uint32_t waived = 0;
    for (Violation& violation : verdict.violations) {
      const bool waivable =
          std::find(envelope.allowed_constraints.begin(), envelope.allowed_constraints.end(),
                    violation.constraint_kind) != envelope.allowed_constraints.end() &&
          !constraint_kind_is_hard_interlock(violation.constraint_kind);
      if (!waivable) {
        continue;
      }
      violation.waived_by = envelope.envelope_id;
      ++waived;
    }
    if (waived > 0u) {
      OverrideUse use;
      use.envelope_id = envelope.envelope_id;
      use.principal = grant.principal;
      use.usage_id = grant.usage_id;
      use.grant_digest = grant.grant_digest;
      use.waived_count = waived;
      verdict.override_use = std::move(use);
    }
  }

  bool blocked = false;
  for (const Violation& violation : verdict.violations) {
    if (!violation.waived_by.has_value()) {
      blocked = true;
      break;
    }
  }
  verdict.decision = blocked ? Decision::Ineligible : Decision::Eligible;
  verdict.evidence_digest = candidate_evidence_digest(prepared.request, candidate);
  verdict.verdict_digest = compute_verdict_digest(verdict);
  return verdict;
}

}  // namespace

PolicyBinding PolicySnapshot::binding() const {
  return PolicyBinding{policy.policy_id, policy.revision, policy.digest};
}

Result<PolicySnapshot> make_policy_snapshot(PolicyDocument policy, AuthorityEpoch authority_epoch,
                                            StoreSequence store_sequence,
                                            TopologyGeneration topology_floor,
                                            FailureDomainGeneration failure_domain_floor) {
  auto canonical = canonicalize_policy(std::move(policy));
  if (!canonical.has_value()) {
    return canonical.error();
  }
  if (!authority_epoch.is_valid()) {
    return Error(ErrorCode::MissingField, "a policy snapshot needs an authority epoch");
  }
  if (!store_sequence.is_valid()) {
    return Error(ErrorCode::MissingField, "a policy snapshot needs a store sequence");
  }
  PolicySnapshot snapshot;
  snapshot.policy = std::move(canonical.value());
  snapshot.authority_epoch = authority_epoch;
  snapshot.store_sequence = store_sequence;
  snapshot.topology_floor = topology_floor;
  snapshot.failure_domain_floor = failure_domain_floor;
  return snapshot;
}

Result<OverrideGrant> canonicalize_grant(OverrideGrant grant) {
  // The digest is what canonicalisation produces, so it is not a precondition.
  const auto shape = validate_grant_shape(grant, false);
  if (!shape.has_value()) {
    return shape.error();
  }
  grant.grant_digest = compute_grant_digest(grant);
  return grant;
}

bool verify_grant_digest(const OverrideGrant& grant) {
  return digest_equal(compute_grant_digest(grant), grant.grant_digest);
}

Result<EvaluationInput> canonicalize_evaluation_input(EvaluationInput input) {
  auto request = canonicalize_request(std::move(input.request));
  if (!request.has_value()) {
    return request.error();
  }
  EvaluationInput out;
  out.request = std::move(request.value());
  out.grants = std::move(input.grants);
  std::sort(out.grants.begin(), out.grants.end(),
            [](const OverrideGrant& lhs, const OverrideGrant& rhs) {
              return lhs.usage_id < rhs.usage_id;
            });
  for (const OverrideGrant& grant : out.grants) {
    const auto shape = validate_grant_shape(grant);
    if (!shape.has_value()) {
      return shape.error();
    }
  }
  return out;
}

Result<PlacementVerdictSet> evaluate(const PolicySnapshot& snapshot, const EvaluationInput& input,
                                     EvaluationOptions options) {
  auto prepared = prepare(snapshot, input, options);
  if (!prepared.has_value()) {
    return prepared.error();
  }

  PlacementVerdictSet verdicts;
  verdicts.request_id = prepared.value().request.request_id;
  verdicts.policy = snapshot.binding();
  verdicts.authority_epoch = snapshot.authority_epoch;
  verdicts.generations = prepared.value().request.generations;
  verdicts.occupancy_generation = prepared.value().request.occupancy.generation;
  verdicts.maintenance_generation = prepared.value().request.maintenance.generation;
  verdicts.evaluated_at = prepared.value().request.requested_at;
  verdicts.request_digest = prepared.value().request_digest_value;
  verdicts.candidates.reserve(prepared.value().request.candidates.size());

  for (const CandidatePlacement& candidate : prepared.value().request.candidates) {
    auto verdict = evaluate_one(prepared.value(), candidate);
    if (!verdict.has_value()) {
      return verdict.error();
    }
    verdicts.candidates.push_back(std::move(verdict.value()));
  }

  // The candidates were canonicalised by identity, so the result is indexed by
  // identity and a permutation of the request cannot change these bytes.
  std::sort(verdicts.candidates.begin(), verdicts.candidates.end(),
            [](const CandidateVerdict& lhs, const CandidateVerdict& rhs) {
              return lhs.candidate_id < rhs.candidate_id;
            });
  return verdicts;
}

Result<CandidateVerdict> evaluate_candidate(const PolicySnapshot& snapshot,
                                            const EvaluationInput& input,
                                            const CandidateId& candidate_id,
                                            EvaluationOptions options) {
  auto prepared = prepare(snapshot, input, options);
  if (!prepared.has_value()) {
    return prepared.error();
  }
  const CandidatePlacement* candidate = find_candidate(prepared.value().request, candidate_id);
  if (candidate == nullptr) {
    return Error(ErrorCode::NotFound, "the request does not contain this candidate")
        .with_detail("candidate=" + std::string(candidate_id.value()));
  }
  return evaluate_one(prepared.value(), *candidate);
}

std::string_view decision_token(Decision decision) noexcept {
  return decision == Decision::Eligible ? "eligible" : "ineligible";
}

}  // namespace dccp::facility_placement_policy
