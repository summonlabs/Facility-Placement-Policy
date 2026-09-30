// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs.

#ifndef DCCP_FACILITY_PLACEMENT_POLICY_VERDICT_HPP
#define DCCP_FACILITY_PLACEMENT_POLICY_VERDICT_HPP

#include <array>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "dccp/facility_placement_policy/digest.hpp"
#include "dccp/facility_placement_policy/facility.hpp"
#include "dccp/facility_placement_policy/generation.hpp"
#include "dccp/facility_placement_policy/policy.hpp"
#include "dccp/facility_placement_policy/result.hpp"
#include "dccp/facility_placement_policy/strong_id.hpp"
#include "dccp/facility_placement_policy/time.hpp"

namespace dccp::facility_placement_policy {

/// The decision. There are exactly two. Anything that is not a decision is a
/// refusal, reported as an Error with its own stable code, so "we could not
/// decide" can never be mistaken for "decided yes".
enum class Decision : std::uint8_t {
  Eligible = 0,
  Ineligible = 1,
};

inline constexpr std::array<std::pair<Decision, std::string_view>, 2> kDecisionTokens = {
    {{Decision::Eligible, "eligible"}, {Decision::Ineligible, "ineligible"}}};

constexpr std::string_view decision_name(Decision value) noexcept {
  return enum_token(kDecisionTokens, value);
}

inline Result<Decision> parse_decision(std::string_view text) {
  return enum_from_token(kDecisionTokens, text, "decision");
}

/// Why a constraint was not satisfied. The code is stable and machine-readable;
/// the accompanying detail carries the compared values so that a refusal is
/// attributable without re-running the evaluation.
enum class ViolationCode : std::uint8_t {
  JurisdictionUnknown = 0,
  JurisdictionNotAllowed = 1,
  JurisdictionDenied = 2,
  AttributeUnmeasured = 3,
  AttributeUnsatisfied = 4,
  DimensionUnmeasured = 5,
  SeparationDenied = 6,
  SeparationNotAllowed = 7,
  AntiAffinityExceeded = 8,
  CoTenancyExceeded = 9,
  RedundancyUnsatisfied = 10,
  MaintenanceEvidenceAbsent = 11,
  MaintenanceBlackout = 12,
  MaintenanceDegraded = 13,
  MaintenanceScopeUnverifiable = 14,
  /// Appended after the first vocabulary: constraints that reason about what
  /// already exists need occupancy evidence, and no evidence is not the same as
  /// no neighbours.
  OccupancyEvidenceAbsent = 15,
};

inline constexpr std::array<std::pair<ViolationCode, std::string_view>, 16>
    kViolationCodeTokens = {
        {{ViolationCode::JurisdictionUnknown, "jurisdiction-unknown"},
         {ViolationCode::JurisdictionNotAllowed, "jurisdiction-not-allowed"},
         {ViolationCode::JurisdictionDenied, "jurisdiction-denied"},
         {ViolationCode::AttributeUnmeasured, "attribute-unmeasured"},
         {ViolationCode::AttributeUnsatisfied, "attribute-unsatisfied"},
         {ViolationCode::DimensionUnmeasured, "dimension-unmeasured"},
         {ViolationCode::SeparationDenied, "separation-denied"},
         {ViolationCode::SeparationNotAllowed, "separation-not-allowed"},
         {ViolationCode::AntiAffinityExceeded, "anti-affinity-exceeded"},
         {ViolationCode::CoTenancyExceeded, "co-tenancy-exceeded"},
         {ViolationCode::RedundancyUnsatisfied, "redundancy-unsatisfied"},
         {ViolationCode::MaintenanceEvidenceAbsent, "maintenance-evidence-absent"},
         {ViolationCode::MaintenanceBlackout, "maintenance-blackout"},
         {ViolationCode::MaintenanceDegraded, "maintenance-degraded"},
         {ViolationCode::MaintenanceScopeUnverifiable, "maintenance-scope-unverifiable"},
         {ViolationCode::OccupancyEvidenceAbsent, "occupancy-evidence-absent"}}};

constexpr std::string_view violation_code_name(ViolationCode value) noexcept {
  return enum_token(kViolationCodeTokens, value);
}

inline Result<ViolationCode> parse_violation_code(std::string_view text) {
  return enum_from_token(kViolationCodeTokens, text, "violation");
}

/// One unsatisfied requirement.
struct Violation {
  RuleId rule_id;
  ConstraintKind constraint_kind = ConstraintKind::AntiAffinity;
  /// Position of the constraint inside its rule, in canonical order.
  std::uint32_t constraint_index = 0;
  ViolationCode code = ViolationCode::AntiAffinityExceeded;
  /// Bounded, deterministic, and derived only from the bound evidence.
  std::string detail;
  /// Set when an override waived this violation.
  std::optional<EnvelopeId> waived_by;
};

/// The override that was applied to a verdict, and what it waived.
struct OverrideUse {
  EnvelopeId envelope_id;
  PrincipalId principal;
  UsageId usage_id;
  Digest grant_digest;
  std::uint32_t waived_count = 0;
};

/// The verdict for one candidate.
struct CandidateVerdict {
  CandidateId candidate_id;
  Decision decision = Decision::Ineligible;
  /// Canonically ordered. Nothing is dropped: a waiver marks the violation, it
  /// does not remove it, so the explanation always shows what the policy said.
  std::vector<Violation> violations;
  /// Rules whose selector matched, sorted. Proof that the policy was consulted.
  std::vector<RuleId> applied_rules;
  /// Rules whose selector did not match, sorted.
  std::vector<RuleId> not_applicable_rules;
  /// True when at least one rule applied. An eligible verdict from an
  /// unconstrained evaluation is visible as such rather than looking identical
  /// to a constrained one.
  bool constrained = false;
  std::optional<OverrideUse> override_use;
  Digest evidence_digest{};
  /// SHA-256 over the canonical encoding of this verdict with the digest field
  /// and the replay marker excluded.
  Digest verdict_digest{};
  /// True when this verdict was returned from durable state rather than
  /// recomputed.
  bool replayed = false;
};

/// The result of one evaluation: one verdict per candidate in the request.
struct PlacementVerdictSet {
  RequestId request_id;
  PolicyBinding policy;
  AuthorityEpoch authority_epoch;
  EvidenceGenerations generations;
  std::optional<OccupancyGeneration> occupancy_generation;
  std::optional<MaintenanceGeneration> maintenance_generation;
  Instant evaluated_at;
  Digest request_digest{};
  /// Sorted by candidate identity. The order in which candidates appeared in the
  /// request is not observable here, which is what makes a batch permutation
  /// invariant.
  std::vector<CandidateVerdict> candidates;
  /// True when the whole set was returned from durable state.
  bool replayed = false;
};

/// The authority a verdict is checked against.
struct AuthorityState {
  PolicyBinding policy;
  AuthorityEpoch authority_epoch;
  EvidenceGenerations generations;
  std::optional<OccupancyGeneration> occupancy_generation;
  std::optional<MaintenanceGeneration> maintenance_generation;
};

enum class FencingStatus : std::uint8_t {
  /// Every bound field still matches, and the verdict's own digest verifies.
  Valid = 0,
  /// At least one bound field no longer matches. The verdict is history.
  Fenced = 1,
};

/// One field of the comparison, whether or not it is stale.
struct FencingField {
  std::string name;
  std::string bound;
  std::string current;
  bool stale = false;
};

struct FencingReport {
  FencingStatus status = FencingStatus::Fenced;
  CandidateId candidate_id;
  Digest verdict_digest{};
  /// False when the verdict's own digest did not verify; in that case the
  /// verdict is not merely stale, it is not a verdict this runtime issued.
  bool digest_verified = false;
  /// Every compared field, in a fixed order, so two runs produce identical text.
  std::vector<FencingField> fields;
};

/// Recomputes a verdict's canonical digest. Returns false when the stored digest
/// does not match the content.
bool verify_verdict_digest(const CandidateVerdict& verdict);

/// Checks a verdict against the current authority.
Result<FencingReport> verify_verdict(const PlacementVerdictSet& verdicts,
                                     const CandidateId& candidate_id,
                                     const AuthorityState& current);

/// Renders a fencing report as stable text, one field per line.
std::string fencing_report_text(const FencingReport& report);

/// Renders a verdict set as stable text. This is the explanation surface: it
/// names the policy revision, every bound generation and every violation.
std::string verdict_set_text(const PlacementVerdictSet& verdicts);

}  // namespace dccp::facility_placement_policy

#endif  // DCCP_FACILITY_PLACEMENT_POLICY_VERDICT_HPP
