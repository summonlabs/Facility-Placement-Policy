// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs.
//
// Consume evidence published by adjacent authorities.
//
// A decision is a pure function of evidence that is already bound to the
// generation it was read at. This program shows the boundary from both sides:
// an evaluation that binds all six generations, one refusal that is a verdict
// because the maintenance generation is absent, and one refusal that is an Error
// because the topology generation is older than the watermark the snapshot
// carries. Nothing here reads a clock.
//
//   usage: facility_placement_policy_example_consume_upstream_evidence

#include <cstdint>
#include <iostream>
#include <string_view>

#include "dccp/facility_placement_policy/facility_placement_policy.hpp"

namespace fpp = dccp::facility_placement_policy;

namespace {

/// Legal placement (jurisdiction) and exposure to published maintenance inside a
/// thirty-day lookahead window. Both are hard interlocks: an override can never
/// waive either, so the only way to be eligible is to have the evidence.
constexpr std::string_view kPolicyText =
    "fpp-document policy\n"
    "format 1\n"
    "policy-id upstream-evidence-policy\n"
    "revision 1\n"
    "rule legal-placement-and-maintenance {\n"
    "  description \"no placement outside the allowed jurisdiction or into a published outage\"\n"
    "  select service-classes=svc-web\n"
    "  require jurisdiction allow=eu-west deny=\n"
    "  require maintenance-exposure min-severity=degraded horizon=30d\n"
    "}\n";

/// Every generation this request consumes comes from the authority that owns the
/// fact: topology (7), failure domains (5), tenants (3), service classes (4),
/// occupancy (11) and maintenance (12). The only exposure published inside the
/// lookahead window is scoped to facility-south, so it does not cover the
/// candidate and the candidate is eligible.
constexpr std::string_view kRequestText =
    "fpp-document request\n"
    "format 1\n"
    "request-id req-upstream-1\n"
    "tenant tenant-a\n"
    "service-class svc-web\n"
    "requested-at 2026-02-14T09:30:00.000000Z\n"
    "generations topology=7 failure-domain=5 tenant=3 service-class=4\n"
    "facility facility-north jurisdiction=eu-west\n"
    "candidate cand-a facility=facility-north site=site-1 room=room-1 row=row-1 rack=rack-1 "
    "failure-domains=power:pd-1,cooling:cd-1\n"
    "occupancy generation=11\n"
    "placed placement-existing tenant=tenant-a service-class=svc-web facility=facility-north "
    "site=site-1 room=room-1 row=row-1 rack=rack-4 failure-domains=power:pd-2\n"
    "maintenance generation=12\n"
    "exposure exposure-south kind=planned severity=blackout scope-facility=facility-south "
    "start=2026-03-01T00:00:00.000000Z end=2026-03-02T00:00:00.000000Z\n";

constexpr std::uint64_t kAuthorityEpoch = 1;
constexpr std::uint64_t kStoreSequence = 1;
constexpr std::uint64_t kTopologyFloor = 7;
constexpr std::uint64_t kNewerTopologyFloor = 8;
constexpr std::uint64_t kFailureDomainFloor = 5;
constexpr std::string_view kCandidate = "cand-a";
constexpr std::string_view kRule = "legal-placement-and-maintenance";

int report(std::string_view what, const fpp::Error& error) {
  std::cerr << what << ": " << error.to_string() << "\n";
  return 1;
}

const fpp::CandidateVerdict* find_verdict(const fpp::PlacementVerdictSet& verdicts,
                                          std::string_view candidate_id) {
  for (const fpp::CandidateVerdict& verdict : verdicts.candidates) {
    if (verdict.candidate_id.value() == candidate_id) {
      return &verdict;
    }
  }
  return nullptr;
}

bool cites(const fpp::CandidateVerdict& verdict, fpp::ViolationCode code) {
  for (const fpp::Violation& violation : verdict.violations) {
    if (violation.code == code) {
      return true;
    }
  }
  return false;
}

bool applies(const fpp::CandidateVerdict& verdict, std::string_view rule_id) {
  for (const fpp::RuleId& rule : verdict.applied_rules) {
    if (rule.value() == rule_id) {
      return true;
    }
  }
  return false;
}

std::string generations_text(const fpp::PlacementVerdictSet& verdicts) {
  std::string out = "topology=" + verdicts.generations.topology.to_string();
  out.append(" failure-domain=").append(verdicts.generations.failure_domain.to_string());
  out.append(" tenant=").append(verdicts.generations.tenant.to_string());
  out.append(" service-class=").append(verdicts.generations.service_class.to_string());
  out.append(" occupancy=");
  out.append(verdicts.occupancy_generation.has_value() ? verdicts.occupancy_generation->to_string()
                                                       : std::string("absent"));
  out.append(" maintenance=");
  out.append(verdicts.maintenance_generation.has_value()
                 ? verdicts.maintenance_generation->to_string()
                 : std::string("absent"));
  return out;
}

}  // namespace

int main() {
  auto policy = fpp::parse_policy_document(kPolicyText);
  if (!policy.has_value()) {
    return report("policy document", policy.error());
  }
  auto request = fpp::parse_request_document(kRequestText);
  if (!request.has_value()) {
    return report("request document", request.error());
  }

  const auto epoch = fpp::AuthorityEpoch::from_value(kAuthorityEpoch);
  const auto sequence = fpp::StoreSequence::from_value(kStoreSequence);
  const auto topology_floor = fpp::TopologyGeneration::from_value(kTopologyFloor);
  const auto newer_topology_floor = fpp::TopologyGeneration::from_value(kNewerTopologyFloor);
  const auto failure_domain_floor = fpp::FailureDomainGeneration::from_value(kFailureDomainFloor);
  if (!epoch.has_value() || !sequence.has_value() || !topology_floor.has_value() ||
      !newer_topology_floor.has_value() || !failure_domain_floor.has_value()) {
    std::cerr << "the example's literal counters were refused\n";
    return 1;
  }

  // The watermark is the greatest generation this runtime has already accepted.
  // A snapshot that carries one refuses a request bound to anything older.
  auto snapshot = fpp::make_policy_snapshot(policy.value(), epoch.value(), sequence.value(),
                                            topology_floor.value(), failure_domain_floor.value());
  if (!snapshot.has_value()) {
    return report("policy snapshot", snapshot.error());
  }

  std::cout << "upstream evidence boundary demonstration\n";
  std::cout << "policy " << snapshot.value().policy.policy_id.value() << " revision "
            << snapshot.value().policy.revision.to_string() << ", watermarks topology>="
            << snapshot.value().topology_floor.to_string() << " failure-domain>="
            << snapshot.value().failure_domain_floor.to_string() << "\n\n";

  fpp::EvaluationInput input;
  input.request = request.value();

  std::cout << "case 1: every consumed generation is bound\n";
  const auto bound = fpp::evaluate(snapshot.value(), input);
  if (!bound.has_value()) {
    return report("evaluation with complete evidence", bound.error());
  }
  std::cout << "bound " << generations_text(bound.value()) << "\n";
  std::cout << fpp::verdict_set_text(bound.value());

  const fpp::CandidateVerdict* verdict = find_verdict(bound.value(), kCandidate);
  if (verdict == nullptr) {
    std::cerr << "the verdict set does not contain " << kCandidate << "\n";
    return 1;
  }
  if (verdict->decision != fpp::Decision::Eligible || !verdict->constrained ||
      !applies(*verdict, kRule)) {
    std::cerr << kCandidate << " must be eligible under " << kRule << " when all evidence is "
                 "bound\n";
    return 1;
  }
  std::cout << "checked: " << kCandidate << "=" << fpp::decision_token(verdict->decision)
            << " constrained=true rule=" << kRule << " violations=0\n\n";

  // The Maintenance Coordinator has published nothing this runtime can bind, so
  // the caller carries no maintenance generation. Evidence without a generation
  // is not evidence, and the exposures go with it.
  fpp::PlacementRequest unpublished = request.value();
  unpublished.maintenance = fpp::MaintenanceEvidence{};
  auto without_maintenance = fpp::canonicalize_request(std::move(unpublished));
  if (!without_maintenance.has_value()) {
    return report("request without maintenance evidence", without_maintenance.error());
  }

  std::cout << "case 2: the maintenance evidence generation is absent\n";
  fpp::EvaluationInput unpublished_input;
  unpublished_input.request = std::move(without_maintenance.value());
  const auto refused = fpp::evaluate(snapshot.value(), unpublished_input);
  if (!refused.has_value()) {
    return report("evaluation without maintenance evidence", refused.error());
  }
  std::cout << "bound " << generations_text(refused.value()) << "\n";
  std::cout << fpp::verdict_set_text(refused.value());

  const fpp::CandidateVerdict* absent = find_verdict(refused.value(), kCandidate);
  if (absent == nullptr || absent->decision != fpp::Decision::Ineligible ||
      !cites(*absent, fpp::ViolationCode::MaintenanceEvidenceAbsent)) {
    std::cerr << kCandidate << " must be ineligible with maintenance-evidence-absent when the "
                 "generation is missing\n";
    return 1;
  }
  std::cout << "checked: " << kCandidate << "=" << fpp::decision_token(absent->decision)
            << " violation=maintenance-evidence-absent\n\n";

  // The same request, judged against a runtime that has already accepted topology
  // generation 8. The bound evidence is stale, so this is not a verdict at all:
  // it is a refusal that carries no decision.
  auto newer_snapshot = fpp::make_policy_snapshot(policy.value(), epoch.value(), sequence.value(),
                                                  newer_topology_floor.value(),
                                                  failure_domain_floor.value());
  if (!newer_snapshot.has_value()) {
    return report("policy snapshot with a newer watermark", newer_snapshot.error());
  }

  std::cout << "case 3: the topology generation is older than the snapshot watermark\n";
  const auto stale = fpp::evaluate(newer_snapshot.value(), input);
  if (stale.has_value()) {
    std::cerr << "a request bound to topology 7 must be refused by a snapshot whose floor is "
              << newer_topology_floor.value().to_string() << "\n";
    return 1;
  }
  if (stale.error().code() != fpp::ErrorCode::StaleTopologyGeneration) {
    return report("evaluation against a newer watermark", stale.error());
  }
  std::cout << "refused: " << stale.error().to_string() << "\n";
  std::cout << "checked: no verdict was issued, category="
            << fpp::error_category_name(stale.error().category()) << "\n";
  return 0;
}
