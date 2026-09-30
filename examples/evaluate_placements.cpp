// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs.
//
// Evaluate two proposed placements against one policy snapshot.
//
// The policy and the request are written in the text document format, so every
// fact the decision is made from is visible in this file, and the engine reads
// no clock: the evaluation instant is the one the request binds. The program
// prints the verdict text and exits non-zero when the verdicts are not the ones
// the documents describe.

#include <cstdint>
#include <iostream>
#include <string_view>

#include "dccp/facility_placement_policy/facility_placement_policy.hpp"

namespace fpp = dccp::facility_placement_policy;

namespace {

/// One rule, two constraints. A placement for tenant-a must be in a jurisdiction
/// the policy allows and must not share a rack with a placement the tenant
/// already has. Jurisdiction membership is a hard interlock; anti-affinity is
/// not, which is why the durable store example can waive one and never the
/// other.
constexpr std::string_view kPolicyText =
    "fpp-document policy\n"
    "format 1\n"
    "policy-id placement-policy\n"
    "revision 1\n"
    "rule rack-anti-affinity {\n"
    "  description \"one rack holds one placement of this tenant\"\n"
    "  select tenants=tenant-a\n"
    "  require jurisdiction allow=eu-west deny=\n"
    "  require anti-affinity scope=tenant dimension=rack max-shared=0\n"
    "}\n";

/// Two candidates in one site. cand-shared lands on the rack that already holds
/// a placement of tenant-a; cand-free lands on a rack that holds nothing.
constexpr std::string_view kRequestText =
    "fpp-document request\n"
    "format 1\n"
    "request-id req-placements-1\n"
    "tenant tenant-a\n"
    "service-class svc-web\n"
    "requested-at 2026-02-14T09:30:00.000000Z\n"
    "generations topology=7 failure-domain=5 tenant=3 service-class=4\n"
    "facility facility-north jurisdiction=eu-west\n"
    "facility facility-south jurisdiction=eu-west\n"
    "candidate cand-free facility=facility-south site=site-1 room=room-1 row=row-2 "
    "rack=rack-9\n"
    "candidate cand-shared facility=facility-north site=site-1 room=room-1 row=row-1 "
    "rack=rack-7\n"
    "occupancy generation=11\n"
    "placed placement-existing tenant=tenant-a service-class=svc-web "
    "facility=facility-north site=site-1 room=room-1 row=row-1 rack=rack-7\n";

/// The counters the snapshot binds. They are literals: this example has no store
/// behind it and reads no clock, so the runtime's own counters start at one.
constexpr std::uint64_t kAuthorityEpoch = 1;
constexpr std::uint64_t kStoreSequence = 1;

constexpr std::string_view kSharedCandidate = "cand-shared";
constexpr std::string_view kFreeCandidate = "cand-free";

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
  if (!epoch.has_value() || !sequence.has_value()) {
    std::cerr << "the example's literal counters were refused\n";
    return 1;
  }

  // The snapshot is immutable for the whole batch: neither candidate can see the
  // other, and no candidate is placed before the next one is considered. Neither
  // watermark is set here, so no request is refused for being older than one.
  auto snapshot = fpp::make_policy_snapshot(std::move(policy.value()), epoch.value(),
                                            sequence.value(), fpp::TopologyGeneration{},
                                            fpp::FailureDomainGeneration{});
  if (!snapshot.has_value()) {
    return report("policy snapshot", snapshot.error());
  }

  fpp::EvaluationInput input;
  input.request = std::move(request.value());
  auto verdicts = fpp::evaluate(snapshot.value(), input);
  if (!verdicts.has_value()) {
    return report("evaluation", verdicts.error());
  }

  std::cout << "evaluated " << verdicts.value().candidates.size()
            << " candidate(s) against policy " << verdicts.value().policy.policy_id.value()
            << " revision " << verdicts.value().policy.revision.to_string() << "\n\n";
  std::cout << fpp::verdict_set_text(verdicts.value());

  const fpp::CandidateVerdict* shared = find_verdict(verdicts.value(), kSharedCandidate);
  const fpp::CandidateVerdict* free_rack = find_verdict(verdicts.value(), kFreeCandidate);
  if (shared == nullptr || free_rack == nullptr) {
    std::cerr << "the verdict set does not contain both candidates\n";
    return 1;
  }

  bool ok = true;
  if (shared->decision != fpp::Decision::Ineligible ||
      !cites(*shared, fpp::ViolationCode::AntiAffinityExceeded)) {
    std::cerr << kSharedCandidate
              << " shares rack-7 with an existing placement and must be ineligible for "
                 "anti-affinity\n";
    ok = false;
  }
  if (free_rack->decision != fpp::Decision::Eligible) {
    std::cerr << kFreeCandidate << " shares no rack and must be eligible\n";
    ok = false;
  }
  if (!ok) {
    return 1;
  }

  std::cout << "\nchecked " << kSharedCandidate << "="
            << fpp::decision_token(shared->decision) << " (anti-affinity-exceeded), "
            << kFreeCandidate << "=" << fpp::decision_token(free_rack->decision) << "\n";
  return 0;
}
