// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs.
//
// Exercises the installed package the way a real consumer would: build a
// policy and a request from documents, decide eligibility, explain the refusal,
// run a durable store end to end, prove that a retried request is answered from
// the record, and check that a policy change fences the authority that came
// before it.

#include <cstdio>
#include <string>
#include <vector>

#include "dccp/facility_placement_policy/facility_placement_policy.hpp"

namespace {

using namespace dccp::facility_placement_policy;

int failures = 0;

void require(bool condition, const char* what) {
  if (!condition) {
    std::fprintf(stderr, "downstream check failed: %s\n", what);
    ++failures;
  }
}

const char* const kPolicyText =
    "fpp-document policy\n"
    "format 1\n"
    "policy-id downstream-grid\n"
    "revision 1\n"
    "rule spread {\n"
    "  require anti-affinity scope=tenant dimension=rack max-shared=0\n"
    "}\n"
    "rule legal {\n"
    "  require jurisdiction allow=jurisdiction:eu-de deny=\n"
    "}\n";

const char* const kRequestText =
    "fpp-document request\n"
    "format 1\n"
    "request-id downstream-req-1\n"
    "tenant tenant:acme\n"
    "service-class service-class:gold\n"
    "requested-at 2026-02-14T09:30:00.000000Z\n"
    "generations topology=12 failure-domain=9 tenant=4 service-class=3\n"
    "facility facility:dc1 jurisdiction=jurisdiction:eu-de\n"
    "candidate shared facility=facility:dc1 rack=rack:07\n"
    "candidate free facility=facility:dc1 rack=rack:09\n"
    "occupancy generation=77\n"
    "placed p1 tenant=tenant:acme service-class=service-class:gold facility=facility:dc1 "
    "rack=rack:07\n"
    "maintenance generation=41\n";

const CandidateVerdict* find(const PlacementVerdictSet& verdicts, const char* id) {
  for (const CandidateVerdict& candidate : verdicts.candidates) {
    if (candidate.candidate_id.value() == id) {
      return &candidate;
    }
  }
  return nullptr;
}

}  // namespace

int main(int argc, char** argv) {
  const std::string store_directory = argc > 1 ? argv[1] : "downstream-store";
  const Instant at = Instant::parse("2026-02-14T09:00:00.000000Z").value();
  const Instant evaluated_at = Instant::parse("2026-02-14T09:30:00.000000Z").value();

  // A policy is a document with an identity that a caller can compare.
  auto policy = parse_policy_document(kPolicyText);
  require(policy.has_value(), "the policy document parses");
  if (!policy.has_value()) {
    return 1;
  }
  require(policy.value().rules.size() == 2, "both rules are present");
  require(!digest_is_zero(policy.value().digest), "the policy carries a digest");
  const std::string canonical = policy_document_text(policy.value());
  auto reparsed = parse_policy_document(canonical);
  require(reparsed.has_value(), "the canonical text parses again");
  if (reparsed.has_value()) {
    require(digest_equal(reparsed.value().digest, policy.value().digest),
            "the canonical text has the same identity");
  }

  auto snapshot = make_policy_snapshot(std::move(policy.value()),
                                       AuthorityEpoch::from_value(2).value(),
                                       StoreSequence::from_value(2).value(), TopologyGeneration{},
                                       FailureDomainGeneration{});
  require(snapshot.has_value(), "a snapshot can be built from the policy");
  if (!snapshot.has_value()) {
    return 1;
  }

  auto request = parse_request_document(kRequestText);
  require(request.has_value(), "the request document parses");
  if (!request.has_value()) {
    return 1;
  }
  EvaluationInput input;
  input.request = std::move(request.value());
  auto verdicts = evaluate(snapshot.value(), input);
  require(verdicts.has_value(), "the batch evaluates");
  if (!verdicts.has_value()) {
    return 1;
  }

  const CandidateVerdict* shared = find(verdicts.value(), "shared");
  const CandidateVerdict* free_candidate = find(verdicts.value(), "free");
  require(shared != nullptr && free_candidate != nullptr, "both candidates are decided");
  if (shared == nullptr || free_candidate == nullptr) {
    return 1;
  }
  require(shared->decision == Decision::Ineligible, "the sharing candidate is ineligible");
  require(free_candidate->decision == Decision::Eligible, "the free candidate is eligible");
  require(!shared->violations.empty(), "the refusal is explained");
  if (!shared->violations.empty()) {
    require(shared->violations.front().code == ViolationCode::AntiAffinityExceeded,
            "the refusal names anti-affinity");
    require(!shared->violations.front().detail.empty(), "the refusal carries the compared values");
  }
  require(verify_verdict_digest(*shared), "the verdict digest verifies");

  // Every candidate's evidence digest is its own.
  require(!digest_equal(shared->evidence_digest, free_candidate->evidence_digest),
          "each candidate has its own evidence digest");

  // Permuting the request cannot change any decision.
  auto reversed = parse_request_document(kRequestText);
  if (reversed.has_value()) {
    std::swap(reversed.value().candidates[0], reversed.value().candidates[1]);
    EvaluationInput reversed_input;
    reversed_input.request = std::move(reversed.value());
    auto reversed_verdicts = evaluate(snapshot.value(), reversed_input);
    require(reversed_verdicts.has_value(), "the permuted request evaluates");
    if (reversed_verdicts.has_value()) {
      require(encode_verdict_set(reversed_verdicts.value()).value() ==
                  encode_verdict_set(verdicts.value()).value(),
              "a batch is permutation invariant");
    }
  }

  // The durable side: initialise, activate, record, replay, and fence.
  const auto created = initialize_store(store_directory, StoreId::parse("store:downstream").value(), at);
  require(created.has_value(), "the store initialises");
  if (!created.has_value()) {
    std::fprintf(stderr, "downstream: %s\n", created.error().to_string().c_str());
    return 1;
  }
  auto store = Store::open(store_directory, StoreOpenMode::ReadWrite);
  require(store.has_value(), "the store opens for writing");
  if (!store.has_value()) {
    return 1;
  }
  auto before_activation = store.value().snapshot();
  require(!before_activation.has_value(), "a store with no policy refuses to evaluate");
  if (!before_activation.has_value()) {
    require(before_activation.error().code() == ErrorCode::NoActivePolicy,
            "the refusal names the missing authority");
  }

  auto document = parse_policy_document(kPolicyText);
  require(document.has_value(), "the activation document parses");
  if (!document.has_value()) {
    return 1;
  }
  auto binding = store.value().activate_policy(document.value(), at);
  require(binding.has_value(), "the policy activates");
  if (!binding.has_value()) {
    std::fprintf(stderr, "downstream: %s\n", binding.error().to_string().c_str());
    return 1;
  }

  auto recorded = store.value().evaluate_recorded(input, evaluated_at);
  require(recorded.has_value(), "the evaluation is recorded");
  if (!recorded.has_value()) {
    std::fprintf(stderr, "downstream: %s\n", recorded.error().to_string().c_str());
    return 1;
  }
  require(!recorded.value().replayed, "the first recording is not a replay");

  auto replayed = store.value().evaluate_recorded(input, evaluated_at);
  require(replayed.has_value(), "the retry is answered");
  if (replayed.has_value()) {
    require(replayed.value().replayed, "the retry is answered from the record");
    require(digest_equal(replayed.value().candidates.front().verdict_digest,
                         recorded.value().candidates.front().verdict_digest),
            "the replay has the same verdict identity");
  }

  // A new revision advances the authority epoch, which fences the older verdict.
  std::string next_text(kPolicyText);
  const std::size_t position = next_text.find("revision 1");
  next_text.replace(position, std::string("revision 1").size(), "revision 2");
  auto next_document = parse_policy_document(next_text);
  require(next_document.has_value(), "the second revision parses");
  if (next_document.has_value()) {
    auto second = store.value().activate_policy(next_document.value(), at);
    require(second.has_value(), "the second revision activates");
    if (second.has_value()) {
      require(second.value().revision.value() == 2, "the second revision is active");
      require(store.value().status().authority_epoch.value() == 3,
              "the authority epoch advanced with the publication");
      AuthorityState current;
      current.policy = second.value();
      current.authority_epoch = store.value().status().authority_epoch;
      current.generations = recorded.value().generations;
      current.occupancy_generation = recorded.value().occupancy_generation;
      current.maintenance_generation = recorded.value().maintenance_generation;
      auto report = verify_verdict(recorded.value(), recorded.value().candidates.front().candidate_id, current);
      require(report.has_value(), "the older verdict can be checked");
      if (report.has_value()) {
        require(report.value().status == FencingStatus::Fenced,
                "the older verdict is fenced by the new epoch");
      }
    }
  }

  if (failures != 0) {
    std::fprintf(stderr, "downstream: %d check(s) failed\n", failures);
    return 1;
  }
  std::printf("downstream consumer: all checks passed against the installed package\n");
  std::printf("  policy %s revision %s digest %s\n",
              binding.value().policy_id.value().data(),
              binding.value().revision.to_string().c_str(),
              digest_tagged_hex(binding.value().digest).c_str());
  std::printf("  shared=%s free=%s recorded=%zu replayed=%s\n",
              std::string(decision_name(shared->decision)).c_str(),
              std::string(decision_name(free_candidate->decision)).c_str(),
              recorded.value().candidates.size(),
              replayed.has_value() && replayed.value().replayed ? "true" : "false");
  return 0;
}
