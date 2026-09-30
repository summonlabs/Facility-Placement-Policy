// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs.

#include <string>

#include "test_framework.hpp"

#include "dccp/facility_placement_policy/canonical.hpp"
#include "dccp/facility_placement_policy/text.hpp"

namespace {

using namespace dccp::facility_placement_policy;

const char* const kPolicy =
    "fpp-document policy\n"
    "format 1\n"
    "policy-id grid-a\n"
    "revision 4\n"
    "rule spread {\n"
    "  require anti-affinity scope=tenant dimension=rack max-shared=0\n"
    "}\n";

const char* const kRequest =
    "fpp-document request\n"
    "format 1\n"
    "request-id req-1\n"
    "tenant tenant:acme\n"
    "service-class service-class:gold\n"
    "requested-at 2026-02-14T09:30:00.000000Z\n"
    "generations topology=12 failure-domain=9 tenant=4 service-class=3\n"
    "facility facility:dc1 jurisdiction=jurisdiction:eu-de\n"
    "candidate c1 facility=facility:dc1 rack=rack:07\n"
    "occupancy generation=77\n"
    "placed p1 tenant=tenant:acme service-class=service-class:gold facility=facility:dc1 "
    "rack=rack:07\n"
    "maintenance generation=41\n";

PlacementVerdictSet run() {
  auto policy = parse_policy_document(kPolicy);
  FPT_REQUIRE_OK(policy);
  auto snapshot = make_policy_snapshot(std::move(policy.value()),
                                       AuthorityEpoch::from_value(6).value(),
                                       StoreSequence::from_value(3).value(), TopologyGeneration{},
                                       FailureDomainGeneration{});
  FPT_REQUIRE_OK(snapshot);
  EvaluationInput input;
  input.request = parse_request_document(kRequest).value();
  auto verdicts = evaluate(snapshot.value(), input);
  FPT_REQUIRE_OK(verdicts);
  return verdicts.value();
}

AuthorityState current_state(const PlacementVerdictSet& verdicts) {
  AuthorityState state;
  state.policy = verdicts.policy;
  state.authority_epoch = verdicts.authority_epoch;
  state.generations = verdicts.generations;
  state.occupancy_generation = verdicts.occupancy_generation;
  state.maintenance_generation = verdicts.maintenance_generation;
  return state;
}

}  // namespace

FPT_TEST(verdict, a_verdict_binds_the_policy_the_epoch_and_every_generation) {
  const PlacementVerdictSet verdicts = run();
  FPT_CHECK_EQ(verdicts.policy.policy_id.value(), std::string_view("grid-a"));
  FPT_CHECK_EQ(verdicts.policy.revision.value(), std::uint64_t(4));
  FPT_CHECK_EQ(verdicts.authority_epoch.value(), std::uint64_t(6));
  FPT_CHECK_EQ(verdicts.generations.topology.value(), std::uint64_t(12));
  FPT_CHECK_EQ(verdicts.generations.failure_domain.value(), std::uint64_t(9));
  FPT_CHECK_EQ(verdicts.generations.tenant.value(), std::uint64_t(4));
  FPT_CHECK_EQ(verdicts.generations.service_class.value(), std::uint64_t(3));
  FPT_REQUIRE(verdicts.occupancy_generation.has_value());
  FPT_CHECK_EQ(verdicts.occupancy_generation->value(), std::uint64_t(77));
  FPT_REQUIRE(verdicts.maintenance_generation.has_value());
  FPT_CHECK_EQ(verdicts.maintenance_generation->value(), std::uint64_t(41));
  FPT_CHECK_EQ(verdicts.evaluated_at.to_string(), std::string("2026-02-14T09:30:00.000000Z"));
  FPT_CHECK(!digest_is_zero(verdicts.request_digest));
}

FPT_TEST(verdict, the_verdict_digest_verifies_and_detects_tampering) {
  const PlacementVerdictSet verdicts = run();
  const CandidateVerdict& verdict = verdicts.candidates.front();
  FPT_CHECK(verify_verdict_digest(verdict));

  CandidateVerdict tampered = verdict;
  tampered.decision = Decision::Eligible;
  FPT_CHECK(!verify_verdict_digest(tampered));

  CandidateVerdict replayed = verdict;
  replayed.replayed = true;
  // The replay marker is not part of the identity: a replayed verdict is the
  // same verdict.
  FPT_CHECK(verify_verdict_digest(replayed));

  CandidateVerdict reindexed = verdict;
  reindexed.violations.front().detail.append("x");
  FPT_CHECK(!verify_verdict_digest(reindexed));
}

FPT_TEST(verdict, verification_agrees_until_anything_it_binds_moves) {
  const PlacementVerdictSet verdicts = run();
  const CandidateId candidate = verdicts.candidates.front().candidate_id;
  const AuthorityState current = current_state(verdicts);

  auto valid = verify_verdict(verdicts, candidate, current);
  FPT_REQUIRE_OK(valid);
  FPT_CHECK(valid.value().status == FencingStatus::Valid);
  FPT_CHECK(valid.value().digest_verified);
  for (const FencingField& field : valid.value().fields) {
    FPT_CHECK(!field.stale);
  }

  struct Case {
    const char* name;
    void (*mutate)(AuthorityState&);
  };
  const Case cases[] = {
      {"policy-id", [](AuthorityState& state) {
         state.policy.policy_id = PolicyId::parse("grid-b").value();
       }},
      {"policy-revision", [](AuthorityState& state) {
         state.policy.revision = PolicyRevision::from_value(5).value();
       }},
      {"policy-digest", [](AuthorityState& state) { state.policy.digest = digest_of("other"); }},
      {"authority-epoch", [](AuthorityState& state) {
         state.authority_epoch = AuthorityEpoch::from_value(7).value();
       }},
      {"topology", [](AuthorityState& state) {
         state.generations.topology = TopologyGeneration::from_value(13).value();
       }},
      {"failure-domain", [](AuthorityState& state) {
         state.generations.failure_domain = FailureDomainGeneration::from_value(10).value();
       }},
      {"tenant", [](AuthorityState& state) {
         state.generations.tenant = TenantGeneration::from_value(5).value();
       }},
      {"service-class", [](AuthorityState& state) {
         state.generations.service_class = ServiceClassGeneration::from_value(5).value();
       }},
      {"occupancy", [](AuthorityState& state) {
         state.occupancy_generation = OccupancyGeneration::from_value(78).value();
       }},
      {"maintenance", [](AuthorityState& state) {
         state.maintenance_generation = MaintenanceGeneration::from_value(42).value();
       }},
      {"occupancy-absent", [](AuthorityState& state) { state.occupancy_generation.reset(); }},
  };
  for (const Case& item : cases) {
    AuthorityState moved = current;
    item.mutate(moved);
    auto report = verify_verdict(verdicts, candidate, moved);
    FPT_REQUIRE_OK(report);
    FPT_CHECK(report.value().status == FencingStatus::Fenced);
    bool found = false;
    for (const FencingField& field : report.value().fields) {
      if (field.stale) {
        found = true;
        FPT_CHECK(!field.bound.empty());
        FPT_CHECK(!field.current.empty());
      }
    }
    FPT_CHECK(found);
  }

  // A generation that went backwards is still a mismatch, and the report says
  // which direction it went.
  AuthorityState regression = current;
  regression.generations.topology = TopologyGeneration::from_value(11).value();
  auto report = verify_verdict(verdicts, candidate, regression);
  FPT_REQUIRE_OK(report);
  FPT_CHECK(report.value().status == FencingStatus::Fenced);

  FPT_CHECK_ERROR(verify_verdict(verdicts, CandidateId::parse("missing").value(), current),
                  ErrorCode::NotFound);
}

FPT_TEST(verdict, text_rendering_is_stable_and_round_trips) {
  const PlacementVerdictSet verdicts = run();
  const std::string text = verdict_set_text(verdicts);
  FPT_CHECK(text.find("fpp-document verdict") == 0);
  FPT_CHECK(text.find("decision ineligible") != std::string::npos);
  FPT_CHECK(text.find("code=anti-affinity-exceeded") != std::string::npos);

  auto reparsed = parse_verdict_document(text);
  FPT_REQUIRE_OK(reparsed);
  FPT_CHECK_EQ(verdict_document_text(reparsed.value()), text);
  FPT_CHECK(digest_equal(reparsed.value().policy.digest, verdicts.policy.digest));
  FPT_CHECK(verify_verdict_digest(reparsed.value().candidates.front()));

  const FencingReport report = verify_verdict(verdicts, verdicts.candidates.front().candidate_id,
                                              current_state(verdicts))
                                   .value();
  const std::string report_text = fencing_report_text(report);
  FPT_CHECK(report_text.find("valid") != std::string::npos);
  FPT_CHECK(report_text.find("verdict-digest-verified=true") != std::string::npos);
}

FPT_TEST(verdict, a_verdict_set_document_survives_a_round_trip_through_the_encoder) {
  const PlacementVerdictSet verdicts = run();
  auto encoded = encode_verdict_set(verdicts);
  FPT_REQUIRE_OK(encoded);
  auto decoded = decode_verdict_set(encoded.value());
  FPT_REQUIRE_OK(decoded);
  FPT_CHECK_EQ(verdict_document_text(decoded.value()), verdict_set_text(verdicts));
  FPT_CHECK(verify_verdict_digest(decoded.value().candidates.front()));
}
