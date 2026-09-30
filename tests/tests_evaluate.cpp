// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs.

#include <algorithm>
#include <string>
#include <vector>

#include "test_framework.hpp"

#include "dccp/facility_placement_policy/canonical.hpp"
#include "dccp/facility_placement_policy/text.hpp"

namespace {

using namespace dccp::facility_placement_policy;
using namespace fptest;

PolicySnapshot snapshot_of(const std::string& policy_text, std::uint64_t epoch = 2,
                           const std::string& topology_floor = "",
                           const std::string& failure_domain_floor = "") {
  auto policy = parse_policy_document(policy_text);
  FPT_REQUIRE_OK(policy);
  TopologyGeneration topology;
  FailureDomainGeneration failure_domain;
  if (!topology_floor.empty()) {
    topology = TopologyGeneration::from_value(std::stoull(topology_floor)).value();
  }
  if (!failure_domain_floor.empty()) {
    failure_domain = FailureDomainGeneration::from_value(std::stoull(failure_domain_floor)).value();
  }
  auto snapshot = make_policy_snapshot(std::move(policy.value()),
                                       AuthorityEpoch::from_value(epoch).value(),
                                       StoreSequence::from_value(9).value(), topology,
                                       failure_domain);
  FPT_REQUIRE_OK(snapshot);
  return snapshot.value();
}

PlacementRequest request_of(const std::string& request_text) {
  auto request = parse_request_document(request_text);
  FPT_REQUIRE_OK(request);
  return request.value();
}

/// The verdict for one candidate, or a failure when the evaluation refused.
Result<CandidateVerdict> verdict_for(const PolicySnapshot& snapshot,
                                     const EvaluationInput& input,
                                     const std::string& candidate_id) {
  auto verdicts = evaluate(snapshot, input);
  if (!verdicts.has_value()) {
    return verdicts.error();
  }
  for (const CandidateVerdict& candidate : verdicts.value().candidates) {
    if (candidate.candidate_id.value() == candidate_id) {
      return candidate;
    }
  }
  return Error(ErrorCode::NotFound, "no such candidate").with_subject(candidate_id);
}

std::string rule_wrapping(const std::string& requirement) {
  return "fpp-document policy\nformat 1\npolicy-id grid-a\nrevision 1\nrule r {\n  require " +
         requirement + "\n}\n";
}

std::string request_with(const std::string& extra_facility, const std::string& candidate_extra,
                         const std::string& occupancy, const std::string& maintenance) {
  return "fpp-document request\n"
         "format 1\n"
         "request-id req-1\n"
         "tenant tenant:acme\n"
         "service-class service-class:gold\n"
         "requested-at 2026-02-14T09:30:00.000000Z\n"
         "generations topology=12 failure-domain=9 tenant=4 service-class=3\n"
         "facility facility:dc1 jurisdiction=jurisdiction:eu-de\n" +
         extra_facility +
         "candidate c1 facility=facility:dc1 rack=rack:07 " + candidate_extra + "\n" + occupancy +
         maintenance;
}

const char* const kBaseOccupancy =
    "occupancy generation=77\n"
    "placed p1 tenant=tenant:acme service-class=service-class:gold facility=facility:dc1 "
    "rack=rack:07 failure-domains=power:pd-1\n";

const char* const kBaseMaintenance = "maintenance generation=41\n";

}  // namespace

FPT_TEST(evaluate, a_policy_with_no_applicable_rule_says_so) {
  const PolicySnapshot snapshot = snapshot_of(
      "fpp-document policy\nformat 1\npolicy-id grid-a\nrevision 1\n"
      "rule scoped {\n  select tenants=tenant:other\n"
      "  require anti-affinity scope=tenant dimension=rack max-shared=0\n}\n");
  const PlacementRequest request =
      request_of(request_with("", "", kBaseOccupancy, kBaseMaintenance));
  EvaluationInput input;
  input.request = request;
  auto verdict = verdict_for(snapshot, input, "c1");
  FPT_REQUIRE_OK(verdict);
  FPT_CHECK(verdict.value().decision == Decision::Eligible);
  FPT_CHECK(!verdict.value().constrained);
  FPT_CHECK(verdict.value().applied_rules.empty());
  FPT_CHECK_EQ(verdict.value().not_applicable_rules.size(), std::size_t(1));
}

FPT_TEST(evaluate, jurisdiction_is_typed_and_unknown_is_not_a_match) {
  const PolicySnapshot allow = snapshot_of(rule_wrapping(
      "jurisdiction allow=jurisdiction:eu-de,jurisdiction:eu-fr deny="));
  EvaluationInput input;
  input.request = request_of(request_with("", "", kBaseOccupancy, kBaseMaintenance));
  auto eligible = verdict_for(allow, input, "c1");
  FPT_REQUIRE_OK(eligible);
  FPT_CHECK(eligible.value().decision == Decision::Eligible);

  const PolicySnapshot deny =
      snapshot_of(rule_wrapping("jurisdiction allow= deny=jurisdiction:eu-de"));
  auto denied = verdict_for(deny, input, "c1");
  FPT_REQUIRE_OK(denied);
  FPT_CHECK(denied.value().decision == Decision::Ineligible);
  FPT_CHECK_EQ(denied.value().violations.size(), std::size_t(1));
  FPT_CHECK(denied.value().violations.front().code == ViolationCode::JurisdictionDenied);

  const PolicySnapshot elsewhere = snapshot_of(rule_wrapping("jurisdiction allow=jurisdiction:us-east deny="));
  auto not_allowed = verdict_for(elsewhere, input, "c1");
  FPT_REQUIRE_OK(not_allowed);
  FPT_CHECK(not_allowed.value().violations.front().code == ViolationCode::JurisdictionNotAllowed);

  // A facility with no published jurisdiction never satisfies a jurisdiction
  // requirement, whatever the allow list says.
  const PolicySnapshot unknown = snapshot_of(rule_wrapping("jurisdiction allow=jurisdiction:eu-de deny="));
  EvaluationInput unknown_input;
  unknown_input.request = request_of(request_with("", "", kBaseOccupancy, kBaseMaintenance));
  unknown_input.request.facilities.front().jurisdiction.reset();
  auto refused = verdict_for(unknown, unknown_input, "c1");
  FPT_REQUIRE_OK(refused);
  FPT_CHECK(refused.value().decision == Decision::Ineligible);
  FPT_CHECK(refused.value().violations.front().code == ViolationCode::JurisdictionUnknown);
}

FPT_TEST(evaluate, typed_attribute_predicates_compare_values_not_names) {
  const std::string facility = "attribute facility=facility:dc1 key=power-feed-count value=3\n";
  const std::string cooling = "attribute facility=facility:dc1 key=cooling-mode value=direct-liquid\n";
  const PlacementRequest request =
      request_of(request_with(facility + cooling, "", kBaseOccupancy, kBaseMaintenance));

  const PolicySnapshot satisfied = snapshot_of(rule_wrapping(
      "facility-attribute key=power-feed-count op=at-least value=2"));
  EvaluationInput input;
  input.request = request;
  auto ok = verdict_for(satisfied, input, "c1");
  FPT_REQUIRE_OK(ok);
  FPT_CHECK(ok.value().decision == Decision::Eligible);

  const PolicySnapshot too_high = snapshot_of(rule_wrapping(
      "facility-attribute key=power-feed-count op=at-least value=4"));
  auto below = verdict_for(too_high, input, "c1");
  FPT_REQUIRE_OK(below);
  FPT_CHECK(below.value().violations.front().code == ViolationCode::AttributeUnsatisfied);

  const PolicySnapshot enums = snapshot_of(rule_wrapping(
      "facility-attribute key=cooling-mode op=equal value=direct-liquid"));
  auto equal = verdict_for(enums, input, "c1");
  FPT_REQUIRE_OK(equal);
  FPT_CHECK(equal.value().decision == Decision::Eligible);

  const PolicySnapshot wrong_enum = snapshot_of(rule_wrapping(
      "facility-attribute key=cooling-mode op=not-equal value=direct-liquid"));
  auto excluded = verdict_for(wrong_enum, input, "c1");
  FPT_REQUIRE_OK(excluded);
  FPT_CHECK(excluded.value().violations.front().code == ViolationCode::AttributeUnsatisfied);

  // An attribute the facility does not publish can never satisfy a predicate
  // that needs its value.
  const PolicySnapshot unmeasured = snapshot_of(rule_wrapping(
      "facility-attribute key=security-tier op=at-most value=4"));
  auto missing = verdict_for(unmeasured, input, "c1");
  FPT_REQUIRE_OK(missing);
  FPT_CHECK(missing.value().violations.front().code == ViolationCode::AttributeUnmeasured);

  // Requiring absence is satisfied by an absent attribute.
  const PolicySnapshot absent = snapshot_of(rule_wrapping(
      "facility-attribute key=security-tier op=absent"));
  auto absent_ok = verdict_for(absent, input, "c1");
  FPT_REQUIRE_OK(absent_ok);
  FPT_CHECK(absent_ok.value().decision == Decision::Eligible);

  const PolicySnapshot present = snapshot_of(rule_wrapping(
      "facility-attribute key=security-tier op=present"));
  auto absent_fails = verdict_for(present, input, "c1");
  FPT_REQUIRE_OK(absent_fails);
  FPT_CHECK(absent_fails.value().violations.front().code == ViolationCode::AttributeUnmeasured);

  const PolicySnapshot equal_ok = snapshot_of(rule_wrapping(
      "facility-attribute key=power-feed-count op=equal value=3"));
  auto exact = verdict_for(equal_ok, input, "c1");
  FPT_REQUIRE_OK(exact);
  FPT_CHECK(exact.value().decision == Decision::Eligible);
}

FPT_TEST(evaluate, separation_uses_explicit_identities_per_dimension) {
  const PlacementRequest request =
      request_of(request_with("", "failure-domains=power:pd-1", kBaseOccupancy, kBaseMaintenance));
  EvaluationInput input;
  input.request = request;

  const PolicySnapshot denied = snapshot_of(rule_wrapping(
      "separation dimension=rack deny=rack:rack:07"));
  auto refused = verdict_for(denied, input, "c1");
  FPT_REQUIRE_OK(refused);
  FPT_CHECK(refused.value().violations.front().code == ViolationCode::SeparationDenied);

  const PolicySnapshot allowed = snapshot_of(rule_wrapping(
      "separation dimension=rack allow=rack:rack:07"));
  auto ok = verdict_for(allowed, input, "c1");
  FPT_REQUIRE_OK(ok);
  FPT_CHECK(ok.value().decision == Decision::Eligible);

  const PolicySnapshot not_allowed = snapshot_of(rule_wrapping(
      "separation dimension=rack allow=rack:rack:01"));
  auto elsewhere = verdict_for(not_allowed, input, "c1");
  FPT_REQUIRE_OK(elsewhere);
  FPT_CHECK(elsewhere.value().violations.front().code == ViolationCode::SeparationNotAllowed);

  // A dimension the candidate does not declare cannot be compared, and silence
  // is not agreement.
  const PolicySnapshot unmeasured = snapshot_of(rule_wrapping(
      "separation dimension=room deny=room:room:1"));
  auto missing = verdict_for(unmeasured, input, "c1");
  FPT_REQUIRE_OK(missing);
  FPT_CHECK(missing.value().violations.front().code == ViolationCode::DimensionUnmeasured);
}

FPT_TEST(evaluate, anti_affinity_counts_only_what_the_evidence_shows) {
  const PlacementRequest request =
      request_of(request_with("", "", kBaseOccupancy, kBaseMaintenance));
  EvaluationInput input;
  input.request = request;

  const PolicySnapshot strict = snapshot_of(rule_wrapping(
      "anti-affinity scope=tenant dimension=rack max-shared=0"));
  auto blocked = verdict_for(strict, input, "c1");
  FPT_REQUIRE_OK(blocked);
  FPT_CHECK(blocked.value().decision == Decision::Ineligible);
  FPT_CHECK(blocked.value().violations.front().code == ViolationCode::AntiAffinityExceeded);

  const PolicySnapshot tolerant = snapshot_of(rule_wrapping(
      "anti-affinity scope=tenant dimension=rack max-shared=1"));
  auto allowed = verdict_for(tolerant, input, "c1");
  FPT_REQUIRE_OK(allowed);
  FPT_CHECK(allowed.value().decision == Decision::Eligible);

  // Another tenant's placements are not in scope.
  const PolicySnapshot by_other_tenant = snapshot_of(rule_wrapping(
      "anti-affinity scope=service-class dimension=rack max-shared=0"));
  auto other_scope = verdict_for(by_other_tenant, input, "c1");
  FPT_REQUIRE_OK(other_scope);
  FPT_CHECK(other_scope.value().decision == Decision::Ineligible);
  const PolicySnapshot any_scope = snapshot_of(rule_wrapping(
      "anti-affinity scope=any dimension=rack max-shared=0"));
  auto any_result = verdict_for(any_scope, input, "c1");
  FPT_REQUIRE_OK(any_result);
  FPT_CHECK(any_result.value().decision == Decision::Ineligible);

  // No occupancy evidence at all is not the same as no neighbours.
  EvaluationInput without_occupancy;
  PlacementRequest bare = request_of(request_with("", "", "", kBaseMaintenance));
  without_occupancy.request = bare;
  auto absent = verdict_for(strict, without_occupancy, "c1");
  FPT_REQUIRE_OK(absent);
  FPT_CHECK(absent.value().violations.front().code == ViolationCode::OccupancyEvidenceAbsent);

  // A neighbour whose identity in the dimension is unknown cannot be shown to be
  // somewhere else, so separation from it cannot be established.
  EvaluationInput unknown_neighbour;
  unknown_neighbour.request = request_of(
      request_with("", "", "occupancy generation=77\n"
                           "placed p1 tenant=tenant:acme service-class=service-class:gold "
                           "facility=facility:dc1\n",
                   kBaseMaintenance));
  auto unverifiable = verdict_for(strict, unknown_neighbour, "c1");
  FPT_REQUIRE_OK(unverifiable);
  FPT_CHECK(unverifiable.value().violations.front().code == ViolationCode::DimensionUnmeasured);

  // An empty occupancy set with a published generation is a real observation.
  EvaluationInput empty_occupancy;
  empty_occupancy.request =
      request_of(request_with("", "", "occupancy generation=77\n", kBaseMaintenance));
  auto alone = verdict_for(strict, empty_occupancy, "c1");
  FPT_REQUIRE_OK(alone);
  FPT_CHECK(alone.value().decision == Decision::Eligible);
}

FPT_TEST(evaluate, redundancy_counts_distinct_domains_including_the_candidate) {
  const std::string occupancy =
      "occupancy generation=77\n"
      "placed p1 tenant=tenant:acme service-class=service-class:gold facility=facility:dc1 "
      "rack=rack:07 failure-domains=power:pd-1\n"
      "placed p2 tenant=tenant:acme service-class=service-class:gold facility=facility:dc1 "
      "rack=rack:09 failure-domains=power:pd-2\n";
  EvaluationInput input;
  input.request = request_of(
      request_with("", "failure-domains=power:pd-1", occupancy, kBaseMaintenance));

  // The candidate shares pd-1 with p1, so the set spans two power domains.
  const PolicySnapshot two = snapshot_of(rule_wrapping(
      "redundancy scope=tenant dimension=failure-domain:power min-distinct-domains=2"));
  auto satisfied = verdict_for(two, input, "c1");
  FPT_REQUIRE_OK(satisfied);
  FPT_CHECK(satisfied.value().decision == Decision::Eligible);

  const PolicySnapshot three = snapshot_of(rule_wrapping(
      "redundancy scope=tenant dimension=failure-domain:power min-distinct-domains=3"));
  auto unsatisfied = verdict_for(three, input, "c1");
  FPT_REQUIRE_OK(unsatisfied);
  FPT_CHECK(unsatisfied.value().violations.front().code == ViolationCode::RedundancyUnsatisfied);

  // A single placement always spans one domain.
  EvaluationInput alone;
  alone.request = request_of(request_with("", "failure-domains=power:pd-1",
                                          "occupancy generation=77\n", kBaseMaintenance));
  const PolicySnapshot one = snapshot_of(rule_wrapping(
      "redundancy scope=tenant dimension=failure-domain:power min-distinct-domains=1"));
  auto single = verdict_for(one, alone, "c1");
  FPT_REQUIRE_OK(single);
  FPT_CHECK(single.value().decision == Decision::Eligible);
}

FPT_TEST(evaluate, co_tenancy_separates_named_tenants_and_service_classes) {
  const std::string occupancy =
      "occupancy generation=77\n"
      "placed p1 tenant=tenant:other service-class=service-class:bronze facility=facility:dc1 "
      "rack=rack:07\n";
  EvaluationInput input;
  input.request = request_of(request_with("", "", occupancy, kBaseMaintenance));

  const PolicySnapshot forbidden_tenant = snapshot_of(rule_wrapping(
      "co-tenancy dimension=rack tenants=tenant:other service-classes= max-shared=0"));
  auto blocked = verdict_for(forbidden_tenant, input, "c1");
  FPT_REQUIRE_OK(blocked);
  FPT_CHECK(blocked.value().violations.front().code == ViolationCode::CoTenancyExceeded);

  const PolicySnapshot forbidden_class = snapshot_of(rule_wrapping(
      "co-tenancy dimension=rack tenants= service-classes=service-class:bronze max-shared=0"));
  auto blocked_class = verdict_for(forbidden_class, input, "c1");
  FPT_REQUIRE_OK(blocked_class);
  FPT_CHECK(blocked_class.value().violations.front().code == ViolationCode::CoTenancyExceeded);

  const PolicySnapshot unrelated = snapshot_of(rule_wrapping(
      "co-tenancy dimension=rack tenants=tenant:nobody service-classes= max-shared=0"));
  auto fine = verdict_for(unrelated, input, "c1");
  FPT_REQUIRE_OK(fine);
  FPT_CHECK(fine.value().decision == Decision::Eligible);

  // A forbidden placement with an unknown rack cannot be shown to be elsewhere.
  EvaluationInput unknown;
  unknown.request = request_of(
      request_with("", "", "occupancy generation=77\n"
                           "placed p1 tenant=tenant:other service-class=service-class:bronze "
                           "facility=facility:dc1\n",
                   kBaseMaintenance));
  auto unverifiable = verdict_for(forbidden_tenant, unknown, "c1");
  FPT_REQUIRE_OK(unverifiable);
  FPT_CHECK(unverifiable.value().violations.front().code == ViolationCode::DimensionUnmeasured);
}

FPT_TEST(evaluate, maintenance_exposure_is_windowed_and_severity_thresholded) {
  const std::string blackout =
      "maintenance generation=41\n"
      "exposure e1 kind=planned severity=blackout scope-rack=rack:07 "
      "start=2026-02-14T10:00:00.000000Z end=2026-02-14T12:00:00.000000Z\n";
  const std::string advisory =
      "maintenance generation=41\n"
      "exposure e1 kind=degradation severity=advisory scope-rack=rack:07 "
      "start=2026-02-14T10:00:00.000000Z end=2026-02-14T12:00:00.000000Z\n";
  const std::string degraded =
      "maintenance generation=41\n"
      "exposure e1 kind=degradation severity=degraded scope-rack=rack:07 "
      "start=2026-02-14T10:00:00.000000Z end=2026-02-14T12:00:00.000000Z\n";
  // A window that ends exactly when the evaluation happens is in the past.
  const std::string past =
      "maintenance generation=41\n"
      "exposure e1 kind=planned severity=blackout scope-rack=rack:07 "
      "start=2026-02-14T07:00:00.000000Z end=2026-02-14T09:30:00.000000Z\n";

  const PolicySnapshot constraint = snapshot_of(rule_wrapping(
      "maintenance-exposure min-severity=degraded horizon=1d"));

  const auto check = [&constraint](const std::string& maintenance) -> CandidateVerdict {
    EvaluationInput input;
    input.request = request_of(request_with("", "", kBaseOccupancy, maintenance));
    auto verdict = verdict_for(constraint, input, "c1");
    FPT_REQUIRE_OK(verdict);
    return verdict.value();
  };

  const CandidateVerdict blocked = check(blackout);
  FPT_CHECK(blocked.decision == Decision::Ineligible);
  FPT_CHECK(blocked.violations.front().code == ViolationCode::MaintenanceBlackout);

  const CandidateVerdict degraded_result = check(degraded);
  FPT_CHECK(degraded_result.violations.front().code == ViolationCode::MaintenanceDegraded);

  const CandidateVerdict advisory_result = check(advisory);
  FPT_CHECK(advisory_result.decision == Decision::Eligible);

  const CandidateVerdict past_result = check(past);
  FPT_CHECK(past_result.decision == Decision::Eligible);

  // Advisory exposure only blocks when the policy asks for it.
  const PolicySnapshot strict = snapshot_of(rule_wrapping(
      "maintenance-exposure min-severity=advisory horizon=1d"));
  EvaluationInput advisory_input;
  advisory_input.request = request_of(request_with("", "", kBaseOccupancy, advisory));
  auto strict_result = verdict_for(strict, advisory_input, "c1");
  FPT_REQUIRE_OK(strict_result);
  FPT_CHECK(strict_result.value().decision == Decision::Ineligible);

  // A horizon that does not reach the window does not block.
  const PolicySnapshot short_horizon = snapshot_of(rule_wrapping(
      "maintenance-exposure min-severity=degraded horizon=1m"));
  EvaluationInput blackout_input;
  blackout_input.request = request_of(request_with("", "", kBaseOccupancy, blackout));
  auto short_result = verdict_for(short_horizon, blackout_input, "c1");
  FPT_REQUIRE_OK(short_result);
  FPT_CHECK(short_result.value().decision == Decision::Eligible);

  // No maintenance evidence at all is not "no maintenance".
  EvaluationInput absent;
  absent.request = request_of(request_with("", "", kBaseOccupancy, ""));
  auto absent_result = verdict_for(constraint, absent, "c1");
  FPT_REQUIRE_OK(absent_result);
  FPT_CHECK(absent_result.value().violations.front().code ==
            ViolationCode::MaintenanceEvidenceAbsent);

  // An exposure scoped to a place the candidate does not declare cannot be ruled
  // out.
  EvaluationInput unverifiable;
  unverifiable.request = request_of(
      request_with("", "", kBaseOccupancy,
                   "maintenance generation=41\n"
                   "exposure e1 kind=planned severity=blackout scope-room=room:9 "
                   "start=2026-02-14T10:00:00.000000Z end=2026-02-14T12:00:00.000000Z\n"));
  auto unverifiable_result = verdict_for(constraint, unverifiable, "c1");
  FPT_REQUIRE_OK(unverifiable_result);
  FPT_CHECK(unverifiable_result.value().violations.front().code ==
            ViolationCode::MaintenanceScopeUnverifiable);

  // An exposure scoped to another facility provably does not apply.
  EvaluationInput elsewhere;
  elsewhere.request = request_of(
      request_with("", "", kBaseOccupancy,
                   "maintenance generation=41\n"
                   "exposure e1 kind=planned severity=blackout scope-facility=facility:dc2 "
                   "start=2026-02-14T10:00:00.000000Z end=2026-02-14T12:00:00.000000Z\n"));
  auto elsewhere_result = verdict_for(constraint, elsewhere, "c1");
  FPT_REQUIRE_OK(elsewhere_result);
  FPT_CHECK(elsewhere_result.value().decision == Decision::Eligible);
}

FPT_TEST(evaluate, the_generation_floor_refuses_a_replayed_older_world) {
  const PolicySnapshot snapshot = snapshot_of(rule_wrapping("jurisdiction allow=jurisdiction:eu-de deny="),
                                              2, "12", "9");
  EvaluationInput input;
  input.request = request_of(request_with("", "", kBaseOccupancy, kBaseMaintenance));
  FPT_REQUIRE_OK(evaluate(snapshot, input));

  // The same request with an older topology generation is refused before any
  // decision is made.
  EvaluationInput stale;
  stale.request = input.request;
  stale.request.generations.topology = TopologyGeneration::from_value(11).value();
  FPT_CHECK_ERROR(evaluate(snapshot, stale), ErrorCode::StaleTopologyGeneration);

  EvaluationInput stale_domain;
  stale_domain.request = input.request;
  stale_domain.request.generations.failure_domain =
      FailureDomainGeneration::from_value(8).value();
  FPT_CHECK_ERROR(evaluate(snapshot, stale_domain), ErrorCode::StaleFailureDomainGeneration);

  // A newer generation is accepted and a caller that genuinely means to replay
  // historical evidence can say so explicitly.
  EvaluationInput newer;
  newer.request = input.request;
  newer.request.generations.topology = TopologyGeneration::from_value(13).value();
  FPT_REQUIRE_OK(evaluate(snapshot, newer));
  EvaluationOptions relaxed;
  relaxed.enforce_generation_floor = false;
  FPT_REQUIRE_OK(evaluate(snapshot, stale, relaxed));
}

FPT_TEST(evaluate, a_batch_is_permutation_invariant_and_self_consistent) {
  const std::string policy =
      "fpp-document policy\n"
      "format 1\n"
      "policy-id grid-a\n"
      "revision 1\n"
      "rule spread {\n"
      "  require anti-affinity scope=tenant dimension=rack max-shared=0\n"
      "}\n"
      "rule legal {\n"
      "  require jurisdiction allow=jurisdiction:eu-de deny=\n"
      "}\n";
  const std::string request_text =
      "fpp-document request\n"
      "format 1\n"
      "request-id req-1\n"
      "tenant tenant:acme\n"
      "service-class service-class:gold\n"
      "requested-at 2026-02-14T09:30:00.000000Z\n"
      "generations topology=12 failure-domain=9 tenant=4 service-class=3\n"
      "facility facility:dc1 jurisdiction=jurisdiction:eu-de\n"
      "candidate c3 facility=facility:dc1 rack=rack:07\n"
      "candidate c1 facility=facility:dc1 rack=rack:09\n"
      "candidate c2 facility=facility:dc1 rack=rack:07\n"
      "occupancy generation=77\n"
      "placed p1 tenant=tenant:acme service-class=service-class:gold facility=facility:dc1 "
      "rack=rack:07\n"
      "maintenance generation=41\n";
  const PolicySnapshot snapshot = snapshot_of(policy);
  EvaluationInput input;
  input.request = request_of(request_text);
  auto forward = evaluate(snapshot, input);
  FPT_REQUIRE_OK(forward);
  FPT_CHECK_EQ(forward.value().candidates.size(), std::size_t(3));
  FPT_CHECK_EQ(forward.value().candidates[0].candidate_id.value(), std::string_view("c1"));
  FPT_CHECK_EQ(forward.value().candidates[1].candidate_id.value(), std::string_view("c2"));

  // The same candidates in the opposite order produce identical bytes.
  auto reversed_request = parse_request_document(request_text);
  FPT_REQUIRE_OK(reversed_request);
  std::reverse(reversed_request.value().candidates.begin(), reversed_request.value().candidates.end());
  EvaluationInput reversed_input;
  reversed_input.request = std::move(reversed_request.value());
  auto reversed = evaluate(snapshot, reversed_input);
  FPT_REQUIRE_OK(reversed);
  FPT_CHECK(encode_verdict_set(forward.value()).value() ==
            encode_verdict_set(reversed.value()).value());

  // Every candidate carries its own evidence digest and its own verdict digest.
  FPT_CHECK(!digest_equal(forward.value().candidates[0].evidence_digest,
                          forward.value().candidates[1].evidence_digest));
  FPT_CHECK(!digest_equal(forward.value().candidates[0].verdict_digest,
                          forward.value().candidates[1].verdict_digest));
  for (const CandidateVerdict& candidate : forward.value().candidates) {
    FPT_CHECK(verify_verdict_digest(candidate));
  }

  // c1 is in another rack and is eligible; c2 and c3 share a rack with p1.
  FPT_CHECK(forward.value().candidates[0].decision == Decision::Eligible);
  FPT_CHECK(forward.value().candidates[1].decision == Decision::Ineligible);
  FPT_CHECK(forward.value().candidates[2].decision == Decision::Ineligible);

  // Evaluating one candidate on its own agrees with the batch.
  auto single = evaluate_candidate(snapshot, input, CandidateId::parse("c2").value());
  FPT_REQUIRE_OK(single);
  FPT_CHECK(digest_equal(single.value().verdict_digest, forward.value().candidates[1].verdict_digest));
}
