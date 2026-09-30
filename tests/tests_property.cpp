// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs.

#include <algorithm>
#include <cstdint>
#include <string>
#include <vector>

#include "test_framework.hpp"
#include "test_rng.hpp"
#include "test_support.hpp"

#include "dccp/facility_placement_policy/facility_placement_policy.hpp"

namespace {

using namespace dccp::facility_placement_policy;
using namespace fptest;

/// Builds a policy whose rules and constraints are written in the given order.
std::string build_policy(const std::vector<std::pair<std::string, std::vector<std::string>>>& rules) {
  std::string text =
      "fpp-document policy\nformat 1\npolicy-id grid-a\nrevision 1\n";
  for (const auto& rule : rules) {
    text.append("rule " + rule.first + " {\n");
    for (const std::string& constraint : rule.second) {
      text.append("  require " + constraint + "\n");
    }
    text.append("}\n");
  }
  return text;
}

std::vector<std::pair<std::string, std::vector<std::string>>> base_rules() {
  return {{"alpha", {"jurisdiction allow=jurisdiction:eu-de,jurisdiction:eu-fr deny="}},
          {"beta", {"anti-affinity scope=tenant dimension=rack max-shared=1",
                    "redundancy scope=service-class dimension=failure-domain:power "
                    "min-distinct-domains=2"}},
          {"gamma", {"facility-attribute key=power-feed-count op=at-least value=2",
                     "separation dimension=rack deny=rack:rack:99",
                     "co-tenancy dimension=row tenants=tenant:other service-classes= max-shared=0",
                     "maintenance-exposure min-severity=degraded horizon=7d"}}};
}

std::string build_request(std::uint64_t seed, std::size_t candidates) {
  fptest::Rng rng(seed);
  fptest::RngAdapter random(rng);
  std::string text =
      "fpp-document request\n"
      "format 1\n"
      "request-id req-prop\n"
      "tenant tenant:acme\n"
      "service-class service-class:gold\n"
      "requested-at 2026-02-14T09:30:00.000000Z\n"
      "generations topology=12 failure-domain=9 tenant=4 service-class=3\n"
      "facility facility:dc1 jurisdiction=jurisdiction:eu-de\n";
  std::vector<std::string> racks;
  for (std::size_t index = 0; index < candidates; ++index) {
    const std::string rack = "rack:r" + std::to_string(rng.below(6));
    racks.push_back(rack);
    text.append("candidate c" + std::to_string(index) + " facility=facility:dc1 rack=" + rack +
                " failure-domains=power:pd-" + std::to_string(rng.below(4)) + "\n");
  }
  text.append("occupancy generation=77\n");
  for (std::size_t index = 0; index < 4; ++index) {
    text.append("placed p" + std::to_string(index) +
                " tenant=tenant:acme service-class=service-class:gold facility=facility:dc1 rack=" +
                racks[rng.below(racks.size())] + "\n");
  }
  text.append("maintenance generation=41\n");
  return text;
}

}  // namespace

FPT_TEST(property, canonical_identity_is_independent_of_authoring_order) {
  const auto rules = base_rules();
  auto reference = parse_policy_document(build_policy(rules));
  FPT_REQUIRE_OK(reference);
  const Digest expected = reference.value().digest;
  const std::string canonical = policy_document_text(reference.value());

  for (std::uint64_t seed = 1; seed <= 40; ++seed) {
    fptest::Rng rng(seed * 7919u);
    fptest::RngAdapter random(rng);
    auto shuffled = rules;
    std::shuffle(shuffled.begin(), shuffled.end(), random);
    for (auto& rule : shuffled) {
      std::shuffle(rule.second.begin(), rule.second.end(), random);
    }
    fptest::set_failure_context("order-seed=" + std::to_string(seed));
    auto document = parse_policy_document(build_policy(shuffled));
    FPT_REQUIRE_OK(document);
    FPT_CHECK(digest_equal(document.value().digest, expected));
    FPT_CHECK_EQ(policy_document_text(document.value()), canonical);
    auto encoded = encode_policy(document.value());
    FPT_REQUIRE_OK(encoded);
    auto decoded = decode_policy(encoded.value());
    FPT_REQUIRE_OK(decoded);
    FPT_CHECK(encode_policy(decoded.value()).value() == encoded.value());
  }
  fptest::set_failure_context("");
}

FPT_TEST(property, a_batch_never_depends_on_the_order_of_its_candidates) {
  const auto rules = base_rules();
  auto policy = parse_policy_document(build_policy(rules));
  FPT_REQUIRE_OK(policy);
  auto snapshot = make_policy_snapshot(std::move(policy.value()),
                                       AuthorityEpoch::from_value(3).value(),
                                       StoreSequence::from_value(4).value(), TopologyGeneration{},
                                       FailureDomainGeneration{});
  FPT_REQUIRE_OK(snapshot);

  for (std::uint64_t seed = 1; seed <= 25; ++seed) {
    const std::string text = build_request(seed, 6);
    auto forward = parse_request_document(text);
    FPT_REQUIRE_OK(forward);
    EvaluationInput forward_input;
    forward_input.request = forward.value();
    auto reference = evaluate(snapshot.value(), forward_input);
    FPT_REQUIRE_OK(reference);
    const ByteBuffer expected = encode_verdict_set(reference.value()).value();

    for (int attempt = 0; attempt < 4; ++attempt) {
      fptest::Rng rng(seed * 104729u + static_cast<std::uint64_t>(attempt));
      fptest::RngAdapter random(rng);
      auto shuffled = forward.value();
      std::shuffle(shuffled.candidates.begin(), shuffled.candidates.end(), random);
      EvaluationInput input;
      input.request = std::move(shuffled);
      fptest::set_failure_context("batch-seed=" + std::to_string(seed) +
                                  " attempt=" + std::to_string(attempt));
      auto verdicts = evaluate(snapshot.value(), input);
      FPT_REQUIRE_OK(verdicts);
      FPT_CHECK(encode_verdict_set(verdicts.value()).value() == expected);
      // Evaluating one candidate alone agrees with its entry in the batch.
      const CandidateId id = verdicts.value().candidates.front().candidate_id;
      auto single = evaluate_candidate(snapshot.value(), input, id);
      FPT_REQUIRE_OK(single);
      FPT_CHECK(digest_equal(single.value().verdict_digest,
                             verdicts.value().candidates.front().verdict_digest));
    }
  }
  fptest::set_failure_context("");
}

FPT_TEST(property, the_same_request_always_produces_the_same_verdict) {
  auto policy = parse_policy_document(build_policy(base_rules()));
  FPT_REQUIRE_OK(policy);
  auto snapshot = make_policy_snapshot(std::move(policy.value()),
                                       AuthorityEpoch::from_value(3).value(),
                                       StoreSequence::from_value(4).value(), TopologyGeneration{},
                                       FailureDomainGeneration{});
  FPT_REQUIRE_OK(snapshot);
  EvaluationInput input;
  input.request = parse_request_document(build_request(1234, 8)).value();
  auto first = evaluate(snapshot.value(), input);
  FPT_REQUIRE_OK(first);
  for (int repeat = 0; repeat < 5; ++repeat) {
    auto again = evaluate(snapshot.value(), input);
    FPT_REQUIRE_OK(again);
    FPT_CHECK(encode_verdict_set(again.value()).value() ==
              encode_verdict_set(first.value()).value());
  }
}

FPT_TEST(property, a_seeded_state_machine_keeps_its_invariants_after_every_action) {
  auto directory = fresh_directory("property-machine");
  FPT_REQUIRE_OK(directory);
  const auto created = initialize_store(directory.value(), StoreId::parse("store:main").value(),
                                        Instant::parse("2026-02-14T09:00:00.000000Z").value());
  FPT_REQUIRE_OK(created);
  auto store = Store::open(directory.value(), StoreOpenMode::ReadWrite);
  FPT_REQUIRE_OK(store);

  const std::string policy_text = build_policy(base_rules());
  const std::string request_text = build_request(99, 4);
  std::uint64_t revision = 0;
  std::uint64_t request_counter = 0;
  std::uint64_t usage_counter = 0;

  fptest::Rng rng(0xC0FFEEULL);
  for (int step = 0; step < 60; ++step) {
    const std::uint64_t action = rng.below(5);
    fptest::set_failure_context("machine-step=" + std::to_string(step) +
                                " action=" + std::to_string(action));
    if (action == 0 || revision == 0) {
      revision += 1;
      std::string text = policy_text;
      const std::size_t position = text.find("revision 1");
      text.replace(position, std::string("revision 1").size(), "revision " + std::to_string(revision));
      auto document = parse_policy_document(text);
      FPT_REQUIRE_OK(document);
      auto binding = store.value().activate_policy(document.value(),
                                                   Instant::parse("2026-02-14T09:05:00.000000Z").value());
      FPT_REQUIRE_OK(binding);
      FPT_CHECK_EQ(binding.value().revision.value(), revision);
      continue;
    }
    if (action == 1) {
      auto status = store.value().status();
      FPT_CHECK(status.policy.revision.is_valid());
      FPT_CHECK_EQ(status.policy.revision.value(), revision);
      FPT_CHECK(!status.recovered_from_backup);
      FPT_CHECK_EQ(status.unreferenced_records, std::size_t(0));
      continue;
    }
    if (action == 2) {
      request_counter += 1;
      auto request = parse_request_document(request_text);
      FPT_REQUIRE_OK(request);
      request.value().request_id =
          RequestId::parse("req-" + std::to_string(request_counter)).value();
      EvaluationInput input;
      input.request = std::move(request.value());
      auto verdicts = store.value().evaluate_recorded(
          input, Instant::parse("2026-02-14T09:30:00.000000Z").value());
      FPT_REQUIRE_OK(verdicts);
      // Replaying the same identity returns the same verdicts.
      auto replay = store.value().evaluate_recorded(
          input, Instant::parse("2026-02-14T09:31:00.000000Z").value());
      FPT_REQUIRE_OK(replay);
      FPT_CHECK(replay.value().replayed);
      FPT_REQUIRE_EQ(replay.value().candidates.size(), verdicts.value().candidates.size());
      for (std::size_t index = 0; index < verdicts.value().candidates.size(); ++index) {
        // The replay marker is not part of a decision's identity: the digest of
        // the decision itself must be unchanged.
        FPT_CHECK(digest_equal(replay.value().candidates[index].verdict_digest,
                               verdicts.value().candidates[index].verdict_digest));
        FPT_CHECK(replay.value().candidates[index].decision ==
                  verdicts.value().candidates[index].decision);
      }
      continue;
    }
    if (action == 3) {
      auto snapshot = store.value().snapshot();
      FPT_REQUIRE_OK(snapshot);
      FPT_CHECK(digest_equal(snapshot.value().policy.digest, store.value().status().policy.digest));
      continue;
    }
    // Compaction and reopening must not change what the store says.
    FPT_REQUIRE_OK(store.value().compact(Instant::parse("2026-02-14T09:40:00.000000Z").value()));
    const std::uint64_t revision_before = store.value().status().policy.revision.value();
    store.value().close();
    auto reopened = Store::open(directory.value(), StoreOpenMode::ReadWrite);
    FPT_REQUIRE_OK(reopened);
    store = std::move(reopened.value());
    FPT_CHECK_EQ(store.value().status().policy.revision.value(), revision_before);
    FPT_CHECK_EQ(store.value().status().unreferenced_records, std::size_t(0));
    ++usage_counter;
  }
  FPT_CHECK(usage_counter > 0);
  fptest::set_failure_context("");
  FPT_CHECK_EQ(store.value().status().policy.revision.value(), revision);
}
