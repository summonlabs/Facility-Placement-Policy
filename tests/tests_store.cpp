// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs.

#include <string>

#include "test_framework.hpp"
#include "test_support.hpp"

#include "dccp/facility_placement_policy/facility_placement_policy.hpp"

namespace {

using namespace dccp::facility_placement_policy;
using namespace fptest;

const char* const kPolicy =
    "fpp-document policy\n"
    "format 1\n"
    "policy-id grid-a\n"
    "revision 1\n"
    "rule legal {\n"
    "  require jurisdiction allow=jurisdiction:eu-de deny=\n"
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
    "maintenance generation=41\n";

Instant at(const char* text) { return Instant::parse(text).value(); }

std::string with_revision(const std::string& text, std::uint64_t revision) {
  std::string out = text;
  const std::size_t position = out.find("revision 1");
  out.replace(position, std::string("revision 1").size(), "revision " + std::to_string(revision));
  return out;
}

Result<std::string> new_store_directory(const std::string& name) {
  auto directory = fresh_directory(name);
  if (!directory.has_value()) {
    return directory.error();
  }
  const auto created = initialize_store(directory.value(), StoreId::parse("store:main").value(),
                                        at("2026-02-14T09:00:00.000000Z"));
  if (!created.has_value()) {
    return created.error();
  }
  return directory.value();
}

}  // namespace

FPT_TEST(store, a_store_exists_before_it_has_authority_and_refuses_to_decide) {
  auto directory = new_store_directory("store-empty");
  FPT_REQUIRE_OK(directory);
  auto store = Store::open(directory.value(), StoreOpenMode::ReadWrite);
  FPT_REQUIRE_OK(store);
  const StoreStatus status = store.value().status();
  FPT_CHECK_EQ(status.sequence.value(), std::uint64_t(1));
  FPT_CHECK_EQ(status.authority_epoch.value(), std::uint64_t(1));
  FPT_CHECK(status.policy.policy_id.empty());
  FPT_CHECK(!status.topology_floor.is_valid());
  FPT_CHECK_EQ(status.unreferenced_records, std::size_t(0));

  FPT_CHECK_ERROR(store.value().snapshot(), ErrorCode::NoActivePolicy);
  EvaluationInput input;
  input.request = parse_request_document(kRequest).value();
  FPT_CHECK_ERROR(store.value().evaluate_recorded(input, at("2026-02-14T09:30:00.000000Z")),
                  ErrorCode::NoActivePolicy);
  FPT_CHECK_ERROR(store.value().authorize_override(
                      EnvelopeId::parse("e").value(), PrincipalId::parse("p").value(),
                      UsageId::parse("u").value(), TenantId::parse("tenant:acme").value(),
                      ServiceClassId::parse("service-class:gold").value(),
                      FacilityId::parse("facility:dc1").value(),
                      at("2026-02-14T09:30:00.000000Z")),
                  ErrorCode::NoActivePolicy);
  // The store is complete and verifiable, but it is not a policy authority yet.
  store.value().close();
  FPT_REQUIRE_OK(Store::open(directory.value(), StoreOpenMode::ReadOnly));
}

FPT_TEST(store, revisions_advance_by_one_within_one_lineage) {
  auto directory = new_store_directory("store-revisions");
  FPT_REQUIRE_OK(directory);
  auto store = Store::open(directory.value(), StoreOpenMode::ReadWrite);
  FPT_REQUIRE_OK(store);

  auto first = parse_policy_document(kPolicy);
  FPT_REQUIRE_OK(first);
  auto binding = store.value().activate_policy(first.value(), at("2026-02-14T09:05:00.000000Z"));
  FPT_REQUIRE_OK(binding);
  FPT_CHECK_EQ(binding.value().revision.value(), std::uint64_t(1));
  FPT_CHECK_EQ(binding.value().policy_id.value(), std::string_view("grid-a"));

  // A gap is refused: authority that was never published cannot be skipped to.
  auto third = parse_policy_document(with_revision(kPolicy, 3));
  FPT_REQUIRE_OK(third);
  FPT_CHECK_ERROR(store.value().activate_policy(third.value(), at("2026-02-14T09:06:00.000000Z")),
                  ErrorCode::PolicyRevisionConflict);

  // Re-publishing the active revision is not a new revision.
  FPT_CHECK_ERROR(store.value().activate_policy(first.value(), at("2026-02-14T09:06:00.000000Z")),
                  ErrorCode::StalePolicyRevision);

  auto second = parse_policy_document(with_revision(kPolicy, 2));
  FPT_REQUIRE_OK(second);
  auto second_binding = store.value().activate_policy(second.value(), at("2026-02-14T09:07:00.000000Z"));
  FPT_REQUIRE_OK(second_binding);
  FPT_CHECK_EQ(store.value().status().authority_epoch.value(), std::uint64_t(3));

  // A different policy identity would silently replace the lineage.
  std::string other = with_revision(kPolicy, 3);
  const std::size_t id = other.find("policy-id grid-a");
  other.replace(id, std::string("policy-id grid-a").size(), "policy-id grid-b");
  auto other_document = parse_policy_document(other);
  FPT_REQUIRE_OK(other_document);
  FPT_CHECK_ERROR(
      store.value().activate_policy(other_document.value(), at("2026-02-14T09:08:00.000000Z")),
      ErrorCode::PolicyRevisionConflict);

  // Both revisions are retained and readable, and the older one is still exactly
  // the document that was published.
  FPT_CHECK_EQ(store.value().status().retained_policy_revisions, std::size_t(2));
  auto older = store.value().read_policy(PolicyRevision::from_value(1).value());
  FPT_REQUIRE_OK(older);
  FPT_CHECK(digest_equal(older.value().digest, first.value().digest));
  FPT_CHECK_ERROR(store.value().read_policy(PolicyRevision::from_value(9).value()),
                  ErrorCode::NotFound);
}

FPT_TEST(store, authority_survives_a_close_and_reopen) {
  auto directory = new_store_directory("store-reopen");
  FPT_REQUIRE_OK(directory);
  PolicyBinding published;
  {
    auto store = Store::open(directory.value(), StoreOpenMode::ReadWrite);
    FPT_REQUIRE_OK(store);
    auto document = parse_policy_document(kPolicy);
    FPT_REQUIRE_OK(document);
    auto binding = store.value().activate_policy(document.value(), at("2026-02-14T09:05:00.000000Z"));
    FPT_REQUIRE_OK(binding);
    published = binding.value();
  }
  auto reopened = Store::open(directory.value(), StoreOpenMode::ReadOnly);
  FPT_REQUIRE_OK(reopened);
  const StoreStatus status = reopened.value().status();
  FPT_CHECK(status.policy.revision.is_valid());
  FPT_CHECK(digest_equal(status.policy.digest, published.digest));
  FPT_CHECK(!status.recovered_from_backup);
  auto snapshot = reopened.value().snapshot();
  FPT_REQUIRE_OK(snapshot);
  FPT_CHECK(digest_equal(snapshot.value().policy.digest, published.digest));
  FPT_CHECK_EQ(snapshot.value().authority_epoch.value(), status.authority_epoch.value());
}

FPT_TEST(store, a_read_only_store_refuses_every_mutation) {
  auto directory = new_store_directory("store-readonly");
  FPT_REQUIRE_OK(directory);
  {
    auto writer = Store::open(directory.value(), StoreOpenMode::ReadWrite);
    FPT_REQUIRE_OK(writer);
    auto document = parse_policy_document(kPolicy);
    FPT_REQUIRE_OK(document);
    FPT_REQUIRE_OK(writer.value().activate_policy(document.value(), at("2026-02-14T09:05:00.000000Z")));
  }
  auto reader = Store::open(directory.value(), StoreOpenMode::ReadOnly);
  FPT_REQUIRE_OK(reader);
  FPT_CHECK(reader.value().mode() == StoreOpenMode::ReadOnly);
  auto document = parse_policy_document(with_revision(kPolicy, 2));
  FPT_REQUIRE_OK(document);
  FPT_CHECK_ERROR(reader.value().activate_policy(document.value(), at("2026-02-14T09:06:00.000000Z")),
                  ErrorCode::StoreReadOnly);
  FPT_CHECK_ERROR(reader.value().compact(at("2026-02-14T09:06:00.000000Z")),
                  ErrorCode::StoreReadOnly);
  EvaluationInput input;
  input.request = parse_request_document(kRequest).value();
  FPT_CHECK_ERROR(reader.value().evaluate_recorded(input, at("2026-02-14T09:30:00.000000Z")),
                  ErrorCode::StoreReadOnly);
  // Reading is still allowed, and a pure evaluation needs no write at all.
  auto snapshot = reader.value().snapshot();
  FPT_REQUIRE_OK(snapshot);
  FPT_REQUIRE_OK(evaluate(snapshot.value(), input));
}

FPT_TEST(store, a_recorded_request_is_answered_from_the_record) {
  auto directory = new_store_directory("store-record");
  FPT_REQUIRE_OK(directory);
  auto store = Store::open(directory.value(), StoreOpenMode::ReadWrite);
  FPT_REQUIRE_OK(store);
  auto document = parse_policy_document(kPolicy);
  FPT_REQUIRE_OK(document);
  FPT_REQUIRE_OK(store.value().activate_policy(document.value(), at("2026-02-14T09:05:00.000000Z")));

  EvaluationInput input;
  input.request = parse_request_document(kRequest).value();
  auto first = store.value().evaluate_recorded(input, at("2026-02-14T09:30:00.000000Z"));
  FPT_REQUIRE_OK(first);
  FPT_CHECK(!first.value().replayed);
  const StoreSequence after_first = store.value().status().sequence;
  FPT_CHECK_EQ(store.value().status().recorded_evaluations, std::size_t(1));

  // The retry is answered with the recorded verdicts and consumes no new state.
  auto replay = store.value().evaluate_recorded(input, at("2026-02-14T09:31:00.000000Z"));
  FPT_REQUIRE_OK(replay);
  FPT_CHECK(replay.value().replayed);
  FPT_CHECK(replay.value().candidates.front().replayed);
  FPT_CHECK(digest_equal(replay.value().candidates.front().verdict_digest,
                         first.value().candidates.front().verdict_digest));
  FPT_CHECK(store.value().status().sequence == after_first);

  // A different request identity produces a different record.
  EvaluationInput other = input;
  other.request.request_id = RequestId::parse("req-2").value();
  FPT_REQUIRE_OK(store.value().evaluate_recorded(other, at("2026-02-14T09:32:00.000000Z")));
  FPT_CHECK_EQ(store.value().status().recorded_evaluations, std::size_t(2));

  // The same identity with different content is a conflict, not a replay.
  EvaluationInput conflicting = input;
  conflicting.request.candidates.front().location.rack = RackId::parse("rack:99").value();
  FPT_CHECK_ERROR(store.value().evaluate_recorded(conflicting, at("2026-02-14T09:33:00.000000Z")),
                  ErrorCode::RequestIdConflict);

  auto direct = store.value().recorded_verdicts(RequestId::parse("req-1").value());
  FPT_REQUIRE_OK(direct);
  FPT_CHECK(direct.value().replayed);
  FPT_CHECK_ERROR(store.value().recorded_verdicts(RequestId::parse("req-nothing").value()),
                  ErrorCode::NotFound);
}

FPT_TEST(store, recording_advances_the_generation_watermarks) {
  auto directory = new_store_directory("store-watermark");
  FPT_REQUIRE_OK(directory);
  auto store = Store::open(directory.value(), StoreOpenMode::ReadWrite);
  FPT_REQUIRE_OK(store);
  auto document = parse_policy_document(kPolicy);
  FPT_REQUIRE_OK(document);
  FPT_REQUIRE_OK(store.value().activate_policy(document.value(), at("2026-02-14T09:05:00.000000Z")));
  FPT_CHECK(!store.value().status().topology_floor.is_valid());

  EvaluationInput input;
  input.request = parse_request_document(kRequest).value();
  FPT_REQUIRE_OK(store.value().evaluate_recorded(input, at("2026-02-14T09:30:00.000000Z")));
  FPT_CHECK_EQ(store.value().status().topology_floor.value(), std::uint64_t(12));
  FPT_CHECK_EQ(store.value().status().failure_domain_floor.value(), std::uint64_t(9));

  // An older world can no longer be evaluated, which is what fences a replay of
  // stale topology evidence.
  EvaluationInput older = input;
  older.request.request_id = RequestId::parse("req-old").value();
  older.request.generations.topology = TopologyGeneration::from_value(11).value();
  FPT_CHECK_ERROR(store.value().evaluate_recorded(older, at("2026-02-14T09:31:00.000000Z")),
                  ErrorCode::StaleTopologyGeneration);

  // A newer world advances the floor.
  EvaluationInput newer = input;
  newer.request.request_id = RequestId::parse("req-new").value();
  newer.request.generations.topology = TopologyGeneration::from_value(20).value();
  FPT_REQUIRE_OK(store.value().evaluate_recorded(newer, at("2026-02-14T09:32:00.000000Z")));
  FPT_CHECK_EQ(store.value().status().topology_floor.value(), std::uint64_t(20));

  auto snapshot = store.value().snapshot();
  FPT_REQUIRE_OK(snapshot);
  FPT_CHECK_EQ(snapshot.value().topology_floor.value(), std::uint64_t(20));
}

FPT_TEST(store, compaction_publishes_a_state_the_ordinary_reader_accepts) {
  auto directory = new_store_directory("store-compact");
  FPT_REQUIRE_OK(directory);
  auto store = Store::open(directory.value(), StoreOpenMode::ReadWrite);
  FPT_REQUIRE_OK(store);
  for (std::uint64_t revision = 1; revision <= 4; ++revision) {
    auto document = parse_policy_document(with_revision(kPolicy, revision));
    FPT_REQUIRE_OK(document);
    FPT_REQUIRE_OK(store.value().activate_policy(document.value(), at("2026-02-14T09:05:00.000000Z")));
  }
  const std::uint64_t before = store.value().status().sequence.value();
  FPT_REQUIRE_OK(store.value().compact(at("2026-02-14T09:06:00.000000Z")));
  FPT_CHECK(store.value().status().sequence.value() > before);

  // A plain file left behind by an earlier crash is ignored and then removed.
  FPT_REQUIRE_OK(write_text_file(directory.value() + "/ledger/stray.fpp", "not a record at all"));
  FPT_REQUIRE_OK(write_text_file(directory.value() + "/policies/policy-9-deadbeef.fpp", "junk"));
  store.value().close();
  auto reopened = Store::open(directory.value(), StoreOpenMode::ReadOnly);
  FPT_REQUIRE_OK(reopened);
  FPT_CHECK_EQ(reopened.value().status().unreferenced_records, std::size_t(2));
  reopened.value().close();

  auto writer = Store::open(directory.value(), StoreOpenMode::ReadWrite);
  FPT_REQUIRE_OK(writer);
  FPT_REQUIRE_OK(writer.value().compact(at("2026-02-14T09:07:00.000000Z")));
  FPT_CHECK_EQ(writer.value().status().unreferenced_records, std::size_t(0));
  FPT_CHECK_EQ(writer.value().status().retained_policy_revisions, std::size_t(4));

  // The active policy is still the latest revision and still readable.
  auto snapshot = writer.value().snapshot();
  FPT_REQUIRE_OK(snapshot);
  FPT_CHECK_EQ(snapshot.value().policy.revision.value(), std::uint64_t(4));
}

FPT_TEST(store, initialisation_refuses_to_overwrite_durable_state) {
  auto directory = new_store_directory("store-reinit");
  FPT_REQUIRE_OK(directory);
  FPT_CHECK_ERROR(initialize_store(directory.value(), StoreId::parse("store:other").value(),
                                   at("2026-02-14T09:00:00.000000Z")),
                  ErrorCode::AlreadyInitialized);
  FPT_CHECK_ERROR(Store::open(directory.value() + "/does-not-exist", StoreOpenMode::ReadOnly),
                  ErrorCode::StoreNotFound);
}

FPT_TEST(store, the_documented_format_description_names_the_head_and_its_guard) {
  const std::string description = store_format_description();
  FPT_CHECK(description.find("manifest.fpp") != std::string::npos);
  FPT_CHECK(description.find("manifest.fpp.bak") != std::string::npos);
  FPT_CHECK(description.find("immutable") != std::string::npos);
}
