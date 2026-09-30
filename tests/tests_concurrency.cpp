// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs.

#include <atomic>
#include <string>
#include <thread>
#include <vector>

#include "test_framework.hpp"
#include "test_support.hpp"

#include "dccp/facility_placement_policy/facility_placement_policy.hpp"

namespace {

using namespace dccp::facility_placement_policy;

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

std::string with_revision(std::uint64_t revision) {
  std::string text(kPolicy);
  const std::size_t position = text.find("revision 1");
  text.replace(position, std::string("revision 1").size(), "revision " + std::to_string(revision));
  return text;
}

Result<std::string> prepared_store(const std::string& name) {
  auto directory = fptest::fresh_directory(name);
  if (!directory.has_value()) {
    return directory.error();
  }
  const auto created = initialize_store(directory.value(), StoreId::parse("store:main").value(),
                                        at("2026-02-14T09:00:00.000000Z"));
  if (!created.has_value()) {
    return created.error();
  }
  auto store = Store::open(directory.value(), StoreOpenMode::ReadWrite);
  if (!store.has_value()) {
    return store.error();
  }
  auto document = parse_policy_document(kPolicy);
  if (!document.has_value()) {
    return document.error();
  }
  auto binding = store.value().activate_policy(document.value(), at("2026-02-14T09:05:00.000000Z"));
  if (!binding.has_value()) {
    return binding.error();
  }
  return directory.value();
}

}  // namespace

FPT_TEST(concurrency, readers_and_a_writer_share_one_store_without_interfering) {
  auto directory = prepared_store("concurrency-shared");
  FPT_REQUIRE_OK(directory);
  auto store = Store::open(directory.value(), StoreOpenMode::ReadWrite);
  FPT_REQUIRE_OK(store);

  std::atomic<bool> stop{false};
  std::atomic<int> failures{0};
  std::atomic<int> reads{0};
  std::vector<std::thread> readers;
  for (int index = 0; index < 4; ++index) {
    readers.emplace_back([&store, &stop, &failures, &reads]() {
      while (!stop.load()) {
        auto snapshot = store.value().snapshot();
        if (!snapshot.has_value()) {
          ++failures;
          continue;
        }
        if (!snapshot.value().policy.revision.is_valid()) {
          ++failures;
        }
        const StoreStatus status = store.value().status();
        if (!status.policy.revision.is_valid() ||
            !(status.policy.revision == snapshot.value().policy.revision)) {
          ++failures;
        }
        ++reads;
      }
    });
  }

  for (std::uint64_t revision = 2; revision <= 6; ++revision) {
    auto document = parse_policy_document(with_revision(revision));
    FPT_REQUIRE_OK(document);
    auto binding = store.value().activate_policy(document.value(),
                                                 at("2026-02-14T09:10:00.000000Z"));
    FPT_REQUIRE_OK(binding);
    EvaluationInput input;
    input.request = parse_request_document(kRequest).value();
    input.request.request_id = RequestId::parse("req-" + std::to_string(revision)).value();
    FPT_REQUIRE_OK(store.value().evaluate_recorded(input, at("2026-02-14T09:30:00.000000Z")));
  }
  stop.store(true);
  for (std::thread& reader : readers) {
    reader.join();
  }
  FPT_CHECK_EQ(failures.load(), 0);
  FPT_CHECK(reads.load() > 0);
  FPT_CHECK_EQ(store.value().status().policy.revision.value(), std::uint64_t(6));
}

FPT_TEST(concurrency, a_second_writer_in_the_same_process_is_refused) {
  auto directory = prepared_store("concurrency-two-writers");
  FPT_REQUIRE_OK(directory);
  auto first = Store::open(directory.value(), StoreOpenMode::ReadWrite);
  FPT_REQUIRE_OK(first);
  FPT_CHECK_ERROR(Store::open(directory.value(), StoreOpenMode::ReadWrite), ErrorCode::StoreLocked);
  // A reader is also excluded while a writer holds the store: the lock is one
  // exclusive lock, not a reader-writer lock with a writer preference.
  FPT_CHECK_ERROR(Store::open(directory.value(), StoreOpenMode::ReadOnly), ErrorCode::StoreLocked);

  first.value().close();
  FPT_CHECK(!first.value().is_open());
  auto after = Store::open(directory.value(), StoreOpenMode::ReadWrite);
  FPT_REQUIRE_OK(after);
}

FPT_TEST(concurrency, several_readers_coexist_and_a_writer_waits_for_them) {
  auto directory = prepared_store("concurrency-readers");
  FPT_REQUIRE_OK(directory);
  auto first = Store::open(directory.value(), StoreOpenMode::ReadOnly);
  FPT_REQUIRE_OK(first);
  auto second = Store::open(directory.value(), StoreOpenMode::ReadOnly);
  FPT_REQUIRE_OK(second);
  FPT_CHECK_ERROR(Store::open(directory.value(), StoreOpenMode::ReadWrite), ErrorCode::StoreLocked);
  first.value().close();
  FPT_CHECK_ERROR(Store::open(directory.value(), StoreOpenMode::ReadWrite), ErrorCode::StoreLocked);
  second.value().close();
  FPT_REQUIRE_OK(Store::open(directory.value(), StoreOpenMode::ReadWrite));
}

FPT_TEST(concurrency, a_closed_store_refuses_every_operation) {
  auto directory = prepared_store("concurrency-closed");
  FPT_REQUIRE_OK(directory);
  auto store = Store::open(directory.value(), StoreOpenMode::ReadWrite);
  FPT_REQUIRE_OK(store);
  store.value().close();
  FPT_CHECK(!store.value().is_open());
  FPT_CHECK_ERROR(store.value().snapshot(), ErrorCode::StoreClosed);
  FPT_CHECK_ERROR(store.value().read_policy(PolicyRevision::from_value(1).value()),
                  ErrorCode::StoreClosed);
  auto document = parse_policy_document(with_revision(2));
  FPT_REQUIRE_OK(document);
  FPT_CHECK_ERROR(store.value().activate_policy(document.value(), at("2026-02-14T09:10:00.000000Z")),
                  ErrorCode::StoreClosed);
  EvaluationInput input;
  input.request = parse_request_document(kRequest).value();
  FPT_CHECK_ERROR(store.value().evaluate_recorded(input, at("2026-02-14T09:30:00.000000Z")),
                  ErrorCode::StoreClosed);
  FPT_CHECK_ERROR(store.value().compact(at("2026-02-14T09:30:00.000000Z")), ErrorCode::StoreClosed);
  store.value().close();
}
