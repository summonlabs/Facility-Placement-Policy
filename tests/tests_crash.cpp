// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs.

#include <chrono>
#include <string>
#include <thread>
#include <vector>

#include "child_process.hpp"
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

std::string child_command(const std::vector<std::string>& arguments) {
  std::string command = quote_argument(crash_child_path());
  for (const std::string& argument : arguments) {
    command.push_back(' ');
    command.append(quote_argument(argument));
  }
  return command;
}

/// A store with revision 1 active, a policy file and a request file, all inside
/// the scratch root so the child can be handed plain paths.
Result<std::string> crash_scenario(const std::string& name) {
  auto directory = fresh_directory(name);
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
  const auto policy_file = write_text_file(directory.value() + "/policy.txt", kPolicy);
  if (!policy_file.has_value()) {
    return policy_file.error();
  }
  const auto request_file = write_text_file(directory.value() + "/request.txt", kRequest);
  if (!request_file.has_value()) {
    return request_file.error();
  }
  return directory.value();
}

/// The delays, in milliseconds, at which the writer is killed. They are fixed so
/// a failure can be reproduced exactly.
const int kKillDelays[] = {0, 3, 9, 21, 45, 90};

}  // namespace

FPT_TEST(crash, killing_a_policy_activation_leaves_one_of_two_verifiable_states) {
  if (crash_child_path().empty()) {
    FPT_FAIL("the crash helper was not built");
  }
  for (const int delay : kKillDelays) {
    auto directory = crash_scenario("crash-activate-" + std::to_string(delay));
    FPT_REQUIRE_OK(directory);
    fptest::set_failure_context("kill-delay-ms=" + std::to_string(delay));

    auto child = ChildProcess::start_captured(
        child_command({"activate", directory.value(), directory.value() + "/policy.txt",
                       "2026-02-14T09:20:00.000000Z", "12"}),
        scratch_root());
    FPT_REQUIRE_OK(child);
    std::this_thread::sleep_for(std::chrono::milliseconds(delay));
    FPT_REQUIRE_OK(child.value().terminate());
    static_cast<void>(child.value().read_output());
    auto exit_code = child.value().wait();
    FPT_REQUIRE_OK(exit_code);
    // A process that was killed does not report a clean exit.
    FPT_CHECK(exit_code.value() != 0);

    // Whatever it was doing, the store opens and verifies, and its authority is
    // exactly one of the revisions that were published.
    auto store = Store::open(directory.value(), StoreOpenMode::ReadWrite);
    FPT_REQUIRE_OK(store);
    const StoreStatus status = store.value().status();
    FPT_CHECK(status.policy.revision.is_valid());
    FPT_CHECK(status.policy.revision.value() >= 1);
    FPT_CHECK(status.policy.revision.value() <= 13);
    auto snapshot = store.value().snapshot();
    FPT_REQUIRE_OK(snapshot);
    FPT_CHECK(digest_equal(snapshot.value().policy.digest, status.policy.digest));

    // The store is still usable: the lock was released by the kernel and the
    // state that survived is a state the ordinary reader accepts.
    const std::uint64_t revision = status.policy.revision.value();
    std::string next = kPolicy;
    const std::size_t position = next.find("revision 1");
    next.replace(position, std::string("revision 1").size(),
                 "revision " + std::to_string(revision + 1));
    auto document = parse_policy_document(next);
    FPT_REQUIRE_OK(document);
    auto binding = store.value().activate_policy(document.value(), at("2026-02-14T09:40:00.000000Z"));
    FPT_REQUIRE_OK(binding);
    FPT_CHECK_EQ(binding.value().revision.value(), revision + 1);
    // The publication that a crash left unreferenced is reclaimed by the next
    // commit rather than lingering, because nothing a reader may choose refers
    // to it any more.
    FPT_CHECK_EQ(store.value().status().unreferenced_records, std::size_t(0));
  }
  fptest::set_failure_context("");
}

FPT_TEST(crash, killing_a_recorded_evaluation_leaves_the_ledger_consistent) {
  if (crash_child_path().empty()) {
    FPT_FAIL("the crash helper was not built");
  }
  for (const int delay : kKillDelays) {
    auto directory = crash_scenario("crash-record-" + std::to_string(delay));
    FPT_REQUIRE_OK(directory);
    fptest::set_failure_context("kill-delay-ms=" + std::to_string(delay));

    auto child = ChildProcess::start_captured(
        child_command({"record", directory.value(), directory.value() + "/request.txt",
                       "2026-02-14T09:30:00.000000Z", "12"}),
        scratch_root());
    FPT_REQUIRE_OK(child);
    std::this_thread::sleep_for(std::chrono::milliseconds(delay));
    FPT_REQUIRE_OK(child.value().terminate());
    static_cast<void>(child.value().read_output());
    FPT_REQUIRE_OK(child.value().wait());

    auto store = Store::open(directory.value(), StoreOpenMode::ReadWrite);
    FPT_REQUIRE_OK(store);
    const StoreStatus status = store.value().status();
    FPT_CHECK(status.recorded_evaluations <= kMaxEvaluationRecords);

    // Every evaluation the ledger claims to hold is readable and verifiable, and
    // the watermarks moved with the publications that were completed.
    if (status.recorded_evaluations > 0) {
      auto recorded = store.value().recorded_verdicts(RequestId::parse("crash-req-1").value());
      FPT_REQUIRE_OK(recorded);
      FPT_CHECK(recorded.value().replayed);
      FPT_CHECK(verify_verdict_digest(recorded.value().candidates.front()));
      FPT_CHECK_EQ(status.topology_floor.value(), std::uint64_t(12));
    }

    // The store still accepts work.
    EvaluationInput input;
    input.request = parse_request_document(kRequest).value();
    input.request.request_id = RequestId::parse("after-crash").value();
    auto verdicts = store.value().evaluate_recorded(input, at("2026-02-14T09:35:00.000000Z"));
    FPT_REQUIRE_OK(verdicts);
    FPT_CHECK_EQ(store.value().status().unreferenced_records, std::size_t(0));
  }
  fptest::set_failure_context("");
}
