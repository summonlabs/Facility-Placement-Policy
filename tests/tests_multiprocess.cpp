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

Instant at(const char* text) { return Instant::parse(text).value(); }

Result<std::string> prepared_store(const std::string& name) {
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
  return directory.value();
}

std::string child_command(const std::vector<std::string>& arguments) {
  std::string command = quote_argument(crash_child_path());
  for (const std::string& argument : arguments) {
    command.push_back(' ');
    command.append(quote_argument(argument));
  }
  return command;
}

/// Waits until the store can no longer be opened for writing, which means the
/// child holds it.
bool wait_until_locked(const std::string& directory) {
  for (int attempt = 0; attempt < 400; ++attempt) {
    auto store = Store::open(directory, StoreOpenMode::ReadWrite);
    if (!store.has_value()) {
      if (store.error().code() == ErrorCode::StoreLocked) {
        return true;
      }
    } else {
      store.value().close();
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(5));
  }
  return false;
}

}  // namespace

FPT_TEST(multiprocess, a_writer_in_another_process_excludes_this_one) {
  if (crash_child_path().empty()) {
    FPT_FAIL("the crash helper was not built");
  }
  auto directory = prepared_store("multiprocess-writer");
  FPT_REQUIRE_OK(directory);

  auto child = ChildProcess::start_captured(child_command({"hold", directory.value(), "30000"}),
                                            scratch_root());
  FPT_REQUIRE_OK(child);
  FPT_REQUIRE(wait_until_locked(directory.value()));

  FPT_CHECK_ERROR(Store::open(directory.value(), StoreOpenMode::ReadWrite), ErrorCode::StoreLocked);
  FPT_CHECK_ERROR(Store::open(directory.value(), StoreOpenMode::ReadOnly), ErrorCode::StoreLocked);

  FPT_REQUIRE_OK(child.value().terminate());
  FPT_REQUIRE_OK(child.value().read_output());
  const auto exit_code = child.value().wait();
  FPT_REQUIRE_OK(exit_code);
  FPT_CHECK(exit_code.value() != 0);

  // The operating system released the lock when the process died, with no
  // cleanup step of its own.
  auto reopened = Store::open(directory.value(), StoreOpenMode::ReadWrite);
  FPT_REQUIRE_OK(reopened);
  FPT_CHECK_EQ(reopened.value().status().policy.revision.value(), std::uint64_t(1));
}

FPT_TEST(multiprocess, a_reader_in_another_process_coexists_with_a_reader_and_not_a_writer) {
  if (crash_child_path().empty()) {
    FPT_FAIL("the crash helper was not built");
  }
  auto directory = prepared_store("multiprocess-reader");
  FPT_REQUIRE_OK(directory);
  auto child = ChildProcess::start_captured(child_command({"hold-read", directory.value(), "30000"}),
                                            scratch_root());
  FPT_REQUIRE_OK(child);

  // The child prints "holding" only after it has the lock.
  bool holding = false;
  for (int attempt = 0; attempt < 400 && !holding; ++attempt) {
    auto reader = Store::open(directory.value(), StoreOpenMode::ReadOnly);
    if (!reader.has_value()) {
      holding = reader.error().code() == ErrorCode::StoreLocked;
      if (!holding) {
        break;
      }
    } else {
      // Another reader is admitted, which is what a shared lock means.
      reader.value().close();
      std::this_thread::sleep_for(std::chrono::milliseconds(5));
    }
  }
  FPT_REQUIRE(wait_until_locked(directory.value()));
  FPT_REQUIRE_OK(child.value().terminate());
  FPT_REQUIRE_OK(child.value().read_output());
  FPT_REQUIRE_OK(child.value().wait());
  FPT_REQUIRE_OK(Store::open(directory.value(), StoreOpenMode::ReadWrite));
}

FPT_TEST(multiprocess, only_one_of_two_independent_processes_can_write) {
  if (crash_child_path().empty()) {
    FPT_FAIL("the crash helper was not built");
  }
  auto directory = prepared_store("multiprocess-two-children");
  FPT_REQUIRE_OK(directory);

  auto first = ChildProcess::start_captured(child_command({"hold", directory.value(), "30000"}),
                                            scratch_root());
  FPT_REQUIRE_OK(first);
  FPT_REQUIRE(wait_until_locked(directory.value()));

  auto second = ChildProcess::start_captured(child_command({"hold", directory.value(), "50"}),
                                             scratch_root());
  FPT_REQUIRE_OK(second);
  const std::string second_output = second.value().read_output().value();
  auto second_exit = second.value().wait();
  FPT_REQUIRE_OK(second_exit);
  FPT_CHECK_EQ(second_exit.value(), 2);
  FPT_CHECK(second_output.find("STORE_LOCKED") != std::string::npos);

  FPT_REQUIRE_OK(first.value().terminate());
  FPT_REQUIRE_OK(first.value().read_output());
  FPT_REQUIRE_OK(first.value().wait());
}

FPT_TEST(multiprocess, a_store_written_by_one_process_is_read_by_another) {
  if (crash_child_path().empty()) {
    FPT_FAIL("the crash helper was not built");
  }
  auto directory = prepared_store("multiprocess-handover");
  FPT_REQUIRE_OK(directory);
  // The child advances the store through four real commits in its own process.
  FPT_REQUIRE_OK(write_text_file(directory.value() + "/policy.txt", kPolicy));
  auto child = ChildProcess::start_captured(
      child_command({"activate", directory.value(), directory.value() + "/policy.txt",
                     "2026-02-14T09:20:00.000000Z", "4"}),
      scratch_root());
  FPT_REQUIRE_OK(child);
  const std::string output = normalize_newlines(child.value().read_output().value());
  auto exit_code = child.value().wait();
  FPT_REQUIRE_OK(exit_code);
  FPT_CHECK_EQ(exit_code.value(), 0);
  FPT_CHECK(output.find("activated 5") != std::string::npos);

  // This process reads exactly what that process published.
  auto store = Store::open(directory.value(), StoreOpenMode::ReadOnly);
  FPT_REQUIRE_OK(store);
  FPT_CHECK_EQ(store.value().status().policy.revision.value(), std::uint64_t(5));
  FPT_CHECK_EQ(store.value().status().authority_epoch.value(), std::uint64_t(6));
  FPT_CHECK(!store.value().status().recovered_from_backup);
  FPT_CHECK_EQ(store.value().status().unreferenced_records, std::size_t(0));
  auto snapshot = store.value().snapshot();
  FPT_REQUIRE_OK(snapshot);
  FPT_CHECK_EQ(snapshot.value().policy.revision.value(), std::uint64_t(5));
}
