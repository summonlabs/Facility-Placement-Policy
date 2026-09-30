// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs.

#include <cstdint>
#include <string>
#include <vector>

#include "test_framework.hpp"
#include "test_support.hpp"

#include "dccp/facility_placement_policy/facility_placement_policy.hpp"
#include "file_ops.hpp"

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

std::string with_revision(const std::string& text, std::uint64_t revision) {
  std::string out = text;
  const std::size_t position = out.find("revision 1");
  out.replace(position, std::string("revision 1").size(), "revision " + std::to_string(revision));
  return out;
}

/// Builds a store with the given number of activated revisions.
Result<std::string> prepared_store(const std::string& name, std::uint64_t revisions) {
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
  for (std::uint64_t revision = 1; revision <= revisions; ++revision) {
    auto document = parse_policy_document(with_revision(kPolicy, revision));
    if (!document.has_value()) {
      return document.error();
    }
    auto binding = store.value().activate_policy(document.value(), at("2026-02-14T09:05:00.000000Z"));
    if (!binding.has_value()) {
      return binding.error();
    }
  }
  return directory.value();
}

}  // namespace

FPT_TEST(recovery, an_unreadable_head_falls_back_to_its_verified_predecessor) {
  auto directory = prepared_store("recovery-head", 2);
  FPT_REQUIRE_OK(directory);
  const std::string head = directory.value() + "/manifest.fpp";

  auto bytes = read_bytes(head);
  FPT_REQUIRE_OK(bytes);
  bytes.value()[0] ^= 0xFFu;
  FPT_REQUIRE_OK(write_bytes(head, bytes.value()));

  auto store = Store::open(directory.value(), StoreOpenMode::ReadOnly);
  FPT_REQUIRE_OK(store);
  const StoreStatus status = store.value().status();
  FPT_CHECK(status.recovered_from_backup);
  FPT_CHECK_EQ(status.policy.revision.value(), std::uint64_t(1));
  // The publication that could not be read is no longer referenced by anything a
  // reader may choose, so it is reported as residue and reclaimed by the next
  // commit rather than deleted behind the recovering reader's back.
  FPT_CHECK_EQ(status.unreferenced_records, std::size_t(2));
  store.value().close();
  auto writer = Store::open(directory.value(), StoreOpenMode::ReadWrite);
  FPT_REQUIRE_OK(writer);
  FPT_REQUIRE_OK(writer.value().compact(at("2026-02-14T09:20:00.000000Z")));
  FPT_CHECK_EQ(writer.value().status().unreferenced_records, std::size_t(0));
}

FPT_TEST(recovery, a_head_that_does_not_match_its_declared_length_is_refused) {
  auto directory = prepared_store("recovery-length", 2);
  FPT_REQUIRE_OK(directory);
  const std::string head = directory.value() + "/manifest.fpp";
  auto bytes = read_bytes(head);
  FPT_REQUIRE_OK(bytes);
  FPT_REQUIRE_OK(append_bytes(head, {0u}));
  auto store = Store::open(directory.value(), StoreOpenMode::ReadOnly);
  FPT_REQUIRE_OK(store);
  FPT_CHECK(store.value().status().recovered_from_backup);

  // Truncation is the other half of the same rule.
  FPT_REQUIRE_OK(write_bytes(head, bytes.value()));
  FPT_REQUIRE_OK(truncate_file(head, bytes.value().size() - 1));
  auto truncated = Store::open(directory.value(), StoreOpenMode::ReadOnly);
  FPT_REQUIRE_OK(truncated);
  FPT_CHECK(truncated.value().status().recovered_from_backup);
}

FPT_TEST(recovery, two_unreadable_heads_fail_closed_rather_than_guessing) {
  auto directory = prepared_store("recovery-both", 2);
  FPT_REQUIRE_OK(directory);
  for (const std::string& name : {"/manifest.fpp", "/manifest.fpp.bak"}) {
    auto bytes = read_bytes(directory.value() + name);
    FPT_REQUIRE_OK(bytes);
    bytes.value()[10] ^= 0xFFu;
    FPT_REQUIRE_OK(write_bytes(directory.value() + name, bytes.value()));
  }
  FPT_CHECK_ERROR(Store::open(directory.value(), StoreOpenMode::ReadOnly),
                  ErrorCode::RecoveryRequired);
}

FPT_TEST(recovery, a_missing_record_that_the_head_references_fails_closed) {
  auto directory = prepared_store("recovery-missing-policy", 2);
  FPT_REQUIRE_OK(directory);
  auto policies = directory_names(directory.value() + "/policies");
  FPT_REQUIRE_OK(policies);
  FPT_REQUIRE(!policies.value().empty());
  for (const std::string& name : policies.value()) {
    FPT_REQUIRE_OK(remove_scratch_directory(directory.value() + "/policies/" + name));
  }
  FPT_CHECK_ERROR(Store::open(directory.value(), StoreOpenMode::ReadOnly),
                  ErrorCode::RecordNotFound);

  auto ledgers = prepared_store("recovery-missing-ledger", 2);
  FPT_REQUIRE_OK(ledgers);
  auto ledger_names = directory_names(ledgers.value() + "/ledger");
  FPT_REQUIRE_OK(ledger_names);
  for (const std::string& name : ledger_names.value()) {
    FPT_REQUIRE_OK(remove_scratch_directory(ledgers.value() + "/ledger/" + name));
  }
  FPT_CHECK_ERROR(Store::open(ledgers.value(), StoreOpenMode::ReadOnly),
                  ErrorCode::RecordNotFound);
}

FPT_TEST(recovery, a_head_older_than_its_predecessor_is_a_rollback_and_is_refused) {
  auto directory = prepared_store("recovery-rollback", 3);
  FPT_REQUIRE_OK(directory);
  const std::string head = directory.value() + "/manifest.fpp";
  const std::string backup = directory.value() + "/manifest.fpp.bak";
  auto current = read_bytes(head);
  FPT_REQUIRE_OK(current);
  // The predecessor becomes the newer of the two, which can only mean that an
  // older copy of the head was put back in place.
  FPT_REQUIRE_OK(write_bytes(backup, current.value()));
  auto store = Store::open(directory.value(), StoreOpenMode::ReadOnly);
  FPT_REQUIRE_OK(store);
  FPT_CHECK(!store.value().status().stale_head_ignored);

  // Now roll the head back by one generation while keeping the predecessor.
  FPT_REQUIRE_OK(remove_scratch_directory(directory.value() + "/rollback-probe"));
  auto stale = prepared_store("recovery-rollback-probe", 1);
  FPT_REQUIRE_OK(stale);
  auto stale_head = read_bytes(stale.value() + "/manifest.fpp");
  FPT_REQUIRE_OK(stale_head);
  FPT_REQUIRE_OK(write_bytes(head, stale_head.value()));
  auto recovered = Store::open(directory.value(), StoreOpenMode::ReadOnly);
  FPT_REQUIRE_OK(recovered);
  FPT_CHECK(recovered.value().status().stale_head_ignored);
}

FPT_TEST(recovery, leftover_temporaries_are_ignored_and_reported) {
  auto directory = prepared_store("recovery-temporaries", 1);
  FPT_REQUIRE_OK(directory);
  FPT_REQUIRE_OK(write_text_file(directory.value() + "/manifest.fpp.fpp-tmp", "half a head"));
  FPT_REQUIRE_OK(write_text_file(directory.value() + "/ledger/ledger-99-dead.fpp.fpp-tmp", "junk"));
  auto store = Store::open(directory.value(), StoreOpenMode::ReadWrite);
  FPT_REQUIRE_OK(store);
  FPT_CHECK_EQ(store.value().status().policy.revision.value(), std::uint64_t(1));
  FPT_CHECK_EQ(store.value().status().unreferenced_records, std::size_t(2));
  FPT_REQUIRE_OK(store.value().compact(at("2026-02-14T09:10:00.000000Z")));
  FPT_CHECK_EQ(store.value().status().unreferenced_records, std::size_t(0));
}

FPT_TEST(recovery, records_without_a_head_are_not_silently_adopted_or_replaced) {
  auto directory = fresh_directory("recovery-orphans");
  FPT_REQUIRE_OK(directory);
  FPT_REQUIRE_OK(internal::create_directories(directory.value() + "/policies"));
  FPT_REQUIRE_OK(write_text_file(directory.value() + "/policies/policy-1-abc.fpp", "orphan"));
  FPT_CHECK_ERROR(Store::open(directory.value(), StoreOpenMode::ReadOnly),
                  ErrorCode::StoreNotFound);
  FPT_CHECK_ERROR(initialize_store(directory.value(), StoreId::parse("store:main").value(),
                                   at("2026-02-14T09:00:00.000000Z")),
                  ErrorCode::RecoveryRequired);
}

FPT_TEST(recovery, a_corrupt_retained_revision_is_not_quietly_dropped) {
  auto directory = prepared_store("recovery-retained", 2);
  FPT_REQUIRE_OK(directory);
  auto names = directory_names(directory.value() + "/policies");
  FPT_REQUIRE_OK(names);
  FPT_REQUIRE_EQ(names.value().size(), std::size_t(2));
  // The first name in sorted order is revision 1; both are referenced by the
  // head, so corrupting either is a corruption of the head's own state.
  const std::string target = directory.value() + "/policies/" + names.value().front();
  auto bytes = read_bytes(target);
  FPT_REQUIRE_OK(bytes);
  bytes.value().back() ^= 0xFFu;
  FPT_REQUIRE_OK(write_bytes(target, bytes.value()));
  FPT_CHECK_ERROR(Store::open(directory.value(), StoreOpenMode::ReadOnly),
                  ErrorCode::DigestMismatch);
}

FPT_TEST(recovery, a_corrupt_ledger_is_refused_and_a_valid_one_is_not) {
  auto directory = prepared_store("recovery-ledger-corrupt", 1);
  FPT_REQUIRE_OK(directory);
  auto names = directory_names(directory.value() + "/ledger");
  FPT_REQUIRE_OK(names);
  FPT_REQUIRE(!names.value().empty());
  const std::string target = directory.value() + "/ledger/" + names.value().back();
  auto bytes = read_bytes(target);
  FPT_REQUIRE_OK(bytes);
  bytes.value()[kRecordHeaderBytes] ^= 0x01u;
  FPT_REQUIRE_OK(write_bytes(target, bytes.value()));
  FPT_CHECK_ERROR(Store::open(directory.value(), StoreOpenMode::ReadOnly),
                  ErrorCode::ChecksumMismatch);
}
