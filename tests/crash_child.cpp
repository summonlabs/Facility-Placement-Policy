// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs.
//
// A helper that performs real durable work in its own process so the test suite
// can kill it in the middle of a commit. It has no test-only hooks inside the
// library: the parent simply terminates the process while it is working, and the
// store it was writing is then opened and verified by the ordinary reader.

#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <string>
#include <thread>
#include <vector>

#include "dccp/facility_placement_policy/facility_placement_policy.hpp"
#include "file_ops.hpp"

namespace {

using namespace dccp::facility_placement_policy;

void say(const std::string& text) {
  std::fwrite(text.data(), 1, text.size(), stdout);
  std::fputc('\n', stdout);
  std::fflush(stdout);
}

Result<std::string> read_text(const std::string& path) {
  auto bytes = internal::read_file_bounded(path, kMaxDocumentBytes);
  if (!bytes.has_value()) {
    return bytes.error();
  }
  return std::string(reinterpret_cast<const char*>(bytes.value().data()), bytes.value().size());
}

/// Replaces the decimal value of the first statement that starts with the given
/// keyword, which is how this helper walks a document forward one revision or
/// one request identity at a time.
Result<std::string> replace_statement_value(const std::string& document,
                                            const std::string& keyword, std::uint64_t value) {
  const std::string needle = "\n" + keyword + " ";
  const std::size_t start = document.find(needle);
  if (start == std::string::npos) {
    return Error(ErrorCode::MissingField, "the document does not state the expected keyword")
        .with_subject(keyword);
  }
  const std::size_t value_start = start + needle.size();
  const std::size_t value_end = document.find('\n', value_start);
  if (value_end == std::string::npos) {
    return Error(ErrorCode::TruncatedInput, "the document ends inside the statement");
  }
  std::string out = document;
  out.replace(value_start, value_end - value_start, std::to_string(value));
  return out;
}

Result<std::string> replace_identifier(const std::string& document, const std::string& keyword,
                                       const std::string& value) {
  const std::string needle = "\n" + keyword + " ";
  const std::size_t start = document.find(needle);
  if (start == std::string::npos) {
    return Error(ErrorCode::MissingField, "the document does not state the expected keyword")
        .with_subject(keyword);
  }
  const std::size_t value_start = start + needle.size();
  const std::size_t value_end = document.find('\n', value_start);
  if (value_end == std::string::npos) {
    return Error(ErrorCode::TruncatedInput, "the document ends inside the statement");
  }
  std::string out = document;
  out.replace(value_start, value_end - value_start, value);
  return out;
}

int activate_loop(const std::vector<std::string>& arguments) {
  if (arguments.size() != 4) {
    say("usage: crash_child activate <dir> <policy> <instants> <iterations>");
    return 2;
  }
  const std::string& directory = arguments[0];
  auto text = read_text(arguments[1]);
  if (!text.has_value()) {
    say(text.error().to_string());
    return 2;
  }
  auto instant = Instant::parse(arguments[2]);
  if (!instant.has_value()) {
    say(instant.error().to_string());
    return 2;
  }
  auto document = parse_policy_document(text.value());
  if (!document.has_value()) {
    say(document.error().to_string());
    return 2;
  }
  const std::uint64_t iterations = std::stoull(arguments[3]);
  const std::uint64_t base_revision = document.value().revision.value();

  auto store = Store::open(directory, StoreOpenMode::ReadWrite);
  if (!store.has_value()) {
    say(store.error().to_string());
    return 2;
  }
  for (std::uint64_t index = 1; index <= iterations; ++index) {
    auto next_text = replace_statement_value(text.value(), "revision", base_revision + index);
    if (!next_text.has_value()) {
      say(next_text.error().to_string());
      return 2;
    }
    auto next = parse_policy_document(next_text.value());
    if (!next.has_value()) {
      say(next.error().to_string());
      return 2;
    }
    auto committed = store.value().activate_policy(next.value(), instant.value());
    if (!committed.has_value()) {
      say(committed.error().to_string());
      return 3;
    }
    say("activated " + committed.value().revision.to_string());
  }
  return 0;
}

int record_loop(const std::vector<std::string>& arguments) {
  if (arguments.size() != 4) {
    say("usage: crash_child record <dir> <request> <instants> <iterations>");
    return 2;
  }
  const std::string& directory = arguments[0];
  auto text = read_text(arguments[1]);
  if (!text.has_value()) {
    say(text.error().to_string());
    return 2;
  }
  auto instant = Instant::parse(arguments[2]);
  if (!instant.has_value()) {
    say(instant.error().to_string());
    return 2;
  }
  const std::uint64_t iterations = std::stoull(arguments[3]);

  auto store = Store::open(directory, StoreOpenMode::ReadWrite);
  if (!store.has_value()) {
    say(store.error().to_string());
    return 2;
  }
  for (std::uint64_t index = 1; index <= iterations; ++index) {
    auto next_text = replace_identifier(text.value(), "request-id", "crash-req-" + std::to_string(index));
    if (!next_text.has_value()) {
      say(next_text.error().to_string());
      return 2;
    }
    auto request = parse_request_document(next_text.value());
    if (!request.has_value()) {
      say(request.error().to_string());
      return 2;
    }
    EvaluationInput input;
    input.request = std::move(request.value());
    auto verdicts = store.value().evaluate_recorded(input, instant.value());
    if (!verdicts.has_value()) {
      say(verdicts.error().to_string());
      return 3;
    }
    say("recorded crash-req-" + std::to_string(index));
  }
  return 0;
}

int hold_lock(const std::vector<std::string>& arguments, bool read_only) {
  if (arguments.size() != 2) {
    say("usage: crash_child hold <dir> <milliseconds>");
    return 2;
  }
  auto store = Store::open(arguments[0], read_only ? StoreOpenMode::ReadOnly
                                                   : StoreOpenMode::ReadWrite);
  if (!store.has_value()) {
    say(store.error().to_string());
    return 2;
  }
  say("holding");
  const auto milliseconds = std::stoll(arguments[1]);
  std::this_thread::sleep_for(std::chrono::milliseconds(milliseconds));
  return 0;
}

}  // namespace

int main(int argc, char** argv) {
  std::vector<std::string> arguments;
  for (int index = 2; index < argc; ++index) {
    arguments.emplace_back(argv[index]);
  }
  if (argc < 2) {
    say("usage: crash_child <activate|record|hold> ...");
    return 2;
  }
  const std::string mode = argv[1];
  if (mode == "activate") {
    return activate_loop(arguments);
  }
  if (mode == "record") {
    return record_loop(arguments);
  }
  if (mode == "hold") {
    return hold_lock(arguments, false);
  }
  if (mode == "hold-read") {
    return hold_lock(arguments, true);
  }
  say("unknown mode: " + mode);
  return 2;
}
