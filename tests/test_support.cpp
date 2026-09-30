// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs.

#include "test_support.hpp"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

#include "file_ops.hpp"
#include "test_framework.hpp"

namespace fptest {
namespace {

constexpr std::size_t kMaxTestFileBytes = 64u * 1024u * 1024u;

std::string configured_scratch_root() {
#ifdef FACILITY_PLACEMENT_POLICY_SCRATCH_ROOT
  return std::string(FACILITY_PLACEMENT_POLICY_SCRATCH_ROOT);
#else
  return std::string("test-scratch");
#endif
}

}  // namespace

std::string scratch_root() { return configured_scratch_root(); }

Result<void> make_scratch_root() {
  const std::string root = configured_scratch_root();
  const auto removed = dccp::facility_placement_policy::internal::remove_tree(root);
  if (!removed.has_value()) {
    return removed.error();
  }
  return dccp::facility_placement_policy::internal::create_directories(root);
}

Result<void> remove_scratch_directory(const std::string& path) {
  const std::string root = configured_scratch_root();
  if (path.size() <= root.size() || path.compare(0, root.size(), root) != 0) {
    return dccp::facility_placement_policy::Error(
               dccp::facility_placement_policy::ErrorCode::PathInvalid,
               "a test may only remove directories inside the scratch root")
        .with_subject(path.substr(0, 160));
  }
  return dccp::facility_placement_policy::internal::remove_tree(path);
}

Result<std::string> fresh_directory(const std::string& name) {
  const auto component = dccp::facility_placement_policy::internal::validate_path_component(name);
  if (!component.has_value()) {
    return component.error();
  }
  const std::string path = configured_scratch_root() + "/" + name;
  const auto removed = remove_scratch_directory(path);
  if (!removed.has_value()) {
    return removed.error();
  }
  const auto created = dccp::facility_placement_policy::internal::create_directories(path);
  if (!created.has_value()) {
    return created.error();
  }
  return path;
}

std::string lines(std::initializer_list<std::string> parts) {
  std::string out;
  for (const std::string& part : parts) {
    out.append(part);
    out.push_back('\n');
  }
  return out;
}

Result<std::string> read_text_file(const std::string& path) {
  auto bytes = dccp::facility_placement_policy::internal::read_file_bounded(path, kMaxTestFileBytes);
  if (!bytes.has_value()) {
    return bytes.error();
  }
  return std::string(reinterpret_cast<const char*>(bytes.value().data()), bytes.value().size());
}

Result<void> write_text_file(const std::string& path, const std::string& text) {
  return dccp::facility_placement_policy::internal::write_file_atomic(
      path, std::span<const std::uint8_t>(reinterpret_cast<const std::uint8_t*>(text.data()),
                                          text.size()));
}

Result<ByteBuffer> read_bytes(const std::string& path) {
  return dccp::facility_placement_policy::internal::read_file_bounded(path, kMaxTestFileBytes);
}

Result<void> write_bytes(const std::string& path, const ByteBuffer& bytes) {
  return dccp::facility_placement_policy::internal::write_file_atomic(
      path, std::span<const std::uint8_t>(bytes.data(), bytes.size()));
}

Result<void> patch_bytes(const std::string& path, std::size_t offset,
                         const std::vector<std::uint8_t>& replacement) {
  auto bytes = read_bytes(path);
  if (!bytes.has_value()) {
    return bytes.error();
  }
  if (offset + replacement.size() > bytes.value().size()) {
    return dccp::facility_placement_policy::Error(
               dccp::facility_placement_policy::ErrorCode::LimitExceeded,
               "the patch is larger than the file")
        .with_detail("offset=" + std::to_string(offset));
  }
  for (std::size_t index = 0; index < replacement.size(); ++index) {
    bytes.value()[offset + index] = replacement[index];
  }
  return write_bytes(path, bytes.value());
}

Result<void> truncate_file(const std::string& path, std::size_t bytes) {
  auto content = read_bytes(path);
  if (!content.has_value()) {
    return content.error();
  }
  if (bytes > content.value().size()) {
    return dccp::facility_placement_policy::Error(
               dccp::facility_placement_policy::ErrorCode::LimitExceeded,
               "cannot truncate a file to a larger size");
  }
  content.value().resize(bytes);
  return write_bytes(path, content.value());
}

Result<void> append_bytes(const std::string& path, const std::vector<std::uint8_t>& extra) {
  auto content = read_bytes(path);
  if (!content.has_value()) {
    return content.error();
  }
  content.value().insert(content.value().end(), extra.begin(), extra.end());
  return write_bytes(path, content.value());
}

Result<std::vector<std::string>> directory_names(const std::string& path) {
  return dccp::facility_placement_policy::internal::list_directory(path);
}

bool file_present(const std::string& path) {
  return dccp::facility_placement_policy::internal::file_exists(path);
}

std::string cli_path() {
#ifdef FACILITY_PLACEMENT_POLICY_CLI_PATH
  return std::string(FACILITY_PLACEMENT_POLICY_CLI_PATH);
#else
  return std::string();
#endif
}

std::string crash_child_path() {
#ifdef FACILITY_PLACEMENT_POLICY_CRASH_CHILD_PATH
  return std::string(FACILITY_PLACEMENT_POLICY_CRASH_CHILD_PATH);
#else
  return std::string();
#endif
}

std::string normalize_newlines(std::string text) {
  std::string out;
  out.reserve(text.size());
  for (std::size_t index = 0; index < text.size(); ++index) {
    if (text[index] == '\r' && index + 1 < text.size() && text[index + 1] == '\n') {
      continue;
    }
    out.push_back(text[index]);
  }
  return out;
}

std::string quote_argument(const std::string& argument) {
  if (!argument.empty() && argument.find_first_of(" \t\"") == std::string::npos) {
    return argument;
  }
  std::string out;
  out.push_back('"');
  std::size_t backslashes = 0;
  for (const char ch : argument) {
    if (ch == '\\') {
      ++backslashes;
      continue;
    }
    if (ch == '"') {
      out.append(backslashes * 2 + 1, '\\');
      out.push_back('"');
      backslashes = 0;
      continue;
    }
    out.append(backslashes, '\\');
    backslashes = 0;
    out.push_back(ch);
  }
  out.append(backslashes * 2, '\\');
  out.push_back('"');
  return out;
}

}  // namespace fptest
