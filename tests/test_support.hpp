// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs.

#ifndef DCCP_FACILITY_PLACEMENT_POLICY_TESTS_TEST_SUPPORT_HPP
#define DCCP_FACILITY_PLACEMENT_POLICY_TESTS_TEST_SUPPORT_HPP

#include <cstdint>
#include <initializer_list>
#include <string>
#include <vector>

#include "dccp/facility_placement_policy/canonical.hpp"
#include "dccp/facility_placement_policy/result.hpp"

namespace fptest {

using dccp::facility_placement_policy::ByteBuffer;
using dccp::facility_placement_policy::Result;

/// Absolute path of the directory the test suite may create files in. It is
/// inside the build tree and is removed before the suite starts and after it
/// finishes.
std::string scratch_root();

/// Creates the scratch root, removing anything that was there before. Called
/// once by run_all.
Result<void> make_scratch_root();

/// Removes a directory tree inside the scratch root. Refuses a path outside it,
/// so a test cannot delete something it does not own.
Result<void> remove_scratch_directory(const std::string& path);

/// A fresh, empty directory under the scratch root with a deterministic name.
Result<std::string> fresh_directory(const std::string& name);

/// Joins lines with newlines and a trailing newline.
std::string lines(std::initializer_list<std::string> parts);

/// Reads a whole file with the library's own bounded reader.
Result<std::string> read_text_file(const std::string& path);

/// Writes a whole file with the library's own atomic writer.
Result<void> write_text_file(const std::string& path, const std::string& text);

/// Reads a whole file as raw bytes.
Result<ByteBuffer> read_bytes(const std::string& path);

/// Writes raw bytes.
Result<void> write_bytes(const std::string& path, const ByteBuffer& bytes);

/// Overwrites a byte range inside a file, for corruption sweeps.
Result<void> patch_bytes(const std::string& path, std::size_t offset,
                         const std::vector<std::uint8_t>& replacement);

/// Truncates a file to a byte count.
Result<void> truncate_file(const std::string& path, std::size_t bytes);

/// Extends a file with arbitrary bytes.
Result<void> append_bytes(const std::string& path, const std::vector<std::uint8_t>& extra);

/// Every file name directly inside a directory, sorted.
Result<std::vector<std::string>> directory_names(const std::string& path);

/// True when the path names an existing regular file.
bool file_present(const std::string& path);

/// The command line of the built CLI, or an empty string when it was not built.
std::string cli_path();

/// The command line of the crash helper, or an empty string when it was not
/// built.
std::string crash_child_path();

/// Quotes one argument for a Windows command line.
std::string quote_argument(const std::string& argument);

/// Replaces CRLF with LF.
///
/// A process whose standard output is a pipe still gets the C runtime's
/// text-mode translation on Windows, so captured output has CRLF line endings
/// even though the program wrote LF. Comparisons against expected text should
/// not depend on which platform produced the bytes.
std::string normalize_newlines(std::string text);

}  // namespace fptest

#endif  // DCCP_FACILITY_PLACEMENT_POLICY_TESTS_TEST_SUPPORT_HPP
