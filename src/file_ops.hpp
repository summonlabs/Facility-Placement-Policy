// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs.
//
// Operating-system file operations for the durable store. Not installed.
//
// Everything the store does to the filesystem goes through this layer, so the
// durability and locking claims have exactly one implementation to audit. Paths
// are UTF-8 and are converted with the strict conversion; long paths are
// supported.

#ifndef DCCP_FACILITY_PLACEMENT_POLICY_SRC_FILE_OPS_HPP
#define DCCP_FACILITY_PLACEMENT_POLICY_SRC_FILE_OPS_HPP

#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <vector>

#include "dccp/facility_placement_policy/canonical.hpp"
#include "dccp/facility_placement_policy/result.hpp"

namespace dccp::facility_placement_policy::internal {

/// Reads a whole file. A file larger than max_bytes is refused before it is
/// read, so an absurd declared or actual size cannot be turned into an
/// allocation.
Result<ByteBuffer> read_file_bounded(const std::string& path, std::size_t max_bytes);

/// Writes bytes to path atomically and durably:
///   create "<path>.fpp-tmp" exclusively, write it all, flush it to the device,
///   close it, then replace path with it in one rename.
/// A crash before the rename leaves path exactly as it was; a crash after it
/// leaves the new contents. There is no intermediate state.
Result<void> write_file_atomic(const std::string& path, std::span<const std::uint8_t> bytes);

bool file_exists(const std::string& path);
bool directory_exists(const std::string& path);

/// Creates the directory and every missing parent. Succeeds when it already
/// exists as a directory.
Result<void> create_directories(const std::string& path);

/// Names of the regular files directly inside the directory, sorted by byte
/// value so callers see a deterministic order.
Result<std::vector<std::string>> list_directory(const std::string& path);

/// Removes a file. Missing is not an error.
Result<void> remove_file(const std::string& path);

/// Removes a directory tree. Missing is not an error.
Result<void> remove_tree(const std::string& path);

/// Flushes directory metadata to the device where the platform supports it.
Result<void> sync_directory(const std::string& path);

/// Rejects a directory path this runtime refuses to use: empty, containing a
/// NUL, ending in a Windows reserved device name, or containing a character the
/// platform cannot represent in a path.
Result<void> validate_directory_path(const std::string& path);

/// Validates a single path component produced from untrusted text: no
/// separators, no reserved names, no relative components, at most 64 bytes of
/// ASCII letters, digits, '.' and '-'.
Result<void> validate_path_component(const std::string& component);

/// An advisory lock held on a file for as long as the object lives.
///
/// The lock is taken with the operating system's non-blocking interface, so a
/// second writer is told "locked" immediately instead of waiting, and the kernel
/// releases the lock when the process dies for any reason, including an abrupt
/// one.
class FileLock {
 public:
  FileLock() noexcept = default;
  ~FileLock();

  FileLock(FileLock&& other) noexcept;
  FileLock& operator=(FileLock&& other) noexcept;
  FileLock(const FileLock&) = delete;
  FileLock& operator=(const FileLock&) = delete;

  /// Opens (creating if needed) the lock file and takes the lock. Reports
  /// ErrorCode::StoreLocked when another process holds a conflicting lock.
  static Result<FileLock> acquire(const std::string& path, bool exclusive);

  bool held() const noexcept;
  void release() noexcept;

 private:
#if defined(_WIN32)
  void* handle_ = nullptr;
#else
  int descriptor_ = -1;
#endif
};

}  // namespace dccp::facility_placement_policy::internal

#endif  // DCCP_FACILITY_PLACEMENT_POLICY_SRC_FILE_OPS_HPP
