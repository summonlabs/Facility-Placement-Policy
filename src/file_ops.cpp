// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs.

#include "file_ops.hpp"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "dccp/facility_placement_policy/text_util.hpp"

#if defined(_WIN32)
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#else
#include <cerrno>
#include <cstring>
#include <dirent.h>
#include <fcntl.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#endif

namespace dccp::facility_placement_policy::internal {
namespace {

constexpr std::string_view kTemporarySuffix = ".fpp-tmp";

#if defined(_WIN32)

std::string windows_error_detail(unsigned long code) {
  return "win32-error=" + std::to_string(code);
}

/// Converts a UTF-8 path to the wide form the Windows API needs and makes it
/// long-path capable. Relative paths are resolved first, because the extended
/// prefix requires a fully qualified path.
Result<std::wstring> to_wide_path(const std::string& path) {
  if (path.empty()) {
    return Error(ErrorCode::PathInvalid, "path is empty");
  }
  if (path.find('\0') != std::string::npos) {
    return Error(ErrorCode::PathInvalid, "path contains a NUL byte");
  }
  const int needed = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, path.c_str(),
                                         static_cast<int>(path.size()), nullptr, 0);
  if (needed <= 0) {
    return Error(ErrorCode::PathInvalid, "path is not valid UTF-8")
        .with_subject(path.substr(0, 160));
  }
  std::wstring wide(static_cast<std::size_t>(needed), L'\0');
  MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, path.c_str(), static_cast<int>(path.size()),
                      wide.data(), needed);

  const DWORD length = GetFullPathNameW(wide.c_str(), 0, nullptr, nullptr);
  if (length == 0) {
    return Error(ErrorCode::PathInvalid, "path cannot be resolved to a full path")
        .with_subject(path.substr(0, 160))
        .with_detail(windows_error_detail(GetLastError()));
  }
  std::wstring full(static_cast<std::size_t>(length), L'\0');
  const DWORD written = GetFullPathNameW(wide.c_str(), length, full.data(), nullptr);
  if (written == 0 || written >= length) {
    return Error(ErrorCode::PathInvalid, "path cannot be resolved to a full path")
        .with_subject(path.substr(0, 160))
        .with_detail(windows_error_detail(GetLastError()));
  }
  full.resize(written);

  if (full.rfind(L"\\\\?\\", 0) == 0) {
    return full;
  }
  if (full.rfind(L"\\\\", 0) == 0) {
    // A UNC path becomes \\?\UNC\server\share\...
    std::wstring extended = L"\\\\?\\UNC";
    extended.append(full, 1, std::wstring::npos);
    return extended;
  }
  std::wstring extended = L"\\\\?\\";
  extended.append(full);
  return extended;
}

Result<void> report_windows_failure(const char* what, const std::string& path) {
  return Error(ErrorCode::IoError, std::string(what) + " failed")
      .with_subject(path.substr(0, 160))
      .with_detail(windows_error_detail(GetLastError()));
}

#endif  // _WIN32

}  // namespace

Result<ByteBuffer> read_file_bounded(const std::string& path, std::size_t max_bytes) {
#if defined(_WIN32)
  const auto wide = to_wide_path(path);
  if (!wide.has_value()) {
    return wide.error();
  }
  // The share mode must include write and delete: durable publication replaces
  // a file while a reader may still hold it open, and a reader that refused
  // replacement would turn a concurrent commit into an access-denied failure.
  HANDLE handle = CreateFileW(wide.value().c_str(), GENERIC_READ,
                              FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr,
                              OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
  if (handle == INVALID_HANDLE_VALUE) {
    const DWORD code = GetLastError();
    if (code == ERROR_FILE_NOT_FOUND || code == ERROR_PATH_NOT_FOUND) {
      return Error(ErrorCode::RecordNotFound, "file does not exist")
          .with_subject(path.substr(0, 160));
    }
    return Error(ErrorCode::IoError, "cannot open file for reading")
        .with_subject(path.substr(0, 160))
        .with_detail(windows_error_detail(code));
  }
  LARGE_INTEGER size{};
  if (GetFileSizeEx(handle, &size) == 0) {
    const DWORD code = GetLastError();
    CloseHandle(handle);
    return Error(ErrorCode::IoError, "cannot size file")
        .with_subject(path.substr(0, 160))
        .with_detail(windows_error_detail(code));
  }
  if (size.QuadPart < 0 ||
      static_cast<std::uint64_t>(size.QuadPart) > static_cast<std::uint64_t>(max_bytes)) {
    CloseHandle(handle);
    return Error(ErrorCode::LimitExceeded, "file is larger than the limit")
        .with_subject(path.substr(0, 160))
        .with_detail("limit=" + std::to_string(max_bytes) +
                     " actual=" + std::to_string(size.QuadPart));
  }
  ByteBuffer buffer(static_cast<std::size_t>(size.QuadPart));
  std::size_t offset = 0;
  while (offset < buffer.size()) {
    const DWORD chunk = static_cast<DWORD>(
        std::min<std::size_t>(buffer.size() - offset, 1u << 20));
    DWORD read = 0;
    if (ReadFile(handle, buffer.data() + offset, chunk, &read, nullptr) == 0) {
      const DWORD code = GetLastError();
      CloseHandle(handle);
      return Error(ErrorCode::IoError, "cannot read file")
          .with_subject(path.substr(0, 160))
          .with_detail(windows_error_detail(code));
    }
    if (read == 0) {
      CloseHandle(handle);
      return Error(ErrorCode::TruncatedInput, "file ended before its declared length")
          .with_subject(path.substr(0, 160));
    }
    offset += read;
  }
  CloseHandle(handle);
  return buffer;
#else
  const int descriptor = ::open(path.c_str(), O_RDONLY | O_CLOEXEC);
  if (descriptor < 0) {
    if (errno == ENOENT) {
      return Error(ErrorCode::RecordNotFound, "file does not exist")
          .with_subject(path.substr(0, 160));
    }
    return Error(ErrorCode::IoError, "cannot open file for reading")
        .with_subject(path.substr(0, 160))
        .with_detail(std::string("errno=") + std::strerror(errno));
  }
  struct stat info {};
  if (::fstat(descriptor, &info) != 0) {
    ::close(descriptor);
    return Error(ErrorCode::IoError, "cannot size file").with_subject(path.substr(0, 160));
  }
  if (info.st_size < 0 || static_cast<std::uint64_t>(info.st_size) > max_bytes) {
    ::close(descriptor);
    return Error(ErrorCode::LimitExceeded, "file is larger than the limit")
        .with_subject(path.substr(0, 160))
        .with_detail("limit=" + std::to_string(max_bytes));
  }
  ByteBuffer buffer(static_cast<std::size_t>(info.st_size));
  std::size_t offset = 0;
  while (offset < buffer.size()) {
    const ssize_t read = ::read(descriptor, buffer.data() + offset, buffer.size() - offset);
    if (read < 0) {
      if (errno == EINTR) {
        continue;
      }
      ::close(descriptor);
      return Error(ErrorCode::IoError, "cannot read file").with_subject(path.substr(0, 160));
    }
    if (read == 0) {
      ::close(descriptor);
      return Error(ErrorCode::TruncatedInput, "file ended before its declared length")
          .with_subject(path.substr(0, 160));
    }
    offset += static_cast<std::size_t>(read);
  }
  ::close(descriptor);
  return buffer;
#endif
}

Result<void> write_file_atomic(const std::string& path, std::span<const std::uint8_t> bytes) {
  const std::string temporary = path + std::string(kTemporarySuffix);
#if defined(_WIN32)
  const auto wide_temp = to_wide_path(temporary);
  if (!wide_temp.has_value()) {
    return wide_temp.error();
  }
  const auto wide_final = to_wide_path(path);
  if (!wide_final.has_value()) {
    return wide_final.error();
  }
  HANDLE handle = CreateFileW(wide_temp.value().c_str(), GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS,
                              FILE_ATTRIBUTE_NORMAL, nullptr);
  if (handle == INVALID_HANDLE_VALUE) {
    return report_windows_failure("cannot create temporary file", temporary);
  }
  std::size_t offset = 0;
  while (offset < bytes.size()) {
    const DWORD chunk =
        static_cast<DWORD>(std::min<std::size_t>(bytes.size() - offset, 1u << 20));
    DWORD written = 0;
    if (WriteFile(handle, bytes.data() + offset, chunk, &written, nullptr) == 0) {
      const DWORD code = GetLastError();
      CloseHandle(handle);
      DeleteFileW(wide_temp.value().c_str());
      return Error(ErrorCode::IoError, "cannot write temporary file")
          .with_subject(temporary.substr(0, 160))
          .with_detail(windows_error_detail(code));
    }
    offset += written;
  }
  if (FlushFileBuffers(handle) == 0) {
    const DWORD code = GetLastError();
    CloseHandle(handle);
    DeleteFileW(wide_temp.value().c_str());
    return Error(ErrorCode::IoError, "cannot flush temporary file to the device")
        .with_subject(temporary.substr(0, 160))
        .with_detail(windows_error_detail(code));
  }
  CloseHandle(handle);
  if (MoveFileExW(wide_temp.value().c_str(), wide_final.value().c_str(),
                  MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH) == 0) {
    const DWORD code = GetLastError();
    DeleteFileW(wide_temp.value().c_str());
    return Error(ErrorCode::IoError, "cannot publish file")
        .with_subject(path.substr(0, 160))
        .with_detail(windows_error_detail(code));
  }
  return success;
#else
  const int descriptor =
      ::open(temporary.c_str(), O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
  if (descriptor < 0) {
    return Error(ErrorCode::IoError, "cannot create temporary file")
        .with_subject(temporary.substr(0, 160))
        .with_detail(std::string("errno=") + std::strerror(errno));
  }
  std::size_t offset = 0;
  while (offset < bytes.size()) {
    const ssize_t written = ::write(descriptor, bytes.data() + offset, bytes.size() - offset);
    if (written < 0) {
      if (errno == EINTR) {
        continue;
      }
      ::close(descriptor);
      ::unlink(temporary.c_str());
      return Error(ErrorCode::IoError, "cannot write temporary file")
          .with_subject(temporary.substr(0, 160));
    }
    offset += static_cast<std::size_t>(written);
  }
  if (::fsync(descriptor) != 0) {
    ::close(descriptor);
    ::unlink(temporary.c_str());
    return Error(ErrorCode::IoError, "cannot flush temporary file to the device")
        .with_subject(temporary.substr(0, 160));
  }
  if (::close(descriptor) != 0) {
    ::unlink(temporary.c_str());
    return Error(ErrorCode::IoError, "cannot close temporary file")
        .with_subject(temporary.substr(0, 160));
  }
  if (::rename(temporary.c_str(), path.c_str()) != 0) {
    ::unlink(temporary.c_str());
    return Error(ErrorCode::IoError, "cannot publish file")
        .with_subject(path.substr(0, 160))
        .with_detail(std::string("errno=") + std::strerror(errno));
  }
  return success;
#endif
}

bool file_exists(const std::string& path) {
#if defined(_WIN32)
  const auto wide = to_wide_path(path);
  if (!wide.has_value()) {
    return false;
  }
  const DWORD attributes = GetFileAttributesW(wide.value().c_str());
  return attributes != INVALID_FILE_ATTRIBUTES && (attributes & FILE_ATTRIBUTE_DIRECTORY) == 0;
#else
  struct stat info {};
  return ::stat(path.c_str(), &info) == 0 && S_ISREG(info.st_mode);
#endif
}

bool directory_exists(const std::string& path) {
#if defined(_WIN32)
  const auto wide = to_wide_path(path);
  if (!wide.has_value()) {
    return false;
  }
  const DWORD attributes = GetFileAttributesW(wide.value().c_str());
  return attributes != INVALID_FILE_ATTRIBUTES && (attributes & FILE_ATTRIBUTE_DIRECTORY) != 0;
#else
  struct stat info {};
  return ::stat(path.c_str(), &info) == 0 && S_ISDIR(info.st_mode);
#endif
}

Result<void> create_directories(const std::string& path) {
  if (path.empty()) {
    return Error(ErrorCode::PathInvalid, "directory path is empty");
  }
  if (directory_exists(path)) {
    return success;
  }
  const std::size_t separator = path.find_last_of("/\\");
  if (separator != std::string::npos && separator > 0) {
    const std::string parent = path.substr(0, separator);
    if (!parent.empty() && !directory_exists(parent)) {
      const auto parent_result = create_directories(parent);
      if (!parent_result.has_value()) {
        return parent_result.error();
      }
    }
  }
#if defined(_WIN32)
  const auto wide = to_wide_path(path);
  if (!wide.has_value()) {
    return wide.error();
  }
  if (CreateDirectoryW(wide.value().c_str(), nullptr) == 0) {
    const DWORD code = GetLastError();
    if (code != ERROR_ALREADY_EXISTS) {
      return Error(ErrorCode::IoError, "cannot create directory")
          .with_subject(path.substr(0, 160))
          .with_detail(windows_error_detail(code));
    }
  }
  return success;
#else
  if (::mkdir(path.c_str(), 0700) != 0 && errno != EEXIST) {
    return Error(ErrorCode::IoError, "cannot create directory")
        .with_subject(path.substr(0, 160))
        .with_detail(std::string("errno=") + std::strerror(errno));
  }
  return success;
#endif
}

Result<std::vector<std::string>> list_directory(const std::string& path) {
  std::vector<std::string> names;
#if defined(_WIN32)
  const auto wide = to_wide_path(path);
  if (!wide.has_value()) {
    return wide.error();
  }
  std::wstring pattern = wide.value();
  if (!pattern.empty() && pattern.back() != L'\\') {
    pattern.push_back(L'\\');
  }
  pattern.push_back(L'*');
  WIN32_FIND_DATAW entry{};
  HANDLE search = FindFirstFileW(pattern.c_str(), &entry);
  if (search == INVALID_HANDLE_VALUE) {
    const DWORD code = GetLastError();
    if (code == ERROR_FILE_NOT_FOUND) {
      return names;
    }
    return Error(ErrorCode::IoError, "cannot list directory")
        .with_subject(path.substr(0, 160))
        .with_detail(windows_error_detail(code));
  }
  do {
    if ((entry.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0) {
      continue;
    }
    const int needed = WideCharToMultiByte(CP_UTF8, 0, entry.cFileName, -1, nullptr, 0, nullptr,
                                           nullptr);
    if (needed <= 1) {
      continue;
    }
    std::string name(static_cast<std::size_t>(needed - 1), '\0');
    WideCharToMultiByte(CP_UTF8, 0, entry.cFileName, -1, name.data(), needed, nullptr, nullptr);
    names.push_back(std::move(name));
  } while (FindNextFileW(search, &entry) != 0);
  FindClose(search);
#else
  DIR* directory = ::opendir(path.c_str());
  if (directory == nullptr) {
    if (errno == ENOENT) {
      return names;
    }
    return Error(ErrorCode::IoError, "cannot list directory").with_subject(path.substr(0, 160));
  }
  while (const dirent* entry = ::readdir(directory)) {
    const std::string name = entry->d_name;
    if (name == "." || name == "..") {
      continue;
    }
    struct stat info {};
    const std::string full = path + "/" + name;
    if (::stat(full.c_str(), &info) == 0 && S_ISREG(info.st_mode)) {
      names.push_back(name);
    }
  }
  ::closedir(directory);
#endif
  std::sort(names.begin(), names.end());
  return names;
}

Result<void> remove_file(const std::string& path) {
#if defined(_WIN32)
  const auto wide = to_wide_path(path);
  if (!wide.has_value()) {
    return wide.error();
  }
  if (DeleteFileW(wide.value().c_str()) == 0) {
    const DWORD code = GetLastError();
    if (code != ERROR_FILE_NOT_FOUND && code != ERROR_PATH_NOT_FOUND) {
      return Error(ErrorCode::IoError, "cannot remove file")
          .with_subject(path.substr(0, 160))
          .with_detail(windows_error_detail(code));
    }
  }
  return success;
#else
  if (::unlink(path.c_str()) != 0 && errno != ENOENT) {
    return Error(ErrorCode::IoError, "cannot remove file")
        .with_subject(path.substr(0, 160))
        .with_detail(std::string("errno=") + std::strerror(errno));
  }
  return success;
#endif
}

Result<void> remove_tree(const std::string& path) {
  if (!directory_exists(path)) {
    if (!file_exists(path)) {
      return success;
    }
    return remove_file(path);
  }

  // A tree holds directories as well as files, so the walk has to recurse. A
  // listing that returned only regular files would leave the subdirectories
  // behind and the final removal would fail with "directory not empty".
#if defined(_WIN32)
  {
    const auto wide = to_wide_path(path);
    if (!wide.has_value()) {
      return wide.error();
    }
    std::wstring pattern = wide.value();
    if (!pattern.empty() && pattern.back() != L'\\') {
      pattern.push_back(L'\\');
    }
    pattern.push_back(L'*');
    WIN32_FIND_DATAW entry{};
    HANDLE search = FindFirstFileW(pattern.c_str(), &entry);
    if (search != INVALID_HANDLE_VALUE) {
      do {
        const std::wstring name = entry.cFileName;
        if (name == L"." || name == L"..") {
          continue;
        }
        const int needed =
            WideCharToMultiByte(CP_UTF8, 0, name.c_str(), -1, nullptr, 0, nullptr, nullptr);
        if (needed <= 1) {
          continue;
        }
        std::string utf8(static_cast<std::size_t>(needed - 1), '\0');
        WideCharToMultiByte(CP_UTF8, 0, name.c_str(), -1, utf8.data(), needed, nullptr, nullptr);
        const auto removed = remove_tree(path + "/" + utf8);
        if (!removed.has_value()) {
          FindClose(search);
          return removed.error();
        }
      } while (FindNextFileW(search, &entry) != 0);
      FindClose(search);
    }
    if (RemoveDirectoryW(wide.value().c_str()) == 0) {
      const DWORD code = GetLastError();
      if (code != ERROR_PATH_NOT_FOUND && code != ERROR_FILE_NOT_FOUND) {
        return Error(ErrorCode::IoError, "cannot remove directory")
            .with_subject(path.substr(0, 160))
            .with_detail(windows_error_detail(code));
      }
    }
    return success;
  }
#else
  {
    DIR* directory = ::opendir(path.c_str());
    if (directory == nullptr) {
      if (errno == ENOENT) {
        return success;
      }
      return Error(ErrorCode::IoError, "cannot list directory").with_subject(path.substr(0, 160));
    }
    while (const dirent* entry = ::readdir(directory)) {
      const std::string name = entry->d_name;
      if (name == "." || name == "..") {
        continue;
      }
      const std::string child = path + "/" + name;
      struct stat info {};
      if (::lstat(child.c_str(), &info) != 0) {
        continue;
      }
      const auto removed = S_ISDIR(info.st_mode) ? remove_tree(child) : remove_file(child);
      if (!removed.has_value()) {
        ::closedir(directory);
        return removed.error();
      }
    }
    ::closedir(directory);
    if (::rmdir(path.c_str()) != 0 && errno != ENOENT) {
      return Error(ErrorCode::IoError, "cannot remove directory")
          .with_subject(path.substr(0, 160))
          .with_detail(std::string("errno=") + std::strerror(errno));
    }
    return success;
  }
#endif
}

Result<void> sync_directory(const std::string& path) {
#if defined(_WIN32)
  // Windows has no directory flush that this layer can call; the atomic replace
  // is issued with MOVEFILE_WRITE_THROUGH, which waits for the metadata change
  // to reach the device before it returns.
  if (!directory_exists(path)) {
    return Error(ErrorCode::RecordNotFound, "directory does not exist")
        .with_subject(path.substr(0, 160));
  }
  return success;
#else
  const int descriptor = ::open(path.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC);
  if (descriptor < 0) {
    return Error(ErrorCode::IoError, "cannot open directory").with_subject(path.substr(0, 160));
  }
  const int result = ::fsync(descriptor);
  ::close(descriptor);
  if (result != 0) {
    return Error(ErrorCode::IoError, "cannot flush directory").with_subject(path.substr(0, 160));
  }
  return success;
#endif
}

bool is_reserved_device_name(std::string_view component) {
  std::string stem(component);
  const std::size_t dot = stem.find('.');
  if (dot != std::string::npos) {
    stem.resize(dot);
  }
  const std::string upper = ascii_upper(stem);
  if (upper == "CON" || upper == "PRN" || upper == "AUX" || upper == "NUL") {
    return true;
  }
  return upper.size() == 4 && (upper.rfind("COM", 0) == 0 || upper.rfind("LPT", 0) == 0) &&
         upper[3] >= '1' && upper[3] <= '9';
}

Result<void> validate_directory_path(const std::string& path) {
  if (path.empty()) {
    return Error(ErrorCode::PathInvalid, "directory path is empty");
  }
  if (path.find('\0') != std::string::npos) {
    return Error(ErrorCode::PathInvalid, "directory path contains a NUL byte");
  }
  if (path.size() > 4096) {
    return Error(ErrorCode::PathInvalid, "directory path is longer than 4096 bytes");
  }
  std::size_t end = path.size();
  while (end > 0 && (path[end - 1] == '/' || path[end - 1] == '\\')) {
    --end;
  }
  const std::size_t separator = path.find_last_of("/\\", end == 0 ? 0 : end - 1);
  const std::string final_component =
      path.substr(separator == std::string::npos ? 0 : separator + 1,
                  end - (separator == std::string::npos ? 0 : separator + 1));
  if (final_component.empty()) {
    return Error(ErrorCode::PathInvalid, "directory path has no final component");
  }
  // The directory is chosen by an operator, so anything the operating system can
  // represent is allowed; a reserved device name is not, because it would not
  // name a directory at all. Everything this runtime creates inside the
  // directory has a fixed or digest-derived name, so nothing untrusted reaches
  // the filesystem.
  if (is_reserved_device_name(final_component)) {
    return Error(ErrorCode::PathInvalid, "directory path ends in a reserved device name")
        .with_subject(final_component);
  }
  if (final_component == "." || final_component == "..") {
    return Error(ErrorCode::PathInvalid,
                 "directory path ends in a relative component, which would name the store "
                 "somewhere other than where it says")
        .with_subject(final_component);
  }
  return success;
}

Result<void> validate_path_component(const std::string& component) {
  if (component.empty()) {
    return Error(ErrorCode::PathInvalid, "path component is empty");
  }
  if (component.size() > 64) {
    return Error(ErrorCode::PathInvalid, "path component is longer than 64 bytes")
        .with_subject(component.substr(0, 160));
  }
  for (const char ch : component) {
    const bool allowed = (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') ||
                         (ch >= '0' && ch <= '9') || ch == '.' || ch == '-' || ch == '_';
    if (!allowed) {
      return Error(ErrorCode::PathInvalid, "path component contains a character outside "
                                           "[A-Za-z0-9._-]")
          .with_subject(component.substr(0, 160));
    }
  }
  if (component == "." || component == "..") {
    return Error(ErrorCode::PathInvalid, "path component is a relative component")
        .with_subject(component);
  }
  // Reserved device names are reserved with or without an extension and in any
  // case, so they are refused rather than created.
  if (is_reserved_device_name(component)) {
    return Error(ErrorCode::PathInvalid, "path component is a reserved device name")
        .with_subject(component);
  }
  return success;
}

FileLock::~FileLock() { release(); }

FileLock::FileLock(FileLock&& other) noexcept {
#if defined(_WIN32)
  handle_ = other.handle_;
  other.handle_ = nullptr;
#else
  descriptor_ = other.descriptor_;
  other.descriptor_ = -1;
#endif
}

FileLock& FileLock::operator=(FileLock&& other) noexcept {
  if (this != &other) {
    release();
#if defined(_WIN32)
    handle_ = other.handle_;
    other.handle_ = nullptr;
#else
    descriptor_ = other.descriptor_;
    other.descriptor_ = -1;
#endif
  }
  return *this;
}

bool FileLock::held() const noexcept {
#if defined(_WIN32)
  return handle_ != nullptr;
#else
  return descriptor_ >= 0;
#endif
}

void FileLock::release() noexcept {
#if defined(_WIN32)
  if (handle_ != nullptr) {
    OVERLAPPED overlapped{};
    UnlockFileEx(static_cast<HANDLE>(handle_), 0, 1, 0, &overlapped);
    CloseHandle(static_cast<HANDLE>(handle_));
    handle_ = nullptr;
  }
#else
  if (descriptor_ >= 0) {
    ::flock(descriptor_, LOCK_UN);
    ::close(descriptor_);
    descriptor_ = -1;
  }
#endif
}

Result<FileLock> FileLock::acquire(const std::string& path, bool exclusive) {
  FileLock lock;
#if defined(_WIN32)
  const auto wide = to_wide_path(path);
  if (!wide.has_value()) {
    return wide.error();
  }
  HANDLE handle = CreateFileW(wide.value().c_str(), GENERIC_READ | GENERIC_WRITE,
                              FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_ALWAYS,
                              FILE_ATTRIBUTE_NORMAL, nullptr);
  if (handle == INVALID_HANDLE_VALUE) {
    return Error(ErrorCode::IoError, "cannot open the lock file")
        .with_subject(path.substr(0, 160))
        .with_detail(windows_error_detail(GetLastError()));
  }
  OVERLAPPED overlapped{};
  DWORD flags = LOCKFILE_FAIL_IMMEDIATELY;
  if (exclusive) {
    flags |= LOCKFILE_EXCLUSIVE_LOCK;
  }
  if (LockFileEx(handle, flags, 0, 1, 0, &overlapped) == 0) {
    const DWORD code = GetLastError();
    CloseHandle(handle);
    if (code == ERROR_LOCK_VIOLATION || code == ERROR_IO_PENDING) {
      return Error(ErrorCode::StoreLocked,
                   "another process or thread already holds this store")
          .with_subject(path.substr(0, 160));
    }
    return Error(ErrorCode::LockUnavailable, "cannot take the store lock")
        .with_subject(path.substr(0, 160))
        .with_detail(windows_error_detail(code));
  }
  lock.handle_ = handle;
  return lock;
#else
  const int descriptor = ::open(path.c_str(), O_RDWR | O_CREAT | O_CLOEXEC, 0600);
  if (descriptor < 0) {
    return Error(ErrorCode::IoError, "cannot open the lock file")
        .with_subject(path.substr(0, 160))
        .with_detail(std::string("errno=") + std::strerror(errno));
  }
  if (::flock(descriptor, (exclusive ? LOCK_EX : LOCK_SH) | LOCK_NB) != 0) {
    const int code = errno;
    ::close(descriptor);
    if (code == EWOULDBLOCK) {
      return Error(ErrorCode::StoreLocked, "another process already holds this store")
          .with_subject(path.substr(0, 160));
    }
    return Error(ErrorCode::LockUnavailable, "cannot take the store lock")
        .with_subject(path.substr(0, 160))
        .with_detail(std::string("errno=") + std::strerror(code));
  }
  lock.descriptor_ = descriptor;
  return lock;
#endif
}

}  // namespace dccp::facility_placement_policy::internal
