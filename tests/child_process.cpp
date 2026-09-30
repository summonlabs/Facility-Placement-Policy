// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs.

#include "child_process.hpp"

#include <string>
#include <vector>

#if defined(_WIN32)
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#else
#include <csignal>
#include <cstring>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#endif

namespace fptest {

using dccp::facility_placement_policy::Error;
using dccp::facility_placement_policy::ErrorCode;

#if defined(_WIN32)

namespace {

Result<std::wstring> to_wide(const std::string& text) {
  if (text.empty()) {
    return std::wstring();
  }
  const int needed = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, text.c_str(),
                                        static_cast<int>(text.size()), nullptr, 0);
  if (needed <= 0) {
    return Error(ErrorCode::PathInvalid, "text is not valid UTF-8");
  }
  std::wstring wide(static_cast<std::size_t>(needed), L'\0');
  MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, text.c_str(), static_cast<int>(text.size()),
                      wide.data(), needed);
  return wide;
}

}  // namespace

#endif

ChildProcess::~ChildProcess() {
  if (running()) {
    static_cast<void>(terminate());
  }
  static_cast<void>(wait());
#if defined(_WIN32)
  if (read_pipe_ != nullptr) {
    CloseHandle(static_cast<HANDLE>(read_pipe_));
    read_pipe_ = nullptr;
  }
#else
  if (read_pipe_ >= 0) {
    ::close(read_pipe_);
    read_pipe_ = -1;
  }
#endif
}

ChildProcess::ChildProcess(ChildProcess&& other) noexcept {
#if defined(_WIN32)
  process_ = other.process_;
  thread_ = other.thread_;
  read_pipe_ = other.read_pipe_;
  other.process_ = nullptr;
  other.thread_ = nullptr;
  other.read_pipe_ = nullptr;
#else
  pid_ = other.pid_;
  read_pipe_ = other.read_pipe_;
  other.pid_ = -1;
  other.read_pipe_ = -1;
#endif
  pid_value_ = other.pid_value_;
  reaped_ = other.reaped_;
  other.reaped_ = true;
}

ChildProcess& ChildProcess::operator=(ChildProcess&& other) noexcept {
  if (this != &other) {
    if (running()) {
      static_cast<void>(terminate());
    }
    static_cast<void>(wait());
#if defined(_WIN32)
    if (read_pipe_ != nullptr) {
      CloseHandle(static_cast<HANDLE>(read_pipe_));
    }
    process_ = other.process_;
    thread_ = other.thread_;
    read_pipe_ = other.read_pipe_;
    other.process_ = nullptr;
    other.thread_ = nullptr;
    other.read_pipe_ = nullptr;
#else
    if (read_pipe_ >= 0) {
      ::close(read_pipe_);
    }
    pid_ = other.pid_;
    read_pipe_ = other.read_pipe_;
    other.pid_ = -1;
    other.read_pipe_ = -1;
#endif
    pid_value_ = other.pid_value_;
    reaped_ = other.reaped_;
    other.reaped_ = true;
  }
  return *this;
}

Result<ChildProcess> ChildProcess::start(const std::string& command_line,
                                         const std::string& working_directory) {
  ChildProcess child;
#if defined(_WIN32)
  auto wide_command = to_wide(command_line);
  if (!wide_command.has_value()) {
    return wide_command.error();
  }
  auto wide_directory = to_wide(working_directory);
  if (!wide_directory.has_value()) {
    return wide_directory.error();
  }
  std::vector<wchar_t> mutable_command(wide_command.value().begin(), wide_command.value().end());
  mutable_command.push_back(L'\0');

  STARTUPINFOW startup{};
  startup.cb = sizeof(startup);
  PROCESS_INFORMATION information{};
  const BOOL created = CreateProcessW(
      nullptr, mutable_command.data(), nullptr, nullptr, FALSE, CREATE_NO_WINDOW, nullptr,
      wide_directory.value().empty() ? nullptr : wide_directory.value().c_str(), &startup,
      &information);
  if (created == FALSE) {
    return Error(ErrorCode::IoError, "cannot start the child process")
        .with_detail("win32-error=" + std::to_string(GetLastError()));
  }
  child.process_ = information.hProcess;
  child.thread_ = information.hThread;
  child.pid_value_ = information.dwProcessId;
  child.reaped_ = false;
  return child;
#else
  const pid_t pid = ::fork();
  if (pid < 0) {
    return Error(ErrorCode::IoError, "cannot fork the child process");
  }
  if (pid == 0) {
    if (!working_directory.empty()) {
      if (::chdir(working_directory.c_str()) != 0) {
        ::_exit(126);
      }
    }
    std::vector<std::string> parts;
    std::string current;
    bool quoted = false;
    for (const char ch : command_line) {
      if (ch == '"') {
        quoted = !quoted;
        continue;
      }
      if (ch == ' ' && !quoted) {
        if (!current.empty()) {
          parts.push_back(current);
          current.clear();
        }
        continue;
      }
      current.push_back(ch);
    }
    if (!current.empty()) {
      parts.push_back(current);
    }
    std::vector<char*> argv;
    for (std::string& part : parts) {
      argv.push_back(part.data());
    }
    argv.push_back(nullptr);
    if (argv.empty() || argv[0] == nullptr) {
      ::_exit(127);
    }
    ::execvp(argv[0], argv.data());
    ::_exit(127);
  }
  child.pid_ = pid;
  child.pid_value_ = static_cast<unsigned long>(pid);
  child.reaped_ = false;
  return child;
#endif
}

Result<ChildProcess> ChildProcess::start_captured(const std::string& command_line,
                                                     const std::string& working_directory) {
#if defined(_WIN32)
  ChildProcess child;
  auto wide_command = to_wide(command_line);
  if (!wide_command.has_value()) {
    return wide_command.error();
  }
  auto wide_directory = to_wide(working_directory);
  if (!wide_directory.has_value()) {
    return wide_directory.error();
  }
  SECURITY_ATTRIBUTES attributes{};
  attributes.nLength = sizeof(attributes);
  attributes.bInheritHandle = TRUE;
  HANDLE read_end = nullptr;
  HANDLE write_end = nullptr;
  if (CreatePipe(&read_end, &write_end, &attributes, 0) == FALSE) {
    return Error(ErrorCode::IoError, "cannot create the capture pipe");
  }
  if (SetHandleInformation(read_end, HANDLE_FLAG_INHERIT, 0) == FALSE) {
    CloseHandle(read_end);
    CloseHandle(write_end);
    return Error(ErrorCode::IoError, "cannot mark the read end private");
  }
  std::vector<wchar_t> mutable_command(wide_command.value().begin(), wide_command.value().end());
  mutable_command.push_back(L'\0');
  STARTUPINFOW startup{};
  startup.cb = sizeof(startup);
  startup.dwFlags = STARTF_USESTDHANDLES;
  startup.hStdOutput = write_end;
  startup.hStdError = write_end;
  startup.hStdInput = nullptr;
  PROCESS_INFORMATION information{};
  const BOOL created = CreateProcessW(
      nullptr, mutable_command.data(), nullptr, nullptr, TRUE, CREATE_NO_WINDOW, nullptr,
      wide_directory.value().empty() ? nullptr : wide_directory.value().c_str(), &startup,
      &information);
  CloseHandle(write_end);
  if (created == FALSE) {
    CloseHandle(read_end);
    return Error(ErrorCode::IoError, "cannot start the child process")
        .with_detail("win32-error=" + std::to_string(GetLastError()));
  }
  child.process_ = information.hProcess;
  child.thread_ = information.hThread;
  child.read_pipe_ = read_end;
  child.pid_value_ = information.dwProcessId;
  child.reaped_ = false;
  return child;
#else
  ChildProcess child;
  int descriptors[2] = {-1, -1};
  if (::pipe(descriptors) != 0) {
    return Error(ErrorCode::IoError, "cannot create the capture pipe");
  }
  const pid_t pid = ::fork();
  if (pid < 0) {
    ::close(descriptors[0]);
    ::close(descriptors[1]);
    return Error(ErrorCode::IoError, "cannot fork the child process");
  }
  if (pid == 0) {
    ::close(descriptors[0]);
    ::dup2(descriptors[1], STDOUT_FILENO);
    ::dup2(descriptors[1], STDERR_FILENO);
    ::close(descriptors[1]);
    static_cast<void>(working_directory);
    ::execl("/bin/sh", "sh", "-c", command_line.c_str(), static_cast<char*>(nullptr));
    ::_exit(127);
  }
  ::close(descriptors[1]);
  child.pid_ = pid;
  child.read_pipe_ = descriptors[0];
  child.pid_value_ = static_cast<unsigned long>(pid);
  child.reaped_ = false;
  return child;
#endif
}

Result<std::string> ChildProcess::read_output() {
  std::string out;
#if defined(_WIN32)
  if (read_pipe_ == nullptr) {
    return Error(ErrorCode::InvalidState, "this child was not started with a captured pipe");
  }
  char buffer[4096];
  while (true) {
    DWORD read = 0;
    if (ReadFile(static_cast<HANDLE>(read_pipe_), buffer, sizeof(buffer), &read, nullptr) == FALSE) {
      break;
    }
    if (read == 0) {
      break;
    }
    out.append(buffer, read);
  }
  CloseHandle(static_cast<HANDLE>(read_pipe_));
  read_pipe_ = nullptr;
  return out;
#else
  if (read_pipe_ < 0) {
    return Error(ErrorCode::InvalidState, "this child was not started with a captured pipe");
  }
  char buffer[4096];
  while (true) {
    const ssize_t read = ::read(read_pipe_, buffer, sizeof(buffer));
    if (read <= 0) {
      break;
    }
    out.append(buffer, static_cast<std::size_t>(read));
  }
  ::close(read_pipe_);
  read_pipe_ = -1;
  return out;
#endif
}

bool ChildProcess::started() const noexcept {
#if defined(_WIN32)
  return process_ != nullptr;
#else
  return pid_ > 0;
#endif
}

bool ChildProcess::running() const noexcept {
  if (!started() || reaped_) {
    return false;
  }
#if defined(_WIN32)
  return WaitForSingleObject(static_cast<HANDLE>(process_), 0) == WAIT_TIMEOUT;
#else
  int status = 0;
  const pid_t result = ::waitpid(static_cast<pid_t>(pid_), &status, WNOHANG);
  return result == 0;
#endif
}

Result<int> ChildProcess::wait() {
  if (!started() || reaped_) {
    return reaped_ ? 0 : -1;
  }
#if defined(_WIN32)
  const DWORD waited = WaitForSingleObject(static_cast<HANDLE>(process_), INFINITE);
  if (waited != WAIT_OBJECT_0) {
    return Error(ErrorCode::IoError, "waiting for the child process failed");
  }
  DWORD code = 0;
  if (GetExitCodeProcess(static_cast<HANDLE>(process_), &code) == FALSE) {
    return Error(ErrorCode::IoError, "cannot read the child process exit code");
  }
  if (thread_ != nullptr) {
    CloseHandle(static_cast<HANDLE>(thread_));
    thread_ = nullptr;
  }
  CloseHandle(static_cast<HANDLE>(process_));
  process_ = nullptr;
  reaped_ = true;
  return static_cast<int>(code);
#else
  int status = 0;
  if (::waitpid(static_cast<pid_t>(pid_), &status, 0) < 0) {
    return Error(ErrorCode::IoError, "waiting for the child process failed");
  }
  reaped_ = true;
  if (WIFEXITED(status)) {
    return WEXITSTATUS(status);
  }
  return 128 + (WIFSIGNALED(status) ? WTERMSIG(status) : 0);
#endif
}

Result<void> ChildProcess::terminate() {
  if (!started() || reaped_) {
    return dccp::facility_placement_policy::success;
  }
#if defined(_WIN32)
  if (TerminateProcess(static_cast<HANDLE>(process_), 3) == FALSE) {
    return Error(ErrorCode::IoError, "cannot terminate the child process")
        .with_detail("win32-error=" + std::to_string(GetLastError()));
  }
  return dccp::facility_placement_policy::success;
#else
  if (::kill(static_cast<pid_t>(pid_), SIGKILL) != 0) {
    return Error(ErrorCode::IoError, "cannot terminate the child process");
  }
  return dccp::facility_placement_policy::success;
#endif
}

unsigned long ChildProcess::pid() const noexcept { return pid_value_; }

}  // namespace fptest
