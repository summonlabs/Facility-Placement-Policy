// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs.
//
// Starting and killing real operating-system processes, so the multiprocess and
// crash-consistency claims are tested against real processes rather than
// simulated ones.

#ifndef DCCP_FACILITY_PLACEMENT_POLICY_TESTS_CHILD_PROCESS_HPP
#define DCCP_FACILITY_PLACEMENT_POLICY_TESTS_CHILD_PROCESS_HPP

#include <string>

#include "dccp/facility_placement_policy/result.hpp"

namespace fptest {

using dccp::facility_placement_policy::Result;

/// A child process. The destructor terminates a still-running child and reaps
/// it, so a failing test cannot leave a stray process holding a store lock.
class ChildProcess {
 public:
  ChildProcess() noexcept = default;
  ~ChildProcess();

  ChildProcess(ChildProcess&& other) noexcept;
  ChildProcess& operator=(ChildProcess&& other) noexcept;
  ChildProcess(const ChildProcess&) = delete;
  ChildProcess& operator=(const ChildProcess&) = delete;

  /// Starts a process. The command line is passed to the platform's shell-free
  /// process creation, so the first token must be an executable path.
  static Result<ChildProcess> start(const std::string& command_line,
                                    const std::string& working_directory);

  /// Starts a process with its standard output and standard error connected to a
  /// pipe this object owns. read_output() returns everything the process wrote;
  /// call it before wait() so a chatty child can never fill the pipe and block.
  static Result<ChildProcess> start_captured(const std::string& command_line,
                                             const std::string& working_directory);

  bool started() const noexcept;
  bool running() const noexcept;

  /// Waits for exit and returns the exit code.
  Result<int> wait();

  /// Everything the child wrote, read until end of file. Only meaningful for a
  /// child started with start_captured().
  Result<std::string> read_output();

  /// Terminates the process abruptly, the way a crash would: no unwinding, no
  /// destructors, no flush.
  Result<void> terminate();

  unsigned long pid() const noexcept;

 private:
#if defined(_WIN32)
  void* process_ = nullptr;
  void* thread_ = nullptr;
  void* read_pipe_ = nullptr;
#else
  long pid_ = -1;
  int read_pipe_ = -1;
#endif
  unsigned long pid_value_ = 0;
  bool reaped_ = false;
};

}  // namespace fptest

#endif  // DCCP_FACILITY_PLACEMENT_POLICY_TESTS_CHILD_PROCESS_HPP
