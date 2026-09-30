// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs.

#ifndef DCCP_FACILITY_PLACEMENT_POLICY_APPS_FPPCTL_COMMANDS_HPP
#define DCCP_FACILITY_PLACEMENT_POLICY_APPS_FPPCTL_COMMANDS_HPP

#include <map>
#include <set>
#include <string>
#include <vector>

namespace dccp::facility_placement_policy::cli {

/// Exit codes are part of the tool's contract.
///
///   0  the command succeeded, and for an evaluation every candidate is eligible
///   1  the command line is wrong
///   2  the runtime refused: the request, policy or store state was rejected
///   3  the command succeeded and at least one candidate is ineligible
enum class ExitCode : int {
  Ok = 0,
  Usage = 1,
  Refused = 2,
  Ineligible = 3,
};

/// A parsed command line.
struct CommandLine {
  std::string command;
  std::vector<std::string> positional;
  std::map<std::string, std::string> values;
  std::set<std::string> switches;
};

/// Parses arguments after the program name. Value flags are given as
/// "--name value"; switch flags are given as "--name".
bool parse_command_line(const std::vector<std::string>& arguments,
                        const std::set<std::string>& value_flags,
                        const std::set<std::string>& switch_flags, CommandLine& out,
                        std::string& error);

/// Runs the tool. Returns the process exit status.
int run(const std::vector<std::string>& arguments);

}  // namespace dccp::facility_placement_policy::cli

#endif  // DCCP_FACILITY_PLACEMENT_POLICY_APPS_FPPCTL_COMMANDS_HPP
