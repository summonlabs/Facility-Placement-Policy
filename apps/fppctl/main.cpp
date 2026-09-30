// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs.

#include <string>
#include <vector>

#include "commands.hpp"

int main(int argc, char** argv) {
  std::vector<std::string> arguments;
  arguments.reserve(static_cast<std::size_t>(argc > 0 ? argc - 1 : 0));
  for (int index = 1; index < argc; ++index) {
    arguments.emplace_back(argv[index]);
  }
  return dccp::facility_placement_policy::cli::run(arguments);
}
