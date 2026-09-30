// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs.

#include "test_framework.hpp"

#include <algorithm>
#include <cstdio>
#include <cstdlib>
#include <exception>
#include <string>
#include <vector>

#include "test_support.hpp"

namespace fptest {
namespace {

std::string g_failure_context;
std::size_t g_failures = 0;
std::size_t g_checks = 0;

bool suite_selected(const std::vector<std::string>& suites, const std::string& suite) {
  if (suites.empty()) {
    return true;
  }
  return std::find(suites.begin(), suites.end(), suite) != suites.end();
}

void write_line(const std::string& text) {
  std::fwrite(text.data(), 1, text.size(), stdout);
  std::fputc('\n', stdout);
  std::fflush(stdout);
}

void write_error_line(const std::string& text) {
  std::fwrite(text.data(), 1, text.size(), stderr);
  std::fputc('\n', stderr);
  std::fflush(stderr);
}

}  // namespace

std::vector<TestCase>& registry() {
  static std::vector<TestCase> tests;
  return tests;
}

int register_test(const char* suite, const char* name, void (*function)()) {
  registry().push_back(TestCase{suite, name, function});
  return 0;
}

void fail(const char* file, int line, const std::string& message) {
  ++g_failures;
  ++g_checks;
  std::string text = "FAIL ";
  text.append(file);
  text.push_back(':');
  text.append(std::to_string(line));
  text.append(": ");
  text.append(message);
  if (!g_failure_context.empty()) {
    text.append(" [context=");
    text.append(g_failure_context);
    text.push_back(']');
  }
  write_error_line(text);
}

void note(const std::string& message) { write_line("note: " + message); }

bool truthy(bool value) noexcept { return value; }

std::string render(const std::string& value) { return value; }
std::string render(std::string_view value) { return std::string(value); }
std::string render(const char* value) { return value == nullptr ? "<null>" : std::string(value); }
std::string render(bool value) { return value ? "true" : "false"; }
std::string render(const Error& value) { return value.to_string(); }
std::string render(const std::error_code& value) { return value.message(); }

std::uint64_t current_seed() { return 0x5eed1234ULL; }

void set_failure_context(const std::string& context) { g_failure_context = context; }

int run_all(const std::vector<std::string>& arguments) {
  std::vector<std::string> suites;
  bool list_only = false;
  for (std::size_t index = 0; index < arguments.size(); ++index) {
    const std::string& argument = arguments[index];
    if (argument == "--suite") {
      if (index + 1 >= arguments.size()) {
        write_error_line("--suite needs a name");
        return 2;
      }
      suites.push_back(arguments[++index]);
      continue;
    }
    if (argument == "--list") {
      list_only = true;
      continue;
    }
    write_error_line("unknown argument: " + argument);
    return 2;
  }

  // A suite name that matches nothing is a defect in the build definition, not a
  // reason to run fewer tests silently.
  for (const std::string& suite : suites) {
    const bool known = std::any_of(registry().begin(), registry().end(),
                                   [&suite](const TestCase& test) { return test.suite == suite; });
    if (!known) {
      write_error_line("no such suite: " + suite);
      return 2;
    }
  }

  if (list_only) {
    for (const TestCase& test : registry()) {
      write_line(test.suite + "." + test.name);
    }
    return 0;
  }

  const auto cleanup = make_scratch_root();
  if (!cleanup.has_value()) {
    write_error_line("cannot prepare the scratch root: " + cleanup.error().to_string());
    return 2;
  }

  std::size_t executed = 0;
  for (const TestCase& test : registry()) {
    if (!suite_selected(suites, test.suite)) {
      continue;
    }
    ++executed;
    const std::size_t failures_before = g_failures;
    g_failure_context.clear();
    try {
      test.function();
    } catch (const TestAborted&) {
      // The failure was already reported.
    } catch (const std::exception& exception) {
      fail(__FILE__, __LINE__,
           "test threw an unexpected exception: " + std::string(exception.what()));
    } catch (...) {
      fail(__FILE__, __LINE__, "test threw a non-standard exception");
    }
    if (g_failures == failures_before) {
      write_line("ok   " + test.suite + "." + test.name);
    } else {
      write_line("FAIL " + test.suite + "." + test.name);
    }
  }

  if (executed == 0) {
    write_error_line("no tests ran");
    return 2;
  }

  std::string summary = std::to_string(executed) + " test(s) ran, " + std::to_string(g_failures) +
                        " failure(s)";
  write_line(summary);
  return g_failures == 0 ? 0 : 1;
}

}  // namespace fptest

int main(int argc, char** argv) {
  std::vector<std::string> arguments;
  for (int index = 1; index < argc; ++index) {
    arguments.emplace_back(argv[index]);
  }
  return fptest::run_all(arguments);
}
