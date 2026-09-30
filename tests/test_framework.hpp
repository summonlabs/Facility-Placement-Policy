// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs.
//
// Minimal deterministic test framework.
//
// The framework has no external dependencies and no timing logic: every test
// runs to completion. Property tests take an explicit seed so a failing case can
// be reproduced exactly, and the seed is printed on failure.

#ifndef DCCP_FACILITY_PLACEMENT_POLICY_TESTS_TEST_FRAMEWORK_HPP
#define DCCP_FACILITY_PLACEMENT_POLICY_TESTS_TEST_FRAMEWORK_HPP

#include <cstdint>
#include <ostream>
#include <sstream>
#include <string>
#include <string_view>
#include <system_error>
#include <type_traits>
#include <utility>
#include <vector>

#include "dccp/facility_placement_policy/result.hpp"

namespace fptest {

using dccp::facility_placement_policy::Error;
using dccp::facility_placement_policy::ErrorCode;
using dccp::facility_placement_policy::Result;
using dccp::facility_placement_policy::Success;
using dccp::facility_placement_policy::success;

struct TestCase {
  std::string suite;
  std::string name;
  void (*function)();
};

std::vector<TestCase>& registry();
int register_test(const char* suite, const char* name, void (*function)());

/// Thrown by FPT_REQUIRE to abandon the rest of a test body.
struct TestAborted {};

void fail(const char* file, int line, const std::string& message);
void note(const std::string& message);

/// Returns its argument unchanged.
///
/// The check macros route every condition through this call so that a
/// deliberately constant condition — asserting a compile-time bound, for example
/// — does not trip the compiler's "conditional expression is constant"
/// diagnostic, which a strict warning policy turns into an error.
bool truthy(bool value) noexcept;

/// Runs the suites named on the command line, or all of them. Returns the
/// process exit status.
int run_all(const std::vector<std::string>& arguments);

/// Seed used by property tests in the current run.
std::uint64_t current_seed();

/// Sets the context printed alongside a failure, so a property failure names the
/// seed and the iteration that produced it.
void set_failure_context(const std::string& context);

struct Registrar {
  Registrar(const char* suite, const char* name, void (*function)()) {
    register_test(suite, name, function);
  }
};

}  // namespace fptest

#define FPT_TEST(suite_name, case_name)                                                      \
  static void suite_name##_##case_name##_body();                                             \
  static const ::fptest::Registrar suite_name##_##case_name##_registrar(                     \
      #suite_name, #case_name, &suite_name##_##case_name##_body);                            \
  static void suite_name##_##case_name##_body()

#define FPT_FAIL(message) ::fptest::fail(__FILE__, __LINE__, (message))

#define FPT_CHECK(condition)                                                     \
  do {                                                                           \
    if (!::fptest::truthy(static_cast<bool>(condition))) {                        \
      FPT_FAIL(std::string("CHECK failed: ") + #condition);                       \
    }                                                                            \
  } while (false)

#define FPT_REQUIRE(condition)                                                   \
  do {                                                                           \
    if (!::fptest::truthy(static_cast<bool>(condition))) {                        \
      FPT_FAIL(std::string("REQUIRE failed: ") + #condition);                     \
      throw ::fptest::TestAborted{};                                              \
    }                                                                            \
  } while (false)

#define FPT_CHECK_EQ(actual, expected)                                                           \
  do {                                                                                           \
    const auto fptest_actual = (actual);                                                         \
    const auto fptest_expected = (expected);                                                     \
    if (!::fptest::truthy(fptest_actual == fptest_expected)) {                                    \
      std::ostringstream fptest_stream;                                                          \
      fptest_stream << "CHECK_EQ failed: " #actual " == " #expected " (actual="                   \
                    << ::fptest::render(fptest_actual)                                           \
                    << ", expected=" << ::fptest::render(fptest_expected) << ")";                 \
      FPT_FAIL(fptest_stream.str());                                                             \
    }                                                                                            \
  } while (false)

#define FPT_REQUIRE_EQ(actual, expected)                                                         \
  do {                                                                                           \
    const auto fptest_actual = (actual);                                                         \
    const auto fptest_expected = (expected);                                                     \
    if (!::fptest::truthy(fptest_actual == fptest_expected)) {                                    \
      std::ostringstream fptest_stream;                                                          \
      fptest_stream << "REQUIRE_EQ failed: " #actual " == " #expected " (actual="                 \
                    << ::fptest::render(fptest_actual)                                           \
                    << ", expected=" << ::fptest::render(fptest_expected) << ")";                 \
      FPT_FAIL(fptest_stream.str());                                                             \
      throw ::fptest::TestAborted{};                                                             \
    }                                                                                            \
  } while (false)

#define FPT_CHECK_NE(actual, expected)                                                           \
  do {                                                                                           \
    const auto fptest_actual = (actual);                                                         \
    const auto fptest_expected = (expected);                                                     \
    if (::fptest::truthy(fptest_actual == fptest_expected)) {                                     \
      FPT_FAIL(std::string("CHECK_NE failed: " #actual " != " #expected));                        \
    }                                                                                            \
  } while (false)

/// Asserts that a Result failed with a specific stable error code.
#define FPT_CHECK_ERROR(expression, expected_code)                                               \
  do {                                                                                           \
    const auto& fptest_result = (expression);                                                    \
    if (fptest_result.has_value()) {                                                             \
      FPT_FAIL(std::string("expected failure " #expected_code " but the call succeeded: "        \
                           #expression));                                                        \
    } else if (fptest_result.error().code() != (expected_code)) {                                \
      FPT_FAIL(std::string("expected ") +                                                        \
               std::string(::dccp::facility_placement_policy::error_code_name(expected_code)) +  \
               " but got " + fptest_result.error().to_string());                                 \
    }                                                                                            \
  } while (false)

#define FPT_CHECK_OK(expression)                                                                 \
  do {                                                                                           \
    const auto& fptest_result = (expression);                                                    \
    if (!fptest_result.has_value()) {                                                            \
      FPT_FAIL(std::string("expected success but got ") + fptest_result.error().to_string());     \
    }                                                                                            \
  } while (false)

#define FPT_REQUIRE_OK(expression)                                                               \
  do {                                                                                           \
    const auto& fptest_result = (expression);                                                    \
    if (!fptest_result.has_value()) {                                                            \
      FPT_FAIL(std::string("REQUIRE_OK failed: " #expression " -> ") +                           \
               fptest_result.error().to_string());                                               \
      throw ::fptest::TestAborted{};                                                             \
    }                                                                                            \
  } while (false)

namespace fptest {

std::string render(const std::string& value);
std::string render(std::string_view value);
std::string render(const char* value);
std::string render(bool value);
std::string render(const Error& value);
std::string render(const std::error_code& value);

template <class T, class = void>
struct is_streamable : std::false_type {};

template <class T>
struct is_streamable<
    T, std::void_t<decltype(std::declval<std::ostream&>() << std::declval<const T&>())>>
    : std::true_type {};

/// Renders any value for a failure message: streamable values directly,
/// iterable values element by element, anything else as a placeholder.
template <class T>
std::string render(const T& value) {
  if constexpr (is_streamable<T>::value) {
    std::ostringstream stream;
    stream << value;
    return stream.str();
  } else if constexpr (requires { std::begin(value); std::end(value); }) {
    std::string out = "[";
    bool first = true;
    for (const auto& item : value) {
      if (!first) {
        out.append(", ");
      }
      first = false;
      out.append(render(item));
    }
    out.push_back(']');
    return out;
  } else {
    return "<value>";
  }
}

}  // namespace fptest

#endif  // DCCP_FACILITY_PLACEMENT_POLICY_TESTS_TEST_FRAMEWORK_HPP
