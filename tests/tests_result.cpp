// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs.

#include <array>
#include <string>
#include <vector>

#include "test_framework.hpp"

#include "dccp/facility_placement_policy/limits.hpp"
#include "dccp/facility_placement_policy/records.hpp"
#include "dccp/facility_placement_policy/version.hpp"

namespace {

using namespace dccp::facility_placement_policy;

constexpr ErrorCode kAllCodes[] = {
#define DCCP_FACILITY_PLACEMENT_POLICY_CODE_ENTRY(name, text, category) ErrorCode::name,
    DCCP_FACILITY_PLACEMENT_POLICY_ERROR_CODES(DCCP_FACILITY_PLACEMENT_POLICY_CODE_ENTRY)
#undef DCCP_FACILITY_PLACEMENT_POLICY_CODE_ENTRY
};

}  // namespace

FPT_TEST(result, every_code_has_a_stable_name_and_category) {
  std::vector<std::string> names;
  for (const ErrorCode code : kAllCodes) {
    const std::string_view name = error_code_name(code);
    FPT_CHECK(!name.empty());
    FPT_CHECK(name != std::string_view("UNKNOWN"));
    for (const char ch : name) {
      const bool allowed = (ch >= 'A' && ch <= 'Z') || (ch >= '0' && ch <= '9') || ch == '_';
      FPT_CHECK(allowed);
    }
    names.emplace_back(name);
    const ErrorCategory category = error_category(code);
    FPT_CHECK(category != ErrorCategory::Internal || code == ErrorCode::InternalError);
    FPT_CHECK(!error_category_name(category).empty());
  }

  // Names are the machine-readable contract, so they may not collide.
  for (std::size_t index = 0; index < names.size(); ++index) {
    for (std::size_t other = index + 1; other < names.size(); ++other) {
      FPT_CHECK_NE(names[index], names[other]);
    }
  }
}

FPT_TEST(result, the_first_code_is_ok_and_means_success) {
  FPT_CHECK_EQ(error_code_name(ErrorCode::Ok), std::string_view("OK"));
  FPT_CHECK(error_category(ErrorCode::Ok) == ErrorCategory::Ok);
  FPT_CHECK_EQ(error_category_name(ErrorCategory::Ok), std::string_view("OK"));
}

FPT_TEST(result, an_error_carries_code_message_subject_and_detail) {
  const Error error = Error(ErrorCode::MalformedIdentifier, "bad identity")
                          .with_subject("a b")
                          .with_detail("length=3");
  FPT_CHECK(error.code() == ErrorCode::MalformedIdentifier);
  FPT_CHECK(error.category() == ErrorCategory::Argument);
  FPT_CHECK_EQ(error.code_name(), std::string_view("MALFORMED_IDENTIFIER"));
  FPT_CHECK_EQ(error.message(), std::string("bad identity"));
  FPT_CHECK_EQ(error.subject(), std::string("a b"));
  FPT_CHECK_EQ(error.detail(), std::string("length=3"));
  FPT_CHECK_EQ(error.to_string(),
               std::string("MALFORMED_IDENTIFIER: bad identity [subject=a b] [detail=length=3]"));
}

FPT_TEST(result, to_string_omits_empty_optional_parts) {
  const Error bare(ErrorCode::NotFound, "nothing here");
  FPT_CHECK_EQ(bare.to_string(), std::string("NOT_FOUND: nothing here"));
}

FPT_TEST(result, result_carries_either_a_value_or_an_error) {
  const Result<int> value = 7;
  FPT_REQUIRE(value.has_value());
  FPT_CHECK_EQ(value.value(), 7);
  FPT_CHECK_EQ(*value, 7);

  const Result<int> failure = Error(ErrorCode::InvalidArgument, "no");
  FPT_REQUIRE(!failure.has_value());
  FPT_CHECK(failure.error().code() == ErrorCode::InvalidArgument);
  FPT_CHECK_EQ(failure.value_or(3), 3);
}

FPT_TEST(result, a_void_result_is_never_success_by_default) {
  const Result<void> ok = success;
  FPT_REQUIRE(ok.has_value());
  const Result<void> bad = Error(ErrorCode::InternalError, "defect");
  FPT_REQUIRE(!bad.has_value());
  FPT_CHECK(bad.error().code() == ErrorCode::InternalError);
}

FPT_TEST(result, the_compiled_version_matches_the_build_configuration) {
  FPT_CHECK_EQ(std::string(version_string()), std::string(FACILITY_PLACEMENT_POLICY_CMAKE_VERSION));
  FPT_CHECK_EQ(version_major(), 1);
  FPT_CHECK_EQ(std::string(kVersionString), std::string("1.0.0"));
}

FPT_TEST(result, the_limits_are_ordered_and_positive) {
  FPT_CHECK(kMaxIdentifierBytes > 0);
  FPT_CHECK(kMaxTextBytes >= kMaxIdentifierBytes);
  FPT_CHECK(kMaxDocumentBytes > kMaxTextBytes);
  FPT_CHECK(kMaxRecordBytes > 0);
  FPT_CHECK(kMaxRulesPerPolicy > 0);
  FPT_CHECK(kMaxConstraintsPerRule > 0);
  FPT_CHECK(kMaxCandidatesPerRequest > 0);
  FPT_CHECK(kMaxOverrideUses > 0);
  FPT_CHECK(kMaxRetainedPolicyRevisions > 1);
  FPT_CHECK(kMaxViolationsPerVerdict > 0);
  FPT_CHECK(kMaxUsageRecords > 0);
  FPT_CHECK(kMaxEvaluationRecords > 0);
  // A framed record has a fixed overhead, so the frame is always larger.
  FPT_CHECK(kRecordFrameOverhead == kRecordHeaderBytes + kRecordTrailerBytes);
  FPT_CHECK(kRecordFrameOverhead < kMaxRecordBytes);
}

FPT_TEST(result, the_record_magics_are_distinct_eight_byte_ascii_tokens) {
  const std::array<std::uint64_t, 5> magics = {kManifestMagic, kPolicyRecordMagic,
                                               kLedgerRecordMagic, kGrantRecordMagic,
                                               kEvaluationRecordMagic};
  for (std::size_t index = 0; index < magics.size(); ++index) {
    for (std::size_t other = index + 1; other < magics.size(); ++other) {
      FPT_CHECK_NE(magics[index], magics[other]);
    }
    // Little-endian on disk, so the low byte is the first character.
    FPT_CHECK_EQ(static_cast<char>(magics[index] & 0xFFu), 'F');
  }
}
