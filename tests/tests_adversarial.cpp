// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs.

#include <cstdint>
#include <string>
#include <vector>

#include "test_framework.hpp"
#include "test_support.hpp"

#include "dccp/facility_placement_policy/facility_placement_policy.hpp"

namespace {

using namespace dccp::facility_placement_policy;
using namespace fptest;

std::string policy_header() {
  return "fpp-document policy\nformat 1\npolicy-id grid-a\nrevision 1\n";
}

std::string request_header() {
  return "fpp-document request\n"
         "format 1\n"
         "request-id req-1\n"
         "tenant tenant:acme\n"
         "service-class service-class:gold\n"
         "requested-at 2026-02-14T09:30:00.000000Z\n"
         "generations topology=12 failure-domain=9 tenant=4 service-class=3\n"
         "facility facility:dc1 jurisdiction=jurisdiction:eu-de\n";
}

}  // namespace

FPT_TEST(adversarial, a_document_that_exceeds_a_bound_is_refused_by_name) {
  // More rules than the limit allows.
  std::string many = policy_header();
  for (std::size_t index = 0; index <= kMaxRulesPerPolicy; ++index) {
    many.append("rule r" + std::to_string(index) +
                " {\n  require jurisdiction allow=jurisdiction:eu-de deny=\n}\n");
  }
  FPT_CHECK_ERROR(parse_policy_document(many), ErrorCode::LimitExceeded);

  // More constraints in one rule than the limit allows.
  std::string crowded = policy_header() + "rule r {\n";
  for (std::size_t index = 0; index <= kMaxConstraintsPerRule; ++index) {
    crowded.append("  require facility-attribute key=power-feed-count op=at-least value=1\n");
  }
  crowded.append("}\n");
  FPT_CHECK_ERROR(parse_policy_document(crowded), ErrorCode::LimitExceeded);

  // A single line longer than the limit.
  std::string long_line = policy_header() + "rule r {\n  description \"";
  long_line.append(kMaxLineBytes, 'a');
  long_line.append("\"\n  require jurisdiction allow=jurisdiction:eu-de deny=\n}\n");
  FPT_CHECK_ERROR(parse_policy_document(long_line), ErrorCode::LimitExceeded);
}

FPT_TEST(adversarial, hostile_text_is_refused_rather_than_normalised) {
  // Invalid UTF-8 inside a quoted value.
  std::string invalid = policy_header() + "rule r {\n  description \"";
  invalid.push_back(static_cast<char>(0xFF));
  invalid.append("\"\n  require jurisdiction allow=jurisdiction:eu-de deny=\n}\n");
  FPT_CHECK_ERROR(parse_policy_document(invalid), ErrorCode::InvalidUtf8);

  // An overlong UTF-8 encoding is not a valid description either.
  std::string overlong = policy_header() + "rule r {\n  description \"";
  overlong.push_back(static_cast<char>(0xC0));
  overlong.push_back(static_cast<char>(0x80));
  overlong.append("\"\n  require jurisdiction allow=jurisdiction:eu-de deny=\n}\n");
  FPT_CHECK_ERROR(parse_policy_document(overlong), ErrorCode::InvalidUtf8);

  // A NUL byte inside a bare token is not part of any identifier.
  std::string nul_token = policy_header() + "rule r";
  nul_token.push_back('\0');
  nul_token.append(" {\n  require jurisdiction allow=jurisdiction:eu-de deny=\n}\n");
  FPT_CHECK_ERROR(parse_policy_document(nul_token), ErrorCode::MalformedIdentifier);

  // An unterminated quoted value.
  FPT_CHECK_ERROR(parse_policy_document(policy_header() +
                                        "rule r {\n  description \"unterminated\n}\n"),
                  ErrorCode::TruncatedInput);

  // A brace where a section may not open, and a nested section.
  FPT_CHECK_ERROR(parse_policy_document(policy_header() + "rule r {\n  {\n}\n"),
                  ErrorCode::UnexpectedToken);
  FPT_CHECK_ERROR(parse_policy_document(policy_header() + "rule r {\n  rule s {\n}\n}\n"),
                  ErrorCode::UnsupportedFeature);
  FPT_CHECK_ERROR(parse_policy_document(policy_header() + "}\n"), ErrorCode::UnexpectedToken);
}

FPT_TEST(adversarial, duplicate_identities_are_never_merged_silently) {
  std::string duplicate_candidates = request_header();
  duplicate_candidates.append("candidate c1 facility=facility:dc1 rack=rack:01\n");
  duplicate_candidates.append("candidate c1 facility=facility:dc1 rack=rack:02\n");
  FPT_CHECK_ERROR(parse_request_document(duplicate_candidates), ErrorCode::CandidateDuplicateId);

  std::string duplicate_facilities = request_header();
  duplicate_facilities.append("facility facility:dc1 jurisdiction=jurisdiction:eu-fr\n");
  duplicate_facilities.append("candidate c1 facility=facility:dc1 rack=rack:01\n");
  FPT_CHECK_ERROR(parse_request_document(duplicate_facilities), ErrorCode::DuplicateField);

  std::string duplicate_attributes = request_header();
  duplicate_attributes.append("attribute facility=facility:dc1 key=power-feed-count value=1\n");
  duplicate_attributes.append("attribute facility=facility:dc1 key=power-feed-count value=2\n");
  duplicate_attributes.append("candidate c1 facility=facility:dc1 rack=rack:01\n");
  FPT_CHECK_ERROR(parse_request_document(duplicate_attributes), ErrorCode::DuplicateField);

  std::string duplicate_exposures = request_header();
  duplicate_exposures.append("candidate c1 facility=facility:dc1 rack=rack:01\n");
  duplicate_exposures.append("maintenance generation=41\n");
  duplicate_exposures.append("exposure e1 kind=planned severity=blackout scope-rack=rack:rack:01 "
                             "start=2026-02-20T00:00:00.000000Z end=2026-02-21T00:00:00.000000Z\n");
  duplicate_exposures.append("exposure e1 kind=planned severity=blackout scope-rack=rack:rack:01 "
                             "start=2026-02-20T00:00:00.000000Z end=2026-02-21T00:00:00.000000Z\n");
  FPT_CHECK_ERROR(parse_request_document(duplicate_exposures), ErrorCode::DuplicateField);

  std::string duplicate_domain_kind = request_header();
  duplicate_domain_kind.append(
      "candidate c1 facility=facility:dc1 rack=rack:01 failure-domains=power:pd-1,power:pd-2\n");
  FPT_CHECK_ERROR(parse_request_document(duplicate_domain_kind), ErrorCode::DuplicateField);
}

FPT_TEST(adversarial, a_request_that_references_what_it_does_not_describe_is_refused) {
  std::string undeclared = request_header();
  undeclared.append("candidate c1 facility=facility:dc9 rack=rack:01\n");
  FPT_CHECK_ERROR(parse_request_document(undeclared), ErrorCode::NotFound);

  std::string orphan_attribute = request_header();
  orphan_attribute.append("attribute facility=facility:dc9 key=power-feed-count value=1\n");
  orphan_attribute.append("candidate c1 facility=facility:dc1 rack=rack:01\n");
  FPT_CHECK_ERROR(parse_request_document(orphan_attribute), ErrorCode::NotFound);

  std::string empty_candidate = request_header();
  empty_candidate.append("candidate  facility=facility:dc1 rack=rack:01\n");
  FPT_CHECK_ERROR(parse_request_document(empty_candidate), ErrorCode::UnexpectedToken);
}

FPT_TEST(adversarial, counters_and_instants_are_bounded_in_documents) {
  FPT_CHECK_ERROR(parse_policy_document(policy_header() +
                                        "rule r {\n  require jurisdiction "
                                        "allow=jurisdiction:eu-de deny=\n}\n"
                                        "revision 99999999999999999999\n"),
                  ErrorCode::DuplicateField);
  FPT_CHECK_ERROR(parse_request_document(request_header() +
                                         "candidate c1 facility=facility:dc1 rack=rack:01\n"
                                         "occupancy generation=0\n"),
                  ErrorCode::InvalidArgument);
  FPT_CHECK_ERROR(parse_request_document(request_header() +
                                         "candidate c1 facility=facility:dc1 rack=rack:01\n"
                                         "occupancy generation=99999999999999999999\n"),
                  ErrorCode::NumericOverflow);
  FPT_CHECK_ERROR(parse_request_document(
                      "fpp-document request\nformat 1\nrequest-id r\ntenant t\n"
                      "service-class s\nrequested-at 2026-02-14T09:30:00+01:00\n"
                      "generations topology=1 failure-domain=1 tenant=1 service-class=1\n"),
                  ErrorCode::MalformedDocument);
}

FPT_TEST(adversarial, store_directories_are_validated_before_anything_is_created) {
  FPT_CHECK_ERROR(initialize_store("", StoreId::parse("store:main").value(),
                                   Instant::parse("2026-02-14T09:00:00.000000Z").value()),
                  ErrorCode::PathInvalid);
  FPT_CHECK_ERROR(initialize_store(std::string("bad\0name", 8),
                                   StoreId::parse("store:main").value(),
                                   Instant::parse("2026-02-14T09:00:00.000000Z").value()),
                  ErrorCode::PathInvalid);
  const char* reserved[] = {"NUL", "con", "PRN", "aux", "COM1", "lpt9", "NUL.fpp"};
  for (const char* name : reserved) {
    FPT_CHECK_ERROR(initialize_store(name, StoreId::parse("store:main").value(),
                                     Instant::parse("2026-02-14T09:00:00.000000Z").value()),
                    ErrorCode::PathInvalid);
  }
  // A relative component that would escape is refused.
  FPT_CHECK_ERROR(initialize_store(scratch_root() + "/..", StoreId::parse("store:main").value(),
                                   Instant::parse("2026-02-14T09:00:00.000000Z").value()),
                  ErrorCode::PathInvalid);
  // A trailing separator and a space are operator choices, not defects: the
  // store creates only fixed and digest-derived names inside the directory.
  const auto trailing = initialize_store(scratch_root() + "/trailing/",
                                         StoreId::parse("store:main").value(),
                                         Instant::parse("2026-02-14T09:00:00.000000Z").value());
  FPT_REQUIRE_OK(trailing);
  FPT_CHECK(file_present(scratch_root() + "/trailing/manifest.fpp"));
  FPT_CHECK_ERROR(initialize_store(scratch_root() + "/with space", StoreId{},
                                   Instant::parse("2026-02-14T09:00:00.000000Z").value()),
                  ErrorCode::MissingField);
}

FPT_TEST(adversarial, identities_that_look_like_paths_never_reach_the_filesystem) {
  // The identifier grammar is what keeps user text out of file names: every
  // store file name is either fixed or derived from a digest.
  // A device name is a legal identifier; it is the *directory* that must not be
  // one, which the store checks separately.
  const char* hostile[] = {"../escape", "..\\escape", "C:/absolute", "a/b", "a\\b", "a b",
                           "a\nb"};
  for (const char* text : hostile) {
    FPT_CHECK_ERROR(StoreId::parse(text), ErrorCode::MalformedIdentifier);
    FPT_CHECK_ERROR(TenantId::parse(text), ErrorCode::MalformedIdentifier);
    FPT_CHECK_ERROR(FacilityId::parse(text), ErrorCode::MalformedIdentifier);
  }

  auto directory = fresh_directory("adversarial-names");
  FPT_REQUIRE_OK(directory);
  const auto created = initialize_store(directory.value(), StoreId::parse("store:main").value(),
                                        Instant::parse("2026-02-14T09:00:00.000000Z").value());
  FPT_REQUIRE_OK(created);
  // Nothing outside the store directory was created by initialisation.
  FPT_CHECK(!file_present(scratch_root() + "/manifest.fpp"));
  FPT_CHECK(file_present(directory.value() + "/manifest.fpp"));
}

FPT_TEST(adversarial, a_store_directory_that_is_a_file_is_not_a_store) {
  auto directory = fresh_directory("adversarial-not-a-directory");
  FPT_REQUIRE_OK(directory);
  const std::string path = directory.value() + "/file";
  FPT_REQUIRE_OK(write_text_file(path, "not a store"));
  FPT_CHECK_ERROR(Store::open(path, StoreOpenMode::ReadOnly), ErrorCode::StoreNotFound);
  FPT_CHECK_ERROR(initialize_store(path, StoreId::parse("store:main").value(),
                                   Instant::parse("2026-02-14T09:00:00.000000Z").value()),
                  ErrorCode::PathInvalid);
}

FPT_TEST(adversarial, evaluating_a_candidate_that_is_not_in_the_request_is_refused) {
  auto policy = parse_policy_document(policy_header() +
                                      "rule r {\n  require jurisdiction "
                                      "allow=jurisdiction:eu-de deny=\n}\n");
  FPT_REQUIRE_OK(policy);
  auto snapshot = make_policy_snapshot(std::move(policy.value()),
                                       AuthorityEpoch::from_value(1).value(),
                                       StoreSequence::from_value(1).value(), TopologyGeneration{},
                                       FailureDomainGeneration{});
  FPT_REQUIRE_OK(snapshot);
  EvaluationInput input;
  input.request = parse_request_document(request_header() +
                                         "candidate c1 facility=facility:dc1 rack=rack:01\n")
                      .value();
  FPT_CHECK_ERROR(evaluate_candidate(snapshot.value(), input,
                                     CandidateId::parse("missing").value()),
                  ErrorCode::NotFound);
}

FPT_TEST(adversarial, a_request_with_no_candidates_is_refused) {
  FPT_CHECK_ERROR(parse_request_document(request_header()), ErrorCode::EmptyRequest);
}

FPT_TEST(adversarial, control_characters_inside_quoted_text_survive_or_are_refused_cleanly) {
  // A tab is a legal escape target and a legal member of a description.
  std::string with_tab = policy_header() +
                         "rule r {\n  description \"a\\tb\"\n  require jurisdiction "
                         "allow=jurisdiction:eu-de deny=\n}\n";
  auto parsed = parse_policy_document(with_tab);
  FPT_REQUIRE_OK(parsed);
  FPT_CHECK_EQ(parsed.value().rules.front().description, std::string("a\tb"));

  // A newline written as an escape inside a description is a control byte and
  // therefore canonical, while a printable byte written as an escape is not.
  std::string control_escape = policy_header() +
                               "rule r {\n  description \"a\\x0A b\"\n  require jurisdiction "
                               "allow=jurisdiction:eu-de deny=\n}\n";
  auto escaped = parse_policy_document(control_escape);
  FPT_REQUIRE_OK(escaped);
  FPT_CHECK_EQ(escaped.value().rules.front().description, std::string("a\n b"));

  std::string bad_escape = policy_header() +
                           "rule r {\n  description \"a\\x41 b\"\n  require jurisdiction "
                           "allow=jurisdiction:eu-de deny=\n}\n";
  FPT_CHECK_ERROR(parse_policy_document(bad_escape), ErrorCode::MalformedDocument);
}
