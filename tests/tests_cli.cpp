// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs.

#include <string>
#include <vector>

#include "child_process.hpp"
#include "test_framework.hpp"
#include "test_support.hpp"

namespace {

using namespace dccp::facility_placement_policy;
using namespace fptest;

struct CliRun {
  int exit_code = -1;
  std::string output;
};

Result<CliRun> run_cli(const std::vector<std::string>& arguments) {
  if (cli_path().empty()) {
    return Error(ErrorCode::NotFound, "the command line tool was not built");
  }
  std::string command = quote_argument(cli_path());
  for (const std::string& argument : arguments) {
    command.push_back(' ');
    command.append(quote_argument(argument));
  }
  auto child = fptest::ChildProcess::start_captured(command, fptest::scratch_root());
  if (!child.has_value()) {
    return child.error();
  }
  auto output = child.value().read_output();
  if (!output.has_value()) {
    return output.error();
  }
  auto exit_code = child.value().wait();
  if (!exit_code.has_value()) {
    return exit_code.error();
  }
  CliRun run;
  run.exit_code = exit_code.value();
  run.output = fptest::normalize_newlines(output.value());
  return run;
}

const char* const kPolicy =
    "fpp-document policy\n"
    "format 1\n"
    "policy-id grid-a\n"
    "revision 1\n"
    "rule spread {\n"
    "  require anti-affinity scope=tenant dimension=rack max-shared=0\n"
    "}\n"
    "rule legal {\n"
    "  require jurisdiction allow=jurisdiction:eu-de deny=\n"
    "}\n"
    "envelope emergency {\n"
    "  scope facilities=facility:dc1\n"
    "  allow-kinds anti-affinity\n"
    "  principals principal:sre\n"
    "  max-uses 1\n"
    "  grant-validity 15m\n"
    "}\n";

const char* const kRequest =
    "fpp-document request\n"
    "format 1\n"
    "request-id req-1\n"
    "tenant tenant:acme\n"
    "service-class service-class:gold\n"
    "requested-at 2026-02-14T09:30:00.000000Z\n"
    "generations topology=12 failure-domain=9 tenant=4 service-class=3\n"
    "facility facility:dc1 jurisdiction=jurisdiction:eu-de\n"
    "candidate c1 facility=facility:dc1 rack=rack:07\n"
    "occupancy generation=77\n"
    "placed p1 tenant=tenant:acme service-class=service-class:gold facility=facility:dc1 "
    "rack=rack:07\n"
    "maintenance generation=41\n";

/// A store with revision 1 active, plus the two document files beside it.
Result<std::string> cli_scenario(const std::string& name) {
  auto directory = fptest::fresh_directory(name);
  if (!directory.has_value()) {
    return directory.error();
  }
  const auto policy_file = fptest::write_text_file(directory.value() + "/policy.txt", kPolicy);
  if (!policy_file.has_value()) {
    return policy_file.error();
  }
  const auto request_file = fptest::write_text_file(directory.value() + "/request.txt", kRequest);
  if (!request_file.has_value()) {
    return request_file.error();
  }
  auto initialized = run_cli({"store", "init", directory.value() + "/store", "--store-id",
                              "store:main", "--at", "2026-02-14T09:00:00.000000Z"});
  if (!initialized.has_value()) {
    return initialized.error();
  }
  if (initialized.value().exit_code != 0) {
    return Error(ErrorCode::InternalError, "store init failed")
        .with_detail(initialized.value().output);
  }
  auto activated = run_cli({"policy", "activate", directory.value() + "/store",
                            directory.value() + "/policy.txt", "--at",
                            "2026-02-14T09:05:00.000000Z"});
  if (!activated.has_value()) {
    return activated.error();
  }
  if (activated.value().exit_code != 0) {
    return Error(ErrorCode::InternalError, "policy activate failed")
        .with_detail(activated.value().output);
  }
  return directory.value();
}

}  // namespace

FPT_TEST(cli, the_tool_reports_itself_and_its_self_test) {
  auto self_test = run_cli({"selftest"});
  FPT_REQUIRE_OK(self_test);
  FPT_CHECK_EQ(self_test.value().exit_code, 0);
  FPT_CHECK(self_test.value().output.find("selftest ok") != std::string::npos);

  auto version = run_cli({"version"});
  FPT_REQUIRE_OK(version);
  FPT_CHECK_EQ(version.value().exit_code, 0);
  FPT_CHECK(version.value().output.find("1.0.0") != std::string::npos);

  auto format = run_cli({"format"});
  FPT_REQUIRE_OK(format);
  FPT_CHECK_EQ(format.value().exit_code, 0);
  FPT_CHECK(format.value().output.find("manifest.fpp") != std::string::npos);

  auto help = run_cli({"help"});
  FPT_REQUIRE_OK(help);
  FPT_CHECK_EQ(help.value().exit_code, 0);
  FPT_CHECK(help.value().output.find("fppctl") != std::string::npos);

  auto unknown = run_cli({"nonsense"});
  FPT_REQUIRE_OK(unknown);
  FPT_CHECK_EQ(unknown.value().exit_code, 1);
  FPT_CHECK(unknown.value().output.find("unknown command") != std::string::npos);
}

FPT_TEST(cli, policy_documents_are_validated_canonicalised_and_digested) {
  auto directory = fptest::fresh_directory("cli-policy");
  FPT_REQUIRE_OK(directory);
  FPT_REQUIRE_OK(fptest::write_text_file(directory.value() + "/policy.txt", kPolicy));

  auto validate = run_cli({"policy", "validate", directory.value() + "/policy.txt"});
  FPT_REQUIRE_OK(validate);
  FPT_CHECK_EQ(validate.value().exit_code, 0);
  FPT_CHECK(validate.value().output.find("valid policy grid-a revision 1") != std::string::npos);

  auto canonical = run_cli({"policy", "canonicalize", directory.value() + "/policy.txt"});
  FPT_REQUIRE_OK(canonical);
  FPT_CHECK_EQ(canonical.value().exit_code, 0);
  FPT_CHECK_EQ(canonical.value().output.rfind("fpp-document policy", 0), std::size_t(0));
  FPT_REQUIRE_OK(fptest::write_text_file(directory.value() + "/canonical.txt",
                                         canonical.value().output));

  // The canonical form digests to the same value as the original.
  auto first = run_cli({"policy", "digest", directory.value() + "/policy.txt"});
  FPT_REQUIRE_OK(first);
  auto second = run_cli({"policy", "digest", directory.value() + "/canonical.txt"});
  FPT_REQUIRE_OK(second);
  FPT_CHECK_EQ(first.value().output, second.value().output);
  FPT_CHECK_EQ(first.value().output.rfind("sha256:", 0), std::size_t(0));

  // A malformed document is refused with a named reason.
  FPT_REQUIRE_OK(fptest::write_text_file(directory.value() + "/bad.txt",
                                         "fpp-document policy\nformat 1\npolicy-id grid-a\n"
                                         "revision 1\nrule r {\n}\n"));
  auto bad = run_cli({"policy", "validate", directory.value() + "/bad.txt"});
  FPT_REQUIRE_OK(bad);
  FPT_CHECK_EQ(bad.value().exit_code, 2);
  FPT_CHECK(bad.value().output.find("RULE_WITHOUT_CONSTRAINTS") != std::string::npos);
}

FPT_TEST(cli, a_store_can_be_initialised_inspected_and_verified_from_the_shell) {
  auto directory = cli_scenario("cli-store");
  FPT_REQUIRE_OK(directory);
  const std::string store = directory.value() + "/store";

  auto status = run_cli({"store", "status", store, "--json"});
  FPT_REQUIRE_OK(status);
  FPT_CHECK_EQ(status.value().exit_code, 0);
  FPT_CHECK(status.value().output.find("\"store-id\":\"store:main\"") != std::string::npos);
  FPT_CHECK(status.value().output.find("\"policy-revision\":1") != std::string::npos);
  FPT_CHECK(status.value().output.find("\"unreferenced-records\":0") != std::string::npos);

  auto verify = run_cli({"store", "verify", store});
  FPT_REQUIRE_OK(verify);
  FPT_CHECK_EQ(verify.value().exit_code, 0);
  FPT_CHECK_EQ(verify.value().output.rfind("verified\n", 0), std::size_t(0));

  auto policy = run_cli({"store", "policy", store});
  FPT_REQUIRE_OK(policy);
  FPT_CHECK_EQ(policy.value().exit_code, 0);
  FPT_CHECK_EQ(policy.value().output.rfind("fpp-document policy", 0), std::size_t(0));

  auto missing = run_cli({"store", "status", directory.value() + "/nothing"});
  FPT_REQUIRE_OK(missing);
  FPT_CHECK_EQ(missing.value().exit_code, 2);
  FPT_CHECK(missing.value().output.find("STORE_NOT_FOUND") != std::string::npos);
}

FPT_TEST(cli, evaluation_reports_the_decision_in_its_exit_code) {
  auto directory = cli_scenario("cli-evaluate");
  FPT_REQUIRE_OK(directory);
  const std::string store = directory.value() + "/store";
  const std::string request = directory.value() + "/request.txt";

  auto ineligible = run_cli({"evaluate", request, "--store", store});
  FPT_REQUIRE_OK(ineligible);
  FPT_CHECK_EQ(ineligible.value().exit_code, 3);
  FPT_CHECK(ineligible.value().output.find("decision ineligible") != std::string::npos);
  FPT_CHECK(ineligible.value().output.find("code=anti-affinity-exceeded") != std::string::npos);
  FPT_REQUIRE_OK(fptest::write_text_file(directory.value() + "/verdict.txt",
                                         ineligible.value().output));

  auto json = run_cli({"evaluate", request, "--store", store, "--json"});
  FPT_REQUIRE_OK(json);
  FPT_CHECK_EQ(json.value().exit_code, 3);
  FPT_CHECK(json.value().output.find("\"decision\":\"ineligible\"") != std::string::npos);
  FPT_CHECK(json.value().output.find("\"verdict-digest\":\"sha256:") != std::string::npos);

  // An override authorised by the policy turns the decision around, and the
  // verdict still names the violation it waived.
  auto grant = run_cli({"override", "authorize", store, "--envelope", "emergency", "--principal",
                        "principal:sre", "--usage", "usage-1", "--tenant", "tenant:acme",
                        "--service-class", "service-class:gold", "--facility", "facility:dc1",
                        "--at", "2026-02-14T09:30:00.000000Z", "--out",
                        directory.value() + "/grant.txt"});
  FPT_REQUIRE_OK(grant);
  FPT_CHECK_EQ(grant.value().exit_code, 0);

  auto authorized = run_cli({"override", "status", store, "--json"});
  FPT_REQUIRE_OK(authorized);
  FPT_CHECK_EQ(authorized.value().exit_code, 0);
  FPT_CHECK(authorized.value().output.find("\"used\":1") != std::string::npos);
  FPT_CHECK(authorized.value().output.find("\"remaining\":0") != std::string::npos);

  auto overridden = run_cli({"evaluate", request, directory.value() + "/grant.txt", "--store", store});
  FPT_REQUIRE_OK(overridden);
  FPT_CHECK_EQ(overridden.value().exit_code, 0);
  FPT_CHECK(overridden.value().output.find("decision eligible") != std::string::npos);
  FPT_CHECK(overridden.value().output.find("waived-by=emergency") != std::string::npos);
}

FPT_TEST(cli, a_fenced_verdict_is_reported_as_fenced) {
  auto directory = cli_scenario("cli-verify");
  FPT_REQUIRE_OK(directory);
  const std::string store = directory.value() + "/store";
  const std::string request = directory.value() + "/request.txt";

  auto evaluated = run_cli({"evaluate", request, "--store", store});
  FPT_REQUIRE_OK(evaluated);
  FPT_REQUIRE_OK(fptest::write_text_file(directory.value() + "/verdict.txt",
                                         evaluated.value().output));

  auto valid = run_cli({"verify", directory.value() + "/verdict.txt", "--candidate", "c1",
                        "--store", store, "--generations",
                        "topology=12,failure-domain=9,tenant=4,service-class=3",
                        "--occupancy-generation", "77", "--maintenance-generation", "41"});
  FPT_REQUIRE_OK(valid);
  FPT_CHECK_EQ(valid.value().exit_code, 0);
  FPT_CHECK(valid.value().output.find("valid") != std::string::npos);

  // The same verdict against a world that has moved on is fenced, and the report
  // names the field that moved.
  auto fenced = run_cli({"verify", directory.value() + "/verdict.txt", "--candidate", "c1",
                         "--store", store, "--generations",
                         "topology=13,failure-domain=9,tenant=4,service-class=3",
                         "--occupancy-generation", "77", "--maintenance-generation", "41"});
  FPT_REQUIRE_OK(fenced);
  FPT_CHECK_EQ(fenced.value().exit_code, 2);
  FPT_CHECK(fenced.value().output.find("fenced") != std::string::npos);
  FPT_CHECK(fenced.value().output.find("stale topology-generation") != std::string::npos);

  // A verify that did not state the current state would be guessing, so it is a
  // usage error rather than a silent pass.
  auto incomplete = run_cli({"verify", directory.value() + "/verdict.txt", "--candidate", "c1",
                             "--store", store, "--generations",
                             "topology=12,failure-domain=9,tenant=4"});
  FPT_REQUIRE_OK(incomplete);
  FPT_CHECK_EQ(incomplete.value().exit_code, 2);
}

FPT_TEST(cli, a_recorded_request_replays_from_the_shell) {
  auto directory = cli_scenario("cli-record");
  FPT_REQUIRE_OK(directory);
  const std::string store = directory.value() + "/store";
  const std::string request = directory.value() + "/request.txt";

  auto first = run_cli({"evaluate", request, "--store", store, "--record", "--at",
                        "2026-02-14T09:30:00.000000Z"});
  FPT_REQUIRE_OK(first);
  FPT_CHECK_EQ(first.value().exit_code, 3);
  FPT_CHECK(first.value().output.find("replayed false") != std::string::npos);

  auto replay = run_cli({"evaluate", request, "--store", store, "--record", "--at",
                         "2026-02-14T09:31:00.000000Z"});
  FPT_REQUIRE_OK(replay);
  FPT_CHECK_EQ(replay.value().exit_code, 3);
  FPT_CHECK(replay.value().output.find("replayed true") != std::string::npos);

  auto recorded = run_cli({"record", store, "--request", "req-1", "--json"});
  FPT_REQUIRE_OK(recorded);
  FPT_CHECK_EQ(recorded.value().exit_code, 3);
  FPT_CHECK(recorded.value().output.find("\"replayed\":true") != std::string::npos);

  auto absent = run_cli({"record", store, "--request", "req-nothing"});
  FPT_REQUIRE_OK(absent);
  FPT_CHECK_EQ(absent.value().exit_code, 2);
  FPT_CHECK(absent.value().output.find("NOT_FOUND") != std::string::npos);

  auto compacted = run_cli({"store", "compact", store, "--at", "2026-02-14T09:40:00.000000Z"});
  FPT_REQUIRE_OK(compacted);
  FPT_CHECK_EQ(compacted.value().exit_code, 0);
  FPT_CHECK(compacted.value().output.find("unreferenced-records 0") != std::string::npos);
}
