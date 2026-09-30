// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs.

#include "commands.hpp"

#include <cstdio>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "dccp/facility_placement_policy/facility_placement_policy.hpp"
#include "file_ops.hpp"
#include "json_out.hpp"

namespace dccp::facility_placement_policy::cli {
namespace {

using internal::json_array;
using internal::json_bool;
using internal::json_counter;
using internal::json_digest;
using internal::json_null;
using internal::json_number;
using internal::json_object;
using internal::json_optional_counter;
using internal::json_string;
using internal::json_string_array;

void write_out(const std::string& text) {
  if (!text.empty()) {
    std::fwrite(text.data(), 1, text.size(), stdout);
  }
}

void write_err(const std::string& text) {
  if (!text.empty()) {
    std::fwrite(text.data(), 1, text.size(), stderr);
  }
}

int refuse(const Error& error) {
  write_err("refused: " + error.to_string() + "\n");
  return static_cast<int>(ExitCode::Refused);
}

int usage_error(const std::string& message) {
  write_err("usage: " + message + "\n");
  return static_cast<int>(ExitCode::Usage);
}

std::string usage_text() {
  return
      "fppctl - Facility Placement Policy\n"
      "\n"
      "  fppctl selftest\n"
      "  fppctl version\n"
      "  fppctl format\n"
      "  fppctl policy validate <file> [--json]\n"
      "  fppctl policy canonicalize <file>\n"
      "  fppctl policy digest <file>\n"
      "  fppctl store init <dir> --store-id <id> --at <instant>\n"
      "  fppctl store status <dir> [--json]\n"
      "  fppctl store verify <dir> [--json]\n"
      "  fppctl store compact <dir> --at <instant>\n"
      "  fppctl store policy <dir> [--revision <n>]\n"
      "  fppctl policy activate <dir> <file> --at <instant>\n"
      "  fppctl override status <dir> [--envelope <id>] [--json]\n"
      "  fppctl override authorize <dir> --envelope <id> --principal <id> --usage <id>\n"
      "         --tenant <id> --service-class <id> --facility <id> --at <instant>\n"
      "         [--out <file>]\n"
      "  fppctl evaluate <request> [<grant>...] --store <dir> [--record --at <instant>] [--json]\n"
      "  fppctl record <dir> --request <id> [--json]\n"
      "  fppctl verify <verdict> --candidate <id> --store <dir>\n"
      "         --generations topology=<n>,failure-domain=<n>,tenant=<n>,service-class=<n>\n"
      "         [--occupancy-generation <n>] [--maintenance-generation <n>]\n"
      "\n"
      "Exit codes: 0 ok and every candidate eligible, 1 usage, 2 refused, 3 ineligible.\n";
}

Result<std::string> read_document(const std::string& path) {
  auto bytes = internal::read_file_bounded(path, kMaxDocumentBytes);
  if (!bytes.has_value()) {
    return bytes.error();
  }
  const std::string_view view(reinterpret_cast<const char*>(bytes.value().data()),
                              bytes.value().size());
  auto checked = require_valid_utf8(view, path, kMaxDocumentBytes);
  if (!checked.has_value()) {
    return checked.error();
  }
  return checked.value();
}

Result<Instant> require_instant(const CommandLine& line, std::string_view flag) {
  const auto found = line.values.find(std::string(flag));
  if (found == line.values.end()) {
    return Error(ErrorCode::MissingField, "this command needs an instant")
        .with_detail("flag=--" + std::string(flag));
  }
  return Instant::parse(found->second);
}

Result<std::string> require_value(const CommandLine& line, std::string_view flag) {
  const auto found = line.values.find(std::string(flag));
  if (found == line.values.end()) {
    return Error(ErrorCode::MissingField, "this command needs a value")
        .with_detail("flag=--" + std::string(flag));
  }
  return found->second;
}

template <class Id>
Result<Id> require_id(const CommandLine& line, std::string_view flag) {
  auto value = require_value(line, flag);
  if (!value.has_value()) {
    return value.error();
  }
  return Id::parse(value.value());
}

Result<std::uint32_t> require_u32(const CommandLine& line, std::string_view flag) {
  auto value = require_value(line, flag);
  if (!value.has_value()) {
    return value.error();
  }
  auto parsed = parse_uint64_strict(value.value(), flag, true);
  if (!parsed.has_value()) {
    return parsed.error();
  }
  if (parsed.value() > UINT32_MAX) {
    return Error(ErrorCode::NumericOverflow, "value does not fit in 32 bits")
        .with_subject(std::string(flag));
  }
  return static_cast<std::uint32_t>(parsed.value());
}

bool has_switch(const CommandLine& line, std::string_view flag) {
  return line.switches.count(std::string(flag)) != 0u;
}

std::string status_json(const StoreStatus& status) {
  std::vector<internal::JsonField> fields;
  fields.emplace_back("store-id", json_string(status.store_id.value()));
  fields.emplace_back("sequence", json_number(status.sequence.value()));
  fields.emplace_back("authority-epoch", json_number(status.authority_epoch.value()));
  fields.emplace_back("has-active-policy",
                      json_bool(!status.policy.policy_id.empty() &&
                                status.policy.revision.is_valid()));
  fields.emplace_back("policy-id", json_string(status.policy.policy_id.value()));
  fields.emplace_back("policy-revision", json_counter(status.policy.revision));
  fields.emplace_back("policy-digest", json_digest(status.policy.digest));
  fields.emplace_back("topology-floor", json_counter(status.topology_floor));
  fields.emplace_back("failure-domain-floor", json_counter(status.failure_domain_floor));
  fields.emplace_back("retained-policy-revisions",
                      json_number(static_cast<std::uint64_t>(status.retained_policy_revisions)));
  fields.emplace_back("usage-counters",
                      json_number(static_cast<std::uint64_t>(status.usage_counters)));
  fields.emplace_back("usage-records",
                      json_number(static_cast<std::uint64_t>(status.usage_records)));
  fields.emplace_back("recorded-evaluations",
                      json_number(static_cast<std::uint64_t>(status.recorded_evaluations)));
  fields.emplace_back("unreferenced-records",
                      json_number(static_cast<std::uint64_t>(status.unreferenced_records)));
  fields.emplace_back("created-at", json_string(status.created_at.to_string()));
  fields.emplace_back("last-commit-at", json_string(status.last_commit_at.to_string()));
  fields.emplace_back("recovered-from-backup", json_bool(status.recovered_from_backup));
  fields.emplace_back("stale-head-ignored", json_bool(status.stale_head_ignored));
  return json_object(std::move(fields));
}

std::string status_text(const StoreStatus& status) {
  std::string out;
  out.append("store-id ");
  out.append(status.store_id.value());
  out.push_back('\n');
  out.append("sequence ");
  out.append(status.sequence.to_string());
  out.push_back('\n');
  out.append("authority-epoch ");
  out.append(status.authority_epoch.to_string());
  out.push_back('\n');
  if (!status.policy.policy_id.empty() && status.policy.revision.is_valid()) {
    out.append("policy ");
    out.append(status.policy.policy_id.value());
    out.append(" revision ");
    out.append(status.policy.revision.to_string());
    out.append(" digest ");
    out.append(digest_tagged_hex(status.policy.digest));
    out.push_back('\n');
  } else {
    out.append("policy none\n");
  }
  out.append("topology-floor ");
  out.append(status.topology_floor.is_valid() ? status.topology_floor.to_string() : "none");
  out.push_back('\n');
  out.append("failure-domain-floor ");
  out.append(status.failure_domain_floor.is_valid() ? status.failure_domain_floor.to_string()
                                                    : "none");
  out.push_back('\n');
  out.append("retained-policy-revisions ");
  out.append(std::to_string(status.retained_policy_revisions));
  out.append(" usage-counters ");
  out.append(std::to_string(status.usage_counters));
  out.append(" usage-records ");
  out.append(std::to_string(status.usage_records));
  out.append(" recorded-evaluations ");
  out.append(std::to_string(status.recorded_evaluations));
  out.push_back('\n');
  out.append("unreferenced-records ");
  out.append(std::to_string(status.unreferenced_records));
  out.append(" recovered-from-backup ");
  out.append(status.recovered_from_backup ? "true" : "false");
  out.append(" stale-head-ignored ");
  out.append(status.stale_head_ignored ? "true" : "false");
  out.push_back('\n');
  out.append("created-at ");
  out.append(status.created_at.to_string());
  out.append(" last-commit-at ");
  out.append(status.last_commit_at.to_string());
  out.push_back('\n');
  return out;
}

std::string violation_json(const Violation& violation) {
  std::vector<internal::JsonField> fields;
  fields.emplace_back("rule", json_string(violation.rule_id.value()));
  fields.emplace_back("constraint-kind", json_string(constraint_kind_name(violation.constraint_kind)));
  fields.emplace_back("constraint-index", json_number(static_cast<std::uint64_t>(violation.constraint_index)));
  fields.emplace_back("code", json_string(violation_code_name(violation.code)));
  fields.emplace_back("detail", json_string(violation.detail));
  if (violation.waived_by.has_value()) {
    fields.emplace_back("waived-by", json_string(violation.waived_by->value()));
  }
  return json_object(std::move(fields));
}

std::string candidate_json(const CandidateVerdict& verdict) {
  std::vector<std::string> applied;
  for (const RuleId& rule : verdict.applied_rules) {
    applied.emplace_back(rule.value());
  }
  std::vector<std::string> not_applicable;
  for (const RuleId& rule : verdict.not_applicable_rules) {
    not_applicable.emplace_back(rule.value());
  }
  std::vector<std::string> violations;
  for (const Violation& violation : verdict.violations) {
    violations.push_back(violation_json(violation));
  }
  std::vector<internal::JsonField> fields;
  fields.emplace_back("candidate-id", json_string(verdict.candidate_id.value()));
  fields.emplace_back("decision", json_string(decision_name(verdict.decision)));
  fields.emplace_back("constrained", json_bool(verdict.constrained));
  fields.emplace_back("replayed", json_bool(verdict.replayed));
  fields.emplace_back("applied-rules", json_string_array(applied));
  fields.emplace_back("not-applicable-rules", json_string_array(not_applicable));
  fields.emplace_back("violations", json_array(std::move(violations)));
  if (verdict.override_use.has_value()) {
    std::vector<internal::JsonField> use;
    use.emplace_back("envelope", json_string(verdict.override_use->envelope_id.value()));
    use.emplace_back("principal", json_string(verdict.override_use->principal.value()));
    use.emplace_back("usage", json_string(verdict.override_use->usage_id.value()));
    use.emplace_back("grant-digest", json_digest(verdict.override_use->grant_digest));
    use.emplace_back("waived-count",
                     json_number(static_cast<std::uint64_t>(verdict.override_use->waived_count)));
    fields.emplace_back("override", json_object(std::move(use)));
  } else {
    fields.emplace_back("override", json_null());
  }
  fields.emplace_back("evidence-digest", json_digest(verdict.evidence_digest));
  fields.emplace_back("verdict-digest", json_digest(verdict.verdict_digest));
  return json_object(std::move(fields));
}

std::string verdict_json(const PlacementVerdictSet& verdicts) {
  std::vector<std::string> candidates;
  for (const CandidateVerdict& candidate : verdicts.candidates) {
    candidates.push_back(candidate_json(candidate));
  }
  std::vector<internal::JsonField> generations;
  generations.emplace_back("topology", json_counter(verdicts.generations.topology));
  generations.emplace_back("failure-domain", json_counter(verdicts.generations.failure_domain));
  generations.emplace_back("tenant", json_counter(verdicts.generations.tenant));
  generations.emplace_back("service-class", json_counter(verdicts.generations.service_class));
  std::vector<internal::JsonField> fields;
  fields.emplace_back("request-id", json_string(verdicts.request_id.value()));
  fields.emplace_back("policy-id", json_string(verdicts.policy.policy_id.value()));
  fields.emplace_back("policy-revision", json_counter(verdicts.policy.revision));
  fields.emplace_back("policy-digest", json_digest(verdicts.policy.digest));
  fields.emplace_back("authority-epoch", json_counter(verdicts.authority_epoch));
  fields.emplace_back("generations", json_object(std::move(generations)));
  fields.emplace_back("occupancy-generation", json_optional_counter(verdicts.occupancy_generation));
  fields.emplace_back("maintenance-generation",
                      json_optional_counter(verdicts.maintenance_generation));
  fields.emplace_back("evaluated-at", json_string(verdicts.evaluated_at.to_string()));
  fields.emplace_back("request-digest", json_digest(verdicts.request_digest));
  fields.emplace_back("replayed", json_bool(verdicts.replayed));
  fields.emplace_back("candidates", json_array(std::move(candidates)));
  return json_object(std::move(fields));
}

std::string override_status_json(const std::vector<OverrideStatus>& statuses) {
  std::vector<std::string> items;
  for (const OverrideStatus& status : statuses) {
    std::vector<internal::JsonField> fields;
    fields.emplace_back("envelope", json_string(status.envelope_id.value()));
    fields.emplace_back("max-uses", json_number(static_cast<std::uint64_t>(status.max_uses)));
    fields.emplace_back("used", json_number(static_cast<std::uint64_t>(status.used)));
    fields.emplace_back("remaining", json_number(static_cast<std::uint64_t>(status.remaining)));
    fields.emplace_back("retained-usage-records",
                        json_number(static_cast<std::uint64_t>(status.retained_usage_records)));
    items.push_back(json_object(std::move(fields)));
  }
  return json_array(std::move(items));
}

std::string override_status_text(const OverrideStatus& status) {
  std::string out;
  out.append("envelope ");
  out.append(status.envelope_id.value());
  out.append(" max-uses ");
  out.append(std::to_string(status.max_uses));
  out.append(" used ");
  out.append(std::to_string(status.used));
  out.append(" remaining ");
  out.append(std::to_string(status.remaining));
  out.append(" retained-usage-records ");
  out.append(std::to_string(status.retained_usage_records));
  out.push_back('\n');
  return out;
}

int decision_exit_code(const PlacementVerdictSet& verdicts) {
  for (const CandidateVerdict& candidate : verdicts.candidates) {
    if (candidate.decision != Decision::Eligible) {
      return static_cast<int>(ExitCode::Ineligible);
    }
  }
  return static_cast<int>(ExitCode::Ok);
}

int command_selftest() {
  const bool digest_ok = digest_self_test();
  const bool crc_ok = crc32c_self_test();
  const bool time_ok = time_self_test();
  if (digest_ok && crc_ok && time_ok) {
    write_out("selftest ok (sha256 known answers, crc32c check vector, calendar round trips)\n");
    return static_cast<int>(ExitCode::Ok);
  }
  write_err("selftest failed: sha256=" + std::string(digest_ok ? "ok" : "failed") +
            " crc32c=" + std::string(crc_ok ? "ok" : "failed") +
            " time=" + std::string(time_ok ? "ok" : "failed") + "\n");
  return static_cast<int>(ExitCode::Refused);
}

int command_policy_validate(const CommandLine& line) {
  if (line.positional.size() != 1) {
    return usage_error("policy validate <file> [--json]");
  }
  auto text = read_document(line.positional.front());
  if (!text.has_value()) {
    return refuse(text.error());
  }
  auto document = parse_policy_document(text.value());
  if (!document.has_value()) {
    return refuse(document.error());
  }
  const auto& policy = document.value();
  if (has_switch(line, "json")) {
    std::vector<internal::JsonField> fields;
    fields.emplace_back("policy-id", json_string(policy.policy_id.value()));
    fields.emplace_back("revision", json_counter(policy.revision));
    fields.emplace_back("digest", json_digest(policy.digest));
    fields.emplace_back("rules", json_number(static_cast<std::uint64_t>(policy.rules.size())));
    fields.emplace_back("envelopes",
                        json_number(static_cast<std::uint64_t>(policy.envelopes.size())));
    fields.emplace_back("valid", json_bool(true));
    write_out(json_object(std::move(fields)) + "\n");
  } else {
    std::string out = "valid policy ";
    out.append(policy.policy_id.value());
    out.append(" revision ");
    out.append(policy.revision.to_string());
    out.append(" digest ");
    out.append(digest_tagged_hex(policy.digest));
    out.append(" rules ");
    out.append(std::to_string(policy.rules.size()));
    out.append(" envelopes ");
    out.append(std::to_string(policy.envelopes.size()));
    out.push_back('\n');
    write_out(out);
  }
  return static_cast<int>(ExitCode::Ok);
}

int command_policy_canonicalize(const CommandLine& line) {
  if (line.positional.size() != 1) {
    return usage_error("policy canonicalize <file>");
  }
  auto text = read_document(line.positional.front());
  if (!text.has_value()) {
    return refuse(text.error());
  }
  auto document = parse_policy_document(text.value());
  if (!document.has_value()) {
    return refuse(document.error());
  }
  write_out(policy_document_text(document.value()));
  return static_cast<int>(ExitCode::Ok);
}

int command_policy_digest(const CommandLine& line) {
  if (line.positional.size() != 1) {
    return usage_error("policy digest <file>");
  }
  auto text = read_document(line.positional.front());
  if (!text.has_value()) {
    return refuse(text.error());
  }
  auto document = parse_policy_document(text.value());
  if (!document.has_value()) {
    return refuse(document.error());
  }
  write_out(digest_tagged_hex(document.value().digest) + "\n");
  return static_cast<int>(ExitCode::Ok);
}

int command_store_init(const CommandLine& line) {
  if (line.positional.size() != 1) {
    return usage_error("store init <dir> --store-id <id> --at <instant>");
  }
  auto store_id = require_id<StoreId>(line, "store-id");
  if (!store_id.has_value()) {
    return refuse(store_id.error());
  }
  auto at = require_instant(line, "at");
  if (!at.has_value()) {
    return refuse(at.error());
  }
  const auto created = initialize_store(line.positional.front(), store_id.value(), at.value());
  if (!created.has_value()) {
    return refuse(created.error());
  }
  write_out("initialised store " + std::string(store_id.value().value()) + " in " +
            line.positional.front() + "\n");
  return static_cast<int>(ExitCode::Ok);
}

Result<Store> open_store(const std::string& directory, StoreOpenMode mode) {
  return Store::open(directory, mode);
}

int command_store_status(const CommandLine& line) {
  if (line.positional.size() != 1) {
    return usage_error("store status <dir> [--json]");
  }
  auto store = open_store(line.positional.front(), StoreOpenMode::ReadOnly);
  if (!store.has_value()) {
    return refuse(store.error());
  }
  const StoreStatus status = store.value().status();
  write_out(has_switch(line, "json") ? status_json(status) + "\n" : status_text(status));
  return static_cast<int>(ExitCode::Ok);
}

int command_store_verify(const CommandLine& line) {
  if (line.positional.size() != 1) {
    return usage_error("store verify <dir> [--json]");
  }
  auto store = open_store(line.positional.front(), StoreOpenMode::ReadOnly);
  if (!store.has_value()) {
    return refuse(store.error());
  }
  const StoreStatus status = store.value().status();
  if (has_switch(line, "json")) {
    std::vector<internal::JsonField> fields;
    fields.emplace_back("verified", json_bool(true));
    fields.emplace_back("status", status_json(status));
    write_out(json_object(std::move(fields)) + "\n");
  } else {
    write_out("verified\n");
    write_out(status_text(status));
  }
  return static_cast<int>(ExitCode::Ok);
}

int command_store_compact(const CommandLine& line) {
  if (line.positional.size() != 1) {
    return usage_error("store compact <dir> --at <instant>");
  }
  auto at = require_instant(line, "at");
  if (!at.has_value()) {
    return refuse(at.error());
  }
  auto store = open_store(line.positional.front(), StoreOpenMode::ReadWrite);
  if (!store.has_value()) {
    return refuse(store.error());
  }
  const auto compacted = store.value().compact(at.value());
  if (!compacted.has_value()) {
    return refuse(compacted.error());
  }
  write_out(status_text(store.value().status()));
  return static_cast<int>(ExitCode::Ok);
}

int command_store_policy(const CommandLine& line) {
  if (line.positional.size() != 1) {
    return usage_error("store policy <dir> [--revision <n>]");
  }
  auto store = open_store(line.positional.front(), StoreOpenMode::ReadOnly);
  if (!store.has_value()) {
    return refuse(store.error());
  }
  if (line.values.count("revision") == 0u) {
    auto snapshot = store.value().snapshot();
    if (!snapshot.has_value()) {
      return refuse(snapshot.error());
    }
    write_out(policy_document_text(snapshot.value().policy));
    return static_cast<int>(ExitCode::Ok);
  }
  auto revision = require_u32(line, "revision");
  if (!revision.has_value()) {
    return refuse(revision.error());
  }
  auto counter = PolicyRevision::from_value(revision.value());
  if (!counter.has_value()) {
    return refuse(counter.error());
  }
  auto document = store.value().read_policy(counter.value());
  if (!document.has_value()) {
    return refuse(document.error());
  }
  write_out(policy_document_text(document.value()));
  return static_cast<int>(ExitCode::Ok);
}

int command_policy_activate(const CommandLine& line) {
  if (line.positional.size() != 2) {
    return usage_error("policy activate <dir> <file> --at <instant>");
  }
  auto at = require_instant(line, "at");
  if (!at.has_value()) {
    return refuse(at.error());
  }
  auto text = read_document(line.positional[1]);
  if (!text.has_value()) {
    return refuse(text.error());
  }
  auto document = parse_policy_document(text.value());
  if (!document.has_value()) {
    return refuse(document.error());
  }
  auto store = open_store(line.positional[0], StoreOpenMode::ReadWrite);
  if (!store.has_value()) {
    return refuse(store.error());
  }
  auto binding = store.value().activate_policy(document.value(), at.value());
  if (!binding.has_value()) {
    return refuse(binding.error());
  }
  write_out("active policy " + std::string(binding.value().policy_id.value()) + " revision " +
            binding.value().revision.to_string() + " digest " +
            digest_tagged_hex(binding.value().digest) + " epoch " +
            store.value().status().authority_epoch.to_string() + "\n");
  return static_cast<int>(ExitCode::Ok);
}

int command_override_status(const CommandLine& line) {
  if (line.positional.size() != 1) {
    return usage_error("override status <dir> [--envelope <id>] [--json]");
  }
  auto store = open_store(line.positional.front(), StoreOpenMode::ReadOnly);
  if (!store.has_value()) {
    return refuse(store.error());
  }
  if (line.values.count("envelope") != 0u) {
    auto envelope = require_id<EnvelopeId>(line, "envelope");
    if (!envelope.has_value()) {
      return refuse(envelope.error());
    }
    auto status = store.value().override_status(envelope.value());
    if (!status.has_value()) {
      return refuse(status.error());
    }
    write_out(has_switch(line, "json")
                  ? json_object({{"envelope", json_string(status.value().envelope_id.value())},
                                 {"max-uses", json_number(status.value().max_uses)},
                                 {"used", json_number(status.value().used)},
                                 {"remaining", json_number(status.value().remaining)},
                                 {"retained-usage-records",
                                  json_number(static_cast<std::uint64_t>(
                                      status.value().retained_usage_records))}}) +
                        "\n"
                  : override_status_text(status.value()));
    return static_cast<int>(ExitCode::Ok);
  }
  auto statuses = store.value().override_statuses();
  if (!statuses.has_value()) {
    return refuse(statuses.error());
  }
  if (has_switch(line, "json")) {
    write_out(override_status_json(statuses.value()) + "\n");
    return static_cast<int>(ExitCode::Ok);
  }
  std::string out;
  for (const OverrideStatus& status : statuses.value()) {
    out.append(override_status_text(status));
  }
  write_out(out);
  return static_cast<int>(ExitCode::Ok);
}

int command_override_authorize(const CommandLine& line) {
  if (line.positional.size() != 1) {
    return usage_error("override authorize <dir> --envelope <id> --principal <id> --usage <id> "
                       "--tenant <id> --service-class <id> --facility <id> --at <instant>");
  }
  auto envelope = require_id<EnvelopeId>(line, "envelope");
  if (!envelope.has_value()) {
    return refuse(envelope.error());
  }
  auto principal = require_id<PrincipalId>(line, "principal");
  if (!principal.has_value()) {
    return refuse(principal.error());
  }
  auto usage = require_id<UsageId>(line, "usage");
  if (!usage.has_value()) {
    return refuse(usage.error());
  }
  auto tenant = require_id<TenantId>(line, "tenant");
  if (!tenant.has_value()) {
    return refuse(tenant.error());
  }
  auto service_class = require_id<ServiceClassId>(line, "service-class");
  if (!service_class.has_value()) {
    return refuse(service_class.error());
  }
  auto facility = require_id<FacilityId>(line, "facility");
  if (!facility.has_value()) {
    return refuse(facility.error());
  }
  auto at = require_instant(line, "at");
  if (!at.has_value()) {
    return refuse(at.error());
  }
  auto store = open_store(line.positional.front(), StoreOpenMode::ReadWrite);
  if (!store.has_value()) {
    return refuse(store.error());
  }
  auto grant = store.value().authorize_override(envelope.value(), principal.value(),
                                                usage.value(), tenant.value(),
                                                service_class.value(), facility.value(), at.value());
  if (!grant.has_value()) {
    return refuse(grant.error());
  }
  const std::string text = grant_document_text(grant.value());
  if (line.values.count("out") != 0u) {
    auto path = require_value(line, "out");
    if (!path.has_value()) {
      return refuse(path.error());
    }
    auto encoded = encode_grant(grant.value());
    if (!encoded.has_value()) {
      return refuse(encoded.error());
    }
    const std::string document = text;
    const auto written = internal::write_file_atomic(
        path.value(), std::span<const std::uint8_t>(
                          reinterpret_cast<const std::uint8_t*>(document.data()), document.size()));
    if (!written.has_value()) {
      return refuse(written.error());
    }
    write_out("grant " + std::string(grant.value().usage_id.value()) + " written to " +
              path.value() + "\n");
    return static_cast<int>(ExitCode::Ok);
  }
  write_out(text);
  return static_cast<int>(ExitCode::Ok);
}

int command_evaluate(const CommandLine& line) {
  if (line.positional.empty()) {
    return usage_error("evaluate <request> [<grant>...] --store <dir> [--record --at <instant>]");
  }
  auto store_path = require_value(line, "store");
  if (!store_path.has_value()) {
    return refuse(store_path.error());
  }
  auto request_text = read_document(line.positional.front());
  if (!request_text.has_value()) {
    return refuse(request_text.error());
  }
  auto request = parse_request_document(request_text.value());
  if (!request.has_value()) {
    return refuse(request.error());
  }
  EvaluationInput input;
  input.request = std::move(request.value());
  for (std::size_t index = 1; index < line.positional.size(); ++index) {
    auto grant_text = read_document(line.positional[index]);
    if (!grant_text.has_value()) {
      return refuse(grant_text.error());
    }
    auto kind = document_kind(grant_text.value());
    if (!kind.has_value()) {
      return refuse(kind.error());
    }
    if (kind.value() != "grant") {
      return refuse(Error(ErrorCode::UnexpectedToken,
                          "every file after the request must be a grant document")
                       .with_detail("file=" + line.positional[index]));
    }
    auto grant = parse_grant_document(grant_text.value());
    if (!grant.has_value()) {
      return refuse(grant.error());
    }
    input.grants.push_back(std::move(grant.value()));
  }

  const bool record = has_switch(line, "record");
  auto store = open_store(store_path.value(),
                          record ? StoreOpenMode::ReadWrite : StoreOpenMode::ReadOnly);
  if (!store.has_value()) {
    return refuse(store.error());
  }

  Result<PlacementVerdictSet> verdicts = Error(ErrorCode::InternalError, "unreachable");
  if (record) {
    auto at = require_instant(line, "at");
    if (!at.has_value()) {
      return refuse(at.error());
    }
    verdicts = store.value().evaluate_recorded(input, at.value());
  } else {
    auto snapshot = store.value().snapshot();
    if (!snapshot.has_value()) {
      return refuse(snapshot.error());
    }
    verdicts = evaluate(snapshot.value(), input);
  }
  if (!verdicts.has_value()) {
    return refuse(verdicts.error());
  }
  write_out(has_switch(line, "json") ? verdict_json(verdicts.value()) + "\n"
                                     : verdict_set_text(verdicts.value()));
  return decision_exit_code(verdicts.value());
}

int command_record(const CommandLine& line) {
  if (line.positional.size() != 1) {
    return usage_error("record <dir> --request <id> [--json]");
  }
  auto request_id = require_id<RequestId>(line, "request");
  if (!request_id.has_value()) {
    return refuse(request_id.error());
  }
  auto store = open_store(line.positional.front(), StoreOpenMode::ReadOnly);
  if (!store.has_value()) {
    return refuse(store.error());
  }
  auto verdicts = store.value().recorded_verdicts(request_id.value());
  if (!verdicts.has_value()) {
    return refuse(verdicts.error());
  }
  write_out(has_switch(line, "json") ? verdict_json(verdicts.value()) + "\n"
                                     : verdict_set_text(verdicts.value()));
  return decision_exit_code(verdicts.value());
}

Result<EvidenceGenerations> parse_generations(const std::string& text) {
  EvidenceGenerations generations;
  std::size_t start = 0;
  int seen = 0;
  while (start <= text.size()) {
    const std::size_t comma = text.find(',', start);
    const std::size_t stop = comma == std::string::npos ? text.size() : comma;
    const std::string element = text.substr(start, stop - start);
    const std::size_t equals = element.find('=');
    if (equals == std::string::npos) {
      return Error(ErrorCode::MalformedDocument,
                   "generations are written name=value, for example topology=12")
          .with_subject(element);
    }
    const std::string name = element.substr(0, equals);
    auto value = parse_uint64_strict(std::string_view(element).substr(equals + 1), name, false);
    if (!value.has_value()) {
      return value.error();
    }
    if (name == "topology") {
      generations.topology = TopologyGeneration::from_value(value.value()).value();
    } else if (name == "failure-domain") {
      generations.failure_domain = FailureDomainGeneration::from_value(value.value()).value();
    } else if (name == "tenant") {
      generations.tenant = TenantGeneration::from_value(value.value()).value();
    } else if (name == "service-class") {
      generations.service_class = ServiceClassGeneration::from_value(value.value()).value();
    } else {
      return Error(ErrorCode::UnknownEnumToken, "unknown generation name").with_subject(name);
    }
    ++seen;
    if (comma == std::string::npos) {
      break;
    }
    start = comma + 1;
  }
  if (seen != 4) {
    return Error(ErrorCode::MissingField,
                 "the current state of all four generations must be supplied; a verify that "
                 "silently assumed them would report a stale verdict as valid");
  }
  return generations;
}

int command_verify(const CommandLine& line) {
  if (line.positional.size() != 1) {
    return usage_error("verify <verdict> --candidate <id> --store <dir> --generations ...");
  }
  auto candidate = require_id<CandidateId>(line, "candidate");
  if (!candidate.has_value()) {
    return refuse(candidate.error());
  }
  auto store_path = require_value(line, "store");
  if (!store_path.has_value()) {
    return refuse(store_path.error());
  }
  auto generations_text = require_value(line, "generations");
  if (!generations_text.has_value()) {
    return refuse(generations_text.error());
  }
  auto generations = parse_generations(generations_text.value());
  if (!generations.has_value()) {
    return refuse(generations.error());
  }
  auto verdict_text = read_document(line.positional.front());
  if (!verdict_text.has_value()) {
    return refuse(verdict_text.error());
  }
  auto verdicts = parse_verdict_document(verdict_text.value());
  if (!verdicts.has_value()) {
    return refuse(verdicts.error());
  }
  auto store = open_store(store_path.value(), StoreOpenMode::ReadOnly);
  if (!store.has_value()) {
    return refuse(store.error());
  }
  const StoreStatus status = store.value().status();

  AuthorityState current;
  current.policy = status.policy;
  current.authority_epoch = status.authority_epoch;
  current.generations = generations.value();
  if (line.values.count("occupancy-generation") != 0u) {
    auto value = require_u32(line, "occupancy-generation");
    if (!value.has_value()) {
      return refuse(value.error());
    }
    current.occupancy_generation = OccupancyGeneration::from_value(value.value()).value();
  }
  if (line.values.count("maintenance-generation") != 0u) {
    auto value = require_u32(line, "maintenance-generation");
    if (!value.has_value()) {
      return refuse(value.error());
    }
    current.maintenance_generation = MaintenanceGeneration::from_value(value.value()).value();
  }

  auto report = verify_verdict(verdicts.value(), candidate.value(), current);
  if (!report.has_value()) {
    return refuse(report.error());
  }
  if (has_switch(line, "json")) {
    std::vector<std::string> fields;
    for (const FencingField& field : report.value().fields) {
      fields.push_back(json_object({{"name", json_string(field.name)},
                                    {"bound", json_string(field.bound)},
                                    {"current", json_string(field.current)},
                                    {"stale", json_bool(field.stale)}}));
    }
    write_out(json_object({{"candidate", json_string(candidate.value().value())},
                           {"status", json_string(report.value().status == FencingStatus::Valid
                                                      ? "valid"
                                                      : "fenced")},
                           {"digest-verified", json_bool(report.value().digest_verified)},
                           {"fields", json_array(std::move(fields))}}) +
              "\n");
  } else {
    write_out(fencing_report_text(report.value()));
  }
  return report.value().status == FencingStatus::Valid ? static_cast<int>(ExitCode::Ok)
                                                       : static_cast<int>(ExitCode::Refused);
}

}  // namespace

bool parse_command_line(const std::vector<std::string>& arguments,
                        const std::set<std::string>& value_flags,
                        const std::set<std::string>& switch_flags, CommandLine& out,
                        std::string& error) {
  // Every element is an option or a positional argument; the command word is not
  // part of what this function sees, so a caller that passes only positional
  // arguments still gets them.
  out = CommandLine{};
  for (std::size_t index = 0; index < arguments.size(); ++index) {
    const std::string& token = arguments[index];
    if (token.size() >= 2 && token[0] == '-' && token[1] == '-') {
      const std::string name = token.substr(2);
      if (switch_flags.count(name) != 0u) {
        out.switches.insert(name);
        continue;
      }
      if (value_flags.count(name) != 0u) {
        if (index + 1 >= arguments.size()) {
          error = "--" + name + " needs a value";
          return false;
        }
        out.values[name] = arguments[index + 1];
        ++index;
        continue;
      }
      error = "unknown option --" + name;
      return false;
    }
    out.positional.push_back(token);
  }
  return true;
}

namespace {

int dispatch_group(const std::string& group, const std::vector<std::string>& rest);

int dispatch(const std::string& name, const std::vector<std::string>& rest) {
  if (name == "selftest") {
    return command_selftest();
  }
  if (name == "format") {
    write_out(store_format_description() + "\n");
    return static_cast<int>(ExitCode::Ok);
  }
  if (name == "policy") {
    return dispatch_group(name, rest);
  }
  if (name == "store") {
    return dispatch_group(name, rest);
  }
  if (name == "override") {
    return dispatch_group(name, rest);
  }
  if (name == "evaluate") {
    CommandLine line;
    std::string error;
    if (!parse_command_line(rest, {"store", "at"}, {"record", "json"}, line, error)) {
      return usage_error(error);
    }
    return command_evaluate(line);
  }
  if (name == "record") {
    CommandLine line;
    std::string error;
    if (!parse_command_line(rest, {"request"}, {"json"}, line, error)) {
      return usage_error(error);
    }
    return command_record(line);
  }
  if (name == "verify") {
    CommandLine line;
    std::string error;
    if (!parse_command_line(rest, {"candidate", "store", "generations", "occupancy-generation",
                                   "maintenance-generation"},
                            {"json"}, line, error)) {
      return usage_error(error);
    }
    return command_verify(line);
  }
  write_err("unknown command: " + name + "\n" + usage_text());
  return static_cast<int>(ExitCode::Usage);
}

int dispatch_group(const std::string& group, const std::vector<std::string>& rest) {
  if (rest.empty()) {
    return usage_error(group + " needs a subcommand");
  }
  const std::string sub = rest.front();
  const std::vector<std::string> tail(rest.begin() + 1, rest.end());
  CommandLine line;
  std::string error;
  if (group == "policy") {
    if (sub == "validate") {
      if (!parse_command_line(tail, {}, {"json"}, line, error)) {
        return usage_error(error);
      }
      return command_policy_validate(line);
    }
    if (sub == "canonicalize") {
      if (!parse_command_line(tail, {}, {}, line, error)) {
        return usage_error(error);
      }
      return command_policy_canonicalize(line);
    }
    if (sub == "digest") {
      if (!parse_command_line(tail, {}, {}, line, error)) {
        return usage_error(error);
      }
      return command_policy_digest(line);
    }
    if (sub == "activate") {
      if (!parse_command_line(tail, {"at"}, {}, line, error)) {
        return usage_error(error);
      }
      return command_policy_activate(line);
    }
    write_err("unknown policy subcommand: " + sub + "\n" + usage_text());
    return static_cast<int>(ExitCode::Usage);
  }
  if (group == "store") {
    if (sub == "init") {
      if (!parse_command_line(tail, {"store-id", "at"}, {}, line, error)) {
        return usage_error(error);
      }
      return command_store_init(line);
    }
    if (sub == "status") {
      if (!parse_command_line(tail, {}, {"json"}, line, error)) {
        return usage_error(error);
      }
      return command_store_status(line);
    }
    if (sub == "verify") {
      if (!parse_command_line(tail, {}, {"json"}, line, error)) {
        return usage_error(error);
      }
      return command_store_verify(line);
    }
    if (sub == "compact") {
      if (!parse_command_line(tail, {"at"}, {}, line, error)) {
        return usage_error(error);
      }
      return command_store_compact(line);
    }
    if (sub == "policy") {
      if (!parse_command_line(tail, {"revision"}, {}, line, error)) {
        return usage_error(error);
      }
      return command_store_policy(line);
    }
    write_err("unknown store subcommand: " + sub + "\n" + usage_text());
    return static_cast<int>(ExitCode::Usage);
  }
  if (group == "override") {
    if (sub == "status") {
      if (!parse_command_line(tail, {"envelope"}, {"json"}, line, error)) {
        return usage_error(error);
      }
      return command_override_status(line);
    }
    if (sub == "authorize") {
      if (!parse_command_line(tail,
                              {"envelope", "principal", "usage", "tenant", "service-class",
                               "facility", "at", "out"},
                              {}, line, error)) {
        return usage_error(error);
      }
      return command_override_authorize(line);
    }
    write_err("unknown override subcommand: " + sub + "\n" + usage_text());
    return static_cast<int>(ExitCode::Usage);
  }
  return usage_error("unknown group " + group);
}

}  // namespace

int run(const std::vector<std::string>& arguments) {
  if (arguments.empty()) {
    write_err(usage_text());
    return static_cast<int>(ExitCode::Usage);
  }
  const std::string& first = arguments.front();
  if (first == "help" || first == "--help" || first == "-h") {
    write_out(usage_text());
    return static_cast<int>(ExitCode::Ok);
  }
  if (first == "version" || first == "--version") {
    write_out(std::string(version_string()) + "\n");
    return static_cast<int>(ExitCode::Ok);
  }
  const std::vector<std::string> rest(arguments.begin() + 1, arguments.end());
  return dispatch(first, rest);
}

}  // namespace dccp::facility_placement_policy::cli
