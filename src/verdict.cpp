// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs.

#include "dccp/facility_placement_policy/verdict.hpp"

#include <string>
#include <vector>

#include "dccp/facility_placement_policy/canonical.hpp"
#include "dccp/facility_placement_policy/text.hpp"

namespace dccp::facility_placement_policy {
namespace {

template <class Tag>
std::string counter_text(const Counter<Tag>& counter) {
  return counter.is_valid() ? counter.to_string() : std::string("absent");
}

template <class Tag>
std::string optional_counter_text(const std::optional<Counter<Tag>>& counter) {
  return counter.has_value() ? counter_text(*counter) : std::string("absent");
}

/// Adds one comparison row, marking it stale when the values differ.
void add_field(FencingReport& report, std::string name, std::string bound, std::string current) {
  FencingField field;
  field.stale = bound != current;
  field.name = std::move(name);
  field.bound = std::move(bound);
  field.current = std::move(current);
  report.fields.push_back(std::move(field));
}

}  // namespace

bool verify_verdict_digest(const CandidateVerdict& verdict) {
  const Digest recomputed = compute_verdict_digest(verdict);
  return digest_equal(recomputed, verdict.verdict_digest);
}

Result<FencingReport> verify_verdict(const PlacementVerdictSet& verdicts,
                                     const CandidateId& candidate_id,
                                     const AuthorityState& current) {
  const CandidateVerdict* verdict = nullptr;
  for (const CandidateVerdict& candidate : verdicts.candidates) {
    if (candidate.candidate_id == candidate_id) {
      verdict = &candidate;
      break;
    }
  }
  if (verdict == nullptr) {
    return Error(ErrorCode::NotFound, "the verdict set does not contain this candidate")
        .with_detail("candidate=" + std::string(candidate_id.value()));
  }

  FencingReport report;
  report.candidate_id = candidate_id;
  report.verdict_digest = verdict->verdict_digest;
  report.digest_verified = verify_verdict_digest(*verdict);

  add_field(report, "policy-id", std::string(verdicts.policy.policy_id.value()),
            std::string(current.policy.policy_id.value()));
  add_field(report, "policy-revision", counter_text(verdicts.policy.revision),
            counter_text(current.policy.revision));
  add_field(report, "policy-digest", digest_hex(verdicts.policy.digest),
            digest_hex(current.policy.digest));
  add_field(report, "authority-epoch", counter_text(verdicts.authority_epoch),
            counter_text(current.authority_epoch));
  add_field(report, "topology-generation", counter_text(verdicts.generations.topology),
            counter_text(current.generations.topology));
  add_field(report, "failure-domain-generation",
            counter_text(verdicts.generations.failure_domain),
            counter_text(current.generations.failure_domain));
  add_field(report, "tenant-generation", counter_text(verdicts.generations.tenant),
            counter_text(current.generations.tenant));
  add_field(report, "service-class-generation", counter_text(verdicts.generations.service_class),
            counter_text(current.generations.service_class));
  add_field(report, "occupancy-generation", optional_counter_text(verdicts.occupancy_generation),
            optional_counter_text(current.occupancy_generation));
  add_field(report, "maintenance-generation", optional_counter_text(verdicts.maintenance_generation),
            optional_counter_text(current.maintenance_generation));

  bool stale = !report.digest_verified;
  for (const FencingField& field : report.fields) {
    if (field.stale) {
      stale = true;
    }
  }
  report.status = stale ? FencingStatus::Fenced : FencingStatus::Valid;
  return report;
}

std::string fencing_report_text(const FencingReport& report) {
  std::string out;
  out.append("candidate ");
  out.append(report.candidate_id.value());
  out.append(": ");
  out.append(report.status == FencingStatus::Valid ? "valid" : "fenced");
  out.append(" verdict-digest-verified=");
  out.append(report.digest_verified ? "true" : "false");
  out.push_back('\n');
  for (const FencingField& field : report.fields) {
    out.append(field.stale ? "  stale " : "  match ");
    out.append(field.name);
    out.append(" bound=");
    out.append(field.bound);
    out.append(" current=");
    out.append(field.current);
    out.push_back('\n');
  }
  return out;
}

std::string verdict_set_text(const PlacementVerdictSet& verdicts) {
  return verdict_document_text(verdicts);
}

}  // namespace dccp::facility_placement_policy
