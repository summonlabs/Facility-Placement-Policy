// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs.
//
// Durable policy store: activate a revision, issue one override grant, record an
// evaluation, and replay it.
//
// The store is created inside the directory given on the command line and
// nothing outside that directory is written or removed. Every instant comes from
// a literal in this file; the library never reads a clock.
//
//   usage: facility_placement_policy_example_durable_policy_store <directory>

#include <cstdint>
#include <filesystem>
#include <iostream>
#include <string>
#include <string_view>
#include <system_error>

#include "dccp/facility_placement_policy/facility_placement_policy.hpp"

namespace fpp = dccp::facility_placement_policy;

namespace {

/// The store lives in one fixed subdirectory of the caller's directory, so a
/// repeat run resets exactly what this example created and nothing else.
constexpr std::string_view kStoreSubdirectory = "policy-store";
constexpr std::string_view kStoreId = "demo-store";
constexpr std::string_view kStartInstant = "2026-02-14T09:30:00.000000Z";
constexpr std::string_view kReplayInstant = "2026-02-14T10:00:00.000000Z";

constexpr std::string_view kEnvelopeId = "envelope-rack-exception";
constexpr std::string_view kPrincipalId = "principal-ops";
constexpr std::string_view kUsageId = "usage-1";
constexpr std::string_view kTenantId = "tenant-a";
constexpr std::string_view kServiceClassId = "svc-web";
constexpr std::string_view kFacilityId = "facility-north";
constexpr std::string_view kRequestId = "req-durable-1";
constexpr std::string_view kFreeCandidateId = "cand-north-free";
constexpr std::string_view kSharedCandidateId = "cand-north-shared";

/// The rule forbids sharing a rack with an existing placement of the same
/// tenant. The envelope is the authority to waive exactly that constraint, for
/// one tenant, one service class and one facility, at most three times, with
/// grants that live for an hour. It cannot reach jurisdiction, separation or
/// maintenance exposure: those are hard interlocks.
constexpr std::string_view kPolicyText =
    "fpp-document policy\n"
    "format 1\n"
    "policy-id placement-policy\n"
    "revision 1\n"
    "rule rack-anti-affinity {\n"
    "  description \"one rack holds one placement of this tenant\"\n"
    "  select tenants=tenant-a\n"
    "  require anti-affinity scope=tenant dimension=rack max-shared=0\n"
    "}\n"
    "envelope envelope-rack-exception {\n"
    "  scope tenants=tenant-a service-classes=svc-web facilities=facility-north\n"
    "  allow-kinds anti-affinity\n"
    "  principals principal-ops\n"
    "  max-uses 3\n"
    "  grant-validity 1h\n"
    "}\n";

/// Two candidates in the one facility the envelope covers. cand-north-free sits
/// on a rack nothing else uses; cand-north-shared sits on the rack that already
/// holds a placement of the tenant, which is the situation the envelope exists
/// for. The occupancy evidence is bound to its generation, and this policy needs
/// no maintenance evidence.
constexpr std::string_view kRequestText =
    "fpp-document request\n"
    "format 1\n"
    "request-id req-durable-1\n"
    "tenant tenant-a\n"
    "service-class svc-web\n"
    "requested-at 2026-02-14T09:30:00.000000Z\n"
    "generations topology=7 failure-domain=5 tenant=3 service-class=4\n"
    "facility facility-north jurisdiction=eu-west\n"
    "candidate cand-north-free facility=facility-north site=site-1 room=room-1 row=row-1 "
    "rack=rack-9\n"
    "candidate cand-north-shared facility=facility-north site=site-1 room=room-1 row=row-1 "
    "rack=rack-7\n"
    "occupancy generation=11\n"
    "placed placement-existing tenant=tenant-a service-class=svc-web "
    "facility=facility-north site=site-1 room=room-1 row=row-1 rack=rack-7\n";

int report(std::string_view what, const fpp::Error& error) {
  std::cerr << what << ": " << error.to_string() << "\n";
  return 1;
}

/// Parses one of this example's own literal identities, reporting the defect
/// that stopped the demonstration rather than assuming it cannot happen.
template <class Id>
bool parse_id(std::string_view text, Id& out) {
  const auto parsed = Id::parse(text);
  if (!parsed.has_value()) {
    std::cerr << "identifier " << text << " was refused: " << parsed.error().to_string() << "\n";
    return false;
  }
  out = parsed.value();
  return true;
}

/// The library takes UTF-8 paths and does its own conversion; a narrow
/// std::filesystem path would be read in the active code page on Windows.
std::filesystem::path as_path(const std::string& text) {
  const std::u8string utf8(reinterpret_cast<const char8_t*>(text.data()), text.size());
  return std::filesystem::path(utf8);
}

std::string join(const std::string& base, std::string_view name) {
  std::string out = base;
  while (!out.empty() && (out.back() == '/' || out.back() == '\\')) {
    out.pop_back();
  }
  out.push_back('/');
  out.append(name);
  return out;
}

bool reset_directory(const std::string& path) {
  std::error_code code;
  std::filesystem::remove_all(as_path(path), code);
  if (code) {
    std::cerr << "cannot reset " << path << ": " << code.message() << "\n";
    return false;
  }
  return true;
}

const fpp::CandidateVerdict* find_verdict(const fpp::PlacementVerdictSet& verdicts,
                                          std::string_view candidate_id) {
  for (const fpp::CandidateVerdict& verdict : verdicts.candidates) {
    if (verdict.candidate_id.value() == candidate_id) {
      return &verdict;
    }
  }
  return nullptr;
}

void print_override_status(const fpp::OverrideStatus& status) {
  std::cout << "envelope " << status.envelope_id.value() << ": max-uses=" << status.max_uses
            << " used=" << status.used << " remaining=" << status.remaining
            << " retained-usage-records=" << status.retained_usage_records << "\n";
}

}  // namespace

int main(int argc, char** argv) {
  if (argc < 2 || argv[1] == nullptr || argv[1][0] == '\0') {
    std::cerr << "usage: facility_placement_policy_example_durable_policy_store <directory>\n"
                 "  <directory> is created when missing; the store is created in "
              << kStoreSubdirectory << " inside it\n";
    return 2;
  }
  const std::string store_directory = join(argv[1], kStoreSubdirectory);

  auto start = fpp::Instant::parse(kStartInstant);
  auto replay_at = fpp::Instant::parse(kReplayInstant);
  if (!start.has_value()) {
    return report("start instant", start.error());
  }
  if (!replay_at.has_value()) {
    return report("replay instant", replay_at.error());
  }

  fpp::StoreId store_id;
  fpp::EnvelopeId envelope_id;
  fpp::PrincipalId principal;
  fpp::UsageId usage;
  fpp::TenantId tenant;
  fpp::ServiceClassId service_class;
  fpp::FacilityId facility;
  fpp::RequestId request_id;
  if (!parse_id(kStoreId, store_id) || !parse_id(kEnvelopeId, envelope_id) ||
      !parse_id(kPrincipalId, principal) || !parse_id(kUsageId, usage) ||
      !parse_id(kTenantId, tenant) || !parse_id(kServiceClassId, service_class) ||
      !parse_id(kFacilityId, facility) || !parse_id(kRequestId, request_id)) {
    return 1;
  }

  std::cout << "durable policy store demonstration\n";
  std::cout << "store directory: " << store_directory << "\n";
  if (!reset_directory(store_directory)) {
    return 1;
  }

  const auto initialized = fpp::initialize_store(store_directory, store_id, start.value());
  if (!initialized.has_value()) {
    return report("initialize_store", initialized.error());
  }
  std::cout << "initialised store " << store_id.value() << " at " << start.value().to_string()
            << "\n";

  auto opened = fpp::Store::open(store_directory, fpp::StoreOpenMode::ReadWrite);
  if (!opened.has_value()) {
    return report("Store::open", opened.error());
  }
  fpp::Store store = std::move(opened.value());

  auto policy = fpp::parse_policy_document(kPolicyText);
  if (!policy.has_value()) {
    return report("policy document", policy.error());
  }
  const auto activated = store.activate_policy(policy.value(), start.value());
  if (!activated.has_value()) {
    return report("Store::activate_policy", activated.error());
  }

  const fpp::StoreStatus status = store.status();
  std::cout << "status: store=" << status.store_id.value()
            << " sequence=" << status.sequence.to_string()
            << " authority-epoch=" << status.authority_epoch.to_string()
            << " policy=" << status.policy.policy_id.value()
            << " revision=" << status.policy.revision.to_string()
            << " retained-revisions=" << status.retained_policy_revisions
            << " usage-counters=" << status.usage_counters
            << " usage-records=" << status.usage_records
            << " recorded-evaluations=" << status.recorded_evaluations
            << " unreferenced-records=" << status.unreferenced_records
            << " recovered-from-backup=" << (status.recovered_from_backup ? "true" : "false")
            << "\n";

  // One use of the envelope, scoped to the tenant, service class and facility
  // the envelope names. The store is the only thing that can count a use.
  const auto grant = store.authorize_override(envelope_id, principal, usage, tenant, service_class,
                                              facility, start.value());
  if (!grant.has_value()) {
    return report("Store::authorize_override", grant.error());
  }
  std::cout << "grant: usage=" << grant.value().usage_id.value()
            << " envelope=" << grant.value().envelope_id.value()
            << " principal=" << grant.value().principal.value()
            << " issued=" << grant.value().issued_at.to_string()
            << " expires=" << grant.value().expires_at.to_string()
            << " grant-digest=" << fpp::digest_tagged_hex(grant.value().grant_digest) << "\n";

  const auto after_grant = store.override_status(envelope_id);
  if (!after_grant.has_value()) {
    return report("Store::override_status", after_grant.error());
  }
  print_override_status(after_grant.value());
  const std::uint32_t uses_after_grant = after_grant.value().used;

  auto request = fpp::parse_request_document(kRequestText);
  if (!request.has_value()) {
    return report("request document", request.error());
  }
  fpp::EvaluationInput input;
  input.request = std::move(request.value());
  input.grants.push_back(grant.value());

  const auto recorded = store.evaluate_recorded(input, start.value());
  if (!recorded.has_value()) {
    return report("Store::evaluate_recorded", recorded.error());
  }
  std::cout << "\nrecorded evaluation:\n" << fpp::verdict_set_text(recorded.value());

  const fpp::CandidateVerdict* free_rack = find_verdict(recorded.value(), kFreeCandidateId);
  const fpp::CandidateVerdict* shared_rack = find_verdict(recorded.value(), kSharedCandidateId);
  if (free_rack == nullptr || shared_rack == nullptr) {
    std::cerr << "the recorded verdict set does not contain both candidates\n";
    return 1;
  }
  if (recorded.value().replayed || free_rack->replayed || shared_rack->replayed) {
    std::cerr << "the first evaluation was returned as a replay\n";
    return 1;
  }
  if (free_rack->decision != fpp::Decision::Eligible) {
    std::cerr << kFreeCandidateId << " shares no rack and must be eligible\n";
    return 1;
  }
  if (!(recorded.value().authority_epoch == status.authority_epoch) ||
      !fpp::digest_equal(recorded.value().policy.digest, status.policy.digest)) {
    std::cerr << "the recording is bound to a different authority than the store holds\n";
    return 1;
  }

  // The same request identity, a different recording instant. The store answers
  // from durable state before it evaluates anything, so this cannot be refused
  // and cannot consume the grant a second time.
  const auto replayed = store.evaluate_recorded(input, replay_at.value());
  if (!replayed.has_value()) {
    std::cerr << "replaying the recorded request was refused: " << replayed.error().to_string()
              << "\n";
    return 1;
  }
  const fpp::CandidateVerdict* replay_free = find_verdict(replayed.value(), kFreeCandidateId);
  const fpp::CandidateVerdict* replay_shared = find_verdict(replayed.value(), kSharedCandidateId);
  if (replay_free == nullptr || replay_shared == nullptr) {
    std::cerr << "the replayed verdict set does not contain both candidates\n";
    return 1;
  }
  const auto after_replay = store.override_status(envelope_id);
  if (!after_replay.has_value()) {
    return report("Store::override_status", after_replay.error());
  }

  const bool digests_unchanged =
      fpp::digest_equal(replay_free->verdict_digest, free_rack->verdict_digest) &&
      fpp::digest_equal(replay_shared->verdict_digest, shared_rack->verdict_digest);
  const bool replay_ok = replayed.value().replayed && replay_free->replayed &&
                         replay_shared->replayed && !recorded.value().replayed &&
                         replay_free->decision == free_rack->decision &&
                         replay_shared->decision == shared_rack->decision && digests_unchanged &&
                         after_replay.value().used == uses_after_grant;
  std::cout << "replay: set-replayed=" << (replayed.value().replayed ? "true" : "false")
            << " candidates-replayed="
            << ((replay_free->replayed && replay_shared->replayed) ? "true" : "false")
            << " verdict-digests-unchanged=" << (digests_unchanged ? "true" : "false")
            << " decisions=" << fpp::decision_token(replay_free->decision) << "/"
            << fpp::decision_token(replay_shared->decision) << "\n";
  print_override_status(after_replay.value());

  const fpp::StoreStatus final_status = store.status();
  std::cout << "final status: sequence=" << final_status.sequence.to_string()
            << " recorded-evaluations=" << final_status.recorded_evaluations
            << " usage-records=" << final_status.usage_records << "\n";

  store.close();
  if (!replay_ok) {
    std::cerr << "replaying the request identity did not return the recorded verdicts unchanged, "
                 "or it consumed another use of the envelope\n";
    return 1;
  }
  return 0;
}
