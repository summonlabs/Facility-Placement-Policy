// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs.
//
// Facility Placement Policy benchmarks.
//
//   usage: facility_placement_policy_benchmarks [directory]
//
// The directory defaults to the current directory. The benchmark creates its
// store in one fixed subdirectory of it and removes nothing outside that
// subdirectory. The library starts no threads and reads no clock; every instant
// these workloads bind is derived from a literal in this file.

#include <chrono>
#include <cstdint>
#include <filesystem>
#include <iomanip>
#include <iostream>
#include <string>
#include <string_view>
#include <system_error>
#include <vector>

#include "dccp/facility_placement_policy/facility_placement_policy.hpp"

namespace fpp = dccp::facility_placement_policy;

namespace {

using Clock = std::chrono::steady_clock;

// Workload sizes. They are constants, not arguments: the numbers below are only
// comparable to another run of this same file.
constexpr std::size_t kDigestPolicyRules = 256;
constexpr std::size_t kDigestIterations = 200;
constexpr std::size_t kBatchPolicyRules = 16;
constexpr std::size_t kBatchFacilities = 16;
constexpr std::size_t kBatchCandidates = 512;
constexpr std::size_t kBatchIterations = 50;
constexpr std::size_t kActivationRules = 32;
constexpr std::size_t kActivationIterations = 64;
constexpr std::size_t kRecordingCandidates = 32;
constexpr std::size_t kRecordingIterations = 64;

constexpr std::string_view kStoreSubdirectory = "bench-store";
constexpr std::string_view kStoreId = "benchmark-store";
constexpr std::string_view kBaseInstant = "2026-02-14T09:30:00.000000Z";
constexpr std::string_view kProvenanceSynthetic = "SYNTHETIC";
constexpr std::string_view kProvenanceReal = "REAL";

/// One measurement of completed operations.
struct Measurement {
  std::string operation;
  std::size_t iterations = 0;
  std::uint64_t total_nanoseconds = 0;
  std::string provenance;
};

int report(std::string_view what, const fpp::Error& error) {
  std::cerr << what << ": " << error.to_string() << "\n";
  return 1;
}

int defect(std::string_view what) {
  std::cerr << "benchmark defect: " << what << "\n";
  return 1;
}

/// Zero-padded decimal, so generated identities sort and read predictably.
std::string number(std::size_t value, std::size_t width) {
  std::string text = std::to_string(value);
  if (text.size() < width) {
    text.insert(text.begin(), width - text.size(), '0');
  }
  return text;
}

std::uint64_t elapsed_nanoseconds(Clock::time_point start, Clock::time_point stop) {
  return static_cast<std::uint64_t>(
      std::chrono::duration_cast<std::chrono::nanoseconds>(stop - start).count());
}

void print_measurement(const Measurement& measurement) {
  const double mean = measurement.iterations == 0
                          ? 0.0
                          : static_cast<double>(measurement.total_nanoseconds) /
                                static_cast<double>(measurement.iterations);
  std::cout << std::left << std::setw(72) << measurement.operation << std::right << std::setw(12)
            << measurement.iterations << std::setw(18) << measurement.total_nanoseconds
            << std::setw(16) << std::fixed << std::setprecision(1) << mean << "  "
            << measurement.provenance << "\n";
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

/// A policy document with `rules` rules. Each rule selects one facility and
/// requires an allowed jurisdiction and rack anti-affinity, which is the shape a
/// real policy has: many small rules rather than one large one.
std::string policy_text(std::uint64_t revision, std::size_t rules, bool with_envelope) {
  std::string text;
  text += "fpp-document policy\n";
  text += "format 1\n";
  text += "policy-id benchmark-policy\n";
  text += "revision " + std::to_string(revision) + "\n";
  for (std::size_t index = 0; index < rules; ++index) {
    const std::string suffix = number(index, 3);
    text += "rule rule-" + suffix + " {\n";
    text += "  select facilities=facility-" + suffix + "\n";
    text += "  require jurisdiction allow=eu-west deny=\n";
    text += "  require anti-affinity scope=tenant dimension=rack max-shared=0\n";
    text += "}\n";
  }
  if (with_envelope) {
    text += "envelope envelope-bench {\n";
    text += "  scope facilities=facility-000\n";
    text += "  allow-kinds anti-affinity\n";
    text += "  principals principal-ops\n";
    text += "  max-uses 1000\n";
    text += "  grant-validity 1h\n";
    text += "}\n";
  }
  return text;
}

/// One request with many candidates and eight existing placements. Candidates
/// whose rack already holds a placement are ineligible for anti-affinity; the
/// rest are eligible, so both decision paths are exercised.
std::string batch_request_text() {
  std::string text;
  text += "fpp-document request\n";
  text += "format 1\n";
  text += "request-id req-bench-batch\n";
  text += "tenant tenant-a\n";
  text += "service-class svc-web\n";
  text += "requested-at " + std::string(kBaseInstant) + "\n";
  text += "generations topology=7 failure-domain=5 tenant=3 service-class=4\n";
  for (std::size_t index = 0; index < kBatchFacilities; ++index) {
    text += "facility facility-" + number(index, 3) + " jurisdiction=eu-west\n";
  }
  text += "occupancy generation=11\n";
  for (std::size_t index = 0; index < 8; ++index) {
    text += "placed placement-" + number(index, 3) + " tenant=tenant-a service-class=svc-web "
            "facility=facility-" + number(index, 3) + " site=site-1 room=room-1 row=row-1 "
            "rack=rack-" + number(index, 3) + "\n";
  }
  for (std::size_t index = 0; index < kBatchCandidates; ++index) {
    text += "candidate cand-" + number(index, 4) +
            " facility=facility-" + number(index % kBatchFacilities, 3) +
            " site=site-1 room=room-1 row=row-1 rack=rack-" + number(index % 17, 3) + "\n";
  }
  return text;
}

/// One recorded batch for the durable measurement. Its candidates sit on racks
/// no existing placement uses, so every evaluation is a completed eligible
/// verdict and the measurement is about the durable path, not about the verdict.
std::string recording_request_text(std::size_t index) {
  std::string text;
  text += "fpp-document request\n";
  text += "format 1\n";
  text += "request-id req-bench-record-" + number(index, 4) + "\n";
  text += "tenant tenant-a\n";
  text += "service-class svc-web\n";
  text += "requested-at " + std::string(kBaseInstant) + "\n";
  text += "generations topology=7 failure-domain=5 tenant=3 service-class=4\n";
  for (std::size_t facility = 0; facility < 4; ++facility) {
    text += "facility facility-" + number(facility, 3) + " jurisdiction=eu-west\n";
  }
  text += "occupancy generation=11\n";
  for (std::size_t placed = 0; placed < 4; ++placed) {
    text += "placed placement-" + number(placed, 3) + " tenant=tenant-a service-class=svc-web "
            "facility=facility-" + number(placed, 3) + " site=site-1 room=room-1 row=row-1 "
            "rack=rack-" + number(700 + placed, 3) + "\n";
  }
  for (std::size_t candidate = 0; candidate < kRecordingCandidates; ++candidate) {
    text += "candidate cand-" + number(candidate, 2) +
            " facility=facility-" + number(candidate % 4, 3) +
            " site=site-1 room=room-1 row=row-1 rack=rack-" + number(500 + candidate, 3) + "\n";
  }
  return text;
}

}  // namespace

int main(int argc, char** argv) {
  const std::string base =
      (argc > 1 && argv[1] != nullptr && argv[1][0] != '\0') ? std::string(argv[1]) : ".";
  const std::string store_directory = join(base, kStoreSubdirectory);

  std::cout << "Facility Placement Policy benchmarks\n\n";
  std::cout << "These are single-host measurements taken on the machine that ran them, with the\n";
  std::cout << "workloads generated in this process. They are not a statement about any other\n";
  std::cout << "machine and they are not a service-level guarantee.\n\n";
  std::cout << "Every measurement times a COMPLETED operation only: the timer starts after the\n";
  std::cout << "operation's input has been built and stops when the operation has returned. No\n";
  std::cout << "enqueue, submission, queue-wait or scheduling latency is reported, because this\n";
  std::cout << "library has no queue: an operation either completes or returns an Error.\n\n";
  std::cout << "provenance SYNTHETIC  the input is generated in this process and held in memory\n";
  std::cout << "provenance REAL       the operation runs against a real durable store directory,\n";
  std::cout << "                      including the stage, flush, read-back and publication path\n";
  std::cout << "                      the durability guarantee is about\n\n";
  std::cout << "store directory: " << store_directory << "\n\n";

  const auto base_instant = fpp::Instant::parse(kBaseInstant);
  const auto epoch = fpp::AuthorityEpoch::from_value(1);
  const auto sequence = fpp::StoreSequence::from_value(1);
  if (!base_instant.has_value() || !epoch.has_value() || !sequence.has_value()) {
    return defect("the literal instant or counters were refused");
  }

  // -------------------------------------------------------------------------
  // (a) Canonical policy digest over a policy with many rules.
  // -------------------------------------------------------------------------
  const auto digest_policy = fpp::parse_policy_document(policy_text(1, kDigestPolicyRules, false));
  if (!digest_policy.has_value()) {
    return report("policy with many rules", digest_policy.error());
  }

  Measurement digest;
  digest.operation = "SHA-256 canonical policy digest, 256 rules (canonicalize_policy)";
  digest.provenance = std::string(kProvenanceSynthetic);
  for (std::size_t iteration = 0; iteration < kDigestIterations; ++iteration) {
    fpp::PolicyDocument copy = digest_policy.value();
    const auto start = Clock::now();
    auto canonical = fpp::canonicalize_policy(std::move(copy));
    const auto stop = Clock::now();
    if (!canonical.has_value()) {
      return report("canonicalize_policy", canonical.error());
    }
    if (fpp::digest_is_zero(canonical.value().digest)) {
      return defect("canonicalize_policy returned an absent digest");
    }
    digest.total_nanoseconds += elapsed_nanoseconds(start, stop);
    ++digest.iterations;
  }

  // -------------------------------------------------------------------------
  // (b) One batch of candidates against one immutable snapshot.
  // -------------------------------------------------------------------------
  const auto batch_policy = fpp::parse_policy_document(policy_text(1, kBatchPolicyRules, false));
  if (!batch_policy.has_value()) {
    return report("batch policy", batch_policy.error());
  }
  const auto batch_request = fpp::parse_request_document(batch_request_text());
  if (!batch_request.has_value()) {
    return report("batch request", batch_request.error());
  }
  auto batch_snapshot = fpp::make_policy_snapshot(
      batch_policy.value(), epoch.value(), sequence.value(), fpp::TopologyGeneration{},
      fpp::FailureDomainGeneration{});
  if (!batch_snapshot.has_value()) {
    return report("batch snapshot", batch_snapshot.error());
  }
  fpp::EvaluationInput batch_input;
  batch_input.request = std::move(batch_request.value());

  Measurement batch;
  batch.operation = "evaluate: 512 candidates against one PolicySnapshot";
  batch.provenance = std::string(kProvenanceSynthetic);
  std::size_t ineligible = 0;
  for (std::size_t iteration = 0; iteration < kBatchIterations; ++iteration) {
    const auto start = Clock::now();
    auto verdicts = fpp::evaluate(batch_snapshot.value(), batch_input);
    const auto stop = Clock::now();
    if (!verdicts.has_value()) {
      return report("evaluate", verdicts.error());
    }
    if (verdicts.value().candidates.size() != kBatchCandidates) {
      return defect("the batch did not produce one verdict per candidate");
    }
    ineligible = 0;
    for (const fpp::CandidateVerdict& verdict : verdicts.value().candidates) {
      if (verdict.decision == fpp::Decision::Ineligible) {
        ++ineligible;
      }
    }
    batch.total_nanoseconds += elapsed_nanoseconds(start, stop);
    ++batch.iterations;
  }

  // -------------------------------------------------------------------------
  // (c) The real durable path: activation and recorded evaluation.
  // -------------------------------------------------------------------------
  if (!reset_directory(store_directory)) {
    return 1;
  }
  const auto store_id = fpp::StoreId::parse(kStoreId);
  if (!store_id.has_value()) {
    return report("store identity", store_id.error());
  }
  const auto initialized =
      fpp::initialize_store(store_directory, store_id.value(), base_instant.value());
  if (!initialized.has_value()) {
    return report("initialize_store", initialized.error());
  }
  auto opened = fpp::Store::open(store_directory, fpp::StoreOpenMode::ReadWrite);
  if (!opened.has_value()) {
    return report("Store::open", opened.error());
  }
  fpp::Store store = std::move(opened.value());

  // Every revision, request and instant is built before the timer runs, so the
  // measurements below contain the durable operation and nothing else.
  std::vector<fpp::PolicyDocument> revisions;
  revisions.reserve(kActivationIterations);
  for (std::size_t revision = 0; revision < kActivationIterations; ++revision) {
    auto parsed = fpp::parse_policy_document(
        policy_text(static_cast<std::uint64_t>(revision) + 1u, kActivationRules, true));
    if (!parsed.has_value()) {
      return report("activation policy", parsed.error());
    }
    revisions.push_back(std::move(parsed.value()));
  }
  std::vector<fpp::Instant> instants;
  instants.reserve(kActivationIterations + kRecordingIterations);
  for (std::size_t index = 0; index < kActivationIterations + kRecordingIterations; ++index) {
    const auto at = fpp::checked_add(
        base_instant.value(),
        fpp::Duration::from_microseconds(static_cast<std::int64_t>(index) * 1000000));
    if (!at.has_value()) {
      return report("commit instant", at.error());
    }
    instants.push_back(at.value());
  }
  std::vector<fpp::PlacementRequest> recordings;
  recordings.reserve(kRecordingIterations);
  for (std::size_t index = 0; index < kRecordingIterations; ++index) {
    auto parsed = fpp::parse_request_document(recording_request_text(index));
    if (!parsed.has_value()) {
      return report("recording request", parsed.error());
    }
    recordings.push_back(std::move(parsed.value()));
  }

  Measurement activation;
  activation.operation = "Store::activate_policy: publish a 32-rule revision (real store)";
  activation.provenance = std::string(kProvenanceReal);
  for (std::size_t iteration = 0; iteration < kActivationIterations; ++iteration) {
    const auto start = Clock::now();
    auto binding = store.activate_policy(revisions[iteration], instants[iteration]);
    const auto stop = Clock::now();
    if (!binding.has_value()) {
      return report("Store::activate_policy", binding.error());
    }
    if (binding.value().revision.value() != static_cast<std::uint64_t>(iteration) + 1u) {
      return defect("an activation published a different revision than it was given");
    }
    activation.total_nanoseconds += elapsed_nanoseconds(start, stop);
    ++activation.iterations;
  }

  Measurement recording;
  recording.operation = "Store::evaluate_recorded: record 32 candidates (real store)";
  recording.provenance = std::string(kProvenanceReal);
  for (std::size_t iteration = 0; iteration < kRecordingIterations; ++iteration) {
    fpp::EvaluationInput input;
    input.request = recordings[iteration];
    const auto start = Clock::now();
    auto verdicts = store.evaluate_recorded(input, instants[kActivationIterations + iteration]);
    const auto stop = Clock::now();
    if (!verdicts.has_value()) {
      return report("Store::evaluate_recorded", verdicts.error());
    }
    if (verdicts.value().replayed) {
      return defect("a first recording came back as a replay");
    }
    if (verdicts.value().candidates.size() != kRecordingCandidates) {
      return defect("a recorded batch did not produce one verdict per candidate");
    }
    recording.total_nanoseconds += elapsed_nanoseconds(start, stop);
    ++recording.iterations;
  }
  store.close();

  std::cout << std::left << std::setw(72) << "operation" << std::right << std::setw(12)
            << "iterations" << std::setw(18) << "total-ns" << std::setw(16) << "mean-ns"
            << "  provenance\n";
  std::cout << std::string(130, '-') << "\n";
  print_measurement(digest);
  print_measurement(batch);
  print_measurement(activation);
  print_measurement(recording);
  std::cout << "\nworkload: digest policy " << kDigestPolicyRules << " rules; batch "
            << kBatchCandidates << " candidates (" << ineligible << " ineligible, "
            << kBatchCandidates - ineligible << " eligible); activation " << kActivationIterations
            << " revisions of " << kActivationRules << " rules; recording " << kRecordingIterations
            << " requests of " << kRecordingCandidates << " candidates\n";
  std::cout << "store left in place: " << store_directory << "\n";
  return 0;
}
