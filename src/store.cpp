// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs.

#include "dccp/facility_placement_policy/store.hpp"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <set>
#include <shared_mutex>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "dccp/facility_placement_policy/canonical.hpp"
#include "dccp/facility_placement_policy/text_util.hpp"
#include "file_ops.hpp"
#include "internal_util.hpp"

namespace dccp::facility_placement_policy {
namespace {

using internal::FileLock;
using internal::read_file_bounded;
using internal::write_file_atomic;

/// The largest framed record this runtime reads from disk.
constexpr std::size_t kMaxFramedRecordBytes = kMaxRecordBytes + kRecordFrameOverhead;

struct StoreFiles {
  std::string root;
  std::string lock;
  std::string manifest;
  std::string manifest_backup;
  std::string policies;
  std::string ledger;
  std::string evaluations;
};

StoreFiles make_files(const std::string& root) {
  StoreFiles files;
  files.root = root;
  files.lock = root + "/lock.fpp";
  files.manifest = root + "/manifest.fpp";
  files.manifest_backup = root + "/manifest.fpp.bak";
  files.policies = root + "/policies";
  files.ledger = root + "/ledger";
  files.evaluations = root + "/evaluations";
  return files;
}

std::string policy_file_name(PolicyRevision revision, const Digest& digest) {
  return "policy-" + revision.to_string() + "-" + digest_hex(digest) + ".fpp";
}

std::string ledger_file_name(StoreSequence sequence, const Digest& digest) {
  return "ledger-" + sequence.to_string() + "-" + digest_hex(digest) + ".fpp";
}

std::string evaluation_file_name(const Digest& digest) {
  return "evaluation-" + digest_hex(digest) + ".fpp";
}

std::string join_path(const std::string& directory, const std::string& name) {
  return directory + "/" + name;
}

bool is_temporary_name(const std::string& name) {
  constexpr std::string_view kSuffix = ".fpp-tmp";
  return name.size() >= kSuffix.size() &&
         name.compare(name.size() - kSuffix.size(), kSuffix.size(), kSuffix) == 0;
}

/// Frames a payload, writes it, reads it back, compares it byte for byte,
/// verifies its digest and decodes it with the caller's verifier.
///
/// A record is never referenced by a head until this process has read the bytes
/// it just wrote and agreed with them, which is what makes "the manifest
/// protects a publication that already happened" true rather than aspirational.
template <class NameFor, class Verify>
Result<RecordRef> publish_record(const std::string& directory, std::uint64_t magic,
                                 std::span<const std::uint8_t> payload, NameFor name_for,
                                 Verify verify) {
  auto framed = frame_record(magic, payload);
  if (!framed.has_value()) {
    return framed.error();
  }
  const Digest digest = framed_record_digest(framed.value());
  const std::string path = join_path(directory, name_for(digest));
  const auto written = write_file_atomic(path, framed.value());
  if (!written.has_value()) {
    return written.error();
  }
  const auto readback = read_file_bounded(path, kMaxFramedRecordBytes);
  if (!readback.has_value()) {
    return readback.error();
  }
  if (readback.value() != framed.value()) {
    return Error(ErrorCode::IntegrityFailure, "record read back differs from what was written")
        .with_subject(path.substr(0, 160));
  }
  auto unframed = unframe_record(readback.value());
  if (!unframed.has_value()) {
    return unframed.error();
  }
  if (!digest_equal(unframed.value().digest, digest)) {
    return Error(ErrorCode::DigestMismatch, "record digest changed between write and read")
        .with_subject(path.substr(0, 160));
  }
  auto verified = verify(std::span<const std::uint8_t>(unframed.value().payload));
  if (!verified.has_value()) {
    return verified.error();
  }
  RecordRef reference;
  reference.digest = digest;
  reference.bytes = readback.value().size();
  return reference;
}

struct LoadedRecord {
  ByteBuffer framed;
  FramedRecord record;
};

Result<LoadedRecord> load_record(const std::string& path, std::uint64_t expected_magic) {
  auto raw = read_file_bounded(path, kMaxFramedRecordBytes);
  if (!raw.has_value()) {
    return raw.error();
  }
  auto unframed = unframe_record(raw.value());
  if (!unframed.has_value()) {
    return unframed.error();
  }
  if (unframed.value().magic != expected_magic) {
    return Error(ErrorCode::RecordCorrupt, "record has the wrong kind")
        .with_subject(path.substr(0, 160));
  }
  LoadedRecord loaded;
  loaded.framed = std::move(raw.value());
  loaded.record = std::move(unframed.value());
  return loaded;
}

struct LoadedManifest {
  ManifestRecord manifest;
  ByteBuffer bytes;
};

Result<LoadedManifest> load_manifest(const std::string& path) {
  auto loaded = load_record(path, kManifestMagic);
  if (!loaded.has_value()) {
    return loaded.error();
  }
  auto decoded = decode_manifest(std::span<const std::uint8_t>(loaded.value().record.payload));
  if (!decoded.has_value()) {
    return Error(ErrorCode::ManifestCorrupt, "manifest does not decode")
        .with_subject(path.substr(0, 160))
        .with_detail(decoded.error().to_string());
  }
  LoadedManifest out;
  out.manifest = std::move(decoded.value());
  out.bytes = std::move(loaded.value().framed);
  return out;
}

/// Reads one policy revision record and checks it against the reference the head
/// carries. The active revision is additionally checked against the binding.
Result<std::shared_ptr<const PolicyDocument>> read_policy_record(
    const StoreFiles& files, const RetainedPolicy& retained,
    const PolicyBinding* active_binding) {
  const std::string path = join_path(files.policies, policy_file_name(retained.revision, retained.record.digest));
  auto loaded = load_record(path, kPolicyRecordMagic);
  if (!loaded.has_value()) {
    return loaded.error();
  }
  if (loaded.value().framed.size() != retained.record.bytes) {
    return Error(ErrorCode::IntegrityFailure, "policy record length does not match the head")
        .with_subject(path.substr(0, 160));
  }
  auto document = decode_policy(std::span<const std::uint8_t>(loaded.value().record.payload));
  if (!document.has_value()) {
    return Error(ErrorCode::RecordCorrupt, "policy record does not decode")
        .with_subject(path.substr(0, 160))
        .with_detail(document.error().to_string());
  }
  if (!(document.value().revision == retained.revision) ||
      !(document.value().policy_id == retained.policy_id)) {
    return Error(ErrorCode::RecordCorrupt, "policy record identity does not match the head")
        .with_subject(path.substr(0, 160));
  }
  const auto canonical = validate_canonical_policy(document.value());
  if (!canonical.has_value()) {
    return canonical.error();
  }
  if (active_binding != nullptr) {
    if (!(document.value().revision == active_binding->revision) ||
        !(document.value().policy_id == active_binding->policy_id) ||
        !digest_equal(document.value().digest, active_binding->digest)) {
      return Error(ErrorCode::RecordCorrupt,
                   "the active policy record does not match the binding in the head")
          .with_subject(path.substr(0, 160));
    }
  }
  return std::make_shared<const PolicyDocument>(std::move(document.value()));
}

Result<LedgerRecord> read_ledger_record(const StoreFiles& files, const ManifestRecord& manifest) {
  const std::string path =
      join_path(files.ledger, ledger_file_name(manifest.sequence, manifest.ledger.digest));
  auto loaded = load_record(path, kLedgerRecordMagic);
  if (!loaded.has_value()) {
    return loaded.error();
  }
  if (loaded.value().framed.size() != manifest.ledger.bytes) {
    return Error(ErrorCode::IntegrityFailure, "ledger record length does not match the head")
        .with_subject(path.substr(0, 160));
  }
  auto ledger = decode_ledger(std::span<const std::uint8_t>(loaded.value().record.payload));
  if (!ledger.has_value()) {
    return Error(ErrorCode::RecordCorrupt, "ledger record does not decode")
        .with_subject(path.substr(0, 160))
        .with_detail(ledger.error().to_string());
  }
  if (!(ledger.value().sequence == manifest.sequence)) {
    return Error(ErrorCode::SequenceRegression, "ledger sequence does not match the head")
        .with_detail("ledger=" + ledger.value().sequence.to_string() +
                     " head=" + manifest.sequence.to_string());
  }
  return ledger;
}

/// Checks the ledger's own invariants and every record it references.
Result<void> verify_ledger_contents(const StoreFiles& files, const LedgerRecord& ledger) {
  if (!internal::is_strictly_increasing(
          ledger.usage_counters,
          [](const EnvelopeUsageCounter& lhs, const EnvelopeUsageCounter& rhs) {
            return lhs.envelope_id < rhs.envelope_id;
          })) {
    return Error(ErrorCode::RecordCorrupt,
                 "ledger usage counters are not in canonical order or repeat an envelope");
  }
  for (const EnvelopeUsageCounter& counter : ledger.usage_counters) {
    if (counter.uses > kMaxOverrideUses) {
      return Error(ErrorCode::RecordCorrupt, "ledger usage counter is above the permitted maximum")
          .with_detail("envelope=" + std::string(counter.envelope_id.value()));
    }
  }
  for (std::size_t index = 0; index < ledger.usage_records.size(); ++index) {
    const OverrideGrant& grant = ledger.usage_records[index].grant;
    if (!verify_grant_digest(grant)) {
      return Error(ErrorCode::DigestMismatch, "a retained grant does not match its digest")
          .with_detail("usage=" + std::string(grant.usage_id.value()));
    }
    for (std::size_t other = index + 1; other < ledger.usage_records.size(); ++other) {
      if (ledger.usage_records[other].grant.usage_id == grant.usage_id) {
        return Error(ErrorCode::RecordCorrupt, "the ledger retains one usage identity twice")
            .with_detail("usage=" + std::string(grant.usage_id.value()));
      }
    }
  }
  for (std::size_t index = 0; index < ledger.evaluations.size(); ++index) {
    const RecordedEvaluationIndex& entry = ledger.evaluations[index];
    for (std::size_t other = index + 1; other < ledger.evaluations.size(); ++other) {
      if (ledger.evaluations[other].request_id == entry.request_id) {
        return Error(ErrorCode::RecordCorrupt, "the ledger retains one request identity twice")
            .with_detail("request=" + std::string(entry.request_id.value()));
      }
    }
    const std::string path =
        join_path(files.evaluations, evaluation_file_name(entry.record.digest));
    auto loaded = load_record(path, kEvaluationRecordMagic);
    if (!loaded.has_value()) {
      return Error(ErrorCode::RecordNotFound, "a recorded evaluation is missing or corrupt")
          .with_subject(path.substr(0, 160))
          .with_detail(loaded.error().to_string());
    }
    if (loaded.value().framed.size() != entry.record.bytes) {
      return Error(ErrorCode::IntegrityFailure,
                   "recorded evaluation length does not match the ledger")
          .with_subject(path.substr(0, 160));
    }
    auto payload = decode_evaluation_payload(std::span<const std::uint8_t>(loaded.value().record.payload));
    if (!payload.has_value()) {
      return Error(ErrorCode::RecordCorrupt, "recorded evaluation does not decode")
          .with_subject(path.substr(0, 160))
          .with_detail(payload.error().to_string());
    }
    if (!(payload.value().verdicts.request_id == entry.request_id) ||
        !digest_equal(payload.value().verdicts.request_digest, entry.request_digest)) {
      return Error(ErrorCode::RecordCorrupt,
                   "recorded evaluation does not match the identity the ledger records")
          .with_subject(path.substr(0, 160));
    }
  }
  return success;
}

struct VerifiedState {
  ManifestRecord manifest;
  ByteBuffer manifest_bytes;
  LedgerRecord ledger;
  std::shared_ptr<const PolicyDocument> active_policy;
  bool recovered_from_backup = false;
  bool stale_head_ignored = false;
};

Result<VerifiedState> verify_state(const StoreFiles& files, const ManifestRecord& manifest,
                                   ByteBuffer manifest_bytes, bool recovered_from_backup,
                                   bool stale_head_ignored) {
  if (!manifest.has_active_policy && !manifest.retained.empty()) {
    return Error(ErrorCode::ManifestCorrupt,
                 "a head with no active policy may not retain policy revisions");
  }
  if (manifest.has_active_policy) {
    if (manifest.retained.empty()) {
      return Error(ErrorCode::ManifestCorrupt, "a head with an active policy retains nothing");
    }
    if (!internal::is_strictly_increasing(
            manifest.retained, [](const RetainedPolicy& lhs, const RetainedPolicy& rhs) {
              return lhs.revision < rhs.revision;
            })) {
      return Error(ErrorCode::ManifestCorrupt, "retained policy revisions are not ordered");
    }
    bool active_found = false;
    for (const RetainedPolicy& retained : manifest.retained) {
      if (retained.revision == manifest.active.revision) {
        active_found = true;
        if (!(retained.policy_id == manifest.active.policy_id) ||
            !digest_equal(retained.record.digest, manifest.active.record.digest)) {
          return Error(ErrorCode::ManifestCorrupt,
                       "the head's active policy does not match its retained entry");
        }
      }
    }
    if (!active_found) {
      return Error(ErrorCode::ManifestCorrupt, "the active policy is not in the retained set");
    }
    if (!(manifest.active.revision == manifest.policy.revision)) {
      return Error(ErrorCode::ManifestCorrupt,
                   "the head's binding and active entry disagree about the revision");
    }
  }

  VerifiedState state;
  state.manifest = manifest;
  state.manifest_bytes = std::move(manifest_bytes);
  state.recovered_from_backup = recovered_from_backup;
  state.stale_head_ignored = stale_head_ignored;

  if (manifest.has_active_policy) {
    for (const RetainedPolicy& retained : manifest.retained) {
      const PolicyBinding* binding =
          retained.revision == manifest.active.revision ? &manifest.policy : nullptr;
      auto document = read_policy_record(files, retained, binding);
      if (!document.has_value()) {
        return document.error();
      }
      if (retained.revision == manifest.active.revision) {
        state.active_policy = document.value();
      }
    }
  }

  auto ledger = read_ledger_record(files, manifest);
  if (!ledger.has_value()) {
    return ledger.error();
  }
  const auto contents = verify_ledger_contents(files, ledger.value());
  if (!contents.has_value()) {
    return contents.error();
  }
  state.ledger = std::move(ledger.value());
  return state;
}

Result<VerifiedState> open_state(const StoreFiles& files) {
  auto primary = load_manifest(files.manifest);
  auto backup = load_manifest(files.manifest_backup);
  const bool primary_ok = primary.has_value();
  const bool backup_ok = backup.has_value();

  if (!primary_ok && !backup_ok) {
    if (!internal::file_exists(files.manifest) && !internal::file_exists(files.manifest_backup)) {
      return Error(ErrorCode::StoreNotFound, "the directory holds no store head")
          .with_subject(files.root.substr(0, 160));
    }
    return Error(ErrorCode::RecoveryRequired,
                 "durable state exists but neither the head nor its predecessor could be "
                 "verified; this runtime refuses to guess which state was meant")
        .with_subject(files.root.substr(0, 160))
        .with_detail("head=" + primary.error().to_string() + " | backup=" +
                     backup.error().to_string());
  }

  if (primary_ok && backup_ok) {
    const StoreSequence primary_sequence = primary.value().manifest.sequence;
    const StoreSequence backup_sequence = backup.value().manifest.sequence;
    if (primary_sequence == backup_sequence) {
      if (primary.value().bytes != backup.value().bytes) {
        return Error(ErrorCode::IntegrityFailure,
                     "the head and its predecessor claim the same sequence but differ");
      }
    } else if (backup_sequence > primary_sequence) {
      // The head went backwards: a stale copy was put back in place. The later
      // state wins and the regression is reported.
      return verify_state(files, backup.value().manifest, std::move(backup.value().bytes), false,
                          true);
    }
    return verify_state(files, primary.value().manifest, std::move(primary.value().bytes), false,
                        false);
  }

  if (primary_ok) {
    return verify_state(files, primary.value().manifest, std::move(primary.value().bytes), false,
                        false);
  }
  return verify_state(files, backup.value().manifest, std::move(backup.value().bytes), true, false);
}

void collect_references(const ManifestRecord& manifest, const LedgerRecord& ledger,
                        std::set<std::string>& policies, std::set<std::string>& ledgers,
                        std::set<std::string>& evaluations) {
  if (manifest.has_active_policy) {
    for (const RetainedPolicy& retained : manifest.retained) {
      policies.insert(policy_file_name(retained.revision, retained.record.digest));
    }
  }
  if (manifest.ledger.bytes != 0) {
    ledgers.insert(ledger_file_name(manifest.sequence, manifest.ledger.digest));
  }
  for (const RecordedEvaluationIndex& entry : ledger.evaluations) {
    evaluations.insert(evaluation_file_name(entry.record.digest));
  }
}

/// Deletes every file in the directory that is neither referenced nor a
/// temporary. Failures are reported to the caller, which decides whether they
/// matter; the store reports how much residue is left either way.
Result<void> prune_directory(const std::string& directory, const std::set<std::string>& keep) {
  auto names = internal::list_directory(directory);
  if (!names.has_value()) {
    return names.error();
  }
  for (const std::string& name : names.value()) {
    if (keep.count(name) != 0u) {
      continue;
    }
    const auto removed = internal::remove_file(join_path(directory, name));
    if (!removed.has_value()) {
      return removed.error();
    }
  }
  return success;
}

/// Interrupted publications leave a temporary file behind. They live next to
/// the file they were going to replace, which for the head is the store root,
/// so the root is swept as well as the three record directories.
std::size_t count_root_temporaries(const std::string& root) {
  auto names = internal::list_directory(root);
  if (!names.has_value()) {
    return 0;
  }
  std::size_t count = 0;
  for (const std::string& name : names.value()) {
    if (is_temporary_name(name)) {
      ++count;
    }
  }
  return count;
}

Result<void> prune_root_temporaries(const std::string& root) {
  auto names = internal::list_directory(root);
  if (!names.has_value()) {
    return names.error();
  }
  for (const std::string& name : names.value()) {
    if (!is_temporary_name(name)) {
      continue;
    }
    const auto removed = internal::remove_file(join_path(root, name));
    if (!removed.has_value()) {
      return removed.error();
    }
  }
  return success;
}

std::size_t count_residue(const std::string& directory, const std::set<std::string>& keep) {
  auto names = internal::list_directory(directory);
  if (!names.has_value()) {
    return 0;
  }
  std::size_t count = 0;
  for (const std::string& name : names.value()) {
    if (keep.count(name) == 0u) {
      ++count;
    }
  }
  return count;
}

bool scope_matches_without_jurisdiction(const RuleSelector& selector, const TenantId& tenant,
                                        const ServiceClassId& service_class,
                                        const FacilityId& facility) noexcept {
  if (!selector.tenants.empty() &&
      std::find(selector.tenants.begin(), selector.tenants.end(), tenant) ==
          selector.tenants.end()) {
    return false;
  }
  if (!selector.service_classes.empty() &&
      std::find(selector.service_classes.begin(), selector.service_classes.end(), service_class) ==
          selector.service_classes.end()) {
    return false;
  }
  if (!selector.facilities.empty() &&
      std::find(selector.facilities.begin(), selector.facilities.end(), facility) ==
          selector.facilities.end()) {
    return false;
  }
  return true;
}

}  // namespace

struct Store::Impl {
  StoreFiles files;
  FileLock file_lock;
  StoreOpenMode mode = StoreOpenMode::ReadOnly;
  bool is_open = false;
  ManifestRecord manifest;
  ByteBuffer manifest_bytes;
  LedgerRecord ledger;
  std::shared_ptr<const PolicyDocument> active_policy;
  std::shared_ptr<const PolicySnapshot> snapshot;
  bool recovered_from_backup = false;
  bool stale_head_ignored = false;
  mutable std::shared_mutex mutex;

  void refresh_snapshot() {
    snapshot.reset();
    if (!manifest.has_active_policy || active_policy == nullptr) {
      return;
    }
    auto built = make_policy_snapshot(*active_policy, manifest.authority_epoch, manifest.sequence,
                                      manifest.topology_floor, manifest.failure_domain_floor);
    if (built.has_value()) {
      snapshot = std::make_shared<const PolicySnapshot>(std::move(built.value()));
    }
  }

  /// Publishes a new head. Everything the head references is written, flushed and
  /// read back first; the head itself is published last, and the previous head is
  /// preserved as the predecessor before that happens.
  Result<void> commit(ManifestRecord next, const LedgerRecord& next_ledger,
                      Instant committed_at) {
    auto payload = encode_ledger(next_ledger);
    if (!payload.has_value()) {
      return payload.error();
    }
    const StoreSequence ledger_sequence = next_ledger.sequence;
    auto reference = publish_record(
        files.ledger, kLedgerRecordMagic, std::span<const std::uint8_t>(payload.value()),
        [ledger_sequence](const Digest& digest) { return ledger_file_name(ledger_sequence, digest); },
        [ledger_sequence](std::span<const std::uint8_t> bytes) -> Result<void> {
          auto decoded = decode_ledger(bytes);
          if (!decoded.has_value()) {
            return decoded.error();
          }
          if (!(decoded.value().sequence == ledger_sequence)) {
            return Error(ErrorCode::IntegrityFailure,
                         "ledger read back with a different sequence");
          }
          return success;
        });
    if (!reference.has_value()) {
      return reference.error();
    }
    next.ledger = reference.value();
    next.last_commit_at = committed_at;

    auto manifest_payload = encode_manifest(next);
    if (!manifest_payload.has_value()) {
      return manifest_payload.error();
    }
    auto framed = frame_record(kManifestMagic, std::span<const std::uint8_t>(manifest_payload.value()));
    if (!framed.has_value()) {
      return framed.error();
    }

    if (!manifest_bytes.empty()) {
      const auto backup_written =
          write_file_atomic(files.manifest_backup, std::span<const std::uint8_t>(manifest_bytes));
      if (!backup_written.has_value()) {
        return backup_written.error();
      }
    }
    const auto head_written =
        write_file_atomic(files.manifest, std::span<const std::uint8_t>(framed.value()));
    if (!head_written.has_value()) {
      return head_written.error();
    }

    auto readback = read_file_bounded(files.manifest, kMaxFramedRecordBytes);
    if (!readback.has_value()) {
      return readback.error();
    }
    if (readback.value() != framed.value()) {
      return Error(ErrorCode::IntegrityFailure, "head read back differs from what was written");
    }
    auto unframed = unframe_record(readback.value());
    if (!unframed.has_value()) {
      return unframed.error();
    }
    auto decoded = decode_manifest(std::span<const std::uint8_t>(unframed.value().payload));
    if (!decoded.has_value()) {
      return Error(ErrorCode::ManifestCorrupt, "head read back does not decode")
          .with_detail(decoded.error().to_string());
    }

    // Both the state being replaced and the state being published stay readable:
    // the head and its predecessor are the only two manifests a reader may
    // choose between, so neither may reference a file this step removes.
    std::set<std::string> keep_policies;
    std::set<std::string> keep_ledgers;
    std::set<std::string> keep_evaluations;
    collect_references(manifest, ledger, keep_policies, keep_ledgers, keep_evaluations);
    collect_references(decoded.value(), next_ledger, keep_policies, keep_ledgers,
                       keep_evaluations);
    static_cast<void>(prune_directory(files.policies, keep_policies));
    static_cast<void>(prune_directory(files.ledger, keep_ledgers));
    static_cast<void>(prune_directory(files.evaluations, keep_evaluations));
    static_cast<void>(prune_root_temporaries(files.root));

    manifest = std::move(decoded.value());
    manifest_bytes = std::move(readback.value());
    ledger = next_ledger;
    return success;
  }
};

Store::Store() noexcept = default;

Store::~Store() { close(); }

Store::Store(Store&& other) noexcept : impl_(std::move(other.impl_)) {}

Store& Store::operator=(Store&& other) noexcept {
  if (this != &other) {
    close();
    impl_ = std::move(other.impl_);
  }
  return *this;
}

bool Store::is_open() const noexcept { return impl_ != nullptr && impl_->is_open; }

StoreOpenMode Store::mode() const noexcept {
  return impl_ != nullptr ? impl_->mode : StoreOpenMode::ReadOnly;
}

void Store::close() noexcept {
  if (impl_ == nullptr) {
    return;
  }
  impl_->file_lock.release();
  impl_->is_open = false;
  impl_.reset();
}

Result<void> initialize_store(const std::string& directory, const StoreId& store_id,
                              Instant created_at) {
  const auto path_check = internal::validate_directory_path(directory);
  if (!path_check.has_value()) {
    return path_check.error();
  }
  if (store_id.empty()) {
    return Error(ErrorCode::MissingField, "a store needs an identity");
  }
  if (!created_at.is_set()) {
    return Error(ErrorCode::MissingField, "initialising a store needs an instant");
  }
  if (internal::file_exists(directory)) {
    return Error(ErrorCode::PathInvalid,
                 "the store path exists and is a file, not a directory")
        .with_subject(directory.substr(0, 160));
  }
  const auto created = internal::create_directories(directory);
  if (!created.has_value()) {
    return created.error();
  }
  const StoreFiles files = make_files(directory);
  for (const std::string& sub : {files.policies, files.ledger, files.evaluations}) {
    const auto made = internal::create_directories(sub);
    if (!made.has_value()) {
      return made.error();
    }
  }
  auto lock = FileLock::acquire(files.lock, true);
  if (!lock.has_value()) {
    return lock.error();
  }
  if (internal::file_exists(files.manifest) || internal::file_exists(files.manifest_backup)) {
    return Error(ErrorCode::AlreadyInitialized, "the directory already holds a store")
        .with_subject(files.root.substr(0, 160));
  }
  auto existing_policies = internal::list_directory(files.policies);
  auto existing_ledgers = internal::list_directory(files.ledger);
  auto existing_evaluations = internal::list_directory(files.evaluations);
  if (!existing_policies.has_value() || !existing_ledgers.has_value() ||
      !existing_evaluations.has_value()) {
    return Error(ErrorCode::IoError, "cannot inspect the store directory");
  }
  if (!existing_policies.value().empty() || !existing_ledgers.value().empty() ||
      !existing_evaluations.value().empty()) {
    return Error(ErrorCode::RecoveryRequired,
                 "records exist but no head does; this runtime refuses to start a new store over "
                 "state it cannot interpret")
        .with_subject(files.root.substr(0, 160));
  }

  LedgerRecord ledger;
  ledger.sequence = StoreSequence::from_value(1).value();
  auto ledger_payload = encode_ledger(ledger);
  if (!ledger_payload.has_value()) {
    return ledger_payload.error();
  }
  auto ledger_ref = publish_record(
      files.ledger, kLedgerRecordMagic, std::span<const std::uint8_t>(ledger_payload.value()),
      [](const Digest& digest) { return ledger_file_name(StoreSequence::from_value(1).value(), digest); },
      [](std::span<const std::uint8_t> bytes) -> Result<void> {
        auto decoded = decode_ledger(bytes);
        if (!decoded.has_value()) {
          return decoded.error();
        }
        return success;
      });
  if (!ledger_ref.has_value()) {
    return ledger_ref.error();
  }

  ManifestRecord manifest;
  manifest.store_id = store_id;
  manifest.sequence = StoreSequence::from_value(1).value();
  manifest.authority_epoch = AuthorityEpoch::from_value(1).value();
  manifest.has_active_policy = false;
  manifest.ledger = ledger_ref.value();
  manifest.created_at = created_at;
  manifest.last_commit_at = created_at;

  auto manifest_payload = encode_manifest(manifest);
  if (!manifest_payload.has_value()) {
    return manifest_payload.error();
  }
  auto framed = frame_record(kManifestMagic, std::span<const std::uint8_t>(manifest_payload.value()));
  if (!framed.has_value()) {
    return framed.error();
  }
  return write_file_atomic(files.manifest, std::span<const std::uint8_t>(framed.value()));
}

Result<Store> Store::open(const std::string& directory, StoreOpenMode mode) {
  const auto path_check = internal::validate_directory_path(directory);
  if (!path_check.has_value()) {
    return path_check.error();
  }
  if (!internal::directory_exists(directory)) {
    return Error(ErrorCode::StoreNotFound, "the store directory does not exist")
        .with_subject(directory.substr(0, 160));
  }
  Store store;
  store.impl_ = std::make_unique<Store::Impl>();
  store.impl_->files = make_files(directory);
  store.impl_->mode = mode;
  auto lock = FileLock::acquire(store.impl_->files.lock, mode == StoreOpenMode::ReadWrite);
  if (!lock.has_value()) {
    return lock.error();
  }
  store.impl_->file_lock = std::move(lock.value());

  auto state = open_state(store.impl_->files);
  if (!state.has_value()) {
    return state.error();
  }
  store.impl_->manifest = std::move(state.value().manifest);
  store.impl_->manifest_bytes = std::move(state.value().manifest_bytes);
  store.impl_->ledger = std::move(state.value().ledger);
  store.impl_->active_policy = std::move(state.value().active_policy);
  store.impl_->recovered_from_backup = state.value().recovered_from_backup;
  store.impl_->stale_head_ignored = state.value().stale_head_ignored;
  store.impl_->refresh_snapshot();
  store.impl_->is_open = true;
  return std::move(store);
}

StoreStatus Store::status() const {
  StoreStatus status;
  if (impl_ == nullptr) {
    return status;
  }
  ManifestRecord manifest_copy;
  LedgerRecord ledger_copy;
  {
    std::shared_lock lock(impl_->mutex);
    manifest_copy = impl_->manifest;
    ledger_copy = impl_->ledger;
    status.store_id = impl_->manifest.store_id;
  status.sequence = impl_->manifest.sequence;
  status.authority_epoch = impl_->manifest.authority_epoch;
  status.policy = impl_->manifest.policy;
  status.topology_floor = impl_->manifest.topology_floor;
  status.failure_domain_floor = impl_->manifest.failure_domain_floor;
  status.retained_policy_revisions = impl_->manifest.retained.size();
  status.usage_counters = impl_->ledger.usage_counters.size();
  status.usage_records = impl_->ledger.usage_records.size();
  status.recorded_evaluations = impl_->ledger.evaluations.size();
  status.created_at = impl_->manifest.created_at;
  status.last_commit_at = impl_->manifest.last_commit_at;
    status.recovered_from_backup = impl_->recovered_from_backup;
    status.stale_head_ignored = impl_->stale_head_ignored;
  }
  // Directory inspection happens outside the store lock: no file operation this
  // class performs ever runs while the lock that guards in-memory state is held.
  //
  // The predecessor head is still a state a reader may have to fall back to, so
  // the records it references are not residue. Counting them as residue would
  // report a healthy store as untidy.
  std::set<std::string> policies;
  std::set<std::string> ledgers;
  std::set<std::string> evaluations;
  collect_references(manifest_copy, ledger_copy, policies, ledgers, evaluations);
  auto predecessor = load_manifest(impl_->files.manifest_backup);
  if (predecessor.has_value()) {
    auto predecessor_ledger = read_ledger_record(impl_->files, predecessor.value().manifest);
    if (predecessor_ledger.has_value()) {
      collect_references(predecessor.value().manifest, predecessor_ledger.value(), policies,
                         ledgers, evaluations);
    } else {
      collect_references(predecessor.value().manifest, LedgerRecord{}, policies, ledgers,
                         evaluations);
    }
  }
  status.unreferenced_records = count_residue(impl_->files.policies, policies) +
                                count_residue(impl_->files.ledger, ledgers) +
                                count_residue(impl_->files.evaluations, evaluations) +
                                count_root_temporaries(impl_->files.root);
  return status;
}

Result<PolicySnapshot> Store::snapshot() const {
  if (impl_ == nullptr || !impl_->is_open) {
    return Error(ErrorCode::StoreClosed, "the store is not open");
  }
  std::shared_lock lock(impl_->mutex);
  if (impl_->snapshot == nullptr) {
    return Error(ErrorCode::NoActivePolicy,
                 "no policy revision has been activated, so nothing may be evaluated")
        .with_detail("store=" + std::string(impl_->manifest.store_id.value()));
  }
  return *impl_->snapshot;
}

Result<PolicyDocument> Store::read_policy(PolicyRevision revision) const {
  if (impl_ == nullptr || !impl_->is_open) {
    return Error(ErrorCode::StoreClosed, "the store is not open");
  }
  std::shared_lock lock(impl_->mutex);
  for (const RetainedPolicy& retained : impl_->manifest.retained) {
    if (retained.revision == revision) {
      auto document = read_policy_record(impl_->files, retained, nullptr);
      if (!document.has_value()) {
        return document.error();
      }
      return *document.value();
    }
  }
  return Error(ErrorCode::NotFound, "the store does not retain this policy revision")
      .with_detail("revision=" + revision.to_string());
}

Result<PolicyBinding> Store::activate_policy(const PolicyDocument& document, Instant committed_at) {
  if (impl_ == nullptr || !impl_->is_open) {
    return Error(ErrorCode::StoreClosed, "the store is not open");
  }
  if (impl_->mode != StoreOpenMode::ReadWrite) {
    return Error(ErrorCode::StoreReadOnly, "a read-only store cannot change authority");
  }
  if (!committed_at.is_set()) {
    return Error(ErrorCode::MissingField, "activating a policy needs an instant");
  }
  auto canonical = canonicalize_policy(document);
  if (!canonical.has_value()) {
    return canonical.error();
  }
  const PolicyDocument& next_policy = canonical.value();

  std::unique_lock lock(impl_->mutex);
  if (impl_->manifest.has_active_policy) {
    if (!(next_policy.policy_id == impl_->manifest.policy.policy_id)) {
      return Error(ErrorCode::PolicyRevisionConflict,
                   "a store governs exactly one policy lineage; activating a different policy "
                   "identity would silently replace the authority it fences")
          .with_detail("active=" + std::string(impl_->manifest.policy.policy_id.value()) +
                       " requested=" + std::string(next_policy.policy_id.value()));
    }
    if (!(next_policy.revision > impl_->manifest.policy.revision)) {
      return Error(ErrorCode::StalePolicyRevision,
                   "the policy revision is not newer than the active one")
          .with_detail("active=" + impl_->manifest.policy.revision.to_string() +
                       " requested=" + next_policy.revision.to_string());
    }
    auto expected = impl_->manifest.policy.revision.next();
    if (!expected.has_value()) {
      return expected.error();
    }
    if (!(next_policy.revision == expected.value())) {
      return Error(ErrorCode::PolicyRevisionConflict,
                   "revisions advance by exactly one; a gap would leave authority unaccounted for")
          .with_detail("expected=" + expected.value().to_string() +
                       " requested=" + next_policy.revision.to_string());
    }
  }

  std::set<EnvelopeId> known_envelopes;
  for (const EnvelopeUsageCounter& counter : impl_->ledger.usage_counters) {
    known_envelopes.insert(counter.envelope_id);
  }
  for (const OverrideEnvelope& envelope : next_policy.envelopes) {
    known_envelopes.insert(envelope.envelope_id);
  }
  if (known_envelopes.size() > kMaxSetEntries) {
    return Error(ErrorCode::LimitExceeded,
                 "this store has seen more distinct override envelope identities than it can "
                 "account for")
        .with_detail("limit=" + std::to_string(kMaxSetEntries));
  }

  auto payload = encode_policy(next_policy);
  if (!payload.has_value()) {
    return payload.error();
  }
  const PolicyRevision revision = next_policy.revision;
  auto reference = publish_record(
      impl_->files.policies, kPolicyRecordMagic, std::span<const std::uint8_t>(payload.value()),
      [revision](const Digest& digest) { return policy_file_name(revision, digest); },
      [revision](std::span<const std::uint8_t> bytes) -> Result<void> {
        auto decoded = decode_policy(bytes);
        if (!decoded.has_value()) {
          return decoded.error();
        }
        if (!(decoded.value().revision == revision)) {
          return Error(ErrorCode::IntegrityFailure,
                       "policy read back with a different revision");
        }
        return validate_canonical_policy(decoded.value());
      });
  if (!reference.has_value()) {
    return reference.error();
  }

  LedgerRecord ledger = impl_->ledger;
  auto ledger_sequence = ledger.sequence.next();
  if (!ledger_sequence.has_value()) {
    return ledger_sequence.error();
  }
  ledger.sequence = ledger_sequence.value();
  for (const OverrideEnvelope& envelope : next_policy.envelopes) {
    bool present = false;
    for (const EnvelopeUsageCounter& counter : ledger.usage_counters) {
      if (counter.envelope_id == envelope.envelope_id) {
        present = true;
        break;
      }
    }
    if (!present) {
      EnvelopeUsageCounter counter;
      counter.envelope_id = envelope.envelope_id;
      counter.uses = 0;
      ledger.usage_counters.push_back(std::move(counter));
    }
  }
  internal::sort_unique(ledger.usage_counters,
                        [](const EnvelopeUsageCounter& lhs, const EnvelopeUsageCounter& rhs) {
                          return lhs.envelope_id < rhs.envelope_id;
                        });

  ManifestRecord manifest = impl_->manifest;
  auto sequence = manifest.sequence.next();
  if (!sequence.has_value()) {
    return sequence.error();
  }
  manifest.sequence = sequence.value();
  auto epoch = manifest.authority_epoch.next();
  if (!epoch.has_value()) {
    return epoch.error();
  }
  // The authority epoch advances in the same publication that makes the new
  // revision active, so every older grant and verdict is fenced atomically with
  // the change that supersedes it.
  manifest.authority_epoch = epoch.value();
  manifest.has_active_policy = true;
  manifest.policy = PolicyBinding{next_policy.policy_id, next_policy.revision,
                                  next_policy.digest};
  RetainedPolicy active;
  active.revision = next_policy.revision;
  active.policy_id = next_policy.policy_id;
  active.record = reference.value();
  manifest.active = active;
  manifest.retained.push_back(active);
  if (manifest.retained.size() > kMaxRetainedPolicyRevisions) {
    manifest.retained.erase(manifest.retained.begin());
  }

  const auto committed = impl_->commit(std::move(manifest), ledger, committed_at);
  if (!committed.has_value()) {
    return committed.error();
  }
  impl_->active_policy = std::make_shared<const PolicyDocument>(next_policy);
  impl_->refresh_snapshot();
  return impl_->manifest.policy;
}

Result<OverrideGrant> Store::authorize_override(const EnvelopeId& envelope_id,
                                                const PrincipalId& principal,
                                                const UsageId& usage_id, TenantId tenant,
                                                ServiceClassId service_class,
                                                const FacilityId& facility, Instant issued_at) {
  if (impl_ == nullptr || !impl_->is_open) {
    return Error(ErrorCode::StoreClosed, "the store is not open");
  }
  if (impl_->mode != StoreOpenMode::ReadWrite) {
    return Error(ErrorCode::StoreReadOnly, "a read-only store cannot issue a grant");
  }
  if (envelope_id.empty() || principal.empty() || usage_id.empty() || tenant.empty() ||
      service_class.empty() || facility.empty()) {
    return Error(ErrorCode::MissingField, "a grant request needs every identity field");
  }
  if (!issued_at.is_set()) {
    return Error(ErrorCode::MissingField, "issuing a grant needs an instant");
  }

  std::unique_lock lock(impl_->mutex);
  if (!impl_->manifest.has_active_policy || impl_->active_policy == nullptr) {
    return Error(ErrorCode::NoActivePolicy, "no policy revision has been activated");
  }
  const OverrideEnvelope* envelope = find_envelope(*impl_->active_policy, envelope_id);
  if (envelope == nullptr) {
    return Error(ErrorCode::OverrideUnknownEnvelope,
                 "the active policy does not declare this envelope")
        .with_detail("envelope=" + std::string(envelope_id.value()));
  }
  if (std::find(envelope->authorized_principals.begin(), envelope->authorized_principals.end(),
                principal) == envelope->authorized_principals.end()) {
    return Error(ErrorCode::OverridePrincipalNotAuthorized,
                 "the principal is not authorised by this envelope")
        .with_detail("envelope=" + std::string(envelope_id.value()) +
                     " principal=" + std::string(principal.value()));
  }
  if (envelope->not_before.is_set() && issued_at < envelope->not_before) {
    return Error(ErrorCode::OverrideNotYetValid, "the envelope is not open yet")
        .with_detail("envelope=" + std::string(envelope_id.value()));
  }
  if (envelope->expires_at.is_set() && !(issued_at < envelope->expires_at)) {
    return Error(ErrorCode::OverrideExpired, "the envelope has closed")
        .with_detail("envelope=" + std::string(envelope_id.value()));
  }
  if (!scope_matches_without_jurisdiction(envelope->scope, tenant, service_class, facility)) {
    return Error(ErrorCode::OverrideScopeMismatch, "the request is outside the envelope's scope")
        .with_detail("envelope=" + std::string(envelope_id.value()) +
                     " facility=" + std::string(facility.value()));
  }

  for (const OverrideUsageRecord& record : impl_->ledger.usage_records) {
    if (!(record.grant.usage_id == usage_id)) {
      continue;
    }
    const OverrideGrant& existing = record.grant;
    if (existing.envelope_id == envelope_id && existing.principal == principal &&
        existing.tenant == tenant && existing.service_class == service_class &&
        existing.facility == facility) {
      // A lost response is answered with the grant that was already issued, and
      // no second use is consumed.
      return existing;
    }
    return Error(ErrorCode::OverrideUsageConflict,
                 "this usage identity was already used for a different binding")
        .with_detail("usage=" + std::string(usage_id.value()));
  }

  std::uint32_t used = 0;
  for (const EnvelopeUsageCounter& counter : impl_->ledger.usage_counters) {
    if (counter.envelope_id == envelope_id) {
      used = counter.uses;
      break;
    }
  }
  if (used >= envelope->max_uses) {
    return Error(ErrorCode::OverrideLimitExceeded,
                 "the envelope has no uses left; the limit is the authority, not the caller")
        .with_detail("envelope=" + std::string(envelope_id.value()) +
                     " max-uses=" + std::to_string(envelope->max_uses));
  }

  auto validity = checked_add(issued_at, envelope->grant_validity);
  if (!validity.has_value()) {
    return validity.error();
  }
  Instant expires_at = validity.value();
  if (envelope->expires_at.is_set() && envelope->expires_at < expires_at) {
    expires_at = envelope->expires_at;
  }

  OverrideGrant grant;
  grant.envelope_id = envelope_id;
  grant.envelope_digest = envelope_digest(*envelope);
  grant.principal = principal;
  grant.usage_id = usage_id;
  grant.policy = impl_->manifest.policy;
  grant.authority_epoch = impl_->manifest.authority_epoch;
  grant.tenant = tenant;
  grant.service_class = service_class;
  grant.facility = facility;
  grant.issued_at = issued_at;
  grant.expires_at = expires_at;
  grant.grant_digest = compute_grant_digest(grant);

  LedgerRecord ledger = impl_->ledger;
  auto ledger_sequence = ledger.sequence.next();
  if (!ledger_sequence.has_value()) {
    return ledger_sequence.error();
  }
  ledger.sequence = ledger_sequence.value();
  for (EnvelopeUsageCounter& counter : ledger.usage_counters) {
    if (counter.envelope_id == envelope_id) {
      counter.uses += 1u;
      break;
    }
  }
  OverrideUsageRecord record;
  record.grant = grant;
  ledger.usage_records.insert(ledger.usage_records.begin(), std::move(record));
  if (ledger.usage_records.size() > kMaxUsageRecords) {
    ledger.usage_records.resize(kMaxUsageRecords);
  }

  ManifestRecord manifest = impl_->manifest;
  auto sequence = manifest.sequence.next();
  if (!sequence.has_value()) {
    return sequence.error();
  }
  manifest.sequence = sequence.value();
  const auto committed = impl_->commit(std::move(manifest), ledger, issued_at);
  if (!committed.has_value()) {
    return committed.error();
  }
  impl_->refresh_snapshot();
  return grant;
}

Result<OverrideStatus> Store::override_status(const EnvelopeId& envelope_id) const {
  if (impl_ == nullptr || !impl_->is_open) {
    return Error(ErrorCode::StoreClosed, "the store is not open");
  }
  std::shared_lock lock(impl_->mutex);
  OverrideStatus status;
  status.envelope_id = envelope_id;
  bool declared = false;
  if (impl_->active_policy != nullptr) {
    const OverrideEnvelope* envelope = find_envelope(*impl_->active_policy, envelope_id);
    if (envelope != nullptr) {
      declared = true;
      status.max_uses = envelope->max_uses;
    }
  }
  for (const EnvelopeUsageCounter& counter : impl_->ledger.usage_counters) {
    if (counter.envelope_id == envelope_id) {
      status.used = counter.uses;
    }
  }
  for (const OverrideUsageRecord& record : impl_->ledger.usage_records) {
    if (record.grant.envelope_id == envelope_id) {
      ++status.retained_usage_records;
    }
  }
  status.remaining = status.max_uses > status.used ? status.max_uses - status.used : 0u;
  if (!declared) {
    return Error(ErrorCode::OverrideUnknownEnvelope,
                 "the active policy does not declare this envelope")
        .with_detail("envelope=" + std::string(envelope_id.value()));
  }
  return status;
}

Result<std::vector<OverrideStatus>> Store::override_statuses() const {
  if (impl_ == nullptr || !impl_->is_open) {
    return Error(ErrorCode::StoreClosed, "the store is not open");
  }
  std::shared_lock lock(impl_->mutex);
  if (impl_->active_policy == nullptr) {
    return Error(ErrorCode::NoActivePolicy, "no policy revision has been activated");
  }
  std::vector<OverrideStatus> statuses;
  for (const OverrideEnvelope& envelope : impl_->active_policy->envelopes) {
    OverrideStatus status;
    status.envelope_id = envelope.envelope_id;
    status.max_uses = envelope.max_uses;
    for (const EnvelopeUsageCounter& counter : impl_->ledger.usage_counters) {
      if (counter.envelope_id == envelope.envelope_id) {
        status.used = counter.uses;
      }
    }
    for (const OverrideUsageRecord& record : impl_->ledger.usage_records) {
      if (record.grant.envelope_id == envelope.envelope_id) {
        ++status.retained_usage_records;
      }
    }
    status.remaining = status.max_uses > status.used ? status.max_uses - status.used : 0u;
    statuses.push_back(std::move(status));
  }
  return statuses;
}

Result<PlacementVerdictSet> Store::evaluate_recorded(const EvaluationInput& input,
                                                     Instant recorded_at,
                                                     EvaluationOptions options) {
  if (impl_ == nullptr || !impl_->is_open) {
    return Error(ErrorCode::StoreClosed, "the store is not open");
  }
  if (impl_->mode != StoreOpenMode::ReadWrite) {
    return Error(ErrorCode::StoreReadOnly, "a read-only store cannot record a verdict");
  }
  if (!recorded_at.is_set()) {
    return Error(ErrorCode::MissingField, "recording a verdict needs an instant");
  }
  auto canonical = canonicalize_evaluation_input(input);
  if (!canonical.has_value()) {
    return canonical.error();
  }
  const Digest digest = request_digest(canonical.value().request);

  std::unique_lock lock(impl_->mutex);

  // A request identity that was already decided is answered with the recorded
  // verdicts before any staleness check runs: that is what makes a lost response
  // safe to retry.
  for (const RecordedEvaluationIndex& entry : impl_->ledger.evaluations) {
    if (!(entry.request_id == canonical.value().request.request_id)) {
      continue;
    }
    if (!digest_equal(entry.request_digest, digest)) {
      return Error(ErrorCode::RequestIdConflict,
                   "this request identity was already decided with different content")
          .with_detail("request=" + std::string(entry.request_id.value()));
    }
    const std::string path =
        join_path(impl_->files.evaluations, evaluation_file_name(entry.record.digest));
    auto loaded = load_record(path, kEvaluationRecordMagic);
    if (!loaded.has_value()) {
      return loaded.error();
    }
    auto payload = decode_evaluation_payload(std::span<const std::uint8_t>(loaded.value().record.payload));
    if (!payload.has_value()) {
      return payload.error();
    }
    PlacementVerdictSet verdicts = std::move(payload.value().verdicts);
    verdicts.replayed = true;
    for (CandidateVerdict& candidate : verdicts.candidates) {
      candidate.replayed = true;
    }
    return verdicts;
  }

  if (impl_->snapshot == nullptr) {
    return Error(ErrorCode::NoActivePolicy,
                 "no policy revision has been activated, so nothing may be evaluated");
  }
  auto verdicts = evaluate(*impl_->snapshot, canonical.value(), options);
  if (!verdicts.has_value()) {
    return verdicts.error();
  }

  RecordedEvaluationPayload payload;
  payload.verdicts = verdicts.value();
  auto encoded = encode_evaluation_payload(payload);
  if (!encoded.has_value()) {
    return encoded.error();
  }
  auto reference = publish_record(
      impl_->files.evaluations, kEvaluationRecordMagic,
      std::span<const std::uint8_t>(encoded.value()),
      [](const Digest& digest) { return evaluation_file_name(digest); },
      [](std::span<const std::uint8_t> bytes) -> Result<void> {
        auto decoded = decode_evaluation_payload(bytes);
        if (!decoded.has_value()) {
          return decoded.error();
        }
        return success;
      });
  if (!reference.has_value()) {
    return reference.error();
  }

  LedgerRecord ledger = impl_->ledger;
  auto ledger_sequence = ledger.sequence.next();
  if (!ledger_sequence.has_value()) {
    return ledger_sequence.error();
  }
  ledger.sequence = ledger_sequence.value();
  RecordedEvaluationIndex entry;
  entry.request_id = canonical.value().request.request_id;
  entry.request_digest = digest;
  entry.record = reference.value();
  entry.recorded_at = recorded_at;
  ledger.evaluations.insert(ledger.evaluations.begin(), std::move(entry));
  if (ledger.evaluations.size() > kMaxEvaluationRecords) {
    ledger.evaluations.resize(kMaxEvaluationRecords);
  }

  ManifestRecord manifest = impl_->manifest;
  auto sequence = manifest.sequence.next();
  if (!sequence.has_value()) {
    return sequence.error();
  }
  manifest.sequence = sequence.value();
  // The watermark advances with the publication, so an older generation cannot
  // be replayed into a fresh decision afterwards.
  manifest.topology_floor = later_of(manifest.topology_floor,
                                     canonical.value().request.generations.topology);
  manifest.failure_domain_floor = later_of(manifest.failure_domain_floor,
                                           canonical.value().request.generations.failure_domain);

  const auto committed = impl_->commit(std::move(manifest), ledger, recorded_at);
  if (!committed.has_value()) {
    return committed.error();
  }
  impl_->refresh_snapshot();
  return verdicts.value();
}

Result<PlacementVerdictSet> Store::recorded_verdicts(const RequestId& request_id) const {
  if (impl_ == nullptr || !impl_->is_open) {
    return Error(ErrorCode::StoreClosed, "the store is not open");
  }
  std::shared_lock lock(impl_->mutex);
  for (const RecordedEvaluationIndex& entry : impl_->ledger.evaluations) {
    if (!(entry.request_id == request_id)) {
      continue;
    }
    const std::string path =
        join_path(impl_->files.evaluations, evaluation_file_name(entry.record.digest));
    auto loaded = load_record(path, kEvaluationRecordMagic);
    if (!loaded.has_value()) {
      return loaded.error();
    }
    auto payload = decode_evaluation_payload(std::span<const std::uint8_t>(loaded.value().record.payload));
    if (!payload.has_value()) {
      return payload.error();
    }
    PlacementVerdictSet verdicts = std::move(payload.value().verdicts);
    verdicts.replayed = true;
    for (CandidateVerdict& candidate : verdicts.candidates) {
      candidate.replayed = true;
    }
    return verdicts;
  }
  return Error(ErrorCode::NotFound, "no evaluation is recorded under this request identity")
      .with_detail("request=" + std::string(request_id.value()));
}

Result<void> Store::compact(Instant committed_at) {
  if (impl_ == nullptr || !impl_->is_open) {
    return Error(ErrorCode::StoreClosed, "the store is not open");
  }
  if (impl_->mode != StoreOpenMode::ReadWrite) {
    return Error(ErrorCode::StoreReadOnly, "a read-only store cannot compact");
  }
  if (!committed_at.is_set()) {
    return Error(ErrorCode::MissingField, "compacting a store needs an instant");
  }
  std::unique_lock lock(impl_->mutex);
  LedgerRecord ledger = impl_->ledger;
  auto ledger_sequence = ledger.sequence.next();
  if (!ledger_sequence.has_value()) {
    return ledger_sequence.error();
  }
  ledger.sequence = ledger_sequence.value();
  ManifestRecord manifest = impl_->manifest;
  auto sequence = manifest.sequence.next();
  if (!sequence.has_value()) {
    return sequence.error();
  }
  manifest.sequence = sequence.value();
  return impl_->commit(std::move(manifest), ledger, committed_at);
}

std::string store_format_description() {
  return "store v1: manifest.fpp (head) + manifest.fpp.bak (predecessor), policies/, ledger/ and "
         "evaluations/ hold immutable framed records; the head is published last and every record "
         "it references is flushed and read back beforehand";
}

}  // namespace dccp::facility_placement_policy
