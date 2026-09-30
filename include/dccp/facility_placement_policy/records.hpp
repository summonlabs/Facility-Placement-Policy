// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs.

#ifndef DCCP_FACILITY_PLACEMENT_POLICY_RECORDS_HPP
#define DCCP_FACILITY_PLACEMENT_POLICY_RECORDS_HPP

#include <cstdint>
#include <string>
#include <vector>

#include "dccp/facility_placement_policy/digest.hpp"
#include "dccp/facility_placement_policy/evaluate.hpp"
#include "dccp/facility_placement_policy/generation.hpp"
#include "dccp/facility_placement_policy/limits.hpp"
#include "dccp/facility_placement_policy/result.hpp"
#include "dccp/facility_placement_policy/strong_id.hpp"
#include "dccp/facility_placement_policy/time.hpp"
#include "dccp/facility_placement_policy/verdict.hpp"

/// The shape of durable state.
///
/// Every file in a store is a framed record:
///
///   magic           u64   little endian, per record kind
///   format_version  u32   little endian, currently kStoreFormatVersion
///   kind            u32   little endian, reserved: must be zero
///   reserved        u32   little endian, reserved: must be zero
///   payload_bytes   u64   little endian, at most kMaxRecordBytes
///   payload         payload_bytes bytes
///   crc32c          u32   little endian, over the payload bytes only
///   digest          u8[32] SHA-256 over magic..crc32c inclusive
///
/// The header is 28 bytes and the trailer is 36, so the file length must equal
/// 64 + payload_bytes exactly. A file that is short, long, wrongly framed or
/// whose checksum or digest does not verify is a corruption: the reader refuses
/// it instead of guessing which part was meant.
namespace dccp::facility_placement_policy {

/// Length of the framed record header, in bytes.
inline constexpr std::size_t kRecordHeaderBytes = 28;

/// Length of the framed record trailer, in bytes.
inline constexpr std::size_t kRecordTrailerBytes = 36;

/// Length of the complete frame around an empty payload.
inline constexpr std::size_t kRecordFrameOverhead = kRecordHeaderBytes + kRecordTrailerBytes;

/// A reference to an immutable record held elsewhere in the store.
struct RecordRef {
  Digest digest{};
  std::uint64_t bytes = 0;

  friend bool operator==(const RecordRef& lhs, const RecordRef& rhs) noexcept {
    return lhs.bytes == rhs.bytes && digest_equal(lhs.digest, rhs.digest);
  }
};

/// A policy revision held by the store.
struct RetainedPolicy {
  PolicyRevision revision;
  PolicyId policy_id;
  RecordRef record;

  friend bool operator==(const RetainedPolicy& lhs, const RetainedPolicy& rhs) noexcept {
    return lhs.revision == rhs.revision && lhs.policy_id == rhs.policy_id &&
           lhs.record == rhs.record;
  }
};

/// The store head. Published last, and the only file whose replacement makes a
/// commit visible.
struct ManifestRecord {
  StoreId store_id;
  /// Monotonic commit sequence. A head with a lower sequence than one that has
  /// already been observed is a rollback and is refused.
  StoreSequence sequence;
  AuthorityEpoch authority_epoch;
  /// False until the first policy revision is activated. A store exists before
  /// it has authority, and while it has none every evaluation is refused with
  /// ErrorCode::NoActivePolicy rather than allowed by default.
  bool has_active_policy = false;
  PolicyBinding policy;
  RetainedPolicy active;
  /// Every policy revision still readable, sorted by revision, including the
  /// active one.
  std::vector<RetainedPolicy> retained;
  RecordRef ledger;
  TopologyGeneration topology_floor;
  FailureDomainGeneration failure_domain_floor;
  Instant created_at;
  Instant last_commit_at;
};

/// How many uses of one envelope have been granted. This counter is the
/// authority for the envelope's limit; it is never reconstructed from the
/// retained usage records, and it is never evicted while the envelope is
/// referenced by a retained policy.
struct EnvelopeUsageCounter {
  EnvelopeId envelope_id;
  std::uint32_t uses = 0;

  friend bool operator==(const EnvelopeUsageCounter& lhs,
                         const EnvelopeUsageCounter& rhs) noexcept {
    return lhs.envelope_id == rhs.envelope_id && lhs.uses == rhs.uses;
  }
};

/// One issued grant, retained so that a lost response can be answered with the
/// same grant instead of consuming another use.
struct OverrideUsageRecord {
  OverrideGrant grant;

  friend bool operator==(const OverrideUsageRecord& lhs,
                         const OverrideUsageRecord& rhs) noexcept {
    return lhs.grant.usage_id == rhs.grant.usage_id &&
           lhs.grant.envelope_id == rhs.grant.envelope_id &&
           digest_equal(lhs.grant.grant_digest, rhs.grant.grant_digest);
  }
};

/// Where a recorded evaluation's payload lives. The ledger keeps the index; the
/// verdicts themselves are an immutable content-addressed record, so the ledger
/// snapshot stays small enough to rewrite on every commit.
struct RecordedEvaluationIndex {
  RequestId request_id;
  Digest request_digest{};
  RecordRef record;
  Instant recorded_at;

  friend bool operator==(const RecordedEvaluationIndex& lhs,
                         const RecordedEvaluationIndex& rhs) noexcept {
    return lhs.request_id == rhs.request_id &&
           digest_equal(lhs.request_digest, rhs.request_digest) && lhs.record == rhs.record;
  }
};

/// The ledger: everything durable that is not the head or a policy revision.
struct LedgerRecord {
  StoreSequence sequence;
  /// Sorted by envelope identity.
  std::vector<EnvelopeUsageCounter> usage_counters;
  /// Most recent first, bounded by kMaxUsageRecords.
  std::vector<OverrideUsageRecord> usage_records;
  /// Most recent first, bounded by kMaxEvaluationRecords.
  std::vector<RecordedEvaluationIndex> evaluations;
};

/// A recorded evaluation payload: the verdicts exactly as they were issued.
struct RecordedEvaluationPayload {
  PlacementVerdictSet verdicts;
};

/// Number of usage records retained in the ledger.
inline constexpr std::size_t kMaxUsageRecords = 512;

/// Number of recorded evaluations retained in the ledger.
inline constexpr std::size_t kMaxEvaluationRecords = 64;

}  // namespace dccp::facility_placement_policy

#endif  // DCCP_FACILITY_PLACEMENT_POLICY_RECORDS_HPP
