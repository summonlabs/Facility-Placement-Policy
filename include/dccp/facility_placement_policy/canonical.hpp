// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs.

#ifndef DCCP_FACILITY_PLACEMENT_POLICY_CANONICAL_HPP
#define DCCP_FACILITY_PLACEMENT_POLICY_CANONICAL_HPP

#include <cstdint>
#include <span>
#include <vector>

#include "dccp/facility_placement_policy/digest.hpp"
#include "dccp/facility_placement_policy/evaluate.hpp"
#include "dccp/facility_placement_policy/policy.hpp"
#include "dccp/facility_placement_policy/records.hpp"
#include "dccp/facility_placement_policy/request.hpp"
#include "dccp/facility_placement_policy/result.hpp"
#include "dccp/facility_placement_policy/verdict.hpp"

/// Canonical serialization.
///
/// The canonical encoding is the digested and persisted representation of every
/// model type. It is deliberately not a text format and not a self-describing
/// one: it is a fixed, versioned, little-endian layout whose only job is to be
/// unambiguous, bounded and identical on every platform for equivalent inputs.
///
/// Properties the test suite holds this code to:
///
///  * encode(decode(bytes)) == bytes for any bytes the decoder accepted, so a
///    decoded value is always exactly the value that was digested;
///  * decode never reads past a declared length, never allocates from an
///    unvalidated length, and never accepts a non-zero reserved field;
///  * every length is bounded before it is used, and every count is checked
///    against the limits in limits.hpp.
namespace dccp::facility_placement_policy {

using ByteBuffer = std::vector<std::uint8_t>;

/// A framed durable record as it was read from disk.
struct FramedRecord {
  std::uint64_t magic = 0;
  std::uint32_t format_version = 0;
  ByteBuffer payload;
  /// SHA-256 over the entire framed record. This is the record's identity and
  /// the value a RecordRef carries.
  Digest digest{};
};

/// Wraps a payload in the framed record envelope described in records.hpp.
Result<ByteBuffer> frame_record(std::uint64_t magic, std::span<const std::uint8_t> payload);

/// Validates a framed record and returns its parts. Rejects a short or long
/// file, a foreign magic, an unknown version, a non-zero reserved field, a
/// payload larger than kMaxRecordBytes, a checksum mismatch and a digest
/// mismatch, in that order.
Result<FramedRecord> unframe_record(std::span<const std::uint8_t> bytes);

/// The identity of a framed record: SHA-256 over every byte of the record up to
/// but not including its trailing digest field. A digest cannot cover itself, so
/// this is exactly the value stored in the trailer, and it is what a RecordRef
/// carries.
Digest framed_record_digest(std::span<const std::uint8_t> bytes) noexcept;

Result<ByteBuffer> encode_policy(const PolicyDocument& document);
Result<PolicyDocument> decode_policy(std::span<const std::uint8_t> bytes);

Result<ByteBuffer> encode_request(const PlacementRequest& request);
Result<PlacementRequest> decode_request(std::span<const std::uint8_t> bytes);

Result<ByteBuffer> encode_verdict_set(const PlacementVerdictSet& verdicts);
Result<PlacementVerdictSet> decode_verdict_set(std::span<const std::uint8_t> bytes);

Result<ByteBuffer> encode_candidate_verdict(const CandidateVerdict& verdict);
Result<CandidateVerdict> decode_candidate_verdict(std::span<const std::uint8_t> bytes);

Result<ByteBuffer> encode_grant(const OverrideGrant& grant);
Result<OverrideGrant> decode_grant(std::span<const std::uint8_t> bytes);

Result<ByteBuffer> encode_envelope(const OverrideEnvelope& envelope);

Result<ByteBuffer> encode_manifest(const ManifestRecord& manifest);
Result<ManifestRecord> decode_manifest(std::span<const std::uint8_t> bytes);

Result<ByteBuffer> encode_ledger(const LedgerRecord& ledger);
Result<LedgerRecord> decode_ledger(std::span<const std::uint8_t> bytes);

Result<ByteBuffer> encode_evaluation_payload(const RecordedEvaluationPayload& payload);
Result<RecordedEvaluationPayload> decode_evaluation_payload(std::span<const std::uint8_t> bytes);

/// Digest of one override envelope, as it appears in an envelope-scoped grant.
Digest envelope_digest(const OverrideEnvelope& envelope);

/// Digest of one candidate verdict, with the digest field and the replay marker
/// excluded.
Digest compute_verdict_digest(const CandidateVerdict& verdict);

/// Digest of one policy snapshot's watermark set, used by the store to detect a
/// change that must fence prior authority.
Digest compute_watermark_digest(TopologyGeneration topology, FailureDomainGeneration failure_domain);

}  // namespace dccp::facility_placement_policy

#endif  // DCCP_FACILITY_PLACEMENT_POLICY_CANONICAL_HPP
