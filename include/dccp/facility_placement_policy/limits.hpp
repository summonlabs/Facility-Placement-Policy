// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs.

#ifndef DCCP_FACILITY_PLACEMENT_POLICY_LIMITS_HPP
#define DCCP_FACILITY_PLACEMENT_POLICY_LIMITS_HPP

#include <cstddef>
#include <cstdint>

/// Every bound the runtime enforces against untrusted input.
///
/// The values are part of the public contract: a caller can size its own input
/// against them, and a document that exceeds one is rejected with
/// ErrorCode::LimitExceeded (or a more specific code) instead of being truncated
/// or partially accepted. Nothing in the library sizes an allocation from an
/// untrusted length without first checking it against one of these bounds.
namespace dccp::facility_placement_policy {

/// Longest identifier accepted anywhere (identities, rule names, tokens).
inline constexpr std::size_t kMaxIdentifierBytes = 128;

/// Longest free text field (rule description, override justification).
inline constexpr std::size_t kMaxTextBytes = 1024;

/// Largest input document (policy, request, verdict, grant) the text reader and
/// the durable reader will accept, in bytes. The multiplication is performed in
/// the widest type the constant needs, so the bound does not depend on the width
/// of the type the literal happened to have.
inline constexpr std::size_t kMaxDocumentBytes = static_cast<std::size_t>(8) * 1024u * 1024u;

/// Largest single durable record payload, in bytes.
inline constexpr std::size_t kMaxRecordBytes = static_cast<std::size_t>(32) * 1024u * 1024u;

/// Longest single input line, in bytes, before the reader reports a defect.
inline constexpr std::size_t kMaxLineBytes = static_cast<std::size_t>(64) * 1024u;

inline constexpr std::size_t kMaxRulesPerPolicy = 4096;
inline constexpr std::size_t kMaxConstraintsPerRule = 64;
inline constexpr std::size_t kMaxEnvelopesPerPolicy = 1024;
inline constexpr std::size_t kMaxSelectorEntries = 512;
inline constexpr std::size_t kMaxSetEntries = 4096;

inline constexpr std::size_t kMaxCandidatesPerRequest = 4096;
inline constexpr std::size_t kMaxPlacedInstances = 200000;
inline constexpr std::size_t kMaxMaintenanceExposures = 200000;
inline constexpr std::size_t kMaxFacilityAttributes = 32;
inline constexpr std::size_t kMaxFailureDomainsPerPlacement = 16;

/// Override envelope usage ceiling. A request may not ask for more than this,
/// and a counter never wraps.
inline constexpr std::uint32_t kMaxOverrideUses = 1000000;

/// Ledger entries retained in the durable store. Entries are evicted oldest
/// first once the bound is reached; override usage counters are never evicted
/// while the envelope they belong to is still referenced by the active policy.
inline constexpr std::size_t kMaxLedgerEntries = 4096;

/// Policy revisions retained in the durable store, including the active one.
inline constexpr std::size_t kMaxRetainedPolicyRevisions = 16;

/// Release note floor: a store never claims more usage records than this.
inline constexpr std::size_t kMaxUsageRecordsPerEnvelope = 4096;

/// Format versions. A reader rejects any other value; it never guesses.
inline constexpr std::uint32_t kTextFormatVersion = 1;
inline constexpr std::uint32_t kStoreFormatVersion = 1;
inline constexpr std::uint32_t kPayloadFormatVersion = 1;

/// Violations reported for one candidate. A verdict stays bounded so that the
/// ledger index stays small; the count of violations is always reported, and
/// truncation is visible rather than silent.
inline constexpr std::size_t kMaxViolationsPerVerdict = 64;

/// Magic numbers for durable records, spelled in ASCII so that a hex dump of a
/// corrupt file says what it was meant to be. They are written little endian,
/// so the first eight bytes of a manifest read "FPP1MANI".
inline constexpr std::uint64_t kManifestMagic = 0x494E414D31504646ULL;    // "FPP1MANI"
inline constexpr std::uint64_t kPolicyRecordMagic = 0x494C4F5031504646ULL;  // "FPP1POLI"
inline constexpr std::uint64_t kLedgerRecordMagic = 0x4744454C31504646ULL;  // "FPP1LEDG"
inline constexpr std::uint64_t kGrantRecordMagic = 0x544E524731504646ULL;   // "FPP1GRNT"
inline constexpr std::uint64_t kEvaluationRecordMagic = 0x4C41564531504646ULL;  // "FPP1EVAL"

}  // namespace dccp::facility_placement_policy

#endif  // DCCP_FACILITY_PLACEMENT_POLICY_LIMITS_HPP
