// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs.

#ifndef DCCP_FACILITY_PLACEMENT_POLICY_STORE_HPP
#define DCCP_FACILITY_PLACEMENT_POLICY_STORE_HPP

#include <cstddef>
#include <cstdint>
#include <memory>
#include <string>
#include <vector>

#include "dccp/facility_placement_policy/digest.hpp"
#include "dccp/facility_placement_policy/evaluate.hpp"
#include "dccp/facility_placement_policy/records.hpp"
#include "dccp/facility_placement_policy/result.hpp"
#include "dccp/facility_placement_policy/strong_id.hpp"
#include "dccp/facility_placement_policy/time.hpp"
#include "dccp/facility_placement_policy/verdict.hpp"

/// Durable state: the canonical policy revision, the authority epoch that fences
/// it, the override ledger and the anti-rollback watermarks.
///
/// Guarantees:
///
///  * every commit is a single atomic publication of the head file; a crash
///    before it leaves the previous head authoritative, and a crash after it
///    leaves the new one authoritative, with no third possibility;
///  * a commit stages, flushes, reads back and verifies the records it
///    references before it publishes the head that references them;
///  * opening verifies the whole referenced chain; a store whose state cannot be
///    verified is refused, never repaired by guessing and never silently started
///    empty;
///  * exactly one writer at a time, enforced with a real operating-system file
///    lock that the kernel releases when the process dies;
///  * read-only opens take a shared lock and obey exactly the same integrity and
///    rollback rules as a read-write open;
///  * a new policy revision bumps the authority epoch in the same publication
///    that makes it active, so old authority is fenced atomically.
namespace dccp::facility_placement_policy {

enum class StoreOpenMode : std::uint8_t {
  /// Shared lock; every mutating operation is refused.
  ReadOnly = 0,
  /// Exclusive lock; the only mode in which authority can change.
  ReadWrite = 1,
};

/// Creates a new store. Fails when the directory already holds durable state.
Result<void> initialize_store(const std::string& directory, const StoreId& store_id,
                              Instant created_at);

/// What the store currently holds.
struct StoreStatus {
  StoreId store_id;
  StoreSequence sequence;
  AuthorityEpoch authority_epoch;
  PolicyBinding policy;
  TopologyGeneration topology_floor;
  FailureDomainGeneration failure_domain_floor;
  std::size_t retained_policy_revisions = 0;
  std::size_t usage_counters = 0;
  std::size_t usage_records = 0;
  std::size_t recorded_evaluations = 0;
  Instant created_at;
  Instant last_commit_at;
  /// Records on disk that the head and its predecessor do not reference: either
  /// a publication that was never referenced, or a file that could not be
  /// removed. They are inert, and compact() retries the removal.
  std::size_t unreferenced_records = 0;
  /// True when the head could not be read and the previous head was adopted.
  /// The store is still fully verified; this only reports that recovery chose
  /// the older of exactly two verifiable heads.
  bool recovered_from_backup = false;
  /// True when a stale copy of the head was found and ignored.
  bool stale_head_ignored = false;
};

/// The state of one override envelope.
struct OverrideStatus {
  EnvelopeId envelope_id;
  std::uint32_t max_uses = 0;
  std::uint32_t used = 0;
  std::uint32_t remaining = 0;
  std::size_t retained_usage_records = 0;
};

/// A connection to one durable store.
///
/// The store is internally synchronised: read paths take a shared lock on its
/// state and the commit path takes an exclusive lock. No lock is ever upgraded
/// in place, no callback is invoked while the lock is held, and the library
/// starts no threads. Two threads may therefore share one Store safely, and two
/// processes may not both hold it for writing.
class Store {
 public:
  Store() noexcept;
  ~Store();

  Store(Store&& other) noexcept;
  Store& operator=(Store&& other) noexcept;
  Store(const Store&) = delete;
  Store& operator=(const Store&) = delete;

  /// Opens an existing store, verifying all durable state.
  static Result<Store> open(const std::string& directory, StoreOpenMode mode);

  bool is_open() const noexcept;
  StoreOpenMode mode() const noexcept;

  /// Current status. Takes a shared lock and reads only memory that was verified
  /// when the store was opened or committed.
  StoreStatus status() const;

  /// The active policy revision as an immutable snapshot, including the
  /// watermarks a request must not be older than.
  Result<PolicySnapshot> snapshot() const;

  /// Reads a policy revision held by the store.
  Result<PolicyDocument> read_policy(PolicyRevision revision) const;

  /// Validates a policy, stages it as a new immutable revision, and publishes it
  /// as the active policy with a new authority epoch. Refused when the store is
  /// read-only, when the revision is not exactly one greater than the active
  /// revision, or when validation fails.
  Result<PolicyBinding> activate_policy(const PolicyDocument& document, Instant committed_at);

  /// Issues a grant for one use of one envelope, scoped to one tenant, service
  /// class and facility. Consumes one use durably. Replaying the same usage
  /// identity with an identical binding returns the same grant without
  /// consuming another use; replaying it with a different binding is refused.
  Result<OverrideGrant> authorize_override(const EnvelopeId& envelope_id,
                                           const PrincipalId& principal,
                                           const UsageId& usage_id, TenantId tenant,
                                           ServiceClassId service_class,
                                           const FacilityId& facility, Instant issued_at);

  /// The state of one envelope's usage.
  Result<OverrideStatus> override_status(const EnvelopeId& envelope_id) const;

  /// Evaluates and records the result under the request identity.
  ///
  /// A request identity that was already decided is answered with the recorded
  /// verdicts before any staleness check, which is what makes a lost response
  /// safe to retry. The same identity carrying different content is refused.
  Result<PlacementVerdictSet> evaluate_recorded(const EvaluationInput& input,
                                                Instant recorded_at,
                                                EvaluationOptions options = {});

  /// Reads a recorded evaluation without evaluating anything.
  Result<PlacementVerdictSet> recorded_verdicts(const RequestId& request_id) const;

  /// Rewrites the ledger as a compact snapshot, dropping nothing that is still
  /// referenced, and publishes it through the ordinary commit path. The result
  /// is a store the ordinary reader accepts, because the ordinary reader's
  /// verification runs against the staged files before publication.
  Result<void> compact(Instant committed_at);

  /// Every envelope the active policy declares, with its usage.
  Result<std::vector<OverrideStatus>> override_statuses() const;

  /// Closes the store, releasing the file lock. Idempotent.
  void close() noexcept;

 private:
  struct Impl;
  std::unique_ptr<Impl> impl_;
};

/// A short, stable description of the on-disk format, for documentation and for
/// the inspection tool.
std::string store_format_description();

}  // namespace dccp::facility_placement_policy

#endif  // DCCP_FACILITY_PLACEMENT_POLICY_STORE_HPP
