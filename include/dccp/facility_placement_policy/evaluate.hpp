// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs.

#ifndef DCCP_FACILITY_PLACEMENT_POLICY_EVALUATE_HPP
#define DCCP_FACILITY_PLACEMENT_POLICY_EVALUATE_HPP

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

#include "dccp/facility_placement_policy/digest.hpp"
#include "dccp/facility_placement_policy/facility.hpp"
#include "dccp/facility_placement_policy/generation.hpp"
#include "dccp/facility_placement_policy/policy.hpp"
#include "dccp/facility_placement_policy/request.hpp"
#include "dccp/facility_placement_policy/result.hpp"
#include "dccp/facility_placement_policy/time.hpp"
#include "dccp/facility_placement_policy/verdict.hpp"

namespace dccp::facility_placement_policy {

/// The exact policy revision that governs, together with the watermarks the
/// runtime has already observed from the authorities it consumes.
///
/// A snapshot is immutable. Evaluation never reads the store again, so a
/// concurrent activation cannot change the policy halfway through a batch.
struct PolicySnapshot {
  PolicyDocument policy;
  AuthorityEpoch authority_epoch;
  StoreSequence store_sequence;
  /// The greatest topology generation this runtime has already accepted. A
  /// request that binds an older one is refused, which is what stops an old
  /// topology snapshot from being replayed into a fresh grant.
  TopologyGeneration topology_floor;
  /// The same anti-rollback watermark for failure-domain membership.
  FailureDomainGeneration failure_domain_floor;

  /// The identity of the policy revision this snapshot governs. Not noexcept:
  /// identities own their text.
  PolicyBinding binding() const;
};

/// Validates and canonicalises a policy, then adopts it as a snapshot.
Result<PolicySnapshot> make_policy_snapshot(PolicyDocument policy, AuthorityEpoch authority_epoch,
                                            StoreSequence store_sequence,
                                            TopologyGeneration topology_floor,
                                            FailureDomainGeneration failure_domain_floor);

/// A granted exception: the durable, attributable, scoped and expiring record of
/// one exercise of one envelope.
///
/// The grant is issued by the store, which is the only thing that can count a
/// use. Evaluation only consumes it, and checks that it is still bound to the
/// policy revision, the authority epoch and the scope it was issued for.
struct OverrideGrant {
  EnvelopeId envelope_id;
  /// Identity of the envelope as it was when the grant was issued. Re-issuing
  /// the envelope with a different scope changes this digest, which invalidates
  /// every outstanding grant, exactly like a policy change does.
  Digest envelope_digest{};
  PrincipalId principal;
  UsageId usage_id;
  PolicyBinding policy;
  AuthorityEpoch authority_epoch;
  TenantId tenant;
  ServiceClassId service_class;
  FacilityId facility;
  Instant issued_at;
  Instant expires_at;
  /// SHA-256 over the canonical encoding of this grant with the digest field
  /// excluded.
  Digest grant_digest{};
};

/// Computes the canonical digest of a grant.
Digest compute_grant_digest(const OverrideGrant& grant);

/// Recomputes and stores the grant digest.
Result<OverrideGrant> canonicalize_grant(OverrideGrant grant);

/// True when the grant's own digest verifies.
bool verify_grant_digest(const OverrideGrant& grant);

/// Everything one evaluation needs.
struct EvaluationInput {
  PlacementRequest request;
  /// At most one grant per candidate facility. The tenant and service class must
  /// match the request: an exception issued for one scope is never applied to
  /// another.
  std::vector<OverrideGrant> grants;
};

/// Sorts grants and validates the input.
Result<EvaluationInput> canonicalize_evaluation_input(EvaluationInput input);

/// Knobs that change what is refused. They never change what is eligible.
struct EvaluationOptions {
  /// Refuse a request whose bound generations are older than the snapshot's
  /// watermarks. On by default; turning it off is for replay of historical
  /// evidence and is recorded in the verdict, not silently ignored.
  bool enforce_generation_floor = true;
};

/// Evaluates every candidate in the request against the snapshot.
///
/// The result is indexed by candidate identity and sorted, so permuting the
/// candidates in the request produces byte-identical output. Each candidate is
/// evaluated against the same immutable evidence: no candidate's outcome depends
/// on another candidate in the batch, and no candidate is "placed" before the
/// next one is considered.
Result<PlacementVerdictSet> evaluate(const PolicySnapshot& snapshot, const EvaluationInput& input,
                                     EvaluationOptions options = {});

/// Evaluates a single candidate. Equivalent to calling evaluate() and selecting
/// one entry, and provided so callers that need one decision do not build a
/// batch.
Result<CandidateVerdict> evaluate_candidate(const PolicySnapshot& snapshot,
                                            const EvaluationInput& input,
                                            const CandidateId& candidate_id,
                                            EvaluationOptions options = {});

/// Renders a decision as a single stable word, for shell use: "eligible" or
/// "ineligible".
std::string_view decision_token(Decision decision) noexcept;

}  // namespace dccp::facility_placement_policy

#endif  // DCCP_FACILITY_PLACEMENT_POLICY_EVALUATE_HPP
