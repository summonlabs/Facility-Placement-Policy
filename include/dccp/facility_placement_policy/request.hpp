// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs.

#ifndef DCCP_FACILITY_PLACEMENT_POLICY_REQUEST_HPP
#define DCCP_FACILITY_PLACEMENT_POLICY_REQUEST_HPP

#include <optional>
#include <string>
#include <vector>

#include "dccp/facility_placement_policy/digest.hpp"
#include "dccp/facility_placement_policy/facility.hpp"
#include "dccp/facility_placement_policy/generation.hpp"
#include "dccp/facility_placement_policy/result.hpp"
#include "dccp/facility_placement_policy/strong_id.hpp"
#include "dccp/facility_placement_policy/time.hpp"

/// A placement request: what a caller wants decided, together with the exact
/// evidence the decision must be made from.
///
/// The request carries its own evidence rather than reaching for ambient state,
/// for three reasons: an evaluation is then a pure function of its inputs, two
/// runs over the same request cannot disagree, and the evidence set can be
/// digested and bound into the verdict.
namespace dccp::facility_placement_policy {

/// One proposed placement.
struct CandidatePlacement {
  CandidateId candidate_id;
  FacilityLocation location;
};

/// Everything one evaluation decides on.
struct PlacementRequest {
  RequestId request_id;
  TenantId tenant;
  ServiceClassId service_class;
  /// The instant the decision is being made at. Never read from a clock.
  Instant requested_at;
  EvidenceGenerations generations;
  /// Facility facts for every candidate, sorted by facility identity. A
  /// candidate whose facility is not here is refused; facility metadata is never
  /// inferred from the candidate's own fields.
  std::vector<FacilityRecord> facilities;
  /// At least one, unique identities, sorted by candidate identity.
  std::vector<CandidatePlacement> candidates;
  OccupancyEvidence occupancy;
  MaintenanceEvidence maintenance;
};

/// Sorts every set into canonical order and validates the request.
Result<PlacementRequest> canonicalize_request(PlacementRequest request);

/// Validates a request that is already in canonical order, including every
/// bound limit, identity, generation and cross-reference.
Result<void> validate_request_shape(const PlacementRequest& request);

/// Finds the facility record for an identity, or nullptr.
const FacilityRecord* find_facility(const PlacementRequest& request,
                                    const FacilityId& facility) noexcept;

/// Finds a candidate by identity, or nullptr.
const CandidatePlacement* find_candidate(const PlacementRequest& request,
                                         const CandidateId& candidate_id) noexcept;

/// Digest of the whole canonical request. This is the identity of a submitted
/// request, used to detect a replayed request identity that carries different
/// content.
Digest request_digest(const PlacementRequest& request);

/// Digest of exactly the evidence one candidate's verdict depends on: every
/// request-level fact plus that candidate, and nothing about the other
/// candidates. Adding an unrelated candidate to a batch therefore cannot
/// invalidate an already issued verdict.
Digest candidate_evidence_digest(const PlacementRequest& request,
                                 const CandidatePlacement& candidate);

}  // namespace dccp::facility_placement_policy

#endif  // DCCP_FACILITY_PLACEMENT_POLICY_REQUEST_HPP
