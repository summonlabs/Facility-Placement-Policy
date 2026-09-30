// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs.

#include "dccp/facility_placement_policy/request.hpp"

#include <algorithm>
#include <cstddef>
#include <string>

#include "dccp/facility_placement_policy/text_util.hpp"
#include "internal_util.hpp"

namespace dccp::facility_placement_policy {
namespace {

void sort_location(FacilityLocation& location) {
  std::sort(location.failure_domains.begin(), location.failure_domains.end());
}

bool attributes_less(const std::pair<FacilityAttributeKey, AttributeValue>& lhs,
                     const std::pair<FacilityAttributeKey, AttributeValue>& rhs) {
  return lhs.first < rhs.first;
}

Result<void> validate_location(const FacilityLocation& location, std::string_view what) {
  if (location.facility.empty()) {
    return Error(ErrorCode::MissingField, "a placement needs a facility identity")
        .with_subject(std::string(what));
  }
  if (location.failure_domains.size() > kMaxFailureDomainsPerPlacement) {
    return Error(ErrorCode::LimitExceeded,
                 "a placement names more failure domains than the limit allows")
        .with_subject(std::string(what))
        .with_detail("limit=" + std::to_string(kMaxFailureDomainsPerPlacement) +
                     " actual=" + std::to_string(location.failure_domains.size()));
  }
  for (std::size_t index = 1; index < location.failure_domains.size(); ++index) {
    if (location.failure_domains[index - 1].first == location.failure_domains[index].first) {
      return Error(ErrorCode::DuplicateField,
                   "a placement names the same failure domain kind twice")
          .with_subject(std::string(what))
          .with_detail("kind=" +
                       std::string(failure_domain_kind_name(location.failure_domains[index].first)));
    }
  }
  return success;
}

}  // namespace

Result<PlacementRequest> canonicalize_request(PlacementRequest request) {
  for (FacilityRecord& facility : request.facilities) {
    std::sort(facility.attributes.begin(), facility.attributes.end(), attributes_less);
  }
  std::sort(request.facilities.begin(), request.facilities.end(),
            [](const FacilityRecord& lhs, const FacilityRecord& rhs) {
              return lhs.facility < rhs.facility;
            });
  for (CandidatePlacement& candidate : request.candidates) {
    sort_location(candidate.location);
  }
  std::sort(request.candidates.begin(), request.candidates.end(),
            [](const CandidatePlacement& lhs, const CandidatePlacement& rhs) {
              return lhs.candidate_id < rhs.candidate_id;
            });
  for (PlacedInstance& instance : request.occupancy.instances) {
    sort_location(instance.location);
  }
  std::sort(request.occupancy.instances.begin(), request.occupancy.instances.end(),
            [](const PlacedInstance& lhs, const PlacedInstance& rhs) {
              return lhs.placement_id < rhs.placement_id;
            });
  std::sort(request.maintenance.exposures.begin(), request.maintenance.exposures.end(),
            [](const MaintenanceExposure& lhs, const MaintenanceExposure& rhs) {
              return lhs.exposure_id < rhs.exposure_id;
            });

  const auto validation = validate_request_shape(request);
  if (!validation.has_value()) {
    return validation.error();
  }
  return request;
}

Result<void> validate_request_shape(const PlacementRequest& request) {
  if (request.request_id.empty()) {
    return Error(ErrorCode::MissingField, "a request needs an identity");
  }
  if (request.tenant.empty()) {
    return Error(ErrorCode::MissingField, "a request needs a tenant");
  }
  if (request.service_class.empty()) {
    return Error(ErrorCode::MissingField, "a request needs a service class");
  }
  if (!evidence_generations_complete(request.generations)) {
    return Error(ErrorCode::EvidenceGenerationAbsent,
                 "every evaluation binds to the generation of every authority it consumes")
        .with_detail("absent=" + std::string(first_absent_generation(request.generations)));
  }

  if (request.facilities.size() > kMaxSetEntries) {
    return Error(ErrorCode::LimitExceeded, "request describes more facilities than the limit allows")
        .with_detail("limit=" + std::to_string(kMaxSetEntries));
  }
  for (std::size_t index = 0; index < request.facilities.size(); ++index) {
    const FacilityRecord& facility = request.facilities[index];
    if (facility.facility.empty()) {
      return Error(ErrorCode::MissingField, "a facility record needs an identity");
    }
    if (facility.attributes.size() > kMaxFacilityAttributes) {
      return Error(ErrorCode::LimitExceeded,
                   "a facility records more attributes than the limit allows")
          .with_detail("facility=" + std::string(facility.facility.value()) +
                       " limit=" + std::to_string(kMaxFacilityAttributes));
    }
    for (std::size_t attribute_index = 0; attribute_index < facility.attributes.size();
         ++attribute_index) {
      const auto& entry = facility.attributes[attribute_index];
      if (!attribute_value_matches(entry.first, entry.second)) {
        return Error(ErrorCode::InvalidAttributeValue,
                     "a facility attribute carries a value of the wrong kind")
            .with_detail("facility=" + std::string(facility.facility.value()) + " attribute=" +
                         std::string(facility_attribute_key_name(entry.first)));
      }
      if (attribute_index > 0 &&
          facility.attributes[attribute_index - 1].first == entry.first) {
        return Error(ErrorCode::DuplicateField, "a facility states the same attribute twice")
            .with_detail("facility=" + std::string(facility.facility.value()) + " attribute=" +
                         std::string(facility_attribute_key_name(entry.first)));
      }
    }
    if (index > 0 && request.facilities[index - 1].facility == facility.facility) {
      return Error(ErrorCode::DuplicateField, "two facility records share an identity")
          .with_detail("facility=" + std::string(facility.facility.value()));
    }
  }

  if (request.candidates.empty()) {
    return Error(ErrorCode::EmptyRequest, "a request needs at least one candidate");
  }
  if (request.candidates.size() > kMaxCandidatesPerRequest) {
    return Error(ErrorCode::LimitExceeded, "request has more candidates than the limit allows")
        .with_detail("limit=" + std::to_string(kMaxCandidatesPerRequest) +
                     " actual=" + std::to_string(request.candidates.size()));
  }
  for (std::size_t index = 0; index < request.candidates.size(); ++index) {
    const CandidatePlacement& candidate = request.candidates[index];
    if (candidate.candidate_id.empty()) {
      return Error(ErrorCode::MissingField, "a candidate needs an identity");
    }
    const auto location_result =
        validate_location(candidate.location, std::string(candidate.candidate_id.value()));
    if (!location_result.has_value()) {
      return location_result.error();
    }
    if (index > 0 && request.candidates[index - 1].candidate_id == candidate.candidate_id) {
      return Error(ErrorCode::CandidateDuplicateId, "two candidates share an identity")
          .with_detail("candidate=" + std::string(candidate.candidate_id.value()));
    }
    if (find_facility(request, candidate.location.facility) == nullptr) {
      return Error(ErrorCode::NotFound,
                   "a candidate names a facility the request does not describe; facility "
                   "metadata is never inferred from a candidate")
          .with_detail("candidate=" + std::string(candidate.candidate_id.value()) + " facility=" +
                       std::string(candidate.location.facility.value()));
    }
  }

  if (request.occupancy.generation.has_value() &&
      !request.occupancy.generation->is_valid()) {
    return Error(ErrorCode::InvalidGeneration, "occupancy generation is absent");
  }
  if (request.occupancy.instances.size() > kMaxPlacedInstances) {
    return Error(ErrorCode::LimitExceeded,
                 "occupancy evidence holds more instances than the limit allows")
        .with_detail("limit=" + std::to_string(kMaxPlacedInstances));
  }
  for (std::size_t index = 0; index < request.occupancy.instances.size(); ++index) {
    const PlacedInstance& instance = request.occupancy.instances[index];
    if (instance.placement_id.empty()) {
      return Error(ErrorCode::MissingField, "a placed instance needs an identity");
    }
    if (instance.tenant.empty() || instance.service_class.empty()) {
      return Error(ErrorCode::MissingField,
                   "a placed instance needs a tenant and a service class; an unidentified "
                   "neighbour cannot be reasoned about")
          .with_detail("placement=" + std::string(instance.placement_id.value()));
    }
    const auto location_result =
        validate_location(instance.location, std::string(instance.placement_id.value()));
    if (!location_result.has_value()) {
      return location_result.error();
    }
    if (index > 0 && request.occupancy.instances[index - 1].placement_id == instance.placement_id) {
      return Error(ErrorCode::DuplicateField, "two placed instances share an identity")
          .with_detail("placement=" + std::string(instance.placement_id.value()));
    }
  }

  if (request.maintenance.generation.has_value() && !request.maintenance.generation->is_valid()) {
    return Error(ErrorCode::InvalidGeneration, "maintenance generation is absent");
  }
  if (request.maintenance.exposures.size() > kMaxMaintenanceExposures) {
    return Error(ErrorCode::LimitExceeded,
                 "maintenance evidence holds more exposures than the limit allows")
        .with_detail("limit=" + std::to_string(kMaxMaintenanceExposures));
  }
  for (std::size_t index = 0; index < request.maintenance.exposures.size(); ++index) {
    const MaintenanceExposure& exposure = request.maintenance.exposures[index];
    if (exposure.exposure_id.empty()) {
      return Error(ErrorCode::MissingField, "a maintenance exposure needs an identity");
    }
    if (!(exposure.start < exposure.end)) {
      return Error(ErrorCode::InvalidConstraintOperand,
                   "a maintenance exposure window must be non-empty and ordered")
          .with_detail("exposure=" + std::string(exposure.exposure_id.value()) + " start=" +
                       exposure.start.to_string() + " end=" + exposure.end.to_string());
    }
    if (exposure.scope.is_empty()) {
      return Error(ErrorCode::InvalidConstraintOperand,
                   "a maintenance exposure must name at least one place it applies to")
          .with_detail("exposure=" + std::string(exposure.exposure_id.value()));
    }
    if (exposure.scope.failure_domain_kind.has_value() !=
        exposure.scope.failure_domain.has_value()) {
      return Error(ErrorCode::InvalidConstraintOperand,
                   "a maintenance exposure that names a failure domain needs both its kind and "
                   "its identity")
          .with_detail("exposure=" + std::string(exposure.exposure_id.value()));
    }
    if (index > 0 &&
        request.maintenance.exposures[index - 1].exposure_id == exposure.exposure_id) {
      return Error(ErrorCode::DuplicateField, "two maintenance exposures share an identity")
          .with_detail("exposure=" + std::string(exposure.exposure_id.value()));
    }
  }
  return success;
}

const FacilityRecord* find_facility(const PlacementRequest& request,
                                    const FacilityId& facility) noexcept {
  for (const FacilityRecord& record : request.facilities) {
    if (record.facility == facility) {
      return &record;
    }
  }
  return nullptr;
}

const CandidatePlacement* find_candidate(const PlacementRequest& request,
                                         const CandidateId& candidate_id) noexcept {
  for (const CandidatePlacement& candidate : request.candidates) {
    if (candidate.candidate_id == candidate_id) {
      return &candidate;
    }
  }
  return nullptr;
}

}  // namespace dccp::facility_placement_policy
