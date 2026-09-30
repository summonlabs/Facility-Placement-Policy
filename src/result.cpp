// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs.

#include "dccp/facility_placement_policy/result.hpp"

namespace dccp::facility_placement_policy {

std::string_view error_code_name(ErrorCode code) noexcept {
  switch (code) {
#define DCCP_FACILITY_PLACEMENT_POLICY_NAME_ENTRY(name, text, category) \
  case ErrorCode::name:                                                 \
    return text;
    DCCP_FACILITY_PLACEMENT_POLICY_ERROR_CODES(DCCP_FACILITY_PLACEMENT_POLICY_NAME_ENTRY)
#undef DCCP_FACILITY_PLACEMENT_POLICY_NAME_ENTRY
  }
  return "UNKNOWN";
}

ErrorCategory error_category(ErrorCode code) noexcept {
  switch (code) {
#define DCCP_FACILITY_PLACEMENT_POLICY_CATEGORY_ENTRY(name, text, category) \
  case ErrorCode::name:                                                      \
    return ErrorCategory::category;
    DCCP_FACILITY_PLACEMENT_POLICY_ERROR_CODES(DCCP_FACILITY_PLACEMENT_POLICY_CATEGORY_ENTRY)
#undef DCCP_FACILITY_PLACEMENT_POLICY_CATEGORY_ENTRY
  }
  return ErrorCategory::Internal;
}

std::string_view error_category_name(ErrorCategory category) noexcept {
  switch (category) {
    case ErrorCategory::Ok:
      return "OK";
    case ErrorCategory::Argument:
      return "ARGUMENT";
    case ErrorCategory::Structure:
      return "STRUCTURE";
    case ErrorCategory::Authority:
      return "AUTHORITY";
    case ErrorCategory::Persistence:
      return "PERSISTENCE";
    case ErrorCategory::Lifecycle:
      return "LIFECYCLE";
    case ErrorCategory::Limit:
      return "LIMIT";
    case ErrorCategory::Cancelled:
      return "CANCELLED";
    case ErrorCategory::Internal:
      return "INTERNAL";
  }
  return "UNKNOWN";
}

std::string Error::to_string() const {
  std::string out(code_name());
  out.append(": ");
  out.append(message_);
  if (!subject_.empty()) {
    out.append(" [subject=");
    out.append(subject_);
    out.push_back(']');
  }
  if (!detail_.empty()) {
    out.append(" [detail=");
    out.append(detail_);
    out.push_back(']');
  }
  return out;
}

}  // namespace dccp::facility_placement_policy
