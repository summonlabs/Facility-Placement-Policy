// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs.

#ifndef DCCP_FACILITY_PLACEMENT_POLICY_TEXT_HPP
#define DCCP_FACILITY_PLACEMENT_POLICY_TEXT_HPP

#include <string>
#include <string_view>

#include "dccp/facility_placement_policy/evaluate.hpp"
#include "dccp/facility_placement_policy/policy.hpp"
#include "dccp/facility_placement_policy/records.hpp"
#include "dccp/facility_placement_policy/request.hpp"
#include "dccp/facility_placement_policy/result.hpp"
#include "dccp/facility_placement_policy/verdict.hpp"

/// The text document format.
///
/// The format exists so that an operator can read, diff and review a policy, and
/// so that two documents that mean the same thing produce the same bytes after a
/// round trip. It is deliberately small:
///
///   * a document starts with "fpp-document <kind>" and "format 1";
///   * every line is either blank, a comment starting with '#', a
///     "keyword key=value ..." statement, a "keyword value ... {" section
///     opening or a "}" section close;
///   * sections nest exactly one level deep;
///   * values are either bare tokens or double-quoted strings with the escapes
///     defined by text_escape();
///   * names and keys are case sensitive; there is no whitespace inside a value.
///
/// Parsing is strict: an unknown keyword, an unknown key, a repeated key, a
/// missing required key, a value that does not have the right type and an
/// unexpected section are all errors. Nothing is ignored, because a silently
/// ignored line in a policy is a silently weakened policy.
///
/// The emitters produce canonical text: statements in a fixed order, sets
/// sorted, one entry per line. Parsing canonical text and re-emitting it is
/// idempotent, and parsing it and encoding it produces the same bytes as
/// encoding the original model.
namespace dccp::facility_placement_policy {

Result<PolicyDocument> parse_policy_document(std::string_view text);
Result<PlacementRequest> parse_request_document(std::string_view text);
Result<OverrideGrant> parse_grant_document(std::string_view text);
Result<PlacementVerdictSet> parse_verdict_document(std::string_view text);

std::string policy_document_text(const PolicyDocument& document);
std::string request_document_text(const PlacementRequest& request);
std::string grant_document_text(const OverrideGrant& grant);
std::string verdict_document_text(const PlacementVerdictSet& verdicts);

/// The document kind token a document declares, without parsing the rest of it.
/// Used by the CLI to dispatch on the first line.
Result<std::string> document_kind(std::string_view text);

}  // namespace dccp::facility_placement_policy

#endif  // DCCP_FACILITY_PLACEMENT_POLICY_TEXT_HPP
