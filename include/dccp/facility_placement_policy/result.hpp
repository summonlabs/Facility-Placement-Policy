// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs.

#ifndef DCCP_FACILITY_PLACEMENT_POLICY_RESULT_HPP
#define DCCP_FACILITY_PLACEMENT_POLICY_RESULT_HPP

#include <cstdint>
#include <string>
#include <string_view>
#include <type_traits>
#include <utility>
#include <variant>

namespace dccp::facility_placement_policy {

// The error vocabulary is defined once, in a table, so that the enumerators, the
// stable textual names and the coarse categories can never drift apart. New
// codes are appended; existing enumerators are never renumbered or repurposed,
// because callers and operators match on them.
//
// Columns: enumerator, stable textual name, category.
#define DCCP_FACILITY_PLACEMENT_POLICY_ERROR_CODES(X)                     \
  X(Ok, "OK", Ok)                                                         \
  /* Input shape and encoding. */                                         \
  X(InvalidArgument, "INVALID_ARGUMENT", Argument)                        \
  X(MalformedIdentifier, "MALFORMED_IDENTIFIER", Argument)                \
  X(IdentifierTooLong, "IDENTIFIER_TOO_LONG", Argument)                   \
  X(InvalidUtf8, "INVALID_UTF8", Argument)                                \
  X(TextTooLong, "TEXT_TOO_LONG", Argument)                               \
  X(UnknownEnumToken, "UNKNOWN_ENUM_TOKEN", Argument)                     \
  X(MissingField, "MISSING_FIELD", Argument)                              \
  X(DuplicateField, "DUPLICATE_FIELD", Argument)                          \
  X(MalformedDocument, "MALFORMED_DOCUMENT", Argument)                    \
  X(EmptyDocument, "EMPTY_DOCUMENT", Argument)                            \
  X(UnsupportedFormatVersion, "UNSUPPORTED_FORMAT_VERSION", Argument)     \
  X(TruncatedInput, "TRUNCATED_INPUT", Argument)                          \
  X(DigestMismatch, "DIGEST_MISMATCH", Argument)                          \
  X(ChecksumMismatch, "CHECKSUM_MISMATCH", Argument)                      \
  X(LimitExceeded, "LIMIT_EXCEEDED", Limit)                               \
  X(UnexpectedToken, "UNEXPECTED_TOKEN", Argument)                        \
  X(NumericOverflow, "NUMERIC_OVERFLOW", Argument)                        \
  X(NumericUnderflow, "NUMERIC_UNDERFLOW", Argument)                      \
  X(ReservedFieldNotZero, "RESERVED_FIELD_NOT_ZERO", Argument)            \
  X(InvalidBoolean, "INVALID_BOOLEAN", Argument)                          \
  X(UnknownKeyword, "UNKNOWN_KEYWORD", Argument)                          \
  X(UnexpectedEndOfInput, "UNEXPECTED_END_OF_INPUT", Argument)            \
  X(TrailingContent, "TRAILING_CONTENT", Argument)                        \
  /* Policy structure and semantics. */                                   \
  X(EmptyPolicy, "EMPTY_POLICY", Structure)                               \
  X(DuplicateRuleId, "DUPLICATE_RULE_ID", Structure)                      \
  X(RuleWithoutConstraints, "RULE_WITHOUT_CONSTRAINTS", Structure)        \
  X(UnsupportedConstraintKind, "UNSUPPORTED_CONSTRAINT_KIND", Structure)  \
  X(InvalidConstraintOperand, "INVALID_CONSTRAINT_OPERAND", Structure)    \
  X(ContradictoryConstraint, "CONTRADICTORY_CONSTRAINT", Structure)       \
  X(DuplicateEnvelopeId, "DUPLICATE_ENVELOPE_ID", Structure)              \
  X(EnvelopeWithoutPrincipals, "ENVELOPE_WITHOUT_PRINCIPALS", Structure)  \
  X(EnvelopeWithoutConstraintKinds, "ENVELOPE_WITHOUT_CONSTRAINT_KINDS", Structure) \
  X(HardInterlockNotOverridable, "HARD_INTERLOCK_NOT_OVERRIDABLE", Structure) \
  X(InvalidEnvelopeWindow, "INVALID_ENVELOPE_WINDOW", Structure)          \
  X(InvalidAttributeValue, "INVALID_ATTRIBUTE_VALUE", Structure)          \
  X(InvalidOperatorForKey, "INVALID_OPERATOR_FOR_KEY", Structure)         \
  X(SelectorEmpty, "SELECTOR_EMPTY", Structure)                           \
  X(UnsupportedFeature, "UNSUPPORTED_FEATURE", Structure)                 \
  /* Authority, generations and lifecycle. */                             \
  X(NoActivePolicy, "NO_ACTIVE_POLICY", Authority)                        \
  X(StalePolicyRevision, "STALE_POLICY_REVISION", Authority)              \
  X(PolicyRevisionRegression, "POLICY_REVISION_REGRESSION", Authority)    \
  X(PolicyRevisionConflict, "POLICY_REVISION_CONFLICT", Authority)        \
  X(StaleAuthorityEpoch, "STALE_AUTHORITY_EPOCH", Authority)              \
  X(AuthorityEpochOverflow, "AUTHORITY_EPOCH_OVERFLOW", Authority)        \
  X(StaleTopologyGeneration, "STALE_TOPOLOGY_GENERATION", Authority)      \
  X(StaleFailureDomainGeneration, "STALE_FAILURE_DOMAIN_GENERATION", Authority) \
  X(StaleTenantGeneration, "STALE_TENANT_GENERATION", Authority)          \
  X(StaleServiceClassGeneration, "STALE_SERVICE_CLASS_GENERATION", Authority) \
  X(StaleMaintenanceGeneration, "STALE_MAINTENANCE_GENERATION", Authority) \
  X(StaleOccupancyGeneration, "STALE_OCCUPANCY_GENERATION", Authority)    \
  X(EvidenceGenerationAbsent, "EVIDENCE_GENERATION_ABSENT", Authority)    \
  X(InvalidGeneration, "INVALID_GENERATION", Authority)                   \
  X(GenerationOverflow, "GENERATION_OVERFLOW", Authority)                 \
  X(InvalidState, "INVALID_STATE", Lifecycle)                             \
  X(AlreadyActive, "ALREADY_ACTIVE", Lifecycle)                           \
  X(NotInitialized, "NOT_INITIALIZED", Lifecycle)                         \
  X(AlreadyInitialized, "ALREADY_INITIALIZED", Lifecycle)                 \
  X(NotFound, "NOT_FOUND", Lifecycle)                                     \
  X(AlreadyPresent, "ALREADY_PRESENT", Lifecycle)                         \
  X(Cancelled, "CANCELLED", Cancelled)                                    \
  /* Overrides and exceptions. */                                         \
  X(OverrideUnknownEnvelope, "OVERRIDE_UNKNOWN_ENVELOPE", Authority)      \
  X(OverrideNotYetValid, "OVERRIDE_NOT_YET_VALID", Authority)             \
  X(OverrideExpired, "OVERRIDE_EXPIRED", Authority)                       \
  X(OverrideLimitExceeded, "OVERRIDE_LIMIT_EXCEEDED", Authority)          \
  X(OverrideUsageConflict, "OVERRIDE_USAGE_CONFLICT", Authority)          \
  X(OverrideScopeMismatch, "OVERRIDE_SCOPE_MISMATCH", Authority)          \
  X(OverrideKindNotAllowed, "OVERRIDE_KIND_NOT_ALLOWED", Authority)       \
  X(OverridePrincipalNotAuthorized, "OVERRIDE_PRINCIPAL_NOT_AUTHORIZED", Authority) \
  X(OverrideHardInterlockDenied, "OVERRIDE_HARD_INTERLOCK_DENIED", Authority) \
  X(OverrideBindingMismatch, "OVERRIDE_BINDING_MISMATCH", Authority)      \
  X(OverrideGrantEnvelopeMismatch, "OVERRIDE_GRANT_ENVELOPE_MISMATCH", Authority) \
  X(RequestIdConflict, "REQUEST_ID_CONFLICT", Authority)                  \
  /* Verdicts and fencing. */                                             \
  X(VerdictDigestMismatch, "VERDICT_DIGEST_MISMATCH", Authority)          \
  X(VerdictFenced, "VERDICT_FENCED", Authority)                           \
  X(CandidateDuplicateId, "CANDIDATE_DUPLICATE_ID", Argument)             \
  X(EmptyRequest, "EMPTY_REQUEST", Argument)                              \
  /* Persistence. */                                                      \
  X(StoreNotFound, "STORE_NOT_FOUND", Persistence)                        \
  X(StoreNotEmpty, "STORE_NOT_EMPTY", Persistence)                        \
  X(StoreMismatch, "STORE_MISMATCH", Persistence)                         \
  X(StoreLocked, "STORE_LOCKED", Lifecycle)                               \
  X(LockUnavailable, "LOCK_UNAVAILABLE", Persistence)                     \
  X(StoreReadOnly, "STORE_READ_ONLY", Lifecycle)                          \
  X(StoreClosed, "STORE_CLOSED", Lifecycle)                               \
  X(IntegrityFailure, "INTEGRITY_FAILURE", Persistence)                   \
  X(RecoveryRequired, "RECOVERY_REQUIRED", Persistence)                   \
  X(RecoveryUnavailable, "RECOVERY_UNAVAILABLE", Persistence)             \
  X(IoError, "IO_ERROR", Persistence)                                     \
  X(PathInvalid, "PATH_INVALID", Persistence)                             \
  X(ManifestMissing, "MANIFEST_MISSING", Persistence)                     \
  X(ManifestCorrupt, "MANIFEST_CORRUPT", Persistence)                     \
  X(RecordNotFound, "RECORD_NOT_FOUND", Persistence)                      \
  X(RecordCorrupt, "RECORD_CORRUPT", Persistence)                         \
  X(SequenceRegression, "SEQUENCE_REGRESSION", Persistence)               \
  X(SequenceOverflow, "SEQUENCE_OVERFLOW", Persistence)                   \
  X(InternalError, "INTERNAL_ERROR", Internal)

/// Stable, machine-readable outcome codes.
enum class ErrorCode : std::uint16_t {
#define DCCP_FACILITY_PLACEMENT_POLICY_ENUM_ENTRY(name, text, category) name,
  DCCP_FACILITY_PLACEMENT_POLICY_ERROR_CODES(DCCP_FACILITY_PLACEMENT_POLICY_ENUM_ENTRY)
#undef DCCP_FACILITY_PLACEMENT_POLICY_ENUM_ENTRY
};

/// Coarse classification of an ErrorCode, for callers that branch on the kind
/// of failure rather than the exact code.
enum class ErrorCategory : std::uint8_t {
  Ok = 0,
  Argument,     // untrusted or caller-supplied input was rejected
  Structure,    // a policy document would be structurally unsound
  Authority,    // a generation, revision, epoch or override precondition failed
  Persistence,  // durable state is missing, corrupt or unwritable
  Lifecycle,    // the store or an object is in the wrong state
  Limit,        // a configured bound was exceeded
  Cancelled,    // the operation was cancelled before publication
  Internal,     // a defect in the library
};

/// Stable textual name of an error code (upper snake case).
std::string_view error_code_name(ErrorCode code) noexcept;

/// Coarse category of an error code.
ErrorCategory error_category(ErrorCode code) noexcept;

/// Stable textual name of an error category.
std::string_view error_category_name(ErrorCategory category) noexcept;

/// A refusal, with enough structure to be attributable and machine-readable.
///
/// A refusal always names an exact code. The optional subject echoes the input
/// that was rejected (bounded, never a whole document) and the optional detail
/// carries secondary evidence that would otherwise be lost, such as the field
/// that conflicted or the generation that was expected.
class Error {
 public:
  Error(ErrorCode code, std::string message)
      : code_(code), message_(std::move(message)) {}

  ErrorCode code() const noexcept { return code_; }
  ErrorCategory category() const noexcept { return error_category(code_); }
  std::string_view code_name() const noexcept { return error_code_name(code_); }
  const std::string& message() const noexcept { return message_; }
  const std::string& subject() const noexcept { return subject_; }
  const std::string& detail() const noexcept { return detail_; }

  Error& with_subject(std::string subject) {
    subject_ = std::move(subject);
    return *this;
  }
  Error& with_detail(std::string detail) {
    detail_ = std::move(detail);
    return *this;
  }

  /// "CODE: message (subject=..., detail=...)" with the optional parts omitted
  /// when empty.
  std::string to_string() const;

  friend bool operator==(const Error& lhs, const Error& rhs) noexcept {
    return lhs.code_ == rhs.code_ && lhs.message_ == rhs.message_ &&
           lhs.subject_ == rhs.subject_ && lhs.detail_ == rhs.detail_;
  }

 private:
  ErrorCode code_;
  std::string message_;
  std::string subject_;
  std::string detail_;
};

/// Explicit success marker. Result<void> is deliberately not default
/// constructible: a missing return value must never read as success.
struct Success {};

/// Marker value for a successful Result<void>.
inline constexpr Success success{};

/// Either a value or an Error.
template <class T>
class Result {
  static_assert(!std::is_same_v<T, Error>, "Result<Error> is not a meaningful type");

 public:
  Result(T value) : storage_(std::in_place_index<0>, std::move(value)) {}
  Result(Error error) : storage_(std::in_place_index<1>, std::move(error)) {}

  bool has_value() const noexcept { return storage_.index() == 0; }
  explicit operator bool() const noexcept { return has_value(); }

  T& value() & { return std::get<0>(storage_); }
  const T& value() const& { return std::get<0>(storage_); }
  T&& value() && { return std::get<0>(std::move(storage_)); }

  T* operator->() { return &std::get<0>(storage_); }
  const T* operator->() const { return &std::get<0>(storage_); }
  T& operator*() & { return std::get<0>(storage_); }
  const T& operator*() const& { return std::get<0>(storage_); }

  Error& error() & { return std::get<1>(storage_); }
  const Error& error() const& { return std::get<1>(storage_); }
  Error&& error() && { return std::get<1>(std::move(storage_)); }

  const T& value_or(const T& fallback) const& { return has_value() ? value() : fallback; }

 private:
  std::variant<T, Error> storage_;
};

/// Either success or an Error.
template <>
class Result<void> {
 public:
  Result(Success) noexcept {}
  Result(Error error) : error_(std::move(error)), has_error_(true) {}

  bool has_value() const noexcept { return !has_error_; }
  explicit operator bool() const noexcept { return !has_error_; }

  Error& error() & { return error_; }
  const Error& error() const& { return error_; }

 private:
  Error error_{ErrorCode::Ok, std::string()};
  bool has_error_ = false;
};

}  // namespace dccp::facility_placement_policy

#endif  // DCCP_FACILITY_PLACEMENT_POLICY_RESULT_HPP
