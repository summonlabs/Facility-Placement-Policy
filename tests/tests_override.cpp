// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs.

#include <string>

#include "test_framework.hpp"
#include "test_support.hpp"

#include "dccp/facility_placement_policy/facility_placement_policy.hpp"

namespace {

using namespace dccp::facility_placement_policy;

const char* const kPolicy =
    "fpp-document policy\n"
    "format 1\n"
    "policy-id grid-a\n"
    "revision 1\n"
    "rule spread {\n"
    "  require anti-affinity scope=tenant dimension=rack max-shared=0\n"
    "}\n"
    "rule legal {\n"
    "  require jurisdiction allow=jurisdiction:eu-de deny=\n"
    "}\n"
    "envelope emergency {\n"
    "  scope tenants=tenant:acme facilities=facility:dc1\n"
    "  allow-kinds anti-affinity\n"
    "  principals principal:sre\n"
    "  max-uses 2\n"
    "  grant-validity 15m\n"
    "}\n";

const char* const kRequest =
    "fpp-document request\n"
    "format 1\n"
    "request-id req-1\n"
    "tenant tenant:acme\n"
    "service-class service-class:gold\n"
    "requested-at 2026-02-14T09:30:00.000000Z\n"
    "generations topology=12 failure-domain=9 tenant=4 service-class=3\n"
    "facility facility:dc1 jurisdiction=jurisdiction:eu-de\n"
    "candidate c1 facility=facility:dc1 rack=rack:07\n"
    "occupancy generation=77\n"
    "placed p1 tenant=tenant:acme service-class=service-class:gold facility=facility:dc1 "
    "rack=rack:07\n"
    "maintenance generation=41\n";

Instant at(const char* text) { return Instant::parse(text).value(); }

Result<Store> fresh_store(const std::string& name, const char* policy_text = kPolicy) {
  auto directory = fptest::fresh_directory(name);
  if (!directory.has_value()) {
    return directory.error();
  }
  const StoreId store_id = StoreId::parse("store:main").value();
  const auto created = initialize_store(directory.value(), store_id, at("2026-02-14T09:00:00.000000Z"));
  if (!created.has_value()) {
    return created.error();
  }
  auto store = Store::open(directory.value(), StoreOpenMode::ReadWrite);
  if (!store.has_value()) {
    return store.error();
  }
  auto document = parse_policy_document(policy_text);
  if (!document.has_value()) {
    return document.error();
  }
  auto activated = store.value().activate_policy(document.value(), at("2026-02-14T09:05:00.000000Z"));
  if (!activated.has_value()) {
    return activated.error();
  }
  return store;
}

EvaluationInput input_with(const OverrideGrant* grant) {
  EvaluationInput input;
  input.request = parse_request_document(kRequest).value();
  if (grant != nullptr) {
    input.grants.push_back(*grant);
  }
  return input;
}

}  // namespace

FPT_TEST(override, a_grant_is_scoped_to_one_envelope_and_one_scope) {
  auto store = fresh_store("override-scope");
  FPT_REQUIRE_OK(store);
  const EnvelopeId envelope = EnvelopeId::parse("emergency").value();
  const PrincipalId principal = PrincipalId::parse("principal:sre").value();
  const TenantId tenant = TenantId::parse("tenant:acme").value();
  const ServiceClassId service_class = ServiceClassId::parse("service-class:gold").value();
  const FacilityId facility = FacilityId::parse("facility:dc1").value();

  FPT_CHECK_ERROR(store.value().authorize_override(EnvelopeId::parse("nope").value(), principal,
                                                   UsageId::parse("u0").value(), tenant,
                                                   service_class, facility,
                                                   at("2026-02-14T09:30:00.000000Z")),
                  ErrorCode::OverrideUnknownEnvelope);
  FPT_CHECK_ERROR(store.value().authorize_override(envelope,
                                                   PrincipalId::parse("principal:nobody").value(),
                                                   UsageId::parse("u1").value(), tenant,
                                                   service_class, facility,
                                                   at("2026-02-14T09:30:00.000000Z")),
                  ErrorCode::OverridePrincipalNotAuthorized);
  FPT_CHECK_ERROR(store.value().authorize_override(envelope, principal,
                                                   UsageId::parse("u2").value(),
                                                   TenantId::parse("tenant:other").value(),
                                                   service_class, facility,
                                                   at("2026-02-14T09:30:00.000000Z")),
                  ErrorCode::OverrideScopeMismatch);
  FPT_CHECK_ERROR(store.value().authorize_override(envelope, principal,
                                                   UsageId::parse("u3").value(), tenant,
                                                   service_class,
                                                   FacilityId::parse("facility:dc2").value(),
                                                   at("2026-02-14T09:30:00.000000Z")),
                  ErrorCode::OverrideScopeMismatch);

  auto granted = store.value().authorize_override(envelope, principal, UsageId::parse("u4").value(),
                                                  tenant, service_class, facility,
                                                  at("2026-02-14T09:30:00.000000Z"));
  FPT_REQUIRE_OK(granted);
  FPT_CHECK(verify_grant_digest(granted.value()));
  FPT_CHECK_EQ(granted.value().expires_at.to_string(), std::string("2026-02-14T09:45:00.000000Z"));
  FPT_CHECK(digest_equal(granted.value().policy.digest, store.value().status().policy.digest));
}

FPT_TEST(override, a_usage_identity_is_consumed_once_and_replays_identically) {
  auto store = fresh_store("override-replay");
  FPT_REQUIRE_OK(store);
  const EnvelopeId envelope = EnvelopeId::parse("emergency").value();
  const PrincipalId principal = PrincipalId::parse("principal:sre").value();
  const TenantId tenant = TenantId::parse("tenant:acme").value();
  const ServiceClassId service_class = ServiceClassId::parse("service-class:gold").value();
  const FacilityId facility = FacilityId::parse("facility:dc1").value();
  const UsageId usage = UsageId::parse("usage-a").value();

  auto first = store.value().authorize_override(envelope, principal, usage, tenant, service_class,
                                                facility, at("2026-02-14T09:30:00.000000Z"));
  FPT_REQUIRE_OK(first);
  auto status = store.value().override_status(envelope);
  FPT_REQUIRE_OK(status);
  FPT_CHECK_EQ(status.value().used, std::uint32_t(1));
  FPT_CHECK_EQ(status.value().remaining, std::uint32_t(1));

  // A lost response is answered with the same grant and consumes nothing more.
  auto replay = store.value().authorize_override(envelope, principal, usage, tenant,
                                                 service_class, facility,
                                                 at("2026-02-14T09:31:00.000000Z"));
  FPT_REQUIRE_OK(replay);
  FPT_CHECK(digest_equal(replay.value().grant_digest, first.value().grant_digest));
  FPT_CHECK_EQ(replay.value().issued_at.to_string(), first.value().issued_at.to_string());
  status = store.value().override_status(envelope);
  FPT_REQUIRE_OK(status);
  FPT_CHECK_EQ(status.value().used, std::uint32_t(1));

  // The same usage identity with a different binding is a conflict, not a second
  // use and not a silent success.
  FPT_CHECK_ERROR(store.value().authorize_override(envelope, principal, usage, tenant,
                                                   service_class,
                                                   FacilityId::parse("facility:dc2").value(),
                                                   at("2026-02-14T09:31:00.000000Z")),
                  ErrorCode::OverrideScopeMismatch);

  // The limit is the authority: the second use succeeds, the third does not.
  auto second = store.value().authorize_override(envelope, principal, UsageId::parse("usage-b").value(),
                                                 tenant, service_class, facility,
                                                 at("2026-02-14T09:30:00.000000Z"));
  FPT_REQUIRE_OK(second);
  FPT_CHECK_ERROR(store.value().authorize_override(envelope, principal,
                                                   UsageId::parse("usage-c").value(), tenant,
                                                   service_class, facility,
                                                   at("2026-02-14T09:30:00.000000Z")),
                  ErrorCode::OverrideLimitExceeded);
  status = store.value().override_status(envelope);
  FPT_REQUIRE_OK(status);
  FPT_CHECK_EQ(status.value().used, std::uint32_t(2));
  FPT_CHECK_EQ(status.value().remaining, std::uint32_t(0));

  auto statuses = store.value().override_statuses();
  FPT_REQUIRE_OK(statuses);
  FPT_CHECK_EQ(statuses.value().size(), std::size_t(1));
  FPT_CHECK_EQ(statuses.value().front().envelope_id.value(), std::string_view("emergency"));
}

FPT_TEST(override, a_waived_violation_is_still_reported_and_the_decision_flips) {
  auto store = fresh_store("override-waive");
  FPT_REQUIRE_OK(store);
  auto snapshot = store.value().snapshot();
  FPT_REQUIRE_OK(snapshot);

  auto without = evaluate(snapshot.value(), input_with(nullptr));
  FPT_REQUIRE_OK(without);
  FPT_CHECK(without.value().candidates.front().decision == Decision::Ineligible);
  FPT_CHECK(!without.value().candidates.front().override_use.has_value());

  auto grant = store.value().authorize_override(
      EnvelopeId::parse("emergency").value(), PrincipalId::parse("principal:sre").value(),
      UsageId::parse("usage-w").value(), TenantId::parse("tenant:acme").value(),
      ServiceClassId::parse("service-class:gold").value(),
      FacilityId::parse("facility:dc1").value(), at("2026-02-14T09:30:00.000000Z"));
  FPT_REQUIRE_OK(grant);

  auto with = evaluate(snapshot.value(), input_with(&grant.value()));
  FPT_REQUIRE_OK(with);
  const CandidateVerdict& verdict = with.value().candidates.front();
  FPT_CHECK(verdict.decision == Decision::Eligible);
  // The violation is still there; it is marked as waived rather than removed.
  FPT_REQUIRE(!verdict.violations.empty());
  FPT_CHECK(verdict.violations.front().code == ViolationCode::AntiAffinityExceeded);
  FPT_REQUIRE(verdict.violations.front().waived_by.has_value());
  FPT_CHECK_EQ(verdict.violations.front().waived_by->value(), std::string_view("emergency"));
  FPT_REQUIRE(verdict.override_use.has_value());
  FPT_CHECK_EQ(verdict.override_use->waived_count, std::uint32_t(1));
  FPT_CHECK(verify_verdict_digest(verdict));
}

FPT_TEST(override, an_expired_grant_is_refused_at_evaluation_time) {
  auto store = fresh_store("override-expiry");
  FPT_REQUIRE_OK(store);
  auto grant = store.value().authorize_override(
      EnvelopeId::parse("emergency").value(), PrincipalId::parse("principal:sre").value(),
      UsageId::parse("usage-e").value(), TenantId::parse("tenant:acme").value(),
      ServiceClassId::parse("service-class:gold").value(),
      FacilityId::parse("facility:dc1").value(), at("2026-02-14T09:30:00.000000Z"));
  FPT_REQUIRE_OK(grant);
  auto snapshot = store.value().snapshot();
  FPT_REQUIRE_OK(snapshot);

  // Inside the window it applies.
  FPT_REQUIRE_OK(evaluate(snapshot.value(), input_with(&grant.value())));

  // After it, the evaluation is refused rather than silently deciding without it.
  EvaluationInput late = input_with(&grant.value());
  late.request.requested_at = at("2026-02-14T10:00:00.000000Z");
  FPT_CHECK_ERROR(evaluate(snapshot.value(), late), ErrorCode::OverrideExpired);
}

FPT_TEST(override, a_new_policy_epoch_fences_every_outstanding_grant) {
  auto store = fresh_store("override-epoch");
  FPT_REQUIRE_OK(store);
  auto grant = store.value().authorize_override(
      EnvelopeId::parse("emergency").value(), PrincipalId::parse("principal:sre").value(),
      UsageId::parse("usage-f").value(), TenantId::parse("tenant:acme").value(),
      ServiceClassId::parse("service-class:gold").value(),
      FacilityId::parse("facility:dc1").value(), at("2026-02-14T09:30:00.000000Z"));
  FPT_REQUIRE_OK(grant);
  auto snapshot = store.value().snapshot();
  FPT_REQUIRE_OK(snapshot);
  FPT_REQUIRE_OK(evaluate(snapshot.value(), input_with(&grant.value())));

  // Revision 2 with the same envelope changes nothing about the envelope, but the
  // authority epoch advances with the publication, so the grant is fenced.
  std::string next_text(kPolicy);
  const std::size_t position = next_text.find("revision 1");
  next_text.replace(position, std::string("revision 1").size(), "revision 2");
  auto next = parse_policy_document(next_text);
  FPT_REQUIRE_OK(next);
  auto activated = store.value().activate_policy(next.value(), at("2026-02-14T09:40:00.000000Z"));
  FPT_REQUIRE_OK(activated);
  auto new_snapshot = store.value().snapshot();
  FPT_REQUIRE_OK(new_snapshot);
  FPT_CHECK(new_snapshot.value().authority_epoch.value() >
            snapshot.value().authority_epoch.value());
  // The policy binding is checked before the epoch, so a grant that names the
  // old revision is fenced for that reason first.
  FPT_CHECK_ERROR(evaluate(new_snapshot.value(), input_with(&grant.value())),
                  ErrorCode::OverrideBindingMismatch);

  // A grant that names the new revision but the old epoch is fenced by the epoch
  // alone, which is what proves the epoch is a binding and not a comment.
  OverrideGrant rebound = grant.value();
  rebound.policy = new_snapshot.value().binding();
  auto canonically_rebound = canonicalize_grant(rebound);
  FPT_REQUIRE_OK(canonically_rebound);
  EvaluationInput rebound_input;
  rebound_input.request = parse_request_document(kRequest).value();
  rebound_input.grants.push_back(canonically_rebound.value());
  FPT_CHECK_ERROR(evaluate(new_snapshot.value(), rebound_input), ErrorCode::StaleAuthorityEpoch);
}

FPT_TEST(override, a_changed_envelope_fences_the_grants_issued_against_it) {
  auto store = fresh_store("override-envelope-change");
  FPT_REQUIRE_OK(store);
  auto grant = store.value().authorize_override(
      EnvelopeId::parse("emergency").value(), PrincipalId::parse("principal:sre").value(),
      UsageId::parse("usage-g").value(), TenantId::parse("tenant:acme").value(),
      ServiceClassId::parse("service-class:gold").value(),
      FacilityId::parse("facility:dc1").value(), at("2026-02-14T09:30:00.000000Z"));
  FPT_REQUIRE_OK(grant);

  // The same envelope identity with a wider use limit is a different envelope.
  std::string next_text(kPolicy);
  const std::size_t position = next_text.find("revision 1");
  next_text.replace(position, std::string("revision 1").size(), "revision 2");
  const std::size_t uses = next_text.find("max-uses 2");
  next_text.replace(uses, std::string("max-uses 2").size(), "max-uses 9");
  auto next = parse_policy_document(next_text);
  FPT_REQUIRE_OK(next);
  FPT_REQUIRE_OK(store.value().activate_policy(next.value(), at("2026-02-14T09:40:00.000000Z")));
  auto snapshot = store.value().snapshot();
  FPT_REQUIRE_OK(snapshot);
  // The envelope changed, so the grant is fenced by the envelope digest before
  // the epoch is even considered.
  FPT_CHECK_ERROR(evaluate(snapshot.value(), input_with(&grant.value())),
                  ErrorCode::OverrideGrantEnvelopeMismatch);

  OverrideGrant rewritten = grant.value();
  rewritten.authority_epoch = snapshot.value().authority_epoch;
  rewritten.policy = snapshot.value().binding();
  FPT_REQUIRE_OK(canonicalize_grant(rewritten));
  EvaluationInput input;
  input.request = parse_request_document(kRequest).value();
  input.grants.push_back(canonicalize_grant(rewritten).value());
  FPT_CHECK_ERROR(evaluate(snapshot.value(), input), ErrorCode::OverrideGrantEnvelopeMismatch);
}

FPT_TEST(override, only_one_grant_may_apply_to_one_facility) {
  auto store = fresh_store("override-two-grants");
  FPT_REQUIRE_OK(store);
  auto snapshot = store.value().snapshot();
  FPT_REQUIRE_OK(snapshot);

  auto first = store.value().authorize_override(
      EnvelopeId::parse("emergency").value(), PrincipalId::parse("principal:sre").value(),
      UsageId::parse("usage-h").value(), TenantId::parse("tenant:acme").value(),
      ServiceClassId::parse("service-class:gold").value(),
      FacilityId::parse("facility:dc1").value(), at("2026-02-14T09:30:00.000000Z"));
  FPT_REQUIRE_OK(first);
  auto second = store.value().authorize_override(
      EnvelopeId::parse("emergency").value(), PrincipalId::parse("principal:sre").value(),
      UsageId::parse("usage-i").value(), TenantId::parse("tenant:acme").value(),
      ServiceClassId::parse("service-class:gold").value(),
      FacilityId::parse("facility:dc1").value(), at("2026-02-14T09:30:00.000000Z"));
  FPT_REQUIRE_OK(second);

  EvaluationInput input;
  input.request = parse_request_document(kRequest).value();
  input.grants.push_back(first.value());
  input.grants.push_back(second.value());
  FPT_CHECK_ERROR(evaluate(snapshot.value(), input), ErrorCode::OverrideUsageConflict);
}

FPT_TEST(override, a_grant_that_does_not_cover_the_violation_changes_nothing) {
  // The envelope may waive anti-affinity; the jurisdiction rule is a hard
  // interlock, so a request that violates it stays ineligible.
  auto store = fresh_store("override-hard-interlock");
  FPT_REQUIRE_OK(store);
  auto grant = store.value().authorize_override(
      EnvelopeId::parse("emergency").value(), PrincipalId::parse("principal:sre").value(),
      UsageId::parse("usage-j").value(), TenantId::parse("tenant:acme").value(),
      ServiceClassId::parse("service-class:gold").value(),
      FacilityId::parse("facility:dc1").value(), at("2026-02-14T09:30:00.000000Z"));
  FPT_REQUIRE_OK(grant);
  auto snapshot = store.value().snapshot();
  FPT_REQUIRE_OK(snapshot);

  EvaluationInput input = input_with(&grant.value());
  input.request.facilities.front().jurisdiction = JurisdictionId::parse("jurisdiction:us-east").value();
  auto verdicts = evaluate(snapshot.value(), input);
  FPT_REQUIRE_OK(verdicts);
  const CandidateVerdict& verdict = verdicts.value().candidates.front();
  FPT_CHECK(verdict.decision == Decision::Ineligible);
  bool saw_jurisdiction = false;
  for (const Violation& violation : verdict.violations) {
    if (violation.code == ViolationCode::JurisdictionNotAllowed) {
      saw_jurisdiction = true;
      // Not waived, because the envelope does not reach a hard interlock.
      FPT_CHECK(!violation.waived_by.has_value());
    }
  }
  FPT_CHECK(saw_jurisdiction);
}
