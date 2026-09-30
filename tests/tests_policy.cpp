// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs.

#include <algorithm>
#include <string>
#include <vector>

#include "test_framework.hpp"

#include "dccp/facility_placement_policy/canonical.hpp"
#include "dccp/facility_placement_policy/policy.hpp"
#include "dccp/facility_placement_policy/text.hpp"

namespace {

using namespace dccp::facility_placement_policy;

/// The smallest well-formed policy: one rule, one constraint.
std::string minimal_policy_text(const std::string& revision = "1",
                                const std::string& extra_rule = "") {
  std::string text =
      "fpp-document policy\n"
      "format 1\n"
      "policy-id grid-a\n"
      "revision " +
      revision +
      "\n"
      "rule spread {\n"
      "  require anti-affinity scope=tenant dimension=rack max-shared=0\n"
      "}\n";
  text.append(extra_rule);
  return text;
}

Result<PolicyDocument> parse(const std::string& text) { return parse_policy_document(text); }

}  // namespace

FPT_TEST(policy, canonicalisation_makes_authoring_order_irrelevant) {
  const std::string first =
      "fpp-document policy\n"
      "format 1\n"
      "policy-id grid-a\n"
      "revision 7\n"
      "rule beta {\n"
      "  require jurisdiction allow=jurisdiction:eu-fr,jurisdiction:eu-de deny=\n"
      "  require anti-affinity scope=tenant dimension=rack max-shared=1\n"
      "}\n"
      "rule alpha {\n"
      "  require redundancy scope=service-class dimension=failure-domain:power "
      "min-distinct-domains=2\n"
      "}\n";
  const std::string second =
      "fpp-document policy\n"
      "format 1\n"
      "policy-id grid-a\n"
      "revision 7\n"
      "rule alpha {\n"
      "  require redundancy min-distinct-domains=2 dimension=failure-domain:power "
      "scope=service-class\n"
      "}\n"
      "rule beta {\n"
      "  require anti-affinity max-shared=1 dimension=rack scope=tenant\n"
      "  require jurisdiction deny= allow=jurisdiction:eu-de,jurisdiction:eu-fr\n"
      "}\n";
  auto left = parse(first);
  auto right = parse(second);
  FPT_REQUIRE_OK(left);
  FPT_REQUIRE_OK(right);
  FPT_CHECK(digest_equal(left.value().digest, right.value().digest));
  FPT_CHECK_EQ(policy_document_text(left.value()), policy_document_text(right.value()));
  FPT_CHECK_EQ(left.value().rules.front().rule_id.value(), std::string_view("alpha"));
  FPT_CHECK_EQ(left.value().rules.back().rule_id.value(), std::string_view("beta"));
  // Constraints inside a rule are ordered by their canonical text.
  FPT_CHECK(constraint_text(left.value().rules[1].constraints[0]) <
            constraint_text(left.value().rules[1].constraints[1]));
}

FPT_TEST(policy, the_digest_changes_when_anything_that_matters_changes) {
  auto base = parse(minimal_policy_text());
  FPT_REQUIRE_OK(base);
  const Digest baseline = base.value().digest;

  auto other_revision = parse(minimal_policy_text("2"));
  FPT_REQUIRE_OK(other_revision);
  FPT_CHECK(!digest_equal(baseline, other_revision.value().digest));

  auto described = parse(minimal_policy_text("1", "rule note {\n"
                                                   "  description \"a note\"\n"
                                                   "  require anti-affinity scope=tenant "
                                                   "dimension=row max-shared=0\n"
                                                   "}\n"));
  FPT_REQUIRE_OK(described);
  FPT_CHECK(!digest_equal(baseline, described.value().digest));

  // Re-parsing the canonical text reproduces the digest exactly, so the text
  // form is a faithful normal form of the digested document.
  auto round_tripped = parse(policy_document_text(base.value()));
  FPT_REQUIRE_OK(round_tripped);
  FPT_CHECK(digest_equal(baseline, round_tripped.value().digest));
  FPT_CHECK_EQ(policy_document_text(round_tripped.value()),
               policy_document_text(base.value()));
}

FPT_TEST(policy, a_document_cannot_assert_its_own_identity) {
  auto document = parse(minimal_policy_text());
  FPT_REQUIRE_OK(document);
  PolicyDocument forged = document.value();
  forged.digest[0] ^= 0xFFu;
  FPT_CHECK_ERROR(validate_canonical_policy(forged), ErrorCode::DigestMismatch);

  // An unsorted document is a corruption when it comes from durable state.
  PolicyDocument unsorted = document.value();
  Rule extra = unsorted.rules.front();
  extra.rule_id = RuleId::parse("aaa").value();
  unsorted.rules.insert(unsorted.rules.begin(), extra);
  const auto reordered = canonicalize_policy(unsorted);
  FPT_REQUIRE_OK(reordered);
  FPT_CHECK_EQ(reordered.value().rules.front().rule_id.value(), std::string_view("aaa"));
}

FPT_TEST(policy, structural_defects_are_refused) {
  FPT_CHECK_ERROR(parse("fpp-document policy\nformat 1\npolicy-id grid-a\nrevision 1\n"),
                  ErrorCode::EmptyPolicy);
  FPT_CHECK_ERROR(parse("fpp-document policy\nformat 1\nrevision 1\nrule a {\n"
                        "  require anti-affinity scope=tenant dimension=rack max-shared=0\n}\n"),
                  ErrorCode::MissingField);
  FPT_CHECK_ERROR(parse("fpp-document policy\nformat 1\npolicy-id grid-a\nrule a {\n"
                        "  require anti-affinity scope=tenant dimension=rack max-shared=0\n}\n"),
                  ErrorCode::MissingField);
  FPT_CHECK_ERROR(parse(minimal_policy_text("1", "rule spread {\n"
                                                   "  require anti-affinity scope=tenant "
                                                   "dimension=row max-shared=0\n}\n")),
                  ErrorCode::DuplicateRuleId);
  FPT_CHECK_ERROR(parse("fpp-document policy\nformat 1\npolicy-id grid-a\nrevision 1\n"
                        "rule empty {\n}\n"),
                  ErrorCode::RuleWithoutConstraints);
  FPT_CHECK_ERROR(parse(minimal_policy_text() + "nonsense statement\n"), ErrorCode::UnknownKeyword);
  FPT_CHECK_ERROR(parse("fpp-document policy\nformat 2\npolicy-id grid-a\nrevision 1\n"),
                  ErrorCode::UnsupportedFormatVersion);
  FPT_CHECK_ERROR(parse("fpp-document request\nformat 1\n"), ErrorCode::UnexpectedToken);
  FPT_CHECK_ERROR(parse(""), ErrorCode::EmptyDocument);
}

FPT_TEST(policy, a_rule_that_can_never_be_satisfied_is_refused) {
  // The same jurisdiction is allowed and denied.
  FPT_CHECK_ERROR(
      parse(minimal_policy_text("1", "rule legal {\n"
                                     "  require jurisdiction allow=jurisdiction:eu-de "
                                     "deny=jurisdiction:eu-de\n}\n")),
      ErrorCode::ContradictoryConstraint);

  // A numeric interval with nothing inside it.
  FPT_CHECK_ERROR(
      parse(minimal_policy_text("1", "rule power {\n"
                                     "  require facility-attribute key=power-feed-count "
                                     "op=at-least value=5\n"
                                     "  require facility-attribute key=power-feed-count "
                                     "op=at-most value=3\n}\n")),
      ErrorCode::ContradictoryConstraint);

  // The single permitted value is also excluded.
  FPT_CHECK_ERROR(
      parse(minimal_policy_text("1", "rule power {\n"
                                     "  require facility-attribute key=security-tier "
                                     "op=at-least value=4\n"
                                     "  require facility-attribute key=security-tier "
                                     "op=at-most value=4\n"
                                     "  require facility-attribute key=security-tier "
                                     "op=not-equal value=4\n}\n")),
      ErrorCode::ContradictoryConstraint);

  // An enum-valued attribute cannot be two different things at once.
  FPT_CHECK_ERROR(
      parse(minimal_policy_text("1", "rule cooling {\n"
                                     "  require facility-attribute key=cooling-mode op=equal "
                                     "value=air\n"
                                     "  require facility-attribute key=cooling-mode op=equal "
                                     "value=immersion\n}\n")),
      ErrorCode::ContradictoryConstraint);

  FPT_CHECK_ERROR(
      parse(minimal_policy_text("1", "rule cooling {\n"
                                     "  require facility-attribute key=cooling-mode op=equal "
                                     "value=air\n"
                                     "  require facility-attribute key=cooling-mode op=not-equal "
                                     "value=air\n}\n")),
      ErrorCode::ContradictoryConstraint);

  FPT_CHECK_ERROR(
      parse(minimal_policy_text("1", "rule power {\n"
                                     "  require facility-attribute key=power-feed-count "
                                     "op=present\n"
                                     "  require facility-attribute key=power-feed-count "
                                     "op=absent\n}\n")),
      ErrorCode::ContradictoryConstraint);

  // Two allow-lists for one dimension that share no identity.
  FPT_CHECK_ERROR(
      parse(minimal_policy_text("1", "rule racks {\n"
                                     "  require separation dimension=rack "
                                     "allow=rack:r1,rack:r2 deny=\n"
                                     "  require separation dimension=rack "
                                     "allow=rack:r3 deny=\n}\n")),
      ErrorCode::ContradictoryConstraint);

  // A consistent pair is fine.
  FPT_REQUIRE_OK(parse(minimal_policy_text(
      "1", "rule racks {\n"
           "  require separation dimension=rack allow=rack:r1,rack:r2,rack:r3 deny=\n"
           "  require separation dimension=rack allow=rack:r2,rack:r3 deny=\n}\n")));
}

FPT_TEST(policy, constraint_operands_are_validated_against_their_key) {
  // A value that is not a number at all is refused while the document is read.
  FPT_CHECK_ERROR(parse(minimal_policy_text("1", "rule bad {\n"
                                                   "  require facility-attribute "
                                                   "key=power-feed-count op=at-least value=air\n}\n")),
                  ErrorCode::MalformedDocument);
  // The text reader cannot produce an operand of the wrong type, so that check
  // is exercised through the model: a cooling mode is not a power feed count.
  FacilityAttributeConstraint mismatched;
  mismatched.key = FacilityAttributeKey::PowerFeedCount;
  mismatched.op = AttributeOperator::AtLeast;
  mismatched.operand = AttributeValue(CoolingModeClass::Air);
  FPT_CHECK_ERROR(validate_constraint(Constraint{mismatched}), ErrorCode::InvalidAttributeValue);
  FPT_CHECK_ERROR(parse(minimal_policy_text("1", "rule bad {\n"
                                                   "  require facility-attribute "
                                                   "key=cooling-mode op=at-least value=air\n}\n")),
                  ErrorCode::InvalidOperatorForKey);
  // An ordered operator with no operand is refused by validation, because the
  // text reader cannot invent one.
  FPT_CHECK_ERROR(parse(minimal_policy_text("1", "rule bad {\n"
                                                   "  require facility-attribute "
                                                   "key=power-feed-count op=at-least\n}\n")),
                  ErrorCode::InvalidConstraintOperand);
  FPT_CHECK_ERROR(parse(minimal_policy_text("1", "rule bad {\n"
                                                   "  require facility-attribute "
                                                   "key=power-feed-count op=present value=2\n}\n")),
                  ErrorCode::InvalidConstraintOperand);
  FPT_CHECK_ERROR(parse(minimal_policy_text("1", "rule bad {\n"
                                                   "  require jurisdiction allow= deny=\n}\n")),
                  ErrorCode::InvalidConstraintOperand);
  FPT_CHECK_ERROR(parse(minimal_policy_text("1", "rule bad {\n"
                                                   "  require redundancy scope=tenant "
                                                   "dimension=rack min-distinct-domains=0\n}\n")),
                  ErrorCode::InvalidConstraintOperand);
  FPT_CHECK_ERROR(parse(minimal_policy_text("1", "rule bad {\n"
                                                   "  require co-tenancy dimension=rack "
                                                   "tenants= service-classes= max-shared=0\n}\n")),
                  ErrorCode::InvalidConstraintOperand);
  FPT_CHECK_ERROR(parse(minimal_policy_text("1", "rule bad {\n"
                                                   "  require maintenance-exposure "
                                                   "min-severity=degraded horizon=0s\n}\n")),
                  ErrorCode::InvalidConstraintOperand);
  FPT_CHECK_ERROR(parse(minimal_policy_text("1", "rule bad {\n"
                                                   "  require maintenance-exposure "
                                                   "min-severity=degraded horizon=400d\n}\n")),
                  ErrorCode::InvalidConstraintOperand);
  // A failure domain dimension without a kind, and a kind on a physical one.
  FPT_CHECK_ERROR(parse(minimal_policy_text("1", "rule bad {\n"
                                                   "  require anti-affinity scope=tenant "
                                                   "dimension=failure-domain max-shared=0\n}\n")),
                  ErrorCode::MissingField);
  FPT_CHECK_ERROR(parse(minimal_policy_text("1", "rule bad {\n"
                                                   "  require anti-affinity scope=tenant "
                                                   "dimension=rack:power max-shared=0\n}\n")),
                  ErrorCode::InvalidConstraintOperand);
  // A separation identity from the wrong dimension.
  FPT_CHECK_ERROR(parse(minimal_policy_text("1", "rule bad {\n"
                                                   "  require separation dimension=rack "
                                                   "deny=room:r1\n}\n")),
                  ErrorCode::InvalidConstraintOperand);
}

FPT_TEST(policy, override_envelopes_cannot_widen_authority) {
  const auto envelope = [](const std::string& body) {
    return minimal_policy_text("1", "envelope emergency {\n" + body + "}\n");
  };

  // A hard interlock is refused at load time, not narrowed silently.
  FPT_CHECK_ERROR(parse(envelope("  scope tenants=tenant:acme\n"
                                 "  allow-kinds maintenance-exposure\n"
                                 "  principals principal:sre\n"
                                 "  max-uses 1\n"
                                 "  grant-validity 5m\n")),
                  ErrorCode::HardInterlockNotOverridable);
  FPT_CHECK_ERROR(parse(envelope("  scope tenants=tenant:acme\n"
                                 "  allow-kinds jurisdiction\n"
                                 "  principals principal:sre\n"
                                 "  max-uses 1\n"
                                 "  grant-validity 5m\n")),
                  ErrorCode::HardInterlockNotOverridable);
  FPT_CHECK_ERROR(parse(envelope("  scope tenants=tenant:acme\n"
                                 "  allow-kinds separation\n"
                                 "  principals principal:sre\n"
                                 "  max-uses 1\n"
                                 "  grant-validity 5m\n")),
                  ErrorCode::HardInterlockNotOverridable);

  // An envelope that covers everything is not a scoped exception.
  FPT_CHECK_ERROR(parse(envelope("  scope\n"
                                 "  allow-kinds anti-affinity\n"
                                 "  principals principal:sre\n"
                                 "  max-uses 1\n"
                                 "  grant-validity 5m\n")),
                  ErrorCode::SelectorEmpty);
  FPT_CHECK_ERROR(parse(envelope("  scope tenants=\n"
                                 "  allow-kinds anti-affinity\n"
                                 "  principals principal:sre\n"
                                 "  max-uses 1\n"
                                 "  grant-validity 5m\n")),
                  ErrorCode::SelectorEmpty);
  FPT_CHECK_ERROR(parse(envelope("  scope tenants=tenant:acme\n"
                                 "  allow-kinds anti-affinity\n"
                                 "  principals=\n"
                                 "  max-uses 1\n"
                                 "  grant-validity 5m\n")),
                  ErrorCode::EnvelopeWithoutPrincipals);
  FPT_CHECK_ERROR(parse(envelope("  scope tenants=tenant:acme\n"
                                 "  allow-kinds=\n"
                                 "  principals principal:sre\n"
                                 "  max-uses 1\n"
                                 "  grant-validity 5m\n")),
                  ErrorCode::EnvelopeWithoutConstraintKinds);
  FPT_CHECK_ERROR(parse(envelope("  scope tenants=tenant:acme\n"
                                 "  allow-kinds anti-affinity\n"
                                 "  principals principal:sre\n"
                                 "  max-uses 0\n"
                                 "  grant-validity 5m\n")),
                  ErrorCode::InvalidConstraintOperand);
  FPT_CHECK_ERROR(parse(envelope("  scope tenants=tenant:acme\n"
                                 "  allow-kinds anti-affinity\n"
                                 "  principals principal:sre\n"
                                 "  max-uses 1\n"
                                 "  grant-validity 1us\n")),
                  ErrorCode::InvalidConstraintOperand);
  FPT_CHECK_ERROR(parse(envelope("  scope tenants=tenant:acme\n"
                                 "  allow-kinds anti-affinity\n"
                                 "  principals principal:sre\n"
                                 "  max-uses 1\n"
                                 "  grant-validity 15m\n"
                                 "  not-before 2026-02-14T10:00:00.000000Z\n"
                                 "  expires-at 2026-02-14T09:00:00.000000Z\n")),
                  ErrorCode::InvalidEnvelopeWindow);

  // A legitimate envelope is accepted, and its identity is part of the digest.
  auto accepted = parse(envelope("  scope tenants=tenant:acme\n"
                                 "  allow-kinds anti-affinity\n"
                                 "  principals principal:sre\n"
                                 "  max-uses 2\n"
                                 "  grant-validity 15m\n"));
  FPT_REQUIRE_OK(accepted);
  FPT_CHECK_EQ(accepted.value().envelopes.size(), std::size_t(1));
  auto changed = parse(envelope("  scope tenants=tenant:acme\n"
                                "  allow-kinds anti-affinity\n"
                                "  principals principal:sre\n"
                                "  max-uses 3\n"
                                "  grant-validity 15m\n"));
  FPT_REQUIRE_OK(changed);
  FPT_CHECK(!digest_equal(accepted.value().digest, changed.value().digest));
}

FPT_TEST(policy, the_hard_interlock_set_is_fixed_and_small) {
  const std::vector<ConstraintKind>& interlocks = hard_interlock_kinds();
  FPT_CHECK_EQ(interlocks.size(), std::size_t(3));
  for (const ConstraintKind kind : interlocks) {
    FPT_CHECK(constraint_kind_is_hard_interlock(kind));
  }
  FPT_CHECK(!constraint_kind_is_hard_interlock(ConstraintKind::AntiAffinity));
  FPT_CHECK(!constraint_kind_is_hard_interlock(ConstraintKind::Redundancy));
  FPT_CHECK(!constraint_kind_is_hard_interlock(ConstraintKind::CoTenancy));
  FPT_CHECK(!constraint_kind_is_hard_interlock(ConstraintKind::FacilityAttribute));
}

FPT_TEST(policy, constraint_kinds_are_injective_and_their_text_is_too) {
  // The variant alternative order is the enumerator order.
  const Constraint kinds[] = {
      JurisdictionConstraint{{}, {}},
      FacilityAttributeConstraint{},
      SeparationConstraint{},
      AntiAffinityConstraint{},
      RedundancyConstraint{},
      CoTenancyConstraint{},
      MaintenanceConstraint{},
  };
  for (std::size_t index = 0; index < 7; ++index) {
    FPT_CHECK_EQ(static_cast<std::size_t>(constraint_kind_of(kinds[index])), index);
  }

  // Distinct constraints must never render identically, because the canonical
  // order is defined by that rendering.
  std::vector<std::string> texts;
  AntiAffinityConstraint first;
  first.scope = PlacementScopeKind::Tenant;
  first.dimension = DimensionSelector{PlacementDimension::Rack, std::nullopt};
  first.max_shared = 0;
  AntiAffinityConstraint second = first;
  second.max_shared = 1;
  AntiAffinityConstraint third = first;
  third.scope = PlacementScopeKind::Any;
  AntiAffinityConstraint fourth = first;
  fourth.dimension = DimensionSelector{PlacementDimension::Row, std::nullopt};
  texts.push_back(constraint_text(Constraint{first}));
  texts.push_back(constraint_text(Constraint{second}));
  texts.push_back(constraint_text(Constraint{third}));
  texts.push_back(constraint_text(Constraint{fourth}));
  for (std::size_t index = 0; index < texts.size(); ++index) {
    for (std::size_t other = index + 1; other < texts.size(); ++other) {
      FPT_CHECK_NE(texts[index], texts[other]);
    }
  }
}

FPT_TEST(policy, selectors_match_only_on_facts_that_are_present) {
  RuleSelector selector;
  selector.tenants.push_back(TenantId::parse("tenant:acme").value());
  const TenantId acme = TenantId::parse("tenant:acme").value();
  const TenantId other = TenantId::parse("tenant:other").value();
  const ServiceClassId gold = ServiceClassId::parse("service-class:gold").value();
  const FacilityId dc1 = FacilityId::parse("facility:dc1").value();
  const JurisdictionId eu = JurisdictionId::parse("jurisdiction:eu-de").value();

  FPT_CHECK(rule_selector_matches(selector, acme, gold, dc1, eu));
  FPT_CHECK(!rule_selector_matches(selector, other, gold, dc1, eu));
  FPT_CHECK(rule_selector_matches(RuleSelector{}, other, gold, dc1, std::nullopt));

  RuleSelector by_jurisdiction;
  by_jurisdiction.jurisdictions.push_back(eu);
  FPT_CHECK(rule_selector_matches(by_jurisdiction, acme, gold, dc1, eu));
  // A facility whose jurisdiction is unknown matches no jurisdiction selector;
  // it is never treated as a match or as a mismatch by accident.
  FPT_CHECK(!rule_selector_matches(by_jurisdiction, acme, gold, dc1, std::nullopt));

  RuleSelector by_facility;
  by_facility.facilities.push_back(dc1);
  const FacilityId dc2 = FacilityId::parse("facility:dc2").value();
  FPT_CHECK(rule_selector_matches(by_facility, acme, gold, dc1, std::nullopt));
  FPT_CHECK(!rule_selector_matches(by_facility, acme, gold, dc2, std::nullopt));
  FPT_CHECK(RuleSelector{}.is_empty());
  FPT_CHECK(!by_facility.is_empty());
}

FPT_TEST(policy, the_text_reader_refuses_what_it_does_not_understand) {
  FPT_CHECK_ERROR(parse(minimal_policy_text() + "  stray\n"), ErrorCode::UnknownKeyword);
  FPT_CHECK_ERROR(parse("fpp-document policy\nformat 1\npolicy-id grid-a\nrevision 1\n"
                        "rule a {\n"
                        "  require anti-affinity scope=tenant dimension=rack max-shared=0\n"
                        "  bogus statement\n}\n"),
                  ErrorCode::UnknownKeyword);
  FPT_CHECK_ERROR(parse("fpp-document policy\nformat 1\npolicy-id grid-a\nrevision 1\n"
                        "rule a {\n"
                        "  require anti-affinity scope=tenant dimension=rack max-shared=0 "
                        "max-shared=1\n}\n"),
                  ErrorCode::DuplicateField);
  FPT_CHECK_ERROR(parse("fpp-document policy\nformat 1\npolicy-id grid-a\nrevision 1\n"
                        "rule a {\n"
                        "  require anti-affinity scope=tenant dimension=rack max-shared=0\n"
                        "  select tenants=tenant:acme\n"
                        "  select facilities=facility:dc1\n}\n"),
                  ErrorCode::DuplicateField);
  FPT_CHECK_ERROR(parse("fpp-document policy\nformat 1\npolicy-id grid-a\nrevision 1\n"
                        "rule a {\n"
                        "  require anti-affinity scope=tenant dimension=rack max-shared=0\n"),
                  ErrorCode::UnexpectedEndOfInput);
  FPT_CHECK_ERROR(parse("fpp-document policy\nformat 1\npolicy-id grid-a\nrevision 0\n"
                        "rule a {\n"
                        "  require anti-affinity scope=tenant dimension=rack max-shared=0\n}\n"),
                  ErrorCode::InvalidArgument);
  // A quoted value is the only place a space may appear, and an unknown escape
  // is still an error inside it.
  FPT_CHECK_ERROR(parse("fpp-document policy\nformat 1\npolicy-id grid-a\nrevision 1\n"
                        "rule a {\n"
                        "  description \"bad \\q escape\"\n"
                        "  require anti-affinity scope=tenant dimension=rack max-shared=0\n}\n"),
                  ErrorCode::UnknownEnumToken);
}
