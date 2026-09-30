// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs.

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

#include "test_framework.hpp"

#include "dccp/facility_placement_policy/canonical.hpp"
#include "dccp/facility_placement_policy/limits.hpp"
#include "dccp/facility_placement_policy/text.hpp"

namespace {

using namespace dccp::facility_placement_policy;

const char* const kPolicyText =
    "fpp-document policy\n"
    "format 1\n"
    "policy-id grid-a\n"
    "revision 3\n"
    "rule legal {\n"
    "  require jurisdiction allow=jurisdiction:eu-de deny=jurisdiction:us-east\n"
    "}\n"
    "rule spread {\n"
    "  description \"keep a tenant inside one failure domain set\"\n"
    "  select tenants=tenant:acme\n"
    "  require anti-affinity scope=tenant dimension=rack max-shared=0\n"
    "  require redundancy scope=tenant dimension=failure-domain:power min-distinct-domains=2\n"
    "  require facility-attribute key=power-feed-count op=at-least value=2\n"
    "  require maintenance-exposure min-severity=degraded horizon=7d\n"
    "}\n";

const char* const kRequestText =
    "fpp-document request\n"
    "format 1\n"
    "request-id req-9\n"
    "tenant tenant:acme\n"
    "service-class service-class:gold\n"
    "requested-at 2026-02-14T09:30:00.000000Z\n"
    "generations topology=12 failure-domain=9 tenant=4 service-class=3\n"
    "facility facility:dc1 jurisdiction=jurisdiction:eu-de\n"
    "attribute facility=facility:dc1 key=power-feed-count value=3\n"
    "attribute facility=facility:dc1 key=cooling-mode value=direct-liquid\n"
    "candidate c1 facility=facility:dc1 site=site:a room=room:1 row=row:3 rack=rack:07 "
    "failure-domains=power:pd-1,cooling:cd-2\n"
    "candidate c2 facility=facility:dc1 rack=rack:09 failure-domains=power:pd-2\n"
    "occupancy generation=77\n"
    "placed p1 tenant=tenant:acme service-class=service-class:gold facility=facility:dc1 "
    "rack=rack:07 failure-domains=power:pd-1\n"
    "maintenance generation=41\n"
    "exposure e1 kind=planned severity=blackout scope-facility=facility:dc1 "
    "start=2026-02-20T00:00:00.000000Z end=2026-02-21T00:00:00.000000Z\n";

PolicyDocument policy_fixture() { return parse_policy_document(kPolicyText).value(); }

PlacementRequest request_fixture() { return parse_request_document(kRequestText).value(); }

}  // namespace

FPT_TEST(canonical, a_policy_round_trips_byte_for_byte) {
  const PolicyDocument document = policy_fixture();
  auto encoded = encode_policy(document);
  FPT_REQUIRE_OK(encoded);
  auto decoded = decode_policy(encoded.value());
  FPT_REQUIRE_OK(decoded);
  auto reencoded = encode_policy(decoded.value());
  FPT_REQUIRE_OK(reencoded);
  FPT_CHECK(reencoded.value() == encoded.value());
  FPT_CHECK(digest_equal(decoded.value().digest, document.digest));
  FPT_CHECK_EQ(policy_document_text(decoded.value()), policy_document_text(document));
}

FPT_TEST(canonical, a_request_round_trips_byte_for_byte) {
  const PlacementRequest request = request_fixture();
  auto encoded = encode_request(request);
  FPT_REQUIRE_OK(encoded);
  auto decoded = decode_request(encoded.value());
  FPT_REQUIRE_OK(decoded);
  auto reencoded = encode_request(decoded.value());
  FPT_REQUIRE_OK(reencoded);
  FPT_CHECK(reencoded.value() == encoded.value());
  FPT_CHECK_EQ(request_document_text(decoded.value()), request_document_text(request));
  FPT_CHECK(digest_equal(request_digest(decoded.value()), request_digest(request)));
}

FPT_TEST(canonical, truncating_a_record_anywhere_is_refused) {
  const ByteBuffer encoded = encode_request(request_fixture()).value();
  for (std::size_t length = 0; length < encoded.size(); ++length) {
    const std::span<const std::uint8_t> prefix(encoded.data(), length);
    FPT_CHECK(!decode_request(prefix).has_value());
  }
  FPT_REQUIRE_OK(decode_request(std::span<const std::uint8_t>(encoded.data(), encoded.size())));
}

FPT_TEST(canonical, trailing_bytes_are_refused) {
  const ByteBuffer encoded = encode_policy(policy_fixture()).value();
  ByteBuffer extended = encoded;
  extended.push_back(0u);
  FPT_CHECK_ERROR(decode_policy(extended), ErrorCode::TrailingContent);
}

FPT_TEST(canonical, any_byte_mutation_either_fails_cleanly_or_round_trips_exactly) {
  const ByteBuffer original = encode_request(request_fixture()).value();
  std::size_t accepted = 0;
  for (std::size_t index = 0; index < original.size(); ++index) {
    for (const std::uint8_t value : {std::uint8_t{0x00}, std::uint8_t{0x01}, std::uint8_t{0xFF}}) {
      ByteBuffer mutated = original;
      if (mutated[index] == value) {
        continue;
      }
      mutated[index] = value;
      auto decoded = decode_request(mutated);
      if (!decoded.has_value()) {
        continue;
      }
      ++accepted;
      auto reencoded = encode_request(decoded.value());
      FPT_REQUIRE_OK(reencoded);
      // The decoder accepted the bytes, so it must have understood all of them.
      FPT_CHECK(reencoded.value() == mutated);
    }
  }
  // The sweep is only meaningful if it also produced accepted mutations.
  FPT_CHECK(accepted > 0);
}

FPT_TEST(canonical, a_verdict_and_a_grant_round_trip) {
  PolicySnapshot snapshot = make_policy_snapshot(
                               policy_fixture(), AuthorityEpoch::from_value(2).value(),
                               StoreSequence::from_value(5).value(), TopologyGeneration{},
                               FailureDomainGeneration{})
                               .value();
  EvaluationInput input;
  input.request = request_fixture();
  auto verdicts = evaluate(snapshot, input);
  FPT_REQUIRE_OK(verdicts);
  auto encoded = encode_verdict_set(verdicts.value());
  FPT_REQUIRE_OK(encoded);
  auto decoded = decode_verdict_set(encoded.value());
  FPT_REQUIRE_OK(decoded);
  FPT_CHECK(encode_verdict_set(decoded.value()).value() == encoded.value());

  // A decoded verdict is still verifiable: the digest it carries describes the
  // verdict it was issued for, not the bytes it arrived in.
  for (const CandidateVerdict& candidate : decoded.value().candidates) {
    FPT_CHECK(verify_verdict_digest(candidate));
  }

  OverrideGrant grant;
  grant.envelope_id = EnvelopeId::parse("e1").value();
  grant.envelope_digest = digest_of("envelope");
  grant.principal = PrincipalId::parse("principal:sre").value();
  grant.usage_id = UsageId::parse("usage-1").value();
  grant.policy = snapshot.binding();
  grant.authority_epoch = snapshot.authority_epoch;
  grant.tenant = TenantId::parse("tenant:acme").value();
  grant.service_class = ServiceClassId::parse("service-class:gold").value();
  grant.facility = FacilityId::parse("facility:dc1").value();
  grant.issued_at = Instant::parse("2026-02-14T09:00:00.000000Z").value();
  grant.expires_at = Instant::parse("2026-02-14T09:15:00.000000Z").value();
  auto canonical_grant = canonicalize_grant(grant);
  FPT_REQUIRE_OK(canonical_grant);
  FPT_CHECK(verify_grant_digest(canonical_grant.value()));
  auto encoded_grant = encode_grant(canonical_grant.value());
  FPT_REQUIRE_OK(encoded_grant);
  auto decoded_grant = decode_grant(encoded_grant.value());
  FPT_REQUIRE_OK(decoded_grant);
  FPT_CHECK(encode_grant(decoded_grant.value()).value() == encoded_grant.value());
  FPT_CHECK(verify_grant_digest(decoded_grant.value()));
  FPT_CHECK_EQ(grant_document_text(decoded_grant.value()),
               grant_document_text(canonical_grant.value()));

  // Changing a bound field changes the identity of the grant.
  OverrideGrant altered = canonical_grant.value();
  altered.facility = FacilityId::parse("facility:dc2").value();
  FPT_CHECK(!digest_equal(compute_grant_digest(altered), canonical_grant.value().grant_digest));
}

FPT_TEST(canonical, candidate_evidence_is_scoped_to_one_candidate) {
  const PlacementRequest request = request_fixture();
  const Digest first = candidate_evidence_digest(request, request.candidates.front());
  const Digest second = candidate_evidence_digest(request, request.candidates.back());
  FPT_CHECK(!digest_equal(first, second));

  // Adding an unrelated candidate must not change an existing candidate's
  // evidence digest, which is what makes a batch's verdicts independent.
  PlacementRequest extended = request;
  CandidatePlacement extra;
  extra.candidate_id = CandidateId::parse("c3").value();
  extra.location.facility = FacilityId::parse("facility:dc1").value();
  extra.location.rack = RackId::parse("rack:11").value();
  extended.candidates.push_back(extra);
  const auto recanonicalised = canonicalize_request(extended);
  FPT_REQUIRE_OK(recanonicalised);
  FPT_CHECK(digest_equal(candidate_evidence_digest(recanonicalised.value(),
                                                   recanonicalised.value().candidates.front()),
                         first));
  FPT_CHECK(!digest_equal(request_digest(recanonicalised.value()), request_digest(request)));
}

FPT_TEST(canonical, hostile_lengths_and_enumerators_are_refused) {
  // A declared count above its bound is refused before anything is allocated.
  {
    ByteBuffer encoded = encode_request(request_fixture()).value();
    // The candidate count sits after the fixed prefix; find it by searching for
    // the canonical count of 2 and replacing it with an absurd one. A mutation
    // sweep is not precise enough, so the count is rebuilt by hand.
    const std::uint32_t absurd = static_cast<std::uint32_t>(kMaxCandidatesPerRequest + 1u);
    bool patched = false;
    for (std::size_t index = 0; index + 4 <= encoded.size(); ++index) {
      if (encoded[index] == 2u && encoded[index + 1] == 0u && encoded[index + 2] == 0u &&
          encoded[index + 3] == 0u) {
        encoded[index] = static_cast<std::uint8_t>(absurd & 0xFFu);
        encoded[index + 1] = static_cast<std::uint8_t>((absurd >> 8) & 0xFFu);
        encoded[index + 2] = static_cast<std::uint8_t>((absurd >> 16) & 0xFFu);
        encoded[index + 3] = static_cast<std::uint8_t>((absurd >> 24) & 0xFFu);
        patched = true;
        break;
      }
    }
    FPT_CHECK(patched);
    const auto decoded = decode_request(encoded);
    FPT_CHECK(!decoded.has_value());
    if (!decoded.has_value()) {
      FPT_CHECK(decoded.error().code() == ErrorCode::LimitExceeded ||
                decoded.error().code() == ErrorCode::TruncatedInput ||
                decoded.error().code() == ErrorCode::MalformedIdentifier ||
                decoded.error().code() == ErrorCode::UnknownEnumToken);
    }
  }
  // An unknown format version is refused explicitly.
  {
    ByteBuffer encoded = encode_policy(policy_fixture()).value();
    encoded[0] = 9u;
    FPT_CHECK_ERROR(decode_policy(encoded), ErrorCode::UnsupportedFormatVersion);
  }
}

FPT_TEST(canonical, equal_documents_encode_identically_regardless_of_ordering) {
  const std::string reversed =
      "fpp-document policy\n"
      "format 1\n"
      "policy-id grid-a\n"
      "revision 3\n"
      "rule spread {\n"
      "  select tenants=tenant:acme\n"
      "  description \"keep a tenant inside one failure domain set\"\n"
      "  require maintenance-exposure horizon=7d min-severity=degraded\n"
      "  require facility-attribute value=2 op=at-least key=power-feed-count\n"
      "  require anti-affinity max-shared=0 dimension=rack scope=tenant\n"
      "  require redundancy min-distinct-domains=2 dimension=failure-domain:power "
      "scope=tenant\n"
      "}\n"
      "rule legal {\n"
      "  require jurisdiction deny=jurisdiction:us-east allow=jurisdiction:eu-de\n"
      "}\n";
  const auto left = parse_policy_document(kPolicyText);
  const auto right = parse_policy_document(reversed);
  FPT_REQUIRE_OK(left);
  FPT_REQUIRE_OK(right);
  FPT_CHECK(digest_equal(left.value().digest, right.value().digest));
  FPT_CHECK(encode_policy(left.value()).value() == encode_policy(right.value()).value());
}

FPT_TEST(canonical, the_envelope_digest_tracks_the_envelope) {
  const PolicyDocument document = policy_fixture();
  FPT_CHECK(document.envelopes.empty());
  OverrideEnvelope envelope;
  envelope.envelope_id = EnvelopeId::parse("e1").value();
  envelope.scope.tenants.push_back(TenantId::parse("tenant:acme").value());
  envelope.allowed_constraints.push_back(ConstraintKind::AntiAffinity);
  envelope.authorized_principals.push_back(PrincipalId::parse("principal:sre").value());
  envelope.max_uses = 2;
  envelope.grant_validity = Duration::from_minutes(15).value();
  const Digest first = envelope_digest(envelope);
  envelope.max_uses = 3;
  FPT_CHECK(!digest_equal(first, envelope_digest(envelope)));
  auto encoded = encode_envelope(envelope);
  FPT_REQUIRE_OK(encoded);
  FPT_CHECK(!encoded.value().empty());
}
