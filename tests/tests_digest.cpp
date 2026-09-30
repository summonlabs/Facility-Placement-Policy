// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs.

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

#include "test_framework.hpp"
#include "test_support.hpp"

#include "dccp/facility_placement_policy/canonical.hpp"
#include "dccp/facility_placement_policy/digest.hpp"
#include "dccp/facility_placement_policy/limits.hpp"
#include "dccp/facility_placement_policy/text_util.hpp"

namespace {

using namespace dccp::facility_placement_policy;

/// The framed bytes of a small record with the given magic.
Result<ByteBuffer> frame_sample(std::uint64_t magic, const std::string& payload) {
  return frame_record(magic, std::span<const std::uint8_t>(
                                 reinterpret_cast<const std::uint8_t*>(payload.data()),
                                 payload.size()));
}

void write_u32(ByteBuffer& bytes, std::size_t offset, std::uint32_t value) {
  for (int shift = 0; shift < 32; shift += 8) {
    bytes[offset + static_cast<std::size_t>(shift / 8)] =
        static_cast<std::uint8_t>((value >> shift) & 0xFFu);
  }
}

void write_u64(ByteBuffer& bytes, std::size_t offset, std::uint64_t value) {
  for (int shift = 0; shift < 64; shift += 8) {
    bytes[offset + static_cast<std::size_t>(shift / 8)] =
        static_cast<std::uint8_t>((value >> shift) & 0xFFu);
  }
}

}  // namespace

FPT_TEST(digest, sha256_matches_the_fips_known_answers) {
  struct Vector {
    const char* input;
    const char* expected;
  };
  const Vector vectors[] = {
      {"", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"},
      {"abc", "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"},
      {"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
       "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"},
      {"The quick brown fox jumps over the lazy dog",
       "d7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c9e592"},
  };
  for (const Vector& vector : vectors) {
    FPT_CHECK_EQ(digest_hex(digest_of(vector.input)), std::string(vector.expected));
  }
  FPT_CHECK(digest_self_test());
}

FPT_TEST(digest, streaming_agrees_with_one_shot_across_every_chunk_boundary) {
  std::string sample;
  for (std::size_t index = 0; index < 200; ++index) {
    sample.push_back(static_cast<char>('a' + (index % 26)));
  }
  const Digest expected = digest_of(sample);
  for (std::size_t chunk = 1; chunk <= 70; ++chunk) {
    Sha256 hasher;
    for (std::size_t offset = 0; offset < sample.size(); offset += chunk) {
      const std::size_t take = (sample.size() - offset) < chunk ? (sample.size() - offset) : chunk;
      hasher.update(sample.data() + offset, take);
    }
    FPT_CHECK(digest_equal(hasher.finish(), expected));
  }
}

FPT_TEST(digest, finish_is_idempotent) {
  Sha256 hasher;
  hasher.update("facility placement policy");
  const Digest first = hasher.finish();
  const Digest second = hasher.finish();
  FPT_CHECK(digest_equal(first, second));
}

FPT_TEST(digest, parsing_is_strict_about_length_and_alphabet) {
  const Digest digest = digest_of("sample");
  const std::string hex = digest_hex(digest);
  FPT_CHECK_EQ(hex.size(), std::size_t(64));
  FPT_REQUIRE_OK(digest_parse(hex));
  FPT_REQUIRE_OK(digest_parse(ascii_upper(hex)));
  FPT_CHECK(digest_equal(digest_parse(hex).value(), digest));

  FPT_CHECK_ERROR(digest_parse(hex.substr(0, 63)), ErrorCode::MalformedDocument);
  FPT_CHECK_ERROR(digest_parse(hex + "0"), ErrorCode::MalformedDocument);
  FPT_CHECK_ERROR(digest_parse(std::string(64, 'z')), ErrorCode::MalformedDocument);
  FPT_CHECK_ERROR(digest_parse(std::string(64, ' ')), ErrorCode::MalformedDocument);
  FPT_CHECK_ERROR(digest_parse(""), ErrorCode::MalformedDocument);

  const std::string tagged = digest_tagged_hex(digest);
  FPT_CHECK_EQ(tagged.substr(0, 7), std::string("sha256:"));
  FPT_REQUIRE_OK(digest_parse_tagged(tagged));
  FPT_CHECK_ERROR(digest_parse_tagged("sha512:" + hex), ErrorCode::MalformedDocument);
  FPT_CHECK_ERROR(digest_parse_tagged(hex), ErrorCode::MalformedDocument);
}

FPT_TEST(digest, the_zero_digest_means_absent) {
  FPT_CHECK(digest_is_zero(Digest{}));
  FPT_CHECK(!digest_is_zero(digest_of("")));
  FPT_CHECK(!digest_equal(Digest{}, digest_of("")));
}

FPT_TEST(digest, crc32c_matches_the_standard_check_vector) {
  FPT_CHECK_EQ(crc32c("123456789"), 0xE3069283u);
  FPT_CHECK_EQ(crc32c(""), 0u);
  FPT_CHECK(crc32c_self_test());

  std::uint32_t incremental = 0;
  const std::string sample = "facility-placement-policy";
  for (const char ch : sample) {
    incremental = crc32c_update(incremental, std::string_view(&ch, 1));
  }
  FPT_CHECK_EQ(incremental, crc32c(sample));
}

FPT_TEST(digest, a_framed_record_round_trips_exactly) {
  const std::string payload = "some record payload";
  auto framed = frame_sample(kManifestMagic, payload);
  FPT_REQUIRE_OK(framed);
  FPT_CHECK_EQ(framed.value().size(), payload.size() + kRecordFrameOverhead);

  auto unframed = unframe_record(framed.value());
  FPT_REQUIRE_OK(unframed);
  FPT_CHECK_EQ(unframed.value().magic, kManifestMagic);
  FPT_CHECK_EQ(unframed.value().format_version, kStoreFormatVersion);
  FPT_CHECK_EQ(std::string(unframed.value().payload.begin(), unframed.value().payload.end()),
               payload);
  FPT_CHECK(digest_equal(unframed.value().digest, framed_record_digest(framed.value())));
}

FPT_TEST(digest, framing_refuses_every_kind_of_damage_in_a_defined_order) {
  const std::string payload = "payload";
  auto framed = frame_sample(kLedgerRecordMagic, payload);
  FPT_REQUIRE_OK(framed);
  const ByteBuffer good = framed.value();

  // An unknown magic is refused before anything else is interpreted.
  ByteBuffer unknown_magic = good;
  unknown_magic[0] = 0x7Au;
  unknown_magic[1] = 0x7Au;
  FPT_CHECK_ERROR(unframe_record(unknown_magic), ErrorCode::ManifestCorrupt);

  // An unknown format version.
  ByteBuffer wrong_version = good;
  write_u32(wrong_version, 8, 99u);
  FPT_CHECK_ERROR(unframe_record(wrong_version), ErrorCode::UnsupportedFormatVersion);

  // A reserved field that is not zero.
  ByteBuffer reserved = good;
  write_u32(reserved, 16, 1u);
  FPT_CHECK_ERROR(unframe_record(reserved), ErrorCode::ReservedFieldNotZero);

  // A declared payload larger than the bound.
  ByteBuffer absurd = good;
  write_u64(absurd, 20, static_cast<std::uint64_t>(kMaxRecordBytes) + 4096u);
  FPT_CHECK_ERROR(unframe_record(absurd), ErrorCode::LimitExceeded);

  // A declared length that is shorter than the file is trailing content; one
  // that is longer is a truncated file. The two are distinguished on purpose.
  ByteBuffer short_declared = good;
  write_u64(short_declared, 20, 1u);
  FPT_CHECK_ERROR(unframe_record(short_declared), ErrorCode::TrailingContent);
  ByteBuffer long_declared = good;
  write_u64(long_declared, 20, 4096u);
  FPT_CHECK_ERROR(unframe_record(long_declared), ErrorCode::TruncatedInput);

  FPT_CHECK_ERROR(unframe_record(std::span<const std::uint8_t>(good).first(good.size() - 1)),
                  ErrorCode::TruncatedInput);
  FPT_CHECK_ERROR(
      unframe_record(std::span<const std::uint8_t>(good).first(kRecordFrameOverhead - 1)),
      ErrorCode::TruncatedInput);

  ByteBuffer extended = good;
  extended.push_back(0u);
  FPT_CHECK_ERROR(unframe_record(extended), ErrorCode::TrailingContent);

  // A flipped payload byte is caught by the checksum.
  ByteBuffer flipped_payload = good;
  flipped_payload[kRecordHeaderBytes] ^= 0x01u;
  FPT_CHECK_ERROR(unframe_record(flipped_payload), ErrorCode::ChecksumMismatch);

  // A rewritten trailer is caught by the digest.
  ByteBuffer flipped_digest = good;
  flipped_digest.back() ^= 0xFFu;
  FPT_CHECK_ERROR(unframe_record(flipped_digest), ErrorCode::DigestMismatch);
}

FPT_TEST(digest, the_record_digest_never_covers_its_own_trailer) {
  auto framed = frame_sample(kManifestMagic, "abc");
  FPT_REQUIRE_OK(framed);
  const std::span<const std::uint8_t> bytes(framed.value());
  const Digest identity = framed_record_digest(bytes);
  const Digest content_only =
      digest_of(std::string_view(reinterpret_cast<const char*>(bytes.data()),
                                 bytes.size() - kDigestBytes));
  FPT_CHECK(digest_equal(identity, content_only));
  // Rewriting the trailer must not change the identity, only break the record.
  ByteBuffer tampered = framed.value();
  tampered.back() ^= 0x01u;
  FPT_CHECK(digest_equal(framed_record_digest(tampered), identity));
}
