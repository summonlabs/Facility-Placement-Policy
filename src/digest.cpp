// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs.

#include "dccp/facility_placement_policy/digest.hpp"

#include <cstring>
#include <string>

namespace dccp::facility_placement_policy {
namespace {

constexpr std::array<std::uint32_t, 64> kRoundConstants = {
    0x428a2f98u, 0x71374491u, 0xb5c0fbcfu, 0xe9b5dba5u, 0x3956c25bu, 0x59f111f1u,
    0x923f82a4u, 0xab1c5ed5u, 0xd807aa98u, 0x12835b01u, 0x243185beu, 0x550c7dc3u,
    0x72be5d74u, 0x80deb1feu, 0x9bdc06a7u, 0xc19bf174u, 0xe49b69c1u, 0xefbe4786u,
    0x0fc19dc6u, 0x240ca1ccu, 0x2de92c6fu, 0x4a7484aau, 0x5cb0a9dcu, 0x76f988dau,
    0x983e5152u, 0xa831c66du, 0xb00327c8u, 0xbf597fc7u, 0xc6e00bf3u, 0xd5a79147u,
    0x06ca6351u, 0x14292967u, 0x27b70a85u, 0x2e1b2138u, 0x4d2c6dfcu, 0x53380d13u,
    0x650a7354u, 0x766a0abbu, 0x81c2c92eu, 0x92722c85u, 0xa2bfe8a1u, 0xa81a664bu,
    0xc24b8b70u, 0xc76c51a3u, 0xd192e819u, 0xd6990624u, 0xf40e3585u, 0x106aa070u,
    0x19a4c116u, 0x1e376c08u, 0x2748774cu, 0x34b0bcb5u, 0x391c0cb3u, 0x4ed8aa4au,
    0x5b9cca4fu, 0x682e6ff3u, 0x748f82eeu, 0x78a5636fu, 0x84c87814u, 0x8cc70208u,
    0x90befffau, 0xa4506cebu, 0xbef9a3f7u, 0xc67178f2u};

constexpr std::array<std::uint32_t, 8> kInitialState = {
    0x6a09e667u, 0xbb67ae85u, 0x3c6ef372u, 0xa54ff53au,
    0x510e527fu, 0x9b05688cu, 0x1f83d9abu, 0x5be0cd19u};

constexpr std::uint32_t rotr(std::uint32_t value, unsigned count) noexcept {
  return (value >> count) | (value << (32u - count));
}

constexpr std::uint32_t big_endian_word(const std::uint8_t* bytes) noexcept {
  return (static_cast<std::uint32_t>(bytes[0]) << 24) |
         (static_cast<std::uint32_t>(bytes[1]) << 16) |
         (static_cast<std::uint32_t>(bytes[2]) << 8) |
         static_cast<std::uint32_t>(bytes[3]);
}

constexpr char hex_digit(unsigned value) noexcept {
  return static_cast<char>(value < 10u ? ('0' + value) : ('a' + (value - 10u)));
}

constexpr int hex_value(char ch) noexcept {
  if (ch >= '0' && ch <= '9') {
    return ch - '0';
  }
  if (ch >= 'a' && ch <= 'f') {
    return 10 + (ch - 'a');
  }
  if (ch >= 'A' && ch <= 'F') {
    return 10 + (ch - 'A');
  }
  return -1;
}

}  // namespace

Sha256::Sha256() noexcept
    : state_(kInitialState), buffer_{}, total_bytes_(0), buffered_(0), finished_(false) {}

void Sha256::compress(const std::uint8_t block[64]) noexcept {
  std::uint32_t schedule[64];
  for (std::size_t index = 0; index < 16; ++index) {
    schedule[index] = big_endian_word(block + index * 4);
  }
  for (std::size_t index = 16; index < 64; ++index) {
    const std::uint32_t s0 = rotr(schedule[index - 15], 7) ^ rotr(schedule[index - 15], 18) ^
                             (schedule[index - 15] >> 3);
    const std::uint32_t s1 = rotr(schedule[index - 2], 17) ^ rotr(schedule[index - 2], 19) ^
                             (schedule[index - 2] >> 10);
    schedule[index] = schedule[index - 16] + s0 + schedule[index - 7] + s1;
  }

  std::uint32_t a = state_[0];
  std::uint32_t b = state_[1];
  std::uint32_t c = state_[2];
  std::uint32_t d = state_[3];
  std::uint32_t e = state_[4];
  std::uint32_t f = state_[5];
  std::uint32_t g = state_[6];
  std::uint32_t h = state_[7];

  for (std::size_t index = 0; index < 64; ++index) {
    const std::uint32_t sigma1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
    const std::uint32_t choose = (e & f) ^ ((~e) & g);
    const std::uint32_t temp1 = h + sigma1 + choose + kRoundConstants[index] + schedule[index];
    const std::uint32_t sigma0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
    const std::uint32_t majority = (a & b) ^ (a & c) ^ (b & c);
    const std::uint32_t temp2 = sigma0 + majority;

    h = g;
    g = f;
    f = e;
    e = d + temp1;
    d = c;
    c = b;
    b = a;
    a = temp1 + temp2;
  }

  state_[0] += a;
  state_[1] += b;
  state_[2] += c;
  state_[3] += d;
  state_[4] += e;
  state_[5] += f;
  state_[6] += g;
  state_[7] += h;

  std::memset(schedule, 0, sizeof(schedule));
}

void Sha256::update(const std::uint8_t* data, std::size_t size) noexcept {
  if (finished_ || size == 0) {
    return;
  }
  total_bytes_ += static_cast<std::uint64_t>(size);
  std::size_t offset = 0;

  if (buffered_ > 0) {
    while (offset < size && buffered_ < 64) {
      buffer_[buffered_++] = data[offset++];
    }
    if (buffered_ == 64) {
      compress(buffer_.data());
      buffered_ = 0;
    }
  }

  while (size - offset >= 64) {
    compress(data + offset);
    offset += 64;
  }

  while (offset < size) {
    buffer_[buffered_++] = data[offset++];
  }
}

Digest Sha256::finish() noexcept {
  if (!finished_) {
    const std::uint64_t bit_length = total_bytes_ * 8u;
    const std::uint8_t padding = 0x80u;
    update(&padding, 1);
    const std::uint8_t zero = 0x00u;
    while (buffered_ != 56) {
      update(&zero, 1);
    }
    std::uint8_t length_bytes[8];
    for (std::size_t index = 0; index < 8; ++index) {
      length_bytes[index] = static_cast<std::uint8_t>((bit_length >> (56u - index * 8u)) & 0xFFu);
    }
    update(length_bytes, 8);
    finished_ = true;
  }

  Digest out{};
  for (std::size_t index = 0; index < 8; ++index) {
    out[index * 4 + 0] = static_cast<std::uint8_t>((state_[index] >> 24) & 0xFFu);
    out[index * 4 + 1] = static_cast<std::uint8_t>((state_[index] >> 16) & 0xFFu);
    out[index * 4 + 2] = static_cast<std::uint8_t>((state_[index] >> 8) & 0xFFu);
    out[index * 4 + 3] = static_cast<std::uint8_t>(state_[index] & 0xFFu);
  }
  return out;
}

std::string digest_hex(const Digest& digest) {
  std::string out;
  out.reserve(kDigestBytes * 2);
  for (const std::uint8_t byte : digest) {
    out.push_back(hex_digit(byte >> 4));
    out.push_back(hex_digit(byte & 0x0Fu));
  }
  return out;
}

Result<Digest> digest_parse(std::string_view text) {
  if (text.size() != kDigestBytes * 2) {
    return Error(ErrorCode::MalformedDocument,
                 "a digest is exactly 64 hexadecimal characters")
        .with_subject(std::string(text.substr(0, 96)))
        .with_detail("length=" + std::to_string(text.size()));
  }
  Digest out{};
  for (std::size_t index = 0; index < kDigestBytes; ++index) {
    const int high = hex_value(text[index * 2]);
    const int low = hex_value(text[index * 2 + 1]);
    if (high < 0 || low < 0) {
      return Error(ErrorCode::MalformedDocument,
                   "a digest contains only hexadecimal characters")
          .with_subject(std::string(text.substr(0, 96)));
    }
    out[index] = static_cast<std::uint8_t>((high << 4) | low);
  }
  return out;
}

Digest digest_of(std::string_view bytes) noexcept {
  Sha256 hasher;
  hasher.update(bytes);
  return hasher.finish();
}

std::string digest_tagged_hex(const Digest& digest) {
  std::string out(kDigestAlgorithmToken);
  out.push_back(':');
  out.append(digest_hex(digest));
  return out;
}

Result<Digest> digest_parse_tagged(std::string_view text) {
  if (text.size() < kDigestAlgorithmToken.size() + 1 ||
      text.substr(0, kDigestAlgorithmToken.size()) != kDigestAlgorithmToken ||
      text[kDigestAlgorithmToken.size()] != ':') {
    return Error(ErrorCode::MalformedDocument,
                 "a tagged digest must start with the algorithm token followed by a colon")
        .with_subject(std::string(text.substr(0, 96)));
  }
  return digest_parse(text.substr(kDigestAlgorithmToken.size() + 1));
}

bool digest_is_zero(const Digest& digest) noexcept {
  for (const std::uint8_t byte : digest) {
    if (byte != 0u) {
      return false;
    }
  }
  return true;
}

bool digest_equal(const Digest& lhs, const Digest& rhs) noexcept {
  for (std::size_t index = 0; index < kDigestBytes; ++index) {
    if (lhs[index] != rhs[index]) {
      return false;
    }
  }
  return true;
}

bool digest_self_test() {
  struct Vector {
    std::string_view input;
    std::string_view expected;
  };
  static constexpr Vector kEmptyVectors[] = {
      {"", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"},
      {"abc", "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"},
      {"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
       "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"},
      {"message digest", "f7846f55cf23e14eebeab5b4e1550cad5b509e3348fbc4efa3a1413d393cb650"},
      {"The quick brown fox jumps over the lazy dog",
       "d7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c9e592"},
  };
  for (const Vector& vector : kEmptyVectors) {
    if (digest_hex(digest_of(vector.input)) != vector.expected) {
      return false;
    }
  }

  // The streaming path must agree with the one-shot path for every chunk size,
  // including chunk sizes that straddle the 64-byte block boundary and the
  // length field.
  std::string sample;
  for (std::size_t index = 0; index < 1000; ++index) {
    sample.push_back(static_cast<char>('a' + (index % 26)));
  }
  for (std::size_t chunk = 1; chunk <= 130; ++chunk) {
    Sha256 hasher;
    for (std::size_t offset = 0; offset < sample.size(); offset += chunk) {
      const std::size_t take = (sample.size() - offset) < chunk ? (sample.size() - offset) : chunk;
      hasher.update(sample.data() + offset, take);
    }
    if (!digest_equal(hasher.finish(), digest_of(sample))) {
      return false;
    }
  }

  // A million 'a' characters, streamed, exercises multi-block and the length
  // encoding well past 32 bits of message length.
  Sha256 hasher;
  std::string million;
  million.assign(1000, 'a');
  for (int index = 0; index < 1000; ++index) {
    hasher.update(million);
  }
  if (digest_hex(hasher.finish()) !=
      "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0") {
    return false;
  }

  // Parsing round trips, and rejects malformed input.
  const Digest parsed = digest_parse(digest_hex(digest_of(sample))).value();
  if (!digest_equal(parsed, digest_of(sample))) {
    return false;
  }
  if (digest_parse(std::string(63, '0')).has_value()) {
    return false;
  }
  if (digest_parse(std::string(64, 'z')).has_value()) {
    return false;
  }
  if (!digest_is_zero(Digest{})) {
    return false;
  }
  return digest_parse_tagged(digest_tagged_hex(parsed)).has_value();
}

}  // namespace dccp::facility_placement_policy
