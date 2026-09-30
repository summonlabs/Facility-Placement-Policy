// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs.

#ifndef DCCP_FACILITY_PLACEMENT_POLICY_DIGEST_HPP
#define DCCP_FACILITY_PLACEMENT_POLICY_DIGEST_HPP

#include <array>
#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>

#include "dccp/facility_placement_policy/result.hpp"

namespace dccp::facility_placement_policy {

/// Length in bytes of the content digest used for canonical policy identity and
/// for durable-state integrity.
inline constexpr std::size_t kDigestBytes = 32;

/// A SHA-256 digest (FIPS 180-4).
///
/// The digest protects meaningful bindings only: the canonical revision identity
/// of a policy document, the identity of a verdict against its evidence, the
/// integrity of durable records against corruption, and grant binding. It is not
/// used as a key, a password primitive or an authentication tag.
using Digest = std::array<std::uint8_t, kDigestBytes>;

/// Incremental SHA-256.
class Sha256 {
 public:
  Sha256() noexcept;

  void update(const std::uint8_t* data, std::size_t size) noexcept;
  void update(std::string_view bytes) noexcept {
    update(reinterpret_cast<const std::uint8_t*>(bytes.data()), bytes.size());
  }
  void update(const char* data, std::size_t size) noexcept {
    update(reinterpret_cast<const std::uint8_t*>(data), size);
  }

  /// Finalizes the digest. The object is spent afterwards; construct a new one
  /// to compute another digest. Calling finish() twice returns the same value
  /// and does not corrupt state.
  Digest finish() noexcept;

 private:
  void compress(const std::uint8_t block[64]) noexcept;

  std::array<std::uint32_t, 8> state_;
  std::array<std::uint8_t, 64> buffer_;
  std::uint64_t total_bytes_;
  std::size_t buffered_;
  bool finished_;
};

/// Lower-case hexadecimal encoding of a digest (64 characters).
std::string digest_hex(const Digest& digest);

/// Strictly parses exactly 64 hexadecimal characters (either case).
Result<Digest> digest_parse(std::string_view text);

/// Convenience: digest of a byte range.
Digest digest_of(std::string_view bytes) noexcept;

/// "sha256"
inline constexpr std::string_view kDigestAlgorithmToken = "sha256";

/// Formats "sha256:<hex>".
std::string digest_tagged_hex(const Digest& digest);

/// Parses "sha256:<hex>"; any other algorithm token is rejected.
Result<Digest> digest_parse_tagged(std::string_view text);

/// True when every byte is zero. The all-zero digest means "absent".
bool digest_is_zero(const Digest& digest) noexcept;

/// Ordinary equality. This is not a constant-time comparison and must not be
/// used where a timing side channel would matter; it never is, because the
/// digests compared here are already published alongside their contents.
bool digest_equal(const Digest& lhs, const Digest& rhs) noexcept;

/// Runs the FIPS 180-4 known-answer vectors against this implementation. Not
/// noexcept: the vectors are compared as text, so it allocates.
bool digest_self_test();

/// CRC-32C (Castagnoli, reflected, polynomial 0x1EDC6F41), used as the record
/// checksum that catches accidental corruption before the digest is verified.
std::uint32_t crc32c(std::string_view bytes) noexcept;

/// Incremental CRC-32C. Pass 0 to start a new value.
std::uint32_t crc32c_update(std::uint32_t state, std::string_view bytes) noexcept;

/// Runs the standard CRC-32C check vector ("123456789" -> 0xE3069283).
bool crc32c_self_test() noexcept;

}  // namespace dccp::facility_placement_policy

#endif  // DCCP_FACILITY_PLACEMENT_POLICY_DIGEST_HPP
