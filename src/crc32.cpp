// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs.

#include "dccp/facility_placement_policy/digest.hpp"

#include <array>

namespace dccp::facility_placement_policy {
namespace {

/// Reflected Castagnoli polynomial (CRC-32C), as used by iSCSI and by the
/// hardware CRC instruction on x86 and ARM.
constexpr std::uint32_t kCrc32cPolynomial = 0x82F63B78u;

constexpr std::array<std::uint32_t, 256> make_table() noexcept {
  std::array<std::uint32_t, 256> table{};
  for (std::uint32_t index = 0; index < 256u; ++index) {
    std::uint32_t crc = index;
    for (int bit = 0; bit < 8; ++bit) {
      crc = (crc & 1u) != 0u ? ((crc >> 1) ^ kCrc32cPolynomial) : (crc >> 1);
    }
    table[index] = crc;
  }
  return table;
}

constexpr std::array<std::uint32_t, 256> kTable = make_table();

}  // namespace

std::uint32_t crc32c_update(std::uint32_t state, std::string_view bytes) noexcept {
  std::uint32_t crc = state ^ 0xFFFFFFFFu;
  for (const char ch : bytes) {
    const auto index = static_cast<std::uint8_t>(static_cast<unsigned char>(ch));
    crc = kTable[(crc ^ index) & 0xFFu] ^ (crc >> 8);
  }
  return crc ^ 0xFFFFFFFFu;
}

std::uint32_t crc32c(std::string_view bytes) noexcept { return crc32c_update(0u, bytes); }

bool crc32c_self_test() noexcept {
  // The standard CRC-32C check vector from the iSCSI specification.
  if (crc32c("123456789") != 0xE3069283u) {
    return false;
  }
  if (crc32c("") != 0u) {
    return false;
  }
  // The incremental form must agree with the one-shot form, including when the
  // value is fed one byte at a time.
  std::uint32_t incremental = 0u;
  const std::string_view sample = "facility-placement-policy";
  for (const char ch : sample) {
    const char single[2] = {ch, '\0'};
    incremental = crc32c_update(incremental, std::string_view(single, 1));
  }
  return incremental == crc32c(sample);
}

}  // namespace dccp::facility_placement_policy
