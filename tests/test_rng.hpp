// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs.
//
// A deterministic generator for property tests. The seed is printed with every
// failure, so a failing case can be replayed exactly.

#ifndef DCCP_FACILITY_PLACEMENT_POLICY_TESTS_TEST_RNG_HPP
#define DCCP_FACILITY_PLACEMENT_POLICY_TESTS_TEST_RNG_HPP

#include <cstdint>
#include <string>

namespace fptest {

/// splitmix64: small, fast, and completely specified, so the same seed produces
/// the same sequence on every platform.
class Rng {
 public:
  explicit Rng(std::uint64_t seed) noexcept : state_(seed), seed_(seed) {}

  std::uint64_t next() noexcept {
    state_ += 0x9E3779B97F4A7C15ULL;
    std::uint64_t z = state_;
    z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ULL;
    z = (z ^ (z >> 27)) * 0x94D049BB133111EBULL;
    return z ^ (z >> 31);
  }

  /// Uniform value in [0, bound).
  std::uint64_t below(std::uint64_t bound) noexcept {
    return bound == 0 ? 0 : next() % bound;
  }

  bool flip() noexcept { return (next() & 1ULL) != 0ULL; }

  std::uint64_t seed() const noexcept { return seed_; }

 private:
  std::uint64_t state_;
  std::uint64_t seed_ = 0;
};

/// Adapts Rng to the UniformRandomBitGenerator concept so it can drive the
/// standard algorithms, which keeps a shuffle reproducible from its seed.
class RngAdapter {
 public:
  using result_type = std::uint64_t;

  explicit RngAdapter(Rng& rng) noexcept : rng_(&rng) {}

  static constexpr std::uint64_t min() noexcept { return 0; }
  static constexpr std::uint64_t max() noexcept { return UINT64_MAX; }
  std::uint64_t operator()() noexcept { return rng_->next(); }

 private:
  Rng* rng_;
};

}  // namespace fptest

#endif  // DCCP_FACILITY_PLACEMENT_POLICY_TESTS_TEST_RNG_HPP
