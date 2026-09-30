// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs.
//
// Canonical byte writer and reader. Not installed.
//
// The reader carries a sticky first failure: every primitive records the first
// error and returns a benign value afterwards, and a decode function checks
// ok() once before it returns the value it built. That keeps the decoders
// linear and free of error-handling noise while still making a partial decode
// impossible to mistake for a successful one.

#ifndef DCCP_FACILITY_PLACEMENT_POLICY_SRC_CANONICAL_INTERNAL_HPP
#define DCCP_FACILITY_PLACEMENT_POLICY_SRC_CANONICAL_INTERNAL_HPP

#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <string_view>
#include <vector>

#include "dccp/facility_placement_policy/canonical.hpp"
#include "dccp/facility_placement_policy/limits.hpp"
#include "dccp/facility_placement_policy/result.hpp"

namespace dccp::facility_placement_policy::internal {

class Writer {
 public:
  void u8(std::uint8_t value) { buffer_.push_back(value); }

  void u32(std::uint32_t value) {
    for (int shift = 0; shift < 32; shift += 8) {
      buffer_.push_back(static_cast<std::uint8_t>((value >> shift) & 0xFFu));
    }
  }

  void u64(std::uint64_t value) {
    for (int shift = 0; shift < 64; shift += 8) {
      buffer_.push_back(static_cast<std::uint8_t>((value >> shift) & 0xFFu));
    }
  }

  void i64(std::int64_t value) { u64(static_cast<std::uint64_t>(value)); }

  void boolean(bool value) { u8(value ? 1u : 0u); }

  void bytes(std::span<const std::uint8_t> value) { buffer_.insert(buffer_.end(), value.begin(), value.end()); }

  void blob(std::string_view value) {
    u32(static_cast<std::uint32_t>(value.size()));
    buffer_.insert(buffer_.end(), value.begin(), value.end());
  }

  void digest(const Digest& value) { bytes(std::span<const std::uint8_t>(value.data(), value.size())); }

  void raw_buffer(ByteBuffer value) { buffer_ = std::move(value); }

  const ByteBuffer& buffer() const noexcept { return buffer_; }
  ByteBuffer take() { return std::move(buffer_); }

 private:
  ByteBuffer buffer_;
};

class Reader {
 public:
  explicit Reader(std::span<const std::uint8_t> bytes) noexcept : bytes_(bytes) {}

  std::uint8_t u8() noexcept {
    if (offset_ >= bytes_.size()) {
      fail(Error(ErrorCode::TruncatedInput, "record ends inside a field"));
      return 0;
    }
    return bytes_[offset_++];
  }

  std::uint32_t u32() noexcept {
    std::uint32_t value = 0;
    for (int shift = 0; shift < 32; shift += 8) {
      value |= static_cast<std::uint32_t>(u8()) << shift;
    }
    return value;
  }

  std::uint64_t u64() noexcept {
    std::uint64_t value = 0;
    for (int shift = 0; shift < 64; shift += 8) {
      value |= static_cast<std::uint64_t>(u8()) << shift;
    }
    return value;
  }

  std::int64_t i64() noexcept { return static_cast<std::int64_t>(u64()); }

  bool boolean() noexcept {
    const std::uint8_t raw = u8();
    if (raw > 1u) {
      fail(Error(ErrorCode::InvalidBoolean, "encoded boolean is neither zero nor one"));
      return false;
    }
    return raw == 1u;
  }

  bool flag() noexcept { return boolean(); }

  /// Length-prefixed byte string, bounded before it is used.
  std::string text(std::size_t max_bytes) noexcept {
    const std::uint32_t length = u32();
    if (length > max_bytes) {
      fail(Error(ErrorCode::LimitExceeded, "declared text length exceeds the limit")
               .with_detail("declared=" + std::to_string(length) +
                            " limit=" + std::to_string(max_bytes)));
      return {};
    }
    return take_bytes(length);
  }

  std::span<const std::uint8_t> fixed(std::size_t count) noexcept {
    if (bytes_.size() - offset_ < count) {
      fail(Error(ErrorCode::TruncatedInput, "record ends inside a fixed-size field"));
      return {};
    }
    const std::span<const std::uint8_t> out = bytes_.subspan(offset_, count);
    offset_ += count;
    return out;
  }

  Digest digest() noexcept {
    Digest out{};
    const std::span<const std::uint8_t> raw = fixed(out.size());
    for (std::size_t index = 0; index < out.size() && index < raw.size(); ++index) {
      out[index] = raw[index];
    }
    return out;
  }

  bool ok() const noexcept { return !has_error_; }
  const Error& error() const noexcept { return error_; }
  bool at_end() const noexcept { return offset_ == bytes_.size(); }
  std::size_t remaining() const noexcept { return bytes_.size() - offset_; }

  void fail(Error error) noexcept {
    if (!has_error_) {
      has_error_ = true;
      error_ = std::move(error);
    }
  }

  /// Reads a count and refuses any value above the given bound. The bound is
  /// always a compile-time limit from limits.hpp, so no allocation is ever sized
  /// from an unvalidated number.
  std::uint32_t count(std::size_t limit, std::string_view what) noexcept {
    const std::uint32_t value = u32();
    if (value > limit) {
      fail(Error(ErrorCode::LimitExceeded, "declared element count exceeds the limit")
               .with_subject(std::string(what))
               .with_detail("declared=" + std::to_string(value) +
                            " limit=" + std::to_string(limit)));
      return 0;
    }
    return value;
  }

  /// Requires that the record ended exactly here.
  Result<void> finish(std::string_view what) noexcept {
    if (!ok()) {
      return error_;
    }
    if (!at_end()) {
      return Error(ErrorCode::TrailingContent, "record has bytes after the last field")
          .with_subject(std::string(what))
          .with_detail("extra=" + std::to_string(remaining()));
    }
    return success;
  }

 private:
  std::string take_bytes(std::size_t count) noexcept {
    if (bytes_.size() - offset_ < count) {
      fail(Error(ErrorCode::TruncatedInput, "record ends inside a length-prefixed field"));
      return {};
    }
    std::string out(reinterpret_cast<const char*>(bytes_.data() + offset_), count);
    offset_ += count;
    return out;
  }

  std::span<const std::uint8_t> bytes_;
  std::size_t offset_ = 0;
  Error error_{ErrorCode::Ok, std::string()};
  bool has_error_ = false;
};

template <class Enum>
void write_enum(Writer& writer, Enum value) {
  writer.u8(static_cast<std::uint8_t>(value));
}

template <class Enum>
Enum read_enum(Reader& reader, std::uint8_t max_value, std::string_view what) noexcept {
  const std::uint8_t raw = reader.u8();
  if (raw > max_value) {
    reader.fail(Error(ErrorCode::UnknownEnumToken, "encoded enum value is outside its range")
                    .with_subject(std::string(what))
                    .with_detail("value=" + std::to_string(raw)));
    return static_cast<Enum>(0);
  }
  return static_cast<Enum>(raw);
}

template <class Tag>
void write_id(Writer& writer, const StrongId<Tag>& id) { writer.blob(id.value()); }

/// Reads an identifier of the requested identity type. The type parameter is the
/// identity alias (TenantId, FacilityId, ...), not its tag, so a decoded value
/// can be handed straight to the field it belongs to.
template <class Id>
Id read_id(Reader& reader, std::string_view what) noexcept {
  const std::string raw = reader.text(kMaxIdentifierBytes);
  if (!reader.ok()) {
    return Id{};
  }
  auto parsed = Id::from_trusted(raw);
  if (!parsed.has_value()) {
    reader.fail(std::move(parsed.error()).with_subject(std::string(what)));
    return Id{};
  }
  return parsed.value();
}

template <class Tag>
void write_counter(Writer& writer, const Counter<Tag>& counter) { writer.u64(counter.value()); }

template <class Tag>
Counter<Tag> read_counter(Reader& reader, std::string_view what) noexcept {
  const std::uint64_t raw = reader.u64();
  if (!reader.ok()) {
    return {};
  }
  if (raw == 0) {
    reader.fail(Error(ErrorCode::InvalidGeneration, "encoded counter is zero, which means absent")
                    .with_subject(std::string(what)));
    return {};
  }
  return Counter<Tag>::from_value(raw).value();
}

template <class Tag>
void write_optional_counter(Writer& writer, const std::optional<Counter<Tag>>& counter) {
  writer.boolean(counter.has_value());
  if (counter.has_value()) {
    writer.u64(counter->value());
  }
}

template <class Tag>
std::optional<Counter<Tag>> read_optional_counter(Reader& reader, std::string_view what) noexcept {
  if (!reader.flag()) {
    return std::nullopt;
  }
  const std::uint64_t raw = reader.u64();
  if (!reader.ok()) {
    return std::nullopt;
  }
  if (raw == 0) {
    reader.fail(Error(ErrorCode::InvalidGeneration, "encoded counter is zero, which means absent")
                    .with_subject(std::string(what)));
    return std::nullopt;
  }
  return Counter<Tag>::from_value(raw).value();
}

template <class Id>
void write_optional_id(Writer& writer, const std::optional<Id>& id) {
  writer.boolean(id.has_value());
  if (id.has_value()) {
    writer.blob(id->value());
  }
}

template <class Id>
std::optional<Id> read_optional_id(Reader& reader, std::string_view what) noexcept {
  if (!reader.flag()) {
    return std::nullopt;
  }
  const Id id = read_id<Id>(reader, what);
  if (!reader.ok()) {
    return std::nullopt;
  }
  return id;
}

/// Counters that are legitimately absent. A watermark is unset until the first
/// evaluation observes a generation, and that state has to survive a round trip
/// exactly like every other state.
template <class Tag>
void write_maybe_counter(Writer& writer, const Counter<Tag>& counter) {
  writer.boolean(counter.is_valid());
  if (counter.is_valid()) {
    writer.u64(counter.value());
  }
}

template <class Tag>
Counter<Tag> read_maybe_counter(Reader& reader, std::string_view what) noexcept {
  if (!reader.flag()) {
    return {};
  }
  const std::uint64_t raw = reader.u64();
  if (!reader.ok()) {
    return {};
  }
  if (raw == 0) {
    reader.fail(Error(ErrorCode::InvalidGeneration,
                      "a present counter may not encode the absent value zero")
                    .with_subject(std::string(what)));
    return {};
  }
  return Counter<Tag>::from_value(raw).value();
}

/// Instants are written with their own set flag, so a decode is exact even for
/// a value that was never set.
void write_instant(Writer& writer, Instant instant);
Instant read_instant(Reader& reader, std::string_view what) noexcept;

void write_digest(Writer& writer, const Digest& digest);
Digest read_digest(Reader& reader);

}  // namespace dccp::facility_placement_policy::internal

#endif  // DCCP_FACILITY_PLACEMENT_POLICY_SRC_CANONICAL_INTERNAL_HPP
