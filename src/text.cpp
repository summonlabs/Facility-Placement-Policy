// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs.

#include "dccp/facility_placement_policy/text.hpp"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <type_traits>
#include <utility>
#include <variant>
#include <vector>

#include "dccp/facility_placement_policy/canonical.hpp"
#include "dccp/facility_placement_policy/text_util.hpp"
#include "internal_util.hpp"

namespace dccp::facility_placement_policy {
namespace {

// ---------------------------------------------------------------------------
// Lines, statements and sections
// ---------------------------------------------------------------------------

struct Line {
  std::size_t number = 0;
  std::string keyword;
  std::vector<std::string> positional;
  std::vector<std::pair<std::string, std::string>> named;
  bool opens_section = false;
};

constexpr bool is_space(char ch) noexcept {
  return ch == ' ' || ch == '\t' || ch == '\r' || ch == '\f' || ch == '\v';
}

class LineScanner {
 public:
  explicit LineScanner(std::string_view text) : text_(text) {}

  /// Reads the next content line. The returned bool is false at end of input.
  Result<bool> next(Line& out) {
    while (offset_ < text_.size()) {
      const std::size_t newline = text_.find('\n', offset_);
      const std::size_t stop = newline == std::string_view::npos ? text_.size() : newline;
      std::string_view raw = text_.substr(offset_, stop - offset_);
      offset_ = stop == text_.size() ? text_.size() : stop + 1;
      ++line_number_;
      if (!raw.empty() && raw.back() == '\r') {
        raw.remove_suffix(1);
      }
      if (raw.size() > kMaxLineBytes) {
        return Error(ErrorCode::LimitExceeded, "line exceeds the maximum length")
            .with_detail("line=" + std::to_string(line_number_) +
                         " limit=" + std::to_string(kMaxLineBytes));
      }
      const std::string_view trimmed = trim_ascii(raw);
      if (trimmed.empty() || trimmed.front() == '#') {
        continue;
      }
      return parse_line(trimmed, out);
    }
    return false;
  }

  std::size_t line_number() const noexcept { return line_number_; }

 private:
  Result<bool> parse_line(std::string_view line, Line& out) {
    out = Line{};
    out.number = line_number_;
    std::size_t index = 0;
    bool first = true;
    while (index < line.size()) {
      while (index < line.size() && is_space(line[index])) {
        ++index;
      }
      if (index >= line.size()) {
        break;
      }
      const char ch = line[index];
      if (ch == '}' || ch == '{') {
        ++index;
        while (index < line.size() && is_space(line[index])) {
          ++index;
        }
        if (index != line.size()) {
          return Error(ErrorCode::UnexpectedToken,
                       "a section brace must be alone at the end of its line")
              .with_detail("line=" + std::to_string(line_number_));
        }
        if (ch == '}' && !first) {
          return Error(ErrorCode::UnexpectedToken, "a closing brace must be alone on its line")
              .with_detail("line=" + std::to_string(line_number_));
        }
        if (ch == '}' && first) {
          out.keyword = "}";
          return true;
        }
        if (ch == '{' && first) {
          return Error(ErrorCode::UnexpectedToken, "a section brace must follow a keyword")
              .with_detail("line=" + std::to_string(line_number_));
        }
        out.opens_section = true;
        break;
      }

      std::string token;
      bool quoted = false;
      if (ch == '"') {
        quoted = true;
        ++index;
        std::string escaped;
        bool closed = false;
        while (index < line.size()) {
          const char inner = line[index];
          if (inner == '\\') {
            if (index + 1 >= line.size()) {
              break;
            }
            escaped.push_back(inner);
            escaped.push_back(line[index + 1]);
            index += 2;
            continue;
          }
          if (inner == '"') {
            closed = true;
            ++index;
            break;
          }
          escaped.push_back(inner);
          ++index;
        }
        if (!closed) {
          return Error(ErrorCode::TruncatedInput, "unterminated quoted value")
              .with_detail("line=" + std::to_string(line_number_));
        }
        auto unescaped = text_unescape(escaped);
        if (!unescaped.has_value()) {
          return unescaped.error();
        }
        token = std::move(unescaped.value());
      } else {
        while (index < line.size() && !is_space(line[index]) && line[index] != '"') {
          token.push_back(line[index]);
          ++index;
        }
        // "key=\"a value with spaces\"" is a named field whose value is quoted.
        // Without this the quoted text becomes a stray positional argument and
        // the field silently parses as empty.
        if (index < line.size() && line[index] == '"' && !token.empty() &&
            token.back() == '=') {
          ++index;
          std::string escaped;
          bool closed = false;
          while (index < line.size()) {
            const char inner = line[index];
            if (inner == '\\') {
              if (index + 1 >= line.size()) {
                break;
              }
              escaped.push_back(inner);
              escaped.push_back(line[index + 1]);
              index += 2;
              continue;
            }
            if (inner == '"') {
              closed = true;
              ++index;
              break;
            }
            escaped.push_back(inner);
            ++index;
          }
          if (!closed) {
            return Error(ErrorCode::TruncatedInput, "unterminated quoted value")
                .with_detail("line=" + std::to_string(line_number_));
          }
          auto unescaped = text_unescape(escaped);
          if (!unescaped.has_value()) {
            return unescaped.error();
          }
          token.append(unescaped.value());
        }
      }

      if (first) {
        // "keyword=" is the same statement as "keyword """ when the argument is
        // an empty list, and an empty list is a legitimate argument.
        const std::size_t equals = quoted ? std::string::npos : token.find('=');
        if (equals != std::string::npos && equals + 1 == token.size()) {
          out.keyword = token.substr(0, equals);
          out.positional.emplace_back();
        } else {
          out.keyword = std::move(token);
        }
        first = false;
        continue;
      }
      if (!quoted) {
        const std::size_t equals = token.find('=');
        if (equals != std::string::npos) {
          out.named.emplace_back(token.substr(0, equals), token.substr(equals + 1));
          continue;
        }
      }
      out.positional.push_back(std::move(token));
    }
    return true;
  }

  std::string_view text_;
  std::size_t offset_ = 0;
  std::size_t line_number_ = 0;
};

/// Reads one section body, stopping at its closing brace.
class SectionReader {
 public:
  SectionReader(LineScanner& scanner, std::size_t opened_at)
      : scanner_(scanner), opened_at_(opened_at) {}

  Result<bool> next(Line& out) {
    auto got = scanner_.next(out);
    if (!got.has_value()) {
      return got.error();
    }
    if (!got.value()) {
      return Error(ErrorCode::UnexpectedEndOfInput, "section is never closed")
          .with_detail("opened-line=" + std::to_string(opened_at_));
    }
    if (out.keyword == "}") {
      return false;
    }
    if (out.opens_section) {
      return Error(ErrorCode::UnsupportedFeature, "sections may not nest")
          .with_detail("line=" + std::to_string(out.number));
    }
    return true;
  }

 private:
  LineScanner& scanner_;
  std::size_t opened_at_;
};

/// Named-field access with duplicate and unknown-field detection.
class Fields {
 public:
  explicit Fields(const Line& line) : line_(line), used_(line.named.size(), false) {}

  Result<std::string> required(std::string_view key) {
    for (std::size_t index = 0; index < line_.named.size(); ++index) {
      if (line_.named[index].first != key) {
        continue;
      }
      if (used_[index]) {
        return Error(ErrorCode::DuplicateField, "field appears more than once")
            .with_subject(std::string(key))
            .with_detail("line=" + std::to_string(line_.number));
      }
      used_[index] = true;
      return line_.named[index].second;
    }
    return Error(ErrorCode::MissingField, "required field is missing")
        .with_subject(std::string(key))
        .with_detail("line=" + std::to_string(line_.number));
  }

  /// Engaged when the field was written, even when its value is empty.
  std::optional<std::string> optional(std::string_view key) {
    for (std::size_t index = 0; index < line_.named.size(); ++index) {
      if (line_.named[index].first != key) {
        continue;
      }
      if (used_[index]) {
        return std::nullopt;
      }
      used_[index] = true;
      return line_.named[index].second;
    }
    return std::nullopt;
  }

  Result<void> finish() const {
    for (std::size_t index = 0; index < line_.named.size(); ++index) {
      if (used_[index]) {
        continue;
      }
      // A field this statement understands but has already consumed is a repeat,
      // which is a different mistake from a field it does not understand.
      for (std::size_t other = 0; other < line_.named.size(); ++other) {
        if (other != index && used_[other] &&
            line_.named[other].first == line_.named[index].first) {
          return Error(ErrorCode::DuplicateField, "field appears more than once")
              .with_subject(line_.named[index].first)
              .with_detail("line=" + std::to_string(line_.number));
        }
      }
      return Error(ErrorCode::UnknownKeyword, "unknown field")
          .with_subject(line_.named[index].first)
          .with_detail("line=" + std::to_string(line_.number));
    }
    return success;
  }

 private:
  const Line& line_;
  std::vector<bool> used_;
};

Result<void> require_positional(const Line& line, std::size_t count) {
  if (line.positional.size() != count) {
    return Error(ErrorCode::UnexpectedToken, "statement has the wrong number of arguments")
        .with_subject(line.keyword)
        .with_detail("line=" + std::to_string(line.number) +
                     " expected=" + std::to_string(count) +
                     " actual=" + std::to_string(line.positional.size()));
  }
  return success;
}

Result<void> require_plain_statement(const Line& line, std::size_t count) {
  if (line.opens_section) {
    return Error(ErrorCode::UnexpectedToken, "this statement does not open a section")
        .with_subject(line.keyword)
        .with_detail("line=" + std::to_string(line.number));
  }
  return require_positional(line, count);
}

// ---------------------------------------------------------------------------
// Value parsing
// ---------------------------------------------------------------------------

std::vector<std::string> split_commas(std::string_view text) {
  std::vector<std::string> out;
  if (text.empty()) {
    return out;
  }
  std::size_t start = 0;
  while (true) {
    const std::size_t comma = text.find(',', start);
    const std::size_t stop = comma == std::string_view::npos ? text.size() : comma;
    out.emplace_back(text.substr(start, stop - start));
    if (comma == std::string_view::npos) {
      break;
    }
    start = comma + 1;
  }
  return out;
}

template <class Id>
Result<std::vector<Id>> parse_id_list(std::string_view text, std::string_view what) {
  std::vector<Id> out;
  for (const std::string& element : split_commas(text)) {
    auto parsed = Id::parse(element);
    if (!parsed.has_value()) {
      return std::move(parsed.error()).with_detail(std::string(what));
    }
    out.push_back(parsed.value());
  }
  return out;
}

Result<std::uint64_t> parse_counter_text(std::string_view text, std::string_view what) {
  auto value = parse_uint64_strict(text, what, false);
  if (!value.has_value()) {
    return value.error();
  }
  return value.value();
}

Result<std::uint32_t> parse_u32(std::string_view text, std::string_view what) {
  auto value = parse_uint64_strict(text, what, true);
  if (!value.has_value()) {
    return value.error();
  }
  if (value.value() > UINT32_MAX) {
    return Error(ErrorCode::NumericOverflow, "value does not fit in 32 bits")
        .with_subject(std::string(what));
  }
  return static_cast<std::uint32_t>(value.value());
}

Result<bool> parse_bool(std::string_view text, std::string_view what) {
  if (text == "true") {
    return true;
  }
  if (text == "false") {
    return false;
  }
  return Error(ErrorCode::InvalidBoolean, "boolean must be true or false")
      .with_subject(std::string(what));
}

Result<Instant> parse_instant_field(std::string_view text, std::string_view what) {
  auto parsed = Instant::parse(text);
  if (!parsed.has_value()) {
    return std::move(parsed.error()).with_detail(std::string(what));
  }
  return parsed.value();
}

Result<Digest> parse_digest_field(std::string_view text, std::string_view what) {
  auto parsed = digest_parse_tagged(text);
  if (!parsed.has_value()) {
    return std::move(parsed.error()).with_detail(std::string(what));
  }
  return parsed.value();
}

Result<std::vector<std::pair<FailureDomainKind, FailureDomainId>>> parse_failure_domains(
    std::string_view text) {
  std::vector<std::pair<FailureDomainKind, FailureDomainId>> out;
  for (const std::string& element : split_commas(text)) {
    const std::size_t colon = element.find(':');
    if (colon == std::string::npos) {
      return Error(ErrorCode::MalformedDocument,
                   "a failure domain is written kind:identity, for example power:pd-1")
          .with_subject(element);
    }
    auto kind = parse_failure_domain_kind(std::string_view(element).substr(0, colon));
    if (!kind.has_value()) {
      return kind.error();
    }
    auto id = FailureDomainId::parse(std::string_view(element).substr(colon + 1));
    if (!id.has_value()) {
      return id.error();
    }
    out.emplace_back(kind.value(), id.value());
  }
  return out;
}

Result<DimensionIdentity> parse_identity(std::string_view text, PlacementDimension dimension) {
  const std::size_t colon = text.find(':');
  if (colon == std::string::npos) {
    return Error(ErrorCode::MalformedDocument,
                 "an identity is written dimension:identity, for example rack:row-3")
        .with_subject(std::string(text));
  }
  auto parsed_dimension = parse_placement_dimension(text.substr(0, colon));
  if (!parsed_dimension.has_value()) {
    return parsed_dimension.error();
  }
  if (parsed_dimension.value() != dimension) {
    return Error(ErrorCode::InvalidConstraintOperand,
                 "identity prefix does not match the constraint's dimension")
        .with_subject(std::string(text));
  }
  const std::string_view value = text.substr(colon + 1);
  switch (dimension) {
    case PlacementDimension::Site: {
      auto id = SiteId::parse(value);
      if (!id.has_value()) {
        return id.error();
      }
      return DimensionIdentity(id.value());
    }
    case PlacementDimension::Room: {
      auto id = RoomId::parse(value);
      if (!id.has_value()) {
        return id.error();
      }
      return DimensionIdentity(id.value());
    }
    case PlacementDimension::Row: {
      auto id = RowId::parse(value);
      if (!id.has_value()) {
        return id.error();
      }
      return DimensionIdentity(id.value());
    }
    case PlacementDimension::Rack: {
      auto id = RackId::parse(value);
      if (!id.has_value()) {
        return id.error();
      }
      return DimensionIdentity(id.value());
    }
    case PlacementDimension::FailureDomain: {
      auto id = FailureDomainId::parse(value);
      if (!id.has_value()) {
        return id.error();
      }
      return DimensionIdentity(id.value());
    }
  }
  return Error(ErrorCode::InternalError, "unreachable dimension");
}

Result<std::vector<DimensionIdentity>> parse_identity_list(std::string_view text,
                                                           PlacementDimension dimension) {
  std::vector<DimensionIdentity> out;
  for (const std::string& element : split_commas(text)) {
    auto parsed = parse_identity(element, dimension);
    if (!parsed.has_value()) {
      return parsed.error();
    }
    out.push_back(parsed.value());
  }
  return out;
}

Result<DimensionSelector> parse_dimension_selector(std::string_view text) {
  const std::size_t colon = text.find(':');
  const std::string_view prefix = colon == std::string_view::npos ? text : text.substr(0, colon);
  auto dimension = parse_placement_dimension(prefix);
  if (!dimension.has_value()) {
    return dimension.error();
  }
  DimensionSelector selector;
  selector.dimension = dimension.value();
  if (dimension.value() == PlacementDimension::FailureDomain) {
    if (colon == std::string_view::npos) {
      return Error(ErrorCode::MissingField,
                   "a failure domain dimension needs a kind, for example failure-domain:power")
          .with_subject(std::string(text));
    }
    auto kind = parse_failure_domain_kind(text.substr(colon + 1));
    if (!kind.has_value()) {
      return kind.error();
    }
    selector.failure_domain_kind = kind.value();
  } else if (colon != std::string_view::npos) {
    return Error(ErrorCode::InvalidConstraintOperand,
                 "only a failure domain dimension carries a kind")
        .with_subject(std::string(text));
  }
  return selector;
}

Result<AttributeValue> parse_attribute_value(FacilityAttributeKey key, std::string_view text) {
  switch (attribute_value_kind(key)) {
    case AttributeValueKind::Unsigned: {
      auto value = parse_u32(text, facility_attribute_key_name(key));
      if (!value.has_value()) {
        return value.error();
      }
      return AttributeValue(value.value());
    }
    case AttributeValueKind::Instant: {
      auto value = Instant::parse(text);
      if (!value.has_value()) {
        return value.error();
      }
      return AttributeValue(value.value());
    }
    case AttributeValueKind::Redundancy: {
      auto value = parse_redundancy_class(text);
      if (!value.has_value()) {
        return value.error();
      }
      return AttributeValue(value.value());
    }
    case AttributeValueKind::CoolingMode: {
      auto value = parse_cooling_mode(text);
      if (!value.has_value()) {
        return value.error();
      }
      return AttributeValue(value.value());
    }
    case AttributeValueKind::FireSuppression: {
      auto value = parse_fire_suppression(text);
      if (!value.has_value()) {
        return value.error();
      }
      return AttributeValue(value.value());
    }
    case AttributeValueKind::NetworkIsolation: {
      auto value = parse_network_isolation(text);
      if (!value.has_value()) {
        return value.error();
      }
      return AttributeValue(value.value());
    }
    case AttributeValueKind::EnvironmentalControl: {
      auto value = parse_environmental_control(text);
      if (!value.has_value()) {
        return value.error();
      }
      return AttributeValue(value.value());
    }
  }
  return Error(ErrorCode::InternalError, "unreachable attribute value kind");
}

// ---------------------------------------------------------------------------
// Emitting helpers
// ---------------------------------------------------------------------------

void append_line(std::string& out, std::string_view text) {
  out.append(text);
  out.push_back('\n');
}

std::string quoted(std::string_view text) {
  std::string out;
  out.push_back('"');
  out.append(text_escape(text));
  out.push_back('"');
  return out;
}

template <class Range, class Render>
std::string joined(const Range& values, Render render) {
  std::string out;
  bool first = true;
  for (const auto& value : values) {
    if (!first) {
      out.push_back(',');
    }
    first = false;
    out.append(render(value));
  }
  return out;
}

/// A positional list argument. An empty list is written as an empty quoted
/// string, because an empty bare token would leave the statement with no
/// argument at all and the reader would see a keyword it does not know.
std::string positional_list(const std::string& joined_values) {
  return joined_values.empty() ? std::string("""") : joined_values;
}

std::string failure_domains_text(
    const std::vector<std::pair<FailureDomainKind, FailureDomainId>>& domains) {
  return joined(domains, [](const std::pair<FailureDomainKind, FailureDomainId>& entry) {
    return std::string(failure_domain_kind_name(entry.first)) + ":" +
           std::string(entry.second.value());
  });
}

std::string identities_text(const std::vector<DimensionIdentity>& identities) {
  return joined(identities,
                [](const DimensionIdentity& identity) { return dimension_identity_text(identity); });
}

// ---------------------------------------------------------------------------
// Policy documents
// ---------------------------------------------------------------------------

/// A selector states only the fields it restricts; an omitted field restricts
/// nothing. An omitted field is not the same as an empty one in the sense of a
/// typo: an unknown field name is still rejected by Fields::finish().
Result<RuleSelector> parse_selector_fields(Fields& fields) {
  RuleSelector selector;
  const auto tenants = fields.optional("tenants");
  if (tenants.has_value() && !tenants->empty()) {
    auto parsed = parse_id_list<TenantId>(*tenants, "selector tenants");
    if (!parsed.has_value()) {
      return parsed.error();
    }
    selector.tenants = std::move(parsed.value());
  }
  const auto service_classes = fields.optional("service-classes");
  if (service_classes.has_value() && !service_classes->empty()) {
    auto parsed = parse_id_list<ServiceClassId>(*service_classes, "selector service classes");
    if (!parsed.has_value()) {
      return parsed.error();
    }
    selector.service_classes = std::move(parsed.value());
  }
  const auto facilities = fields.optional("facilities");
  if (facilities.has_value() && !facilities->empty()) {
    auto parsed = parse_id_list<FacilityId>(*facilities, "selector facilities");
    if (!parsed.has_value()) {
      return parsed.error();
    }
    selector.facilities = std::move(parsed.value());
  }
  const auto jurisdictions = fields.optional("jurisdictions");
  if (jurisdictions.has_value() && !jurisdictions->empty()) {
    auto parsed = parse_id_list<JurisdictionId>(*jurisdictions, "selector jurisdictions");
    if (!parsed.has_value()) {
      return parsed.error();
    }
    selector.jurisdictions = std::move(parsed.value());
  }
  return selector;
}

std::string selector_text(const RuleSelector& selector) {
  std::string out = "tenants=";
  out.append(joined(selector.tenants,
                    [](const TenantId& id) { return std::string(id.value()); }));
  out.append(" service-classes=");
  out.append(joined(selector.service_classes,
                    [](const ServiceClassId& id) { return std::string(id.value()); }));
  out.append(" facilities=");
  out.append(joined(selector.facilities,
                    [](const FacilityId& id) { return std::string(id.value()); }));
  out.append(" jurisdictions=");
  out.append(joined(selector.jurisdictions,
                    [](const JurisdictionId& id) { return std::string(id.value()); }));
  return out;
}

Result<Constraint> parse_constraint_statement(const Line& line) {
  if (line.opens_section) {
    return Error(ErrorCode::UnexpectedToken, "a requirement does not open a section")
        .with_detail("line=" + std::to_string(line.number));
  }
  if (line.positional.size() != 1) {
    return Error(ErrorCode::UnexpectedToken,
                 "a requirement names exactly one constraint kind")
        .with_detail("line=" + std::to_string(line.number));
  }
  auto kind = parse_constraint_kind(line.positional.front());
  if (!kind.has_value()) {
    return kind.error();
  }
  Fields fields(line);
  Constraint constraint;
  switch (kind.value()) {
    case ConstraintKind::JurisdictionMembership: {
      JurisdictionConstraint concrete;
      const auto allow = fields.optional("allow");
      if (allow.has_value() && !allow->empty()) {
        auto parsed = parse_id_list<JurisdictionId>(*allow, "jurisdiction allow");
        if (!parsed.has_value()) {
          return parsed.error();
        }
        concrete.allow = std::move(parsed.value());
      }
      const auto deny = fields.optional("deny");
      if (deny.has_value() && !deny->empty()) {
        auto parsed = parse_id_list<JurisdictionId>(*deny, "jurisdiction deny");
        if (!parsed.has_value()) {
          return parsed.error();
        }
        concrete.deny = std::move(parsed.value());
      }
      constraint = concrete;
      break;
    }
    case ConstraintKind::FacilityAttribute: {
      FacilityAttributeConstraint concrete;
      const auto key = fields.required("key");
      if (!key.has_value()) {
        return key.error();
      }
      auto parsed_key = parse_facility_attribute_key(key.value());
      if (!parsed_key.has_value()) {
        return parsed_key.error();
      }
      concrete.key = parsed_key.value();
      const auto op = fields.required("op");
      if (!op.has_value()) {
        return op.error();
      }
      auto parsed_op = parse_attribute_operator(op.value());
      if (!parsed_op.has_value()) {
        return parsed_op.error();
      }
      concrete.op = parsed_op.value();
      const std::optional<std::string> value = fields.optional("value");
      if (value.has_value() && !value->empty()) {
        auto parsed_value = parse_attribute_value(concrete.key, *value);
        if (!parsed_value.has_value()) {
          return parsed_value.error();
        }
        concrete.operand = parsed_value.value();
      } else if (value.has_value() && concrete.op != AttributeOperator::Present &&
                 concrete.op != AttributeOperator::Absent) {
        return Error(ErrorCode::MissingField, "this operator needs a value")
            .with_detail("line=" + std::to_string(line.number));
      }
      constraint = concrete;
      break;
    }
    case ConstraintKind::Separation: {
      SeparationConstraint concrete;
      const auto dimension = fields.required("dimension");
      if (!dimension.has_value()) {
        return dimension.error();
      }
      auto parsed_dimension = parse_dimension_selector(dimension.value());
      if (!parsed_dimension.has_value()) {
        return parsed_dimension.error();
      }
      concrete.dimension = parsed_dimension.value();
      const auto allow = fields.optional("allow");
      if (allow.has_value() && !allow->empty()) {
        auto parsed = parse_identity_list(*allow, concrete.dimension.dimension);
        if (!parsed.has_value()) {
          return parsed.error();
        }
        concrete.allow = std::move(parsed.value());
      }
      const auto deny = fields.optional("deny");
      if (deny.has_value() && !deny->empty()) {
        auto parsed = parse_identity_list(*deny, concrete.dimension.dimension);
        if (!parsed.has_value()) {
          return parsed.error();
        }
        concrete.deny = std::move(parsed.value());
      }
      constraint = concrete;
      break;
    }
    case ConstraintKind::AntiAffinity: {
      AntiAffinityConstraint concrete;
      const auto scope = fields.required("scope");
      if (!scope.has_value()) {
        return scope.error();
      }
      auto parsed_scope = parse_placement_scope(scope.value());
      if (!parsed_scope.has_value()) {
        return parsed_scope.error();
      }
      concrete.scope = parsed_scope.value();
      const auto dimension = fields.required("dimension");
      if (!dimension.has_value()) {
        return dimension.error();
      }
      auto parsed_dimension = parse_dimension_selector(dimension.value());
      if (!parsed_dimension.has_value()) {
        return parsed_dimension.error();
      }
      concrete.dimension = parsed_dimension.value();
      const auto max_shared = fields.required("max-shared");
      if (!max_shared.has_value()) {
        return max_shared.error();
      }
      auto parsed_max = parse_u32(max_shared.value(), "max-shared");
      if (!parsed_max.has_value()) {
        return parsed_max.error();
      }
      concrete.max_shared = parsed_max.value();
      constraint = concrete;
      break;
    }
    case ConstraintKind::Redundancy: {
      RedundancyConstraint concrete;
      const auto scope = fields.required("scope");
      if (!scope.has_value()) {
        return scope.error();
      }
      auto parsed_scope = parse_placement_scope(scope.value());
      if (!parsed_scope.has_value()) {
        return parsed_scope.error();
      }
      concrete.scope = parsed_scope.value();
      const auto dimension = fields.required("dimension");
      if (!dimension.has_value()) {
        return dimension.error();
      }
      auto parsed_dimension = parse_dimension_selector(dimension.value());
      if (!parsed_dimension.has_value()) {
        return parsed_dimension.error();
      }
      concrete.dimension = parsed_dimension.value();
      const auto minimum = fields.required("min-distinct-domains");
      if (!minimum.has_value()) {
        return minimum.error();
      }
      auto parsed_minimum = parse_u32(minimum.value(), "min-distinct-domains");
      if (!parsed_minimum.has_value()) {
        return parsed_minimum.error();
      }
      concrete.min_distinct_domains = parsed_minimum.value();
      constraint = concrete;
      break;
    }
    case ConstraintKind::CoTenancy: {
      CoTenancyConstraint concrete;
      const auto dimension = fields.required("dimension");
      if (!dimension.has_value()) {
        return dimension.error();
      }
      auto parsed_dimension = parse_dimension_selector(dimension.value());
      if (!parsed_dimension.has_value()) {
        return parsed_dimension.error();
      }
      concrete.dimension = parsed_dimension.value();
      const auto tenants = fields.optional("tenants");
      if (tenants.has_value() && !tenants->empty()) {
        auto parsed = parse_id_list<TenantId>(*tenants, "co-tenancy tenants");
        if (!parsed.has_value()) {
          return parsed.error();
        }
        concrete.forbidden_tenants = std::move(parsed.value());
      }
      const auto service_classes = fields.optional("service-classes");
      if (service_classes.has_value() && !service_classes->empty()) {
        auto parsed = parse_id_list<ServiceClassId>(*service_classes, "co-tenancy service classes");
        if (!parsed.has_value()) {
          return parsed.error();
        }
        concrete.forbidden_service_classes = std::move(parsed.value());
      }
      const auto max_shared = fields.required("max-shared");
      if (!max_shared.has_value()) {
        return max_shared.error();
      }
      auto parsed_max = parse_u32(max_shared.value(), "max-shared");
      if (!parsed_max.has_value()) {
        return parsed_max.error();
      }
      concrete.max_shared = parsed_max.value();
      constraint = concrete;
      break;
    }
    case ConstraintKind::MaintenanceExposure: {
      MaintenanceConstraint concrete;
      const auto severity = fields.required("min-severity");
      if (!severity.has_value()) {
        return severity.error();
      }
      auto parsed_severity = parse_maintenance_severity(severity.value());
      if (!parsed_severity.has_value()) {
        return parsed_severity.error();
      }
      concrete.minimum_blocking_severity = parsed_severity.value();
      const auto horizon = fields.required("horizon");
      if (!horizon.has_value()) {
        return horizon.error();
      }
      auto parsed_horizon = Duration::parse(horizon.value());
      if (!parsed_horizon.has_value()) {
        return parsed_horizon.error();
      }
      concrete.horizon = parsed_horizon.value();
      constraint = concrete;
      break;
    }
  }
  const auto finished = fields.finish();
  if (!finished.has_value()) {
    return finished.error();
  }
  return constraint;
}

Result<Rule> parse_rule_section(LineScanner& scanner, const Line& header) {
  const auto positional = require_positional(header, 1);
  if (!positional.has_value()) {
    return positional.error();
  }
  auto rule_id = RuleId::parse(header.positional.front());
  if (!rule_id.has_value()) {
    return rule_id.error();
  }
  Rule rule;
  rule.rule_id = rule_id.value();
  bool have_selector = false;
  SectionReader section(scanner, header.number);
  Line line;
  while (true) {
    auto got = section.next(line);
    if (!got.has_value()) {
      return got.error();
    }
    if (!got.value()) {
      break;
    }
    if (line.keyword == "description") {
      const auto plain = require_plain_statement(line, 1);
      if (!plain.has_value()) {
        return plain.error();
      }
      if (!rule.description.empty()) {
        return Error(ErrorCode::DuplicateField, "a rule states its description twice")
            .with_detail("line=" + std::to_string(line.number));
      }
      auto checked = require_valid_utf8(line.positional.front(), "rule description", kMaxTextBytes);
      if (!checked.has_value()) {
        return checked.error();
      }
      rule.description = std::move(checked.value());
      continue;
    }
    if (line.keyword == "select") {
      if (have_selector) {
        return Error(ErrorCode::DuplicateField, "a rule states its selector twice")
            .with_detail("line=" + std::to_string(line.number));
      }
      if (line.opens_section || !line.positional.empty()) {
        return Error(ErrorCode::UnexpectedToken, "select takes named fields only")
            .with_detail("line=" + std::to_string(line.number));
      }
      Fields fields(line);
      auto selector = parse_selector_fields(fields);
      if (!selector.has_value()) {
        return selector.error();
      }
      const auto finished = fields.finish();
      if (!finished.has_value()) {
        return finished.error();
      }
      rule.selector = std::move(selector.value());
      have_selector = true;
      continue;
    }
    if (line.keyword == "require") {
      auto constraint = parse_constraint_statement(line);
      if (!constraint.has_value()) {
        return constraint.error();
      }
      rule.constraints.push_back(std::move(constraint.value()));
      continue;
    }
    return Error(ErrorCode::UnknownKeyword, "unknown statement inside a rule")
        .with_subject(line.keyword)
        .with_detail("line=" + std::to_string(line.number));
  }
  return rule;
}

Result<OverrideEnvelope> parse_envelope_section(LineScanner& scanner, const Line& header) {
  const auto positional = require_positional(header, 1);
  if (!positional.has_value()) {
    return positional.error();
  }
  auto envelope_id = EnvelopeId::parse(header.positional.front());
  if (!envelope_id.has_value()) {
    return envelope_id.error();
  }
  OverrideEnvelope envelope;
  envelope.envelope_id = envelope_id.value();
  bool have_scope = false;
  SectionReader section(scanner, header.number);
  Line line;
  while (true) {
    auto got = section.next(line);
    if (!got.has_value()) {
      return got.error();
    }
    if (!got.value()) {
      break;
    }
    if (line.keyword == "scope") {
      if (have_scope) {
        return Error(ErrorCode::DuplicateField, "an envelope states its scope twice")
            .with_detail("line=" + std::to_string(line.number));
      }
      if (line.opens_section || !line.positional.empty()) {
        return Error(ErrorCode::UnexpectedToken, "scope takes named fields only")
            .with_detail("line=" + std::to_string(line.number));
      }
      Fields fields(line);
      auto selector = parse_selector_fields(fields);
      if (!selector.has_value()) {
        return selector.error();
      }
      const auto finished = fields.finish();
      if (!finished.has_value()) {
        return finished.error();
      }
      envelope.scope = std::move(selector.value());
      have_scope = true;
      continue;
    }
    if (line.keyword == "allow-kinds") {
      const auto plain = require_plain_statement(line, 1);
      if (!plain.has_value()) {
        return plain.error();
      }
      for (const std::string& element : split_commas(line.positional.front())) {
        auto kind = parse_constraint_kind(element);
        if (!kind.has_value()) {
          return kind.error();
        }
        envelope.allowed_constraints.push_back(kind.value());
      }
      continue;
    }
    if (line.keyword == "principals") {
      const auto plain = require_plain_statement(line, 1);
      if (!plain.has_value()) {
        return plain.error();
      }
      auto principals = parse_id_list<PrincipalId>(line.positional.front(), "principals");
      if (!principals.has_value()) {
        return principals.error();
      }
      envelope.authorized_principals = std::move(principals.value());
      continue;
    }
    if (line.keyword == "max-uses") {
      const auto plain = require_plain_statement(line, 1);
      if (!plain.has_value()) {
        return plain.error();
      }
      auto value = parse_u32(line.positional.front(), "max-uses");
      if (!value.has_value()) {
        return value.error();
      }
      envelope.max_uses = value.value();
      continue;
    }
    if (line.keyword == "grant-validity") {
      const auto plain = require_plain_statement(line, 1);
      if (!plain.has_value()) {
        return plain.error();
      }
      auto value = Duration::parse(line.positional.front());
      if (!value.has_value()) {
        return value.error();
      }
      envelope.grant_validity = value.value();
      continue;
    }
    if (line.keyword == "not-before" || line.keyword == "expires-at") {
      const auto plain = require_plain_statement(line, 1);
      if (!plain.has_value()) {
        return plain.error();
      }
      auto value = parse_instant_field(line.positional.front(), line.keyword);
      if (!value.has_value()) {
        return value.error();
      }
      if (line.keyword == "not-before") {
        envelope.not_before = value.value();
      } else {
        envelope.expires_at = value.value();
      }
      continue;
    }
    return Error(ErrorCode::UnknownKeyword, "unknown statement inside an envelope")
        .with_subject(line.keyword)
        .with_detail("line=" + std::to_string(line.number));
  }
  return envelope;
}

Result<void> expect_header(LineScanner& scanner, std::string_view kind) {
  Line line;
  auto first = scanner.next(line);
  if (!first.has_value()) {
    return first.error();
  }
  if (!first.value()) {
    return Error(ErrorCode::EmptyDocument, "document is empty");
  }
  if (line.keyword != "fpp-document" || line.opens_section) {
    return Error(ErrorCode::MalformedDocument,
                 "a document starts with 'fpp-document <kind>'")
        .with_detail("line=" + std::to_string(line.number));
  }
  const auto positional = require_positional(line, 1);
  if (!positional.has_value()) {
    return positional.error();
  }
  if (line.positional.front() != kind) {
    return Error(ErrorCode::UnexpectedToken, "document kind does not match the requested parse")
        .with_detail("expected=" + std::string(kind) +
                     " actual=" + line.positional.front());
  }
  Line format_line;
  auto second = scanner.next(format_line);
  if (!second.has_value()) {
    return second.error();
  }
  if (!second.value() || format_line.keyword != "format" || format_line.opens_section) {
    return Error(ErrorCode::MalformedDocument, "a document states its format version second")
        .with_detail("line=" + std::to_string(format_line.number));
  }
  const auto format_positional = require_positional(format_line, 1);
  if (!format_positional.has_value()) {
    return format_positional.error();
  }
  auto version = parse_u32(format_line.positional.front(), "format");
  if (!version.has_value()) {
    return version.error();
  }
  if (version.value() != kTextFormatVersion) {
    return Error(ErrorCode::UnsupportedFormatVersion, "text format version is not supported")
        .with_detail("version=" + std::to_string(version.value()));
  }
  return success;
}

}  // namespace

Result<std::string> document_kind(std::string_view text) {
  LineScanner scanner(text);
  Line line;
  auto got = scanner.next(line);
  if (!got.has_value()) {
    return got.error();
  }
  if (!got.value()) {
    return Error(ErrorCode::EmptyDocument, "document is empty");
  }
  if (line.keyword != "fpp-document" || line.opens_section) {
    return Error(ErrorCode::MalformedDocument, "a document starts with 'fpp-document <kind>'")
        .with_detail("line=" + std::to_string(line.number));
  }
  const auto positional = require_positional(line, 1);
  if (!positional.has_value()) {
    return positional.error();
  }
  return line.positional.front();
}

Result<PolicyDocument> parse_policy_document(std::string_view text) {
  LineScanner scanner(text);
  const auto header = expect_header(scanner, "policy");
  if (!header.has_value()) {
    return header.error();
  }

  PolicyDocument document;
  bool have_policy_id = false;
  bool have_revision = false;
  Line line;
  while (true) {
    auto got = scanner.next(line);
    if (!got.has_value()) {
      return got.error();
    }
    if (!got.value()) {
      break;
    }
    if (line.keyword == "}") {
      return Error(ErrorCode::UnexpectedToken, "no section is open here")
          .with_detail("line=" + std::to_string(line.number));
    }
    if (line.keyword == "policy-id") {
      const auto plain = require_plain_statement(line, 1);
      if (!plain.has_value()) {
        return plain.error();
      }
      if (have_policy_id) {
        return Error(ErrorCode::DuplicateField, "a policy states its identity twice");
      }
      auto id = PolicyId::parse(line.positional.front());
      if (!id.has_value()) {
        return id.error();
      }
      document.policy_id = id.value();
      have_policy_id = true;
      continue;
    }
    if (line.keyword == "revision") {
      const auto plain = require_plain_statement(line, 1);
      if (!plain.has_value()) {
        return plain.error();
      }
      if (have_revision) {
        return Error(ErrorCode::DuplicateField, "a policy states its revision twice");
      }
      auto value = parse_counter_text(line.positional.front(), "revision");
      if (!value.has_value()) {
        return value.error();
      }
      auto counter = PolicyRevision::from_value(value.value());
      if (!counter.has_value()) {
        return counter.error();
      }
      document.revision = counter.value();
      have_revision = true;
      continue;
    }
    if (line.keyword == "rule" && line.opens_section) {
      auto rule = parse_rule_section(scanner, line);
      if (!rule.has_value()) {
        return rule.error();
      }
      document.rules.push_back(std::move(rule.value()));
      continue;
    }
    if (line.keyword == "envelope" && line.opens_section) {
      auto envelope = parse_envelope_section(scanner, line);
      if (!envelope.has_value()) {
        return envelope.error();
      }
      document.envelopes.push_back(std::move(envelope.value()));
      continue;
    }
    return Error(ErrorCode::UnknownKeyword, "unknown statement in a policy document")
        .with_subject(line.keyword)
        .with_detail("line=" + std::to_string(line.number));
  }

  if (!have_policy_id) {
    return Error(ErrorCode::MissingField, "a policy needs policy-id");
  }
  if (!have_revision) {
    return Error(ErrorCode::MissingField, "a policy needs revision");
  }
  return canonicalize_policy(std::move(document));
}

std::string policy_document_text(const PolicyDocument& document) {
  std::string out;
  append_line(out, "fpp-document policy");
  append_line(out, "format " + std::to_string(kTextFormatVersion));
  append_line(out, "policy-id " + std::string(document.policy_id.value()));
  append_line(out, "revision " + document.revision.to_string());
  for (const Rule& rule : document.rules) {
    append_line(out, "rule " + std::string(rule.rule_id.value()) + " {");
    if (!rule.description.empty()) {
      append_line(out, "  description " + quoted(rule.description));
    }
    if (!rule.selector.is_empty()) {
      append_line(out, "  select " + selector_text(rule.selector));
    }
    for (const Constraint& constraint : rule.constraints) {
      append_line(out, "  require " + constraint_text(constraint));
    }
    append_line(out, "}");
  }
  for (const OverrideEnvelope& envelope : document.envelopes) {
    append_line(out, "envelope " + std::string(envelope.envelope_id.value()) + " {");
    append_line(out, "  scope " + selector_text(envelope.scope));
    std::string kinds;
    bool first = true;
    for (const ConstraintKind kind : envelope.allowed_constraints) {
      if (!first) {
        kinds.push_back(',');
      }
      first = false;
      kinds.append(constraint_kind_name(kind));
    }
    append_line(out, "  allow-kinds " + positional_list(kinds));
    std::string principals;
    first = true;
    for (const PrincipalId& principal : envelope.authorized_principals) {
      if (!first) {
        principals.push_back(',');
      }
      first = false;
      principals.append(principal.value());
    }
    append_line(out, "  principals " + positional_list(principals));
    append_line(out, "  max-uses " + std::to_string(envelope.max_uses));
    append_line(out, "  grant-validity " + envelope.grant_validity.to_string());
    if (envelope.not_before.is_set()) {
      append_line(out, "  not-before " + envelope.not_before.to_string());
    }
    if (envelope.expires_at.is_set()) {
      append_line(out, "  expires-at " + envelope.expires_at.to_string());
    }
    append_line(out, "}");
  }
  return out;
}

namespace {

/// Reads the location fields shared by candidates and placed instances.
Result<FacilityLocation> parse_location_fields(Fields& fields) {
  FacilityLocation location;
  const auto facility = fields.required("facility");
  if (!facility.has_value()) {
    return facility.error();
  }
  auto parsed_facility = FacilityId::parse(facility.value());
  if (!parsed_facility.has_value()) {
    return parsed_facility.error();
  }
  location.facility = parsed_facility.value();

  const auto take_optional_id = [&fields](std::string_view key,
                                          auto& target) -> Result<void> {
    const std::optional<std::string> value = fields.optional(key);
    if (!value.has_value() || value->empty()) {
      return success;
    }
    using Id = std::decay_t<decltype(target)>::value_type;
    auto parsed = Id::parse(*value);
    if (!parsed.has_value()) {
      return std::move(parsed.error()).with_subject(std::string(key));
    }
    target = parsed.value();
    return success;
  };

  const auto site = take_optional_id("site", location.site);
  if (!site.has_value()) {
    return site.error();
  }
  const auto room = take_optional_id("room", location.room);
  if (!room.has_value()) {
    return room.error();
  }
  const auto row = take_optional_id("row", location.row);
  if (!row.has_value()) {
    return row.error();
  }
  const auto rack = take_optional_id("rack", location.rack);
  if (!rack.has_value()) {
    return rack.error();
  }

  const std::optional<std::string> domains = fields.optional("failure-domains");
  if (domains.has_value() && !domains->empty()) {
    auto parsed = parse_failure_domains(*domains);
    if (!parsed.has_value()) {
      return parsed.error();
    }
    location.failure_domains = std::move(parsed.value());
  }
  return location;
}

std::string location_text(const FacilityLocation& location, std::string_view indent) {
  std::string out(indent);
  out.append("facility=");
  out.append(location.facility.value());
  if (location.site.has_value()) {
    out.append(" site=");
    out.append(location.site->value());
  }
  if (location.room.has_value()) {
    out.append(" room=");
    out.append(location.room->value());
  }
  if (location.row.has_value()) {
    out.append(" row=");
    out.append(location.row->value());
  }
  if (location.rack.has_value()) {
    out.append(" rack=");
    out.append(location.rack->value());
  }
  if (!location.failure_domains.empty()) {
    out.append(" failure-domains=");
    out.append(failure_domains_text(location.failure_domains));
  }
  return out;
}

Result<MaintenanceScope> parse_scope_fields(Fields& fields) {
  MaintenanceScope scope;
  const auto take = [&fields](std::string_view key, auto& target) -> Result<void> {
    const std::optional<std::string> value = fields.optional(key);
    if (!value.has_value() || value->empty()) {
      return success;
    }
    using Id = std::decay_t<decltype(target)>::value_type;
    auto parsed = Id::parse(*value);
    if (!parsed.has_value()) {
      return std::move(parsed.error()).with_subject(std::string(key));
    }
    target = parsed.value();
    return success;
  };
  const auto facility = take("scope-facility", scope.facility);
  if (!facility.has_value()) {
    return facility.error();
  }
  const auto site = take("scope-site", scope.site);
  if (!site.has_value()) {
    return site.error();
  }
  const auto room = take("scope-room", scope.room);
  if (!room.has_value()) {
    return room.error();
  }
  const auto row = take("scope-row", scope.row);
  if (!row.has_value()) {
    return row.error();
  }
  const auto rack = take("scope-rack", scope.rack);
  if (!rack.has_value()) {
    return rack.error();
  }
  const std::optional<std::string> domain = fields.optional("scope-failure-domain");
  if (domain.has_value() && !domain->empty()) {
    const std::size_t colon = domain->find(':');
    if (colon == std::string::npos) {
      return Error(ErrorCode::MalformedDocument,
                   "a failure domain scope is written kind:identity")
          .with_subject(*domain);
    }
    auto kind = parse_failure_domain_kind(std::string_view(*domain).substr(0, colon));
    if (!kind.has_value()) {
      return kind.error();
    }
    auto id = FailureDomainId::parse(std::string_view(*domain).substr(colon + 1));
    if (!id.has_value()) {
      return id.error();
    }
    scope.failure_domain_kind = kind.value();
    scope.failure_domain = id.value();
  }
  return scope;
}

std::string scope_text(const MaintenanceScope& scope) {
  std::string out;
  const auto append_id = [&out](std::string_view key, const auto& value) {
    if (value.has_value()) {
      out.push_back(' ');
      out.append(key);
      out.push_back('=');
      out.append(value->value());
    }
  };
  append_id("scope-facility", scope.facility);
  append_id("scope-site", scope.site);
  append_id("scope-room", scope.room);
  append_id("scope-row", scope.row);
  append_id("scope-rack", scope.rack);
  if (scope.failure_domain_kind.has_value() && scope.failure_domain.has_value()) {
    out.append(" scope-failure-domain=");
    out.append(failure_domain_kind_name(*scope.failure_domain_kind));
    out.push_back(':');
    out.append(scope.failure_domain->value());
  }
  return out;
}

}  // namespace

Result<PlacementRequest> parse_request_document(std::string_view text) {
  LineScanner scanner(text);
  const auto header = expect_header(scanner, "request");
  if (!header.has_value()) {
    return header.error();
  }

  PlacementRequest request;
  bool have_request_id = false;
  bool have_tenant = false;
  bool have_service_class = false;
  bool have_requested_at = false;
  bool have_generations = false;
  bool have_occupancy = false;
  bool have_maintenance = false;
  std::vector<std::pair<FacilityId, std::pair<FacilityAttributeKey, AttributeValue>>> pending;

  Line line;
  while (true) {
    auto got = scanner.next(line);
    if (!got.has_value()) {
      return got.error();
    }
    if (!got.value()) {
      break;
    }
    if (line.keyword == "}") {
      return Error(ErrorCode::UnexpectedToken, "no section is open here")
          .with_detail("line=" + std::to_string(line.number));
    }
    if (line.keyword == "request-id" || line.keyword == "tenant" ||
        line.keyword == "service-class") {
      const auto plain = require_plain_statement(line, 1);
      if (!plain.has_value()) {
        return plain.error();
      }
      if (line.keyword == "request-id") {
        if (have_request_id) {
          return Error(ErrorCode::DuplicateField, "a request states its identity twice");
        }
        auto id = RequestId::parse(line.positional.front());
        if (!id.has_value()) {
          return id.error();
        }
        request.request_id = id.value();
        have_request_id = true;
      } else if (line.keyword == "tenant") {
        if (have_tenant) {
          return Error(ErrorCode::DuplicateField, "a request states its tenant twice");
        }
        auto id = TenantId::parse(line.positional.front());
        if (!id.has_value()) {
          return id.error();
        }
        request.tenant = id.value();
        have_tenant = true;
      } else {
        if (have_service_class) {
          return Error(ErrorCode::DuplicateField, "a request states its service class twice");
        }
        auto id = ServiceClassId::parse(line.positional.front());
        if (!id.has_value()) {
          return id.error();
        }
        request.service_class = id.value();
        have_service_class = true;
      }
      continue;
    }
    if (line.keyword == "requested-at") {
      const auto plain = require_plain_statement(line, 1);
      if (!plain.has_value()) {
        return plain.error();
      }
      if (have_requested_at) {
        return Error(ErrorCode::DuplicateField, "a request states its instant twice");
      }
      auto instant = parse_instant_field(line.positional.front(), "requested-at");
      if (!instant.has_value()) {
        return instant.error();
      }
      request.requested_at = instant.value();
      have_requested_at = true;
      continue;
    }
    if (line.keyword == "generations") {
      if (have_generations) {
        return Error(ErrorCode::DuplicateField, "a request states its generations twice");
      }
      if (line.opens_section || !line.positional.empty()) {
        return Error(ErrorCode::UnexpectedToken, "generations takes named fields only")
            .with_detail("line=" + std::to_string(line.number));
      }
      Fields fields(line);
      const auto topology = fields.required("topology");
      if (!topology.has_value()) {
        return topology.error();
      }
      auto parsed_topology = parse_counter_text(topology.value(), "topology-generation");
      if (!parsed_topology.has_value()) {
        return parsed_topology.error();
      }
      request.generations.topology = TopologyGeneration::from_value(parsed_topology.value()).value();
      const auto failure_domain = fields.required("failure-domain");
      if (!failure_domain.has_value()) {
        return failure_domain.error();
      }
      auto parsed_failure_domain =
          parse_counter_text(failure_domain.value(), "failure-domain-generation");
      if (!parsed_failure_domain.has_value()) {
        return parsed_failure_domain.error();
      }
      request.generations.failure_domain =
          FailureDomainGeneration::from_value(parsed_failure_domain.value()).value();
      const auto tenant = fields.required("tenant");
      if (!tenant.has_value()) {
        return tenant.error();
      }
      auto parsed_tenant = parse_counter_text(tenant.value(), "tenant-generation");
      if (!parsed_tenant.has_value()) {
        return parsed_tenant.error();
      }
      request.generations.tenant = TenantGeneration::from_value(parsed_tenant.value()).value();
      const auto service_class = fields.required("service-class");
      if (!service_class.has_value()) {
        return service_class.error();
      }
      auto parsed_service_class =
          parse_counter_text(service_class.value(), "service-class-generation");
      if (!parsed_service_class.has_value()) {
        return parsed_service_class.error();
      }
      request.generations.service_class =
          ServiceClassGeneration::from_value(parsed_service_class.value()).value();
      const auto finished = fields.finish();
      if (!finished.has_value()) {
        return finished.error();
      }
      have_generations = true;
      continue;
    }
    if (line.keyword == "facility") {
      const auto plain = require_plain_statement(line, 1);
      if (!plain.has_value()) {
        return plain.error();
      }
      auto id = FacilityId::parse(line.positional.front());
      if (!id.has_value()) {
        return id.error();
      }
      Fields fields(line);
      FacilityRecord record;
      record.facility = id.value();
      const std::optional<std::string> jurisdiction = fields.optional("jurisdiction");
      if (jurisdiction.has_value() && !jurisdiction->empty()) {
        auto parsed = JurisdictionId::parse(*jurisdiction);
        if (!parsed.has_value()) {
          return parsed.error();
        }
        record.jurisdiction = parsed.value();
      }
      const auto finished = fields.finish();
      if (!finished.has_value()) {
        return finished.error();
      }
      request.facilities.push_back(std::move(record));
      continue;
    }
    if (line.keyword == "attribute") {
      Fields fields(line);
      const auto facility = fields.required("facility");
      if (!facility.has_value()) {
        return facility.error();
      }
      auto parsed_facility = FacilityId::parse(facility.value());
      if (!parsed_facility.has_value()) {
        return parsed_facility.error();
      }
      const auto key = fields.required("key");
      if (!key.has_value()) {
        return key.error();
      }
      auto parsed_key = parse_facility_attribute_key(key.value());
      if (!parsed_key.has_value()) {
        return parsed_key.error();
      }
      const auto value = fields.required("value");
      if (!value.has_value()) {
        return value.error();
      }
      auto parsed_value = parse_attribute_value(parsed_key.value(), value.value());
      if (!parsed_value.has_value()) {
        return parsed_value.error();
      }
      const auto finished = fields.finish();
      if (!finished.has_value()) {
        return finished.error();
      }
      pending.emplace_back(parsed_facility.value(),
                           std::make_pair(parsed_key.value(), parsed_value.value()));
      continue;
    }
    if (line.keyword == "candidate") {
      const auto plain = require_plain_statement(line, 1);
      if (!plain.has_value()) {
        return plain.error();
      }
      auto id = CandidateId::parse(line.positional.front());
      if (!id.has_value()) {
        return id.error();
      }
      Fields fields(line);
      auto location = parse_location_fields(fields);
      if (!location.has_value()) {
        return location.error();
      }
      const auto finished = fields.finish();
      if (!finished.has_value()) {
        return finished.error();
      }
      CandidatePlacement candidate;
      candidate.candidate_id = id.value();
      candidate.location = std::move(location.value());
      request.candidates.push_back(std::move(candidate));
      continue;
    }
    if (line.keyword == "occupancy") {
      if (have_occupancy) {
        return Error(ErrorCode::DuplicateField, "a request states occupancy twice");
      }
      Fields fields(line);
      const auto generation = fields.required("generation");
      if (!generation.has_value()) {
        return generation.error();
      }
      auto parsed = parse_counter_text(generation.value(), "occupancy-generation");
      if (!parsed.has_value()) {
        return parsed.error();
      }
      const auto finished = fields.finish();
      if (!finished.has_value()) {
        return finished.error();
      }
      request.occupancy.generation = OccupancyGeneration::from_value(parsed.value()).value();
      have_occupancy = true;
      continue;
    }
    if (line.keyword == "placed") {
      const auto plain = require_plain_statement(line, 1);
      if (!plain.has_value()) {
        return plain.error();
      }
      auto id = PlacementId::parse(line.positional.front());
      if (!id.has_value()) {
        return id.error();
      }
      Fields fields(line);
      PlacedInstance instance;
      instance.placement_id = id.value();
      const auto tenant = fields.required("tenant");
      if (!tenant.has_value()) {
        return tenant.error();
      }
      auto parsed_tenant = TenantId::parse(tenant.value());
      if (!parsed_tenant.has_value()) {
        return parsed_tenant.error();
      }
      instance.tenant = parsed_tenant.value();
      const auto service_class = fields.required("service-class");
      if (!service_class.has_value()) {
        return service_class.error();
      }
      auto parsed_service_class = ServiceClassId::parse(service_class.value());
      if (!parsed_service_class.has_value()) {
        return parsed_service_class.error();
      }
      instance.service_class = parsed_service_class.value();
      auto location = parse_location_fields(fields);
      if (!location.has_value()) {
        return location.error();
      }
      instance.location = std::move(location.value());
      const auto finished = fields.finish();
      if (!finished.has_value()) {
        return finished.error();
      }
      request.occupancy.instances.push_back(std::move(instance));
      continue;
    }
    if (line.keyword == "maintenance") {
      if (have_maintenance) {
        return Error(ErrorCode::DuplicateField, "a request states maintenance twice");
      }
      Fields fields(line);
      const auto generation = fields.required("generation");
      if (!generation.has_value()) {
        return generation.error();
      }
      auto parsed = parse_counter_text(generation.value(), "maintenance-generation");
      if (!parsed.has_value()) {
        return parsed.error();
      }
      const auto finished = fields.finish();
      if (!finished.has_value()) {
        return finished.error();
      }
      request.maintenance.generation = MaintenanceGeneration::from_value(parsed.value()).value();
      have_maintenance = true;
      continue;
    }
    if (line.keyword == "exposure") {
      const auto plain = require_plain_statement(line, 1);
      if (!plain.has_value()) {
        return plain.error();
      }
      auto id = ExposureId::parse(line.positional.front());
      if (!id.has_value()) {
        return id.error();
      }
      Fields fields(line);
      MaintenanceExposure exposure;
      exposure.exposure_id = id.value();
      const auto kind = fields.required("kind");
      if (!kind.has_value()) {
        return kind.error();
      }
      auto parsed_kind = parse_maintenance_kind(kind.value());
      if (!parsed_kind.has_value()) {
        return parsed_kind.error();
      }
      exposure.kind = parsed_kind.value();
      const auto severity = fields.required("severity");
      if (!severity.has_value()) {
        return severity.error();
      }
      auto parsed_severity = parse_maintenance_severity(severity.value());
      if (!parsed_severity.has_value()) {
        return parsed_severity.error();
      }
      exposure.severity = parsed_severity.value();
      auto scope = parse_scope_fields(fields);
      if (!scope.has_value()) {
        return scope.error();
      }
      exposure.scope = std::move(scope.value());
      const auto start = fields.required("start");
      if (!start.has_value()) {
        return start.error();
      }
      auto parsed_start = parse_instant_field(start.value(), "start");
      if (!parsed_start.has_value()) {
        return parsed_start.error();
      }
      exposure.start = parsed_start.value();
      const auto end = fields.required("end");
      if (!end.has_value()) {
        return end.error();
      }
      auto parsed_end = parse_instant_field(end.value(), "end");
      if (!parsed_end.has_value()) {
        return parsed_end.error();
      }
      exposure.end = parsed_end.value();
      const auto finished = fields.finish();
      if (!finished.has_value()) {
        return finished.error();
      }
      request.maintenance.exposures.push_back(std::move(exposure));
      continue;
    }
    return Error(ErrorCode::UnknownKeyword, "unknown statement in a request document")
        .with_subject(line.keyword)
        .with_detail("line=" + std::to_string(line.number));
  }

  if (!have_request_id) {
    return Error(ErrorCode::MissingField, "a request needs request-id");
  }
  if (!have_tenant) {
    return Error(ErrorCode::MissingField, "a request needs tenant");
  }
  if (!have_service_class) {
    return Error(ErrorCode::MissingField, "a request needs service-class");
  }
  if (!have_requested_at) {
    return Error(ErrorCode::MissingField, "a request needs requested-at");
  }
  if (!have_generations) {
    return Error(ErrorCode::MissingField, "a request needs generations");
  }

  for (const auto& entry : pending) {
    FacilityRecord* record = nullptr;
    for (FacilityRecord& candidate : request.facilities) {
      if (candidate.facility == entry.first) {
        record = &candidate;
        break;
      }
    }
    if (record == nullptr) {
      return Error(ErrorCode::NotFound,
                   "an attribute names a facility the request does not describe")
          .with_detail("facility=" + std::string(entry.first.value()));
    }
    record->attributes.emplace_back(entry.second.first, entry.second.second);
  }
  return canonicalize_request(std::move(request));
}

std::string request_document_text(const PlacementRequest& request) {
  std::string out;
  append_line(out, "fpp-document request");
  append_line(out, "format " + std::to_string(kTextFormatVersion));
  append_line(out, "request-id " + std::string(request.request_id.value()));
  append_line(out, "tenant " + std::string(request.tenant.value()));
  append_line(out, "service-class " + std::string(request.service_class.value()));
  append_line(out, "requested-at " + request.requested_at.to_string());
  append_line(out, "generations topology=" + request.generations.topology.to_string() +
                       " failure-domain=" + request.generations.failure_domain.to_string() +
                       " tenant=" + request.generations.tenant.to_string() +
                       " service-class=" + request.generations.service_class.to_string());
  for (const FacilityRecord& record : request.facilities) {
    std::string statement = "facility " + std::string(record.facility.value());
    if (record.jurisdiction.has_value()) {
      statement.append(" jurisdiction=");
      statement.append(record.jurisdiction->value());
    }
    append_line(out, statement);
  }
  for (const FacilityRecord& record : request.facilities) {
    for (const auto& entry : record.attributes) {
      append_line(out, "attribute facility=" + std::string(record.facility.value()) +
                           " key=" + std::string(facility_attribute_key_name(entry.first)) +
                           " value=" + attribute_value_text(entry.second));
    }
  }
  for (const CandidatePlacement& candidate : request.candidates) {
    append_line(out, "candidate " + std::string(candidate.candidate_id.value()) + " " +
                         location_text(candidate.location, ""));
  }
  if (request.occupancy.generation.has_value()) {
    append_line(out, "occupancy generation=" + request.occupancy.generation->to_string());
  }
  for (const PlacedInstance& instance : request.occupancy.instances) {
    append_line(out, "placed " + std::string(instance.placement_id.value()) +
                         " tenant=" + std::string(instance.tenant.value()) +
                         " service-class=" + std::string(instance.service_class.value()) + " " +
                         location_text(instance.location, ""));
  }
  if (request.maintenance.generation.has_value()) {
    append_line(out, "maintenance generation=" + request.maintenance.generation->to_string());
  }
  for (const MaintenanceExposure& exposure : request.maintenance.exposures) {
    append_line(out, "exposure " + std::string(exposure.exposure_id.value()) +
                         " kind=" + std::string(maintenance_kind_name(exposure.kind)) +
                         " severity=" + std::string(maintenance_severity_name(exposure.severity)) +
                         scope_text(exposure.scope) + " start=" + exposure.start.to_string() +
                         " end=" + exposure.end.to_string());
  }
  return out;
}

Result<OverrideGrant> parse_grant_document(std::string_view text) {
  LineScanner scanner(text);
  const auto header = expect_header(scanner, "grant");
  if (!header.has_value()) {
    return header.error();
  }
  OverrideGrant grant;
  bool have_envelope = false;
  bool have_usage = false;
  bool have_policy_revision = false;
  bool have_issued = false;
  bool have_expires = false;
  Line line;
  while (true) {
    auto got = scanner.next(line);
    if (!got.has_value()) {
      return got.error();
    }
    if (!got.value()) {
      break;
    }
    if (line.keyword == "}") {
      return Error(ErrorCode::UnexpectedToken, "no section is open here")
          .with_detail("line=" + std::to_string(line.number));
    }
    if (line.positional.size() != 1) {
      return Error(ErrorCode::UnexpectedToken, "a grant statement takes exactly one value")
          .with_subject(line.keyword)
          .with_detail("line=" + std::to_string(line.number));
    }
    const std::string& value = line.positional.front();
    if (line.keyword == "envelope") {
      auto id = EnvelopeId::parse(value);
      if (!id.has_value()) {
        return id.error();
      }
      grant.envelope_id = id.value();
      have_envelope = true;
    } else if (line.keyword == "envelope-digest") {
      auto parsed = parse_digest_field(value, "envelope-digest");
      if (!parsed.has_value()) {
        return parsed.error();
      }
      grant.envelope_digest = parsed.value();
    } else if (line.keyword == "principal") {
      auto id = PrincipalId::parse(value);
      if (!id.has_value()) {
        return id.error();
      }
      grant.principal = id.value();
    } else if (line.keyword == "usage-id") {
      auto id = UsageId::parse(value);
      if (!id.has_value()) {
        return id.error();
      }
      grant.usage_id = id.value();
      have_usage = true;
    } else if (line.keyword == "policy-id") {
      auto id = PolicyId::parse(value);
      if (!id.has_value()) {
        return id.error();
      }
      grant.policy.policy_id = id.value();
    } else if (line.keyword == "policy-revision") {
      auto parsed = parse_counter_text(value, "policy-revision");
      if (!parsed.has_value()) {
        return parsed.error();
      }
      grant.policy.revision = PolicyRevision::from_value(parsed.value()).value();
      have_policy_revision = true;
    } else if (line.keyword == "policy-digest") {
      auto parsed = parse_digest_field(value, "policy-digest");
      if (!parsed.has_value()) {
        return parsed.error();
      }
      grant.policy.digest = parsed.value();
    } else if (line.keyword == "authority-epoch") {
      auto parsed = parse_counter_text(value, "authority-epoch");
      if (!parsed.has_value()) {
        return parsed.error();
      }
      grant.authority_epoch = AuthorityEpoch::from_value(parsed.value()).value();
    } else if (line.keyword == "tenant") {
      auto id = TenantId::parse(value);
      if (!id.has_value()) {
        return id.error();
      }
      grant.tenant = id.value();
    } else if (line.keyword == "service-class") {
      auto id = ServiceClassId::parse(value);
      if (!id.has_value()) {
        return id.error();
      }
      grant.service_class = id.value();
    } else if (line.keyword == "facility") {
      auto id = FacilityId::parse(value);
      if (!id.has_value()) {
        return id.error();
      }
      grant.facility = id.value();
    } else if (line.keyword == "issued-at") {
      auto parsed = parse_instant_field(value, "issued-at");
      if (!parsed.has_value()) {
        return parsed.error();
      }
      grant.issued_at = parsed.value();
      have_issued = true;
    } else if (line.keyword == "expires-at") {
      auto parsed = parse_instant_field(value, "expires-at");
      if (!parsed.has_value()) {
        return parsed.error();
      }
      grant.expires_at = parsed.value();
      have_expires = true;
    } else if (line.keyword == "grant-digest") {
      auto parsed = parse_digest_field(value, "grant-digest");
      if (!parsed.has_value()) {
        return parsed.error();
      }
      grant.grant_digest = parsed.value();
    } else {
      return Error(ErrorCode::UnknownKeyword, "unknown statement in a grant document")
          .with_subject(line.keyword)
          .with_detail("line=" + std::to_string(line.number));
    }
  }
  if (!have_envelope || !have_usage || !have_policy_revision || !have_issued || !have_expires) {
    return Error(ErrorCode::MissingField, "a grant document is incomplete");
  }
  if (!verify_grant_digest(grant)) {
    return Error(ErrorCode::DigestMismatch, "grant digest does not match its contents");
  }
  return grant;
}

std::string grant_document_text(const OverrideGrant& grant) {
  std::string out;
  append_line(out, "fpp-document grant");
  append_line(out, "format " + std::to_string(kTextFormatVersion));
  append_line(out, "envelope " + std::string(grant.envelope_id.value()));
  append_line(out, "envelope-digest " + digest_tagged_hex(grant.envelope_digest));
  append_line(out, "principal " + std::string(grant.principal.value()));
  append_line(out, "usage-id " + std::string(grant.usage_id.value()));
  append_line(out, "policy-id " + std::string(grant.policy.policy_id.value()));
  append_line(out, "policy-revision " + grant.policy.revision.to_string());
  append_line(out, "policy-digest " + digest_tagged_hex(grant.policy.digest));
  append_line(out, "authority-epoch " + grant.authority_epoch.to_string());
  append_line(out, "tenant " + std::string(grant.tenant.value()));
  append_line(out, "service-class " + std::string(grant.service_class.value()));
  append_line(out, "facility " + std::string(grant.facility.value()));
  append_line(out, "issued-at " + grant.issued_at.to_string());
  append_line(out, "expires-at " + grant.expires_at.to_string());
  append_line(out, "grant-digest " + digest_tagged_hex(grant.grant_digest));
  return out;
}

Result<PlacementVerdictSet> parse_verdict_document(std::string_view text) {
  LineScanner scanner(text);
  const auto header = expect_header(scanner, "verdict");
  if (!header.has_value()) {
    return header.error();
  }
  PlacementVerdictSet verdicts;
  bool have_policy_revision = false;
  bool have_evaluated_at = false;
  bool have_generations = false;
  Line line;
  while (true) {
    auto got = scanner.next(line);
    if (!got.has_value()) {
      return got.error();
    }
    if (!got.value()) {
      break;
    }
    if (line.keyword == "candidate" && line.opens_section) {
      const auto positional = require_positional(line, 1);
      if (!positional.has_value()) {
        return positional.error();
      }
      auto id = CandidateId::parse(line.positional.front());
      if (!id.has_value()) {
        return id.error();
      }
      CandidateVerdict verdict;
      verdict.candidate_id = id.value();
      bool have_decision = false;
      SectionReader section(scanner, line.number);
      Line body;
      while (true) {
        auto inner = section.next(body);
        if (!inner.has_value()) {
          return inner.error();
        }
        if (!inner.value()) {
          break;
        }
        if (body.keyword == "applied-rule" || body.keyword == "not-applicable-rule") {
          const auto plain = require_plain_statement(body, 1);
          if (!plain.has_value()) {
            return plain.error();
          }
          auto parsed = RuleId::parse(body.positional.front());
          if (!parsed.has_value()) {
            return parsed.error();
          }
          if (body.keyword == "applied-rule") {
            verdict.applied_rules.push_back(parsed.value());
          } else {
            verdict.not_applicable_rules.push_back(parsed.value());
          }
          continue;
        }
        if (body.keyword == "violation") {
          Fields fields(body);
          Violation violation;
          const auto rule = fields.required("rule");
          if (!rule.has_value()) {
            return rule.error();
          }
          auto parsed_rule = RuleId::parse(rule.value());
          if (!parsed_rule.has_value()) {
            return parsed_rule.error();
          }
          violation.rule_id = parsed_rule.value();
          const auto kind = fields.required("kind");
          if (!kind.has_value()) {
            return kind.error();
          }
          auto parsed_kind = parse_constraint_kind(kind.value());
          if (!parsed_kind.has_value()) {
            return parsed_kind.error();
          }
          violation.constraint_kind = parsed_kind.value();
          const auto index = fields.required("index");
          if (!index.has_value()) {
            return index.error();
          }
          auto parsed_index = parse_u32(index.value(), "index");
          if (!parsed_index.has_value()) {
            return parsed_index.error();
          }
          violation.constraint_index = parsed_index.value();
          const auto code = fields.required("code");
          if (!code.has_value()) {
            return code.error();
          }
          auto parsed_code = parse_violation_code(code.value());
          if (!parsed_code.has_value()) {
            return parsed_code.error();
          }
          violation.code = parsed_code.value();
          const auto detail = fields.required("detail");
          if (!detail.has_value()) {
            return detail.error();
          }
          auto checked = require_valid_utf8(detail.value(), "violation detail", kMaxTextBytes);
          if (!checked.has_value()) {
            return checked.error();
          }
          violation.detail = std::move(checked.value());
          const std::optional<std::string> waived = fields.optional("waived-by");
          if (waived.has_value() && !waived->empty()) {
            auto parsed = EnvelopeId::parse(*waived);
            if (!parsed.has_value()) {
              return parsed.error();
            }
            violation.waived_by = parsed.value();
          }
          const auto finished = fields.finish();
          if (!finished.has_value()) {
            return finished.error();
          }
          verdict.violations.push_back(std::move(violation));
          continue;
        }
        if (body.keyword == "override") {
          Fields fields(body);
          OverrideUse use;
          const auto envelope = fields.required("envelope");
          if (!envelope.has_value()) {
            return envelope.error();
          }
          auto parsed_envelope = EnvelopeId::parse(envelope.value());
          if (!parsed_envelope.has_value()) {
            return parsed_envelope.error();
          }
          use.envelope_id = parsed_envelope.value();
          const auto principal = fields.required("principal");
          if (!principal.has_value()) {
            return principal.error();
          }
          auto parsed_principal = PrincipalId::parse(principal.value());
          if (!parsed_principal.has_value()) {
            return parsed_principal.error();
          }
          use.principal = parsed_principal.value();
          const auto usage = fields.required("usage");
          if (!usage.has_value()) {
            return usage.error();
          }
          auto parsed_usage = UsageId::parse(usage.value());
          if (!parsed_usage.has_value()) {
            return parsed_usage.error();
          }
          use.usage_id = parsed_usage.value();
          const auto digest = fields.required("grant-digest");
          if (!digest.has_value()) {
            return digest.error();
          }
          auto parsed_digest = parse_digest_field(digest.value(), "grant-digest");
          if (!parsed_digest.has_value()) {
            return parsed_digest.error();
          }
          use.grant_digest = parsed_digest.value();
          const auto waived = fields.required("waived");
          if (!waived.has_value()) {
            return waived.error();
          }
          auto parsed_waived = parse_u32(waived.value(), "waived");
          if (!parsed_waived.has_value()) {
            return parsed_waived.error();
          }
          use.waived_count = parsed_waived.value();
          const auto finished = fields.finish();
          if (!finished.has_value()) {
            return finished.error();
          }
          verdict.override_use = std::move(use);
          continue;
        }

        if (body.positional.size() != 1) {
          return Error(ErrorCode::UnexpectedToken, "verdict statement takes exactly one value")
              .with_subject(body.keyword)
              .with_detail("line=" + std::to_string(body.number));
        }
        const std::string& value = body.positional.front();
        if (body.keyword == "decision") {
          auto parsed = parse_decision(value);
          if (!parsed.has_value()) {
            return parsed.error();
          }
          verdict.decision = parsed.value();
          have_decision = true;
        } else if (body.keyword == "constrained") {
          auto parsed = parse_bool(value, "constrained");
          if (!parsed.has_value()) {
            return parsed.error();
          }
          verdict.constrained = parsed.value();
        } else if (body.keyword == "replayed") {
          auto parsed = parse_bool(value, "replayed");
          if (!parsed.has_value()) {
            return parsed.error();
          }
          verdict.replayed = parsed.value();
        } else if (body.keyword == "evidence-digest") {
          auto parsed = parse_digest_field(value, "evidence-digest");
          if (!parsed.has_value()) {
            return parsed.error();
          }
          verdict.evidence_digest = parsed.value();
        } else if (body.keyword == "verdict-digest") {
          auto parsed = parse_digest_field(value, "verdict-digest");
          if (!parsed.has_value()) {
            return parsed.error();
          }
          verdict.verdict_digest = parsed.value();
        } else {
          return Error(ErrorCode::UnknownKeyword, "unknown statement inside a candidate verdict")
              .with_subject(body.keyword)
              .with_detail("line=" + std::to_string(body.number));
        }
      }
      if (!have_decision) {
        return Error(ErrorCode::MissingField, "a candidate verdict needs a decision")
            .with_detail("candidate=" + std::string(verdict.candidate_id.value()));
      }
      verdicts.candidates.push_back(std::move(verdict));
      continue;
    }

    if (line.keyword == "generations") {
      if (line.opens_section || !line.positional.empty()) {
        return Error(ErrorCode::UnexpectedToken, "generations takes named fields only")
            .with_detail("line=" + std::to_string(line.number));
      }
      Fields fields(line);
      const auto topology = fields.required("topology");
      if (!topology.has_value()) {
        return topology.error();
      }
      auto parsed_topology = parse_counter_text(topology.value(), "topology-generation");
      if (!parsed_topology.has_value()) {
        return parsed_topology.error();
      }
      verdicts.generations.topology = TopologyGeneration::from_value(parsed_topology.value()).value();
      const auto failure_domain = fields.required("failure-domain");
      if (!failure_domain.has_value()) {
        return failure_domain.error();
      }
      auto parsed_failure_domain =
          parse_counter_text(failure_domain.value(), "failure-domain-generation");
      if (!parsed_failure_domain.has_value()) {
        return parsed_failure_domain.error();
      }
      verdicts.generations.failure_domain =
          FailureDomainGeneration::from_value(parsed_failure_domain.value()).value();
      const auto tenant = fields.required("tenant");
      if (!tenant.has_value()) {
        return tenant.error();
      }
      auto parsed_tenant = parse_counter_text(tenant.value(), "tenant-generation");
      if (!parsed_tenant.has_value()) {
        return parsed_tenant.error();
      }
      verdicts.generations.tenant = TenantGeneration::from_value(parsed_tenant.value()).value();
      const auto service_class = fields.required("service-class");
      if (!service_class.has_value()) {
        return service_class.error();
      }
      auto parsed_service_class =
          parse_counter_text(service_class.value(), "service-class-generation");
      if (!parsed_service_class.has_value()) {
        return parsed_service_class.error();
      }
      verdicts.generations.service_class =
          ServiceClassGeneration::from_value(parsed_service_class.value()).value();
      const auto finished = fields.finish();
      if (!finished.has_value()) {
        return finished.error();
      }
      have_generations = true;
      continue;
    }

    if (line.positional.size() != 1) {
      return Error(ErrorCode::UnexpectedToken, "verdict statement takes exactly one value")
          .with_subject(line.keyword)
          .with_detail("line=" + std::to_string(line.number));
    }
    const std::string& value = line.positional.front();
    if (line.keyword == "request-id") {
      auto id = RequestId::parse(value);
      if (!id.has_value()) {
        return id.error();
      }
      verdicts.request_id = id.value();
    } else if (line.keyword == "policy-id") {
      auto id = PolicyId::parse(value);
      if (!id.has_value()) {
        return id.error();
      }
      verdicts.policy.policy_id = id.value();
    } else if (line.keyword == "policy-revision") {
      auto parsed = parse_counter_text(value, "policy-revision");
      if (!parsed.has_value()) {
        return parsed.error();
      }
      verdicts.policy.revision = PolicyRevision::from_value(parsed.value()).value();
      have_policy_revision = true;
    } else if (line.keyword == "policy-digest") {
      auto parsed = parse_digest_field(value, "policy-digest");
      if (!parsed.has_value()) {
        return parsed.error();
      }
      verdicts.policy.digest = parsed.value();
    } else if (line.keyword == "authority-epoch") {
      auto parsed = parse_counter_text(value, "authority-epoch");
      if (!parsed.has_value()) {
        return parsed.error();
      }
      verdicts.authority_epoch = AuthorityEpoch::from_value(parsed.value()).value();
    } else if (line.keyword == "occupancy-generation") {
      auto parsed = parse_counter_text(value, "occupancy-generation");
      if (!parsed.has_value()) {
        return parsed.error();
      }
      verdicts.occupancy_generation = OccupancyGeneration::from_value(parsed.value()).value();
    } else if (line.keyword == "maintenance-generation") {
      auto parsed = parse_counter_text(value, "maintenance-generation");
      if (!parsed.has_value()) {
        return parsed.error();
      }
      verdicts.maintenance_generation = MaintenanceGeneration::from_value(parsed.value()).value();
    } else if (line.keyword == "evaluated-at") {
      auto parsed = parse_instant_field(value, "evaluated-at");
      if (!parsed.has_value()) {
        return parsed.error();
      }
      verdicts.evaluated_at = parsed.value();
      have_evaluated_at = true;
    } else if (line.keyword == "request-digest") {
      auto parsed = parse_digest_field(value, "request-digest");
      if (!parsed.has_value()) {
        return parsed.error();
      }
      verdicts.request_digest = parsed.value();
    } else if (line.keyword == "replayed") {
      auto parsed = parse_bool(value, "replayed");
      if (!parsed.has_value()) {
        return parsed.error();
      }
      verdicts.replayed = parsed.value();
    } else {
      return Error(ErrorCode::UnknownKeyword, "unknown statement in a verdict document")
          .with_subject(line.keyword)
          .with_detail("line=" + std::to_string(line.number));
    }
  }
  if (!have_policy_revision || !have_evaluated_at || !have_generations) {
    return Error(ErrorCode::MissingField, "a verdict document is incomplete");
  }
  std::sort(verdicts.candidates.begin(), verdicts.candidates.end(),
            [](const CandidateVerdict& lhs, const CandidateVerdict& rhs) {
              return lhs.candidate_id < rhs.candidate_id;
            });
  return verdicts;
}

std::string verdict_document_text(const PlacementVerdictSet& verdicts) {
  std::string out;
  append_line(out, "fpp-document verdict");
  append_line(out, "format " + std::to_string(kTextFormatVersion));
  append_line(out, "request-id " + std::string(verdicts.request_id.value()));
  append_line(out, "policy-id " + std::string(verdicts.policy.policy_id.value()));
  append_line(out, "policy-revision " + verdicts.policy.revision.to_string());
  append_line(out, "policy-digest " + digest_tagged_hex(verdicts.policy.digest));
  append_line(out, "authority-epoch " + verdicts.authority_epoch.to_string());
  append_line(out, "generations topology=" + verdicts.generations.topology.to_string() +
                       " failure-domain=" + verdicts.generations.failure_domain.to_string() +
                       " tenant=" + verdicts.generations.tenant.to_string() +
                       " service-class=" + verdicts.generations.service_class.to_string());
  if (verdicts.occupancy_generation.has_value()) {
    append_line(out, "occupancy-generation " + verdicts.occupancy_generation->to_string());
  }
  if (verdicts.maintenance_generation.has_value()) {
    append_line(out, "maintenance-generation " + verdicts.maintenance_generation->to_string());
  }
  append_line(out, "evaluated-at " + verdicts.evaluated_at.to_string());
  append_line(out, "request-digest " + digest_tagged_hex(verdicts.request_digest));
  for (const CandidateVerdict& candidate : verdicts.candidates) {
    append_line(out, "candidate " + std::string(candidate.candidate_id.value()) + " {");
    append_line(out, "  decision " + std::string(decision_name(candidate.decision)));
    append_line(out, "  constrained " + std::string(candidate.constrained ? "true" : "false"));
    append_line(out, "  replayed " + std::string(candidate.replayed ? "true" : "false"));
    append_line(out, "  evidence-digest " + digest_tagged_hex(candidate.evidence_digest));
    append_line(out, "  verdict-digest " + digest_tagged_hex(candidate.verdict_digest));
    for (const RuleId& rule : candidate.applied_rules) {
      append_line(out, "  applied-rule " + std::string(rule.value()));
    }
    for (const RuleId& rule : candidate.not_applicable_rules) {
      append_line(out, "  not-applicable-rule " + std::string(rule.value()));
    }
    if (candidate.override_use.has_value()) {
      const OverrideUse& use = *candidate.override_use;
      append_line(out, "  override envelope=" + std::string(use.envelope_id.value()) +
                           " principal=" + std::string(use.principal.value()) +
                           " usage=" + std::string(use.usage_id.value()) +
                           " grant-digest=" + digest_tagged_hex(use.grant_digest) +
                           " waived=" + std::to_string(use.waived_count));
    }
    for (const Violation& violation : candidate.violations) {
      std::string statement = "  violation rule=" + std::string(violation.rule_id.value()) +
                              " kind=" + std::string(constraint_kind_name(violation.constraint_kind)) +
                              " index=" + std::to_string(violation.constraint_index) +
                              " code=" + std::string(violation_code_name(violation.code)) +
                              " detail=" + quoted(violation.detail);
      if (violation.waived_by.has_value()) {
        statement.append(" waived-by=");
        statement.append(violation.waived_by->value());
      }
      append_line(out, statement);
    }
    append_line(out, "}");
  }
  append_line(out, "replayed " + std::string(verdicts.replayed ? "true" : "false"));
  return out;
}

}  // namespace dccp::facility_placement_policy
