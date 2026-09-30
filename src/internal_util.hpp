// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs.
//
// Internal helpers shared by the implementation files. Not installed.

#ifndef DCCP_FACILITY_PLACEMENT_POLICY_SRC_INTERNAL_UTIL_HPP
#define DCCP_FACILITY_PLACEMENT_POLICY_SRC_INTERNAL_UTIL_HPP

#include <algorithm>
#include <cstddef>
#include <functional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace dccp::facility_placement_policy::internal {

/// Sorts a vector and removes elements that compare equivalent, using one
/// strict weak ordering for both steps. Canonicalisation is the only place this
/// is used, and it is what makes a digest independent of authoring order.
template <class T, class Less>
void sort_unique(std::vector<T>& values, Less less) {
  std::sort(values.begin(), values.end(), less);
  values.erase(std::unique(values.begin(), values.end(),
                           [&less](const T& lhs, const T& rhs) {
                             return !less(lhs, rhs) && !less(rhs, lhs);
                           }),
               values.end());
}

/// Sorts a vector of naturally ordered values and removes duplicates.
template <class T>
void sort_unique(std::vector<T>& values) {
  sort_unique(values, std::less<T>{});
}

/// True when the vector is strictly increasing under the ordering, which is the
/// invariant every canonical document must satisfy.
template <class T, class Less>
bool is_strictly_increasing(const std::vector<T>& values, Less less) {
  for (std::size_t index = 1; index < values.size(); ++index) {
    if (!less(values[index - 1], values[index])) {
      return false;
    }
  }
  return true;
}

template <class T>
bool is_strictly_increasing(const std::vector<T>& values) {
  return is_strictly_increasing(values, std::less<T>{});
}

/// True when two sequences share at least one element.
template <class T>
bool shares_any_element(std::vector<T> lhs, std::vector<T> rhs) {
  sort_unique(lhs);
  sort_unique(rhs);
  std::size_t left = 0;
  std::size_t right = 0;
  while (left < lhs.size() && right < rhs.size()) {
    if (lhs[left] == rhs[right]) {
      return true;
    }
    if (lhs[left] < rhs[right]) {
      ++left;
    } else {
      ++right;
    }
  }
  return false;
}

/// Elements present in both sequences, in ascending order.
template <class T>
std::vector<T> intersection(std::vector<T> lhs, std::vector<T> rhs) {
  sort_unique(lhs);
  sort_unique(rhs);
  std::vector<T> out;
  std::size_t left = 0;
  std::size_t right = 0;
  while (left < lhs.size() && right < rhs.size()) {
    if (lhs[left] == rhs[right]) {
      out.push_back(lhs[left]);
      ++left;
      ++right;
    } else if (lhs[left] < rhs[right]) {
      ++left;
    } else {
      ++right;
    }
  }
  return out;
}

/// Joins a rendered sequence with commas.
template <class Range, class Render>
std::string join(const Range& values, Render render) {
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

}  // namespace dccp::facility_placement_policy::internal

#endif  // DCCP_FACILITY_PLACEMENT_POLICY_SRC_INTERNAL_UTIL_HPP
