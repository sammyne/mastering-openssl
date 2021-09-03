#pragma once

#include <memory>
#include <vector>

namespace ministd::result {

template <typename T>
using Result = std::pair<T, int>;

template <typename T>
Result<T> Err(int err) {
  return std::make_pair(T{}, err);
}

template <typename T>
Result<T> Ok(T &v) {
  return std::make_pair(std::move(v), 0);
}

template <typename T>
Result<std::shared_ptr<T>> PtrErr(int err) {
  return std::make_pair(nullptr, err);
}

}  // namespace ministd::result