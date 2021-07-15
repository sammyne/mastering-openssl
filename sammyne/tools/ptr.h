#pragma once

#include <functional>
#include <memory>
#include <vector>

namespace sammyne::tools::ptr {
using namespace std;

template <class T, class Deleter>
shared_ptr<T> new_shared_ptr(T *ptr, Deleter d) {
  return shared_ptr<T>(ptr, [&](auto v) {
    if (v) {
      d(v);
    }
  });
}

template <class T, class Deleter>
unique_ptr<T, function<void(T *)>> new_unique_ptr(T *ptr, Deleter d) {
  return unique_ptr<T, function<void(T *)>>(ptr, [&](auto v) {
    if (v) {
      d(v);
    }
  });
}
}  // namespace sammyne::tools::ptr