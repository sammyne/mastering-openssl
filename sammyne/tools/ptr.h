#pragma once

#include <functional>
#include <memory>
#include <vector>

namespace sammyne::tools::ptr {
using namespace std;

template <class T, class Deleter>
shared_ptr<T> new_shared_ptr(T *ptr, Deleter d) {
  // capture by ref will trigger segment faults
  return shared_ptr<T>(ptr, [=](auto v) {
    if (v) {
      d(v);
    }
  });
}

template <class T, class Deleter>
unique_ptr<T, Deleter> new_unique_ptr(T *ptr, Deleter d) {
  // - capture by ref will trigger segment faults
  // - unique_ptr won't invoke deleter for nil pointer
  return unique_ptr<T, Deleter>(ptr, d);
}

}  // namespace sammyne::tools::ptr