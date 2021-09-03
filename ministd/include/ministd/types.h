#pragma once

#include <vector>
#include <cstdint>

#include "ministd/result.h"

namespace ministd {

using Bytes = std::vector<uint8_t>;

template <typename T>
using Result = result::Result<T>;

}