#pragma once

#include <string>
#include <vector>

namespace ministd::encoding::hex {

using std::string;
using std::vector;

int DecodeString(const char *s, vector<uint8_t> &out);

string EncodeToString(const uint8_t *data, size_t dataLen);

}  // namespace ministd::encoding::hex
