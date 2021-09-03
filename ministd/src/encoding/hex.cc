#include "ministd/encoding/hex.h"

#include <cstring>

namespace ministd::encoding::hex {

bool unhexlifyChar(const char c, uint8_t &v) {
  if (c >= '0' && c <= '9') {
    v = c - '0';
  } else if (c >= 'a' && c <= 'f') {
    v = 10 + uint8_t(c - 'a');
  } else if (c >= 'A' && c <= 'F') {
    v = 10 + uint8_t(c - 'A');
  } else {
    return false;
  }

  return true;
};

int DecodeString(const char *s, vector<uint8_t> &out) {
  if (!s) {
    return 0;
  }

  auto sLen = strlen(s);
  if (0 != (sLen % 2)) {
    return 1;
  }

  out.resize(sLen / 2);

  for (auto i = 0; i < sLen; i += 2) {
    uint8_t a, b;
    if (!unhexlifyChar(s[i], a) || !unhexlifyChar(s[i + 1], b)) {
      return 2;
    }

    out[i / 2] = (a << 4) | b;
  }

  return 0;
}

string EncodeToString(const uint8_t *data, size_t dataLen) {
  const char *ALPHABET = "0123456789ABCDEF";
  string out;
  out.reserve(dataLen);

  for (auto i = 0; i < dataLen; ++i) {
    out.push_back(ALPHABET[data[i] >> 4]);
    out.push_back(ALPHABET[data[i] & 0x0f]);
  }

  return out;
}

}  // namespace ministd::encoding::hex
