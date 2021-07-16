#include <iostream>

#include <openssl/evp.h>

#include <cppcodec/hex_lower.hpp>

using namespace std;

using hex = cppcodec::hex_lower;

int main() {
  auto ctx = EVP_MD_CTX_new();
  if (auto err = EVP_DigestInit(ctx, EVP_sm3()); err != 1) {
    printf("EVP_DigestInit failed: %d\n", err);
    return 1;
  }

  const string msg_hex =
      "6162636461626364616263646162636461626364616263646162636461626364"
      "6162636461626364616263646162636461626364616263646162636461626364";

  auto msg = hex::decode(msg_hex);

  if (auto err = EVP_DigestUpdate(ctx, msg.data(), msg.size()); err != 1) {
    printf("EVP_DigestUpdate failed: %d\n", err);
    return 2;
  }

  uint8_t hash[32] = {0};
  if (auto err = EVP_DigestFinal(ctx, hash, nullptr); err != 1) {
    printf("EVP_DigestFinal failed: %d\n", err);
    return 3;
  }

  const string expect = "debe9ff92275b8a138604889c18e5a4d6fdb70e5387e5765293dcba39c0c5732";

  auto got = hex::encode(hash, sizeof(hash));
  if (got != expect) {
    cout << "invalid digest: got " << got << ", expect " << expect << endl;
    return 4;
  }

  uint8_t hash2[32] = {0};
  if (auto err = EVP_Digest(msg.data(), msg.size(), hash2, nullptr, EVP_sm3(), nullptr); err != 1) {
    cout << "EVP_Digest failed: " << err << endl;
    return 5;
  }

  if (auto got = hex::encode(hash2, sizeof(hash2)); expect != got) {
    cout << "invalid digest2: expect " << expect << ", got " << got << endl;
    return 6;
  }

  cout << "SM3: PASS" << endl;

  return 0;
}