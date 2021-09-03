#include <iostream>
#include <cstring>

#include "openssl/evp.h"
#include "openssl/aes.h"
#include "openssl/modes.h"
#include "openssl/crypto.h"

#include "ministd/ministd.h"

using namespace std;

using namespace ministd;
using namespace ministd::tools;
using namespace ministd::encoding;

const size_t kIvLen = 12;
const size_t kKeyLen = 16;
const size_t kTagLen = 16;
const auto NewBlockCipher128 = EVP_aes_128_gcm;

Bytes StringToBytes(const char *s, int repeat_count = 1);

Result<Bytes> Decrypt(const Bytes &ciphertext, const Bytes &aad, const uint8_t tag[kTagLen],
                      const uint8_t key[kKeyLen], const uint8_t iv[kIvLen]);

Result<Bytes> Encrypt(const Bytes &plaintext, const Bytes &aad, const uint8_t key[kKeyLen],
                      const uint8_t iv[kIvLen], uint8_t tag[kTagLen]);

// @ref:
// https://cpp.hotexamples.com/zh/examples/-/-/CRYPTO_gcm128_encrypt/cpp-crypto_gcm128_encrypt-function-examples.html
int main() {
  ERR_load_crypto_strings();

  auto aad = StringToBytes("hello");
  uint8_t tag[kTagLen] = {0};
  uint8_t sk[16] = "world";
  uint8_t iv[kIvLen] = "iv";
  auto plaintext = StringToBytes("how do you do ?", 10);

  auto [ciphertext, err1] = Encrypt(plaintext, aad, sk, iv, tag);
  if (0 != err1) {
    printf("encrypt failed: %d\n", err1);
    return 1;
  }

  cout << "       tag = " << hex::EncodeToString(tag, sizeof(tag)) << endl;
  cout << "ciphertext = " << hex::EncodeToString(ciphertext.data(), ciphertext.size()) << endl;

  auto [recovered, err] = Decrypt(ciphertext, aad, tag, sk, iv);
  if (0 != err) {
    printf("decrypt failed: %d\n", err);
    return 2;
  }

  if ((plaintext.size() != recovered.size()) ||
      memcmp(plaintext.data(), recovered.data(), recovered.size())) {
    printf("bad plaintext\n");
    return 3;
  }

  printf("fine :)\n");

  return 0;
}

Result<Bytes> Decrypt(const Bytes &ciphertext, const Bytes &aad, const uint8_t tag[kTagLen],
                      const uint8_t sk[kKeyLen], const uint8_t iv[kIvLen]) {
  const auto newErr = result::Err<Bytes>;

  AES_KEY aes_key;
  if (errors::check(0, AES_set_decrypt_key(sk, kKeyLen * 8, &aes_key), "AES_set_decrypt_key")) {
    return newErr(1);
  }

  auto ctx_ = ptr::new_unique_ptr(CRYPTO_gcm128_new(&aes_key, (block128_f)AES_decrypt),
                                  CRYPTO_gcm128_release);
  if (!ctx_) {
    return newErr(2);
  }
  auto ctx = ctx_.get();

  CRYPTO_gcm128_setiv(ctx, iv, kIvLen);

  if (errors::check(0, CRYPTO_gcm128_aad(ctx, aad.data(), aad.size()), "CRYPTO_gcm128_aad")) {
    return newErr(3);
  }

  Bytes recovered(ciphertext.size(), 0);
  if (errors::check(
          0, CRYPTO_gcm128_decrypt(ctx, ciphertext.data(), recovered.data(), ciphertext.size()),
          "CRYPTO_gcm128_decrypt")) {
    return newErr(4);
  }

  // uint8_t tag2[kTagLen] = {0};
  if (errors::check(0, CRYPTO_gcm128_finish(ctx, tag, kTagLen), "CRYPTO_gcm128_finish")) {
    return newErr(6);
  }
  // cout << "tag2 = " << hex::EncodeToString(tag, kTagLen) << endl;
  // if (memcmp(tag, tag2, kTagLen)) {
  //  return newErr(5);
  //}

  // CRYPTO_gcm128_tag(ctx, tag2, kTagLen);
  // if (memcmp(tag, tag2, kTagLen)) {
  //  return newErr(5);
  //}
  // cout << "tag3 = " << hex::EncodeToString(tag, kTagLen) << endl;

  // cout << "      tag2 = " << hex::EncodeToString(tag2, sizeof(tag2)) << endl;

  return result::Ok(recovered);
}

Result<Bytes> Encrypt(const Bytes &plaintext, const Bytes &aad, const uint8_t sk[kKeyLen],
                      const uint8_t iv[kIvLen], uint8_t tag[kTagLen]) {
  const auto newErr = result::Err<Bytes>;

  AES_KEY aes_key;
  if (errors::check(0, AES_set_encrypt_key(sk, kKeyLen * 8, &aes_key), "AES_set_encrypt_key")) {
    return newErr(1);
  }

  auto ctx_ = ptr::new_unique_ptr(CRYPTO_gcm128_new(&aes_key, (block128_f)AES_encrypt),
                                  CRYPTO_gcm128_release);
  if (!ctx_) {
    return newErr(2);
  }
  auto ctx = ctx_.get();

  CRYPTO_gcm128_setiv(ctx, iv, kIvLen);

  if (errors::check(0, CRYPTO_gcm128_aad(ctx, aad.data(), aad.size()), "CRYPTO_gcm128_aad")) {
    return newErr(3);
  }

  Bytes ciphertext(plaintext.size(), 0);
  if (errors::check(
          0, CRYPTO_gcm128_encrypt(ctx, plaintext.data(), ciphertext.data(), plaintext.size()),
          "CRYPTO_gcm128_encrypt")) {
    return newErr(4);
  }

  CRYPTO_gcm128_tag(ctx, tag, kTagLen);

  return result::Ok(ciphertext);
}

Bytes StringToBytes(const char *s, int repeat_count) {
  auto str_len = strlen(s);

  Bytes out;
  out.reserve(str_len * repeat_count);

  auto from = s;
  auto to = s + str_len;
  for (auto i = 0; i < repeat_count; ++i) {
    out.insert(out.end(), from, to);
  }

  return std::move(out);
}
