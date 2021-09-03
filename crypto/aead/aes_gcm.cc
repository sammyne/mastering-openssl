// @ref:
// https://wiki.openssl.org/index.php/EVP_Authenticated_Encryption_and_Decryption#Authenticated_Decryption_using_GCM_mode
#include <iostream>
#include <cstring>

#include "openssl/evp.h"

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

Result<Bytes> Decrypt(const Bytes &ciphertext, const Bytes &aad, uint8_t tag[kTagLen],
                      uint8_t key[kKeyLen], uint8_t iv[kIvLen]);

Result<Bytes> Encrypt(const Bytes &plaintext, const Bytes &aad, uint8_t key[kKeyLen],
                      uint8_t iv[kIvLen], uint8_t tag[kTagLen]);

int main() {
  auto aad = StringToBytes("hello");
  uint8_t tag[kTagLen] = {0};
  uint8_t sk[16] = "world";
  uint8_t iv[kIvLen] = "iv";
  auto plaintext = StringToBytes("how do you do ?", 10);
  printf("plaintext[3]=%c\n", plaintext[3]);

  auto [ciphertext, err1] = Encrypt(plaintext, aad, sk, iv, tag);
  if (0 != err1) {
    printf("encrypt failed: %d\n", err1);
    return 1;
  }

  cout << "ciphertext = " << hex::EncodeToString(ciphertext.data(), ciphertext.size()) << endl;
  cout << "       tag = " << hex::EncodeToString(tag, sizeof(tag)) << endl;

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

Result<Bytes> Decrypt(const Bytes &ciphertext, const Bytes &aad, uint8_t tag[kTagLen],
                      uint8_t key[kKeyLen], uint8_t iv[kIvLen]) {
  const auto newErr = result::Err<Bytes>;

  /* Create and initialise the context */
  auto ctx_ = ptr::new_unique_ptr(EVP_CIPHER_CTX_new(), EVP_CIPHER_CTX_free);
  if (!ctx_) {
    return newErr(1);
  }
  auto ctx = ctx_.get();

  /* Initialise the decryption operation. */
  if (auto err = EVP_DecryptInit_ex(ctx, NewBlockCipher128(), NULL, NULL, NULL); 1 != err) {
    return newErr(2);
  }

  /* Set IV length. Not necessary if this is 12 bytes (96 bits) */
  if (auto err = EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, kIvLen, NULL); 1 != err) {
    return newErr(3);
  }

  /* Initialise key and IV */
  if (auto err = EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv); 1 != err) {
    return newErr(4);
  }

  /*
   * Provide any AAD data. This can be called zero or more times as
   * required
   */
  int ell = 0;
  if (auto err = EVP_DecryptUpdate(ctx, NULL, &ell, aad.data(), aad.size()); 1 != err) {
    return newErr(5);
  }

  /*
   * Provide the message to be decrypted, and obtain the plaintext output.
   * EVP_DecryptUpdate can be called multiple times if necessary
   */
  // 16 is the block size
  Bytes out(ciphertext.size() + 16, 0);
  if (!EVP_DecryptUpdate(ctx, out.data(), &ell, ciphertext.data(), ciphertext.size())) {
    return newErr(6);
  }
  auto outLen = ell;

  /* Set expected tag value. Works in OpenSSL 1.0.1d and later */
  if (auto err = EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, kTagLen, tag); 1 != err) {
    return newErr(7);
  }

  /*
   * Finalise the decryption. A positive return value indicates success,
   * anything else is a failure - the plaintext is not trustworthy.
   */
  if (auto err = EVP_DecryptFinal_ex(ctx, out.data() + ell, &ell); 1 != err) {
    return newErr(8);
  }
  outLen += ell;
  out.resize(outLen);

  return result::Ok(out);
}

Result<Bytes> Encrypt(const Bytes &plaintext, const Bytes &aad, uint8_t key[kKeyLen],
                      uint8_t iv[kIvLen], uint8_t tag[kTagLen]) {
  const auto newErr = result::Err<Bytes>;

  /* Create and initialise the context */
  auto ctx_ = ptr::new_unique_ptr(EVP_CIPHER_CTX_new(), EVP_CIPHER_CTX_free);
  if (!ctx_) {
    return newErr(1);
  }
  auto ctx = ctx_.get();

  /* Initialise the encryption operation. */
  if (1 != EVP_EncryptInit_ex(ctx, NewBlockCipher128(), NULL, NULL, NULL)) {
    return newErr(2);
  }

  /*
   * Set IV length if default 12 bytes (96 bits) is not appropriate
   */
  if (1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, kIvLen, NULL)) {
    return newErr(3);
  }

  /* Initialise key and IV */
  if (1 != EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv)) {
    return newErr(4);
  }

  int ell = 0;
  /*
   * Provide any AAD data. This can be called zero or more times as
   * required
   */
  if (1 != EVP_EncryptUpdate(ctx, NULL, &ell, aad.data(), aad.size())) {
    return newErr(5);
  }

  Bytes out(plaintext.size() + 16);
  /*
   * Provide the message to be encrypted, and obtain the encrypted output.
   * EVP_EncryptUpdate can be called multiple times if necessary
   */
  if (1 != EVP_EncryptUpdate(ctx, out.data(), &ell, plaintext.data(), plaintext.size())) {
    return newErr(6);
  }
  auto out_len = ell;

  /*
   * Finalise the encryption. Normally ciphertext bytes may be written at
   * this stage, but this does not occur in GCM mode
   */
  if (1 != EVP_EncryptFinal_ex(ctx, out.data() + out_len, &ell)) {
    return newErr(7);
  }
  out_len += ell;
  out.resize(out_len);

  /* Get the tag */
  if (1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, kTagLen, tag)) {
    return newErr(8);
  }

  return result::Ok(out);
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