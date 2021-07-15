#include <cstdint>
#include <functional>
#include <iostream>
#include <memory>
#include <vector>

#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/sha.h>

#include "sammyne/tools.h"

using namespace std;

namespace errors = sammyne::tools::errors;
namespace ptr = sammyne::tools::ptr;

const string APP = "[ECDSA: Sign and Verify]";

// SHA3 isn't supported

shared_ptr<EVP_PKEY> generateKey() {
  // SECG curve over a 256 bit prime field, a.k.a NIST-P256
  auto key = ptr::new_unique_ptr(EC_KEY_new_by_curve_name(NID_secp256k1), EC_KEY_free);
  if (errors::check(1, EC_KEY_generate_key(key.get()), "generate key")) {
    return nullptr;
  }

  if (errors::check(1, EC_KEY_check_key(key.get()), "bad generated key")) {
    return nullptr;
  }

  auto pkey = ptr::new_shared_ptr(EVP_PKEY_new(), EVP_PKEY_free);
  if (errors::check(1, EVP_PKEY_assign_EC_KEY(pkey.get(), key.get()), "assign key as EVP")) {
    return nullptr;
  }
  key.release();

  return pkey;
}

int sign(const string message, EVP_PKEY* pkey, vector<uint8_t>& sig) {
  auto md = ptr::new_shared_ptr(EVP_MD_CTX_new(), EVP_MD_CTX_free);

  EVP_SignInit(md.get(), EVP_sha256());
  if (errors::check(1, EVP_SignUpdate(md.get(), message.c_str(), message.size()), "init md")) {
    return -1;
  }

  unsigned int sigLen = sig.size();
  if (errors::check(1, EVP_SignFinal(md.get(), sig.data(), &sigLen, pkey), "finalize sig")) {
    return -2;
  }
  sig.resize(sigLen);

  return 0;
}

int verify(const string message, EVP_PKEY* pkey, const vector<uint8_t>& sig) {
  // message digest
  auto md = ptr::new_shared_ptr(EVP_MD_CTX_new(), EVP_MD_CTX_free);
  if (auto err = EVP_VerifyInit(md.get(), EVP_sha256()); errors::check(1, err, "init md")) {
    return err;
  }

  if (auto err = EVP_VerifyUpdate(md.get(), message.c_str(), message.size());
      errors::check(1, err, "update vrf")) {
    return err;
  }

  if (errors::check(1, EVP_VerifyFinal(md.get(), sig.data(), sig.size(), pkey), "finalize vrf")) {
    return -2;
  }

  return 0;
}

int main() {
  ERR_load_crypto_strings();

  auto pkey = generateKey();

  const string message = "";

  auto sig = vector<uint8_t>(EVP_PKEY_size(pkey.get()), 0);

  if (errors::check(0, sign(message, pkey.get(), sig), "fail to sign")) {
    return -1;
  }

  if (errors::check(0, verify(message, pkey.get(), sig), "failed to verify")) {
    return -1;
  }

  cout << APP << ": PASSED" << endl;

  // ERR_free_strings(); // this is redundant since openssl>=1.1.0

  return 0;
}
