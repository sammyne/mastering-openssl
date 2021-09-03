#include <cstdint>
#include <iostream>
#include <memory>
#include <vector>

#include <openssl/ec.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>

#include "sammyne/tools.h"

using namespace std;

namespace errors = sammyne::tools::errors;
namespace ptr = sammyne::tools::ptr;

const string APP = "[SM2: Generate key using EVP_PKEY_CTX]";

int main() {
  ERR_load_crypto_strings();

  auto ctx = ptr::new_unique_ptr(EVP_PKEY_CTX_new_id(NID_sm2, nullptr), EVP_PKEY_CTX_free);
  if (auto err = EVP_PKEY_keygen_init(ctx.get()); err <= 0) {
    printf("EVP_PKEY_keygen_init failed: %d\n", err);
    return -1;
  }

  EVP_PKEY *pkey = nullptr;
  if (auto err = EVP_PKEY_keygen(ctx.get(), &pkey); err <= 0) {
    printf("EVP_PKEY_keygen failed: %d\n", err);
    return -2;
  }

  printf("  id = %d\n", EVP_PKEY_id(pkey));
  printf("type = %d\n", EVP_PKEY_type(EVP_PKEY_id(pkey)));

  PEM_write_PrivateKey(stdout, pkey, nullptr, nullptr, 0, nullptr, nullptr);

  /*
  auto key = ptr::new_unique_ptr(EC_KEY_new_by_curve_name(NID_sm2), EC_KEY_free);
  if (errors::check(1, EC_KEY_generate_key(key.get()), "generate key")) {
    return -1;
  }

  if (errors::check(1, EC_KEY_check_key(key.get()), "bad generated key")) {
    return -2;
  }

  printf("-----------------------------\n");
  printf("before EVP_PKEY_assign_EC_KEY\n");
  auto pkey = ptr::new_shared_ptr(EVP_PKEY_new(), EVP_PKEY_free);
  if (errors::check(1, EVP_PKEY_assign_EC_KEY(pkey.get(), key.get()), "assign key as EVP")) {
    return -3;
  }
  printf(" after EVP_PKEY_assign_EC_KEY\n");
  printf("-----------------------------\n");
  key.release();
  */

  cout << APP << ": PASSED" << endl;

  // ERR_free_strings(); // this is redundant since openssl>=1.1.0

  return 0;
}
