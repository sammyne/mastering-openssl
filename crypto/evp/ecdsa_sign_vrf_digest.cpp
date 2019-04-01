#include <iostream>

#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/sha.h>

using namespace std;

const string APP = "[ECDSA: Digest Sign and Verify]";

void report()
{
  auto err = ERR_get_error();
  cout << "code = " << err << endl;
  cout << ERR_reason_error_string(err) << endl;
}

// SHA3 isn't supported

EVP_PKEY *generateKey()
{
  // SECG curve over a 256 bit prime field
  auto key = EC_KEY_new_by_curve_name(NID_secp256k1);

  if (1 != EC_KEY_generate_key(key))
  {
    cout << "failed to generate key" << endl;
    report();
    return nullptr;
  }

  if (1 != EC_KEY_check_key(key))
  {
    cout << "the generated key is invalid" << endl;
    report();
    return nullptr;
  }

  EVP_PKEY *pkey = EVP_PKEY_new();
  EVP_PKEY_assign_EC_KEY(pkey, key);

  return pkey;
}

int sign(unsigned char *sig, size_t *sigLen, const string message,
         EVP_PKEY *pkey)
{
  // message digest
  EVP_MD_CTX *ctx = EVP_MD_CTX_new();
  if (1 != EVP_DigestSignInit(ctx, nullptr, EVP_sha256(), nullptr, pkey))
  {
    report();
    return -1;
  }

  auto data = (const unsigned char *)(message.c_str());
  if (1 != EVP_DigestSign(ctx, sig, sigLen, data, message.size()))
  {
    report();
    return -1;
  }

  return 1;
}

int verify(unsigned char *sig, size_t sigLen, const string message,
           EVP_PKEY *pkey)
{
  // message digest
  EVP_MD_CTX *ctx = EVP_MD_CTX_new();

  if (1 != EVP_DigestVerifyInit(ctx, nullptr, EVP_sha256(), nullptr, pkey))
  {
    report();
    return 0;
  }

  auto tbs = (const unsigned char *)(message.c_str());
  if (1 != EVP_DigestVerify(ctx, sig, sigLen, tbs, message.size()))
  {
    report();
    return 0;
  }

  return 1;
}

int main()
{
  ERR_load_crypto_strings();

  auto pkey = generateKey();

  const string message = "";

  auto sig = new unsigned char[EVP_PKEY_size(pkey)];
  size_t sigLen;

  if (1 != sign(sig, &sigLen, message, pkey))
  {
    cout << "failed to sign" << endl;
    delete[] sig;
    EVP_PKEY_free(pkey);

    report();
    return -1;
  }

  if (1 != verify(sig, sigLen, message, pkey))
  {
    cout << "failed to verify" << endl;
    delete[] sig;
    EVP_PKEY_free(pkey);
    report();
    return -1;
  }

  cout << APP << ": PASSED" << endl;

  delete[] sig;
  EVP_PKEY_free(pkey);
  ERR_free_strings();

  return 0;
}
