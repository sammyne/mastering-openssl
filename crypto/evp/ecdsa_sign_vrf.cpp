#include <iostream>

#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/sha.h>

using namespace std;

const string APP = "[ECDSA: Sign and Verify]";

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

int sign(unsigned char *sig, unsigned int *sigLen, const string message,
         EVP_PKEY *pkey)
{
  // message digest
  EVP_MD_CTX *ctx = EVP_MD_CTX_new();

  EVP_SignInit(ctx, EVP_sha256());
  if (1 != EVP_SignUpdate(ctx, message.c_str(), message.size()))
  {
    cout << "failed to initialize context" << endl;
    EVP_MD_CTX_free(ctx);
    return -1;
  }

  auto resp = EVP_SignFinal(ctx, sig, sigLen, pkey);
  EVP_MD_CTX_free(ctx);

  return resp;
}

int verify(unsigned char *sig, unsigned int sigLen, const string message,
           EVP_PKEY *pkey)
{
  // message digest
  EVP_MD_CTX *ctx = EVP_MD_CTX_new();

  auto resp = EVP_VerifyInit(ctx, EVP_sha256());
  if (1 != resp)
  {
    cout << "failed initialize verification" << endl;
    return resp;
  }

  resp = EVP_VerifyUpdate(ctx, message.c_str(), message.size());
  if (1 != resp)
  {
    cout << "failed update verification" << endl;
    return resp;
  }

  resp = EVP_VerifyFinal(ctx, sig, sigLen, pkey);
  EVP_MD_CTX_free(ctx);

  return resp;
}

int main()
{
  ERR_load_crypto_strings();

  auto pkey = generateKey();

  const string message = "";

  auto sig = new unsigned char[EVP_PKEY_size(pkey)];
  unsigned int sigLen;

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

void ugly()
{
  /*
  auto paramCtx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, nullptr);
  if (nullptr == paramCtx)
  {
    cout << "failed to make pkey context" << endl;
    report();
    return -1;
  }

  auto resp = EVP_PKEY_paramgen_init(paramCtx);
  if (1 != resp)
  {
    cout << "failed initialize parameters" << endl;
    report();
    return resp;
  }

  resp = EVP_PKEY_CTX_set_ec_paramgen_curve_nid(paramCtx, NID_secp256k1);
  if (1 != resp)
  {
    cout << "failed to set NID" << endl;
    report();
    return resp;
  }

  auto params = EVP_PKEY_new();
  resp = EVP_PKEY_paramgen(paramCtx, &params);
  if (1 != resp)
  {
    cout << "failed to generate parameters" << endl;
    report();
    return resp;
  }

  auto keyCtx = EVP_PKEY_CTX_new(params, nullptr);
  if (nullptr == keyCtx)
  {
    cout << "failed to spare a new key context" << endl;
    report();
    return -1;
  }

  resp = EVP_PKEY_keygen_init(keyCtx);
  if (1 != resp)
  {
    cout << "failed to initialize ctx for key" << endl;
    report();
    return resp;
  }

  auto pkey = EVP_PKEY_new();
  resp = EVP_PKEY_keygen(keyCtx, &pkey);
  if (1 != resp)
  {
    cout << "failed to generate key" << endl;
    report();
    return resp;
  }

  auto pkey = generateKey();

  const string message = "";

  auto sig = new unsigned char[EVP_PKEY_size(pkey)];
  unsigned int sigLen;

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

  EVP_PKEY_CTX_free(keyCtx);
  EVP_PKEY_free(params);
  EVP_PKEY_free(pkey);
  EVP_PKEY_CTX_free(paramCtx);

  /*
  auto keyCtx = EVP_PKEY_CTX_new_id(NID_secp256k1, nullptr);
  if (nullptr == keyCtx)
  {
    cout << "failed to spare a new key context" << endl;
    report();
    return -1;
  }

  auto pkey = EVP_PKEY_new();
  auto resp = EVP_PKEY_keygen(keyCtx, &pkey);
  if (1 != resp)
  {
    cout << "failed to generate key" << endl;
    return resp;
  }

  EVP_PKEY_free(pkey);
  EVP_PKEY_CTX_free(keyCtx);
  */
}