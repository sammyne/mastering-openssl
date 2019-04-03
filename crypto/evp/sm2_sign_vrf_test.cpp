#include <iostream>
#include <memory>

#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/sha.h>

using namespace std;
using defer = shared_ptr<void>;

const string APP = "[SM2: Sign and Verify Test]";

void printPoint(const EC_GROUP *group, const EC_POINT *P)
{
  auto x = BN_new();
  auto y = BN_new();

  if (!EC_POINT_get_affine_coordinates_GFp(group, P, x, y, nullptr))
  {
    BN_free(y);
    BN_free(x);
    return;
  }

  auto bx = BN_bn2hex(x);
  auto by = BN_bn2hex(y);

  cout << "x: " << bx << endl;
  cout << "y: " << by << endl;

  OPENSSL_free(by);
  OPENSSL_free(bx);

  BN_free(y);
  BN_free(x);
}

void report()
{
  auto err = ERR_get_error();
  if (err)
  {
    cout << "code = " << err << endl;
    cout << ERR_reason_error_string(err) << endl;
  }
}

// SHA3 isn't supported

EVP_PKEY *generateKey()
{
  // SECG curve over a 256 bit prime field
  auto key = EC_KEY_new_by_curve_name(NID_sm2);
  if (nullptr == key)
  {
    cout << "world" << endl;
    return nullptr;
  }

  auto prv = BN_new();
  BN_hex2bn(&prv, "3945208F7B2144B13F36E38AC6D39F95889393692860B51A42FB81EF4DF7C5B8");

  EC_KEY_set_private_key(key, prv);

  auto group = EC_KEY_get0_group(key);
  auto pub = EC_POINT_new(group);
  if (1 != EC_POINT_mul(group, pub, prv, nullptr, nullptr, nullptr))
  {
    cout << "hi" << endl;
  }

  EC_KEY_set_public_key(key, pub);

  //if (1 != EC_KEY_generate_key(key))
  //{
  //  return nullptr;
  //}

  if (1 != EC_KEY_check_key(key))
  {
    cout << "hello" << endl;
    BN_free(prv);
    EC_KEY_free(key);
    return nullptr;
  }

  auto prvKey = EC_KEY_get0_private_key(key);
  auto x = BN_bn2hex(prvKey);

  cout << "d: " << x << endl;

  auto pubKey = EC_KEY_get0_public_key(key);
  printPoint(group, pubKey);

  delete[] x;

  BN_free(prv);
  EC_KEY_free(key);

  /*
  EVP_PKEY *pkey = EVP_PKEY_new();
  EVP_PKEY_assign_EC_KEY(pkey, key);

  return pkey;
  */
  return nullptr;
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
    return 0;
  }

  auto tbs = (const unsigned char *)(message.c_str());
  if (1 != EVP_DigestVerify(ctx, sig, sigLen, tbs, message.size()))
  {
    return 0;
  }

  return 1;
}

int main0()
{
  ERR_load_crypto_strings();

  auto pkey = generateKey();
  //defer _(nullptr, [&](...) {
  //  EVP_PKEY_free(pkey);
  //  ERR_free_strings();

  //  report();
  //});

  if (nullptr == pkey)
  {
    return -1;
  }

  const string message = "message digest";

  auto sig = new unsigned char[EVP_PKEY_size(pkey) * 2];
  size_t sigLen;

  defer _(nullptr, [&](...) {
    delete[] sig;
    EVP_PKEY_free(pkey);
    ERR_free_strings();

    report();
  });

  if (1 != sign(sig, &sigLen, message, pkey))
  {
    return -1;
  }

  if (1 != verify(sig, sigLen, message, pkey))
  {
    return -1;
  }

  cout << APP << ": PASSED" << endl;

  return 0;
}

int main()
{
  ERR_load_crypto_strings();

  auto pkey = generateKey();

  report();

  EVP_PKEY_free(pkey);
  ERR_free_strings();

  return 0;
}