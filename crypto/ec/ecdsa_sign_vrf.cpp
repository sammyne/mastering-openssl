#include <iostream>

#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/evp.h>
#include <openssl/sha.h>

using namespace std;

const string APP = "[ECDSA: Sign and Verify]";

int main()
{
  // SECG curve over a 256 bit prime field
  const int curveNID = 714;

  auto group = EC_GROUP_new_by_curve_name(curveNID);
  if (nullptr == group)
  {
    cout << "failed to make group" << endl;
    return -1;
  }

  EC_KEY *key = EC_KEY_new();
  if (1 != EC_KEY_set_group(key, group))
  {
    cout << "failed to configure group for key" << endl;
    return -1;
  }

  if (1 != EC_KEY_generate_key(key))
  {
    cout << "failed to generate key" << endl;
    return -1;
  }

  if (1 != EC_KEY_check_key(key))
  {
    cout << "the generated key is invalid" << endl;
    return -1;
  }

  cout << "key size = " << ECDSA_size(key) << endl;

  const string message = "";

  // message digest
  unsigned char md[SHA256_DIGEST_LENGTH] = {0};
  unsigned int mdLen = 0;

  EVP_Digest(message.c_str(), message.size(), md, &mdLen, EVP_sha3_256(),
             nullptr);

  auto sig = ECDSA_do_sign(md, mdLen, key);
  if (nullptr == sig)
  {
    cout << "failed to generate signature" << endl;
    return -1;
  }

  auto resp = ECDSA_do_verify(md, mdLen, sig, key);
  if (1 != resp)
  {
    cout << "failed to verify signature" << endl;
    return resp;
  }

  cout << APP << ": PASSED" << endl;

  return 0;
}