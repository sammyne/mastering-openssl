#include <iostream>

#include <openssl/evp.h>
#include <openssl/sha.h>

#include "cppcodec/hex_lower.hpp"

using namespace std;
using hex = cppcodec::hex_lower;

const string APP = "[SHA3-256]";

int main()
{
  EVP_MD_CTX *ctx = EVP_MD_CTX_new();
  EVP_DigestInit(ctx, EVP_sha3_256());

  const string message = "";

  EVP_DigestUpdate(ctx, message.c_str(), message.size());

  unsigned char digest[SHA256_DIGEST_LENGTH] = {0};
  unsigned int digestLen = 0;
  EVP_DigestFinal(ctx, digest, &digestLen);

  const string expect = "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a";

  //string got = encoding::hexlify(digest, digestLen);
  auto got = hex::encode(digest, digestLen);
  if (got != expect)
  {
    cout << APP << " invalid digest: got " << got << ", expect " << expect << endl;
    return -1;
  }

  cout << APP << " PASSED" << endl;

  return 0;
}