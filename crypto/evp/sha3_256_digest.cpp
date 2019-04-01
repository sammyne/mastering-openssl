#include <iostream>

#include <openssl/evp.h>
#include <openssl/sha.h>

#include "hex.h"

using namespace std;

const string APP = "[SHA3-256-DIGEST]";

int main()
{
  const string message = "";

  // message digest
  unsigned char md[SHA256_DIGEST_LENGTH] = {0};
  unsigned int mdLen = 0;

  EVP_Digest(message.c_str(), message.size(), md, &mdLen, EVP_sha3_256(),
             nullptr);

  const string expect = "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a";

  string got = encoding::hexlify(md, mdLen);
  if (got != expect)
  {
    cout << APP << " invalid digest: got " << got << ", expect " << expect << endl;
    return -1;
  }

  cout << APP << " PASSED" << endl;

  return 0;
}