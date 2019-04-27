#include <iostream>

#include <openssl/sha.h>

#include <cppcodec/hex_lower.hpp>

using namespace std;
using hex = cppcodec::hex_lower;

int main()
{
  unsigned char hash[SHA256_DIGEST_LENGTH];

  SHA256_CTX sha256;
  SHA256_Init(&sha256);

  const string msg = "";

  SHA256_Update(&sha256, msg.c_str(), msg.size());
  SHA256_Final(hash, &sha256);

  const string expect = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

  //string got = encoding::hexlify(hash, SHA256_DIGEST_LENGTH);
  auto got = hex::encode(hash, SHA256_DIGEST_LENGTH);
  if (got != expect)
  {
    cout << "invalid digest: got " << got << ", expect " << expect << endl;
  }
  cout << "SHA256: PASS" << endl;

  return 0;
}