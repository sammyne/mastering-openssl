#include <iostream>
#include <vector>

#include <openssl/evp.h>
#include <openssl/sha.h>

#include <cppcodec/hex_upper.hpp>

using namespace std;
using hex = cppcodec::hex_upper;

const string APP = "[SM3-DIGEST]";

int main()
{
  const string ENTL = "0080";
  // "12345678"
  const string ID = "31323334353637383132333435363738";
  // "FFFFFFFE FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF 00000000 FFFFFFFF FFFFFFFC"
  const string a = "FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC";
  // 28E9 FA9E 9D9F 5E34 4D5A 9E4B CF65 09A7 F397 89F5 15AB 8F92 DDBC BD41 4D94 0E93
  const string b = "28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93";
  const string Gx = "32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7";
  const string Gy = "BC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0";
  const string x = "09F9DF311E5421A150DD7D161E4BC5C672179FAD1833FC076BB08FF356F35020";
  const string y = "CCEA490CE26775A52DC6EA718CC1AA600AED05FBF35E084A6632F6072DA9AD13";

  //const auto z = ENTL + ID + a + b + Gx + Gy + x + y;
  const auto z = hex::decode(ENTL + ID + a + b + Gx + Gy + x + y);

  unsigned char md[SHA256_DIGEST_LENGTH] = {0};
  unsigned int mdLen = 0;

  EVP_Digest(z.data(), z.size(), md, &mdLen, EVP_sm3(), nullptr);

  // B2E1 4C5C 79C6 DF5B 85F4 FE7E D8DB 7A26 2B9D A7E0 7CCB 0EA9 F474 7B8C CDA8 A4F3
  const string expect = "B2E14C5C79C6DF5B85F4FE7ED8DB7A262B9DA7E07CCB0EA9F4747B8CCDA8A4F3";

  //string got = encoding::hexlify(md, mdLen);
  auto got = hex::encode(md, mdLen);
  if (got != expect)
  {
    cout << APP << " invalid digest: got " << got << ", expect " << expect << endl;
    return -1;
  }

  cout << APP << " PASSED" << endl;

  return 0;
}