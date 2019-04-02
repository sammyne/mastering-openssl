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

const string APP = "[SM2: Curve]";

void report()
{
  auto err = ERR_get_error();
  if (err)
  {
    cout << "code = " << err << endl;
    cout << ERR_reason_error_string(err) << endl;
  }
}

struct
{
  /* data */
  string p;
  string a, b;
  string Gx, Gy;
  string n;
} expect{
    "FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF",
    "FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC",
    "28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93",
    "32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7",
    "BC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0",
    "FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123",
};

int main()
{
  ERR_load_crypto_strings();

  auto group = EC_GROUP_new_by_curve_name(NID_sm2);

  defer _(nullptr, [&](...) {
    ERR_free_strings();

    report();
  });

  if (nullptr == group)
  {
    return -1;
  }

  int status = 0;

  //EC_GROUP_get_degree()
  auto method = EC_GROUP_method_of(group);

  /* check generator */
  auto G = EC_GROUP_get0_generator(group);
  auto x = BN_new();
  auto y = BN_new();

  if (!EC_POINT_get_affine_coordinates_GFp(group, G, x, y, nullptr))
  {
    BN_free(y);
    BN_free(x);
    return -1;
  }

  auto bx = BN_bn2hex(x);
  auto by = BN_bn2hex(y);

  //cout << bx << endl;
  //cout << by << endl;
  if (string(bx) != expect.Gx || string(by) != expect.Gy)
  {
    cout << "invalid G: " << endl;
    cout << "   got (" << bx << ", " << by << ")" << endl;
    cout << "expect (" << expect.Gx << ", " << expect.Gy << ")" << endl;
    status = -1;
  }
  OPENSSL_free(by);
  OPENSSL_free(bx);

  BN_free(y);
  BN_free(x);

  if (-1 == status)
  {
    return -1;
  }

  /* check generator */

  auto n = EC_GROUP_get0_order(group);
  auto n16 = BN_bn2hex(n);
  if (string(n16) != expect.n)
  {
    cout << "invalid order: got " << n16 << ", expect " << expect.n << endl;
    status = -1;
  }

  if (-1 == status)
  {
    return -1;
  }

  cout << APP << ": PASSED" << endl;

  return status;
}