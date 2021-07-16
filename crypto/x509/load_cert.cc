#include <iostream>

#include <openssl/pem.h>
#include <openssl/x509.h>

#include "sammyne/os.h"
#include "sammyne/tools.h"

namespace ptr = sammyne::tools::ptr;
namespace errors = sammyne::tools::errors;
namespace os = sammyne::os;

using namespace std;

using Certificate = shared_ptr<X509>;

int ParseCertificateFromPEM(const uint8_t *pem, int pemLen, Certificate &out) {
  auto cert = ptr::new_shared_ptr(BIO_new(BIO_s_mem()), BIO_free);
  if (!cert.get()) {
    return 1;
  }

  size_t length = 0;
  if (BIO_write_ex(cert.get(), pem, pemLen, &length) != 1) {
    return 2;
  }
  if (length != pemLen) {
    return 3;
  }

  out = ptr::new_shared_ptr(PEM_read_bio_X509_AUX(cert.get(), NULL, NULL, NULL), X509_free);
  if (!out.get()) {
    return 4;
  }

  return 0;
}

int main(int argc, char *argv[]) {
  if (argc < 2) {
    printf("missing cert path\n");
    return -1;
  }

  vector<uint8_t> certPEM;
  if (auto err = os::ReadFile(argv[1], certPEM); err != 0) {
    printf("fail to read cert: %d\n", err);
    return -2;
  }

  {
    auto s = (char *)certPEM.data();
    string cc(s, s + certPEM.size());
    printf("cert PEM goes as\n\n");
    printf("%s\n", cc.c_str());
  }

  Certificate cert;
  if (auto err = ParseCertificateFromPEM(certPEM.data(), certPEM.size(), cert); err != 0) {
    return -3;
  }

  return 0;
}