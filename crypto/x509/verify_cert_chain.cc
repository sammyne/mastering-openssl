#include <iostream>

#include <openssl/pem.h>
#include <openssl/x509.h>

#include "sammyne/os.h"
#include "sammyne/tools.h"

using namespace std;

namespace ptr = sammyne::tools::ptr;
namespace errors = sammyne::tools::errors;
namespace os = sammyne::os;

using Certificate = shared_ptr<X509>;

int parse_certificate_from_pem(const uint8_t *pem, int pemLen, Certificate &out, const char *debug);

int load_cert(const char *path, Certificate &out, const char *debug) {
  vector<uint8_t> certPEM;
  if (auto err = os::ReadFile(path, certPEM); err != 0) {
    return -1;
  }

  return parse_certificate_from_pem(certPEM.data(), certPEM.size(), out, debug);
}

int parse_certificate_from_pem(const uint8_t *pem, int pemLen, Certificate &out,
                               const char *debug) {
  auto cert = ptr::new_unique_ptr(BIO_new(BIO_s_mem()), BIO_free);
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

int verify_callback(int ok, X509_STORE_CTX *ctx) {
  if (ok) {
    return ok;
  }

  auto err = X509_STORE_CTX_get_error(ctx);
  auto depth = X509_STORE_CTX_get_error_depth(ctx);
  printf("error depth %d, cert error %d\n", depth, err);

  return ok;
}

int verify_cert(X509 *root_ca, X509 *intermediate_ca, X509 *app) {
  auto store = ptr::new_unique_ptr(X509_STORE_new(), X509_STORE_free);
  X509_STORE_set_verify_cb(store.get(), verify_callback);

  if (!X509_STORE_add_cert(store.get(), root_ca)) {
    return -1;
  }

  auto untrusted = ptr::new_unique_ptr(sk_X509_new_null(), sk_X509_free);
  sk_X509_push(untrusted.get(), intermediate_ca);

  auto ctx = ptr::new_unique_ptr(X509_STORE_CTX_new(), X509_STORE_CTX_free);
  if (!X509_STORE_CTX_init(ctx.get(), store.get(), app, untrusted.get())) {
    return -2;
  }

  if (!X509_verify_cert(ctx.get())) {
    return -3;
  }

  return 0;
}

int main(int argc, char *argv[]) {
  if (argc != 4) {
    printf("[usage] %s root-ca intermediate-ca app\n", argv[0]);
    return 1;
  }
  auto root_ca_path = argv[1];
  auto intermediate_ca_path = argv[2];
  auto app_cert_path = argv[3];

  // printf("        root ca path: %s\n", root_ca_path);
  // printf("intermediate ca path: %s\n", intermediate_ca_path);
  // printf("       app cert path: %s\n", app_cert_path);

  Certificate root_ca, intermediate_ca, app;
  const char *debug = "root-ca";
  if (auto err = load_cert(root_ca_path, root_ca, debug); err != 0) {
    printf("fail to load root CA: %d\n", err);
    return 2;
  }

  if (auto err = load_cert(intermediate_ca_path, intermediate_ca, debug); err != 0) {
    printf("fail to load intermediate CA: %d\n", err);
    return 3;
  }

  if (auto err = load_cert(app_cert_path, app, debug); err != 0) {
    printf("fail to load app cert: %d\n", err);
    return 4;
  }

  if (auto err = verify_cert(root_ca.get(), intermediate_ca.get(), app.get()); err != 0) {
    printf("bad cert chain: %d\n", err);
    return 5;
  }

  if (auto err = verify_cert(intermediate_ca.get(), intermediate_ca.get(), app.get()); err == 0) {
    printf("corrupted root CA should fail the verification\n");
    return 5;
  }

  printf("ok :)\n");

  return 0;
}