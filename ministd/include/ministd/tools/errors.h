#pragma once

#include <iostream>
#include <vector>

#include <openssl/err.h>

namespace ministd::tools::errors {

using namespace std;

void report_openssl_error() {
  auto err = ERR_get_error();
  cout << "code = " << err << endl;
  cout << ERR_reason_error_string(err) << endl;
}

bool check(int expected, int got, const string &hint = "") {
  auto ok = (got == expected);
  if (ok) {
    return false;
  }

  if (hint.length() > 0) {
    cout << hint << endl;
  }

  cout << "bad status: expect " << expected << ", got " << got << endl;
  // auto err = ERR_get_error();
  // cout << "code = " << err << endl;
  // cout << ERR_reason_error_string(err) << endl;
  report_openssl_error();

  return true;
}
}  // namespace ministd::tools::errors