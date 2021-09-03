#pragma once

#include <iostream>
#include <string>
#include <vector>

#include "ministd/tools/ptr.h"

namespace ministd::os {

namespace ptr = tools::ptr;

using std::string;
using std::vector;

int ReadFile(const char* name, vector<uint8_t>& out) {
  auto fd = ptr::new_shared_ptr(fopen(name, "r"), fclose);
  if (!fd.get()) {
    return 1;
  }

  fseek(fd.get(), 0, SEEK_END);
  auto ell = ftell(fd.get());

  out.resize(ell);

  fseek(fd.get(), 0, SEEK_SET);  // back to start
  if (auto n = fread(out.data(), 1, ell, fd.get()); n != ell) {
    return 2;
  }

  return 0;
}
}  // namespace ministd::os