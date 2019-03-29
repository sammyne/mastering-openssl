#include <iomanip>
#include <sstream>

#include "hex.h"

using namespace std;

namespace encoding
{
string hexlify(const unsigned char *msg, unsigned int sz)
{
  stringstream ss;
  for (int i = 0; i < sz; i++)
  {
    ss << hex << setw(2) << setfill('0') << (int)msg[i];
  }

  return ss.str();
}
} // namespace encoding