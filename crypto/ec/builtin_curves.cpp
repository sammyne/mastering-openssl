#include <iostream>

#include <openssl/ec.h>

using namespace std;

const string APP = "[BUILTIN-CURVES]";

int main()
{
  cout << "--- " << APP << " ---" << endl;

  auto nCurves = EC_get_builtin_curves(nullptr, 0);
  EC_builtin_curve *curves = new EC_builtin_curve[nCurves];

  //cout << "#(curves) = " << nCurves << endl;
  EC_get_builtin_curves(curves, nCurves);
  for (int i = 0; i < nCurves; i++)
  {
    cout << curves[i].nid << ": " << curves[i].comment << endl;
  }

  delete[] curves;

  cout << "--- end " << APP << " ---" << endl;

  return 0;
}