#!/bin/bash

set -e

if [ $# != 1 ]; then
  echo "missing out dir for openssl"
  exit 1
fi

outDir="$1"
#ls $outDir
if [ "$(ls $outDir)" ]; then
  echo "openssl is ready"
  exit 0
fi

remote=https://github.com/openssl/openssl
rev=OpenSSL_1_1_1l

git clone $remote $outDir
cd $outDir
git checkout $rev
cd -

cat > $outDir/.clang-format <<EOF
{
  "DisableFormat": true,
  "SortIncludes": false
}
EOF
