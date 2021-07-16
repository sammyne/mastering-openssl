#!/bin/bash

set -e

caConfig=root-ca.cnf
caCert=root-ca.crt
caKey=root-ca.key

intermediateCACSR=intermediate-ca.csr
intermediateCACert=intermediate-ca.crt
intermediateCAConfig=intermediate-ca.cnf
intermediateCAKey=intermediate-ca.key

serverCSR=server.csr
serverCert=server.crt
serverConfig=server.cnf
serverKey=server.key

rm -f *.db* *.crt *.csr *.key *.pem serial*
#exit 0

echo "faking CA key and cert ..."
# -nodes: omits the password or passphrase so you can examine the certificate.
#   It's a really bad idea to omit the password or passphrase.
openssl req                             \
  -config ${caConfig}                   \
  -keyout ${caKey}                      \
  -newkey ec                            \
  -nodes                                \
  -out $caCert                          \
  -pkeyopt ec_paramgen_curve:secp256k1  \
  -sha256                               \
  -subj "/CN=sammyne"                   \
  -x509

#echo "----------------"
#echo "show CA cert ..."
#openssl x509 -noout -text -in $caCert

echo "create CA certs DB ..."
touch ca-certs.db

echo "--------------------------------"
echo "fake CSR for intermediate CA ..."
openssl req                             \
  -config $intermediateCAConfig         \
  -keyout $intermediateCAKey            \
  -newkey ec                            \
  -nodes                                \
  -out $intermediateCACSR               \
  -pkeyopt ec_paramgen_curve:sm2  \
  -sha256                               \
  -subj "/CN=sammyne-intermediate-CA"

echo "-----------------------------------"
echo "signing cert for intermediateCA ..."
openssl ca                  \
  -batch                    \
  -cert $caCert             \
  -config $caConfig         \
  -extensions signing_req   \
  -in $intermediateCACSR    \
  -keyfile $caKey           \
  -notext                   \
  -out $intermediateCACert  \
  -outdir .                 \
  -policy signing_policy    \
  -rand_serial

#echo "------------------------"
#echo "show intermediate CA ..."
#openssl x509 -noout -text -in $intermediateCACert

echo "---------------------------"
echo "fake CSR for server ..."
openssl req                             \
  -config $serverConfig                 \
  -keyout $serverKey                    \
  -newkey ec                            \
  -nodes                                \
  -out $serverCSR                       \
  -pkeyopt ec_paramgen_curve:sm2  \
  -sha256                               \
  -subj "/CN=sammyne-app"

echo "---------------------------"
echo "signing cert for server ..."
openssl ca                      \
  -batch                        \
  -cert $intermediateCACert     \
  -config $intermediateCAConfig \
  -extensions signing_req       \
  -in $serverCSR                \
  -keyfile $intermediateCAKey   \
  -notext                       \
  -out $serverCert              \
  -outdir .                     \
  -policy signing_policy        \
  -rand_serial

#echo "------------------------"
#echo "show server CA ..."
#openssl x509 -noout -text -in $serverCert

echo "---------------------"
echo "verify cert chain ..."
# -untrusted is for specifying intermediate CA
openssl verify            \
  -CAfile $caCert         \
  -untrusted $intermediateCACert \
  -verbose                \
  $serverCert
