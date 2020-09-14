#!/bin/bash

OPENSSL_LIB_PATH=/opt/openssl1.1/lib
OPENSSL_BIN_PATH=/opt/openssl1.1/bin/openssl

# Set the dynamic lib path for 1.1 openssl
export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:$OPENSSL_LIB_PATH

# Generate ECDSA key for the Root CA
# This will be our self signed certificate authority private key that will sign our keys later on
$OPENSSL_BIN_PATH genpkey -out cakey.pem -algorithm ED448 -out cakey.pem

# After the creation of the ca configuration file
# we can take the root private key and create a certificate from it as our root self signed certificate
$OPENSSL_BIN_PATH req -new -x509 -key cakey.pem -sha512 -out ca.crt -config ca.conf

# Now we can generate a keypair for our SSL server
# This will be used in conjunction with a signed certificate from our CA for the client as well
$OPENSSL_BIN_PATH genpkey -out cakey.pem -algorithm ED448 -out serverkey.pem

# Now we can create a request to sign the key that we generated with the CA
$OPENSSL_BIN_PATH req -new -sha512 -key serverkey.pem -subj "/CN=TLS Server" -out server.csr

# And lastly, we can now take the sign request, along with the configuration for our specific server (server.conf)
# And use both to create the server certificate for the client and the server signed by our local CA
$OPENSSL_BIN_PATH x509 -req -in server.csr -CA ca.crt -CAkey cakey.pem -extfile server.conf -set_serial 0 -out server.crt -days 1024 -sha512

