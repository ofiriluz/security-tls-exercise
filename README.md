Security training exercise
==========================

This repo is intended for the security training course of CyberArk

generate_certs.sh
-----------------
Utility for generating the certificates and private keys needed
It will perform the following:
- Generate ECDSA key for the Root CA
- Generate a certificate from ca.conf as our root certificate
- Generate a keypair for our SSL server
- Generate a CSR request file to sign using our CA key
- Generate the certificate to be used by the server signed by the CA with the server.conf

In order to run it:
```
chmod +x generate_certs.sh
./generate_certs.sh
```
Note that you can change the script for openssl path accordingly

run_tshark.sh
-------------
Utility for running wireshark CLI with the openssl s_client, to create a pcap of the client - server communication between the s_client and the tls_server in the repo
Do note that the server has to be running, so below for how to run the server

In order to run it:
```
chmod +x run_tshark.sh
./run_tshark.sh
```

tls_server.py
-------------
Client / Server for encrypted TLS file upload / download

Requires a 16 byte secret for the AES encryption

Can also be ran with envelope encryption for KEK / DEK encryption / decryption accordingly

Script server help:
```
$ python tls_server.py server --help

usage: tls_server.py server [-h] [-cds]

optional arguments:
  -h, --help            show this help message
                        and exit
  -cds, --clear-datastore
```

Script client help:
```
$ python tls_server.py client --help

usage: tls_server.py client [-h] -s SECRET
                            [-ee]
                            {download,upload}
                            ...

positional arguments:
  {download,upload}

optional arguments:
  -h, --help            show this help message
                        and exit
  -s SECRET, --secret SECRET
  -ee, --envelope-encryption
```

Running the server:
```
python tls_server server -cds
```

Running the client upload:
```
python tls_server.py client -s a1a2a3a4a5a6a7a8 -ee upload -fp ./certs/ca.conf
```

Running the client download:
```
python tls_server.py client -s a1a2a3a4a5a6a7a8 -ee download -fn ca.conf -op /tmp/ca.conf2
```