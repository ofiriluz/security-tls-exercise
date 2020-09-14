#!/bin/bash

# Set the dynamic lib path for 1.1 openssl
export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:/opt/openssl1.1/lib

# Run tshark to record a pcap output on the server port
tshark -i loopback -f "tcp port 4431" -w servertls1_3.pcap -P -V &
tshark_pid=$!

# Sleep to let tshark start on background
sleep 1.0

# Run the openssl client
/opt/openssl1.1/bin/openssl s_client -host 172.31.22.238 -port 4431 -CAfile ./certs/ca.crt -tls1_3 &

# Sleep to let the s_client connection through
sleep 1.5

# Kill the tshark background process
kill -9 $tshark_pid