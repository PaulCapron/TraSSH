#!/bin/sh
# sudo apt install openssh-client — normally installed by default

case $# in
    0) port=22;;
    1) port=$1;;
    *) echo "Usage: $0 [port=22]" >&2; exit 64
esac

echo Testing SSH connection on localhost:$port with $(which ssh)…
echo

exec ssh -vvv -p $port                                           \
     -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
     -o HostKeyAlgorithms=ecdsa-sha2-nistp384,ssh-rsa            \
     localhost
