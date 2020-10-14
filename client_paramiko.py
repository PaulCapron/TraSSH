#!/usr/bin/env python
import paramiko  # sudo apt install python3-paramiko
import sys

if len(sys.argv) > 2:
    print("Usage %s [port=22]" % sys.argv[0], file=sys.stderr)
    sys.exit(64)
elif len(sys.argv) > 1:
    port = int(sys.argv[1])
else:
    port = 22

client = paramiko.SSHClient()

print("Testing SSH connection to localhost:%u…\n" % port)
client.connect("localhost", port=port, username="root", password="sekreet")
client.close()
