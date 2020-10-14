#!/usr/bin/env python
# sudo apt install python3-pip && pip3 install ansible-pylibssh  — sorry
from pylibsshext.session import Session
from pylibsshext.errors import LibsshSessionException
from pylibsshext import __libssh_version__
import sys
import logging

if len(sys.argv) > 2:
    print("Usage %s [port=22]" % sys.argv[0], file=sys.stderr)
    sys.exit(64)
elif len(sys.argv) > 1:
    port = int(sys.argv[1])
else:
    port = 22

print("Attempting to establish an SSH connection to localhost:%u..." % port)
print(f'{__libssh_version__=}')

ssh = Session()
ssh.set_log_level(logging.CRITICAL)  # CRITICAL is actually mapped to libssh.SSH_LOG_TRACE (…!)
try:
    ssh.connect(
        host="localhost",
        user="root",
        password="sekreet",
        timeout=2,
        port=port,
        look_for_keys=False,
        host_key_checking=False
    )
except LibsshSessionException as e:
    print(f'Failed to connect to localhost:{port} over SSH: {e!s}')
