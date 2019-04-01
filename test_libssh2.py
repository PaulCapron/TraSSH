#!/usr/bin/env python2
import socket, libssh2

ssh  = libssh2.Session()
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.connect(("localhost", 22))

print "This process should hang!"
ssh.startup(sock)
print ssh.last_error()
