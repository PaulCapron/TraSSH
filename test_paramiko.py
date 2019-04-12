#!/usr/bin/env python2
import paramiko  # sudo apt install python-paramiko

client = paramiko.SSHClient()

print "This process should hang!"
client.connect("localhost", username="root", password="sekreet")

stdin, stdout, stderr = client.exec_command("whoami")
for line in stdout:
    print line.strip("\n")
client.close()
