TraSSH (_“trash”_ + _“SSH”_) is a fake SSH server.

`packcraft.pl`, via `make`, generates a bogus SSH handshake.
That’s basically a one-time operation.

`trassh[.c]`, a “dæmon” (long-lived process), then serves that handshake
to connecting clients, one at a time.
`trassh` is expected to be launched & supervised by `systemd`.

The goals are to:
 * waste the time & energy of bots in search of a genuine SSH server to hack
 * gather intelligence about these bots (IP addresses, etc.)
 * learn about the SSH protocol, cryptography, TCP, &c. while developing
   (or studying) the program.
