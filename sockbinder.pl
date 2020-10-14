#!/usr/bin/env perl
# This is a minimal launcher for `trassh', useful during development.
# It depends only on Perl and some of its built-in modules.
# Example usage:  make && ./sockmaker.pl 2222 ./trassh <trassh.dat
use Socket;
use constant SOCK_FD => 3;

sub usage {
  ($port, $prog, $prog_args) = ('port', 'prog', 'prog_args');
  if (-t STDERR) {
    require Term::ANSIColor;
    for ($port, $prog, $prog_args) {
      $_ = Term::ANSIColor::colored($_, 'bold italic');
    }
  }
  die "Usage: $0 $port $prog [$prog_args]…

  Create a TCP socket listening on 0.0.0.0:$port, then execute $prog
  with the socket as file descriptor #" . SOCK_FD . ", and SIGPIPE ignored.

$port is an integer in [1, 65535].
$prog is an executable name.
$prog_args are any arguments to pass to $prog.
";
}

$port = shift or usage;
$prog = shift or usage;
usage if $port !~ /^\d+$/ or $port < 1 or $port > 65535;

$^F = SOCK_FD;
# Do not close-on-exec the socket!
# See https://perldoc.perl.org/perlvar.html#%24%5eF

socket(SOCK_FD, PF_INET, SOCK_STREAM, getprotobyname 'tcp') or die "socket: $!";
bind(SOCK_FD, sockaddr_in($port, INADDR_ANY)) or die "bind: $!";
listen(SOCK_FD, 32) or die "listen: $!";

$SIG{'PIPE'} = 'IGNORE';
# Not needed for `trassh` (the MSG_NOSIGNAL flag of send()/recv() is set),
# but generally desirable because a client disconnection triggers SIGPIPE,
# and an unhandled signal by default terminates a process.
# Preserved accross exec():
# > Except for SIGCHLD, signals set to be ignored (SIG_IGN) by the calling
# > process image shall be set to be ignored by the new process image.
# — https://pubs.OpenGroup.org/onlinepubs/9699919799/functions/exec.html

print "$0: listening on port $port (fd #" . SOCK_FD . "). "
    . "Metamorphosing into $prog…\n";
exec $prog, @ARGV or die "exec: $!";
