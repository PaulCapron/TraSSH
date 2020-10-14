#!/usr/bin/env perl
use Net::SSH2;  # sudo apt install libnet-ssh2-perl

my $port = shift || 22;
die "Usage: $0 [port=22]\n" if @ARGV > 0;

print "Testing SSH connection to localhost:$port with libssh2…\n";

my $ssh = Net::SSH2->new();
$ssh->connect('localhost', $port) or $ssh->die_with_error;
