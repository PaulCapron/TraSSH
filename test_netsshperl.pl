#!/usr/bin/env perl
use Net::SSH::Perl;  # cpan -i Net::SSH::Perl

print "This process should hang!\n";

my $ssh = Net::SSH::Perl->new('localhost');
$ssh->login('root', 'sekreetpasswd');
my ($stdout, $stderr, $exit) = $ssh->cmd('whoami');
