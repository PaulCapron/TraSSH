#!/usr/bin/env perl
# Half-automated SSH packet generation. See RFC 4253 & RFC 4251.
#
# This script outputs a valid SSH key-exchange packet (in binary format),
# to be then manually copy/pasted in sshtarp.c
#
# `hexdump'/`hd' is your friend to transform the output of this script to proper
# C character literals or hexadecimal escape sequences. Yeah, that’s laborious,
# but it’s basically a one-time job. And everything that can be done statically,
# at (pre-)compile time, should be done that way!
#
use strict;
use warnings;

use constant {
  SIZEOF_PACKLEN_FIELD => 4,  # one uint32 (four bytes)
  SIZEOF_PADLEN_FIELD  => 1,  # one byte

  SSH_MSG_KEXINIT => 20  # see https://tools.ietf.org/html/rfc4253#section-12
};

# Encapsulate in SSH wire format the given payload.
# See https://tools.ietf.org/html/rfc4253#section-6
sub craft_ssh_packet($) {
  my $payload = $_[0];
  my $paylen = length $payload;

  # "Arbitrary-length padding, such that the total length of
  #  (packet_length || padding_length || payload || random padding)
  # is a multiple of the cipher block size or 8, whichever is larger."
  my $padlen = 8 - (SIZEOF_PACKLEN_FIELD + SIZEOF_PADLEN_FIELD + $paylen) % 8;

  $padlen += 8 if $padlen < 4;  # there MUST be at least four bytes of padding

  # Make the padding delicious, like it contains a part of /etc/passwd:
  my $pad = substr 'eva:*:1029:', 0, $padlen;

  my $packlen = SIZEOF_PADLEN_FIELD + $paylen + $padlen;

  return pack('N', $packlen)
      . pack('C', $padlen)
      . $payload
      . $pad;
}

# Structure as an SSH "name-list" the given strings.
# See https://tools.ietf.org/html/rfc4251#section-5
sub pack_name_list(@) {
  my $str = join(',', @_);
  return pack('N', length $str), $str;
};

# See https://tools.ietf.org/html/rfc4253#section-7.1
my @kex_algorithms = ('diffie-hellman-group14-sha1');
my @server_host_key_algorithms = ('ssh-rsa', 'ssh-dss');
my @encryption_algorithms_client_to_server = ('aes256-ctr', 'aes128-cbc');
my @encryption_algorithms_server_to_client = ('aes256-ctr', 'aes128-cbc');
my @mac_algorithms_client_to_server = ('hmac-sha2-256', 'hmac-sha1');
my @mac_algorithms_server_to_client = ('hmac-sha2-256', 'hmac-sha1');
my @compression_algorithms_client_to_server = ('none');
my @compression_algorithms_server_to_client = ('zlib', 'none');
my @languages_client_to_server = ();
my @languages_server_to_client = ();

my @packed_lists = (
  pack_name_list(@kex_algorithms),
  pack_name_list(@server_host_key_algorithms),
  pack_name_list(@encryption_algorithms_client_to_server),
  pack_name_list(@encryption_algorithms_server_to_client),
  pack_name_list(@mac_algorithms_client_to_server),
  pack_name_list(@mac_algorithms_server_to_client),
  pack_name_list(@compression_algorithms_client_to_server),
  pack_name_list(@compression_algorithms_server_to_client),
  pack_name_list(@languages_client_to_server),
  pack_name_list(@languages_server_to_client),
);

my $payload = pack('C', SSH_MSG_KEXINIT)
    . "erhart:/bin/csh\n"  # suspicious "random" cookie
    . join('', @packed_lists)
    . pack('C', 0)   # guessed kex follows?
    . pack('N', 0);  # "reserved for future use" by RFC4253

my $packet = craft_ssh_packet($payload);

print $packet;
