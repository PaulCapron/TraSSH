#!/usr/bin/env perl
# Manually guided SSH packet generation. See RFC4253.
use strict;
use warnings;

use constant {
  SIZEOF_PACKLEN_FIELD => 4,  # uint32
  SIZEOF_PADLEN_FIELD  => 1,  # byte

  SSH_MSG_KEXINIT => 20  # message code
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

my @kex_algorithms = ('diffie-hellman-group14-sha1');
my @server_host_key_algorithms = ('ssh-rsa');
my @encryption_algorithms_client_to_server = ('aes128-cbc');
my @encryption_algorithms_server_to_client = ('aes128-cbc');
my @mac_algorithms_client_to_server = ('hmac-sha1');
my @mac_algorithms_server_to_client = ('hmac-sha1');
my @compression_algorithms_client_to_server = ('none');
my @compression_algorithms_server_to_client = ('zlib', 'none');
my @languages_client_to_server = ();
my @languages_server_to_client = ();

sub pack_name_list(@) {
  my $str = join(',', @_);
  return pack('N', length $str), $str;
};

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
    . pack('C', 1)   # guessed kex follows?
    . pack('N', 0);  # "reserved for future use" by RFC4253

my $packet = craft_ssh_packet($payload);

print $packet;
