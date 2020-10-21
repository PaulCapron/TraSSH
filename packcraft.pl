#!/usr/bin/env perl
# SSH (bogus) keyshake packets/messages generation.
#
# Author: Paul <paul@fragara.com>
# Created: 2020 AD
# SPDX-License-Identifier: CC0-1.0
#  The author has dedicated all rights to this software to the public domain.
#  This software is distributed without any warranty.
use strict; use warnings;

sub usage {
  my ($MSGTYPE, $KEYTYPE) = ('MSGTYPE', 'KEYTYPE');
  my ($kexinit, $kexdhreply, $newkeys, $ecdsa384, $rsaBITS) =
      ('kexinit', 'kexdhreply', 'newkeys', 'ecdsa384', 'rsa<size_in_bits>');
  if (-t STDERR) {
    require Term::ANSIColor;
    $_ = Term::ANSIColor::colored($_, 'bold italic') for ($MSGTYPE, $KEYTYPE);
    $_ = Term::ANSIColor::colored($_, 'bold')
        for ($kexinit, $kexdhreply, $newkeys, $ecdsa384, $rsaBITS);
  }
  die "Usage: $0 $MSGTYPE [$KEYTYPE]

  Print on stdout an SSH packet encapsulating an handshake message.

$MSGTYPE is “$kexinit”, “$kexdhreply”, or “$newkeys”;
When it’s $kexinit or $kexdhreply:
 – $KEYTYPE must be set, and
 – stdin is read for key material (think /dev/urandom).
$KEYTYPE is “$ecdsa384” or “$rsaBITS” (e.g.: rsa8192).
";
}


use constant {
  SIZEOF_PACKLEN_FIELD => 4,  # size of the “packet_length” field (one uint32)
  SIZEOF_PADLEN_FIELD  => 1,  # size of the “padding_length” field (one byte)

  # These codes are defined in https://tools.IETF.org/html/rfc4253#section-12
  SSH_MSG_KEXINIT     => 20,
  SSH_MSG_NEWKEYS     => 21,
  # The next one is defined in https://www.RFC-editor.org/errata/eid1486
  SSH_MSG_KEXDH_REPLY => 31,
};


# Encapsulate in SSH wire format the given payload.
# See https://tools.IETF.org/html/rfc4253#section-6
sub packet($) {
  my $payload = $_[0];
  my $paylen = length $payload;

  # “Arbitrary-length padding, such that the total length of
  #  (packet_length || padding_length || payload || random padding)
  # is a multiple of the cipher block size or 8, whichever is larger.”
  my $padlen = 8 - (SIZEOF_PACKLEN_FIELD + SIZEOF_PADLEN_FIELD + $paylen) % 8;
  $padlen += 8 if $padlen < 4;  # “there MUST be at least four bytes of padding”

  my $packlen = SIZEOF_PADLEN_FIELD + $paylen + $padlen;

  # https://GitHub.com/mkj/dropbear/blob/a27e8b053/default_options.h#L293
  warn "dropbear refuses a $paylen bytes payload; its max is 32 KiB"
      if $paylen > (32 * 1024);

  # https://GitHub.com/openssh/openssh-portable/blob/18813a32b/packet.c#L96
  # https://GitHub.com/golang/crypto/blob/c90954cbb/ssh/cipher.go#L32
  # https://git.libssh.org/projects/libssh.git/tree/include/libssh/priv.h?id=693383d1e#n171
  warn "OpenSSH, golang ssh, & libssh refuse a $packlen bytes packet; their max is 256 KiB"
      if $packlen > (256 * 1024);

  # https://GitHub.com/libssh2/libssh2/blob/ff1b15573/include/libssh2.h#L263
  warn "libssh2 refuses a $packlen bytes packet; its max is 40 kB"
      if $packlen > 40_000;

  return pack('N', $packlen)
      . pack('C', $padlen)
      . $payload
      . ("\0" x $padlen);
}


# Structure as an SSH "string" the given value.
# An SSH string is prefixed by its length, which must be lower than 2³².
# It is _not_ null-terminated. It may be binary data.
# See https://tools.IETF.org/html/rfc4251#section-5
sub string($) {
  my $len = length $_[0];
  die "A length of $len is too much for an SSH string" if $len >= 2**32;
  return pack('N', $len) . $_[0];
}

# Structure as an SSH "name-list" the given strings.
# The names are joined by commas, the whole lot is encoded as an SSH string.
# See https://tools.IETF.org/html/rfc4251#section-5
sub namelist(@) {
  return string(join(',', @_));
};

# Structure as an SSH "mpint" the given number (a bytestring).
# ⚠ Here the given bytes are implied to always represent a _positive_ number.
# See https://tools.IETF.org/html/rfc4251#section-5
sub mpint($) {
  my $bytestr = $_[0];
  my $firstbyte = unpack 'C', $bytestr;

  # “If the most significant bit would be set for a positive number,
  # the number MUST be preceded by a zero byte.”
  $bytestr = "\0" . $bytestr if $firstbyte > 0x7F;

  return string($bytestr);
}

# Structure as an SSH RSA public host key the given exponent & modulus.
# See https://tools.IETF.org/html/rfc4253#section-6.6
# and https://tools.IETF.org/html/rfc4253#section-8
sub hostkey_rsa($$) {
  my ($e, $n) = @_;
  return string('ssh-rsa')
      . mpint($e)
      . mpint($n);
}

# Structure as an SSH RSA signature the given blob.
# See https://tools.IETF.org/html/rfc4253#section-6.6
# and https://tools.IETF.org/html/rfc4253#section-8
sub signedhash_rsa($) {
  return string('ssh-rsa')
      . string($_[0]);
}

# Structure as an SSH ECC public host key the given elliptic curve point.
# The point is given already encoded as a bytestring.
# See https://tools.IETF.org/html/rfc5656#section-3.1
sub hostkey_ecdsa($$) {
  my ($curve, $q) = @_;
  warn "Unusual curve: $curve" if $curve !~ /^nistp(?:256|384|521)$/;
  return string('ecdsa-sha2-' . $curve)
      . string($curve)
      . string($q);
}

# Structure as an SSH ECDSA signature the given ‘r’ and ‘s’ (the output
# of the ECDSA algorithm).
# See https://tools.IETF.org/html/rfc5656#section-3.1.2
sub signedhash_ecdsa($$$) {
  my ($curve, $r, $s) = @_;
  warn "Unusual curve: $curve" if $curve !~ /^nistp(?:256|384|521)$/;
  return string('ecdsa-sha2-' . $curve)
      . string(  mpint($r)
               . mpint($s) );
}


# Make up a new RSA public key: an exponent, & a modulus of the given size.
# See https://tools.IETF.org/html/rfc8017#section-3.1
sub new_rsa_pubkey($) {
  my $size = $_[0];
  my ($e, $n);

  # Use a 24-bit⇔3-byte odd exponent; some clients refuse bigger values
  $e = "\xFF\xF7\xFF";  # the bigger the Hamming weight (# of 1s) the slower!
                        # add a 0 in the middle to disturb branch prediction (?)

  # Get a big odd modulus:
  read STDIN, $n, (($size / 8) - 1) or die "Can't read stdin: $!";
  $n = $n . "\xFF";

  return ($e, $n);
}

# Make up a bogus, but superficially OK, RSASSA-PKCS1-v1_5 signature, given
# an RSA modulus.
# See https://tools.IETF.org/html/rfc3447#section-8.2.1
sub fake_rsa_sig($) {
  my $n = $_[0];

  # The signature must have the same byte length than the RSA modulus,
  # but its numerical value must be strictly lower than the modulus:
  return substr($n, 0, -1) . "\x00";
}


# Make up a new ECDSA public key: a point on the NIST-P384 curve.
# See https://www.SECG.org/sec2-v2.pdf#page=15
sub new_ecdsa384_pubkey() {
  use Math::BigInt;  # built-in module

  # Our point doesn’t have to be generated by a private key (hence we can
  # avoid all the “double-and-add” machinery) but it still has to be valid;
  # see https://www.SECG.org/sec1-v2.pdf#page=30
  # So let’s solve the curve equation: that’s slow but straightforward.

  use constant {
    # The equation is 𝒚² = 𝒙³ + 𝑎⋅𝒙 + 𝑏, with 𝑎 and 𝑏 being:
    NISTP384_A => Math::BigInt->from_hex(
      'FFFFFFFF_FFFFFFFF_FFFFFFFF_FFFFFFFF_FFFFFFFF_FFFFFFFF_FFFFFFFF'
      . 'FFFFFFFE_FFFFFFFF_00000000_00000000_FFFFFFFC'),
    NISTP384_B => Math::BigInt->from_hex(
      'B3312FA7_E23EE7E4_988E056B_E3F82D19_181D9C6E_FE814112_0314088F'
      . '5013875A_C656398D_8A2ED19D_2A85C8ED_D3EC2AEF'),

    # The curve is applied over the prime finite field 𝔽𝑝, with 𝑝 being:
    NISTP384_P => Math::BigInt->from_hex(
      'FFFFFFFF_FFFFFFFF_FFFFFFFF_FFFFFFFF_FFFFFFFF_FFFFFFFF_FFFFFFFF'
      . 'FFFFFFFE_FFFFFFFF_00000000_00000000_FFFFFFFF'),
  };
  use constant {
    # We’ll use the following constants wrt. quadratic residue:
    NISTP384_PMINUS1_HALVED => NISTP384_P->copy->bdec->brsft(1),
    NISTP384_PPLUS1_QUARTERED => NISTP384_P->copy->binc->brsft(2)
  };

  my ($x, $y);   # point coordinates
  my $rhs;       # right-hand side / polynomial of the curve equation
  my $legendre;  # https://en.Wikipedia.org/wiki/Legendre_symbol

  do {
    # Let’s try a random 𝒙 the same size as, but lower than, 𝑝:
    # (It follows that, by construction, 𝒙 ≡ 𝒙 mod 𝑝)
    read STDIN, $x, 47 or die "Can't read stdin: $!";
    $x = Math::BigInt->from_bytes("\xFE" . $x);

    # Plug that 𝒙 in the right-hand side of the equation, and compute:
    $rhs = $x->copy->bpow(3)
        ->badd(NISTP384_A->copy->bmul($x))
        ->badd(NISTP384_B)
        ->bmod(NISTP384_P);  # …in 𝔽𝑝

    # There may actually be no 𝒚 such as 𝒚² ≡ 𝒙³+𝑎⋅𝒙+𝑏 (mod 𝑝). Let’s check:
    $legendre = $rhs->copy->bmodpow(NISTP384_PMINUS1_HALVED, NISTP384_P);
  } while (!$legendre->is_one);

  # Now that we have a valid 𝒙, getting 𝒚 is easy — only because 𝑝 ≡ 3 mod 4;
  # see https://en.Wikipedia.org/wiki/Quadratic_residue#Prime_or_prime_power_modulus
  $y = $rhs->bmodpow(NISTP384_PPLUS1_QUARTERED, NISTP384_P);

  # Finally, encode (𝒙, 𝒚) as per https://www.SECG.org/sec1-v2.pdf#page=16
  # Use “uncompressed form”; sadly compressed form ain’t as widely supported,
  # see e.g. https://GitHub.com/golang/go/issues/34105
  return sprintf "\x04%48s%48s", $x->to_bytes, $y->to_bytes;
};

# Make up a bogus, but superficially OK, signature on the NIST-P384 curve.
# See https://www.SECG.org/sec1-v2.pdf#page=49
sub fake_ecdsa384_sig() {
  my ($r, $s);

  # Two numbers, each lower than the curve order:
  read STDIN, $r, 47 or die "Can't read stdin: $!";
  read STDIN, $s, 47 or die "Can't read stdin: $!";
  $r = "\x7F" . $r;  # to ensure mpint() doesn’t add a leading 0 byte
  $s = "\x7F" . $s;

  return ($r, $s);
}


# See https://tools.IETF.org/html/rfc4253#section-7.1
sub kexinit($) {
  my $keyalg = $_[0];

  my $cook;
  read STDIN, $cook, 16 or die "Can't read stdin: $!";

  # Group 14 is widely supported, 16 less so. 1 is legacy:
  my @kex_algorithms = ('diffie-hellman-group1-sha1',
                        'diffie-hellman-group14-sha1',
                        'diffie-hellman-group16-sha512');
  my @server_host_key_algorithms = ($keyalg);
  my @encryption_algorithms_client_to_server = ('aes192-cbc', 'aes256-ctr');
  my @encryption_algorithms_server_to_client = ('aes256-ctr', 'aes128-cbc');
  my @mac_algorithms_client_to_server = ('hmac-sha2-256', 'hmac-sha1');
  my @mac_algorithms_server_to_client = ('hmac-sha1', 'hmac-sha2-256');
  my @compression_algorithms_client_to_server = ('none');
  my @compression_algorithms_server_to_client = ('none');
  my @languages_client_to_server = ();
  my @languages_server_to_client = ();

  my @packed_lists = (
    namelist(@kex_algorithms),
    namelist(@server_host_key_algorithms),
    namelist(@encryption_algorithms_client_to_server),
    namelist(@encryption_algorithms_server_to_client),
    namelist(@mac_algorithms_client_to_server),
    namelist(@mac_algorithms_server_to_client),
    namelist(@compression_algorithms_client_to_server),
    namelist(@compression_algorithms_server_to_client),
    namelist(@languages_client_to_server),
    namelist(@languages_server_to_client),
  );

  return pack('C', SSH_MSG_KEXINIT)
      . $cook
      . join('', @packed_lists)
      . pack('C', 0)   # “guessed kex follows?”
      . pack('N', 0);  # “reserved for future use” by RFC 4253
}

# See https://tools.IETF.org/html/rfc4253#section-8
sub kexdhreply($$) {
  my ($key, $sig) = @_;
  my $f;  # public Diffie-Hellman key

  # Make f smaller than it normally is; it’s still valid, and we save bytes:
  read STDIN, $f, 22 or die "Can't read stdin: $!";
  $f = "\x7F" . $f;  # to ensure mpint() doesnt add a leading 0 byte

  return pack('C', SSH_MSG_KEXDH_REPLY)
      . string($key)
      . mpint($f)
      . string($sig);
}

# See https://tools.IETF.org/html/rfc4253#section-7.3
# libssh seems to wait for a MSG_NEWKEYS before checking the KEXDH_REPLY
sub newkeys() {
  return pack('C', SSH_MSG_NEWKEYS);
}


usage() if @ARGV < 1 || @ARGV > 2;

my $payload;

if ($ARGV[0] eq 'kexinit' || $ARGV[0] eq 'kexdhreply') {
  my $keytype = $ARGV[1] or usage();
  my $size;
  if ($keytype =~ /^rsa(\d+)$/i) {
    $size = $1;
  } elsif ($keytype ne 'ecdsa384') {
    warn "Unrecognized host key type: $keytype\n";
    usage();
  }

  if ($ARGV[0] eq 'kexinit') {
    $payload = kexinit(($keytype eq 'ecdsa384') ? 'ecdsa-sha2-nistp384' : 'ssh-rsa');
  } else {
    my ($key, $sig);

    if ($keytype eq 'ecdsa384') {
      $key = hostkey_ecdsa('nistp384', new_ecdsa384_pubkey());
      my ($r, $s) = fake_ecdsa384_sig();
      $sig = signedhash_ecdsa('nistp384', $r, $s);
    } else {
      my ($e, $n) = new_rsa_pubkey($size);
      $key = hostkey_rsa($e, $n);
      $sig = signedhash_rsa(fake_rsa_sig($n));

      # https://git.OpenSSL.org/gitweb/?p=openssl.git;f=include/openssl/rsa.h;hb=62f27ab9d#l37
      warn "OpenSSL refuses a $size-bit RSA key/sig; its max is 16 KiB"
          if $size > (16 * 1024);

      # https://GitHub.com/ARMmbed/mbedtls/commit/da1b4de0e
      warn "MbedTLS refuses a $size-bit RSA key/sig; its max is 8 KiB"
          if $size > (8 * 1024);
    }
    $payload = kexdhreply($key, $sig);
  }
} elsif ($ARGV[0] eq 'newkeys') {
  $payload = newkeys();
} else {
  usage();
}

print packet($payload);
