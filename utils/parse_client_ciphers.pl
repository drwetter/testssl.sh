#!/usr/bin/perl

use strict;
use Data::Dumper;
use JSON;

my $namelength = 30;

# Get all ciphers first (sorry only works on 64 bit mac atm)
my @spec;
my %ciphers;
foreach my $line ( split /\n/, `bin/openssl.Darwin.x86_64 ciphers -V 'ALL:COMPLEMENTOFALL:\@STRENGTH'`) {
	my @fields = split /\s+/, $line;
	my $hex = "";
	foreach my $byte ( split /,/, $fields[1] ) {
		$byte = lc $byte;
		$byte =~ s/^0x//;
		$hex .= $byte;
	}
	$hex =~ s/^0+//;
	$ciphers{hex "0x$hex"} = $fields[3];
}

open OUT, ">client-simulation-data.sh" or die "Unable to open client-simulation-data.sh";
print OUT "#!/bin/bash

# This file contains client handshake data used in the run_client_simulation function
# Don't update this file by hand, but run util/parse_client_ciphers.pl instead

# --- Qualys SSL Labs --- From: https://api.dev.ssllabs.com/api/v3/getClients ---
";

# Get the data
my $json = `curl 'https://api.dev.ssllabs.com/api/v3/getClients'`;
my $ssllabs = decode_json($json);

foreach my $client ( @$ssllabs ) {
	# Names
	my $name = "$client->{name} $client->{version}";
	$name .= " $client->{platform}" if exists $client->{platform};
	# Get first namelength characters only
	$name = substr($name . (" " x $namelength),0,$namelength);
	print OUT "names+=(\"$name\")\n";

	# Shorts
	my $shortname = "$client->{name}_$client->{version}";
	$shortname =~ s/ /_/g;
	$shortname =~ s/\.//g;
	$shortname .= "_$client->{platform}" if exists $client->{platform};
	$shortname =~ s/[ \.]//g;
	$shortname = lc($shortname);
	print OUT "short+=(\"$shortname\")\n";

	# Ciphers
	my @ciphers = ();
	foreach my $suite ( @{$client->{suiteIds}} ) {
		push @ciphers, $ciphers{$suite} if exists $ciphers{$suite};
	}
	print OUT "ciphers+=(\"" . (join ":", @ciphers) . "\")\n";

	# SNI
	if ( exists $client->{supportsSni} && $client->{supportsSni} ) {
		print OUT "sni+=(\"\$SNI\")\n";
	} else {
		print OUT "sni+=(\"\")\n";		
	}

	# warning (if needed)
	print OUT "warning+=(\"\")\n";

	# Handshake
	if ( exists $client->{hexHandshakeBytes} ) {
		print OUT "handshakebytes+=(\"$client->{hexHandshakeBytes}\")\n"
	} else {
		print OUT "handshakebytes+=(\"\")\n"
	}

	# protos
	my @proto_flags = ();
	my @tls_flags = ();
	# Figure out if we need to support sslv2
	if ( $client->{lowestProtocol} < 768 && $client->{highestProtocol} >= 512 ) { 
		# 512 = 0x200 = sslv2
		# 768 = 0x300 = sslv3
		push @proto_flags, "-ssl2";
	} else {
		push @proto_flags, "-no_ssl2";
	}
	# Do we need to support SSL3?
	if ( $client->{lowestProtocol} <= 768 && $client->{highestProtocol} >= 768 ) { 
		# 768 = 0x300 = sslv3
		push @proto_flags, "-ssl3";
	} else {
		push @proto_flags, "-no_ssl3"
	}
	# Do we need to support TLS 1.0?
	if ( $client->{lowestProtocol} <= 769 && $client->{highestProtocol} >= 769 ) { 
		# 769 = 0x301 = tls1.0
		push @tls_flags, "-tls1";
	} else {
		push @proto_flags, "-no_tls1"
	}
	# Do we need to support TLS 1.1?
	if ( $client->{lowestProtocol} <= 770 && $client->{highestProtocol} >= 770 ) { 
		# 770 = 0x302 = tls1.1
		push @tls_flags, "-tls1_1";
	} else {
		push @proto_flags, "-no_tls1_1"
	}
	# Do we need to support TLS 1.2?
	if ( $client->{lowestProtocol} <= 771 && $client->{highestProtocol} >= 771 ) { 
		# 771 = 0x303 = tls1.2
		push @tls_flags, "-tls1_2";
	} else {
		push @proto_flags, "-no_tls1_2"
	}
	print OUT "protos+=(\"" . (join " ", @proto_flags) . "\")\n";
	print OUT "tlsvers+=(\"" . (join " ", reverse @tls_flags) . "\")\n";
	printf OUT "lowest_protocol+=(\"0x%04x\")\n", $client->{lowestProtocol};
	printf OUT "highest_protocol+=(\"0x%04x\")\n", $client->{highestProtocol};

	print OUT "service+=(\"HTTP\")\n";

	print OUT "\n";
}

print OUT 
'# --- testssl.sh maintained clients ---
	     
#names+=("Mail iOS 9.3.2                ")
#short+=("mail_ios_932")
#ciphers+=("ECDHE-ECDSA-AES256-SHA384:ECDHE-ECDSA-AES128-SHA256:ECDHE-ECDSA-AES256-SHA:ECDHE-ECDSA-AES128-SHA:ECDHE-ECDSA-DES-CBC3-SHA:ECDHE-RSA-AES256-SHA384:ECDHE-RSA-AES128-SHA256:ECDHE-RSA-AES256-SHA:ECDHE-RSA-AES128-SHA:ECDHE-RSA-DES-CBC3-SHA:DHE-RSA-AES256-SHA256:DHE-RSA-AES128-SHA256:DHE-RSA-AES256-SHA:DHE-RSA-AES128-SHA:EDH-RSA-DES-CBC3-SHA:AES256-SHA256:AES128-SHA256:AES256-SHA:AES128-SHA:DES-CBC3-SHA:ECDHE-ECDSA-RC4-SHA:ECDHE-RSA-RC4-SHA:RC4-SHA:RC4-MD5")
#sni+=("$SNI")
#warning+=("")
#handshakebytes+=("16030100bb010000b703015767e6ae46f9abf3138e26a9f9880f9697bf3387f7eff709db1fa220e692d80420fb04b0979bae1664e11ef172d4dfba15af59dd200b7831992a35c73cde9efed9003200ffc024c023c00ac009c008c028c027c014c013c012006b0067003900330016003d003c0035002f000ac007c011000500040100003c000000190017000014696d61702e73656374696f6e7a65726f2e6f7267000a00080006001700180019000b0002010000050005010000000000120000")
#protos+=("-no_ssl2 -ssl3")
#tlsvers+=("-tls_1_2 -tls_1_1 -tls1")
#lowest_protocol+=("0x0300")
#highest_protocol+=("0x0304")
#service+=("SMTP,POP,IMAP")";
';

exit;


