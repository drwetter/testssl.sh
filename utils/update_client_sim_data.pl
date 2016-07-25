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

# Get the data
my $json = `curl 'https://api.dev.ssllabs.com/api/v3/getClients'`;
my $ssllabs = decode_json($json);

my %sims;
foreach my $client ( @$ssllabs ) {
	# Shorts
	my $shortname = "$client->{name}_$client->{version}";
	$shortname =~ s/ /_/g;
	$shortname =~ s/\.//g;
	$shortname .= "_$client->{platform}" if exists $client->{platform};
	$shortname =~ s/[ \.]//g;
	$shortname = lc($shortname);

	# Deduplicate
	if ( ! exists $sims{$shortname} || $sims{$shortname}->{id} < $client->{id} ) {
		my $sim = {};
		$sims{$shortname} = $sim;
		$sim->{shortname} = "short+=(\"$shortname\")";

		# Names
		my $name = "$client->{name} $client->{version}";
		$name .= " $client->{platform}" if exists $client->{platform};
		# Get first namelength characters only
		$name = substr($name . " " x $namelength,0,$namelength);
		$sim->{name} = "names+=(\"$name\")";

		# Ciphers
		my @ciphers = ();
		foreach my $suite ( @{$client->{suiteIds}} ) {
			push @ciphers, $ciphers{$suite} if exists $ciphers{$suite};
		}
		$sim->{ciphers} = "ciphers+=(\"" . (join ":", @ciphers) . "\")";

		# SNI
		if ( exists $client->{supportsSni} && $client->{supportsSni} ) {
			$sim->{sni} = "sni+=(\"\$SNI\")";
		} else {
			$sim->{sni} = "sni+=(\"\")";		
		}

		# warning (if needed)
		$sim->{warning} = "warning+=(\"\")";

		# Handshake
		if ( exists $client->{hexHandshakeBytes} ) {
			$sim->{handshakebytes} = "handshakebytes+=(\"$client->{hexHandshakeBytes}\")";
		} else {
			$sim->{handshakebytes} = "handshakebytes+=(\"\")";
		}

		# protos
		my @proto_flags = ();
		my @tls_flags = ();
		# Figure out if we need to support sslv2
		if ( $client->{lowestProtocol} < 768 && $client->{highestProtocol} >= 512 ) { 
			# 512 = 0x200 = sslv2
			# 768 = 0x300 = sslv3
			push @proto_flags, "-ssl2";
		}
		# Do we need to support SSL3?
		if ( $client->{lowestProtocol} <= 768 && $client->{highestProtocol} >= 768 ) { 
			# 768 = 0x300 = sslv3
			push @proto_flags, "-ssl3";
		}
		# Do we need to support TLS 1.0?
		if ( $client->{lowestProtocol} <= 769 && $client->{highestProtocol} >= 769 ) { 
			# 769 = 0x301 = tls1.0
			push @proto_flags, "-tls1";
		}
		# Do we need to support TLS 1.1?
		if ( $client->{lowestProtocol} <= 770 && $client->{highestProtocol} >= 770 ) { 
			# 770 = 0x302 = tls1.1
			push @proto_flags, "-tls1_1";
		}
		# Do we need to support TLS 1.2?
		if ( $client->{lowestProtocol} <= 771 && $client->{highestProtocol} >= 771 ) { 
			# 771 = 0x303 = tls1.2
			push @proto_flags, "-tls1_2";
		}
		$sim->{protos} = "protos+=(\"" . (join " ", reverse @proto_flags) . "\")";
		$sim->{lowestProtocol} = sprintf("lowest_protocol+=(\"0x%04x\")", $client->{lowestProtocol});
		$sim->{highestProtocol} = sprintf("highest_protocol+=(\"0x%04x\")", $client->{highestProtocol});

		if ( lc($client->{name}) eq "java" || lc($client->{name}) eq "openssl" ) {
			# Java and OpenSSL are generic clients
			$sim->{service} =  "service+=(\"ANY\")";		
		} elsif ( $shortname =~ /^apple_ats/ ) { 
			# Apple ATS is HTTP(s) only
			$sim->{service} = "service+=(\"HTTP\")";
		} else {
			# All others are HTTP(s)/FTP only
			$sim->{service} = "service+=(\"HTTP,FTP\")";
		}

		# Bit size limitations
		$sim->{minDhBits} = "minDhBits+=($client->{minDhBits})";
		$sim->{maxDhBits} = "maxDhBits+=($client->{maxDhBits})";
		$sim->{minRsaBits} = "minRsaBits+=($client->{minRsaBits})";
		$sim->{maxRsaBits} = "maxRsaBits+=($client->{maxRsaBits})";
		$sim->{minEcdsaBits} = "minEcdsaBits+=($client->{minEcdsaBits})";
		if ( defined $client->{requiresSha2} && $client->{requiresSha2} ) {
			$sim->{requiresSha2} = "requiresSha2+=(true)";
		} else {
			$sim->{requiresSha2} = "requiresSha2+=(false)";		
		}
	}
}

#
# This is where we maintain our own clients
my $sim;
$sim = {};
#$sim->{name} = "names+=(\"Mail iOS 9.3.2                \")";
#$sim->{shortname} = "short+=(\"mail_ios_932\")";
#$sim->{ciphers} = "ciphers+=(\"ECDHE-ECDSA-AES256-SHA384:ECDHE-ECDSA-AES128-SHA256:ECDHE-ECDSA-AES256-SHA:ECDHE-ECDSA-AES128-SHA:ECDHE-ECDSA-DES-CBC3-SHA:ECDHE-RSA-AES256-SHA384:ECDHE-RSA-AES128-SHA256:ECDHE-RSA-AES256-SHA:ECDHE-RSA-AES128-SHA:ECDHE-RSA-DES-CBC3-SHA:DHE-RSA-AES256-SHA256:DHE-RSA-AES128-SHA256:DHE-RSA-AES256-SHA:DHE-RSA-AES128-SHA:EDH-RSA-DES-CBC3-SHA:AES256-SHA256:AES128-SHA256:AES256-SHA:AES128-SHA:DES-CBC3-SHA:ECDHE-ECDSA-RC4-SHA:ECDHE-RSA-RC4-SHA:RC4-SHA:RC4-MD5\")";
#$sim->{sni} = "sni+=(\"\$SNI\")";
#$sim->{warning} = "warning+=(\"\")";
#$sim->{handshakebytes} = "handshakebytes+=(\"16030100bb010000b703015767e6ae46f9abf3138e26a9f9880f9697bf3387f7eff709db1fa220e692d80420fb04b0979bae1664e11ef172d4dfba15af59dd200b7831992a35c73cde9efed9003200ffc024c023c00ac009c008c028c027c014c013c012006b0067003900330016003d003c0035002f000ac007c011000500040100003c000000190017000014696d61702e73656374696f6e7a65726f2e6f7267000a00080006001700180019000b0002010000050005010000000000120000\")";
#$sim->{protos} = "protos+=(\"#-tls1_1 -tls1\")";
#$sim->{lowestProtocol} = "lowest_protocol+=(\"0x0300\")";
#$sim->{highestProtocol} = "highest_protocol+=(\"0x0301\")";
#$sim->{service} = "service+=(\"SMTP,POP,IMAP\")";
#$sim->{minDhBits} = "minDhBits+=(-1)";
#$sim->{maxDhBits} = "maxDhBits+=(-1)";
#$sim->{minRsaBits} = "minRsaBits+=(-1)";
#$sim->{maxRsaBits} = "maxRsaBits+=(-1)";
#$sim->{minEcdsaBits} = "minEcdsaBits+=(-1)";
#$sim->{requiresSha2} = "requiresSha2+=(false)";
#
#$sim->{name} = "names+=(\"Mail OSX 10.11.15             \")";
#$sim->{shortname} = "short+=(\"mail_osx_101115\")";
#$sim->{ciphers} = "ciphers+=(\"ECDHE-ECDSA-AES256-SHA384:ECDHE-ECDSA-AES128-SHA256:ECDHE-ECDSA-AES256-SHA:ECDHE-ECDSA-AES128-SHA:ECDHE-ECDSA-DES-CBC3-SHA:ECDHE-RSA-AES256-SHA384:ECDHE-RSA-AES128-SHA256:ECDHE-RSA-AES256-SHA:ECDHE-RSA-AES128-SHA:ECDHE-RSA-DES-CBC3-SHA:DHE-RSA-AES256-SHA256:DHE-RSA-AES128-SHA256:DHE-RSA-AES256-SHA:DHE-RSA-AES128-SHA:EDH-RSA-DES-CBC3-SHA:AES256-SHA256:AES128-SHA256:AES256-SHA:AES128-SHA:DES-CBC3-SHA:ECDHE-ECDSA-RC4-SHA:ECDHE-RSA-RC4-SHA:RC4-SHA:RC4-MD5\")";
#$sim->{sni} = "sni+=(\"\$SNI\")";
#$sim->{warning} = "warning+=(\"\")";
#$sim->{handshakebytes} = "handshakebytes+=(\"16030100940100009003015770e928499e82df2eb7477200e2a828d9fa4109514385bd1602df44aaf2b0f400003200ffc024c023c00ac009c008c028c027c014c013c012006b0067003900330016003d003c0035002f000ac007c011000500040100003500000012001000000d3137382e3233372e33342e3932000a00080006001700180019000b0002010000050005010000000000120000\")";
#$sim->{protos} = "protos+=(\"-tls1\")";
#$sim->{lowestProtocol} = "lowest_protocol+=(\"0x0301\")";
#$sim->{highestProtocol} = "highest_protocol+=(\"0x0301\")";
#$sim->{service} = "service+=(\"SMTP,POP,IMAP\")";
#$sim->{minDhBits} = "minDhBits+=(-1)";
#$sim->{maxDhBits} = "maxDhBits+=(-1)";
#$sim->{minRsaBits} = "minRsaBits+=(-1)";
#$sim->{maxRsaBits} = "maxRsaBits+=(-1)";
#$sim->{minEcdsaBits} = "minEcdsaBits+=(-1)";
#$sim->{requiresSha2} = "requiresSha2+=(false)";

$sim = {};
$sim->{name} = "names+=(\"Thunderbird 45.1.1 OSX 10.11  \")";
$sim->{shortname} = "short+=(\"thunderbird_45.1.1_osx_101115\")";
$sim->{ciphers} = "ciphers+=(\"ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-SHA:ECDHE-ECDSA-AES128-SHA:ECDHE-RSA-AES128-SHA:ECDHE-RSA-AES256-SHA:DHE-RSA-AES128-SHA:DHE-RSA-AES256-SHA:AES128-SHA:AES256-SHA:DES-CBC3-SHA\")";
$sim->{sni} = "sni+=(\"\$SNI\")";
$sim->{warning} = "warning+=(\"\")";
$sim->{handshakebytes} = "handshakebytes+=(\"160301009d010000990303c7c5b3ff80b3aa597c770c538b98ae34a94c9590ad8f947ba7bc28692061cb57000016c02bc02fc00ac009c013c01400330039002f0035000a0100005a0000001800160000136d78332e73656374696f6e7a65726f2e6f7267ff01000100000a00080006001700180019000b0002010000230000000500050100000000000d001600140401050106010201040305030603020304020202\")";
$sim->{protos} = "protos+=(\"-tls1_2 -tls1_1 -tls1\")";
$sim->{lowestProtocol} = "lowest_protocol+=(\"0x0301\")";
$sim->{highestProtocol} = "highest_protocol+=(\"0x0303\")";
$sim->{service} = "service+=(\"SMTP,POP,IMAP\")";
$sim->{minDhBits} = "minDhBits+=(-1)";
$sim->{maxDhBits} = "maxDhBits+=(-1)";
$sim->{minRsaBits} = "minRsaBits+=(-1)";
$sim->{maxRsaBits} = "maxRsaBits+=(-1)";#
$sim->{minEcdsaBits} = "minEcdsaBits+=(-1)";
$sim->{requiresSha2} = "requiresSha2+=(false)";
$sims{$sim->{shortname}} = $sim;

my %count;
foreach my $shortname ( reverse sort keys %sims ) {
	if ( $shortname =~ /^baidu/ ) {
		$count{baidu}++;
		if ( $count{baidu} <= 1 ) {
			$sims{$shortname}->{current} = "current+=(true)";
		} else {
			$sims{$shortname}->{current} = "current+=(false)";
		}
	} elsif ($shortname =~ /^bing/) {
		$count{bing}++;
		if ( $count{bing} <= 1 ) {
			$sims{$shortname}->{current} = "current+=(true)";
		} else {
			$sims{$shortname}->{current} = "current+=(false)";
		}
	} elsif ($shortname =~ /^chrome/) {
		$count{chrome}++;
		if ( $count{chrome} <= 1 ) {
			$sims{$shortname}->{current} = "current+=(true)";
		} else {
			$sims{$shortname}->{current} = "current+=(false)";
		}
	} elsif ($shortname =~ /^firefox/) {
		$count{firefox}++;
		if ( $count{firefox} <= 3 ) {
			$sims{$shortname}->{current} = "current+=(true)";
		} else {
			$sims{$shortname}->{current} = "current+=(false)";
		}
	} elsif ($shortname =~ /^googlebot/) {
		$count{googlebot}++;
		if ( $count{googlebot} <= 1 ) {
			$sims{$shortname}->{current} = "current+=(true)";
		} else {
			$sims{$shortname}->{current} = "current+=(false)";
		}
	} elsif ($shortname =~ /^tor/) {
		$count{tor}++;
		if ( $count{tor} <= 1 ) {
			$sims{$shortname}->{current} = "current+=(true)";
		} else {
			$sims{$shortname}->{current} = "current+=(false)";
		}
	} elsif ($shortname =~ /^yahoo/) {
		$count{yahoo}++;
		if ( $count{yahoo} <= 1 ) {
			$sims{$shortname}->{current} = "current+=(true)";
		} else {
			$sims{$shortname}->{current} = "current+=(false)";
		}
	} elsif ($shortname =~ /^yandex/) {
		$count{yandex}++;
		if ( $count{yandex} <= 1 ) {
			$sims{$shortname}->{current} = "current+=(true)";
		} else {
			$sims{$shortname}->{current} = "current+=(false)";
		}
	} elsif ($shortname =~ /^opera/) {
		# Opera isn't a current browser
		$sims{$shortname}->{current} = "current+=(false)";
	} else {
		# All versions are current
		$sims{$shortname}->{current} = "current+=(true)";
	}
}

open OUT, ">include/client_sim.data" or die "Unable to open include/client_sim.data";
print OUT "#!/usr/bin/env bash
#
# vim:ts=5:sw=5:expandtab
# we have a spaces softtab, that ensures readability with other editors too

# This file contains client handshake data used in the run_client_simulation function
# Don't update this file by hand, but run util/update_client_sim_data.pl instead

# Most clients are taken from Qualys SSL Labs --- From: https://api.dev.ssllabs.com/api/v3/getClients 
";
foreach my $shortname ( sort keys %sims ) {
	foreach my $k ( qw(name shortname ciphers sni warning handshakebytes protos lowestProtocol highestProtocol service
		minDhBits maxDhBits minRsaBits maxRsaBits minEcdsaBits requiresSha2 current) ) {
		print OUT "     $sims{$shortname}->{$k}\n";
	}
	print OUT "\n";
}
close OUT;

exit;
