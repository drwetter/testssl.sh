#!/usr/bin/perl

use strict;
use Data::Dumper;
use JSON;

my @spec;
my %ciphers;

my @spec;
my %ciphers;
my $ossl = "bin/openssl." . `uname -s` . "." . `uname -m`;
$ossl =~ s/\R//g; 					# remove LFs

die "Unable to open $ossl" unless -f $ossl;
my $ossl = "$ossl" . " ciphers -V 'ALL:COMPLEMENTOFALL:\@STRENGTH'";

# we get all data from here
my $json = `curl 'https://api.dev.ssllabs.com/api/v3/getClients'`;

foreach my $line ( split /\n/, `$ossl`) {
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

my $namelength = 30;
# Get the data
my $ssllabs = decode_json($json);

my %sims;
foreach my $client ( @$ssllabs ) {
	# Shorts
	my $has_matched = 1;
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
		$name = substr($name . "" x $namelength,0,$namelength);
		$sim->{name} = "names+=(\"$name\")";

		# Ciphers
		my @ciphers = ();
		my @ciphersuites = ();
		foreach my $suite ( @{$client->{suiteIds}} ) {
			if  ( $suite == "4865" ) {
				push @ciphersuites, "TLS_AES_128_GCM_SHA256"; }
			elsif ( $suite == "4866" ) {
				push @ciphersuites, "TLS_AES_256_GCM_SHA384"; }
			elsif ( $suite == "4867" ) {
				push @ciphersuites, "TLS_CHACHA20_POLY1305_SHA256"; }
			elsif ( $suite == "4868" ) {
				push @ciphersuites, "TLS_AES_128_CCM_SHA256"; }
			elsif ( $suite == "4869" ) {
				push @ciphersuites, "TLS_AES_128_CCM_8_SHA256"; }
			elsif ( exists $ciphers{$suite} ) {
				push @ciphers, $ciphers{$suite}; }
			elsif ( $suite == "255" ) {
				# no openssl name for this:
				if ( $has_matched ) {
					print "Ignored: \"$shortname\" has" ;
					$has_matched = 0;
				}
				print " \"0xFF\""; }
			elsif ( $suite == "65279" ) {
				# SSL_RSA_FIPS_WITH_3DES_EDE_CBC_SHA
				if ( $has_matched ) {
					print "Ignored: \"$shortname\" has" ;
					$has_matched = 0;
				}
				print " \"0xFEFF\""; }
			elsif ( $suite == "52392" ) {
				push @ciphers, "ECDHE-RSA-CHACHA20-POLY1305"; }
			elsif ( $suite == "52393" ) {
				push @ciphers, "ECDHE-ECDSA-CHACHA20-POLY1305"; }
			elsif ( $suite == "52394" ) {
				push @ciphers, "DHE-RSA-CHACHA20-POLY1305"; }
			elsif ( $suite == "4865" ) {
				push @ciphers, "TLS13-AES-128-GCM-SHA256"; }
			elsif ( $suite == "4866" ) {
				push @ciphers, "TLS13-AES-256-GCM-SHA384"; }
			elsif ( $suite == "4867" ) {
				push @ciphers, "TLS13-CHACHA20-POLY1305-SHA256"; }
			elsif ( $suite == "4868" ) {
				push @ciphers, "TLS13-AES-128-CCM-SHA256"; }
			elsif ( $suite == "4869" ) {
				push @ciphers, "TLS13-AES-128-CCM-8-SHA256"; }
			elsif ( $suite == "2570" || $suite == "6682" || $suite == "10794" ||
				   $suite == "14906" || $suite == "19018" || $suite == "23130" ||
				   $suite == "27242" || $suite == "31354" || $suite == "35466" ||
				   $suite == "39578" || $suite == "43690" || $suite == "47802" ||
				   $suite == "51914" || $suite == "56026" || $suite == "60138" ||
				   $suite == "64250" ) {
				if ( $has_matched ) {
					print " \"$shortname\": ";
					$has_matched = 0;
				}
				print " skipping GREASE cipher "; printf("%s%04X", "0x", $suite);
			}
			else {
				print " | FIXME: ";
				if ( $has_matched ) {
					print " \"$shortname\" has ";
					$has_matched = 0;
				}
				printf("%s%04X", "0x", $suite); printf " ($suite)";
			}
		}
		print "\n" if ! $has_matched ;
		$sim->{ciphers} = "ch_ciphers+=(\"" . (join ":", @ciphers) . "\")";
		$sim->{ciphersuites} = "ciphersuites+=(\"" . (join ":", @ciphersuites) . "\")";

		# SNI
		if ( exists $client->{supportsSni} && $client->{supportsSni} ) {
			$sim->{sni} = "ch_sni+=(\"\$SNI\")";
		} else {
			$sim->{sni} = "ch_sni+=(\"\")";
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
		if ( $client->{lowestProtocol} == $client->{highestProtocol} ) {
			if ( $client->{lowestProtocol} == 512 ) {
				push @proto_flags, "-ssl2"; }
			elsif ( $client->{lowestProtocol} == 768 ) {
				push @proto_flags, "-ssl3"; }
			elsif ( $client->{lowestProtocol} == 769 ) {
				push @proto_flags, "-tls1"; }
			elsif ( $client->{lowestProtocol} == 770 ) {
				push @proto_flags, "-tls1_1"; }
			elsif ( $client->{lowestProtocol} == 771 ) {
				push @proto_flags, "-tls1_2"; }
			elsif ( $client->{lowestProtocol} == 772 ) {
				push @proto_flags, "-tls1_3"; }
		} else {
			# Figure out if we need to support sslv2
			if ( $client->{lowestProtocol} > 512 ) {
				# 512 = 0x200 = sslv2
				push @proto_flags, "-no_ssl2";
			}
			# Do we need to support SSL3?
			if ( $client->{lowestProtocol} > 768 || $client->{highestProtocol} < 768 ) {
				# 768 = 0x300 = sslv3
				push @proto_flags, "-no_ssl3";
			}
			# Do we need to support TLS 1.0?
			if ( $client->{lowestProtocol} > 769 || $client->{highestProtocol} < 769 ) {
				# 769 = 0x301 = tls1.0
				push @proto_flags, "-no_tls1";
			} else {
				push @tls_flags, "-tls1";
			}
			# Do we need to support TLS 1.1?
			if ( $client->{lowestProtocol} > 770 || $client->{highestProtocol} < 770 ) {
				# 770 = 0x302 = tls1.1
				push @proto_flags, "-no_tls1_1";
			} else {
				push @tls_flags, "-tls1_1";
			}
			# Do we need to support TLS 1.2?
			if ( $client->{lowestProtocol} > 771 || $client->{highestProtocol} < 771 ) {
				# 771 = 0x303 = tls1.2
				push @proto_flags, "-no_tls1_2";
			} else {
				push @tls_flags, "-tls1_2";
			}
		}
		$sim->{protos} = "protos+=(\"" . (join " ", reverse @proto_flags) . "\")";
		$sim->{tlsvers} = "tlsvers+=(\"" . (join " ", reverse @tls_flags) . "\")";
		$sim->{lowestProtocol} = sprintf("lowest_protocol+=(\"0x%04x\")", $client->{lowestProtocol});
		# https://api.dev.ssllabs.com/api/v3/getClients incorrectly indicates
		# a highestProtocol of TLS 1.2 for clients that support TLS 1.3, which
		# can lead to client simulation reporting "no connection" if the connection
		# is made using TLS 1.3. In order to avoid this problem, assume that any
		# client with a highestProtocol of TLS 1.2 that supports any TLS 1.3
		# ciphers really supports TLS 1.3.
		if ( $client->{highestProtocol} != 771 || scalar(@ciphersuites) == 0 ) {
			$sim->{highestProtocol} = sprintf("highest_protocol+=(\"0x%04x\")", $client->{highestProtocol});
		} else {
			$sim->{highestProtocol} = sprintf("highest_protocol+=(\"0x0304\")", $client->{highestProtocol});
		}

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

		my @curves = ();
		foreach my $curve ( @{$client->{ellipticCurves}} ) {
			if ( $curve == 1 ) {
				push @curves, "sect163k1"; }
			elsif ( $curve == 2 ) {
				push @curves, "sect163r1"; }
			elsif ( $curve == 3 ) {
				push @curves, "sect163r2"; }
			elsif ( $curve == 4 ) {
				push @curves, "sect193r1"; }
			elsif ( $curve == 5 ) {
				push @curves, "sect193r2"; }
			elsif ( $curve == 6 ) {
				push @curves, "sect233k1"; }
			elsif ( $curve == 7 ) {
				push @curves, "sect233r1"; }
			elsif ( $curve == 8 ) {
				push @curves, "sect239k1"; }
			elsif ( $curve == 9 ) {
				push @curves, "sect283k1"; }
			elsif ( $curve == 10 ) {
				push @curves, "sect283r1"; }
			elsif ( $curve == 11 ) {
				push @curves, "sect409k1"; }
			elsif ( $curve == 12 ) {
				push @curves, "sect409r1"; }
			elsif ( $curve == 13 ) {
				push @curves, "sect571k1"; }
			elsif ( $curve == 14 ) {
				push @curves, "sect571r1"; }
			elsif ( $curve == 15 ) {
				push @curves, "secp160k1"; }
			elsif ( $curve == 16 ) {
				push @curves, "secp160r1"; }
			elsif ( $curve == 17 ) {
				push @curves, "secp160r2"; }
			elsif ( $curve == 18 ) {
				push @curves, "secp192k1"; }
			elsif ( $curve == 19 ) {
				push @curves, "prime192v1"; }
			elsif ( $curve == 20 ) {
				push @curves, "secp224k1"; }
			elsif ( $curve == 21 ) {
				push @curves, "secp224r1"; }
			elsif ( $curve == 22 ) {
				push @curves, "secp256k1"; }
			elsif ( $curve == 23 ) {
				push @curves, "prime256v1"; }
			elsif ( $curve == 24 ) {
				push @curves, "secp384r1"; }
			elsif ( $curve == 25 ) {
				push @curves, "secp521r1"; }
			elsif ( $curve == 26 ) {
				push @curves, "brainpoolP256r1"; }
			elsif ( $curve == 27 ) {
				push @curves, "brainpoolP384r1"; }
			elsif ( $curve == 28 ) {
				push @curves, "brainpoolP512r1"; }
			elsif ( $curve == 29 ) {
				push @curves, "X25519"; }
			elsif ( $curve == 30 ) {
				push @curves, "X448"; }
		}
		$sim->{ellipticCurves} = "curves+=(\"" . (join ":", @curves) . "\")";
	}
}

#
# This is where we maintain our own clients
my $sim = {};
#$sim->{name} = "names+=(\"Mail iOS 9.3.2                \")";
#$sim->{shortname} = "short+=(\"mail_ios_932\")";
#$sim->{ciphers} = "ch_ciphers+=(\"ECDHE-ECDSA-AES256-SHA384:ECDHE-ECDSA-AES128-SHA256:ECDHE-ECDSA-AES256-SHA:ECDHE-ECDSA-AES128-SHA:ECDHE-ECDSA-DES-CBC3-SHA:ECDHE-RSA-AES256-SHA384:ECDHE-RSA-AES128-SHA256:ECDHE-RSA-AES256-SHA:ECDHE-RSA-AES128-SHA:ECDHE-RSA-DES-CBC3-SHA:DHE-RSA-AES256-SHA256:DHE-RSA-AES128-SHA256:DHE-RSA-AES256-SHA:DHE-RSA-AES128-SHA:EDH-RSA-DES-CBC3-SHA:AES256-SHA256:AES128-SHA256:AES256-SHA:AES128-SHA:DES-CBC3-SHA:ECDHE-ECDSA-RC4-SHA:ECDHE-RSA-RC4-SHA:RC4-SHA:RC4-MD5\")";
#$sim->{ciphersuites} = "ciphersuites+=(\"\")";
#$sim->{sni} = "ch_sni+=(\"\$SNI\")";
#$sim->{warning} = "warning+=(\"\")";
#$sim->{handshakebytes} = "handshakebytes+=(\"16030100bb010000b703015767e6ae46f9abf3138e26a9f9880f9697bf3387f7eff709db1fa220e692d80420fb04b0979bae1664e11ef172d4dfba15af59dd200b7831992a35c73cde9efed9003200ffc024c023c00ac009c008c028c027c014c013c012006b0067003900330016003d003c0035002f000ac007c011000500040100003c000000190017000014696d61702e73656374696f6e7a65726f2e6f7267000a00080006001700180019000b0002010000050005010000000000120000\")";
#$sim->{protos} = "protos+=(\"#-no_tls1_2 -no_ssl3 -no_ssl2\")";
#$sim->{tlsvers} = "tlsvers+=(\"#-tls1_1 -tls1\")";
#$sim->{lowestProtocol} = "lowest_protocol+=(\"0x0300\")";
#$sim->{highestProtocol} = "highest_protocol+=(\"0x0301\")";
#$sim->{service} = "service+=(\"SMTP,POP,IMAP\")";
#$sim->{minDhBits} = "minDhBits+=(-1)";
#$sim->{maxDhBits} = "maxDhBits+=(-1)";
#$sim->{minRsaBits} = "minRsaBits+=(-1)";
#$sim->{maxRsaBits} = "maxRsaBits+=(-1)";
#$sim->{minEcdsaBits} = "minEcdsaBits+=(-1)";
#$sim->{ellipticCurves} = "curves+=(\"sect233k1:secp256r1:secp384r1:secp521r1\")";
#$sim->{requiresSha2} = "requiresSha2+=(false)";
#
#$sim->{name} = "names+=(\"Mail OSX 10.11.15             \")";
#$sim->{shortname} = "short+=(\"mail_osx_101115\")";
#$sim->{ciphers} = "ch_ciphers+=(\"ECDHE-ECDSA-AES256-SHA384:ECDHE-ECDSA-AES128-SHA256:ECDHE-ECDSA-AES256-SHA:ECDHE-ECDSA-AES128-SHA:ECDHE-ECDSA-DES-CBC3-SHA:ECDHE-RSA-AES256-SHA384:ECDHE-RSA-AES128-SHA256:ECDHE-RSA-AES256-SHA:ECDHE-RSA-AES128-SHA:ECDHE-RSA-DES-CBC3-SHA:DHE-RSA-AES256-SHA256:DHE-RSA-AES128-SHA256:DHE-RSA-AES256-SHA:DHE-RSA-AES128-SHA:EDH-RSA-DES-CBC3-SHA:AES256-SHA256:AES128-SHA256:AES256-SHA:AES128-SHA:DES-CBC3-SHA:ECDHE-ECDSA-RC4-SHA:ECDHE-RSA-RC4-SHA:RC4-SHA:RC4-MD5\")";
#$sim->{ciphersuites} = "ciphersuites+=(\"\")";
#$sim->{sni} = "ch_sni+=(\"\$SNI\")";
#$sim->{warning} = "warning+=(\"\")";
#$sim->{handshakebytes} = "handshakebytes+=(\"16030100940100009003015770e928499e82df2eb7477200e2a828d9fa4109514385bd1602df44aaf2b0f400003200ffc024c023c00ac009c008c028c027c014c013c012006b0067003900330016003d003c0035002f000ac007c011000500040100003500000012001000000d3137382e3233372e33342e3932000a00080006001700180019000b0002010000050005010000000000120000\")";
#$sim->{protos} = "protos+=(\"-tls1\")";
#$sim->{tlsvers} = "tlsvers+=(\"-tls1\")";
#$sim->{lowestProtocol} = "lowest_protocol+=(\"0x0301\")";
#$sim->{highestProtocol} = "highest_protocol+=(\"0x0301\")";
#$sim->{service} = "service+=(\"SMTP,POP,IMAP\")";
#$sim->{minDhBits} = "minDhBits+=(-1)";
#$sim->{maxDhBits} = "maxDhBits+=(-1)";
#$sim->{minRsaBits} = "minRsaBits+=(-1)";
#$sim->{maxRsaBits} = "maxRsaBits+=(-1)";
#$sim->{minEcdsaBits} = "minEcdsaBits+=(-1)";
#$sim->{ellipticCurves} = "curves+=(\"sect233k1:secp256r1:secp384r1:secp521r1\")";
#$sim->{requiresSha2} = "requiresSha2+=(false)";

# example of self generated / provided handshake:
$sim->{name} = "names+=(\"Thunderbird 45.1.1 OSX 10.11  \")";
$sim->{shortname} = "short+=(\"thunderbird_45.1.1_osx_101115\")";
$sim->{ciphers} = "ch_ciphers+=(\"ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-SHA:ECDHE-ECDSA-AES128-SHA:ECDHE-RSA-AES128-SHA:ECDHE-RSA-AES256-SHA:DHE-RSA-AES128-SHA:DHE-RSA-AES256-SHA:AES128-SHA:AES256-SHA:DES-CBC3-SHA\")";
$sim->{ciphersuites} = "ciphersuites+=(\"\")";
$sim->{sni} = "ch_sni+=(\"\$SNI\")";
$sim->{warning} = "warning+=(\"\")";
$sim->{handshakebytes} = "handshakebytes+=(\"160301009d010000990303c7c5b3ff80b3aa597c770c538b98ae34a94c9590ad8f947ba7bc28692061cb57000016c02bc02fc00ac009c013c01400330039002f0035000a0100005a0000001800160000136d78332e73656374696f6e7a65726f2e6f7267ff01000100000a00080006001700180019000b0002010000230000000500050100000000000d001600140401050106010201040305030603020304020202\")";
$sim->{protos} = "protos+=(\"-no_ssl3 -no_ssl2\")";
$sim->{tlsvers} = "tlsvers+=(\"-tls1_2 -tls1_1 -tls1\")";
$sim->{lowestProtocol} = "lowest_protocol+=(\"0x0301\")";
$sim->{highestProtocol} = "highest_protocol+=(\"0x0303\")";
$sim->{service} = "service+=(\"SMTP,POP,IMAP\")";
$sim->{minDhBits} = "minDhBits+=(-1)";
$sim->{maxDhBits} = "maxDhBits+=(-1)";
$sim->{minRsaBits} = "minRsaBits+=(-1)";
$sim->{maxRsaBits} = "maxRsaBits+=(-1)";
$sim->{minEcdsaBits} = "minEcdsaBits+=(-1)";
$sim->{ellipticCurves} = "curves+=(\"sect233k1:secp256r1:secp384r1:secp521r1\")";
$sim->{requiresSha2} = "requiresSha2+=(false)";

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
		# Latest version + ESR releases
		if ( $shortname =~ /ESR/ ) {
			$sims{$shortname}->{current} = "current+=(true)";
		} else {
			$count{firefox}++;
			if ( $count{firefox} <= 1 ) {
				$sims{$shortname}->{current} = "current+=(true)";
			} else {
				$sims{$shortname}->{current} = "current+=(false)";
			}
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
		$count{opera}++;
		if ( $count{opera} <= 1 ) {
			$sims{$shortname}->{current} = "current+=(true)";
		} else {
			$sims{$shortname}->{current} = "current+=(false)";
		}
	} elsif ($shortname =~ /^java 7/) {
		$count{java7}++;
		if ( $count{java7} <= 1 ) {
			$sims{$shortname}->{current} = "current+=(true)";
		} else {
			$sims{$shortname}->{current} = "current+=(false)";
		}
	} elsif ($shortname =~ /^java 8/) {
		$count{java8}++;
		if ( $count{java8} <= 1 ) {
			$sims{$shortname}->{current} = "current+=(true)";
		} else {
			$sims{$shortname}->{current} = "current+=(false)";
		}
	} elsif ($shortname =~ /^java/) {
		# Other/older versions of java aren't current
		$sims{$shortname}->{current} = "current+=(false)";
	} elsif ($shortname =~ /^openssl/) {
		$count{openssl}++;
		if ( $count{openssl} <= 1 ) {
			$sims{$shortname}->{current} = "current+=(true)";
		} else {
			$sims{$shortname}->{current} = "current+=(false)";
		}
	} elsif ($shortname =~ /^safari/) {
		$count{safari}++;
		if ( $count{safari} <= 2 ) {
			$sims{$shortname}->{current} = "current+=(true)";
		} else {
			$sims{$shortname}->{current} = "current+=(false)";
		}
	} else {
		# All versions are current
		$sims{$shortname}->{current} = "current+=(true)";
	}
}


my $header = <<"EOF";
# This file contains client handshake data used in the run_client_simulation() function.
# The file distributed with testssl.sh (etc/client-simulation.txt) has been generated
# from this script and manually edited (=which UA to show up) and sorted.
#
# Most clients are taken from Qualys SSL Labs --- From: https://api.dev.ssllabs.com/api/v3/getClients

EOF

open OUT, ">client-simulation_generated.txt" or die "Unable to open client-simulation_generated.txt";
print OUT "$header";

foreach my $shortname ( sort keys %sims ) {
	foreach my $k ( qw(name shortname ciphers ciphersuites sni warning handshakebytes protos tlsvers lowestProtocol highestProtocol service 
		minDhBits maxDhBits minRsaBits maxRsaBits minEcdsaBits ellipticCurves requiresSha2 current) ) {
		print OUT "     $sims{$shortname}->{$k}\n";
	}
	print OUT "\n";
}
close OUT;

exit;
