#!/usr/bin/perl

use strict;
use Data::Dumper;

my @spec;
my %ciphers;

# Turn cipher section of page like this https://www.ssllabs.com/ssltest/viewClient.html?name=Android&version=4.0.4
# into an openssl cipher spec

foreach my $line ( split /\n/, `../bin/openssl.Linux.x86_64 ciphers -V 'ALL:COMPLEMENTOFALL:\@STRENGTH'`) {
	my @fields = split /\s+/, $line;
	my $hex = "";
	foreach my $byte ( split /,/, $fields[1] ) {
		$byte = lc $byte;
		$byte =~ s/^0x//;
		$hex .= $byte;
	}
	$hex =~ s/^0+//;
	$ciphers{"0x$hex"} = $fields[3];
}

while (<>) {
	chomp;
	if ( $_ =~ /^(TLS|SSL)/ ) {
		if ( $_ !~ /^TLS_EMPTY_RENEGOTIATION_INFO_SCSV/ ) {
			$_ =~ /(0x[0-9a-f]+)/;
			if ( $1 ) {
				push @spec, $ciphers{$1};
				unless ( $ciphers{$1} ) {
					die "Unable to find cipher for $1";
				}
			} else {
				print "** $_\n";
			}
		}
	}
}
print join ":", @spec;
print "\n";
my $count = @spec;
print "$count ciphers\n";
