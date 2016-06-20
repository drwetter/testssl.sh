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
	$ciphers{"0x$hex"} = $fields[3];
}
#die Dumper \%ciphers;
#exit;

my @ciphers = ();
while (<>) {
	if ( /^\s*Cipher Suite\:/ ) {
		/\((0x[0-9a-f]+)\)\s*$/;
		my $n = $1;
		$n =~ s/0x0*/0x/;
		if ( $n && exists $ciphers{$n} ) {
			push @ciphers, $ciphers{$n};
		} else {
			print STDERR "No matching cipher for: $n on line\n$_"
		}
	} else {
		print STDERR "Ignoring line $_"
	}
}

print "\n\n" . join ":", @ciphers;
print "\n";