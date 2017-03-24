#!/usr/bin/env perl

use strict;
use Test::More;
use Data::Dumper;
use JSON;

my $tests = 0;

pass("Running openssl based client simulations against mozilla-modern.badssl.com"); $tests++;
my $opensslout = `./testssl.sh -c --ssl-native --jsonfile tmp.json --color 0 mozilla-modern.badssl.com`;
my $openssl = json('tmp.json');
unlike($opensslout, qr/Running client simulations via sockets/, "Tests didn't run via sockets"); $tests++;

pass("Running socket based client simulations against mozilla-modern.badssl.com"); $tests++;
my $socketout = `./testssl.sh -c --jsonfile tmp.json --color 0 mozilla-modern.badssl.com`;
my $socket = json('tmp.json');
like($socketout, qr/Running client simulations via sockets/, "Tests ran via sockets"); $tests++;

my $i = 0;
foreach my $s ( @$socket ) {
	my $o = $$openssl[$i+1];
	if ( $s->{id} =~ /^client_/ ) {
		pass("Comparing $s->{id}"); $tests++;
		cmp_ok($s->{id}, "eq", $o->{id}, "Id's match"); $tests++;
		cmp_ok($s->{severity}, "eq", $o->{severity}, "Severities match"); $tests++;
		cmp_ok($s->{finding}, "eq", $o->{finding}, "Findings match"); $tests++;
	}
	$i++;
}

done_testing($tests);

sub json($) {
	my $file = shift;
	$file = `cat $file`;
	unlink $file;
	return from_json($file);
}
