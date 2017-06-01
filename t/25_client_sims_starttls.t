#!/usr/bin/env perl

use strict;
use Test::More;
use Data::Dumper;
use JSON;

my $tests = 0;

unlink "tmp.json";
pass("Running openssl based client simulations against smtp-relay.gmail.com:587"); $tests++;
my $opensslout = `./testssl.sh --client-simulation --ssl-native -t smtp --jsonfile tmp.json --color 0 smtp-relay.gmail.com:587`;
my $openssl = json('tmp.json');
unlike($opensslout, qr/Running client simulations via sockets/, "Tests didn't run via sockets"); $tests++;

pass("Running socket based client simulations against smtp-relay.gmail.com:587"); $tests++;
unlink "tmp.json";
my $socketout = `./testssl.sh --client-simulation -t smtp --jsonfile tmp.json --color 0 smtp-relay.gmail.com:587`;
my $socket = json('tmp.json');
like($socketout, qr/Running client simulations via sockets/, "Tests ran via sockets"); $tests++;


#my $i = 0;
#foreach my $o ( @$openssl ) {
#	my $s = $$socket[$i];
#	if ( $o->{id} =~ /^client_/ ) {
#		pass("Comparing $o->{id}"); $tests++;
#		cmp_ok($o->{id}, "eq", $s->{id}, "Id's match"); $tests++;
#		cmp_ok($o->{severity}, "eq", $s->{severity}, "Severities match"); $tests++;
#		cmp_ok($o->{finding}, "eq", $s->{finding}, "Findings match"); $tests++;
#	}
#	$i++;
#}

done_testing($tests);
unlink "tmp.json";

sub json($) {
	my $file = shift;
	$file = `cat $file`;
	unlink $file;
	return from_json($file);
}

# problem: 1-4 ok but of limited use: wy should we test whether runs really via sockets or openssl??
# 5-n:     no sense, we know sockets and ssl are diffferent why should we have a unit test comparing those???
