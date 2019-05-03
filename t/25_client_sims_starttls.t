#!/usr/bin/env perl

# Just a functional test, whether there are any problems on the client side
# Probably we could also inspect the JSON for any problems for 
#    "id"           : "scanProblem"
#    "finding"      : "Scan interrupted"

use strict;
use Test::More;
use Data::Dumper;
use JSON;

my $tests = 0;
my $check2run ="--client-simulation -q --ip=one --color 0";

unlink "tmp.json";
printf "\n%s\n", "Running socket based client simulations against google.com ...";
# $tests++;
my $socketout = `./testssl.sh $check2run --jsonfile tmp.json google.com`;
my $socket = json('tmp.json');
#FIXME: This comparison is maybe not sufficient yet:
unlike($socketout, qr/(e|E)rror|(f|F)atal/, "");
$tests++;


unlink "tmp.json";
printf "\n%s\n", "Running OpenSSL based client simulations against google.com ...";
# $tests++;
my $opensslout = `./testssl.sh $check2run --ssl-native --jsonfile tmp.json google.com`;
my $openssl = json('tmp.json');
#FIXME: This comparison is maybe sufficient yet:
unlike($opensslout, qr/(e|E)rror|(f|F)atal|Oops|s_client connect problem/, "");
$tests++;


unlink "tmp.json";
printf "\n%s\n", "STARTTLS: Running socket based client simulations against smtp-relay.gmail.com:587 ...";
# $tests++;
my $socketout = `./testssl.sh $check2run --jsonfile tmp.json -t smtp smtp-relay.gmail.com:587`;
my $socket = json('tmp.json');
unlike($socketout, qr/(e|E)rror|(f|F)atal/, "");
$tests++;


unlink "tmp.json";
printf "\n%s\n", "STARTTLS: Running OpenSSL based client simulations against smtp-relay.gmail.com:587 ...";
# $tests++;
my $opensslout = `./testssl.sh --ssl-native $check2run --jsonfile tmp.json -t smtp smtp-relay.gmail.com:587`;
my $openssl = json('tmp.json');
unlike($opensslout, qr/(e|E)rror|(f|F)atal|Oops|s_client connect problem/, "");
$tests++;

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

