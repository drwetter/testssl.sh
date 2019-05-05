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
my $uri="";
my $socketout="";
my $opensslout="";

# $check2run="--jsonfile tmp.json $check2run";


$uri="google.com";

unlink "tmp.json";
printf "\n%s\n", "Client simulations unit test via sockets --> $uri ...";
$socketout = `./testssl.sh $check2run $uri`;
# my $socket = json('tmp.json');
#FIXME: This comparison is maybe not sufficient yet:
unlike($socketout, qr/(e|E)rror|(f|F)atal/, "");
$tests++;


unlink "tmp.json";
printf "\n%s\n", "Client simulations unit test via OpenSSL --> $uri ...";
$opensslout = `./testssl.sh $check2run --ssl-native $uri`;
# my $openssl = json('tmp.json');
#FIXME: This comparison is maybe sufficient yet:
unlike($opensslout, qr/(e|E)rror|(f|F)atal|Oops|s_client connect problem/, "");
$tests++;


$uri="smtp-relay.gmail.com:587";

unlink "tmp.json";
printf "\n%s\n", "STARTTLS: Client simulations unit test via sockets --> $uri ...";
$socketout = `./testssl.sh $check2run -t smtp $uri`;
# my $socket = json('tmp.json');
unlike($socketout, qr/(e|E)rror|(f|F)atal/, "");
$tests++;

unlink "tmp.json";
printf "\n%s\n", "STARTTLS: Client simulations unit test via OpenSSL --> $uri ...";
$opensslout = `./testssl.sh --ssl-native $check2run -t smtp $uri`;
# my $openssl = json('tmp.json');
unlike($opensslout, qr/(e|E)rror|(f|F)atal|Oops|s_client connect problem/, "");
$tests++;

done_testing($tests);
unlink "tmp.json";



sub json($) {
	my $file = shift;
	$file = `cat $file`;
	unlink $file;
	return from_json($file);
}

