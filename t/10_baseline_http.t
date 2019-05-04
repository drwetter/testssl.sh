#!/usr/bin/env perl

# Just a functional test, whether there are any problems on the client side
# Probably we could also inspect the JSON for any problems for
#    "id"           : "scanProblem"
#    "finding"      : "Scan interrupted"

use strict;
use Test::More;
use Data::Dumper;
# use JSON;

my $tests = 0;
my $check2run ="-p -s -P --pfs -S -h -U -q --ip=one --color 0";
my $uri="";
my $socketout="";
my $opensslout="";

# $check2run="--jsonfile tmp.json $check2run";


$uri="google.com";

unlink "tmp.json";
printf "\n%s\n", "Baseline unit test IPv4 via sockets --> $uri ...";
$socketout = `./testssl.sh $check2run $uri 2>&1`;
# my $socket = json('tmp.json');
#FIXME: This comparison is maybe not sufficient yet:
unlike($socketout, qr/(e|E)rror|\.\/testssl\.sh: line |(f|F)atal/, "");
$tests++;


unlink "tmp.json";
printf "\n%s\n", "Baseline unit test IPv4 via OpenSSL --> $uri ...";
$opensslout = `./testssl.sh $check2run --ssl-native $uri 2>&1`;
# my $openssl = json('tmp.json');
# This happens with Google only, so we white list a pattern here:
$opensslout =~ s/testssl.*warning: command substitution: ignored null byte in input\n//g;
#FIXME: This comparison is maybe sufficient yet:
unlike($opensslout, qr/(e|E)rror|(f|F)atal|\.\/testssl\.sh: line |Oops|s_client connect problem/, "");
$tests++;


$uri="ipv6.google.com";

unlink "tmp.json";
printf "\n%s\n", "Baseline unit test IPv6 via sockets --> $uri ...";
$socketout = `./testssl.sh $check2run -6 $uri 2>&1`;
# my $socket = json('tmp.json');
unlike($socketout, qr/(e|E)rror|\.\/testssl\.sh: line |(f|F)atal/, "");
$tests++;

unlink "tmp.json";
printf "\n%s\n", "Baseline unit test IPv6 via OpenSSL --> $uri ...";
$opensslout = `./testssl.sh --ssl-native $check2run -6 $uri 2>&1`;
# my $openssl = json('tmp.json');
$opensslout =~ s/testssl.*warning: command substitution: ignored null byte in input\n//g;
unlike($opensslout, qr/(e|E)rror|(f|F)atal|\.\/testssl\.sh: line |Oops|s_client connect problem/, "");
$tests++;

done_testing($tests);
unlink "tmp.json";



sub json($) {
	my $file = shift;
	$file = `cat $file`;
	unlink $file;
	return from_json($file);
}

