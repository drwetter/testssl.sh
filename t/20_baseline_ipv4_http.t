#!/usr/bin/env perl

# Just a functional test, whether there are any problems on the client side
# Probably we could also inspect the JSON for any problems for
#    "id"           : "scanProblem"
#    "finding"      : "Scan interrupted"

use strict;
use Test::More;
use Data::Dumper;
# use JSON;
# if we need JSON we need to comment this and the lines below in

my $tests = 0;
my $prg="./testssl.sh";
my $check2run ="-p -s -P --pfs -S -h -U -q --ip=one --color 0";
my $uri="";
my $socket_out="";
my $openssl_out="";
# Blacklists we use to trigger an error:
my $socket_regex_bl='(e|E)rror|\.\/testssl\.sh: line |(f|F)atal';
my $openssl_regex_bl='(e|E)rror|(f|F)atal|\.\/testssl\.sh: line |Oops|s_client connect problem';

# my $socket_json="";
# my $openssl_json="";
# $check2run="--jsonfile tmp.json $check2run";

die "Unable to open $prg" unless -f $prg;

$uri="google.com";

# unlink "tmp.json";
printf "\n%s\n", "Baseline unit test IPv4 via sockets --> $uri ...";
$socket_out = `./testssl.sh $check2run $uri 2>&1`;
# $socket_json = json('tmp.json');
unlike($socket_out, qr/$socket_regex_bl/, "");
$tests++;

# unlink "tmp.json";
printf "\n%s\n", "Baseline unit test IPv4 via OpenSSL --> $uri ...";
$openssl_out = `./testssl.sh --ssl-native $check2run $uri 2>&1`;
# $openssl_json = json('tmp.json');
# With Google only we encounter an error as they return a 0 char with openssl, so we white list this pattern here:
$openssl_out =~ s/testssl.*warning: command substitution: ignored null byte in input\n//g;
unlike($openssl_out, qr/$openssl_regex_bl/, "");
$tests++;


done_testing($tests);
unlink "tmp.json";



sub json($) {
	my $file = shift;
	$file = `cat $file`;
	unlink $file;
	return from_json($file);
}

