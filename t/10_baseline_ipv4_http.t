#!/usr/bin/env perl

# baseline test for testssl, screen and JSON output

# This is referred by the documentation.

# We could also inspect the JSON for any problems for
#    "id"           : "scanProblem"
#    "finding"      : "Scan interrupted"

use strict;
use Test::More;
use Data::Dumper;
use JSON;

my $tests = 0;
my $prg="./testssl.sh";
my $check2run="-p -s -P --fs -S -h -U -q --ip=one --color 0";
my $uri="google.com";
my $socket_out="";
my $openssl_out="";
# Blacklists we use to trigger an error:
my $socket_regex_bl='(e|E)rror|\.\/testssl\.sh: line |(f|F)atal';
my $openssl_regex_bl='(e|E)rror|(f|F)atal|\.\/testssl\.sh: line |Oops|s_client connect problem';
my $json_regex_bl='(id".*:\s"scanProblem"|severity".*:\s"FATAL"|"Scan interrupted")';

my $socket_json="";
my $openssl_json="";
$check2run="--jsonfile tmp.json $check2run";

die "Unable to open $prg" unless -f $prg;

# Provide proper start conditions
unlink "tmp.json";

# Title
printf "\n%s\n", "Baseline unit test IPv4 against \"$uri\"";

#1
$socket_out = `$prg $check2run $uri 2>&1`;
$socket_json = json('tmp.json');
unlink "tmp.json";
unlike($socket_out, qr/$socket_regex_bl/, "via sockets, terminal output");
$tests++;
unlike($socket_json, qr/$json_regex_bl/, "via sockets JSON output");
$tests++;

#2
$openssl_out = `$prg --ssl-native $check2run $uri 2>&1`;
$openssl_json = json('tmp.json');
unlink "tmp.json";
# With Google only we somtimes encounter an error as they return a 0 char with openssl, so we white list this pattern here:
# It should be fixed in the code though so we comment this out
# $openssl_out =~ s/testssl.*warning: command substitution: ignored null byte in input\n//g;
unlike($openssl_out, qr/$openssl_regex_bl/, "via OpenSSL");
$tests++;
unlike($openssl_json, qr/$json_regex_bl/, "via OpenSSL JSON output");
$tests++;

done_testing($tests);
printf "\n";


sub json($) {
	my $file = shift;
	$file = `cat $file`;
	unlink $file;
	return from_json($file);
}

