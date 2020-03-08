#!/usr/bin/env perl

use strict;
use Test::More;

my $tests = 0;
my $prg="./testssl.sh";
my $check2run ="--ip=one --debug=1 -q --color 0";
my $uri="dev.testssl.sh";
my $out="";
# Blacklists we use to trigger an error:
my $socket_regex_error1='length of byte .* called from .* is not ok';
my $socket_regex_error2='char .* called from .* doesn\'t start with a ';
my $socket_regex_error3='char .* called from .* doesn\'t have an x in second position';
my $socket_regex_error4='byte .* called from .* is not hex';

die "Unable to open $prg" unless -f $prg;

printf "\n%s\n", "Unit test to verify socket byte stream is properly formatted --> $uri ...";

$out = `$prg $check2run $uri 2>&1`;
unlike($out, qr/$socket_regex_error1/, "check: \"$socket_regex_error1\"");
$tests++;
unlike($out, qr/$socket_regex_error2/, "check: \"$socket_regex_error2\"");
$tests++;
unlike($out, qr/$socket_regex_error3/, "check: \"$socket_regex_error3\"");
$tests++;
unlike($out, qr/$socket_regex_error4/, "check: \"$socket_regex_error4\"");
$tests++;

printf "\n";
done_testing($tests);


