#!/usr/bin/env perl

# Basics: is there a synatx error where already bash hiccups on?
# --banner is equal to --version

use strict;
use Test::More;

my $tests = 0;
my $fileout="";
# Blacklists we use to trigger an error:
my $error_regexp1='(syntax|parse) (e|E)rror';
my $error_regexp2='testssl.sh: line';
my $error_regexp3='bash: warning';
my $error_regexp4='command not found';
my $error_regexp5='(syntax error|unexpected token)';
my $good_regexp='free software([\s\S]*)USAGE w/o ANY WARRANTY([\s\S]*)OWN RISK([\s\S]*)Using([\s\S]*)ciphers([\s\S]*)built([\s\S]*)platform';

printf "\n%s\n", "Testing whether just calling \"./testssl.sh --banner\" produces no error ...";
$fileout = `timeout 10 bash ./testssl.sh --banner 2>&1`;
my $retval=$?;

unlike($fileout, qr/$error_regexp1/, "regex 1");
$tests++;

unlike($fileout, qr/$error_regexp2/, "regex 2");
$tests++;

unlike($fileout, qr/$error_regexp3/, "regex 3");
$tests++;

unlike($fileout, qr/$error_regexp4/, "regex 4");
$tests++;

unlike($fileout, qr/$error_regexp5/, "regex 5");
$tests++;

like($fileout, qr/$good_regexp/, "regex positive");
$tests++;

is($retval, 0, "return value should be equal zero: \"$retval\"");
$tests++;

printf "\n";
done_testing($tests);


