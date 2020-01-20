#!/usr/bin/env perl

# Basics: is there a synatx error where already bash hiccups on?
# --banner is equal to --version

use strict;
use Test::More;

my $tests = 0;
my $fileout="";
# Blacklists we use to trigger an error:
my $error_regexp='^(\|)+([0-9])+>\s+[a-z]';

printf "\n%s\n", "Testing whether we forgot \"set -x\" ...";
$fileout = `./testssl.sh --help 2>&1`;
my $retval=$?;

unlike($fileout, qr/$error_regexp/, "just ran help");
$tests++;

$fileout = `./testssl.sh --ssl-native --color=0 --fast --ip=one google.com 2>&1`;
unlike($fileout, qr/$error_regexp/, "ran --ssl-native --color=0 --fast --ip=one google.com");
$tests++;

printf "\n";
done_testing($tests);


