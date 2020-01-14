#!/usr/bin/env perl

# Just a functional test, whether ~/etc/client-simulation.txt
# doesn't have any synatx errors

use strict;
use Test::More;

my $tests = 0;
my $fileout="";
# Blacklists we use to trigger an error:
my $error_regexp1='(syntax|parse) (e|E)rror';
my $error_regexp2='client-simulation.txt:';

printf "\n%s\n", "Testing whether \"~/etc/client-simulation.txt\" isn't broken ...";
$fileout = `bash ./etc/client-simulation.txt 2>&1`;
unlike($fileout, qr/$error_regexp1/, "regex 1");
$tests++;

unlike($fileout, qr/$error_regexp2/, "regex 2");
$tests++;

printf "\n";
done_testing($tests);


