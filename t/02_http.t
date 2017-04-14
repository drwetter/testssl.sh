#!/usr/bin/env perl

use strict;
use Test::More;
use Data::Dumper;

my $tests = 0;

pass("Running testssl.sh against badssl.com to create HTML and terminal outputs (may take 2~3 minutes)"); $tests++;
# specify a TERM_WIDTH so that the two calls to testssl.sh don't create HTML files with different values of TERM_WIDTH
my $okout = `TERM_WIDTH=80 ./testssl.sh --color 0 --quiet --append --htmlfile tmp.html badssl.com`;
my $okhtml = `cat tmp.html`;
# $modedhtml will contain the HTML with formatting information removed in order to compare against terminal output
my $modedhtml = `cat tmp.html`;
unlink 'tmp.html';

# Remove any hypertext links for URLs
$modedhtml =~ s/<a href=[0-9A-Za-z ";:=\/\.\?\-]*>//g;
$modedhtml =~ s/<\/a>//g;

# Replace escaped characters with their original text
$modedhtml =~ s/&amp;/&/g;
$modedhtml =~ s/&lt;/</g;
$modedhtml =~ s/&gt;/>/g;
$modedhtml =~ s/&quot;/"/g;
$modedhtml =~ s/&apos;/'/g;

pass("Comparing HTML and terminal outputs"); $tests++;
cmp_ok($modedhtml, "eq", $okout, "HTML file matches terminal output"); $tests++;

pass("Running testssl.sh against badssl.com with --debug 4 to create HTML output (may take 2~3 minutes)"); $tests++;
# Redirect stderr to /dev/null in order to avoid some unexplained "date: invalid date" error messages
my $debugout = `TERM_WIDTH=80 ./testssl.sh --color 0 --quiet --append --debug 4 --htmlfile tmp.html badssl.com 2> /dev/null`;
my $debughtml = `cat tmp.html`;
unlink 'tmp.html';

# Remove date information from the Start and Done banners in the two HTML files, since they were created at different times
$okhtml =~ s/Start 2[0-9][0-9][0-9]-[0-3][0-9]-[0-3][0-9] [0-2][0-9]:[0-5][0-9]:[0-5][0-9]//;
$debughtml =~ s/Start 2[0-9][0-9][0-9]-[0-3][0-9]-[0-3][0-9] [0-2][0-9]:[0-5][0-9]:[0-5][0-9]//;

$okhtml =~ s/Done 2[0-9][0-9][0-9]-[0-3][0-9]-[0-3][0-9] [0-2][0-9]:[0-5][0-9]:[0-5][0-9] \[  [0-9]*s\]//;
$debughtml =~ s/Done 2[0-9][0-9][0-9]-[0-3][0-9]-[0-3][0-9] [0-2][0-9]:[0-5][0-9]:[0-5][0-9] \[  [0-9]*s\]//;

# Remove time difference from "HTTP clock skew" line
$okhtml =~ s/HTTP clock skew              +?-?[0-9]* //;
$debughtml =~ s/HTTP clock skew              +?-?[0-9]* //;

pass("Checking that using the --debug option doesn't affect the HTML file"); $tests++;
cmp_ok($debughtml, "eq", $okhtml, "HTML file created with --debug 4 matches HTML file created without --debug"); $tests++;

done_testing($tests);
