#!/usr/bin/env perl

# Checking whether the HTML output is somehow valid
# This could be amended by using HTML::Tidy or HTML::Valid

use strict;
use Test::More;
use Data::Dumper;

my $tests = 0;
my $prg="./testssl.sh";
my $uri="heise.de";
my $out="";
my $html="";
my $debughtml="";
my $edited_html="";
my $check2run="--ip=one --color 0 --htmlfile tmp.html";

die "Unable to open $prg" unless -f $prg;

printf "\n%s\n", "Doing HTML output checks";
unlink 'tmp.html';

#1
printf "%s\n", " .. running $prg against \"$uri\" to create HTML and terminal outputs (may take ~2 minutes)";
# specify a TERM_WIDTH so that the two calls to testssl.sh don't create HTML files with different values of TERM_WIDTH
$out = `TERM_WIDTH=120 $prg $check2run $uri`;
$html = `cat tmp.html`;
# $edited_html will contain the HTML with formatting information removed in order to compare against terminal output
# Start by removing the HTML header.
$edited_html = `tail -n +11 tmp.html`;
unlink 'tmp.html';

# Remove the HTML footer
$edited_html =~ s/\n\<\/pre\>\n\<\/body\>\n\<\/html\>//;
# Remove any hypertext links for URLs
$edited_html =~ s/<a href=[0-9A-Za-z ";:=\/\.\?\-]*>//g;
$edited_html =~ s/<\/a>//g;

# Replace escaped characters with their original text
$edited_html =~ s/&amp;/&/g;
$edited_html =~ s/&lt;/</g;
$edited_html =~ s/&gt;/>/g;
$edited_html =~ s/&quot;/"/g;
$edited_html =~ s/&apos;/'/g;

cmp_ok($edited_html, "eq", $out, "HTML file matches terminal output");
$tests++;

#2
printf "\n%s\n", " .. running again $prg against \"$uri\", now with --debug 4 to create HTML output (may take another ~2 minutes)";
# Redirect stderr to /dev/null in order to avoid some unexplained "date: invalid date" error messages
$out = `TERM_WIDTH=120 $prg $check2run --debug 4 $uri 2> /dev/null`;
$debughtml = `cat tmp.html`;
unlink 'tmp.html';

# Remove date information from the Start and Done banners in the two HTML files, since they were created at different times
$html =~ s/Start 2[0-9][0-9][0-9]-[0-3][0-9]-[0-3][0-9] [0-2][0-9]:[0-5][0-9]:[0-5][0-9]/Start XXXX-XX-XX XX:XX:XX/;
$debughtml =~ s/Start 2[0-9][0-9][0-9]-[0-3][0-9]-[0-3][0-9] [0-2][0-9]:[0-5][0-9]:[0-5][0-9]/Start XXXX-XX-XX XX:XX:XX/;

$html =~ s/Done 2[0-9][0-9][0-9]-[0-3][0-9]-[0-3][0-9] [0-2][0-9]:[0-5][0-9]:[0-5][0-9] \[ *[0-9]*s\]/Done XXXX-XX-XX XX:XX:XX [   Xs]/;
$debughtml =~ s/Done 2[0-9][0-9][0-9]-[0-3][0-9]-[0-3][0-9] [0-2][0-9]:[0-5][0-9]:[0-5][0-9] \[ *[0-9]*s\]/Done XXXX-XX-XX XX:XX:XX [   Xs]/;

# Remove time difference from "HTTP clock skew" line
$html =~ s/HTTP clock skew              \+?-?[0-9]* /HTTP clock skew              X /;
$debughtml =~ s/HTTP clock skew              \+?-?[0-9]* /HTTP clock skew              X /;

$debughtml =~ s/ Pre-test: .*\n//g;
$debughtml =~ s/.*OK: below 825 days.*\n//g;
$debughtml =~ s/.*DEBUG:.*\n//g;

cmp_ok($debughtml, "eq", $html, "HTML file created with --debug 4 matches HTML file created without --debug");
$tests++;

printf "\n";
done_testing($tests);
