#!/usr/bin/env perl

use strict;
use Test::More;
use Data::Dumper;
use JSON;

my $out="";
my $json="";
my $json_pretty="";
my $csv="";
my $found="";
my $tests = 0;
my $check2run="--ip=one -s -p -P -e -U --ids-friendly --severity LOW --color 0";
my $linenum=0;
my $prg="./testssl.sh";
#my $uri="badssl.com";
my $uri="google.com";

die "Unable to open $prg" unless -f $prg;

# Provide proper start conditions
unlink 'tmp.json';
unlink 'tmp.csv';

printf "\n%s\n", "Doing severity level checks in JSON formats and CSV against \"$uri\"";

#1 (first run)
printf ".. create JSON+CSV reports with severity level >= LOW (may take ~2 minutes)\n";
$out = `$prg $check2run --jsonfile tmp.json --csvfile tmp.csv $uri`;
$json = json('tmp.json');
$csv = csv('tmp.csv');
$found = 0;
cmp_ok(@$json,'>',0,"At least 1 finding is expected in JSON");
$tests++;

# 2 count lines in CSV
$linenum = $csv =~ tr/\n//;
ok($linenum ge 4, "we should have at least 4 results in CSV: $linenum" );
$tests++;

#3
foreach my $f ( @$json ) {
    if ( $f->{severity} eq "INFO" ) {
        $found = 1;
        last;
    }
}
is($found,0,"We should not have any findings with INFO level in JSON");
unlink 'tmp.json';
$tests++;

#4
unlike($csv, qr/,\"INFO\",/,"We should not have any findings with INFO level in CSV");
unlink 'tmp.csv';
$tests++;


#5 (second run)
# We still do CSV here despite it's thge same as above.
# There was a bug which creates an INFO level output.
printf ".. create a JSON-PRETTY report with severity level >= LOW (may take ~2 minutes)\n";
$out = `$prg $check2run --jsonfile-pretty tmp.json --csvfile tmp.csv $uri`;
$json_pretty = json('tmp.json');
$csv = csv('tmp.csv');
$found = 0;
cmp_ok(@$json,'>',0,"At least 1 finding is expected");
$tests++;

#6 count lines in CSV
$linenum = $csv =~ tr/\n//;
ok($linenum ge 4, "we should have at least 4 results in CSV: $linenum" );
$tests++;

#7
my $vulnerabilities = $json_pretty->{scanResult}->[0]->{vulnerabilities};
foreach my $f ( @$vulnerabilities ) {
    if ( $f->{severity} eq "INFO" ) {
        $found = 1;
        last;
    }
}
is($found,0,"We should not have any findings with INFO level in JSON");
unlink "tmp.json";
$tests++;

#8 failed. See bug above
unlike($csv, qr/,\"INFO\",/,"We should not have any findings with INFO level in CSV");
unlink 'tmp.csv';
$tests++;


done_testing();
# done_testing($tests);
printf "\n";

sub json($) {
    my $file = shift;
    $file = `cat $file`;
    return from_json($file);
}

sub csv($) {
    my $file = shift;
    $file = `cat $file`;
    return ($file);
}
