#!/usr/bin/env perl

use strict;
use Test::More;
use Data::Dumper;
use JSON;

my (
    $out,
    $json,
    $json_pretty,
    $found,
    $tests
);

$tests = 0;

#1
pass("Running testssl.sh against badssl.com to create a JSON report with severity level equal greater than LOW (may take 2~3 minutes)"); $tests++;
$out = `./testssl.sh -S -e -U --jsonfile tmp.json --severity LOW --color 0 badssl.com`;
$json = json('tmp.json');
unlink 'tmp.json';
$found = 0;
cmp_ok(@$json,'>',0,"At least 1 finding is expected"); $tests++;
foreach my $f ( @$json ) {
    if ( $f->{severity} eq "INFO" ) {
        $found = 1;
        last;
    }
}
is($found,0,"We should not have any finding with INFO level"); $tests++;

#2
pass("Running testssl.sh against badssl.com to create a JSON-PRETTY report with severity level equal greater than LOW (may take 2~3 minutes)"); $tests++;
$out = `./testssl.sh -S -e -U --jsonfile-pretty tmp.json --severity LOW --color 0 badssl.com`;
$json_pretty = json('tmp.json');
unlink 'tmp.json';
$found = 0;
my $vulnerabilities = $json_pretty->{scanResult}->[0]->{vulnerabilities};
foreach my $f ( @$vulnerabilities ) {
    if ( $f->{severity} eq "INFO" ) {
        $found = 1;
        last;
    }
}
is($found,0,"We should not have any finding with INFO level"); $tests++;

done_testing($tests);

sub json($) {
    my $file = shift;
    $file = `cat $file`;
    unlink $file;
    return from_json($file);
}
