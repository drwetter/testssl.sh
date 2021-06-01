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

my $prg="./testssl.sh";
my $check2run = '-S -e --ids-friendly -U --severity LOW --color 0';
my $uri = 'badssl.com';

printf "\n%s\n", "Doing severity level checks";

die "Unable to open $prg" unless -f $prg;
unlink 'tmp.json';

#1
pass(" .. running testssl.sh against $uri to create a JSON report with severity level >= LOW (may take 2~3 minutes)"); $tests++;
$out = `$prg $check2run --jsonfile tmp.json $uri`;
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
pass(" .. running testssl.sh against $uri to create a JSON-PRETTY report with severity level >= LOW (may take 2~3 minutes)"); $tests++;
$out = `$prg $check2run --jsonfile-pretty tmp.json $uri`;
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

printf "\n";
done_testing($tests);

sub json($) {
    my $file = shift;
    $file = `cat $file`;
    unlink $file;
    return from_json($file);
}


#  vim:ts=5:sw=5:expandtab

