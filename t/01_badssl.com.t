#!/usr/bin/env perl

use strict;
use Test::More;
use Data::Dumper;
use JSON;

my $tests = 21;

my (
	$out,
	$json,
	$found,
);
# OK
my $okout = `./testssl.sh -S --jsonfile tmp.json --color 0 badssl.com`;
my $okjson = json('tmp.json');
cmp_ok(@$okjson,'>',10,"We have more then 10 findings");

# Expiration
$out = `./testssl.sh -S --jsonfile tmp.json --color 0 expired.badssl.com`;
like($out, qr/Certificate Expiration\s+expired\!/,"The certificate should be expired");
$json = json('tmp.json');
$found = 0;
foreach my $f ( @$json ) {
	if ( $f->{id} eq "expiration" ) {
		$found = 1;
		like($f->{finding},qr/^Certificate Expiration.*expired\!/,"Finding reads expired.");
		is($f->{severity}, "NOT ok", "Severity should be NOT ok");
		last;
    }
}
is($found,1,"We had a finding for this in the JSON output");

# Self signed and not-expired
$out = `./testssl.sh -S --jsonfile tmp.json --color 0 self-signed.badssl.com`;
like($out, qr/Certificate Expiration\s+\d+/,"The certificate should not be expired");
$json = json('tmp.json');
$found = 0;
foreach my $f ( @$json ) {
	if ( $f->{id} eq "expiration" ) {
		$found = 1;
		like($f->{finding},qr/^Certificate Expiration \: \d+/,"Finding doesn't read expired.");
		is($f->{severity}, "OK", "Severity should be ok");
		last;
    }
}
is($found,1,"We had a finding for this in the JSON output");

like($out, qr/Chain of trust.*?NOT ok.*\(self signed\)/,"Chain of trust should fail because of self signed");
$found = 0;
foreach my $f ( @$json ) {
	if ( $f->{id} eq "trust" ) {
		$found = 1;
		like($f->{finding},qr/^All certificate trust checks failed/,"Finding says certificate cannot be trusted.");
		is($f->{severity}, "NOT ok", "Severity should be NOT ok");
		last;
    }
}
is($found,1,"We had a finding for this in the JSON output");

like($okout, qr/Chain of trust[^\n]*?Ok/,"Chain of trust should be ok");
$found = 0;
foreach my $f ( @$okjson ) {
	if ( $f->{id} eq "trust" ) {
		$found = 1;
		is($f->{finding},"All certificate trust checks passed.","Finding says certificate can be trusted.");
		is($f->{severity}, "OK", "Severity should be OK");
		last;
    }
}
is($found,1,"We had a finding for this in the JSON output");

# Wrong host
#$out = `./testssl.sh -S --jsonfile tmp.json --color 0 wrong.host.badssl.com`;
#unlike($out, qr/Certificate Expiration\s+expired\!/,"The certificate should not be expired");
#$json = json('tmp.json');
#$found = 0;
#foreach my $f ( @$json ) {
#	if ( $f->{id} eq "expiration" ) {
#		$found = 1;
#		unlike($f->{finding},qr/^Certificate Expiration.*expired\!/,"Finding should not read expired.");
#		is($f->{severity}, "ok", "Severity should be ok");
#		last;
#    }
#}
#is($found,1,"We had a finding for this in the JSON output");

# Incomplete chain
# Self signed and not-expired

$out = `./testssl.sh -S --jsonfile tmp.json --color 0 incomplete-chain.badssl.com`;
like($out, qr/Chain of trust.*?NOT ok\s+\(chain incomplete\)/,"Chain of trust should fail because of incomplete");
$json = json('tmp.json');
$found = 0;
foreach my $f ( @$json ) {
	if ( $f->{id} eq "trust" ) {
		$found = 1;
		like($f->{finding},qr/^All certificate trust checks failed.*incomplete/,"Finding says certificate cannot be trusted.");
		is($f->{severity}, "NOT ok", "Severity should be NOT ok");
		last;
    }
}
is($found,1,"We had a finding for this in the JSON output");

# TODO: RSA 8192



done_testing($tests);

sub json($) {
	my $file = shift;
	$file = `cat $file`;
	unlink $file;
	return from_json($file);
}