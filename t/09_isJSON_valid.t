#!/usr/bin/env perl

# This is more a PoC. Improvements welcome!
#
# Current catches:
#     * JSON::Validator cannot swallow --json-pretty 
#     * other validators "Test::JSON", "Test::JSON::More", "JSON::Schema", "JSON::Parse" had issues too

use strict;
use Test::More;
use JSON;
use JSON::Validator;

my $jv = JSON::Validator->new;
my (
    $out,
    $json,
    $found,
    $tests
);
$tests = 0;

my $hostn = "cloudflare.com";
unlink 'tmp.json';

#1
pass("Running testssl.sh against $hostn with plain JSON output");
$tests++;
$out = `./testssl.sh --ssl-native --ip=one -q --jsonfile tmp.json --color 0 $hostn`;
$json = json('tmp.json');
unlink 'tmp.json';

#2
my @errors = $jv->validate(@$json);
is(@errors,0,"no errors");
$tests++;

#3
pass("Running testssl.sh --mx against $hostn with plain JSON");
$tests++;
$out = `./testssl.sh --ssl-native --ip=one --mx -q --jsonfile tmp.json --color 0 $hostn`;
$json = json('tmp.json');
unlink 'tmp.json';

#4
my @errors = $jv->validate(@$json);
is(@errors,0,"no errors");
$tests++;

done_testing($tests);

sub json($) {
    my $file = shift;
    $file = `cat $file`;
    return from_json($file);
}


