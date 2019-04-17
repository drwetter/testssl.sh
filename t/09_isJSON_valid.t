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
my $hostm = "smtp-relay.gmail.com:587";
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
# This testss.sh run deliberately does NOT work as travis-ci.org blocks port 25 egress. The idea
# is to have a unit test for a failed connection. 
pass("Running testssl.sh --mx against $hostn with plain JSON -- run will fail");
$tests++;
$out = `./testssl.sh --ssl-native --openssl-timeout=10 --ip=one --mx -q --jsonfile tmp.json --color 0 $hostn`;
$json = json('tmp.json');
unlink 'tmp.json';

#4
my @errors = $jv->validate(@$json);
is(@errors,0,"no errors");
$tests++;

#5
pass("Running testssl.sh against $hostm with plain JSON output");
$out = `./testssl.sh  --jsonfile tmp.json --color 0  -t smtp  $hostm`;
$tests++;
$json = json('tmp.json');
unlink 'tmp.json';

#6
my @errors = $jv->validate(@$json);
is(@errors,0,"no errors");
$tests++;


done_testing($tests);

sub json($) {
    my $file = shift;
    $file = `cat $file`;
    return from_json($file);
}


