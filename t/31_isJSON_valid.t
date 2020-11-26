#!/usr/bin/env perl

# This is more a PoC. Improvements welcome!
#

use strict;
use Test::More;
use JSON;

my $tests = 0;
my $prg="./testssl.sh";
my $check2run ="--ip=one -q --color 0";
my $uri="";
my $json="";
my $out="";
# Blacklists we use to trigger an error:
my $socket_regex_bl='(e|E)rror|\.\/testssl\.sh: line |(f|F)atal';
my $openssl_regex_bl='(e|E)rror|(f|F)atal|\.\/testssl\.sh: line |Oops|s_client connect problem';

die "Unable to open $prg" unless -f $prg;

my $uri="cloudflare.com";

printf "\n%s\n", "Unit testing JSON output ...";
unlink 'tmp.json';

#1
printf "%s\n", ".. plain JSON --> $uri ";
$out = `./testssl.sh $check2run --jsonfile tmp.json $uri`;
$json = json('tmp.json');
unlink 'tmp.json';
my @errors=eval { decode_json($json) };
is(@errors,0,"no errors");
$tests++;

#2
printf "%s\n", ".. pretty JSON --> $uri ";
$out = `./testssl.sh $check2run --jsonfile-pretty tmp.json $uri`;
$json = json('tmp.json');
unlink 'tmp.json';
@errors=eval { decode_json($json) };
is(@errors,0,"no errors");
$tests++;


#3
# This testss.sh run deliberately does NOT work as travis-ci.org blocks port 25 egress.
# but the output should be fine. The idea is to have a unit test for a failed connection.
printf "%s\n", ".. plain JSON for a failed run: '--mx $uri' ...";
$out = `./testssl.sh --ssl-native --openssl-timeout=10 $check2run --jsonfile tmp.json --mx $uri`;
$json = json('tmp.json');
unlink 'tmp.json';
@errors=eval { decode_json($json) };
is(@errors,0,"no errors");
$tests++;

#4
# Same as above but with pretty JSON
printf "%s\n", ".. pretty JSON for a failed run '--mx $uri' ...";
$out = `./testssl.sh --ssl-native --openssl-timeout=10 $check2run --jsonfile-pretty tmp.json --mx $uri`;
$json = json('tmp.json');
unlink 'tmp.json';
@errors=eval { decode_json($json) };
is(@errors,0,"no errors");
$tests++;

#5
my $uri = "smtp-relay.gmail.com:587";
printf "%s\n", " .. plain JSON and STARTTLS --> $uri ...";
$out = `./testssl.sh  --jsonfile tmp.json $check2run -t smtp $uri`;
$json = json('tmp.json');
unlink 'tmp.json';
@errors=eval { decode_json($json) };
is(@errors,0,"no errors");
$tests++;

printf "\n";
done_testing($tests);

sub json($) {
    my $file = shift;
    $file = `cat $file`;
    return from_json($file);
}


