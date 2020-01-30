#!/usr/bin/env perl

use strict;
use Test::More;
use JSON;

my $tests = 0;
my $prg="./testssl.sh";
my $check2run ="--ip=one -q --color 0";
my $filechecks = "--jsonfile-pretty tmp.json --csvfile tmp.csv";
my $uri="cloudflare.com";
my $json="";
my $csv="";
my $out="";		# not in use currently
# Blacklists we use to trigger an error:
my $socket_regex_bl='(e|E)rror|\.\/testssl\.sh: line |(f|F)atal';
my $openssl_regex_bl='(e|E)rror|(f|F)atal|\.\/testssl\.sh: line |Oops|s_client connect problem';

die "Unable to open $prg" unless -f $prg;

# Provide proper start conditions
unlink 'tmp.json';
unlink 'tmp.csv';

printf "\n%s\n", "Unit testing JSON and CSV output ...";

#1
printf "%s\n", ".. CSV and plain JSON --> $uri ";
$out = `$prg $check2run $filechecks $uri`;
$json = json('tmp.json');
$csv = csv('tmp.csv');
unlink 'tmp.json';
unlink 'tmp.csv';
my @errors=eval { decode_json($json) };
is(@errors,0,"no errors");
$tests++;

#2
# check header ~ "id","fqdn/ip","port","severity","finding","cve","cwe"
#              macth or count: "cipherorder", ~ cert_ ~cert\ , HTTP, HSTS , cipher_, clientsimulation

# later: not FATAL


#2
printf "%s\n", ".. pretty JSON --> $uri ";
$out = `$prg $check2run $filechecks $uri`;
$json = json('tmp.json');
unlink 'tmp.json';
unlink 'tmp.csv';
@errors=eval { decode_json($json) };
is(@errors,0,"no errors");
$tests++;


#3
# This testss.sh run deliberately does NOT work as travis-ci.org blocks port 25 egress.
# but the output should be fine. The idea is to have a unit test for a failed connection.
printf "%s\n", ".. plain JSON for a failed run: '--mx $uri' (deliberate messy output follows)";
$out = `$prg --ssl-native --openssl-timeout=10 $check2run $filechecks --mx $uri`;
$json = json('tmp.json');
$csv = csv('tmp.csv');
unlink 'tmp.json';
unlink 'tmp.csv';
printf "$csv\n";
@errors=eval { decode_json($json) };
is(@errors,0,"no errors");
$tests++;

# check both for FATAL / Can't connect / scanProblem

#4
# Same as #3 with pretty JSON
printf "%s\n", ".. pretty JSON for a failed run '--mx $uri' (deliberate messy output follows)";
$out = `$prg --ssl-native --openssl-timeout=10 $check2run --jsonfile-pretty tmp.json --csvfile tmp.csv --mx $uri`;
$json = json('tmp.json');
unlink 'tmp.json';
unlink 'tmp.csv';
@errors=eval { decode_json($json) };
is(@errors,0,"no errors");
$tests++;

# check both for FATAL / Can't connect / scanProblem

#5
my $uri = "smtp-relay.gmail.com:587";
printf "%s\n", " .. plain JSON and STARTTLS --> $uri ...";
$out = `$prg  $filechecks $check2run -t smtp $uri`;
$json = json('tmp.json');
$csv = csv('tmp.csv');
unlink 'tmp.json';
unlink 'tmp.csv';
@errors=eval { decode_json($json) };
is(@errors,0,"no errors");
$tests++;

done_testing($tests);
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
