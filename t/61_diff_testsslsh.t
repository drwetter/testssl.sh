#!/usr/bin/env perl

# Baseline diff test against testssl.sh (csv output)
#
# We don't use a full run yet and only the certificate section.
# There we would need to blacklist at least:
# cert_serialNumber, cert_fingerprintSHA1, cert_fingerprintSHA256, cert
# cert_expirationStatus, cert_notBefore, cert_notAfter, cert_caIssuers, intermediate_cert
#
# help is appreciated here

use strict;
use Test::More;
use Data::Dumper;
use Text::Diff;

my $tests = 0;
my $prg="./testssl.sh";
my $master_socket_csv="./t/baseline_data/default_testssl.csvfile";
my $socket_csv="tmp.csv";
my $check2run="-p -s -P --fs -h -U -c -q --ip=one --color 0 --csvfile $socket_csv";
#my $check2run="-p --color 0 --csvfile $socket_csv";
my $uri="testssl.sh";
my $diff="";

die "Unable to open $prg" unless -f $prg;
die "Unable to open $master_socket_csv" unless -f $master_socket_csv;


# Provide proper start conditions
unlink "tmp.csv";

# Title
printf "\n%s\n", "Diff unit test IPv4 against \"$uri\"";

#1 run
`$prg $check2run $uri 2>&1`;

$diff = diff $socket_csv, $master_socket_csv;

$socket_csv=`cat tmp.csv`;
$master_socket_csv=`cat $master_socket_csv`;

# Filter for changes that are allowed to occur
$socket_csv=~ s/HTTP_clock_skew.*\n//g;
$master_socket_csv=~ s/HTTP_clock_skew.*\n//g;

# DROWN
$socket_csv=~ s/censys.io.*\n//g;
$master_socket_csv=~ s/censys.io.*\n//g;

# HTTP time
$socket_csv=~ s/HTTP_headerTime.*\n//g;
$master_socket_csv=~ s/HTTP_headerTime.*\n//g;

# Compare the differences to the master file -- and print differences if there were detected.
#
cmp_ok($socket_csv, "eq", $master_socket_csv, "Check whether CSV output matches master file from $uri") or
     diag ("\n%s\n", "$diff");

$tests++;

unlink "tmp.csv";

done_testing($tests);
printf "\n";


#  vim:ts=5:sw=5:expandtab

