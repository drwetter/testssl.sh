#!/usr/bin/env perl

use strict;
use Test::More;

printf "\n%s\n", "Testing whether CA certificates are newer their SPKI hashes \"~/etc/ca_hashes.txt\" ...";

my $newer_bundles=`find etc/*.pem -newer etc/ca_hashes.txt`;
is($newer_bundles,"","If there's an output with a *.pem file run \"~/utils/create_ca_hashes.sh\"");

printf "\n";
done_testing;
