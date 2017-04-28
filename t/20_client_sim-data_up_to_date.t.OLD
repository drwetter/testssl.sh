#!/usr/bin/env perl

use strict;
use Test::More tests => 2;


my $outdated=`find etc/client_simulation.txt -mtime +14`;
ok($outdated eq "","etc/client_simulation.txt should be no older then 14 days, run utils/update_client_sim_data.pl to correct");
my $newer=`find utils/update_client_sim_data.pl -newer etc/client_simulation.txt`;
ok($newer eq "","utils/update_client_sim_data.pl should not be newer then etc/client_simulation.txt, run utils/update_client_sim_data.pl to correct");
done_testing;
