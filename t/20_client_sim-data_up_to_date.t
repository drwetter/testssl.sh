#!/usr/bin/env perl

use strict;
use Test::More tests => 2;


my $outdated=`find include/client_sim.data -mtime 14d`;
ok($outdated eq "","include/client_sim.data should be no older then 14 days, run utils/update_client_sim_data.pl to correct"); 
my $newer=`find utils/update_client_sim_data.pl -newer include/client_sim.data`;
ok($newer eq "","utils/update_client_sim_data.pl should not be newer then include/client_sim.data, run utils/update_client_sim_data.pl to correct");
done_testing;