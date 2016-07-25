#!/usr/bin/env perl

use strict;
use Test::More;
use Data::Dumper;
use JSON;

my $tests = 0;

pass("This test was intentionally left blank"); $tests++;
#pass("Running openssl based client simulations against testssl.sh"); $tests++;
#my $opensslout = `./testssl.sh -c --ssl-native --jsonfile tmp.json --color 0 testssl.sh`;
#my $openssl = json('tmp.json');
#unlike($opensslout, qr/Running browser simulations via sockets/, "Tests didn't run via sockets"); $tests++;

#pass("Running socket based client simulations against testssl.sh"); $tests++;
#my $socketout = `./testssl.sh -c --jsonfile tmp.json --color 0 testssl.sh`;
#my $socket = json('tmp.json');
#like($socketout, qr/Running browser simulations via sockets/, "Tests ran via sockets"); $tests++;


#my $i = 0;
#foreach my $o ( @$openssl ) {
#	my $s = $$socket[$i];
#	if ( $o->{id} =~ /^client_/ ) {
#		pass("Comparing $o->{id}"); $tests++;
#		cmp_ok($o->{id}, "eq", $s->{id}, "Id's match"); $tests++;
#		cmp_ok($o->{severity}, "eq", $s->{severity}, "Severities match"); $tests++;
#		if ( $o->{finding} eq $s->{finding} ) {
#			pass("Findings match"); $tests++;
#		} elsif ( 
#			# TODO: The no connection thing is weird, need to look at it, but not now
#			$o->{finding}=~/(TLSv1\.[012] EC|No Connection)/ && 
#			$s->{finding}=~/TLSv1\.[012] (DH|RSA|AES)/ && 
#			$o->{id} =~/^client_(chrome_[456789]|ie_[891]|edge_1|yahoo|android_[6789])/ 
#			) {
#			pass("Findings differ, most likely due to curve differences.\nSockets: $s->{finding}\nOpenSSL: $o->{finding}"); $tests++
#		} else {
#			cmp_ok($o->{finding}, "eq", $s->{finding}, "Findings match"); $tests++;		
#		}
#	}
#	$i++;
#}

done_testing($tests);

sub json($) {
	my $file = shift;
	$file = `cat $file`;
	unlink $file;
	return from_json($file);
}