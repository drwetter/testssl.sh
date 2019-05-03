#!/usr/bin/env perl

# Just a functional test, whether there are any problems on the client side
# Probably we could also inspect the JSON for any problems for 
#    "id"           : "scanProblem"
#    "finding"      : "Scan interrupted"

# Catches:
# - This unit test takes very long
# - Hosts which match the regex patterns should be avoided

use strict;
use Test::More;
use Data::Dumper;
use JSON;

my $tests = 0;
my $check2run_smtp="--protocols --standard --pfs --server-preference --headers --vulnerable --each-cipher -q --ip=one --color 0";
my $check2run="-q --ip=one --color 0";
my $uri="";
my $socketout="";
my $opensslout="";

# $check2run_smtp="--jsonfile tmp.json $check2run_smtp";
# $check2run="--jsonfile tmp.json $check2run";

$uri="smtp-relay.gmail.com:587";

# we will have client simulations later, so we don't need to run everything again:
unlink "tmp.json";
printf "\n%s\n", "STARTTLS SMTP unit test via sockets --> $uri ...";
$socketout = `./testssl.sh $check2run_smtp -t smtp $uri`;
# my $socket = json('tmp.json');
unlike($socketout, qr/(e|E)rror|(f|F)atal/, "");
$tests++;

unlink "tmp.json";
printf "\n%s\n", "STARTTLS SMTP unit tests via OpenSSL --> $uri ...";
$opensslout = `./testssl.sh --ssl-native $check2run_smtp -t smtp $uri`;
# my $openssl = json('tmp.json');
unlike($opensslout, qr/(e|E)rror|(f|F)atal|Oops|s_client connect problem/, "");
$tests++;


$uri="pop.gmx.net:110";

unlink "tmp.json";
printf "\n%s\n", "STARTTLS POP3 unit tests via sockets --> $uri ...";
$socketout = `./testssl.sh $check2run -t pop3 $uri`;
# my $socket = json('tmp.json');
unlike($socketout, qr/(e|E)rror|(f|F)atal/, "");
$tests++;

unlink "tmp.json";
printf "\n%s\n", "STARTTLS POP3 unit tests via OpenSSL --> $uri ...";
$opensslout = `./testssl.sh --ssl-native $check2run -t pop3 $uri`;
# my $openssl = json('tmp.json');
unlike($opensslout, qr/(e|E)rror|(f|F)atal|Oops|s_client connect problem/, "");
$tests++;


$uri="imap.gmx.net:143";

unlink "tmp.json";
printf "\n%s\n", "STARTTLS IMAP unit tests via sockets --> $uri ...";
$socketout = `./testssl.sh $check2run -t imap $uri`;
# my $socket = json('tmp.json');
unlike($socketout, qr/(e|E)rror|(f|F)atal/, "");
$tests++;

printf "\n%s\n", "STARTTLS IMAP unit tests via OpenSSL --> $uri ...";
$opensslout = `./testssl.sh --ssl-native $check2run -t imap $uri`;
# my $openssl = json('tmp.json');
unlike($opensslout, qr/(e|E)rror|(f|F)atal|Oops|s_client connect problem/, "");
$tests++;


$uri="jabber.org:5222";

unlink "tmp.json";
printf "\n%s\n", "STARTTLS XMPP unit tests via sockets --> $uri ...";
$socketout = `./testssl.sh $check2run -t xmpp $uri`;
# my $socket = json('tmp.json');
unlike($socketout, qr/(e|E)rror|(f|F)atal/, "");
$tests++;

printf "\n%s\n", "STARTTLS XMPP unit tests via OpenSSL --> $uri ...";
$opensslout = `./testssl.sh --ssl-native $check2run -t xmpp $uri`;
# my $openssl = json('tmp.json');
unlike($opensslout, qr/(e|E)rror|(f|F)atal|Oops|s_client connect problem/, "");
$tests++;


$uri="ldap.uni-rostock.de:21";

unlink "tmp.json";
printf "\n%s\n", "STARTTLS FTP unit tests via sockets --> $uri ...";
$socketout = `./testssl.sh $check2run -t ftp $uri`;
# my $socket = json('tmp.json');
# OCSP stapling fails sometimes with: 'offered, error querying OCSP responder (ERROR: No Status found)'
$socketout =~ s/ error querying OCSP responder .*\n//g;
unlike($socketout, qr/(e|E)rror|(f|F)atal/, "");
$tests++;

printf "\n%s\n", "STARTTLS FTP unit tests via OpenSSL --> $uri ...";
$opensslout = `./testssl.sh --ssl-native $check2run -t ftp $uri`;
# my $openssl = json('tmp.json');
# OCSP stapling fails sometimes with: 'offered, error querying OCSP responder (ERROR: No Status found)'
$opensslout =~ s/ error querying OCSP responder .*\n//g;
unlike($opensslout, qr/(e|E)rror|(f|F)atal|Oops|s_client connect problem/, "");
$tests++;


# https://ldapwiki.com/wiki/Public%20LDAP%20Servers
$uri="ldap.telesec.de:389";

printf "\n%s\n", "STARTTLS LDAP unit tests via OpenSSL --> $uri ...";
$opensslout = `./testssl.sh --ssl-native $check2run -t ldap $uri`;
# my $openssl = json('tmp.json');
unlike($opensslout, qr/(e|E)rror|(f|F)atal|Oops|s_client connect problem/, "");
$tests++;


$uri="news.newsguy.com:119";

unlink "tmp.json";
printf "\n%s\n", "STARTTLS NNTP unit tests via sockets --> $uri ...";
$socketout = `./testssl.sh $check2run -t nntp $uri`;
# my $socket = json('tmp.json');
unlike($socketout, qr/(e|E)rror|(f|F)atal/, "");
$tests++;

printf "\n%s\n", "STARTTLS NNTP unit tests via OpenSSL --> $uri ...";
$opensslout = `./testssl.sh --ssl-native $check2run -t nntp $uri`;
# my $openssl = json('tmp.json');
unlike($opensslout, qr/(e|E)rror|(f|F)atal|Oops|s_client connect problem/, "");
$tests++;


# IRC: missing
# LTMP, mysql, postgres



done_testing($tests);
unlink "tmp.json";

sub json($) {
	my $file = shift;
	$file = `cat $file`;
	unlink $file;
	return from_json($file);
}

