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
# use JSON;
# if we need JSON we need to comment this and the lines below in

my $tests = 0;
my $prg="./testssl.sh";
my $check2run_smtp="--protocols --standard --fs --server-preference --headers --vulnerable --each-cipher -q --ip=one --color 0";
my $check2run="-q --ip=one --color 0";
my $uri="";
my $socket_out="";
my $openssl_out="";
# Blacklists we use to trigger an error:
my $socket_regex_bl='(e|E)rror|\.\/testssl\.sh: line |(f|F)atal';
my $openssl_regex_bl='(e|E)rror|(f|F)atal|\.\/testssl\.sh: line |Oops|s_client connect problem';

# my $socket_json="";
# my $openssl_json="";
# $check2run_smtp="--jsonfile tmp.json $check2run_smtp";
# $check2run="--jsonfile tmp.json $check2run";

die "Unable to open $prg" unless -f $prg;

$uri="smtp-relay.gmail.com:587";

# we will have client simulations later, so we don't need to run everything again:
# unlink "tmp.json";
printf "\n%s\n", "STARTTLS SMTP unit test via sockets --> $uri ...";
$socket_out = `./testssl.sh $check2run_smtp -t smtp $uri 2>&1`;
# $socket_json = json('tmp.json');
unlike($socket_out, qr/$socket_regex_bl/, "");
$tests++;

# unlink "tmp.json";
printf "\n%s\n", "STARTTLS SMTP unit tests via OpenSSL --> $uri ...";
$openssl_out = `./testssl.sh --ssl-native $check2run_smtp -t smtp $uri 2>&1`;
# $openssl_json = json('tmp.json');
unlike($openssl_out, qr/$openssl_regex_bl/, "");
$tests++;


$uri="pop.gmx.net:110";

# unlink "tmp.json";
printf "\n%s\n", "STARTTLS POP3 unit tests via sockets --> $uri ...";
$socket_out = `./testssl.sh $check2run -t pop3 $uri 2>&1`;
# $socket_json = json('tmp.json');
unlike($socket_out, qr/$socket_regex_bl/, "");
$tests++;

# unlink "tmp.json";
printf "\n%s\n", "STARTTLS POP3 unit tests via OpenSSL --> $uri ...";
$openssl_out = `./testssl.sh --ssl-native $check2run -t pop3 $uri 2>&1`;
# $openssl_json = json('tmp.json');
unlike($openssl_out, qr/$openssl_regex_bl/, "");
$tests++;


$uri="imap.gmx.net:143";

# unlink "tmp.json";
printf "\n%s\n", "STARTTLS IMAP unit tests via sockets --> $uri ...";
$socket_out = `./testssl.sh $check2run -t imap $uri 2>&1`;
# $socket_json = json('tmp.json');
unlike($socket_out, qr/$socket_regex_bl/, "");
$tests++;

printf "\n%s\n", "STARTTLS IMAP unit tests via OpenSSL --> $uri ...";
$openssl_out = `./testssl.sh --ssl-native $check2run -t imap $uri 2>&1`;
# $openssl_json = json('tmp.json');
unlike($openssl_out, qr/$openssl_regex_bl/, "");
$tests++;


$uri="jabber.org:5222";

# unlink "tmp.json";
printf "\n%s\n", "STARTTLS XMPP unit tests via sockets --> $uri ...";
$socket_out = `./testssl.sh $check2run -t xmpp $uri 2>&1`;
# $socket_json = json('tmp.json');
unlike($openssl_out, qr/$openssl_regex_bl/, "");
$tests++;

printf "\n%s\n", "STARTTLS XMPP unit tests via OpenSSL --> $uri ...";
$openssl_out = `./testssl.sh --ssl-native $check2run -t xmpp $uri 2>&1`;
# $openssl_json = json('tmp.json');
unlike($openssl_out, qr/$openssl_regex_bl/, "");
$tests++;

# $uri="jabber.ccc.de:5269";
# printf "\n%s\n", "Quick STARTTLS XMPP S2S unit tests via sockets --> $uri ...";
# $openssl_out = `./testssl.sh --openssl=/usr/bin/openssl -p $check2run -t xmpp-server $uri 2>&1`;
# # $openssl_json = json('tmp.json');
# unlike($openssl_out, qr/$openssl_regex_bl/, "");
# $tests++;


$uri="ldap.uni-rostock.de:21";

# unlink "tmp.json";
printf "\n%s\n", "STARTTLS FTP unit tests via sockets --> $uri ...";
$socket_out = `./testssl.sh $check2run -t ftp $uri 2>&1`;
# $socket_json = json('tmp.json');
# OCSP stapling fails sometimes with: 'offered, error querying OCSP responder (ERROR: No Status found)'
$socket_out =~ s/ error querying OCSP responder .*\n//g;
unlike($socket_out, qr/$socket_regex_bl/, "");
$tests++;

printf "\n%s\n", "STARTTLS FTP unit tests via OpenSSL --> $uri ...";
$openssl_out = `./testssl.sh --ssl-native $check2run -t ftp $uri 2>&1`;
# $openssl_json = json('tmp.json');
# OCSP stapling fails sometimes with: 'offered, error querying OCSP responder (ERROR: No Status found)'
$openssl_out =~ s/ error querying OCSP responder .*\n//g;
unlike($openssl_out, qr/$openssl_regex_bl/, "");
$tests++;


# https://ldapwiki.com/wiki/Public%20LDAP%20Servers
$uri="db.debian.org:389";

printf "\n%s\n", "STARTTLS LDAP unit tests via OpenSSL --> $uri ...";
$openssl_out = `./testssl.sh --ssl-native $check2run -t ldap $uri 2>&1`;
# $openssl_json = json('tmp.json');
unlike($openssl_out, qr/$openssl_regex_bl/, "");
$tests++;


$uri="news.newsguy.com:119";

# unlink "tmp.json";
printf "\n%s\n", "STARTTLS NNTP unit tests via sockets --> $uri ...";
$socket_out = `./testssl.sh $check2run -t nntp $uri 2>&1`;
# $socket_json = json('tmp.json');
unlike($socket_out, qr/$socket_regex_bl/, "");
$tests++;

printf "\n%s\n", "STARTTLS NNTP unit tests via OpenSSL --> $uri ...";
$openssl_out = `./testssl.sh --ssl-native $check2run -t nntp $uri 2>&1`;
# $openssl_json = json('tmp.json');
unlike($openssl_out, qr/$openssl_regex_bl/, "");
$tests++;


# IRC: missing
# LTMP, mysql, postgres



done_testing($tests);
# unlink "tmp.json";

sub json($) {
	my $file = shift;
	$file = `cat $file`;
	unlink $file;
	return from_json($file);
}

