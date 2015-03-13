#!/usr/bin/env bash
#
# bash is needed for some distros which use dash as /bin/sh and for tcp sockets which 
# this program uses a couple of times. Also some expressions are bashisms as I expect
# them to be faster. Idea is to not overdo it though.

# testssl.sh is a program for spotting weak SSL encryption, ciphers, version and some 
# vulnerablities or features
#
# Devel version is availabe from https://github.com/drwetter/testssl.sh,
# stable version from            https://testssl.sh

VERSION="2.3dev"				# any char suffixes denotes non=stable
SWURL="https://testssl.sh"
SWCONTACT="dirk aet testssl dot sh"

# Author: Dirk Wetter, copyleft: 2007-2015, contributions so far see CREDIT.md
#
# License: GPLv2, see http://www.fsf.org/licensing/licenses/info/GPLv2.html
# and accompanying license "LICENSE.txt". Redistribution + modification under this
# license permitted. 
# If you enclose this script or parts of it in your software, it has to
# be accompanied by the same license (see link) and the place where to get
# the recent version of this program. Don't violate the license!
#
# USAGE WITHOUT ANY WARRANTY, THE SOFTWARE IS PROVIDED "AS IS". USE IT AT
# your OWN RISK

# HISTORY: I know reading this shell script is sometimes neither nice nor is it rocket science
# (well ok, maybe the bash sockets are kind of cool).
# It all started with a few openssl commands. It is a such a good swiss army knife (see e.g.
#  wiki.openssl.org/index.php/Command_Line_Utilities) that it was difficult to resist wrapping 
# with some shell commandos around it. This is how everything started
# Probably you can achieve the same result with my favorite zsh (zmodload zsh/net/socket b4
# -- checkout zsh/net/tcp too! -- but bash is way more often used, within Linux and: cross-platform!

# Q: So what's the difference between https://www.ssllabs.com/ssltest or
#    https://sslcheck.globalsign.com/?
# A: As of now ssllabs only check webservers on standard ports, reachable from
#    the internet. And the examples above are 3rd parties. If those restrictions are fine
#    with you, they might tell you more than this tool -- as of now.

# Note that for "standard" openssl binaries a lot of features (ciphers, protocols, vulnerabilities)
# are disabled as they'll impact security otherwise. For security testing though we
# need all those features. Thus it's highly recommended to use the suppied binaries.
# Except on-available local ciphers you'll get a warning about missing features


# following variables make use of $ENV, e.g. OPENSSL=<myprivate_path_to_openssl> ./testssl.sh <host>
COLOR=${COLOR:-2}					# 2: Full color, 1: b/w+positioning, 0: no ESC at all
SHOW_LOC_CIPH=${SHOW_LOC_CIPH:-0} 		# determines whether the client side ciphers are displayed at all (makes no sense normally)
VERBERR=${VERBERR:-1}				# 0 means to be more verbose (some like the errors to be dispayed so that one can tell better
								# whether handshake succeeded or not. For errors with individual ciphers you also need to have SHOW_EACH_C=1
LOCERR=${LOCERR:-0}					# displays the local error 
SHOW_EACH_C=${SHOW_EACH_C:-0}			# where individual ciphers are tested show just the positively ones tested
SNEAKY=${SNEAKY:-1}					# if zero: the referer and useragent we leave while checking the http header is just usual
HEADER_MAXSLEEP=${HEADER_MAXSLEEP:-3}	# we wait this long before killing the process to retrieve a service banner / http header
SSL_NATIVE=${SSL_NATIVE:-0}			# we do per default bash sockets!
ASSUMING_HTTP=${ASSUMING_HTTP:-0}		# in seldom cases (WAF, old servers/grumpy SSL) the service detection fails. Set to 1 for HTTP

#FIXME: still to be filled with (more) sense:
DEBUG=${DEBUG:-0}		# if 1 the temp files won't be erased. 2: list more what's going on (formerly: eq VERBOSE=1), 3: slight hexdumps
					# and other info, 4: the whole nine yards of output
PS4='+(${BASH_SOURCE}:${LINENO}): ${FUNCNAME[0]:+${FUNCNAME[0]}(): }'

CAPATH="${CAPATH:-/etc/ssl/certs/}"	# Does nothing yet. FC has only a CA bundle per default, ==> openssl version -d
HSTS_MIN=180			# >180 days is ok for HSTS
HPKP_MIN=30			# >=30 days should be ok for HPKP_MIN, practical hints?
MAX_WAITSOCK=10		# waiting at max 10 seconds for socket reply
CLIENT_MIN_PFS=5		# number of ciphers needed to run a test for PFS
DAYS2WARN1=60			# days to warn before cert expires, threshold 1
DAYS2WARN2=30			# days to warn before cert expires, threshold 2

# more global vars, here just declared
ECHO="/usr/bin/printf --"			# works under Linux, BSD, MacOS. 
NPN_PROTOs="spdy/4a2,spdy/3,spdy/3.1,spdy/2,spdy/1,http/1.1"
RUN_DIR=`dirname $0`
TEMPDIR=""
TLS_PROTO_OFFERED=""
SOCKREPLY=""
HEXC=""
SNI=""
IP4=""
IP6=""
OSSL_VER=""			# openssl version, will be autodetermined
OSSL_VER_MAJOR=0
OSSL_VER_MINOR=0
OSSL_VER_APPENDIX="none"
NODEIP=""
IPS=""
SERVICE=""			# is the server running an HTTP server, SMTP, POP or IMAP?

BLA=""


# make sure that temporary files are cleaned up after use
trap "cleanup" QUIT EXIT

# The various hexdump commands we need to replace xxd (BSD compatability))
HEXDUMPVIEW=(hexdump -C) 				# This is used in verbose mode to see what's going on
HEXDUMP=(hexdump -ve '16/1 "%02x " " \n"') 	# This is used to analyse the reply
HEXDUMPPLAIN=(hexdump -ve '1/1 "%.2x"') 	# Replaces both xxd -p and tr -cd '[:print:]'
        
out()   { 
	$ECHO "$1" 
}
outln() { 
	[[ -z "$1" ]] || $ECHO "$1"
	$ECHO "\n"
}

# http://www.tldp.org/HOWTO/Bash-Prompt-HOWTO/x329.html
#### color print functions

pr_off() { 
	[[ "$COLOR" -ne 0 ]] && out "\033[m\c" 
}

pr_liteblueln() { pr_liteblue "$1"; outln; }
pr_liteblue() { 
	[[ "$COLOR" -eq 2 ]] && out "\033[0;34m$1 " || out "$1 "
	pr_off
}

pr_blueln() { pr_blue "$1"; outln; }
pr_blue() { 
	[[ "$COLOR" -eq 2 ]] && out "\033[1;34m$1 " || out "$1 "
	pr_off
}

pr_literedln() { pr_litered "$1"; outln; }
pr_litered() { 
	[[ "$COLOR" -eq 2 ]] && out "\033[0;31m$1 " || pr_bold "$1 "
	pr_off
}

pr_redln() { pr_red "$1"; outln; }
pr_red() { 
	[[ "$COLOR" -eq 2 ]] && out "\033[1;31m$1 " || pr_bold "$1 "
	pr_off
}

pr_litemagentaln() { pr_litemagenta "$1"; outln; }
pr_litemagenta() { 
	[[ "$COLOR" -eq 2 ]] && out "\033[0;35m$1 " || pr_underline "$1 "
	pr_off
}

pr_magentaln() { pr_magenta "$1"; outln; }
pr_magenta() { 
	[[ "$COLOR" -eq 2 ]] && out "\033[1;35m$1 " || pr_underline "$1 "
	pr_off
}

pr_litecyanln() { pr_litecyan "$1"; outln; }
pr_litecyan() { 
	[[ "$COLOR" -eq 2 ]] && out "\033[0;36m$1 " || out "$1 "
	pr_off
}

pr_cyanln() { pr_cyan "$1"; outln; }
pr_cyan() { 
	[[ "$COLOR" = 2 ]] && out "\033[1;36m$1 " || out "$1 "
	pr_off
}

pr_greyln() { pr_grey "$1"; outln; }
pr_grey() { 
	[[ "$COLOR" -eq 2 ]] && out "\033[1;30m$1 " || out "$1 "
	pr_off
}

pr_litegreyln() { pr_litegrey "$1"; outln; }
pr_litegrey() { 
	[[ "$COLOR" -eq 2 ]] && out "\033[0;37m$1 " || out "$1 "
	pr_off
}

pr_litegreenln() { pr_litegreen "$1"; outln; }
pr_litegreen() { 
	[[ "$COLOR" -eq 2 ]] && out "\033[0;32m$1 " || out "$1 "
	pr_off
}

pr_greenln() { pr_green "$1"; outln; }
pr_green() { 
	[[ "$COLOR" -eq 2 ]] && out "\033[1;32m$1 " || out "$1 "
	pr_off
}

pr_brownln() { pr_brown "$1"; outln; }
pr_brown() { 
	[[ "$COLOR" -eq 2 ]] && out "\033[0;33m$1 " || out "$1 "
	pr_off
}

pr_yellowln() { pr_yellow "$1"; outln; }
pr_yellow() { 
	[[ "$COLOR" -eq 2 ]] && out "\033[1;33m$1 " || out "$1 "
	pr_off
}

pr_boldln()       { pr_bold "$1" ; outln; }
pr_bold()         { [[ "$COLOR" -ne 0 ]] && out "\033[1m$1" || out "$1" ; pr_off; }
pr_underline()    { [[ "$COLOR" -ne 0 ]] && out "\033[4m$1" || out "$1" ; pr_off; }
pr_boldandunder() { [[ "$COLOR" -ne 0 ]] && out "\033[1m\033[4m$1" || out "$1" ; pr_off; }
pr_reverse()      { [[ "$COLOR" -ne 0 ]] && out "\033[7m$1" || out "$1"; pr_off; }

### colorswitcher (see e.g. https://linuxtidbits.wordpress.com/2008/08/11/output-color-on-bash-scripts/
###                         http://www.tldp.org/HOWTO/Bash-Prompt-HOWTO/x405.html
if [[ "$COLOR" -eq 2 ]]; then
	red=$(tput setaf 1) 
	green=$(tput setaf 2) 
	yellow=$(tput setaf 3) 
	blue=$(tput setaf 4) 
	off=$(tput sgr0)
fi

if [[ "$COLOR" -ge 1 ]]; then
	bold=$(tput bold)
	underline=$(tput sgr 0 1)
fi


###### function definitions

debugme() {
	if [[ $DEBUG -ge 2 ]]; then
		echo "$@"
		"$@" 
	else
		:
	fi
}

tmpfile_handle() {
	if [[ "$DEBUG" -eq 0 ]] ; then
		rm $TMPFILE
	else
		mv $TMPFILE "$TEMPDIR/$1"
	fi
}


# whether it is ok to offer/not to offer enc/cipher/version
ok(){
	if [ "$2" -eq 1 ] ; then		
		case $1 in
			1) pr_redln "offered (NOT ok)" ;;   # 1 1
			0) pr_greenln "not offered (OK)" ;; # 0 1
		esac
	else	
		case $1 in
			7) pr_brownln "not offered" ;;   	# 7 0
			6) pr_literedln "offered (NOT ok)" ;; # 6 0
			5) pr_litered "supported but couldn't detect a cipher"; outln "(may need debugging)"  ;;		# 5 5
			4) pr_litegreenln "offered (OK)" ;;  	# 4 0
			3) pr_brownln "offered" ;;  		# 3 0
			2) outln "offered" ;;  			# 2 0
			1) pr_greenln "offered (OK)" ;;  	# 1 0
			0) pr_boldln "not offered" ;;    	# 0 0
		esac
	fi
	return $2
}


# ARG1= pid which is in the backgnd and we wait for ($2 seconds)
wait_kill(){
	pid=$1
	maxsleep=$2
	while true; do
		if ! ps $pid 2>&1 >/dev/null; then
			return 0 	# didn't reach maxsleep yet
		fi
		sleep 1
		maxsleep=`expr $maxsleep - 1`
		test $maxsleep -eq 0 && break
	done # needs to be killed:
	kill $pid >&2 2>/dev/null
	wait $pid 2>/dev/null
	return 3   # killed
}

# in a nutshell: It's HTTP-level compression & an attack which works against any cipher suite and 
# is agnostic to the version of TLS/SSL, more: http://www.breachattack.com/
# foreign referers are the important thing here!
breach() {
	pr_bold " BREACH"; out " (CVE-2013-3587) =HTTP Compression  "
	url="$1"
	[ -z "$url" ] && url="/"
	if [ $SNEAKY -eq 0 ] ; then
		referer="Referer: http://google.com/" # see https://community.qualys.com/message/20360
		useragent="User-Agent: Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.0)"
	else
		referer="Referer: TLS/SSL-Tester from $SWURL"
		useragent="User-Agent: Mozilla/4.0 (X11; Linux x86_64; rv:42.0) Gecko/19700101 Firefox/42.0"
	fi
	(
	$OPENSSL  s_client -quiet -connect $NODEIP:$PORT $SNI << EOF
GET $url HTTP/1.1
Host: $NODE
$useragent
Accept: text/*
Accept-Language: en-US,en
Accept-encoding: gzip,deflate,compress
$referer
Connection: close

EOF
) &>$HEADERFILE_BREACH &
	pid=$!
	if wait_kill $pid $HEADER_MAXSLEEP; then
		result=`cat $HEADERFILE_BREACH | grep -a '^Content-Encoding' | sed -e 's/^Content-Encoding//' -e 's/://' -e 's/ //g'`
		result=`echo $result | tr -cd '\40-\176'`
		if [ -z $result ]; then
			pr_green "no HTTP compression (OK) " 
			ret=0
		else
			pr_litered "NOT ok, uses $result compression "
			ret=1
		fi
		# Catch: any URL can be vulnerable. I am testing now only the root. URL!
		outln "(only \"$url\" tested)"
	else
		pr_litemagentaln "failed (HTTP header request stalled)"
		ret=3
	fi
	return $ret
}


# determines whether the port has an HTTP service running or not (plain TLS, no STARTTLS)
runs_HTTP() {
	# SNI is nonsense for !HTTP but fortunately SMTP and friends don't care
	printf "GET / HTTP/1.1\r\nHost: $NODE\r\nUser-Agent: Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.0)\r\nAccept: text/*\r\n\r\n" | $OPENSSL s_client -quiet -connect $NODE:$PORT $SNI &>$TMPFILE &
	wait_kill $! $HEADER_MAXSLEEP
	head $TMPFILE | grep -q ^HTTP && SERVICE=HTTP
	head $TMPFILE | grep -q SMTP && SERVICE=SMTP
	head $TMPFILE | grep -q POP && SERVICE=POP
	head $TMPFILE | grep -q IMAP && SERVICE=IMAP
	debugme head $TMPFILE
# $TMPFILE contains also a banner which we could use if there's a need for it

	out " Service detected:      "
	case $SERVICE in
		HTTP) 
			out " $SERVICE" 
			ret=0 ;;
		IMAP|POP|SMTP) 
			out " $SERVICE, thus skipping HTTP specific checks" 
			ret=0 ;;
		*)   out " Couldn't determine what's running on port $PORT"
			if [[ $ASSUMING_HTTP -eq 1 ]]; then
				SERVICE=HTTP
				out " -- ASSUMING_HTTP set though"
				ret=0
			else
				out ", assuming not HTTP, skipping HTTP checks"
				ret=1
			fi
			;;
	esac

	outln
	tmpfile_handle $FUNCNAME.txt
	return $ret
}

#problems not handled: chunked
http_header() {
	[ -z "$1" ] && url="/" || url="$1"
	if [ $SNEAKY -eq 0 ] ; then
		referer="Referer: http://google.com/"
		useragent="User-Agent: Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.0)"
	else
		referer="Referer: TLS/SSL-Tester from $SWURL"
		useragent="User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:42.0) Gecko/19700101 Firefox/42.0"
	fi
	(
	$OPENSSL  s_client -quiet -connect $NODEIP:$PORT $SNI << EOF
GET $url HTTP/1.1
Host: $NODE
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-us,en;q=0.7,de-de;q=0.3
$useragent
$referer
Connection: close

EOF
) &>$HEADERFILE &
	pid=$!
	if wait_kill $pid $HEADER_MAXSLEEP; then
		if ! egrep -iq "XML|HTML|DOCTYPE|HTTP|Connection" $HEADERFILE; then
			pr_litemagenta "likely HTTP header requests failed (#lines: $(cat $HEADERFILE | wc -l))."
			outln "Rerun with DEBUG=1 and inspect \"http_header.txt\"\n"
			debugme cat $HEADERFILE
			ret=7
		fi
		sed  -e '/^<HTML/,$d' -e '/^<html/,$d' -e '/^<XML /,$d' -e '/<?XML /,$d' \
			-e '/^<xml /,$d' -e '/<?xml /,$d'  -e '/^<\!DOCTYPE/,$d' -e '/^<\!doctype/,$d' $HEADERFILE >$HEADERFILE.2
#### ^^^ Attention: the filtering for the html body only as of now, doesn't work for other content yet
		mv $HEADERFILE.2  $HEADERFILE	 # sed'ing in place doesn't work with BSD and Linux simultaneously
		ret=0
	else
		pr_litemagentaln "failed (HTTP header request stalled)"
		ret=3
	fi
	if egrep -awq "301|302|^Location" $HEADERFILE; then
		redir2=`grep -a '^Location' $HEADERFILE | sed 's/Location: //' | tr -d '\r\n'`
		outln " (got 30x to $redir2, may be better try this URL?)\n"
	fi
	[[ $DEBUG -eq 0 ]] && rm $HEADERFILE.2 2>/dev/null
	
	return $ret
}

includeSubDomains() {
	if grep -aiqw includeSubDomains "$1"; then
		pr_litegreen ", includeSubDomains"
	else
		pr_litecyan ", just this domain"
	fi
}

preload() {
	grep -aiqw preload "$1" && pr_litegreen ", preload"
}

hsts() {
	local hsts_age_sec
	local hsts_age_days

	if [ ! -s $HEADERFILE ] ; then
		http_header "$1" || return 3
	fi
	pr_bold " HSTS          "
	grep -iaw '^Strict-Transport-Security' $HEADERFILE >$TMPFILE
	if [ $? -eq 0 ]; then
		grep -aciw '^Strict-Transport-Security' $HEADERFILE | egrep -wq "1" || out "(two HSTS header, using 1st one) "
		hsts_age_sec=`sed -e 's/[^0-9]*//g' $TMPFILE | head -1` 
		hsts_age_days=$(( hsts_age_sec / 86400))
		if [ $hsts_age_days -gt $HSTS_MIN ]; then
			pr_litegreen "$hsts_age_days days \c" ; out "($hsts_age_sec s)"
		else
			pr_brown "$hsts_age_days days (<$HSTS_MIN is not good enough)"
		fi
		includeSubDomains "$TMPFILE"
		preload "$TMPFILE"  #FIXME: To be checked against: e.g. https://dxr.mozilla.org/mozilla-central/source/security/manager/boot/src/nsSTSPreloadList.inc and https://chromium.googlesource.com/chromium/src/+/master/net/http/transport_security_state_static.json
	else
		out "--"
	fi
	outln

	tmpfile_handle $FUNCNAME.txt
	return $?
}

hpkp() {
	local hpkp_age_sec
	local hpkp_age_days
	
	if [ ! -s $HEADERFILE ] ; then
		http_header "$1" || return 3
	fi
	pr_bold " HPKP          "
	egrep -aiw '^Public-Key-Pins|Public-Key-Pins-Report-Only' $HEADERFILE >$TMPFILE
	if [ $? -eq 0 ]; then
		egrep -aciw '^Public-Key-Pins|Public-Key-Pins-Report-Only' $HEADERFILE | egrep -wq "1" || out "(two HPKP header, using 1st one) "
		# dirty trick so that grep -c really counts occurances and not lines w/ occurances:
		if [ `sed 's/pin-sha/pin-sha\n/g' < $TMPFILE | grep -c pin-sha` -eq 1 ]; then
			pr_brown "One key is not sufficent, "
		fi
		hpkp_age_sec=`sed -e 's/\r//g' -e 's/^.*max-age=//' -e 's/;.*//' $TMPFILE`
		hpkp_age_days=$((hpkp_age_sec / 86400))
		if [ $hpkp_age_days -ge $HPKP_MIN ]; then
			pr_litegreen "$hpkp_age_days days \c" ; out "= $hpkp_age_sec s"
		else
			pr_brown "$hpkp_age_days days (<$HPKP_MIN is not good enough)"
		fi
		
		includeSubDomains "$TMPFILE"
		preload "$TMPFILE"
		out " (fingerprints not checked)"
	else
		out "--"
	fi
	outln

	tmpfile_handle $FUNCNAME.txt
	return $?
}

emphasize_numbers_in_headers(){
# see http://www.grymoire.com/Unix/Sed.html#uh-3
#	outln "$1" | sed "s/[0-9]*/$yellow&$off/g"
	outln "$1" | sed "s/\([0-9]\)/$yellow\1$off/g"
}


serverbanner() {
	if [ ! -s $HEADERFILE ] ; then
		http_header "$1" || return 3
	fi
	pr_bold " Server        "
	grep -ai '^Server' $HEADERFILE >$TMPFILE
	if [ $? -eq 0 ]; then
		serverbanner=`cat $TMPFILE | sed -e 's/^Server: //' -e 's/^server: //'`
		if [ x"$serverbanner" == "x\n" -o x"$serverbanner" == "x\n\r" -o x"$serverbanner" == "x" ]; then
			outln "banner exists but empty string"
		else
			emphasize_numbers_in_headers "$serverbanner"
		fi
	else
		outln "no \"Server\" line in header, interesting!"
	fi

	tmpfile_handle $FUNCNAME.txt
	return $?
}

applicationbanner() {
	if [ ! -s $HEADERFILE ] ; then
		http_header "$1" || return 3
	fi
	pr_bold " Application  "
# examples: dev.testssl.sh, php.net, asp.net , www.regonline.com
	egrep -ai '^X-Powered-By|^X-AspNet-Version|^X-Runtime|^X-Version' $HEADERFILE >$TMPFILE
	if [ $? -eq 0 ]; then
		#cat $TMPFILE | sed 's/^.*:/:/'  | sed -e :a -e '$!N;s/\n:/ \n\             +/;ta' -e 'P;D' | sed 's/://g' 
		#sed 's/^/ /g' $TMPFILE | tr -t '\n\r' '  ' | sed "s/\([0-9]\)/$pr_red\1$off/g"
		emphasize_numbers_in_headers "$(sed 's/^/ /g' $TMPFILE | tr -t '\n\r' '  ')"
		#i=0
		#cat $TMPFILE | sed 's/^/ /' | while read line; do
		#	out "$line" 
		#	if [[ $i -eq 0 ]] ; then
		#		out "               " 
		#		i=1
		#	fi
		#done
	else
		outln " (no banner at \"$url\")"
	fi

	tmpfile_handle $FUNCNAME.txt
	return $?
}

cookieflags() {	# ARG1: Path, ARG2: path
	if [ ! -s $HEADERFILE ] ; then
		http_header "$1" || return 3
	fi
	pr_bold " Cookie(s)     "
	grep -ai '^Set-Cookie' $HEADERFILE >$TMPFILE
	if [ $? -eq 0 ]; then
		nr_cookies=`cat $TMPFILE | wc -l`
		out "$nr_cookies issued: "
		if [ $nr_cookies -gt 1 ] ; then
			negative_word="NONE"
		else
			negative_word="NOT"
		fi
		nr_secure=`grep -iac secure $TMPFILE`
		case $nr_secure in
			0) out "$negative_word secure, " ;;
			[123456789]) pr_litegreen "$nr_secure/$nr_cookies"; out "secure, ";;
		esac
		nr_httponly=`grep -cai httponly $TMPFILE`
		case $nr_httponly in
			0) out "$negative_word HttpOnly" ;;
			[123456789]) pr_litegreen "$nr_httponly/$nr_cookies"; out "HttpOnly" ;;
		esac
	else
		out "(none issued at \"$url\")"
	fi
	outln

	tmpfile_handle $FUNCNAME.txt
	return 0
}
#FIXME: Access-Control-Allow-Origin, CSP, Upgrade, X-Frame-Options, X-XSS-Protection, X-Content-Type-Options
# https://en.wikipedia.org/wiki/List_of_HTTP_header_fields


# #1: string with 2 opensssl codes, HEXC= same in NSS/ssllab terminology
normalize_ciphercode() {
	part1=`echo "$1" | awk -F',' '{ print $1 }'`
	part2=`echo "$1" | awk -F',' '{ print $2 }'`
	part3=`echo "$1" | awk -F',' '{ print $3 }'`
	if [ "$part1" == "0x00" ] ; then		# leading 0x00
		HEXC=$part2
	else
		part2=`echo $part2 | sed 's/0x//g'`
		if [ -n "$part3" ] ; then    # a SSLv2 cipher has three parts
			part3=`echo $part3 | sed 's/0x//g'`
		fi
		HEXC="$part1$part2$part3"
	fi
	HEXC=`echo $HEXC | tr 'A-Z' 'a-z' |  sed 's/0x/x/'` #tolower + strip leading 0
	return 0
}

prettyprint_local() {
	pr_blue "--> Displaying all local ciphers"; 
	if [ ! -z "$1" ]; then
		pr_blue "matching word pattern "\"$1\"" (ignore case)"; 
	fi
	outln "\n"

	neat_header

	if [ -z "$1" ]; then
		$OPENSSL ciphers -V 'ALL:COMPLEMENTOFALL:@STRENGTH' | while read hexcode dash ciph sslvers kx auth enc mac export ; do
			normalize_ciphercode $hexcode
			neat_list $HEXC $ciph $kx $enc | strings  
		done
	else
		for arg in `echo $@ | sed 's/,/ /g'`; do
			$OPENSSL ciphers -V 'ALL:COMPLEMENTOFALL:@STRENGTH' | while read hexcode dash ciph sslvers kx auth enc mac export ; do
				normalize_ciphercode $hexcode
				neat_list $HEXC $ciph $kx $enc | strings | grep -wai "$arg"
			done
     	done
	fi
	outln
	return 0
}


# list ciphers (and makes sure you have them locally configured)
# arg[1]: cipher list (or anything else)
listciphers() {
	$OPENSSL ciphers $1 &>$TMPFILE
	ret=$?
	[[ $LOCERR -eq 1 ]] && cat $TMPFILE 

     tmpfile_handle $FUNCNAME.txt
	return $ret
}


# argv[1]: cipher list to test 
# argv[2]: string on console
# argv[3]: ok to offer? 0: yes, 1: no
std_cipherlists() {
	out "$2 "; 
	if listciphers $1; then  # is that locally available??
		[ $SHOW_LOC_CIPH = "1" ] && out "local ciphers are: " && cat $TMPFILE | sed 's/:/, /g'
		$OPENSSL s_client -cipher "$1" $STARTTLS -connect $NODEIP:$PORT $SNI 2>$TMPFILE >/dev/null </dev/null
		ret=$?
		[[ $DEBUG -ge 2 ]] && cat $TMPFILE
		case $3 in
			0)	# ok to offer
				if [[ $ret -eq 0 ]]; then	# was offered
					ok 1 0			# pr_green
				else
					ok 0 0			# black
				fi ;;
			2) 	# not really bad
				if [[ $ret -eq 0 ]]; then
					ok 2 0			# offered in normal
				else
					ok 2 0              # not offered also in normal
				fi;;
			*) # the ugly rest
				if [[ $ret -eq 0 ]]; then
					ok 1 1			# was offered! --> pr_red
				else
					#ok 0 0			# was not offered, that's ok
					ok 0 1			# was not offered --> pr_green
				fi ;;
		esac
		tmpfile_handle $FUNCNAME.txt
	else
		singlespaces=`echo "$2" | sed -e 's/ \+/ /g' -e 's/^ //' -e 's/ $//g' -e 's/  //g'`
		pr_magentaln "Local problem: No $singlespaces configured in $OPENSSL" 
	fi
	# we need lf in those cases:
	[[ $LOCERR -eq 1 ]] && echo
	[[ $DEBUG -ge 2 ]] && echo
}


# sockets inspired by http://blog.chris007.de/?p=238
# ARG1: hexbyte with a leading comma (!!), seperated by commas
# ARG2: sleep
socksend() {
	# the following works under BSD and Linux, which is quite tricky. So don't mess with it unless you're really sure what you do
	data=`echo "$1" | sed -e 's/# .*$//g' -e 's/ //g' | sed -E 's/^[[:space:]]+//; s/[[:space:]]+$//; /^$/d' | sed 's/,/\\\/g' | tr -d '\n'`
	[[ $DEBUG -ge 4 ]] && echo "\"$data\""
	printf -- "$data" >&5 2>/dev/null &
	sleep $2
}


sockread() {
	[ "x$2" = "x" ] && maxsleep=$MAX_WAITSOCK || maxsleep=$2
	ret=0

	ddreply=`mktemp /tmp/ddreply.XXXXXX` || exit 7
	dd bs=$1 of=$ddreply count=1 <&5 2>/dev/null &
	pid=$!
	
	while true; do
		if ! ps $pid 2>&1 >/dev/null; then
			break  # didn't reach maxsleep yet
			kill $pid >&2 2>/dev/null
		fi
		sleep 1
		maxsleep=`expr $maxsleep - 1`
		test $maxsleep -eq 0 && break
	done
#FIXME: cleanup, we have extra function for this now

	if ps $pid 2>&1 >/dev/null; then
		# time's up and dd is still alive --> timeout
		kill $pid 
		wait $pid 2>/dev/null
		ret=3 # means killed
	fi
	SOCKREPLY=`cat $ddreply`
	rm $ddreply

	return $ret
}


show_rfc_style(){
	[ ! -r "$MAP_RFC_FNAME" ] && return 1
	RFCname=`grep -iw $1 "$MAP_RFC_FNAME" | sed -e 's/^.*TLS/TLS/' -e 's/^.*SSL/SSL/'`
	[[ -n "$RFCname" ]] && out "$RFCname" 
	return 0
}

neat_header(){
	outln "Hexcode  Cipher Suite Name (OpenSSL)    KeyExch.   Encryption Bits${MAP_RFC_FNAME:+        Cipher Suite Name (RFC)}"
	outln "%s-------------------------------------------------------------------------${MAP_RFC_FNAME:+----------------------------------------------}"
}

neat_list(){
	kx=`echo $3 | sed 's/Kx=//g'`
	enc=`echo $4 | sed 's/Enc=//g'`
	strength=`echo $enc | sed -e 's/.*(//' -e 's/)//'`					# strength = encryption bits
	strength=`echo $strength | sed -e 's/ChaCha20-Poly1305/ly1305/g'` 		# workaround for empty bits ChaCha20-Poly1305
	enc=`echo $enc | sed -e 's/(.*)//g' -e 's/ChaCha20-Poly1305/ChaCha20-Po/g'` # workaround for empty bits ChaCha20-Poly1305
	echo "$export" | grep -iq export && strength="$strength,export"
	if [ -r "$MAP_RFC_FNAME" ]; then
		printf -- " %-7s %-30s %-10s %-11s%-11s${MAP_RFC_FNAME:+ %-48s}${SHOW_EACH_C:+  }" "$1" "$2" "$kx" "$enc" "$strength" "$(show_rfc_style $HEXC)"
	else
		printf -- " %-7s %-30s %-10s %-11s%-11s${SHOW_EACH_C:+  }" "$1" "$2" "$kx" "$enc" "$strength"
	fi
}

test_just_one(){
	pr_blue "--> Testing single cipher with word pattern "\"$1\"" (ignore case)"; outln "\n"
	neat_header
	for arg in `echo $@ | sed 's/,/ /g'`; do 
		# 1st check whether openssl has cipher or not
		$OPENSSL ciphers -V 'ALL:COMPLEMENTOFALL:@STRENGTH' | while read hexcode dash ciph sslvers kx auth enc mac export ; do
			normalize_ciphercode $hexcode 
			neat_list $HEXC $ciph $kx $enc | strings | grep -qwai "$arg" 
			if [ $? -eq 0 ]; then
				$OPENSSL s_client -cipher $ciph $STARTTLS -connect $NODEIP:$PORT $SNI &>$TMPFILE </dev/null
				ret=$?
				neat_list $HEXC $ciph $kx $enc

				if [ $ret -eq 0 ]; then
					pr_cyan "  available"
				else
					out "  not a/v"
				fi
				outln
			fi
		done
	done
	outln

	tmpfile_handle $FUNCNAME.txt
	return 0
}


# test for all ciphers locally configured (w/o distinguishing whether they are good or bad
allciphers(){
	nr_ciphers=`$OPENSSL ciphers  'ALL:COMPLEMENTOFALL:@STRENGTH' | sed 's/:/ /g' | wc -w`
	pr_blue "--> Testing all locally available $nr_ciphers ciphers against the server"; outln "\n"
	neat_header

	$OPENSSL ciphers -V 'ALL:COMPLEMENTOFALL:@STRENGTH' | while read hexcode n ciph sslvers kx auth enc mac export; do
	# FIXME: e.g. OpenSSL < 1.0 doesn't understand "-V" --> we can't do anything about it!
		$OPENSSL s_client -cipher $ciph $STARTTLS -connect $NODEIP:$PORT $SNI &>$TMPFILE  </dev/null
		ret=$?
		if [ $ret -ne 0 ] && [ "$SHOW_EACH_C" -eq 0 ]; then
			continue		# no successful connect AND not verbose displaying each cipher
		fi
		normalize_ciphercode $hexcode
		neat_list $HEXC $ciph $kx $enc
		if [ "$SHOW_EACH_C" -ne 0 ]; then
			if [ $ret -eq 0 ]; then
				pr_cyan "  available"
			else
				out "  not a/v"
			fi
		fi
		outln
		tmpfile_handle $FUNCNAME.txt
	done
	return 0
}

# test for all ciphers per protocol locally configured (w/o distinguishing whether they are good or bad
cipher_per_proto(){
	pr_blue "--> Testing all locally available ciphers per protocol against the server"; outln "\n"
	neat_header
	outln " -ssl2 SSLv2\n -ssl3 SSLv3\n -tls1 TLSv1\n -tls1_1 TLSv1.1\n -tls1_2 TLSv1.2"| while read proto prtext; do
		locally_supported "$proto" "$prtext" || continue
		outln
		$OPENSSL ciphers $proto -V 'ALL:COMPLEMENTOFALL:@STRENGTH' | while read hexcode n ciph sslvers kx auth enc mac export; do
			$OPENSSL s_client -cipher $ciph $proto $STARTTLS -connect $NODEIP:$PORT $SNI &>$TMPFILE  </dev/null
			ret=$?
			if [ $ret -ne 0 ] && [ "$SHOW_EACH_C" -eq 0 ]; then
				continue       # no successful connect AND not verbose displaying each cipher
			fi
			normalize_ciphercode $hexcode
			neat_list $HEXC $ciph $kx $enc
			if [ "$SHOW_EACH_C" -ne 0 ]; then
				if [ $ret -eq 0 ]; then
					pr_cyan "  available"
				else
					out "  not a/v"
				fi
			fi
			outln
			tmpfile_handle $FUNCNAME.txt
		done
	done

	return 0
}

locally_supported() {
	out "$2 "
	$OPENSSL s_client "$1" 2>&1 | grep -q "unknown option"
	if [ $? -eq 0 ]; then
		pr_magentaln "Local problem: $OPENSSL doesn't support \"s_client $1\""
		ret=7
	else
		ret=0
	fi

	return $ret
	
}

testversion() {
	local sni=$SNI
	[ "x$1" = "x-ssl2" ] && sni=""  # newer openssl throw an error if SNI with SSLv2

	$OPENSSL s_client -state $1 $STARTTLS -connect $NODEIP:$PORT $sni &>$TMPFILE </dev/null
	ret=$?
	[ "$VERBERR" -eq 0 ] && egrep "error|failure" $TMPFILE | egrep -v "unable to get local|verify error"
	
	if grep -q "no cipher list" $TMPFILE ; then
		ret=5
	fi

	tmpfile_handle $FUNCNAME.txt
	return $ret
}

testprotohelper() {
	if locally_supported "$1" "$2" ; then
		testversion "$1" "$2" 
		return $?
	else
		return 7
	fi
}


runprotocols() {
	pr_blue "--> Testing Protocols"; outln "\n"
	if [ $SSL_NATIVE -eq 1 ] || [ -n "$STARTTLS" ]; then
		testprotohelper "-ssl2" " SSLv2     "  
		case $? in
			0) 	ok 1 1 ;;	# pr_red 
			5) 	ok 5 5 ;;	# protocol ok, but no cipher
			1) 	ok 0 1 ;; # pr_green "not offered (ok)"
			7) ;;		# no local support
		esac
	else
		sslv2_sockets
	fi
	
	testprotohelper "-ssl3" " SSLv3     " 
	case $? in
		0) ok 6 0 ;;	# poodle hack"
		1) ok 0 1 ;;	# pr_green "not offered (ok)"
		5) ok 5 5 ;;	# protocol ok, but no cipher
		7) ;;		# no local support
	esac

	testprotohelper "-tls1" " TLSv1     "
	case $? in
		0) ok 2 0 ;;   # no GCM, thus only normal print
		1) ok 0 0 ;;
		5) ok 5 5 ;;	# protocol ok, but no cipher
		7) ;;		# no local support
	esac

	testprotohelper "-tls1_1" " TLSv1.1   "
	case $? in
		0) ok 2 0 ;;   # normal print
		1) ok 7 0 ;;   # no GCM, penalty
		5) ok 5 5 ;;	# protocol ok, but no cipher
		7) ;;		# no local support
	esac

	testprotohelper "-tls1_2" " TLSv1.2   "
	case $? in
		0) ok 1 0 ;;
		1) ok 7 0 ;;   # no GCM, penalty
		5) ok 5 5 ;;	# protocol ok, but no cipher
		7) ;;		# no local support
	esac

	return 0
}

run_std_cipherlists() {
	outln
	pr_blue "--> Testing standard cipher lists"; outln "\n"
# see man ciphers
	std_cipherlists NULL:eNULL                   " Null Cipher             " 1
	std_cipherlists aNULL                        " Anonymous NULL Cipher   " 1
	std_cipherlists ADH                          " Anonymous DH Cipher     " 1
	#if [[ "$OSSL_VER" = *chacha* ]]; then
		#out " 40 Bit encryption        "; pr_magentaln "Local problem: $OPENSSL has a bug here"
	#else
		std_cipherlists EXPORT40                     " 40 Bit encryption       " 1
	#fi
	std_cipherlists EXPORT56                     " 56 Bit encryption       " 1
	#if [[ "$OSSL_VER" = *chacha* ]]; then
	#	out " Export Cipher (general)  "; pr_magentaln "Local problem: $OPENSSL has a bug here"
	#else
		std_cipherlists EXPORT                       " Export Cipher (general) " 1
	#fi
	std_cipherlists LOW                          " Low (<=64 Bit)          " 1
	std_cipherlists DES                          " DES Cipher              " 1
	std_cipherlists 3DES                         " Triple DES Cipher       " 2
	std_cipherlists "MEDIUM:!NULL:!aNULL:!SSLv2" " Medium grade encryption " 2
	std_cipherlists "HIGH:!NULL:!aNULL"          " High grade encryption   " 0
	return 0
}

openssl_error() {
	pr_magenta "$OPENSSL returned an error. This shouldn't happen. "
	outln "continuing anyway"
	return 0
}

server_preference() {
	list1="DES-CBC3-SHA:RC4-MD5:DES-CBC-SHA:RC4-SHA:AES128-SHA:AES128-SHA:AES256-SHA:DHE-RSA-AES128-SHA:DHE-RSA-AES256-SHA:DHE-DSS-AES128-SHA:DHE-DSS-AES128-SHA:DHE-DSS-AES256-SHA:ECDH-RSA-DES-CBC3-SHA:ECDH-RSA-AES128-SHA:ECDH-RSA-AES256-SHA:ECDHE-RSA-AES256-GCM-SHA384:DHE-RSA-AES128-SHA256:DHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES128-SHA256:ECDHE-RSA-AES256-SHA384:DHE-DSS-AES256-GCM-SHA384"
	outln;
	pr_blue "--> Testing server preferences"; outln "\n"

	$OPENSSL s_client $STARTTLS -cipher $list1 -connect $NODEIP:$PORT $SNI </dev/null 2>/dev/null >$TMPFILE
	if [ $? -ne 0 ]; then
          openssl_error
          ret=6
	else
		cipher1=`grep -w Cipher $TMPFILE | egrep -vw "New|is" | sed -e 's/^ \+Cipher \+://' -e 's/ //g'`
		list2=`echo $list1 | tr ':' '\n' | sort -r | tr '\n' ':'`	# pr_reverse the list
		$OPENSSL s_client $STARTTLS -cipher $list2 -connect $NODEIP:$PORT $SNI </dev/null 2>/dev/null >$TMPFILE
		cipher2=`grep -w Cipher $TMPFILE | egrep -vw "New|is" | sed -e 's/^ \+Cipher \+://' -e 's/ //g'`

		out " Has server cipher order?     "
		if [[ "$cipher1" != "$cipher2" ]]; then
			pr_litered "nope (NOT ok)"
			remark4default_cipher=" (limited sense as client will pick)"
		else
			pr_green "yes (OK)"
			remark4default_cipher=""
		fi
		[[ $DEBUG -ge 2 ]] && out "  $cipher1 | $cipher2"
		outln

		$OPENSSL s_client $STARTTLS -connect $NODEIP:$PORT $SNI </dev/null 2>/dev/null >$TMPFILE
		out " Negotiated protocol          "
		default_proto=`grep -w "Protocol" $TMPFILE | sed -e 's/^.*Protocol.*://' -e 's/ //g'`
		case "$default_proto" in
			*TLSv1.2)		pr_greenln $default_proto ;;
			*TLSv1.1)		pr_litegreenln $default_proto ;;
			*TLSv1)		outln $default_proto ;;
			*SSLv2)		pr_redln $default_proto ;;
			*SSLv3)		pr_redln $default_proto ;;
			*)			outln "FIXME: $default_proto" ;;
		esac
 
		out " Negotiated cipher            "
		default_cipher=`grep -w "Cipher" $TMPFILE | egrep -vw "New|is" | sed -e 's/^.*Cipher.*://' -e 's/ //g'`
		case "$default_cipher" in
			*NULL*|*EXP*)	pr_red "$default_cipher" ;;
			*RC4*)		pr_litered "$default_cipher" ;;
			*CBC*)		pr_brown "$default_cipher" ;; #FIXME BEAST: We miss some CBC ciphers here, need to work w/ a list
			*GCM*)		pr_green "$default_cipher" ;;   # best ones
			*CHACHA20*)	pr_green "$default_cipher" ;;   # best ones
			ECDHE*AES*)    pr_yellow "$default_cipher" ;;   # it's CBC. --> lucky13
			*)			out "$default_cipher" ;;
		esac
		outln "$remark4default_cipher"

		out " Negotiated cipher per proto $remark4default_cipher"
		i=1
		for p in sslv2 ssl3 tls1 tls1_1 tls1_2; do
		# proto-check b4!
			$OPENSSL s_client  $STARTTLS -"$p" -connect $NODEIP:$PORT $SNI </dev/null 2>/dev/null  >$TMPFILE
			if [ $ret -eq 0 ]; then
				 proto[i]=`grep -w "Protocol" $TMPFILE | sed -e 's/^ \+Protocol \+://' -e 's/ //g'`
				 cipher[i]=`grep -w "Cipher" $TMPFILE | egrep -vw "New|is" | sed -e 's/^ \+Cipher \+://' -e 's/ //g'`
				 [[ ${cipher[i]} == "0000" ]] && cipher[i]=""  # Hack!
				 [[ $DEBUG -ge 2 ]] && outln "Default cipher for ${proto[i]}: ${cipher[i]}"
			else
				 proto[i]=""
				 cipher[i]=""
			fi
			i=`expr $i + 1`
		done

		if spdy_pre ; then		# is NPN/SPDY supported and is this no STARTTLS?
			$OPENSSL s_client -host $NODE -port $PORT -nextprotoneg "$NPN_PROTOs" </dev/null 2>/dev/null  >$TMPFILE
			if [ $? -eq 0 ]; then
				proto[i]=`grep -aw "Next protocol" $TMPFILE | sed -e 's/^Next protocol://' -e 's/(.)//' -e 's/ //g'`
				if [ -z "${proto[i]}" ]; then
					cipher[i]=""
				else
					cipher[i]=`grep -aw "Cipher" $TMPFILE | egrep -vw "New|is" | sed -e 's/^ \+Cipher \+://' -e 's/ //g'`
					[[ $DEBUG -ge 2 ]] && outln "Default cipher for ${proto[i]}: ${cipher[i]}"
				fi
			fi
		fi

		for i in 1 2 3 4 5 6; do
			if [[ -n "${cipher[i]}" ]]; then                              # cipher nicht leer
				 if [[ -z "${cipher[i-1]}" ]]; then                      # der davor leer
				 	outln
					printf -- "     %-30s %s" "${cipher[i]}:" "${proto[i]}"            # beides ausgeben
				 else                                                    # davor nihct leer
					if [[ "${cipher[i-1]}" == "${cipher[i]}" ]]; then   # und bei vorigem Protokoll selber cipher
						out ", ${proto[i]}"                         	  # selber Cipher --> Nur Protokoll dahinter
					else
						outln
						printf -- "     %-30s %s" "${cipher[i]}:" "${proto[i]}"            # beides ausgeben
				    fi
				 fi
			fi
		done
	fi
	outln

	tmpfile_handle $FUNCNAME.txt
	return 0
}


server_defaults() {
	outln
	pr_blue "--> Testing server defaults (Server Hello)"; outln "\n"
	localtime=`date "+%s"`

	# throwing every cipher/protocol at the server and displaying its pick
	$OPENSSL s_client $STARTTLS -connect $NODEIP:$PORT $SNI -tlsextdebug -status </dev/null 2>/dev/null >$TMPFILE
	ret=$?
	$OPENSSL s_client $STARTTLS -connect $NODEIP:$PORT $SNI 2>/dev/null </dev/null | awk '/-----BEGIN/,/-----END/ { print $0 }'  >$HOSTCERT
	if [ $? -ne 0 ] || [ $ret -ne 0 ]; then
		openssl_error
		ret=6
	else
		out " TLS server extensions        "
		extensions=`grep -w "^TLS server extension" $TMPFILE | sed -e 's/^TLS server extension \"//' -e 's/\".*$/,/g'`
		if [ -z "$extensions" ]; then
			outln "(none)"
		else
			echo $extensions | sed 's/,$//'	# remove last comma
		fi

		out " Session Tickets RFC 5077     "
		sessticket_str=`grep -w "session ticket" $TMPFILE | grep lifetime`
		if [ -z "$sessticket_str" ]; then
			outln "(none)"
		else
			lifetime=`echo $sessticket_str | grep lifetime | sed 's/[A-Za-z:() ]//g'`
			unit=`echo $sessticket_str | grep lifetime | sed -e 's/^.*'"$lifetime"'//' -e 's/[ ()]//g'`
			outln "$lifetime $unit"
		fi

		out " Server key size              "
		keysize=`grep -w "^Server public key is" $TMPFILE | sed -e 's/^Server public key is //'`
		if [ -z "$keysize" ]; then
			outln "(couldn't determine)"
		else
			case "$keysize" in
				1024*) pr_brownln "$keysize" ;;
				2048*) outln "$keysize" ;;
				4096*) pr_litegreenln "$keysize" ;;
				*) outln "$keysize" ;;
			esac
		fi
# google seems to have EC keys which displays as 256 Bit

		out " Signature Algorithm          "
		algo=`$OPENSSL x509 -in $HOSTCERT -noout -text  | grep "Signature Algorithm" | sed 's/^.*Signature Algorithm: //' | sort -u `
		case $algo in
     		sha1WithRSAEncryption) 	pr_brownln "SHA1withRSA" ;;
	     	sha256WithRSAEncryption) pr_litegreenln "SHA256withRSA" ;;
		     sha512WithRSAEncryption) pr_litegreenln "SHA512withRSA" ;;
		     md5*) 				pr_redln "MD5" ;;
			*) 					outln "$algo" ;;
		esac
		# old, but interesting: https://blog.hboeck.de/archives/754-Playing-with-the-EFF-SSL-Observatory.html

		out " Fingerprint / Serial         "
		outln "$($OPENSSL x509 -noout -in $HOSTCERT -fingerprint -sha1 | sed 's/Fingerprint=//' | sed 's/://g' ) / $($OPENSSL x509 -noout -in $HOSTCERT -serial | sed 's/serial=//')"
		outln "                              $($OPENSSL x509 -noout -in $HOSTCERT -fingerprint -sha256 | sed 's/Fingerprint=//' | sed 's/://g' )"

		out " Common Name (CN)             "
		CN=`$OPENSSL x509 -in $HOSTCERT -noout -subject | sed 's/subject= //' | sed -e 's/^.*CN=//' -e 's/\/emailAdd.*//'`
		out "$CN"

		CN_nosni=`$OPENSSL s_client $STARTTLS -connect $NODEIP:$PORT 2>/dev/null </dev/null | awk '/-----BEGIN/,/-----END/ { print $0 }'  | \
			$OPENSSL x509 -noout -subject | sed 's/subject= //' | sed -e 's/^.*CN=//' -e 's/\/emailAdd.*//'`
		[[ $DEBUG -ge 2 ]] && out "$NODE | $CN | $CN_nosni"
		if [[ $NODE == $CN_nosni ]]; then
			outln " (works w/o SNI)"
		else
			outln " (CN response to request w/o SNI: '$CN_nosni')"
		fi

		SAN=`$OPENSSL x509 -in $HOSTCERT -noout -text | grep -A3 "Subject Alternative Name" | grep "DNS:" | \
			sed -e 's/DNS://g' -e 's/ //g' -e 's/,/\n/g' -e 's/othername:<unsupported>//g'`
#                                                               ^^^ CACert
		[ x"$SAN" != "x" ] && SAN=`echo "$SAN" | sed -e ':a' -e 'N' -e '$!ba' -e 's/\n/ /g'` && outln " subjectAltName (SAN)         $SAN"
										# replace line feed by " "

		out " Issuer                       "
		issuer=`$OPENSSL x509 -in $HOSTCERT -noout -issuer | sed -e 's/^.*CN=//g' -e 's/\/.*$//g'`
		issuer_o=`$OPENSSL x509 -in $HOSTCERT -noout -issuer | sed 's/^.*O=//g' | sed 's/\/.*$//g'`
		if $OPENSSL x509 -in $HOSTCERT -noout -issuer | grep -q 'C=' ; then 
			issuer_c=`$OPENSSL x509 -in $HOSTCERT -noout -issuer | sed 's/^.*C=//g' | sed 's/\/.*$//g'`
		else
			issuer_c="" 		# CACert would have 'issuer= ' here otherwise
		fi
		if [ "$issuer_o" == "issuer=" ] || [ "$issuer" == "$CN" ] ; then
			pr_redln "selfsigned (not OK)"
		else
			[ "$issuer_c" == "" ] && \
				outln "$issuer ('$issuer_o')" || \
				outln "$issuer ('$issuer_o' from '$issuer_c')"
		fi

		out " Certificate Expiration       "
		expire=`$OPENSSL x509 -in $HOSTCERT -checkend 0`
		if ! echo $expire | grep -qw not; then
	     	pr_red "expired!"
		else
			SECS2WARN=`expr 24 \* 60 \* 60 \* $DAYS2WARN2`  # low threshold first
		     expire=`$OPENSSL x509 -in $HOSTCERT -checkend $SECS2WARN`
			if echo "$expire" | grep -qw not; then
				SECS2WARN=`expr 24 \* 60 \* 60 \* $DAYS2WARN2`
				expire=`$OPENSSL x509 -in $HOSTCERT -checkend $SECS2WARN`
				if echo "$expire" | grep -qw not; then
					pr_litegreen ">= $DAYS2WARN1 days"
				else
		     		pr_brown "expires < $DAYS2WARN1 days"
				fi
			else
		     		pr_litered "expires < $DAYS2WARN2 days!"
			fi
		fi
		enddate=`date --date="$($OPENSSL x509 -in $HOSTCERT -noout -enddate | cut -d= -f 2)" +"%F %H:%M %z"`
		startdate=`date --date="$($OPENSSL x509 -in $HOSTCERT -noout -startdate | cut -d= -f 2)" +"%F %H:%M"`
		outln " ($startdate --> $enddate)"

		savedir=`pwd`; cd $TEMPDIR
		$OPENSSL s_client -showcerts $STARTTLS -connect $NODEIP:$PORT $SNI 2>/dev/null </dev/null | \
     		awk -v c=-1 '/-----BEGIN CERTIFICATE-----/{inc=1;c++} inc {print > ("level" c ".crt")} /---END CERTIFICATE-----/{inc=0}'
		nrsaved=`ls $TEMPDIR/level?.crt 2>/dev/null | wc -w`
		outln " # of certificates provided   $nrsaved"
		cd $savedir

		out " Certificate Revocation List  "
		crl=`$OPENSSL x509 -in $HOSTCERT -noout -text | grep -A 4 "CRL Distribution" | grep URI | sed 's/^.*URI://'`
		[ x"$crl" == "x" ] && pr_literedln "--" || echo "$crl"

		out " OCSP URI                     "
		ocsp_uri=`$OPENSSL x509 -in $HOSTCERT -noout -ocsp_uri`
		[ x"$ocsp_uri" == "x" ] && pr_literedln "--" || echo "$ocsp_uri"

		out " OCSP stapling               "
		if grep "OCSP response" $TMPFILE | grep -q "no response sent" ; then
			out " not offered"
		else
			if grep "OCSP Response Status" $TMPFILE | grep -q successful; then
				pr_litegreen " OCSP stapling offered"
			else
				outln " not sure what's going on here, debug:"
				grep -A 20 "OCSP response"  $TMPFILE
				ret=2
			fi
		fi
	fi
	outln

		#gmt_unix_time, removed since 1.0.1f
		#
		#remotetime=`grep -w "Start Time" $TMPFILE | sed 's/[A-Za-z:() ]//g'`
		#if [ ! -z "$remotetime" ]; then
		#	remotetime_stdformat=`date --date="@$remotetime" "+%Y-%m-%d %r"`
		#	difftime=`expr $localtime - $remotetime`
		#	[ $difftime -gt 0 ] && difftime="+"$difftime
		#	difftime=$difftime" s"
		#	outln " remotetime? : $remotetime ($difftime) = $remotetime_stdformat"
		#	outln " $remotetime"
		#	outln " $localtime"
		#fi
		#http://www.moserware.com/2009/06/first-few-milliseconds-of-https.html

	tmpfile_handle tlsextdebug+status.txt
	return $ret
}
# FIXME: revoked, see checkcert.sh 
# FIXME: Trust (only CN)



# http://www.heise.de/security/artikel/Forward-Secrecy-testen-und-einrichten-1932806.html
pfs() {
	local ret
	local none
	local number_pfs
	local hexcode n ciph sslvers kx auth enc mac

	outln
	pr_blue "--> Testing (Perfect) Forward Secrecy  (P)FS)"; outln " -- omitting 3DES, RC4 and Null Encryption here"
# https://community.qualys.com/blogs/securitylabs/2013/08/05/configuring-apache-nginx-and-openssl-for-forward-secrecy
	PFSOK='EECDH+ECDSA+AESGCM EECDH+aRSA+AESGCM EECDH+ECDSA+SHA256 EECDH+aRSA+SHA256 EECDH+aRSA+RC4 EDH+aRSA EECDH RC4 !RC4-SHA !aNULL !eNULL !LOW !3DES !MD5 !EXP !PSK !SRP !DSS:@STRENGTH'
# ^^^ remark: the exclusing via ! doesn't work with libressl. 
#
#	PFSOK='EECDH+ECDSA+AESGCM EECDH+aRSA+AESGCM EECDH+ECDSA+SHA384 EECDH+ECDSA+SHA256 EECDH+aRSA+SHA384 EECDH'
# this catches also ECDHE-ECDSA-NULL-SHA  or  ECDHE-RSA-RC4-SHA

	$OPENSSL ciphers -V "$PFSOK" >$TMPFILE 2>/dev/null
	if [ $? -ne 0 ] ; then
		number_pfs=`wc -l $TMPFILE | awk '{ print $1 }'`
		if [ "$number_pfs" -le "$CLIENT_MIN_PFS" ] ; then
			outln
			pr_magentaln " Local problem: you have only $number_pfs client side PFS ciphers "
			outln " Thus it doesn't make sense to test PFS"
			[ $number_pfs -ne 0 ] && cat $TMPFILE 
			return 1
		fi
	fi
	savedciphers=`cat $TMPFILE`
	[ $SHOW_LOC_CIPH = "1" ] && echo "local ciphers available for testing PFS:" && echo `cat $TMPFILE`

	$OPENSSL s_client -cipher 'ECDH:DH' $STARTTLS -connect $NODEIP:$PORT $SNI &>$TMPFILE </dev/null
	ret=$?
	outln
	if [ $ret -ne 0 ] || [ `grep -c "BEGIN CERTIFICATE" $TMPFILE` -eq 0 ]; then
		pr_brown "No PFS available"
	else
		pr_litegreenln "In general PFS is offered. Now testing specific ciphers ..."; 
		outln "(it depends on the browser/client whether one of them will be used)\n"
		none=0
		neat_header
		while read hexcode n ciph sslvers kx auth enc mac; do
			$OPENSSL s_client -cipher $ciph $STARTTLS -connect $NODEIP:$PORT $SNI &>/dev/null </dev/null
			ret2=$?
			if [ $ret2 -ne 0 ] && [ "$SHOW_EACH_C" -eq 0 ] ; then
				continue # no successful connect AND not verbose displaying each cipher
			fi
			normalize_ciphercode $hexcode
			neat_list $HEXC $ciph $kx $enc $strength
			let "none++"
			((none++))
			if [ "$SHOW_EACH_C" -ne 0 ] ; then
				if [ $ret2 -eq 0 ]; then
					pr_green "works"
				else
					out "not a/v"
				fi
			fi
			outln
		done < <($OPENSSL ciphers -V "$PFSOK")
		#    ^^^^^ posix redirect as shopt will either segfault or doesn't work with old bash versions
		outln
		debugme echo $none

		if [ "$none" -eq 0 ] ; then
			 pr_brown "no PFS ciphers found"
			 ret=1
		else
			 ret=0
		fi
	fi
	tmpfile_handle $FUNCNAME.txt
	return $ret
}


# https://en.wikipedia.org/wiki/Transport_Layer_Security#RC4_attacks
# http://blog.cryptographyengineering.com/2013/03/attack-of-week-rc4-is-kind-of-broken-in.html
# new ietf rfc is very strict: https://tools.ietf.org/html/rfc7465
rc4() {
	outln
	pr_blue "--> Checking RC4 Ciphers" ; outln
	$OPENSSL ciphers -V 'RC4:@STRENGTH' >$TMPFILE 
	[ $SHOW_LOC_CIPH = "1" ] && echo "local ciphers available for testing RC4:" && echo `cat $TMPFILE`
	$OPENSSL s_client -cipher `$OPENSSL ciphers RC4` $STARTTLS -connect $NODEIP:$PORT $SNI &>/dev/null </dev/null
	if [ $? -eq 0 ]; then
		pr_literedln "\nRC4 is broken and is offered! Now testing specific ciphers..."; 
		outln "(for legacy support e.g. IE6 rather consider x13 or x0a)\n"
		bad=1
		neat_header
		while read hexcode n ciph sslvers kx auth enc mac; do
			$OPENSSL s_client -cipher $ciph $STARTTLS -connect $NODEIP:$PORT $SNI </dev/null &>/dev/null
			ret=$?
			if [ $ret -ne 0 ] && [ "$SHOW_EACH_C" -eq 0 ] ; then
				continue # no successful connect AND not verbose displaying each cipher
			fi
			normalize_ciphercode $hexcode
			neat_list $HEXC $ciph $kx $enc $strength
			if [ "$SHOW_EACH_C" -ne 0 ]; then
				if [ $ret -eq 0 ]; then
					pr_litered "available"
				else
					out "not a/v"
				fi
			else
				bad=1
				out
			fi
			outln
		done < $TMPFILE
		#    ^^^^^ posix redirect as shopt will either segfault or doesn't work with old bash versions
		outln
	else
		outln
		pr_litegreenln "no RC4 ciphers detected (OK)"
		bad=0
	fi

	tmpfile_handle $FUNCNAME.txt
	return $bad
}


# good source for configuration and bugs: https://wiki.mozilla.org/Security/Server_Side_TLS
# good start to read: http://en.wikipedia.org/wiki/Transport_Layer_Security#Attacks_against_TLS.2FSSL


lucky13() {
#FIXME: to do
# CVE-2013-0169
# in a nutshell: don't offer CBC suites (again). MAC as a fix for padding oracles is not enough
# best: TLS v1.2+ AES GCM
	echo "FIXME"
	echo
}


spdy_pre(){
	if [ "x$STARTTLS" != "x" ]; then
		[[ $DEBUG -ge 2 ]] && outln "SPDY doesn't work with !HTTP"
		return 1
	fi
	# first, does the current openssl support it?
	$OPENSSL s_client help 2>&1 | grep -qw nextprotoneg
	if [ $? -ne 0 ]; then
		pr_magenta "Local problem: $OPENSSL doesn't support SPDY"; outln
		return 7
	fi
	return 0
}

spdy() {
	out " SPDY/NPN   "
	spdy_pre || return 0
	$OPENSSL s_client -host $NODE -port $PORT -nextprotoneg $NPN_PROTOs </dev/null 2>/dev/null >$TMPFILE
	if [ $? -eq 0 ]; then
		# we need -a here 
		tmpstr=`grep -a '^Protocols' $TMPFILE | sed 's/Protocols.*: //'`
		if [ -z "$tmpstr" -o "$tmpstr" = " " ] ; then
			out "not offered"
			ret=1
		else
			# now comes a strange thing: "Protocols advertised by server:" is empty but connection succeeded
			if echo $tmpstr | egrep -q "spdy|http" ; then
				pr_bold "$tmpstr" ; out " (advertised)"
				ret=0
			else
				pr_litemagenta "please check manually, response from server was ambigious ..."
				ret=10
			fi
		fi
	else
		pr_litemagenta "handshake failed"
		ret=2
	fi
	outln
	# btw: nmap can do that too http://nmap.org/nsedoc/scripts/tls-nextprotoneg.html
	# nmap --script=tls-nextprotoneg #NODE -p $PORT is your friend if your openssl doesn't want to test this
	tmpfile_handle $FUNCNAME.txt
	return $ret
}

fd_socket() {
# arg doesn't work here
	if ! exec 5<> /dev/tcp/$NODEIP/$PORT; then
		pr_magenta "`basename $0`: unable to open a socket to $NODEIP:$PORT"
		return 6
	fi
	return 0
}

close_socket(){
	exec 5<&-
	exec 5>&-
	return 0
}

## old network code ^^^^^^


### new funcs for network follow

socksend_clienthello() {
	code2network "$SSLv2_CLIENT_HELLO"
	data=`echo $NW_STR`
	[[ "$DEBUG" -ge 3 ]] && echo "\"$data\""
	printf -- "$data" >&5 2>/dev/null &
	sleep $USLEEP_SND
}

sockread_serverhello() {
     [[ "x$2" = "x" ]] && maxsleep=$MAX_WAITSOCK || maxsleep=$2
     ret=0

     SOCK_REPLY_FILE=`mktemp $TEMPDIR/ddreply.XXXXXX` || exit 7
     dd bs=$1 of=$SOCK_REPLY_FILE count=1 <&5 2>/dev/null &
     pid=$!

     while true; do
          if ! ps ax | grep -v grep | grep -q $pid; then
               break  # didn't reach maxsleep yet
               kill $pid >&2 2>/dev/null
          fi
          sleep $USLEEP_REC
          maxsleep=$(($maxsleep - 1))
          [[ $maxsleep -le 0 ]] && break
     done

     if ps $pid 2>&1 >/dev/null; then
          # time's up and dd is still alive --> timeout
          kill $pid >&2 2>/dev/null
          wait $pid 2>/dev/null
          ret=3 # means killed
     fi

     return $ret
}

# arg1: name of file with socket reply
display_sslv2serverhello() {
# server hello:									in hex representation, see below
# byte 1+2: length of server hello						0123
# 3:        04=Handshake message, server hello			45
# 4:        session id hit or not (boolean: 00=false, this  67
#           is the normal case)						
# 5:        certificate type, 01 = x509					89
# 6+7       version (00 02 = SSLv2)					10-13
# 8+9       certificate length						14-17
# 10+11     cipher spec length						17-20
# 12+13     connection id length						
# [certificate length] ==> certificate				
# [cipher spec length] ==> ciphers GOOD: HERE ARE ALL CIPHERS ALREADY!

	v2_hello_ascii=`hexdump -v -e '16/1 "%02X"' $1`
	[[ "$DEBUG" -ge 4 ]] && echo $v2_hello_ascii 	# one line without any blanks
	if [[ -z $v2_hello_ascii ]] ; then
		ret=0								# no server hello received
		debugme echo "server hello empty"
	else
		# now scrape two bytes out of the reply per byte
		v2_hello_initbyte="${v2_hello_ascii:0:1}"  # normally this belongs to the next, should be 8!
		v2_hello_length="${v2_hello_ascii:1:3}"  # + 0x8000 see above
		v2_hello_handshake="${v2_hello_ascii:4:2}"
		v2_hello_cert_length="${v2_hello_ascii:14:4}"
		v2_hello_cipherspec_length="${v2_hello_ascii:18:4}"

		if [[ $v2_hello_initbyte != "8" ]] || [[ $v2_hello_handshake != "04" ]]; then
			[[ $DEBUG -ge 2 ]] && echo "$v2_hello_initbyte / $v2_hello_handshake"
			ret=1
		fi

		if [[ $DEBUG -ge 3 ]]; then
			echo "SSLv2 server hello length: 0x0$v2_hello_length"
			echo "SSLv2 certificate length:  0x$v2_hello_cert_length"
			echo "SSLv2 cipher spec length:  0x$v2_hello_cipherspec_length"
		fi

		V2_HELLO_CIPHERSPEC_LENGTH=`printf "%d\n" "0x$v2_hello_cipherspec_length" 2>/dev/null`
		[ $? -ne 0 ] && ret=7
	fi
	return $ret
}


# arg1: name of file with socket reply
display_tls_serverhello() {
	# server hello:					
	# byte 0:     0x16=TLS, 0x15= TLS alert
	# byte 1+2:   03, TLS version			
	# byte 3+4:   length all				
	# byte 5:     handshake type (2=hello)    TLS alert: level (2=fatal), descr (0x28=handshake failure)
	# byte 6+7+8: length server hello       
	# byte 9+10:  03, TLS version           (00: SSLv3, 01: TLS 1.0, 02: TLS 1.1, 03: TLS 1.2)
	# byte 11-14: TLS timestamp
	# byte 15-42: random 	 		(28 bytes)
	# byte 43   : session id length
	# byte 44+45+sid-len:  cipher suite!
	# byte 46+sid-len:     compression method:  00: none, 01: deflate
	# byte 47+48+sid-len:  extension length

	tls_hello_ascii=`hexdump -v -e '16/1 "%02X"' $1`
	[[ "$DEBUG" -eq 5 ]] && echo $tls_hello_ascii      # one line without any blanks
	[[ -z $tls_hello_ascii ]] && return 0              # no server hello received

	# now scrape two bytes out of the reply per byte
	tls_hello_initbyte="${tls_hello_ascii:0:2}"  # normally this is x16
	tls_hello_protocol="${tls_hello_ascii:2:4}"
	tls_len_all=`printf "%d\n" ${tls_hello_ascii:6:4}`

	if [[ $tls_hello_initbyte != "16" ]] ; then
		[[ $DEBUG -ge 1 ]] && echo "tls_hello_initbyte:  0x$tls_hello_initbyte"
		if [[ $DEBUG -ge 2 ]]; then
			echo "tls_hello_protocol:  0x$tls_hello_protocol"
			echo "tls_len_all:         $tls_len_all"
			echo "tls_err_level:       ${tls_hello_ascii:10:2}"
			echo "tls_err_descr:       0x${tls_hello_ascii:12:2}"
		fi
		return 1
	fi

	DETECTED_TLS_VERSION=$tls_hello_protocol

	tls_hello="${tls_hello_ascii:10:2}"		# normally this is x02
	tls_hello_protocol2="${tls_hello_ascii:18:4}"
	tls_hello_time="${tls_hello_ascii:22:8}"
	tls_time=`printf "%d\n" 0x$tls_hello_time`
	tls_time=`date --date="@$tls_time" "+%Y-%m-%d %r"`
	tls_sid_len=`printf "%d\n" 0x${tls_hello_ascii:86:2}`
	let sid_offset=88+$tls_sid_len*2
	tls_cipher_suite="${tls_hello_ascii:$sid_offset:4}"
	let sid_offset=92+$tls_sid_len*2
	tls_compression_method="${tls_hello_ascii:$sid_offset:2}"

	if [[ $DEBUG -ge 2 ]]; then

		echo "tls_hello_initbyte:  0x$tls_hello_initbyte"
		echo "tls_hello:           0x$tls_hello"
		echo "tls_hello_protocol:  0x$tls_hello_protocol"
		if [[ $DEBUG -ge 4 ]]; then
			echo "tls_hello_protocol2: 0x$tls_hello_protocol2"
			echo "tls_len_all:         $tls_len_all"
			echo "tls_sid_len:         $tls_sid_len"
		fi
		echo "tls_hello_time:      0x$tls_hello_time ($tls_time)"
		echo "tls_cipher_suite:    0x$tls_cipher_suite"
		echo "tls_compression_method: 0x$tls_compression_method"
	fi

	return 0
}


# helper function for protocol checks
# arg1: formatted string here in the code
code2network() {
	NW_STR=`echo "$1" | sed -e 's/,/\\\x/g' | sed -e 's/# .*$//g' -e 's/ //g' -e '/^$/d' | tr -d '\n' | tr -d '\t'`
}

len2twobytes() {
     len_arg1=`echo ${#1}`
     [[ $len_arg1 -le 2 ]] && LEN_STR=`printf "00, %02s \n" $1`
     [[ $len_arg1 -eq 3 ]] && LEN_STR=`printf "%02s, %02s \n" ${1:0:1} ${1:1:2}`
     [[ $len_arg1 -eq 4 ]] && LEN_STR=`printf "%02s, %02s \n" ${1:0:2} ${1:2:2}`
}


sslv2_sockets() {
	V2_HELLO_CIPHERSPEC_LENGTH=0	# initialize
	USLEEP_REC=${USLEEP_REC:-0.2}
	USLEEP_SND=${USLEEP_SND:-0.1}	# 1 second wait until otherwise specified
	SOCK_REPLY_FILE=""			# we do this with a file here. At a certain point heartbleed and ccs needs to be changed and make use of code2network
	NW_STR=""

	out " SSLv2      ";

	# SSLV2 chello:
	SSLv2_CLIENT_HELLO="
	,80,34    # length (here: 52)
	,01       # Client Hello 
	,00,02    # SSLv2
	,00,1b    # cipher spec length (here: 27 )
	,00,00    # session ID length
	,00,10    # challenge length
	,05,00,80 # 1st cipher	9 cipher specs, only classical V2 ciphers are used here, see  http://max.euston.net/d/tip_sslciphers.html
	,03,00,80 # 2nd          there are v3 in v2!!! : https://tools.ietf.org/html/rfc6101#appendix-E
	,01,00,80 # 3rd          Cipher specifications introduced in version 3.0 can be included in version 2.0 client hello messages using
	,07,00,c0 # 4th          the syntax below. [..] # V2CipherSpec (see Version 3.0 name) = { 0x00, CipherSuite }; !!!!
	,08,00,80 # 5th
	,06,00,40 # 6th
	,04,00,80 # 7th
	,02,00,80 # 8th
	,00,00,00 # 9th
	,29,22,be,b3,5a,01,8b,04,fe,5f,80,03,a0,13,eb,c4" # Challenge

	fd_socket 5 || return 6

	[[ "$DEBUG" -ge 2 ]] && out "sending client hello... "
	socksend_clienthello 

	sockread_serverhello 32768 0
	[[ "$DEBUG" -ge 2 ]] && out "reading server hello... "
	if [[ "$DEBUG" -eq 3 ]]; then
		hexdump -C $SOCK_REPLY_FILE | head -6
		outln
	fi

	display_sslv2serverhello "$SOCK_REPLY_FILE"
	if [ $? -eq 7 ]; then
		# strange reply
		pr_litemagenta "strange v2 reply "
		outln " (rerun with DEBUG=2)"
		[[ $DEBUG -ge 2 ]] && hexdump -C $SOCK_REPLY_FILE | head -1
	else
		# see https://secure.wand.net.nz/trac/libprotoident/wiki/SSL
		lines=`cat "$SOCK_REPLY_FILE" 2>/dev/null | hexdump -C | wc -l` 
		[[ "$DEBUG" -ge 2 ]] && out "  ($lines lines)  "

		if [[ "$lines" -gt 1 ]] ;then
			ciphers_detected=$(($V2_HELLO_CIPHERSPEC_LENGTH / 3 ))
			if [ 0 -eq $ciphers_detected ] ; then
				pr_litered "supported but couldn't detect a cipher"; outln "(may need debugging)"
			else
				pr_red "offered (NOT ok)"; outln " -- $ciphers_detected ciphers"
			fi
			ret=1
		else
			pr_greenln "not offered (OK)"
			ret=0
		fi
	fi
	pr_off

	close_socket
	TMPFILE=$SOCK_REPLY_FILE
	tmpfile_handle $FUNCNAME.dd
	return $ret
}


#for tls_low_byte in "00" "01" "02" "03"; do
tls_sockets() {
	SN_HEX=""
	LEN_SN_HEX=0
	COL_WIDTH=32
	USLEEP_REC=${USLEEP_REC:-0.2}
	USLEEP_SND=${USLEEP_SND:-0.1}	# 1 second wait until otherwise specified
	MAX_WAITSOCK=2
	SOCK_REPLY_FILE=""
	NW_STR=""
	LEN_STR=""
	DETECTED_TLS_VERSION=""

	# 133 cipher: spdy, TLS 1.2
	TLS12_CIPHER="
	cc, 14, cc, 13, cc, 15, c0, 30, c0, 2c, c0, 28, c0, 24, c0, 14,
	c0, 0a, c0, 22, c0, 21, c0, 20, 00, a5, 00, a3, 00, a1, 00, 9f,
	00, 6b, 00, 6a, 00, 69, 00, 68, 00, 39, 00, 38, 00, 37, 00, 36,
	c0, 77, c0, 73, 00, c4, 00, c3, 00, c2, 00, c1, 00, 88, 00, 87,
	00, 86, 00, 85, c0, 32, c0, 2e, c0, 2a, c0, 26, c0, 0f, c0, 05,
	c0, 79, c0, 75, 00, 9d, 00, 3d, 00, 35, 00, c0, 00, 84, c0, 2f,
	c0, 2b, c0, 27, c0, 23, c0, 13, c0, 09, c0, 1f, c0, 1e, c0, 1d,
	00, a4, 00, a2, 00, a0, 00, 9e, 00, 67, 00, 40, 00, 3f, 00, 3e,
	00, 33, 00, 32, 00, 31, 00, 30, c0, 76, c0, 72, 00, be, 00, bd,
	00, bc, 00, bb, 00, 9a, 00, 99, 00, 98, 00, 97, 00, 45, 00, 44,
	00, 43, 00, 42, c0, 31, c0, 2d, c0, 29, c0, 25, c0, 0e, c0, 04,
	c0, 78, c0, 74, 00, 9c, 00, 3c, 00, 2f, 00, ba, 00, 96, 00, 41,
	00, 07, c0, 11, c0, 07, 00, 66, c0, 0c, c0, 02, 00, 05, 00, 04,
	c0, 12, c0, 08, c0, 1c, c0, 1b, c0, 1a, 00, 16, 00, 13, 00, 10,
	00, 0d, c0, 0d, c0, 03, 00, 0a, 00, 63, 00, 15, 00, 12, 00, 0f,
	00, 0c, 00, 62, 00, 09, 00, 65, 00, 64, 00, 14, 00, 11, 00, 0e,
	00, 0b, 00, 08, 00, 06, 00, 03, 00, ff"

	# 76 cipher for SSLv3, TLS 1, TLS 1.1:
	TLS_CIPHER="
	c0, 14, c0, 0a, c0, 22, c0, 21, c0, 20, 00, 39, 00, 38, 00, 37,
	00, 36, 00, 88, 00, 87, 00, 86, 00, 85, c0, 0f, c0, 05, 00, 35,
	00, 84, c0, 13, c0, 09, c0, 1f, c0, 1e, c0, 1d, 00, 33, 00, 32,
	00, 31, 00, 30, 00, 9a, 00, 99, 00, 98, 00, 97, 00, 45, 00, 44,
	00, 43, 00, 42, c0, 0e, c0, 04, 00, 2f, 00, 96, 00, 41, 00, 07,
	c0, 11, c0, 07, 00, 66, c0, 0c, c0, 02, 00, 05, 00, 04, c0, 12,
	c0, 08, c0, 1c, c0, 1b, c0, 1a, 00, 16, 00, 13, 00, 10, 00, 0d,
	c0, 0d, c0, 03, 00, 0a, 00, 63, 00, 15, 00, 12, 00, 0f, 00, 0c,
	00, 62, 00, 09, 00, 65, 00, 64, 00, 14, 00, 11, 00, 0e, 00, 0b,
	00, 08, 00, 06, 00, 03, 00, ff" 

#formatted example for SNI
#00 00 	# extention server_name
#00 1a    # length       			= the following +2 = server_name length + 5
#00 18    # server_name list_length	= server_name length +3
#00 		# server_name type (hostname)
#00 15 	# server_name length
#66 66 66 66 66 66 2e 66 66 66 66 66 66 66 66 66 66 2e 66 66 66  target.mydomain1.tld # server_name target



# arg1: TLS_VER_LSB
# arg2: CIPHER_SUITES string
# arg3: SERVERNAME
# ??? more extensions?

	len_sni=`echo ${#3}`
	#tls_ver=printf "%02x\n" $1"

	code2network "$2"
	cipher_suites="$NW_STR"	# we don't have the leading \x here so string length is two byte less, see next

	# convert length's from dec to hex:
	hex_len_sn_hex=`printf "%02x\n" $LEN_SN_HEX`
	hex_len_sn_hex3=`printf "%02x\n" $((LEN_SN_HEX+3))`
	hex_len_sn_hex5=`printf "%02x\n" $((LEN_SN_HEX+5))`
	hex_len_extention=`printf "%02x\n" $((LEN_SN_HEX+9))`
	
	len_ciph_suites_byte=`echo ${#cipher_suites}`
	let "len_ciph_suites_byte += 2"

	# we have additional 2 chars \x in each 2 byte string and 2 byte ciphers, so we need to divide by 4:
	len_ciph_suites=`printf "%02x\n" $(($len_ciph_suites_byte / 4 ))`
	len2twobytes "$len_ciph_suites"
	len_ciph_suites_word="$LEN_STR"
	[[ $DEBUG -ge 4 ]] && echo $len_ciph_suites_word

	len2twobytes `printf "%02x\n" $((0x$len_ciph_suites + 0x27 + 0x$hex_len_extention + 0x2))`
	#len2twobytes `printf "%02x\n" $((0x$len_ciph_suites + 0x27))`
	len_c_hello_word="$LEN_STR"
	[[ $DEBUG -ge 4 ]] && echo $len_c_hello_word

	len2twobytes `printf "%02x\n" $((0x$len_ciph_suites + 0x2b + 0x$hex_len_extention + 0x2))`
	#len2twobytes `printf "%02x\n" $((0x$len_ciph_suites + 0x2b))`
	len_all_word="$LEN_STR"
	[[ $DEBUG -ge 4 ]] && echo $len_all_word

	TLS_CLIENT_HELLO="
	# TLS header ( 5 bytes)
	,16, 03, $1            # TLS Version
	,$len_all_word          # Length  <---
	# Handshake header:
	,01                     # Type (x01 for ClientHello)
	,00, $len_c_hello_word  # Length ClientHello
	,03, $1                 # TLS Version (again)
	,54, 51, 1e, 7a         # Unix time since  see www.moserware.com/2009/06/first-few-milliseconds-of-https.html
	,de, ad, be, ef         # Random 28 bytes
	,31, 33, 07, 00, 00, 00, 00, 00
	,cf, bd, 39, 04, cc, 16, 0a, 85
	,03, 90, 9f, 77, 04, 33, d4, de
	,00                     # Session ID length
	,$len_ciph_suites_word  # Cipher suites length
	# Cipher suites 
	,$cipher_suites
	,01                     # Compression methods length
	,00"                    # Compression method (x00 for NULL)

	EXTENSION_CONTAINING_SNI="
	,00, $hex_len_extention  # first the len of all (here: 1) extentions. We assume len(hostname) < FF - 9
	,00, 00                  # extention server_name
	,00, $hex_len_sn_hex5    # length SNI EXT
	,00, $hex_len_sn_hex3    # server_name list_length
	,00                      # server_name type (hostname)
	,00, $hex_len_sn_hex     # server_name length
	,$SN_HEX"                # server_name target

	fd_socket 5 || return 6

	code2network "$TLS_CLIENT_HELLO$EXTENSION_CONTAINING_SNI"
	#code2network "$TLS_CLIENT_HELLO"
	data=`echo $NW_STR`

	[[ "$DEBUG" -ge 2 ]] && printf "sending client hello..."
	if [[ "$tls_low_byte" == "03" ]] ; then
		socksend_clienthello $tls_low_byte "$TLS12_CIPHER" $SNIHEX
	else
		socksend_clienthello $tls_low_byte "$TLS_CIPHER" $SNIHEX
	fi

	sockread_serverhello 32768 0
	[[ "$DEBUG" -ge 2 ]] && printf "reading server hello..."
	if [[ "$DEBUG" -ge 3 ]]; then
		hexdump -C $SOCK_REPLY_FILE | head -6
		echo
	fi

	display_tls_serverhello "$SOCK_REPLY_FILE"
	ret=$?

	# see https://secure.wand.net.nz/trac/libprotoident/wiki/SSL
	lines=`cat "$SOCK_REPLY_FILE" 2>/dev/null | hexdump -C | wc -l` 
	[[ "$DEBUG" -ge 2 ]] && out "  (returned $lines lines)  " 

#	case $tls_low_byte in
#		00) tls_str="SSLv3" ;;
#		01) tls_str="TLS 1" ;;
#		02) tls_str="TLS 1.1" ;;
#		03) tls_str="TLS 1.2" ;;
#	esac

#	printf "Protokoll "; tput bold; printf "$tls_low_byte = $tls_str"; tput sgr0; printf ":  "

	if [[ $ret -eq 1 ]] || [[ $lines -eq 1 ]] ; then
		outln "NOT available"
		ret=1
	else
		if [[ 03$tls_low_byte -eq $DETECTED_TLS_VERSION ]]; then
			outln "available"
			ret=0
		else
			out "NOT available "
			[[ $DEBUG -ge 2 ]] && echo -n "send: 0x03$tls_low_byte, returned: 0x$DETECTED_TLS_VERSION" 
			echo
		fi
	fi


	close_socket
	TMPFILE=$SOCK_REPLY_FILE
	tmpfile_handle $FUNCNAME.dd
	return $ret
}



ok_ids(){
	greenln "\n ok -- something resetted our ccs packets"
	return 0
}


ccs_injection(){
	# see https://www.openssl.org/news/secadv_20140605.txt
	# mainly adapted from Ramon de C Valle's C code from https://gist.github.com/rcvalle/71f4b027d61a78c42607
	pr_bold " CCS "; out " (CVE-2014-0224), experimental        "

	$OPENSSL s_client $STARTTLS -connect $NODEIP:$PORT &>$TMPFILE </dev/null

	tls_proto_offered=`grep -w Protocol $TMPFILE | sed -E 's/[^[:digit:]]//g'`
	#tls_proto_offered=`grep -w Protocol $TMPFILE | sed 's/^.*Protocol//'`
	case $tls_proto_offered in
		12)	tls_hexcode="x03, x03" ;;
		11)	tls_hexcode="x03, x02" ;;
		*) tls_hexcode="x03, x01" ;;
	esac
	ccs_message=", x14, $tls_hexcode ,x00, x01, x01"

	client_hello="
	# TLS header (5 bytes)
	,x16,               # content type (x16 for handshake)
	$tls_hexcode,       # TLS version
	x00, x93,           # length
	# Handshake header
	x01,                # type (x01 for ClientHello)
	x00, x00, x8f,      # length
	$tls_hexcode,       # TLS version
	# Random (32 byte) 
	x53, x43, x5b, x90, x9d, x9b, x72, x0b,
	xbc, x0c, xbc, x2b, x92, xa8, x48, x97,
	xcf, xbd, x39, x04, xcc, x16, x0a, x85,
	x03, x90, x9f, x77, x04, x33, xd4, xde,
	x00,                # session ID length
	x00, x68,           # cipher suites length
	# Cipher suites (51 suites)
	xc0, x13, xc0, x12, xc0, x11, xc0, x10,
	xc0, x0f, xc0, x0e, xc0, x0d, xc0, x0c,
	xc0, x0b, xc0, x0a, xc0, x09, xc0, x08,
	xc0, x07, xc0, x06, xc0, x05, xc0, x04,
	xc0, x03, xc0, x02, xc0, x01, x00, x39,
	x00, x38, x00, x37, x00, x36, x00, x35, x00, x34,
	x00, x33, x00, x32, x00, x31, x00, x30,
	x00, x2f, x00, x16, x00, x15, x00, x14,
	x00, x13, x00, x12, x00, x11, x00, x10,
	x00, x0f, x00, x0e, x00, x0d, x00, x0c,
	x00, x0b, x00, x0a, x00, x09, x00, x08,
	x00, x07, x00, x06, x00, x05, x00, x04,
	x00, x03, x00, x02, x00, x01, x01, x00"

	fd_socket 5 || return 6

	[[ $DEBUG -ge 2 ]] && out "\nsending client hello, "
	socksend "$client_hello" 1
	sockread 16384 

	[[ $DEBUG -ge 2 ]] && outln "\nreading server hello"
	if [[ $DEBUG -ge 3 ]]; then
		echo "$SOCKREPLY" | "${HEXDUMPVIEW[@]}" | head -20
		outln "[...]"
		outln "\npayload #1 with TLS version $tls_hexcode:"
	fi

	socksend "$ccs_message" 1 || ok_ids
	sockread 2048 5		# 5 seconds
	if [[ $DEBUG -ge 3 ]]; then
		outln "\n1st reply: " 
		out "$SOCKREPLY" | "${HEXDUMPVIEW[@]}" | head -20
# ok:      15 | 0301 | 02 | 02 0a == ALERT | TLS 1.0 | Length=2 | Unexpected Message (0a)
		outln
		outln "payload #2 with TLS version $tls_hexcode:"
	fi

	socksend "$ccs_message" 2 || ok_ids
	sockread 2048 5
	retval=$?

	if [[ $DEBUG -ge 3 ]]; then
		outln "\n2nd reply: "
		out "$SOCKREPLY" | "${HEXDUMPVIEW[@]}"
# not ok:  15 | 0301 | 02 | 02 | 15 == ALERT | TLS 1.0 | Length=2 | Decryption failed (21)
# ok:  0a or nothing: ==> RST
		outln
	fi

	reply_sanitized=`echo "$SOCKREPLY" | "${HEXDUMPPLAIN[@]}" | sed 's/^..........//'`
	lines=`echo "$SOCKREPLY" | "${HEXDUMP[@]}" | wc -l`

	if [ "$reply_sanitized" == "0a" ] || [ "$lines" -gt 1 ] ; then
		pr_green "not vulnerable (OK)"
		ret=0
	else
		pr_red "VULNERABLE (not OK)"
		ret=1
	fi
	[ $retval -eq 3 ] && out "(timed out)"
	outln 

	close_socket
	tmpfile_handle $FUNCNAME.txt
	return $ret
}

heartbleed(){
	pr_bold " Heartbleed\c"; out " (CVE-2014-0160)                "
	# mainly adapted from https://gist.github.com/takeshixx/10107280

	# determine TLS versions available:
	$OPENSSL s_client $STARTTLS -connect $NODEIP:$PORT -tlsextdebug &>$TMPFILE </dev/null
		
	tls_proto_offered=`grep -w Protocol $TMPFILE | sed -E 's/[^[:digit:]]//g'`
	case $tls_proto_offered in
		12)	tls_hexcode="x03, x03" ;;
		11)	tls_hexcode="x03, x02" ;;
		*) tls_hexcode="x03, x01" ;;
	esac
	heartbleed_payload=", x18, $tls_hexcode, x00, x03, x01, x40, x00"

	client_hello="
	# TLS header ( 5 bytes)
	,x16,                      # content type (x16 for handshake)
	$tls_hexcode,              # TLS version
	x00, xdc,                  # length
	# Handshake header
	x01,                       # type (x01 for ClientHello)
	x00, x00, xd8,             # length
	$tls_hexcode,              # TLS version
	# Random (32 byte)
	x53, x43, x5b, x90, x9d, x9b, x72, x0b,
	xbc, x0c, xbc, x2b, x92, xa8, x48, x97,
	xcf, xbd, x39, x04, xcc, x16, x0a, x85,
	x03, x90, x9f, x77, x04, x33, xd4, xde,
	x00,                       # session ID length
	x00, x66,                  # cipher suites length
						  # cipher suites (51 suites)
	xc0, x14, xc0, x0a, xc0, x22, xc0, x21,
	x00, x39, x00, x38, x00, x88, x00, x87,
	xc0, x0f, xc0, x05, x00, x35, x00, x84,
	xc0, x12, xc0, x08, xc0, x1c, xc0, x1b,
	x00, x16, x00, x13, xc0, x0d, xc0, x03,
	x00, x0a, xc0, x13, xc0, x09, xc0, x1f,
	xc0, x1e, x00, x33, x00, x32, x00, x9a,
	x00, x99, x00, x45, x00, x44, xc0, x0e,
	xc0, x04, x00, x2f, x00, x96, x00, x41,
	xc0, x11, xc0, x07, xc0, x0c, xc0, x02,
	x00, x05, x00, x04, x00, x15, x00, x12,
	x00, x09, x00, x14, x00, x11, x00, x08,
	x00, x06, x00, x03, x00, xff,
	x01,                       # compression methods length
	x00,                       # compression method (x00 for NULL)
	x00, x49,                  # extensions length
	# extension: ec_point_formats
	x00, x0b, x00, x04, x03, x00, x01, x02,
	# extension: elliptic_curves
	x00, x0a, x00, x34, x00, x32, x00, x0e,
	x00, x0d, x00, x19, x00, x0b, x00, x0c,
	x00, x18, x00, x09, x00, x0a, x00, x16,
	x00, x17, x00, x08, x00, x06, x00, x07,
	x00, x14, x00, x15, x00, x04, x00, x05,
	x00, x12, x00, x13, x00, x01, x00, x02,
	x00, x03, x00, x0f, x00, x10, x00, x11,
	# extension: session ticket TLS
	x00, x23, x00, x00,
	# extension: heartbeat
	x00, x0f, x00, x01, x01"

	fd_socket 5 || return 6

	[[ $DEBUG -ge 2 ]] && outln "\nsending client hello (TLS version $tls_hexcode)"
	socksend "$client_hello" 1
	sockread 16384 

	[[ $DEBUG -ge 2 ]] && outln "\nreading server hello"
	if [[ $DEBUG -ge 3 ]]; then
		echo "$SOCKREPLY" | "${HEXDUMPVIEW[@]}" | head -20
		outln "[...]"
		outln "\nsending payload with TLS version $tls_hexcode:"
	fi

	socksend "$heartbleed_payload" 1
	sockread 16384
	retval=$?

	if [[ $DEBUG -ge 3 ]]; then
		outln "\nheartbleed reply: "
		echo "$SOCKREPLY" | "${HEXDUMPVIEW[@]}"
		outln
	fi

	lines_returned=`echo "$SOCKREPLY" | "${HEXDUMP[@]}" | wc -l`
	if [ $lines_returned -gt 1 ]; then
		pr_red "VULNERABLE"
		ret=1
	else
		pr_green "not vulnerable (OK)"
		ret=0
	fi
	[ $retval -eq 3 ] && out "(timed out)"
	outln 

	close_socket
	tmpfile_handle $FUNCNAME.txt
	return $ret
}


# This tests for CVE-2009-3555 / RFC5746, OSVDB: 59968-59974
renego() {
	ADDCMD=""
	case "$OSSL_VER" in
		0.9.8*)  # we need this for Mac OSX unfortunately
			case "$OSSL_VER_APPENDIX" in
				[a-l])
					pr_magenta "Your $OPENSSL $OSSL_VER cannot test the secure renegotiation vulnerability"
					return 3 ;;
				[m-z])
					# all ok ;;
			esac ;;
		1.0.1*|1.0.2*)
			ADDCMD="-legacy_renegotiation" ;;
		0.9.9*|1.0*)
			# all ok ;;
	esac
	pr_bold " Secure Client-Initiated Renegotiation     "	# RFC 5746, community.qualys.com/blogs/securitylabs/2011/10/31/tls-renegotiation-and-denial-of-service-attacks
	echo R | $OPENSSL s_client $ADDCMD $STARTTLS -connect $NODEIP:$PORT $SNI &>$TMPFILE
	reneg_ok=$?									# 0=client is renegotiating and does not get an error: vuln to DoS via client initiated renegotiation
	case $reneg_ok in
		0) pr_litered "VULNERABLE (NOT ok)"; outln ", DoS threat" ;;
		1) pr_litegreenln "not vulnerable (OK)" ;;
		*) outln "FIXME: $reneg_ok" ;;
	esac

	pr_bold " Renegotiation "; out "(CVE 2009-3555)             "
	NEG_STR="Secure Renegotiation IS NOT"
	echo "R" | $OPENSSL s_client $STARTTLS -connect $NODEIP:$PORT $SNI 2>&1 | grep -iq "$NEG_STR"
	secreg=$?						# 0= Secure Renegotiation IS NOT supported
	case $secreg in
		0) pr_redln "VULNERABLE (NOT ok)" ;;
		1) pr_greenln "not vulnerable (OK)" ;;
		*) outln "FIXME: $secreg" ;;
	esac

	tmpfile_handle $FUNCNAME.txt
	return $secreg
	# https://community.qualys.com/blogs/securitylabs/2009/11/05/ssl-and-tls-authentication-gap-vulnerability-discovered
}

crime() {
	# in a nutshell: don't offer TLS/SPDY compression on the server side
	# 
	# This tests for CRIME Vulnerability (www.ekoparty.org/2012/juliano-rizzo.php) on HTTPS, not SPDY (yet)
     # Please note that it is an attack where you need client side control, so in regular situations this
	# means anyway "game over", w/wo CRIME
	# www.h-online.com/security/news/item/Vulnerability-in-SSL-encryption-is-barely-exploitable-1708604.html
	#

	ADDCMD=""
	case "$OSSL_VER" in
		# =< 0.9.7 was weeded out before
		0.9.8)
			ADDCMD="-no_ssl2" ;;
		0.9.9*|1.0*)
		;;
	esac

	pr_bold " CRIME, TLS " ; out "(CVE-2012-4929)                "

	# first we need to test whether OpenSSL binary has zlib support
	$OPENSSL zlib -e -a  -in /dev/stdin &>/dev/stdout </dev/null | grep -q zlib 
	if [ $? -eq 0 ]; then
		pr_magentaln "Local Problem: Your $OPENSSL lacks zlib support"
		return 7  
	fi

	#STR=`$OPENSSL s_client $ADDCMD $STARTTLS -connect $NODEIP:$PORT $SNI 2>&1 </dev/null | grep Compression `
	$OPENSSL s_client $ADDCMD $STARTTLS -connect $NODEIP:$PORT $SNI </dev/null &>$TMPFILE
	if grep Compression $TMPFILE | grep -q NONE >/dev/null; then
		pr_green "not vulnerable (OK)"
		[[ $SERVICE == "HTTP" ]] || out " (not using HTTP anyway)"
		ret=0
	else
		if [[ $SERVICE == "HTTP" ]]; then
			pr_red "VULNERABLE (NOT ok)"
		else	 
			pr_brown "VULNERABLE (NOT ok), but not using HTTP: probably no exploit known"
		fi
		ret=1
	fi
	# not clear whether this is a protocol != HTTP as one needs to have the ability to modify the 
	# compression input which is done via javascript in the context of HTTP
	outln

# this needs to be re-done i order to remove the redundant check for spdy

	# weed out starttls, spdy-crime is a web thingy
#	if [ "x$STARTTLS" != "x" ]; then
#		echo
#		return $ret
#	fi

	# weed out non-webports, spdy-crime is a web thingy. there's a catch thoug, you see it?
#	case $PORT in
#		25|465|587|80|110|143|993|995|21)
#		echo
#		return $ret
#	esac

#	$OPENSSL s_client help 2>&1 | grep -qw nextprotoneg
#	if [ $? -eq 0 ]; then
#		$OPENSSL s_client -host $NODE -port $PORT -nextprotoneg $NPN_PROTOs  $SNI </dev/null 2>/dev/null >$TMPFILE
#		if [ $? -eq 0 ]; then
#			echo
#			pr_bold "CRIME Vulnerability, SPDY \c" ; outln "(CVE-2012-4929): \c"

#			STR=`grep Compression $TMPFILE `
#			if echo $STR | grep -q NONE >/dev/null; then
#				pr_green "not vulnerable (OK)"
#				ret=`expr $ret + 0`
#			else
#				pr_red "VULNERABLE (NOT ok)"
#				ret=`expr $ret + 1`
#			fi
#		fi
#	fi
	[ $VERBERR -eq 0 ] && outln "$STR"
	#echo
	tmpfile_handle $FUNCNAME.txt
	return $ret
}

# for appliance which use padding, no fallack needed
tls_poodle() {
	pr_bold " POODLE, SSL"; out " CVE-2014-8730), experimental "
	#FIXME
	echo "#FIXME"
	return 7
}


# Padding Oracle On Downgraded Legacy Encryption, in a nutshell: don't use CBC Ciphers in SSLv3 
ssl_poodle() {
	local ret
	local cbc_ciphers

	pr_bold " POODLE, SSL"; out " (CVE-2014-3566), experimental "
	cbc_ciphers=`$OPENSSL ciphers -v 'ALL:eNULL' | awk '/CBC/ { print $1 }' | tr '\n' ':'`
	debugme echo $cbc_ciphers
	$OPENSSL s_client -ssl3 $STARTTLS -cipher $cbc_ciphers -connect $NODEIP:$PORT $SNI &>$TMPFILE </dev/null
	ret=$?
	[ "$VERBERR" -eq 0 ] && cat $TMPFILE | egrep "error|failure" | egrep -v "unable to get local|verify error"
	if [ $ret -eq 0 ]; then
		pr_litered "VULNERABLE (NOT ok)"; out ", uses SSLv3+CBC (no TLS_FALLBACK_SCSV mitigation tested)"
	else
		pr_green "not vulnerable (OK)"
	fi
	outln 

	tmpfile_handle $FUNCNAME.txt
	return $ret	
}


# freak attack: don't use EXPORT RSA ciphers, see https://freakattack.com/
freak() {
	local ret
	local exportrsa_ciphers
	local addtl_warning=""

	pr_bold " FREAK "; out " (CVE-2015-0204), experimental      "
	no_exportrsa_ciphers=`$OPENSSL ciphers -v 'ALL:eNULL' | egrep "^EXP.*RSA" | wc -l`
	exportrsa_ciphers=`$OPENSSL ciphers -v 'ALL:eNULL' | awk '/^EXP.*RSA/ {print $1}' | tr '\n' ':'`
	debugme echo $exportrsa_ciphers
	# with correct build it should list these 7 ciphers (plus the two latter as SSLv2 ciphers):
	# EXP1024-DES-CBC-SHA:EXP1024-RC4-SHA:EXP-EDH-RSA-DES-CBC-SHA:EXP-DH-RSA-DES-CBC-SHA:EXP-DES-CBC-SHA:EXP-RC2-CBC-MD5:EXP-RC4-MD5
	case $no_exportrsa_ciphers in
		0) 	pr_magentaln "Local problem: your $OPENSSL doesn't have any EXPORT RSA ciphers configured" 
			return 3
			;;
		1,2,3) 
			addtl_warning=" (tested only with $no_exportrsa_ciphers out of 9 ciphers)" ;;
		7,8,9,10,11)
			addtl_warning="";;
		4,5,6) 
			addtl_warning=" (tested with $no_exportrsa_ciphers/9 ciphers)" ;;
	esac
	$OPENSSL s_client $STARTTLS -cipher $exportrsa_ciphers -connect $NODEIP:$PORT $SNI &>$TMPFILE </dev/null
	ret=$?
	[ "$VERBERR" -eq 0 ] && cat $TMPFILE | egrep "error|failure" | egrep -v "unable to get local|verify error"
	if [ $ret -eq 0 ]; then
		pr_red "VULNERABLE (NOT ok)"; out ", uses EXPORT RSA ciphers"
	else
		pr_green "not vulnerable (OK)"; out "$addtl_warning"
	fi
	outln 

	tmpfile_handle $FUNCNAME.txt
	return $ret	
}


#in a nutshell: don't use CBC Ciphers in SSLv3 TLSv1.0
# Browser Exploit Against SSL/TLS
beast(){
	local hexcode dash cbc_cipher sslvers kx auth enc mac export
	local detected_proto
	local detected_cbc_cipher=""
	local higher_proto_supported=""
	local -i ret=0
	local spaces="                                           "
	
	pr_bold " BEAST"; out " (CVE-2011-3389)                     "

	# 2) test handfull of common CBC ciphers
	for proto in ssl3 tls1; do
		$OPENSSL s_client -"$proto" $STARTTLS -connect $NODEIP:$PORT $SNI >$TMPFILE 2>/dev/null </dev/null
		if [ $? -ne 0 ]; then
			continue	# protocol no supported, so we do not need to check each cipher with that protocol
		fi
		while read hexcode dash cbc_cipher sslvers kx auth enc mac export ; do
			$OPENSSL s_client -cipher "$cbc_cipher" -"$proto" $STARTTLS -connect $NODEIP:$PORT $SNI >$TMPFILE 2>/dev/null </dev/null
			#normalize_ciphercode $hexcode
			#neat_list $HEXC $ciph $kx $enc | strings | grep -wai "$arg"
			if [ $? -eq 0 ]; then
				detected_cbc_cipher="$detected_cbc_cipher ""$(grep -w "Cipher" $TMPFILE | egrep -vw "New|is" | sed -e 's/^.*Cipher.*://' -e 's/ //g')"
			fi
		done < <($OPENSSL ciphers -V 'ALL:eNULL' | grep CBC)   
		#    ^^^^^ process substitution as shopt will either segfault or doesn't work with old bash versions

		#detected_cbc_cipher=`echo $detected_cbc_cipher | sed 's/ //g'`
		if [ -z "$detected_cbc_cipher" ]; then
			pr_litegreenln "no CBC ciphers for $(echo $proto | tr '[a-z]' '[A-Z]') (OK)"
		else
			detected_cbc_cipher=$(echo "$detected_cbc_cipher" | sed -e 's/ /\n      '"${spaces}"'/9' -e 's/ /\n      '"${spaces}"'/6' -e 's/ /\n      '"${spaces}"'/3')
			[ $ret -eq 1 ] && out "$spaces"
			out "$(echo $proto | tr '[a-z]' '[A-Z]'):"; pr_brownln "$detected_cbc_cipher"
			ret=1
			detected_cbc_cipher=""
		fi
	done

	# 2) support for TLS 1.1+1.2?
	for proto in tls1_1 tls1_2; do
		$OPENSSL s_client -state -"$proto" $STARTTLS -connect $NODEIP:$PORT $SNI 2>/dev/null >$TMPFILE </dev/null
		if [ $? -eq 0 ]; then
			higher_proto_supported="$higher_proto_supported ""$(grep -w "Protocol" $TMPFILE | sed -e 's/^.*Protocol .*://' -e 's/ //g')"
		fi
	done
	if [ $ret -eq 1 ] ; then
		[ ! -z "$higher_proto_supported" ] && outln "$spaces but also supports higher protocols (possible mitigation):$higher_proto_supported"
	fi

#	printf "For a full individual test of each CBC cipher suites support by your $OPENSSL run \"$0 -x CBC $NODE\"\n"

	tmpfile_handle $FUNCNAME.txt
	return $ret
}

youknowwho() {
# CVE-2013-2566, 
# NOT FIXME as there's no code: http://www.isg.rhul.ac.uk/tls/
# http://blog.cryptographyengineering.com/2013/03/attack-of-week-rc4-is-kind-of-broken-in.html
return 0
# in a nutshell: don't use RC4, really not!
}

old_fart() {
	pr_magentaln "Your $OPENSSL $OSSL_VER version is an old fart..."
	pr_magentaln "Get the precompiled bins, it doesn\'t make much sense to proceed"
	exit 3
}

find_openssl_binary() {
# 0. check environment variable whether it's executable
	if [ ! -z "$OPENSSL" ] && [ ! -x "$OPENSSL" ]; then
		pr_redln "\ncannot execute specified ($OPENSSL) openssl binary."
		outln "continuing ..."
	fi
	if [ -x "$OPENSSL" ]; then
# 1. check environment variable
		:
	else
# 2. otherwise try openssl in path of testssl.sh
		OPENSSL=$RUN_DIR/openssl
		if [ ! -x $OPENSSL ] ; then
# 3. with arch suffix
			OPENSSL=$RUN_DIR/openssl.`uname -m`
			if [ ! -x $OPENSSL ] ; then
#4. finally: didn't fiond anything, so we take the one propably from system:
				OPENSSL=`which openssl`
			fi
		fi
	fi

	# http://www.openssl.org/news/openssl-notes.html
	OSSL_VER=`$OPENSSL version | awk -F' ' '{ print $2 }'`
	OSSL_VER_MAJOR=`echo "$OSSL_VER" | sed 's/\..*$//'`
	OSSL_VER_MINOR=`echo "$OSSL_VER" | sed -e 's/^.\.//' | sed 's/\..*.//'`
	OSSL_VER_APPENDIX=`echo "$OSSL_VER" | tr -d '[0-9.]'`
	OSSL_VER_PLATFORM=`$OPENSSL version -p | sed 's/^platform: //'`
	OSSL_BUILD_DATE=`$OPENSSL version -a | grep '^built' | sed -e 's/built on//' -e 's/: ... //' -e 's/: //' -e 's/ UTC//' -e 's/ +0000//' -e 's/.000000000//'`
	echo $OSSL_BUILD_DATE | grep -q "not available" && OSSL_BUILD_DATE="" 
	export OPENSSL OSSL_VER OSSL_BUILD_DATE OSSL_VER_PLATFORM
	case "$OSSL_VER" in
		0.9.7*|0.9.6*|0.9.5*)
			# 0.9.5a was latest in 0.9.5 an released 2000/4/1, that'll NOT suffice for this test
			old_fart ;;
		0.9.8)
			case $OSSL_VER_APPENDIX in
				a|b|c|d|e) old_fart;; # no SNI!
				# other than that we leave this for MacOSX but it's a pain and no guarantees!
			esac
			;;
	esac
	if [ $OSSL_VER_MAJOR -lt 1 ]; then ## mm: Patch for libressl
		outln
		pr_magentaln " ¡¡¡ <Enter> at your own risk !!! $OPENSSL is way too old (< version 1.0)"
		outln " Proceeding may likely result in false negatives or positives\n"
		read a
	fi
	return 0
}


starttls() {
	protocol=`echo "$1" | sed 's/s$//'`	 # strip trailing s in ftp(s), smtp(s), pop3(s), imap(s), ldap(s), telnet(s)
	case "$1" in
		ftp|smtp|pop3|imap|xmpp|telnet|ldap)
			outln " Trying STARTTLS via $(echo $protocol| tr '[a-z]' '[A-Z]')\n"
			$OPENSSL s_client -connect $NODEIP:$PORT $SNI -starttls $protocol </dev/null >$TMPFILE 2>&1
			ret=$?
			if [ $ret -ne 0 ]; then
				pr_bold "Problem: $OPENSSL couldn't establish STARTTLS via $protocol"; outln
				cat $TMPFILE
				return 3
			else
# now, this is lame: normally this should be handled by top level. Then I need to do proper parsing
# of the cmdline e.g. with getopts. 
				STARTTLS="-starttls $protocol"
				export STARTTLS
				runprotocols		; ret=`expr $? + $ret`
				run_std_cipherlists	; ret=`expr $? + $ret`
				server_preference	; ret=`expr $? + $ret`
				server_defaults	; ret=`expr $? + $ret`

				outln; pr_blue "--> Testing specific vulnerabilities" ; outln "\n"
#FIXME: heartbleed + CCS won't work this way yet
#				heartbleed     ; ret=`expr $? + $ret`
#				ccs_injection  ; ret=`expr $? + $ret`
				renego		; ret=`expr $? + $ret`
				crime		; ret=`expr $? + $ret`
				ssl_poodle	; ret=`expr $? + $ret`
				freak		; ret=`expr $? + $ret`
				beast		; ret=`expr $? + $ret`

				rc4			; ret=`expr $? + $ret`
				pfs			; ret=`expr $? + $ret`

				outln
				#cipher_per_proto   ; ret=`expr $? + $ret`
				allciphers		; ret=`expr $? + $ret`
			fi
			;;
		*) pr_litemagentaln "momentarily only ftp, smtp, pop3, imap, xmpp and telnet, ldap allowed" >&2
			ret=2
			;;
	esac
	tmpfile_handle $FUNCNAME.txt
	return $ret
}


help() {
	PRG=`basename $0`
	cat << EOF

$PRG <options>       

    <-h|--help>                           what you're looking at
    <-b|--banner>                         displays banner + version
    <-v|--version>                        same as above
    <-V|--local>                          pretty print all local ciphers
    <-V|--local> pattern                  what local cipher with <pattern> is a/v?

$PRG <options> URI

    <-e|--each-cipher>                    check each local ciphers remotely 
    <-E|-ee|--cipher-per-proto>           check those per protocol
    <-f|--ciphers>                        check cipher suites
    <-p|--protocols>                      check TLS/SSL protocols only
    <-S|--server_defaults>                displays the servers default picks and certificate info
    <-P|--preference>                     displays the servers picks: protocol+cipher
    <-y|--spdy>                           checks for SPDY/NPN
    <-x|--single-ciphers-test> <pattern>  tests matched <pattern> of cipher
    <-B|--heartbleed>                     tests only for heartbleed vulnerability
    <-I|--ccs|--ccs_injection>            tests only for CCS injection vulnerability
    <-R|--renegotiation>                  tests only for renegotiation vulnerability
    <-C|--compression|--crime>            tests only for CRIME vulnerability
    <-T|--breach>                         tests only for BREACH vulnerability
    <-O|--poodle>                         tests only for POODLE (SSL) vulnerability
    <-F|--freak>                          tests only for FREAK vulnerability
    <-A|--beast>                          tests only for BEAST vulnerability
    <-s|--pfs|--fs|--nsa>                 checks (perfect) forward secrecy settings
    <-4|--rc4|--appelbaum>                which RC4 ciphers are being offered?
    <-H|--header|--headers>               check for HSTS, HPKP and server/application banner string

    <-t|--starttls> protocol              does a default run against a STARTTLS enabled service
    <--mx>                                tests MX records from high to low priority (STARTTLS, port 25)


partly mandatory parameters:

    URI                   host|host:port|URL|URL:port   (port 443 is assumed unless otherwise specified)
    pattern               an ignore case word pattern of cipher hexcode or any other string in the name, kx or bits
    protocol              is one of ftp,smtp,pop3,imap,xmpp,telnet,ldap (for the latter two you need e.g. the supplied openssl)


EOF
	return $?
}


mybanner() {
	me=`basename $0`
	osslver=`$OPENSSL version`
	osslpath=`which $OPENSSL`
	nr_ciphers=`$OPENSSL ciphers  'ALL:COMPLEMENTOFALL:@STRENGTH' | sed 's/:/ /g' | wc -w`
	hn=`hostname`
	#poor man's ident (nowadays ident not neccessarily installed)
	idtag=`grep '\$Id' $0 | grep -w [E]xp | sed -e 's/^#  //' -e 's/\$ $/\$/'`
	[ "$COLOR" -ne 0 ] && idtag="\033[1;30m$idtag\033[m\033[1m"
	bb=`cat <<EOF

#########################################################
$me v$VERSION  ($SWURL)
($idtag)

   This program is free software. Redistribution + 
   modification under GPLv2 is permitted. 
   USAGE w/o ANY WARRANTY. USE IT AT YOUR OWN RISK!

 Note: you can only check the server with what is
 available (ciphers/protocols) locally on your machine!
#########################################################
EOF
`
pr_bold "$bb"
outln "\n"
outln " Using \"$osslver\" [~$nr_ciphers ciphers] on
 $hn:$osslpath
 (built: \"$OSSL_BUILD_DATE\", platform: \"$OSSL_VER_PLATFORM\")\n"

}

maketempf () {
	TEMPDIR=`mktemp -d /tmp/ssltester.XXXXXX` || exit 6
	TMPFILE=$TEMPDIR/tempfile.txt || exit 6
	HOSTCERT=$TEMPDIR/host_cerificate.txt
	HEADERFILE=$TEMPDIR/http_header.txt
	HEADERFILE_BREACH=$TEMPDIR/http_header_breach.txt
	LOGFILE=$TEMPDIR/logfile.txt
	if [ $DEBUG -ne 0 ]; then
		cat >$TEMPDIR/environment.txt << EOF

PID: $$
bash version: ${BASH_VERSINFO[0]}.${BASH_VERSINFO[1]}.${BASH_VERSINFO[2]}
status: ${BASH_VERSINFO[4]}
machine: ${BASH_VERSINFO[5]}
shellopts: $SHELLOPTS

"$osslver" [$nr_ciphers ciphers] on $hn:$osslpath
built: "$OSSL_BUILD_DATE", platform: "$OSSL_VER_PLATFORM"
$idtag

PATH: $PATH
RUN_DIR: $RUN_DIR

CAPATH:  $CAPATH
ECHO: $ECHO
COLOR: $COLOR
SHOW_LOC_CIPH: $SHOW_LOC_CIPH
VERBERR: $VERBERR 
LOCERR: $LOCERR
SHOW_EACH_C: $SHOW_EACH_C
SNEAKY: $SNEAKY
DEBUG: $DEBUG

HSTS_MIN: $HSTS_MIN
HPKP_MIN: $HPKP_MIN
MAX_WAITSOCK: $MAX_WAITSOCK
HEADER_MAXSLEEP: $HEADER_MAXSLEEP
CLIENT_MIN_PFS: $CLIENT_MIN_PFS
DAYS2WARN1: $DAYS2WARN1
DAYS2WARN2: $DAYS2WARN2

EOF
		$OPENSSL ciphers -V $1  &>$TEMPDIR/all_local_ciphers.txt
	fi


}

cleanup () {
	if [[ "$DEBUG" -ge 1 ]] ; then
		outln "\n"
		pr_underline "DEBUG (level $DEBUG): see files in $TEMPDIR"
	else
		[ -d "$TEMPDIR" ] && rm -rf ${TEMPDIR};
	fi
	outln
	[ -n "$NODE" ] && datebanner "Done"  # only if running against server
	outln
}

# for now only GOST engine
initialize_engine(){
	if ! $OPENSSL engine gost -vvvv -t -c >/dev/null 2>&1; then
		pr_litemagenta "No engine or GOST support via engine with your $OPENSSL"; outln "\n"
		return 1
	elif $OPENSSL engine gost -vvvv -t -c 2>&1 | grep -iq "No such" ; then
		pr_litemagenta "No engine or GOST support via engine with your $OPENSSL"; outln "\n"
		return 1
	elif echo $osslver | grep -q LibreSSL; then
		return 1
	else
		if [ ! -z "$OPENSSL_CONF" ]; then
			pr_litemagenta "For now I am providing the config file in to have GOST support"; outln
		else
			[ -z "$TEMPDIR" ] && maketempf
			OPENSSL_CONF=$TEMPDIR/gost.conf || exit 6
			# see https://www.mail-archive.com/openssl-users@openssl.org/msg65395.html
			cat >$OPENSSL_CONF << EOF
openssl_conf            = openssl_def

[ openssl_def ]
engines                 = engine_section

[ engine_section ]
gost = gost_section

[ gost_section ]
engine_id = gost
default_algorithms = ALL
CRYPT_PARAMS = id-Gost28147-89-CryptoPro-A-ParamSet

EOF
			export OPENSSL_CONF
		fi
	fi
	return 0
}


ignore_no_or_lame() {
	[ "$WARNINGS" = "off" -o "$WARNINGS" = "false" ] && return 0
	[ "$WARNINGS" = "batch" ] && return 1
	pr_magenta "$1 "
	read a
	case $a in
		Y|y|Yes|YES|yes) 
			return 0;;
		default) 
			;;
	esac
	return 1
}


parse_hn_port() {
	PORT=443		# unless otherwise auto-determined, see below
	NODE="$1"

	# strip "https" and trailing urlpath supposed it was supplied additionally
	echo $NODE | grep -q 'https://' && NODE=`echo $NODE | sed -e 's/https\:\/\///'` 

	# strip trailing urlpath
	NODE=`echo $NODE | sed -e 's/\/.*$//'`

	# was the address supplied like [AA:BB:CC::]:port ?
	if echo $NODE | grep -q ']' ; then
		tmp_port=`printf $NODE | sed 's/\[.*\]//' | sed 's/://'`
		# determine v6 port, supposed it was supplied additionally
		if [ ! -z "$tmp_port" ] ; then
			PORT=$tmp_port
			NODE=`printf $NODE | sed "s/:$PORT//"`
		fi
		NODE=`printf $NODE | sed -e 's/\[//' -e 's/\]//'`
	else
		# determine v4 port, supposed it was supplied additionally
		echo $NODE | grep -q ':' && PORT=`echo $NODE | sed 's/^.*\://'` && NODE=`echo $NODE | sed 's/\:.*$//'`
	fi
	SNI="-servername $NODE" 

	URL_PATH=`echo $1 | sed 's/.*'"${NODE}"'//' | sed 's/.*'"${PORT}"'//'`		# remove protocol and node part and port
	URL_PATH=`echo $URL_PATH | sed 's/\/\//\//g'`    	# we rather want // -> /

	# now get NODEIP
	get_dns_entries

	# check if we can connect to port 
	if ! fd_socket; then
		ignore_no_or_lame "Ignore? "
		[ $? -ne 0 ] && exit 3
	fi
	close_socket

	if  [[ -z "$2" ]] ; then	# for starttls we don't want this check
		# is ssl service listening on port? FIXME: better with bash on IP!
		$OPENSSL s_client -connect "$NODE:$PORT" $SNI </dev/null >/dev/null 2>&1 
		if [ $? -ne 0 ]; then
			pr_boldln "$NODE:$PORT doesn't seem a TLS/SSL enabled server or it requires a certificate"; 
			ignore_no_or_lame "Proceed (note that the results might look ok but they are nonsense) ? "
			[ $? -ne 0 ] && exit 3
		fi
	fi

	datebanner "Testing"
	[[ -z "$2" ]] && runs_HTTP	# for starttls we don't check the protocol as it is supplied on the cmd line
	initialize_engine

	return 0
}


get_dns_entries() {
	test4iponly=`printf $NODE | sed -e 's/[0-9]//g' -e 's/\.//g'`
	if [ "x$test4iponly" == "x" ]; then  # only an IPv4 address was supplied
		IP4=$NODE
		SNI=""	# override this as we test the IP only
	else
		# for security testing sometimes we have local host entries, so getent is preferred
	    if which getent &>/dev/null; then
			getent ahostsv4 $NODE 2>/dev/null >/dev/null
			if [ $? -eq 0 ]; then
				# Linux:
				IP4=`getent ahostsv4 $NODE 2>/dev/null | grep -v ':' | awk '/STREAM/ { print $1}' | uniq`
			#else
			#	IP4=`getent hosts $NODE 2>/dev/null | grep -v ':' | awk '{ print $1}' | uniq`
			#FIXME: FreeBSD returns only one entry 
			fi
		fi
		if [ -z "$IP4" ] ; then 		# getent returned nothing:
			IP4=`host -t a $NODE 2>/dev/null | grep -v alias | sed 's/^.*address //'`
			if  echo "$IP4" | grep -q NXDOMAIN || echo "$IP4" | grep -q "no A record"; then
				pr_magenta "Can't proceed: No IP address for \"$NODE\" available"; outln "\n"
				exit 1
			fi
		fi
		# MSYS2 has no host or getent, so we do this
		if [ -z "$IP4" ] ; then
			IP4=`nslookup $NODE 2>/dev/null | grep -A10 Name | grep -v Name | sed 's/^Address.*: .//'`
		fi

		# for IPv6 we often get this :ffff:IPV4 address which isn't of any use
		#which getent 2>&1 >/dev/null && IP6=`getent ahostsv6 $NODE | grep $NODE | awk '{ print $1}' | grep -v '::ffff' | uniq`
		if [ -z "$IP6" ] ; then
			if host -t aaaa $NODE &>/dev/null ; then
				IP6=`host -t aaaa $NODE | grep -v alias | grep -v "no AAAA record" | sed 's/^.*address //'`
			else
				IP6=""
			fi
		fi
		# MSYS2 has no host or getent, so we do this
          if [ -z "$IP6" ] ; then
               IP6=`nslookup -type=aaaa $NODE 2>/dev/null | grep -A10 Name | grep -v Name | sed 's/^Address.*: .//'`
          fi

	fi # test4iponly
	
	IPADDRs=`echo $IP4`
	[ ! -z "$IP6" ] && IPADDRs=`echo $IP4`" "`echo $IP6`

	# FIXME: we could/should test more than one IPv4 addresses if available, same IPv6. For now we test the first IPv4:
	NODEIP=`echo "$IP4" | head -1`

	# we can't do this as some checks and even openssl are not yet IPv6 safe. BTW: bash sockets do IPv6 transparently!
	#NODEIP=`echo "$IP6" | head -1`
	rDNS=`host -t PTR $NODEIP 2>/dev/null | grep -v "is an alias for" | sed -e 's/^.*pointer //' -e 's/\.$//'`
	echo $rDNS | grep -q NXDOMAIN  && rDNS=" - "
}


display_rdns_etc() {
     if [ `printf "$IPADDRs" | wc -w` -gt 1 ]; then
          out " further IP addresses:  "
          for i in $IPADDRs; do
               [ "$i" == "$NODEIP" ] && continue
               out " $i"
          done
		outln
	fi
	if  [ -n "$rDNS" ] ; then
		printf " %-23s %s" "rDNS ($NODEIP):" "$rDNS"
	fi
}

datebanner() {
	tojour=`date +%F`" "`date +%R`
	outln
	pr_reverse "$1 now ($tojour) ---> $NODEIP:$PORT ($NODE) <---"; outln "\n"
	if [ "$1" = "Testing" ] ; then
		display_rdns_etc 
	fi
	outln
}


mx_allentries() {
	if which dig &> /dev/null; then
		MXs=$(dig +short -t MX $1)
	elif which host &> /dev/null; then
		MXs=$(host -t MX $1 | grep 'handled by' | sed -e 's/^.*by //' -e 's/\.$//')
	elif which nslookup &> /dev/null; then
		MXs=$(nslookup -type=MX $1 2> /dev/null | grep 'mail exchanger = ' | sed 's/^.*mail exchanger = //g')
	else
		pr_magentaln 'No dig, host or nslookup'
		exit 3
	fi

	# test first higher priority servers
	MXs=$(echo "$MXs" | sort -n | sed -e 's/^.* //' -e 's/\.$//')

	if [ -n "$MXs" ] ; then
		for MX in $MXs; do
			parse_hn_port "$MX:25" 'smtp' && starttls 'smtp'
		done
	else
		pr_boldln "$1 has no mail server(s)"
	fi
}



################# main: #################


case "$1" in
	-h|--help|-help|"")
		help
		exit $?  ;;
esac

# auto determine where bins are
find_openssl_binary
mybanner

#PATH_TO_TESTSSL="$(cd "${0%/*}" 2>/dev/null; echo "$PWD"/"${0##*/}")"
PATH_TO_TESTSSL=`readlink "$BASH_SOURCE"` 2>/dev/null
[ -z $PATH_TO_TESTSSL ] && PATH_TO_TESTSSL="."
#
# next file provides a pair "keycode/ RFC style name", see the RFCs, cipher(1) and
# https://www.carbonwind.net/TLS_Cipher_Suites_Project/tls_ssl_cipher_suites_simple_table_all.htm
[ -r "$(dirname $PATH_TO_TESTSSL)/mapping-rfc.txt" ] && MAP_RFC_FNAME=`dirname $PATH_TO_TESTSSL`"/mapping-rfc.txt"


#FIXME: I know this sucks and getoptS is better

case "$1" in
     -b|--banner|-banner|-v|--version|-version)
		exit 0 
		;;
	--mx) 
		mx_allentries $2
		exit $?
		;;
	-V|--local)
		initialize_engine 	# GOST support
		prettyprint_local "$2"
		exit $? ;;
	-x|--single-ciphers-test)
		maketempf
		parse_hn_port "$3"
		test_just_one $2
		exit $? ;;
	-t|--starttls)			
		maketempf
		parse_hn_port "$3" "$2" # here comes protocol to signal starttls and  hostname:port 
		starttls "$2"		# protocol
		exit $? ;;
	-e|--each-cipher)
		maketempf
		parse_hn_port "$2"
		allciphers 
		exit $? ;;
	-E|-ee|--cipher-per-proto)  
		maketempf
		parse_hn_port "$2"
		cipher_per_proto
		exit $? ;;
	-p|--protocols)
		maketempf
		parse_hn_port "$2"
		runprotocols 	; ret=$?
		spdy			; ret=`expr $? + $ret`
		exit $ret ;;
	-f|--ciphers)
		maketempf
		parse_hn_port "$2"
		run_std_cipherlists
		exit $? ;;
     -S|--server_defaults)   
		maketempf
		parse_hn_port "$2"
		server_defaults
		exit $? ;;
     -P|--server_preference)   
		maketempf
		parse_hn_port "$2"
		server_preference
		exit $? ;;
	-y|--spdy|--google)
		maketempf
		parse_hn_port "$2"
		spdy
		exit $?  ;;
	-B|--heartbleet)
		maketempf
		parse_hn_port "$2"
		outln; pr_blue "--> Testing for heartbleed vulnerability"; outln "\n"
		heartbleed
		exit $?  ;;
	-I|--ccs|--ccs_injection)
		maketempf
		parse_hn_port "$2"
		outln; pr_blue "--> Testing for CCS injection vulnerability"; outln "\n"
		ccs_injection
		exit $?  ;;
	-R|--renegotiation)
		maketempf
		parse_hn_port "$2"
		outln; pr_blue "--> Testing for Renegotiation vulnerability"; outln "\n"
		renego
		exit $?  ;;
	-C|--compression|--crime)
		maketempf
		parse_hn_port "$2"
		outln; pr_blue "--> Testing for CRIME vulnerability"; outln "\n"
		crime
		exit $? ;;
	-T|--breach)
		maketempf
		parse_hn_port "$2"
		outln; pr_blue "--> Testing for BREACH (HTTP compression) vulnerability"; outln "\n"
		if [[ $SERVICE != "HTTP" ]] ; then
			pr_litemagentaln " Wrong usage: You're not targetting a HTTP service"
			ret=2
		else
			breach "$URL_PATH"
			ret=$?
		fi
		ret=`expr $? + $ret`
		exit $ret ;;
	-O|--ssl_poodle|poodle)
		maketempf
		parse_hn_port "$2"
		outln; pr_blue "--> Testing for POODLE (Padding Oracle On Downgraded Legacy Encryption) vulnerability, SSLv3"; outln "\n"
		ssl_poodle
		exit $? ;;
	-F|--freak)
		maketempf
		parse_hn_port "$2"
		outln; pr_blue "--> Testing for FREAK attack"; outln "\n"
		freak
		exit $? ;;
	-4|--rc4|--appelbaum)
		maketempf
		parse_hn_port "$2"
		rc4
		exit $? ;;
	-s|--pfs|--fs|--nsa)
		maketempf
		parse_hn_port "$2"
		pfs
		exit $? ;;
	-A|--beast)
		maketempf 
		parse_hn_port "$2"
		beast
		exit $? ;;
	-H|--header|--headers)  
		maketempf
		parse_hn_port "$2"
		outln; pr_blue "--> Testing HTTP Header response"; outln "\n"
		if [[ $SERVICE == "HTTP" ]]; then
			hsts "$URL_PATH"
			hpkp "$URL_PATH"
			ret=$?
			serverbanner "$URL_PATH"
			ret=`expr $? + $ret`
			applicationbanner "$URL_PATH"
			ret=`expr $? + $ret`
			cookieflags "$URL_PATH"
			ret=`expr $? + $ret`
		else
			pr_litemagentaln " Wrong usage: You're not targetting a HTTP service"
			ret=2
		fi
		exit $ret ;;
	-*)  help ;;    # wrong argument
	*)
		maketempf
		parse_hn_port "$1"

		outln
		runprotocols		; ret=$?
		spdy 			; ret=`expr $? + $ret`
		run_std_cipherlists	; ret=`expr $? + $ret`
		server_preference	; ret=`expr $? + $ret`
		server_defaults 	; ret=`expr $? + $ret`

		if [[ $SERVICE == "HTTP" ]]; then
			outln; pr_blue "--> Testing HTTP Header response"
			outln "\n"
			hsts "$URL_PATH"			; ret=`expr $? + $ret`
			hpkp "$URL_PATH"			; ret=`expr $? + $ret`
			serverbanner "$URL_PATH"		; ret=`expr $? + $ret`
			applicationbanner "$URL_PATH"		; ret=`expr $? + $ret`
			cookieflags  "$URL_PATH"		; ret=`expr $? + $ret`
		fi

		outln; pr_blue "--> Testing specific vulnerabilities" 
		outln "\n"
		heartbleed          ; ret=`expr $? + $ret`
		ccs_injection       ; ret=`expr $? + $ret`
		renego			; ret=`expr $? + $ret`
		crime			; ret=`expr $? + $ret`
		[[ $SERVICE == "HTTP" ]] && breach "$URL_PATH"	; ret=`expr $? + $ret`
		ssl_poodle		; ret=`expr $? + $ret`
		freak			; ret=`expr $? + $ret`
		beast			; ret=`expr $? + $ret`

		rc4				; ret=`expr $? + $ret`
		pfs				; ret=`expr $? + $ret`
		exit $ret ;;
esac

#  $Id: testssl.sh,v 1.203 2015/03/13 11:20:18 dirkw Exp $ 
# vim:ts=5:sw=5

