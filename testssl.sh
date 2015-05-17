#!/usr/bin/env bash
#
# bash is needed for some distros which use dash as /bin/sh and for tcp sockets which 
# this program uses a couple of times. Also some expressions are bashisms as I expect
# them to be faster. Idea is to not overdo it though.

# testssl.sh is a program for spotting weak SSL encryption, ciphers, version and some 
# vulnerablities or features
#
# Devel version is availabe from https://github.com/drwetter/testssl.sh
# Stable version from            https://testssl.sh
# Please file bugs at github!

VERSION="2.4"
SWURL="https://testssl.sh"
SWCONTACT="dirk aet testssl dot sh"

# Main author: Dirk Wetter, copyleft: 2007-2015, contributions so far see CREDIT.md
#
# License: GPLv2, see http://www.fsf.org/licensing/licenses/info/GPLv2.html
# and accompanying license "LICENSE.txt". Redistribution + modification under this
# license permitted. 
# If you enclose this script or parts of it in your software, it has to
# be accompanied by the same license (see link) and the place where to get
# the recent version of this program. Don't violate the license!
#
# USAGE WITHOUT ANY WARRANTY, THE SOFTWARE IS PROVIDED "AS IS". USE IT AT
# your OWN RISK!

# HISTORY: I know this shell script is still on its way to be nice and readable. ;-) It
# all started with a few openssl commands around 2006.  That's because openssl is a such a good
# swiss army knife (see e.g.  wiki.openssl.org/index.php/Command_Line_Utilities) that it was
# difficult to resist wrapping # with some shell commandos around it. This is how everything started.
# Now it has grown up, it has bash socket support for some features which basically replacing
# more and more functions of OpenSSL and will serve as some kind of library in the future.
# The socket checks in bash may sound cool and unique -- they are -- but probably you
# can achieve e.g. the same result with my favorite intgeractive shell: zsh (zmodload zsh/net/socket
# -- checkout zsh/net/tcp too!) But bash is way more often used within Linux and it's perfect
# for cross plattform support, see MacOS X and Windows MSYS2 extenstion.
#
# Q: So what's the difference to www.ssllabs.com/ssltest or sslcheck.globalsign.com/?
# A: As of now ssllabs only check webservers on standard ports, reachable from
#    the internet. And the examples above are 3rd parties. If those restrictions are fine
#    with you, and you need a management compatible rating -- go ahead and use those.
#    Also testssl.sh is meant as a tool in your hand and it's way more flexible.
#
# Note that for "standard" openssl binaries a lot of features (ciphers, protocols, vulnerabilities)
# are disabled as they'll impact security otherwise. For security testing though we need
# all b0rken features. testssl.sh will over time replace those checks with bash sockets --
# however it's still recommended to use the supplied binaries or cook your own, see 
# https://github.com/drwetter/testssl.sh/blob/master/openssl-bins/openssl-1.0.2-chacha.pm/Readme.md
# Don't worry if feature X is not available you'll get a warning about this missing feature!


readonly PROG_NAME=$(basename "$0")
PROG_DIR=$(readlink "$BASH_SOURCE") 2>/dev/null
readonly RUN_DIR=$(dirname $0)

# following variables make use of $ENV, e.g. OPENSSL=<myprivate_path_to_openssl> ./testssl.sh <host>
# 0 means (normally) true here. Some of the variables are also accessible with a command line switch

COLOR=${COLOR:-2}					# 2: Full color, 1: b/w+positioning, 0: no ESC at all
SHOW_LOC_CIPH=${SHOW_LOC_CIPH:-1} 		# will client side ciphers displayed before an individual test (makes no sense normally)
SHOW_EACH_C=${SHOW_EACH_C:-0}			# where individual ciphers are tested show just the positively ones tested #FIXME: wrong value
SNEAKY=${SNEAKY:-1}					# if zero: the referer and useragent we leave while checking the http header is just usual
SSL_NATIVE=${SSL_NATIVE:-1}			# we do per default bash sockets where possible 0: switch back to native openssl
ASSUMING_HTTP=${ASSUMING_HTTP:-1}		# in seldom cases (WAF, old servers/grumpy SSL) the service detection fails. Set to 0 for forcing HTTP
DEBUG=${DEBUG:-0}					# if 1 the temp files won't be erased. 2: list more what's going on (formerly: eq VERBOSE=1), 
								# 3: slight hexdumps + other info, 4: send bytes via sockets, 5: received, 6: whole 9 yards 
								#FIXME: still to be filled with (more) sense or following to be included:
VERBERR=${VERBERR:-1}				# 0 means to be more verbose (handshake errors to be displayed so that one can tell better
								# whether handshake succeeded or not. While testing individual ciphers you also need to have SHOW_EACH_C=1
LONG=${LONG:-1}					# whether to display for some options the cipher or the table with hexcode/KX,Enc,strength etc.

HEADER_MAXSLEEP=${HEADER_MAXSLEEP:-5}	# we wait this long before killing the process to retrieve a service banner / http header
MAX_WAITSOCK=10					# waiting at max 10 seconds for socket reply 
CCS_MAX_WAITSOCK=5					# for the two CCS payload (each)
HEARTBLEED_MAX_WAITSOCK=8			# for the heartbleed payload
USLEEP_SND=${USLEEP_SND:-0.1}			# sleep time for general socket send
USLEEP_REC=${USLEEP_REC:-0.2} 		# sleep time for general socket receive

CAPATH="${CAPATH:-/etc/ssl/certs/}"	# Does nothing yet (FC has only a CA bundle per default, ==> openssl version -d)
readonly HSTS_MIN=179				# >179 days is ok for HSTS
readonly HPKP_MIN=30				# >=30 days should be ok for HPKP_MIN, practical hints?
readonly CLIENT_MIN_PFS=5			# number of ciphers needed to run a test for PFS
readonly DAYS2WARN1=60				# days to warn before cert expires, threshold 1
readonly DAYS2WARN2=30				# days to warn before cert expires, threshold 2

# more global vars, here just declared
readonly ECHO="/usr/bin/printf --"		# works under Linux, BSD, MacOS. 
TERM_DWITH=${COLUMNS:-$(tput cols)} 	# for future costum line wrapping 
TERM_CURRPOS=0						#   ^^^ we also need to find out the length or current pos in the line
readonly SYSTEM=$(uname -s)			# OS

readonly NPN_PROTOs="spdy/4a2,spdy/3,spdy/3.1,spdy/2,spdy/1,http/1.1"
TEMPDIR=""
TLS_PROTO_OFFERED=""
DETECTED_TLS_VERSION=""
SOCKREPLY=""
SOCK_REPLY_FILE=""
HEXC=""
NW_STR=""
LEN_STR=""
SNI=""
IP4=""
IP6=""
OSSL_VER=""			# openssl version, will be autodetermined
OSSL_VER_MAJOR=0
OSSL_VER_MINOR=0
OSSL_VER_APPENDIX="none"
NODEIP=""
VULN_COUNT=0
readonly VULN_THRESHLD=1	# if bigger than this no we show a separate header in blue
IPS=""
SERVICE=""			# is the server running an HTTP server, SMTP, POP or IMAP?
URI=""
STARTTLS_PROTOCOL=""
OPTIMAL_PROTO=""		# we need this for IIS6 (sigh) and OpenSSL 1.02, otherwise some handshakes will fail, see https://github.com/PeterMosmans/openssl/issues/19#issuecomment-100897892

TLS_TIME=""
TLS_NOW=""
HTTP_TIME=""
GET_REQ11=""
HEAD_REQ10=""
readonly UA_SNEAKY="Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.0)"
readonly UA_STD="Mozilla/5.0 (X11; Linux x86_64; rv:42.0) Gecko/19700101 Firefox/42.0"

# Devel stuff, see -q below
TLS_LOW_BYTE=""
HEX_CIPHER=""


# debugging help:
#PS4='+(${BASH_SOURCE}:${LINENO}): ${FUNCNAME[0]:+${FUNCNAME[0]}(): }'
readonly PS4='${LINENO}: ${FUNCNAME[0]:+${FUNCNAME[0]}(): }'

# make sure that temporary files are cleaned up after use
trap "cleanup" QUIT EXIT


# The various hexdump commands we need to replace xxd (BSD compatability))
HEXDUMPVIEW=(hexdump -C) 				# This is used in verbose mode to see what's going on
HEXDUMP=(hexdump -ve '16/1 "%02x " " \n"') 	# This is used to analyse the reply
HEXDUMPPLAIN=(hexdump -ve '1/1 "%.2x"') 	# Replaces both xxd -p and tr -cd '[:print:]'


###### some hexbytes for bash network sockets ######

# 133 standard cipher + 4x GOST for TLS 1.2 and SPDY/NPN
readonly TLS12_CIPHER="
cc,14, cc,13, cc,15, c0,30, c0,2c, c0,28, c0,24, c0,14,
c0,0a, c0,22, c0,21, c0,20, 00,a5, 00,a3, 00,a1, 00,9f,
00,6b, 00,6a, 00,69, 00,68, 00,39, 00,38, 00,37, 00,36, 00,80, 00,81, 00,82, 00,83,
c0,77, c0,73, 00,c4, 00,c3, 00,c2, 00,c1, 00,88, 00,87,
00,86, 00,85, c0,32, c0,2e, c0,2a, c0,26, c0,0f, c0,05,
c0,79, c0,75, 00,9d, 00,3d, 00,35, 00,c0, 00,84, c0,2f,
c0,2b, c0,27, c0,23, c0,13, c0,09, c0,1f, c0,1e, c0,1d,
00,a4, 00,a2, 00,a0, 00,9e, 00,67, 00,40, 00,3f, 00,3e,
00,33, 00,32, 00,31, 00,30, c0,76, c0,72, 00,be, 00,bd,
00,bc, 00,bb, 00,9a, 00,99, 00,98, 00,97, 00,45, 00,44,
00,43, 00,42, c0,31, c0,2d, c0,29, c0,25, c0,0e, c0,04,
c0,78, c0,74, 00,9c, 00,3c, 00,2f, 00,ba, 00,96, 00,41,
00,07, c0,11, c0,07, 00,66, c0,0c, c0,02, 00,05, 00,04,
c0,12, c0,08, c0,1c, c0,1b, c0,1a, 00,16, 00,13, 00,10,
00,0d, c0,0d, c0,03, 00,0a, 00,63, 00,15, 00,12, 00,0f,
00,0c, 00,62, 00,09, 00,65, 00,64, 00,14, 00,11, 00,0e,
00,0b, 00,08, 00,06, 00,03, 00,ff"

# 76 standard cipher +4x GOST for SSLv3, TLS 1, TLS 1.1
readonly TLS_CIPHER="
c0,14, c0,0a, c0,22, c0,21, c0,20, 00,39, 00,38, 00,37,
00,36, 00,88, 00,87, 00,86, 00,85, c0,0f, c0,05, 00,35,
00,84, c0,13, c0,09, c0,1f, c0,1e, c0,1d, 00,33, 00,32, 00,80, 00,81, 00,82, 00,83,
00,31, 00,30, 00,9a, 00,99, 00,98, 00,97, 00,45, 00,44,
00,43, 00,42, c0,0e, c0,04, 00,2f, 00,96, 00,41, 00,07,
c0,11, c0,07, 00,66, c0,0c, c0,02, 00,05, 00,04, c0,12,
c0,08, c0,1c, c0,1b, c0,1a, 00,16, 00,13, 00,10, 00,0d,
c0,0d, c0,03, 00,0a, 00,63, 00,15, 00,12, 00,0f, 00,0c,
00,62, 00,09, 00,65, 00,64, 00,14, 00,11, 00,0e, 00,0b,
00,08, 00,06, 00,03, 00,ff" 

readonly SSLv2_CLIENT_HELLO="
,80,34    # length (here: 52)
,01       # Client Hello 
,00,02    # SSLv2
,00,1b    # cipher spec length (here: 27 )
,00,00    # session ID length
,00,10    # challenge length
,05,00,80 # 1st cipher	9 cipher specs, only classical V2 ciphers are used here, see  FIXME below
,03,00,80 # 2nd          there are v3 in v2!!! : https://tools.ietf.org/html/rfc6101#appendix-E
,01,00,80 # 3rd          Cipher specifications introduced in version 3.0 can be included in version 2.0 client hello messages using
,07,00,c0 # 4th          the syntax below. [..] # V2CipherSpec (see Version 3.0 name) = { 0x00, CipherSuite }; !!!!
,08,00,80 # 5th
,06,00,40 # 6th
,04,00,80 # 7th
,02,00,80 # 8th
,00,00,00 # 9th
,29,22,be,b3,5a,01,8b,04,fe,5f,80,03,a0,13,eb,c4" # Challenge
# https://idea.popcount.org/2012-06-16-dissecting-ssl-handshake/ (client)
# FIXME: http://max.euston.net/d/tip_sslciphers.html


###### output functions ######
        
out() { 
	$ECHO "$1" 
}
outln() { 
	[[ -z "$1" ]] || $ECHO "$1"
	$ECHO "\n"
}

# color print functions, see also http://www.tldp.org/HOWTO/Bash-Prompt-HOWTO/x329.html

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

# empty vars if we have no color:
red=""
green=""
brown=""
blue=""
cyan=""
off=""
bold=""
underline=""

if [[ "$COLOR" -eq 2 ]]; then
	red=$(tput setaf 1) 
	green=$(tput setaf 2) 
	brown=$(tput setaf 3) 
	blue=$(tput setaf 4) 
	yellow=$(tput setaf 3; tput bold)
	off=$(tput sgr0)
fi

if [[ "$COLOR" -ge 1 ]]; then
	bold=$(tput bold)
	underline=$(tput sgr 0 1)
fi


###### helper function definitions ######

debugme() {
	[[ $DEBUG -ge 2 ]] && "$@" 
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
		if ! ps $pid >/dev/null ; then
			return 0 	# didn't reach maxsleep yet
		fi
		sleep 1
		maxsleep=$((maxsleep - 1))
		test $maxsleep -eq 0 && break
	done # needs to be killed:
	kill $pid >&2 2>/dev/null
	wait $pid 2>/dev/null
#FIXME: do we need wait here???? normally it's good to report the exit status?!
	return 3   # killed
}


###### check code starts here ######

# determines whether the port has an HTTP service running or not (plain TLS, no STARTTLS)
# arg1 could be the protocol determined as "working". IIS6 needs that
runs_HTTP() {
	# SNI is nonsense for !HTTPS but fortunately other protocols don't seem to care
	printf "$GET_REQ11" | $OPENSSL s_client $1 -quiet -connect $NODEIP:$PORT $SNI &>$TMPFILE &
	wait_kill $! $HEADER_MAXSLEEP
	head $TMPFILE | grep -aq ^HTTP && SERVICE=HTTP
	head $TMPFILE | grep -aq SMTP && SERVICE=SMTP
	head $TMPFILE | grep -aq POP && SERVICE=POP
	head $TMPFILE | grep -aq IMAP && SERVICE=IMAP
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
			if [[ $ASSUMING_HTTP -eq 0 ]]; then
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
	outln; pr_blue "--> Testing HTTP header response"; outln "\n"

	[ -z "$1" ] && url="/" || url="$1"
	if [ $SNEAKY -eq 0 ] ; then
		referer="http://google.com/"
		useragent="$UA_SNEAKY"
	else
		referer="TLS/SSL-Tester from $SWURL"
		useragent="$UA_STD"
	fi
	(
	$OPENSSL s_client $OPTIMAL_PROTO -quiet -connect $NODEIP:$PORT $SNI << EOF
GET $url HTTP/1.1
Host: $NODE
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-us,en;q=0.7,de-de;q=0.3
User-Agent: $useragent
Referer: $referer
Connection: close

EOF
) &>$HEADERFILE &
	pid=$!
	if wait_kill $pid $HEADER_MAXSLEEP; then
		if ! egrep -iaq "XML|HTML|DOCTYPE|HTTP|Connection" $HEADERFILE; then
			pr_litemagenta " likely HTTP header requests failed (#lines: $(wc -l < $HEADERFILE | sed 's/ //g'))."
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
		pr_litemagentaln " failed (HTTP header request stalled)"
		ret=3
	fi
	if egrep -aq "^HTTP.1.. 301|^HTTP.1.. 302|^Location" $HEADERFILE; then
		redir2=$(grep -a '^Location' $HEADERFILE | sed 's/Location: //' | tr -d '\r\n')
		outln " (got 30x to $redir2 - may be better try this URL?)\n"
	fi
	if egrep -aq "^HTTP.1.. 401|^WWW-Authenticate" $HEADERFILE; then
		outln " (got 401 / WWW-Authenticate, can't look beyond it)\n"
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
	pr_bold " HSTS              "
	grep -iaw '^Strict-Transport-Security' $HEADERFILE >$TMPFILE
	if [ $? -eq 0 ]; then
		grep -aciw '^Strict-Transport-Security' $HEADERFILE | egrep -waq "1" || out "(two HSTS header, using 1st one) "
		hsts_age_sec=$(sed -e 's/[^0-9]*//g' $TMPFILE | head -1)
		hsts_age_days=$(( hsts_age_sec / 86400))
		if [ $hsts_age_days -gt $HSTS_MIN ]; then
			pr_litegreen "$hsts_age_days days \c" ; out "($hsts_age_sec s)"
		else
			pr_brown "$hsts_age_days days (<$HSTS_MIN is not good enough)"
		fi
		includeSubDomains "$TMPFILE"
		preload "$TMPFILE"  
		#FIXME: To be checked against e.g. https://dxr.mozilla.org/mozilla-central/source/security/manager/boot/src/nsSTSPreloadList.inc 
		# 						 and https://chromium.googlesource.com/chromium/src/+/master/net/http/transport_security_state_static.json
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
	local hpkp_nr_keys
	local hpkp_key
	
	if [ ! -s $HEADERFILE ] ; then
		http_header "$1" || return 3
	fi
	pr_bold " HPKP              "
	egrep -aiw '^Public-Key-Pins|Public-Key-Pins-Report-Only' $HEADERFILE >$TMPFILE
	if [ $? -eq 0 ]; then
		egrep -aciw '^Public-Key-Pins|Public-Key-Pins-Report-Only' $HEADERFILE | egrep -waq "1" || out "(two HPKP header, using 1st one) "
		# dirty trick so that grep -c really counts occurances and not lines w/ occurances:
		hpkp_nr_keys=$(sed 's/pin-sha/pin-sha\n/g' < $TMPFILE | grep -ac pin-sha)
		if [ $hpkp_nr_keys -eq 1 ]; then
			pr_brown "One key is not sufficent, "
		fi
		hpkp_age_sec=$(sed -e 's/\r//g' -e 's/^.*max-age=//' -e 's/;.*//' $TMPFILE)
		hpkp_age_days=$((hpkp_age_sec / 86400))
		if [ $hpkp_age_days -ge $HPKP_MIN ]; then
			pr_litegreen "$hpkp_age_days days \c" ; out "= $hpkp_age_sec s"
		else
			pr_brown "$hpkp_age_days days (<$HPKP_MIN is not good enough)"
		fi
		
		includeSubDomains "$TMPFILE"
		preload "$TMPFILE"

		# get the key fingerprints:
		sed -i -e 's/Public-Key-Pins://g' -e s'/Public-Key-Pins-Report-Only://' $TMPFILE
		while read hpkp_key; do
			#FIXME: to be checked against level0.crt
			# like openssl x509 -in level0.crt -pubkey -noout | openssl rsa -pubin -outform der | openssl dgst -sha256 -binary | openssl base64 -d
			debugme echo "$hpkp_key="
		done < <(sed -e 's/;/\n/g' -e 's/ //g'  $TMPFILE | awk -F'=' '/pin.*=/ { print $2 }')
		
		out " (fingerprints not checked)"
	else
		out "--"
	fi
	outln

	tmpfile_handle $FUNCNAME.txt
	return $?
}

emphasize_stuff_in_headers(){
# see http://www.grymoire.com/Unix/Sed.html#uh-3
#	outln "$1" | sed "s/[0-9]*/$brown&$off/g"
	outln "$1" | sed -e "s/\([0-9]\)/$brown\1$off/g" \
		-e "s/Debian/"$yellow"\Debian$off/g" \
		-e "s/Ubuntu/"$yellow"Ubuntu$off/g" \
		-e "s/ubuntu/"$yellow"ubuntu$off/g" \
		-e "s/squeeze/"$yellow"squeeze$off/g" \
		-e "s/lenny/"$yellow"lenny$off/g" \
		-e "s/SUSE/"$yellow"SUSE$off/g" \
		-e "s/Red Hat Enterprise Linux/"$yellow"Red Hat Enterprise Linux$off/g" \
		-e "s/Red Hat/"$yellow"Red Hat$off/g" \
		-e "s/CentOS/"$yellow"CentOS$off/g" \
		-e "s/X-Powered-By: ASP.NET/"$yellow"X-Powered-By: ASP.NET$off/g" \
		-e "s/X-Powered-By/"$yellow"X-Powered-By$off/g" \
		-e "s/X-AspNet-Version/"$yellow"X-AspNet-Version$off/g" 
}


serverbanner() {
	if [ ! -s $HEADERFILE ] ; then
		http_header "$1" || return 3
	fi
	pr_bold " Server            "
	grep -ai '^Server' $HEADERFILE >$TMPFILE
	if [ $? -eq 0 ]; then
		serverbanner=$(sed -e 's/^Server: //' -e 's/^server: //' $TMPFILE)
		if [ x"$serverbanner" == "x\n" -o x"$serverbanner" == "x\n\r" -o x"$serverbanner" == "x" ]; then
			outln "banner exists but empty string"
		else
			emphasize_stuff_in_headers "$serverbanner"
			[[ "$serverbanner" = *Microsoft-IIS/6.* ]] && [[ $OSSL_VER == 1.0.2* ]] && pr_litemagentaln "                   It's recommended to run another test w/ OpenSSL 1.01 !"
			# see https://github.com/PeterMosmans/openssl/issues/19#issuecomment-100897892
		fi
		# mozilla.github.io/server-side-tls/ssl-config-generator/
          # https://support.microsoft.com/en-us/kb/245030
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
	pr_bold " Application      "
# examples: dev.testssl.sh, php.net, asp.net , www.regonline.com
	egrep -ai '^X-Powered-By|^X-AspNet-Version|^X-Version' $HEADERFILE >$TMPFILE
	if [ $? -ne 0 ]; then
		outln " (no banner at \"$url\")"
	else
		#cat $TMPFILE | sed 's/^.*:/:/'  | sed -e :a -e '$!N;s/\n:/ \n\             +/;ta' -e 'P;D' | sed 's/://g' 
		#sed 's/^/ /g' $TMPFILE | tr -t '\n\r' '  ' | sed "s/\([0-9]\)/$pr_red\1$off/g"
		emphasize_stuff_in_headers "$(sed 's/^/ /g' $TMPFILE | tr '\n\r' '  ')"
		#i=0
		#cat $TMPFILE | sed 's/^/ /' | while read line; do
		#	out "$line" 
		#	if [[ $i -eq 0 ]] ; then
		#		out "               " 
		#		i=1
		#	fi
		#done
	fi

	tmpfile_handle $FUNCNAME.txt
	return $?
}

cookieflags() {	# ARG1: Path, ARG2: path
	if [ ! -s $HEADERFILE ] ; then
		http_header "$1" || return 3
	fi
	pr_bold " Cookie(s)         "
	grep -ai '^Set-Cookie' $HEADERFILE >$TMPFILE
	if [ $? -eq 0 ]; then
		nr_cookies=$(wc -l < $TMPFILE | sed 's/ //g')
		out "$nr_cookies issued: "
		if [ $nr_cookies -gt 1 ] ; then
			negative_word="NONE"
		else
			negative_word="NOT"
		fi
		nr_secure=$(grep -iac secure $TMPFILE)
		case $nr_secure in
			0) pr_brown "$negative_word" ;;
			[123456789]) pr_litegreen "$nr_secure/$nr_cookies";;
		esac
 		out "secure, "
		nr_httponly=$(grep -cai httponly $TMPFILE)
		case $nr_httponly in
			0) pr_brown "$negative_word" ;;
			[123456789]) pr_litegreen "$nr_httponly/$nr_cookies";; 
		esac
		out "HttpOnly"
	else
		out "(none issued at \"$url\")"
	fi
	outln

	tmpfile_handle $FUNCNAME.txt
	return 0
}


moreflags() {
	local good_flags2test="X-Frame-Options X-XSS-Protection X-Content-Type-Options Content-Security-Policy X-Content-Security-Policy X-WebKit-CSP" 
	local other_flags2test="Access-Control-Allow-Origin Via Upgrade X-Served-By"
	local egrep_pattern=""
	local f2t result_str
	local blanks="                   "

	if [ ! -s $HEADERFILE ] ; then
		http_header "$1" || return 3
	fi
	pr_bold " Security headers  "
	egrep_pattern=$(echo "$good_flags2test $other_flags2test"| sed -e 's/ /|\^/g' -e 's/^/\^/g') # space -> |^
	egrep -ai $egrep_pattern $HEADERFILE >$TMPFILE
	if [ $? -ne 0 ]; then
		outln "(none at \"$url\")"
		ret=1
	else
		ret=0
		first=true
		for f2t in $good_flags2test; do
			result_str=$(grep -i "^$f2t" $TMPFILE)
			[ -z "$result_str" ] && continue
			if ! $first; then
				out "$blanks"	# output leading spaces if the first header
			else
				first=false
			fi
			if [ $(echo "$result_str" | wc -l | sed 's/ //g') -eq 1 ]; then
				pr_litegreenln "$result_str"
			else # for the case we hace two times the same header:
				# exchange the linefeeds between the two lines only:
				pr_litecyan "double -->" ; echo "$result_str" |  tr '\n\r' '  | ' | sed 's/| $//g'
				pr_litecyanln "<-- double"
			fi
		done
		# now the same with other flags
		for f2t in $other_flags2test; do
			result_str=$(grep -i "^$f2t" $TMPFILE)
			[ -z "$result_str" ] && continue
			if $first; then
				outln "$result_str"
				first=false
			else
				out "$blanks"; outln "$result_str"
			fi
		done
	fi
#FIXME: I am not testing for the correctness or anything stupid yet, e.g. "X-Frame-Options: allowall"

	tmpfile_handle $FUNCNAME.txt
	return $ret
}


# #1: string with 2 opensssl codes, HEXC= same in NSS/ssllab terminology
normalize_ciphercode() {
	part1=$(echo "$1" | awk -F',' '{ print $1 }')
	part2=$(echo "$1" | awk -F',' '{ print $2 }')
	part3=$(echo "$1" | awk -F',' '{ print $3 }')
	if [ "$part1" == "0x00" ] ; then		# leading 0x00
		HEXC=$part2
	else
		part2=$(echo $part2 | sed 's/0x//g')
		if [ -n "$part3" ] ; then    # a SSLv2 cipher has three parts
			part3=$(echo $part3 | sed 's/0x//g')
		fi
		HEXC="$part1$part2$part3"
	fi
	HEXC=$(echo $HEXC | tr 'A-Z' 'a-z' |  sed 's/0x/x/') #tolower + strip leading 0
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
		$OPENSSL ciphers -V 'ALL:COMPLEMENTOFALL:@STRENGTH' | while read hexcode dash ciph sslvers kx auth enc mac export ; do       # -V doesn't work with openssl < 1.0
			normalize_ciphercode $hexcode
			neat_list $HEXC $ciph $kx $enc 
			outln
		done
	else
		for arg in $(echo $@ | sed 's/,/ /g'); do
			$OPENSSL ciphers -V 'ALL:COMPLEMENTOFALL:@STRENGTH' | while read hexcode dash ciph sslvers kx auth enc mac export ; do	# -V doesn't work with openssl < 1.0
				normalize_ciphercode $hexcode
				neat_list $HEXC $ciph $kx $enc | grep -wai "$arg"
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
	debugme cat $TMPFILE 

     tmpfile_handle $FUNCNAME.txt
	return $ret
}


# argv[1]: cipher list to test 
# argv[2]: string on console
# argv[3]: ok to offer? 0: yes, 1: no
std_cipherlists() {
	out "$2 "; 
	if listciphers $1; then  # is that locally available??
		[ $SHOW_LOC_CIPH -eq 0 ] && out "local ciphers are: " && sed 's/:/, /g' $TMPFILE
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
					ok 0 1              # not offered also in normal
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
		singlespaces=$(echo "$2" | sed -e 's/ \+/ /g' -e 's/^ //' -e 's/ $//g' -e 's/  //g')
		pr_magentaln "Local problem: No $singlespaces configured in $OPENSSL" 
	fi
	# we need lf in those cases:
	[[ $DEBUG -ge 2 ]] && echo
}


# sockets inspired by http://blog.chris007.de/?p=238
# ARG1: hexbyte with a leading comma (!!), seperated by commas
# ARG2: sleep
socksend() {
	# the following works under BSD and Linux, which is quite tricky. So don't mess with it unless you're really sure what you do
	data=$(echo "$1" | sed -e 's/# .*$//g' -e 's/ //g' | sed -E 's/^[[:space:]]+//; s/[[:space:]]+$//; /^$/d' | sed 's/,/\\/g' | tr -d '\n')
	[[ $DEBUG -ge 4 ]] && echo "\"$data\""
	printf -- "$data" >&5 2>/dev/null &
	sleep $2
}


#FIXME: This is only for HB and CCS, others use sockread_serverhello()
sockread() {
	[ "x$2" = "x" ] && maxsleep=$MAX_WAITSOCK || maxsleep=$2
	ret=0

	ddreply=$(mktemp $TEMPDIR/ddreply.XXXXXX) || return 7
	dd bs=$1 of=$ddreply count=1 <&5 2>/dev/null &
	pid=$!

	wait_kill $pid $maxsleep
	ret=$?
	SOCKREPLY=$(cat $ddreply)
	rm $ddreply

	return $ret
}


show_rfc_style(){
	[ ! -r "$MAP_RFC_FNAME" ] && return 1
	RFCname=$(grep -iw $1 "$MAP_RFC_FNAME" | sed -e 's/^.*TLS/TLS/' -e 's/^.*SSL/SSL/')
	[[ -n "$RFCname" ]] && out "$RFCname" 
	return 0
}

neat_header(){
	outln "Hexcode  Cipher Suite Name (OpenSSL)    KeyExch.   Encryption Bits${MAP_RFC_FNAME:+        Cipher Suite Name (RFC)}"
	outln "%s-------------------------------------------------------------------------${MAP_RFC_FNAME:+----------------------------------------------}"
}

neat_list(){
	kx=$(echo $3 | sed 's/Kx=//g')
	enc=$(echo $4 | sed 's/Enc=//g')
	strength=$(echo $enc | sed -e 's/.*(//' -e 's/)//')						# strength = encryption bits
	strength=$(echo $strength | sed -e 's/ChaCha20-Poly1305/ly1305/g') 			# workaround for empty bits ChaCha20-Poly1305
	enc=$(echo $enc | sed -e 's/(.*)//g' -e 's/ChaCha20-Poly1305/ChaCha20-Po/g')	# workaround for empty bits ChaCha20-Poly1305
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
	for arg in $(echo $@ | sed 's/,/ /g'); do 
		# 1st check whether openssl has cipher or not
		$OPENSSL ciphers -V 'ALL:COMPLEMENTOFALL:@STRENGTH' | while read hexcode dash ciph sslvers kx auth enc mac export ; do
			normalize_ciphercode $hexcode 
			neat_list $HEXC $ciph $kx $enc | grep -qwai "$arg" 
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
	nr_ciphers=$($OPENSSL ciphers  'ALL:COMPLEMENTOFALL:@STRENGTH' | sed 's/:/ /g' | wc -w)
	pr_blue "--> Testing all locally available $nr_ciphers ciphers against the server"; outln "(ordered by encryption strength)\n"
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
	local proto proto_text
	local hexcode n ciph sslvers kx auth enc mac export
	local ret

	pr_blue "--> Testing all locally available ciphers per protocol against the server"; outln "(ordered by encryption strength)\n"
	neat_header
	outln " -ssl2 SSLv2\n -ssl3 SSLv3\n -tls1 TLS 1\n -tls1_1 TLS 1.1\n -tls1_2 TLS 1.2"| while read proto proto_text; do
		locally_supported "$proto" "$proto_text" || continue
		outln
		$OPENSSL ciphers $proto -V 'ALL:COMPLEMENTOFALL:@STRENGTH' | while read hexcode n ciph sslvers kx auth enc mac export; do	# -V doesn't work with openssl < 1.0
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
	local ret

	[ -n "$2" ] && out "$2 "
	$OPENSSL s_client "$1" 2>&1 | grep -aq "unknown option"
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
# FIXME: hoer gibt BSD immer eine Null zurueck! --> error lesen
	[ "$VERBERR" -eq 0 ] && egrep "error|failure" $TMPFILE | egrep -av "unable to get local|verify error"
	
	if grep -aq "no cipher list" $TMPFILE ; then
		ret=5
	fi
	tmpfile_handle $FUNCNAME.txt
	return $ret
}

testprotohelper() {
	if locally_supported "$1" "$2" ; then
		testversion "$1" "$2" 
		return $?
		# 0: offered
		# 1: not offered
		# 5: protocol ok, but no cipher
	else
		return 7
	fi
}


runprotocols() {
	local using_sockets=0

	pr_blue "--> Testing protocols"; 

	if [ $SSL_NATIVE -eq 0 ] || [ -n "$STARTTLS" ]; then
		using_sockets=1
		outln "(via native openssl)\n"
	else
		outln "(via sockets for SSLv2, SSLv3)\n"
	fi

	out " SSLv2      ";
	if [ $SSL_NATIVE -eq 0 ] || [ -n "$STARTTLS" ]; then
		testprotohelper "-ssl2"
		case $? in
			0) 	ok 1 1 ;;	# pr_red 
			1) 	ok 0 1 ;; # pr_green "not offered (ok)"
			5) 	ok 5 5 ;;	# protocol ok, but no cipher
			7) ;;		# no local support
		esac
	else
		sslv2_sockets #FIXME: --> Umschreiben, Interpretation mit CASE wie native
	fi

	out " SSLv3      ";
	if [ $SSL_NATIVE -eq 0 ] || [ -n "$STARTTLS" ]; then
		testprotohelper "-ssl3"
	else
		tls_sockets "00" "$TLS_CIPHER"
	fi
	case $? in
		0) ok 6 0 ;;	# pr_litered offered (NOT ok)
		1) ok 0 1 ;;	# pr_green "not offered (ok)"
		2) ok 0 1 ;;   #FIXME: downgraded. still missing a testcase here
		5) ok 5 5 ;;	# protocol ok, but no cipher
		7) ;;		# no local support
	esac

	out " TLS 1      ";
	#if [ $SSL_NATIVE -eq 0 ] || [ -n "$STARTTLS" ]; then
		testprotohelper "-tls1"
	#else
		#tls_sockets "01" "$TLS_CIPHER"
	#fi
	case $? in
		0) ok 2 0 ;;   # no GCM, thus only normal print
		1) outln "not offered" ;;  # we should change everything later here
		# 2) ok 0 0 ;; downgraded 
		5) ok 5 5 ;;	# protocol ok, but no cipher
		7) ;;		# no local support
	esac

	out " TLS 1.1    ";
	testprotohelper "-tls1_1"
	case $? in
		0) ok 2 0 ;;   # normal print
		1) ok 7 0 ;;   # no GCM, penalty
		5) ok 5 5 ;;	# protocol ok, but no cipher
		7) ;;		# no local support
	esac

	out " TLS 1.2    ";
	testprotohelper "-tls1_2"
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
# see ciphers(1ssl)
	std_cipherlists NULL:eNULL                   " Null Cipher             " 1
	std_cipherlists aNULL                        " Anonymous NULL Cipher   " 1
	std_cipherlists ADH                          " Anonymous DH Cipher     " 1
	std_cipherlists EXPORT40                     " 40 Bit encryption       " 1
	std_cipherlists EXPORT56                     " 56 Bit encryption       " 1
	std_cipherlists EXPORT                       " Export Cipher (general) " 1
	std_cipherlists LOW                          " Low (<=64 Bit)          " 1
	std_cipherlists DES                          " DES Cipher              " 1
	std_cipherlists 3DES                         " Triple DES Cipher       " 2
	std_cipherlists "MEDIUM:!NULL:!aNULL:!SSLv2" " Medium grade encryption " 2
	std_cipherlists "HIGH:!NULL:!aNULL"          " High grade encryption   " 0
	return 0
}

server_preference() {
	local list1="DES-CBC3-SHA:RC4-MD5:DES-CBC-SHA:RC4-SHA:AES128-SHA:AES128-SHA256:AES256-SHA:ECDHE-RSA-AES128-SHA:DHE-RSA-AES128-SHA:DHE-RSA-AES256-SHA:DHE-DSS-AES128-SHA:DHE-DSS-AES128-SHA:DHE-DSS-AES256-SHA:ECDH-RSA-DES-CBC3-SHA:ECDH-RSA-AES128-SHA:ECDH-RSA-AES256-SHA:ECDHE-RSA-AES256-GCM-SHA384:DHE-RSA-AES128-SHA256:DHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES128-SHA256:ECDHE-RSA-AES256-SHA384:ECDHE-RSA-AES256-SHA:DHE-DSS-AES256-GCM-SHA384:AES256-SHA256"
	outln;
	pr_blue "--> Testing server preferences"; outln "\n"

	out " Has server cipher order?     "
	$OPENSSL s_client $STARTTLS -cipher $list1 -connect $NODEIP:$PORT $SNI </dev/null 2>/dev/null >$TMPFILE
	if [ $? -ne 0 ]; then
		pr_magenta "no matching cipher in this list found (pls report this): "
		outln "$list1  . "
          ret=6
	else
		cipher1=$(grep -wa Cipher $TMPFILE | egrep -avw "New|is" | sed -e 's/^ \+Cipher \+://' -e 's/ //g')
		list2=$(echo $list1 | tr ':' '\n' | sort -r | tr '\n' ':')	# pr_reverse the list
		$OPENSSL s_client $STARTTLS -cipher $list2 -connect $NODEIP:$PORT $SNI </dev/null 2>/dev/null >$TMPFILE
		cipher2=$(grep -wa Cipher $TMPFILE | egrep -avw "New|is" | sed -e 's/^ \+Cipher \+://' -e 's/ //g')

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
		default_proto=$(grep -aw "Protocol" $TMPFILE | sed -e 's/^.*Protocol.*://' -e 's/ //g')
		case "$default_proto" in
			*TLSv1.2)		pr_greenln $default_proto ;;
			*TLSv1.1)		pr_litegreenln $default_proto ;;
			*TLSv1)		outln $default_proto ;;
			*SSLv2)		pr_redln $default_proto ;;
			*SSLv3)		pr_redln $default_proto ;;
			"")			pr_litemagenta "default proto empty";  [[ $OSSL_VER == 1.0.2* ]] && outln "(IIS6+OpenSSL 1.02?)" ;; # maybe you can try to use openssl 1.01 here
			*)			outln "$default_proto" ;;
		esac
 
		out " Negotiated cipher            "
		default_cipher=$(grep -aw "Cipher" $TMPFILE | egrep -avw "New|is" | sed -e 's/^.*Cipher.*://' -e 's/ //g')
		case "$default_cipher" in
			*NULL*|*EXP*)	pr_red "$default_cipher" ;;
			*RC4*)		pr_litered "$default_cipher" ;;
			*CBC*)		pr_brown "$default_cipher" ;; #FIXME BEAST: We miss some CBC ciphers here, need to work w/ a list
			*GCM*)		pr_green "$default_cipher" ;;   # best ones
			*CHACHA20*)	pr_green "$default_cipher" ;;   # best ones
			ECDHE*AES*)    pr_yellow "$default_cipher" ;;   # it's CBC. --> lucky13
			"")			pr_litemagenta "default cipher empty" ;  [[ $OSSL_VER == 1.0.2* ]] && out "(IIS6+OpenSSL 1.02?)" ;; # maybe you can try to use openssl 1.01 here
			*)			out "$default_cipher" ;;
		esac
		outln "$remark4default_cipher"

		if [ ! -z "$remark4default_cipher" ]; then
			out " Negotiated cipher per proto $remark4default_cipher"
			i=1
			for p in ssl2 ssl3 tls1 tls1_1 tls1_2; do
			locally_supported -"$p" || continue
				$OPENSSL s_client  $STARTTLS -"$p" -connect $NODEIP:$PORT $SNI </dev/null 2>/dev/null  >$TMPFILE
				if [ $? -eq 0 ]; then
					proto[i]=$(grep -aw "Protocol" $TMPFILE | sed -e 's/^.*Protocol.*://' -e 's/ //g')
					cipher[i]=$(grep -aw "Cipher" $TMPFILE | egrep -avw "New|is" | sed -e 's/^.*Cipher.*://' -e 's/ //g')
					[[ ${cipher[i]} == "0000" ]] && cipher[i]=""  # Hack!
					[[ $DEBUG -ge 2 ]] && outln "Default cipher for ${proto[i]}: ${cipher[i]}"
				else
					 proto[i]=""
					 cipher[i]=""
				fi
				i=$(($i + 1))
			done

			if spdy_pre ; then		# is NPN/SPDY supported and is this no STARTTLS?
				$OPENSSL s_client -host $NODE -port $PORT -nextprotoneg "$NPN_PROTOs" </dev/null 2>/dev/null  >$TMPFILE
				if [ $? -eq 0 ]; then
					proto[i]=$(grep -aw "Next protocol" $TMPFILE | sed -e 's/^Next protocol://' -e 's/(.)//' -e 's/ //g')
					if [ -z "${proto[i]}" ]; then
						cipher[i]=""
					else
						cipher[i]=$(grep -aw "Cipher" $TMPFILE | egrep -avw "New|is" | sed -e 's/^.*Cipher.*://' -e 's/ //g')
						[[ $DEBUG -ge 2 ]] && outln "Default cipher for ${proto[i]}: ${cipher[i]}"
					fi
				fi
			fi

			for i in 1 2 3 4 5 6; do
				if [[ -n "${cipher[i]}" ]]; then                              		# cipher not empty
					 if [[ -z "${cipher[i-1]}" ]]; then                      		# previous one empty 
						outln
						printf -- "     %-30s %s" "${cipher[i]}:" "${proto[i]}"	# print out both
					 else                                                    		# previous NOT empty
						if [[ "${cipher[i-1]}" == "${cipher[i]}" ]]; then   		# and previous protocol same cipher
							out ", ${proto[i]}"                         	  		# same cipher --> only print out protocol behind it
						else
							outln
							printf -- "     %-30s %s" "${cipher[i]}:" "${proto[i]}"	# print out both
					    fi
					 fi
				fi
			done
		fi
	fi

	tmpfile_handle $FUNCNAME.txt

	if [ -z "$remark4default_cipher" ]; then
		cipher_pref_check
	else
		outln "\n No further cipher order check as order is determined by the client"
	fi

	return 0
}

cipher_pref_check() {
	local p proto protos
	local tested_cipher cipher

	out " Cipher order"

	for p in ssl2 ssl3 tls1 tls1_1 tls1_2; do
		$OPENSSL s_client $STARTTLS -"$p" -connect $NODEIP:$PORT $SNI </dev/null 2>/dev/null  >$TMPFILE
		if [ $? -eq 0 ]; then
			tested_cipher=""
			proto=$(grep -aw "Protocol" $TMPFILE | sed -e 's/^.*Protocol.*://' -e 's/ //g')
			cipher=$(grep -aw "Cipher" $TMPFILE | egrep -avw "New|is" | sed -e 's/^.*Cipher.*://' -e 's/ //g')
			[ -z "$proto" ] && continue	# for early openssl versions sometimes needed
			outln
			printf "     %-10s %s " "$proto:" "$cipher"
			tested_cipher="-"$cipher
			while true; do
				$OPENSSL s_client $STARTTLS -"$p" -cipher "ALL:$tested_cipher" -connect $NODEIP:$PORT $SNI </dev/null 2>/dev/null  >$TMPFILE
				[ $? -ne 0 ] && break
				cipher=$(grep -aw "Cipher" $TMPFILE | egrep -avw "New|is" | sed -e 's/^.*Cipher.*://' -e 's/ //g')
				out "$cipher "
				tested_cipher="$tested_cipher:-$cipher"
			done
		fi
	done
	outln

	if ! spdy_pre ; then		# is NPN/SPDY supported and is this no STARTTLS?
		:
	else
		protos=$($OPENSSL s_client -host $NODE -port $PORT -nextprotoneg  \"\" </dev/null 2>/dev/null | grep -a "^Protocols " | sed -e 's/^Protocols.*server: //' -e 's/,//g')  
		for p in $protos; do
			$OPENSSL s_client -host $NODE -port $PORT -nextprotoneg "$p" </dev/null 2>/dev/null >$TMPFILE
			cipher=$(grep -aw "Cipher" $TMPFILE | egrep -avw "New|is" | sed -e 's/^.*Cipher.*://' -e 's/ //g')
			printf "     %-10s %s " "$p:" "$cipher"
			tested_cipher="-"$cipher
			while true; do
				$OPENSSL s_client -cipher "ALL:$tested_cipher" -host $NODE -port $PORT -nextprotoneg "$p" </dev/null 2>/dev/null >$TMPFILE
				[ $? -ne 0 ] && break
				cipher=$(grep -aw "Cipher" $TMPFILE | egrep -avw "New|is" | sed -e 's/^.*Cipher.*://' -e 's/ //g')
				out "$cipher "
				tested_cipher="$tested_cipher:-$cipher"
			done
		outln
		done
	fi
	
	tmpfile_handle $FUNCNAME.txt
	return 0
}


server_defaults() {
	local proto 
	local gost_status_problem=false
	local now difftime
	local extensions 
	local sessticket_str lifetime unit keysize algo
	local expire ocsp_uri crl savedir startdate enddate issuer_c issuer_o issuer sans san cn cn_nosni

	outln
	pr_blue "--> Testing server defaults (Server Hello)"; outln "\n"

	# first TLS time:
	if [ -n "$STARTTLS" ] ; then
		outln " TLS timestamp:               (not yet implemented for STARTTLS) "
	else
		tls_sockets "03" "$TLS12_CIPHER"
		[ -z "$TLS_TIME" ] && tls_sockets "02" "$TLS_CIPHER"
		[ -z "$TLS_TIME" ] && tls_sockets "01" "$TLS_CIPHER"
		[ -z "$TLS_TIME" ] && tls_sockets "00" "$TLS_CIPHER"

		if [ -n "$TLS_TIME" ]; then
			difftime=$(($TLS_NOW - $TLS_TIME))
			if [[ "${#difftime}" -gt 5 ]]; then
				# openssl >= 1.0.1f fills this field with random values
				out " TLS timestamp:               random values, no fingerprinting possible "
			else
				[[ $difftime != "-"* ]] && [[ $difftime != "0" ]] && difftime="+$difftime"
				out " TLS clock skew:              $difftime sec from localtime";
			fi
			debugme out "$TLS_TIME"
			outln
		else
			out " TLS timestamp:               "; pr_litemagentaln "SSLv3 through TLS 1.2 didn't return a timestamp"
		fi
	fi

	# HTTP date:
	out " HTTP clock skew:             "
	if [[ $SERVICE != "HTTP" ]] ; then
		out "not tested as we're not tagetting HTTP"
	else
		printf "$GET_REQ11" | $OPENSSL s_client  $OPTIMAL_PROTO -ign_eof -connect $NODEIP:$PORT $SNI &>$TMPFILE
		now=$(date "+%s")
		HTTP_TIME=$(awk -F': ' '/^date:/ { print $2 }  /^Date:/ { print $2 }' $TMPFILE)
		if [ -n "$HTTP_TIME" ] ; then
			case $SYSTEM in
				*BSD|Darwin)   HTTP_TIME=$(date -j -f "%a, %d %b %Y %T %Z" "$HTTP_TIME" "+%s" 2>/dev/null) ;; # the trailing \r confuses BSD flavors otherwise
				*) 			HTTP_TIME=$(date --date="$HTTP_TIME" "+%s") ;;
			esac
			difftime=$(($now - $HTTP_TIME))
			[[ $difftime != "-"* ]] && [[ $difftime != "0" ]] && difftime="+$difftime"
			out "$difftime sec from localtime";
		else
			out "Got no HTTP time, maybe try different URL?";
		fi
		debugme out "$HTTP_TIME"
	fi
	outln

	#TLS extensions follow now
	# throwing 1st every cipher/protocol at the server to know what works
	for proto in tls1_2 tls1_1 tls1 ssl3; do
		$OPENSSL s_client $STARTTLS -connect $NODEIP:$PORT $SNI -$proto -tlsextdebug -status </dev/null 2>/dev/null >$TMPFILE	
		ret=$?
		$OPENSSL s_client $STARTTLS -connect $NODEIP:$PORT $SNI -$proto 2>/dev/null </dev/null | awk '/-----BEGIN/,/-----END/ { print $0 }'  >$HOSTCERT
		[ $? -eq 0 ] && [ $ret -eq 0 ] && break
		ret=7
	done		# this loop is need for testing IIS/6
	if [ $ret -eq 7 ]; then
		# "-status" kills GOST only servers, so we do another test without it and see whether that works then:
		if ! $OPENSSL s_client $STARTTLS -connect $NODEIP:$PORT $SNI -$proto -tlsextdebug </dev/null 2>/dev/null >$TMPFILE; then
			pr_magentaln "$OPENSSL returned an error around line $LINENO".
			tmpfile_handle tlsextdebug+status.txt
			return 7   # this is ugly, I know
		else
			gost_status_problem=true
		fi
	fi
	$OPENSSL s_client $STARTTLS -connect $NODEIP:$PORT -$proto 2>/dev/null </dev/null | awk '/-----BEGIN/,/-----END/ { print $0 }'  >$HOSTCERT.nosni
	out " TLS server extensions        "
	extensions=$(grep -aw "^TLS server extension" $TMPFILE | sed -e 's/^TLS server extension \"//' -e 's/\".*$/,/g')
	if [ -z "$extensions" ]; then
		outln "(none)"
	else
		echo $extensions | sed 's/,$//'	# remove last comma
	fi

	out " Session Tickets RFC 5077     "
	sessticket_str=$(grep -aw "session ticket" $TMPFILE | grep -a lifetime)
	if [ -z "$sessticket_str" ]; then
		outln "(none)"
	else
		lifetime=$(echo $sessticket_str | grep -a lifetime | sed 's/[A-Za-z:() ]//g')
		unit=$(echo $sessticket_str | grep -a lifetime | sed -e 's/^.*'"$lifetime"'//' -e 's/[ ()]//g')
		outln "$lifetime $unit"
	fi

	out " Server key size              "
	keysize=$(grep -aw "^Server public key is" $TMPFILE | sed -e 's/^Server public key is //')
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
#FIXME: google seems to have EC keys which displays as 256 Bit

	out " Signature Algorithm          "
	algo=$($OPENSSL x509 -in $HOSTCERT -noout -text  | grep "Signature Algorithm" | sed 's/^.*Signature Algorithm: //' | sort -u )
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
	cn=$($OPENSSL x509 -in $HOSTCERT -noout -subject | sed 's/subject= //' | sed -e 's/^.*CN=//' -e 's/\/emailAdd.*//')
	pr_underline "$cn"

	cn_nosni=$($OPENSSL x509 -in $HOSTCERT.nosni -noout -subject | sed 's/subject= //' | sed -e 's/^.*CN=//' -e 's/\/emailAdd.*//')
	[[ $DEBUG -ge 2 ]] && out "\'$NODE\' | \'$cn\' | \'$cn_nosni\'"
	if [[ $NODE == $cn_nosni ]]; then
		if [[ $SERVICE != "HTTP" ]] ; then
			outln " (matches certificate directly)"
		else
			outln " (works w/o SNI)"
		fi
	else
		if [[ $SERVICE != "HTTP" ]] ; then
			pr_brownln " (CN doesn't match but for non-HTTP services it might be ok)"
		else
			out " (CN response to request w/o SNI: "; pr_underline "$cn_nosni"; outln ")"
		fi
	fi

	sans=$($OPENSSL x509 -in $HOSTCERT -noout -text | grep -A3 "Subject Alternative Name" | grep "DNS:" | \
		sed -e 's/DNS://g' -e 's/ //g' -e 's/,/\n/g' -e 's/othername:<unsupported>//g')
#                                                          ^^^ CACert
		out " subjectAltName (SAN)         "
	if [ -n "$sans" ]; then
		sans=$(echo "$sans" | sed -e ':a' -e 'N' -e '$!ba' -e 's/\n/ /g') # replace line feed by " "
		for san in $sans; do
			out "$underline$san$off "
		done
	else
		out "-- "
	fi
	outln
	out " Issuer                       "
	issuer=$($OPENSSL x509 -in $HOSTCERT -noout -issuer | sed -e 's/^.*CN=//g' -e 's/\/.*$//g')
	issuer_o=$($OPENSSL x509 -in $HOSTCERT -noout -issuer | sed 's/^.*O=//g' | sed 's/\/.*$//g')
	if $OPENSSL x509 -in $HOSTCERT -noout -issuer | grep -q 'C=' ; then 
		issuer_c=$($OPENSSL x509 -in $HOSTCERT -noout -issuer | sed 's/^.*C=//g' | sed 's/\/.*$//g')
	else
		issuer_c="" 		# CACert would have 'issuer= ' here otherwise
	fi
	if [ "$issuer_o" == "issuer=" ] || [ "$issuer" == "$CN" ] ; then
		pr_redln "selfsigned (not OK)"
	else
		[ "$issuer_c" == "" ] && \
			outln "$underline$issuer$off ($underline$issuer_o$off" || \
			outln "$underline$issuer$off ($underline$issuer_o$off from $underline$issuer_c$off)"
	fi

	out " Certificate Expiration       "
	expire=$($OPENSSL x509 -in $HOSTCERT -checkend 0)
	if ! echo $expire | grep -qw not; then
     	pr_red "expired!"
	else
		SECS2WARN=$((24 * 60 * 60 * $DAYS2WARN2))  # low threshold first
	     expire=$($OPENSSL x509 -in $HOSTCERT -checkend $SECS2WARN)
		if echo "$expire" | grep -qw not; then
			SECS2WARN=$((24 * 60 * 60 * $DAYS2WARN2))
			expire=$($OPENSSL x509 -in $HOSTCERT -checkend $SECS2WARN)
			if echo "$expire" | grep -qw not; then
				pr_litegreen ">= $DAYS2WARN1 days"
			else
	     		pr_brown "expires < $DAYS2WARN1 days"
			fi
		else
	     		pr_litered "expires < $DAYS2WARN2 days!"
		fi
	fi
	case $SYSTEM in
		*BSD|Darwin*)
			enddate=$(date -j -f "%b %d %T %Y %Z" "$($OPENSSL x509 -in $HOSTCERT -noout -enddate | cut -d= -f 2)" +"%F %H:%M %z")
			startdate=$(date -j -f "%b %d %T %Y %Z" "$($OPENSSL x509 -in $HOSTCERT -noout -startdate | cut -d= -f 2)" +"%F %H:%M")
			;;
		*)
			enddate=$(date --date="$($OPENSSL x509 -in $HOSTCERT -noout -enddate | cut -d= -f 2)" +"%F %H:%M %z")
			startdate=$(date --date="$($OPENSSL x509 -in $HOSTCERT -noout -startdate | cut -d= -f 2)" +"%F %H:%M")
			;;
	esac
	outln " ($startdate --> $enddate)"

	savedir=$(pwd); cd $TEMPDIR
	$OPENSSL s_client -showcerts $STARTTLS -connect $NODEIP:$PORT $SNI 2>/dev/null </dev/null | \
    		awk -v c=-1 '/-----BEGIN CERTIFICATE-----/{inc=1;c++} inc {print > ("level" c ".crt")} /---END CERTIFICATE-----/{inc=0}'
	nrsaved=$(ls $TEMPDIR/level?.crt 2>/dev/null | wc -w | sed 's/^ *//')
	outln " # of certificates provided   $nrsaved"
	cd $savedir

	out " Certificate Revocation List  "
	crl=$($OPENSSL x509 -in $HOSTCERT -noout -text | grep -A 4 "CRL Distribution" | grep URI | sed 's/^.*URI://')
	[ x"$crl" == "x" ] && pr_literedln "--" || echo "$crl"

	out " OCSP URI                     "
	ocsp_uri=$($OPENSSL x509 -in $HOSTCERT -noout -ocsp_uri)
	[ x"$ocsp_uri" == "x" ] && pr_literedln "--" || echo "$ocsp_uri"

	out " OCSP stapling               "
	if grep "OCSP response" $TMPFILE | grep -q "no response sent" ; then
		out " not offered"
	else
		if grep "OCSP Response Status" $TMPFILE | grep -q successful; then
			pr_litegreen " OCSP stapling offered"
		else
			if [ $gost_status_problem = "true" ]; then
				outln " (GOST servers make problems here, sorry)"
				ret=0
			else
				outln " not sure what's going on here, debug:"
				grep -A 20 "OCSP response"  $TMPFILE
				ret=2
			fi
		fi
	fi
	outln

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
	# https://community.qualys.com/blogs/securitylabs/2013/08/05/configuring-apache-nginx-and-openssl-for-forward-secrecy -- but with RC4:
	#local pfs_ciphers='EECDH+ECDSA+AESGCM EECDH+aRSA+AESGCM EECDH+ECDSA+SHA256 EECDH+aRSA+SHA256 EECDH+aRSA+RC4 EDH+aRSA EECDH RC4 !RC4-SHA !aNULL !eNULL !LOW !3DES !MD5 !EXP !PSK !SRP !DSS:@STRENGTH'
	local pfs_ciphers='EECDH+ECDSA+AESGCM EECDH+aRSA+AESGCM EECDH+ECDSA+SHA256 EECDH+aRSA+SHA256 EDH+aRSA EECDH !RC4-SHA !aNULL !eNULL !LOW !3DES !MD5 !EXP !PSK !SRP !DSS:@STRENGTH'
	# ^^^ the exclusion via ! doesn't work with libressl and openssl 0.9.8

	outln
	pr_blue "--> Testing (perfect) forward secrecy, (P)FS"; outln " -- omitting 3DES, RC4 and Null Encryption here"

	$OPENSSL ciphers -V "$pfs_ciphers" >$TMPFILE 2>/dev/null	# -V doesn't work with openssl < 1.0
	if [ $? -ne 0 ] ; then
		number_pfs=$(wc -l < $TMPFILE | sed 's/ //g')
		if [ "$number_pfs" -le "$CLIENT_MIN_PFS" ] ; then
			# this will be called also if the ! and @ syntax can't be understood
			outln
			pr_magentaln " Local problem: you only have $number_pfs PFS ciphers on the client side "
			[ $number_pfs -ne 0 ] && cat $TMPFILE 
			return 1
		fi
	fi
	savedciphers=$(cat $TMPFILE)
	[ $SHOW_LOC_CIPH -eq 0 ] && echo "local ciphers available for testing PFS:" && echo $(cat $TMPFILE)

	$OPENSSL s_client -cipher 'ECDH:DH' $STARTTLS -connect $NODEIP:$PORT $SNI &>$TMPFILE </dev/null
	ret=$?
	outln
	if [ $ret -ne 0 ] || [ $(grep -ac "BEGIN CERTIFICATE" $TMPFILE) -eq 0 ]; then
		pr_brownln "Not OK: No ciphers supporting Forward Secrecy offered"
	else
		pr_litegreen "OK: PFS is offered. "; 
		outln "Client/browser support is important here. Offered PFS server ciphers follow... \n"
		none=0
		neat_header
		while read hexcode n ciph sslvers kx auth enc mac; do
			$OPENSSL s_client -cipher $ciph $STARTTLS -connect $NODEIP:$PORT $SNI &>/dev/null </dev/null
			ret2=$?
			if [[ $ret2 -ne 0 ]] && [[ "$SHOW_EACH_C" -eq 0 ]] ; then
				continue # no successful connect AND not verbose displaying each cipher
			fi
			normalize_ciphercode $hexcode
			neat_list $HEXC $ciph $kx $enc $strength
			let "none++"
			if [[ "$SHOW_EACH_C" -ne 0 ]] ; then
				if [[ $ret2 -eq 0 ]]; then
					pr_green "works"
				else
					out "not a/v"
				fi
			fi
			outln
		done < <($OPENSSL ciphers -V "$pfs_ciphers")		# -V doesn't work with openssl < 1.0
		#    ^^^^^ posix redirect as shopt will either segfault or doesn't work with old bash versions
		debugme echo $none

		if [ "$none" -eq 0 ] ; then
			 pr_brown "no PFS ciphers found"
			 ret=1
		else
			 ret=0
		fi
	fi
	outln

	tmpfile_handle $FUNCNAME.txt
	return $ret
}


# good source for configuration and bugs: https://wiki.mozilla.org/Security/Server_Side_TLS
# good start to read: http://en.wikipedia.org/wiki/Transport_Layer_Security#Attacks_against_TLS.2FSSL

spdy_pre(){
	if [ ! -z "$STARTTLS" ]; then
		out "\n     (SPDY is a HTTP protocol and thus not tested here)"
		return 1
	fi
	# first, does the current openssl support it?
	$OPENSSL s_client help 2>&1 | grep -qw nextprotoneg
	if [ $? -ne 0 ]; then
		pr_magentaln "Local problem: $OPENSSL doesn't support SPDY/NPN"; 
		return 7
	fi
	return 0
}

spdy() {
	out " SPDY/NPN   "
	spdy_pre || return 0
	$OPENSSL s_client -host $NODE -port $PORT -nextprotoneg $NPN_PROTOs </dev/null 2>/dev/null >$TMPFILE
	tmpstr=$(grep -a '^Protocols' $TMPFILE | sed 's/Protocols.*: //')
	if [ -z "$tmpstr" -o "$tmpstr" = " " ] ; then
		out "not offered"
		ret=1
	else
		# now comes a strange thing: "Protocols advertised by server:" is empty but connection succeeded
		if echo $tmpstr | egrep -aq "spdy|http" ; then
			pr_bold "$tmpstr" ; out " (advertised)"
			ret=0
		else
			pr_litemagenta "please check manually, server response was ambigious ..."
			ret=10
		fi
	fi
	outln
	# btw: nmap can do that too http://nmap.org/nsedoc/scripts/tls-nextprotoneg.html
	# nmap --script=tls-nextprotoneg #NODE -p $PORT is your friend if your openssl doesn't want to test this
	tmpfile_handle $FUNCNAME.txt
	return $ret
}

# arg for a fd doesn't work here
fd_socket() {
	if ! exec 5<>/dev/tcp/$NODEIP/$PORT; then	#  2>/dev/null removes an error message, but disables debugging
		outln
		pr_magenta "Unable to open a socket to $NODEIP:$PORT"
		# It can last ~2 minutes but for for those rare occasions we don't do a tiemout handler here, KISS
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


###### new funcs for network follow 

# first: helper function for protocol checks

code2network() {
	# arg1: formatted string here in the code
	NW_STR=$(echo "$1" | sed -e 's/,/\\\x/g' | sed -e 's/# .*$//g' -e 's/ //g' -e '/^$/d' | tr -d '\n' | tr -d '\t')
}

len2twobytes() {
     len_arg1=$(echo ${#1})
     [[ $len_arg1 -le 2 ]] && LEN_STR=$(printf "00, %02s \n" $1)
     [[ $len_arg1 -eq 3 ]] && LEN_STR=$(printf "%02s, %02s \n" ${1:0:1} ${1:1:2})
     [[ $len_arg1 -eq 4 ]] && LEN_STR=$(printf "%02s, %02s \n" ${1:0:2} ${1:2:2})
}

socksend_sslv2_clienthello() {
	code2network "$1"
	data=$(echo $NW_STR)
	[[ "$DEBUG" -ge 4 ]] && echo "\"$data\""
	printf -- "$data" >&5 2>/dev/null &
	sleep $USLEEP_SND
}

# for SSLv2 to TLS 1.2:
sockread_serverhello() {
     [[ -z "$2" ]] && maxsleep=$MAX_WAITSOCK || maxsleep=$2

     SOCK_REPLY_FILE=$(mktemp $TEMPDIR/ddreply.XXXXXX) || return 7
     dd bs=$1 of=$SOCK_REPLY_FILE count=1 <&5 2>/dev/null &
     pid=$!

	wait_kill $pid $maxsleep
	return $?
}

# arg1: name of file with socket reply
display_sslv2_serverhello() {
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

	local ret=3

	v2_hello_ascii=$(hexdump -v -e '16/1 "%02X"' $1)
	[[ "$DEBUG" -ge 5 ]] && echo $v2_hello_ascii
	if [[ -z $v2_hello_ascii ]] ; then
		ret=0								# 1 line without any blanks: no server hello received
		debugme echo "server hello empty"
	else
		# now scrape two bytes out of the reply per byte
		v2_hello_initbyte="${v2_hello_ascii:0:1}"  # normally this belongs to the next, should be 8!
		v2_hello_length="${v2_hello_ascii:1:3}"    # + 0x8000 see above
		v2_hello_handshake="${v2_hello_ascii:4:2}"
		v2_hello_cert_length="${v2_hello_ascii:14:4}"
		v2_hello_cipherspec_length="${v2_hello_ascii:18:4}"

		V2_HELLO_CIPHERSPEC_LENGTH=$(printf "%d\n" "0x$v2_hello_cipherspec_length" 2>/dev/null)
		[ $? -ne 0 ] && ret=7

		if [[ $v2_hello_initbyte != "8" ]] || [[ $v2_hello_handshake != "04" ]]; then
			ret=1
			if [[ $DEBUG -ge 2 ]]; then
				echo "no correct server hello"
				echo "SSLv2 server init byte:    0x0$v2_hello_initbyte"
				echo "SSLv2 hello handshake :    0x$v2_hello_handshake"
			fi
		fi

		if [[ $DEBUG -ge 3 ]]; then
			echo "SSLv2 server hello length: 0x0$v2_hello_length"
			echo "SSLv2 certificate length:  0x$v2_hello_cert_length"
			echo "SSLv2 cipher spec length:  0x$v2_hello_cipherspec_length"
		fi
	fi
	return $ret
}


# arg1: name of file with socket reply
display_tls_serverhello() {
	# server hello, handshake details see http://en.wikipedia.org/wiki/Transport_Layer_Security-SSL#TLS_record
	# byte 0:      type: x16=TLS, 0x15=TLS alert, 0x14=CCS, 0x18=HB
	# byte 1+2:    TLS version word, see below. 1st byte is always 03
	# byte 3+4:    length all				
	# byte 5:      handshake type (2=hello)    TLS alert: level (2=fatal), descr (0x28=handshake failure)
	# byte 6+7+8:  length server hello       
	# byte 9+10:   03, TLS version byte       (00=SSL3, 01=TLS1 02=TLS1.1 03=TLS 1.2
	# byte 11-14:  TLS timestamp
	# byte 15-42:  random, 28 bytes
	# byte 43:     session id length
	# byte 44+45+sid-len:  cipher suite!
	# byte 46+sid-len:     compression method:  00: none, 01: deflate
	# byte 47+48+sid-len:  extension length

	tls_hello_ascii=$(hexdump -v -e '16/1 "%02X"' $1)
	[[ "$DEBUG" -eq 5 ]] && echo $tls_hello_ascii      # one line without any blanks
	[[ -z $tls_hello_ascii ]] && debugme echo "server hello empty, TCP connection closed" && return 0              # no server hello received

	# now scrape two bytes out of the reply per byte
	tls_hello_initbyte="${tls_hello_ascii:0:2}"  # normally this is x16
	tls_hello_protocol="${tls_hello_ascii:2:4}"
	tls_len_all=${tls_hello_ascii:6:4}

	if [[ $tls_hello_initbyte != "16" ]] ; then
		if [[ $DEBUG -ge 2 ]]; then
			echo "tls_hello_initbyte:  0x$tls_hello_initbyte"
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
	TLS_TIME=$(printf "%d\n" 0x$tls_hello_time)
	case $SYSTEM in
		*BSD|Darwin)	tls_time=$(date -j -f %s "$TLS_TIME" "+%Y-%m-%d %r") ;;
		*)			tls_time=$(date --date="@$TLS_TIME" "+%Y-%m-%d %r") ;;
	esac
	tls_sid_len=$(printf "%d\n" 0x${tls_hello_ascii:86:2})
	let sid_offset=88+$tls_sid_len*2
	tls_cipher_suite="${tls_hello_ascii:$sid_offset:4}"
	let sid_offset=92+$tls_sid_len*2
	tls_compression_method="${tls_hello_ascii:$sid_offset:2}"

	if [[ $DEBUG -ge 2 ]]; then
		echo "tls_hello:           0x$tls_hello"
		if [[ $DEBUG -ge 4 ]]; then
			echo "tls_hello_protocol2: 0x$tls_hello_protocol2"
			echo "tls_sid_len:         $tls_sid_len"
		fi
		echo "tls_hello_time:      0x$tls_hello_time ($tls_time)"
		echo "tls_cipher_suite:    0x$tls_cipher_suite"
		echo "tls_compression_method: 0x$tls_compression_method"
		outln
	fi

	return 0
}


sslv2_sockets() {
	local ciphers_detected

	fd_socket 5 || return 6
	[[ "$DEBUG" -ge 2 ]] && outln "sending client hello... "
	socksend_sslv2_clienthello "$SSLv2_CLIENT_HELLO"

	sockread_serverhello 32768 
	[[ "$DEBUG" -ge 2 ]] && outln "reading server hello... "
	if [[ "$DEBUG" -ge 4 ]]; then
		hexdump -C $SOCK_REPLY_FILE | head -6
		outln
	fi

	display_sslv2_serverhello "$SOCK_REPLY_FILE"
	case $? in
		7) # strange reply, couldn't convert the cipher spec length to a hex number
			pr_litemagenta "strange v2 reply "
			outln " (rerun with DEBUG >=2)"
			[[ $DEBUG -ge 3 ]] && hexdump -C $SOCK_REPLY_FILE | head -1
			ret=7 ;;
		1) # no sslv2 server hello returned, like in openlitespeed which returns HTTP!
			pr_greenln "not offered (OK)"
			ret=0 ;;
		0) # reset
			pr_greenln "not offered (OK)"
			ret=0 ;;
		3) # everything else
			lines=$(hexdump -C "$SOCK_REPLY_FILE" 2>/dev/null | wc -l | sed 's/ //g')
			[[ "$DEBUG" -ge 2 ]] && out "  ($lines lines)  "
			if [[ "$lines" -gt 1 ]] ;then
				ciphers_detected=$(($V2_HELLO_CIPHERSPEC_LENGTH / 3 ))
				if [ 0 -eq "$ciphers_detected" ] ; then
					pr_litered "supported but couldn't detect a cipher"; outln "(may need further attention)"
				else
					pr_red "offered (NOT ok)"; outln " -- $ciphers_detected ciphers"
				fi
				ret=1
			fi ;;
	esac 
	pr_off
	debugme outln

	close_socket
	TMPFILE=$SOCK_REPLY_FILE
	tmpfile_handle $FUNCNAME.dd
	return $ret
}


# ARG1: TLS version low byte (00: SSLv3,  01: TLS 1.0,  02: TLS 1.1,  03: TLS 1.2)
# ARG2: CIPHER_SUITES string
socksend_tls_clienthello() {
	local tls_low_byte
	local servername_hexstr len_servername len_servername_hex
	local hexdump_format_str
	local len_sni_listlen len_sni_ext len_extension_hex
	local cipher_suites len_ciph_suites len_ciph_suites_word
	local len_client_hello_word len_all_word

	tls_low_byte="$1"
	len_servername=$(echo ${#NODE})
	hexdump_format_str="$len_servername/1 \"%02x,\""
	servername_hexstr=$(printf $NODE | hexdump -v -e "${hexdump_format_str}" | sed 's/,$//')

	code2network "$2"        # CIPHER_SUITES
	cipher_suites="$NW_STR"	# we don't have the leading \x here so string length is two byte less, see next

#formatted example for SNI
#00 00 	# extension server_name
#00 1a    # length       			= the following +2 = server_name length + 5
#00 18    # server_name list_length	= server_name length +3
#00 		# server_name type (hostname)
#00 15 	# server_name length
#66 66 66 66 66 66 2e 66 66 66 66 66 66 66 66 66 66 2e 66 66 66  target.mydomain1.tld # server_name target

	# convert lengths we need to fill in from dec to hex:
	len_servername_hex=$(printf "%02x\n" $len_servername)
	len_sni_listlen=$(printf "%02x\n" $((len_servername+3)))
	len_sni_ext=$(printf "%02x\n" $((len_servername+5)))
	len_extension_hex=$(printf "%02x\n" $((len_servername+9)))

	len_ciph_suites_byte=$(echo ${#cipher_suites})
	let "len_ciph_suites_byte += 2"

	# we have additional 2 chars \x in each 2 byte string and 2 byte ciphers, so we need to divide by 4:
	len_ciph_suites=$(printf "%02x\n" $(($len_ciph_suites_byte / 4 )))
	len2twobytes "$len_ciph_suites"
	len_ciph_suites_word="$LEN_STR"
	#[[ $DEBUG -ge 3 ]] && echo $len_ciph_suites_word

	# RFC 3546 doesn't specify SSLv3 to have SNI, openssl just ignores the switch if supplied
	if [ "$tls_low_byte" == "00" ]; then
		len2twobytes $(printf "%02x\n" $((0x$len_ciph_suites + 0x27)))
	else
		len2twobytes $(printf "%02x\n" $((0x$len_ciph_suites + 0x27 + 0x$len_extension_hex + 0x2)))
	fi
	len_client_hello_word="$LEN_STR"
	#[[ $DEBUG -ge 3 ]] && echo $len_client_hello_word

	if [ "$tls_low_byte" == "00" ]; then
		len2twobytes $(printf "%02x\n" $((0x$len_ciph_suites + 0x2b)))
	else
		len2twobytes $(printf "%02x\n" $((0x$len_ciph_suites + 0x2b + 0x$len_extension_hex + 0x2)))
	fi
	len_all_word="$LEN_STR"
	#[[ $DEBUG -ge 3 ]] && echo $len_all_word

	TLS_CLIENT_HELLO="
	# TLS header ( 5 bytes)
	,16, 03, $tls_low_byte   # TLS Version
	,$len_all_word           # Length  <---
	# Handshake header:
	,01                      # Type (x01 for ClientHello)
	,00, $len_client_hello_word   # Length ClientHello
	,03, $tls_low_byte       # TLS Version (again)
	,54, 51, 1e, 7a          # Unix time since  see www.moserware.com/2009/06/first-few-milliseconds-of-https.html
	,de, ad, be, ef          # Random 28 bytes
	,31, 33, 07, 00, 00, 00, 00, 00
	,cf, bd, 39, 04, cc, 16, 0a, 85
	,03, 90, 9f, 77, 04, 33, d4, de
	,00                      # Session ID length
	,$len_ciph_suites_word   # Cipher suites length
	,$cipher_suites
	,01                      # Compression methods length
	,00"                     # Compression method (x00 for NULL)

	if [ "$tls_low_byte" == "00" ]; then
		EXTENSION_CONTAINING_SNI=""  # RFC 3546 doesn't specify SSLv3 to have SNI, openssl just ignores the switch if supplied
	else
		EXTENSION_CONTAINING_SNI="
		,00, $len_extension_hex  # first the len of all (here: 1) extentions. We assume len(hostname) < FF - 9
		,00, 00                  # extension server_name
		,00, $len_sni_ext        # length SNI EXT
		,00, $len_sni_listlen    # server_name list_length
		,00                      # server_name type (hostname)
		,00, $len_servername_hex # server_name length
		,$servername_hexstr"     # server_name target
	fi
	fd_socket 5 || return 6

	code2network "$TLS_CLIENT_HELLO$EXTENSION_CONTAINING_SNI"
	data=$(echo $NW_STR)
	[[ "$DEBUG" -ge 4 ]] && echo "\"$data\""
	printf -- "$data" >&5 2>/dev/null &
	sleep $USLEEP_SND

	return 0
}

# ARG1: TLS version low byte (00: SSLv3,  01: TLS 1.0,  02: TLS 1.1,  03: TLS 1.2)
tls_sockets() {
	local ret save
	local lines
	local tls_low_byte
	local cipher_list_2send

	tls_low_byte="$1"
	if [ -n "$2" ]; then			# use supplied arg2 if there
		cipher_list_2send="$2"				
	else 						# otherwise use std ciphers then
		if [ "$tls_low_byte" = "03" ]; then
			cipher_list_2send="$TLS12_CIPHER"
		else
			cipher_list_2send="$TLS_CIPHER"
		fi
	fi

	[[ "$DEBUG" -ge 2 ]] && echo "sending client hello..."
	socksend_tls_clienthello "$tls_low_byte" "$cipher_list_2send"
	ret=$?	# 6 means opening socket didn't succeed, e.g. timeout


	# if sending didn't succeed we don't bother
	if [ $ret -eq 0 ]; then
		sockread_serverhello 32768 
		TLS_NOW=$(date "+%s")
		[[ "$DEBUG" -ge 2 ]] && outln "reading server hello..."
		if [[ "$DEBUG" -ge 3 ]]; then
			hexdump -C $SOCK_REPLY_FILE | head -6
			echo
		fi

		display_tls_serverhello "$SOCK_REPLY_FILE"
		save=$?

		# see https://secure.wand.net.nz/trac/libprotoident/wiki/SSL
		lines=$(hexdump -C "$SOCK_REPLY_FILE" 2>/dev/null | wc -l | sed 's/ //g')
		[[ "$DEBUG" -ge 2 ]] && out "  (returned $lines lines)  " 

#	printf "Protokoll "; tput bold; printf "$tls_low_byte = $tls_str"; tput sgr0; printf ":  "

		# determine the return value for higher level, so that they can tell what the result is
		if [[ $save -eq 1 ]] || [[ $lines -eq 1 ]] ; then
			ret=1	# NOT available
		else
			if [[ 03$tls_low_byte -eq $DETECTED_TLS_VERSION ]]; then
				ret=0	# available
			else
				[[ $DEBUG -ge 2 ]] && echo -n "send: 0x03$tls_low_byte, returned: 0x$DETECTED_TLS_VERSION" 
				ret=2	# NOT available, server downgraded
			fi
		fi
		debugme outln
	else
		debugme "stuck on sending: $ret"
	fi

	close_socket
	TMPFILE=$SOCK_REPLY_FILE
	tmpfile_handle $FUNCNAME.dd
	return $ret
}


####### vulnerabilities follow #######

# general overview which browser supports which vulnerability:
# http://en.wikipedia.org/wiki/Transport_Layer_Security-SSL#Web_browsers


# mainly adapted from https://gist.github.com/takeshixx/10107280
heartbleed(){
	[ $VULN_COUNT -le $VULN_THRESHLD ]  && outln && pr_blue "--> Testing for heartbleed vulnerability" && outln "\n"
	pr_bold " Heartbleed\c"; out " (CVE-2014-0160)                "

     if [ ! -z "$STARTTLS" ] ; then
		outln "(not yet implemented for STARTTLS)"
		return 0
	fi

	# determine TLS versions available:
	$OPENSSL s_client $STARTTLS -connect $NODEIP:$PORT -tlsextdebug &>$TMPFILE </dev/null
		
	tls_proto_offered=$(grep -aw Protocol $TMPFILE | sed -E 's/[^[:digit:]]//g')
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
	sockread 16384 $HEARTBLEED_MAX_WAITSOCK
	retval=$?

	if [[ $DEBUG -ge 3 ]]; then
		outln "\nheartbleed reply: "
		echo "$SOCKREPLY" | "${HEXDUMPVIEW[@]}"
		outln
	fi

	lines_returned=$(echo "$SOCKREPLY" | "${HEXDUMP[@]}" | wc -l | sed 's/ //g')
	if [ $lines_returned -gt 1 ]; then
		pr_red "VULNERABLE (NOT ok)"
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

# helper function
ok_ids(){
	pr_greenln "\n ok -- something resetted our ccs packets"
	return 0
}

#FIXME: At a certain point heartbleed and ccs needs to be changed and make use of code2network using a file, then tls_sockets
ccs_injection(){
	# see https://www.openssl.org/news/secadv_20140605.txt
	# mainly adapted from Ramon de C Valle's C code from https://gist.github.com/rcvalle/71f4b027d61a78c42607
	[ $VULN_COUNT -le $VULN_THRESHLD ]  && outln && pr_blue "--> Testing for CCS injection vulnerability" && outln "\n"
	pr_bold " CCS "; out " (CVE-2014-0224)                      "

     if [ ! -z "$STARTTLS" ] ; then
		outln "(not yet implemented for STARTTLS)"
		return 0
	fi
	$OPENSSL s_client $STARTTLS -connect $NODEIP:$PORT &>$TMPFILE </dev/null

	tls_proto_offered=$(grep -aw Protocol $TMPFILE | sed -E 's/[^[:digit:]]//g')
	#tls_proto_offered=$(grep -aw Protocol $TMPFILE | sed 's/^.*Protocol//')
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
	sockread 2048 $CCS_MAX_WAITSOCK
	if [[ $DEBUG -ge 3 ]]; then
		outln "\n1st reply: " 
		out "$SOCKREPLY" | "${HEXDUMPVIEW[@]}" | head -20
# ok:      15 | 0301 | 02 | 02 0a == ALERT | TLS 1.0 | Length=2 | Unexpected Message (0a)
		outln
		outln "payload #2 with TLS version $tls_hexcode:"
	fi

	socksend "$ccs_message" 2 || ok_ids
	sockread 2048 $CCS_MAX_WAITSOCK
	retval=$?

	if [[ $DEBUG -ge 3 ]]; then
		outln "\n2nd reply: "
		out "$SOCKREPLY" | "${HEXDUMPVIEW[@]}"
# not ok:  15 | 0301 | 02 | 02 | 15 == ALERT | TLS 1.0 | Length=2 | Decryption failed (21)
# ok:  0a or nothing: ==> RST
		outln
	fi

	reply_sanitized=$(echo "$SOCKREPLY" | "${HEXDUMPPLAIN[@]}" | sed 's/^..........//')
	lines=$(echo "$SOCKREPLY" | "${HEXDUMP[@]}" | wc -l | sed 's/ //g')

	if [ "$reply_sanitized" == "0a" ] || [ "$lines" -gt 1 ] ; then
		pr_green "not vulnerable (OK)"
		ret=0
	else
		pr_red "VULNERABLE (NOT ok)"
		ret=1
	fi
	[ $retval -eq 3 ] && out "(timed out)"
	outln 

	close_socket
	tmpfile_handle $FUNCNAME.txt
	return $ret
}

renego() {
# no SNI here. Not needed as there won't be two different SSL stacks for one IP
	local legacycmd=""
	local insecure_renogo_str
	local sec_renego sec_client_renego

	[ $VULN_COUNT -le $VULN_THRESHLD ]  && outln && pr_blue "--> Testing for Renegotiation vulnerability" && outln "\n"

	pr_bold " Secure Renegotiation "; out "(CVE 2009-3555)      " 	# and RFC5746, OSVDB 59968-59974
														# community.qualys.com/blogs/securitylabs/2009/11/05/ssl-and-tls-authentication-gap-vulnerability-discovered
	insecure_renogo_str="Secure Renegotiation IS NOT"
	$OPENSSL s_client $STARTTLS -connect $NODEIP:$PORT 2>&1 </dev/null | grep -iaq "$insecure_renogo_str"
	sec_renego=$?											# 0= Secure Renegotiation IS NOT supported
#FIXME: didn't occur to me yet but why not also to check on "Secure Renegotiation IS supported"
	case $sec_renego in
		0) pr_redln "VULNERABLE (NOT ok)" ;;
		1) pr_greenln "not vulnerable (OK)" ;;
		*) pr_magentaln "FIXME (bug): $sec_renego" ;;
	esac

	pr_bold " Secure Client-Initiated Renegotiation     "	# RFC 5746
	# see: https://community.qualys.com/blogs/securitylabs/2011/10/31/tls-renegotiation-and-denial-of-service-attacks
	#      http://blog.ivanristic.com/2009/12/testing-for-ssl-renegotiation.html -- head/get doesn't seem to be needed though
	case "$OSSL_VER" in
		0.9.8*)  			# we need this for Mac OSX unfortunately
			case "$OSSL_VER_APPENDIX" in
				[a-l]) pr_magenta "Your $OPENSSL $OSSL_VER cannot test the secure renegotiation vulnerability"
					  return 3 ;;
				[m-z]) ;; # all ok
			esac ;;
		1.0.1*|1.0.2*) legacycmd="-legacy_renegotiation" ;;
		0.9.9*|1.0*) ;;   # all ok 
	esac

	# We need up to two tries here, as some LiteSpeed servers don't answer on "R" and block. Thus first try in the background
	echo R | $OPENSSL s_client $legacycmd $STARTTLS -msg -connect $NODEIP:$PORT &>$TMPFILE & 	# msg enables us to look deeper into it while debugging
	wait_kill $! $HEADER_MAXSLEEP
	if [ $? -eq 3 ]; then
		pr_litegreen "likely not vulnerable (OK)"; outln "(timed out)" 					# it hung
		sec_client_renego=1
	else
		# second try in the foreground as we are sure now it won't hang
		echo R | $OPENSSL s_client $legacycmd $STARTTLS -msg -connect $NODEIP:$PORT &>$TMPFILE
		sec_client_renego=$?													# 0=client is renegotiating & doesn't return an error --> vuln!
		case $sec_client_renego in
			0) pr_litered "VULNERABLE (NOT ok)"; outln ", DoS threat" ;;
			1) pr_litegreenln "not vulnerable (OK)" ;;
			*) "FIXME (bug): $sec_client_renego" ;;
		esac
	fi

	#FIXME Insecure Client-Initiated Renegotiation is missing

	tmpfile_handle $FUNCNAME.txt
	return $(($sec_renego + $sec_client_renego))
#FIXME: the return value is wrong, should be 0 if all ok. But as the caller doesn't care we don't care either ... yet ;-)
}

crime() {
	# in a nutshell: don't offer TLS/SPDY compression on the server side
	# This tests for CRIME Vulnerability (www.ekoparty.org/2012/juliano-rizzo.php) on HTTPS, not SPDY (yet)
     # Please note that it is an attack where you need client side control, so in regular situations this
	# means anyway "game over", w/wo CRIME
	# www.h-online.com/security/news/item/Vulnerability-in-SSL-encryption-is-barely-exploitable-1708604.html

	[ $VULN_COUNT -le $VULN_THRESHLD ]  && outln && pr_blue "--> Testing for CRIME vulnerability" && outln "\n"
	pr_bold " CRIME, TLS " ; out "(CVE-2012-4929)                "

	case "$OSSL_VER" in
		0.9.8*)      ADDCMD="-no_ssl2" ;;
		0.9.9*|1.0*) ADDCMD="" ;;
	esac

	# first we need to test whether OpenSSL binary has zlib support
	$OPENSSL zlib -e -a -in /dev/stdin &>/dev/stdout </dev/null | grep -q zlib 
	if [ $? -eq 0 ]; then
		pr_magentaln "Local Problem: Your $OPENSSL lacks zlib support"
		return 7  
	fi

	#STR=$($OPENSSL s_client $ADDCMD $STARTTLS -connect $NODEIP:$PORT $SNI 2>&1 </dev/null | grep Compression )
	$OPENSSL s_client $ADDCMD $STARTTLS -connect $NODEIP:$PORT $SNI </dev/null &>$TMPFILE
	if grep -a Compression $TMPFILE | grep -aq NONE >/dev/null; then
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

#			STR=$(grep Compression $TMPFILE )
#			if echo $STR | grep -q NONE >/dev/null; then
#				pr_green "not vulnerable (OK)"
#				ret=$(($ret + 0))
#			else
#				pr_red "VULNERABLE (NOT ok)"
#				ret=$(($ret + 1))
#			fi
#		fi
#	fi
	[ $VERBERR -eq 0 ] && outln "$STR"
	#echo
	tmpfile_handle $FUNCNAME.txt
	return $ret
}

# BREACH is a HTTP-level compression & an attack which works against any cipher suite and is agnostic
# to the version of TLS/SSL, more: http://www.breachattack.com/ . Foreign referers are the important thing here!
breach() {
	[[ $SERVICE != "HTTP" ]] && return 7

	[ $VULN_COUNT -le $VULN_THRESHLD ]  && outln && pr_blue "--> Testing for BREACH (HTTP compression) vulnerability" && outln "\n"
	pr_bold " BREACH"; out " (CVE-2013-3587)                    "

	url="$1"
	[ -z "$url" ] && url="/"
	if [ $SNEAKY -eq 0 ] ; then
		# see https://community.qualys.com/message/20360
		if [[ "$NODE" =~ google ]]; then  
			referer="http://yandex.ru/" # otherwise we have a false positive for google.com 
		else
			referer="http://google.com/"
		fi
		useragent="$UA_SNEAKY"
	else
		referer="TLS/SSL-Tester from $SWURL"
		useragent="$UA_STD"
	fi
	(
	$OPENSSL s_client $OPTIMAL_PROTO -quiet -connect $NODEIP:$PORT $SNI << EOF
GET $url HTTP/1.1
Host: $NODE
User-Agent: $useragent
Accept: text/*
Accept-Language: en-US,en
Accept-encoding: gzip,deflate,compress
Referer: $referer
Connection: close

EOF
) &>$HEADERFILE_BREACH &
	pid=$!
	if wait_kill $pid $HEADER_MAXSLEEP; then
		result=$(grep -a '^Content-Encoding' $HEADERFILE_BREACH | sed -e 's/^Content-Encoding//' -e 's/://' -e 's/ //g')
		result=$(echo $result | tr -cd '\40-\176')
		if [ -z $result ]; then
			pr_green "no HTTP compression (OK) " 
			ret=0
		else
			pr_litered "NOT ok: uses $result HTTP compression "
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


# Padding Oracle On Downgraded Legacy Encryption, in a nutshell: don't use CBC Ciphers in SSLv3 
ssl_poodle() {
	local ret
	local cbc_ciphers

	[ $VULN_COUNT -le $VULN_THRESHLD ]  && outln && pr_blue "--> Testing for SSLv3 POODLE (Padding Oracle On Downgraded Legacy Encryption)" && outln "\n"
	pr_bold " POODLE, SSL"; out " (CVE-2014-3566)               "
	cbc_ciphers=$($OPENSSL ciphers -v 'ALL:eNULL' | awk '/CBC/ { print $1 }' | tr '\n' ':')
#FIXME: even with worst openssl client (FreeBSD9) we have 17 reasonable ciphers but is that enough to check??
	debugme echo $cbc_ciphers
	$OPENSSL s_client -ssl3 $STARTTLS -cipher $cbc_ciphers -connect $NODEIP:$PORT $SNI &>$TMPFILE </dev/null
	ret=$?
	[ "$VERBERR" -eq 0 ] && egrep -q "error|failure" $TMPFILE | egrep -av "unable to get local|verify error"
	if [ $ret -eq 0 ]; then
		pr_litered "VULNERABLE (NOT ok)"; out ", uses SSLv3+CBC (no TLS_FALLBACK_SCSV mitigation tested)"
	else
		pr_green "not vulnerable (OK)"
	fi
	outln 
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


# Factoring RSA Export Keys: don't use EXPORT RSA ciphers, see https://freakattack.com/
freak() {
	local ret
	local exportrsa_ciphers
	local addtl_warning=""

	[ $VULN_COUNT -le $VULN_THRESHLD ]  && outln && pr_blue "--> Testing for FREAK attack" && outln "\n"
	pr_bold " FREAK "; out " (CVE-2015-0204), experimental      "
	no_exportrsa_ciphers=$($OPENSSL ciphers -v 'ALL:eNULL' | egrep -a "^EXP.*RSA" | wc -l | sed 's/ //g')
	exportrsa_ciphers=$($OPENSSL ciphers -v 'ALL:eNULL' | awk '/^EXP.*RSA/ {print $1}' | tr '\n' ':')
	debugme echo $exportrsa_ciphers
	# with correct build it should list these 7 ciphers (plus the two latter as SSLv2 ciphers):
	# EXP1024-DES-CBC-SHA:EXP1024-RC4-SHA:EXP-EDH-RSA-DES-CBC-SHA:EXP-DH-RSA-DES-CBC-SHA:EXP-DES-CBC-SHA:EXP-RC2-CBC-MD5:EXP-RC4-MD5
	case $no_exportrsa_ciphers in
		0) 	pr_magentaln "Local problem: your $OPENSSL doesn't have any EXPORT RSA ciphers configured" 
			return 3 ;;
		1,2,3) 
			addtl_warning=" (tested only with $no_exportrsa_ciphers out of 9 ciphers)" ;;
		7,8,9,10,11)
			addtl_warning="" ;;
		4,5,6) 
			addtl_warning=" (tested with $no_exportrsa_ciphers/9 ciphers)" ;;
	esac
	$OPENSSL s_client $STARTTLS -cipher $exportrsa_ciphers -connect $NODEIP:$PORT $SNI &>$TMPFILE </dev/null
	ret=$?
	[ "$VERBERR" -eq 0 ] && egrep -a "error|failure" $TMPFILE | egrep -av "unable to get local|verify error"
	if [ $ret -eq 0 ]; then
		pr_red "VULNERABLE (NOT ok)"; out ", uses EXPORT RSA ciphers"
	else
		pr_green "not vulnerable (OK)"; out "$addtl_warning"
	fi
	outln 

	tmpfile_handle $FUNCNAME.txt
	return $ret	
}


# Browser Exploit Against SSL/TLS: don't use CBC Ciphers in SSLv3 TLSv1.0
beast(){
	local hexcode dash cbc_cipher sslvers kx auth enc mac export
	local detected_proto
	local detected_cbc_cipher=""
	local higher_proto_supported=""
	local -i ret=0
	local spaces="                                           "
	local cr=$'\n'
	local first=true

	[ $VULN_COUNT -le $VULN_THRESHLD ]  && outln && pr_blue "--> Testing for BEAST vulnerability" && outln "\n"
	pr_bold " BEAST"; out " (CVE-2011-3389)                     "

	# 2) test handfull of common CBC ciphers
	for proto in ssl3 tls1; do
		$OPENSSL s_client -"$proto" $STARTTLS -connect $NODEIP:$PORT $SNI >$TMPFILE 2>/dev/null </dev/null
		if [ $? -ne 0 ]; then
			continue			# protocol no supported, so we do not need to check each cipher with that protocol
		fi
		while read hexcode dash cbc_cipher sslvers kx auth enc mac export ; do
			$OPENSSL s_client -cipher "$cbc_cipher" -"$proto" $STARTTLS -connect $NODEIP:$PORT $SNI >$TMPFILE 2>/dev/null </dev/null
			#normalize_ciphercode $hexcode
			#neat_list $HEXC $ciph $kx $enc | grep -wai "$arg"
			if [ $? -eq 0 ]; then
				detected_cbc_cipher="$detected_cbc_cipher ""$(grep -aw "Cipher" $TMPFILE | egrep -avw "New|is" | sed -e 's/^.*Cipher.*://' -e 's/ //g')"
			fi
		done < <($OPENSSL ciphers -V 'ALL:eNULL' | grep -a CBC)   	# -V doesn't work with openssl < 1.0
		#    ^^^^^ process substitution as shopt will either segfault or doesn't work with old bash versions

		#detected_cbc_cipher=$(echo $detected_cbc_cipher | sed 's/ //g')
		if [ -z "$detected_cbc_cipher" ]; then
			[[ $proto == "tls1" ]] && ! $first && printf "$spaces"
			pr_litegreenln "no CBC ciphers for $(echo $proto | tr '[a-z]' '[A-Z]') (OK)"
			first=false
		else
			detected_cbc_cipher=$(echo "$detected_cbc_cipher" | sed -e "s/ /\\${cr}      ${spaces}/9" -e "s/ /\\${cr}      ${spaces}/6" -e "s/ /\\${cr}      ${spaces}/3")
			[ $ret -eq 1 ] && out "$spaces"
			out "$(echo $proto | tr '[a-z]' '[A-Z]'):"; pr_brownln "$detected_cbc_cipher"
			ret=1
			detected_cbc_cipher=""
			first=false
		fi
	done  

	# 2) support for TLS 1.1+1.2?
	for proto in tls1_1 tls1_2; do
		$OPENSSL s_client -state -"$proto" $STARTTLS -connect $NODEIP:$PORT $SNI 2>/dev/null >$TMPFILE </dev/null
		if [ $? -eq 0 ]; then
			higher_proto_supported="$higher_proto_supported ""$(grep -aw "Protocol" $TMPFILE | sed -e 's/^.*Protocol .*://' -e 's/ //g')"
		fi
	done
	if [ $ret -eq 1 ] ; then
		[ ! -z "$higher_proto_supported" ] && outln "${spaces}-- but also supports higher protocols (possible mitigation):$higher_proto_supported"
	fi

#	printf "For a full individual test of each CBC cipher suites support by your $OPENSSL run \"$0 -x CBC $NODE\"\n"

	tmpfile_handle $FUNCNAME.txt
	return $ret
}

lucky13() {
#FIXME: to do . CVE-2013-0169
# in a nutshell: don't offer CBC suites (again). MAC as a fix for padding oracles is not enough. Best: TLS v1.2+ AES GCM
	echo "FIXME"
	return -1
}


# https://tools.ietf.org/html/rfc7465    REQUIRES that TLS clients and servers NEVER negotiate the use of RC4 cipher suites!
# https://en.wikipedia.org/wiki/Transport_Layer_Security#RC4_attacks
# http://blog.cryptographyengineering.com/2013/03/attack-of-week-rc4-is-kind-of-broken-in.html
rc4() {
	local ret
	local hexcode n ciph sslvers kx auth enc mac strength

	if [ $VULN_COUNT -le $VULN_THRESHLD ] || [ $LONG -eq 0 ] ; then
		outln 
		pr_blue "--> Checking for vulnerable RC4 Ciphers" ; outln "\n"
	fi
	pr_bold " RC4"; out " (CVE-2013-2566, CVE-2015-2808)        "

	$OPENSSL ciphers -V 'RC4:@STRENGTH' >$TMPFILE 	# -V doesn't work with openssl < 1.0
	[ $LONG -eq 0 ] && [ $SHOW_LOC_CIPH -eq 0 ] && echo "local ciphers available for testing RC4:" && echo $(cat $TMPFILE)
	$OPENSSL s_client -cipher $($OPENSSL ciphers RC4) $STARTTLS -connect $NODEIP:$PORT $SNI &>/dev/null </dev/null
	if [ $? -eq 0 ]; then
		pr_litered "VULNERABLE (NOT ok):"
		[[ $LONG -eq 0 ]] && outln "\n"
		rc4_offered=1
		[[ $LONG -eq 0 ]] && neat_header
		while read hexcode n ciph sslvers kx auth enc mac; do
			$OPENSSL s_client -cipher $ciph $STARTTLS -connect $NODEIP:$PORT $SNI </dev/null &>/dev/null
			ret=$? 		# here we have a fp with openssl < 1.0
			if [[ $ret -ne 0 ]] && [[ "$SHOW_EACH_C" -eq 0 ]] ; then
				continue	# no successful connect AND not verbose displaying each cipher
			fi
			if [ $LONG -eq 0 ]; then
				normalize_ciphercode $hexcode
				neat_list $HEXC $ciph $kx $enc $strength
				if [[ "$SHOW_EACH_C" -ne 0 ]]; then
					if [[ $ret -eq 0 ]]; then
						pr_litered "available"
					else
						out "not a/v"
					fi
				else
					rc4_offered=1
					out
				fi
				outln
			else
				pr_litered "$ciph "
			fi
		done < $TMPFILE
		#    ^^^^^ posix redirect as shopt will either segfault or doesn't work with old bash versions
		outln
	else
		pr_litegreenln "no RC4 ciphers detected (OK)"
		rc4_offered=0
	fi

	tmpfile_handle $FUNCNAME.txt
	return $rc4_offered
}


youknowwho() {
# CVE-2013-2566, 
# NOT FIXME as there's no code: http://www.isg.rhul.ac.uk/tls/
# http://blog.cryptographyengineering.com/2013/03/attack-of-week-rc4-is-kind-of-broken-in.html
return 0
# in a nutshell: don't use RC4, really not!
}

# https://www.usenix.org/conference/woot13/workshop-program/presentation/smyth
# https://secure-resumption.com/tlsauth.pdf
tls_truncation() {
#FIXME: difficult to test, is there any test available, pls let me know
:
}

old_fart() {
	pr_magentaln "Your $OPENSSL $OSSL_VER version is an old fart... . It doesn\'t make much sense to proceed."
	outln "Get precompiled bins or compile https://github.com/PeterMosmans/openssl ."
	exit 3
}

find_openssl_binary() {
# 0. check environment variable whether it's executable
	if [ ! -z "$OPENSSL" ] && [ ! -x "$OPENSSL" ]; then
		pr_redln "\ncannot find (\$OPENSSL=$OPENSSL) binary."
		outln "continuing ..."
	fi
	if [ -x "$OPENSSL" ]; then
# 1. check environment variable
		:
	else
# 2. otherwise try openssl in path of testssl.sh
		OPENSSL=$RUN_DIR/openssl
		if [ ! -x "$OPENSSL" ] ; then
# 3. with arch suffix
			OPENSSL=$RUN_DIR/openssl.$(uname -m)
			if [ ! -x "$OPENSSL" ] ; then
#4. finally: didn't find anything, so we take the one from the system:
				OPENSSL=$(which openssl 2>/dev/null)
			fi
		fi
	fi

	"$OPENSSL" version -a 2>&1 >/dev/null
	if [ $? -ne 0 ] || [ ! -x "$OPENSSL" ]; then
		outln
		pr_magentaln "FATAL: cannot exec or find any openssl binary "
		exit -1
	fi

	# http://www.openssl.org/news/openssl-notes.html
	OSSL_VER=$($OPENSSL version | awk -F' ' '{ print $2 }')
	OSSL_VER_MAJOR=$(echo "$OSSL_VER" | sed 's/\..*$//')
	OSSL_VER_MINOR=$(echo "$OSSL_VER" | sed -e 's/^.\.//' | tr -d '[a-zA-Z]')
	OSSL_VER_APPENDIX=$(echo "$OSSL_VER" | tr -d '[0-9.]')
	OSSL_VER_PLATFORM=$($OPENSSL version -p | sed 's/^platform: //')
	OSSL_BUILD_DATE=$($OPENSSL version -a | grep '^built' | sed -e 's/built on//' -e 's/: ... //' -e 's/: //' -e 's/ UTC//' -e 's/ +0000//' -e 's/.000000000//')
	echo $OSSL_BUILD_DATE | grep -q "not available" && OSSL_BUILD_DATE="" 
	export OPENSSL OSSL_VER OSSL_BUILD_DATE OSSL_VER_PLATFORM
	return 0
}

openssl_age() {
	case "$OSSL_VER" in
		0.9.7*|0.9.6*|0.9.5*)
			# 0.9.5a was latest in 0.9.5 an released 2000/4/1, that'll NOT suffice for this test
			old_fart ;;
		0.9.8)
			case $OSSL_VER_APPENDIX in
				a|b|c|d|e) old_fart;; # no SNI!
				# other than that we leave this for MacOSX and FreeBSD but it's a pain and likely gives false negatives/positives
			esac
			;;
	esac
	if [ $OSSL_VER_MAJOR -lt 1 ]; then ## mm: Patch for libressl
		pr_magentaln " Your \"$OPENSSL\" is way too old (<version 1.0) !"
		case $SYSTEM in
			*BSD|Darwin)
				outln " Please use openssl from ports/brew or compile from github.com/PeterMosmans/openssl" ;;
			*)   outln " Update openssl binaries or compile from github.com/PeterMosmans/openssl" ;;
		esac
		ignore_no_or_lame " Type \"yes\" to accept some false negatives or positives "
	fi
}


help() {
	cat << EOF

$PROG_NAME <options> 

     <-h|--help>                           what you're looking at
     <-b|--banner>                         displays banner + version of $PROG_NAME
     <-v|--version>                        same as previous
     <-V|--local>                          pretty print all local ciphers
     <-V|--local> <pattern>                what local cipher with <pattern> is a/v?

$PROG_NAME <options> URI    ("$PROG_NAME URI" does everything except ciphers per proto/each cipher)

     <-e|--each-cipher>                    checks each local cipher remotely 
     <-E|--cipher-per-proto>               checks those per protocol
     <-f|--ciphers>                        checks common cipher suites
     <-p|--protocols>                      checks TLS/SSL protocols 
     <-S|--server_defaults>                displays the servers default picks and certificate info
     <-P|--preference>                     displays the servers picks: protocol+cipher
     <-y|--spdy|--npn>                     checks for SPDY/NPN
     <-x|--single-cipher-test> <pattern>   tests matched <pattern> of cipher
     <-U|--vulnerable>                     tests all vulnerabilities
     <-B|--heartbleed>                     tests for heartbleed vulnerability
     <-I|--ccs|--ccs-injection>            tests for CCS injection vulnerability
     <-R|--renegotiation>                  tests renegotiation vulnerabilities
     <-C|--compression|--crime>            tests CRIME vulnerability
     <-T|--breach>                         tests BREACH vulnerability
     <-O|--poodle>                         tests for POODLE (SSL) vulnerability
     <-F|--freak>                          tests FREAK vulnerability
     <-A|--beast>                          tests BEAST vulnerability
     <-s|--pfs|--fs|--nsa>                 checks (perfect) forward secrecy settings
     <-4|--rc4|--appelbaum>                which RC4 ciphers are being offered?
     <-H|--header|--headers>               tests HSTS, HPKP, server/app banner, security headers, cookie

  special invocations:

     <-t|--starttls> protocol              does a default run against a STARTTLS enabled service
     <--mx> domain/host                    tests MX records from high to low priority (STARTTLS, port 25)


partly mandatory parameters:

     URI                   host|host:port|URL|URL:port   (port 443 is assumed unless otherwise specified)
     pattern               an ignore case word pattern of cipher hexcode or any other string in the name, kx or bits
     protocol              is one of ftp,smtp,pop3,imap,xmpp,telnet,ldap (for the latter two you need e.g. the supplied openssl)

tuning options:

     --assuming-http                       if protocol check fails it assumes HTTP protocol and enforces HTTP checks
     --ssl-native                          fallback to checks with OpenSSL where sockets are normally used
     --sneaky                              be less verbose wrt referer headers      
     --long                                wide output for tests like RC4 also with hexcode, kx, strength
     --warnings <batch|off|false>          "batch" doesn't wait for keypress, "off|false" skips connection warning
     --color                               0: no escape or other codes 1: b/w escape codes 2: color (default)
     --debug                               1: screen output normal but debug output in itemp files. 2-6: see line ~60
    

Need HTML output? Just pipe through "aha" (Ansi HTML Adapter: github.com/theZiz/aha) like 

   "$PROG_NAME <options> <URI> | aha >output.html"
EOF
	exit $1
}


mybanner() {
	me=$(basename "$0")
	osslver=$($OPENSSL version)
	osslpath=$(which $OPENSSL)
	nr_ciphers=$($OPENSSL ciphers  'ALL:COMPLEMENTOFALL:@STRENGTH' | sed 's/:/ /g' | wc -w | sed 's/ //g')
	hn=$(hostname)
	#poor man's ident (nowadays ident not neccessarily installed)
	idtag=$(grep -a '\$Id' $0 | grep -aw "[E]xp" | sed -e 's/^#  //' -e 's/\$ $/\$/')
	[ "$COLOR" -ne 0 ] && idtag="\033[1;30m$idtag\033[m\033[1m"
	bb=$(cat <<EOF

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
)
pr_bold "$bb"
outln "\n"
outln " Using \"$osslver\" [~$nr_ciphers ciphers] on
 $hn:$osslpath
 (built: \"$OSSL_BUILD_DATE\", platform: \"$OSSL_VER_PLATFORM\")\n"

}

maketempf() {
	TEMPDIR=$(mktemp -d /tmp/ssltester.XXXXXX) || exit 6
	TMPFILE=$TEMPDIR/tempfile.txt || exit 6
	HOSTCERT=$TEMPDIR/host_certificate.txt
	HEADERFILE=$TEMPDIR/http_header.txt
	HEADERFILE_BREACH=$TEMPDIR/http_header_breach.txt
	LOGFILE=$TEMPDIR/logfile.txt
	if [ $DEBUG -ne 0 ]; then
		cat >$TEMPDIR/environment.txt << EOF

PID: $$
bash version: ${BASH_VERSINFO[0]}.${BASH_VERSINFO[1]}.${BASH_VERSINFO[2]}
status: ${BASH_VERSINFO[4]}
machine: ${BASH_VERSINFO[5]}
operating system: $SYSTEM
shellopts: $SHELLOPTS

"$osslver" [$nr_ciphers ciphers] on $hn:$osslpath
built: "$OSSL_BUILD_DATE", platform: "$OSSL_VER_PLATFORM"
$idtag

PATH: $PATH
PROG_NAME: $PROG_NAME
PROG_DIR: $PROG_DIR
RUN_DIR: $RUN_DIR

CAPATH: $CAPATH
ECHO: $ECHO
COLOR: $COLOR
TERM_DWITH: $TERM_DWITH

SHOW_LOC_CIPH: $SHOW_LOC_CIPH
SHOW_EACH_C: $SHOW_EACH_C
SSL_NATIVE: $SSL_NATIVE
ASSUMING_HTTP $ASSUMING_HTTP
SNEAKY: $SNEAKY

VERBERR: $VERBERR 
DEBUG: $DEBUG

HSTS_MIN: $HSTS_MIN
HPKP_MIN: $HPKP_MIN
CLIENT_MIN_PFS: $CLIENT_MIN_PFS
DAYS2WARN1: $DAYS2WARN1
DAYS2WARN2: $DAYS2WARN2

HEADER_MAXSLEEP: $HEADER_MAXSLEEP
MAX_WAITSOCK: $MAX_WAITSOCK
HEARTBLEED_MAX_WAITSOCK: $HEARTBLEED_MAX_WAITSOCK
CCS_MAX_WAITSOCK: $CCS_MAX_WAITSOCK
USLEEP_SND $USLEEP_SND
USLEEP_REC $USLEEP_REC


EOF
		which locale &>/dev/null && locale >>$TEMPDIR/environment.txt || echo "locale doesn't exist" >>$TEMPDIR/environment.txt
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
		outln
		pr_litemagenta "No engine or GOST support via engine with your $OPENSSL"; outln 
		return 1
	elif $OPENSSL engine gost -vvvv -t -c 2>&1 | grep -iq "No such" ; then
		outln
		pr_litemagenta "No engine or GOST support via engine with your $OPENSSL"; outln 
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
		Y|y|Yes|YES|yes) return 0;;
		default)         ;;
	esac
	return 1
}

# Parameters: 1    URI
#             [2]  protocol
parse_hn_port() {
	PORT=443		# unless otherwise auto-determined, see below
	NODE="$1"

	# strip "https" and trailing urlpath supposed it was supplied additionally
	echo $NODE | grep -q 'https://' && NODE=$(echo $NODE | sed -e 's/https\:\/\///')

	# strip trailing urlpath
	NODE=$(echo $NODE | sed -e 's/\/.*$//')

	# was the address supplied like [AA:BB:CC::]:port ?
	if echo $NODE | grep -q ']' ; then
		tmp_port=$(printf $NODE | sed 's/\[.*\]//' | sed 's/://')
		# determine v6 port, supposed it was supplied additionally
		if [ ! -z "$tmp_port" ] ; then
			PORT=$tmp_port
			NODE=$(printf $NODE | sed "s/:$PORT//")
		fi
		NODE=$(printf $NODE | sed -e 's/\[//' -e 's/\]//')
	else
		# determine v4 port, supposed it was supplied additionally
		echo $NODE | grep -q ':' && PORT=$(echo $NODE | sed 's/^.*\://') && NODE=$(echo $NODE | sed 's/\:.*$//')
	fi
	SNI="-servername $NODE" 

	URL_PATH=$(echo $1 | sed 's/.*'"${NODE}"'//' | sed 's/.*'"${PORT}"'//')		# remove protocol and node part and port
	URL_PATH=$(echo $URL_PATH | sed 's/\/\//\//g')    	# we rather want // -> /
	[ -z "$URL_PATH" ] && URL_PATH="/"

	# now get NODEIP
	if ! get_dns_entries ; then
		pr_magenta "Can't proceed: No IP address for \"$NODE\" available"; outln "\n"
		exit -1
	fi

	# check if we can connect to port 
	if ! fd_socket; then
		ignore_no_or_lame "Ignore? "
		[ $? -ne 0 ] && exit 3
	fi
	close_socket

	datebanner "Testing"

	if  [[ -z "$2" ]] ; then		# for starttls we want another check
		# determine protocol which works (needed for IIS6). If we don't have IIS6, 1st try will succeed --> better because we use the variable 
		# all over the place. Stupid thing that we need to do that stuff for IIS<=6
		for OPTIMAL_PROTO in "" "-tls1_2" "-tls1" "-ssl3" "-tls1_1" "-ssl2" ""; do
			$OPENSSL s_client $OPTIMAL_PROTO -connect "$NODEIP:$PORT" $SNI </dev/null &>/dev/null && all_failed=1 && break
			all_failed=0
		done
		debugme echo "OPTIMAL_PROTO: $OPTIMAL_PROTO"
		if [ $all_failed -eq 0 ]; then
			outln
			pr_boldln " $NODEIP:$PORT doesn't seem a TLS/SSL enabled server or it requires a certificate"; 
			ignore_no_or_lame " Note that the results might look ok but they are nonsense. Proceed ? "
			[ $? -ne 0 ] && exit 3
		fi
		if [ $SNEAKY -eq 0 ] ; then
			GET_REQ11="GET $URL_PATH HTTP/1.1\r\nHost: $NODE\r\nUser-Agent: $UA_SNEAKY\r\nConnection: Close\r\nAccept: text/*\r\n\r\n"
			HEAD_REQ10="HEAD $URL_PATH HTTP/1.0\r\nUser-Agent: $UA_SNEAKY\r\nAccept: text/*\r\n\r\n"
		else
			GET_REQ11="GET $URL_PATH HTTP/1.1\r\nHost: $NODE\r\nUser-Agent: $UA_STD\r\nConnection: Close\r\nAccept: text/*\r\n\r\n"
			HEAD_REQ10="HEAD $URL_PATH HTTP/1.0\r\nUser-Agent: $UA_STD\r\nAccept: text/*\r\n\r\n"
		fi
		runs_HTTP $OPTIMAL_PROTO
	else
		protocol=$(echo "$2" | sed 's/s$//')     # strip trailing s in ftp(s), smtp(s), pop3(s), imap(s), ldap(s), telnet(s)
		case "$protocol" in
			ftp|smtp|pop3|imap|xmpp|telnet|ldap)
				STARTTLS="-starttls $protocol"; export STARTTLS
				$OPENSSL s_client -connect $NODEIP:$PORT $STARTTLS 2>/dev/null >$TMPFILE </dev/null
				if [ $? -ne 0 ]; then
					pr_magentaln " $OPENSSL couldn't establish STARTTLS via $protocol to $NODEIP:$PORT"
					debugme cat $TMPFILE
					exit 3
				fi
				out " Service set:            STARTTLS via "
				echo $protocol | tr '[a-z]' '[A-Z]'
				;;
			*)	pr_litemagentaln "momentarily only ftp, smtp, pop3, imap, xmpp and telnet, ldap allowed" >&2
				exit 1
				;;
		esac
	fi
					
	${do_mx_allentries} || initialize_engine
	outln

	return 0
}


get_dns_entries() {
	test4iponly=$(printf $NODE | sed -e 's/[0-9]//g' -e 's/\.//g')
	if [ "x$test4iponly" == "x" ]; then	# only an IPv4 address was supplied
		IP4=$NODE
		SNI=""						# override Server Name Indication as we test the IP only
	else
		# for security testing sometimes we have local entries. Getent is BS under Linux for localhost: No network, no resulution
		IP4=$(grep -w "$NODE" /etc/hosts | egrep -v ':|^#' |  egrep  "[[:space:]]$NODE" | awk '{ print $1 }')
		if which host &> /dev/null && [ -z "$IP4" ] ; then 
			IP4=$(host -t a $NODE 2>/dev/null | grep -v alias | sed 's/^.*address //')
			if echo "$IP4" | grep -q NXDOMAIN || echo "$IP4" | grep -q "no A record"; then
				return 1
			fi
		fi
		# MSYS2 has no host or getent, so we do this
		if [ -z "$IP4" ] ; then
			IP4=$(nslookup $NODE 2>/dev/null | grep -A10 Name | grep -v Name | sed 's/^Address.*: .//')
			[ -z "$IP4" ] && return 2
		fi

		# for IPv6 we often get this :ffff:IPV4 address which isn't of any use
		#which getent 2>&1 >/dev/null && IP6=$(getent ahostsv6 $NODE | grep $NODE | awk '{ print $1}' | grep -v '::ffff' | uniq)
		if [ -z "$IP6" ] ; then
			if host -t aaaa $NODE &>/dev/null ; then
				IP6=$(host -t aaaa $NODE | grep -v alias | grep -v "no AAAA record" | sed 's/^.*address //')
			else
				IP6=""
			fi
		fi
		# MSYS2 has no host or getent, so we do this
          if [ -z "$IP6" ] ; then
               IP6=$(nslookup -type=aaaa $NODE 2>/dev/null | grep -A10 Name | grep -v Name | sed 's/^Address.*: .//')
          fi

	fi # test4iponly
	
	IPADDRs="$IP4"
	[ ! -z "$IP6" ] && IPADDRs="$IP4 $IP6"

	# FIXME: we could/should test more than one IPv4 addresses if available, same IPv6. For now we test the first IPv4:
	NODEIP=$(echo "$IP4" | head -1)
	[ -z "$NODEIP" ] && return 3

	# we can't do this as some checks and even openssl are not yet IPv6 safe. BTW: bash sockets do IPv6 transparently!
	#NODEIP=$(echo "$IP6" | head -1)
	if which host &> /dev/null; then
		#rDNS=$(host -t PTR $NODEIP 2>/dev/null | grep -v "is an alias for" | sed -e 's/^.*pointer //' -e 's/\.$//')
		rDNS=$(host -t PTR $NODEIP 2>/dev/null | grep 'pointer' | sed -e 's/^.*pointer //' -e 's/\.$//')
	elif which nslookup &> /dev/null; then
		rDNS=$(nslookup -type=PTR $NODEIP 2> /dev/null | grep -v 'canonical name =' | grep 'name = ' | awk '{ print $NF }' | sed 's/\.$//')
	fi
	[ -z "$rDNS" ] && rDNS="--"
	return 0
}


display_rdns_etc() {
     if [ $(printf "$IPADDRs" | wc -w) -gt 1 ]; then
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
	tojour=$(date +%F)" "$(date +%R)
	outln
	pr_reverse "$1 now ($tojour) ---> $NODEIP:$PORT ($NODE) <---"; outln "\n"
	if [ "$1" = "Testing" ] ; then
		display_rdns_etc 
	fi
	outln
}


mx_allentries() {
	local mxs mx
	local mxport

	if which host &> /dev/null; then
		mxs=$(host -t MX "$1" | grep 'handled by' | sed -e 's/^.*by //g' -e 's/\.$//')
	elif which dig &> /dev/null; then
		mxs=$(dig +short -t MX "$1")
	elif which nslookup &> /dev/null; then
		mxs=$(nslookup -type=MX "$1" 2> /dev/null | grep 'mail exchanger = ' | sed 's/^.*mail exchanger = //g')
	else
		pr_magentaln 'No dig, host or nslookup'
		exit 3
	fi

	# test first higher priority servers
	mxs=$(echo "$mxs" | sort -n | sed -e 's/^.* //' -e 's/\.$//' | tr '\n' ' ')

	mxport=${2:-25}
	if [ -n "$mxs" ] && [ "$mxs" != ' ' ] ; then
		starttls_proto="smtp"
		[[ $mxport == "465" ]] && starttls_proto=""  # no starttls for Port 465
		pr_bold "Testing now all MX records (on port $mxport): "; outln "$mxs"
		for mx in $mxs; do
			parse_hn_port "$mx:$mxport" $starttls_proto && lets_roll
		done
	else
		pr_boldln " $1 has no MX records(s)"
	fi
}


# This intializes boolean global do_* variables, meant primarily to keep track of what to do
initialize_globals() {
	do_allciphers=false
	do_vulnerabilities=false
	do_beast=false
	do_breach=false
	do_ccs_injection=false
	do_cipher_per_proto=false
	do_crime=false
	do_freak=false
	do_header=false
	do_heartbleed=false
	do_mx_allentries=false
	do_pfs=false
	do_protocols=false
	do_rc4=false
	do_renego=false
	do_run_std_cipherlists=false
	do_server_defaults=false
	do_server_preference=false
	do_spdy=false
	do_ssl_poodle=false
	do_test_just_one=false
	do_tls_sockets=false
}


# Set default scanning options
set_scanning_defaults() {
	do_vulnerabilities=true
	do_beast=true
	do_breach=true
	do_ccs_injection=true
	do_crime=true
	do_freak=true
	do_header=true
	do_heartbleed=true
	do_pfs=true
	do_protocols=true
	do_rc4=true
	do_renego=true
	do_run_std_cipherlists=true
	do_server_defaults=true
	do_server_preference=true
	do_spdy=true
	do_ssl_poodle=true
	VULN_COUNT=10
}

query_globals() {
	local gbl
	local true_nr=0

	for gbl in do_allciphers do_vulnerabilities do_beast do_breach do_ccs_injection do_cipher_per_proto do_crime \
     		do_freak do_header do_heartbleed do_mx_allentries do_pfs do_protocols do_rc4 do_renego \
     		do_run_std_cipherlists do_server_defaults do_server_preference do_spdy do_ssl_poodle \
     		do_test_just_one do_tls_sockets; do
				[ "${!gbl}" == "true" ] && let true_nr++
	done
	return $true_nr
}


debug_globals() {
	local gbl

	for gbl in do_allciphers do_vulnerabilities do_beast do_breach do_ccs_injection do_cipher_per_proto do_crime \
     		do_freak do_header do_heartbleed do_mx_allentries do_pfs do_protocols do_rc4 do_renego \
     		do_run_std_cipherlists do_server_defaults do_server_preference do_spdy do_ssl_poodle \
     		do_test_just_one do_tls_sockets; do
		printf "%-22s = %s\n" $gbl "${!gbl}" 
	done
     printf "%-22s : %s\n" URI: "$URI"
}



# Parses options
startup() {
	# Set defaults if only an URI was specified, maybe ToDo: use "="-option, then: ${i#*=} i.e. substring removal
	[[ "$#" -eq 1 ]] && set_scanning_defaults

	while [[ $# -gt 0 ]]; do
		case $1 in
			-b|--banner|-v|--version)
		  		exit 0;;
			--mx)
				do_mx_allentries=true;;
			--mx465)  # doesn't work with major ISPs
				do_mx_allentries=true
				PORT=465 ;;
			--mx587) # doesn't work with major ISPs
				do_mx_allentries=true
				PORT=587 ;;
			-V|--local)
				initialize_engine 	# GOST support-
				prettyprint_local "$2"
				exit $? ;;
			-x|--single-ciphers-test|--single-cipher-test|--single_cipher_test|--single_ciphers_test)
				do_test_just_one=true
				single_cipher=$2
				shift;;
			-t|--starttls)
				STARTTLS_PROTOCOL=$2
				do_starttls=true
				shift;;
			-e|--each-cipher)
				do_allciphers=true;;
			-E|--cipher-per-proto|--cipher_per_proto)
				do_cipher_per_proto=true;;
			-h|--help)
				help 0 ;;
			-p|--protocols)
				do_protocols=true
				do_spdy=true;;
			-y|--spdy|--npn)
				do_spdy=true;;
			-f|--ciphers)
				do_run_std_cipherlists=true;;
			-S|--server_defaults|--server-defaults)
				do_server_defaults=true;;
			-P|--server_preference|--server-preference)
				do_server_preference=true;;
			-H|--header|--headers)
				do_header=true;;
			-U|--vulnerable)
				do_vulnerabilities=true
				do_heartbleed=true
				do_ccs_injection=true
				do_renego=true
				do_crime=true
				do_breach=true
				do_ssl_poodle=true
				do_freak=true
				do_beast=true
				do_rc4=true
				VULN_COUNT=10 ;;
			-B|--heartbleed)
				do_heartbleed=true
				let "VULN_COUNT++" ;;
			-I|--ccs|--ccs_injection|--ccs-injection)
				do_ccs_injection=true
				let "VULN_COUNT++" ;;
			-R|--renegotiation)
				do_renego=true
				let "VULN_COUNT++" ;;
			-C|--compression|--crime)
				do_crime=true
				let "VULN_COUNT++" ;;
			-T|--breach)
				do_breach=true
				let "VULN_COUNT++" ;;
			-O|--poodle)
				do_ssl_poodle=true
				let "VULN_COUNT++" ;;
			-F|--freak)
				do_freak=true
				let "VULN_COUNT++" ;;
			-A|--beast)
				do_beast=true
				let "VULN_COUNT++" ;;
			-4|--rc4|--appelbaum)
				do_rc4=true;;
			-s|--pfs|--fs|--nsa)
				do_pfs=true;;
			-q) ### this is a development feature and will disappear:
				# DEBUG=3  ./testssl.sh -q 03 "cc, 13, c0, 13" google.de
				# DEBUG=3  ./testssl.sh -q 01 yandex.ru
				TLS_LOW_BYTE="$2"; HEX_CIPHER=""
				if [ $# -eq 4 ]; then  # protocol AND ciphers specified
					HEX_CIPHER="$3"
					shift 
		 		fi
				shift
				do_tls_sockets=true
				outln "TLS_LOW_BYTE/HEX_CIPHER: ${TLS_LOW_BYTE}/${HEX_CIPHER}" ;;
               --long) LONG=0 ;;
			--assuming-http|--assuming_http|--assume_http|--assume-http)
				ASSUMING_HTTP=0 ;;
			--sneaky)
				SNEAKY=0 ;;
			--warnings)
				case "$2" in
					batch|off|false) 	WARNINGS="$2" ;;
					default)   		pr_magentaln "warnings can be either \"batch\", \"off\" or \"false\"" ;;
				esac
				shift ;;
			--show-each-cipher)
				SHOW_EACH_C=1 ;; #FIXME: sense is vice versa
			--debug)
				DEBUG="$2"
				shift ;;
			--color)
				COLOR=$2
				if [ $COLOR -ne 0 ] && [ $COLOR -ne 1 ] && [ $COLOR -ne 2 ] ; then
					COLOR=2
					pr_magentaln "$0: unrecognized color: $2" 1>&2
					help 1
				fi
				shift ;;
			--ssl_native|--ssl-native)
				SSL_NATIVE=0 ;;
			(--) shift
				break ;;
			(-*) pr_magentaln "$0: unrecognized option $1" 1>&2; 
				help 1 ;;
			(*)	break ;; 
		esac
		shift
	done

	# Show usage if no options were specified
	[ -z $1 ] && help 0

	# left off here is the URI
	URI=$1

	[ "$DEBUG" -ge 4 ] && debug_globals
	# if we have no "do_*" set here --> query_globals: we do a standard run -- otherwise just the one specified
	query_globals && set_scanning_defaults
}


lets_roll() {
	local ret

	${do_tls_sockets} && { tls_sockets "$TLS_LOW_BYTE" "$HEX_CIPHER"; exit $?; }

	${do_test_just_one} && test_just_one ${single_cipher}
	${do_allciphers} && { allciphers; ret=$(($? + ret)); }
	${do_cipher_per_proto} && { cipher_per_proto; ret=$(($? + ret)); }
	${do_protocols} && { runprotocols; ret=$(($? + ret)); }
	${do_spdy} && { spdy; ret=$(($? + ret)); }
	${do_run_std_cipherlists} && { run_std_cipherlists; ret=$(($? + ret)); }
	${do_server_preference} && { server_preference; ret=$(($? + ret)); }
	${do_server_defaults} && { server_defaults; ret=$(($? + ret)); }

	if ${do_header}; then
		#TODO: refactor this into functions
		if [[ $SERVICE == "HTTP" ]]; then
			hsts "$URL_PATH"
			hpkp "$URL_PATH"
			serverbanner "$URL_PATH"
			applicationbanner "$URL_PATH"
			cookieflags "$URL_PATH"
			moreflags "$URL_PATH"
	    fi
	fi

	# vulnerabilities
	if [ $VULN_COUNT -gt $VULN_THRESHLD ] || ${do_vulnerabilities}; then
		outln; pr_blue "--> Testing vulnerabilities" 
		outln "\n"
	fi
	${do_heartbleed} && { heartbleed; ret=$(($? + ret)); }
	${do_ccs_injection} && { ccs_injection; ret=$(($? + ret)); }
	${do_renego} && { renego; ret=$(($? + ret)); }
	${do_crime} && { crime; ret=$(($? + ret)); }
	${do_breach} && { breach "$URL_PATH" ; ret=$(($? + ret)); }
	${do_ssl_poodle} && { ssl_poodle; ret=$(($? + ret)); }
	${do_freak} && { freak; ret=$(($? + ret)); }
	${do_beast} && { beast; ret=$(($? + ret)); }
	${do_rc4} && { rc4; ret=$(($? + ret)); }

	${do_pfs} && { pfs; ret=$(($? + ret)); }

	return $ret
}



################# main #################

find_openssl_binary
mybanner

[ -z "$PROG_DIR" ] && PROG_DIR="."

# mapping file provides a pair "keycode/ RFC style name", see the RFCs, cipher(1) and
# www.carbonwind.net/TLS_Cipher_Suites_Project/tls_ssl_cipher_suites_simple_table_all.htm
[ -r "$(dirname $PROG_DIR)/mapping-rfc.txt" ] && MAP_RFC_FNAME=$(dirname $PROG_DIR)"/mapping-rfc.txt"

initialize_globals

startup "$@"
openssl_age
maketempf

if ${do_mx_allentries} ; then
     query_globals 
     # if we have just one "do_*" set here --> query_globals: we do a standard run -- otherwise just the one specified
	[ $? -eq 1 ] && set_scanning_defaults
	initialize_engine
	mx_allentries "${URI}" $PORT
	ret=$?
else
     parse_hn_port "${URI}" "${STARTTLS_PROTOCOL}"
	lets_roll
	ret=$?
fi

exit $ret

#  $Id: testssl.sh,v 1.250 2015/05/16 18:42:08 dirkw Exp $ 
# vim:ts=5:sw=5
# ^^^ FYI: use vim and you will see everything beautifully indented with a 5 char tab
