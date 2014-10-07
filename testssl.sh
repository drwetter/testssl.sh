#!/usr/bin/env bash
# bash is needed for some distros which use dash as /bin/sh and for the heartbleed check!

# Program for spotting weak SSL encryption, ciphers, version and some vulnerablities or features

VERSION="2.1alpha"
SWURL="https://testssl.sh"
SWCONTACT="dirk aet testssl dot sh"

# Author: Dirk Wetter, copyleft: 2007-2014
#
# License: GPLv2, see http://www.fsf.org/licensing/licenses/info/GPLv2.html
# and accompanying license "LICENSE.txt". Redistribution + modification under this
# license permitted. 
# If you enclose this script or parts of it in your software, it has to
# be accompanied by the same license (see link) and the place where to get
# the recent version of this program: https://testssl.sh
# Don't violate the license.
#
# USAGE WITHOUT ANY WARRANTY, THE SOFTWARE IS PROVIDED "AS IS". USE IT AT
# your OWN RISK

# I know reading this shell script is neither nice nor it's rocket science.  However openssl 
# is a such a good swiss army knife (e.g. wiki.openssl.org/index.php/Command_Line_Utilities)
# that it was difficult to resist wrapping it with some shell commandos. That's how everything
# started -- but that was (and still is) a long way to go.
#
# One can do the same in other languages and/or choose another crypto provider as openssl -- YMMV.

# Q: So what's the difference between https://www.ssllabs.com/ssltest or
#    https://sslcheck.globalsign.com/?
# A: As of now ssllabs only check webservers on standard ports, reachable from
#    the internet. And those are 3rd parties. If those four restrictions are fine
#    with you, they might tell you more than this tool -- as of now.

# Note that 56Bit ciphers are disabled during compile time in $OPENSSL > 0.9.8c
# (http://rt.$OPENSSL.org/Ticket/Display.html?user=guest&pass=guest&id=1461)
# ---> TLS1_ALLOW_EXPERIMENTAL_CIPHERSUITES in ssl/tls1.h . For testing it's recommended 
# to change this to 1 and recompile e.g. w/ ./config --prefix=/usr/  --openssldir=/etc/ssl .
# Also some distributions disable SSLv2. Please note: Everything which is disabled or not
# supported on the client side is not possible to test on the server side!
# Thus as a courtesy I provide openssl binaries for Linux which have everything you need
# enabled, see website
#

# following variables make use of $ENV, e.g. OPENSSL=<myprivate_path_to_openssl> ./testssl.sh <host>

#OPENSSL="${OPENSSL:-/usr/bin/openssl}"	# private openssl version --> is now evaluated below
CAPATH="${CAPATH:-/etc/ssl/certs/}"	# same as previous. Doing nothing yet. FC has only a CA bundle per default, ==> openssl version -d
OSSL_VER=""				# openssl version, will be autodetermined
NC=""					# netcat will be autodetermined
ECHO="/usr/bin/printf" 		# works under Linux, BSD, MacOS. watch out under Solaris, not tested yet under cygwin
COLOR=0					# with screen, tee and friends put 1 here (i.e. no color)
SHOW_LCIPHERS=no    		# determines whether the client side ciphers are displayed at all (makes no sense normally)
VERBERR=${VERBERR:-1}		# 0 means to be more verbose (some like the errors to be dispayed so that one can tell better
		# whether the handshake succeeded or not. For errors with individual ciphers you also need to have SHOW_EACH_C=1
LOCERR=${LOCERR:-1}			# Same as before, just displays am error if local cipher isn't support
SHOW_EACH_C=${SHOW_EACH_C:-0}	# where individual ciphers are tested show just the positively ones tested
SNEAKY=${SNEAKY:-1}			# if zero: the referer and useragent we leave while checking the http header is just usual
#FIXME: consequently we should mute the initial netcat and openssl s_client -connect as they cause a 400 (nginx, apache)

#FIXME: still to be filled with (more) sense:
DEBUG=${DEBUG:-0}			# if 1 the temp file won't be erased. Currently only keeps the last output anyway
VERBOSE=${VERBOSE:-0}		# if 1 it shows what's going on. Currently only used for heartbleed and ccs injection
VERB_CLIST=""	     		# ... and if so, "-V" shows them row by row cipher, SSL-version, KX, Au, Enc and Mac
HSTS_MIN=180				#>180 days is ok for HSTS
NPN_PROTOs="spdy/4a2,spdy/3,spdy/3.1,spdy/2,spdy/1,http/1.1"

#global vars:
TLS_PROTO_OFFERED=""
SOCKREPLY=""
HEXC=""
SNI=""
IP4=""
IP6=""
OSSL_VER_MAJOR=0
OSSL_VER_MINOR=0
OSSL_VER_APPENDIX="none"
NODEIP=""
IPS=""
MAX_WAITSOCK=10			# waiting at max 10 seconds for socket reply

go2_column() { $ECHO "\033[${1}G"; }

out() {
	# if 2 args: second is column position
	[ ! -z "$2" ] && go2_column "$2"
	$ECHO "$1"
}

outln() {
	[ ! -z "$1" ] && $ECHO "$1"
	$ECHO "\n"
}

# some functions for text (i know we could do this with tput, but what about systems having no terminfo?
# http://www.tldp.org/HOWTO/Bash-Prompt-HOWTO/x329.html
off() {
	out "\033[m\c"
}

liteblue() { 
	[ $COLOR = 0 ] && out "\033[0;34m$1 " || out "$1 "
	off
}
liteblueln() { liteblue "$1"; outln; }

blue() { 
	[ $COLOR = 0 ] && out "\033[1;34m$1 " || out "$1 "
	off
}
blueln() { blue "$1"; outln; }

litered() { 
	[ $COLOR = 0 ] && out "\033[0;31m$1 " || out "*$1* "
	off
}
literedln() { litered "$1"; outln; }

red() { 
	[ $COLOR = 0 ] && out "\033[1;31m$1 " || "**$1** "
	off
}
redln() { red "$1"; outln; }

litemagenta() { 
	[ $COLOR = 0 ] && out "\033[0;35m$1 " || out "$1 "
	off
}
litemagentaln() { litemagenta "$1"; outln; }


magenta() { 
	[ $COLOR = 0 ] && out "\033[1;35m$1 " || out "**$1** "
	off
}
magentaln() { magenta "$1"; outln; }

litecyan() { 
	[ $COLOR = 0 ] && out "\033[0;36m$1 " || out "$1 "
	off
}
litecyanln() { litecyan "$1"; outln; }

cyan() { 
	[ $COLOR = 0 ] && out "\033[1;36m$1 " || out "**$1** "
	off
}
cyanln() { cyan "$1"; outln; }

grey() { 
	[ $COLOR = 0 ] && out "\033[1;30m$1 " || out "$1 "
	off
}
greyln() { grey "$1"; outln; }

litegrey() { 
	[ $COLOR = 0 ] && out "\033[0;37m$1 " || out "$1 "
	off
}
litegreyln() { litegrey "$1"; outln; }

litegreen() { 
	[ $COLOR = 0 ] && out "\033[0;32m$1 " || out "$1 "
	off
}
litegreenln() { litegreen "$1"; outln; }

green() { 
	[ $COLOR = 0 ] && out "\033[1;32m$1 " || out "**$1** "
	off
}
greenln() { green "$1"; outln; }

brown() { 
	[ $COLOR = 0 ] && out "\033[0;33m$1 " || out "**$1** "
	off
}
brownln() { brown "$1"; outln; }

yellow() { 
	[ $COLOR = 0 ] && out "\033[1;33m$1 " || out "**$1** "
	off
}
yellowlnln() { yellowln "$1"; outln; }

bold() { out "\033[1m$1"; off; }
boldln() { bold "$1" ; outln; }

underline() { out "\033[4m$1" ; off; }

boldandunder() { out "\033[1m\033[4m$1" ; off; }

reverse() { out "\033[7m$1" ; off; }


# whether it is ok for offer/not offer enc/cipher/version
ok(){
	if [ "$2" -eq 1 ] ; then		
		case $1 in
			1) redln "offered (NOT ok)" ;;   # 1 1
			0) greenln "not offered (OK)" ;; # 0 1
		esac
	else	
		case $1 in
			3) brownln "offered" ;;  		# 2 0
			2) boldln "offered" ;;  		# 2 0
			1) greenln "offered (OK)" ;;  	# 1 0
			0) boldln "not offered" ;;    	# 0 0
		esac
	fi
	return $2
}

# in a nutshell: It's HTTP-level compression & an attack which works against any cipher suite and 
# is agnostic to the version of TLS/SSL, more: http://www.breachattack.com/
breach() {
	bold " BREACH"; out " =HTTP Compression, experimental    "
	[ -z "$1" ] && url="/"
# referers are important here!
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
Accept-Language: en-US,en
Accept-encoding: gzip,deflate,compress
$referer
Connection: close

EOF
) &>$HEADERFILE_BREACH
ret=$?
# sometimes it hangs here. Currently only kill helps
#test  $DEBUG -eq 1 && \
result=`cat $HEADERFILE_BREACH | grep -a '^Content-Encoding' | sed -e 's/^Content-Encoding//' -e 's/://' -e 's/ //g'`
result=`echo $result | tr -cd '\40-\176'`
     if [ -z $result ]; then
		green "no HTTP compression " 
	else
		litered "uses $result compression "
	fi
# Catch: any URL cvan be vulnerable. I am testing now only the root
	outln "(only \"$url\" tested)"

	return $ret
}


#problems not handled: chunked, 302
http_header() {
	[ -z "$1" ] && url="/"
	if [ $SNEAKY -eq 0 ] ; then
		referer="Referer: " 
		useragent="User-Agent: Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.0)"
	else
		referer="Referer: TLS/SSL-Tester from $SWURL"
		useragent="User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:42.0) Gecko/19700101 Firefox/42.0"
	fi
	(
	$OPENSSL  s_client -quiet -connect $NODEIP:$PORT $SNI << EOF
GET $url HTTP/1.1
Host: $NODE
$useragent
Accept-Language: en-US,en
$referer
Connection: close

EOF
) &>$HEADERFILE
	ret=$?
	# sometimes it hangs here ^^^. Currently only kill helps
	test $DEBUG -eq 1 && cat $HEADERFILE
	sed  -e '/^<HTML/,$d' -e '/^<html/,$d' -e '/^<XML /,$d' -e '/<?XML /,$d' \
          -e '/^<xml /,$d' -e '/<?xml /,$d'  -e '/^<\!DOCTYPE/,$d' -e '/^<\!doctype/,$d' $HEADERFILE >$HEADERFILE.2
#### ^^^ Attention: the filtering for the html body only as of now, doesn't work for other content yet
	mv $HEADERFILE.2  $HEADERFILE	 # sed'ing in place doesn't work with BSD and Linux simultaneously

	  return $ret
}

#FIXME: it doesn't follow a 30x. At least a path should be possible to provide
hsts() {
	[ -s $HEADERFILE ] || http_header
	bold " HSTS        "
	grep -i '^Strict-Transport-Security' $HEADERFILE >$TMPFILE
	if [ $? -eq 0 ]; then
		AGE_SEC=`sed -e 's/[^0-9]*//g' $TMPFILE` 
		AGE_DAYS=`expr $AGE_SEC \/ 86400`
		if [ $AGE_DAYS -gt $HSTS_MIN ]; then
			litegreen "$AGE_DAYS days \c" ; outln "($AGE_SEC s)"
		else
			brown "$AGE_DAYS days (<$HSTS_MIN is not good enough)"
		fi
	else
		litecyan "no"
	fi
	outln

	rm $TMPFILE
	return $?
}

serverbanner() {
	[ -s $HEADERFILE ] || http_header
	bold " Server      "
	grep -i '^Server' $HEADERFILE >$TMPFILE
	if [ $? -eq 0 ]; then
		#out=`cat $TMPFILE | sed -e 's/^Server: //' -e 's/^server: //' -e 's/^[[:space:]]//'`
		serverbanner=`cat $TMPFILE | sed -e 's/^Server: //' -e 's/^server: //'`
#		if [ x"$out" == "x\n" -o x"$out" == "x\n\r" -o x"$out" == "x" ]; then
#			outln "(line exists but empty string)"
#		else
			outln "$serverbanner"
#		fi
	else
		outln "(None, interesting!)"
	fi

	bold " Application"
# examples: php.net, asp.net , www.regonline.com
	egrep -i '^X-Powered-By|^X-AspNet-Version|^X-Runtime|^X-Version' $HEADERFILE >$TMPFILE
	if [ $? -eq 0 ]; then
		#cat $TMPFILE | sed 's/^.*:/:/'  | sed -e :a -e '$!N;s/\n:/ \n\             +/;ta' -e 'P;D' | sed 's/://g' 
		cat $TMPFILE | sed 's/^/ /' 
	else
		litegrey " (None)"
	fi
	outln

	rm $TMPFILE
	return $?
}

#dead function as of now
secure_cookie() {	# ARG1: Path
	[ -s $HEADERFILE ] || http_header
	grep -i '^Set-Cookie' $HEADERFILE >$TMPFILE
	if [ $? -eq 0 ]; then
		outln "Cookie issued, status: "
		if grep -q -i secure $TMPFILE; then
			litegreenln "Secure Flag"
			echo $TMPFILE
		else
			outln "no secure flag"
		fi
	fi
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
	HEXC=`echo $HEXC | tr 'A-Z' 'a-z'` #tolower
	return 0
}

prettyprint_local() {
	if [ -z "$1" ]; then
		blue "--> Displaying all local ciphers"; outln "\n"
	fi

	neat_header

	$OPENSSL ciphers -V 'ALL:COMPLEMENTOFALL:@STRENGTH' | while read hexcode dash ciph sslversmin kx auth enc mac export; do
		normalize_ciphercode $hexcode
		if [ -n "$1" ]; then
			echo $HEXC | grep -iq "$1" || continue
		fi
		neat_list $HEXC $ciph $kx $enc
		outln
	done
	outln

	return 0
}


# list ciphers (and makes sure you have them locally configured)
# arg[1]: cipher list (or anything else)
listciphers() {
	if [ $LOCERR = 0 ]; then
		$OPENSSL ciphers "$VERB_CLIST" $1 2>&1 >$TMPFILE
	else
		$OPENSSL ciphers "$VERB_CLIST" $1  &>$TMPFILE
	fi
	return $?
}


# argv[1]: cipher list to test 
# argv[2]: string on console
# argv[3]: ok to offer? 0: yes, 1: no
std_cipherlists() {
	out "$2 "; 
	if listciphers $1; then
		[ x$SHOW_LCIPHERS = "xyes" ] && out "local ciphers are: " && cat $TMPFILE | sed 's/:/, /g'
		$OPENSSL s_client -cipher "$1" $STARTTLS -connect $NODEIP:$PORT $SNI 2>$TMPFILE >/dev/null </dev/null
		ret=$?
		if [ $VERBERR -eq 0 ]; then
		#	echo | $OPENSSL s_client -cipher $1  -connect "$NODE:$PORT" >&1 >$TMPFILE
			head -2 $TMPFILE | egrep -v "depth|num="
		fi
		if [ $3 -eq 0 ]; then 		# ok to offer
			if [ $ret -eq 0 ]; then	# was offered
				ok 1 0			# green
			else
				ok 0 0			# black
			fi
		elif [ $3 -eq 2 ]; then		# not really bad
			if [ $ret -eq 0 ]; then
				ok 2 0			# offered in bold
			else
				ok 0 0              # not offered also in bold
			fi
		else
			if [ $ret -eq 0 ]; then
				ok 1 1			# was offered! --> red
			else
				#ok 0 0			# was not offered, that's ok
				ok 0 1			# was not offered --> green
		fi
	fi
	rm $TMPFILE
	else
		magenta "Local problem: No $2 configured in $OPENSSL" ; outln
	fi
	# we need lf in those cases:
	[ "$LOCERR" -eq 0 ] && echo
	[ "$VERBERR" -eq 0 ] && echo
}


# sockets inspired by http://blog.chris007.de/?p=238
# ARG1: hexbyte, ARG2: hexode for TLS Version, ARG3: sleep
socksend() {
	data=`echo $1 | sed 's/tls_version/'"$2"'/g'`
	[ $VERBOSE -eq 1 ] && echo "\"$data\""
	out "$data" >&5 &
	sleep $3
}

#sockread() {
	#SOCKREPLY=`dd bs=$1 count=1 <&5 2>/dev/null`
#}

sockread() {
	maxsleep=$MAX_WAITSOCK
	ret=0

	ddreply=`mktemp /tmp/ddreply.XXXXXX` || exit 7
	dd bs=$1 of=$ddreply count=1 <&5 2>/dev/null &
	pid=$!
	
	while true; do
		if ! ps ax | grep -v grep | grep -q $pid; then
			break  # didn't reach maxsleep yet
			kill $pid >&2 2>/dev/null
		fi
		sleep 1
		maxsleep=`expr $maxsleep - 1`
		test $maxsleep -eq 0 && break
	done
	if ps ax | grep -v grep | grep -q $pid; then
		# time's up and dd is still alive --> tiemout
		kill $pid
		wait $pid 2>/dev/null
		ret=3 # means killed
	fi
	SOCKREPLY=`cat $ddreply`
	rm $ddreply

	return $ret
}


show_rfc_style(){
	RFCname=`grep -iw $1 $MAP_RFC_FNAME | sed -e 's/^.*TLS/TLS/' -e 's/^.*SSL/SSL/'`
     if [ -n "$RFCname" ] ; then
		out "$RFCname" "$2";
	fi
}

# header and list for all_ciphers+cipher_per_proto, and PFS+RC4
neat_header(){
	out " Hexcode";  out "Cipher Suite Name (OpenSSL)" 13; out "KeyExch." 43; out "Encryption" 52; out "Bits" 63
	[ -r $MAP_RFC_FNAME ] && out "Cipher Suite Name (RFC)" 73
	outln 
	printf "%s-----------------------------------------------------------------------"
	[ -r $MAP_RFC_FNAME ] && printf "%s---------------------------------------------"
	outln 
}

neat_list(){
	kx=`echo $3 | sed 's/Kx=//g'`
	enc=`echo $4 | sed 's/Enc=//g'`
	strength=`echo $enc | sed -e 's/.*(//' -e 's/)//'`
	strength=`echo $strength | sed -e 's/ChaCha20-Poly1305//g'` # workaround for empty strength=ChaCha20-Poly1305
	enc=`echo $enc | sed -e 's/(.*)//g'`
	echo "$export" | grep -iq export && strength="$strength,export"
	out " [$1]"; out "$2" 13;  out "$kx" 43; out "$enc" 54; out "$strength" 63
	[ -r $MAP_RFC_FNAME ] && show_rfc_style $HEXC 73
}

test_just_one(){

	ciph=""
	for arg in $@; do
		$OPENSSL ciphers -V 'ALL:COMPLEMENTOFALL:@STRENGTH' | while read hexcode dash ciph restofline; do
			normalize_ciphercode $hexcode
			grep arg 
		done
	done

	neat_header

	$OPENSSL ciphers -V 'ALL:COMPLEMENTOFALL:@STRENGTH' | while read hexcode dash ciph sslversmin kx auth enc mac export; do
		for ciph in $@; do
			$OPENSSL s_client -cipher $ciph $STARTTLS -connect $NODEIP:$PORT $SNI &>$TMPFILE  </dev/null
			ret=$?
			if [ $ret -ne 0 ] && [ "$SHOW_EACH_C" -eq 0 ]; then
				continue		# no successful connect AND not verbose displaying each cipher
			fi
			normalize_ciphercode $hexcode
			neat_list $HEXC $ciph $kx $enc
			if [ "$SHOW_EACH_C" -ne 0 ]; then
				[ -r $MAP_RFC_FNAME ] && go2_column 114
				if [ $ret -eq 0 ]; then
					cyan "  available"
				else
					out "  not a/v"
				fi
			fi
		done
		outln
		rm $TMPFILE
	done

	return 0
}


# test for all ciphers locally configured (w/o distinguishing whether they are good or bad
allciphers(){
# FIXME: e.g. OpenSSL < 1.0 doesn't understand "-V"
	blue "--> Testing all locally available ciphers against the server"; outln "\n"
	neat_header
	$OPENSSL ciphers -V 'ALL:COMPLEMENTOFALL:@STRENGTH' | while read hexcode n ciph sslvers kx auth enc mac export; do
		$OPENSSL s_client -cipher $ciph $STARTTLS -connect $NODEIP:$PORT $SNI &>$TMPFILE  </dev/null
		ret=$?
		if [ $ret -ne 0 ] && [ "$SHOW_EACH_C" -eq 0 ]; then
			continue		# no successful connect AND not verbose displaying each cipher
		fi
		normalize_ciphercode $hexcode
		neat_list $HEXC $ciph $kx $enc
		if [ "$SHOW_EACH_C" -ne 0 ]; then
			[ -r $MAP_RFC_FNAME ] && go2_column 114
			if [ $ret -eq 0 ]; then
				cyan "  available"
			else
				out "  not a/v"
			fi
		fi
		outln
		rm $TMPFILE
	done
	return 0
}

# test for all ciphers per protocol locally configured (w/o distinguishing whether they are good or bad
cipher_per_proto(){
	blue "--> Testing all locally available ciphers per protocol against the server"; outln "\n"
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
				[ -r $MAP_RFC_FNAME ] && go2_column 114
				if [ $ret -eq 0 ]; then
					cyan "  available"
				else
					out "  not a/v"
				fi
			fi
			outln
			rm $TMPFILE
		done
	done

	return 0
}

locally_supported() {
	out "$2 "
	$OPENSSL s_client "$1" 2>&1 | grep -q "unknown option"
	if [ $? -eq 0 ]; then
		magenta "Local problem: $OPENSSL doesn't support \"s_client $1\""
		return 7
	else
		return 0
	fi
}

testversion_new() {
	$OPENSSL s_client -state $1 $STARTTLS -connect $NODEIP:$PORT $SNI &>$TMPFILE </dev/null
	ret=$?
	[ "$VERBERR" -eq 0 ] && cat $TMPFILE | egrep "error|failure" | egrep -v "unable to get local|verify error"
	rm $TMPFILE
	return $ret
}

testprotohelper() {
	if locally_supported "$1" "$2" ; then
		testversion_new "$1" "$2" 
		return $?
	else
		return 7
	fi
}


runprotocols() {
	blue "--> Testing Protocols"; outln "\n"
	# e.g. ubuntu's 12.04 openssl binary + soon others don't want sslv2 anymore: bugs.launchpad.net/ubuntu/+source/openssl/+bug/955675
	# Sonderlocke hier #FIXME kann woanders auch auftauchen!
	testprotohelper "-ssl2" " SSLv2     " 
	ret=$?; 
	if [ $ret -ne 7 ]; then
		if [ $ret -eq 0 ]; then
			ok 1 1		# red 
		else
			ok 0 1		# green "not offered (ok)"
		fi
	fi
	
	if testprotohelper "-ssl3" " SSLv3     " ; then
		ok 3 0			# brown "offered" 
	else
		ok 0 1			# green "not offered (ok)"
	fi

	if testprotohelper "-tls1" " TLSv1     "; then
		ok 1 0
	else
		ok 0 0  
	fi

	if testprotohelper "-tls1_1" " TLSv1.1   "; then
		ok 1 0
	else
		ok 0 0  
	fi

	if testprotohelper "-tls1_2" " TLSv1.2   "; then
		ok 1 0
	else
		ok 0 0  
	fi
	return 0
}

run_std_cipherlists() {
	outln
	blue "--> Testing standard cipher lists"; outln "\n"
# see man ciphers
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

simple_preference() {
	outln
	blue "--> Testing server defaults (Server Hello)"; outln "\n"
	# throwing every cipher/protocol at the server and displaying its pick
	$OPENSSL s_client $STARTTLS -connect $NODEIP:$PORT $SNI -tlsextdebug -status </dev/null 2>/dev/null >$TMPFILE
	localtime=`date "+%s"`
	if [ $? -ne 0 ]; then
		magentaln "This shouldn't happen. "
		ret=6
	else
		out " Negotiated protocol       "
		TLS_PROTO_OFFERED=`grep -w "Protocol" $TMPFILE | sed -e 's/^ \+Protocol \+://' -e 's/ //g'`
		case "$TLS_PROTO_OFFERED" in
			*TLSv1.2)		greenln $TLS_PROTO_OFFERED ;;
			*TLSv1.1)		litegreenln $TLS_PROTO_OFFERED ;;
			*TLSv1)		outln $TLS_PROTO_OFFERED ;;
			*SSLv2)		redln $TLS_PROTO_OFFERED ;;
			*SSLv3)		brownln $TLS_PROTO_OFFERED ;;
			*)			outln "FIXME: $TLS_PROTO_OFFERED" ;;
		esac

		out " Negotiated cipher         "
		default=`grep -w "Cipher" $TMPFILE | egrep -vw "New|is" | sed -e 's/^ \+Cipher \+://' -e 's/ //g'`
		case "$default" in
			*NULL*|*EXP*)	redln "$default" ;;
			*RC4*)		literedln "$default" ;;
			*CBC*)		literedln "$default" ;; #FIXME BEAST: We miss some CBC ciphers here, need to work w/ a list
			*GCM*)		litegreenln "$default" ;; # best ones
			ECDHE*AES*)    brownln "$default" ;; # it's CBC. so lucky13
			*)			outln "$default" ;;
		esac
		outln

		out " Server key size           "
		keysize=`grep -w "^Server public key is" $TMPFILE | sed -e 's/^Server public key is //'`
		if [ -z "$keysize" ]; then
			outln "(couldn't determine)"
		else
			case "$keysize" in
				1024*) literedln "$keysize" ;;
				2048*) outln "$keysize" ;;
				4096*) litegreenln "$keysize" ;;
				*) outln "$keysize" ;;
			esac
		fi

		out " TLS server extensions     "
		extensions=`grep -w "^TLS server extension" $TMPFILE | sed -e 's/^TLS server extension \"//' -e 's/\".*$/,/g'`
		if [ -z "$extensions" ]; then
			outln "(none)"
		else
			echo $extensions | sed 's/,$//'	# remove last comma
		fi

		out " Session Tickets RFC 5077  "
		sessticket_str=`grep -w "session ticket" $TMPFILE | grep lifetime`
		if [ -z "$sessticket_str" ]; then
			outln "(none)"
		else
			lifetime=`echo $sessticket_str | grep lifetime | sed 's/[A-Za-z:() ]//g'`
			unit=`echo $sessticket_str | grep lifetime | sed -e 's/^.*'"$lifetime"'//' -e 's/[ ()]//g'`
			outln "$lifetime $unit"
		fi

		out " OCSP stapling            "
		if grep "OCSP response" $TMPFILE | grep -q "no response sent" ; then
			out " not offered"
		else
			if grep "OCSP Response Status" $TMPFILE | grep -q successful; then
				litegreen " OCSP stapling offered"
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

	rm $TMPFILE
	return $ret
}


# http://www.heise.de/security/artikel/Forward-Secrecy-testen-und-einrichten-1932806.html
pfs() {
	outln
	blue "--> Testing (Perfect) Forward Secrecy  (P)FS)"; outln
# https://community.qualys.com/blogs/securitylabs/2013/08/05/configuring-apache-nginx-and-openssl-for-forward-secrecy
	PFSOK='EECDH+ECDSA+AESGCM EECDH+aRSA+AESGCM EECDH+ECDSA+SHA256 EECDH+aRSA+SHA256 EECDH+aRSA+RC4 EDH+aRSA EECDH RC4 !RC4-SHA !aNULL !eNULL !LOW !3DES !MD5 !EXP !PSK !SRP !DSS:@STRENGTH'
#	PFSOK='EECDH+ECDSA+AESGCM EECDH+aRSA+AESGCM EECDH+ECDSA+SHA384 EECDH+ECDSA+SHA256 EECDH+aRSA+SHA384 EECDH'

	$OPENSSL ciphers -V "$PFSOK" >$TMPFILE
	if [ $? -ne 0 ] || [ `wc -l $TMPFILE | awk '{ print $1 }' ` -lt 3 ]; then
		out "Note: you have the following client side ciphers only for PFS. "
		out "Thus it doesn't make sense to test PFS"
		cat $TMPFILE 
		return 1
	fi
	savedciphers=`cat $TMPFILE`
	[ x$SHOW_LCIPHERS = "xyes" ] && echo "local ciphers available for testing PFS:" && echo `cat $TMPFILE`

	$OPENSSL s_client -cipher 'ECDH:DH' $STARTTLS -connect $NODEIP:$PORT $SNI &>$TMPFILE </dev/null
	ret=$?
	outln
	if [ $ret -ne 0 ] || [ `grep -c "BEGIN CERTIFICATE" $TMPFILE` -eq 0 ]; then
		brown "No PFS available"
	else
		litegreen "PFS seems generally available. Now testing specific ciphers ..."; outln "\n"
		noone=0
		neat_header
		$OPENSSL ciphers -V "$PFSOK" | while read hexcode n ciph sslvers kx auth enc mac; do
			$OPENSSL s_client -cipher $ciph $STARTTLS -connect $NODEIP:$PORT $SNI &>/dev/null </dev/null
			ret=$?
			if [ $ret -ne 0 ] && [ "$SHOW_EACH_C" -eq 0 ] ; then
				continue # no successful connect AND not verbose displaying each cipher
			fi
			normalize_ciphercode $hexcode
			neat_list $HEXC $ciph $kx $enc $strength
			if [ "$SHOW_EACH_C" -ne 0 ] ; then
				[ -r $MAP_RFC_FNAME ] && go2_column 114
				if [ $ret -eq 0 ]; then
					green "works"
				else
					out "not a/v"
				fi
			else
				noone=1
			fi
			outln
		done
		outln
		if [ "$noone" -eq 0 ] ; then
			 out "Please note: detected PFS ciphers don't necessarily mean any client/browser will use them"
			 ret=0
		else
			 magenta "no PFS ciphers found"
			 ret=1
		fi
		outln
	fi
	rm $TMPFILE
	return $ret
}


rc4() {
	outln
	blue "--> Checking RC4 Ciphers" ; outln
	$OPENSSL ciphers -V 'RC4:@STRENGTH' >$TMPFILE 
	[ x$SHOW_LCIPHERS = "xyes" ] && echo "local ciphers available for testing RC4:" && echo `cat $TMPFILE`
	$OPENSSL s_client -cipher `$OPENSSL ciphers RC4` $STARTTLS -connect $NODEIP:$PORT $SNI &>/dev/null </dev/null
	RC4=$?
	if [ $RC4 -eq 0 ]; then
		litered "\nRC4 seems generally available. Now testing specific ciphers..."; outln "\n"
		bad=1
		neat_header
		cat $TMPFILE | while read hexcode n ciph sslvers kx auth enc mac; do
			$OPENSSL s_client -cipher $ciph $STARTTLS -connect $NODEIP:$PORT $SNI </dev/null &>/dev/null
			ret=$?
			if [ $ret -ne 0 ] && [ "$SHOW_EACH_C" -eq 0 ] ; then
				continue # no successful connect AND not verbose displaying each cipher
			fi
			normalize_ciphercode $hexcode
			neat_list $HEXC $ciph $kx $enc $strength
			if [ "$SHOW_EACH_C" -ne 0 ]; then
				[ -r $MAP_RFC_FNAME ] && go2_column 114
				if [ $ret -eq 0 ]; then
					litered "available "
				else
					out "not a/v "
				fi
			else
				bad=1
				out
			fi
			outln
		done
		# https://en.wikipedia.org/wiki/Transport_Layer_Security#RC4_attacks
		# http://blog.cryptographyengineering.com/2013/03/attack-of-week-rc4-is-kind-of-broken-in.html
		outln
		outln "RC4 is kind of broken, for e.g. IE6 consider 0x13 or 0x0a"
	else
		outln
		litegreenln "no RC4 ciphers detected (OK)"
		bad=0
	fi

	rm $TMPFILE
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


spdy(){
	out " SPDY/NPN   "
	if [ "x$STARTTLS" != "x" ]; then
		outln "SPDY is an HTTP protocol"
		ret=2
	fi
	# first, does the current openssl support it?
	$OPENSSL s_client help 2>&1 | grep -qw nextprotoneg
	if [ $? -ne 0 ]; then
		magenta "Local problem: $OPENSSL cannot test SPDY"; outln
		ret=3
	fi
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
				green "$tmpstr" ; out " (advertised)"
				ret=0
			else
				litemagenta "please check manually, response from server was ambigious ..."
				ret=10
			fi
		fi
	else
		litemagenta "handshake failed"
		ret=2
	fi
	outln
	# btw: nmap can do that too http://nmap.org/nsedoc/scripts/tls-nextprotoneg.html
	# nmap --script=tls-nextprotoneg #NODE -p $PORT is your friend if your openssl doesn't want to test this
	rm $TMPFILE
	return $ret
}

fd_socket() {
# arg doesn't work here
	if ! exec 5<> /dev/tcp/$NODEIP/$PORT; then
		magenta "`basename $0`: unable to open a socket to $NODEIP:$PORT"
		return 6
	fi
	return 0
}

close_socket(){
	exec 5<&-
	exec 5>&-
	return 0
}

ok_ids(){
	echo
	tput bold; tput setaf 2; echo "ok -- something resetted our ccs packets"; tput sgr0
	echo
	exit 0
}

ccs_injection(){
	# see https://www.openssl.org/news/secadv_20140605.txt
	# mainly adapted from Ramon de C Valle's C code from https://gist.github.com/rcvalle/71f4b027d61a78c42607
	bold " CCS "; out " (CVE-2014-0224), experimental        "
	ccs_message="\x14\x03\tls_version\x00\x01\x01"

	$OPENSSL s_client $STARTTLS -connect $NODEIP:$PORT &>$TMPFILE </dev/null

	tls_hexcode=x01
	proto_offered=`grep -w Protocol $TMPFILE | sed -e 's/^ \+Protocol \+://'`
	case $tls_proto_offered in
		*TLSv1.2*)	tls_hexcode=x03 ;;
		*TLSv1.1*)	tls_hexcode=x02 ;;
	esac

	client_hello="
	# TLS header ( 5 bytes)
	,x16,               # Content type (x16 for handshake)
	x03, tls_version,   # TLS Version
	x00, x93,           # Length
	# Handshake header
	x01,                # Type (x01 for ClientHello)
	x00, x00, x8f,      # Length
	x03, tls_version,   # TLS Version
	# Random (32 byte) 
	x53, x43, x5b, x90, x9d, x9b, x72, x0b,
	xbc, x0c, xbc, x2b, x92, xa8, x48, x97,
	xcf, xbd, x39, x04, xcc, x16, x0a, x85,
	x03, x90, x9f, x77, x04, x33, xd4, xde,
	x00,                # Session ID length
	x00, x68,           # Cipher suites length
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

	msg=`echo "$client_hello" | sed -e 's/# .*$//g' -e 's/,/\\\/g' | sed -e 's/ //g' -e 's/[ \t]//g' | tr -d '\n'`

	fd_socket 5 || return 6

	[ $VERBOSE -eq 1 ] && out " sending client hello, "
	socksend "$msg" $tls_hexcode 1
	sockread 10000 

	if [ $VERBOSE -eq 1 ]; then
		outln "\n server hello:"
		echo "$SOCKREPLY" | xxd -c32 | head -20
		outln "[...]"
		outln "payload with TLS version $tls_hexcode:"
	fi

	socksend $ccs_message $tls_hexcode 1 || ok_ids
	socksend $ccs_message $tls_hexcode 2 || ok_ids
	sockread 16384
	retval=$?

	if [ $VERBOSE -eq 1 ]; then
		outln "\n reply: "
		echo "$SOCKREPLY" | xxd -c32
		outln
	fi

	reply_sanitized=`echo "$SOCKREPLY" | xxd -p | tr -cd '[:print:]' | sed 's/^..........//'`
	lines=`echo "$SOCKREPLY" | xxd -c32 | wc -l`

	if [ "$reply_sanitized" == "0a" ] || [ "$lines" -gt 1 ] ; then
		green "not vulnerable (OK)"
		ret=0
	else
		red "VULNERABLE"
		ret=1
	fi
	[ $retval -eq 3 ] && out ", timed out"
	outln 

	close_socket
	rm $TMPFILE
	return $ret
}

heartbleed(){
	bold " Heartbleed\c"; out " (CVE-2014-0160), experimental  "
# see  http://heartbleed.com/
	$OPENSSL s_client -tlsextdebug 2>&1 | grep -wq '^usage'
	if [ $? -eq 0 ]; then
		magenta "Local problem: Your $OPENSSL cannot run the pretest for this - "
		outln "continuing at your own risks"
	fi
# we don't need SNI here:
	$OPENSSL s_client $STARTTLS -connect $NODEIP:$PORT -tlsextdebug &>$TMPFILE </dev/null
	grep "server extension" $TMPFILE | grep -wq heartbeat
	if [ $? -ne 0 ]; then
		greenln "No TLS heartbeat extension (OK)"
		ret=0
	else
		# mainly adapted from https://gist.github.com/takeshixx/10107280
		heartbleed_payload="\x18\x03\tls_version\x00\x03\x01\x40\x00"

		tls_hexcode=x01
		proto_offered=`grep -w Protocol $TMPFILE | sed -e 's/^ \+Protocol \+://'`
		case $tls_proto_offered in
			*TLSv1.2*)	tls_hexcode=x03 ;;
			*TLSv1.1*)	tls_hexcode=x02 ;;
		esac

		client_hello="
		# TLS header ( 5 bytes)
		,x16,                      # Content type (x16 for handshake)
		x03, tls_version,          # TLS Version
		x00, xdc,                  # Length
		# Handshake header
		x01,                       # Type (x01 for ClientHello)
		x00, x00, xd8,             # Length
		x03, tls_version,          # TLS Version
          # Random (32 byte)
		x53, x43, x5b, x90, x9d, x9b, x72, x0b,
		xbc, x0c, xbc, x2b, x92, xa8, x48, x97,
		xcf, xbd, x39, x04, xcc, x16, x0a, x85,
		x03, x90, x9f, x77, x04, x33, xd4, xde,
		x00,                       # Session ID length
		x00, x66,                  # Cipher suites length
                                     # Cipher suites (51 suites)
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
		x01,                       # Compression methods length
		x00,                       # Compression method (x00 for NULL)
		x00, x49,                  # Extensions length
          # Extension: ec_point_formats
		x00, x0b, x00, x04, x03, x00, x01, x02,
          # Extension: elliptic_curves
		x00, x0a, x00, x34, x00, x32, x00, x0e,
		x00, x0d, x00, x19, x00, x0b, x00, x0c,
		x00, x18, x00, x09, x00, x0a, x00, x16,
		x00, x17, x00, x08, x00, x06, x00, x07,
		x00, x14, x00, x15, x00, x04, x00, x05,
		x00, x12, x00, x13, x00, x01, x00, x02,
		x00, x03, x00, x0f, x00, x10, x00, x11,
          # Extension: SessionTicket TLS
		x00, x23, x00, x00,
          # Extension: Heartbeat
		x00, x0f, x00, x01, x01"

		msg=`echo "$client_hello" | sed -e 's/# .*$//g' -e 's/,/\\\/g' | sed -e 's/ //g' -e 's/[ \t]//g' | tr -d '\n'`

		fd_socket 5 || return 6

		[ $VERBOSE -eq 1 ] && out " sending client hello, "
		socksend "$msg" $tls_hexcode 1
		sockread 10000 

		if [ $VERBOSE -eq 1 ]; then
			outln "\n server hello:"
			echo "$SOCKREPLY" | xxd -c32 | head -20
			outln "[...]"
			outln " sending payload with TLS version $tls_hexcode:"
		fi

		socksend $heartbleed_payload $tls_hexcode 1
		sockread 16384
		retval=$?

		if [ $VERBOSE -eq 1 ]; then
			outln "\n heartbleed reply: "
			echo "$SOCKREPLY" | xxd -c32
			outln
		fi

		lines_returned=`echo "$SOCKREPLY" | xxd | wc -l`
		if [ $lines_returned -gt 1 ]; then
			red "VULNERABLE"
			ret=1
		else
			green "not vulnerable (OK)"
			ret=0
		fi
		[ $retval -eq 3 ] && green ", timed out"
		outln 
	fi

	close_socket
	rm $TMPFILE
	return $ret
}


renego() {
	ADDCMD=""
	# This tests for CVE-2009-3555 / RFC5746, OSVDB: 59968-59974
	case "$OSSL_VER" in
		# =< 0.9.7 is weeded out before
		0.9.8*)
			case "$OSSL_VER_APPENDIX" in
				[a-l])
					magenta "Your $OPENSSL $OSSL_VER cannot test the secure renegotiation vulnerability"
					return 3 ;;
				[m-z])
					# all ok ;;
			esac ;;
		1.0.1*)
			ADDCMD="-legacy_renegotiation" ;;
		0.9.9*|1.0*)
			# all ok ;;
	esac
	bold " Renegotiation "; out "(CVE 2009-3555)             "
	echo R | $OPENSSL s_client $ADDCMD $STARTTLS -connect $NODEIP:$PORT $SNI &>/dev/null
	reneg_ok=$?					# 0=client is renegotiating and does not gets an error: that should not be!
	NEG_STR="Secure Renegotiation IS NOT"
	echo "R" | $OPENSSL s_client $STARTTLS -connect $NODEIP:$PORT $SNI 2>&1 | grep -iq "$NEG_STR"
	secreg=$?						# 0= Secure Renegotiation IS NOT supported

	if [ $reneg_ok -eq 0 ] && [ $secreg -eq 0 ]; then
		# Client side renegotiation is accepted and secure renegotiation IS NOT supported 
		redln "IS vulnerable (NOT ok)"
		return 1
	fi
	if [ $reneg_ok -eq 1 ] && [ $secreg -eq 1 ]; then
		greenln "not vulnerable (OK)"
		return 0
	fi
	if [ $reneg_ok -eq 1 ] ; then   # 1,0
		litegreenln "got an error from the server while renegotiating on client: should be ok ($reneg_ok,$secreg)"
		return 0
	fi
	litegreenln "Patched Server detected ($reneg_ok,$secreg), probably ok"	# 0,1
	return 0
}

crime() {
	# in a nutshell: don't offer TLS/SPDY compression on the server side
	# 
	# This tests for CRIME Vulnerability (www.ekoparty.org/2012/juliano-rizzo.php) on HTTPS, not SPDY (yet)
     # Please note that it is an attack where you need client side control, so in regular situations this
	# means anyway "game over", w/wo CRIME
	# www.h-online.com/security/news/item/Vulnerability-in-SSL-encryption-is-barely-exploitable-1708604.html

	ADDCMD=""
	case "$OSSL_VER" in
		# =< 0.9.7 was weeded out before
		0.9.8)
			ADDCMD="-no_ssl2" ;;
		0.9.9*|1.0*)
		;;
	esac

	bold " CRIME, TLS " ; out "(CVE-2012-4929)                "

	# first we need to test whether OpenSSL binary has zlib support
	$OPENSSL zlib -e -a  -in /dev/stdin &>/dev/stdout </dev/null | grep -q zlib 
	if [ $? -eq 0 ]; then
		magentaln "Seems your $OPENSSL hasn't zlib support, so you cannot test for CRIME"; echo
		return 0  #FIXME
	fi

	STR=`$OPENSSL s_client $ADDCMD $STARTTLS -connect $NODEIP:$PORT $SNI 2>&1 </dev/null | grep Compression `
	if echo $STR | grep -q NONE >/dev/null; then
		greenln "not vulnerable (OK) "
		ret=0
	else
		redln "IS vulnerable (NOT ok)"
		ret=1
	fi

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
#			bold "CRIME Vulnerability, SPDY \c" ; outln "(CVE-2012-4929): \c"

#			STR=`grep Compression $TMPFILE `
#			if echo $STR | grep -q NONE >/dev/null; then
#				green "not vulnerable (OK)"
#				ret=`expr $ret + 0`
#			else
#				red "IS vulnerable (NOT ok)"
#				ret=`expr $ret + 1`
#			fi
#		fi
#	fi
	[ $VERBERR -eq 0 ] && outln "$STR"
	#echo
	return $ret
}

beast(){
	#FIXME: to do
#in a nutshell: don't use CBC Ciphers in TLSv1.0
# need to provide a list with bad ciphers. Not sure though whether
# it can be fixed in the OpenSSL/NSS/whatsover stack
	return 0
}

youknowwho() {
# CVE-2013-2566, 
# NOT FIXME as there's no code: http://www.isg.rhul.ac.uk/tls/
# http://blog.cryptographyengineering.com/2013/03/attack-of-week-rc4-is-kind-of-broken-in.html
return 0
# in a nutshell: don't use RC4, really not!
}

old_fart() {
	magentaln "Your $OPENSSL $OSSL_VER version is an old fart..."
	magentaln "Get the precompiled bins, it doesn\'t make much sense to proceed"
	exit 3
}

find_openssl_binary() {
# 0. check environment variable whether it's executable
	if [ ! -z "$OPENSSL" ] && [ ! -x "$OPENSSL" ]; then
		redln "\ncannot execute specified ($OPENSSL) openssl binary."
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
	OSSL_BUILD_DATE=`$OPENSSL version -a | grep '^built' | sed -e 's/built on//' -e 's/: ... //' -e 's/: //' -e 's/ UTC//' -e 's/ +0000//' -e 's/.000000000//'`
	echo $OSSL_BUILD_DATE | grep -q "not available" && OSSL_BUILD_DATE=""
	export OPENSSL OSSL_VER OSSL_BUILD_DATE
	case "$OSSL_VER" in
		0.9.7*|0.9.6*|0.9.5*)
			# 0.9.5a was latest in 0.9.5 an released 2000/4/1, that'll NOT suffice for this test
			old_fart ;;
		0.9.8)
			case $OSSL_VER_APPENDIX in
				a|b|c|d|e) old_fart;; # no SNI!
			esac
			;;
	esac
	if [ $OSSL_VER_MAJOR -ne 1 ]; then
		magentaln "<Enter> at your own risk. $OPENSSL version < 1.0 is too old for this program"
		read a
	fi
	return 0
}


starttls() {
	protocol=`echo "$1" | sed 's/s$//'`	 # strip trailing s in ftp(s), smtp(s), pop3(s), imap(s) 
	case "$1" in
		ftp|smtp|pop3|imap|xmpp|telnet)
			$OPENSSL s_client -connect $NODEIP:$PORT $SNI -starttls $protocol </dev/null >$TMPFILE 2>&1
			ret=$?
			if [ $ret -ne 0 ]; then
				bold "Problem: $OPENSSL couldn't estabilish STARTTLS via $protocol"; outln
				cat $TMPFILE
				return 3
			else
# now, this is lame: normally this should be handled by top level. Then I need to do proper parsing
# of the cmdline e.g. with getopts. 
				STARTTLS="-starttls $protocol"
				export STARTTLS
				runprotocols		; ret=`expr $? + $ret`
				run_std_cipherlists	; ret=`expr $? + $ret`
				simple_preference	; ret=`expr $? + $ret`

				outln; blue "--> Testing specific vulnerabilities" ; outln "\n"
#FIXME: heartbleed + CCS won't work this way yet
#				heartbleed     ; ret=`expr $? + $ret`
#				ccs_injection  ; ret=`expr $? + $ret`
				renego		; ret=`expr $? + $ret`
				crime		; ret=`expr $? + $ret`
				beast		; ret=`expr $? + $ret`

				outln
				#cipher_per_proto   ; ret=`expr $? + $ret`
				allciphers		; ret=`expr $? + $ret`

				rc4			; ret=`expr $? + $ret`
				pfs			; ret=`expr $? + $ret`
			fi
			;;
		*) outln "momentarily only ftp, smtp, pop3, imap, xmpp and telnet allowed" >&2
			ret=2
			;;
	esac
	return $ret
}


help() {
	PRG=`basename $0`
	cat << EOF

$PRG <options> URI

where <options> is *one* of

	<-h|--help>                 what you're looking at
	<-b|--banner>               displays banner + version
	<-v|--version>              same as above
	<-V|--local>                pretty print all local ciphers
	<-V|--local> <hexcode>      what cipher is <pattern hexcode>?

	<-e|--each-cipher>          check each local ciphers remotely 
	<-E|-ee|--cipher-per-proto> check those per protocol
	<-f|--ciphers>              check cipher suites
	<-p|--protocols>            check TLS/SSL protocols only
	<-P|--preference>           displays the servers picks: protocol+cipher
	<-y|--spdy>                 checks for SPDY/NPN
	<-B|--heartbleed>           tests only for heartbleed vulnerability
	<-I|--ccs|--ccs_injection>  tests only for CCS injection vulnerability
    	<-R|--renegotiation>        tests only for renegotiation vulnerability
    	<-C|--compression|--crime>  tests only for CRIME vulnerability
    	<-T|--breach>               tests only for BREACH vulnerability
    	<-s|--pfs|--fs|--nsa>       checks (perfect) forward secrecy settings
 	<-4|--rc4|--appelbaum>      which RC4 ciphers are being offered?
	<-H|--header|--headers>     check for HSTS and server banner string

URI is  host|host:port|URL|URL:port
        (port 443 is assumed unless otherwise specified)

	<-t|--starttls> host:port <ftp|smtp|pop3|imap|xmpp|telnet> <SNI hostname> *)


*) for telnet STARTTLS support you need a/my patched openssl version


EOF
	return $?
}


mybanner() {
	me=`basename $0`
	osslver=`$OPENSSL version`
	osslpath=`which $OPENSSL`
	hn=`hostname`
	#poor man's ident (nowadays not neccessarily installed)
	idtag=`grep '\$Id' $0 | grep -w Exp | grep -v grep | sed -e 's/^#  //' -e 's/\$ $/\$/'`
	idtagshy="\033[1;30m$idtag\033[m\033[1m"
	bb=`cat <<EOF

#########################################################
$me v$VERSION  ($SWURL)
($idtagshy)

   This program is free software. Redistribution + 
   modification under GPLv2 is permitted. 
   USAGE w/o ANY WARRANTY. USE IT AT YOUR OWN RISK!

 Note you can only check the server against what is
 available (ciphers/protocols) locally on your machine
#########################################################
EOF
`
bold "$bb"
outln "\n"
outln "Using \"$osslver\" [$OSSL_BUILD_DATE]
      on \"$hn:$osslpath\"\n"

}

maketempf () {
	TMPFILE=`mktemp /tmp/ssltester.$NODE.XXXXXX` || exit 6
	HEADERFILE=`mktemp /tmp/ssltester.header$NODE.XXXXXX` || exit 6
	HEADERFILE_BREACH=`mktemp /tmp/ssltester.header$NODE.XXXXXX` || exit 6
	#LOGFILE=`mktemp /tmp/ssltester.$NODE.XXXXXX.log` || exit 6
}

cleanup () {
	if [ $DEBUG -eq 1 ] ; then
		[ -e $TMPFILE ] && cat $TMPFILE 
		[ -e $HEADERFILE ] && cat $HEADERFILE 
		[ -e $HEADERFILE_BREACH ] && cat $HEADERFILE_BREACH
		#[ -e $LOGFILE ] && cat $LOGFILE 
	else
		rm $TMPFILE $HEADERFILE $LOGFILE $GOST_CONF 2>/dev/null
	fi
	outln
	outln
	datebanner "Done"
	outln
}

initialize_engine(){
	if uname -s | grep -q BSD || ! $OPENSSL engine gost -vvvv -t -c 2>&1 >/dev/null; then
		litemagenta "No engine or GOST support via engine with your $OPENSSL"; outln "\n"
		return 1
	else 
		if [ -z "$OPENSSL_CONF" ]; then
			GOST_CONF=`mktemp /tmp/ssltester.GOST.XXXXXX` || exit 6
			# see https://www.mail-archive.com/openssl-users@openssl.org/msg65395.html
			cat >$GOST_CONF << EOF
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
			export OPENSSL_CONF=$GOST_CONF
		else
			litemagenta "For now I am providing the config file in to have GOST support"; outln
			sleep 2
			outln
		fi
	fi
	return 0
}


ignore_no_or_lame() {
	if [ "$WARNINGS" = "off" -o "$WARNINGS" = "false" ]; then
		return 0
	fi
	#outln
	out "$1 "
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

	#URLP=`echo $1 | sed 's/'"${PROTO}"':\/\/'"${NODE}"'//'`
	#URLP=`echo $URLP | sed 's/\/\//\//g'`                             # // -> /

	# now get NODEIP
	get_dns_entries

	# check if we can connect to port 
	if ! fd_socket; then
		ignore_no_or_lame "Ignore? "
		[ $? -ne 0 ] && exit 3
	fi
	close_socket

	if [ -z "$2" ]; then	# for starttls we don't want this check
		# is ssl service listening on port? FIXME: better with bash on IP!
		$OPENSSL s_client -connect "$NODE:$PORT" $SNI </dev/null >/dev/null 2>&1 
		if [ $? -ne 0 ]; then
			ignore_no_or_lame "On port $PORT @ $NODE doesn't seem a TLS/SSL enabled server. Really really ignore? \n (Pls note that he results might look ok but they are not) "
			[ $? -ne 0 ] && exit 3
		fi
	fi

	datebanner "Testing"

	[ "$PORT" != 443 ] && bold "A non standard port or testing no web servers might show lame reponses (then just wait)\n"
	initialize_engine
}


get_dns_entries() {
	test4iponly=`printf $NODE | sed -e 's/[0-9]//g' -e 's/\.//g'`
	if [ "x$test4iponly" == "x" ]; then  # only an IPv4 address was supplied
		IP4=$NODE
		SNI=""	# override this as we test the IP only
	else
		# for security testing sometimes we have local host entries, so getent is preferred
		if which getent 2>&1 >/dev/null ; then
			getent ahostsv4 $NODE 2>/dev/null >/dev/null
			if [ $? -eq 0 ]; then
				# Linux, no BSD
				key2get=ahostsv4
			else
				key2get=hosts
			fi
		fi
		IP4=`getent $key2get $NODE &>/dev/null | grep $NODE | grep -v ':' | awk '{ print $1}' | uniq`
		# getent returned nothing:
		if [ -z "$IP4" ] ; then
			IP4=`host -t a $NODE | grep -v alias | sed 's/^.*address //'`
			if  echo "$IP4" | grep -q NXDOMAIN  ; then
				magenta "Can't proceed: No IP resultion from \"$NODE\""; outln "\n"
				exit 1
			fi
		fi

		# for IPv6 we often get this :ffff:IPV4 address which isn't of any use
		#which getent 2>&1 >/dev/null && IP6=`getent ahostsv6 $NODE | grep $NODE | awk '{ print $1}' | grep -v '::ffff' | uniq`

		if [ -z "$IP6" ] ; then
			if host -t aaaa $NODE 2>&1 >/dev/null ; then
				IP6=`host -t aaaa $NODE | grep -v alias | grep -v "no AAAA record" | sed 's/^.*address //'`
			else
				IP6=""
			fi
		fi
	fi
	
	IPADDRs=`echo $IP4`
	[ ! -z "$IP6" ] && IPADDRs=`echo $IP4`" "`echo $IP6`

# FIXME: we could test more than one IPv4 addresses if available, same IPv6. For now we test the first IPv4:
	NODEIP=`echo "$IP4" | head -1`

# we can't do this as some checks are not yet IPv6 safe (sorry!)
	#NODEIP=`echo "$IP6" | head -1`
	rDNS=`host -t PTR $NODEIP | grep -v "is an alias for" | sed -e 's/^.*pointer //' -e 's/\.$//'`
	echo $rDNS | grep -q NXDOMAIN  && rDNS=" - "
}

display_rdns_etc() {
     if [ `echo "$IPADDRs" | wc -w` -gt 1 ]; then
          out " further IP addresses:  "
          for i in $IPADDRs; do
               [ "$i" == "$NODEIP" ] && continue
               out " $i"
          done
		outln
	fi
	if  [ -n "$rDNS" ] ; then
		out  " rDNS ($NODEIP):"
		out "$rDNS" 26
		outln
	fi
}

datebanner() {
	tojour=`date +%F`" "`date +%R`
	reverse "$1 now ($tojour) ---> $NODEIP:$PORT ($NODE) <---"; outln
     if [ "$1" = "Testing" ] ; then
		outln
		display_rdns_etc 
		outln 
	fi
	outln
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
MAP_RFC_FNAME=`dirname $PATH_TO_TESTSSL`"/mapping-rfc.txt" 	# this file provides a pair "keycode/ RFC style name", see the RFCs, cipher(1)
												# and https://www.carbonwind.net/TLS_Cipher_Suites_Project/tls_ssl_cipher_suites_simple_table_all.htm

#FIXME: I know this sucks and getoptS is better

case "$1" in
     -b|--banner|-banner|-v|--version|-version)
		exit 0 
		;;
	-V|--local)
		initialize_engine 	# GOST support
		prettyprint_local "$2"
		exit $? ;;
	-x|--single-test)
		parse_hn_port "$3"
		maketempf
		test_just_one $2
		ret=$?
		cleanup
		exit $ret ;;
	-t|--starttls)			
		parse_hn_port "$2" "$3" # here comes hostname:port and protocol to signal starttls
		maketempf
		starttls "$3"		# protocol
		ret=$?
		cleanup
		exit $ret ;;
	-e|--each-cipher)
		parse_hn_port "$2"
		maketempf
		allciphers 
		ret=$?
		cleanup 
		exit $ret ;;
	-E|-ee|--cipher-per-proto)  
		parse_hn_port "$2"
		maketempf
		cipher_per_proto
		ret=$?
		cleanup 
		exit $ret ;;
	-p|--protocols)
		parse_hn_port "$2"
		maketempf
		runprotocols 	; ret=$?
		spdy			; ret=`expr $? + $ret`
		cleanup
		exit $ret ;;
	-f|--ciphers)
		parse_hn_port "$2"
		maketempf
		run_std_cipherlists
		ret=$?
		cleanup
		exit $ret ;;
     -P|--preference)   
		parse_hn_port "$2"
		maketempf
		simple_preference
		ret=$?
		cleanup
		exit $ret ;;
	-y|--spdy|--google)
		parse_hn_port "$2"
		maketempf
		spdy
		ret=$?
		cleanup
		exit $?  ;;
	-B|--heartbleet)
		parse_hn_port "$2"
		maketempf
		outln; blue "--> Testing for heartbleed vulnerability"; outln "\n"
		heartbleed
		ret=$?
		cleanup
		exit $?  ;;
	-I|--ccs|--ccs_injection)
		parse_hn_port "$2"
		maketempf
		outln; blue "--> Testing for CCS injection vulnerability"; outln "\n"
		ccs_injection
		ret=$?
		cleanup
		exit $?  ;;
	-R|--renegotiation)
		parse_hn_port "$2"
		maketempf
		outln; blue "--> Testing for Renegotiation vulnerability"; outln "\n"
		renego
		ret=$?
		cleanup
		exit $?  ;;
	-C|--compression|--crime)
		parse_hn_port "$2"
		maketempf
		outln; blue "--> Testing for CRIME vulnerability"; outln "\n"
		crime
		ret=$?
		cleanup
		exit $?  ;;
	-T|--breach)
		parse_hn_port "$2"
		maketempf
		outln; blue "--> Testing for BREACH (HTTP compression) vulnerability"; outln "\n"
		breach
		ret=$?
		ret=`expr $? + $ret`
		cleanup
		exit $ret ;;
	-4|--rc4|--appelbaum)
		parse_hn_port "$2"
		maketempf
		rc4
		ret=$?
		cleanup
		exit $?  ;;
	-s|--pfs|--fs|--nsa)
		parse_hn_port "$2"
		maketempf
		pfs
		ret=$?
		cleanup
		exit $ret ;;
	-H|--header|--headers)  
		parse_hn_port "$2"
		maketempf
		outln; blue "--> Testing HTTP Header response"; outln "\n"
		hsts
		ret=$?
		serverbanner
		ret=`expr $? + $ret`
		cleanup
		exit $ret ;;
	*)
		parse_hn_port "$1"
		maketempf

		runprotocols		; ret=$?
		spdy 			; ret=`expr $? + $ret`
		run_std_cipherlists	; ret=`expr $? + $ret`
		simple_preference 	; ret=`expr $? + $ret`

		outln; blue "--> Testing specific vulnerabilities"; outln "\n"
		heartbleed          ; ret=`expr $? + $ret`
		ccs_injection       ; ret=`expr $? + $ret`
		renego			; ret=`expr $? + $ret`
		crime			; ret=`expr $? + $ret`
		breach			; ret=`expr $? + $ret`
		beast			; ret=`expr $? + $ret`

		outln; blue "--> Testing HTTP Header response"; outln "\n"
		hsts 			; ret=`expr $? + $ret`
		serverbanner		; ret=`expr $? + $ret`

		rc4				; ret=`expr $? + $ret`
		pfs				; ret=`expr $? + $ret`

		cleanup 
		exit $ret ;;
esac

#  $Id: testssl.sh,v 1.119 2014/10/07 10:03:47 dirkw Exp $ 
# vim:ts=5:sw=5


