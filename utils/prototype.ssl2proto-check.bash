#!/usr/bin/env bash

# bash socket implementation of checking the availability of SSLv2 protocol
# and ciphers on a remote server (loosely based on my bash-heartbleed implementation).
#
# Author: Dirk Wetter, GPLv2 see https://testssl.sh/LICENSE.txt 

# it helps to wireshark:
# /<path>/openssl s_client -state -ssl2 -connect AA.BB.YYY.XXX:443 </dev/null
# /<path>/openssl s_client -state -debug -ssl2 -connect AA.BB.YYY.XXX:443 </dev/null

V2_HELLO_CIPHERSPEC_LENGTH=0	# initialize
IFILE=./mapping-rfc.txt
NODE=""
COL_WIDTH=32
DEBUG=${DEBUG:-0}
USLEEP_REC=${USLEEP_REC:-0.2}
USLEEP_SND=${USLEEP_SND:-0.1}	# 1 second wait until otherwise specified
MAX_WAITSOCK=2
SOCK_REPLY_FILE=""
NW_STR=""


# 9 cipher specs SSLv2:
SSLv2_CIPHER_SPECS="
05 00 80 
03 00 80 
01 00 80 
07 00 c0 
08 00 80 
06 00 40 
04 00 80 
02 00 80 
00 00 00"

# SSLV2 chello:
SSLv2_CLIENT_HELLO="
,80,34    # length (here: 52)
,01       # Client Hello 
,00,02    # SSLv2
,00,1b    # cipher spec length (here: 27 )
,00,00    # session ID length
,00,10    # challenge length
,05,00,80 # 1st cipher
,03,00,80 # 2nd
,01,00,80 # 3rd
,07,00,c0 # 4th
,08,00,80 # 5th
,06,00,40 # 6th
,04,00,80 # 7th
,02,00,80 # 8th
,00,00,00 # 9th
,29,22,be,b3,5a,01,8b,04,fe,5f,80,03,a0,13,eb,c4 # Challenge
"

# only classical V2 ciphers are used here, see  http://max.euston.net/d/tip_sslciphers.html

# there are v3 in v2!!! : https://tools.ietf.org/html/rfc6101#appendix-E
# Cipher specifications introduced in version 3.0 can be included in version 2.0 client hello messages using
# the syntax below. [..] 
# V2CipherSpec (see Version 3.0 name) = { 0x00, CipherSuite }; !!!!

# see:
#   http://max.euston.net/d/tip_ssldump.html
#   https://idea.popcount.org/2012-06-16-dissecting-ssl-handshake/
#   https://books.google.de/books?id=LfsC03f8oGsC&pg=PA592&lpg=PA592&dq=sslv2+server+hello+struct&source=bl&ots=JWeSD-9pwH&sig=lMzhxTdybJ3tfWC2p9ltIOKlIso&hl=en&sa=X&ei=U3WmVKzyNoTgOOeigNAP&ved=0CDUQ6AEwAw


help() {
	echo
	echo "Syntax $0 <hostname>"
	echo
	exit 1
}


parse_hn_port() {
	PORT=443       # unless otherwise auto-determined, see below
	NODE="$1"

	# strip "https", supposed it was supplied additionally
	echo $NODE | grep -q 'https://' && NODE=`echo $NODE | sed -e 's/https\:\/\///' `

	# strip trailing urlpath
	NODE=`echo $NODE | sed -e 's/\/.*$//'`

	# determine port, supposed it was supplied additionally
	echo $NODE | grep -q ':' && PORT=`echo $NODE | sed 's/^.*\://'` && NODE=`echo $NODE | sed
	's/\:.*$//'`
}

# arg1: formatted string here in the code
code2network() {
	NW_STR=`echo "$1" | sed -e 's/,/\\\x/g' | sed -e 's/# .*$//g' -e 's/ //g' -e '/^$/d' | tr -d '\n' | tr -d '\t'`
}

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

     SOCK_REPLY_FILE=`mktemp /tmp/ddreply.XXXXXX` || exit 7
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

     if ps ax | grep -v grep | grep -q $pid; then
          # time's up and dd is still alive --> timeout
          kill $pid >&2 2>/dev/null
          wait $pid 2>/dev/null
          ret=3 # means killed
     fi

     return $ret
}

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
	[[ "$DEBUG" -eq 4 ]] && echo $v2_hello_ascii 	# one line without any blanks
	[[ -z $v2_hello_ascii ]] && return 0			# no server hello received

	# now scrape two bytes out of the reply per byte
	v2_hello_initbyte="${v2_hello_ascii:0:1}"  # normally this belongs to the next, should be 8!
	v2_hello_length="${v2_hello_ascii:1:3}"  # + 0x8000 see above
	v2_hello_handshake="${v2_hello_ascii:4:2}"
	v2_hello_cert_length="${v2_hello_ascii:14:4}"
	v2_hello_cipherspec_length="${v2_hello_ascii:18:4}"
	V2_HELLO_CIPHERSPEC_LENGTH=`printf "%d\n" "0x$v2_hello_cipherspec_length"`

	if [[ $v2_hello_initbyte != "8" ]] || [[ $v2_hello_handshake != "04" ]]; then
		[[ $DEBUG -ge 1 ]] && echo "$v2_hello_initbyte / $v2_hello_handshake"
		return 1
	fi

	if [[ $DEBUG -ge 2 ]]; then
		echo "SSLv2 server hello length: 0x0$v2_hello_length"
		echo "SSLv2 certificate length:  0x$v2_hello_cert_length"
		echo "SSLv2 cipher spec length:  0x$v2_hello_cipherspec_length"
	fi
	return 0
}


#### main

[[ -z "$1" ]] && help  # hostname

echo
parse_hn_port "$1"

	if ! exec 5<> /dev/tcp/$NODE/$PORT; then
		echo "`basename $0`: unable to connect to $NODE:$PORT"
		exit 2
	fi
	# socket is now open with fd 5

	[[ "$DEBUG" -ge 1 ]] && printf "sending client hello...\n\n"
	socksend_clienthello 

	sockread_serverhello 32768 0
	[[ "$DEBUG" -ge 1 ]] && printf "\nreading server hello...\n\n"
	if [[ "$DEBUG" -eq 3 ]]; then
		#xxd -c$COL_WIDTH $SOCK_REPLY_FILE  | head -3
		#hexdump -v -e '"%04_ax:  " 16/1 "%02X " "\n"' $SOCK_REPLY_FILE | head -6
		hexdump -C $SOCK_REPLY_FILE | head -6
		echo
	fi

	display_sslv2serverhello "$SOCK_REPLY_FILE"

	# see https://secure.wand.net.nz/trac/libprotoident/wiki/SSL
	lines=`cat "$SOCK_REPLY_FILE" 2>/dev/null | hexdump -C | wc -l` 

	printf "Protocol: "; tput bold
	if [[ "$lines" -gt 1 ]] ;then
		tput setaf 1; printf "available with $(($V2_HELLO_CIPHERSPEC_LENGTH / 3 )) ciphers"
		ret=0
	else
		tput setaf 2; printf "NOT available"
		ret=1
	fi
	tput sgr0


	[[ "$DEBUG" -ge 2 ]] && printf "  ($lines lines)"
	echo


	# closing fd:
	exec 5<&-
	exec 5>&-

	rm $SOCK_REPLY_FILE

echo
exit 0

#test: dragon,  simhq.com=gryphon1.gryphoninternet.com  misim.gov.il,   shop4-heating.co.uk, service.hamburgwasser.de
#                74.116.0.167                           147.237.80.2    85.92.77.27

#  vim:tw=110:ts=5:sw=5
#  $Id: prototype.ssl2proto-check.bash,v 1.10 2015/09/25 19:02:24 dirkw Exp $ 
