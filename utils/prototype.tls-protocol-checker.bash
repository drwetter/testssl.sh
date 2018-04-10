#!/usr/bin/env bash

# bash socket implementation of checking the availability of TLS, (SSLv3 to TLS 1.2)
# Based on my bash-heartbleed (loosely based on my bash-heartbleed implementation)
#
# Author: Dirk Wetter, GPLv2 see https://testssl.sh/LICENSE.txt 

# it helps to wireshark:
# /<path>/openssl s_client -state -ssl3 -connect AA.BB.YYY.XXX:443 -servername target
# /<path>/openssl s_client -state -tls1 -connect AA.BB.YYY.XXX:443 -servername target
# /<path>/openssl s_client -state -tls1_1 -connect AA.BB.YYY.XXX:443 -servername target
# /<path>/openssl s_client -state -tls1_2 -connect AA.BB.YYY.XXX:443 -servername target
#
# debug is easier for response:
# /<path>/openssl s_client -tls1 -debug -connect target:443 </dev/null

# todo: NPN     (/<path>/openssl s_client -host target -port 443 -nextprotoneg 'spdy/4a2,spdy/3,spdy/3.1,spdy/2,spdy/1,http/1.1'
# todo: TLS 1.3 (https://tools.ietf.org/html/draft-ietf-tls-tls13-03#section-7.4)
# todo: DTLS    (https://tools.ietf.org/html/rfc4347#section-4.2.2)

IFILE=./mapping-rfc.txt
NODE=""
SN_HEX=""
LEN_SN_HEX=0
COL_WIDTH=32
DEBUG=${DEBUG:-0}
USLEEP_REC=${USLEEP_REC:-0.2}
USLEEP_SND=${USLEEP_SND:-0.1}	# 1 second wait until otherwise specified
MAX_WAITSOCK=2
SOCK_REPLY_FILE=""
NW_STR=""
LEN_STR=""
DETECTED_TLS_VERSION=""

# spdy, TLS 1.2, 133 cipher:
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
00, 0b, 00, 08, 00, 06, 00, 03, 00, ff
"

# 76 cipher fuer SSLv3, TLS 1, TLS 1.1:
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
#00 00 	# extension server_name
#00 1a    # length       			= the following +2 = server_name length + 5
#00 18    # server_name list_length	= server_name length +3
#00 		# server_name type (hostname)
#00 15 	# server_name length
#66 66 66 66 66 66 2e 66 66 66 66 66 66 66 66 66 66 2e 66 66 66  target.mydomain1.tld # server_name target


help() {
	echo "Syntax $0 <hostname> [[TLS lsb]]"
	echo
	echo "example:    $0 google.com "
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
	echo $NODE | grep -q ':' && PORT=`echo $NODE | sed 's/^.*\://'` && NODE=`echo $NODE | sed 's/\:.*$//'`

	# servername to network bytes:
	LEN_SN_HEX=`echo ${#NODE}`
	hexdump_format_str="$LEN_SN_HEX/1 \"%02x,\""
	SN_HEX=`printf $NODE | hexdump -v -e "${hexdump_format_str}" | sed 's/,$//'`
}

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


# arg1: TLS_VER_LSB
# arg2: CIPHER_SUITES string
# arg3: SERVERNAME
# ??? more extensions?
socksend_clienthello() {

	if [[ "$1" != "ff" ]]; then	# internally we use 00 to indicate SSLv2
		len_sni=`echo ${#3}`
		#tls_ver=printf "%02x\n" $1"

		code2network "$2"
		cipher_suites="$NW_STR"	# we don't have the leading \x here so string length is two byte less, see next

		# convert length's from dec to hex:
		hex_len_sn_hex=`printf "%02x\n" $LEN_SN_HEX`
		hex_len_sn_hex3=`printf "%02x\n" $((LEN_SN_HEX+3))`
		hex_len_sn_hex5=`printf "%02x\n" $((LEN_SN_HEX+5))`
		hex_len_extension=`printf "%02x\n" $((LEN_SN_HEX+9))`
		
		len_ciph_suites_byte=`echo ${#cipher_suites}`
		let "len_ciph_suites_byte += 2"

		# we have additional 2 chars \x in each 2 byte string and 2 byte ciphers, so we need to divide by 4:
		len_ciph_suites=`printf "%02x\n" $(($len_ciph_suites_byte / 4 ))`
		len2twobytes "$len_ciph_suites"
		len_ciph_suites_word="$LEN_STR"
		[[ $DEBUG -ge 4 ]] && echo $len_ciph_suites_word

		len2twobytes `printf "%02x\n" $((0x$len_ciph_suites + 0x27 + 0x$hex_len_extension + 0x2))`
		#len2twobytes `printf "%02x\n" $((0x$len_ciph_suites + 0x27))`
		len_c_hello_word="$LEN_STR"
		[[ $DEBUG -ge 4 ]] && echo $len_c_hello_word

		len2twobytes `printf "%02x\n" $((0x$len_ciph_suites + 0x2b + 0x$hex_len_extension + 0x2))`
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
		,00, $hex_len_extension  # first the len of all (here: 1) extensions. We assume len(hostname) < FF - 9
		,00, 00                  # extension server_name
		,00, $hex_len_sn_hex5    # length SNI EXT
		,00, $hex_len_sn_hex3    # server_name list_length
		,00                      # server_name type (hostname)
		,00, $hex_len_sn_hex     # server_name length
		,$SN_HEX"                # server_name target

	fi

	code2network "$TLS_CLIENT_HELLO$EXTENSION_CONTAINING_SNI"
	#code2network "$TLS_CLIENT_HELLO"
	data=`echo $NW_STR`
	
	[[ "$DEBUG" -ge 3 ]] && echo "\"$data\"" 
	printf -- "$data" >&5 2>/dev/null &
	sleep $USLEEP_SND
	echo
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


#### main

[[ -z "$1" ]] && help  # hostname

parse_hn_port "$1"
echo

for tls_low_byte in "00" "01" "02" "03"; do

	if ! exec 5<> /dev/tcp/$NODE/$PORT; then
		echo "`basename $0`: unable to connect to $NODE:$PORT"
		exit 2
	fi

	[[ "$DEBUG" -ge 1 ]] && printf "sending client hello...\n"
	if [[ "$tls_low_byte" == "03" ]] ; then
		socksend_clienthello $tls_low_byte "$TLS12_CIPHER" $SNIHEX
	else
		socksend_clienthello $tls_low_byte "$TLS_CIPHER" $SNIHEX
	fi

	sockread_serverhello 32768 0
	[[ "$DEBUG" -ge 1 ]] && printf "reading server hello...\n"
	if [[ "$DEBUG" -eq 3 ]]; then
		#xxd -c$COL_WIDTH $SOCK_REPLY_FILE  | head -3
		#hexdump -v -e '"%04_ax:  " 32/1 "%02X " "\n"' $SOCK_REPLY_FILE | head -6
		hexdump -C $SOCK_REPLY_FILE | head -6
		echo
	fi

	display_tls_serverhello "$SOCK_REPLY_FILE"
	ret=$?

	# see https://secure.wand.net.nz/trac/libprotoident/wiki/SSL
	lines=`cat "$SOCK_REPLY_FILE" 2>/dev/null | hexdump -v -e '"%04_ax:  " 32/1 "%02X " "\n"' | wc -l` 

	case $tls_low_byte in
		00) tls_str="SSLv3" ;;
		01) tls_str="TLS 1" ;;
		02) tls_str="TLS 1.1" ;;
		03) tls_str="TLS 1.2" ;;
	esac

	printf "Protokoll "; tput bold; printf "$tls_low_byte = $tls_str"; tput sgr0; printf ":  "

	if [[ $ret -eq 1 ]] || [[ $lines -eq 1 ]] ; then
		tput setaf 3; echo "NOT available"
		ret=1
	else
		if [[ 03$tls_low_byte -eq $DETECTED_TLS_VERSION ]]; then
			tput setaf 2; echo "available"
			ret=0
		else
			tput setaf 3; echo -n "NOT available "
			[[ $DEBUG -ge 1 ]] && echo -n "send: 0x03$tls_low_byte, returned: 0x$DETECTED_TLS_VERSION" 
			echo
		fi
	fi
	tput sgr0

	[[ "$DEBUG" -ge 4 ]] && printf "  (returned $lines lines)" && echo
	echo

	# closing fd:
	exec 5<&-
	exec 5>&-

	rm $SOCK_REPLY_FILE

	echo "--------------------------------------------"

done


echo
exit 0

#  vim:tw=110:ts=5:sw=5
#  $Id: prototype.tls-protocol-checker.bash,v 1.13 2015/01/12 22:28:35 dirkw Exp $ 
