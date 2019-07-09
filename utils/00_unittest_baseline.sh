#!/usr/bin/env bash
#
# PoC for unit tests in bash. Basic test with s_server, works under Linux only atm

OPENSSL="bin/openssl.$(uname).$(uname -m)"
$OPENSSL version -a || exit 1

FILE=tmp.json

remove_quotes() {
     sed -i 's/"//g' $FILE
}

# arg1:   id_value
# arg2:   string to check against severity_value (optional)
# arg2,3: string to check against finding_value
# return: 0 whether it contains arg2 or arg3 (0: yes, 1: matches not)
check_result() {
     # id           : sslv3,
     # ip           : localhost/127.0.0.1,
     # port         : 4433,
     # severity     : HIGH,
     # finding      : SSLv3 is offered

     local json_result=""
     local severity_value=""
     local finding_value=""

     remove_quotes
     json_result="$(awk '/id.*'"${1}"'/,/finding.*$/' $FILE)"
     [[ -z $json_result ]] && exit -1
     # is4lines?
     finding_value="$(awk -F':' '/finding/ { print $2" "$3" "$4 }' <<< "$json_result")"
     if [[ $# -eq 2 ]]; then
          [[ $finding_value =~ "$2" ]] && return 0 || return 1
     fi
     severity_value="$(awk -F':' '/severity/ { print $2 }' <<< "$json_result")"
     if [[ $finding_value =~ "$3" ]] && [[ $severity_value =~ "$2" ]] ; then
          return 0
     else
          return 1
     fi
}

### generate self signed certificate
$OPENSSL req -new -x509 -out /tmp/server.crt -nodes -keyout /tmp/server.pem -subj '/CN=localhost' &>/dev/null || exit 2
echo


### 1) test protocol SSlv2:
$OPENSSL s_server -www -ssl2 -key /tmp/server.pem -cert /tmp/server.crt &>/dev/null &
pid=$!
rm $FILE 2>/dev/null
echo "Running testssl.sh SSLv2 protocol check against localhost for SSLv2: "
./testssl.sh -p -q --warnings=off --jsonfile=$FILE localhost:4433
check_result SSLv2 CRITICAL "vulnerable with 9 ciphers"
[[ $? -eq 0 ]] && echo "SSLv2: PASSED" || echo "FAILED"
echo
kill -9 $pid
wait $pid 2>/dev/null

### 2) test NPN + ALPN
$OPENSSL s_server -cipher 'ALL:COMPLEMENTOFALL' -alpn "h2" -nextprotoneg "spdy/3, http/1.1" -www -key /tmp/server.pem -cert /tmp/server.crt &>/dev/null &
pid=$!
rm $FILE
echo "Running testssl.sh HTTP/2 protocol checks against localhost: "
./testssl.sh -q --jsonfile=$FILE --protocols localhost:4433
if check_result NPN "spdy/3,  http/1.1"; then
     echo "SPDY/NPN:  PASSED"
else
     echo "SPDY/NPN:  FAILED"
fi

if check_result ALPN "h2"; then
     echo "HTTP2/ALPN: PASSED"
else
     echo "HTTP2/ALPN: FAILED"
fi
kill -9 $pid
wait $pid 2>/dev/null
rm $FILE

### 3) test almost all other stuff
$OPENSSL s_server -cipher 'ALL:COMPLEMENTOFALL' -www -key /tmp/server.pem -cert /tmp/server.crt &>/dev/null &
pid=$!
rm $FILE
echo "Running baseline check with testssl.sh against localhost"
./testssl.sh -q --jsonfile=$FILE localhost:4433
#check_result sslv2 CRITICAL "is offered"
kill -9 $pid
wait $pid 2>/dev/null

rm $FILE


### test server defaults
# ./testssl.sh -q --jsonfile=$FILE --server-defaults localhost:4433
# -serverpref
# -no_ticket
# -no_resumption_on_reneg
# -status

# vim:ts=5:sw=5:expandtab

