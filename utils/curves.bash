#!/usr/bin/env bash
#
# PoC for checking the ellipticale curves negotiated
# x448 and x25519 are missing, others are not supported
# License see testssl.sh

readonly RUN_DIR=$(dirname "$0")

test_openssl_suffix() {
     local naming_ext="$(uname).$(uname -m)"
     local uname_arch="$(uname -m)"
     local myarch_suffix=""

     [[ $uname_arch =~ 64 ]] && myarch_suffix=64 || myarch_suffix=32
     if [[ -f "$1/openssl" ]] && [[ -x "$1/openssl" ]]; then
          OPENSSL="$1/openssl"
          return 0
     elif [[ -f "$1/openssl.$naming_ext" ]] && [[ -x "$1/openssl.$naming_ext" ]]; then
          OPENSSL="$1/openssl.$naming_ext"
          return 0
     fi
     return 1
}


find_openssl_binary() {
     # 0. check environment variable whether it's executable
     if [[ -n "$OPENSSL" ]] && [[ ! -x "$OPENSSL" ]]; then
          pr_warningln "\ncannot find specified (\$OPENSSL=$OPENSSL) binary."
          outln " Looking some place else ..."
     elif [[ -x "$OPENSSL" ]]; then
          :    # 1. all ok supplied $OPENSSL was found and has executable bit set -- testrun comes below
     elif test_openssl_suffix $RUN_DIR; then
          :    # 2. otherwise try openssl in path of testssl.sh
     elif test_openssl_suffix ../$RUN_DIR; then
          :    # 2. otherwise try openssl in path of testssl.sh
     elif test_openssl_suffix ../$RUN_DIR/bin; then
          :    # 3. otherwise here, this is supposed to be the standard --platform independent path in the future!!!
     elif test_openssl_suffix "$(dirname "$(which openssl)")"; then
          :    # 5. we tried hard and failed, so now we use the system binaries
     fi

     # no ERRFILE initialized yet, thus we use /dev/null for stderr directly
     $OPENSSL version -a 2>/dev/null >/dev/null
     if [[ $? -ne 0 ]] || [[ ! -x "$OPENSSL" ]]; then
          echo "\ncannot exec or find any openssl binary" 
          exit 1
     fi
     echo
     echo "using $OPENSSL"
     echo
}


VERBOSE=false
if [[ $1 == "-v" ]]; then
     VERBOSE=true
     shift
fi

HN="$1"
[ -z "$HN" ] && HN=testssl.sh
find_openssl_binary 

ERRFILE=$(mktemp /tmp/curve_tester.R.XXXXXX) || exit -6
TMPFILE=$(mktemp /tmp/curve_tester.T.XXXXXX) || exit -6


for curve in $($OPENSSL ecparam -list_curves | awk -F':' '/:/ { print $1 }'); do
	#if bin/openssl.Linux.x86_64 s_client -curves $curve -connect $HN:443 -servername $HN </dev/null 2>/dev/null | grep -q "BEGIN CERTIFICATE" ; then
	#	echo 'YES'
	#else
	#	echo '--'
	#fi
	$OPENSSL s_client -cipher ECDH -curves $curve -connect $HN:443 -servername $HN </dev/null 2>$ERRFILE | grep "Server Temp Key:" >$TMPFILE
     if [[ $? -eq 0 ]]; then
	     printf "$curve: "
          cat $TMPFILE | sed 's/^.*Server Temp Key: //'
	else
          if grep -q 'Error with' $ERRFILE; then
               if  "$VERBOSE"; then
                    echo "$curve: no client support"
               fi
          else
		     echo "$curve: --"
          fi
	fi
done

rm -f $ERRFILE $TMPFILE

# vim:ts=5:sw=5:expandtab
#  $Id: curves.bash,v 1.3 2016/07/09 12:22:13 dirkw Exp $ 

