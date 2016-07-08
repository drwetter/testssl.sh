#!/usr/bin/env bash
#
# PoC for checking the ellipticale curves negotiated
# x448 and x25519 are missing, others are not supported
# License see testssl.sh


HN="$1"
[ -z "$HN" ] && HN=testssl.sh
for curve in $(bin/openssl.Linux.x86_64 ecparam -list_curves | awk -F':' '/:/ { print $1 }'); do
	printf "$curve: "
	#if bin/openssl.Linux.x86_64 s_client -curves $curve -connect $HN:443 -servername $HN </dev/null 2>/dev/null | grep -q "BEGIN CERTIFICATE" ; then
	#	echo 'YES'
	#else
	#	echo '--'
	#fi
	if bin/openssl.Linux.x86_64 s_client -cipher ECDH -curves $curve -connect $HN:443 -servername $HN </dev/null 2>/dev/null | grep "Server Temp Key:" ; then
		:
	else
		echo '--'
	fi
done

# vim:ts=5:sw=5:expandtab
#  $Id: curves.bash,v 1.2 2016/07/08 09:39:27 dirkw Exp $ 

