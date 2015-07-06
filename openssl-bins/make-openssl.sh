#!/bin/bash

echo
echo "have you patched yet?"
read a

STDOPTIONS="--prefix=/usr/ --openssldir=/etc/ssl -DOPENSSL_USE_BUILD_DATE enable-zlib enable-ssl2 enable-rc5 enable-rc2 \
enable-GOST enable-cms enable-md2 enable-mdc2 enable-ec enable-ec2m enable-ecdh enable-ecdsa \
enable-seed enable-camellia enable-idea enable-rfc3779 experimental-jpake"

clean() {
	case $NOCLEAN in 
		yes|Y|YES) ;;
		*) make clean ;;
	esac
	#[ $? -ne 0 ] && error "no openssl directory"
	return 0
}

error() {
	tput bold
	echo "ERROR $1"
	tput sgr0
	exit 2
}

makeall() {
	make depend && make && make report
	if [ $? -ne 0 ]; then
		error "making"
	fi
	return 0
}

copyfiles() {
	echo; apps/openssl version -a; echo
	cp -p apps/openssl ../openssl$1
	echo
	return $?
}

case $(uname -m) in
	"i686") clean 
		if [[ "$1" = krb ]]; then
			name2add=krb
			./config $STDOPTIONS no-ec_nistp_64_gcc_128 --with-krb5-flavor=MIT
		else
			name2add=static
			./config $STDOPTIONS no-ec_nistp_64_gcc_128 -static
		fi
		[ $? -ne 0 ] && error "configuring"
		makeall && copyfiles "32-$name2add"
		[ $? -ne 0 ] && error "copying files"
		apps/openssl ciphers -V 'ALL:COMPLEMENTOFALL' | wc -l
		echo
		echo "------------ all ok ------------"
		echo 
		;;
	"x86_64") clean
		if [[ "$1" = krb ]]; then
			name2add=krb
			./config $STDOPTIONS enable-ec_nistp_64_gcc_128 --with-krb5-flavor=MIT
		else
			name2add=static
			./config $STDOPTIONS enable-ec_nistp_64_gcc_128 -static
		fi
		[ $? -ne 0 ] && error "configuring"
		makeall && copyfiles "64-$name2add"
		[ $? -ne 0 ] && error "copying files"
		apps/openssl ciphers -V 'ALL:COMPLEMENTOFALL' | wc -l
		echo
		echo "------------ all ok ------------"
		echo 
		;;
	*)	echo "architecture ???" 
		exit 1
		;;
esac

#  vim:tw=90:ts=5:sw=5
#  $Id: make-openssl.sh,v 1.7 2015/07/06 18:21:41 dirkw Exp $ 

