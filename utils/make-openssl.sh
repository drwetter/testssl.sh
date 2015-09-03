#!/bin/bash

# License GPLv2, see ../LICENSE

echo 
echo "###################################################################"
echo "#######      Build script for Peter Mosmans openssl         #######"
echo "####### which contains all broken and all advanced features #######"
echo "###################################################################"
echo 
sleep 3

STDOPTIONS="--prefix=/usr/ --openssldir=/etc/ssl -DOPENSSL_USE_BUILD_DATE enable-zlib \
enable-ssl2 enable-ssl3 enable-ssl-trace enable-rc5 enable-rc2 \
enable-gost enable-cms enable-md2 enable-mdc2 enable-ec enable-ec2m enable-ecdh enable-ecdsa \
enable-seed enable-camellia enable-idea enable-rfc3779 experimental-jpake -DTEMP_GOST_TLS"

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
	echo "### ERROR $1 ###"
	tput sgr0
	exit 2
}

makeall() {
	make depend || error "depend"
	make || error "making"
	make report || error "testing/make report"
	#FIXME: we need another error handler, as of now a failure doesn't mean a return status of 1
	# see https://github.com/openssl/openssl/pull/336
	return 0
}

copyfiles() {
	echo; apps/openssl version -a; echo
	cp -p apps/openssl ../openssl.$(uname).$(uname -m).$1
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
		makeall && copyfiles "$name2add"
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
		makeall && copyfiles "$name2add"
		[ $? -ne 0 ] && error "copying files"
		apps/openssl ciphers -V 'ALL:COMPLEMENTOFALL' | wc -l
		echo
		echo "------------ all ok ------------"
		echo 
		;;
	*)	echo " Sorry, don't know this architecture $(uname -m)" 
		exit 1
		;;
esac

#  vim:tw=90:ts=5:sw=5
#  $Id: make-openssl.sh,v 1.14 2015/07/20 19:40:54 dirkw Exp $ 

