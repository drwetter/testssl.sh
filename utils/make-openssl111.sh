#!/bin/bash
#
#  vim:tw=90:ts=5:sw=5
#
# Script compiling OpenSSL 1.1.1 from github. Not yet particular sophisticated.
# Just meant to provide a help to get the compile job done

echo
echo "#####################################################"
echo "#######    Build script for openssl 1.1.1     #######"
echo "#######  (contains some weak cryptography)    #######"
echo "#####################################################"
echo

OPT11="enable-tls1_3 enable-ec_nistp_64_gcc_128 sctp enable-aria enable-asan enable-rc5 \
enable-ssl3 enable-ssl3-method enable-dynamic-engine enable-ssl-trace \
-DOPENSSL_TLS_SECURITY_LEVEL=0 "

STDOPTIONS="--prefix=/usr/ --openssldir=/etc/ssl -DOPENSSL_USE_BUILD_DATE enable-zlib \
enable-heartbeats enable-rc5 enable-md2 enable-ssl3 enable-weak-ssl-ciphers zlib no-shared \
enable-rc2 enable-gost enable-cms enable-mdc2 enable-ec enable-ec2m enable-ecdh enable-ecdsa \
enable-seed enable-camellia enable-idea enable-rfc3779"

grep OPENSSL_VERSION_TEXT include/openssl/opensslv.h | grep -q 1.1.1 && STDOPTIONS="$STDOPTIONS $OPT11"

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
	make depend && make -j2 # && make report
	if [ $? -ne 0 ]; then
#FIXME: we need another error handler, as a failure doesn't mean here anymore a return status of 1
		error "making"
		return 1
	fi
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
			./config $STDOPTIONS --with-krb5-flavor=MIT
		else
			name2add=static
			#export CFLAGS='-fPIC'
			./config $STDOPTIONS -static
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
			./config $STDOPTIONS --with-krb5-flavor=MIT
		else
			name2add=static
			./config $STDOPTIONS -static
		fi
		[ $? -ne 0 ] && error "configuring"
		makeall && copyfiles "$name2add"
		[ $? -ne 0 ] && error "copying files"
		# see ciphers(1), SSL_CTX_set_security_level(3)
		apps/openssl ciphers -V 'ALL:COMPLEMENTOFALL:@SECLEVEL=0' | wc -l
		echo
		echo "------------ all ok ------------"
		echo
		;;
	*)	echo " Sorry, don't know this architecture $(uname -m)"
		exit 1
		;;
esac
