#!/bin/sh
#
# This script compiles the "bad openssl" version, 1.0.2 supporting legacy
# cryptography for Linux, FreeBSD and Darwin.
#
# License GPLv2, see ../LICENSE


STDOPTIONS="--prefix=/usr/ -DOPENSSL_USE_BUILD_DATE enable-zlib \
enable-ssl2 enable-ssl3 enable-ssl-trace enable-rc5 enable-rc2 \
enable-gost enable-cms enable-md2 enable-mdc2 enable-ec enable-ec2m enable-ecdh enable-ecdsa \
enable-seed enable-camellia enable-idea enable-rfc3779 experimental-jpake"


error() {
     tput bold
     echo "### ERROR $1 ###"
     tput sgr0
     exit 2
}

clean() {
     case $NOCLEAN in
          yes|Y|YES) ;;
          *)
          if [ -e "Makefile" ]; then
              make clean
              [ $? -ne 0 ] && error "no openssl directory"
          fi
		;;
     esac
     return 0
}

makeall() {
     make depend || error "depend"
     make || error "making"
     make report || error "testing/make report"
     #FIXME: we need another error handler, as of now a failure doesn't mean a return status of != 0
     # see https://github.com/openssl/openssl/pull/336
     return 0
}

copyfiles() {
     local ret
     local target=../openssl.$(uname).$(uname -m).$1

     echo; apps/openssl version -a; echo
     if [ -e "$target" ]; then
		case $(uname) in
          	*BSD|*Darwin)
               	mv $target $target-$(stat -f "%Sm" -t "%Y-%m-%d %H:%M" "$target" | sed -e 's/ .*$//' -e 's/-//g')
				;;
			*) mv $target $target-$(stat -c %y $target | awk '{ print $1 }' | sed -e 's/ .*$//' -e 's/-//g') ;;
		esac
     fi
     cp -pf apps/openssl ../openssl.$(uname).$(uname -m).$1
     ret=$?
     echo
     ls -l apps/openssl ../openssl.$(uname).$(uname -m).$1
     return $ret
}

testv6_patch() {
     if grep -q 'ending bracket for IPv6' apps/s_socket.c; then
          STDOPTIONS="$STDOPTIONS -DOPENSSL_USE_IPV6"
          echo "detected IPv6 patch thus compiling in IPv6 support"
		echo
     else
          echo
          echo "no IPv6 patch (Fedora) detected!!  -- Press ^C and dl & apply from"
          echo "https://github.com/drwetter/testssl.sh/blob/master/bin/fedora-dirk-ipv6.diff"
          echo "or press any key to ignore"
          echo
          read a
     fi
}



echo
echo "###################################################################"
echo "#######   Build script for Peter Mosmans openssl fork       #######"
echo "####### which contains all broken and all advanced features #######"
echo "###################################################################"
echo

testv6_patch

if [ "$1" = krb ]; then
	name2add=krb
else
	if [ $(uname) != "Darwin" ]; then
		name2add=static
	else
		name2add=dynamic
	fi
fi

echo "doing a build for $(uname).$(uname -m)".$name2add
echo
sleep 3


case $(uname) in
     Linux|FreeBSD)
		openssldir_option='--openssldir=/etc/ssl'
		case $(uname -m) in
         		i686|armv7l) clean
				if [ "$1" = krb ]; then
					./config $openssldir_option $STDOPTIONS no-ec_nistp_64_gcc_128 --with-krb5-flavor=MIT
				else
					./config $openssldir_option $STDOPTIONS no-ec_nistp_64_gcc_128 -static
				fi
				[ $? -ne 0 ] && error "configuring"
				;;
			x86_64|amd64) clean
               	if [ "$1" = krb ]; then
					./config $openssldir_option $STDOPTIONS enable-ec_nistp_64_gcc_128 --with-krb5-flavor=MIT
				else
					./config $openssldir_option $STDOPTIONS enable-ec_nistp_64_gcc_128 -static
				fi
				[ $? -ne 0 ] && error "configuring"
				;;
			*) echo " Sorry, don't know this architecture $(uname -m)"
               	exit 1
               	;;
         esac
         ;;
     Darwin)
		openssldir_option='--openssldir=/private/etc/ssl/'
		case $(uname -m) in
			# No Kerberos (yet?) for Darwin. Static doesn't work for Darwin (#1204)
			x86_64) clean || echo "nothing to clean"
				./Configure $openssldir_option  $STDOPTIONS enable-ec_nistp_64_gcc_128 darwin64-x86_64-cc
				[ $? -ne 0 ] && error "configuring"
          		;;
			i386) clean || echo "nothing to clean"
				./config  $openssldir_option $STDOPTIONS no-ec_nistp_64_gcc_128 darwin64-x86_64-cc
				[ $? -ne 0 ] && error "configuring"
				;;
		esac
		;;
	*) echo " Sorry, don't know this OS $(uname)"
	;;
esac


makeall && copyfiles "$name2add"
[ $? -ne 0 ] && error "copying files"
echo
echo "(w/o 4 GOST ciphers): $(apps/openssl ciphers -V 'ALL:COMPLEMENTOFALL' | wc -l)"
echo
echo "------------ all ok ------------"
echo


#  vim:ts=5:sw=5
#  $Id: make-openssl.sh,v 1.20 2019/02/22 09:07:07 dirkw Exp $

