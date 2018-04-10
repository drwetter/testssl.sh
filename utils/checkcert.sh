#!/bin/bash 


# on the command line:
# STARTTLS="-starttls $protocol"; export STARTTLS
#  protocol=smtp,impa,pop,xmpp,jabber

##### THIS WILL BE INTEGRATED INTO testssl.sh 
##### it has no production qualiity yet and I'll likely disregard
##### any issues/patches until this will be done
#
# license is GPLv2, see file LICENSE


DAYS2WARN=60

ECHO="/bin/echo -e"
COLOR=0

CA_BUNDLE="/etc/ssl/ca-bundle.pem"
CA_BUNDLE_CMD="-CApath /etc/ssl/certs/"
#CA_BUNDLE_CMD="-CAfile $CA_BUNDLE"
#`openssl version -d` /certs/

off() {
	if [ $COLOR = 0 ]; then $ECHO "\033[m\c"; fi
}

bold() {
	$ECHO "\033[1m$1"; off
}

underscore() {
	$ECHO "\033[4m$1\c"; off
}


blue() {
	if [ $COLOR = 0 ]; then $ECHO "\033[1;34m$1 "; else $ECHO "**$1** "; fi
	off
}

brown() {
	[ $COLOR = 0 ] && $ECHO "\033[0;33m$1 " || out "**$1** "
	off
}


green() {
	if [ $COLOR = 0 ]; then $ECHO "\033[1;32m$1 "; else $ECHO "**$1** "; fi
	off
}
lgreen() {
	if [ $COLOR = 0 ]; then $ECHO "\033[0;32m$1 "; else $ECHO "**$1** "; fi
	off
}

red() {
	if [ $COLOR = 0 ]; then $ECHO "\033[1;31m$1 "; else $ECHO "**$1** "; fi
	off
}
lred() {
	if [ $COLOR = 0 ]; then $ECHO "\033[0;31m$1 "; else $ECHO "**$1** "; fi
	off
}


datebanner() {
	tojour=`date +%F`" "`date +%R`
	echo
	bold "$1 now ($tojour) ---> $NODEIP:$PORT ($NODE) <---"
}


dns() {
	ip4=`host -t a $1 | grep -v alias | sed 's/^.*address //'`
	which getent 2>&1 >/dev/null && getent ahostsv4 $1 2>&1 >/dev/null && ip4=`getent ahostsv4 $1 | awk '{ print $1}' | uniq`
	NODEIP=`echo "$ip4" | head -1`
	rDNS=`host -t PTR $NODEIP | sed -e 's/^.*pointer //' -e 's/\.$//'`
	echo $rDNS | grep -q NXDOMAIN  && rDNS=""
}


display_dns() {
	$ECHO
	[ -n "$rDNS" ] && $ECHO "rDNS: $rDNS"
	if [ `echo "$ip4" | wc -l` -gt 1 ]; then
		$ECHO "$1 other IPv4 addresses:\c"
		for i in $ip4; do
			[ "$i" == "$NODEIP" ] && continue
			$ECHO " $i\c"
		done
	fi
	echo
}


############## main

NODE="$1"
[ -z "$NODE" ] && echo "arg1 (=node) missing" && exit 1
PORT=${2:-443}

# strip "https" and trailing urlpath supposed it was supplied additionally
echo $NODE | grep -q 'https://' && NODE=`echo $NODE | sed -e 's/https\:\/\///' -e 's/\/.*$//'`

# determine port, supposed it was supplied additionally
echo $NODE | grep -q ':' && PORT=`echo $NODE | sed 's/^.*\://'` && NODE=`echo $NODE | sed 's/\:.*$//'`

dns $NODE
datebanner "Testing" $NODE
display_dns $NODE

TMPDIR=`mktemp -d /tmp/checkcert.$NODE.$PORT.XXXXXX` || exit 6
HOSTCERT_SNI="$TMPDIR/hostcert_sni.txt" 
HOSTCERT="$TMPDIR/hostcert.txt" 

FD2_HOST_SNI="$TMPDIR/fd2_host_sni.txt" 
FD2_HOST="$TMPDIR/fd2_host.txt" 

# test whether I can ssl to it:
#echo | openssl s_client -connect $NODE:$PORT 2>&1 >/dev/null || exit 7

SNI="-servername $NODE"
# dl pub key
openssl s_client $STARTTLS -connect $NODEIP:$PORT $SNI 2>$FD2_HOST_SNI </dev/null | awk '/-----BEGIN/,/-----END/ { print $0 }'  >$HOSTCERT_SNI
openssl s_client $STARTTLS -connect $NODEIP:$PORT      2>$FD2_HOST     </dev/null | awk '/-----BEGIN/,/-----END/ { print $0 }'  >$HOSTCERT

#bold "\nTrust\n"
#openssl verify -verbose $HOSTCERT
#http://www.madboa.com/geek/openssl/#verify-standardA
#http://www.madboa.com/geek/openssl/#verify-system
#echo $?

bold "\nPubkey"
openssl x509 -noout -in $HOSTCERT_SNI -pubkey

bold "\nFingerprint/Serial"
openssl x509 -noout -in $HOSTCERT_SNI -fingerprint
openssl x509 -noout -in $HOSTCERT_SNI -serial

bold "\nSignature Algorithm"
algo=`openssl x509 -noout -in $HOSTCERT_SNI -text | grep "Signature Algorithm" | sed 's/^.*Signature Algorithm: //' | sort -u `
case $algo in
	sha1WithRSAEncryption) brown "SHA1withRSA" ;;
	sha256WithRSAEncryption) lgreen "SHA256withRSA" ;;
	sha512WithRSAEncryption) lgreen "SHA512withRSA" ;;
	md5*) red "MD5" ;;
	*) echo $algo ;;
#https://blog.hboeck.de/archives/754-Playing-with-the-EFF-SSL-Observatory.html
esac

# Secs of a day:
SECS2WARN=`echo "24 * 60 * 60 * $DAYS2WARN" | bc`

bold "\nExpiration"
openssl x509 -noout -in $HOSTCERT_SNI -startdate -enddate

expire=`openssl x509 -in $HOSTCERT_SNI -checkend 0`
if ! echo $expire | grep -qw not; then
	red "Certificate has expired!!"
else
	expire=`openssl x509 -in $HOSTCERT_SNI -checkend $SECS2WARN`
	echo "$expire" | grep -qw not && green "Certificate is ok for the next $DAYS2WARN days" || \
		lred "Certificate will expire within the next $DAYS2WARN days!"
fi


#######
bold "\nSubject / CN issues"

SAN=""
SAN=`openssl x509 -noout -in $HOSTCERT -text | grep -A3 "Subject Alternative Name" | grep "DNS:" | sed -e 's/DNS://g' -e 's/ //g' -e 's/,/\n/g'`
SAN_SNI=`openssl x509 -noout -in $HOSTCERT_SNI -text | grep -A3 "Subject Alternative Name" | grep "DNS:" | sed -e 's/DNS://g' -e 's/ //g' -e 's/,/\n/g'`

subject_sni=`openssl x509 -noout -in $HOSTCERT_SNI -subject | sed 's/subject= //'`
subject_str=`openssl x509 -noout -in $HOSTCERT -subject | sed 's/subject= //'`
CN_SNI=`echo $subject_sni | sed -e 's/^.*CN=//' -e 's/\/emailAdd.*//'`
CN=`echo $subject_str | sed -e 's/^.*CN=//' -e 's/\/emailAdd.*//'`
$ECHO -n "Common Name: "; underscore "$CN_SNI"

test "$DEBUG" && $ECHO " ($subject_sni" # complete certificate subject
test "$DEBUG" && $ECHO " ($subject_str)" # complete certificate subject
#openssl x509 -noout -in $HOSTCERT_SNI  -serial -startdate -enddate -dates -subject -issuer -email -ocsp_uri -ocspid -purpose >$TMPDIR/textout_sni.txt
openssl x509 -noout -in $HOSTCERT_SNI -text >$TMPDIR/textout_level0.cert_sni.txt

MATCHOK=0
REASON_MATCH=""

if [ "$CN_SNI" != "$CN" ]; then
	$ECHO "\nSNI mandatory, otherwise \c"; underscore "$CN\c"; $ECHO " matches\c"
	#FIXME: e.g. google.de hast google.com as $CN, and google.com includes SAN *.google.de
else
	$ECHO " no SNI needed \c"
# haken? siehe lists.appsec.eu vs pm.appsec.eu --> beide haben wildcard
fi

if [ "$NODE" == "$CN" ]; then
#	$ECHO " matches hostname directly, "
	REASON_MATCH="direct match,"
	MATCHOK=1
elif [ "$CN_SNI" == "$NODE" ]; then ###?????
#	$ECHO " matches hostname via SNI, "
	REASON_MATCH="SNI,"
	MATCHOK=1
fi

if [ x"$SAN_SNI" != x"$CN_SNI" ]; then
	$ECHO "\nSAN exist:\c"
	for subjectAltName in `$ECHO $SAN_SNI`; do
		if [ "$NODE" == "$subjectAltName" ] ; then
			underscore "$subjectAltName, \c"
			REASON_MATCH="$REASON_MATCH SAN,"
			MATCHOK=1
		else
			$ECHO " $subjectAltName, \c"
		fi
	done
fi

if echo "$CN_SNI" | grep -q '^\*'; then
	# *.domain.tld = *.domain.tld
	[ "*.$NODE" == "$CN_SNI" ] && REASON_MATCH="$REASON_MATCH Wildcard (all subdomains)" && MATCHOK=1
# expr: können mehrere Gründe sein!

	# prefix.domain.tld = *.domain.tld
	domaintld=`echo $NODE | sed 's/^[0-9a-zA-Z]*\.//1'`
	[ "*.$domaintld" == "$CN_SNI" ] && REASON_MATCH="$REASON_MATCH Wildcard (from TLD)" && MATCHOK=1
fi

if [ $MATCHOK -eq 1 ] ; then
	green "\nMatch OK\c" 
	$ECHO ": $REASON_MATCH"
else
	red "\nMatch failed"
fi


bold "\n\nCertificate chain\c"
#openssl x509 -text -in $HOSTCERT | awk '/Certificate chain/,/--/ { print   $0 }' | sed -e 's/---//' -e 's/Certificate chain//'
openssl s_client $STARTTLS -connect $NODEIP:$PORT $SNI 2>/dev/null </dev/null | awk '/Certificate chain/,/--/ { print $0 }' | sed -e 's/---//' -e 's/Certificate chain//' | tee $TMPDIR/all-chain.txt

# so alle einsacken:
#openssl s_client -showcerts -connect $NODEIP:$PORT $SNI 2>/dev/null </dev/null | awk '/-----BEGIN/,/-----END/ { print   $0 }'
savedir=`pwd`; cd $TMPDIR
openssl s_client -showcerts $STARTTLS -connect $NODEIP:$PORT $SNI 2>/dev/null </dev/null | \
	awk -v c=-1 '/-----BEGIN CERTIFICATE-----/{inc=1;c++} inc {print > ("level" c ".crt")} /---END CERTIFICATE-----/{inc=0}'
nrsaved=`ls level?.crt | wc -w`
$ECHO "retrieved $nrsaved pub certs"
# die CA Kette hochgehen 
for i in level?.crt; do openssl x509 -noout -serial -subject -issuer -in "$i"; echo; done > all.serial-subject-issuer.txt
NR_RETRIEVED=`ls -1 level* | wc -l`
cd $savedir

bold "\nChecking issuer chain against local certs"
issuerok=`echo | openssl s_client $CA_BUNDLE_CMD -connect $NODEIP:$PORT 2>/dev/null | grep "Verify return code" | sed 's/^.*Verify return code: //'`
if echo $issuerok | grep -qw ok ; then
	green "$issuerok"
else 
	red "$issuerok"
fi

bold "\nE-mail"
email=`openssl x509 -noout -in $HOSTCERT_SNI -email`
[ x"$email" == "x" ] &&  underscore "<none>" || echo "$email"
echo



bold "\nOCSP"
echo -en "URL:    "
ocsp_uri=`openssl x509 -noout -in $HOSTCERT_SNI -ocsp_uri`
[ x"$ocsp_uri" == "x" ] && lred "<none>" || echo "$ocsp_uri"


# ARG1: level2check
# ARG2: issuer of level2check cert
check_revocation() {
	#FIXME: check ocsp/ocsp stapling with CA
	# * CRLs/OCSP abfragen (http://backreference.org/2010/05/09/ocsp-verification-with-openssl/)

#FIXME:
	#ocsp_uri=`openssl x509 -noout -in level$1.crt -ocsp_uri`

	[ -z "$ocsp_uri" ] && lred ".. doesn't have a OCSP URL" && return 1
	addissuer=""
	if [ -s $TMPDIR/level$2.crt ]; then
		addissuer="-issuer $TMPDIR/level$2.crt"
		NO_ISSUER_PROVIDED=0
	else
		addissuer="-issuer $CA_BUNDLE"
		NO_ISSUER_PROVIDED=1
	fi

	ocsp_hostheader=`echo $ocsp_uri | sed -e 's/http\:\/\///' -e 's/\/.*$//'`		 #sometimes needed 
	openssl ocsp $CA_BUNDLE_CMD $addissuer -cert $TMPDIR/level$1.crt -text -url $ocsp_uri -header HOST $ocsp_hostheader  &>$TMPDIR/ocsp-longresponse$1.txt
	openssl ocsp $CA_BUNDLE_CMD $addissuer -cert $TMPDIR/level$1.crt -url $ocsp_uri -header HOST $ocsp_hostheader &>$TMPDIR/ocsp-response$1.txt

#tmpdir_escaped=`echo $TMPDIR | sed 's/\//\\\//g'`
#cat $TMPDIR/ocsp-response.txt | egrep -v "^WARNING: no nonce|^Response Verify Failure|OCSP_basic_verify" | sed 's/'"${tmpdir_escaped}"'//'
	cat $TMPDIR/ocsp-response$1.txt | egrep -v "^WARNING: no nonce|^Response Verify Failure|OCSP_basic_verify" | sed 's/^.*level/level/'
	if grep -q "level$1.crt.*good" $TMPDIR/ocsp-response$1.txt ; then
		green "not revoked (OK)\c" 
	else
		lred "pls check manually (hint: $TMPDIR/ocsp-longresponse$1.txt). \c"
		[ $NO_ISSUER_PROVIDED -eq 0 ] && lred " Also the chain might be incomplete\c"
	fi
}

bold "\nChecking whether server certs have been revoked"
#set -x
#for level in `seq 1 $NR_RETRIEVED`; do
for level in 1; do
	minus1=`expr $level - 1`
	$ECHO "##### level$minus1 #####"
	check_revocation $minus1 $level
	$ECHO
done
#set +x


bold "\nPurpose"
openssl x509 -noout -in $HOSTCERT_SNI -purpose | grep -v 'Certificate purpose' | grep -i yes

datebanner "Done" $NODE
echo

printf "logdir is $TMPDIR . Save it? "
read a
case $a in
	y|Y|yes|YES) cp -a $TMPDIR $PWD && echo "saved $TMPDIR to $PWD" ;;
	*) $ECHO "left $TMPDIR"
esac


#rm -rf $TMPDIR

exit 0

# vim:ts=5:sw=5
# $Id: checkcert.sh,v 1.20 2014/09/16 22:38:03 dirkw Exp $ 


