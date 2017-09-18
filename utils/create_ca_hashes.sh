#!/usr/bin/env bash
#
# vim:ts=5:sw=5:expandtab
# we have a spaces softtab, that ensures readability with other editors too

# This file generates the file etc/ca_hashes.txt from the (root)certificate
# Bundles in etc (etc/*.pem)

TEMPDIR="/tmp"

# Check if we are in the right directory
if [[ ! -e etc ]]; then
	echo "Please run this script from the base directory of the testssl.sh project"
	exit 99
fi

echo "Extracting private key hashes from CA bundles"
echo -n > "$TEMPDIR/cahashes"
for bundle_fname in etc/*.pem; do
	if [[ ! -r $bundle_fname ]]; then
		echo "\"$bundle_fname\" cannot be found / not readable"
        exit 99
   	fi
   	bundle_name=$(echo -n $bundle_fname|sed s/^etc\\///|sed 's/\.pem$//')
	echo "CA Bundle: $bundle_name"
   	# Split up the certificate bundle
   	awk -v n=-1 "BEGIN {start=1}
    	/-----BEGIN CERTIFICATE-----/{ if (start) {inc=1; n++} }
        inc { print >> (\"$TEMPDIR/$bundle_name.\" n \".$$.crt\") ; close (\"$TEMPDIR/$bundle_name.\" n \".$$.crt\") }
        /---END CERTIFICATE-----/{ inc=0 }" $bundle_fname
   	for cert_fname in $TEMPDIR/$bundle_name.*.$$.crt; do
   		echo -n "."
        hpkp_key_ca="$( ( openssl x509 -in "$cert_fname" -pubkey -noout | grep -v PUBLIC | openssl base64 -d |
            openssl dgst -sha256 -binary | openssl enc -base64 ) 2>/dev/null )"
		hpkp_name=$( openssl x509 -in "$cert_fname" -subject -noout 2>/dev/null | sed "s/^subject= //")
		if [[ $(echo $hpkp_name|grep 'CN='|wc -l) -eq 1 ]]; then
			hpkp_name=$(echo -n $hpkp_name|sed 's/^.*CN=//'|sed 's/\/.*$//')
		fi
		echo "$hpkp_key_ca $hpkp_name" >> "$TEMPDIR/cahashes"
   	done
   	echo
done

# Make a backup first
cp etc/ca_hashes.txt etc/ca_hashes.txt.bak

sort -u "$TEMPDIR/cahashes" > etc/ca_hashes.txt
