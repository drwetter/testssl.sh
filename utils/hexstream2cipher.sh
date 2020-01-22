#!/bin/bash

hs="$1"
len=${#hs}
echo "# ciphers: $((len/4))"

mapfile="etc/cipher-mapping.txt"
[ -s $mapfile ] || mapfile="../$mapfile"
[ -s $mapfile ] || exit 255

cip=""
first=true

for ((i=0; i<len ; i+=4)); do
	printf "%02d" "$i"
	echo -n ": ${hs:$i:4}"
	grepstr="0x${hs:$i:2},0x${hs:$((i+2)):2}"
        echo -n " --> $grepstr --> "
        cip=$(grep -i -E "^ *${grepstr}" $mapfile | awk '{ print $3 }')
	if [[ $grepstr == 0x00,0xff ]]; then
		echo TLS_EMPTY_RENEGOTIATION_INFO_SCSV
	else
		echo $cip
	fi
	if "$first"; then
		ciphers="$cip"
		first=false
	else
		ciphers="$ciphers:$cip"
	fi
done

echo
# remove leading : because of GREASE, and trailing because of TLS_EMPTY_RENEGOTIATION_INFO_SCSV
ciphers="${ciphers%:}"
echo ${ciphers#:}
