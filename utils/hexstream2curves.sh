#!/usr/bin/env bash

hs="$1"
len=${#hs}
echo "# curves: $((len/4))"

mapfile="etc/curves-mapping.txt"
[ -s $mapfile ] || mapfile="../$mapfile"
[ -s $mapfile ] || exit 255

cur=""
first=true

for ((i=0; i<len ; i+=4)); do
	printf "%02d" "$i"
	echo -n ": ${hs:$i:4}"
	grepstr="0x${hs:$i:2},0x${hs:$((i+2)):2}"
        echo -n " --> $grepstr --> "
        cur=$(grep -i -E "^ *${grepstr}" $mapfile | awk '{ print $3 }')
	if [[ $grepstr == 0x00,0xff ]]; then
		echo TPM_ECC_NONE
	else
		echo $cur
	fi
	if "$first"; then
		curves="$cur"
		first=false
	else
		curves="$curves:$cur"
	fi
done

echo
# remove leading : because of GREASE, and trailing because of TPM_ECC_NONE
curves="${curves%:}"
echo ${curves#:}

#  vim:ts=5:sw=5:expandtab
