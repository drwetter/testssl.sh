#/bin/sh -e

# utility which converts grepable nmap outout to testssl's file input

usage() {
     cat << EOF

usage:

    "$0 filename<.gmap>":               looks for filename/filename.gmap and converts into basename \$(filename)-testssl.txt"
    "$0 filename<.gmap>" "scan option": same as before, only adds testssl.sh scan option in front of IPs"

EOF
     exit 0
}

[ -z "$1" ] && usage
FNAME="$1"
OPT2ADD="${2:-}"

if ! grep -q gmap <<< "$FNAME"; then
     FNAME="$FNAME.gmap"
fi
[ ! -e $FNAME ] && echo "$FNAME not readable" && exit 2


TARGET_FNAME=${FNAME%.*}-testssl.txt

# test whether there's more than one "open" per line
while read -r oneline; do
     if [ $(echo "${oneline}" | tr ',' '\n' | grep -wc 'open') -gt 1 ]; then
          # not supported currently
          echo "$FNAME contains at least on one line more than 1x\"open\""
          exit 3
     fi
done < "$FNAME"

awk '/\<open\>/ { print "'"${OPT2ADD}"' " $2":"$5 }' "$FNAME" | sed 's/\/open.*$//g' >"$TARGET_FNAME"
exit $?

#  vim:ts=5:sw=5

