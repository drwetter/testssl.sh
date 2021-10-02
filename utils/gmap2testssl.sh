#!/usr/bin/env bash

# Utility which converts grepable nmap output to testssl's file input
# It is just borrowed from testssl.sh
# License see testssl.sh


echo A | sed -E 's/A//' >/dev/null 2>&1 && \
declare -r HAS_SED_E=true || \
declare -r HAS_SED_E=false

usage() {
     cat << EOF

usage:

    "$0  <filename>":               looks for <filename> (nmap gmap format) and converts into basename \$(filename)-testssl.txt"

EOF
     exit 0
}

fatal () {
     echo "$1" >&2
     exit $2
}

is_ipv4addr() {
     local octet="(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])"
     local ipv4address="$octet\\.$octet\\.$octet\\.$octet"

     [[ -z "$1" ]] && return 1

     # Check that $1 contains an IPv4 address and nothing else
     [[ "$1" =~ $ipv4address ]] && [[ "$1" == $BASH_REMATCH ]] && \
     return 0 || \
     return 1
}

filter_ip4_address() {
     local a

     for a in "$@"; do
          if ! is_ipv4addr "$a"; then
               continue
          fi
          if "$HAS_SED_E"; then
               sed -E 's/[^[:digit:].]//g' <<< "$a" | sed -e '/^$/d'
          else
               sed -r 's/[^[:digit:].]//g' <<< "$a" | sed -e '/^$/d'
          fi
     done
}

# arg1: a host name. Returned will be 0-n IPv4 addresses
# watch out: $1 can also be a cname! --> all checked
get_a_record() {
     local ip4=""
     local noidnout=""

     ip4=$(filter_ip4_address $(dig -r +short +timeout=2 +tries=2 -t a "$1" 2>/dev/null | awk '/^[0-9]/ { print $1 }'))
     if [[ -z "$ip4" ]]; then
          ip4=$(filter_ip4_address $(host -t a "$1" 2>/dev/null | awk '/address/ { print $NF }'))
     fi
     if [[ -z "$ip4" ]]; then
          ip4=$(filter_ip4_address $(drill a "$1" | awk '/ANSWER SECTION/,/AUTHORITY SECTION/ { print $NF }' | awk '/^[0-9]/'))
     fi
     echo "$ip4"
}

ports2starttls() {
     local tcp_port=$1
     local ret=0

     # https://en.wikipedia.org/wiki/List_of_TCP_and_UDP_port_numbers
     case $tcp_port in
          21)       echo "-t ftp " ;;
          23)       echo "-t telnet " ;;
          119|433)  echo "-t nntp " ;;   # to come
          25|587)   echo "-t smtp " ;;
          110)      echo "-t pop3 " ;;
          143)      echo "-t imap " ;;
          389)      echo "-t ldap ";;
          3306)     echo "-t mysql " ;;
          5222)     echo "-t xmpp " ;;   # domain of jabber server maybe needed
          5432)     echo "-t postgres " ;;
          563)                ;;  # NNTPS
          636)                ;;  # LDAP
          1443|8443|443|981)  ;;  # HTTPS
          465)                ;;  # HTTPS | SMTP
          631)                ;;  # CUPS
          853)                ;;  # DNS over TLS
          995|993)            ;;  # POP3|IMAP
          3389)               ;;  # RDP
          *) ret=1            ;;  # we don't know this ports so we rather do not scan it
     esac
     return $ret
}

nmap_to_plain_file () {

     local fname="$1"
     local target_fname=""
     local oneline=""
     local ip hostdontcare round_brackets ports_specs starttls
     local tmp port host_spec protocol ssl_hint dontcare dontcare1

     # Ok, since we are here we are sure to have an nmap file. To avoid questions we make sure it's the right format too
     if [[ "$(head -1 "$fname")" =~ ( -oG )(.*) ]] || [[ "$(head -1 "$fname")" =~ ( -oA )(.*) ]] ; then
          # yes, greppable
          if [[ $(grep -c Status "$fname") -ge 1 ]]; then
               [[ $(grep -c  '\/open\/' "$fname")  -eq 0 ]] && \
               fatal "Nmap file $fname should contain at least one open port" 250
          else
               fatal "strange, nmap grepable misses \"Status\"" 251
          fi
     else
          fatal "Nmap file $fname is not in grep(p)able format (-oG filename.g(n)map)" 250
     fi
     target_fname="${fname%.*}"-testssl.txt
     [[ -e $target_fname ]] && fatal "$target_fname already exists" 3
     > "${target_fname}" || fatal "Cannot create \"${target_fname}\"" 252

     # Line x:   "Host: AAA.BBB.CCC.DDD (<FQDN>) Status: Up"
     # Line x+1: "Host: AAA.BBB.CCC.DDD (<FQDN>) Ports: 443/open/tcp//https///"
     # (or):      Host: AAA.BBB.CCC.DDD (<FQDN>) Ports: 22/open/tcp//ssh//<banner>/, 25/open/tcp//smtp//<banner>/, 443/open/tcp//ssl|http//<banner>
     while read -r hostdontcare ip round_brackets tmp ports_specs; do
          [[ "$ports_specs" =~ "Status: "  ]] && continue             # we don't need this
          [[ "$ports_specs" =~ '/open/tcp/' ]] || continue            # no open tcp at all for this IP --> move
          host_spec="$ip"
          fqdn="${round_brackets/\(/}"
          fqdn="${fqdn/\)/}"
          if [[ -n "$fqdn" ]]; then
               tmp="$(get_a_record "$fqdn")"
               if [[ "$tmp" == "$ip" ]]; then
                    host_spec="$fqdn"
               fi
          fi
          while read -r oneline; do
               # 25/open/tcp//smtp//<banner>/,
               [[ "$oneline" =~ '/open/tcp/' ]] || continue                # no open tcp for this port on this IP --> move on
               IFS=/ read -r port dontcare protocol ssl_hint dontcare1 <<< "$oneline"
               if [[ "$ssl_hint" =~ ^(ssl|https) ]] || [[ "$dontcare1" =~ ^(ssl|https) ]]; then
                    echo "${host_spec}:${port}" >>"$target_fname"
               else
                    starttls="$(ports2starttls $port)"
                    [[ $? -eq 1 ]] && continue                                  # nmap got a port but we don't know how to speak to
                    echo "${starttls}${host_spec}:${port}" >>"$target_fname"
               fi
          done < <(tr ',' '\n' <<< "$ports_specs")
     done < "$fname"

     [[ -s "$target_fname" ]] || fatal "Couldn't find any open port in $fname" 253
     echo "$target_fname written successfully"
     return 0
}


[[ -z "$1" ]] && usage
FNAME="$1"
[[ ! -e $FNAME ]] && echo "$FNAME not readable" && exit 2

nmap_to_plain_file "$FNAME"

exit $?

#  vim:ts=5:sw=5:expandtab

