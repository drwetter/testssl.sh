#!/usr/bin/env bash
#
# vim:ts=5:sw=5:expandtab
# we have a spaces softtab, that ensures readability with other editors too

[ -z "$BASH_VERSINFO" ] && printf "\n\033[1;35m Please make sure you're using \"bash\"! Bye...\033[m\n\n" >&2 && exit 245
[ $(kill -l | grep -c SIG) -eq 0 ] && printf "\n\033[1;35m Please make sure you're calling me without leading \"sh\"! Bye...\033[m\n\n"  >&2 && exit 245

# testssl.sh is a program for spotting weak SSL encryption, ciphers, version and some
# vulnerabilities or features
#
# Devel version is available from    https://github.com/drwetter/testssl.sh
# Stable version from                https://testssl.sh
# Please file bugs at github!        https://github.com/drwetter/testssl.sh/issues

# Main author: Dirk Wetter, copyleft: 2007-today, contributions so far see CREDITS.md
#
# License: GPLv2, see http://www.fsf.org/licensing/licenses/info/GPLv2.html
# and accompanying license "LICENSE.txt". Redistribution + modification under this
# license permitted.
# If you enclose this script or parts of it in your software, it has to
# be accompanied by the same license (see link) and the place where to get
# the recent version of this program. Do not violate the license and if
# you do not agree to all of these terms, do not use it in the first place.
#
# OpenSSL, which is being used and maybe distributed via one of this projects'
# web sites, is subject to their licensing: https://www.openssl.org/source/license.txt
#
# The client simulation data comes from SSLlabs and is licensed to the 'Qualys SSL Labs
# Terms of Use' (v2.2), see https://www.ssllabs.com/downloads/Qualys_SSL_Labs_Terms_of_Use.pdf,
# stating a CC BY 3.0 US license: https://creativecommons.org/licenses/by/3.0/us/
#
# Please note:  USAGE WITHOUT ANY WARRANTY, THE SOFTWARE IS PROVIDED "AS IS".
#
# USE IT AT your OWN RISK!
# Seriously! The threat is you run this code on your computer and input could be /
# is being supplied via untrusted sources.

# HISTORY:
# Back in 2006 it all started with a few openssl commands...
# That's because openssl is a such a good swiss army knife (see e.g.
# wiki.openssl.org/index.php/Command_Line_Utilities) that it was difficult to resist
# wrapping some shell commands around it, which I used for my pen tests. This is how
# everything started.
# Now it has grown up, it has bash socket support for some features, which is basically replacing
# more and more functions of OpenSSL and will serve as some kind of library in the future.
# The socket checks in bash may sound cool and unique -- they are -- but probably you
# can achieve e.g. the same result with my favorite interactive shell: zsh (zmodload zsh/net/socket
# -- checkout zsh/net/tcp) too!
# /bin/bash though is way more often used within Linux and it's perfect
# for cross platform support, see MacOS X and also under Windows the MSYS2 extension or Cygwin.
# Cross-platform is one of the three main goals of this script. Second: Ease of installation.
# No compiling, install gems, go to CPAN, use pip etc. Third: Easy to use and to interpret
# the results.

# Did I mention it's open source?

# Q: So what's the difference to www.ssllabs.com/ssltest/ or sslcheck.globalsign.com/ ?
# A: As of now ssllabs only check 1) webservers 2) on standard ports, 3) reachable from the
#    internet. And those examples above 4) are 3rd parties. If these restrictions are all fine
#    with you and you need a management compatible rating -- go ahead and use those.

# But also if your fine with those restrictions: testssl.sh is meant as a tool in your hand
# and it's way more flexible.
#
# Oh, and did I mention testssl.sh is open source?

# Note that up to today there were a lot changes for "standard" openssl
# binaries: a lot of features (ciphers, protocols, vulnerabilities)
# are disabled as they'll impact security otherwise. For security
# testing though we need  all broken features. testssl.sh will
# over time replace those checks with bash sockets -- however it's
# still recommended to use the supplied binaries or cook your own, see
# https://github.com/drwetter/testssl.sh/blob/master/bin/Readme.md .
# Don't worry if feature X is not available you'll get a warning about
# this missing feature! The idea is if this script can't tell something
# for sure it speaks up so that you have clear picture.


# debugging help:
readonly PS4='${LINENO}> ${FUNCNAME[0]:+${FUNCNAME[0]}(): }'

# make sure that temporary files are cleaned up after use in ANY case
trap "cleanup" QUIT EXIT

readonly VERSION="2.9dev"
readonly SWCONTACT="dirk aet testssl dot sh"
egrep -q "dev|rc" <<< "$VERSION" && \
     SWURL="https://testssl.sh/dev/" ||
     SWURL="https://testssl.sh/    "

readonly PROG_NAME=$(basename "$0")
readonly RUN_DIR=$(dirname "$0")
TESTSSL_INSTALL_DIR="${TESTSSL_INSTALL_DIR:-""}"   # if you run testssl.sh from a different path you can set either TESTSSL_INSTALL_DIR
CA_BUNDLES_PATH="${CA_BUNDLES_PATH:-""}"           # or CA_BUNDLES_PATH to find the CA BUNDLES. TESTSSL_INSTALL_DIR helps you to find the RFC mapping also
CIPHERS_BY_STRENGTH_FILE=""
OPENSSL_LOCATION=""
HNAME="$(hostname)"
HNAME="${HNAME%%.*}"

readonly CMDLINE="$@"

readonly CVS_REL=$(tail -5 "$0" | awk '/dirkw Exp/ { print $4" "$5" "$6}')
readonly CVS_REL_SHORT=$(tail -5 "$0" | awk '/dirkw Exp/ { print $4 }')
if git log &>/dev/null; then
     readonly GIT_REL=$(git log --format='%h %ci' -1 2>/dev/null | awk '{ print $1" "$2" "$3 }')
     readonly GIT_REL_SHORT=$(git log --format='%h %ci' -1 2>/dev/null | awk '{ print $1 }')
     readonly REL_DATE=$(git log --format='%h %ci' -1 2>/dev/null | awk '{ print $2 }')
else
     readonly REL_DATE=$(tail -5 "$0" | awk '/dirkw Exp/ { print $5 }')
fi
readonly SYSTEM=$(uname -s)
SYSTEM2=""                                             # currently only being used for WSL = bash on windows
date -d @735275209 >/dev/null 2>&1 && \
     readonly HAS_GNUDATE=true || \
     readonly HAS_GNUDATE=false
# FreeBSD and OS X date(1) accept "-f inputformat"
date -j -f '%s' 1234567 >/dev/null 2>&1 && \
     readonly HAS_FREEBSDDATE=true || \
     readonly HAS_FREEBSDDATE=false
echo A | sed -E 's/A//' >/dev/null 2>&1 && \
     readonly HAS_SED_E=true || \
     readonly HAS_SED_E=false

tty -s && \
     readonly INTERACTIVE=true || \
     readonly INTERACTIVE=false

if [[ -z $TERM_WIDTH ]]; then                               # no batch file and no otherwise predefined TERM_WIDTH
     if ! tput cols &>/dev/null || ! "$INTERACTIVE";then    # Prevent tput errors if running non interactive
          export TERM_WIDTH=${COLUMNS:-80}
     else
          export TERM_WIDTH=${COLUMNS:-$(tput cols)}        # for custom line wrapping and dashes
     fi
fi
TERM_CURRPOS=0                                              # custom line wrapping needs alter the current horizontal cursor pos

# following variables make use of $ENV, e.g. OPENSSL=<myprivate_path_to_openssl> ./testssl.sh <host>
# 0 means (normally) true here. Some of the variables are also accessible with a command line switch, see --help

declare -x OPENSSL OPENSSL_TIMEOUT
COLOR=${COLOR:-2}                       # 2: Full color, 1: b/w+positioning, 0: no ESC at all
COLORBLIND=${COLORBLIND:-false}         # if true, swap blue and green in the output
SHOW_EACH_C=${SHOW_EACH_C:-false}       # where individual ciphers are tested show just the positively ones tested
SHOW_SIGALGO=${SHOW_SIGALGO:-false}     # "secret" switch whether testssl.sh shows the signature algorithm for -E / -e
SNEAKY=${SNEAKY:-false}                 # is the referer and useragent we leave behind just usual?
QUIET=${QUIET:-false}                   # don't output the banner. By doing this yiu acknowledge usage term appearing in the banner
SSL_NATIVE=${SSL_NATIVE:-false}         # we do per default bash sockets where possible "true": switch back to "openssl native"
ASSUME_HTTP=${ASSUME_HTTP:-false}       # in seldom cases (WAF, old servers, grumpy SSL) service detection fails. "True" enforces HTTP checks
BUGS=${BUGS:-""}                        # -bugs option from openssl, needed for some BIG IP F5
DEBUG=${DEBUG:-0}                       # 1: normal putput the files in /tmp/ are kept for further debugging purposes
                                        # 2: list more what's going on , also lists some errors of connections
                                        # 3: slight hexdumps + other info,
                                        # 4: display bytes sent via sockets
                                        # 5: display bytes received via sockets
                                        # 6: whole 9 yards
FAST=${FAST:-false}                     # preference: show only first cipher, run_allciphers with openssl instead of sockets
WIDE=${WIDE:-false}                     # whether to display for some options just ciphers or a table w hexcode/KX,Enc,strength etc.
LOGFILE=${LOGFILE:-""}                  # logfile if used
JSONFILE=${JSONFILE:-""}                # jsonfile if used
CSVFILE=${CSVFILE:-""}                  # csvfile if used
APPEND=${APPEND:-false}                 # append to csv/json file instead of overwriting it
GIVE_HINTS=false                        # give an addtional info to findings
HAS_IPv6=${HAS_IPv6:-false}             # if you have OpenSSL with IPv6 support AND IPv6 networking set it to yes
UNBRACKTD_IPV6=${UNBRACKTD_IPV6:-false} # some versions of OpenSSL (like Gentoo) don't support [bracketed] IPv6 addresses
SERVER_SIZE_LIMIT_BUG=false             # Some servers have either a ClientHello total size limit or cipher limit of ~128 ciphers (e.g. old ASAs)

# tuning vars, can not be set by a cmd line switch
EXPERIMENTAL=${EXPERIMENTAL:-false}
HEADER_MAXSLEEP=${HEADER_MAXSLEEP:-5}   # we wait this long before killing the process to retrieve a service banner / http header
readonly MAX_WAITSOCK=10                # waiting at max 10 seconds for socket reply
readonly CCS_MAX_WAITSOCK=5             # for the two CCS payload (each)
readonly HEARTBLEED_MAX_WAITSOCK=8      # for the heartbleed payload
STARTTLS_SLEEP=${STARTTLS_SLEEP:-1}     # max time to wait on a socket replay for STARTTLS
FAST_STARTTLS=${FAST_STARTTLS:-true}    #at the cost of reliabilty decrease the handshakes for STARTTLS
USLEEP_SND=${USLEEP_SND:-0.1}           # sleep time for general socket send
USLEEP_REC=${USLEEP_REC:-0.2}           # sleep time for general socket receive
HSTS_MIN=${HSTS_MIN:-179}               # >179 days is ok for HSTS
     HSTS_MIN=$((HSTS_MIN * 86400))     # correct to seconds
HPKP_MIN=${HPKP_MIN:-30}                # >=30 days should be ok for HPKP_MIN, practical hints?
     HPKP_MIN=$((HPKP_MIN * 86400))     # correct to seconds
DAYS2WARN1=${DAYS2WARN1:-60}            # days to warn before cert expires, threshold 1
DAYS2WARN2=${DAYS2WARN2:-30}            # days to warn before cert expires, threshold 2
VULN_THRESHLD=${VULN_THRESHLD:-1}       # if vulnerabilities to check >$VULN_THRESHLD we DON'T show a separate header line in the output each vuln. check
NODNS=${NODNS:-false}                   # always do DNS lookups per default. For some pentests it might save time to set this to true
readonly CLIENT_MIN_PFS=5               # number of ciphers needed to run a test for PFS
HAD_SLEPT=0
CAPATH="${CAPATH:-/etc/ssl/certs/}"     # Does nothing yet (FC has only a CA bundle per default, ==> openssl version -d)
FNAME=${FNAME:-""}                      # file name to read commands from
IKNOW_FNAME=false

# further global vars just declared here
readonly NPN_PROTOs="spdy/4a2,spdy/3,spdy/3.1,spdy/2,spdy/1,http/1.1"
# alpn_protos needs to be space-separated, not comma-seperated, including odd ones observerd @ facebook and others, old ones like h2-17 omitted as they could not be found
readonly ALPN_PROTOs="h2 spdy/3.1 http/1.1 h2-fb spdy/1 spdy/2 spdy/3 stun.turn stun.nat-discovery webrtc c-webrtc ftp"

TEMPDIR=""
TMPFILE=""
ERRFILE=""
CLIENT_AUTH=false
NO_SSL_SESSIONID=false
HOSTCERT=""
HEADERFILE=""
HEADERVALUE=""
HTTP_STATUS_CODE=""
PROTOS_OFFERED=""
TLS_EXTENSIONS=""
GOST_STATUS_PROBLEM=false
DETECTED_TLS_VERSION=""
PATTERN2SHOW=""
SOCK_REPLY_FILE=""
HEXC=""
NW_STR=""
LEN_STR=""
SNI=""
OSSL_VER=""                             # openssl version, will be auto-determined
OSSL_VER_MAJOR=0
OSSL_VER_MINOR=0
OSSL_VER_APPENDIX="none"
HAS_DH_BITS=${HAS_DH_BITS:-false}       # initialize openssl variables
HAS_SSL2=false
HAS_SSL3=false
HAS_NO_SSL2=false
HAS_ALPN=false
HAS_SPDY=false
HAS_FALLBACK_SCSV=false
HAS_PROXY=false
HAS_XMPP=false
HAS_POSTGRES=false
ADD_RFC_STR="rfc"                       # display RFC ciphernames
SHOW_RFC=""                             # display RFC ciphernames instead of OpenSSL ciphernames
PORT=443                                # unless otherwise auto-determined, see below
NODE=""
NODEIP=""
CORRECT_SPACES=""                       # used for IPv6 and proper output formatting
IPADDRs=""
IP46ADDRs=""
LOCAL_A=false                           # does the $NODEIP come from /etc/hosts?
LOCAL_AAAA=false                        # does the IPv6 IP come from /etc/hosts?
XMPP_HOST=""
PROXY=""
PROXYIP=""
PROXYPORT=""
VULN_COUNT=0
IPS=""
SERVICE=""                              # is the server running an HTTP server, SMTP, POP or IMAP?
URI=""
CERT_FINGERPRINT_SHA2=""
RSA_CERT_FINGERPRINT_SHA2=""
SHOW_CENSYS_LINK=${SHOW_CENSYS_LINK:-true}
STARTTLS_PROTOCOL=""
OPTIMAL_PROTO=""                        # we need this for IIS6 (sigh) and OpenSSL 1.0.2, otherwise some handshakes
                                        # will fail, see https://github.com/PeterMosmans/openssl/issues/19#issuecomment-100897892
STARTTLS_OPTIMAL_PROTO=""               # same for STARTTLS, see https://github.com/drwetter/testssl.sh/issues/188
TLS_TIME=""
TLS_NOW=""
NOW_TIME=""
HTTP_TIME=""
GET_REQ11=""
readonly UA_STD="TLS tester from $SWURL"
readonly UA_SNEAKY="Mozilla/5.0 (X11; Linux x86_64; rv:41.0) Gecko/20100101 Firefox/41.0"
FIRST_FINDING=true                      # Is this the first finding we are outputting to file?
START_TIME=0
END_TIME=0

# Devel stuff, see -q below
TLS_LOW_BYTE=""
HEX_CIPHER=""

                                             # The various hexdump commands we need to replace xxd (BSD compatibility)
HEXDUMP=(hexdump -ve '16/1 "%02x " " \n"')   # This is used to analyze the reply
HEXDUMPPLAIN=(hexdump -ve '1/1 "%.2x"')      # Replaces both xxd -p and tr -cd '[:print:]'

SERVER_COUNTER=0                             # Counter for multiple servers

#################### SEVERITY ####################
INFO=0
OK=0
LOW=1
MEDIUM=2
HIGH=3
CRITICAL=4

SEVERITY_LEVEL=0

set_severity_level() {
   local severity=$1

   if [[ "$severity" == "LOW" ]]; then
           SEVERITY_LEVEL=$LOW
   elif [[ "$severity" == "MEDIUM" ]]; then
           SEVERITY_LEVEL=$MEDIUM
   elif [[ "$severity" == "HIGH" ]]; then
           SEVERITY_LEVEL=$HIGH
   elif [[ "$severity" == "CRITICAL" ]]; then
           SEVERITY_LEVEL=$CRITICAL
   else
        echo "Supported severity levels are LOW, MEDIUM, HIGH, CRITICAL!"
        help
   fi
}

show_finding() {
   local severity=$1

   ([[ "$severity" == "DEBUG" ]]) ||
   ([[ "$severity" == "WARN" ]]) ||
   ([[ "$severity" == "INFO" ]] && [[ $SEVERITY_LEVEL -le $INFO ]]) ||
   ([[ "$severity" == "OK" ]] && [[ $SEVERITY_LEVEL -le $OK ]]) ||
   ([[ "$severity" == "LOW" ]] && [[ $SEVERITY_LEVEL -le $LOW ]]) ||
   ([[ "$severity" == "MEDIUM" ]] && [[ $SEVERITY_LEVEL -le $MEDIUM ]]) ||
   ([[ "$severity" == "HIGH" ]] && [[ $SEVERITY_LEVEL -le $HIGH ]]) ||
   ([[ "$severity" == "CRITICAL" ]] && [[ $SEVERITY_LEVEL -le $CRITICAL ]])
}


###### some hexbytes for bash network sockets follow ######

# 133 standard cipher + 4x GOST for TLS 1.2 and SPDY/NPN
readonly TLS12_CIPHER="
cc,14, cc,13, cc,15, c0,30, c0,2c, c0,28, c0,24, c0,14,
c0,0a, c0,22, c0,21, c0,20, 00,a5, 00,a3, 00,a1, 00,9f,
00,6b, 00,6a, 00,69, 00,68, 00,39, 00,38, 00,37, 00,36, 00,80, 00,81, 00,82, 00,83,
c0,77, c0,73, 00,c4, 00,c3, 00,c2, 00,c1, 00,88, 00,87,
00,86, 00,85, c0,32, c0,2e, c0,2a, c0,26, c0,0f, c0,05,
c0,79, c0,75, 00,9d, 00,3d, 00,35, 00,c0, 00,84, c0,2f,
c0,2b, c0,27, c0,23, c0,13, c0,09, c0,1f, c0,1e, c0,1d,
00,a4, 00,a2, 00,a0, 00,9e, 00,67, 00,40, 00,3f, 00,3e,
00,33, 00,32, 00,31, 00,30, c0,76, c0,72, 00,be, 00,bd,
00,bc, 00,bb, 00,9a, 00,99, 00,98, 00,97, 00,45, 00,44,
00,43, 00,42, c0,31, c0,2d, c0,29, c0,25, c0,0e, c0,04,
c0,78, c0,74, 00,9c, 00,3c, 00,2f, 00,ba, 00,96, 00,41,
00,07, c0,11, c0,07, 00,66, c0,0c, c0,02, 00,05, 00,04,
c0,12, c0,08, c0,1c, c0,1b, c0,1a, 00,16, 00,13, 00,10,
00,0d, c0,0d, c0,03, 00,0a, 00,63, 00,15, 00,12, 00,0f,
00,0c, 00,62, 00,09, 00,65, 00,64, 00,14, 00,11, 00,0e,
00,0b, 00,08, 00,06, 00,03, 00,ff"

# 76 standard cipher +4x GOST for SSLv3, TLS 1, TLS 1.1
readonly TLS_CIPHER="
c0,14, c0,0a, c0,22, c0,21, c0,20, 00,39, 00,38, 00,37,
00,36, 00,88, 00,87, 00,86, 00,85, c0,0f, c0,05, 00,35,
00,84, c0,13, c0,09, c0,1f, c0,1e, c0,1d, 00,33, 00,32, 00,80, 00,81, 00,82, 00,83,
00,31, 00,30, 00,9a, 00,99, 00,98, 00,97, 00,45, 00,44,
00,43, 00,42, c0,0e, c0,04, 00,2f, 00,96, 00,41, 00,07,
c0,11, c0,07, 00,66, c0,0c, c0,02, 00,05, 00,04, c0,12,
c0,08, c0,1c, c0,1b, c0,1a, 00,16, 00,13, 00,10, 00,0d,
c0,0d, c0,03, 00,0a, 00,63, 00,15, 00,12, 00,0f, 00,0c,
00,62, 00,09, 00,65, 00,64, 00,14, 00,11, 00,0e, 00,0b,
00,08, 00,06, 00,03, 00,ff"

readonly -a TLS13_KEY_SHARES=(
 "0" "1" "2" "3" "4" "5" "6" "7" "8" "9" "a" "b" "c" "d" "e" "f"
  "10" "11" "12" "13" "14" "15" "16"
"-----BEGIN EC PARAMETERS-----
BggqhkjOPQMBBw==
-----END EC PARAMETERS-----
-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIHEhQsBkqt1i15mG1wluq/zLqDmjqNQegtgxyNBfRbZSoAoGCCqGSM49
AwEHoUQDQgAEJP3GoZyVYrabOauJMWUZJxM0PEbtjTxW7K8V+JMDhJa+UyRQm8Tf
2LDnzCAiuwzF8m0KhcloHEoptD2WBUmJlQ==
-----END EC PRIVATE KEY-----
"
"-----BEGIN EC PARAMETERS-----
BgUrgQQAIg==
-----END EC PARAMETERS-----
-----BEGIN EC PRIVATE KEY-----
MIGkAgEBBDA7MCUdHy2+Kc73fWph++jWo18LHzzm7SKLgycQBNtmeJu3w1y9pK0G
EXgAWsIePIOgBwYFK4EEACKhZANiAAT/x7tN8plE6gbA6D4Igp3ash5EvZxvNqdG
Q50fcDrIco91ybaVlg2tdngZgurTzte+jv7kdkYrILUmLnXxAUGg4d86yStfcZaI
rDEB8Hc9BgJkFFoLSsXMVCKfoEo777k=
-----END EC PRIVATE KEY-----
"
"-----BEGIN EC PARAMETERS-----
BgUrgQQAIw==
-----END EC PARAMETERS-----
-----BEGIN EC PRIVATE KEY-----
MIHbAgEBBEFjBqkejwKserOf+LoY6xeSUUoLSZQDz/oNLXLB3NQJ3ewDkhbjOvcL
jG1on33V080fXRTN3eNdfvzcqDw4c0GGCKAHBgUrgQQAI6GBiQOBhgAEAHuBnMpQ
+30lnd/gWrHwjLrXQ+EwtxYzMjSDkfRxr0UQ0YuzDNzsVP0azylC06BUlcAvVgiX
+61BiUapw+37EORuAaHOlob0nobmFND7peN0YglQuBeSdqK3cbdP/u9jffGr2H99
bONJgO7LSp05PXa79CEi8sydmKYiH1pSLAzRiQnh
-----END EC PRIVATE KEY-----
" "1a" "1b" "1c"
"-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VuBCIEIACiKGKr1nm2eobXvsI3HrWNKR5wEVAIf7KaCmDPxsJR
-----END PRIVATE KEY-----
" "1e" "1f"
 "20" "21" "22" "23" "24" "25" "26" "27" "28" "29" "2a" "2b" "2c" "2d" "2e" "2f"
 "30" "31" "32" "33" "34" "35" "36" "37" "38" "39" "3a" "3b" "3c" "3d" "3e" "3f"
 "40" "41" "42" "43" "44" "45" "46" "47" "48" "49" "4a" "4b" "4c" "4d" "4e" "4f"
 "50" "51" "52" "53" "54" "55" "56" "57" "58" "59" "5a" "5b" "5c" "5d" "5e" "5f"
 "60" "61" "62" "63" "64" "65" "66" "67" "68" "69" "6a" "6b" "6c" "6d" "6e" "6f"
 "70" "71" "72" "73" "74" "75" "76" "77" "78" "79" "7a" "7b" "7c" "7d" "7e" "7f"
 "80" "81" "82" "83" "84" "85" "86" "87" "88" "89" "8a" "8b" "8c" "8d" "8e" "8f"
 "90" "91" "92" "93" "94" "95" "96" "97" "98" "99" "9a" "9b" "9c" "9d" "9e" "9f"
 "a0" "a1" "a2" "a3" "a4" "a5" "a6" "a7" "a8" "a9" "aa" "ab" "ac" "ad" "ae" "af"
 "b0" "b1" "b2" "b3" "b4" "b5" "b6" "b7" "b8" "b9" "ba" "bb" "bc" "bd" "be" "bf"
 "c0" "c1" "c2" "c3" "c4" "c5" "c6" "c7" "c8" "c9" "ca" "cb" "cc" "cd" "ce" "cf"
 "d0" "d1" "d2" "d3" "d4" "d5" "d6" "d7" "d8" "d9" "da" "db" "dc" "dd" "de" "df"
 "e0" "e1" "e2" "e3" "e4" "e5" "e6" "e7" "e8" "e9" "ea" "eb" "ec" "ed" "ee" "ef"
 "f0" "f1" "f2" "f3" "f4" "f5" "f6" "f7" "f8" "f9" "fa" "fb" "fc" "fd" "fe" "ff"
 "-----BEGIN PRIVATE KEY-----
MIICJgIBADCCARcGCSqGSIb3DQEDATCCAQgCggEBAP//////////rfhUWKK7Spqv
3FYgJz088di5xYPOLTaVqeE2QRRkM/vMk53OJJs++X0v42NjDHXY9oGyAq7EYXrT
3x7V1f1lYSQz9R9fBm7QhWNlVT3tGvO1VxNef1fJNZhPDHDg5ot34qaJ2vPv6HId
8VihNq3nNTCsyk9IOnl6vAqxgrMk+2HRCKlLssjj+7lq2rdg1/RoHU9Co945TfSu
Vu3nY3K7GQsHp8juCm1wngL84c334uzANATNKDQvYZFy/pzphYP/jk8SMu7ygYPD
/jsbTG+tczu1/LwuwiAFxY7xg30Wg7LG80omwbLv+ohrQjhhKFyX//////////8C
AQIEggEEAoIBAHxYskjJGeKwSGdAf//JLxPmGRGP6Uylmt12QX5w1FfFXQVJdrsY
unjdqhTwgV1vTZ1QApd0uZB//q8ZNNM8SZK0elY4ZJsHJAIdJ/ROmvPvkMCkU0fK
S/uUHroP6tEDyKF+v7ooiBF2KXS5CkOYRTKhiOBaWGsdhiFIkd+O7oY6oyhPxPNT
2zQEdhIu3ZgFG/ZcscdliMPMmZnKvt/dF4yV8RnCHl3MRDRdL/3McDAb4z89bWqR
HRexppcgNa9lhOvR+nF/55NCzT3KwkFPQODQmMRH3bzmME+48HZrFcaaom3/DGt+
EC+vidtEr4YW86tV6jvig5+uNR1mIKpE8N4=
-----END PRIVATE KEY-----
"
"-----BEGIN PRIVATE KEY-----
MIIDJgIBADCCAZcGCSqGSIb3DQEDATCCAYgCggGBAP//////////rfhUWKK7Spqv
3FYgJz088di5xYPOLTaVqeE2QRRkM/vMk53OJJs++X0v42NjDHXY9oGyAq7EYXrT
3x7V1f1lYSQz9R9fBm7QhWNlVT3tGvO1VxNef1fJNZhPDHDg5ot34qaJ2vPv6HId
8VihNq3nNTCsyk9IOnl6vAqxgrMk+2HRCKlLssjj+7lq2rdg1/RoHU9Co945TfSu
Vu3nY3K7GQsHp8juCm1wngL84c334uzANATNKDQvYZFy/pzphYP/jk8SMu7ygYPD
/jsbTG+tczu1/LwuwiAFxY7xg30Wg7LG80omwbLv+ohrQjhhH8/c3jVbO2UZA1u8
NPTe+ZwCOGG0b8nW5skHetkdJpH39+5ZjLD6wYbZHK7+EwmFE5JwtBMMk7xDeUT0
/URS4tdN02Ty4h5x9Uv/XK6Cq5yd9p7obSvFIjY6DavFIZebDeraHb+aQtXESE4K
vNBr+lPd7zwbIO4/1Z18JeQdK2bGLjf//////////wIBAgSCAYQCggGAV6hlUz0f
RwpauhaumL+dFJQcZHgYghHX9JfNDZv1uMzkTiKxgVutrtFmfHoaTaYNgw+HEQSF
ZRnGzyOXb14/ZoGWo727N4T5usOqINFcHIeAbPiRimo0mwS7ivYKxEFBaw4N7OyE
zfNKAYWNQe0J+R2FLMKBSbJ+b1nGQ/cUSQDffDpKSUS94+XxwxcvNaCv9Ygtkvnl
e/t61L/0eQu/nmi0o7PzR4brmyVTXGnj2LujG/KOtIB4pXQ1GqrvsYLB3pCUTDdA
E0heXfpYGZJK10ByMkWmOuH3pCuI8C+7+Bh7JwQAXUtSpZ+hp1Bz7v1PKwY/3fG1
2HcPXp85q5N9x9zYZv1vmwFAd0nTdoWdtMbiEJxhCdr6sRpi1+KPg6W3Kqtfcv2f
ZZC6MwVFtxogjzIlXt68O7HRH7Adz+DGhEeZqdxIQpaQR50p4LF7gqQ/mzXq8oCe
XKC3XxrfV5h3OrPEL/zNTd2pzh3LLQB349aOHNz1F+3YPyPlvwOsXkeT
-----END PRIVATE KEY-----
"
"-----BEGIN PRIVATE KEY-----
MIIEJgIBADCCAhcGCSqGSIb3DQEDATCCAggCggIBAP//////////rfhUWKK7Spqv
3FYgJz088di5xYPOLTaVqeE2QRRkM/vMk53OJJs++X0v42NjDHXY9oGyAq7EYXrT
3x7V1f1lYSQz9R9fBm7QhWNlVT3tGvO1VxNef1fJNZhPDHDg5ot34qaJ2vPv6HId
8VihNq3nNTCsyk9IOnl6vAqxgrMk+2HRCKlLssjj+7lq2rdg1/RoHU9Co945TfSu
Vu3nY3K7GQsHp8juCm1wngL84c334uzANATNKDQvYZFy/pzphYP/jk8SMu7ygYPD
/jsbTG+tczu1/LwuwiAFxY7xg30Wg7LG80omwbLv+ohrQjhhH8/c3jVbO2UZA1u8
NPTe+ZwCOGG0b8nW5skHetkdJpH39+5ZjLD6wYbZHK7+EwmFE5JwtBMMk7xDeUT0
/URS4tdN02Ty4h5x9Uv/XK6Cq5yd9p7obSvFIjY6DavFIZebDeraHb+aQtXESE4K
vNBr+lPd7zwbIO4/1Z18JeQdK2aeHvFub1LDFk30+3kw6eTliFe2rH1fQtafbRh3
Y88dVQNABIf1W6V+Mcx6cTXIhu+0MYrtah4BLZ5oMqkHYAqRgTDEbcd4+XGtADgJ
KZmjM8uLehoduT1xQAA8Kk7OqfmNCswKgpHNzsl9z47JtVp/iKRrTbWoUfRBguHG
igB+XmVfav//////////AgECBIICBAKCAgBKs8VkNMjroMib7Wuw71hVoHiB7lF9
3FQsDwU3y//RgETN2CEx8gdarvb35ldNEkypxtiaYck+a5qKVkP8uW4/AUoGlH4V
mIVz8R9e0Cewc4X8229+AgvyguaEhJHozp7EqIYEYlpLyn5GL53l2OYvBB3eH9Yi
yjYKe5vCe16Jy88oJYrS6+ybYLXHcfJsLHIppMS17KuDdH/DUiCvy5HE5fA5ufD3
ExQImgsDa3rm8nW6NUCix9Pl4X5OkWieYE7pXBePZ8Yk8BD4JpPbhsh/9husS4XL
/IpSq+tzgXq44SKQv0o9hbkGaxR6xmTjTwOjRiqW1D/1pS/wHxZbH1qbgJSKq7Fx
6VZZjH5Hyx9Zh5p3mksa7iZ4DQXVW/8ffz+8UdVRQolVUQxXWihcU5qfdtmDEPI0
4dRR5mI/Pk1n7lAhdyE4H/Tz0TmqItfScZvNaj6RbPbk6KOapgHFKIX7dmtPxAOv
oMMudOwsBg7md3CY08zH/XdE6O8lmVgCJQMjfwJ7QMayOKL1NYNMmUDPP0WIxOyz
5UJj3GzmNrKgYftgr2o8blEwwDbETYN/hpgTPyWl8ieVxK2bn7SX8dFXXEwSdCAt
Cg5c3H+YOc+ahx7VYXJtBDyAKuygUKnVqZ1ht6/xLUyJUxiSMZLbFKHBLkR3UuQa
HyRwI92yYN4+Zg==
-----END PRIVATE KEY-----
"
"-----BEGIN PRIVATE KEY-----
MIIGJgIBADCCAxcGCSqGSIb3DQEDATCCAwgCggMBAP//////////rfhUWKK7Spqv
3FYgJz088di5xYPOLTaVqeE2QRRkM/vMk53OJJs++X0v42NjDHXY9oGyAq7EYXrT
3x7V1f1lYSQz9R9fBm7QhWNlVT3tGvO1VxNef1fJNZhPDHDg5ot34qaJ2vPv6HId
8VihNq3nNTCsyk9IOnl6vAqxgrMk+2HRCKlLssjj+7lq2rdg1/RoHU9Co945TfSu
Vu3nY3K7GQsHp8juCm1wngL84c334uzANATNKDQvYZFy/pzphYP/jk8SMu7ygYPD
/jsbTG+tczu1/LwuwiAFxY7xg30Wg7LG80omwbLv+ohrQjhhH8/c3jVbO2UZA1u8
NPTe+ZwCOGG0b8nW5skHetkdJpH39+5ZjLD6wYbZHK7+EwmFE5JwtBMMk7xDeUT0
/URS4tdN02Ty4h5x9Uv/XK6Cq5yd9p7obSvFIjY6DavFIZebDeraHb+aQtXESE4K
vNBr+lPd7zwbIO4/1Z18JeQdK2aeHvFub1LDFk30+3kw6eTliFe2rH1fQtafbRh3
Y88dVQNABIf1W6V+Mcx6cTXIhu+0MYrtah4BLZ5oMqkHYAqRgTDEbcd4+XGtADgJ
KZmjM8uLehoduT1xQAA8Kk7OqfmNCswKgpHNzsl9z47JtVp/iKRrTbWoUfRBguHG
igB+Xg3ZAgv9ZLZFA2x6Tmd9LDhTKjojukRCyvU+pju0VDKbdiTIkXvdZLHA/Uyz
jowzTHAcOs2tBlf8z+xxmx9cPk5GBB84gUf7TP20d6UkcfepqWkQuFUyLttjQNig
DvCSNQUR4wq+wf/546Juf7KfjBgwI8NYfjjaAHfZtHY+TkuUsrvBlMZlHnfK+ZLu
qsAjKigb9rOnOcEiYRaCCujbWEemfL75yQkbRi1TjNcrA3Rq539eYiksMRViqEZQ
XcgtuFQziuSfUjXJW5EXjM8t1crO9APsnRgQxicrBFs7cfnca4DWP91KjprbHmli
ppUm1DFhwaQdVw15ONrUpA4ynNDkDmX//////////wIBAgSCAwQCggMAVvLSfpPC
OJVhuOkMtOYtl6vcKtuP0RXXZYBfMFufb5gQJrEypjSIxS+kRyBjNMk3qSt9iBbG
dpSe5fuu9RtI5O5eD/UXrDNBbI2/ldLNDarV3g+hcYklzKQE6kBSWEt1soktPXEq
PIcvYFVrOtWrH3Nw0UT/brRLZ+Ea9mnRG6CCICM0K2UxMhyjDheGCVCpmZfYJycP
mx0H1SA5RI9lP+GkDm096CgAEtXqk1eej8/9F4vsEn5r48HKobXlZEBp+HFcIq7s
DqrNZkg6jRhMusGjVM7mpFuyt0D5LIshsDBHjwkULJUX9Zd7pcVizbHbst2rpi8u
n7H908pdRFvdQYfvjBwvewl7DwZoFOsL+qA5Jo1MtfgpgegouKsS3jmyRSmY4wLp
uOjv6S1//A1sctJNwXlMI7/3IcONT3bmOwNnyvUeFJE4+lnYeClEpAsrCegcljQa
UNOeSKR1x9ctvzlWaBM5EP2daF0JiYdo3Ug/YISDX5dJFOW4gWz95W8Ii9//6zim
8LgA2/NP5IJBs0DPQxVbEVUI0wRPYMI4aZBm2n5bQFQKI95FQfv8ncKSul/fuTtY
du8INZR6ogMpWdDSz5UsIMwjLzXfg30ehcCyy9ebkDtiPDr8++HrwWKGVvuQaa4p
rPiac3fF1+DCHVKwxRsqM1zgDzNtI59Y9wb85kyPRsHTuG5kR3KUMUUYWmbuuMG6
3yMm7K3hJhlhfiO8hIWt+ZJJHCIEJOFK7FJbsZWmFbS6ukcl1uwlmQzote2aFfYA
5fsL7VeUaXKkJPKY3p05rvHJkayUpxn+oamOA1qW4eVYzio/ZiRtaUNLbmOvb0pU
Z1fyypnlaVzAVynoIF43LfbJ7cdpfnoz6hd//SVA742kuQMA4VeQoXLh6dX1/qZV
8QF7gNjLxgJoqGssaOUwxdxcXqMl+9JUBL/LtvxYs1xcrzla/tj+26XcPT+/tIWR
89TyyCWVPBvFLeWfG5+iIXT0X6g8zJP6d9QCL+2F3yStbJngWCZtFDFD
-----END PRIVATE KEY-----
"
"-----BEGIN PRIVATE KEY-----
MIIIJgIBADCCBBcGCSqGSIb3DQEDATCCBAgCggQBAP//////////rfhUWKK7Spqv
3FYgJz088di5xYPOLTaVqeE2QRRkM/vMk53OJJs++X0v42NjDHXY9oGyAq7EYXrT
3x7V1f1lYSQz9R9fBm7QhWNlVT3tGvO1VxNef1fJNZhPDHDg5ot34qaJ2vPv6HId
8VihNq3nNTCsyk9IOnl6vAqxgrMk+2HRCKlLssjj+7lq2rdg1/RoHU9Co945TfSu
Vu3nY3K7GQsHp8juCm1wngL84c334uzANATNKDQvYZFy/pzphYP/jk8SMu7ygYPD
/jsbTG+tczu1/LwuwiAFxY7xg30Wg7LG80omwbLv+ohrQjhhH8/c3jVbO2UZA1u8
NPTe+ZwCOGG0b8nW5skHetkdJpH39+5ZjLD6wYbZHK7+EwmFE5JwtBMMk7xDeUT0
/URS4tdN02Ty4h5x9Uv/XK6Cq5yd9p7obSvFIjY6DavFIZebDeraHb+aQtXESE4K
vNBr+lPd7zwbIO4/1Z18JeQdK2aeHvFub1LDFk30+3kw6eTliFe2rH1fQtafbRh3
Y88dVQNABIf1W6V+Mcx6cTXIhu+0MYrtah4BLZ5oMqkHYAqRgTDEbcd4+XGtADgJ
KZmjM8uLehoduT1xQAA8Kk7OqfmNCswKgpHNzsl9z47JtVp/iKRrTbWoUfRBguHG
igB+Xg3ZAgv9ZLZFA2x6Tmd9LDhTKjojukRCyvU+pju0VDKbdiTIkXvdZLHA/Uyz
jowzTHAcOs2tBlf8z+xxmx9cPk5GBB84gUf7TP20d6UkcfepqWkQuFUyLttjQNig
DvCSNQUR4wq+wf/546Juf7KfjBgwI8NYfjjaAHfZtHY+TkuUsrvBlMZlHnfK+ZLu
qsAjKigb9rOnOcEiYRaCCujbWEemfL75yQkbRi1TjNcrA3Rq539eYiksMRViqEZQ
XcgtuFQziuSfUjXJW5EXjM8t1crO9APsnRgQxicrBFs7cfnca4DWP91KjprbHmli
ppUm1DFhwaQdVw15ONrUpA4ynM/0aqo2rQBM9gDIOB5CWjHZUa5k/bI/zslQnUNo
f+tp7dHMXguMw732SxDvhrYxQqOriClVWy90fJMmZcssDxzAG9cCKTiIOdKvBeRU
UErHi3WCgihGwLo1w19cWRYMwEb9glFUH8aMnIawIrtwmYdqRg50UaipMQlwP+4c
IX5sOCblLFGqaR4OQjz8menjFlDBIXtiSBbNrZqV+dW4AZSI2cCgof4wdaV34jGD
+B1KPy+kVx78jOC6ik/otoVd/nKwpm7e0vur++WKMPr6vhxdcah+L3Qe+MH+hv6m
u/3lMGd/DZfRHUn3qEQ9CCLlBqn0YU4BHiqUg4/4jNaMi7fFxkJM//////////8C
AQIEggQEAoIEAFBZTkIN/znN/euu0INkB365wc9kj/ibO/Hj3mHLa+NHoaKH4A33
kd3WQCjRmLnLZHlodMbrgJ8vxHtKdeFiv4i1gefsv0aVv7zX9Sp3zpRJC/bhNJkz
BsVJwwp9b+OPfc13d2vb3ZsVyqmfUO6NdMz1x9cEiR+wrpJjrMbWqByliAkByI5w
Znlm/aLrwOWOZ0lkY2SzB5qDcNM/I9m7Uk9pW3Q0GugWC/PMzv/+VCMb/Q56pABX
310qNm0AZov4cBWz5qtD8AQ+cZWBndX4ydL+jLT5n5SwrXR3z8biCBdJWpxpKeVJ
3Dal4LC1UcuJDuwtxswlm+AzfVJI3eiKL5uwsSbIg0Ls7bk7FO1LWGHbGwbL+eof
TijrETwUgsBNiLdmLeDtfWBTDAH3kZnBpZjRhCgIRuRUleTRevvnMtBXR9td5Lkj
N4quHZbx0S9novQLV7EF6+mNW0fddbHxC6mK0C3vCGCTLUTjFoyW6DJMInUYrerO
kTEyH0JCMrA/mIGmU4QR7dXuMPJiTwg+TS3jZYmwa4nL5hES7Ssf9PSaqdyV2ZzU
/oVLTfIuvpFbcidZF7j2DFaObtV6ZjqegufOaNJmTItWJzNJ31s0ZUGwXLq5jygh
HMAW+uzNVX5nv7ezvjOANrOAosSDN1zFVRrUBOilaKbvguwp1fym2bnqiCFD1tKw
CMgtTOTwP8/j1XAMlD/Afu/VTJls3IY3r6ANoCX8hLTXK3ykcewV2irV4nB+8p09
KhhWSr3zF0qj5Keo33oMUnEaN2eIeIUegXKxpp4WtT4JEUE0ritZF8SzZmoHkANw
dgtDm8Ryx/SaZ+QwrqhVFOsSU8TgvIHc455j4M1o8DBAdUiTbXniYlSNslzbvfbK
57uJbPwrw/Op3DzFvZPnOx5vfnDsR9qOmAknfNfgKtEFc0AAno5BiyaiIlHuBUte
TS5AsCL7q4Q9ybS7WehGOWOwHzZEa7DlUJ1kqjFCxBXgYMEKSbwKF5vHpp6x2O3x
0OPzODz1JGoRT5yYXY3UiboRlkldet4NPNufg4MoKW6XooLXq/bIVQNSZtg1gBO6
ipWJlxpfmPhjOdljGlXsstvaazESsMaff5xG8dIIOb+yMFh6DC6GElU49GGzfnAe
EB+RNHS/o8boRFQn4r6/KiVCODk0qGK3TvYStsjXo93vA+KfJwSsqtckwX+wcl5l
mWWvMF+iHQ+gL4L1hz7hH/m7UZGy+o/7mi7lKDSPLvSlGwzzdWcvEQj4Hv4IHQQh
eeSHdeSwhqaL1XjP6JXa+IEY/wXzwIMHohtw+epFwLZhg8NFxkzHUpCKLDZrEDc8
Y9zPgF69gpA9VpStqLAqHxBvEm4BYFoFyfw=
-----END PRIVATE KEY-----
" "105" "106" "107" "108" "109" "10a" "10b" "10c" "10d" "10e" "10f" )

###### Cipher suite information #####
declare -i TLS_NR_CIPHERS=0
declare TLS_CIPHER_HEXCODE=()
declare TLS_CIPHER_OSSL_NAME=()
declare TLS_CIPHER_RFC_NAME=()
declare TLS_CIPHER_SSLVERS=()
declare TLS_CIPHER_KX=()
declare TLS_CIPHER_AUTH=()
declare TLS_CIPHER_ENC=()
declare TLS_CIPHER_EXPORT=()
declare TLS_CIPHER_OSSL_SUPPORTED=()

###### output functions ######
# a little bit of sanitzing with bash internal search&replace -- otherwise printf will hiccup at '%' and '--' does the rest.
out(){
#     if [[ "$BASH_VERSINFO" -eq 4 ]]; then
          printf -- "%b" "${1//%/%%}"
#     else
#          /usr/bin/printf -- "${1//%/%%}"
#     fi
}
outln() { out "$1\n"; }
#TODO: Still no shell injection safe but if just run it from the cmd line: that's fine

# color print functions, see also http://www.tldp.org/HOWTO/Bash-Prompt-HOWTO/x329.html
pr_liteblue()   { [[ "$COLOR" -eq 2 ]] && ( "$COLORBLIND" && out "\033[0;32m$1" || out "\033[0;34m$1" ) || out "$1"; pr_off; }    # not yet used
pr_liteblueln() { pr_liteblue "$1"; outln; }
pr_blue()       { [[ "$COLOR" -eq 2 ]] && ( "$COLORBLIND" && out "\033[1;32m$1" || out "\033[1;34m$1" ) || out "$1"; pr_off; }    # used for head lines of single tests
pr_blueln()     { pr_blue "$1"; outln; }

pr_warning()   { [[ "$COLOR" -eq 2 ]] && out "\033[0;35m$1" || pr_underline "$1"; pr_off; }                                  # some local problem: one test cannot be done
pr_warningln() { pr_warning "$1"; outln; }                                                                                   # litemagenta
pr_magenta()   { [[ "$COLOR" -eq 2 ]] && out "\033[1;35m$1" || pr_underline "$1"; pr_off; }                                  # fatal error: quitting because of this!
pr_magentaln() { pr_magenta "$1"; outln; }

pr_litecyan()   { [[ "$COLOR" -eq 2 ]] && out "\033[0;36m$1" || out "$1"; pr_off; }                                          # not yet used
pr_litecyanln() { pr_litecyan "$1"; outln; }
pr_cyan()       { [[ "$COLOR" -eq 2 ]] && out "\033[1;36m$1" || out "$1"; pr_off; }                                          # additional hint
pr_cyanln()     { pr_cyan "$1"; outln; }

pr_litegreyln() { pr_litegrey "$1"; outln; }                                                                                 # not really usable on a black background, see ..
pr_litegrey()   { [[ "$COLOR" -eq 2 ]] && out "\033[0;37m$1" || out "$1"; pr_off; }                                          # ... https://github.com/drwetter/testssl.sh/pull/600#issuecomment-276129876
pr_grey()       { [[ "$COLOR" -eq 2 ]] && out "\033[1;30m$1" || out "$1"; pr_off; }
pr_greyln()     { pr_grey "$1"; outln; }

pr_done_good()   { [[ "$COLOR" -eq 2 ]] && ( "$COLORBLIND" && out "\033[0;34m$1" || out "\033[0;32m$1" ) || out "$1"; pr_off; }   # litegreen (liteblue), This is good
pr_done_goodln() { pr_done_good "$1"; outln; }
pr_done_best()   { [[ "$COLOR" -eq 2 ]] && ( "$COLORBLIND" && out "\033[1;34m$1" || out "\033[1;32m$1" ) ||  out "$1"; pr_off; }  # green (blue), This is the best
pr_done_bestln() { pr_done_best "$1"; outln; }

pr_svrty_low()       { [[ "$COLOR" -eq 2 ]] && out "\033[1;33m$1" || out "$1"; pr_off; }                   # yellow brown | academic or minor problem
pr_svrty_lowln()     { pr_svrty_low "$1"; outln; }
pr_svrty_medium()    { [[ "$COLOR" -eq 2 ]] && out "\033[0;33m$1" || out "$1"; pr_off; }                   # brown | it is not a bad problem but you shouldn't do this
pr_svrty_mediumln()  { pr_svrty_medium "$1"; outln; }

pr_svrty_high()      { [[ "$COLOR" -eq 2 ]] && out "\033[0;31m$1" || pr_bold "$1"; pr_off; }               # litered
pr_svrty_highln()    { pr_svrty_high "$1"; outln; }
pr_svrty_critical()  { [[ "$COLOR" -eq 2 ]] && out "\033[1;31m$1" || pr_bold "$1"; pr_off; }               # red
pr_svrty_criticalln(){ pr_svrty_critical "$1"; outln; }

pr_deemphasize()     { out "$1"; }                                                                         # hook for a weakened screen output, see #600
pr_deemphasizeln()   { outln "$1"; }

# color=1 functions
pr_off()          { [[ "$COLOR" -ne 0 ]] && out "\033[m"; }
pr_bold()         { [[ "$COLOR" -ne 0 ]] && out "\033[1m$1" || out "$1"; pr_off; }
pr_boldln()       { pr_bold "$1" ; outln; }
pr_italic()       { [[ "$COLOR" -ne 0 ]] && out "\033[3m$1" || out "$1"; pr_off; }
pr_italicln()     { pr_italic "$1" ; outln; }
pr_strikethru()   { [[ "$COLOR" -ne 0 ]] && out "\033[9m$1" || out "$1"; pr_off; }                          # ugly!
pr_strikethruln() { pr_strikethru "$1" ; outln; }
pr_underline()    { [[ "$COLOR" -ne 0 ]] && out "\033[4m$1" || out "$1"; pr_off; }
pr_underlineln()  { pr_underline "$1"; outln; }
pr_reverse()      { [[ "$COLOR" -ne 0 ]] && out "\033[7m$1" || out "$1"; pr_off; }
pr_reverse_bold() { [[ "$COLOR" -ne 0 ]] && out "\033[7m\033[1m$1" || out "$1"; pr_off; }

#pr_headline() { pr_blue "$1"; }
#http://misc.flogisoft.com/bash/tip_colors_and_formatting

#pr_headline() { [[ "$COLOR" -eq 2 ]] && out "\033[1;30m\033[47m$1" || out "$1"; pr_off; }
pr_headline() { [[ "$COLOR" -ne 0 ]] && out "\033[1m\033[4m$1" || out "$1"; pr_off; }
pr_headlineln() { pr_headline "$1" ; outln; }

pr_squoted() { out "'$1'"; }
pr_dquoted() { out "\"$1\""; }

local_problem() { pr_warning "Local problem: $1"; }
local_problem_ln() { pr_warningln "Local problem: $1"; }

fixme() { pr_warning "fixme: $1"; }
fixmeln() { pr_warningln "fixme: $1"; }

### color switcher (see e.g. https://linuxtidbits.wordpress.com/2008/08/11/output-color-on-bash-scripts/
###                         http://www.tldp.org/HOWTO/Bash-Prompt-HOWTO/x405.html
set_color_functions() {
     local ncurses_tput=true

     # empty vars if we have COLOR=0 equals no escape code:
     red=""
     green=""
     brown=""
     blue=""
     magenta=""
     cyan=""
     grey=""
     yellow=""
     off=""
     bold=""
     underline=""
     italic=""

     which tput &>/dev/null || return 0      # Hey wait, do we actually have tput / ncurses ?
     tput cols &>/dev/null || return 0       # tput under BSDs and GNUs doesn't work either (TERM undefined?)
     tput sgr0 &>/dev/null || ncurses_tput=false
     if [[ "$COLOR" -eq 2 ]]; then
          if $ncurses_tput; then
               red=$(tput setaf 1)
               green=$(tput setaf 2)
               brown=$(tput setaf 3)
               blue=$(tput setaf 4)
               magenta=$(tput setaf 5)
               cyan=$(tput setaf 6)
               grey=$(tput setaf 7)
               yellow=$(tput setaf 3; tput bold)
          else      # this is a try for old BSD, see terminfo(5)
               red=$(tput AF 1)
               green=$(tput AF 2)
               brown=$(tput AF 3)
               blue=$(tput AF 4)
               magenta=$(tput AF 5)
               cyan=$(tput AF 6)
               grey=$(tput AF 7)
               yellow=$(tput AF 3; tput md)
          fi
     fi

     if [[ "$COLOR" -ge 1 ]]; then
          if $ncurses_tput; then
               bold=$(tput bold)
               underline=$(tput sgr 0 1)
               italic=$(tput sitm)
               italic_end=$(tput ritm)
               off=$(tput sgr0)
          else      # this is a try for old BSD, see terminfo(5)
               bold=$(tput md)
               underline=$(tput us)
               italic=$(tput ZH)        # that doesn't work on FreeBSD 9+10.x
               italic_end=$(tput ZR)    # here too. Probably entry missing in /etc/termcap
               reverse=$(tput mr)
               off=$(tput me)
          fi
     fi
}

strip_quote() {
     # remove color codes (see http://www.commandlinefu.com/commands/view/3584/remove-color-codes-special-characters-with-sed)
     #  \', leading and all trailing spaces
     sed -e "s,$(echo -e "\033")\[[0-9;]*[a-zA-Z],,g" \
          -e "s/\"/\\'/g" \
          -e 's/^ *//g' \
          -e 's/ *$//g' <<< "$1"
}

#################### JSON FILE FORMATING ####################
fileout_pretty_json_header() {
    START_TIME=$(date +%s)
    target="$NODE"
    $do_mx_all_ips && target="$URI"

    echo -e "          \"Invocation\"  : \"$PROG_NAME $CMDLINE\",
          \"at\"          : \"$HNAME:$OPENSSL_LOCATION\",
          \"version\"     : \"$VERSION ${GIT_REL_SHORT:-$CVS_REL_SHORT} from $REL_DATE\",
          \"openssl\"     : \"$OSSL_VER from $OSSL_BUILD_DATE\",
          \"target host\" : \"$target\",
          \"port\"        : \"$PORT\",
          \"startTime\"   : \"$START_TIME\",
          \"scanResult\"  : ["
}

fileout_pretty_json_footer() {
    local scan_time=$((END_TIME - START_TIME))
    echo -e "          ],
          \"scanTime\"  : \"$scan_time\"\n}"
}

fileout_json_header() {
     "$do_json" && printf "[\n" > "$JSONFILE"
     "$do_pretty_json" && (printf "{\n%s\n" "$(fileout_pretty_json_header)") > "$JSONFILE"
}

fileout_json_footer() {
     "$do_json" && printf "]\n" >> "$JSONFILE"
     "$do_pretty_json" && (printf "$(fileout_pretty_json_footer)") >> "$JSONFILE"
}

fileout_json_section() {
    case $1 in
    1)
        echo -e    "                    \"protocols\"         : ["
        ;;
    2)
        echo -e ",\n                    \"ciphers\"           : ["
        ;;
    3)
        echo -e ",\n                    \"pfs\"               : ["
        ;;
    4)
        echo -e ",\n                    \"serverPreferences\" : ["
        ;;
    5)
        echo -e ",\n                    \"serverDefaults\"    : ["
        ;;
    6)
        echo -e ",\n                    \"headerResponse\"    : ["
        ;;
    7)
        echo -e ",\n                    \"vulnerabilities\"   : ["
        ;;
    8)
        echo -e ",\n                    \"cipherTests\"       : ["
        ;;
    9)
        echo -e ",\n                    \"browserSimulations\": ["
        ;;
    *)
        echo "invalid section"
        ;;
    esac
}

fileout_section_header(){
    local str=""
    $2 && str="$(fileout_section_footer false)"
    "$do_pretty_json" && FIRST_FINDING=true && (printf "%s%s\n" "$str" "$(fileout_json_section "$1")") >> "$JSONFILE"
}

fileout_section_footer() { # IS_THE_LAST_ONE
    "$do_pretty_json" && printf "\n                    ]" >> "$JSONFILE"
    "$do_pretty_json" && $1 && echo -e "\n          }" >> "$JSONFILE"
}

fileout_json_print_parameter() {
    local parameter="$1"
    local filler="$2"
    local value="$3"
    local not_last="$4"

    local shift=""

    if "$do_json"; then
        shift="              "
    else
        shift="                                "
    fi

    if [[ ! -z "$value" ]]; then
        printf "%s%s%s%s" "$shift" "\"$parameter\"" "$filler" ": \"$value\"" >> "$JSONFILE"
        "$not_last" && printf ",\n" >> "$JSONFILE"
    fi
}

fileout_json_finding() {
    if "$do_json"; then
         "$FIRST_FINDING" || echo -n "," >> "$JSONFILE"
         echo -e "        {"  >> "$JSONFILE"
         fileout_json_print_parameter "id" "           " "$1" true
         fileout_json_print_parameter "ip" "           " "$NODE/$NODEIP" true
         fileout_json_print_parameter "port" "         " "$PORT" true
         fileout_json_print_parameter "severity" "     " "$2" true
         fileout_json_print_parameter "cve" "          " "$cve" true
         fileout_json_print_parameter "cwe" "          " "$cwe" true
         "$GIVE_HINTS" && fileout_json_print_parameter "hint" "         " "$hint" true
         fileout_json_print_parameter "finding" "      " "$finding" false
         echo -e "\n         }" >> "$JSONFILE"
    fi
    if "$do_pretty_json"; then
        if [[ "$1" == "service" ]]; then
            if [[ $SERVER_COUNTER -gt 1 ]]; then
                echo "          ," >> "$JSONFILE"
            fi
            echo -e "          {
                    \"service\"         : \"$finding\",
                    \"ip\"              : \"$NODEIP\","  >> "$JSONFILE"
            $do_mx_all_ips && echo -e "                    \"hostname\"        : \"$NODE\","  >> "$JSONFILE"
        else
            ("$FIRST_FINDING" && echo -n "                            {" >> "$JSONFILE") || echo -n ",{" >> "$JSONFILE"
            echo -e -n "\n"  >> "$JSONFILE"
            fileout_json_print_parameter "id" "           " "$1" true
            fileout_json_print_parameter "severity" "     " "$2" true
            fileout_json_print_parameter "cve" "          " "$cve" true
            fileout_json_print_parameter "cwe" "          " "$cwe" true
            "$GIVE_HINTS" && fileout_json_print_parameter "hint" "         " "$hint" true
            fileout_json_print_parameter "finding" "      " "$finding" false
            echo -e -n "\n                           }" >> "$JSONFILE"
        fi
    fi
}

is_json_format() {
    ([[ -f "$JSONFILE" ]] && ("$do_json" || "$do_pretty_json"))
}

################# JSON FILE FORMATING END ####################

##################### FILE FORMATING #########################
fileout_header() {
     if "$APPEND"; then
          if [[ -f "$JSONFILE" ]]; then
               FIRST_FINDING=false # We need to insert a comma, because there is file content already
          else
               fileout_json_header
          fi
          if "$do_csv"; then
               if [[ -f "$CSVFILE" ]]; then
                    # add lf, just for overview
                    echo >> "$CSVFILE"
               else
                    # create file, with headline
                    echo "\"id\",\"fqdn/ip\",\"port\",\"severity\",\"finding\",\"cve\",\"cwe\",\"hint\"" > "$CSVFILE"
               fi
          fi
     else
          fileout_json_header
          "$do_csv" && echo "\"id\",\"fqdn/ip\",\"port\",\"severity\",\"finding\",\"cve\",\"cwe\",\"hint\"" > "$CSVFILE"
     fi
}

fileout_footer() {
     is_json_format && fileout_json_footer
}

fileout() { # ID, SEVERITY, FINDING, CVE, CWE, HINT
     local severity="$2"
     local cwe="$5"
     local hint="$6"

     if show_finding "$severity"; then
         local finding=$(strip_lf "$(newline_to_spaces "$(strip_quote "$3")")")

         is_json_format && (fileout_json_finding "$1" "$severity" "$finding" "$cve" "$cwe" "$hint")

         # does the following do any sanitization?
         if "$do_csv"; then
              echo -e \""$1\"",\"$NODE/$NODEIP\",\"$PORT"\",\""$severity"\",\""$finding"\",\""$cve"\",\""$cwe"\",\""$hint"\"" >> "$CSVFILE"
         fi
         "$FIRST_FINDING" && FIRST_FINDING=false
     fi
}
################### FILE FORMATING END #########################

###### helper function definitions ######

if [[ $(uname) == "Linux" ]] ; then
     toupper() { echo -n "${1^^}" ;  }
     tolower() { echo -n "${1,,}" ;  }
else
     toupper() { echo -n "$1" | tr 'a-z' 'A-Z'; }
     tolower() { echo -n "$1" | tr 'A-Z' 'a-z' ; }
fi

debugme() {
     [[ "$DEBUG" -ge 2 ]] && "$@"
     return 0
}

hex2dec() {
     #/usr/bin/printf -- "%d" 0x"$1"
     echo $((16#$1))
}

# convert 414243 into ABC
hex2ascii() {
          for (( i=0; i<${#1}; i+=2 )); do
               printf "\x${1:$i:2}"
          done
}

# trim spaces for BSD and old sed
count_lines() {
     #echo "${$(wc -l <<< "$1")// /}"
     # ^^ bad substitution under bash, zsh ok. For some reason this does the trick:
     echo $(wc -l <<< "$1")
}

count_words() {
     #echo "${$(wc -w <<< "$1")// /}"
     # ^^ bad substitution under bash, zsh ok. For some reason this does the trick:
     echo $(wc -w <<< "$1")
}

count_ciphers() {
     echo -n "$1" | sed 's/:/ /g' | wc -w | sed 's/ //g'
}

actually_supported_ciphers() {
     $OPENSSL ciphers "$1" 2>/dev/null || echo ""
}

newline_to_spaces() {
     tr '\n' ' ' <<< "$1" | sed 's/ $//'
}

colon_to_spaces() {
     echo "${1//:/ }"
}

strip_lf() {
     tr -d '\n' <<< "$1" | tr -d '\r'
}

strip_spaces() {
     echo "${1// /}"
}

trim_trailing_space() {
     echo "${1%%*( )}"
}

# prints out multiple lines in $1, left aligned by spaces in $2
out_row_aligned() {
     local first=true

     echo "$1" | while read line; do
          "$first" && \
               first=false || \
               out "$2"
          outln "$line"
     done
}

# prints text over multiple lines, trying to make no line longer than $max_width.
# Each line is indented with $spaces and each word in $text is printed using
# $print_function.
out_row_aligned_max_width() {
     local text="$1"
     local spaces="$2"
     local -i max_width="$3"
     local print_function="$4"
     local -i i len cut_point
     local cr=$'\n'
     local line entry first=true last=false

     max_width=$max_width-1                  # at the moment we align to terminal width. This makes sure we don't wrap too late
     max_width=$max_width-${#spaces}
     len=${#text}
     while true; do
          i=$max_width
          if [[ $i -ge $len ]]; then
               i=$len
          else
               while true; do
                    [[ "${text:i:1}" == " " ]] && break
                    [[ $i -eq 0 ]] && break
                    i=$i-1
               done
               if [[ $i -eq 0 ]]; then
                    i=$max_width+1
                    while true; do
                         [[ "${text:i:1}" == " " ]] && break
                         [[ $i -eq $len ]] && break
                         i+=1
                    done
               fi
          fi
          if [[ $i -eq $len ]]; then
               line="$text"
               if ! "$first"; then
                    out "${cr}${spaces}"
               fi
               last=true
          else
               line="${text:0:i}"
               if ! "$first"; then
                    out "${cr}${spaces}"
               fi
               len=$len-$i-1
               i=$i+1
               text="${text:i:len}"
               first=false
               [[ $len -eq 0 ]] && last=true
          fi
          while read entry; do
              $print_function "$entry" ; out " "
          done <<< "$(tr ' ' '\n' <<< "$line")"
          "$last" && break
     done
     return 0
}

is_number() {
     [[ "$1" =~ ^[1-9][0-9]*$ ]] && \
          return 0 || \
          return 1
}

is_ipv4addr() {
     local octet="(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])"
     local ipv4address="$octet\\.$octet\\.$octet\\.$octet"

     [[ -z "$1" ]] && return 1
     # more than numbers, important for hosts like AAA.BBB.CCC.DDD.in-addr.arpa.DOMAIN.TLS
     [[ -n $(tr -d '0-9\.' <<< "$1") ]] && return 1

     echo -n "$1" | grep -Eq "$ipv4address" && \
          return 0 || \
          return 1
}

# a bit easier
is_ipv6addr() {
     [[ -z "$1" ]] && return 1
     # less than 2x ":"
     [[ $(count_lines "$(echo -n "$1" | tr ':' '\n')") -le 1 ]] && \
          return 1
     #check on chars allowed:
     [[ -n "$(tr -d '0-9:a-fA-F ' <<< "$1" | sed -e '/^$/d')" ]] && \
          return 1
     return 0
}


tmpfile_handle() {
     mv $TMPFILE "$TEMPDIR/$NODEIP.$1" 2>/dev/null
     [[ $ERRFILE =~ dev.null ]] && return 0 || \
          mv $ERRFILE "$TEMPDIR/$NODEIP.$(sed 's/\.txt//g' <<<"$1").errorlog" 2>/dev/null
}

# arg1: line with comment sign, tabs and so on
filter_input() {
     echo "$1" | sed -e 's/#.*$//' -e '/^$/d' | tr -d '\n' | tr -d '\t'
}

# dl's any URL (argv1) via HTTP 1.1 GET from port 80, arg2: file to store http body
# proxy is not honored (see cmd line switches)
http_get() {
     local proto z
     local node="" query=""
     local dl="$2"
     local useragent="$UA_STD"

     "$SNEAKY" && useragent="$UA_SNEAKY"

	IFS=/ read proto z node query <<< "$1"

	exec 33<>/dev/tcp/$node/80
	printf "GET /$query HTTP/1.1\r\nHost: $node\r\nUser-Agent: $useragent\r\nConnection: Close\r\nAccept: */*\r\n\r\n" >&33
	cat <&33 | \
		tr -d '\r' | sed '1,/^$/d' >$dl
	# HTTP header stripped now, closing fd:
     exec 33<&-
     [[ -s "$2" ]] && return 0 || return 1
}
# example usage:
# myfile=$(mktemp $TEMPDIR/http_get.XXXXXX.txt)
# http_get "http://crl.startssl.com/sca-server1.crl" "$myfile"


wait_kill(){
     local pid=$1             # pid we wait for or kill
     local maxsleep=$2        # how long we wait before killing

     HAD_SLEPT=0
     while true; do
          if ! ps $pid >/dev/null ; then
               return 0       # process terminated before didn't reach $maxsleep
          fi
          [[ "$DEBUG" -ge 6 ]] && ps $pid
          sleep 1
          maxsleep=$((maxsleep - 1))
          HAD_SLEPT=$((HAD_SLEPT + 1))
          test $maxsleep -le 0 && break
     done                     # needs to be killed:
     kill $pid >&2 2>/dev/null
     wait $pid 2>/dev/null    # make sure pid terminated, see wait(1p)
     return 3                 # means killed
}

# parse_date date format input-format
if "$HAS_GNUDATE"; then  # Linux and NetBSD
	parse_date() {
		LC_ALL=C date -d "$1" "$2"
	}
elif "$HAS_FREEBSDDATE"; then # FreeBSD and OS X
	parse_date() {
		LC_ALL=C date -j -f "$3"  "$2" "$1"
	}
else
	parse_date() {
		LC_ALL=C date -j "$2" "$1"
	}
fi

# arg1: An ASCII-HEX string
# arg2: file name
# Append $arg1 in binary format to $arg2
asciihex_to_binary_file(){
     local string="$1"
     local file="$2"
     local -i len
     local -i i ip2 ip4 ip6 ip8 ip10 ip12 ip14
     local -i remainder

     len=${#string}
     [[ $len%2 -ne 0 ]] && return 1

     for (( i=0; i <= len-16 ; i=i+16 )); do
          ip2=$i+2; ip4=$i+4; ip6=$i+6; ip8=$i+8; ip10=$i+10; ip12=$i+12; ip14=$i+14
          printf -- "\x${string:i:2}\x${string:ip2:2}\x${string:ip4:2}\x${string:ip6:2}\x${string:ip8:2}\x${string:ip10:2}\x${string:ip12:2}\x${string:ip14:2}" >> "$file"
     done

     ip2=$i+2; ip4=$i+4; ip6=$i+6; ip8=$i+8; ip10=$i+10; ip12=$i+12; ip14=$i+14
     remainder=$len-$i
     case $remainder in
           2) printf -- "\x${string:i:2}" >> "$file" ;;
           4) printf -- "\x${string:i:2}\x${string:ip2:2}" >> "$file" ;;
           6) printf -- "\x${string:i:2}\x${string:ip2:2}\x${string:ip4:2}" >> "$file" ;;
           8) printf -- "\x${string:i:2}\x${string:ip2:2}\x${string:ip4:2}\x${string:ip6:2}" >> "$file" ;;
          10) printf -- "\x${string:i:2}\x${string:ip2:2}\x${string:ip4:2}\x${string:ip6:2}\x${string:ip8:2}" >> "$file" ;;
          12) printf -- "\x${string:i:2}\x${string:ip2:2}\x${string:ip4:2}\x${string:ip6:2}\x${string:ip8:2}\x${string:ip10:2}" >> "$file" ;;
          14) printf -- "\x${string:i:2}\x${string:ip2:2}\x${string:ip4:2}\x${string:ip6:2}\x${string:ip8:2}\x${string:ip10:2}\x${string:ip12:2}" >> "$file" ;;
     esac
     return 0
}

# arg1: text string
# Output a comma-separated ASCII-HEX string resprestation of the input string.
string_to_asciihex() {
     local string="$1"
     local -i i eos
     local output=""

     eos=${#string}-1
     for (( i=0; i<eos; i++ )); do
          output+="$(printf "%02x," "'${string:i:1}")"
     done
     [[ -n "$string" ]] && output+="$(printf "%02x" "'${string:eos:1}")"
     out "$output"
     return 0

}

###### check code starts here ######

# determines whether the port has an HTTP service running or not (plain TLS, no STARTTLS)
# arg1 could be the protocol determined as "working". IIS6 needs that
service_detection() {
     local -i ret=0
     local -i was_killed
     local addcmd=""

     if ! $CLIENT_AUTH; then
          # SNI is nonsense for !HTTPS but fortunately for other protocols s_client doesn't seem to care
          [[ ! "$1" =~ ssl ]] && addcmd="$SNI"
          printf "$GET_REQ11" | $OPENSSL s_client $1 -quiet $BUGS -connect $NODEIP:$PORT $PROXY $addcmd >$TMPFILE 2>$ERRFILE &
          wait_kill $! $HEADER_MAXSLEEP
          was_killed=$?
          head $TMPFILE | grep -aq ^HTTP && SERVICE=HTTP
          head $TMPFILE | grep -aq SMTP && SERVICE=SMTP
          head $TMPFILE | grep -aq POP && SERVICE=POP
          head $TMPFILE | grep -aq IMAP && SERVICE=IMAP
          head $TMPFILE | egrep -aqw "Jive News|InterNetNews|NNRP|INN" && SERVICE=NNTP
          debugme head -50 $TMPFILE
     fi
# FIXME: we can guess ports by port number if not properly recognized (and label it as guessed)

     out " Service detected:      $CORRECT_SPACES"
     case $SERVICE in
          HTTP)
               out " $SERVICE"
               fileout "service" "INFO" "Service detected: $SERVICE"
               ret=0 ;;
          IMAP|POP|SMTP|NNTP)
               out " $SERVICE, thus skipping HTTP specific checks"
               fileout "service" "INFO" "Service detected: $SERVICE, thus skipping HTTP specific checks"
               ret=0 ;;
          *)   if $CLIENT_AUTH; then
                    out "certificate based authentication => skipping all HTTP checks"
                    echo "certificate based authentication => skipping all HTTP checks" >$TMPFILE
                    fileout "client_auth" "INFO" "certificate based authentication => skipping all HTTP checks"
               else
                    out " Couldn't determine what's running on port $PORT"
                    if "$ASSUME_HTTP"; then
                         SERVICE=HTTP
                         out " -- ASSUME_HTTP set though"
                         fileout "service" "DEBUG" "Couldn't determine service, --ASSUME_HTTP set"
                         ret=0
                    else
                         out ", assuming no HTTP service => skipping all HTTP checks"
                         fileout "service" "DEBUG" "Couldn't determine service, skipping all HTTP checks"
                         ret=1
                    fi
               fi
               ;;
     esac

     outln "\n"
     tmpfile_handle $FUNCNAME.txt
     return $ret
}


#problems not handled: chunked
run_http_header() {
     local header addcmd=""
     local -i ret
     local referer useragent
     local url redirect

     HEADERFILE=$TEMPDIR/$NODEIP.http_header.txt
     outln; pr_headlineln " Testing HTTP header response @ \"$URL_PATH\" "
     outln

     [[ -z "$1" ]] && url="/" || url="$1"
     [[ ! "$OPTIMAL_PROTO" =~ ssl ]] && addcmd="$SNI"
     printf "$GET_REQ11" | $OPENSSL s_client $OPTIMAL_PROTO $BUGS -quiet -ign_eof -connect $NODEIP:$PORT $PROXY $addcmd >$HEADERFILE 2>$ERRFILE &
     wait_kill $! $HEADER_MAXSLEEP
     if [[ $? -eq 0 ]]; then
          # we do the get command again as it terminated within $HEADER_MAXSLEEP. Thus it didn't hang, we do it
          # again in the foreground to get an accurate header time!
          printf "$GET_REQ11" | $OPENSSL s_client $OPTIMAL_PROTO $BUGS -quiet -ign_eof -connect $NODEIP:$PORT $PROXY $addcmd >$HEADERFILE 2>$ERRFILE
          NOW_TIME=$(date "+%s")
          HTTP_TIME=$(awk -F': ' '/^date:/ { print $2 }  /^Date:/ { print $2 }' $HEADERFILE)
          HAD_SLEPT=0
     else
          # GET request needed to be killed before, try, whether it succeeded:
          if egrep -iaq "XML|HTML|DOCTYPE|HTTP|Connection" $HEADERFILE; then
               NOW_TIME=$(($(date "+%s") - HAD_SLEPT))         # correct by seconds we slept
               HTTP_TIME=$(awk -F': ' '/^date:/ { print $2 }  /^Date:/ { print $2 }' $HEADERFILE)
          else
               pr_warning " likely HTTP header requests failed (#lines: $(wc -l < $HEADERFILE | sed 's/ //g'))."
               outln "Rerun with DEBUG=1 and inspect \"run_http_header.txt\"\n"
               debugme cat $HEADERFILE
               return 7
          fi
     fi
     # populate vars for HTTP time

     debugme echo "$NOW_TIME: $HTTP_TIME"

     # delete from pattern til the end. We ignore any leading spaces (e.g. www.amazon.de)
     sed  -e '/<HTML>/,$d' -e '/<html>/,$d' -e '/<XML/,$d' -e '/<?XML/,$d' \
          -e '/<xml/,$d' -e '/<?xml/,$d'  -e '/<\!DOCTYPE/,$d' -e '/<\!doctype/,$d' $HEADERFILE >$HEADERFILE.2
#### ^^^ Attention: the filtering for the html body only as of now, doesn't work for other content yet
     mv $HEADERFILE.2  $HEADERFILE  # sed'ing in place doesn't work with BSD and Linux simultaneously
     ret=0

     HTTP_STATUS_CODE=$(awk '/^HTTP\// { print $2 }' $HEADERFILE 2>>$ERRFILE)
     msg_thereafter=$(awk -F"$HTTP_STATUS_CODE" '/^HTTP\// { print $2 }' $HEADERFILE 2>>$ERRFILE)   # dirty trick to use the status code as a
     msg_thereafter=$(strip_lf "$msg_thereafter")                                    # field separator, otherwise we need a loop with awk
     debugme echo "Status/MSG: $HTTP_STATUS_CODE $msg_thereafter"

     pr_bold " HTTP Status Code           "
     [[ -z "$HTTP_STATUS_CODE" ]] && pr_cyan "No status code" && return 3

     out "  $HTTP_STATUS_CODE$msg_thereafter"
     case $HTTP_STATUS_CODE in
          301|302|307|308)
               redirect=$(grep -a '^Location' $HEADERFILE | sed 's/Location: //' | tr -d '\r\n')
               out ", redirecting to \"$redirect\""
               if [[ $redirect == "http://"* ]]; then
                    pr_svrty_high " -- Redirect to insecure URL (NOT ok)"
                    fileout "HTTP_STATUS_CODE" "HIGH" \, "Redirect to insecure URL. Url: \"$redirect\""
               fi
               fileout "HTTP_STATUS_CODE" "INFO" \
                    "Testing HTTP header response @ \"$URL_PATH\", $HTTP_STATUS_CODE$msg_thereafter, redirecting to \"$redirect\""
               ;;
          200)
               fileout "HTTP_STATUS_CODE" "INFO" \
                    "Testing HTTP header response @ \"$URL_PATH\", $HTTP_STATUS_CODE$msg_thereafter"
               ;;
          204)
               fileout "HTTP_STATUS_CODE" "INFO" \
                    "Testing HTTP header response @ \"$URL_PATH\", $HTTP_STATUS_CODE$msg_thereafter"
               ;;
          206)
               out " -- WTF?"
               fileout "HTTP_STATUS_CODE" "INFO" \
                    "Testing HTTP header response @ \"$URL_PATH\", $HTTP_STATUS_CODE$msg_thereafter -- WTF?"
               ;;
          400)
               pr_cyan " (Hint: better try another URL)"
               fileout "HTTP_STATUS_CODE" "INFO" \
                    "Testing HTTP header response @ \"$URL_PATH\", $HTTP_STATUS_CODE$msg_thereafter (Hint: better try another URL)"
               ;;
          401)
               grep -aq "^WWW-Authenticate" $HEADERFILE && out "  "; strip_lf "$(grep -a "^WWW-Authenticate" $HEADERFILE)"
               fileout "HTTP_STATUS_CODE" "INFO" \
                    "Testing HTTP header response @ \"$URL_PATH\", $HTTP_STATUS_CODE$msg_thereafter $(grep -a "^WWW-Authenticate" $HEADERFILE)"
               ;;
          403)
               fileout "HTTP_STATUS_CODE" "INFO" \
                    "Testing HTTP header response @ \"$URL_PATH\", $HTTP_STATUS_CODE$msg_thereafter"
               ;;
          404)
               out " (Hint: supply a path which doesn't give a \"$HTTP_STATUS_CODE$msg_thereafter\")"
               fileout "HTTP_STATUS_CODE" "INFO" \
                    "Testing HTTP header response @ \"$URL_PATH\", $HTTP_STATUS_CODE$msg_thereafter (Hint: supply a path which doesn't give a \"$HTTP_STATUS_CODE$msg_thereafter\")"
               ;;
          405)
               fileout "HTTP_STATUS_CODE" "INFO" \
                    "Testing HTTP header response @ \"$URL_PATH\", $HTTP_STATUS_CODE$msg_thereafter"
               ;;
          *)
               pr_warning ". Oh, didn't expect \"$HTTP_STATUS_CODE$msg_thereafter\""
               fileout "HTTP_STATUS_CODE" "DEBUG" \
                    "Testing HTTP header response @ \"$URL_PATH\", $HTTP_STATUS_CODE$msg_thereafter. Oh, didn't expect a $HTTP_STATUS_CODE$msg_thereafter"
               ;;
     esac
     outln

     # we don't call "tmpfile_handle $FUNCNAME.txt" as we need the header file in other functions!
     return $ret
}

# Borrowed from Glenn Jackman, see https://unix.stackexchange.com/users/4667/glenn-jackman
detect_ipv4() {
     local octet="(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])"
     local ipv4address="$octet\\.$octet\\.$octet\\.$octet"
     local whitelisted_header="pagespeed|page-speed|^Content-Security-Policy|^MicrosoftSharePointTeamServices|^X-OWA-Version"
     local your_ip_msg="(check if it's your IP address or e.g. a cluster IP)"
     local result
     local first=true
     local spaces="                              "
     local count

     if [[ ! -s $HEADERFILE ]]; then
          run_http_header "$1" || return 3
     fi

     # white list some headers as they are mistakenly identified as ipv4 address. Issues 158, 323,o facebook has a CSP rule for 127.0.0.1
     if egrep -vi "$whitelisted_header" $HEADERFILE | grep -iqE "$ipv4address"; then
          pr_bold " IPv4 address in header       "
          count=0
          while read line; do
               result="$(grep -E "$ipv4address" <<< "$line")"
               result=$(strip_lf "$result")
               if [[ -n "$result" ]]; then
                    if ! $first; then
                         out "$spaces"
                         your_ip_msg=""
                    else
                         first=false
                    fi
                    pr_svrty_high "$result"
                    outln "\n$spaces$your_ip_msg"
                    fileout "ip_in_header_$count" "HIGH" "IPv4 address in header  $result $your_ip_msg"
               fi
               count=$count+1
          done < $HEADERFILE
     fi
}


run_http_date() {
     local now difftime

     if [[ ! -s $HEADERFILE ]]; then
          run_http_header "$1" || return 3        # this is just for the line "Testing HTTP header response"
     fi
     pr_bold " HTTP clock skew              "
     if [[ $SERVICE != "HTTP" ]]; then
          out "not tested as we're not targeting HTTP"
     else
          if [[ -n "$HTTP_TIME" ]]; then
               HTTP_TIME=$(parse_date "$HTTP_TIME" "+%s" "%a, %d %b %Y %T %Z" 2>>$ERRFILE) # the trailing \r confuses BSD flavors otherwise

               difftime=$((HTTP_TIME - $NOW_TIME))
               [[ $difftime != "-"* ]] && [[ $difftime != "0" ]] && difftime="+$difftime"
               # process was killed, so we need to add an error:
               [[ $HAD_SLEPT -ne 0 ]] && difftime="$difftime (± 1.5)"
               out "$difftime sec from localtime";
               fileout "http_clock_skew" "INFO" "HTTP clock skew $difftime sec from localtime"
          else
               out "Got no HTTP time, maybe try different URL?";
               fileout "http_clock_skew" "INFO" "HTTP clock skew not measured. Got no HTTP time, maybe try different URL?"
          fi
          debugme out ", epoch: $HTTP_TIME"
     fi
     outln
     detect_ipv4
}



# HEADERFILE needs to contain the HTTP header (made sure by invoker)
# arg1: key=word to match
# arg2: hint for fileout()
# returns:
#    0 if header not found
#    1-n nr of headers found, then in HEADERVALUE the first value from key

detect_header() {
     local key="$1"
     local -i nr=0

     nr=$(grep -Faciw "$key:" $HEADERFILE)
     if [[ $nr -eq 0 ]]; then
          HEADERVALUE=""
          return 0
     elif [[ $nr -eq 1 ]]; then
          HEADERVALUE=$(grep -Faiw "$key:" $HEADERFILE | sed 's/^.*://')
          return 1
     else
          pr_svrty_medium "misconfiguration: "
          pr_italic "$key"
          pr_svrty_medium " ${nr}x"
          out " -- checking first one "
          out "\n$spaces"
          # first awk matches the key, second extracts the from the first line the value, be careful with quotes here!
          HEADERVALUE=$(grep -Faiw "$key:" $HEADERFILE | sed 's/^.*://' | head -1)
          [[ $DEBUG -ge 2 ]] && pr_italic "$HEADERVALUE" && out "\n$spaces"
          fileout "$2""_multiple" "WARN" "Multiple $2 headers. Using first header: $HEADERVALUE"
          return $nr
     fi
}
# wir brauchen hier eine Funktion, die generell den Header detectiert


includeSubDomains() {
     if grep -aiqw includeSubDomains "$1"; then
          pr_done_good ", includeSubDomains"
          return 0
     else
          pr_litecyan ", just this domain"
          return 1
     fi
}

preload() {
     if grep -aiqw preload "$1"; then
          pr_done_good ", preload"
          return 0
     else
          return 1
     fi
}


run_hsts() {
     local hsts_age_sec
     local hsts_age_days
     local spaces="                              "

     if [[ ! -s $HEADERFILE ]]; then
          run_http_header "$1" || return 3
     fi
     pr_bold " Strict Transport Security    "
     detect_header "Strict-Transport-Security" "HSTS"
     if [[ $? -ne 0 ]]; then
          echo "$HEADERVALUE" >$TMPFILE
          hsts_age_sec=$(sed -e 's/[^0-9]*//g' <<< $HEADERVALUE)
          debugme echo "hsts_age_sec: $hsts_age_sec"
          if [[ -n $hsts_age_sec ]]; then
               hsts_age_days=$(( hsts_age_sec / 86400))
          else
               hsts_age_days=-1
          fi
          if [[ $hsts_age_days -eq -1 ]]; then
               pr_svrty_medium "HSTS max-age is required but missing. Setting 15552000 s (180 days) or more is recommended"
               fileout "hsts_time" "MEDIUM" "HSTS max-age missing. 15552000 s (180 days) or more recommnded"
          elif [[ $hsts_age_sec -eq 0 ]]; then
               pr_svrty_medium "HSTS max-age is set to 0. HSTS is disabled"
               fileout "hsts_time" "MEDIUM" "HSTS max-age set to 0. HSTS is disabled"
          elif [[ $hsts_age_sec -gt $HSTS_MIN ]]; then
               pr_done_good "$hsts_age_days days" ; out "=$hsts_age_sec s"
               fileout "hsts_time" "OK" "HSTS timeout $hsts_age_days days (=$hsts_age_sec seconds) > $HSTS_MIN days"
          else
               pr_svrty_medium "$hsts_age_sec s = $hsts_age_days days is too short ( >=$HSTS_MIN s recommended)"
               fileout "hsts_time" "MEDIUM" "HSTS timeout too short. $hsts_age_days days (=$hsts_age_sec seconds) < $HSTS_MIN days"
          fi
          if includeSubDomains "$TMPFILE"; then
               fileout "hsts_subdomains" "OK" "HSTS includes subdomains"
          else
               fileout "hsts_subdomains" "INFO" "HSTS only for this domain"
          fi
          if preload "$TMPFILE"; then
               fileout "hsts_preload" "OK" "HSTS domain is marked for preloading"
          else
               fileout "hsts_preload" "INFO" "HSTS domain is NOT marked for preloading"
               #FIXME: To be checked against preloading lists,
               # e.g. https://dxr.mozilla.org/mozilla-central/source/security/manager/boot/src/nsSTSPreloadList.inc
               #      https://chromium.googlesource.com/chromium/src/+/master/net/http/transport_security_state_static.json
          fi
     else
          out "--"
          fileout "hsts" "HIGH" "No support for HTTP Strict Transport Security"
     fi
     outln

     tmpfile_handle $FUNCNAME.txt
     return $?
}


run_hpkp() {
     local -i hpkp_age_sec
     local -i hpkp_age_days
     local -i hpkp_nr_keys
     local hpkp_spki hpkp_spki_hostcert
     local -a backup_spki
     local spaces="                             "
     local spaces_indented="                  "
     local certificate_found=false
     local i
     local hpkp_headers
     local first_hpkp_header
     local spki
     local ca_hashes="$TESTSSL_INSTALL_DIR/etc/ca_hashes.txt"

     if [[ ! -s $HEADERFILE ]]; then
          run_http_header "$1" || return 3
     fi
     pr_bold " Public Key Pinning           "
     egrep -aiw '^Public-Key-Pins|Public-Key-Pins-Report-Only' $HEADERFILE >$TMPFILE
     if [[ $? -eq 0 ]]; then
          if egrep -aciw '^Public-Key-Pins|Public-Key-Pins-Report-Only' $HEADERFILE | egrep -waq "1" ; then
               :
          else
               hpkp_headers=""
               pr_svrty_medium "multiple HPKP headers: "
               # https://scotthelme.co.uk is a candidate
               #FIXME: should display both Public-Key-Pins+Public-Key-Pins-Report-Only --> egrep -ai -w
               for i in $(newline_to_spaces "$(egrep -ai '^Public-Key-Pins' $HEADERFILE | awk -F':' '/Public-Key-Pins/ { print $1 }')"); do
                    pr_italic $i
                    hpkp_headers="$hpkp_headers$i "
                    out " "
               done
               out "\n$spaces Examining first one: "
               first_hpkp_header=$(awk -F':' '/Public-Key-Pins/ { print $1 }' $HEADERFILE | head -1)
               pr_italic "$first_hpkp_header, "
               fileout "hpkp_multiple" "WARN" "Multiple HPKP headers $hpkp_headers. Using first header: $first_hpkp_header"
          fi

          # remove leading Public-Key-Pins*, any colons, double quotes and trailing spaces and taking the first -- whatever that is
          sed -e 's/Public-Key-Pins://g' -e s'/Public-Key-Pins-Report-Only://' $TMPFILE | \
               sed -e 's/;//g' -e 's/\"//g' -e 's/^ //' | head -1 > $TMPFILE.2
          # BSD lacks -i, otherwise we would have done it inline
          # now separate key value and other stuff per line:
          tr ' ' '\n' < $TMPFILE.2 >$TMPFILE

          hpkp_nr_keys=$(grep -ac pin-sha $TMPFILE)
          if [[ $hpkp_nr_keys -eq 1 ]]; then
               pr_svrty_high "1 key (NOT ok), "
               fileout "hpkp_spkis" "HIGH" "Only one key pinned in HPKP header, this means the site may become unavailable if the key is revoked"
          else
               pr_done_good "$hpkp_nr_keys"
               out " keys, "
               fileout "hpkp_spkis" "OK" "$hpkp_nr_keys keys pinned in HPKP header, additional keys are available if the current key is revoked"
          fi

          # print key=value pair with awk, then strip non-numbers, to be improved with proper parsing of key-value with awk
          hpkp_age_sec=$(awk -F= '/max-age/{max_age=$2; print max_age}' $TMPFILE | sed -E 's/[^[:digit:]]//g')
          hpkp_age_days=$((hpkp_age_sec / 86400))
          if [[ $hpkp_age_sec -ge $HPKP_MIN ]]; then
               pr_done_good "$hpkp_age_days days" ; out "=$hpkp_age_sec s"
               fileout "hpkp_age" "OK" "HPKP age is set to $hpkp_age_days days ($hpkp_age_sec sec)"
          else
               out "$hpkp_age_sec s = "
               pr_svrty_medium "$hpkp_age_days days (<$HPKP_MIN days is not good enough)"
               fileout "hpkp_age" "MEDIUM" "HPKP age is set to $hpkp_age_days days ($hpkp_age_sec sec) < $HPKP_MIN days is not good enough."
          fi

          if includeSubDomains "$TMPFILE"; then
               fileout "hpkp_subdomains" "INFO" "HPKP header is valid for subdomains as well"
          else
               fileout "hpkp_subdomains" "INFO" "HPKP header is valid for this domain only"
          fi
          if preload "$TMPFILE"; then
               fileout "hpkp_preload" "INFO" "HPKP header is marked for browser preloading"
          else
               fileout "hpkp_preload" "INFO" "HPKP header is NOT marked for browser preloading"
          fi

          # Get the SPKIs first
          spki=$(tr ';' '\n' < $TMPFILE | tr -d ' ' | tr -d '\"' | awk -F'=' '/pin.*=/ { print $2 }')
          debugme outln "\n$spki"

          # Look at the host certificate first
          # get the key fingerprint from the host certificate
          if [[ ! -s "$HOSTCERT" ]]; then
               get_host_cert || return 1
          fi

          hpkp_spki_hostcert="$($OPENSSL x509 -in $HOSTCERT -pubkey -noout | grep -v PUBLIC | \
               $OPENSSL base64 -d | $OPENSSL dgst -sha256 -binary | $OPENSSL base64)"
          hpkp_ca="$($OPENSSL x509 -in $HOSTCERT -issuer -noout|sed 's/^.*CN=//' | sed 's/\/.*$//')"

          # Get keys/hashes from intermediate certificates
          $OPENSSL s_client -showcerts $STARTTLS $BUGS $PROXY -showcerts -connect $NODEIP:$PORT ${sni[i]}  </dev/null >$TMPFILE 2>$ERRFILE
          # Place the server's certificate in $HOSTCERT and any intermediate
          # certificates that were provided in $TEMPDIR/intermediatecerts.pem
          # http://backreference.org/2010/05/09/ocsp-verification-with-openssl/
          awk -v n=-1 "/Certificate chain/ {start=1}
                  /-----BEGIN CERTIFICATE-----/{ if (start) {inc=1; n++} }
                  inc { print > (\"$TEMPDIR/level\" n \".crt\") }
                  /---END CERTIFICATE-----/{ inc=0 }" $TMPFILE
          nrsaved=$(count_words "$(echo $TEMPDIR/level?.crt 2>/dev/null)")
          rm $TEMPDIR/level0.crt 2>/dev/null

          printf ""> "$TEMPDIR/intermediate.hashes"
          if [[ nrsaved -ge 2 ]]; then
               for cert_fname in $TEMPDIR/level?.crt; do
                    hpkp_spki_ca="$($OPENSSL x509 -in "$cert_fname" -pubkey -noout | grep -v PUBLIC | $OPENSSL base64 -d |
                         $OPENSSL dgst -sha256 -binary | $OPENSSL enc -base64)"
                    hpkp_name="$(get_cn_from_cert $cert_fname)"
                    hpkp_ca="$($OPENSSL x509 -in $cert_fname -issuer -noout|sed 's/^.*CN=//' | sed 's/\/.*$//')"
                    [[ -n $hpkp_name ]] || hpkp_name=$($OPENSSL x509 -in "$cert_fname" -subject -noout | sed 's/^subject= //')
                    echo "$hpkp_spki_ca $hpkp_name" >> "$TEMPDIR/intermediate.hashes"
               done
          fi

          # This is where the matching magic starts, first host certificate, intermediate, then root out of the stores
          spki_match=false
          has_backup_spki=false
          i=0
          for hpkp_spki in $spki; do
               certificate_found=false
               # compare collected SPKIs against the host certificate
               if [[ "$hpkp_spki_hostcert" == "$hpkp_spki" ]] || [[ "$hpkp_spki_hostcert" == "$hpkp_spki=" ]]; then
                    certificate_found=true       # We have a match
                    spki_match=true
                    out "\n$spaces_indented Host cert: "
                    pr_done_good "$hpkp_spki"
                    fileout "hpkp_$hpkp_spki" "OK" "SPKI $hpkp_spki matches the host certificate"
               fi
               debugme out "\n  $hpkp_spki | $hpkp_spki_hostcert"

               # Check for intermediate match
               if ! "$certificate_found"; then
                    hpkp_matches=$(grep "$hpkp_spki" $TEMPDIR/intermediate.hashes 2>/dev/null)
                    if [[ -n $hpkp_matches ]]; then    # hpkp_matches + hpkp_spki + '='
                         # We have a match
                         certificate_found=true
                         spki_match=true
                         out "\n$spaces_indented Sub CA:    "
                         pr_done_good "$hpkp_spki"
                         ca_cn="$(sed "s/^[a-zA-Z0-9\+\/]*=* *//" <<< $"$hpkp_matches" )"
                         pr_italic " $ca_cn"
                         fileout "hpkp_$hpkp_spki" "OK" "SPKI $hpkp_spki matches Intermediate CA \"$ca_cn\" pinned in the HPKP header"
                    fi
               fi

               # we compare now against a precompiled list of SPKIs against the ROOT CAs we have in $ca_hashes
               if ! "$certificate_found"; then
                    hpkp_matches=$(grep -h "$hpkp_spki" $ca_hashes 2>/dev/null | sort -u)
                    if [[ -n $hpkp_matches ]]; then
                         certificate_found=true      # root CA found
                         spki_match=true
                         if [[ $(count_lines "$hpkp_matches") -eq 1 ]]; then
                              # replace by awk
                              match_ca=$(sed "s/[a-zA-Z0-9\+\/]*=* *//" <<< "$hpkp_matches")
                         else
                              match_ca=""

                         fi
                         ca_cn="$(sed "s/^[a-zA-Z0-9\+\/]*=* *//" <<< $"$hpkp_matches" )"
                         if [[ "$match_ca" == "$hpkp_ca" ]]; then          # part of the chain
                              out "\n$spaces_indented Root CA:   "
                              pr_done_good "$hpkp_spki"
                              pr_italic " $ca_cn"
                              fileout "hpkp_$hpkp_spki" "INFO" "SPKI $hpkp_spki matches Root CA \"$ca_cn\" pinned in the HPKP header. (Root CA part of the chain)"
                         else                                              # not part of chain
                              match_ca=""
                              has_backup_spki=true                         # Root CA outside the chain --> we save it for unmatched
                              fileout "hpkp_$hpkp_spki" "INFO" "SPKI $hpkp_spki matches Root CA \"$ca_cn\" pinned in the HPKP header. (Root backup SPKI)"
                              backup_spki[i]="$(strip_lf "$hpkp_spki")"    # save it for later
                              backup_spki_str[i]="$ca_cn"                  # also the name=CN of the root CA
                              i=$((i + 1))
                         fi
                    fi
               fi

               # still no success --> it's probably a backup SPKI
               if ! "$certificate_found"; then
                    # Most likely a backup SPKI, unfortunately we can't tell for what it is: host, intermediates
                    has_backup_spki=true
                    backup_spki[i]="$(strip_lf "$hpkp_spki")"     # save it for later
                    backup_spki_str[i]=""                        # no root ca
                    i=$((i + 1))
                    fileout "hpkp_$hpkp_spki" "INFO" "SPKI $hpkp_spki doesn't match anything. This is ok for a backup for any certificate"
                    # CSV/JSON output here for the sake of simplicity, rest we do en bloc below
               fi
          done

          # now print every backup spki out we saved before
          out "\n$spaces_indented Backups:   "

          # for i=0 manually do the same as below as there's other indentation here
          if [[ -n "${backup_spki_str[0]}" ]]; then
               pr_done_good "${backup_spki[0]}"
               #out " Root CA: "
               pr_italicln " ${backup_spki_str[0]}"
          else
               outln "${backup_spki[0]}"
          fi
          # now for i=1
          for ((i=1; i < ${#backup_spki[@]} ;i++ )); do
               if [[ -n "${backup_spki_str[i]}" ]]; then
                    # it's a Root CA outside the chain
                    pr_done_good "$spaces_indented            ${backup_spki[i]}"
                    #out " Root CA: "
                    pr_italicln " ${backup_spki_str[i]}"
               else
                    outln "$spaces_indented            ${backup_spki[i]}"
               fi
          done
          if [[ ! -f "$ca_hashes" ]] && "$spki_match"; then
               out "$spaces "
               pr_warningln "Attribution of further hashes couldn't be done as $ca_hashes could not be found"
               fileout "hpkp_spkimatch" "WARN" "Attribution of further hashes couldn't be done as $ca_hashes could not be found"
          fi

          # If all else fails...
          if ! "$spki_match"; then
               "$has_backup_spki" && out "$spaces"       # we had a few lines with backup SPKIs already
               pr_svrty_highln " No matching key for SPKI found "
               fileout "hpkp_spkimatch" "HIGH" "None of the SPKI match your host certificate, intermediate CA or known root CAs. You may have bricked this site"
          fi

          if ! "$has_backup_spki"; then
               pr_svrty_highln " No backup keys found. Loss/compromise of the currently pinned key(s) will lead to bricked site. "
               fileout "hpkp_backup" "HIGH" "No backup keys found. Loss/compromise of the currently pinned key(s) will lead to bricked site."
          fi
     else
          outln "--"
          fileout "hpkp" "INFO" "No support for HTTP Public Key Pinning"
     fi

     tmpfile_handle $FUNCNAME.txt
     return $?
}

emphasize_stuff_in_headers(){
# see http://www.grymoire.com/Unix/Sed.html#uh-3
#    outln "$1" | sed "s/[0-9]*/$brown&$off/g"
     outln "$1" | sed -e "s/\([0-9]\)/$brown\1$off/g" \
          -e "s/Debian/"$yellow"\Debian$off/g" \
          -e "s/Win32/"$yellow"\Win32$off/g" \
          -e "s/Win64/"$yellow"\Win64$off/g" \
          -e "s/Ubuntu/"$yellow"Ubuntu$off/g" \
          -e "s/ubuntu/"$yellow"ubuntu$off/g" \
          -e "s/jessie/"$yellow"jessie$off/g" \
          -e "s/squeeze/"$yellow"squeeze$off/g" \
          -e "s/wheezy/"$yellow"wheezy$off/g" \
          -e "s/lenny/"$yellow"lenny$off/g" \
          -e "s/SUSE/"$yellow"SUSE$off/g" \
          -e "s/Red Hat Enterprise Linux/"$yellow"Red Hat Enterprise Linux$off/g" \
          -e "s/Red Hat/"$yellow"Red Hat$off/g" \
          -e "s/CentOS/"$yellow"CentOS$off/g" \
          -e "s/Via/"$yellow"Via$off/g" \
          -e "s/X-Forwarded/"$yellow"X-Forwarded$off/g" \
          -e "s/Liferay-Portal/"$yellow"Liferay-Portal$off/g" \
          -e "s/X-Cache-Lookup/"$yellow"X-Cache-Lookup$off/g" \
          -e "s/X-Cache/"$yellow"X-Cache$off/g" \
          -e "s/X-Squid/"$yellow"X-Squid$off/g" \
          -e "s/X-Server/"$yellow"X-Server$off/g" \
          -e "s/X-Varnish/"$yellow"X-Varnish$off/g" \
          -e "s/X-OWA-Version/"$yellow"X-OWA-Version$off/g" \
          -e "s/MicrosoftSharePointTeamServices/"$yellow"MicrosoftSharePointTeamServices$off/g" \
          -e "s/X-Version/"$yellow"X-Version$off/g" \
          -e "s/X-Powered-By/"$yellow"X-Powered-By$off/g" \
          -e "s/X-UA-Compatible/"$yellow"X-UA-Compatible$off/g" \
          -e "s/X-AspNet-Version/"$yellow"X-AspNet-Version$off/g"
}

run_server_banner() {
     local serverbanner

     if [[ ! -s $HEADERFILE ]]; then
          run_http_header "$1" || return 3
     fi
     pr_bold " Server banner                "
     grep -ai '^Server' $HEADERFILE >$TMPFILE
     if [[ $? -eq 0 ]]; then
          serverbanner=$(sed -e 's/^Server: //' -e 's/^server: //' $TMPFILE)
          if [[ x"$serverbanner" == "x\n" ]] || [[ x"$serverbanner" == "x\n\r" ]] || [[ -z "$serverbanner" ]]; then
               outln "banner exists but empty string"
               fileout "serverbanner" "INFO" "Server banner exists but empty string"
          else
               emphasize_stuff_in_headers "$serverbanner"
               fileout "serverbanner" "INFO" "Server banner identified: $serverbanner"
               if [[ "$serverbanner" = *Microsoft-IIS/6.* ]] && [[ $OSSL_VER == 1.0.2* ]]; then
                    pr_warningln "                              It's recommended to run another test w/ OpenSSL 1.0.1 !"
                    # see https://github.com/PeterMosmans/openssl/issues/19#issuecomment-100897892
                    fileout "IIS6_openssl_mismatch" "WARN" "It is recommended to rerun this test w/ OpenSSL 1.0.1. See https://github.com/PeterMosmans/openssl/issues/19#issuecomment-100897892"
               fi
          fi
          # mozilla.github.io/server-side-tls/ssl-config-generator/
          # https://support.microsoft.com/en-us/kb/245030
     else
          outln "(no \"Server\" line in header, interesting!)"
          fileout "serverbanner" "WARN" "No Server banner in header, interesting!"
     fi

     tmpfile_handle $FUNCNAME.txt
     return 0
}

run_rp_banner() {
     local line
     local first=true
     local spaces="                              "
     local rp_banners=""

     if [[ ! -s $HEADERFILE ]]; then
          run_http_header "$1" || return 3
     fi
     pr_bold " Reverse Proxy banner         "
     egrep -ai '^Via:|^X-Cache|^X-Squid|^X-Varnish:|^X-Server-Name:|^X-Server-Port:|^x-forwarded' $HEADERFILE >$TMPFILE
     if [[ $? -ne 0 ]]; then
          outln "--"
          fileout "rp_header" "INFO" "No reverse proxy banner found"
     else
          while read line; do
               line=$(strip_lf "$line")
               if ! $first; then
                    out "$spaces"
               else
                    first=false
               fi
               emphasize_stuff_in_headers "$line"
               rp_banners="${rp_banners}${line}"
          done < $TMPFILE
          fileout "rp_header" "INFO" "Reverse proxy banner(s) found: $rp_banners"
     fi
     outln

     tmpfile_handle $FUNCNAME.txt
     return 0
#         emphasize_stuff_in_headers "$(sed 's/^/ /g' $TMPFILE | tr '\n\r' '  ')" || \
}

run_application_banner() {
     local line
     local first=true
     local spaces="                              "
     local app_banners=""

     if [[ ! -s $HEADERFILE ]]; then
          run_http_header "$1" || return 3
     fi
     pr_bold " Application banner           "
     egrep -ai '^X-Powered-By|^X-AspNet-Version|^X-Version|^Liferay-Portal|^X-OWA-Version^|^MicrosoftSharePointTeamServices' $HEADERFILE >$TMPFILE
     if [[ $? -ne 0 ]]; then
          outln "--"
          fileout "app_banner" "INFO" "No Application Banners found"
     else
          while IFS='' read -r line; do
               line=$(strip_lf "$line")
               if ! $first; then
                    out "$spaces"
               else
                    first=false
               fi
               emphasize_stuff_in_headers "$line"
               app_banners="${app_banners}${line}"
          done < "$TMPFILE"
          fileout "app_banner" "WARN" "Application Banners found: $app_banners"
     fi
     tmpfile_handle $FUNCNAME.txt
     return 0
}

run_cookie_flags() {     # ARG1: Path
     local -i nr_cookies
     local nr_httponly nr_secure
     local negative_word
     local msg302="" msg302_=""

     if [[ ! -s $HEADERFILE ]]; then
          run_http_header "$1" || return 3
     fi

     if ! grep -q 20 <<< "$HTTP_STATUS_CODE"; then
          if egrep -q "301|302" <<< "$HTTP_STATUS_CODE"; then
               msg302=" -- maybe better try target URL of 30x"
               msg302_=" (30x detected, better try target URL of 30x)"
          else
               msg302=" -- HTTP status $HTTP_STATUS_CODE signals you maybe missed the web application"
               msg302_=" (maybe missed the application)"
          fi
     fi

     pr_bold " Cookie(s)                    "
     grep -ai '^Set-Cookie' $HEADERFILE >$TMPFILE
     if [[ $? -eq 0 ]]; then
          nr_cookies=$(count_lines "$TMPFILE")
          out "$nr_cookies issued: "
          fileout "cookie_count" "INFO" "$nr_cookies cookie(s) issued at \"$1\"$msg302_"
          if [[ $nr_cookies -gt 1 ]]; then
               negative_word="NONE"
          else
               negative_word="NOT"
          fi
          nr_secure=$(grep -iac secure $TMPFILE)
          case $nr_secure in
               0) pr_svrty_medium "$negative_word" ;;
               [123456789]) pr_done_good "$nr_secure/$nr_cookies";;
          esac
          out " secure, "
          if [[ $nr_cookies == $nr_secure ]]; then
               fileout "cookie_secure" "OK" "All $nr_cookies cookie(s) issued at \"$1\" marked as secure"
          else
               fileout "cookie_secure" "WARN" "$nr_secure/$nr_cookies cookie(s) issued at \"$1\" marked as secure"
          fi
          nr_httponly=$(grep -cai httponly $TMPFILE)
          case $nr_httponly in
               0) pr_svrty_medium "$negative_word" ;;
               [123456789]) pr_done_good "$nr_httponly/$nr_cookies";;
          esac
          out " HttpOnly"
          if [[ $nr_cookies == $nr_httponly ]]; then
               fileout "cookie_httponly" "OK" "All $nr_cookies cookie(s) issued at \"$1\" marked as HttpOnly$msg302_"
          else
               fileout "cookie_httponly" "WARN" "$nr_secure/$nr_cookies cookie(s) issued at \"$1\" marked as HttpOnly$msg302_"
          fi
          out "$msg302"
     else
          out "(none issued at \"$1\")$msg302"
          fileout "cookie_count" "INFO" "No cookies issued at \"$1\"$msg302_"
     fi
     outln

     tmpfile_handle $FUNCNAME.txt
     return 0
}


run_more_flags() {
     local good_flags2test="X-Frame-Options X-XSS-Protection X-Content-Type-Options Content-Security-Policy X-Content-Security-Policy X-WebKit-CSP Content-Security-Policy-Report-Only"
     local other_flags2test="Access-Control-Allow-Origin Upgrade X-Served-By X-UA-Compatible"
     local egrep_pattern=""
     local f2t result_str
     local first=true
     local spaces="                              "

     if [[ ! -s $HEADERFILE ]]; then
          run_http_header "$1" || return 3
     fi

     pr_bold " Security headers             "
     for f2t in $good_flags2test; do
          debugme echo "---> $f2t"
          detect_header $f2t $f2t
          if [[ $? -ge 1 ]]; then
               if ! "$first"; then
                    out "$spaces"  # output leading spaces if the first header
               else
                    first=false
               fi
               pr_done_good "$f2t"; outln "$HEADERVALUE"
               fileout "$f2t" "OK" "$f2t: $HEADERVALUE"
          fi
     done

     for f2t in $other_flags2test; do
          debugme echo "---> $f2t"
          detect_header $f2t $f2t
          if [[ $? -ge 1 ]]; then
               if ! "$first"; then
                    out "$spaces"  # output leading spaces if the first header
               else
                    first=false
               fi
               pr_litecyan "$f2t"; outln "$HEADERVALUE"
               fileout "$f2t" "WARN" "$f2t: $HEADERVALUE"
          fi
     done
     #TODO: I am not testing for the correctness or anything stupid yet, e.g. "X-Frame-Options: allowall" or Access-Control-Allow-Origin: *

     if "$first"; then
          pr_svrty_mediumln "--"
          fileout "sec_headers" "MEDIUM" "No security (or other interesting) headers detected"
          ret=1
     else
          ret=0
     fi

     tmpfile_handle $FUNCNAME.txt
     return $ret
}


# #1: string with 2 opensssl codes, HEXC= same in NSS/ssllabs terminology
normalize_ciphercode() {
     part1=$(echo "$1" | awk -F',' '{ print $1 }')
     part2=$(echo "$1" | awk -F',' '{ print $2 }')
     part3=$(echo "$1" | awk -F',' '{ print $3 }')
     if [[ "$part1" == "0x00" ]]; then       # leading 0x00
          HEXC=$part2
     else
          #part2=$(echo $part2 | sed 's/0x//g')
          part2=${part2//0x/}
          if [[ -n "$part3" ]]; then    # a SSLv2 cipher has three parts
               #part3=$(echo $part3 | sed 's/0x//g')
               part3=${part3//0x/}
          fi
          HEXC="$part1$part2$part3"
     fi
#TODO: we should just echo this and avoid the global var HEXC
     HEXC=$(tolower "$HEXC"| sed 's/0x/x/')  # strip leading 0
     return 0
}

prettyprint_local() {
     local arg
     local hexcode dash ciph sslvers kx auth enc mac export
     local re='^[0-9A-Fa-f]+$'

     if [[ "$1" == 0x* ]] || [[ "$1" == 0X* ]]; then
          fatal "pls supply x<number> instead" 2
     fi

     if [[ -z "$1" ]]; then
          pr_headline " Displaying all $OPENSSL_NR_CIPHERS local ciphers ";
     else
          pr_headline " Displaying all local ciphers ";
          # pattern provided; which one?
          [[ $1 =~ $re ]] && \
               pr_headline "matching number pattern \"$1\" " || \
               pr_headline "matching word pattern "\"$1\"" (ignore case) "
     fi
     outln "\n"
     neat_header

     if [[ -z "$1" ]]; then
          $OPENSSL ciphers -V 'ALL:COMPLEMENTOFALL:@STRENGTH' 2>$ERRFILE | while read hexcode dash ciph sslvers kx auth enc mac export ; do       # -V doesn't work with openssl < 1.0
               normalize_ciphercode $hexcode
               neat_list "$HEXC" "$ciph" "$kx" "$enc"
               outln
          done
     else
          #for arg in $(echo $@ | sed 's/,/ /g'); do
          for arg in ${*//,/ /}; do
               $OPENSSL ciphers -V 'ALL:COMPLEMENTOFALL:@STRENGTH' 2>$ERRFILE | while read hexcode dash ciph sslvers kx auth enc mac export ; do # -V doesn't work with openssl < 1.0
                    normalize_ciphercode $hexcode
                    # for numbers we don't do word matching:
                    [[ $arg =~ $re ]] && \
                         neat_list "$HEXC" "$ciph" "$kx" "$enc" | grep -ai "$arg" || \
                         neat_list "$HEXC" "$ciph" "$kx" "$enc" | grep -wai "$arg"
               done
          done
     fi
     outln
     return 0
}


# list ciphers (and makes sure you have them locally configured)
# arg[1]: cipher list (or anything else)
# arg[2]: protocol (e.g., -ssl2)
listciphers() {
     local -i ret
     local debugname="$(sed -e s'/\!/not/g' -e 's/\:/_/g' <<< "$1")"

     $OPENSSL ciphers $2 "$1" &>$TMPFILE
     ret=$?
     debugme cat $TMPFILE

     tmpfile_handle $FUNCNAME.$debugname.txt
     return $ret
}


# argv[1]: cipher list to test in OpenSSL syntax
# argv[2]: string on console
# argv[3]: ok to offer? 0: yes, 1: no
# argv[4]: string for fileout
# argv[5]: non-SSLv2 cipher list to test (hexcodes), if using sockets
# argv[6]: SSLv2 cipher list to test (hexcodes), if using sockets
std_cipherlists() {
     local -i i len sclient_success
     local sslv2_cipherlist detected_ssl2_ciphers
     local singlespaces proto="" addcmd=""
     local debugname="$(sed -e s'/\!/not/g' -e 's/\:/_/g' <<< "$1")"

     [[ "$OPTIMAL_PROTO" == "-ssl2" ]] && proto="$OPTIMAL_PROTO"
     pr_bold "$2    "                   # indenting to be in the same row as server preferences
     if [[ -n "$5" ]] || listciphers "$1" $proto; then
          if [[ -z "$5" ]] || ( "$FAST" && listciphers "$1" -tls1 ); then
               "$HAS_NO_SSL2" && addcmd="-no_ssl2"
               $OPENSSL s_client -cipher "$1" $BUGS $STARTTLS -connect $NODEIP:$PORT $PROXY $SNI $addcmd 2>$ERRFILE >$TMPFILE </dev/null
               sclient_connect_successful $? $TMPFILE
               sclient_success=$?
               debugme cat $ERRFILE
          else
               tls_sockets "03" "$5"
               sclient_success=$?
               [[ $sclient_success -eq 2 ]] && sclient_success=0
          fi
          if [[ $sclient_success -ne 0 ]] && has_server_protocol "ssl2"; then
               if ( [[ -z "$6" ]] || "$FAST" ) && "$HAS_SSL2" && listciphers "$1" -ssl2; then
                    $OPENSSL s_client -cipher "$1" $BUGS $STARTTLS -connect $NODEIP:$PORT $PROXY -ssl2 2>$ERRFILE >$TMPFILE </dev/null
                    sclient_connect_successful $? $TMPFILE
                    sclient_success=$?
                    debugme cat $ERRFILE
               elif [[ -n "$6" ]]; then
                    sslv2_sockets "$6" "true"
                    if [[ $? -eq 3 ]] && [[ "$V2_HELLO_CIPHERSPEC_LENGTH" -ne 0 ]]; then
                         sslv2_cipherlist="$(strip_spaces "${6//,/}")"
                         len=${#sslv2_cipherlist}
                         detected_ssl2_ciphers="$(grep "Supported cipher: " "$TEMPDIR/$NODEIP.parse_sslv2_serverhello.txt")"
                         for (( i=0; i<len; i=i+6 )); do
                              [[ "$detected_ssl2_ciphers" =~ "x${sslv2_cipherlist:i:6}" ]] && sclient_success=0 && break
                         done
                    fi
               fi
          fi
          case $3 in
               0)   # ok to offer
                    if [[ $sclient_success -eq 0 ]]; then
                         pr_done_best "offered (OK)"
                         fileout "std_$4" "OK" "$2 offered"
                    else
                         pr_svrty_medium "not offered"
                         fileout "std_$4" "MEDIUM" "$2 not offered"
                    fi
                    ;;
               1) # the ugly ones
                    if [[ $sclient_success -eq 0 ]]; then
                         pr_svrty_critical "offered (NOT ok)"
                         fileout "std_$4" "CRITICAL" "$2 offered - ugly"
                    else
                         pr_done_best "not offered (OK)"
                         fileout "std_$4" "OK" "$2 not offered"
                    fi
                    ;;
               2)   # bad but not worst
                    if [[ $sclient_success -eq 0 ]]; then
                         pr_svrty_high "offered (NOT ok)"
                         fileout "std_$4" "HIGH" "$2 offered - bad"
                    else
                         pr_done_good "not offered (OK)"
                         fileout "std_$4" "OK" "$2 not offered"
                    fi
                    ;;
               3) # not totally bad
                    if [[ $sclient_success -eq 0 ]]; then
                         pr_svrty_medium "offered"
                         fileout "std_$4" "MEDIUM" "$2 offered - not too bad"
                    else
                         out "not offered (OK)"
                         fileout "std_$4" "OK" "$2 not offered"
                    fi
                    ;;
               *) # we shouldn't reach this
                    pr_warning "?: $3 (please report this)"
                    fileout "std_$4" "WARN" "return condition $3 unclear"
                    ;;
          esac
          tmpfile_handle $FUNCNAME.$debugname.txt
          [[ $DEBUG -ge 1 ]] && outln " -- $1" || outln  #FIXME: should be in standard output at some time
     else
          singlespaces=$(echo "$2" | sed -e 's/ \+/ /g' -e 's/^ //' -e 's/ $//g' -e 's/  //g')
          if [[ "$OPTIMAL_PROTO" == "-ssl2" ]]; then
               local_problem_ln "No $singlespaces for SSLv2 configured in $OPENSSL"
          else
               local_problem_ln "No $singlespaces configured in $OPENSSL"
          fi
          fileout "std_$4" "WARN" "Cipher $2 ($1) not supported by local OpenSSL ($OPENSSL)"
     fi
     # we need 1 x lf in those cases:
     debugme echo
}


# sockets inspired by http://blog.chris007.de/?p=238
# ARG1: hexbyte with a leading comma (!!), separated by commas
# ARG2: sleep
socksend() {
     # the following works under BSD and Linux, which is quite tricky. So don't mess with it unless you're really sure what you do
     if "$HAS_SED_E"; then
          data=$(echo "$1" | sed -e 's/# .*$//g' -e 's/ //g' | sed -E 's/^[[:space:]]+//; s/[[:space:]]+$//; /^$/d' | sed 's/,/\\/g' | tr -d '\n')
     else
          data=$(echo "$1" | sed -e 's/# .*$//g' -e 's/ //g' | sed -r 's/^[[:space:]]+//; s/[[:space:]]+$//; /^$/d' | sed 's/,/\\/g' | tr -d '\n')
     fi
     [[ $DEBUG -ge 4 ]] && echo "\"$data\""
     printf -- "$data" >&5 2>/dev/null &
     sleep $2
}


openssl2rfc() {
     local rfcname=""
     local -i i

     for (( i=0; i < TLS_NR_CIPHERS; i++ )); do
          [[ "$1" == "${TLS_CIPHER_OSSL_NAME[i]}" ]] && rfcname="${TLS_CIPHER_RFC_NAME[i]}" && break
     done
     [[ "$rfcname" == "-" ]] && rfcname=""
     [[ -n "$rfcname" ]] && out "$rfcname"
     return 0
}

rfc2openssl() {
     local ossl_name
     local -i i

     for (( i=0; i < TLS_NR_CIPHERS; i++ )); do
          [[ "$1" == "${TLS_CIPHER_RFC_NAME[i]}" ]] && ossl_name="${TLS_CIPHER_OSSL_NAME[i]}" && break
     done
     [[ "$ossl_name" == "-" ]] && ossl_name=""
     [[ -n "$ossl_name" ]] && out "$ossl_name"
     return 0
}


show_rfc_style(){
     local rfcname="" hexcode
     local -i i

     hexcode="$(toupper "$1")"
     case ${#hexcode} in
          3) hexcode="0x00,0x${hexcode:1:2}" ;;
          5) hexcode="0x${hexcode:1:2},0x${hexcode:3:2}" ;;
          7) hexcode="0x${hexcode:1:2},0x${hexcode:3:2},0x${hexcode:5:2}" ;;
          *) return 1 ;;
     esac
     for (( i=0; i < TLS_NR_CIPHERS; i++ )); do
          [[ "$hexcode" == "${TLS_CIPHER_HEXCODE[i]}" ]] && rfcname="${TLS_CIPHER_RFC_NAME[i]}" && break
     done
     [[ "$rfcname" == "-" ]] && rfcname=""
     [[ -n "$rfcname" ]] && out "$rfcname"
     return 0
}

neat_header(){
     printf -- "Hexcode  Cipher Suite Name (OpenSSL)       KeyExch.   Encryption  Bits${ADD_RFC_STR:+     Cipher Suite Name (RFC)}\n"
     printf -- "%s--------------------------------------------------------------------------${ADD_RFC_STR:+---------------------------------------------------}\n"
}


# arg1: hexcode
# arg2: cipher in openssl notation
# arg3: keyexchange
# arg4: encryption (maybe included "export")
# arg5: "true" if the cipher's "quality" should be highlighted
#       "false" if the line should be printed in light grey
#       empty if line should be printed in black
neat_list(){
     local hexcode="$1"
     local ossl_cipher="$2" tls_cipher=""
     local kx enc strength line

     kx="${3//Kx=/}"
     enc="${4//Enc=/}"
     strength="${enc//\)/}"             # retrieve (). first remove traling ")"
     strength="${strength#*\(}"         # exfiltrate (VAL
     enc="${enc%%\(*}"

     enc="${enc//POLY1305/}"            # remove POLY1305
     enc="${enc//\//}"                  # remove "/"

     echo "$export" | grep -iq export && strength="$strength,exp"

     [[ -n "$ADD_RFC_STR" ]] && tls_cipher="$(show_rfc_style "$hexcode")"

     if [[ "$5" == "false" ]]; then
          line="$(printf -- " %-7s %-33s %-10s %-12s%-8s${ADD_RFC_STR:+ %-49s}${SHOW_EACH_C:+  %-0s}" "$hexcode" "$ossl_cipher" "$kx" "$enc" "$strength" "$tls_cipher")"
          pr_deemphasize "$line"
          return 0
     fi

     #printf -- "%q" "$kx" | xxd | head -1
     # length correction for color escape codes (printf counts the escape color codes!!)
     if printf -- "%q" "$kx" | egrep -aq '.;3.m|E\[1m' ; then     # here's a color code which screws up the formatting with printf below
          while [[ ${#kx} -lt 20 ]]; do
               kx="$kx "
          done
     elif printf -- "%q" "$kx" | grep -aq 'E\[m' ; then   # for color=1/0 we have the pr_off which screws up the formatting
          while [[ ${#kx} -lt 13 ]]; do                   # so it'll be filled up ok
               kx="$kx "
          done
     fi
     #echo "${#kx}"                            # should be always 20 / 13
     printf -- " %-7s %-33s %-10s %-12s%-8s${ADD_RFC_STR:+ %-49s}${SHOW_EACH_C:+  %-0s}" "$hexcode" "$ossl_cipher" "$kx" "$enc" "$strength" "$tls_cipher"
}

test_just_one(){
     local hexc n auth export ciphers_to_test supported_sslv2_ciphers s
     local -a hexcode normalized_hexcode ciph sslvers kx enc export2 sigalg
     local -a ciphers_found ciphers_found2 ciph2 rfc_ciph rfc_ciph2 ossl_supported
     local -a -i index
     local -i nr_ciphers=0 nr_ossl_ciphers=0 nr_nonossl_ciphers=0
     local -i num_bundles mod_check bundle_size bundle end_of_bundle
     local addcmd dhlen has_dh_bits="$HAS_DH_BITS"
     local -i sclient_success
     local re='^[0-9A-Fa-f]+$'
     local using_sockets=true

     "$SSL_NATIVE" && using_sockets=false
     "$FAST" && using_sockets=false
     [[ $TLS_NR_CIPHERS == 0 ]] && using_sockets=false

     pr_headline " Testing ciphers with "
     if [[ $1 =~ $re ]]; then
          pr_headline "matching number pattern \"$1\" "
          tjolines="$tjolines matching number pattern \"$1\"\n\n"
     else
          pr_headline "word pattern "\"$1\"" (ignore case) "
          tjolines="$tjolines word pattern \"$1\" (ignore case)\n\n"
     fi
     outln
     if ! "$using_sockets"; then
          [[ $TLS_NR_CIPHERS == 0 ]] && ! "$SSL_NATIVE" && ! "$FAST" && pr_warning " Cipher mapping not available, doing a fallback to openssl"
          if ! "$HAS_DH_BITS"; then
               [[ $TLS_NR_CIPHERS == 0 ]] && ! "$SSL_NATIVE" && ! "$FAST" && out "."
               pr_warningln "    (Your $OPENSSL cannot show DH/ECDH bits)"
          fi
     fi
     outln
     neat_header
     #for arg in $(echo $@ | sed 's/,/ /g'); do
     for arg in ${*//, /}; do
          if "$using_sockets" || [[ $OSSL_VER_MAJOR -lt 1 ]]; then
               for (( i=0; i < TLS_NR_CIPHERS; i++ )); do
                    hexc="${TLS_CIPHER_HEXCODE[i]}"
                    if [[ ${#hexc} -eq 9 ]]; then
                         hexcode[nr_ciphers]="${hexc:2:2},${hexc:7:2}"
                         if [[ "${hexc:2:2}" == "00" ]]; then
                              normalized_hexcode[nr_ciphers]="x${hexc:7:2}"
                         else
                              normalized_hexcode[nr_ciphers]="x${hexc:2:2}${hexc:7:2}"
                         fi
                    else
                         hexc="$(tolower "$hexc")"
                         hexcode[nr_ciphers]="${hexc:2:2},${hexc:7:2},${hexc:12:2}"
                         normalized_hexcode[nr_ciphers]="x${hexc:2:2}${hexc:7:2}${hexc:12:2}"
                    fi
                    if [[ $arg =~ $re ]]; then
                         neat_list "${normalized_hexcode[nr_ciphers]}" "${TLS_CIPHER_OSSL_NAME[i]}" "${TLS_CIPHER_KX[i]}" "${TLS_CIPHER_ENC[i]}" | grep -qai "$arg"
                    else
                         neat_list "${normalized_hexcode[nr_ciphers]}" "${TLS_CIPHER_OSSL_NAME[i]}" "${TLS_CIPHER_KX[i]}" "${TLS_CIPHER_ENC[i]}" | grep -qwai "$arg"
                    fi
                    if [[ $? -eq 0 ]] && ( "$using_sockets" || "${TLS_CIPHER_OSSL_SUPPORTED[i]}" ); then    # string matches, so we can ssl to it:
                         normalized_hexcode[nr_ciphers]="$(tolower "${normalized_hexcode[nr_ciphers]}")"
                         ciph[nr_ciphers]="${TLS_CIPHER_OSSL_NAME[i]}"
                         rfc_ciph[nr_ciphers]="${TLS_CIPHER_RFC_NAME[i]}"
                         kx[nr_ciphers]="${TLS_CIPHER_KX[i]}"
                         enc[nr_ciphers]="${TLS_CIPHER_ENC[i]}"
                         sslvers[nr_ciphers]="${TLS_CIPHER_SSLVERS[i]}"
                         export2[nr_ciphers]="${TLS_CIPHER_EXPORT[i]}"
                         ciphers_found[nr_ciphers]=false
                         sigalg[nr_ciphers]=""
                         ossl_supported[nr_ciphers]="${TLS_CIPHER_OSSL_SUPPORTED[i]}"
                         if "$using_sockets" && ! "$has_dh_bits" && \
                            ( [[ ${kx[nr_ciphers]} == "Kx=ECDH" ]] || [[ ${kx[nr_ciphers]} == "Kx=DH" ]] || [[ ${kx[nr_ciphers]} == "Kx=EDH" ]] ); then
                              ossl_supported[nr_ciphers]=false
                         fi
                         nr_ciphers+=1
                    fi
               done
          else
               while read hexc n ciph[nr_ciphers] sslvers[nr_ciphers] kx[nr_ciphers] auth enc[nr_ciphers] mac export2[nr_ciphers]; do
                    normalize_ciphercode $hexc
                    # is argument a number?
                    if [[ $arg =~ $re ]]; then
                         neat_list "$HEXC" "${ciph[nr_ciphers]}" "${kx[nr_ciphers]}" "${enc[nr_ciphers]}" | grep -qai "$arg"
                    else
                         neat_list "$HEXC" "${ciph[nr_ciphers]}" "${kx[nr_ciphers]}" "${enc[nr_ciphers]}" | grep -qwai "$arg"
                    fi
                    if [[ $? -eq 0 ]]; then    # string matches, so we can ssl to it:
                         ciphers_found[nr_ciphers]=false
                         normalized_hexcode[nr_ciphers]="$HEXC"
                         sigalg[nr_ciphers]=""
                         ossl_supported[nr_ciphers]=true
                         nr_ciphers+=1
                    fi
               done < <($OPENSSL ciphers $ossl_ciphers_proto -V 'ALL:COMPLEMENTOFALL:@STRENGTH' 2>>$ERRFILE)
          fi

          # Test the SSLv2 ciphers, if any.
          if "$using_sockets"; then
               ciphers_to_test=""
               for (( i=0; i < nr_ciphers; i++ )); do
                    if [[ "${sslvers[i]}" == "SSLv2" ]]; then
                         ciphers_to_test+=", ${hexcode[i]}"
                    fi
               done
               if [[ -n "$ciphers_to_test" ]]; then
                    sslv2_sockets "${ciphers_to_test:2}" "true"
                    if [[ $? -eq 3 ]] && [[ "$V2_HELLO_CIPHERSPEC_LENGTH" -ne 0 ]]; then
                         supported_sslv2_ciphers="$(grep "Supported cipher: " "$TEMPDIR/$NODEIP.parse_sslv2_serverhello.txt")"
                         "$SHOW_SIGALGO" && s="$($OPENSSL x509 -noout -text -in "$HOSTCERT" | awk -F':' '/Signature Algorithm/ { print $2 }' | head -1)"
                         for (( i=0 ; i<nr_ciphers; i++ )); do
                              if [[ "${sslvers[i]}" == "SSLv2" ]] && [[ "$supported_sslv2_ciphers" =~ "${normalized_hexcode[i]}" ]]; then
                                   ciphers_found[i]=true
                                   "$SHOW_SIGALGO" && sigalg[i]="$s"
                              fi
                         done
                    fi
               fi
          else
               ciphers_to_test=""
               for (( i=0; i < nr_ciphers; i++ )); do
                    if [[ "${sslvers[i]}" == "SSLv2" ]]; then
                         ciphers_to_test+=":${ciph[i]}"
                    fi
               done
               if [[ -n "$ciphers_to_test" ]]; then
                    $OPENSSL s_client -cipher "${ciphers_to_test:1}" $STARTTLS $BUGS -connect $NODEIP:$PORT $PROXY -ssl2 >$TMPFILE 2>$ERRFILE </dev/null
                    sclient_connect_successful "$?" "$TMPFILE"
                    if [[ "$?" -eq 0 ]]; then
                         supported_sslv2_ciphers="$(grep -A 4 "Ciphers common between both SSL endpoints:" $TMPFILE)"
                         "$SHOW_SIGALGO" && s="$($OPENSSL x509 -noout -text -in $TMPFILE | awk -F':' '/Signature Algorithm/ { print $2 }' | head -1)"
                         for (( i=0 ; i<nr_ciphers; i++ )); do
                              if [[ "${sslvers[i]}" == "SSLv2" ]] && [[ "$supported_sslv2_ciphers" =~ "${ciph[i]}" ]]; then
                                   ciphers_found[i]=true
                                   "$SHOW_SIGALGO" && sigalg[i]="$s"
                              fi
                         done
                    fi
               fi
          fi

          for (( i=0; i < nr_ciphers; i++ )); do
               if "${ossl_supported[i]}" && [[ "${sslvers[i]}" != "SSLv2" ]]; then
                    ciphers_found2[nr_ossl_ciphers]=false
                    ciph2[nr_ossl_ciphers]="${ciph[i]}"
                    index[nr_ossl_ciphers]=$i
                    nr_ossl_ciphers+=1
               fi
          done
          if [[ $nr_ossl_ciphers -eq 0 ]]; then
               num_bundles=0
          else
               # Some servers can't handle a handshake with >= 128 ciphers. So,
               # test cipher suites in bundles of 128 or less.
               num_bundles=$nr_ossl_ciphers/128
               mod_check=$nr_ossl_ciphers%128
               [[ $mod_check -ne 0 ]] && num_bundles=$num_bundles+1

               bundle_size=$nr_ossl_ciphers/$num_bundles
               mod_check=$nr_ossl_ciphers%$num_bundles
               [[ $mod_check -ne 0 ]] && bundle_size+=1
          fi

          "$HAS_NO_SSL2" && addcmd="-no_ssl2" || addcmd=""
          for (( bundle=0; bundle < num_bundles; bundle++ )); do
               end_of_bundle=$bundle*$bundle_size+$bundle_size
               [[ $end_of_bundle -gt $nr_ossl_ciphers ]] && end_of_bundle=$nr_ossl_ciphers
               while true; do
                    ciphers_to_test=""
                    for (( i=bundle*bundle_size; i < end_of_bundle; i++ )); do
                         ! "${ciphers_found2[i]}" && ciphers_to_test+=":${ciph2[i]}"
                    done
                    [[ -z "$ciphers_to_test" ]] && break
                    $OPENSSL s_client $addcmd -cipher "${ciphers_to_test:1}" $STARTTLS $BUGS -connect $NODEIP:$PORT $PROXY $SNI >$TMPFILE 2>$ERRFILE </dev/null
                    sclient_connect_successful "$?" "$TMPFILE" || break
                    cipher=$(awk '/Cipher *:/ { print $3 }' $TMPFILE)
                    [[ -z "$cipher" ]] && break
                    for (( i=bundle*bundle_size; i < end_of_bundle; i++ )); do
                         [[ "$cipher" == "${ciph2[i]}" ]] && ciphers_found2[i]=true && break
                    done
                    [[ $i -eq $end_of_bundle ]] && break
                    i=${index[i]}
                    ciphers_found[i]=true
                    if [[ ${kx[i]} == "Kx=ECDH" ]] || [[ ${kx[i]} == "Kx=DH" ]] || [[ ${kx[i]} == "Kx=EDH" ]]; then
                         dhlen=$(read_dhbits_from_file "$TMPFILE" quiet)
                         kx[i]="${kx[i]} $dhlen"
                    fi
                    "$SHOW_SIGALGO" && grep -q "\-\-\-\-\-BEGIN CERTIFICATE\-\-\-\-\-" $TMPFILE && \
                         sigalg[i]="$($OPENSSL x509 -noout -text -in $TMPFILE | awk -F':' '/Signature Algorithm/ { print $2 }' | head -1)"
               done
          done

          if "$using_sockets"; then
               for (( i=0; i < nr_ciphers; i++ )); do
                    if ! "${ciphers_found[i]}" && [[ "${sslvers[i]}" != "SSLv2" ]] && [[ "${hexcode[i]}" != "13"* ]]; then
                         ciphers_found2[nr_nonossl_ciphers]=false
                         hexcode2[nr_nonossl_ciphers]="${hexcode[i]}"
                         rfc_ciph2[nr_nonossl_ciphers]="${rfc_ciph[i]}"
                         index[nr_nonossl_ciphers]=$i
                         nr_nonossl_ciphers+=1
                    fi
               done
          fi

          if [[ $nr_nonossl_ciphers -eq 0 ]]; then
               num_bundles=0
          else
               # Some servers can't handle a handshake with >= 128 ciphers. So,
               # test cipher suites in bundles of 128 or less.
               num_bundles=$nr_nonossl_ciphers/128
               mod_check=$nr_nonossl_ciphers%128
               [[ $mod_check -ne 0 ]] && num_bundles=$num_bundles+1

               bundle_size=$nr_nonossl_ciphers/$num_bundles
               mod_check=$nr_nonossl_ciphers%$num_bundles
               [[ $mod_check -ne 0 ]] && bundle_size+=1
          fi

          for (( bundle=0; bundle < num_bundles; bundle++ )); do
               end_of_bundle=$bundle*$bundle_size+$bundle_size
               [[ $end_of_bundle -gt $nr_nonossl_ciphers ]] && end_of_bundle=$nr_nonossl_ciphers
               while true; do
                    ciphers_to_test=""
                    for (( i=bundle*bundle_size; i < end_of_bundle; i++ )); do
                         ! "${ciphers_found2[i]}" && ciphers_to_test+=", ${hexcode2[i]}"
                    done
                    [[ -z "$ciphers_to_test" ]] && break
                    if "$SHOW_SIGALGO"; then
                         tls_sockets "03" "${ciphers_to_test:2}, 00,ff" "all"
                    else
                         tls_sockets "03" "${ciphers_to_test:2}, 00,ff" "ephemeralkey"
                    fi
                    sclient_success=$?
                    [[ $sclient_success -ne 0 ]] && [[ $sclient_success -ne 2 ]] && break
                    cipher=$(awk '/Cipher *:/ { print $3 }' "$TEMPDIR/$NODEIP.parse_tls_serverhello.txt")
                    for (( i=bundle*bundle_size; i < end_of_bundle; i++ )); do
                         [[ "$cipher" == "${rfc_ciph2[i]}" ]] && ciphers_found2[i]=true && break
                    done
                    [[ $i -eq $end_of_bundle ]] && break
                    i=${index[i]}
                    ciphers_found[i]=true
                    if [[ ${kx[i]} == "Kx=ECDH" ]] || [[ ${kx[i]} == "Kx=DH" ]] || [[ ${kx[i]} == "Kx=EDH" ]]; then
                         dhlen=$(read_dhbits_from_file "$TEMPDIR/$NODEIP.parse_tls_serverhello.txt" quiet)
                         kx[i]="${kx[i]} $dhlen"
                    fi
                    "$SHOW_SIGALGO" && [[ -r "$HOSTCERT" ]] && \
                          sigalg[i]="$($OPENSSL x509 -noout -text -in "$HOSTCERT" | awk -F':' '/Signature Algorithm/ { print $2 }' | head -1)"
               done
          done

          for (( i=0; i < nr_ciphers; i++ )); do
               export="${export2[i]}"
               neat_list "${normalized_hexcode[i]}" "${ciph[i]}" "${kx[i]}" "${enc[i]}" "${ciphers_found[i]}"
               if "${ciphers_found[i]}"; then
                    pr_cyan "  available"
                    fileout "cipher_${normalized_hexcode[i]}" "INFO" "$(neat_list "${normalized_hexcode[i]}" "${ciph[i]}" "${kx[i]}" "${enc[i]}") available"
               else
                    pr_deemphasize "  not a/v"
                    fileout "cipher_${normalized_hexcode[i]}" "INFO" "$(neat_list "${normalized_hexcode[i]}" "${ciph[i]}" "${kx[i]}" "${enc[i]}") not a/v"
               fi
               outln
          done
          "$using_sockets" && HAS_DH_BITS="$has_dh_bits"
          exit
     done
     outln

     tmpfile_handle $FUNCNAME.txt
     return 0       # this is a single test for a cipher
}


# test for all ciphers locally configured (w/o distinguishing whether they are good or bad)
run_allciphers() {
     local -i nr_ciphers_tested=0 nr_ciphers=0 nr_ossl_ciphers=0 nr_nonossl_ciphers=0 ret
     local n auth mac export hexc sslv2_ciphers="" s
     local -a normalized_hexcode hexcode ciph sslvers kx enc export2 sigalg ossl_supported
     local -i i end_of_bundle bundle bundle_size num_bundles mod_check
     local -a ciphers_found ciphers_found2 hexcode2 ciph2 sslvers2 rfc_ciph2
     local -i -a index
     local dhlen available ciphers_to_test supported_sslv2_ciphers addcmd=""
     local has_dh_bits="$HAS_DH_BITS"
     local using_sockets=true

     "$SSL_NATIVE" && using_sockets=false
     "$FAST" && using_sockets=false
     [[ $TLS_NR_CIPHERS == 0 ]] && using_sockets=false

     # get a list of all the cipher suites to test
     if "$using_sockets" || [[ $OSSL_VER_MAJOR -lt 1 ]]; then
          for (( i=0; i < TLS_NR_CIPHERS; i++ )); do
               hexc="$(tolower "${TLS_CIPHER_HEXCODE[i]}")"
               ciph[i]="${TLS_CIPHER_OSSL_NAME[i]}"
               sslvers[i]="${TLS_CIPHER_SSLVERS[i]}"
               kx[i]="${TLS_CIPHER_KX[i]}"
               enc[i]="${TLS_CIPHER_ENC[i]}"
               export2[i]="${TLS_CIPHER_EXPORT[i]}"
               ciphers_found[i]=false
               sigalg[i]=""
               ossl_supported[i]=${TLS_CIPHER_OSSL_SUPPORTED[i]}
               if "$using_sockets" && ! "$HAS_DH_BITS" && ( [[ ${kx[i]} == "Kx=ECDH" ]] || [[ ${kx[i]} == "Kx=DH" ]] || [[ ${kx[i]} == "Kx=EDH" ]] ); then
                    ossl_supported[i]=false
               fi
               if [[ ${#hexc} -eq 9 ]]; then
                    hexcode[i]="${hexc:2:2},${hexc:7:2}"
                    if [[ "${hexc:2:2}" == "00" ]]; then
                         normalized_hexcode[i]="x${hexc:7:2}"
                    else
                         normalized_hexcode[i]="x${hexc:2:2}${hexc:7:2}"
                    fi
               else
                    hexcode[i]="${hexc:2:2},${hexc:7:2},${hexc:12:2}"
                    normalized_hexcode[i]="x${hexc:2:2}${hexc:7:2}${hexc:12:2}"
                    sslv2_ciphers="$sslv2_ciphers, ${hexcode[i]}"
               fi
               if "$using_sockets" || "${TLS_CIPHER_OSSL_SUPPORTED[i]}"; then
                    nr_ciphers_tested+=1
               fi
          done
          nr_ciphers=$TLS_NR_CIPHERS
     else
          while read hexc n ciph[nr_ciphers] sslvers[nr_ciphers] kx[nr_ciphers] auth enc[nr_ciphers] mac export2[nr_ciphers]; do
               ciphers_found[nr_ciphers]=false
               if [[ ${#hexc} -eq 9 ]]; then
                    if [[ "${hexc:2:2}" == "00" ]]; then
                         normalized_hexcode[nr_ciphers]="$(tolower "x${hexc:7:2}")"
                    else
                         normalized_hexcode[nr_ciphers]="$(tolower "x${hexc:2:2}${hexc:7:2}")"
                    fi
               else
                    normalized_hexcode[nr_ciphers]="$(tolower "x${hexc:2:2}${hexc:7:2}${hexc:12:2}")"
               fi
               sigalg[nr_ciphers]=""
               ossl_supported[nr_ciphers]=true
               nr_ciphers=$nr_ciphers+1
          done < <($OPENSSL ciphers -V 'ALL:COMPLEMENTOFALL:@STRENGTH' 2>>$ERRFILE)
          nr_ciphers_tested=$nr_ciphers
     fi

     if "$using_sockets"; then
          sslv2_sockets "${sslv2_ciphers:2}" "true"
          if [[ $? -eq 3 ]] && [[ "$V2_HELLO_CIPHERSPEC_LENGTH" -ne 0 ]]; then
               supported_sslv2_ciphers="$(grep "Supported cipher: " "$TEMPDIR/$NODEIP.parse_sslv2_serverhello.txt")"
               "$SHOW_SIGALGO" && s="$($OPENSSL x509 -noout -text -in "$HOSTCERT" | awk -F':' '/Signature Algorithm/ { print $2 }' | head -1)"
               for (( i=0 ; i<nr_ciphers; i++ )); do
                    if [[ "${sslvers[i]}" == "SSLv2" ]] && [[ "$supported_sslv2_ciphers" =~ "${normalized_hexcode[i]}" ]]; then
                         ciphers_found[i]=true
                         "$SHOW_SIGALGO" && sigalg[i]="$s"
                    fi
               done
          fi
     elif "$HAS_SSL2"; then
          $OPENSSL s_client $STARTTLS $BUGS -connect $NODEIP:$PORT $PROXY -ssl2 >$TMPFILE 2>$ERRFILE </dev/null
          sclient_connect_successful "$?" "$TMPFILE"
          if [[ "$?" -eq 0 ]]; then
               supported_sslv2_ciphers="$(grep -A 4 "Ciphers common between both SSL endpoints:" $TMPFILE)"
               "$SHOW_SIGALGO" && s="$($OPENSSL x509 -noout -text -in $TMPFILE | awk -F':' '/Signature Algorithm/ { print $2 }' | head -1)"
               for (( i=0 ; i<nr_ciphers; i++ )); do
                    if [[ "${sslvers[i]}" == "SSLv2" ]] && [[ "$supported_sslv2_ciphers" =~ "${ciph[i]}" ]]; then
                         ciphers_found[i]=true
                         "$SHOW_SIGALGO" && sigalg[i]="$s"
                    fi
               done
          fi
     fi

     outln
     if "$using_sockets"; then
          pr_headlineln " Testing $nr_ciphers_tested ciphers via OpenSSL plus sockets against the server, ordered by encryption strength "
     else
          pr_headlineln " Testing all $nr_ciphers_tested locally available ciphers against the server, ordered by encryption strength "
          [[ $TLS_NR_CIPHERS == 0 ]] && ! "$SSL_NATIVE" && ! "$FAST" && pr_warning " Cipher mapping not available, doing a fallback to openssl"
          outln
          if ! "$HAS_DH_BITS"; then
               [[ $TLS_NR_CIPHERS == 0 ]] && ! "$SSL_NATIVE" && ! "$FAST" && out "."
               pr_warningln " Your $OPENSSL cannot show DH/ECDH bits"
          fi
     fi
     outln
     neat_header

     for (( i=0; i < nr_ciphers; i++ )); do
          if "${ossl_supported[i]}"; then
               ciphers_found2[nr_ossl_ciphers]=false
               sslvers2[nr_ossl_ciphers]="${sslvers[i]}"
               ciph2[nr_ossl_ciphers]="${ciph[i]}"
               index[nr_ossl_ciphers]=$i
               nr_ossl_ciphers+=1
          fi
     done

     if [[ $nr_ossl_ciphers -eq 0 ]]; then
          num_bundles=0
     else
          # Some servers can't handle a handshake with >= 128 ciphers. So,
          # test cipher suites in bundles of 128 or less.
          num_bundles=$nr_ossl_ciphers/128
          mod_check=$nr_ossl_ciphers%128
          [[ $mod_check -ne 0 ]] && num_bundles=$num_bundles+1

          bundle_size=$nr_ossl_ciphers/$num_bundles
          mod_check=$nr_ossl_ciphers%$num_bundles
          [[ $mod_check -ne 0 ]] && bundle_size+=1
     fi

     "$HAS_NO_SSL2" && addcmd="-no_ssl2"
     for (( bundle=0; bundle < num_bundles; bundle++ )); do
          end_of_bundle=$bundle*$bundle_size+$bundle_size
          [[ $end_of_bundle -gt $nr_ossl_ciphers ]] && end_of_bundle=$nr_ossl_ciphers
          for (( success=0; success==0 ; 1 )); do
               ciphers_to_test=""
               for (( i=bundle*bundle_size; i < end_of_bundle; i++ )); do
                    [[ "${sslvers2[i]}" != "SSLv2" ]] && ! "${ciphers_found2[i]}" && ciphers_to_test+=":${ciph2[i]}"
               done
               success=1
               if [[ -n "$ciphers_to_test" ]]; then
                    $OPENSSL s_client $addcmd -cipher "${ciphers_to_test:1}" $STARTTLS $BUGS -connect $NODEIP:$PORT $PROXY $SNI >$TMPFILE 2>$ERRFILE </dev/null
                    sclient_connect_successful "$?" "$TMPFILE"
                    if [[ "$?" -eq 0 ]]; then
                         cipher=$(awk '/Cipher *:/ { print $3 }' $TMPFILE)
                         if [[ -n "$cipher" ]]; then
                              success=0
                              for (( i=bundle*bundle_size; i < end_of_bundle; i++ )); do
                                   [[ "$cipher" == "${ciph2[i]}" ]] && ciphers_found2[i]=true && break
                              done
                              i=${index[i]}
                              ciphers_found[i]=true
                              if [[ ${kx[i]} == "Kx=ECDH" ]] || [[ ${kx[i]} == "Kx=DH" ]] || [[ ${kx[i]} == "Kx=EDH" ]]; then
                                   dhlen=$(read_dhbits_from_file "$TMPFILE" quiet)
                                   kx[i]="${kx[i]} $dhlen"
                              fi
                              "$SHOW_SIGALGO" && grep -q "\-\-\-\-\-BEGIN CERTIFICATE\-\-\-\-\-" $TMPFILE && \
                                   sigalg[i]="$($OPENSSL x509 -noout -text -in $TMPFILE | awk -F':' '/Signature Algorithm/ { print $2 }' | head -1)"
                         fi
                    fi
               fi
          done
     done

     if "$using_sockets"; then
          for (( i=0; i < nr_ciphers; i++ )); do
               if ! "${ciphers_found[i]}"; then
                    ciphers_found2[nr_nonossl_ciphers]=false
                    sslvers2[nr_nonossl_ciphers]="${sslvers[i]}"
                    hexcode2[nr_nonossl_ciphers]="${hexcode[i]}"
                    rfc_ciph2[nr_nonossl_ciphers]="${TLS_CIPHER_RFC_NAME[i]}"
                    index[nr_nonossl_ciphers]=$i
                    nr_nonossl_ciphers+=1
               fi
          done
     fi

     if [[ $nr_nonossl_ciphers -eq 0 ]]; then
          num_bundles=0
     else
          # Some servers can't handle a handshake with >= 128 ciphers. So,
          # test cipher suites in bundles of 128 or less.
          num_bundles=$nr_nonossl_ciphers/128
          mod_check=$nr_nonossl_ciphers%128
          [[ $mod_check -ne 0 ]] && num_bundles=$num_bundles+1

          bundle_size=$nr_nonossl_ciphers/$num_bundles
          mod_check=$nr_nonossl_ciphers%$num_bundles
          [[ $mod_check -ne 0 ]] && bundle_size+=1
     fi

     for (( bundle=0; bundle < num_bundles; bundle++ )); do
          end_of_bundle=$bundle*$bundle_size+$bundle_size
          [[ $end_of_bundle -gt $nr_nonossl_ciphers ]] && end_of_bundle=$nr_nonossl_ciphers
          for (( success=0; success==0 ; 1 )); do
               ciphers_to_test=""
               for (( i=bundle*bundle_size; i < end_of_bundle; i++ )); do
                    [[ "${sslvers2[i]}" != "SSLv2" ]] && ! "${ciphers_found2[i]}" && ciphers_to_test+=", ${hexcode2[i]}"
               done
               success=1
               if [[ -n "$ciphers_to_test" ]]; then
                    if "$SHOW_SIGALGO"; then
                         tls_sockets "03" "${ciphers_to_test:2}, 00,ff" "all"
                    else
                         tls_sockets "03" "${ciphers_to_test:2}, 00,ff" "ephemeralkey"
                    fi
                    ret=$?
                    if [[ $ret -eq 0 ]] || [[ $ret -eq 2 ]]; then
                         success=0
                         cipher=$(awk '/Cipher *:/ { print $3 }' "$TEMPDIR/$NODEIP.parse_tls_serverhello.txt")
                         for (( i=bundle*bundle_size; i < end_of_bundle; i++ )); do
                              [[ "$cipher" == "${rfc_ciph2[i]}" ]] && ciphers_found2[i]=true && break
                         done
                         i=${index[i]}
                         ciphers_found[i]=true
                         if [[ ${kx[i]} == "Kx=ECDH" ]] || [[ ${kx[i]} == "Kx=DH" ]] || [[ ${kx[i]} == "Kx=EDH" ]]; then
                              dhlen=$(read_dhbits_from_file "$TEMPDIR/$NODEIP.parse_tls_serverhello.txt" quiet)
                              kx[i]="${kx[i]} $dhlen"
                         fi
                         "$SHOW_SIGALGO" && [[ -r "$HOSTCERT" ]] && sigalg[i]="$($OPENSSL x509 -noout -text -in "$HOSTCERT" | awk -F':' '/Signature Algorithm/ { print $2 }' | head -1)"
                    fi
               fi
          done
     done

     for (( i=0 ; i<nr_ciphers; i++ )); do
          if "${ciphers_found[i]}" || ( "$SHOW_EACH_C" && ( "$using_sockets" || "${ossl_supported[i]}" ) ); then
               export=${export2[i]}
               neat_list "${normalized_hexcode[i]}" "${ciph[i]}" "${kx[i]}" "${enc[i]}" "${ciphers_found[i]}"
               available=""
               if "$SHOW_EACH_C"; then
                    if ${ciphers_found[i]}; then
                         available="available"
                         pr_cyan "$available"
                    else
                         available="not a/v"
                         pr_deemphasize "$available"
                    fi
               fi
               outln "${sigalg[i]}"
               fileout "cipher_${normalized_hexcode[i]}" "INFO" "$(neat_list "${normalized_hexcode[i]}" "${ciph[i]}" "${kx[i]}" "${enc[i]}") $available"
          fi
     done
     "$using_sockets" && HAS_DH_BITS="$has_dh_bits"

     outln
     return 0
}

# test for all ciphers per protocol locally configured (w/o distinguishing whether they are good or bad)
run_cipher_per_proto() {
     local proto proto_hex proto_text ossl_ciphers_proto
     local -i nr_ciphers nr_ossl_ciphers nr_nonossl_ciphers success
     local n sslvers auth mac export hexc sslv2_ciphers="" cipher
     local -a hexcode normalized_hexcode ciph rfc_ciph kx enc export2
     local -a hexcode2 ciph2 rfc_ciph2
     local -i i bundle end_of_bundle bundle_size num_bundles mod_check
     local -a ciphers_found ciphers_found2 sigalg ossl_supported index
     local dhlen supported_sslv2_ciphers ciphers_to_test addcmd sni temp
     local available
     local id
     local has_dh_bits="$HAS_DH_BITS"
     local using_sockets=true

     "$SSL_NATIVE" && using_sockets=false
     "$FAST" && using_sockets=false
     [[ $TLS_NR_CIPHERS == 0 ]] && using_sockets=false

     outln
     if "$using_sockets"; then
          pr_headlineln " Testing ciphers per protocol via OpenSSL plus sockets against the server, ordered by encryption strength "
     else
          pr_headlineln " Testing all locally available ciphers per protocol against the server, ordered by encryption strength "
          [[ $TLS_NR_CIPHERS == 0 ]] && ! "$SSL_NATIVE" && ! "$FAST" && pr_warning " Cipher mapping not available, doing a fallback to openssl"
          outln
          if ! "$HAS_DH_BITS"; then
               [[ $TLS_NR_CIPHERS == 0 ]] && ! "$SSL_NATIVE" && ! "$FAST" && out "."
               pr_warningln "    (Your $OPENSSL cannot show DH/ECDH bits)"
          fi
     fi
     outln
     neat_header
     outln " -ssl2 22 SSLv2\n -ssl3 00 SSLv3\n -tls1 01 TLS 1\n -tls1_1 02 TLS 1.1\n -tls1_2 03 TLS 1.2"| while read proto proto_hex proto_text; do
          "$using_sockets" || locally_supported "$proto" "$proto_text" || continue
          "$using_sockets" && out "$proto_text "
          outln
          has_server_protocol "${proto:1}" || continue

          # get a list of all the cipher suites to test
          nr_ciphers=0
          if "$using_sockets" || [[ $OSSL_VER_MAJOR -lt 1 ]]; then
               for (( i=0; i < TLS_NR_CIPHERS; i++ )); do
                    hexc="${TLS_CIPHER_HEXCODE[i]}"
                    ciph[nr_ciphers]="${TLS_CIPHER_OSSL_NAME[i]}"
                    rfc_ciph[nr_ciphers]="${TLS_CIPHER_RFC_NAME[i]}"
                    kx[nr_ciphers]="${TLS_CIPHER_KX[i]}"
                    enc[nr_ciphers]="${TLS_CIPHER_ENC[i]}"
                    export2[nr_ciphers]="${TLS_CIPHER_EXPORT[i]}"
                    ciphers_found[nr_ciphers]=false
                    sigalg[nr_ciphers]=""
                    ossl_supported[nr_ciphers]=${TLS_CIPHER_OSSL_SUPPORTED[i]}
                    if "$using_sockets" && ! "$has_dh_bits" && ( [[ ${kx[nr_ciphers]} == "Kx=ECDH" ]] || [[ ${kx[nr_ciphers]} == "Kx=DH" ]] || [[ ${kx[nr_ciphers]} == "Kx=EDH" ]] ); then
                         ossl_supported[nr_ciphers]=false
                    fi
                    if [[ ${#hexc} -eq 9 ]]; then
                         hexcode[nr_ciphers]="${hexc:2:2},${hexc:7:2}"
                         if [[ "${hexc:2:2}" == "00" ]]; then
                              normalized_hexcode[nr_ciphers]="x${hexc:7:2}"
                         else
                              normalized_hexcode[nr_ciphers]="x${hexc:2:2}${hexc:7:2}"
                         fi
                    else
                         hexc="$(tolower "$hexc")"
                         hexcode[nr_ciphers]="${hexc:2:2},${hexc:7:2},${hexc:12:2}"
                         normalized_hexcode[nr_ciphers]="x${hexc:2:2}${hexc:7:2}${hexc:12:2}"
                    fi
                    if ( "$using_sockets" || "${TLS_CIPHER_OSSL_SUPPORTED[i]}" ); then
                         if [[ ${#hexc} -eq 9 ]] && [[ "$proto_text" != "SSLv2" ]]; then
                              if [[ "$proto_text" == "TLS 1.3" ]]; then
                                   [[ "${hexc:2:2}" == "13" ]] && nr_ciphers+=1
                              elif [[ "$proto_text" == "TLS 1.2" ]]; then
                                   [[ "${hexc:2:2}" != "13" ]] && nr_ciphers+=1
                              elif [[ ! "${TLS_CIPHER_RFC_NAME[i]}" =~ "SHA256" ]] && [[ ! "${TLS_CIPHER_RFC_NAME[i]}" =~ "SHA384" ]] && \
                                   [[ "${TLS_CIPHER_RFC_NAME[i]}" != *"_CCM" ]] && [[ "${TLS_CIPHER_RFC_NAME[i]}" != *"_CCM_8" ]]; then
                                   nr_ciphers+=1
                              fi
                         elif [[ ${#hexc} -eq 14 ]] && [[ "$proto_text" == "SSLv2" ]]; then
                              sslv2_ciphers+=", ${hexcode[nr_ciphers]}"
                              nr_ciphers+=1
                         fi
                    fi
               done
          else
               # The OpenSSL ciphers function, prior to version 1.1.0, could only understand -ssl2, -ssl3, and -tls1.
               if [[ "$proto" == "-ssl2" ]] || [[ "$proto" == "-ssl3" ]] || \
                    [[ $OSSL_VER_MAJOR.$OSSL_VER_MINOR == "1.1.0"* ]] || [[ $OSSL_VER_MAJOR.$OSSL_VER_MINOR == "1.1.1"* ]]; then
                    ossl_ciphers_proto="$proto"
               else
                    ossl_ciphers_proto="-tls1"
               fi
               while read hexc n ciph[nr_ciphers] sslvers kx[nr_ciphers] auth enc[nr_ciphers] mac export2[nr_ciphers]; do
                    if [[ "$proto_text" == "TLS 1.2" ]] || \
                       ( [[ "${ciph[nr_ciphers]}" != *"-SHA256" ]] && [[ "${ciph[nr_ciphers]}" != *"-SHA384" ]] && \
                         [[ "${ciph[nr_ciphers]}" != *"-CCM" ]] && [[ "${ciph[nr_ciphers]}" != *"-CCM8" ]] && \
                         [[ ! "${ciph[nr_ciphers]}" =~ "-CHACHA20-POLY1305" ]] ); then
                         ciphers_found[nr_ciphers]=false
                         if [[ ${#hexc} -eq 9 ]]; then
                              if [[ "${hexc:2:2}" == "00" ]]; then
                                   normalized_hexcode[nr_ciphers]="x${hexc:7:2}"
                              else
                                   normalized_hexcode[nr_ciphers]="x${hexc:2:2}${hexc:7:2}"
                              fi
                         else
                              normalized_hexcode[nr_ciphers]="$(tolower "x${hexc:2:2}${hexc:7:2}${hexc:12:2}")"
                         fi
                         sigalg[nr_ciphers]=""
                         ossl_supported[nr_ciphers]=true
                         nr_ciphers+=1
                    fi
               done < <($OPENSSL ciphers $ossl_ciphers_proto -V 'ALL:COMPLEMENTOFALL:@STRENGTH' 2>>$ERRFILE)
          fi

          if [[ "$proto" == "-ssl2" ]] && "$using_sockets"; then
               sslv2_sockets "${sslv2_ciphers:2}" "true"
               if [[ $? -eq 3 ]] && [[ "$V2_HELLO_CIPHERSPEC_LENGTH" -ne 0 ]]; then
                    supported_sslv2_ciphers="$(grep "Supported cipher: " "$TEMPDIR/$NODEIP.parse_sslv2_serverhello.txt")"
                    "$SHOW_SIGALGO" && s="$($OPENSSL x509 -noout -text -in "$HOSTCERT" | awk -F':' '/Signature Algorithm/ { print $2 }' | head -1)"
                    for (( i=0 ; i<nr_ciphers; i++ )); do
                         if [[ "$supported_sslv2_ciphers" =~ "${normalized_hexcode[i]}" ]]; then
                              ciphers_found[i]=true
                              "$SHOW_SIGALGO" && sigalg[i]="$s"
                         fi
                    done
               fi
          elif [[ "$proto" == "-ssl2" ]]; then
               $OPENSSL s_client $STARTTLS $BUGS -connect $NODEIP:$PORT $PROXY -ssl2 >$TMPFILE 2>$ERRFILE </dev/null
               sclient_connect_successful "$?" "$TMPFILE"
               if [[ "$?" -eq 0 ]]; then
                    supported_sslv2_ciphers="$(grep -A 4 "Ciphers common between both SSL endpoints:" $TMPFILE)"
                    "$SHOW_SIGALGO" && s="$($OPENSSL x509 -noout -text -in $TMPFILE | awk -F':' '/Signature Algorithm/ { print $2 }' | head -1)"
                    for (( i=0 ; i<nr_ciphers; i++ )); do
                         if [[ "$supported_sslv2_ciphers" =~ "${ciph[i]}" ]]; then
                              ciphers_found[i]=true
                              "$SHOW_SIGALGO" && sigalg[i]="$s"
                         fi
                    done
               fi
          else
               nr_ossl_ciphers=0
               for (( i=0; i < nr_ciphers; i++ )); do
                    if "${ossl_supported[i]}"; then
                         ciphers_found2[nr_ossl_ciphers]=false
                         ciph2[nr_ossl_ciphers]="${ciph[i]}"
                         index[nr_ossl_ciphers]=$i
                         nr_ossl_ciphers+=1
                    fi
               done

               if [[ $nr_ossl_ciphers -eq 0 ]]; then
                    num_bundles=0
               else
                    # Some servers can't handle a handshake with >= 128 ciphers. So,
                    # test cipher suites in bundles of 128 or less.
                    num_bundles=$nr_ossl_ciphers/128
                    mod_check=$nr_ossl_ciphers%128
                    [[ $mod_check -ne 0 ]] && num_bundles=$num_bundles+1

                    bundle_size=$nr_ossl_ciphers/$num_bundles
                    mod_check=$nr_ossl_ciphers%$num_bundles
                    [[ $mod_check -ne 0 ]] && bundle_size+=1
               fi

               sni=""
               [[ ! "$proto" =~ ssl ]] && sni="$SNI"
               for (( bundle=0; bundle < num_bundles; bundle++ )); do
                    end_of_bundle=$bundle*$bundle_size+$bundle_size
                    [[ $end_of_bundle -gt $nr_ossl_ciphers ]] && end_of_bundle=$nr_ossl_ciphers
                    for (( success=0; success==0 ; 1 )); do
                         ciphers_to_test=""
                         for (( i=bundle*bundle_size; i < end_of_bundle; i++ )); do
                              ! "${ciphers_found2[i]}" && ciphers_to_test+=":${ciph2[i]}"
                         done
                         success=1
                         if [[ -n "$ciphers_to_test" ]]; then
                              $OPENSSL s_client -cipher "${ciphers_to_test:1}" $proto $STARTTLS $BUGS -connect $NODEIP:$PORT $PROXY $sni >$TMPFILE 2>$ERRFILE </dev/null
                              sclient_connect_successful "$?" "$TMPFILE"
                              if [[ "$?" -eq 0 ]]; then
                                   cipher=$(awk '/Cipher *:/ { print $3 }' $TMPFILE)
                                   if [[ -n "$cipher" ]]; then
                                        success=0
                                        for (( i=bundle*bundle_size; i < end_of_bundle; i++ )); do
                                             [[ "$cipher" == "${ciph2[i]}" ]] && ciphers_found2[i]=true && break
                                        done
                                        i=${index[i]}
                                        ciphers_found[i]=true
                                        if [[ ${kx[i]} == "Kx=ECDH" ]] || [[ ${kx[i]} == "Kx=DH" ]] || [[ ${kx[i]} == "Kx=EDH" ]]; then
                                             dhlen=$(read_dhbits_from_file "$TMPFILE" quiet)
                                             kx[i]="${kx[i]} $dhlen"
                                        fi
                                        "$SHOW_SIGALGO" && grep -q "\-\-\-\-\-BEGIN CERTIFICATE\-\-\-\-\-" $TMPFILE && \
                                             sigalg[i]="$($OPENSSL x509 -noout -text -in $TMPFILE | awk -F':' '/Signature Algorithm/ { print $2 }' | head -1)"
                                   fi
                              fi
                         fi
                    done
               done

               if "$using_sockets"; then
                    nr_nonossl_ciphers=0
                    for (( i=0; i < nr_ciphers; i++ )); do
                         if ! "${ciphers_found[i]}"; then
                              ciphers_found2[nr_nonossl_ciphers]=false
                              hexcode2[nr_nonossl_ciphers]="${hexcode[i]}"
                              rfc_ciph2[nr_nonossl_ciphers]="${rfc_ciph[i]}"
                              index[nr_nonossl_ciphers]=$i
                              nr_nonossl_ciphers+=1
                         fi
                    done
               fi

               if [[ $nr_nonossl_ciphers -eq 0 ]]; then
                    num_bundles=0
               else
                    # Some servers can't handle a handshake with >= 128 ciphers. So,
                    # test cipher suites in bundles of 128 or less.
                    num_bundles=$nr_nonossl_ciphers/128
                    mod_check=$nr_nonossl_ciphers%128
                    [[ $mod_check -ne 0 ]] && num_bundles=$num_bundles+1

                    bundle_size=$nr_nonossl_ciphers/$num_bundles
                    mod_check=$nr_nonossl_ciphers%$num_bundles
                    [[ $mod_check -ne 0 ]] && bundle_size+=1
               fi

               for (( bundle=0; bundle < num_bundles; bundle++ )); do
                    end_of_bundle=$bundle*$bundle_size+$bundle_size
                    [[ $end_of_bundle -gt $nr_nonossl_ciphers ]] && end_of_bundle=$nr_nonossl_ciphers
                    for (( success=0; success==0 ; 1 )); do
                         ciphers_to_test=""
                         for (( i=bundle*bundle_size; i < end_of_bundle; i++ )); do
                              ! "${ciphers_found2[i]}" && ciphers_to_test+=", ${hexcode2[i]}"
                         done
                         success=1
                         if [[ -n "$ciphers_to_test" ]]; then
                              if "$SHOW_SIGALGO"; then
                                   tls_sockets "$proto_hex" "${ciphers_to_test:2}, 00,ff" "all"
                              else
                                   tls_sockets "$proto_hex" "${ciphers_to_test:2}, 00,ff" "ephemeralkey"
                              fi
                              if [[ $? -eq 0 ]]; then
                                   success=0
                                   cipher=$(awk '/Cipher *:/ { print $3 }' "$TEMPDIR/$NODEIP.parse_tls_serverhello.txt")
                                   for (( i=bundle*bundle_size; i < end_of_bundle; i++ )); do
                                        [[ "$cipher" == "${rfc_ciph2[i]}" ]] && ciphers_found2[i]=true && break
                                   done
                                   i=${index[i]}
                                   ciphers_found[i]=true
                                   if [[ "$proto_text" == "TLS 1.3" ]]; then
                                        temp=$(awk -F': ' '/^Server Temp Key/ { print $2 }' "$TEMPDIR/$NODEIP.parse_tls_serverhello.txt")        # extract line
                                        kx[i]="Kx=$(awk -F',' '{ print $1 }' <<< $temp)"
                                   fi
                                   if [[ ${kx[i]} == "Kx=ECDH" ]] || [[ ${kx[i]} == "Kx=DH" ]] || [[ ${kx[i]} == "Kx=EDH" ]]; then
                                        dhlen=$(read_dhbits_from_file "$TEMPDIR/$NODEIP.parse_tls_serverhello.txt" quiet)
                                        kx[i]="${kx[i]} $dhlen"
                                   fi
                                   "$SHOW_SIGALGO" && [[ -r "$HOSTCERT" ]] && \
                                        sigalg[i]="$($OPENSSL x509 -noout -text -in "$HOSTCERT" | awk -F':' '/Signature Algorithm/ { print $2 }' | head -1)"
                              fi
                         fi
                    done
               done
          fi

          for (( i=0 ; i<nr_ciphers; i++ )); do
               if "${ciphers_found[i]}" || "$SHOW_EACH_C"; then
                    export=${export2[i]}
                    normalized_hexcode[i]="$(tolower "${normalized_hexcode[i]}")"
                    neat_list "${normalized_hexcode[i]}" "${ciph[i]}" "${kx[i]}" "${enc[i]}" "${ciphers_found[i]}"
                    available=""
                    if "$SHOW_EACH_C"; then
                         if "${ciphers_found[i]}"; then
                              available="available"
                              pr_cyan "$available"
                         else
                              available="not a/v"
                              pr_deemphasize "$available"
                         fi
                    fi
                    outln "${sigalg[i]}"
                    id="cipher$proto"
                    id+="_${normalized_hexcode[i]}"
                    fileout "$id" "INFO" "$proto_text  $(neat_list "${normalized_hexcode[i]}" "${ciph[i]}" "${kx[i]}" "${enc[i]}") $available"
               fi
          done
     done
     "$using_sockets" && HAS_DH_BITS="$has_dh_bits"
     tmpfile_handle $FUNCNAME.txt
     return 0
}

# arg1 is an ASCII-HEX encoded SSLv3 or TLS ClientHello.
# If the ClientHello contains a server name extension, then
# either:
#  1) replace it with one corresponding to $SNI; or
#  2) remove it, if $SNI is empty
create_client_simulation_tls_clienthello() {
     local tls_handshake_ascii="$1"
     local -i len offset tls_handshake_ascii_len len_all len_clienthello
     local -i len_extensions len_extension
     local content_type tls_version_reclayer handshake_msg_type tls_clientversion
     local tls_random tls_sid tls_cipher_suites tls_compression_methods
     local tls_extensions="" extension_type len_extensions_hex
     local len_servername hexdump_format_str servername_hexstr
     local len_servername_hex len_sni_listlen len_sni_ext
     local tls_client_hello len_clienthello_hex tls_handshake_ascii_len_hex
     local sni_extension_found=false

     tls_handshake_ascii_len=${#tls_handshake_ascii}

     tls_content_type="${tls_handshake_ascii:0:2}"
     tls_version_reclayer="${tls_handshake_ascii:2:4}"
     len_all=$(hex2dec "${tls_handshake_ascii:6:4}")

     handshake_msg_type="${tls_handshake_ascii:10:2}"
     len_clienthello=$(hex2dec "${tls_handshake_ascii:12:6}")
     tls_clientversion="${tls_handshake_ascii:18:4}"
     tls_random="${tls_handshake_ascii:22:64}"
     len=2*$(hex2dec "${tls_handshake_ascii:86:2}")+2
     tls_sid="${tls_handshake_ascii:86:$len}"
     offset=86+$len

     len=2*$(hex2dec "${tls_handshake_ascii:$offset:4}")+4
     tls_cipher_suites="${tls_handshake_ascii:$offset:$len}"
     offset=$offset+$len

     len=2*$(hex2dec "${tls_handshake_ascii:$offset:2}")+2
     tls_compression_methods="${tls_handshake_ascii:$offset:$len}"
     offset=$offset+$len

     if [[ $offset -ge $tls_handshake_ascii_len ]]; then
          # No extensions
          out "$tls_handshake_ascii"
          return 0
     fi

     len_extensions=2*$(hex2dec "${tls_handshake_ascii:$offset:4}")
     offset=$offset+4
     for (( 1; offset < tls_handshake_ascii_len; 1 )); do
         extension_type="${tls_handshake_ascii:$offset:4}"
         offset=$offset+4
         len_extension=2*$(hex2dec "${tls_handshake_ascii:$offset:4}")

         if [[ "$extension_type" != "0000" ]]; then
             # The extension will just be copied into the revised ClientHello
             sni_extension_found=true
             offset=$offset-4
             len=$len_extension+8
             tls_extensions+="${tls_handshake_ascii:$offset:$len}"
             offset=$offset+$len
         elif [[ -n "$SNI" ]]; then
             # Create a server name extension that corresponds to $SNI
             len_servername=${#NODE}
             hexdump_format_str="$len_servername/1 \"%02x\""
             servername_hexstr=$(printf $NODE | hexdump -v -e "${hexdump_format_str}")
             # convert lengths we need to fill in from dec to hex:
             len_servername_hex=$(printf "%02x\n" $len_servername)
             len_sni_listlen=$(printf "%02x\n" $((len_servername+3)))
             len_sni_ext=$(printf "%02x\n" $((len_servername+5)))
             tls_extensions+="000000${len_sni_ext}00${len_sni_listlen}0000${len_servername_hex}${servername_hexstr}"
             offset=$offset+$len_extension+4
         fi
     done

     if ! $sni_extension_found; then
          out "$tls_handshake_ascii"
          return 0
     fi

     len_extensions=${#tls_extensions}/2
     len_extensions_hex=$(printf "%02x\n" $len_extensions)
     len2twobytes "$len_extensions_hex"
     tls_extensions="${LEN_STR:0:2}${LEN_STR:4:2}${tls_extensions}"

     tls_client_hello="${tls_clientversion}${tls_random}${tls_sid}${tls_cipher_suites}${tls_compression_methods}${tls_extensions}"
     len_clienthello=${#tls_client_hello}/2
     len_clienthello_hex=$(printf "%02x\n" $len_clienthello)
     len2twobytes "$len_clienthello_hex"
     tls_handshake_ascii="${handshake_msg_type}00${LEN_STR:0:2}${LEN_STR:4:2}${tls_client_hello}"

     tls_handshake_ascii_len=${#tls_handshake_ascii}/2
     tls_handshake_ascii_len_hex=$(printf "%02x\n" $tls_handshake_ascii_len)
     len2twobytes "$tls_handshake_ascii_len_hex"
     tls_handshake_ascii="${tls_content_type}${tls_version_reclayer}${LEN_STR:0:2}${LEN_STR:4:2}${tls_handshake_ascii}"
     out "$tls_handshake_ascii"
     return 0
}

client_simulation_sockets() {
     local -i len i ret=0
     local -i save=0
     local lines clienthello data=""
     local cipher_list_2send
     local sock_reply_file2 sock_reply_file3
     local tls_hello_ascii next_packet hello_done=0

     if [[ "${1:0:4}" == "1603" ]]; then
          clienthello="$(create_client_simulation_tls_clienthello "$1")"
     else
          clienthello="$1"
     fi
     len=${#clienthello}
     for (( i=0; i < len; i=i+2 )); do
          data+=", ${clienthello:i:2}"
     done
     debugme echo "sending client hello..."
     code2network "${data}"
     fd_socket 5 || return 6
     data=$(echo $NW_STR)
     [[ "$DEBUG" -ge 4 ]] && echo "\"$data\""
     printf -- "$data" >&5 2>/dev/null &
     sleep $USLEEP_SND

     sockread_serverhello 32768
     TLS_NOW=$(LC_ALL=C date "+%s")

     tls_hello_ascii=$(hexdump -v -e '16/1 "%02X"' "$SOCK_REPLY_FILE")
     tls_hello_ascii="${tls_hello_ascii%%[!0-9A-F]*}"

     check_tls_serverhellodone "$tls_hello_ascii"
     hello_done=$?

     for(( 1 ; hello_done==1; 1 )); do
          sock_reply_file2=$(mktemp $TEMPDIR/ddreply.XXXXXX) || return 7
          mv "$SOCK_REPLY_FILE" "$sock_reply_file2"

          debugme echo "requesting more server hello data..."
          socksend "" $USLEEP_SND
          sockread_serverhello 32768

          next_packet=$(hexdump -v -e '16/1 "%02X"' "$SOCK_REPLY_FILE")
          next_packet="${next_packet%%[!0-9A-F]*}"
          if [[ ${#next_packet} -eq 0 ]]; then
               # This shouldn't be necessary. However, it protects against
               # getting into an infinite loop if the server has nothing
               # left to send and check_tls_serverhellodone doesn't
               # correctly catch it.
               mv "$sock_reply_file2" "$SOCK_REPLY_FILE"
               hello_done=0
          else
               tls_hello_ascii+="$next_packet"

               sock_reply_file3=$(mktemp $TEMPDIR/ddreply.XXXXXX) || return 7
               mv "$SOCK_REPLY_FILE" "$sock_reply_file3"
               mv "$sock_reply_file2" "$SOCK_REPLY_FILE"
               cat "$sock_reply_file3" >> "$SOCK_REPLY_FILE"
               rm "$sock_reply_file3"

               check_tls_serverhellodone "$tls_hello_ascii"
               hello_done=$?
          fi
     done

     debugme outln "reading server hello..."
     if [[ "$DEBUG" -ge 4 ]]; then
          hexdump -C $SOCK_REPLY_FILE | head -6
          echo
     fi

     parse_tls_serverhello "$tls_hello_ascii" "ephemeralkey"
     save=$?

     if [[ $save -eq 0 ]]; then
          debugme echo "sending close_notify..."
          if [[ "$DETECTED_TLS_VERSION" == "0300" ]]; then
               socksend ",x15, x03, x00, x00, x02, x02, x00" 0
          else
               socksend ",x15, x03, x01, x00, x02, x02, x00" 0
          fi
     fi

     # see https://secure.wand.net.nz/trac/libprotoident/wiki/SSL
     lines=$(count_lines "$(hexdump -C "$SOCK_REPLY_FILE" 2>$ERRFILE)")
     debugme out "  (returned $lines lines)  "

     # determine the return value for higher level, so that they can tell what the result is
     if [[ $save -eq 1 ]] || [[ $lines -eq 1 ]]; then
          ret=1          # NOT available
     else
          ret=0
     fi
     debugme outln

     close_socket
     TMPFILE=$SOCK_REPLY_FILE
     tmpfile_handle $FUNCNAME.dd
     return $ret
}

run_client_simulation() {
     # Runs browser simulations. Browser capabilities gathered from:
     # https://www.ssllabs.com/ssltest/clients.html on 10 jan 2016
     local names=()
     local short=()
     local protos=()
     local ciphers=()
     local tlsvers=()
     local sni=()
     local warning=()
     local handshakebytes=()
     local lowest_protocol=()
     local highest_protocol=()
     local service=()
     local minDhBits=()
     local maxDhBits=()
     local minRsaBits=()
     local maxRsaBits=()
     local minEcdsaBits=()
     local requiresSha2=()
     local i=0
     local name tls proto cipher temp what_dh bits has_dh_bits
     local using_sockets=true

     if "$SSL_NATIVE" || [[ -n "$STARTTLS" ]]; then
          using_sockets=false
     fi

     # doesn't make sense for other services
     if [[ $SERVICE != "HTTP" ]];  then
          return 0
     fi

     # FIXME: At a certain time we should put the following to an external file
     names+=("Android 2.3.7              ")
     short+=("android_237")
     protos+=("-no_tls1_2 -no_tls1_1 -no_ssl2")
     ciphers+=("RC4-MD5:RC4-SHA:AES128-SHA:DHE-RSA-AES128-SHA:DHE-DSS-AES128-SHA:DES-CBC3-SHA:EDH-RSA-DES-CBC3-SHA:EDH-DSS-DES-CBC3-SHA:DES-CBC-SHA:EDH-RSA-DES-CBC-SHA:EDH-DSS-DES-CBC-SHA:EXP-RC4-MD5:EXP-DES-CBC-SHA:EXP-EDH-RSA-DES-CBC-SHA:EXP-EDH-DSS-DES-CBC-SHA")
     tlsvers+=("-tls1")
     sni+=("")
     warning+=("")
     handshakebytes+=("160301004b010000470301531f3de6b36804738bbb94a6ecd570a544789c3bb0a6ef8b9d702f997d928d4b00002000040005002f00330032000a00160013000900150012000300080014001100ff0100")
     lowest_protocol+=("0x0300")
     highest_protocol+=("0x0301")
     service+=("HTTP")
     minDhBits+=(-1)
     maxDhBits+=(-1)
     minRsaBits+=(-1)
     maxRsaBits+=(-1)
     minEcdsaBits+=(-1)
     requiresSha2+=(false)

     names+=("Android 4.0.4              ")
     short+=("android_404")
     protos+=("-no_tls1_2 -no_tls1_1 -no_ssl2")
     ciphers+=("ECDHE-RSA-AES256-SHA:ECDHE-ECDSA-AES256-SHA:DHE-RSA-AES256-SHA:DHE-DSS-AES256-SHA:ECDH-RSA-AES256-SHA:ECDH-ECDSA-AES256-SHA:AES256-SHA:ECDHE-RSA-DES-CBC3-SHA:ECDHE-ECDSA-DES-CBC3-SHA:EDH-RSA-DES-CBC3-SHA:EDH-DSS-DES-CBC3-SHA:ECDH-RSA-DES-CBC3-SHA:ECDH-ECDSA-DES-CBC3-SHA:DES-CBC3-SHA:ECDHE-RSA-AES128-SHA:ECDHE-ECDSA-AES128-SHA:DHE-RSA-AES128-SHA:DHE-DSS-AES128-SHA:ECDH-RSA-AES128-SHA:ECDH-ECDSA-AES128-SHA:AES128-SHA:ECDHE-RSA-RC4-SHA:ECDHE-ECDSA-RC4-SHA:ECDH-RSA-RC4-SHA:ECDH-ECDSA-RC4-SHA:RC4-SHA:RC4-MD5")
     tlsvers+=("-tls1")
     sni+=("$SNI")
     warning+=("")
     handshakebytes+=("16030100c6010000c20301531f479cc7785f455ca7a70142af5be929c1ba931eedbf46dba6b6638da75e95000038c014c00a00390038c00fc0050035c012c00800160013c00dc003000ac013c00900330032c00ec004002fc011c007c00cc0020005000400ff020100006000000014001200000f7777772e73736c6c6162732e636f6d000b000403000102000a00340032000100020003000400050006000700080009000a000b000c000d000e000f00100011001200130014001500160017001800190023000033740000")
     lowest_protocol+=("0x0300")
     highest_protocol+=("0x0301")
     service+=("HTTP")
     minDhBits+=(-1)
     maxDhBits+=(-1)
     minRsaBits+=(-1)
     maxRsaBits+=(-1)
     minEcdsaBits+=(-1)
     requiresSha2+=(false)

     names+=("Android 4.1.1              ")
     short+=("android_411")
     protos+=("-no_tls1_2 -no_tls1_1 -no_ssl2")
     ciphers+=("ECDHE-RSA-AES256-SHA:ECDHE-ECDSA-AES256-SHA:SRP-DSS-AES-256-CBC-SHA:SRP-RSA-AES-256-CBC-SHA:DHE-RSA-AES256-SHA:DHE-DSS-AES256-SHA:ECDH-RSA-AES256-SHA:ECDH-ECDSA-AES256-SHA:AES256-SHA:ECDHE-RSA-DES-CBC3-SHA:ECDHE-ECDSA-DES-CBC3-SHA:SRP-DSS-3DES-EDE-CBC-SHA:SRP-RSA-3DES-EDE-CBC-SHA:EDH-RSA-DES-CBC3-SHA:EDH-DSS-DES-CBC3-SHA:ECDH-RSA-DES-CBC3-SHA:ECDH-ECDSA-DES-CBC3-SHA:DES-CBC3-SHA:ECDHE-RSA-AES128-SHA:ECDHE-ECDSA-AES128-SHA:SRP-DSS-AES-128-CBC-SHA:SRP-RSA-AES-128-CBC-SHA:DHE-RSA-AES128-SHA:DHE-DSS-AES128-SHA:ECDH-RSA-AES128-SHA:ECDH-ECDSA-AES128-SHA:AES128-SHA:ECDHE-RSA-RC4-SHA:ECDHE-ECDSA-RC4-SHA:ECDH-RSA-RC4-SHA:ECDH-ECDSA-RC4-SHA:RC4-SHA:RC4-MD5")
     tlsvers+=("-tls1")
     sni+=("$SNI")
     warning+=("")
     handshakebytes+=("16030100d7010000d30301531f3f6dd9eb5f6b3586c628cc2cdc82cdb259b1a096237ba4df30dbbc0f26fb000044c014c00ac022c02100390038c00fc0050035c012c008c01cc01b00160013c00dc003000ac013c009c01fc01e00330032c00ec004002fc011c007c00cc0020005000400ff020100006500000014001200000f7777772e73736c6c6162732e636f6d000b000403000102000a00340032000e000d0019000b000c00180009000a00160017000800060007001400150004000500120013000100020003000f0010001100230000000f00010133740000")
     lowest_protocol+=("0x0300")
     highest_protocol+=("0x0301")
     service+=("HTTP")
     minDhBits+=(-1)
     maxDhBits+=(-1)
     minRsaBits+=(-1)
     maxRsaBits+=(-1)
     minEcdsaBits+=(-1)
     requiresSha2+=(false)

     names+=("Android 4.2.2              ")
     short+=("android_422")
     protos+=("-no_tls1_2 -no_tls1_1 -no_ssl2")
     ciphers+=("ECDHE-RSA-AES256-SHA:ECDHE-ECDSA-AES256-SHA:SRP-DSS-AES-256-CBC-SHA:SRP-RSA-AES-256-CBC-SHA:DHE-RSA-AES256-SHA:DHE-DSS-AES256-SHA:ECDH-RSA-AES256-SHA:ECDH-ECDSA-AES256-SHA:AES256-SHA:ECDHE-RSA-DES-CBC3-SHA:ECDHE-ECDSA-DES-CBC3-SHA:SRP-DSS-3DES-EDE-CBC-SHA:SRP-RSA-3DES-EDE-CBC-SHA:EDH-RSA-DES-CBC3-SHA:EDH-DSS-DES-CBC3-SHA:ECDH-RSA-DES-CBC3-SHA:ECDH-ECDSA-DES-CBC3-SHA:DES-CBC3-SHA:ECDHE-RSA-AES128-SHA:ECDHE-ECDSA-AES128-SHA:SRP-DSS-AES-128-CBC-SHA:SRP-RSA-AES-128-CBC-SHA:DHE-RSA-AES128-SHA:DHE-DSS-AES128-SHA:ECDH-RSA-AES128-SHA:ECDH-ECDSA-AES128-SHA:AES128-SHA:ECDHE-RSA-RC4-SHA:ECDHE-ECDSA-RC4-SHA:ECDH-RSA-RC4-SHA:ECDH-ECDSA-RC4-SHA:RC4-SHA:RC4-MD5")
     tlsvers+=("-tls1")
     sni+=("$SNI")
     warning+=("")
     handshakebytes+=("16030100d1010000cd0301531f40a89e11d5681f563f3dad094375227035d4e9d2c1654d7d3954e3254558000044c014c00ac022c02100390038c00fc0050035c012c008c01cc01b00160013c00dc003000ac013c009c01fc01e00330032c00ec004002fc011c007c00cc0020005000400ff0100006000000014001200000f7777772e73736c6c6162732e636f6d000b000403000102000a00340032000e000d0019000b000c00180009000a00160017000800060007001400150004000500120013000100020003000f001000110023000033740000")
     lowest_protocol+=("0x0300")
     highest_protocol+=("0x0301")
     minDhBits+=(-1)
     maxDhBits+=(-1)
     minRsaBits+=(-1)
     maxRsaBits+=(-1)
     minEcdsaBits+=(-1)
     requiresSha2+=(false)

     names+=("Android 4.3                ")
     short+=("android_43")
     protos+=("-no_tls1_2 -no_tls1_1 -no_ssl2")
     ciphers+=("ECDHE-RSA-AES256-SHA:ECDHE-ECDSA-AES256-SHA:SRP-DSS-AES-256-CBC-SHA:SRP-RSA-AES-256-CBC-SHA:DHE-RSA-AES256-SHA:DHE-DSS-AES256-SHA:ECDH-RSA-AES256-SHA:ECDH-ECDSA-AES256-SHA:AES256-SHA:ECDHE-RSA-DES-CBC3-SHA:ECDHE-ECDSA-DES-CBC3-SHA:SRP-DSS-3DES-EDE-CBC-SHA:SRP-RSA-3DES-EDE-CBC-SHA:EDH-RSA-DES-CBC3-SHA:EDH-DSS-DES-CBC3-SHA:ECDH-RSA-DES-CBC3-SHA:ECDH-ECDSA-DES-CBC3-SHA:DES-CBC3-SHA:ECDHE-RSA-AES128-SHA:ECDHE-ECDSA-AES128-SHA:SRP-DSS-AES-128-CBC-SHA:SRP-RSA-AES-128-CBC-SHA:DHE-RSA-AES128-SHA:DHE-DSS-AES128-SHA:ECDH-RSA-AES128-SHA:ECDH-ECDSA-AES128-SHA:AES128-SHA:ECDHE-RSA-RC4-SHA:ECDHE-ECDSA-RC4-SHA:ECDH-RSA-RC4-SHA:ECDH-ECDSA-RC4-SHA:RC4-SHA:RC4-MD5")
     tlsvers+=("-tls1")
     sni+=("$SNI")
     warning+=("")
     handshakebytes+=("16030100d1010000cd0301531f41c3c5110dd688458e5e48e06d30814572ad7b8f9d9df1b0a8820b270685000044c014c00ac022c02100390038c00fc0050035c012c008c01cc01b00160013c00dc003000ac013c009c01fc01e00330032c00ec004002fc011c007c00cc0020005000400ff0100006000000014001200000f7777772e73736c6c6162732e636f6d000b000403000102000a00340032000e000d0019000b000c00180009000a00160017000800060007001400150004000500120013000100020003000f001000110023000033740000")
     lowest_protocol+=("0x0300")
     highest_protocol+=("0x0301")
     service+=("HTTP")
     minDhBits+=(-1)
     maxDhBits+=(-1)
     minRsaBits+=(-1)
     maxRsaBits+=(-1)
     minEcdsaBits+=(-1)
     requiresSha2+=(false)

     names+=("Android 4.4.2              ")
     short+=("android_442")
     protos+=("-no_ssl2")
     ciphers+=("ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-SHA:ECDHE-ECDSA-AES256-SHA:DHE-DSS-AES256-GCM-SHA384:DHE-RSA-AES256-GCM-SHA384:DHE-RSA-AES256-SHA256:DHE-DSS-AES256-SHA256:DHE-RSA-AES256-SHA:DHE-DSS-AES256-SHA:AES256-GCM-SHA384:AES256-SHA256:AES256-SHA:ECDHE-RSA-DES-CBC3-SHA:ECDHE-ECDSA-DES-CBC3-SHA:EDH-RSA-DES-CBC3-SHA:EDH-DSS-DES-CBC3-SHA:DES-CBC3-SHA:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-SHA256:ECDHE-ECDSA-AES128-SHA256:ECDHE-RSA-AES128-SHA:ECDHE-ECDSA-AES128-SHA:DHE-DSS-AES128-GCM-SHA256:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES128-SHA256:DHE-DSS-AES128-SHA256:DHE-RSA-AES128-SHA:DHE-DSS-AES128-SHA:AES128-GCM-SHA256:AES128-SHA256:AES128-SHA:ECDHE-RSA-RC4-SHA:ECDHE-ECDSA-RC4-SHA:RC4-SHA:RC4-MD5")
     tlsvers+=("-tls1_2 -tls1_1 -tls1")
     sni+=("$SNI")
     warning+=("")
     handshakebytes+=("16030100d1010000cd0303531f4317998fb70d57feded18c14433a1b665f963f7e3b1b045b6cc3d61bf21300004cc030c02cc014c00a00a3009f006b006a00390038009d003d0035c012c00800160013000ac02fc02bc027c023c013c00900a2009e0067004000330032009c003c002fc011c0070005000400ff0100005800000014001200000f7777772e73736c6c6162732e636f6d000b00020100000a0008000600190018001700230000000d00220020060106020603050105020503040104020403030103020303020102020203010133740000")
     lowest_protocol+=("0x0300")
     highest_protocol+=("0x0303")
     service+=("HTTP")
     minDhBits+=(-1)
     maxDhBits+=(-1)
     minRsaBits+=(-1)
     maxRsaBits+=(-1)
     minEcdsaBits+=(-1)
     requiresSha2+=(false)

     names+=("Android 5.0.0              ")
     short+=("android_500")
     protos+=("-no_ssl2")
     ciphers+=("ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-CHACHA20-POLY1305:ECDHE-RSA-AES256-SHA:ECDHE-ECDSA-AES256-SHA:DHE-RSA-AES256-SHA:DHE-DSS-AES256-SHA:AES256-SHA:ECDHE-RSA-DES-CBC3-SHA:ECDHE-ECDSA-DES-CBC3-SHA:EDH-RSA-DES-CBC3-SHA:EDH-DSS-DES-CBC3-SHA:DES-CBC3-SHA:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-SHA:ECDHE-ECDSA-AES128-SHA:DHE-DSS-AES128-GCM-SHA256:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES128-SHA:DHE-DSS-AES128-SHA:AES128-GCM-SHA256:AES128-SHA:ECDHE-RSA-RC4-SHA:ECDHE-ECDSA-RC4-SHA:RC4-SHA:RC4-MD5")
     tlsvers+=("-tls1_2 -tls1_1 -tls1")
     sni+=("$SNI")
     warning+=("")
     handshakebytes+=("16030100bd010000b9030354c21737f3d9d10696c91debf12415f9c45833a83cfbbd4c60c9b91407d2316b000038cc14cc13cc15c014c00a003900380035c012c00800160013000ac02fc02bc013c00900a2009e00330032009c002fc011c0070005000400ff0100005800000014001200000f6465762e73736c6c6162732e636f6d00230000000d00220020060106020603050105020503040104020403030103020303020102020203010133740000000b00020100000a00080006001900180017")
     lowest_protocol+=("0x0300")
     highest_protocol+=("0x0303")
     service+=("HTTP")
     minDhBits+=(-1)
     maxDhBits+=(-1)
     minRsaBits+=(-1)
     maxRsaBits+=(-1)
     minEcdsaBits+=(-1)
     requiresSha2+=(false)

     names+=("Baidu Jan 2015             ")
     short+=("baidu_jan_2015")
     protos+=("-no_tls1_2 -no_tls1_1 -no_ssl2")
     ciphers+=("ECDHE-ECDSA-AES256-SHA:ECDHE-RSA-AES256-SHA:DHE-RSA-CAMELLIA256-SHA:DHE-DSS-CAMELLIA256-SHA:DHE-RSA-AES256-SHA:DHE-DSS-AES256-SHA:ECDH-RSA-AES256-SHA:ECDH-ECDSA-AES256-SHA:CAMELLIA256-SHA:AES256-SHA:ECDHE-ECDSA-RC4-SHA:ECDHE-ECDSA-AES128-SHA:ECDHE-RSA-RC4-SHA:ECDHE-RSA-AES128-SHA:DHE-RSA-CAMELLIA128-SHA:DHE-DSS-CAMELLIA128-SHA:DHE-RSA-AES128-SHA:DHE-DSS-AES128-SHA:ECDH-RSA-RC4-SHA:ECDH-RSA-AES128-SHA:ECDH-ECDSA-RC4-SHA:ECDH-ECDSA-AES128-SHA:SEED-SHA:CAMELLIA128-SHA:RC4-MD5:RC4-SHA:AES128-SHA:ECDHE-ECDSA-DES-CBC3-SHA:ECDHE-RSA-DES-CBC3-SHA:EDH-RSA-DES-CBC3-SHA:EDH-DSS-DES-CBC3-SHA:ECDH-RSA-DES-CBC3-SHA:ECDH-ECDSA-DES-CBC3-SHA:DES-CBC3-SHA")
     tlsvers+=("-tls1")
     sni+=("$SNI")
     warning+=("")
     handshakebytes+=("16030100a30100009f030154c1a814c755540538a93b25e7824623d0ee9fc294ee752869cf76819edb3aa200004800ffc00ac0140088008700390038c00fc00500840035c007c009c011c0130045004400330032c00cc00ec002c0040096004100040005002fc008c01200160013c00dc003feff000a0100002e00000014001200000f6465762e73736c6c6162732e636f6d000a00080006001700180019000b0002010000230000")
     lowest_protocol+=("0x0300")
     highest_protocol+=("0x0301")
     service+=("HTTP")
     minDhBits+=(-1)
     maxDhBits+=(-1)
     minRsaBits+=(-1)
     maxRsaBits+=(-1)
     minEcdsaBits+=(-1)
     requiresSha2+=(false)

     names+=("BingPreview Jan 2015       ")
     short+=("bingpreview_jan_2015")
     protos+=("-no_ssl2")
     ciphers+=("ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-SHA384:ECDHE-ECDSA-AES256-SHA384:ECDHE-RSA-AES256-SHA:ECDHE-ECDSA-AES256-SHA:SRP-DSS-AES-256-CBC-SHA:SRP-RSA-AES-256-CBC-SHA:DHE-DSS-AES256-GCM-SHA384:DHE-RSA-AES256-GCM-SHA384:DHE-RSA-AES256-SHA256:DHE-DSS-AES256-SHA256:DHE-RSA-AES256-SHA:DHE-DSS-AES256-SHA:DHE-RSA-CAMELLIA256-SHA:DHE-DSS-CAMELLIA256-SHA:ECDH-RSA-AES256-GCM-SHA384:ECDH-ECDSA-AES256-GCM-SHA384:ECDH-RSA-AES256-SHA384:ECDH-ECDSA-AES256-SHA384:ECDH-RSA-AES256-SHA:ECDH-ECDSA-AES256-SHA:AES256-GCM-SHA384:AES256-SHA256:AES256-SHA:CAMELLIA256-SHA:ECDHE-RSA-DES-CBC3-SHA:ECDHE-ECDSA-DES-CBC3-SHA:SRP-DSS-3DES-EDE-CBC-SHA:SRP-RSA-3DES-EDE-CBC-SHA:EDH-RSA-DES-CBC3-SHA:EDH-DSS-DES-CBC3-SHA:ECDH-RSA-DES-CBC3-SHA:ECDH-ECDSA-DES-CBC3-SHA:DES-CBC3-SHA:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-SHA256:ECDHE-ECDSA-AES128-SHA256:ECDHE-RSA-AES128-SHA:ECDHE-ECDSA-AES128-SHA:SRP-DSS-AES-128-CBC-SHA:SRP-RSA-AES-128-CBC-SHA:DHE-DSS-AES128-GCM-SHA256:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES128-SHA256:DHE-DSS-AES128-SHA256:DHE-RSA-AES128-SHA:DHE-DSS-AES128-SHA:DHE-RSA-SEED-SHA:DHE-DSS-SEED-SHA:DHE-RSA-CAMELLIA128-SHA:DHE-DSS-CAMELLIA128-SHA:ECDH-RSA-AES128-GCM-SHA256:ECDH-ECDSA-AES128-GCM-SHA256:ECDH-RSA-AES128-SHA256:ECDH-ECDSA-AES128-SHA256:ECDH-RSA-AES128-SHA:ECDH-ECDSA-AES128-SHA:AES128-GCM-SHA256:AES128-SHA256:AES128-SHA:SEED-SHA:CAMELLIA128-SHA:IDEA-CBC-SHA:ECDHE-RSA-RC4-SHA:ECDHE-ECDSA-RC4-SHA:ECDH-RSA-RC4-SHA:ECDH-ECDSA-RC4-SHA:RC4-SHA:RC4-MD5:EDH-RSA-DES-CBC-SHA:EDH-DSS-DES-CBC-SHA:DES-CBC-SHA:EXP-EDH-RSA-DES-CBC-SHA:EXP-EDH-DSS-DES-CBC-SHA:EXP-DES-CBC-SHA:EXP-RC2-CBC-MD5:EXP-RC4-MD5")
     tlsvers+=("-tls1_2 -tls1_1 -tls1")
     sni+=("$SNI")
     warning+=("")
     handshakebytes+=("16030101510100014d030354c13b79c1ca7169ae70c45d43311f9290d8ac1e326dfc36ff0aa99ea85406d50000a0c030c02cc028c024c014c00ac022c02100a3009f006b006a0039003800880087c032c02ec02ac026c00fc005009d003d00350084c012c008c01cc01b00160013c00dc003000ac02fc02bc027c023c013c009c01fc01e00a2009e0067004000330032009a009900450044c031c02dc029c025c00ec004009c003c002f009600410007c011c007c00cc002000500040015001200090014001100080006000300ff020100008300000014001200000f6465762e73736c6c6162732e636f6d000b000403000102000a00340032000e000d0019000b000c00180009000a00160017000800060007001400150004000500120013000100020003000f00100011000d002200200601060206030501050205030401040204030301030203030201020202030101000f000101")
     lowest_protocol+=("0x0300")
     highest_protocol+=("0x0303")
     service+=("HTTP")
     minDhBits+=(-1)
     maxDhBits+=(-1)
     minRsaBits+=(-1)
     maxRsaBits+=(-1)
     minEcdsaBits+=(-1)
     requiresSha2+=(false)

     names+=("Chrome 47 / OSX            ")
     short+=("chrome_47_osx")
     protos+=("-no_ssl2 -no_ssl3")
     ciphers+=("ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:ECDHE-ECDSA-AES256-SHA:ECDHE-RSA-AES256-SHA:DHE-RSA-AES256-SHA:ECDHE-ECDSA-AES128-SHA:ECDHE-RSA-AES128-SHA:DHE-RSA-AES128-SHA:AES128-GCM-SHA256:AES256-SHA:AES128-SHA:DES-CBC3-SHA")
     tlsvers+=("-tls1_2 -tls1_1 -tls1")
     sni+=("$SNI")
     warning+=("")
     handshakebytes+=("16030100ca010000c6030361f8858af23cda649baf596105ec66bfe5b4642046c486e3e5321b26588392f400001ec02bc02f009ecc14cc13c00ac0140039c009c0130033009c0035002f000a0100007fff0100010000000014001200000f6465762e73736c6c6162732e636f6d0017000000230000000d001600140601060305010503040104030301030302010203000500050100000000337400000012000000100017001508687474702f312e3108737064792f332e3102683275500000000b00020100000a0006000400170018")
     lowest_protocol+=("0x0301")
     highest_protocol+=("0x0303")
     service+=("HTTP")
     minDhBits+=(1024)
     maxDhBits+=(-1)
     minRsaBits+=(-1)
     maxRsaBits+=(8192)
     minEcdsaBits+=(-1)
     requiresSha2+=(false)

     names+=("Firefox 31.3.0ESR / Win7   ")
     short+=("firefox_3130esr_win7")
     protos+=("-no_ssl2 -no_ssl3")
     ciphers+=("ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-SHA:ECDHE-ECDSA-AES128-SHA:ECDHE-RSA-AES128-SHA:ECDHE-RSA-AES256-SHA:ECDHE-RSA-DES-CBC3-SHA:ECDHE-ECDSA-RC4-SHA:ECDHE-RSA-RC4-SHA:DHE-RSA-AES128-SHA:DHE-DSS-AES128-SHA:DHE-RSA-CAMELLIA128-SHA:DHE-RSA-AES256-SHA:DHE-DSS-AES256-SHA:DHE-RSA-CAMELLIA256-SHA:EDH-RSA-DES-CBC3-SHA:AES128-SHA:CAMELLIA128-SHA:AES256-SHA:CAMELLIA256-SHA:DES-CBC3-SHA:RC4-SHA:RC4-MD5")
     tlsvers+=("-tls1_2 -tls1_1 -tls1")
     sni+=("$SNI")
     warning+=("")
     handshakebytes+=("16030100b1010000ad030357ce74b9799a67f62ffd7f53fde81675039c3597b2b17f9e18dbbbd418dd68f600002ec02bc02fc00ac009c013c014c012c007c0110033003200450039003800880016002f004100350084000a000500040100005600000014001200000f6465762e73736c6c6162732e636f6dff01000100000a00080006001700180019000b000201000023000033740000000500050100000000000d0012001004010501020104030503020304020202")
     lowest_protocol+=("0x0301")
     highest_protocol+=("0x0303")
     service+=("HTTP")
     minDhBits+=(-1)
     maxDhBits+=(-1)
     minRsaBits+=(-1)
     maxRsaBits+=(-1)
     minEcdsaBits+=(-1)
     requiresSha2+=(false)

     names+=("Firefox 42 OS X            ")
     short+=("firefox_42_osx")
     protos+=("-no_ssl2 -no_ssl3")
     ciphers+=("ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-SHA:ECDHE-ECDSA-AES128-SHA:ECDHE-RSA-AES128-SHA:ECDHE-RSA-AES256-SHA:DHE-RSA-AES128-SHA:DHE-RSA-AES256-SHA:AES128-SHA:AES256-SHA:DES-CBC3-SHA")
     tlsvers+=("-tls1_2 -tls1_1 -tls1")
     sni+=("$SNI")
     warning+=("")
     handshakebytes+=("16030100b8010000b403038abe51f10e414011c88d4807c3cf465ae02ba1ef74dd1d59a0b8f04c4f13c969000016c02bc02fc00ac009c013c01400330039002f0035000a0100007500000014001200000f6465762e73736c6c6162732e636f6dff01000100000a00080006001700180019000b00020100002300003374000000100017001502683208737064792f332e3108687474702f312e31000500050100000000000d001600140401050106010201040305030603020304020202")
     lowest_protocol+=("0x0301")
     highest_protocol+=("0x0303")
     service+=("HTTP")
     minDhBits+=(1023)
     maxDhBits+=(-1)
     minRsaBits+=(-1)
     maxRsaBits+=(-1)
     minEcdsaBits+=(-1)
     requiresSha2+=(false)

     names+=("GoogleBot Feb 2015         ")
     short+=("googlebot_feb_2015")
     protos+=("-no_ssl2")
     ciphers+=("ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-RC4-SHA:ECDHE-RSA-RC4-SHA:ECDHE-ECDSA-AES128-SHA:ECDHE-RSA-AES128-SHA:ECDHE-ECDSA-AES256-SHA:ECDHE-RSA-AES256-SHA:AES128-GCM-SHA256:RC4-SHA:RC4-MD5:AES128-SHA:DES-CBC3-SHA:AES256-SHA:DHE-RSA-AES128-SHA:DHE-DSS-AES128-SHA:EDH-RSA-DES-CBC3-SHA:EDH-DSS-DES-CBC3-SHA:DHE-RSA-AES256-SHA:DHE-DSS-AES256-SHA")
     tlsvers+=("-tls1_2 -tls1_1 -tls1")
     sni+=("$SNI")
     warning+=("")
     handshakebytes+=("16030100db010000d70303d9c72e000f6a7f0a156840bd4aa9fd0612df4aeb69a1a1c6452c5f1f4d0ba6b000002ac02bc02fc007c011c009c013c00ac014009c00050004002f000a003500330032001600130039003800ff0100008400000014001200000f6465762e73736c6c6162732e636f6d00230000000d0020001e06010602060305010502050304010402040303010302030302010202020333740000000b000403000102000a00340032000e000d0019000b000c00180009000a00160017000800060007001400150004000500120013000100020003000f00100011")
     lowest_protocol+=("0x0300")
     highest_protocol+=("0x0303")
     service+=("HTTP")
     minDhBits+=(-1)
     maxDhBits+=(-1)
     minRsaBits+=(-1)
     maxRsaBits+=(-1)
     minEcdsaBits+=(-1)
     requiresSha2+=(false)

     names+=("IE 6 XP                    ")
     short+=("ie_6_xp")
     protos+=("-no_tls1_2 -no_tls1_1 -no_tls1")
     tlsvers+=("")
     ciphers+=("RC4-MD5:RC4-SHA:DES-CBC3-SHA:RC4-MD5:DES-CBC3-MD5:RC2-CBC-MD5:DES-CBC-SHA:DES-CBC-MD5:EXP1024-RC4-SHA:EXP1024-DES-CBC-SHA:EXP-RC4-MD5:EXP-RC2-CBC-MD5:EXP-RC4-MD5:EXP-RC2-CBC-MD5:EDH-DSS-DES-CBC3-SHA:EDH-DSS-DES-CBC-SHA:EXP1024-DHE-DSS-DES-CBC-SHA")
     sni+=("")
     warning+=("")
     handshakebytes+=("804c01030000330000001000000400000500000a0100800700c003008000000906004000006400006200000300000602008004008000001300001200006317411550ac4c45ccbc8f4538dbc56d3a")
     lowest_protocol+=("0x0200")
     highest_protocol+=("0x0300")
     service+=("HTTP")
     minDhBits+=(-1)
     maxDhBits+=(-1)
     minRsaBits+=(-1)
     maxRsaBits+=(-1)
     minEcdsaBits+=(-1)
     requiresSha2+=(false)

     names+=("IE 7 Vista                 ")
     short+=("ie_7_vista")
     protos+=("-no_tls1_2 -no_tls1_1 -no_ssl2")
     ciphers+=("AES128-SHA:AES256-SHA:RC4-SHA:DES-CBC3-SHA:ECDHE-ECDSA-AES128-SHA:ECDHE-ECDSA-AES256-SHA:ECDHE-RSA-AES128-SHA:ECDHE-RSA-AES256-SHA:DHE-DSS-AES128-SHA:DHE-DSS-AES256-SHA:EDH-DSS-DES-CBC3-SHA:RC4-MD5")
     tlsvers+=("-tls1")
     sni+=("$SNI")
     warning+=("")
     handshakebytes+=("160301007d01000079030151fa62ab452795b7003c5f93ab677dbf57dd62bfa39e0ffaaeabe45b06552452000018002f00350005000ac009c00ac013c01400320038001300040100003800000014001200000f7777772e73736c6c6162732e636f6d000500050100000000000a00080006001700180019000b00020100ff01000100")
     lowest_protocol+=("0x0300")
     highest_protocol+=("0x0301")
     service+=("HTTP")
     minDhBits+=(-1)
     maxDhBits+=(-1)
     minRsaBits+=(-1)
     maxRsaBits+=(-1)
     minEcdsaBits+=(-1)
     requiresSha2+=(false)

     names+=("IE 8 XP                    ")
     short+=("ie_8_xp")
     protos+=("-no_tls1_2 -no_tls1_1 -no_ssl2")
     ciphers+=("RC4-MD5:RC4-SHA:DES-CBC3-SHA:DES-CBC-SHA:EXP1024-RC4-SHA:EXP1024-DES-CBC-SHA:EXP-RC4-MD5:EXP-RC2-CBC-MD5:EDH-DSS-DES-CBC3-SHA:EDH-DSS-DES-CBC-SHA:EXP1024-DHE-DSS-DES-CBC-SHA")
     tlsvers+=("-tls1")
     sni+=("")
     warning+=("")
     handshakebytes+=("16030100410100003d030151fa5ac223f1d72558e48bb4f144baa494403ca6c360349cbd1449997d8dd1ec00001600040005000a000900640062000300060013001200630100")
     lowest_protocol+=("0x0300")
     highest_protocol+=("0x0301")
     service+=("HTTP")
     minDhBits+=(-1)
     maxDhBits+=(-1)
     minRsaBits+=(-1)
     maxRsaBits+=(-1)
     minEcdsaBits+=(-1)
     requiresSha2+=(false)

     names+=("IE 8-10 Win 7              ")
     short+=("ie_8-10_win7")
     protos+=("-no_tls1_2 -no_tls1_1 -no_ssl2")
     ciphers+=("ECDHE-RSA-AES256-SHA:ECDHE-RSA-AES128-SHA:AES256-SHA:AES128-SHA:ECDHE-ECDSA-AES256-SHA:ECDHE-ECDSA-AES128-SHA:DHE-DSS-AES256-SHA:DHE-DSS-AES128-SHA:DES-CBC3-SHA:EDH-DSS-DES-CBC3-SHA:RC4-SHA:RC4-MD5")
     tlsvers+=("-tls1")
     sni+=("$SNI")
     warning+=("")
     handshakebytes+=("160301007d01000079030155f092059b76ac28cceda732dac7f07a52aecc126f8ed890ab80e12e7eca049c000018c014c0130035002fc00ac00900380032000a0013000500040100003800000014001200000f6465762e73736c6c6162732e636f6d000500050100000000000a00080006001700180019000b00020100ff01000100")
     lowest_protocol+=("0x0300")
     highest_protocol+=("0x0301")
     service+=("HTTP")
     minDhBits+=(1024)
     maxDhBits+=(4096)
     minRsaBits+=(-1)
     maxRsaBits+=(16384)
     minEcdsaBits+=(-1)
     requiresSha2+=(false)

     names+=("IE 11 Win 7                ")
     short+=("ie_11_win7")
     protos+=("-no_ssl2")
     ciphers+=("ECDHE-RSA-AES256-SHA384:ECDHE-RSA-AES128-SHA256:ECDHE-RSA-AES256-SHA:ECDHE-RSA-AES128-SHA:DHE-RSA-AES256-GCM-SHA384:DHE-RSA-AES128-GCM-SHA256:AES256-GCM-SHA384:AES128-GCM-SHA256:AES256-SHA256:AES128-SHA256:AES256-SHA:AES128-SHA:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-SHA384:ECDHE-ECDSA-AES128-SHA256:ECDHE-ECDSA-AES256-SHA:ECDHE-ECDSA-AES128-SHA:DHE-DSS-AES256-SHA256:DHE-DSS-AES128-SHA256:DHE-DSS-AES256-SHA:DHE-DSS-AES128-SHA:DES-CBC3-SHA:EDH-DSS-DES-CBC3-SHA:RC4-SHA:RC4-MD5")
     tlsvers+=("-tls1_2 -tls1_1 -tls1")
     sni+=("$SNI")
     warning+=("")
     handshakebytes+=("16030300b1010000ad030354c22c0a4842eab5a1a10763a3c16df20357f1ba3fac1c67136e09bfa94c5c0f000034c028c027c014c013009f009e009d009c003d003c0035002fc02cc02bc024c023c00ac009006a004000380032000a00130005000401000050ff0100010000000014001200000f6465762e73736c6c6162732e636f6d000500050100000000000a00080006001700180019000b00020100000d00140012040105010601020104030503060302030202")
     lowest_protocol+=("0x0300")
     highest_protocol+=("0x0303")
     service+=("HTTP")
     minDhBits+=(-1)
     maxDhBits+=(-1)
     minRsaBits+=(-1)
     maxRsaBits+=(-1)
     minEcdsaBits+=(-1)
     requiresSha2+=(false)

     names+=("IE 11 Win 8.1              ")
     short+=("ie_11_win81")
     protos+=("-no_ssl2")
     ciphers+=("AES128-SHA256:AES128-SHA:AES256-SHA256:AES256-SHA:DES-CBC3-SHA:ECDHE-RSA-AES128-SHA256:ECDHE-RSA-AES128-SHA:ECDHE-RSA-AES256-SHA:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES128-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES256-SHA384:ECDHE-ECDSA-AES128-SHA:ECDHE-ECDSA-AES256-SHA:DHE-DSS-AES128-SHA256:DHE-DSS-AES128-SHA:DHE-DSS-AES256-SHA256:DHE-DSS-AES256-SHA:EDH-DSS-DES-CBC3-SHA")
     tlsvers+=("-tls1_2 -tls1_1 -tls1")
     sni+=("$SNI")
     warning+=("")
     handshakebytes+=("16030300bb010000b7030352678fd707022be386508c7e5837f03bcb1b91c372733322f87872ff873af1db000026003c002f003d0035000ac027c013c014c02bc023c02cc024c009c00a00400032006a0038001301000068ff0100010000000014001200000f7777772e73736c6c6162732e636f6d000500050100000000000a0006000400170018000b00020100000d0010000e04010501020104030503020302020023000000100012001006737064792f3308687474702f312e3133740000")
     lowest_protocol+=("0x0300")
     highest_protocol+=("0x0303")
     service+=("HTTP")
     minDhBits+=(-1)
     maxDhBits+=(-1)
     minRsaBits+=(-1)
     maxRsaBits+=(-1)
     minEcdsaBits+=(-1)
     requiresSha2+=(false)

     names+=("IE 10 Win Phone 8.0        ")
     short+=("ie_10_winphone80")
     protos+=("-no_tls1_2 -no_tls1_1 -no_ssl2")
     ciphers+=("AES128-SHA:AES256-SHA:RC4-SHA:DES-CBC3-SHA:ECDHE-RSA-AES128-SHA:ECDHE-RSA-AES256-SHA:ECDHE-ECDSA-AES128-SHA:ECDHE-ECDSA-AES256-SHA:DHE-DSS-AES128-SHA:DHE-DSS-AES256-SHA:EDH-DSS-DES-CBC3-SHA:RC4-MD5")
     tlsvers+=("-tls1")
     sni+=("$SNI")
     warning+=("")
     handshakebytes+=("160301007f0100007b0301536487d458b1a364f27085798ca9e06353f0b300baeecd775e6ccc90a97037c2000018002f00350005000ac013c014c009c00a00320038001300040100003aff0100010000000014001200000f7777772e73736c6c6162732e636f6d000500050100000000000a0006000400170018000b0002010000230000")
     lowest_protocol+=("0x0300")
     highest_protocol+=("0x0301")
     service+=("HTTP")
     minDhBits+=(-1)
     maxDhBits+=(-1)
     minRsaBits+=(-1)
     maxRsaBits+=(-1)
     minEcdsaBits+=(-1)
     requiresSha2+=(false)

     names+=("IE 11 Win Phone 8.1        ")
     short+=("ie_11_winphone81")
     protos+=("-no_ssl2")
     ciphers+=("AES128-SHA256:AES128-SHA:AES256-SHA256:AES256-SHA:DES-CBC3-SHA:ECDHE-RSA-AES128-SHA256:ECDHE-RSA-AES128-SHA:ECDHE-RSA-AES256-SHA:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES128-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES256-SHA384:ECDHE-ECDSA-AES128-SHA:ECDHE-ECDSA-AES256-SHA:DHE-DSS-AES128-SHA256:DHE-DSS-AES128-SHA:DHE-DSS-AES256-SHA256:DHE-DSS-AES256-SHA:EDH-DSS-DES-CBC3-SHA")
     tlsvers+=("-tls1_2 -tls1_1 -tls1")
     sni+=("$SNI")
     warning+=("")
     handshakebytes+=("16030300bb010000b703035363d297ad92a8fe276a4e5b9395d593e96fff9c3df0987e5dfbab544ce05832000026003c002f003d0035000ac027c013c014c02bc023c02cc024c009c00a00400032006a0038001301000068ff0100010000000014001200000f7777772e73736c6c6162732e636f6d000500050100000000000a0006000400170018000b00020100000d0010000e04010501020104030503020302020023000000100012001006737064792f3308687474702f312e3133740000")
     lowest_protocol+=("0x0300")
     highest_protocol+=("0x0303")
     service+=("HTTP")
     minDhBits+=(-1)
     maxDhBits+=(-1)
     minRsaBits+=(-1)
     maxRsaBits+=(-1)
     minEcdsaBits+=(-1)
     requiresSha2+=(false)

     names+=("IE 11 Win Phone 8.1 Update ")
     short+=("ie_11_winphone81update")
     protos+=("-no_ssl2")
     ciphers+=("ECDHE-RSA-AES256-SHA384:ECDHE-RSA-AES128-SHA256:ECDHE-RSA-AES256-SHA:ECDHE-RSA-AES128-SHA:DHE-RSA-AES256-GCM-SHA384:DHE-RSA-AES128-GCM-SHA256:AES256-GCM-SHA384:AES128-GCM-SHA256:AES256-SHA256:AES128-SHA256:AES256-SHA:AES128-SHA:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-SHA384:ECDHE-ECDSA-AES128-SHA256:ECDHE-ECDSA-AES256-SHA:ECDHE-ECDSA-AES128-SHA:DHE-DSS-AES256-SHA256:DHE-DSS-AES128-SHA256:DHE-DSS-AES256-SHA:DHE-DSS-AES128-SHA:DES-CBC3-SHA:EDH-DSS-DES-CBC3-SHA")
     tlsvers+=("-tls1_2 -tls1_1 -tls1")
     sni+=("$SNI")
     warning+=("")
     handshakebytes+=("16030300c5010000c103035537a79a55362d42c3b3308fea91e85c5656021153d0a4baf03e7fef6e315c72000030c028c027c014c013009f009e009d009c003d003c0035002fc02cc02bc024c023c00ac009006a004000380032000a001301000068ff0100010000000014001200000f6465762e73736c6c6162732e636f6d000500050100000000000a0006000400170018000b00020100000d0010000e04010501020104030503020302020023000000100012001006737064792f3308687474702f312e3133740000")
     lowest_protocol+=("0x0300")
     highest_protocol+=("0x0303")
     service+=("HTTP")
     minDhBits+=(-1)
     maxDhBits+=(-1)
     minRsaBits+=(-1)
     maxRsaBits+=(-1)
     minEcdsaBits+=(-1)
     requiresSha2+=(false)

     names+=("IE 11 Win 10               ")
     short+=("ie_11_win10")
     protos+=("-no_ssl2 -no_ssl3")
     ciphers+=("ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-SHA384:ECDHE-RSA-AES128-SHA256:ECDHE-RSA-AES256-SHA:ECDHE-RSA-AES128-SHA:DHE-RSA-AES256-GCM-SHA384:DHE-RSA-AES128-GCM-SHA256:AES256-GCM-SHA384:AES128-GCM-SHA256:AES256-SHA256:AES128-SHA256:AES256-SHA:AES128-SHA:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-SHA384:ECDHE-ECDSA-AES128-SHA256:ECDHE-ECDSA-AES256-SHA:ECDHE-ECDSA-AES128-SHA:DHE-DSS-AES256-SHA256:DHE-DSS-AES128-SHA256:DHE-DSS-AES256-SHA:DHE-DSS-AES128-SHA:DES-CBC3-SHA:EDH-DSS-DES-CBC3-SHA")
     tlsvers+=("-tls1_2 -tls1_1 -tls1")
     sni+=("$SNI")
     warning+=("")
     handshakebytes+=("16030300c9010000c50303558923f4d57c2d79aba0360f4030073f0554d057176bd610fb2aa74ee4407361000034c030c02fc028c027c014c013009f009e009d009c003d003c0035002fc02cc02bc024c023c00ac009006a004000380032000a00130100006800000014001200000f6465762e73736c6c6162732e636f6d000500050100000000000a0006000400170018000b00020100000d00140012040105010201040305030203020206010603002300000010000e000c02683208687474702f312e3100170000ff01000100")
     lowest_protocol+=("0x0301")
     highest_protocol+=("0x0303")
     service+=("HTTP")
     minDhBits+=(1024)
     maxDhBits+=(4096)
     minRsaBits+=(-1)
     maxRsaBits+=(16384)
     minEcdsaBits+=(-1)
     requiresSha2+=(false)

     names+=("Edge 13 Win 10             ")
     short+=("edge_13_win10")
     protos+=("-no_ssl2 -no_ssl3")
     ciphers+=("ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384:DHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-SHA384:ECDHE-ECDSA-AES128-SHA256:ECDHE-RSA-AES256-SHA384:ECDHE-RSA-AES128-SHA256:ECDHE-ECDSA-AES256-SHA:ECDHE-ECDSA-AES128-SHA:ECDHE-RSA-AES256-SHA:ECDHE-RSA-AES128-SHA:AES256-GCM-SHA384:AES128-GCM-SHA256:AES256-SHA256:AES128-SHA256:AES256-SHA:AES128-SHA:DES-CBC3-SHA:DHE-DSS-AES256-SHA256:DHE-DSS-AES128-SHA256:DHE-DSS-AES256-SHA:DHE-DSS-AES128-SHA:EDH-DSS-DES-CBC3-SHA")
     tlsvers+=("-tls1_2 -tls1_1 -tls1")
     sni+=("$SNI")
     warning+=("")
     handshakebytes+=("16030300d3010000cf0303565ee009f8e3f685347567b3edfd626034a1125966e4d818ec6f57a022d2fc9e000034c02cc02bc030c02f009f009ec024c023c028c027c00ac009c014c013009d009c003d003c0035002f000a006a00400038003200130100007200000014001200000f6465762e73736c6c6162732e636f6d000500050100000000000a0006000400170018000b00020100000d00140012040105010201040305030203020206010603002300000010000e000c02683208687474702f312e310017000055000006000100020002ff01000100")
     lowest_protocol+=("0x0301")
     highest_protocol+=("0x0303")
     service+=("HTTP")
     minDhBits+=(1024)
     maxDhBits+=(4096)
     minRsaBits+=(-1)
     maxRsaBits+=(16384)
     minEcdsaBits+=(-1)
     requiresSha2+=(false)

     names+=("Edge 13 Win Phone 10       ")
     short+=("edge_13_winphone10")
     protos+=("-no_ssl2 -no_ssl3")
     ciphers+=("ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384:DHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-SHA384:ECDHE-ECDSA-AES128-SHA256:ECDHE-RSA-AES256-SHA384:ECDHE-RSA-AES128-SHA256:ECDHE-ECDSA-AES256-SHA:ECDHE-ECDSA-AES128-SHA:ECDHE-RSA-AES256-SHA:ECDHE-RSA-AES128-SHA:AES256-GCM-SHA384:AES128-GCM-SHA256:AES256-SHA256:AES128-SHA256:AES256-SHA:AES128-SHA:DES-CBC3-SHA:DHE-DSS-AES256-SHA256:DHE-DSS-AES128-SHA256:DHE-DSS-AES256-SHA:DHE-DSS-AES128-SHA:EDH-DSS-DES-CBC3-SHA")
     tlsvers+=("-tls1_2 -tls1_1 -tls1")
     sni+=("$SNI")
     warning+=("")
     handshakebytes+=("16030300d3010000cf0303565ee836e62e7b9b734f4dca5f3f1ad62dc4e5f87bdf6c90f325b6a2e0012705000034c02cc02bc030c02f009f009ec024c023c028c027c00ac009c014c013009d009c003d003c0035002f000a006a00400038003200130100007200000014001200000f6465762e73736c6c6162732e636f6d000500050100000000000a0006000400170018000b00020100000d00140012040105010201040305030203020206010603002300000010000e000c02683208687474702f312e310017000055000006000100020002ff01000100")
     lowest_protocol+=("0x0301")
     highest_protocol+=("0x0303")
     service+=("HTTP")
     minDhBits+=(1024)
     maxDhBits+=(4096)
     minRsaBits+=(-1)
     maxRsaBits+=(16384)
     minEcdsaBits+=(-1)
     requiresSha2+=(false)

     names+=("Java 6u45                  ")
     short+=("java_6u45")
     protos+=("-no_tls1_2 -no_tls1_1")
     ciphers+=("RC4-MD5:RC4-MD5:RC4-SHA:AES128-SHA:DHE-RSA-AES128-SHA:DHE-DSS-AES128-SHA:DES-CBC3-SHA:DES-CBC3-MD5:EDH-RSA-DES-CBC3-SHA:EDH-DSS-DES-CBC3-SHA:DES-CBC-SHA:DES-CBC-MD5:EDH-RSA-DES-CBC-SHA:EDH-DSS-DES-CBC-SHA:EXP-RC4-MD5:EXP-RC4-MD5:EXP-DES-CBC-SHA:EXP-EDH-RSA-DES-CBC-SHA:EXP-EDH-DSS-DES-CBC-SHA")
     tlsvers+=("-tls1")
     sni+=("")
     warning+=("")
     handshakebytes+=("8065010301003c0000002000000401008000000500002f00003300003200000a0700c00000160000130000090600400000150000120000030200800000080000140000110000ff52173357f48ce6722f974dbb429b9279208d1cf5b9088947c9ba16d9ecbc0fa6")
     lowest_protocol+=("0x0200")
     highest_protocol+=("0x0301")
     service+=("ANY")
     minDhBits+=(-1)
     maxDhBits+=(1024)
     minRsaBits+=(-1)
     maxRsaBits+=(-1)
     minEcdsaBits+=(-1)
     requiresSha2+=(false)

     names+=("Java 7u25                  ")
     short+=("java_7u25")
     protos+=("-no_ssl2 -no_tls1_2 -no_tls1_1")
     ciphers+=("ECDHE-ECDSA-AES128-SHA:ECDHE-RSA-AES128-SHA:AES128-SHA:ECDH-ECDSA-AES128-SHA:ECDH-RSA-AES128-SHA:DHE-RSA-AES128-SHA:DHE-DSS-AES128-SHA:ECDHE-ECDSA-RC4-SHA:ECDHE-RSA-RC4-SHA:RC4-SHA:ECDH-ECDSA-RC4-SHA:ECDH-RSA-RC4-SHA:ECDHE-ECDSA-DES-CBC3-SHA:ECDHE-RSA-DES-CBC3-SHA:DES-CBC3-SHA:ECDH-ECDSA-DES-CBC3-SHA:ECDH-RSA-DES-CBC3-SHA:EDH-RSA-DES-CBC3-SHA:EDH-DSS-DES-CBC3-SHA:RC4-MD5")
     tlsvers+=("-tls1")
     sni+=("$SNI")
     warning+=("")
     handshakebytes+=("16030100ad010000a9030152178334e8b855253e50e4623e475b6941c18cc312de6395a98e1cd4fd6735e700002ac009c013002fc004c00e00330032c007c0110005c002c00cc008c012000ac003c00d00160013000400ff01000056000a0034003200170001000300130015000600070009000a0018000b000c0019000d000e000f001000110002001200040005001400080016000b0002010000000014001200000f7777772e73736c6c6162732e636f6d")
     lowest_protocol+=("0x0300")
     highest_protocol+=("0x0301")
     service+=("ANY")
     minDhBits+=(-1)
     maxDhBits+=(1024)
     minRsaBits+=(-1)
     maxRsaBits+=(-1)
     minEcdsaBits+=(-1)
     requiresSha2+=(false)

     names+=("Java 8u31                  ")
     short+=("java_8u31")
     protos+=("-no_ssl2 -no_ssl3")
     ciphers+=("ECDHE-ECDSA-AES128-SHA256:ECDHE-RSA-AES128-SHA256:AES128-SHA256:ECDH-ECDSA-AES128-SHA256:ECDH-RSA-AES128-SHA256:DHE-RSA-AES128-SHA256:DHE-DSS-AES128-SHA256:ECDHE-ECDSA-AES128-SHA:ECDHE-RSA-AES128-SHA:AES128-SHA:ECDH-ECDSA-AES128-SHA:ECDH-RSA-AES128-SHA:DHE-RSA-AES128-SHA:DHE-DSS-AES128-SHA:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:AES128-GCM-SHA256:ECDH-ECDSA-AES128-GCM-SHA256:ECDH-RSA-AES128-GCM-SHA256:DHE-RSA-AES128-GCM-SHA256:DHE-DSS-AES128-GCM-SHA256:ECDHE-ECDSA-DES-CBC3-SHA:ECDHE-RSA-DES-CBC3-SHA:DES-CBC3-SHA:ECDH-ECDSA-DES-CBC3-SHA:ECDH-RSA-DES-CBC3-SHA:EDH-RSA-DES-CBC3-SHA:EDH-DSS-DES-CBC3-SHA:ECDHE-ECDSA-RC4-SHA:ECDHE-RSA-RC4-SHA:RC4-SHA:ECDH-ECDSA-RC4-SHA:ECDH-RSA-RC4-SHA:RC4-MD5")
     tlsvers+=("-tls1_2 -tls1_1 -tls1")
     sni+=("$SNI")
     warning+=("")
     handshakebytes+=("16030300e7010000e3030354c21168512b37f2a7410028c16673626ff931146918c7b29f78150b7339e5af000046c023c027003cc025c02900670040c009c013002fc004c00e00330032c02bc02f009cc02dc031009e00a2c008c012000ac003c00d00160013c007c0110005c002c00c000400ff01000074000a0034003200170001000300130015000600070009000a0018000b000c0019000d000e000f001000110002001200040005001400080016000b00020100000d001a001806030601050305010403040103030301020302010202010100000014001200000f6465762e73736c6c6162732e636f6d")
     lowest_protocol+=("0x0301")
     highest_protocol+=("0x0303")
     service+=("ANY")
     minDhBits+=(-1)
     maxDhBits+=(2048)
     minRsaBits+=(-1)
     maxRsaBits+=(-1)
     minEcdsaBits+=(-1)
     requiresSha2+=(false)

     names+=("OpenSSL 0.9.8y             ")
     short+=("openssl_098y")
     protos+=("-no_ssl2 -no_tls1_2 -no_tls1_1")
     ciphers+=("DHE-RSA-AES256-SHA:DHE-DSS-AES256-SHA:AES256-SHA:EDH-RSA-DES-CBC3-SHA:EDH-DSS-DES-CBC3-SHA:DES-CBC3-SHA:DHE-RSA-AES128-SHA:DHE-DSS-AES128-SHA:AES128-SHA:IDEA-CBC-SHA:RC4-SHA:RC4-MD5:EDH-RSA-DES-CBC-SHA:EDH-DSS-DES-CBC-SHA:DES-CBC-SHA:EXP-EDH-RSA-DES-CBC-SHA:EXP-EDH-DSS-DES-CBC-SHA:EXP-DES-CBC-SHA:EXP-RC2-CBC-MD5:EXP-RC4-MD5")
     tlsvers+=("-tls1")
     sni+=("$SNI")
     warning+=("")
     handshakebytes+=("16030100730100006f0301521782e707c1a780d3124742f35573dbb693babe5d3a7e9405c706af18b636bf00002a00390038003500160013000a00330032002f0007000500040015001200090014001100080006000300ff0100001c00000014001200000f7777772e73736c6c6162732e636f6d00230000")
     lowest_protocol+=("0x0300")
     highest_protocol+=("0x0301")
     service+=("ANY")
     minDhBits+=(-1)
     maxDhBits+=(-1)
     minRsaBits+=(-1)
     maxRsaBits+=(-1)
     minEcdsaBits+=(-1)
     requiresSha2+=(false)

     names+=("OpenSSL 1.0.1l             ")
     short+=("openssl_101l")
     protos+=("-no_ssl2")
     ciphers+=("ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-SHA384:ECDHE-ECDSA-AES256-SHA384:ECDHE-RSA-AES256-SHA:ECDHE-ECDSA-AES256-SHA:DHE-DSS-AES256-GCM-SHA384:DHE-RSA-AES256-GCM-SHA384:DHE-RSA-AES256-SHA256:DHE-DSS-AES256-SHA256:DHE-RSA-AES256-SHA:DHE-DSS-AES256-SHA:DHE-RSA-CAMELLIA256-SHA:DHE-DSS-CAMELLIA256-SHA:ECDH-RSA-AES256-GCM-SHA384:ECDH-ECDSA-AES256-GCM-SHA384:ECDH-RSA-AES256-SHA384:ECDH-ECDSA-AES256-SHA384:ECDH-RSA-AES256-SHA:ECDH-ECDSA-AES256-SHA:AES256-GCM-SHA384:AES256-SHA256:AES256-SHA:CAMELLIA256-SHA:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-SHA256:ECDHE-ECDSA-AES128-SHA256:ECDHE-RSA-AES128-SHA:ECDHE-ECDSA-AES128-SHA:DHE-DSS-AES128-GCM-SHA256:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES128-SHA256:DHE-DSS-AES128-SHA256:DHE-RSA-AES128-SHA:DHE-DSS-AES128-SHA:DHE-RSA-SEED-SHA:DHE-DSS-SEED-SHA:DHE-RSA-CAMELLIA128-SHA:DHE-DSS-CAMELLIA128-SHA:ECDH-RSA-AES128-GCM-SHA256:ECDH-ECDSA-AES128-GCM-SHA256:ECDH-RSA-AES128-SHA256:ECDH-ECDSA-AES128-SHA256:ECDH-RSA-AES128-SHA:ECDH-ECDSA-AES128-SHA:AES128-GCM-SHA256:AES128-SHA256:AES128-SHA:SEED-SHA:CAMELLIA128-SHA:IDEA-CBC-SHA:ECDHE-RSA-RC4-SHA:ECDHE-ECDSA-RC4-SHA:ECDH-RSA-RC4-SHA:ECDH-ECDSA-RC4-SHA:RC4-SHA:RC4-MD5:ECDHE-RSA-DES-CBC3-SHA:ECDHE-ECDSA-DES-CBC3-SHA:EDH-RSA-DES-CBC3-SHA:EDH-DSS-DES-CBC3-SHA:ECDH-RSA-DES-CBC3-SHA:ECDH-ECDSA-DES-CBC3-SHA:DES-CBC3-SHA:EDH-RSA-DES-CBC-SHA:EDH-DSS-DES-CBC-SHA:DES-CBC-SHA:EXP-EDH-RSA-DES-CBC-SHA:EXP-EDH-DSS-DES-CBC-SHA:EXP-DES-CBC-SHA:EXP-RC2-CBC-MD5:EXP-RC4-MD5")
     tlsvers+=("-tls1_2 -tls1_1 -tls1")
     sni+=("$SNI")
     warning+=("")
     handshakebytes+=("160301014f0100014b030332b230e5dd8c5573c219a243f397e31f407c7a93b60a26e7c3d5cca06a566fe1000094c030c02cc028c024c014c00a00a3009f006b006a0039003800880087c032c02ec02ac026c00fc005009d003d00350084c02fc02bc027c023c013c00900a2009e0067004000330032009a009900450044c031c02dc029c025c00ec004009c003c002f009600410007c011c007c00cc00200050004c012c00800160013c00dc003000a0015001200090014001100080006000300ff0100008e00000014001200000f6465762e73736c6c6162732e636f6d000b000403000102000a00340032000e000d0019000b000c00180009000a00160017000800060007001400150004000500120013000100020003000f0010001100230000000d0020001e060106020603050105020503040104020403030103020303020102020203000500050100000000000f000101")
     lowest_protocol+=("0x0300")
     highest_protocol+=("0x0303")
     service+=("ANY")
     minDhBits+=(-1)
     maxDhBits+=(-1)
     minRsaBits+=(-1)
     maxRsaBits+=(-1)
     minEcdsaBits+=(-1)
     requiresSha2+=(false)

     names+=("OpenSSL 1.0.2e             ")
     short+=("openssl_102e")
     protos+=("-no_ssl2")
     ciphers+=("ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-SHA384:ECDHE-ECDSA-AES256-SHA384:ECDHE-RSA-AES256-SHA:ECDHE-ECDSA-AES256-SHA:DH-DSS-AES256-GCM-SHA384:DHE-DSS-AES256-GCM-SHA384:DH-RSA-AES256-GCM-SHA384:DHE-RSA-AES256-GCM-SHA384:DHE-RSA-AES256-SHA256:DHE-DSS-AES256-SHA256:DH-RSA-AES256-SHA256:DH-DSS-AES256-SHA256:DHE-RSA-AES256-SHA:DHE-DSS-AES256-SHA:DH-RSA-AES256-SHA:DH-DSS-AES256-SHA:DHE-RSA-CAMELLIA256-SHA:DHE-DSS-CAMELLIA256-SHA:DH-RSA-CAMELLIA256-SHA:DH-DSS-CAMELLIA256-SHA:ECDH-RSA-AES256-GCM-SHA384:ECDH-ECDSA-AES256-GCM-SHA384:ECDH-RSA-AES256-SHA384:ECDH-ECDSA-AES256-SHA384:ECDH-RSA-AES256-SHA:ECDH-ECDSA-AES256-SHA:AES256-GCM-SHA384:AES256-SHA256:AES256-SHA:CAMELLIA256-SHA:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-SHA256:ECDHE-ECDSA-AES128-SHA256:ECDHE-RSA-AES128-SHA:ECDHE-ECDSA-AES128-SHA:DH-DSS-AES128-GCM-SHA256:DHE-DSS-AES128-GCM-SHA256:DH-RSA-AES128-GCM-SHA256:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES128-SHA256:DHE-DSS-AES128-SHA256:DH-RSA-AES128-SHA256:DH-DSS-AES128-SHA256:DHE-RSA-AES128-SHA:DHE-DSS-AES128-SHA:DH-RSA-AES128-SHA:DH-DSS-AES128-SHA:DHE-RSA-SEED-SHA:DHE-DSS-SEED-SHA:DH-RSA-SEED-SHA:DH-DSS-SEED-SHA:DHE-RSA-CAMELLIA128-SHA:DHE-DSS-CAMELLIA128-SHA:DH-RSA-CAMELLIA128-SHA:DH-DSS-CAMELLIA128-SHA:ECDH-RSA-AES128-GCM-SHA256:ECDH-ECDSA-AES128-GCM-SHA256:ECDH-RSA-AES128-SHA256:ECDH-ECDSA-AES128-SHA256:ECDH-RSA-AES128-SHA:ECDH-ECDSA-AES128-SHA:AES128-GCM-SHA256:AES128-SHA256:AES128-SHA:SEED-SHA:CAMELLIA128-SHA:IDEA-CBC-SHA:ECDHE-RSA-RC4-SHA:ECDHE-ECDSA-RC4-SHA:ECDH-RSA-RC4-SHA:ECDH-ECDSA-RC4-SHA:RC4-SHA:RC4-MD5:ECDHE-RSA-DES-CBC3-SHA:ECDHE-ECDSA-DES-CBC3-SHA:EDH-RSA-DES-CBC3-SHA:EDH-DSS-DES-CBC3-SHA:DH-RSA-DES-CBC3-SHA:DH-DSS-DES-CBC3-SHA:ECDH-RSA-DES-CBC3-SHA:ECDH-ECDSA-DES-CBC3-SHA:DES-CBC3-SHA:EDH-RSA-DES-CBC-SHA:EDH-DSS-DES-CBC-SHA:DH-RSA-DES-CBC-SHA:DH-DSS-DES-CBC-SHA:DES-CBC-SHA")
     tlsvers+=("-tls1_2 -tls1_1 -tls1")
     sni+=("$SNI")
     #warning+=("Tests are based on OpenSSL 1.0.1, therefore ciphers 0xe and 0xb are missing")
     warning+=("")
     handshakebytes+=("16030101590100015503032a9db79b37d9364a9a685dc25bfec88c21ef88c206a20b9801108c67607e79800000b6c030c02cc028c024c014c00a00a500a300a1009f006b006a0069006800390038003700360088008700860085c032c02ec02ac026c00fc005009d003d00350084c02fc02bc027c023c013c00900a400a200a0009e00670040003f003e0033003200310030009a0099009800970045004400430042c031c02dc029c025c00ec004009c003c002f009600410007c011c007c00cc00200050004c012c008001600130010000dc00dc003000a00150012000f000c000900ff0100007600000014001200000f6465762e73736c6c6162732e636f6d000b000403000102000a001c001a00170019001c001b0018001a0016000e000d000b000c0009000a00230000000d0020001e060106020603050105020503040104020403030103020303020102020203000500050100000000000f000101")
     lowest_protocol+=("0x0300")
     highest_protocol+=("0x0303")
     service+=("ANY")
     minDhBits+=(-1)
     maxDhBits+=(-1)
     minRsaBits+=(-1)
     maxRsaBits+=(-1)
     minEcdsaBits+=(-1)
     requiresSha2+=(false)

     names+=("Safari 5.1.9 OS X 10.6.8   ")
     short+=("safari_519_osx1068")
     protos+=("-no_ssl2 -no_tls1_2 -no_tls1_1")
     ciphers+=("ECDHE-ECDSA-AES256-SHA:ECDHE-ECDSA-AES128-SHA:ECDHE-ECDSA-RC4-SHA:ECDHE-ECDSA-DES-CBC3-SHA:ECDHE-RSA-AES128-SHA:ECDHE-RSA-AES256-SHA:ECDHE-RSA-RC4-SHA:ECDHE-RSA-DES-CBC3-SHA:ECDH-ECDSA-AES128-SHA:ECDH-ECDSA-AES256-SHA:ECDH-ECDSA-RC4-SHA:ECDH-ECDSA-DES-CBC3-SHA:ECDH-RSA-AES128-SHA:ECDH-RSA-AES256-SHA:ECDH-RSA-RC4-SHA:ECDH-RSA-DES-CBC3-SHA:AES128-SHA:RC4-SHA:RC4-MD5:AES256-SHA:DES-CBC3-SHA:DES-CBC-SHA:EXP-RC4-MD5:EXP-DES-CBC-SHA:EXP-RC2-CBC-MD5:DHE-DSS-AES128-SHA:DHE-RSA-AES128-SHA:DHE-DSS-AES256-SHA:DHE-RSA-AES256-SHA:EDH-RSA-DES-CBC3-SHA:EDH-RSA-DES-CBC-SHA:EXP-EDH-RSA-DES-CBC-SHA:EDH-DSS-DES-CBC3-SHA:EDH-DSS-DES-CBC-SHA:EXP-EDH-DSS-DES-CBC-SHA")
     tlsvers+=("-tls1")
     sni+=("$SNI")
     warning+=("")
     handshakebytes+=("160301009d01000099030151d15dc2887b1852fd4291e36c3f4e8a35266e15dd6354779fbf5438b59b42da000046c00ac009c007c008c013c014c011c012c004c005c002c003c00ec00fc00cc00d002f000500040035000a000900030008000600320033003800390016001500140013001200110100002a00000014001200000f7777772e73736c6c6162732e636f6d000a00080006001700180019000b00020100")
     lowest_protocol+=("0x0300")
     highest_protocol+=("0x0301")
     service+=("HTTP")
     minDhBits+=(-1)
     maxDhBits+=(-1)
     minRsaBits+=(-1)
     maxRsaBits+=(4096)
     minEcdsaBits+=(-1)
     requiresSha2+=(false)

     names+=("Safari 6 iOS 6.0.1         ")
     short+=("safari_6_ios601")
     protos+=("-no_ssl2")
     ciphers+=("ECDHE-ECDSA-AES256-SHA384:ECDHE-ECDSA-AES128-SHA256:ECDHE-ECDSA-AES256-SHA:ECDHE-ECDSA-AES128-SHA:ECDHE-ECDSA-RC4-SHA:ECDHE-ECDSA-DES-CBC3-SHA:ECDHE-RSA-AES256-SHA384:ECDHE-RSA-AES128-SHA256:ECDHE-RSA-AES256-SHA:ECDHE-RSA-AES128-SHA:ECDHE-RSA-RC4-SHA:ECDHE-RSA-DES-CBC3-SHA:ECDH-ECDSA-AES256-SHA384:ECDH-ECDSA-AES128-SHA256:ECDH-RSA-AES256-SHA384:ECDH-RSA-AES128-SHA256:ECDH-ECDSA-AES128-SHA:ECDH-ECDSA-AES256-SHA:ECDH-ECDSA-RC4-SHA:ECDH-ECDSA-DES-CBC3-SHA:ECDH-RSA-AES128-SHA:ECDH-RSA-AES256-SHA:ECDH-RSA-RC4-SHA:ECDH-RSA-DES-CBC3-SHA:AES256-SHA256:AES128-SHA256:AES128-SHA:RC4-SHA:RC4-MD5:AES256-SHA:DES-CBC3-SHA:DHE-RSA-AES128-SHA256:DHE-RSA-AES256-SHA256:DHE-RSA-AES128-SHA:DHE-RSA-AES256-SHA:EDH-RSA-DES-CBC3-SHA:ECDHE-ECDSA-NULL-SHA:ECDHE-RSA-NULL-SHA:ECDH-ECDSA-NULL-SHA:ECDH-RSA-NULL-SHA:NULL-SHA256:NULL-SHA:NULL-MD5")
     tlsvers+=("-tls1_2 -tls1_1 -tls1")
     sni+=("$SNI")
     warning+=("")
     handshakebytes+=("16030300bf010000bb030351d15ce21834380a8b5f491a00790b6d097014bb1e04124706631c6a6a3f973800005800ffc024c023c00ac009c007c008c028c027c014c013c011c012c026c025c02ac029c004c005c002c003c00ec00fc00cc00d003d003c002f000500040035000a0067006b003300390016c006c010c001c00b003b000200010100003a00000014001200000f7777772e73736c6c6162732e636f6d000a00080006001700180019000b00020100000d000c000a05010401020104030203")
     lowest_protocol+=("0x0300")
     highest_protocol+=("0x0303")
     service+=("HTTP")
     minDhBits+=(-1)
     maxDhBits+=(-1)
     minRsaBits+=(-1)
     maxRsaBits+=(4096)
     minEcdsaBits+=(-1)
     requiresSha2+=(false)

     names+=("Safari 6.0.4 OS X 10.8.4   ")
     short+=("safari_604_osx1084")
     protos+=("-no_ssl2 -no_tls1_2 -no_tls1_1")
     ciphers+=("ECDHE-ECDSA-AES256-SHA:ECDHE-ECDSA-AES128-SHA:ECDHE-ECDSA-RC4-SHA:ECDHE-ECDSA-DES-CBC3-SHA:ECDHE-RSA-AES256-SHA:ECDHE-RSA-AES128-SHA:ECDHE-RSA-RC4-SHA:ECDHE-RSA-DES-CBC3-SHA:ECDH-ECDSA-AES128-SHA:ECDH-ECDSA-AES256-SHA:ECDH-ECDSA-RC4-SHA:ECDH-ECDSA-DES-CBC3-SHA:ECDH-RSA-AES128-SHA:ECDH-RSA-AES256-SHA:ECDH-RSA-RC4-SHA:ECDH-RSA-DES-CBC3-SHA:AES128-SHA:RC4-SHA:RC4-MD5:AES256-SHA:DES-CBC3-SHA:DHE-RSA-AES128-SHA:DHE-RSA-AES256-SHA:EDH-RSA-DES-CBC3-SHA")
     tlsvers+=("-tls1")
     sni+=("$SNI")
     warning+=("")
     handshakebytes+=("16030100a9010000a5030151fa327c6576dadde1e8a89d4d45bdc1d0c107b8cbe998337e02ca419a0bcb30204dd1c85d9fbc1607b27a35ec9dfd1dae2c589483843a73999c9de205748633b1003200ffc00ac009c007c008c014c013c011c012c004c005c002c003c00ec00fc00cc00d002f000500040035000a0033003900160100002a00000014001200000f7777772e73736c6c6162732e636f6d000a00080006001700180019000b00020100")
     lowest_protocol+=("0x0300")
     highest_protocol+=("0x0301")
     service+=("HTTP")
     minDhBits+=(-1)
     maxDhBits+=(-1)
     minRsaBits+=(-1)
     maxRsaBits+=(4096)
     minEcdsaBits+=(-1)
     requiresSha2+=(false)

     names+=("Safari 7 iOS 7.1           ")
     short+=("safari_7_ios71")
     protos+=("-no_ssl2")
     ciphers+=("ECDHE-ECDSA-AES256-SHA384:ECDHE-ECDSA-AES128-SHA256:ECDHE-ECDSA-AES256-SHA:ECDHE-ECDSA-AES128-SHA:ECDHE-ECDSA-RC4-SHA:ECDHE-ECDSA-DES-CBC3-SHA:ECDHE-RSA-AES256-SHA384:ECDHE-RSA-AES128-SHA256:ECDHE-RSA-AES256-SHA:ECDHE-RSA-AES128-SHA:ECDHE-RSA-RC4-SHA:ECDHE-RSA-DES-CBC3-SHA:ECDH-ECDSA-AES256-SHA384:ECDH-ECDSA-AES128-SHA256:ECDH-RSA-AES256-SHA384:ECDH-RSA-AES128-SHA256:ECDH-ECDSA-AES256-SHA:ECDH-ECDSA-AES128-SHA:ECDH-ECDSA-RC4-SHA:ECDH-ECDSA-DES-CBC3-SHA:ECDH-RSA-AES256-SHA:ECDH-RSA-AES128-SHA:ECDH-RSA-RC4-SHA:ECDH-RSA-DES-CBC3-SHA:AES256-SHA256:AES128-SHA256:AES128-SHA:RC4-SHA:RC4-MD5:AES256-SHA:DES-CBC3-SHA:DHE-RSA-AES128-SHA256:DHE-RSA-AES256-SHA256:DHE-RSA-AES128-SHA:DHE-RSA-AES256-SHA:EDH-RSA-DES-CBC3-SHA")
     tlsvers+=("-tls1_2 -tls1_1 -tls1")
     sni+=("$SNI")
     warning+=("")
     handshakebytes+=("16030100b1010000ad0303532017204048bb5331c62bf295ab4c2f2b3964f515c649a7d0947c8102d7348600004a00ffc024c023c00ac009c007c008c028c027c014c013c011c012c026c025c02ac029c005c004c002c003c00fc00ec00cc00d003d003c002f000500040035000a0067006b0033003900160100003a00000014001200000f7777772e73736c6c6162732e636f6d000a00080006001700180019000b00020100000d000c000a05010401020104030203")
     lowest_protocol+=("0x0300")
     highest_protocol+=("0x0303")
     service+=("HTTP")
     minDhBits+=(-1)
     maxDhBits+=(-1)
     minRsaBits+=(-1)
     maxRsaBits+=(4096)
     minEcdsaBits+=(-1)
     requiresSha2+=(false)

     names+=("Safari 7 OS X 10.9         ")
     short+=("safari_7_osx109")
     protos+=("-no_ssl2")
     ciphers+=("ECDHE-ECDSA-AES256-SHA384:ECDHE-ECDSA-AES128-SHA256:ECDHE-ECDSA-AES256-SHA:ECDHE-ECDSA-AES128-SHA:ECDHE-ECDSA-RC4-SHA:ECDHE-ECDSA-DES-CBC3-SHA:ECDHE-RSA-AES256-SHA384:ECDHE-RSA-AES128-SHA256:ECDHE-RSA-AES256-SHA:ECDHE-RSA-AES128-SHA:ECDHE-RSA-RC4-SHA:ECDHE-RSA-DES-CBC3-SHA:ECDH-ECDSA-AES256-SHA384:ECDH-ECDSA-AES128-SHA256:ECDH-RSA-AES256-SHA384:ECDH-RSA-AES128-SHA256:ECDH-ECDSA-AES256-SHA:ECDH-ECDSA-AES128-SHA:ECDH-ECDSA-RC4-SHA:ECDH-ECDSA-DES-CBC3-SHA:ECDH-RSA-AES256-SHA:ECDH-RSA-AES128-SHA:ECDH-RSA-RC4-SHA:ECDH-RSA-DES-CBC3-SHA:AES256-SHA256:AES128-SHA256:AES128-SHA:RC4-SHA:RC4-MD5:AES256-SHA:DES-CBC3-SHA:DHE-RSA-AES128-SHA256:DHE-RSA-AES256-SHA256:DHE-RSA-AES128-SHA:DHE-RSA-AES256-SHA:EDH-RSA-DES-CBC3-SHA")
     tlsvers+=("-tls1_2 -tls1_1 -tls1")
     sni+=("$SNI")
     warning+=("")
     handshakebytes+=("16030100d1010000cd030351fa3664edce86d82606540539ccd388418b1a5cb8cfda5e15349c635d4b028b203bf83c63e3da6777e407300b5d657e429f11cd7d857977e4390fda365b8d4664004a00ffc024c023c00ac009c007c008c028c027c014c013c011c012c026c025c02ac029c005c004c002c003c00fc00ec00cc00d003d003c002f000500040035000a0067006b0033003900160100003a00000014001200000f7777772e73736c6c6162732e636f6d000a00080006001700180019000b00020100000d000c000a05010401020104030203")
     lowest_protocol+=("0x0300")
     highest_protocol+=("0x0303")
     service+=("HTTP")
     minDhBits+=(-1)
     maxDhBits+=(-1)
     minRsaBits+=(-1)
     maxRsaBits+=(4096)
     minEcdsaBits+=(-1)
     requiresSha2+=(false)

     names+=("Safari 8 iOS 8.4           ")
     short+=("safari_8_ios84")
     protos+=("-no_ssl2")
     ciphers+=("ECDHE-ECDSA-AES256-SHA384:ECDHE-ECDSA-AES128-SHA256:ECDHE-ECDSA-AES256-SHA:ECDHE-ECDSA-AES128-SHA:ECDHE-ECDSA-DES-CBC3-SHA:ECDHE-RSA-AES256-SHA384:ECDHE-RSA-AES128-SHA256:ECDHE-RSA-AES256-SHA:ECDHE-RSA-AES128-SHA:ECDHE-RSA-DES-CBC3-SHA:ECDH-ECDSA-AES256-SHA384:ECDH-ECDSA-AES128-SHA256:ECDH-ECDSA-AES256-SHA:ECDH-ECDSA-AES128-SHA:ECDH-ECDSA-DES-CBC3-SHA:ECDH-RSA-AES256-SHA384:ECDH-RSA-AES128-SHA256:ECDH-RSA-AES256-SHA:ECDH-RSA-AES128-SHA:ECDH-RSA-DES-CBC3-SHA:DHE-RSA-AES256-SHA256:DHE-RSA-AES128-SHA256:DHE-RSA-AES256-SHA:DHE-RSA-AES128-SHA:EDH-RSA-DES-CBC3-SHA:AES256-SHA256:AES128-SHA256:AES256-SHA:AES128-SHA:DES-CBC3-SHA:ECDHE-ECDSA-RC4-SHA:ECDHE-RSA-RC4-SHA:ECDH-ECDSA-RC4-SHA:ECDH-RSA-RC4-SHA:RC4-SHA:RC4-MD5")
     tlsvers+=("-tls1_2 -tls1_1 -tls1")
     sni+=("$SNI")
     warning+=("")
     handshakebytes+=("16030100b5010000b1030354c20f1647345d0cac1db29f0489aab5e2016e6b2baca65e8c5eb6dd48a1fcd400004a00ffc024c023c00ac009c008c028c027c014c013c012c026c025c005c004c003c02ac029c00fc00ec00d006b0067003900330016003d003c0035002f000ac007c011c002c00c000500040100003e00000014001200000f6465762e73736c6c6162732e636f6d000a00080006001700180019000b00020100000d000c000a0501040102010403020333740000")
     lowest_protocol+=("0x0300")
     highest_protocol+=("0x0303")
     service+=("HTTP")
     minDhBits+=(768)
     maxDhBits+=(-1)
     minRsaBits+=(-1)
     maxRsaBits+=(4096)
     minEcdsaBits+=(-1)
     requiresSha2+=(false)

     names+=("Safari 8 OS X 10.10        ")
     short+=("safari_8_osx1010")
     protos+=("-no_ssl2")
     ciphers+=("ECDHE-ECDSA-AES256-SHA384:ECDHE-ECDSA-AES128-SHA256:ECDHE-ECDSA-AES256-SHA:ECDHE-ECDSA-AES128-SHA:ECDHE-ECDSA-DES-CBC3-SHA:ECDHE-RSA-AES256-SHA384:ECDHE-RSA-AES128-SHA256:ECDHE-RSA-AES256-SHA:ECDHE-RSA-AES128-SHA:ECDHE-RSA-DES-CBC3-SHA:ECDH-ECDSA-AES256-SHA384:ECDH-ECDSA-AES128-SHA256:ECDH-ECDSA-AES256-SHA:ECDH-ECDSA-AES128-SHA:ECDH-ECDSA-DES-CBC3-SHA:ECDH-RSA-AES256-SHA384:ECDH-RSA-AES128-SHA256:ECDH-RSA-AES256-SHA:ECDH-RSA-AES128-SHA:ECDH-RSA-DES-CBC3-SHA:DHE-RSA-AES256-SHA256:DHE-RSA-AES128-SHA256:DHE-RSA-AES256-SHA:DHE-RSA-AES128-SHA:EDH-RSA-DES-CBC3-SHA:AES256-SHA256:AES128-SHA256:AES256-SHA:AES128-SHA:DES-CBC3-SHA:ECDHE-ECDSA-RC4-SHA:ECDHE-RSA-RC4-SHA:ECDH-ECDSA-RC4-SHA:ECDH-RSA-RC4-SHA:RC4-SHA:RC4-MD5")
     tlsvers+=("-tls1_2 -tls1_1 -tls1")
     sni+=("$SNI")
     warning+=("")
     handshakebytes+=("16030100b5010000b1030354c20a44e0d7681f3d55d7e9a764b67e6ffa6722c17b21e15bc2c9c98892460a00004a00ffc024c023c00ac009c008c028c027c014c013c012c026c025c005c004c003c02ac029c00fc00ec00d006b0067003900330016003d003c0035002f000ac007c011c002c00c000500040100003e00000014001200000f6465762e73736c6c6162732e636f6d000a00080006001700180019000b00020100000d000c000a0501040102010403020333740000")
     lowest_protocol+=("0x0300")
     highest_protocol+=("0x0303")
     service+=("HTTP")
     minDhBits+=(768)
     maxDhBits+=(-1)
     minRsaBits+=(-1)
     maxRsaBits+=(8192)
     minEcdsaBits+=(-1)
     requiresSha2+=(false)

     names+=("Safari 9 iOS 9             ")
     short+=("safari_9_ios9")
     protos+=("-no_ssl2 -no_ssl3")
     ciphers+=("ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-SHA384:ECDHE-ECDSA-AES128-SHA256:ECDHE-ECDSA-AES256-SHA:ECDHE-ECDSA-AES128-SHA:ECDHE-ECDSA-DES-CBC3-SHA:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-SHA384:ECDHE-RSA-AES128-SHA256:ECDHE-RSA-AES256-SHA:ECDHE-RSA-AES128-SHA:ECDHE-RSA-DES-CBC3-SHA:AES256-GCM-SHA384:AES128-GCM-SHA256:AES256-SHA256:AES128-SHA256:AES256-SHA:AES128-SHA:DES-CBC3-SHA:ECDHE-ECDSA-RC4-SHA:ECDHE-RSA-RC4-SHA:RC4-SHA:RC4-MD5")
     tlsvers+=("-tls1_2 -tls1_1 -tls1")
     sni+=("$SNI")
     warning+=("")
     handshakebytes+=("16030100e2010000de030355fb38fdc94c6c1ff6ee066f0e69579f40a83ce5454787e8834b60fd8c31e5ac00003400ffc02cc02bc024c023c00ac009c008c030c02fc028c027c014c013c012009d009c003d003c0035002f000ac007c011000500040100008100000014001200000f6465762e73736c6c6162732e636f6d000a00080006001700180019000b00020100000d000e000c0501040102010503040302033374000000100030002e0268320568322d31360568322d31350568322d313408737064792f332e3106737064792f3308687474702f312e3100050005010000000000120000")
     lowest_protocol+=("0x0301")
     highest_protocol+=("0x0303")
     service+=("HTTP")
     minDhBits+=(768)
     maxDhBits+=(-1)
     minRsaBits+=(-1)
     maxRsaBits+=(8192)
     minEcdsaBits+=(-1)
     requiresSha2+=(false)

     names+=("Safari 9 OS X 10.11        ")
     short+=("safari_9_osx1011")
     protos+=("-no_ssl2 -no_ssl3")
     ciphers+=("ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-SHA384:ECDHE-ECDSA-AES128-SHA256:ECDHE-ECDSA-AES256-SHA:ECDHE-ECDSA-AES128-SHA:ECDHE-ECDSA-DES-CBC3-SHA:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-SHA384:ECDHE-RSA-AES128-SHA256:ECDHE-RSA-AES256-SHA:ECDHE-RSA-AES128-SHA:ECDHE-RSA-DES-CBC3-SHA:AES256-GCM-SHA384:AES128-GCM-SHA256:AES256-SHA256:AES128-SHA256:AES256-SHA:AES128-SHA:DES-CBC3-SHA:ECDHE-ECDSA-RC4-SHA:ECDHE-RSA-RC4-SHA:RC4-SHA:RC4-MD5")
     tlsvers+=("-tls1_2 -tls1_1 -tls1")
     sni+=("$SNI")
     warning+=("")
     handshakebytes+=("16030100e2010000de030355def1c4d1f6a12227389012da236581104b0bfa8b8a5bc849372531349dccc600003400ffc02cc02bc024c023c00ac009c008c030c02fc028c027c014c013c012009d009c003d003c0035002f000ac007c011000500040100008100000014001200000f6465762e73736c6c6162732e636f6d000a00080006001700180019000b00020100000d000e000c0501040102010503040302033374000000100030002e0268320568322d31360568322d31350568322d313408737064792f332e3106737064792f3308687474702f312e3100050005010000000000120000")
     lowest_protocol+=("0x0301")
     highest_protocol+=("0x0303")
     service+=("HTTP")
     minDhBits+=(768)
     maxDhBits+=(-1)
     minRsaBits+=(-1)
     maxRsaBits+=(8192)
     minEcdsaBits+=(-1)
     requiresSha2+=(false)

     names+=("Apple ATS 9 iOS 9          ")
     short+=("safari_9_osx1011")
     protos+=("-no_ssl2 -no_ssl3 -no_tls1 -no_tls1_1")
     ciphers+=("ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-SHA384:ECDHE-ECDSA-AES128-SHA256:ECDHE-ECDSA-AES256-SHA:ECDHE-ECDSA-AES128-SHA256:ECDHE-ECDSA-AES128-SHA:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-SHA384:ECDHE-RSA-AES128-SHA256:ECDHE-RSA-AES128-SHA")
     tlsvers+=("-tls1_2")
     sni+=("$SNI")
     warning+=("")
     handshakebytes+=("16030100b9010000b50303282275d1356ba8ceec8897786197b80f96d83a06d9205200a677f850c4b822f2000018c02cc02bc024c023c00ac009c030c02fc028c027c01300ff0201000073000b000403000102000a003a0038000e000d0019001c000b000c001b00180009000a001a00160017000800060007001400150004000500120013000100020003000f0010001100230000000d0020001e060106020603050105020503040104020403030103020303020102020203000f000101")
     lowest_protocol+=("0x0303")
     highest_protocol+=("0x0303")
     service+=("HTTP")
     minDhBits+=(768)
     maxDhBits+=(-1)
     minRsaBits+=(-1)
     maxRsaBits+=(8192)
     minEcdsaBits+=(-1)
     requiresSha2+=(false)

     outln
     if "$using_sockets"; then
          pr_headlineln " Running browser simulations via sockets (experimental) "
     else
          pr_headline " Running browser simulations via openssl (experimental) "
     fi
     outln

     debugme outln
     for name in "${short[@]}"; do
          #FIXME: printf formatting would look better, especially if we want a wide option here
          out " ${names[i]}   "
          if "$using_sockets" && [[ -n "${handshakebytes[i]}" ]]; then
               client_simulation_sockets "${handshakebytes[i]}"
               sclient_success=$?
               if [[ $sclient_success -eq 0 ]]; then
                    if [[ "0x${DETECTED_TLS_VERSION}" -lt ${lowest_protocol[i]} ]] || \
                       [[ "0x${DETECTED_TLS_VERSION}" -gt ${highest_protocol[i]} ]]; then
                         sclient_success=1
                    fi
                    [[ $sclient_success -eq 0 ]] && cp "$TEMPDIR/$NODEIP.parse_tls_serverhello.txt" $TMPFILE >$ERRFILE
               fi
          else
               ! "$HAS_NO_SSL2" && protos[i]="$(sed 's/-no_ssl2//' <<< "${protos[i]}")"
               debugme echo "$OPENSSL s_client -cipher ${ciphers[i]} ${protos[i]} $STARTTLS $BUGS $PROXY -connect $NODEIP:$PORT ${sni[i]}  </dev/null"
               $OPENSSL s_client -cipher ${ciphers[i]} ${protos[i]} $STARTTLS $BUGS $PROXY -connect $NODEIP:$PORT ${sni[i]}  </dev/null >$TMPFILE 2>$ERRFILE
               sclient_connect_successful $? $TMPFILE
               sclient_success=$?
          fi
          if [[ $sclient_success -eq 0 ]]; then
               # If an ephemeral DH key was used, check that the number of bits is within range.
               temp=$(awk -F': ' '/^Server Temp Key/ { print $2 }' "$TMPFILE")        # extract line
               what_dh=$(awk -F',' '{ print $1 }' <<< $temp)
               bits=$(awk -F',' '{ print $3 }' <<< $temp)
               grep -q bits <<< $bits || bits=$(awk -F',' '{ print $2 }' <<< $temp)
               bits=$(tr -d ' bits' <<< $bits)
               if [[ "$what_dh" == "DH" ]]; then
                    [[ ${minDhBits[i]} -ne -1 ]] && [[ $bits -lt ${minDhBits[i]} ]] && sclient_success=1
                    [[ ${maxDhBits[i]} -ne -1 ]] && [[ $bits -gt ${maxDhBits[i]} ]] && sclient_success=1
               fi
          fi
          if [[ $sclient_success -ne 0 ]]; then
               outln "No connection"
               fileout "client_${short[i]}" "INFO" "$(strip_spaces "${names[i]}") client simulation: No connection"
          else
               #FIXME: awk
               proto=$(grep -aw "Protocol" $TMPFILE | sed -e 's/^.*Protocol.*://' -e 's/ //g')
               [[ "$proto" == TLSv1 ]] && proto="TLSv1.0"
               if [[ "$proto" == TLSv1.2 ]] && ( ! "$using_sockets" || [[ -z "${handshakebytes[i]}" ]] ); then
                    # OpenSSL reports TLS1.2 even if the connection is TLS1.1 or TLS1.0. Need to figure out which one it is...
                    for tls in ${tlsvers[i]}; do
                         debugme echo "$OPENSSL s_client $tls -cipher ${ciphers[i]} ${protos[i]} $STARTTLS $BUGS $PROXY -connect $NODEIP:$PORT ${sni[i]}  </dev/null"
                         $OPENSSL s_client $tls -cipher ${ciphers[i]} ${protos[i]} $STARTTLS $BUGS $PROXY -connect $NODEIP:$PORT ${sni[i]}  </dev/null >$TMPFILE 2>$ERRFILE
                         sclient_connect_successful $? $TMPFILE
                         sclient_success=$?
                         if [[ $sclient_success -eq 0 ]]; then
                              case "$tls" in
                                   "-tls1_2")
                                        break
                                        ;;
                                   "-tls1_1")
                                        proto="TLSv1.1"
                                        break
                                        ;;
                                   "-tls1")
                                        proto="TLSv1.0"
                                        break
                                        ;;
                              esac
                         fi
                    done
               fi
               #FiXME: awk
               cipher=$(grep -wa Cipher $TMPFILE | egrep -avw "New|is" | sed -e 's/ //g' -e 's/^Cipher://')
               if [[ -z "$SHOW_RFC" ]] && ( [[ "$cipher" == TLS_* ]] || [[ "$cipher" == SSL_* ]] ); then
                    cipher="$(rfc2openssl "$cipher")"
                    [[ -z "$cipher" ]] && cipher=$(grep -wa Cipher $TMPFILE | egrep -avw "New|is" | sed -e 's/ //g' -e 's/^Cipher://')
               elif [[ -n "$SHOW_RFC" ]] && [[ "$cipher" != TLS_* ]] && [[ "$cipher" != SSL_* ]]; then
                    cipher="$(openssl2rfc "$cipher")"
                    [[ -z "$cipher" ]] && cipher=$(grep -wa Cipher $TMPFILE | egrep -avw "New|is" | sed -e 's/ //g' -e 's/^Cipher://')
               fi
               out "$proto $cipher"
               "$using_sockets" && [[ -n "${handshakebytes[i]}" ]] && has_dh_bits=$HAS_DH_BITS && HAS_DH_BITS=true
               "$HAS_DH_BITS" && read_dhbits_from_file $TMPFILE
               "$using_sockets" && [[ -n "${handshakebytes[i]}" ]] && HAS_DH_BITS=$has_dh_bits
               [[ ":${ROBUST_PFS_CIPHERS}:" =~ ":${cipher}:" ]] && out ", " && pr_done_good "FS"
               outln
               if [[ -n "${warning[i]}" ]]; then
                    out "                            "
                    outln "${warning[i]}"
               fi
               fileout "client_${short[i]}" "INFO" \
                    "$(strip_spaces "${names[i]}") client simulation:  $proto $cipher   ${warning[i]}"
               debugme cat $TMPFILE
          fi
          i=$((i+1))
     done
     tmpfile_handle $FUNCNAME.txt
     return 0
}

# generic function whether $1 is supported by s_client ($2: string to display)
locally_supported() {
     [[ -n "$2" ]] && out "$2 "
     if $OPENSSL s_client "$1" -connect x 2>&1 | grep -aq "unknown option"; then
          local_problem_ln "$OPENSSL doesn't support \"s_client $1\""
          return 7
     fi
     return 0
}


# the protocol check needs to be revamped. It sucks.
# 1) we need to have a variable where the results are being stored so that every other test doesn't have to do this again.
# 2) the code is too old and one can do that way better
# 3) HAS_SSL3/2 does already exist
# we should do what's available and faster (openssl vs. sockets). Keep in mind that the socket reply for SSLv2 returns the number # of ciphers!
#
# arg1: -ssl2|-ssl3|-tls1
# arg2: doesn't seem to be used in calling, seems to be a textstring with the protocol though
run_prototest_openssl() {
     local sni="$SNI"
     local -i ret=0

     $OPENSSL s_client -state $1 $STARTTLS $BUGS -connect $NODEIP:$PORT $PROXY $sni >$TMPFILE 2>$ERRFILE </dev/null
     sclient_connect_successful $? $TMPFILE
     ret=$?
     [[ $DEBUG -eq 2 ]] && egrep "error|failure" $ERRFILE | egrep -av "unable to get local|verify error"
     if ! locally_supported "$1" "$2" ; then
          ret=7
     else                                    # we remove SNI for SSLv2 and v3:
          [[ "$1" =~ ssl ]] && sni=""        # newer openssl throw an error if SNI is supplied with SSLv2,
                                             # SSLv3 doesn't have SNI (openssl doesn't complain though -- yet)
          $OPENSSL s_client -state $1 $STARTTLS $BUGS -connect $NODEIP:$PORT $sni >$TMPFILE 2>$ERRFILE </dev/null
          sclient_connect_successful $? $TMPFILE
          ret=$?
          [[ $DEBUG -eq 2 ]] && egrep "error|failure" $ERRFILE | egrep -av "unable to get local|verify error"
          grep -aq "no cipher list" $TMPFILE && ret=5       # <--- important indicator for SSL2 (maybe others, too)
     fi
     tmpfile_handle $FUNCNAME$1.txt
     return $ret

     # 0: offered
     # 1: not offered
     # 5: protocol ok, but no cipher
     # 7: no local support
}

# idempotent function to add SSL/TLS protocols. It should ease testing
# PROTOS_OFFERED's content is in openssl terminology
add_tls_offered() {
     grep -w "$1" <<< "$PROTOS_OFFERED" || PROTOS_OFFERED+="$1 "
}

# function which checks whether SSLv2 - TLS 1.2 is being offereed
has_server_protocol() {
     [[ -z "$PROTOS_OFFERED" ]] && return 0            # if empty we rather return 0, means check at additional cost=connect will be done
     if grep -qw "$1" <<< "$PROTOS_OFFERED"; then
          return 0
     fi
     return 1
}


# the protocol check needs to be revamped. It sucks, see above
run_protocols() {
     local using_sockets=true
     local supported_no_ciph1="supported but couldn't detect a cipher (may need debugging)"
     local supported_no_ciph2="supported but couldn't detect a cipher"
     local latest_supported=""  # version.major and version.minor of highest version supported by the server.
     local detected_version_string latest_supported_string
     local lines nr_ciphers_detected

     outln; pr_headline " Testing protocols "

     if "$SSL_NATIVE"; then
          using_sockets=false
          pr_underlineln "via native openssl"
     else
          using_sockets=true
          if [[ -n "$STARTTLS" ]]; then
               pr_underlineln "via sockets "
          else
               pr_underlineln "via sockets except SPDY+HTTP2 "
          fi
     fi
     outln

     pr_bold " SSLv2      ";
     if ! "$SSL_NATIVE"; then
          sslv2_sockets
          case $? in
               7) # strange reply, couldn't convert the cipher spec length to a hex number
                    pr_cyan "strange v2 reply "
                    outln " (rerun with DEBUG >=2)"
                    [[ $DEBUG -ge 3 ]] && hexdump -C "$TEMPDIR/$NODEIP.sslv2_sockets.dd" | head -1
                    fileout "sslv2" "WARN" "SSLv2: received a strange SSLv2 reply (rerun with DEBUG>=2)"
                    ;;
               1) # no sslv2 server hello returned, like in openlitespeed which returns HTTP!
                    pr_done_bestln "not offered (OK)"
                    fileout "sslv2" "OK" "SSLv2 is not offered"
                    ;;
               0) # reset
                    pr_done_bestln "not offered (OK)"
                    fileout "sslv2" "OK" "SSLv2 is not offered"
                    ;;
               3) # everything else
                    lines=$(count_lines "$(hexdump -C "$TEMPDIR/$NODEIP.sslv2_sockets.dd" 2>/dev/null)")
                    [[ "$DEBUG" -ge 2 ]] && out "  ($lines lines)  "
                    if [[ "$lines" -gt 1 ]]; then
                         nr_ciphers_detected=$((V2_HELLO_CIPHERSPEC_LENGTH / 3))
                         add_tls_offered "ssl2"
                         if [[ 0 -eq "$nr_ciphers_detected" ]]; then
                              pr_svrty_highln "supported but couldn't detect a cipher and vulnerable to CVE-2015-3197 ";
                              fileout "sslv2" "HIGH" "SSLv2 is offered, vulnerable to CVE-2015-3197"
                         else
                              pr_svrty_critical "offered (NOT ok), also VULNERABLE to DROWN attack";
                              outln " -- $nr_ciphers_detected ciphers"
                              fileout "sslv2" "CRITICAL" "SSLv2 offered, vulnerable to DROWN attack.  Detected ciphers: $nr_ciphers_detected"
                         fi
                    fi ;;
          esac
          debugme outln
     else
          run_prototest_openssl "-ssl2"
          case $? in
               0)
                    pr_svrty_criticalln   "offered (NOT ok)"
                    fileout "sslv2" "CRITICAL" "SSLv2 is offered"
                    add_tls_offered "ssl2"
                    ;;
               1)
                    pr_done_bestln "not offered (OK)"
                    fileout "sslv2" "OK" "SSLv2 is not offered"
                    ;;
               5)
                    pr_svrty_high "CVE-2015-3197: $supported_no_ciph2";
                    fileout "sslv2" "HIGH" "CVE-2015-3197: SSLv2 is $supported_no_ciph2"
                    add_tls_offered "ssl2"
                    ;;
               7)
                    fileout "sslv2" "INFO" "SSLv2 is not tested due to lack of local support"
                    ;;                                                     # no local support
          esac
     fi

     pr_bold " SSLv3      ";
     if "$using_sockets"; then
          tls_sockets "00" "$TLS_CIPHER"
     else
          run_prototest_openssl "-ssl3"
     fi
     case $? in
          0)
               pr_svrty_highln "offered (NOT ok)"
               fileout "sslv3" "HIGH" "SSLv3 is offered"
               latest_supported="0300"
               latest_supported_string="SSLv3"
               add_tls_offered "ssl3"
               ;;
          1)
               pr_done_bestln "not offered (OK)"
               fileout "sslv3" "OK" "SSLv3 is not offered"
               ;;
          2)
               if [[ "$DETECTED_TLS_VERSION" == 03* ]]; then
                    detected_version_string="TLSv1.$((0x$DETECTED_TLS_VERSION-0x0301))"
                    pr_svrty_criticalln "server responded with higher version number ($detected_version_string) than requested by client (NOT ok)"
                    fileout "sslv3" "CRITICAL" "SSLv3: server responded with higher version number ($detected_version_string) than requested by client"
               else
                    pr_svrty_criticalln "server responded with version number ${DETECTED_TLS_VERSION:0:2}.${DETECTED_TLS_VERSION:2:2} (NOT ok)"
                    fileout "sslv3" "CRITICAL" "SSLv3: server responded with version number ${DETECTED_TLS_VERSION:0:2}.${DETECTED_TLS_VERSION:2:2}"
               fi
               ;;
          5)
               pr_svrty_high "$supported_no_ciph2"
               fileout "sslv3" "HIGH" "SSLv3 is $supported_no_ciph1"
               outln "(may need debugging)"
               add_tls_offered "ssl3"
               ;;
          7)
               fileout "sslv3" "INFO" "SSLv3 is not tested due to lack of local support"
               ;;                                                            # no local support
     esac

     pr_bold " TLS 1      ";
     if "$using_sockets"; then
          tls_sockets "01" "$TLS_CIPHER"
     else
          run_prototest_openssl "-tls1"
     fi
     case $? in
          0)
               outln "offered"
               fileout "tls1" "INFO" "TLSv1.0 is offered"
               latest_supported="0301"
               latest_supported_string="TLSv1.0"
               add_tls_offered "tls1"
               ;;                                           # nothing wrong with it -- per se
          1)
               out "not offered"
               if ! "$using_sockets" || [[ -z $latest_supported ]]; then
                    outln
                    fileout "tls1" "INFO" "TLSv1.0 is not offered" # neither good or bad
               else
                    pr_svrty_criticalln " -- connection failed rather than downgrading to $latest_supported_string (NOT ok)"
                    fileout "tls1" "CRITICAL" "TLSv1.0: connection failed rather than downgrading to $latest_supported_string"
               fi
               ;;
          2)
               pr_svrty_medium "not offered"
               if [[ "$DETECTED_TLS_VERSION" == "0300" ]]; then
                    [[ $DEBUG -eq 1 ]] && out " -- downgraded"
                    outln
                    fileout "tls1" "MEDIUM" "TLSv1.0 is not offered, and downgraded to SSL"
               elif [[ "$DETECTED_TLS_VERSION" == 03* ]]; then
                    detected_version_string="TLSv1.$((0x$DETECTED_TLS_VERSION-0x0301))"
                    pr_svrty_criticalln " -- server responded with higher version number ($detected_version_string) than requested by client"
                    fileout "tls1" "CRITICAL" "TLSv1.0: server responded with higher version number ($detected_version_string) than requested by client"
               else
                    pr_svrty_criticalln " -- server responded with version number ${DETECTED_TLS_VERSION:0:2}.${DETECTED_TLS_VERSION:2:2}"
                    fileout "tls1" "CRITICAL" "TLSv1.0: server responded with version number ${DETECTED_TLS_VERSION:0:2}.${DETECTED_TLS_VERSION:2:2}"
               fi
               ;;
          5)
               outln "$supported_no_ciph1"                                 # protocol ok, but no cipher
               fileout "tls1" "WARN" "TLSv1.0 is $supported_no_ciph1"
               add_tls_offered "tls1"
               ;;
          7)
               fileout "tlsv1" "INFO" "TLSv1.0 is not tested due to lack of local support"
               ;;                                                            # no local support
     esac

     pr_bold " TLS 1.1    ";
     if "$using_sockets"; then
          tls_sockets "02" "$TLS_CIPHER"
     else
          run_prototest_openssl "-tls1_1"
     fi
     case $? in
          0)
               outln "offered"
               fileout "tls1_1" "INFO" "TLSv1.1 is offered"
               latest_supported="0302"
               latest_supported_string="TLSv1.1"
               add_tls_offered "tls1_1"
               ;;                                            # nothing wrong with it
          1)
               out "not offered"
               if ! "$using_sockets" || [[ -z $latest_supported ]]; then
                    outln
                    fileout "tls1_1" "INFO" "TLSv1.1 is not offered"  # neither good or bad
               else
                    pr_svrty_criticalln " -- connection failed rather than downgrading to $latest_supported_string"
                    fileout "tls1_1" "CRITICAL" "TLSv1.1: connection failed rather than downgrading to $latest_supported_string"
               fi
               ;;
          2)
               out "not offered"
               if [[ "$DETECTED_TLS_VERSION" == "$latest_supported" ]]; then
                    [[ $DEBUG -eq 1 ]] && out " -- downgraded"
                    outln
                    fileout "tls1_1" "CRITICAL" "TLSv1.1 is not offered, and downgraded to a weaker protocol"
               elif [[ "$DETECTED_TLS_VERSION" == "0300" ]] && [[ "$latest_supported" == "0301" ]]; then
                    pr_svrty_criticalln " -- server supports TLSv1.0, but downgraded to SSLv3 (NOT ok)"
                    fileout "tls1_1" "CRITICAL" "TLSv1.1 is not offered, and downgraded to SSLv3 rather than TLSv1.0"
               elif [[ "$DETECTED_TLS_VERSION" == 03* ]] && [[ 0x$DETECTED_TLS_VERSION -gt 0x0302 ]]; then
                    detected_version_string="TLSv1.$((0x$DETECTED_TLS_VERSION-0x0301))"
                    pr_svrty_criticalln " -- server responded with higher version number ($detected_version_string) than requested by client (NOT ok)"
                    fileout "tls1_1" "CRITICAL" "TLSv1.1 is not offered, server responded with higher version number ($detected_version_string) than requested by client"
               else
                    pr_svrty_criticalln " -- server responded with version number ${DETECTED_TLS_VERSION:0:2}.${DETECTED_TLS_VERSION:2:2} (NOT ok)"
                    fileout "tls1_1" "CRITICAL" "TLSv1.1: server responded with version number ${DETECTED_TLS_VERSION:0:2}.${DETECTED_TLS_VERSION:2:2}"
               fi
               ;;
          5)
               outln "$supported_no_ciph1"
               fileout "tls1_1" "WARN" "TLSv1.1 is $supported_no_ciph1"
               add_tls_offered "tls1_1"
               ;;                                # protocol ok, but no cipher
          7)
               fileout "tls1_1" "INFO" "TLSv1.1 is not tested due to lack of local support"
               ;;                                                            # no local support
     esac

     pr_bold " TLS 1.2    ";
     if "$using_sockets"; then
          tls_sockets "03" "$TLS12_CIPHER"
     else
          run_prototest_openssl "-tls1_2"
     fi
     case $? in
          0)
               pr_done_bestln "offered (OK)"
               fileout "tls1_2" "OK" "TLSv1.2 is offered"
               latest_supported="0303"
               latest_supported_string="TLSv1.2"
               add_tls_offered "tls1_2"
               ;;                                  # GCM cipher in TLS 1.2: very good!
          1)
               pr_svrty_medium "not offered"
               if ! "$using_sockets" || [[ -z $latest_supported ]]; then
                    outln
                    fileout "tls1_2" "MEDIUM" "TLSv1.2 is not offered" # no GCM, penalty
               else
                    pr_svrty_criticalln " -- connection failed rather than downgrading to $latest_supported_string"
                    fileout "tls1_2" "CRITICAL" "TLSv1.2: connection failed rather than downgrading to $latest_supported_string"
               fi
               ;;
          2)
               pr_svrty_medium "not offered"
               if [[ "$DETECTED_TLS_VERSION" == "0300" ]]; then
                    detected_version_string="SSLv3"
               elif [[ "$DETECTED_TLS_VERSION" == 03* ]]; then
                    detected_version_string="TLSv1.$((0x$DETECTED_TLS_VERSION-0x0301))"
               fi
               if [[ "$DETECTED_TLS_VERSION" == "$latest_supported" ]]; then
                    [[ $DEBUG -eq 1 ]] && out " -- downgraded"
                    outln
                    fileout "tls1_2" "MEDIUM" "TLSv1.2 is not offered and downgraded to a weaker protocol"
               elif [[ "$DETECTED_TLS_VERSION" == 03* ]] && [[ 0x$DETECTED_TLS_VERSION -lt 0x$latest_supported ]]; then
                    pr_svrty_criticalln " -- server supports $latest_supported_string, but downgraded to $detected_version_string"
                    fileout "tls1_2" "CRITICAL" "TLSv1.2 is not offered, and downgraded to $detected_version_string rather than $latest_supported_string"
               elif [[ "$DETECTED_TLS_VERSION" == 03* ]] && [[ 0x$DETECTED_TLS_VERSION -gt 0x0303 ]]; then
                    pr_svrty_criticalln " -- server responded with higher version number ($detected_version_string) than requested by client"
                    fileout "tls1_2" "CRITICAL" "TLSv1.2 is not offered, server responded with higher version number ($detected_version_string) than requested by client"
               else
                    pr_svrty_criticalln " -- server responded with version number ${DETECTED_TLS_VERSION:0:2}.${DETECTED_TLS_VERSION:2:2}"
                    fileout "tls1_2" "CRITICAL" "TLSv1.2: server responded with version number ${DETECTED_TLS_VERSION:0:2}.${DETECTED_TLS_VERSION:2:2}"
               fi
               ;;
          5)
               outln "$supported_no_ciph1"
               fileout "tls1_2" "WARN" "TLSv1.2 is $supported_no_ciph1"
               add_tls_offered "tls1_2"
               ;;                                # protocol ok, but no cipher
          7)
               fileout "tls1_2" "INFO" "TLSv1.2 is not tested due to lack of local support"
               ;;                                                            # no local support
     esac
     return 0
}

#TODO: work with fixed lists here
run_std_cipherlists() {
     local hexc hexcode strength
     local -i i
     local null_ciphers="c0,10, c0,06, c0,15, c0,0b, c0,01, c0,3b, c0,3a, c0,39, 00,b9, 00,b8, 00,b5, 00,b4, 00,2e, 00,2d, 00,b1, 00,b0, 00,2c, 00,3b, 00,02, 00,01, 00,82, 00,83, ff,87, 00,ff"
     local sslv2_null_ciphers=""
     local anon_ciphers="c0,19, 00,a7, 00,6d, 00,3a, 00,c5, 00,89, c0,47, c0,5b, c0,85, c0,18, 00,a6, 00,6c, 00,34, 00,bf, 00,9b, 00,46, c0,46, c0,5a, c0,84, c0,16, 00,18, c0,17, 00,1b, 00,1a, 00,19, 00,17, c0,15, 00,ff"
     local sslv2_anon_ciphers=""
     local adh_ciphers="00,a7, 00,6d, 00,3a, 00,c5, 00,89, c0,47, c0,5b, c0,85, 00,a6, 00,6c, 00,34, 00,bf, 00,9b, 00,46, c0,46, c0,5a, c0,84, 00,18, 00,1b, 00,1a, 00,19, 00,17, 00,ff"
     local sslv2_adh_ciphers=""
     local exp40_ciphers="00,14, 00,11, 00,19, 00,08, 00,06, 00,27, 00,26, 00,2a, 00,29, 00,0b, 00,0e, 00,17, 00,03, 00,28, 00,2b, 00,ff"
     local sslv2_exp40_ciphers="04,00,80, 02,00,80"
     local exp56_ciphers="00,63, 00,62, 00,61, 00,65, 00,64, 00,60, 00,ff"
     local sslv2_exp56_ciphers=""
     local exp_ciphers="00,63, 00,62, 00,61, 00,65, 00,64, 00,60, 00,14, 00,11, 00,19, 00,08, 00,06, 00,27, 00,26, 00,2a, 00,29, 00,0b, 00,0e, 00,17, 00,03, 00,28, 00,2b, 00,ff"
     local sslv2_exp_ciphers="04,00,80, 02,00,80"
     local low_ciphers="00,15, 00,12, 00,0f, 00,0c, 00,09, 00,1e, 00,22, fe,fe, ff,e1, 00,ff"
     local sslv2_low_ciphers="08,00,80, 06,00,40"
     local des_ciphers="00,15, 00,12, 00,0f, 00,0c, 00,09, 00,1e, 00,22, fe,fe, ff,e1, 00,ff"
     local sslv2_des_ciphers="06,00,40"
     local medium_ciphers="00,9a, 00,99, 00,98, 00,97, 00,96, 00,07, 00,21, 00,25, c0,11, c0,07, 00,66, c0,0c, c0,02, 00,05, 00,04, 00,92, 00,8a, 00,20, 00,24, c0,33, 00,8e, 00,ff"
     local sslv2_medium_ciphers=""
     local tdes_ciphers="c0,12, c0,08, c0,1c, c0,1b, c0,1a, 00,16, 00,13, 00,10, 00,0d, c0,0d, c0,03, 00,0a, 00,93, 00,8b, 00,1f, 00,23, c0,34, 00,8f, fe,ff, ff,e0, 00,ff"
     local sslv2_tdes_ciphers="07,00,c0"
     local high_ciphers="13,02, 13,03, cc,14, cc,13, cc,15, c0,30, c0,2c, c0,28, c0,24, c0,14, c0,0a, c0,22, c0,21, c0,20, 00,b7, 00,b3, 00,91, c0,9b, c0,99, c0,97, 00,af, c0,95, 00,a5, 00,a3, 00,a1, 00,9f, cc,a9, cc,a8, cc,aa, c0,af, c0,ad, c0,a3, c0,9f, 00,6b, 00,6a, 00,69, 00,68, 00,39, 00,38, 00,37, 00,36, c0,77, c0,73, 00,c4, 00,c3, 00,c2, 00,c1, 00,88, 00,87, 00,86, 00,85, 00,ad, 00,ab, cc,ae, cc,ad, cc,ac, c0,ab, c0,a7, c0,32, c0,2e, c0,2a, c0,26, c0,0f, c0,05, c0,79, c0,75, 00,9d, c0,a1, c0,9d, 00,a9, cc,ab, c0,a9, c0,a5, 00,3d, 00,35, 00,c0, c0,38, c0,36, 00,84, 00,95, 00,8d, c0,3d, c0,3f, c0,41, c0,43, c0,45, c0,49, c0,4b, c0,4d, c0,4f, c0,51, c0,53, c0,55, c0,57, c0,59, c0,5d, c0,5f, c0,61, c0,63, c0,65, c0,67, c0,69, c0,6b, c0,6d, c0,6f, c0,71, c0,7b, c0,7d, c0,7f, c0,81, c0,83, c0,87, c0,89, c0,8b, c0,8d, c0,8f, c0,91, c0,93, 00,80, 00,81, ff,00, ff,01, ff,02, ff,03, ff,85, 16,b7, 16,b8, 16,b9, 16,ba, 13,01, 13,04, 13,05, c0,2f, c0,2b, c0,27, c0,23, c0,13, c0,09, c0,1f, c0,1e, c0,1d, 00,a4, 00,a2, 00,a0, 00,9e, c0,ae, c0,ac, c0,a2, c0,9e, 00,ac, 00,aa, c0,aa, c0,a6, c0,a0, c0,9c, 00,a8, c0,a8, c0,a4, 00,67, 00,40, 00,3f, 00,3e, 00,33, 00,32, 00,31, 00,30, c0,76, c0,72, 00,be, 00,bd, 00,bc, 00,bb, 00,45, 00,44, 00,43, 00,42, c0,31, c0,2d, c0,29, c0,25, c0,0e, c0,04, c0,78, c0,74, 00,9c, 00,3c, 00,2f, 00,ba, c0,37, c0,35, 00,b6, 00,b2, 00,90, 00,41, c0,9a, c0,98, c0,96, 00,ae, c0,94, 00,94, 00,8c, c0,3c, c0,3e, c0,40, c0,42, c0,44, c0,48, c0,4a, c0,4c, c0,4e, c0,50, c0,52, c0,54, c0,56, c0,58, c0,5c, c0,5e, c0,60, c0,62, c0,64, c0,66, c0,68, c0,6a, c0,6c, c0,6e, c0,70, c0,7a, c0,7c, c0,7e, c0,80, c0,82, c0,86, c0,88, c0,8a, c0,8c, c0,8e, c0,90, c0,92, 00,ff"
     local sslv2_high_ciphers=""
     local using_sockets=true

     "$SSL_NATIVE" && using_sockets=false

     if ! "$using_sockets"; then
          null_ciphers=""; anon_ciphers=""; adh_ciphers=""; exp40_ciphers=""
          exp56_ciphers=""; exp_ciphers=""; low_ciphers=""; des_ciphers=""
          medium_ciphers=""; tdes_ciphers=""; high_ciphers=""
          sslv2_null_ciphers=""; sslv2_anon_ciphers=""; sslv2_adh_ciphers=""; sslv2_exp40_ciphers=""
          sslv2_exp56_ciphers=""; sslv2_exp_ciphers=""; sslv2_low_ciphers=""; sslv2_des_ciphers=""
          sslv2_medium_ciphers=""; sslv2_tdes_ciphers=""; sslv2_high_ciphers=""
     fi

     outln
     pr_headlineln " Testing ~standard cipher lists "
     outln
# see ciphers(1ssl) or run 'openssl ciphers -v'
     std_cipherlists 'NULL:eNULL'                       " Null Ciphers             "   1 "NULL"     "$null_ciphers"   "$sslv2_null_ciphers"
     std_cipherlists 'aNULL'                            " Anonymous NULL Ciphers   "   1 "aNULL"    "$anon_ciphers"   "$sslv2_anon_ciphers"
     std_cipherlists 'ADH'                              " Anonymous DH Ciphers     "   1 "ADH"      "$adh_ciphers"    "$sslv2_adh_ciphers"
     std_cipherlists 'EXPORT40'                         " 40 Bit encryption        "   1 "EXPORT40" "$exp40_ciphers"  "$sslv2_exp40_ciphers"
     std_cipherlists 'EXPORT56'                         " 56 Bit encryption        "   1 "EXPORT56" "$exp56_ciphers"  "$sslv2_exp56_ciphers"
     std_cipherlists 'EXPORT'                           " Export Ciphers (general) "   1 "EXPORT"   "$exp_ciphers"    "$sslv2_exp_ciphers"
     std_cipherlists 'LOW:!ADH'                         " Low (<=64 Bit)           "   1 "LOW"      "$low_ciphers"    "$sslv2_low_ciphers"
     std_cipherlists 'DES:!ADH:!EXPORT:!aNULL'          " DES Ciphers              "   1 "DES"      "$des_ciphers"    "$sslv2_des_ciphers"
     std_cipherlists 'MEDIUM:!NULL:!aNULL:!SSLv2:!3DES' " \"Medium\" grade encryption" 2 "MEDIUM"   "$medium_ciphers" "$sslv2_medium_ciphers"
     std_cipherlists '3DES:!ADH:!aNULL'                 " Triple DES Ciphers       "   3 "3DES"     "$tdes_ciphers"   "$sslv2_tdes_ciphers"
     std_cipherlists 'HIGH:!NULL:!aNULL:!DES:!3DES'     " High grade encryption    "   0 "HIGH"     "$high_ciphers"   "$sslv2_high_ciphers"
     outln
     return 0
}

pr_ecdh_curve_quality() {
     curve="$1"
     local -i bits=0

     case "$curve" in
          "sect163k1") bits=163  ;;
          "sect163r1") bits=162  ;;
          "sect163r2") bits=163  ;;
          "sect193r1") bits=193  ;;
          "sect193r2") bits=193  ;;
          "sect233k1") bits=232  ;;
          "sect233r1") bits=233  ;;
          "sect239k1") bits=238  ;;
          "sect283k1") bits=281  ;;
          "sect283r1") bits=282  ;;
          "sect409k1") bits=407 ;;
          "sect409r1") bits=409  ;;
          "sect571k1") bits=570  ;;
          "sect571r1") bits=570  ;;
          "secp160k1") bits=161  ;;
          "secp160r1") bits=161  ;;
          "secp160r2") bits=161  ;;
          "secp192k1") bits=192  ;;
          "prime192v1") bits=192  ;;
          "secp224k1") bits=225  ;;
          "secp224r1") bits=224  ;;
          "secp256k1") bits=256  ;;
          "prime256v1") bits=256  ;;
          "secp384r1") bits=384  ;;
          "secp521r1") bits=521  ;;
          "brainpoolP256r1") bits=256  ;;
          "brainpoolP384r1") bits=384  ;;
          "brainpoolP512r1") bits=512  ;;
          "X25519") bits=253  ;;
          "X448") bits=448  ;;
     esac

     if [[ "$bits" -le 80 ]]; then      # has that ever existed?
          pr_svrty_critical "$curve"
     elif [[ "$bits" -le 108 ]]; then   # has that ever existed?
          pr_svrty_high "$curve"
     elif [[ "$bits" -le 163 ]]; then
          pr_svrty_medium "$curve"
     elif [[ "$bits" -le 193 ]]; then   # hmm, according to https://wiki.openssl.org/index.php/Elliptic_Curve_Cryptography it should ok
          pr_svrty_low "$curve"         # but openssl removed it https://github.com/drwetter/testssl.sh/issues/299#issuecomment-220905416
     elif [[ "$bits" -le 224 ]]; then
          out "$curve"
     elif [[ "$bits" -gt 224 ]]; then
          pr_done_good "$curve"
     else
          out "$curve"
     fi
}

# arg1: file with input for grepping the bit length for ECDH/DHE
# arg2: whether to print warning "old fart" or not (empty: no)
read_dhbits_from_file() {
     local bits what_dh temp curve=""
     local add=""
     local old_fart=" (your $OPENSSL cannot show DH bits)"

     temp=$(awk -F': ' '/^Server Temp Key/ { print $2 }' "$1")        # extract line
     what_dh=$(awk -F',' '{ print $1 }' <<< $temp)
     bits=$(awk -F',' '{ print $3 }' <<< $temp)
     # RH's backport has the DH bits in second arg after comma
     if grep -q bits <<< $bits; then
          curve="$(strip_spaces "$(awk -F',' '{ print $2 }' <<< $temp)")"
     else
          bits=$(awk -F',' '{ print $2 }' <<< $temp)
     fi
     bits=$(tr -d ' bits' <<< $bits)

     if [[ "$what_dh" == "X25519" ]] || [[ "$what_dh" == "X448" ]]; then
          curve="$what_dh"
          what_dh="ECDH"
     fi

     if [[ -n "$curve" ]]; then
          debugme echo ">$HAS_DH_BITS|$what_dh($curve)|$bits<"
     else
          debugme echo ">$HAS_DH_BITS|$what_dh|$bits<"
     fi

     [[ -n "$what_dh" ]] && HAS_DH_BITS=true                            # FIX 190
     if [[ -z "$what_dh" ]] && ! "$HAS_DH_BITS"; then
          if [[ -z "$2" ]]; then
               pr_warning "$old_fart"
          fi
          return 0
     fi

     [[ -n "$bits" ]] && [[ -z "$2" ]] && out ", "
     if [[ $what_dh == "DH" ]] || [[ $what_dh == "EDH" ]]; then
          if [[ -z "$2" ]]; then
               add="bit DH"
               [[ -n "$curve" ]] && add+=" ($curve)"
          fi
          if [[ "$bits" -le 600 ]]; then
               pr_svrty_critical "$bits $add"
          elif [[ "$bits" -le 800 ]]; then
               pr_svrty_high "$bits $add"
          elif [[ "$bits" -le 1280 ]]; then
               pr_svrty_medium "$bits $add"
          elif [[ "$bits" -ge 2048 ]]; then
               pr_done_good "$bits $add"
          else
               out "$bits $add"
          fi
     # https://wiki.openssl.org/index.php/Elliptic_Curve_Cryptography, http://www.keylength.com/en/compare/
     elif [[ $what_dh == "ECDH" ]]; then
          if [[ -z "$2" ]]; then
               add="bit ECDH"
               [[ -n "$curve" ]] && add+=" ($curve)"
          fi
          if [[ "$bits" -le 80 ]]; then      # has that ever existed?
               pr_svrty_critical "$bits $add"
          elif [[ "$bits" -le 108 ]]; then   # has that ever existed?
               pr_svrty_high "$bits $add"
          elif [[ "$bits" -le 163 ]]; then
               pr_svrty_medium "$bits $add"
          elif [[ "$bits" -le 193 ]]; then   # hmm, according to https://wiki.openssl.org/index.php/Elliptic_Curve_Cryptography it should ok
               pr_svrty_low "$bits $add"   # but openssl removed it https://github.com/drwetter/testssl.sh/issues/299#issuecomment-220905416
          elif [[ "$bits" -le 224 ]]; then
               out "$bits $add"
          elif [[ "$bits" -gt 224 ]]; then
               pr_done_good "$bits $add"
          else
               out "$bits $add"
          fi
     fi

     return 0
}


run_server_preference() {
     local cipher1 cipher2
     local default_cipher default_cipher_ossl default_proto
     local remark4default_cipher supported_sslv2_ciphers
     local -a cipher proto
     local p i
     local -i ret=0 j
     local list_fwd="DES-CBC3-SHA:RC4-MD5:DES-CBC-SHA:RC4-SHA:AES128-SHA:AES128-SHA256:AES256-SHA:ECDHE-RSA-AES128-SHA:DHE-RSA-AES128-SHA:DHE-RSA-AES256-SHA:ECDH-RSA-DES-CBC3-SHA:ECDH-RSA-AES128-SHA:ECDH-RSA-AES256-SHA:ECDHE-RSA-AES256-GCM-SHA384:DHE-RSA-AES128-SHA256:DHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES128-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-SHA384:ECDHE-RSA-AES256-SHA:DHE-DSS-AES256-GCM-SHA384:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES128-GCM-SHA256:AES256-SHA256"
     # now reversed offline via tac, see https://github.com/thomassa/testssl.sh/commit/7a4106e839b8c3033259d66697893765fc468393 :
     local list_reverse="AES256-SHA256:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:DHE-DSS-AES256-GCM-SHA384:ECDHE-RSA-AES256-SHA:ECDHE-RSA-AES256-SHA384:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES128-SHA256:DHE-RSA-AES256-GCM-SHA384:DHE-RSA-AES128-SHA256:ECDHE-RSA-AES256-GCM-SHA384:ECDH-RSA-AES256-SHA:ECDH-RSA-AES128-SHA:ECDH-RSA-DES-CBC3-SHA:DHE-RSA-AES256-SHA:DHE-RSA-AES128-SHA:ECDHE-RSA-AES128-SHA:AES256-SHA:AES128-SHA256:AES128-SHA:RC4-SHA:DES-CBC-SHA:RC4-MD5:DES-CBC3-SHA"
     local has_cipher_order=true
     local isok addcmd="" addcmd2="" sni=""
     local using_sockets=true

     "$SSL_NATIVE" && using_sockets=false

     outln
     pr_headlineln " Testing server preferences "
     outln

     pr_bold " Has server cipher order?     "
     [[ "$OPTIMAL_PROTO" == "-ssl2" ]] && addcmd="$OPTIMAL_PROTO"
     if [[ ! "$OPTIMAL_PROTO" =~ ssl ]]; then
          addcmd="$SNI"
          sni="$SNI"
          if "$HAS_NO_SSL2" && [[ -z "$SNI" ]]; then
               # the supplied openssl sends otherwise an sslv2 hello -- e.g. if IP address supplied as target
               # for STARTTLS this doesn't seem to be needed
               addcmd="-no_ssl2"
          fi
     fi
     $OPENSSL s_client $STARTTLS -cipher $list_fwd $BUGS -connect $NODEIP:$PORT $PROXY $addcmd </dev/null 2>$ERRFILE >$TMPFILE
     if ! sclient_connect_successful $? $TMPFILE && [[ -z "$STARTTLS_PROTOCOL" ]]; then
          pr_warning "no matching cipher in this list found (pls report this): "
          outln "$list_fwd  . "
          has_cipher_order=false
          ret=6
          fileout "order_bug" "WARN" "Could not determine server cipher order, no matching cipher in this list found (pls report this): $list_fwd"
     elif [[ -n "$STARTTLS_PROTOCOL" ]]; then
          # now it still could be that we hit this bug: https://github.com/drwetter/testssl.sh/issues/188
          # workaround is to connect with a protocol
          debugme out "(workaround #188) "
          determine_optimal_proto $STARTTLS_PROTOCOL
          $OPENSSL s_client $STARTTLS $STARTTLS_OPTIMAL_PROTO -cipher $list_fwd $BUGS -connect $NODEIP:$PORT $PROXY $addcmd2 </dev/null 2>$ERRFILE >$TMPFILE
          if ! sclient_connect_successful $? $TMPFILE; then
               pr_warning "no matching cipher in this list found (pls report this): "
               outln "$list_fwd  . "
               has_cipher_order=false
               ret=6
               fileout "order_bug" "WARN" "Could not determine server cipher order, no matching cipher in this list found (pls report this): $list_fwd"
          fi
     fi

     if "$has_cipher_order"; then
          cipher1=$(grep -wa Cipher $TMPFILE | egrep -avw "New|is" | sed -e 's/^ \+Cipher \+://' -e 's/ //g')
          addcmd2=""
          if [[ -n "$STARTTLS_OPTIMAL_PROTO" ]]; then
               addcmd2="$STARTTLS_OPTIMAL_PROTO"
               [[ ! "$STARTTLS_OPTIMAL_PROTO" =~ ssl ]] && addcmd2="$addcmd2 $SNI"
          else
               if [[ "$OPTIMAL_PROTO" == "-ssl2" ]]; then
                    addcmd2="$OPTIMAL_PROTO"
               elif "$HAS_NO_SSL2"; then
                    addcmd2="$addcmd2 -no_ssl2"
               fi
               [[ ! "$OPTIMAL_PROTO" =~ ssl ]] && addcmd2="$addcmd2 $SNI"
          fi
          $OPENSSL s_client $STARTTLS -cipher $list_reverse $BUGS -connect $NODEIP:$PORT $PROXY $addcmd2 </dev/null 2>>$ERRFILE >$TMPFILE
          # that worked above so no error handling here
          cipher2=$(grep -wa Cipher $TMPFILE | egrep -avw "New|is" | sed -e 's/^ \+Cipher \+://' -e 's/ //g')

          if [[ "$cipher1" != "$cipher2" ]]; then
               pr_svrty_high "nope (NOT ok)"
               remark4default_cipher=" (limited sense as client will pick)"
               fileout "order" "HIGH" "Server does NOT set a cipher order"
          else
               pr_done_best "yes (OK)"
               remark4default_cipher=""
               fileout "order" "OK" "Server sets a cipher order"
          fi
          debugme out "  $cipher1 | $cipher2"
          outln

          pr_bold " Negotiated protocol          "
          $OPENSSL s_client $STARTTLS $BUGS -connect $NODEIP:$PORT $PROXY $addcmd </dev/null 2>>$ERRFILE >$TMPFILE
          if ! sclient_connect_successful $? $TMPFILE; then
               # 2 second try with $OPTIMAL_PROTO especially for intolerant IIS6 servers:
               $OPENSSL s_client $STARTTLS $OPTIMAL_PROTO $BUGS -connect $NODEIP:$PORT $PROXY $sni </dev/null 2>>$ERRFILE >$TMPFILE
               sclient_connect_successful $? $TMPFILE || pr_warning "Handshake error!"
          fi
          default_proto=$(grep -aw "Protocol" $TMPFILE | sed -e 's/^.*Protocol.*://' -e 's/ //g')
          case "$default_proto" in
               *TLSv1.2)
                    pr_done_bestln $default_proto
                    fileout "order_proto" "OK" "Default protocol TLS1.2"
                    ;;
               *TLSv1.1)
                    pr_done_goodln $default_proto
                    fileout "order_proto" "OK" "Default protocol TLS1.1"
                    ;;
               *TLSv1)
                    outln $default_proto
                    fileout "order_proto" "INFO" "Default protocol TLS1.0"
                    ;;
               *SSLv2)
                    pr_svrty_criticalln $default_proto
                    fileout "order_proto" "CRITICAL" "Default protocol SSLv2"
                    ;;
               *SSLv3)
                    pr_svrty_criticalln $default_proto
                    fileout "order_proto" "CRITICAL" "Default protocol SSLv3"
                    ;;
               "")
                    pr_warning "default proto empty"
                    if [[ $OSSL_VER == 1.0.2* ]]; then
                         outln " (Hint: if IIS6 give OpenSSL 1.0.1 a try)"
                         fileout "order_proto" "WARN" "Default protocol empty (Hint: if IIS6 give OpenSSL 1.0.1 a try)"
                    else
                         fileout "order_proto" "WARN" "Default protocol empty"
                    fi
                    ;;
               *)
                    pr_warning "FIXME line $LINENO: $default_proto"
                    fileout "order_proto" "WARN" "FIXME line $LINENO: $default_proto"
                    ;;
          esac

          pr_bold " Negotiated cipher            "
          default_cipher_ossl=$(grep -aw "Cipher" $TMPFILE | egrep -avw "New|is" | sed -e 's/^.*Cipher.*://' -e 's/ //g')
          if [[ -z "$SHOW_RFC" ]]; then
               default_cipher="$default_cipher_ossl"
          else
               default_cipher="$(openssl2rfc "$default_cipher_ossl")"
               [[ -z "$default_cipher" ]] && default_cipher="$default_cipher_ossl"
          fi
          case "$default_cipher_ossl" in
               *NULL*|*EXP*)
                    pr_svrty_critical "$default_cipher"
                    fileout "order_cipher" "CRITICAL" "Default cipher: $default_cipher$(read_dhbits_from_file "$TMPFILE") $remark4default_cipher"
                    ;;
               *RC4*)
                    pr_svrty_high "$default_cipher"
                    fileout "order_cipher" "HIGH" "Default cipher: $default_cipher$(read_dhbits_from_file "$TMPFILE") $remark4default_cipher"
                    ;;
               *CBC*)
                    pr_svrty_medium "$default_cipher"
                    fileout "order_cipher" "MEDIUM" "Default cipher: $default_cipher$(read_dhbits_from_file "$TMPFILE") $remark4default_cipher"
                    ;;   # FIXME BEAST: We miss some CBC ciphers here, need to work w/ a list
               *GCM*|*CHACHA20*)
                    pr_done_best "$default_cipher"
                    fileout "order_cipher" "OK" "Default cipher: $default_cipher$(read_dhbits_from_file "$TMPFILE") $remark4default_cipher"
                    ;;   # best ones
               ECDHE*AES*)
                    pr_svrty_low "$default_cipher"
                    fileout "order_cipher" "LOW" "Default cipher: $default_cipher$(read_dhbits_from_file "$TMPFILE") (cbc)  $remark4default_cipher"
                    ;;  # it's CBC. --> lucky13
               "")
                    pr_warning "default cipher empty" ;
                    if [[ $OSSL_VER == 1.0.2* ]]; then
                         out " (Hint: if IIS6 give OpenSSL 1.0.1 a try)"
                         fileout "order_cipher" "WARN" "Default cipher empty  (Hint: if IIS6 give OpenSSL 1.0.1 a try)  $remark4default_cipher"
                    else
                         fileout "order_cipher" "WARN" "Default cipher empty  $remark4default_cipher"
                    fi
                    ;;
               *)
                    out "$default_cipher"
                    fileout "order_cipher" "INFO" "Default cipher: $default_cipher$(read_dhbits_from_file "$TMPFILE")  $remark4default_cipher"
                    ;;
          esac
          read_dhbits_from_file "$TMPFILE"
          outln "$remark4default_cipher"

          if [[ ! -z "$remark4default_cipher" ]]; then
               # no cipher order
               pr_bold " Negotiated cipher per proto"; outln " $remark4default_cipher"
               i=1
               for p in ssl2 ssl3 tls1 tls1_1 tls1_2; do
                    if [[ $p == ssl2 ]] && ! "$HAS_SSL2"; then
                         if ! "$using_sockets" || [[ $TLS_NR_CIPHERS -eq 0 ]]; then
                              out "     (SSLv2: "; local_problem "$OPENSSL doesn't support \"s_client -ssl2\""; outln ")";
                              continue
                         else
                              sslv2_sockets "" "true"
                              if [[ $? -eq 3 ]] && [[ "$V2_HELLO_CIPHERSPEC_LENGTH" -ne 0 ]]; then
                                   # Just arbitrarily pick the first cipher in the cipher-mapping.txt list.
                                   proto[i]="SSLv2"
                                   supported_sslv2_ciphers="$(grep "Supported cipher: " "$TEMPDIR/$NODEIP.parse_sslv2_serverhello.txt")"
                                   for (( j=0; j < TLS_NR_CIPHERS; j++ )); do
                                        if [[ "${TLS_CIPHER_SSLVERS[j]}" == "SSLv2" ]]; then
                                             cipher1="${TLS_CIPHER_HEXCODE[j]}"
                                             cipher1="$(tolower "x${cipher1:2:2}${cipher1:7:2}${cipher1:12:2}")"
                                             if [[ "$supported_sslv2_ciphers" =~ "$cipher1" ]]; then
                                                  if ( [[ -z "$SHOW_RFC" ]] && [[ "${TLS_CIPHER_OSSL_NAME[j]}" != "-" ]] ) || [[ "${TLS_CIPHER_RFC_NAME[j]}" == "-" ]]; then
                                                       cipher[i]="${TLS_CIPHER_OSSL_NAME[j]}"
                                                  else
                                                       cipher[i]="${TLS_CIPHER_RFC_NAME[j]}"
                                                  fi
                                                  break
                                             fi
                                        fi
                                   done
                                   [[ $DEBUG -ge 2 ]] && outln "Default cipher for ${proto[i]}: ${cipher[i]}"
                              else
                                   proto[i]=""
                                   cipher[i]=""
                              fi
                         fi
                    elif [[ $p == ssl3 ]] && ! "$HAS_SSL3"; then
                         if ! "$using_sockets"; then
                              out "     (SSLv3: "; local_problem "$OPENSSL doesn't support \"s_client -ssl3\"" ; outln ")";
                              continue
                         else
                              tls_sockets "00" "$TLS_CIPHER"
                              if [[ $? -eq 0 ]]; then
                                   proto[i]="SSLv3"
                                   cipher[i]=""
                                   cipher1=$(awk '/Cipher *:/ { print $3 }' "$TEMPDIR/$NODEIP.parse_tls_serverhello.txt")
                                   if [[ -z "$SHOW_RFC" ]] && [[ $TLS_NR_CIPHERS -ne 0 ]]; then
                                        cipher[i]="$(rfc2openssl "$cipher1")"
                                        [[ -z "${cipher[i]}" ]] && cipher[i]="$cipher1"
                                   fi
                                   [[ $DEBUG -ge 2 ]] && outln "Default cipher for ${proto[i]}: ${cipher[i]}"
                              else
                                   proto[i]=""
                                   cipher[i]=""
                              fi
                         fi
                    else
                         [[ "$p" =~ ssl ]] && sni="" || sni="$SNI"
                         $OPENSSL s_client $STARTTLS -"$p" $BUGS -connect $NODEIP:$PORT $PROXY $sni </dev/null 2>>$ERRFILE >$TMPFILE
                         if sclient_connect_successful $? $TMPFILE; then
                              proto[i]=$(grep -aw "Protocol" $TMPFILE | sed -e 's/^.*Protocol.*://' -e 's/ //g')
                              cipher[i]=$(grep -aw "Cipher" $TMPFILE | egrep -avw "New|is" | sed -e 's/^.*Cipher.*://' -e 's/ //g')
                              [[ ${cipher[i]} == "0000" ]] && cipher[i]=""                     # Hack!
                              if [[ -n "$SHOW_RFC" ]] && [[ -n "${cipher[i]}" ]]; then
                                   cipher[i]="$(openssl2rfc "${cipher[i]}")"
                                   [[ -z "${cipher[i]}" ]] && cipher[i]=$(grep -aw "Cipher" $TMPFILE | egrep -avw "New|is" | sed -e 's/^.*Cipher.*://' -e 's/ //g')
                              fi
                              [[ $DEBUG -ge 2 ]] && outln "Default cipher for ${proto[i]}: ${cipher[i]}"
                         else
                              proto[i]=""
                              cipher[i]=""
                         fi
                    fi
                    i=$(($i + 1))
               done

               [[ -n "$PROXY" ]] && arg="   SPDY/NPN is"
               [[ -n "$STARTTLS" ]] && arg="    "
               if spdy_pre " $arg" ; then                                       # is NPN/SPDY supported and is this no STARTTLS? / no PROXY
                                                                                # ALPN needs also some lines here
                    $OPENSSL s_client -connect $NODEIP:$PORT $BUGS -nextprotoneg "$NPN_PROTOs" $SNI </dev/null 2>>$ERRFILE >$TMPFILE
                    if sclient_connect_successful $? $TMPFILE; then
                         proto[i]=$(grep -aw "Next protocol" $TMPFILE | sed -e 's/^Next protocol://' -e 's/(.)//' -e 's/ //g')
                         if [[ -z "${proto[i]}" ]]; then
                              cipher[i]=""
                         else
                              cipher[i]=$(grep -aw "Cipher" $TMPFILE | egrep -avw "New|is" | sed -e 's/^.*Cipher.*://' -e 's/ //g')
                              if [[ -n "$SHOW_RFC" ]] && [[ -n "${cipher[i]}" ]]; then
                                   cipher[i]="$(openssl2rfc "${cipher[i]}")"
                                   [[ -z "${cipher[i]}" ]] && cipher[i]=$(grep -aw "Cipher" $TMPFILE | egrep -avw "New|is" | sed -e 's/^.*Cipher.*://' -e 's/ //g')
                              fi
                              [[ $DEBUG -ge 2 ]] && outln "Default cipher for ${proto[i]}: ${cipher[i]}"
                         fi
                    fi
               else
                    outln     # we miss for STARTTLS 1x LF otherwise
               fi

               for i in 1 2 3 4 5 6; do
                    if [[ -n "${cipher[i]}" ]]; then                                      # cipher not empty
                          if [[ -z "${cipher[i-1]}" ]]; then                              # previous one empty
                              #outln
                              if [[ -z "$SHOW_RFC" ]]; then
                                   printf -- "     %-30s %s" "${cipher[i]}:" "${proto[i]}"     # print out both
                              else
                                   printf -- "     %-51s %s" "${cipher[i]}:" "${proto[i]}"     # print out both
                              fi
                          else                                                            # previous NOT empty
                              if [[ "${cipher[i-1]}" == "${cipher[i]}" ]]; then           # and previous protocol same cipher
                                   out ", ${proto[i]}"                                    # same cipher --> only print out protocol behind it
                              else
                                   outln
                                   if [[ -z "$SHOW_RFC" ]]; then
                                        printf -- "     %-30s %s" "${cipher[i]}:" "${proto[i]}"     # print out both
                                   else
                                        printf -- "     %-51s %s" "${cipher[i]}:" "${proto[i]}"     # print out both
                                   fi
                             fi
                          fi
                    fi
                    fileout "order_${proto[i]}_cipher" "INFO" "Default cipher on ${proto[i]}: ${cipher[i]} $remark4default_cipher"
               done
          fi
     fi

     tmpfile_handle $FUNCNAME.txt
     if [[ -z "$remark4default_cipher" ]]; then
          cipher_pref_check
     else
          outln "\n No further cipher order check has been done as order is determined by the client"
          outln
     fi
     return 0
}

check_tls12_pref() {
     local batchremoved="-CAMELLIA:-IDEA:-KRB5:-PSK:-SRP:-aNULL:-eNULL"
     local batchremoved_success=false
     local tested_cipher=""
     local order=""
     local -i nr_ciphers_found_r1=0 nr_ciphers_found_r2=0

     while true; do
          $OPENSSL s_client $STARTTLS -tls1_2 $BUGS -cipher "ALL$tested_cipher:$batchremoved" -connect $NODEIP:$PORT $PROXY $SNI </dev/null 2>>$ERRFILE >$TMPFILE
          if sclient_connect_successful $? $TMPFILE ; then
               cipher=$(awk '/Cipher.*:/ { print $3 }' $TMPFILE)
               order+=" $cipher"
               tested_cipher="$tested_cipher:-$cipher"
               nr_ciphers_found_r1+=1
               "$FAST" && break
          else
               debugme outln "A: $tested_cipher"
               break
          fi
     done
     batchremoved="${batchremoved//-/}"
     while true; do
          # no ciphers from "ALL$tested_cipher:$batchremoved" left
          # now we check $batchremoved, and remove the minus signs first:
          $OPENSSL s_client $STARTTLS -tls1_2 $BUGS -cipher "$batchremoved" -connect $NODEIP:$PORT $PROXY $SNI </dev/null 2>>$ERRFILE >$TMPFILE
          if sclient_connect_successful $? $TMPFILE ; then
               batchremoved_success=true               # signals that we have some of those ciphers and need to put everything together later on
               cipher=$(awk '/Cipher.*:/ { print $3 }' $TMPFILE)
               order+=" $cipher"
               batchremoved="$batchremoved:-$cipher"
               nr_ciphers_found_r1+=1
               debugme outln "B1: $batchremoved"
               "$FAST" && break
          else
               debugme outln "B2: $batchremoved"
               break
               # nothing left with batchremoved ciphers, we need to put everything together
          fi
     done

     if "$batchremoved_success"; then
          # now we combine the two cipher sets from both while loops
          [[ "${order:0:1}" == " " ]] && order="${order:1}"
          combined_ciphers="${order// /:}"
          order="" ; tested_cipher=""
          while true; do
               $OPENSSL s_client $STARTTLS -tls1_2 $BUGS -cipher "$combined_ciphers$tested_cipher" -connect $NODEIP:$PORT $PROXY $SNI </dev/null 2>>$ERRFILE >$TMPFILE
               if sclient_connect_successful $? $TMPFILE ; then
                    cipher=$(awk '/Cipher.*:/ { print $3 }' $TMPFILE)
                    order+=" $cipher"
                    tested_cipher="$tested_cipher:-$cipher"
                    nr_ciphers_found_r2+=1
                    "$FAST" && break
               else
                    # nothing left, we're done
                    break
               fi
          done
          if "$FAST" && [[ $nr_ciphers_found_r2 -ne 1 ]]; then
                fixmeln "something weird happened around line $((LINENO - 14))"
                return 1
          elif ! "$FAST" && [[ $nr_ciphers_found_r2 -ne $nr_ciphers_found_r1 ]]; then
                fixmeln "something weird happened around line $((LINENO - 16))"
                return 1
          fi
     fi
     out "$order"

     tmpfile_handle $FUNCNAME.txt
     return 0
}


cipher_pref_check() {
     local p proto proto_hex npn_protos sni
     local tested_cipher cipher order rfc_ciph rfc_order
     local overflow_probe_cipherlist="ALL:-ECDHE-RSA-AES256-GCM-SHA384:-AES128-SHA:-DES-CBC3-SHA"
     local -i i nr_ciphers nr_nonossl_ciphers num_bundles mod_check bundle_size bundle end_of_bundle success
     local hexc ciphers_to_test
     local -a rfc_ciph hexcode ciphers_found ciphers_found2
     local -a -i index
     local using_sockets=true ciphers_found_with_sockets

     "$SSL_NATIVE" && using_sockets=false
     "$FAST" && using_sockets=false
     [[ $TLS_NR_CIPHERS == 0 ]] && using_sockets=false

     pr_bold " Cipher order"

     outln " ssl3 00 SSLv3\n tls1 01 TLSv1\n tls1_1 02 TLSv1.1\n tls1_2 03 TLSv1.2"| while read p proto_hex proto; do
          order=""; ciphers_found_with_sockets=false
          if [[ $p == ssl3 ]] && ! "$HAS_SSL3" && ! "$using_sockets"; then
               out "\n    SSLv3:     "; local_problem "$OPENSSL doesn't support \"s_client -ssl3\"";
               continue
          fi
          has_server_protocol "$p" || continue

          if [[ $p != ssl3 ]] || "$HAS_SSL3"; then
               # with the supplied binaries SNI works also for SSLv3
               [[ "$p" =~ ssl ]] && sni="" || sni=$SNI

               if [[ $p == tls1_2 ]] && ! "$SERVER_SIZE_LIMIT_BUG"; then
                    # for some servers the ClientHello is limited to 128 ciphers or the ClientHello itself has a length restriction.
                    # So far, this was only observed in TLS 1.2, affected are e.g. old Cisco LBs or ASAs, see issue #189
                    # To check whether a workaround is needed we send a laaarge list of ciphers/big client hello. If connect fails,
                    # we hit the bug and automagically do the workround. Cost: this is for all servers only 1x more connect
                    $OPENSSL s_client $STARTTLS -tls1_2 $BUGS -cipher "$overflow_probe_cipherlist" -connect $NODEIP:$PORT $PROXY $SNI </dev/null 2>>$ERRFILE >$TMPFILE
                    if ! sclient_connect_successful $? $TMPFILE; then
#FIXME this needs to be handled differently. We need 2 status: BUG={true,false,not tested yet}
                         SERVER_SIZE_LIMIT_BUG=true
                    fi
               fi
               if [[ $p == tls1_2 ]] && "$SERVER_SIZE_LIMIT_BUG"; then
                    order="$(check_tls12_pref)"
               else
                    tested_cipher=""
                    while true; do
                         $OPENSSL s_client $STARTTLS -"$p" $BUGS -cipher "ALL:COMPLEMENTOFALL$tested_cipher" -connect $NODEIP:$PORT $PROXY $sni </dev/null 2>>$ERRFILE >$TMPFILE
                         sclient_connect_successful $? $TMPFILE || break
                         cipher=$(awk '/Cipher *:/ { print $3 }' $TMPFILE)
                         [[ -z "$cipher" ]] && break
                         order+="$cipher "
                         tested_cipher+=":-"$cipher
                         "$FAST" && break
                    done
               fi
          fi

          nr_nonossl_ciphers=0
          if "$using_sockets"; then
               for (( i=0; i < TLS_NR_CIPHERS; i++ )); do
                    ciphers_found[i]=false
                    hexc="${TLS_CIPHER_HEXCODE[i]}"
                    if [[ ${#hexc} -eq 9 ]]; then
                         if [[ " $order " =~ " ${TLS_CIPHER_OSSL_NAME[i]} " ]]; then
                              ciphers_found[i]=true
                         else
                              ciphers_found2[nr_nonossl_ciphers]=false
                              hexcode[nr_nonossl_ciphers]="${hexc:2:2},${hexc:7:2}"
                              rfc_ciph[nr_nonossl_ciphers]="${TLS_CIPHER_RFC_NAME[i]}"
                              index[nr_nonossl_ciphers]=$i
                              # Only test ciphers that are relevant to the protocol.
                              if [[ "$p" == "tls1_3" ]]; then
                                   [[ "${hexc:2:2}" == "13" ]] && nr_nonossl_ciphers+=1
                              elif [[ "$p" == "tls1_2" ]]; then
                                   [[ "${hexc:2:2}" != "13" ]] && nr_nonossl_ciphers+=1
                              elif [[ ! "${TLS_CIPHER_RFC_NAME[i]}" =~ "SHA256" ]] && \
                                   [[ ! "${TLS_CIPHER_RFC_NAME[i]}" =~ "SHA384" ]] && \
                                   [[ "${TLS_CIPHER_RFC_NAME[i]}" != *"_CCM" ]] && \
                                   [[ "${TLS_CIPHER_RFC_NAME[i]}" != *"_CCM_8" ]]; then
                                   nr_nonossl_ciphers+=1
                              fi
                         fi
                    fi
               done
          fi

          if [[ $nr_nonossl_ciphers -eq 0 ]]; then
               num_bundles=0
          elif [[ $p != tls1_2 ]] || ! "$SERVER_SIZE_LIMIT_BUG"; then
               num_bundles=1
               bundle_size=$nr_nonossl_ciphers
          else
               num_bundles=$nr_nonossl_ciphers/128
               mod_check=$nr_nonossl_ciphers%128
               [[ $mod_check -ne 0 ]] && num_bundles=$num_bundles+1

               bundle_size=$nr_nonossl_ciphers/$num_bundles
               mod_check=$nr_nonossl_ciphers%$num_bundles
               [[ $mod_check -ne 0 ]] && bundle_size+=1
          fi

          for (( bundle=0; bundle < num_bundles; bundle++ )); do
               end_of_bundle=$bundle*$bundle_size+$bundle_size
               [[ $end_of_bundle -gt $nr_nonossl_ciphers ]] && end_of_bundle=$nr_nonossl_ciphers
               while true; do
                    ciphers_to_test=""
                    for (( i=bundle*bundle_size; i < end_of_bundle; i++ )); do
                         ! "${ciphers_found2[i]}" && ciphers_to_test+=", ${hexcode[i]}"
                    done
                    [[ -z "$ciphers_to_test" ]] && break
                    tls_sockets "$proto_hex" "${ciphers_to_test:2}, 00,ff" "ephemeralkey"
                    [[ $? -ne 0 ]] && break
                    cipher=$(awk '/Cipher *:/ { print $3 }' "$TEMPDIR/$NODEIP.parse_tls_serverhello.txt")
                    for (( i=bundle*bundle_size; i < end_of_bundle; i++ )); do
                         [[ "$cipher" == "${rfc_ciph[i]}" ]] && ciphers_found2[i]=true && break
                    done
                    i=${index[i]}
                    ciphers_found[i]=true
                    ciphers_found_with_sockets=true
                    if [[ $p != tls1_2 ]] || ! "$SERVER_SIZE_LIMIT_BUG"; then
                         # Throw out the results found so far and start over using just sockets
                         bundle=$num_bundles
                         for (( i=0; i < TLS_NR_CIPHERS; i++ )); do
                              ciphers_found[i]=true
                         done
                         break
                    fi
               done
          done

          # If additional ciphers were found using sockets and there is no
          # SERVER_SIZE_LIMIT_BUG, then just use sockets to find the cipher order.
          # If there is a SERVER_SIZE_LIMIT_BUG, then use sockets to find the cipher
          # order, but starting with the list of ciphers supported by the server.
          if "$ciphers_found_with_sockets"; then
               order=""
               nr_ciphers=0
               for (( i=0; i < TLS_NR_CIPHERS; i++ )); do
                    hexc="${TLS_CIPHER_HEXCODE[i]}"
                    if "${ciphers_found[i]}" && [[ ${#hexc} -eq 9 ]]; then
                         ciphers_found2[nr_ciphers]=false
                         hexcode[nr_ciphers]="${hexc:2:2},${hexc:7:2}"
                         rfc_ciph[nr_ciphers]="${TLS_CIPHER_RFC_NAME[i]}"
                         if [[ "$p" == "tls1_3" ]]; then
                              [[ "${hexc:2:2}" == "13" ]] && nr_ciphers+=1
                         elif [[ "$p" == "tls1_2" ]]; then
                              [[ "${hexc:2:2}" != "13" ]] && nr_ciphers+=1
                         elif [[ ! "${TLS_CIPHER_RFC_NAME[i]}" =~ "SHA256" ]] && \
                              [[ ! "${TLS_CIPHER_RFC_NAME[i]}" =~ "SHA384" ]] && \
                              [[ "${TLS_CIPHER_RFC_NAME[i]}" != *"_CCM" ]] && \
                              [[ "${TLS_CIPHER_RFC_NAME[i]}" != *"_CCM_8" ]]; then
                              nr_ciphers+=1
                         fi
                    fi
               done
               while true; do
                    ciphers_to_test=""
                    for (( i=0; i < nr_ciphers; i++ )); do
                         ! "${ciphers_found2[i]}" && ciphers_to_test+=", ${hexcode[i]}"
                    done
                    [[ -z "$ciphers_to_test" ]] && break
                    tls_sockets "$proto_hex" "${ciphers_to_test:2}, 00,ff" "ephemeralkey"
                    [[ $? -ne 0 ]] && break
                    cipher=$(awk '/Cipher *:/ { print $3 }' "$TEMPDIR/$NODEIP.parse_tls_serverhello.txt")
                    for (( i=0; i < nr_ciphers; i++ )); do
                         [[ "$cipher" == "${rfc_ciph[i]}" ]] && ciphers_found2[i]=true && break
                    done
                    if [[ -z "$SHOW_RFC" ]] && [[ $TLS_NR_CIPHERS -ne 0 ]]; then
                         cipher="$(rfc2openssl "$cipher")"
                         # If there is no OpenSSL name for the cipher, then use the RFC name
                         [[ -z "$cipher" ]] && cipher=$(awk '/Cipher *:/ { print $3 }' "$TEMPDIR/$NODEIP.parse_tls_serverhello.txt")
                    fi
                    order+="$cipher "
               done
          elif [[ -n "$order" ]] && [[ -n "$SHOW_RFC" ]]; then
               rfc_order=""
               while read -d " " cipher; do
                    rfc_ciph="$(openssl2rfc "$cipher")"
                    if [[ -n "$rfc_ciph" ]]; then
                         rfc_order+="$rfc_ciph "
                    else
                         rfc_order+="$cipher "
                    fi
               done <<< "$order"
               order="$rfc_order"
          fi

          if [[ -n "$order" ]]; then
               outln
               printf "    %-10s " "$proto: "
               out_row_aligned_max_width "$order" "               " $TERM_WIDTH out
               fileout "order_$p" "INFO" "Default cipher order for protocol $p: $order"
          fi
     done
     outln

     if ! spdy_pre "     SPDY/NPN: "; then       # is NPN/SPDY supported and is this no STARTTLS?
          outln
     else
          npn_protos=$($OPENSSL s_client $BUGS -nextprotoneg \"\" -connect $NODEIP:$PORT $SNI </dev/null 2>>$ERRFILE | grep -a "^Protocols " | sed -e 's/^Protocols.*server: //' -e 's/,//g')
          for p in $npn_protos; do
               order=""
               $OPENSSL s_client $BUGS -nextprotoneg "$p" -connect $NODEIP:$PORT $SNI </dev/null 2>>$ERRFILE >$TMPFILE
               cipher=$(awk '/Cipher.*:/ { print $3 }' $TMPFILE)
               printf "    %-10s " "$p:"
               tested_cipher="-"$cipher
               order="$cipher "
               if ! "$FAST"; then
                    while true; do
                         $OPENSSL s_client -cipher "ALL:$tested_cipher" $BUGS -nextprotoneg "$p" -connect $NODEIP:$PORT $SNI </dev/null 2>>$ERRFILE >$TMPFILE
                         sclient_connect_successful $? $TMPFILE || break
                         cipher=$(awk '/Cipher.*:/ { print $3 }' $TMPFILE)
                         tested_cipher="$tested_cipher:-$cipher"
                         order+="$cipher "
                    done
               fi
               if [[ -n "$order" ]] && [[ -n "$SHOW_RFC" ]]; then
                    rfc_order=""
                    while read -d " " cipher; do
                         rfc_ciph="$(openssl2rfc "$cipher")"
                         if [[ -n "$rfc_ciph" ]]; then
                              rfc_order+="$rfc_ciph "
                         else
                              rfc_order+="$cipher "
                         fi
                    done <<< "$order"
                    order="$rfc_order"
               fi
               out_row_aligned_max_width "$order" "               " $TERM_WIDTH out
               outln
               [[ -n $order ]] && fileout "order_spdy_$p" "INFO" "Default cipher order for SPDY protocol $p: $order"
          done
     fi

     outln
     tmpfile_handle $FUNCNAME.txt
     return 0
}


# arg1 is OpenSSL s_client parameter or empty
get_host_cert() {
     local tmpvar=$TEMPDIR/$FUNCNAME.txt     # change later to $TMPFILE

     $OPENSSL s_client $STARTTLS $BUGS -connect $NODEIP:$PORT $PROXY $SNI $1 2>/dev/null </dev/null >$tmpvar
     if sclient_connect_successful $? $tmpvar; then
          awk '/-----BEGIN/,/-----END/ { print $0 }' $tmpvar >$HOSTCERT
          return 0
     else
          [[ -z "$1" ]] && pr_warningln "could not retrieve host certificate!"
          #fileout "host_certificate" "WARN" "Could not retrieve host certificate!"
          return 1
     fi
     #tmpfile_handle $FUNCNAME.txt
     #return $((${PIPESTATUS[0]} + ${PIPESTATUS[1]}))
}

verify_retcode_helper() {
     local ret=0
     local -i retcode=$1

	case $retcode in
		# codes from ./doc/apps/verify.pod | verify(1ssl)
		26) out "(unsupported certificate purpose)" ;; 	# X509_V_ERR_INVALID_PURPOSE
		24) out "(certificate unreadable)" ;; 	# X509_V_ERR_INVALID_CA
		23) out "(certificate revoked)" ;; 		# X509_V_ERR_CERT_REVOKED
		21) out "(chain incomplete, only 1 cert provided)" ;; 	# X509_V_ERR_UNABLE_TO_VERIFY_LEAF_SIGNATURE
		20) out "(chain incomplete)" ;;			# X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY
		19) out "(self signed CA in chain)" ;;	# X509_V_ERR_SELF_SIGNED_CERT_IN_CHAIN
		18) out "(self signed)" ;;				# X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT
		10) out "(expired)" ;;				     # X509_V_ERR_CERT_HAS_EXPIRED
		9)  out "(not yet valid)" ;;		     # X509_V_ERR_CERT_NOT_YET_VALID
		2)  out "(issuer cert missing)" ;;         # X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT
		*) ret=1 ; pr_warning " (unknown, pls report) $1" ;;
	esac
     return $ret
}

# arg1: number of certificate if provided >1
determine_trust() {
	local json_prefix=$1
	local -i i=1
	local -i num_ca_bundles=0
	local bundle_fname=""
	local -a certificate_file verify_retcode trust
	local ok_was=""
	local notok_was=""
	local all_ok=true
	local some_ok=false
     local code
     local ca_bundles=""
     local spaces="                              "
     local -i certificates_provided=1+$(grep -c "\-\-\-\-\-BEGIN CERTIFICATE\-\-\-\-\-" $TEMPDIR/intermediatecerts.pem)
     local addtl_warning

     # If $json_prefix is not empty, then there is more than one certificate
     # and the output should should be indented by two more spaces.
     [[ -n $json_prefix ]] && spaces="                                "

     if [[ $OSSL_VER_MAJOR.$OSSL_VER_MINOR != "1.0.2" ]] && \
          [[ $OSSL_VER_MAJOR.$OSSL_VER_MINOR != "1.1.0" ]] && \
          [[ $OSSL_VER_MAJOR.$OSSL_VER_MINOR != "1.1.1" ]]; then
          addtl_warning="(Your $OPENSSL <= 1.0.2 might be too unreliable to determine trust)"
          fileout "${json_prefix}chain_of_trust_warn" "WARN" "$addtl_warning"
     fi
     debugme outln

     # if you run testssl.sh from a different path /you can set either TESTSSL_INSTALL_DIR or CA_BUNDLES_PATH to find the CA BUNDLES
     if [[ -z $CA_BUNDLES_PATH ]]; then
          ca_bundles="$TESTSSL_INSTALL_DIR/etc/*.pem"
     else
          ca_bundles="$CA_BUNDLES_PATH/*.pem"
     fi
	for bundle_fname in $ca_bundles; do
		certificate_file[i]=$(basename ${bundle_fname//.pem})
          if [[ ! -r $bundle_fname ]]; then
               pr_warningln "\"$bundle_fname\" cannot be found / not readable"
               return 7
          fi
		debugme printf -- " %-12s" "${certificate_file[i]}"
		# set SSL_CERT_DIR to /dev/null so that $OPENSSL verify will only use certificates in $bundle_fname
		(export SSL_CERT_DIR="/dev/null; export SSL_CERT_FILE=/dev/null"
		if [[ $certificates_provided -ge 2 ]]; then
		     $OPENSSL verify -purpose sslserver -CAfile "$bundle_fname" -untrusted $TEMPDIR/intermediatecerts.pem $HOSTCERT >$TEMPDIR/${certificate_file[i]}.1 2>$TEMPDIR/${certificate_file[i]}.2
		else
		     $OPENSSL verify -purpose sslserver -CAfile "$bundle_fname" $HOSTCERT >$TEMPDIR/${certificate_file[i]}.1 2>$TEMPDIR/${certificate_file[i]}.2
		fi)
		verify_retcode[i]=$(awk '/error [1-9][0-9]? at [0-9]+ depth lookup:/ { if (!found) {print $2; found=1} }' $TEMPDIR/${certificate_file[i]}.1)
		[[ -z "${verify_retcode[i]}" ]] && verify_retcode[i]=0
		if [[ ${verify_retcode[i]} -eq 0 ]]; then
			trust[i]=true
			some_ok=true
			debugme pr_done_good "Ok   "
			debugme outln "${verify_retcode[i]}"
		else
			trust[i]=false
			all_ok=false
			debugme pr_svrty_high "not trusted "
			debugme outln "${verify_retcode[i]}"
		fi
		i=$((i + 1))
	done
	num_ca_bundles=$((i - 1))
     debugme out " "
	if $all_ok; then
	     # all stores ok
		pr_done_good "Ok   "; pr_warning "$addtl_warning"
          # we did to stdout the warning above already, so we could stay here with INFO:
          fileout "${json_prefix}chain_of_trust" "OK" "All certificate trust checks passed. $addtl_warning"
	else
	     # at least one failed
		pr_svrty_critical "NOT ok"
		if ! $some_ok; then
		     # all failed (we assume with the same issue), we're displaying the reason
               out " "
			verify_retcode_helper "${verify_retcode[1]}"
               fileout "${json_prefix}chain_of_trust" "CRITICAL" "All certificate trust checks failed: $(verify_retcode_helper "${verify_retcode[1]}"). $addtl_warning"
		else
			# is one ok and the others not ==> display the culprit store
			if $some_ok ; then
				pr_svrty_critical ":"
				for ((i=1;i<=num_ca_bundles;i++)); do
					if ${trust[i]}; then
						ok_was="${certificate_file[i]} $ok_was"
					else
                              #code="$(verify_retcode_helper ${verify_retcode[i]})"
                              #notok_was="${certificate_file[i]} $notok_was"
                              pr_svrty_high " ${certificate_file[i]} "
                              verify_retcode_helper "${verify_retcode[i]}"
			               notok_was="${certificate_file[i]} $(verify_retcode_helper "${verify_retcode[i]}") $notok_was"
               		fi
				done
				#pr_svrty_high "$notok_was "
                    #outln "$code"
                    outln
				# lf + green ones
                    [[ "$DEBUG" -eq 0 ]] && out "$spaces"
				pr_done_good "OK: $ok_was"
               fi
               fileout "${json_prefix}chain_of_trust" "CRITICAL" "Some certificate trust checks failed : OK : $ok_was  NOT ok: $notok_was $addtl_warning"
          fi
          [[ -n "$addtl_warning" ]] && out "\n$spaces" && pr_warning "$addtl_warning"
	fi
	outln
     return 0
}

# not handled: Root CA supplied (contains anchor)

tls_time() {
     local now difftime
     local spaces="               "

     tls_sockets "01" "$TLS_CIPHER"                              # try first TLS 1.0 (most frequently used protocol)
     [[ -z "$TLS_TIME" ]] && tls_sockets "03" "$TLS12_CIPHER"    #           TLS 1.2
     [[ -z "$TLS_TIME" ]] && tls_sockets "02" "$TLS_CIPHER"      #           TLS 1.1
     [[ -z "$TLS_TIME" ]] && tls_sockets "00" "$TLS_CIPHER"      #           SSL 3

     pr_bold " TLS clock skew" ; out "$spaces"
     if [[ -n "$TLS_TIME" ]]; then                               # nothing returned a time!
          difftime=$(($TLS_TIME - $TLS_NOW))                     # TLS_NOW is being set in tls_sockets()
          if [[ "${#difftime}" -gt 5 ]]; then
               # openssl >= 1.0.1f fills this field with random values! --> good for possible fingerprint
               out "random values, no fingerprinting possible "
               fileout "tls_time" "INFO" "Your TLS time seems to be filled with random values to prevent fingerprinting"
          else
               [[ $difftime != "-"* ]] && [[ $difftime != "0" ]] && difftime="+$difftime"
               out "$difftime"; out " sec from localtime";
               fileout "tls_time" "INFO" "Your TLS time is skewed from your localtime by $difftime seconds"
          fi
          debugme out "$TLS_TIME"
          outln
     else
          pr_warningln "SSLv3 through TLS 1.2 didn't return a timestamp"
          fileout "tls_time" "INFO" "No TLS timestamp returned by SSLv3 through TLSv1.2"
     fi
     return 0
}

# core function determining whether handshake succeded or not
sclient_connect_successful() {
     [[ $1 -eq 0 ]] && return 0
     [[ -n $(awk '/Master-Key: / { print $2 }' "$2") ]] && return 0
     # second check saved like
     # fgrep 'Cipher is (NONE)' "$2" &> /dev/null && return 1
     # what's left now is: master key empty and Session-ID not empty ==> probably client based auth with x509 certificate
     return 1
}

# Note that since, at the moment, this function is only called by run_server_defaults()
# and run_heartbleed(), this function does not look for the status request or NPN
# extensions. For run_heartbleed(), only the heartbeat extension needs to be detected.
# For run_server_defaults(), the status request and NPN would already be detected by
# get_server_certificate(), if they are supported. In the case of the status extension,
# since including a status request extension in a ClientHello does not work for GOST
# only servers. In the case of NPN, since a server will not include both the NPN and
# ALPN extensions in the same ServerHello.
determine_tls_extensions() {
     local addcmd
     local -i success=1
     local line params="" tls_extensions=""
     local alpn_proto alpn="" alpn_list_len_hex alpn_extn_len_hex
     local -i alpn_list_len alpn_extn_len
     local cbc_cipher_list="ECDHE-RSA-AES256-SHA384:ECDHE-ECDSA-AES256-SHA384:ECDHE-RSA-AES256-SHA:ECDHE-ECDSA-AES256-SHA:DHE-RSA-AES256-SHA256:DHE-DSS-AES256-SHA256:DH-RSA-AES256-SHA256:DH-DSS-AES256-SHA256:DHE-RSA-AES256-SHA:DHE-DSS-AES256-SHA:DH-RSA-AES256-SHA:DH-DSS-AES256-SHA:ECDHE-RSA-CAMELLIA256-SHA384:ECDHE-ECDSA-CAMELLIA256-SHA384:DHE-RSA-CAMELLIA256-SHA256:DHE-DSS-CAMELLIA256-SHA256:DH-RSA-CAMELLIA256-SHA256:DH-DSS-CAMELLIA256-SHA256:DHE-RSA-CAMELLIA256-SHA:DHE-DSS-CAMELLIA256-SHA:DH-RSA-CAMELLIA256-SHA:DH-DSS-CAMELLIA256-SHA:ECDH-RSA-AES256-SHA384:ECDH-ECDSA-AES256-SHA384:ECDH-RSA-AES256-SHA:ECDH-ECDSA-AES256-SHA:ECDH-RSA-CAMELLIA256-SHA384:ECDH-ECDSA-CAMELLIA256-SHA384:AES256-SHA256:AES256-SHA:CAMELLIA256-SHA256:CAMELLIA256-SHA:ECDHE-RSA-AES128-SHA256:ECDHE-ECDSA-AES128-SHA256:ECDHE-RSA-AES128-SHA:ECDHE-ECDSA-AES128-SHA:DHE-RSA-AES128-SHA256:DHE-DSS-AES128-SHA256:DH-RSA-AES128-SHA256:DH-DSS-AES128-SHA256:DHE-RSA-AES128-SHA:DHE-DSS-AES128-SHA:DH-RSA-AES128-SHA:DH-DSS-AES128-SHA:ECDHE-RSA-CAMELLIA128-SHA256:ECDHE-ECDSA-CAMELLIA128-SHA256:DHE-RSA-CAMELLIA128-SHA256:DHE-DSS-CAMELLIA128-SHA256:DH-RSA-CAMELLIA128-SHA256:DH-DSS-CAMELLIA128-SHA256:DHE-RSA-SEED-SHA:DHE-DSS-SEED-SHA:DH-RSA-SEED-SHA:DH-DSS-SEED-SHA:DHE-RSA-CAMELLIA128-SHA:DHE-DSS-CAMELLIA128-SHA:DH-RSA-CAMELLIA128-SHA:DH-DSS-CAMELLIA128-SHA:ECDH-RSA-AES128-SHA256:ECDH-ECDSA-AES128-SHA256:ECDH-RSA-AES128-SHA:ECDH-ECDSA-AES128-SHA:ECDH-RSA-CAMELLIA128-SHA256:ECDH-ECDSA-CAMELLIA128-SHA256:AES128-SHA256:AES128-SHA:CAMELLIA128-SHA256:SEED-SHA:CAMELLIA128-SHA:IDEA-CBC-SHA:ECDHE-RSA-DES-CBC3-SHA:ECDHE-ECDSA-DES-CBC3-SHA:EDH-RSA-DES-CBC3-SHA:EDH-DSS-DES-CBC3-SHA:DH-RSA-DES-CBC3-SHA:DH-DSS-DES-CBC3-SHA:ECDH-RSA-DES-CBC3-SHA:ECDH-ECDSA-DES-CBC3-SHA:DES-CBC3-SHA:EXP1024-DHE-DSS-DES-CBC-SHA:EDH-RSA-DES-CBC-SHA:EDH-DSS-DES-CBC-SHA:DH-RSA-DES-CBC-SHA:DH-DSS-DES-CBC-SHA:EXP1024-DES-CBC-SHA:DES-CBC-SHA:EXP-EDH-RSA-DES-CBC-SHA:EXP-EDH-DSS-DES-CBC-SHA:EXP-DES-CBC-SHA:EXP-RC2-CBC-MD5:EXP-DH-DSS-DES-CBC-SHA:EXP-DH-RSA-DES-CBC-SHA"
     local cbc_cipher_list_hex="c0,28, c0,24, c0,14, c0,0a, 00,6b, 00,6a, 00,69, 00,68, 00,39, 00,38, 00,37, 00,36, c0,77, c0,73, 00,c4, 00,c3, 00,c2, 00,c1, 00,88, 00,87, 00,86, 00,85, c0,2a, c0,26, c0,0f, c0,05, c0,79, c0,75, 00,3d, 00,35, 00,c0, 00,84, c0,3d, c0,3f, c0,41, c0,43, c0,45, c0,49, c0,4b, c0,4d, c0,4f, c0,27, c0,23, c0,13, c0,09, 00,67, 00,40, 00,3f, 00,3e, 00,33, 00,32, 00,31, 00,30, c0,76, c0,72, 00,be, 00,bd, 00,bc, 00,bb, 00,9a, 00,99, 00,98, 00,97, 00,45, 00,44, 00,43, 00,42, c0,29, c0,25, c0,0e, c0,04, c0,78, c0,74, 00,3c, 00,2f, 00,ba, 00,96, 00,41, 00,07, c0,3c, c0,3e, c0,40, c0,42, c0,44, c0,48, c0,4a, c0,4c, c0,4e, c0,12, c0,08, 00,16, 00,13, 00,10, 00,0d, c0,0d, c0,03, 00,0a, fe,ff, ff,e0, 00,63, 00,15, 00,12, 00,0f, 00,0c, 00,62, 00,09, fe,fe, ff,e1, 00,14, 00,11, 00,08, 00,06, 00,0b, 00,0e"
     local using_sockets=true

     [[ "$OPTIMAL_PROTO" == "-ssl2" ]] && return 0
     "$SSL_NATIVE" && using_sockets=false

     if "$using_sockets"; then
          tls_extensions="00,01,00,01,02, 00,02,00,00, 00,04,00,00, 00,12,00,00, 00,16,00,00, 00,17,00,00"
          if [[ -z $STARTTLS ]]; then
               for alpn_proto in $ALPN_PROTOs; do
                    alpn+=",$(printf "%02x" ${#alpn_proto}),$(string_to_asciihex "$alpn_proto")"
               done
               alpn_list_len=${#alpn}/3
               alpn_list_len_hex=$(printf "%04x" $alpn_list_len)
               alpn_extn_len=$alpn_list_len+2
               alpn_extn_len_hex=$(printf "%04x" $alpn_extn_len)
               tls_extensions+=", 00,10,${alpn_extn_len_hex:0:2},${alpn_extn_len_hex:2:2},${alpn_list_len_hex:0:2},${alpn_list_len_hex:2:2}$alpn"
          fi
          if [[ ! "$TLS_EXTENSIONS" =~ "encrypt-then-mac" ]]; then
               tls_sockets "03" "$cbc_cipher_list_hex, 00,ff" "all" "$tls_extensions"
               success=$?
          fi
          if [[ $success -ne 0 ]] && [[ $success -ne 2 ]]; then
               tls_sockets "03" "$TLS12_CIPHER" "all" "$tls_extensions"
               success=$?
          fi
          [[ $success -eq 2 ]] && success=0
          [[ $success -eq 0 ]] && tls_extensions="$(grep -a 'TLS Extensions: ' "$TEMPDIR/$NODEIP.parse_tls_serverhello.txt" | sed 's/TLS Extensions: //' )"
          if [[ -r "$TEMPDIR/$NODEIP.parse_tls_serverhello.txt" ]]; then
               cp "$TEMPDIR/$NODEIP.parse_tls_serverhello.txt" $TMPFILE
               tmpfile_handle $FUNCNAME.txt
          fi
     else
          if "$HAS_ALPN" && [[ -z $STARTTLS ]]; then
               params="-alpn \"${ALPN_PROTOs// /,}\""  # we need to replace " " by ","
          elif "$HAS_SPDY" && [[ -z $STARTTLS ]]; then
               params="-nextprotoneg \"$NPN_PROTOs\""
          fi
          addcmd=""
          if [[ -z "$OPTIMAL_PROTO" ]] && [[ -z "$SNI" ]] && "$HAS_NO_SSL2"; then
               addcmd="-no_ssl2"
          elif [[ ! "$OPTIMAL_PROTO" =~ ssl ]]; then
               addcmd="$SNI"
          fi
          if [[ ! "$TLS_EXTENSIONS" =~ "encrypt-then-mac" ]]; then
               $OPENSSL s_client $STARTTLS $BUGS -connect $NODEIP:$PORT $PROXY $addcmd $OPTIMAL_PROTO -tlsextdebug $params -cipher $cbc_cipher_list </dev/null 2>$ERRFILE >$TMPFILE
               sclient_connect_successful $? $TMPFILE
               success=$?
          fi
          if [[ $success -ne 0 ]]; then
               $OPENSSL s_client $STARTTLS $BUGS -connect $NODEIP:$PORT $PROXY $addcmd $OPTIMAL_PROTO -tlsextdebug $params </dev/null 2>$ERRFILE >$TMPFILE
               sclient_connect_successful $? $TMPFILE
               success=$?
          fi
          if [[ $success -eq 0 ]]; then
               tls_extensions=$(grep -a 'TLS server extension ' $TMPFILE | \
                    sed -e 's/TLS server extension //g' -e 's/\" (id=/\/#/g' \
                        -e 's/,.*$/,/g' -e 's/),$/\"/g' \
                        -e 's/elliptic curves\/#10/supported_groups\/#10/g')
               tls_extensions=$(echo $tls_extensions)       # into one line
          fi
          tmpfile_handle $FUNCNAME.txt
     fi
     if [[ -n "$tls_extensions" ]]; then
          # check to see if any new TLS extensions were returned and add any new ones to TLS_EXTENSIONS
          while read -d "\"" -r line; do
               if [[ $line != "" ]] && [[ ! "$TLS_EXTENSIONS" =~ "$line" ]]; then
                    TLS_EXTENSIONS+=" \"${line}\""
               fi
          done <<<$tls_extensions
          [[ "${TLS_EXTENSIONS:0:1}" == " " ]] && TLS_EXTENSIONS="${TLS_EXTENSIONS:1}"
     fi
     return $success
}

# arg1 is "-cipher <OpenSSL cipher>" or empty
# arg2 is a list of protocols to try (tls1_2, tls1_1, tls1, ssl3) or empty (if all should be tried)
get_server_certificate() {
     local protocols_to_try proto addcmd
     local success
     local npn_params="" tls_extensions line
     local savedir
     local nrsaved

     "$HAS_SPDY" && [[ -z $STARTTLS ]] && npn_params="-nextprotoneg \"$NPN_PROTOs\""

     if [[ -n "$2" ]]; then
         protocols_to_try="$2"
     else
         protocols_to_try="tls1_2 tls1_1 tls1 ssl3"
     fi

     # throwing 1st every cipher/protocol at the server to know what works
     success=7

     if [[ "$OPTIMAL_PROTO" == "-ssl2" ]]; then
          $OPENSSL s_client $STARTTLS $BUGS $1 -showcerts -connect $NODEIP:$PORT $PROXY -ssl2 </dev/null 2>$ERRFILE >$TMPFILE
          sclient_connect_successful $? $TMPFILE && success=0
          if [[ $success -eq 0 ]]; then
               # Place the server's certificate in $HOSTCERT and any intermediate
               # certificates that were provided in $TEMPDIR/intermediatecerts.pem
               savedir=$(pwd); cd $TEMPDIR
               # http://backreference.org/2010/05/09/ocsp-verification-with-openssl/
               awk -v n=-1 '/Server certificate/ {start=1}
                  /-----BEGIN CERTIFICATE-----/{ if (start) {inc=1; n++} }
                  inc { print > ("level" n ".crt") }
                  /---END CERTIFICATE-----/{ inc=0 }' $TMPFILE
               nrsaved=$(count_words "$(echo level?.crt 2>/dev/null)")
               if [[ $nrsaved -eq 0 ]]; then
                    success=1
               else
                    success=0
                    mv level0.crt $HOSTCERT
                    if [[ $nrsaved -eq 1 ]]; then
                         echo "" > $TEMPDIR/intermediatecerts.pem
                    else
                         cat level?.crt > $TEMPDIR/intermediatecerts.pem
                         rm level?.crt
                    fi
               fi
               cd "$savedir"
          fi
          tmpfile_handle $FUNCNAME.txt
          return $success
     fi

     for proto in $protocols_to_try; do
          addcmd=""
          [[ ! "$proto" =~ ssl ]] && addcmd="$SNI"
          $OPENSSL s_client $STARTTLS $BUGS $1 -showcerts -connect $NODEIP:$PORT $PROXY $addcmd -$proto -tlsextdebug $npn_params -status </dev/null 2>$ERRFILE >$TMPFILE
          sclient_connect_successful $? $TMPFILE && success=0 && break
     done                          # this loop is needed for IIS6 and others which have a handshake size limitations
     if [[ $success -eq 7 ]]; then
          # "-status" above doesn't work for GOST only servers, so we do another test without it and see whether that works then:
          $OPENSSL s_client $STARTTLS $BUGS $1 -showcerts -connect $NODEIP:$PORT $PROXY $addcmd -$proto -tlsextdebug </dev/null 2>>$ERRFILE >$TMPFILE
          if ! sclient_connect_successful $? $TMPFILE; then
               if [ -z "$1" ]; then
                   pr_warningln "Strange, no SSL/TLS protocol seems to be supported (error around line $((LINENO - 6)))"
               fi
               tmpfile_handle $FUNCNAME.txt
               return 7  # this is ugly, I know
          else
               GOST_STATUS_PROBLEM=true
          fi
     fi
     #tls_extensions=$(awk -F'"' '/TLS server extension / { printf "\""$2"\" " }' $TMPFILE)
     #
     # this is not beautiful (grep+sed)
     # but maybe we should just get the ids and do a private matching, according to
     # https://www.iana.org/assignments/tls-extensiontype-values/tls-extensiontype-values.xhtml
     tls_extensions=$(grep -a 'TLS server extension ' $TMPFILE | \
          sed -e 's/TLS server extension //g' -e 's/\" (id=/\/#/g' \
              -e 's/,.*$/,/g' -e 's/),$/\"/g' \
              -e 's/elliptic curves\/#10/supported_groups\/#10/g')
     tls_extensions=$(echo $tls_extensions)       # into one line

     # check to see if any new TLS extensions were returned and add any new ones to TLS_EXTENSIONS
     while read -d "\"" -r line; do
          if [[ $line != "" ]] && [[ ! "$TLS_EXTENSIONS" =~ "$line" ]]; then
#FIXME: This is a string of quoted strings, so this seems to deterime the output format already. Better e.g. would be an array
               TLS_EXTENSIONS+=" \"${line}\""
          fi
     done <<<$tls_extensions
     [[ "${TLS_EXTENSIONS:0:1}" == " " ]] && TLS_EXTENSIONS="${TLS_EXTENSIONS:1}"

     # Place the server's certificate in $HOSTCERT and any intermediate
     # certificates that were provided in $TEMPDIR/intermediatecerts.pem
     savedir=$(pwd); cd $TEMPDIR
     # http://backreference.org/2010/05/09/ocsp-verification-with-openssl/
     awk -v n=-1 '/Certificate chain/ {start=1}
             /-----BEGIN CERTIFICATE-----/{ if (start) {inc=1; n++} }
             inc { print > ("level" n ".crt") }
             /---END CERTIFICATE-----/{ inc=0 }' $TMPFILE
     nrsaved=$(count_words "$(echo level?.crt 2>/dev/null)")
     if [[ $nrsaved -eq 0 ]]; then
         success=1
     else
         success=0
         mv level0.crt $HOSTCERT
         if [[ $nrsaved -eq 1 ]]; then
             echo "" > $TEMPDIR/intermediatecerts.pem
         else
             cat level?.crt > $TEMPDIR/intermediatecerts.pem
             rm level?.crt
         fi
     fi
     cd "$savedir"

     tmpfile_handle $FUNCNAME.txt
     return $success
}

# arg1: path to certificate
# returns CN
get_cn_from_cert() {
     local subject

     # attention! openssl 1.0.2 doesn't properly handle online output from certifcates from trustwave.com/github.com
     #FIXME: use -nameopt oid for robustness

     # for e.g. russian sites -esc_msb,utf8 works in an UTF8 terminal -- any way to check platform indepedent?
     # see x509(1ssl):
     subject="$($OPENSSL x509 -in $1 -noout -subject -nameopt multiline,-align,sname,-esc_msb,utf8,-space_eq 2>>$ERRFILE)"
     echo "$(awk -F'=' '/CN=/ { print $2 }' <<< "$subject")"
     return $?
}

# Return 0 if the name provided in arg1 is a wildcard name
is_wildcard()
{
     local certname="$1"

     # If the first label in the DNS name begins "xn--", then assume it is an
     # A-label and not a wildcard name (RFC 6125, Section 6.4.3).
     [[ "${certname:0:4}" == "xn--" ]] && return 1

     # Remove part of name preceding '*' or '.'. If no "*" appears in the
     # left-most label, then it is not a wildcard name (RFC 6125, Section 6.4.3).
     basename="$(echo -n "$certname" | sed 's/^[a-zA-Z0-9\-]*//')"
     [[ "${basename:0:1}" != "*" ]] && return 1 # not a wildcard name

     # Check that there are no additional wildcard ('*') characters or any
     # other characters that do not belong in a DNS name.
     [[ -n $(echo -n "${basename:1}" | sed 's/^[\.a-zA-Z0-9\-]*//') ]] && return 1
     return 0
}

# Return 0 if the name provided in arg2 is a wildcard name and it matches the name provided in arg1.
wildcard_match()
{
     local servername="$1"
     local certname="$2"
     local basename
     local -i basename_offset len_certname len_part1 len_basename
     local -i len_servername len_wildcard

     len_servername=${#servername}
     len_certname=${#certname}

     # Use rules from RFC 6125 to perform the match.

     # Assume the "*" in the wildcard needs to be replaced by one or more
     # characters, although RFC 6125 is not clear about that.
     [[ $len_servername -lt $len_certname ]] && return 1

     is_wildcard "$certname"
     [[ $? -ne 0 ]] && return 1

     # Comparisons of DNS names are case insenstive, so convert both names to uppercase.
     certname="$(toupper "$certname")"
     servername="$(toupper "$servername")"

     # Extract part of name that comes after the "*"
     basename="$(echo -n "$certname" | sed 's/^[A-Z0-9\-]*\*//')"
     len_basename=${#basename}
     len_part1=$len_certname-$len_basename-1
     len_wildcard=$len_servername-$len_certname+1
     basename_offset=$len_servername-$len_basename

     # Check that initial part of $servername matches initial part of $certname
     # and that final part of $servername matches final part of $certname.
     [[ "${servername:0:len_part1}" != "${certname:0:len_part1}" ]] && return 1
     [[ "${servername:basename_offset:len_basename}" != "$basename" ]] && return 1

     # Check that part of $servername that matches "*" is all part of a single
     # domain label.
     [[ -n $(echo -n "${servername:len_part1:len_wildcard}" | sed 's/^[A-Z0-9\-]*//') ]] && return 1

     return 0
}

# Compare the server name provided in arg1 to the CN and SAN in arg2 and return:
#    0, if server name provided does not match any of the names in the CN or SAN
#    1, if the server name provided matches a name in the SAN
#    2, if the server name provided is a wildcard match against a name in the SAN
#    4, if the server name provided matches the CN
#    5, if the server name provided matches the CN AND a name in the SAN
#    6, if the server name provided matches the CN AND is a wildcard match against a name in the SAN
#    8, if the server name provided is a wildcard match against the CN
#    9, if the server name provided matches a name in the SAN AND is a wildcard match against the CN
#   10, if the server name provided is a wildcard match against the CN AND a name in the SAN

compare_server_name_to_cert()
{
     local servername="$(toupper "$1")"
     local cert="$2"
     local cn dns_sans ip_sans san
     local -i ret=0

     # Check whether any of the DNS names in the certificate match the servername
     dns_sans=$($OPENSSL x509 -in "$cert" -noout -text 2>>$ERRFILE | grep -A2 "Subject Alternative Name" | \
               tr ',' '\n' |  grep "DNS:" | sed -e 's/DNS://g' -e 's/ //g')
     for san in $dns_sans; do
          [[ $(toupper "$san") == "$servername" ]] && ret=1 && break
     done

     if [[ $ret -eq 0 ]]; then
          # Check whether any of the IP addresses in the certificate match the servername
          ip_sans=$($OPENSSL x509 -in "$cert" -noout -text 2>>$ERRFILE | grep -A2 "Subject Alternative Name" | \
                  tr ',' '\n' | grep "IP Address:" | sed -e 's/IP Address://g' -e 's/ //g')
          for san in $ip_sans; do
               [[ "$san" == "$servername" ]] && ret=1 && break
          done
     fi

     # Check whether any of the DNS names in the certificate are wildcard names
     # that match the servername
     if [[ $ret -eq 0 ]]; then
          for san in $dns_sans; do
               wildcard_match "$servername" "$san"
               [[ $? -eq 0 ]] && ret=2 && break
          done
     fi

     cn="$(get_cn_from_cert "$cert")"

     # If the CN contains any characters that are not valid for a DNS name,
     # then assume it does not contain a DNS name.
     [[ -n $(echo -n "$cn" | sed 's/^[\.a-zA-Z0-9*\-]*//') ]] && return $ret

     # Check whether the CN in the certificate matches the servername
     [[ $(toupper "$cn") == "$servername" ]] && ret+=4 && return $ret

     # Check whether the CN in the certificate is a wildcard name that matches
     # the servername
     wildcard_match "$servername" "$cn"
     [[ $? -eq 0 ]] && ret+=8

     return $ret
}

certificate_info() {
     local proto
     local -i certificate_number=$1
     local -i number_of_certificates=$2
     local cipher=$3
     local cert_keysize=$4
     local ocsp_response=$5
     local ocsp_response_status=$6
     local sni_used=$7
     local cert_sig_algo cert_sig_hash_algo cert_key_algo
     local expire days2expire secs2warn ocsp_uri crl startdate enddate issuer_CN issuer_C issuer_O issuer sans san all_san="" cn
     local issuer_DC issuerfinding cn_nosni=""
     local cert_fingerprint_sha1 cert_fingerprint_sha2 cert_fingerprint_serial
     local policy_oid
     local spaces=""
     local trust_sni=0 trust_nosni=0 has_dns_sans
     local -i certificates_provided
     local cnfinding trustfinding trustfinding_nosni
     local cnok="OK"
     local expfinding expok="OK"
     local json_prefix=""     # string to place at beginng of JSON IDs when there is more than one certificate
     local indent=""
     local days2warn2=$DAYS2WARN2
     local days2warn1=$DAYS2WARN1

     if [[ $number_of_certificates -gt 1 ]]; then
          [[ $certificate_number -eq 1 ]] && outln
          indent="  "
          out "$indent"
          pr_headline "Server Certificate #$certificate_number"
          [[ -z "$sni_used" ]] && pr_underline " (in response to request w/o SNI)"
          outln
          json_prefix="Server Certificate #$certificate_number "
          spaces="                                "
     else
          spaces="                              "
     fi

     cert_sig_algo=$($OPENSSL x509 -in $HOSTCERT -noout -text 2>>$ERRFILE | grep "Signature Algorithm" | sed 's/^.*Signature Algorithm: //' | sort -u )
     cert_key_algo=$($OPENSSL x509 -in $HOSTCERT -noout -text 2>>$ERRFILE | awk -F':' '/Public Key Algorithm:/ { print $2 }' | sort -u )

     out "$indent" ; pr_bold " Signature Algorithm          "
     case $cert_sig_algo in
          sha1WithRSAEncryption)
               pr_svrty_medium "SHA1 with RSA"
               if [[ "$SERVICE" == HTTP ]]; then
                    out " -- besides: users will receive a "; pr_svrty_high "strong browser WARNING"
               fi
               outln
               fileout "${json_prefix}algorithm" "MEDIUM" "Signature Algorithm: SHA1 with RSA"
               ;;
          sha224WithRSAEncryption)
               outln "SHA224 with RSA"
               fileout "${json_prefix}algorithm" "INFO" "Signature Algorithm: SHA224 with RSA"
               ;;
          sha256WithRSAEncryption)
               pr_done_goodln "SHA256 with RSA"
               fileout "${json_prefix}algorithm" "OK" "Signature Algorithm: SHA256 with RSA"
               ;;
          sha384WithRSAEncryption)
               pr_done_goodln "SHA384 with RSA"
               fileout "${json_prefix}algorithm" "OK" "Signature Algorithm: SHA384 with RSA"
               ;;
          sha512WithRSAEncryption)
               pr_done_goodln "SHA512 with RSA"
               fileout "${json_prefix}algorithm" "OK" "Signature Algorithm: SHA512 with RSA"
               ;;
          ecdsa-with-SHA1)
               pr_svrty_mediumln "ECDSA with SHA1"
               fileout "${json_prefix}algorithm" "MEDIUM" "Signature Algorithm: ECDSA with SHA1"
               ;;
          ecdsa-with-SHA224)
               outln "ECDSA with SHA224"
               fileout "${json_prefix}algorithm" "INFO" "Signature Algorithm: ECDSA with SHA224"
               ;;
          ecdsa-with-SHA256)
               pr_done_goodln "ECDSA with SHA256"
               fileout "${json_prefix}algorithm" "OK" "Signature Algorithm: ECDSA with SHA256"
               ;;
          ecdsa-with-SHA384)
               pr_done_goodln "ECDSA with SHA384"
               fileout "${json_prefix}algorithm" "OK" "Signature Algorithm: ECDSA with SHA384"
               ;;
          ecdsa-with-SHA512)
               pr_done_goodln "ECDSA with SHA512"
               fileout "${json_prefix}algorithm" "OK" "Signature Algorithm: ECDSA with SHA512"
               ;;
          dsaWithSHA1)
               pr_svrty_mediumln "DSA with SHA1"
               fileout "${json_prefix}algorithm" "MEDIUM" "Signature Algorithm: DSA with SHA1"
               ;;
          dsa_with_SHA224)
               outln "DSA with SHA224"
               fileout "${json_prefix}algorithm" "INFO" "Signature Algorithm: DSA with SHA224"
               ;;
          dsa_with_SHA256)
               pr_done_goodln "DSA with SHA256"
               fileout "${json_prefix}algorithm" "OK" "Signature Algorithm: DSA with SHA256"
               ;;
          rsassaPss)
               cert_sig_hash_algo="$($OPENSSL x509 -in $HOSTCERT -noout -text 2>>$ERRFILE | grep -A 1 "Signature Algorithm" | head -2 | tail -1 | sed 's/^.*Hash Algorithm: //')"
               case $cert_sig_hash_algo in
                    sha1)
                         pr_svrty_mediumln "RSASSA-PSS with SHA1"
                         fileout "${json_prefix}algorithm" "MEDIUM" "Signature Algorithm: RSASSA-PSS with SHA1"
                         ;;
                    sha224)
                         outln "RSASSA-PSS with SHA224"
                         fileout "${json_prefix}algorithm" "INFO" "Signature Algorithm: RSASSA-PSS with SHA224"
                         ;;
                    sha256)
                         pr_done_goodln "RSASSA-PSS with SHA256"
                         fileout "${json_prefix}algorithm" "OK" "Signature Algorithm: RSASSA-PSS with SHA256"
                         ;;
                    sha384)
                         pr_done_goodln "RSASSA-PSS with SHA384"
                         fileout "${json_prefix}algorithm" "OK" "Signature Algorithm: RSASSA-PSS with SHA384"
                         ;;
                    sha512)
                         pr_done_goodln "RSASSA-PSS with SHA512"
                         fileout "${json_prefix}algorithm" "OK" "Signature Algorithm: RSASSA-PSS with SHA512"
                         ;;
                    *)
                         out "RSASSA-PSS with $cert_sig_hash_algo"
                         pr_warningln " (Unknown hash algorithm)"
                         fileout "${json_prefix}algorithm" "DEBUG" "Signature Algorithm: RSASSA-PSS with $cert_sig_hash_algo"
                    esac
                    ;;
          md2*)
               pr_svrty_criticalln "MD2"
               fileout "${json_prefix}algorithm" "CRITICAL" "Signature Algorithm: MD2"
               ;;
          md4*)
               pr_svrty_criticalln "MD4"
               fileout "${json_prefix}algorithm" "CRITICAL" "Signature Algorithm: MD4"
               ;;
          md5*)
               pr_svrty_criticalln "MD5"
               fileout "${json_prefix}algorithm" "CRITICAL" "Signature Algorithm: MD5"
               ;;
          *)
               out "$cert_sig_algo ("
               pr_warning "FIXME: can't tell whether this is good or not"
               outln ")"
               fileout "${json_prefix}algorithm" "DEBUG" "Signature Algorithm: $cert_sig_algo"
               ;;
     esac
     # old, but interesting: https://blog.hboeck.de/archives/754-Playing-with-the-EFF-SSL-Observatory.html

     out "$indent"; pr_bold " Server key size              "
     if [[ -z "$cert_keysize" ]]; then
          outln "(couldn't determine)"
          fileout "${json_prefix}key_size" "WARN" "Server keys size cannot be determined"
     else
          case $cert_key_algo in
               *RSA*|*rsa*)             out "RSA ";;
               *DSA*|*dsa*)             out "DSA ";;
               *ecdsa*|*ecPublicKey)    out "ECDSA ";;
               *GOST*|*gost*)           out "GOST ";;
               *dh*|*DH*)               out "DH " ;;
               *)                       pr_warning "fixme: $cert_key_algo " ;;
          esac
          # https://tools.ietf.org/html/rfc4492,  http://www.keylength.com/en/compare/
          # http://infoscience.epfl.ch/record/164526/files/NPDF-22.pdf
          # see http://csrc.nist.gov/publications/nistpubs/800-57/sp800-57_part1_rev3_general.pdf
          # Table 2 @ chapter 5.6.1 (~ p64)
          if [[ $cert_key_algo =~ ecdsa ]] || [[ $cert_key_algo =~ ecPublicKey  ]]; then
               if [[ "$cert_keysize" -le 110 ]]; then       # a guess
                    pr_svrty_critical "$cert_keysize"
                    fileout "${json_prefix}key_size" "CRITICAL" "Server keys $cert_keysize EC bits"
               elif [[ "$cert_keysize" -le 123 ]]; then    # a guess
                    pr_svrty_high "$cert_keysize"
                    fileout "${json_prefix}key_size" "HIGH" "Server keys $cert_keysize EC bits"
               elif [[ "$cert_keysize" -le 163 ]]; then
                    pr_svrty_medium "$cert_keysize"
                    fileout "${json_prefix}key_size" "MEDIUM" "Server keys $cert_keysize EC bits"
               elif [[ "$cert_keysize" -le 224 ]]; then
                    out "$cert_keysize"
                    fileout "${json_prefix}key_size" "INFO" "Server keys $cert_keysize EC bits"
               elif [[ "$cert_keysize" -le 533 ]]; then
                    pr_done_good "$cert_keysize"
                    fileout "${json_prefix}key_size" "OK" "Server keys $cert_keysize EC bits"
               else
                    out "keysize: $cert_keysize (not expected, FIXME)"
                    fileout "${json_prefix}key_size" "DEBUG" "Server keys $cert_keysize bits (not expected)"
               fi
               outln " bits"
          elif [[ $cert_key_algo = *RSA* ]] || [[ $cert_key_algo = *rsa* ]] || [[ $cert_key_algo = *dsa* ]] || \
               [[ $cert_key_algo =~ dhKeyAgreement ]] || [[ $cert_key_algo =~ "X9.42 DH" ]]; then
               if [[ "$cert_keysize" -le 512 ]]; then
                    pr_svrty_critical "$cert_keysize"
                    outln " bits"
                    fileout "${json_prefix}key_size" "CRITICAL" "Server keys $cert_keysize bits"
               elif [[ "$cert_keysize" -le 768 ]]; then
                    pr_svrty_high "$cert_keysize"
                    outln " bits"
                    fileout "${json_prefix}key_size" "HIGH" "Server keys $cert_keysize bits"
               elif [[ "$cert_keysize" -le 1024 ]]; then
                    pr_svrty_medium "$cert_keysize"
                    outln " bits"
                    fileout "${json_prefix}key_size" "MEDIUM" "Server keys $cert_keysize bits"
               elif [[ "$cert_keysize" -le 2048 ]]; then
                    outln "$cert_keysize bits"
                    fileout "${json_prefix}key_size" "INFO" "Server keys $cert_keysize bits"
               elif [[ "$cert_keysize" -le 4096 ]]; then
                    pr_done_good "$cert_keysize"
                    fileout "${json_prefix}key_size" "OK" "Server keys $cert_keysize bits"
                    outln " bits"
               else
                    pr_magenta "weird key size: $cert_keysize bits"; outln " (could cause compatibility problems)"
                    fileout "${json_prefix}key_size" "WARN" "Server keys $cert_keysize bits (Odd)"
               fi
          else
               out "$cert_keysize bits ("
               pr_warning "FIXME: can't tell whether this is good or not"
               outln ")"
               fileout "${json_prefix}key_size" "WARN" "Server keys $cert_keysize bits (unknown signature algorithm)"
          fi
     fi

     out "$indent"; pr_bold " Fingerprint / Serial         "
     cert_fingerprint_sha1="$($OPENSSL x509 -noout -in $HOSTCERT -fingerprint -sha1 2>>$ERRFILE | sed 's/Fingerprint=//' | sed 's/://g')"
     cert_fingerprint_serial="$($OPENSSL x509 -noout -in $HOSTCERT -serial 2>>$ERRFILE | sed 's/serial=//')"
     cert_fingerprint_sha2="$($OPENSSL x509 -noout -in $HOSTCERT -fingerprint -sha256 2>>$ERRFILE | sed 's/Fingerprint=//' | sed 's/://g' )"
     outln "$cert_fingerprint_sha1 / $cert_fingerprint_serial"
     outln "$spaces$cert_fingerprint_sha2"
     fileout "${json_prefix}fingerprint" "INFO" "Fingerprints / Serial: $cert_fingerprint_sha1 / $cert_fingerprint_serial, $cert_fingerprint_sha2"
     [[ -z $CERT_FINGERPRINT_SHA2 ]] && \
          CERT_FINGERPRINT_SHA2="$cert_fingerprint_sha2" ||
          CERT_FINGERPRINT_SHA2="$cert_fingerprint_sha2 $CERT_FINGERPRINT_SHA2"
     [[ -z $RSA_CERT_FINGERPRINT_SHA2 ]] && \
          ( [[ $cert_key_algo = *RSA* ]] || [[ $cert_key_algo = *rsa* ]] ) &&
          RSA_CERT_FINGERPRINT_SHA2="$cert_fingerprint_sha2"

     out "$indent"; pr_bold " Common Name (CN)             "
     cnfinding="Common Name (CN) : "
     cn="$(get_cn_from_cert $HOSTCERT)"
     if [[ -n "$cn" ]]; then
          pr_italic "$cn"
          cnfinding="$cn"
     else
          cn="no CN field in subject"
          out "($cn)"
          cnfinding="$cn"
          cnok="INFO"
     fi

     if [[ -n "$sni_used" ]]; then
          # no cipher suites specified here. We just want the default vhost subject
          $OPENSSL s_client $STARTTLS $BUGS -connect $NODEIP:$PORT $PROXY $OPTIMAL_PROTO 2>>$ERRFILE </dev/null | awk '/-----BEGIN/,/-----END/ { print $0 }'  >$HOSTCERT.nosni
          if grep -q "\-\-\-\-\-BEGIN" "$HOSTCERT.nosni"; then
               cn_nosni="$(get_cn_from_cert "$HOSTCERT.nosni")"
               [[ -z "$cn_nosni" ]] && cn_nosni="no CN field in subject"
          fi
          debugme out "\"$NODE\" | \"$cn\" | \"$cn_nosni\""
     else
          debugme out "\"$NODE\" | \"$cn\""
     fi

#FIXME: check for SSLv3/v2 and look whether it goes to a different CN (probably not polite)

     if [[ -z "$sni_used" ]] || [[ "$(toupper "$cn_nosni")" == "$(toupper "$cn")" ]]; then
          outln
     elif [[ -z "$cn_nosni" ]]; then
          out " (request w/o SNI didn't succeed";
          cnfinding+=" (request w/o SNI didn't succeed"
          if [[ $cert_sig_algo =~ ecdsa ]]; then
               out ", usual for EC certificates"
               cnfinding+=", usual for EC certificates"
          fi
          outln ")"
          cnfinding+=")"
     elif [[ "$cn_nosni" == *"no CN field"* ]]; then
          outln ", (request w/o SNI: $cn_nosni)"
          cnfinding+=", (request w/o SNI: $cn_nosni)"
     else
          out " (CN in response to request w/o SNI: "; pr_italic "$cn_nosni"; outln ")"
          cnfinding+=" (CN in response to request w/o SNI: \"$cn_nosni\")"
     fi
     fileout "${json_prefix}cn" "$cnok" "$cnfinding"

     sans=$($OPENSSL x509 -in $HOSTCERT -noout -text 2>>$ERRFILE | grep -A2 "Subject Alternative Name" | \
          egrep "DNS:|IP Address:|email:|URI:|DirName:|Registered ID:" | tr ',' '\n' | \
          sed -e 's/ *DNS://g' -e 's/ *IP Address://g' -e 's/ *email://g' -e 's/ *URI://g' -e 's/ *DirName://g' \
              -e 's/ *Registered ID://g' \
              -e 's/ *othername:<unsupported>//g' -e 's/ *X400Name:<unsupported>//g' -e 's/ *EdiPartyName:<unsupported>//g')
#                   ^^^ CACert
     out "$indent"; pr_bold " subjectAltName (SAN)         "
     if [[ -n "$sans" ]]; then
          while read san; do
               [[ -n "$san" ]] && all_san+="$san "
          done <<< "$sans"
          out_row_aligned_max_width "$all_san" "$indent                              " $TERM_WIDTH pr_italic
          fileout "${json_prefix}san" "INFO" "subjectAltName (SAN) : $all_san"
     else
          out "-- "
          fileout "${json_prefix}san" "INFO" "subjectAltName (SAN) : --"
     fi
     outln
     out "$indent"; pr_bold " Issuer                       "
     #FIXME: oid would be better maybe (see above)
     issuer="$($OPENSSL x509 -in  $HOSTCERT -noout -issuer -nameopt multiline,-align,sname,-esc_msb,utf8,-space_eq 2>>$ERRFILE)"
     issuer_CN="$(awk -F'=' '/CN=/ { print $2 }' <<< "$issuer")"
     issuer_O="$(awk -F'=' '/O=/ { print $2 }' <<< "$issuer")"
     issuer_C="$(awk -F'=' '/ C=/ { print $2 }' <<< "$issuer")"
     issuer_DC="$(awk -F'=' '/DC=/ { print $2 }' <<< "$issuer")"

     if [[ "$issuer_O" == "issuer=" ]] || [[ "$issuer_O" == "issuer= " ]] || [[ "$issuer_CN" == "$cn" ]]; then
          pr_svrty_criticalln "self-signed (NOT ok)"
          fileout "${json_prefix}issuer" "CRITICAL" "Issuer: selfsigned"
     else
          issuerfinding="$(pr_italic "$issuer_CN")"
          if [[ -z "$issuer_O" ]] && [[ -n "$issuer_DC" ]]; then
               for san in $issuer_DC; do
                    if [[ -z "$issuer_O" ]]; then
                         issuer_O="${san}"
                    else
                         issuer_O="${san}.${issuer_O}"
                    fi
               done
          fi
          if [[ -n "$issuer_O" ]]; then
               issuerfinding+=" ("
               issuerfinding+="$(pr_italic "$issuer_O")"
               if [[ -n "$issuer_C" ]]; then
                    issuerfinding+=" from "
                    issuerfinding+="$(pr_italic "$issuer_C")"
               fi
               issuerfinding+=")"
          fi
          outln "$issuerfinding"
          fileout "${json_prefix}issuer" "INFO" "Issuer: $issuerfinding"
     fi

     out "$indent"; pr_bold " Trust (hostname)             "
     compare_server_name_to_cert "$NODE" "$HOSTCERT"
     trust_sni=$?

     # Find out if the subjectAltName extension is present and contains
     # a DNS name, since Section 6.3 of RFC 6125 says:
     #      Security Warning: A client MUST NOT seek a match for a reference
     #      identifier of CN-ID if the presented identifiers include a DNS-ID,
     #      SRV-ID, URI-ID, or any application-specific identifier types
     #      supported by the client.
     $OPENSSL x509 -in $HOSTCERT -noout -text 2>>$ERRFILE | \
          grep -A2 "Subject Alternative Name" | grep -q "DNS:" && \
          has_dns_sans=true || has_dns_sans=false

     case $trust_sni in
          0) trustfinding="certificate does not match supplied URI" ;;
          1) trustfinding="Ok via SAN" ;;
          2) trustfinding="Ok via SAN wildcard" ;;
          4) if $has_dns_sans; then
                  trustfinding="Ok via CN, but not SAN"
             else
                  trustfinding="Ok via CN"
             fi
             ;;
          5) trustfinding="Ok via SAN and CN" ;;
          6) trustfinding="Ok via SAN wildcard and CN"
             ;;
          8) if $has_dns_sans; then
                  trustfinding="Ok via CN wildcard, but not SAN"
             else
                  trustfinding="Ok via CN wildcard"
             fi
             ;;
          9) trustfinding="Ok via CN wildcard and SAN"
             ;;
         10) trustfinding="Ok via SAN wildcard and CN wildcard"
             ;;
     esac

     if [[ $trust_sni -eq 0 ]]; then
          pr_svrty_medium "$trustfinding"
          trust_sni="fail"
     elif "$has_dns_sans" && ( [[ $trust_sni -eq 4 ]] || [[ $trust_sni -eq 8 ]] ); then
          pr_svrty_medium "$trustfinding"
          trust_sni="warn"
     else
          pr_done_good "$trustfinding"
          trust_sni="ok"
     fi

     if [[ -n "$cn_nosni" ]]; then
          compare_server_name_to_cert "$NODE" "$HOSTCERT.nosni"
          trust_nosni=$?
          $OPENSSL x509 -in "$HOSTCERT.nosni" -noout -text 2>>$ERRFILE | \
               grep -A2 "Subject Alternative Name" | grep -q "DNS:" && \
               has_dns_sans=true || has_dns_sans=false
     fi

     if [[ -z "$sni_used" ]]; then
          trustfinding_nosni=""
     elif "$has_dns_sans" && [[ $trust_nosni -eq 4 ]]; then
          trustfinding_nosni=" (w/o SNI: Ok via CN, but not SAN)"
     elif "$has_dns_sans" && [[ $trust_nosni -eq 8 ]]; then
          trustfinding_nosni=" (w/o SNI: Ok via CN wildcard, but not SAN)"
     elif [[ $trust_nosni -eq 0 ]] && ( [[ "$trust_sni" == "ok" ]] || [[ "$trust_sni" == "warn" ]] ); then
          trustfinding_nosni=" (SNI mandatory)"
     elif [[ "$trust_sni" == "ok" ]] || [[ "$trust_sni" == "warn" ]]; then
          trustfinding_nosni=" (works w/o SNI)"
     elif [[ $trust_nosni -ne 0 ]]; then
          trustfinding_nosni=" (however, works w/o SNI)"
     else
          trustfinding_nosni=""
     fi
     if "$has_dns_sans" && ( [[ $trust_nosni -eq 4 ]] || [[ $trust_nosni -eq 8 ]] ); then
          pr_svrty_mediumln "$trustfinding_nosni"
     else
          outln "$trustfinding_nosni"
     fi

     if [[ "$trust_sni" == "ok" ]]; then
          fileout "${json_prefix}trust" "INFO" "${trustfinding}${trustfinding_nosni}"
     else
          fileout "${json_prefix}trust" "WARN" "${trustfinding}${trustfinding_nosni}"
     fi

     out "$indent"; pr_bold " Chain of trust"; out "               "
     determine_trust "$json_prefix" # Also handles fileout

     # http://events.ccc.de/congress/2010/Fahrplan/attachments/1777_is-the-SSLiverse-a-safe-place.pdf, see page 40pp
     out "$indent"; pr_bold " EV cert"; out " (experimental)       "
     # only the first one, seldom we have two
     policy_oid=$($OPENSSL x509 -in $HOSTCERT -text 2>>$ERRFILE | awk '/ .Policy: / { print $2 }' | awk 'NR < 2')
     if echo "$issuer" | egrep -q 'Extended Validation|Extended Validated|EV SSL|EV CA' || \
          [[ 2.16.840.1.114028.10.1.2 == "$policy_oid" ]] || \
          [[ 2.16.840.1.114412.1.3.0.2 == "$policy_oid" ]] || \
          [[ 2.16.840.1.114412.2.1 == "$policy_oid" ]] || \
          [[ 2.16.578.1.26.1.3.3 == "$policy_oid" ]] || \
          [[ 1.3.6.1.4.1.17326.10.14.2.1.2 == "$policy_oid" ]] || \
          [[ 1.3.6.1.4.1.17326.10.8.12.1.2 == "$policy_oid" ]] || \
          [[ 1.3.6.1.4.1.13177.10.1.3.10 == "$policy_oid" ]] ; then
          out "yes "
          fileout "${json_prefix}ev" "OK" "Extended Validation (EV) (experimental) : yes"
     else
          out "no "
          fileout "${json_prefix}ev" "INFO" "Extended Validation (EV) (experimental) : no"
     fi
     debugme echo "($(newline_to_spaces "$policy_oid"))"
     outln
#TODO: use browser OIDs:
#         https://mxr.mozilla.org/mozilla-central/source/security/certverifier/ExtendedValidation.cpp
#         http://src.chromium.org/chrome/trunk/src/net/cert/ev_root_ca_metadata.cc
#         https://certs.opera.com/03/ev-oids.xml

     out "$indent"; pr_bold " Certificate Expiration       "

     enddate=$(parse_date "$($OPENSSL x509 -in $HOSTCERT -noout -enddate 2>>$ERRFILE | cut -d= -f 2)" +"%F %H:%M %z" "%b %d %T %Y %Z")
     startdate=$(parse_date "$($OPENSSL x509 -in $HOSTCERT -noout -startdate 2>>$ERRFILE | cut -d= -f 2)" +"%F %H:%M" "%b %d %T %Y %Z")
     days2expire=$(( $(parse_date "$enddate" "+%s" "%F %H:%M %z") - $(LC_ALL=C date "+%s") ))    # in seconds
     days2expire=$((days2expire  / 3600 / 24 ))

     if grep -q "^Let's Encrypt Authority" <<< "$issuer_CN"; then          # we take the half of the thresholds for LE certificates
          days2warn2=$((days2warn2 / 2))
          days2warn1=$((days2warn1 / 2))
     fi

     expire=$($OPENSSL x509 -in $HOSTCERT -checkend 1 2>>$ERRFILE)
     if ! echo $expire | grep -qw not; then
          pr_svrty_critical "expired!"
          expfinding="expired!"
          expok="CRITICAL"
     else
          secs2warn=$((24 * 60 * 60 * days2warn2))  # low threshold first
          expire=$($OPENSSL x509 -in $HOSTCERT -checkend $secs2warn 2>>$ERRFILE)
          if echo "$expire" | grep -qw not; then
               secs2warn=$((24 * 60 * 60 * days2warn1))
               expire=$($OPENSSL x509 -in $HOSTCERT -checkend $secs2warn 2>>$ERRFILE)
               if echo "$expire" | grep -qw not; then
                    pr_done_good "$days2expire >= $days2warn1 days"
                    expfinding+="$days2expire >= $days2warn1 days"
               else
                    pr_svrty_medium "expires < $days2warn1 days ($days2expire)"
                    expfinding+="expires < $days2warn1 days ($days2expire)"
                    expok="MEDIUM"
               fi
          else
               pr_svrty_high "expires < $days2warn2 days ($days2expire) !"
               expfinding+="expires < $days2warn2 days ($days2expire) !"
               expok="HIGH"
          fi
     fi
     outln " ($startdate --> $enddate)"
     fileout "${json_prefix}expiration" "$expok" "Certificate Expiration : $expfinding ($startdate --> $enddate)"

     certificates_provided=1+$(grep -c "\-\-\-\-\-BEGIN CERTIFICATE\-\-\-\-\-" $TEMPDIR/intermediatecerts.pem)
     out "$indent"; pr_bold " # of certificates provided"; outln "   $certificates_provided"
     fileout "${json_prefix}certcount" "INFO" "# of certificates provided :  $certificates_provided"

     # Get both CRL and OCSP URL upfront. If there's none, this is not good. And we need to penalize this in the output
     crl="$($OPENSSL x509 -in $HOSTCERT -noout -text 2>>$ERRFILE | \
           awk '/X509v3 CRL Distribution/{i=50} i&&i--' | awk '/^$/,/^            [a-zA-Z0-9]+|^    Signature Algorithm:/' | awk -F'URI:' '/URI/ { print $2 }')"
     ocsp_uri=$($OPENSSL x509 -in $HOSTCERT -noout -ocsp_uri 2>>$ERRFILE)

     out "$indent"; pr_bold " Certificate Revocation List  "
     if [[ -z "$crl" ]] ; then
          if [[ -n "$ocsp_uri" ]]; then
               outln "--"
               fileout "${json_prefix}crl" "INFO" "No CRL provided"
          else
               pr_svrty_highln "-- (NOT ok)"
               fileout "${json_prefix}crl" "HIGH" "Neither CRL nor OCSP URL provided"
          fi
     elif grep -q http <<< "$crl"; then
          if [[ $(count_lines "$crl") -eq 1 ]]; then
               outln "$crl"
               fileout "${json_prefix}crl" "INFO" "Certificate Revocation List : $crl"
          else # more than one CRL
               out_row_aligned "$crl" "$spaces"
               fileout "${json_prefix}crl" "INFO" "Certificate Revocation List : $crl"
          fi
     else
          pr_warningln "no parsable output \"$crl\", pls report"
          fileout "${json_prefix}crl" "WARN" "Certificate Revocation List : no parsable output \"$crl\", pls report"
     fi

     out "$indent"; pr_bold " OCSP URI                     "
     if [[ -z "$ocsp_uri" ]]; then
          outln "--"
          fileout "${json_prefix}ocsp_uri" "INFO" "OCSP URI : --"
     else
          if [[ $(count_lines "$ocsp_uri") -eq 1 ]]; then
               outln "$ocsp_uri"
          else
               out_row_aligned "$ocsp_uri" "$spaces"
          fi
          fileout "${json_prefix}ocsp_uri" "INFO" "OCSP URI : $ocsp_uri"
     fi

     out "$indent"; pr_bold " OCSP stapling                "
     if grep -a "OCSP response" <<<"$ocsp_response" | grep -q "no response sent" ; then
          pr_svrty_low "--"
          fileout "${json_prefix}ocsp_stapling" "LOW" "OCSP stapling : not offered"
     else
          if grep -a "OCSP Response Status" <<<"$ocsp_response_status" | grep -q successful; then
               pr_done_good "offered"
               fileout "${json_prefix}ocsp_stapling" "OK" "OCSP stapling : offered"
          else
               if $GOST_STATUS_PROBLEM; then
                    outln "(GOST servers make problems here, sorry)"
                    fileout "${json_prefix}ocsp_stapling" "OK" "OCSP stapling : (GOST servers make problems here, sorry)"
                    ret=0
               else
                    out "(response status unknown)"
                    fileout "${json_prefix}ocsp_stapling" "OK" "OCSP stapling : not sure what's going on here, debug: $ocsp_response"
                    debugme grep -a -A20 -B2 "OCSP response"  <<<"$ocsp_response"
                    ret=2
               fi
          fi
     fi
     outln

     out "$indent"; pr_bold " DNS CAA RR"; out " (experimental)    "
     caa="$(get_caa_rr_record $NODE)"
     if [[ -n "$caa" ]]; then
          pr_done_good "OK"; out " (" ; pr_italic "$caa"; out ")"
          fileout "${json_prefix}CAA_record" "OK" "DNS Certification Authority Authorization (CAA) Resource Record / RFC6844 : \"$caa\" "
     else
          pr_svrty_low "--"
          fileout "${json_prefix}CAA_record" "LOW" "DNS Certification Authority Authorization (CAA) Resource Record / RFC6844 : not offered"
     fi

     outln "\n"
     return $ret
}
# FIXME: revoked, see checkcert.sh
# FIXME: Trust (only CN)




run_server_defaults() {
     local ciph match_found newhostcert sni
     local sessticket_str=""
     local lifetime unit
     local line
     local -i i n
     local -i certs_found=0
     local -a previous_hostcert previous_intermediates keysize cipher
     local -a ocsp_response ocsp_response_status sni_used
     local -a ciphers_to_test success
     local cn_nosni cn_sni sans_nosni sans_sni san
     local alpn_proto alpn="" alpn_list_len_hex alpn_extn_len_hex success
     local -i alpn_list_len alpn_extn_len

     # Try each public key type once:
     # ciphers_to_test[1]: cipher suites using certificates with RSA signature public keys
     # ciphers_to_test[2]: cipher suites using certificates with RSA key encipherment public keys
     # ciphers_to_test[3]: cipher suites using certificates with DSA signature public keys
     # ciphers_to_test[4]: cipher suites using certificates with DH key agreement public keys
     # ciphers_to_test[5]: cipher suites using certificates with ECDH key agreement public keys
     # ciphers_to_test[6]: cipher suites using certificates with ECDSA signature public keys
     # ciphers_to_test[7]: cipher suites using certificates with GOST R 34.10 (either 2001 or 94) public keys
     ciphers_to_test[1]=""
     ciphers_to_test[2]=""
     for ciph in $(colon_to_spaces $($OPENSSL ciphers "aRSA")); do
         if grep -q "\-RSA\-" <<<$ciph; then
             ciphers_to_test[1]="${ciphers_to_test[1]}:$ciph"
         else
             ciphers_to_test[2]="${ciphers_to_test[2]}:$ciph"
         fi
     done
     [[ -n "${ciphers_to_test[1]}" ]] && ciphers_to_test[1]="${ciphers_to_test[1]:1}"
     [[ -n "${ciphers_to_test[2]}" ]] && ciphers_to_test[2]="${ciphers_to_test[2]:1}"
     ciphers_to_test[3]="aDSS"
     ciphers_to_test[4]="aDH"
     ciphers_to_test[5]="aECDH"
     ciphers_to_test[6]="aECDSA"
     ciphers_to_test[7]="aGOST"

     for (( n=1; n <= 14 ; n++ )); do
         # Some servers use a different certificate if the ClientHello
         # specifies TLSv1.1 and doesn't include a server name extension.
         # So, for each public key type for which a certificate was found,
         # try again, but only with TLSv1.1 and without SNI.
         if [[ $n -ge 8 ]]; then
              ciphers_to_test[n]=""
              [[ ${success[n-7]} -eq 0 ]] && ciphers_to_test[n]="${ciphers_to_test[n-7]}"
         fi

         if [[ -n "${ciphers_to_test[n]}" ]] && [[ $(count_ciphers $($OPENSSL ciphers "${ciphers_to_test[n]}" 2>>$ERRFILE)) -ge 1 ]]; then
             if [[ $n -ge 8 ]]; then
                  sni="$SNI"
                  SNI=""
                  get_server_certificate "-cipher ${ciphers_to_test[n]}" "tls1_1"
                  success[n]=$?
                  SNI="$sni"
             else
                  get_server_certificate "-cipher ${ciphers_to_test[n]}"
                  success[n]=$?
             fi
             if [[ ${success[n]} -eq 0 ]]; then
                 cp "$TEMPDIR/$NODEIP.get_server_certificate.txt" $TMPFILE
                 >$ERRFILE
                 if [[ -z "$sessticket_str" ]]; then
                     sessticket_str=$(grep -aw "session ticket" $TMPFILE | grep -a lifetime)
                 fi

                 # check whether the host's certificate has been seen before
                 match_found=false
                 i=1
                 newhostcert=$(cat $HOSTCERT)
                 while [[ $i -le $certs_found ]]; do
                     if [ "$newhostcert" == "${previous_hostcert[i]}" ]; then
                        match_found=true
                        break;
                     fi
                     i=$((i + 1))
                 done
                 if ! "$match_found" && [[ $n -ge 8 ]] && [[ $certs_found -ne 0 ]]; then
                     # A new certificate was found using TLSv1.1 without SNI.
                     # Check to see if the new certificate should be displayed.
                     # It should be displayed if it is either a match for the
                     # $NODE being tested or if it has the same subject
                     # (CN and SAN) as other certificates for this host.
                     compare_server_name_to_cert "$NODE" "$HOSTCERT"
                     [[ $? -ne 0 ]] && success[n]=0 || success[n]=1

                     if [[ ${success[n]} -ne 0 ]]; then
                         cn_nosni="$(toupper "$(get_cn_from_cert $HOSTCERT)")"
                         sans_nosni="$(toupper "$($OPENSSL x509 -in $HOSTCERT -noout -text 2>>$ERRFILE | grep -A2 "Subject Alternative Name" | \
                              tr ',' '\n' |  grep "DNS:" | sed -e 's/DNS://g' -e 's/ //g' | tr '\n' ' ')")"

                         echo "${previous_hostcert[1]}" > $HOSTCERT
                         cn_sni="$(toupper "$(get_cn_from_cert $HOSTCERT)")"

                         # FIXME: Not sure what the matching rule should be. At
                         # the moment, the no SNI certificate is considered a
                         # match if the CNs are the same and the SANs (if
                         # present) contain at least one DNS name in common.
                         if [[ "$cn_nosni" == "$cn_sni" ]]; then
                              sans_sni="$(toupper "$($OPENSSL x509 -in $HOSTCERT -noout -text 2>>$ERRFILE | grep -A2 "Subject Alternative Name" | \
                                       tr ',' '\n' |  grep "DNS:" | sed -e 's/DNS://g' -e 's/ //g' | tr '\n' ' ')")"
                              if [[ "$sans_nosni" == "$sans_sni" ]]; then
                                   success[n]=0
                              else
                                   for san in $sans_nosni; do
                                        [[ " $sans_sni " =~ " $san " ]] && success[n]=0 && break
                                   done
                              fi
                         fi
                     fi
                     # If the certificate found for TLSv1.1 w/o SNI appears to
                     # be for a different host, then set match_found to true so
                     # that the new certificate will not be included in the output.
                     [[ ${success[n]} -ne 0 ]] && match_found=true
                 fi
                 if ! "$match_found"; then
                     certs_found=$(($certs_found + 1))
                     cipher[certs_found]=${ciphers_to_test[n]}
                     keysize[certs_found]=$(grep -aw "^Server public key is" $TMPFILE | sed -e 's/^Server public key is //' -e 's/bit//' -e 's/ //')
                     ocsp_response[certs_found]=$(grep -aA 20 "OCSP response" $TMPFILE)
                     ocsp_response_status[certs_found]=$(grep -a "OCSP Response Status" $TMPFILE)
                     previous_hostcert[certs_found]=$newhostcert
                     previous_intermediates[certs_found]=$(cat $TEMPDIR/intermediatecerts.pem)
                     [[ $n -ge 8 ]] && sni_used[certs_found]="" || sni_used[certs_found]="$SNI"
                 fi
             fi
         fi
     done

     determine_tls_extensions
     if [[ $? -eq 0 ]] && [[ "$OPTIMAL_PROTO" != "-ssl2" ]]; then
          cp "$TEMPDIR/$NODEIP.determine_tls_extensions.txt" $TMPFILE
          >$ERRFILE

          [[ -z "$sessticket_str" ]] && sessticket_str=$(grep -aw "session ticket" $TMPFILE | grep -a lifetime)
     fi

     outln
     pr_headlineln " Testing server defaults (Server Hello) "
     outln

     pr_bold " TLS extensions (standard)    "
     if [[ -z "$TLS_EXTENSIONS" ]]; then
          outln "(none)"
          fileout "tls_extensions" "INFO" "TLS server extensions (std): (none)"
     else
#FIXME: we rather want to have the chance to print each ext in italcs or another format. Atm is a string of quoted strings -- that needs to be fixed at the root
          out_row_aligned_max_width "$TLS_EXTENSIONS" "                              " $TERM_WIDTH out; outln
          fileout "tls_extensions" "INFO" "TLS server extensions (std): $TLS_EXTENSIONS"
     fi

     pr_bold " Session Tickets RFC 5077     "
     if [[ -z "$sessticket_str" ]]; then
          outln "(none)"
          fileout "session_ticket" "INFO" "TLS session tickes RFC 5077 not supported"
     else
          lifetime=$(echo $sessticket_str | grep -a lifetime | sed 's/[A-Za-z:() ]//g')
          unit=$(echo $sessticket_str | grep -a lifetime | sed -e 's/^.*'"$lifetime"'//' -e 's/[ ()]//g')
          out "$lifetime $unit "
          pr_svrty_lowln "(PFS requires session ticket keys to be rotated <= daily)"
          fileout "session_ticket" "LOW" "TLS session tickes RFC 5077 valid for $lifetime $unit (PFS requires session ticket keys to be rotated at least daily)"
     fi

     pr_bold " SSL Session ID support       "
     if "$NO_SSL_SESSIONID"; then
          outln "no"
          fileout "session_id" "INFO" "SSL session ID support: no"
     else
          outln "yes"
          fileout "session_id" "INFO" "SSL session ID support: yes"
     fi

     tls_time

     i=1
     while [[ $i -le $certs_found ]]; do
         echo "${previous_hostcert[i]}" > $HOSTCERT
         echo "${previous_intermediates[i]}" > $TEMPDIR/intermediatecerts.pem
         certificate_info "$i" "$certs_found" "${cipher[i]}" "${keysize[i]}" "${ocsp_response[i]}" "${ocsp_response_status[i]}" "${sni_used[i]}"
         i=$((i + 1))
     done
}

run_pfs() {
     local -i sclient_success
     local pfs_offered=false ecdhe_offered=false ffdhe_offered=false
     local hexc dash pfs_cipher sslvers auth mac export curve dhlen
     local -a hexcode normalized_hexcode ciph rfc_ciph kx enc ciphers_found sigalg ossl_supported
     # generated from 'kEECDH:kEDH:!aNULL:!eNULL:!DES:!3DES:!RC4' with openssl 1.0.2i and openssl 1.1.0
     local pfs_cipher_list="DHE-DSS-AES128-GCM-SHA256:DHE-DSS-AES128-SHA256:DHE-DSS-AES128-SHA:DHE-DSS-AES256-GCM-SHA384:DHE-DSS-AES256-SHA256:DHE-DSS-AES256-SHA:DHE-DSS-CAMELLIA128-SHA256:DHE-DSS-CAMELLIA128-SHA:DHE-DSS-CAMELLIA256-SHA256:DHE-DSS-CAMELLIA256-SHA:DHE-DSS-SEED-SHA:DHE-RSA-AES128-CCM8:DHE-RSA-AES128-CCM:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES128-SHA256:DHE-RSA-AES128-SHA:DHE-RSA-AES256-CCM8:DHE-RSA-AES256-CCM:DHE-RSA-AES256-GCM-SHA384:DHE-RSA-AES256-SHA256:DHE-RSA-AES256-SHA:DHE-RSA-CAMELLIA128-SHA256:DHE-RSA-CAMELLIA128-SHA:DHE-RSA-CAMELLIA256-SHA256:DHE-RSA-CAMELLIA256-SHA:DHE-RSA-CHACHA20-POLY1305-OLD:DHE-RSA-CHACHA20-POLY1305:DHE-RSA-SEED-SHA:ECDHE-ECDSA-AES128-CCM8:ECDHE-ECDSA-AES128-CCM:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES128-SHA256:ECDHE-ECDSA-AES128-SHA:ECDHE-ECDSA-AES256-CCM8:ECDHE-ECDSA-AES256-CCM:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES256-SHA384:ECDHE-ECDSA-AES256-SHA:ECDHE-ECDSA-CAMELLIA128-SHA256:ECDHE-ECDSA-CAMELLIA256-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305-OLD:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-SHA256:ECDHE-RSA-AES128-SHA:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-SHA384:ECDHE-RSA-AES256-SHA:ECDHE-RSA-CAMELLIA128-SHA256:ECDHE-RSA-CAMELLIA256-SHA384:ECDHE-RSA-CHACHA20-POLY1305-OLD:ECDHE-RSA-CHACHA20-POLY1305"
     local pfs_hex_cipher_list="" ciphers_to_test
     local ecdhe_cipher_list="" ecdhe_cipher_list_hex="" ffdhe_cipher_list_hex=""
     local curves_hex=("00,01" "00,02" "00,03" "00,04" "00,05" "00,06" "00,07" "00,08" "00,09" "00,0a" "00,0b" "00,0c" "00,0d" "00,0e" "00,0f" "00,10" "00,11" "00,12" "00,13" "00,14" "00,15" "00,16" "00,17" "00,18" "00,19" "00,1a" "00,1b" "00,1c" "00,1d" "00,1e")
     local -a curves_ossl=("sect163k1" "sect163r1" "sect163r2" "sect193r1" "sect193r2" "sect233k1" "sect233r1" "sect239k1" "sect283k1" "sect283r1" "sect409k1" "sect409r1" "sect571k1" "sect571r1" "secp160k1" "secp160r1" "secp160r2" "secp192k1" "prime192v1" "secp224k1" "secp224r1" "secp256k1" "prime256v1" "secp384r1" "secp521r1" "brainpoolP256r1" "brainpoolP384r1" "brainpoolP512r1" "X25519" "X448")
     local -a curves_ossl_output=("K-163" "sect163r1" "B-163" "sect193r1" "sect193r2" "K-233" "B-233" "sect239k1" "K-283" "B-283" "K-409" "B-409" "K-571" "B-571" "secp160k1" "secp160r1" "secp160r2" "secp192k1" "P-192" "secp224k1" "P-224" "secp256k1" "P-256" "P-384" "P-521" "brainpoolP256r1" "brainpoolP384r1" "brainpoolP512r1" "X25519" "X448")
     local -a ffdhe_groups_hex=("01,00" "01,01" "01,02" "01,03" "01,04")
     local -a ffdhe_groups_output=("ffdhe2048" "ffdhe3072" "ffdhe4096" "ffdhe6144" "ffdhe8192")
     local -a supported_curve
     local -i nr_supported_ciphers=0 nr_curves=0 nr_ossl_curves=0 i j low high
     local pfs_ciphers curves_offered="" curves_to_test temp
     local len1 len2 curve_found
     local has_dh_bits="$HAS_DH_BITS"
     local using_sockets=true

     "$SSL_NATIVE" && using_sockets=false
     "$FAST" && using_sockets=false
     [[ $TLS_NR_CIPHERS == 0 ]] && using_sockets=false

     outln
     pr_headline " Testing robust (perfect) forward secrecy"; pr_underlineln ", (P)FS -- omitting Null Authentication/Encryption, 3DES, RC4 "
     if ! "$using_sockets"; then
          [[ $TLS_NR_CIPHERS == 0 ]] && ! "$SSL_NATIVE" && ! "$FAST" && pr_warning " Cipher mapping not available, doing a fallback to openssl"
          if ! "$HAS_DH_BITS" && "$WIDE"; then
               [[ $TLS_NR_CIPHERS == 0 ]] && ! "$SSL_NATIVE" && ! "$FAST" && out "."
               pr_warning "    (Your $OPENSSL cannot show DH/ECDH bits)"
          fi
          outln
     fi

     if "$using_sockets" || [[ $OSSL_VER_MAJOR -lt 1 ]]; then
          for (( i=0; i < TLS_NR_CIPHERS; i++ )); do
               pfs_cipher="${TLS_CIPHER_RFC_NAME[i]}"
               if ( [[ "$pfs_cipher" == "TLS_DHE_"* ]] || [[ "$pfs_cipher" == "TLS_ECDHE_"* ]] ) && \
                  [[ ! "$pfs_cipher" =~ "NULL" ]] && [[ ! "$pfs_cipher" =~ "DES" ]] && [[ ! "$pfs_cipher" =~ "RC4" ]] && \
                  [[ ! "$pfs_cipher" =~ "PSK" ]] && ( "$using_sockets" || "${TLS_CIPHER_OSSL_SUPPORTED[i]}" ); then
                    hexc="${TLS_CIPHER_HEXCODE[i]}"
                    pfs_hex_cipher_list+=", ${hexc:2:2},${hexc:7:2}"
                    ciph[nr_supported_ciphers]="${TLS_CIPHER_OSSL_NAME[i]}"
                    rfc_ciph[nr_supported_ciphers]="${TLS_CIPHER_RFC_NAME[i]}"
                    kx[nr_supported_ciphers]="${TLS_CIPHER_KX[i]}"
                    enc[nr_supported_ciphers]="${TLS_CIPHER_ENC[i]}"
                    ciphers_found[nr_supported_ciphers]=false
                    sigalg[nr_supported_ciphers]=""
                    ossl_supported[nr_supported_ciphers]="${TLS_CIPHER_OSSL_SUPPORTED[i]}"
                    hexcode[nr_supported_ciphers]="${hexc:2:2},${hexc:7:2}"
                    if [[ "${hexc:2:2}" == "00" ]]; then
                         normalized_hexcode[nr_supported_ciphers]="x${hexc:7:2}"
                    else
                         normalized_hexcode[nr_supported_ciphers]="x${hexc:2:2}${hexc:7:2}"
                    fi
                    "$using_sockets" && ! "$has_dh_bits" && "$WIDE" && ossl_supported[nr_supported_ciphers]=false
                    nr_supported_ciphers+=1
               fi
          done
     else
          while read hexc dash ciph[nr_supported_ciphers] sslvers kx[nr_supported_ciphers] auth enc[nr_supported_ciphers] mac export; do
               ciphers_found[nr_supported_ciphers]=false
               if [[ "${hexc:2:2}" == "00" ]]; then
                    normalized_hexcode[nr_supported_ciphers]="x${hexc:7:2}"
               else
                    normalized_hexcode[nr_supported_ciphers]="x${hexc:2:2}${hexc:7:2}"
               fi
               sigalg[nr_supported_ciphers]=""
               ossl_supported[nr_supported_ciphers]=true
               nr_supported_ciphers+=1
          done < <($OPENSSL ciphers -V "$pfs_cipher_list" 2>$ERRFILE)
     fi
     export=""

     if "$using_sockets"; then
          tls_sockets "03" "${pfs_hex_cipher_list:2}"
          sclient_success=$?
          [[ $sclient_success -eq 2 ]] && sclient_success=0
     else
          debugme echo $nr_supported_ciphers
          debugme echo $(actually_supported_ciphers $pfs_cipher_list)
          if [[ "$nr_supported_ciphers" -le "$CLIENT_MIN_PFS" ]]; then
               outln
               local_problem_ln "You only have $nr_supported_ciphers PFS ciphers on the client side "
               fileout "pfs" "WARN" "(Perfect) Forward Secrecy tests: Skipped. You only have $nr_supported_ciphers PFS ciphers on the client site. ($CLIENT_MIN_PFS are required)"
               return 1
          fi
          $OPENSSL s_client -cipher $pfs_cipher_list $STARTTLS $BUGS -connect $NODEIP:$PORT $PROXY $SNI >$TMPFILE 2>$ERRFILE </dev/null
          sclient_connect_successful $? $TMPFILE
          sclient_success=$?
          [[ $sclient_success -eq 0 ]] && [[ $(grep -ac "BEGIN CERTIFICATE" $TMPFILE) -eq 0 ]] && sclient_success=1
     fi

     if [[ $sclient_success -ne 0 ]]; then
          outln
          pr_svrty_mediumln " No ciphers supporting Forward Secrecy offered"
          fileout "pfs" "MEDIUM" "(Perfect) Forward Secrecy : No ciphers supporting Forward Secrecy offered"
     else
          outln
          pfs_offered=true
          pfs_ciphers=""
          pr_done_good " PFS is offered (OK)"
          fileout "pfs" "OK" "(Perfect) Forward Secrecy : PFS is offered"
          if "$WIDE"; then
               outln ", ciphers follow (client/browser support is important here) \n"
               neat_header
          else
               out "          "
          fi
          while true; do
               ciphers_to_test=""
               for (( i=0; i < nr_supported_ciphers; i++ )); do
                    ! "${ciphers_found[i]}" && "${ossl_supported[i]}" && ciphers_to_test+=":${ciph[i]}"
               done
               [[ -z "$ciphers_to_test" ]] && break
               $OPENSSL s_client -cipher "${ciphers_to_test:1}" $STARTTLS $BUGS -connect $NODEIP:$PORT $PROXY $SNI &>$TMPFILE </dev/null
               sclient_connect_successful $? $TMPFILE || break
               pfs_cipher=$(awk '/Cipher *:/ { print $3 }' $TMPFILE)
               [[ -z "$pfs_cipher" ]] && break
               for (( i=0; i < nr_supported_ciphers; i++ )); do
                    [[ "$pfs_cipher" == "${ciph[i]}" ]] && break
               done
               ciphers_found[i]=true
               if "$WIDE"; then
                    dhlen=$(read_dhbits_from_file "$TMPFILE" quiet)
                    kx[i]="${kx[i]} $dhlen"
               fi
               "$WIDE" && "$SHOW_SIGALGO" && grep -q "\-\-\-\-\-BEGIN CERTIFICATE\-\-\-\-\-" $TMPFILE && \
                    sigalg[i]="$($OPENSSL x509 -noout -text -in $TMPFILE | awk -F':' '/Signature Algorithm/ { print $2 }' | head -1)"
          done
          if "$using_sockets"; then
               while true; do
                    ciphers_to_test=""
                    for (( i=0; i < nr_supported_ciphers; i++ )); do
                         ! "${ciphers_found[i]}" && ciphers_to_test+=", ${hexcode[i]}"
                    done
                    [[ -z "$ciphers_to_test" ]] && break
                    if "$WIDE" && "$SHOW_SIGALGO"; then
                         tls_sockets "03" "${ciphers_to_test:2}, 00,ff" "all"
                    else
                         tls_sockets "03" "${ciphers_to_test:2}, 00,ff" "ephemeralkey"
                    fi
                    sclient_success=$?
                    [[ $sclient_success -ne 0 ]] && [[ $sclient_success -ne 2 ]] && break
                    pfs_cipher=$(awk '/Cipher *:/ { print $3 }' "$TEMPDIR/$NODEIP.parse_tls_serverhello.txt")
                    for (( i=0; i < nr_supported_ciphers; i++ )); do
                         [[ "$pfs_cipher" == "${rfc_ciph[i]}" ]] && break
                    done
                    ciphers_found[i]=true
                    if "$WIDE"; then
                         dhlen=$(read_dhbits_from_file "$TEMPDIR/$NODEIP.parse_tls_serverhello.txt" quiet)
                         kx[i]="${kx[i]} $dhlen"
                    fi
                    "$WIDE" && "$SHOW_SIGALGO" && [[ -r "$HOSTCERT" ]] && \
                         sigalg[i]="$($OPENSSL x509 -noout -text -in "$HOSTCERT" | awk -F':' '/Signature Algorithm/ { print $2 }' | head -1)"
               done
          fi
          for (( i=0; i < nr_supported_ciphers; i++ )); do
               ! "${ciphers_found[i]}" && ! "$SHOW_EACH_C" && continue
               if "${ciphers_found[i]}"; then
                    if ( [[ -z "$SHOW_RFC" ]] && [[ "${ciph[i]}" != "-" ]] ) || [[ "${rfc_ciph[i]}" == "-" ]]; then
                         pfs_cipher="${ciph[i]}"
                    else
                         pfs_cipher="${rfc_ciph[i]}"
                    fi
                    pfs_ciphers+="$pfs_cipher "

                    if [[ "${ciph[i]}" == "ECDHE-"* ]] || ( "$using_sockets" && [[ "${rfc_ciph[i]}" == "TLS_ECDHE_"* ]] ); then
                         ecdhe_offered=true
                         ecdhe_cipher_list_hex+=", ${hexcode[i]}"
                         [[ "${ciph[i]}" != "-" ]] && ecdhe_cipher_list+=":$pfs_cipher"
                    fi
                    if [[ "${ciph[i]}" == "DHE-"* ]] || ( "$using_sockets" && [[ "${rfc_ciph[i]}" == "TLS_DHE_"* ]] ); then
                         ffdhe_offered=true
                         ffdhe_cipher_list_hex+=", ${hexcode[i]}"
                    fi
               fi
               if "$WIDE"; then
                    neat_list "$(tolower "${normalized_hexcode[i]}")" "${ciph[i]}" "${kx[i]}" "${enc[i]}" "${ciphers_found[i]}"
                    if "$SHOW_EACH_C"; then
                         if ${ciphers_found[i]}; then
                              pr_done_best "available"
                         else
                              pr_deemphasize "not a/v"
                         fi
                    fi
                    outln "${sigalg[i]}"
               fi
          done
          ! "$WIDE" && out_row_aligned_max_width "$pfs_ciphers" "                              " $TERM_WIDTH out
          debugme echo $pfs_offered
          "$WIDE" || outln
          fileout "pfs_ciphers" "INFO" "(Perfect) Forward Secrecy Ciphers: $pfs_ciphers"
     fi

     # find out what elliptic curves are supported.
     if "$ecdhe_offered"; then
          for curve in "${curves_ossl[@]}"; do
               ossl_supported[nr_curves]=false
               supported_curve[nr_curves]=false
               $OPENSSL s_client -curves $curve -connect x 2>&1 | egrep -iaq "Error with command|unknown option"
               [[ $? -ne 0 ]] && ossl_supported[nr_curves]=true && nr_ossl_curves+=1
               nr_curves+=1
          done

          # OpenSSL limits the number of curves that can be specified in the
          # "-curves" option to 28. So, break the list in two if there are more
          # than 28 curves supported by OpenSSL.
          for j in 1 2; do
               if [[ $j -eq 1 ]]; then
                    if [[ $nr_ossl_curves -le 28 ]]; then
                         low=0; high=$nr_curves
                    else
                         low=0; high=$nr_curves/2
                    fi
               else
                    if [[ $nr_ossl_curves -le 28 ]]; then
                         continue # all curves tested in first round
                    else
                         low=$nr_curves/2; high=$nr_curves
                    fi
               fi
               while true; do
                    curves_to_test=""
                    for (( i=low; i < high; i++ )); do
                         "${ossl_supported[i]}" && ! "${supported_curve[i]}" && curves_to_test+=":${curves_ossl[i]}"
                    done
                    [[ -z "$curves_to_test" ]] && break
                    $OPENSSL s_client -cipher "${ecdhe_cipher_list:1}" -curves "${curves_to_test:1}" $STARTTLS $BUGS -connect $NODEIP:$PORT $PROXY $SNI &>$TMPFILE </dev/null
                    sclient_connect_successful $? $TMPFILE || break
                    temp=$(awk -F': ' '/^Server Temp Key/ { print $2 }' "$TMPFILE")
                    curve_found="$(awk -F',' '{ print $1 }' <<< $temp)"
                    [[ "$curve_found" == "ECDH" ]] && curve_found="$(awk -F', ' '{ print $2 }' <<< $temp)"
                    for (( i=low; i < high; i++ )); do
                         ! "${supported_curve[i]}" && [[ "${curves_ossl_output[i]}" == "$curve_found" ]] && break
                    done
                    [[ $i -eq $high ]] && break
                    supported_curve[i]=true
               done
          done
     fi
     if "$ecdhe_offered" && "$using_sockets"; then
          while true; do
               curves_to_test=""
               for (( i=0; i < nr_curves; i++ )); do
                    ! "${supported_curve[i]}" && curves_to_test+=", ${curves_hex[i]}"
               done
               [[ -z "$curves_to_test" ]] && break
               len1=$(printf "%02x" "$((2*${#curves_to_test}/7))")
               len2=$(printf "%02x" "$((2*${#curves_to_test}/7+2))")
               tls_sockets "03" "${ecdhe_cipher_list_hex:2}" "ephemeralkey" "00, 0a, 00, $len2, 00, $len1, ${curves_to_test:2}"
               sclient_success=$?
               [[ $sclient_success -ne 0 ]] && [[ $sclient_success -ne 2 ]] && break
               temp=$(awk -F': ' '/^Server Temp Key/ { print $2 }' "$TEMPDIR/$NODEIP.parse_tls_serverhello.txt")
               curve_found="$(awk -F',' '{ print $1 }' <<< $temp)"
               [[ "$curve_found" == "ECDH" ]] && curve_found="$(awk -F', ' '{ print $2 }' <<< $temp)"
               for (( i=0; i < nr_curves; i++ )); do
                    ! "${supported_curve[i]}" && [[ "${curves_ossl_output[i]}" == "$curve_found" ]] && break
               done
               [[ $i -eq $nr_curves ]] && break
               supported_curve[i]=true
          done
     fi
     if "$ecdhe_offered"; then
          for (( i=0; i < nr_curves; i++ )); do
               "${supported_curve[i]}" && curves_offered+="${curves_ossl[i]} "
          done
          if [[ -n "$curves_offered" ]]; then
               "$WIDE" && outln
               pr_bold " Elliptic curves offered:     "
               out_row_aligned_max_width "$curves_offered" "                              " $TERM_WIDTH pr_ecdh_curve_quality
               outln
               fileout "ecdhe_curves" "INFO" "Elliptic curves offered $curves_offered"
          fi
     fi
     outln
     if "$ffdhe_offered" && "$using_sockets" && "$EXPERIMENTAL"; then
          # Check to see whether RFC 7919 is supported (see Section 4 of RFC 7919)
          tls_sockets "03" "${ffdhe_cipher_list_hex:2}" "ephemeralkey" "00, 0a, 00, 04, 00, 02, 01, fb"
          sclient_success=$?
          if [[ $sclient_success -ne 0 ]] && [[ $sclient_success -ne 2 ]]; then
               # find out what groups from RFC 7919 are supported.
               nr_curves=0
               for curve in "${ffdhe_groups_output[@]}"; do
                    supported_curve[nr_curves]=false
                    nr_curves+=1
               done
               while true; do
                    curves_to_test=""
                    for (( i=0; i < nr_curves; i++ )); do
                         ! "${supported_curve[i]}" && curves_to_test+=", ${ffdhe_groups_hex[i]}"
                    done
                    [[ -z "$curves_to_test" ]] && break
                    len1=$(printf "%02x" "$((2*${#curves_to_test}/7))")
                    len2=$(printf "%02x" "$((2*${#curves_to_test}/7+2))")
                    tls_sockets "03" "${ffdhe_cipher_list_hex:2}" "ephemeralkey" "00, 0a, 00, $len2, 00, $len1, ${curves_to_test:2}"
                    sclient_success=$?
                    [[ $sclient_success -ne 0 ]] && [[ $sclient_success -ne 2 ]] && break
                    temp=$(awk -F': ' '/^Server Temp Key/ { print $2 }' "$TEMPDIR/$NODEIP.parse_tls_serverhello.txt")
                    curve_found="$(awk -F', ' '{ print $2 }' <<< $temp)"
                    [[ ! "$curve_found" =~ "ffdhe" ]] && break
                    for (( i=0; i < nr_curves; i++ )); do
                         ! "${supported_curve[i]}" && [[ "${ffdhe_groups_output[i]}" == "$curve_found" ]] && break
                    done
                    [[ $i -eq $nr_curves ]] && break
                    supported_curve[i]=true
               done
               curves_offered=""
               for (( i=0; i < nr_curves; i++ )); do
                    "${supported_curve[i]}" && curves_offered+="${ffdhe_groups_output[i]} "
               done
               if [[ -n "$curves_offered" ]]; then
                    pr_bold " RFC 7919 DH groups offered:  "
                    outln "$curves_offered"
                    fileout "rfc7919_groups" "INFO" "RFC 7919 DH groups offered $curves_offered"
               fi
          fi
     fi

     tmpfile_handle $FUNCNAME.txt
     "$using_sockets" && HAS_DH_BITS="$has_dh_bits"
#     sub1_curves
     if "$pfs_offered"; then
          return 0
     else
          return 1
     fi
}


# good source for configuration and bugs: https://wiki.mozilla.org/Security/Server_Side_TLS
# good start to read: http://en.wikipedia.org/wiki/Transport_Layer_Security#Attacks_against_TLS.2FSSL


spdy_pre(){
     if [[ -n "$STARTTLS" ]] || [[ "$SERVICE" != HTTP ]]; then
          [[ -n "$1" ]] && out "$1"
          out "(SPDY is an HTTP protocol and thus not tested here)"
          fileout "spdy_npn" "INFO" "SPDY/NPN : (SPY is an HTTP protocol and thus not tested here)"
          return 1
     fi
     if [[ -n "$PROXY" ]]; then
          [[ -n "$1" ]] && pr_warning "$1"
          pr_warning "not tested as proxies do not support proxying it"
          fileout "spdy_npn" "WARN" "SPDY/NPN : not tested as proxies do not support proxying it"
          return 1
     fi
     if ! "$HAS_SPDY"; then
          local_problem "$OPENSSL doesn't support SPDY/NPN";
          fileout "spdy_npn" "WARN" "SPDY/NPN : not tested $OPENSSL doesn't support SPDY/NPN"
          return 7
     fi
     return 0
}

http2_pre(){
     if [[ -n "$STARTTLS" ]] || [[ "$SERVICE" != HTTP ]]; then
          [[ -n "$1" ]] && out "$1"
          outln "(HTTP/2 is a HTTP protocol and thus not tested here)"
          fileout "https_alpn" "INFO" "HTTP2/ALPN : HTTP/2 is and HTTP protocol and thus not tested"
          return 1
     fi
     if [[ -n "$PROXY" ]]; then
          [[ -n "$1" ]] && pr_warning " $1 "
          pr_warning "not tested as proxies do not support proxying it"
          fileout "https_alpn" "WARN" "HTTP2/ALPN : HTTP/2 was not tested as proxies do not support proxying it"
          return 1
     fi
     if ! "$HAS_ALPN" && "$SSL_NATIVE"; then
          local_problem_ln "$OPENSSL doesn't support HTTP2/ALPN";
          fileout "https_alpn" "WARN" "HTTP2/ALPN : HTTP/2 was not tested as $OPENSSL does not support it"
          return 7
     fi
     return 0
}

run_spdy() {
     local tmpstr
     local -i ret=0

     pr_bold " SPDY/NPN   "
     if ! spdy_pre; then
          outln
          return 0
     fi
     $OPENSSL s_client -connect $NODEIP:$PORT $BUGS $SNI -nextprotoneg "$NPN_PROTOs" </dev/null 2>$ERRFILE >$TMPFILE
     tmpstr=$(grep -a '^Protocols' $TMPFILE | sed 's/Protocols.*: //')
     if [[ -z "$tmpstr" ]] || [[ "$tmpstr" == " " ]]; then
          outln "not offered"
          fileout "spdy_npn" "INFO" "SPDY/NPN : not offered"
          ret=1
     else
          # now comes a strange thing: "Protocols advertised by server:" is empty but connection succeeded
          if echo $tmpstr | egrep -aq "h2|spdy|http" ; then
               out "$tmpstr"
               outln " (advertised)"
               fileout "spdy_npn" "INFO" "SPDY/NPN : $tmpstr (advertised)"
               ret=0
          else
               pr_cyanln "please check manually, server response was ambiguous ..."
               fileout "spdy_npn" "INFO" "SPDY/NPN : please check manually, server response was ambiguous ..."
               ret=10
          fi
     fi
     #outln
     # btw: nmap can do that too http://nmap.org/nsedoc/scripts/tls-nextprotoneg.html
     # nmap --script=tls-nextprotoneg #NODE -p $PORT is your friend if your openssl doesn't want to test this
     tmpfile_handle $FUNCNAME.txt
     return $ret
}


run_http2() {
     local tmpstr alpn_extn len
     local -i ret=0
     local had_alpn_proto=false
     local alpn_finding=""

     pr_bold " HTTP2/ALPN "
     if ! http2_pre; then
          outln
          return 0
     fi
     for proto in $ALPN_PROTOs; do
          # for some reason OpenSSL doesn't list the advertised protocols, so instead try common protocols
          if "$HAS_ALPN"; then
               $OPENSSL s_client -connect $NODEIP:$PORT $BUGS $SNI -alpn $proto </dev/null 2>$ERRFILE >$TMPFILE
          else
               alpn_extn="$(printf "%02x" ${#proto}),$(string_to_asciihex "$proto")"
               len="$(printf "%04x" $((${#proto}+1)))"
               alpn_extn="${len:0:2},${len:2:2},$alpn_extn"
               len="$(printf "%04x" $((${#proto}+3)))"
               alpn_extn="00,10,${len:0:2},${len:2:2},$alpn_extn"
               tls_sockets "03" "$TLS12_CIPHER" "all" "$alpn_extn"
               if [[ -r "$TEMPDIR/$NODEIP.parse_tls_serverhello.txt" ]]; then
                    cp "$TEMPDIR/$NODEIP.parse_tls_serverhello.txt" $TMPFILE
               else
                    echo "" > $TMPFILE
               fi
          fi
          #tmpstr=$(grep -a '^ALPN protocol' $TMPFILE | sed 's/ALPN protocol.*: //')
          #tmpstr=$(awk '/^ALPN protocol*:/ { print $2 }' $TMPFILE)
          tmpstr=$(awk -F':' '/^ALPN protocol*:/ { print $2 }' $TMPFILE)
          if [[ "$tmpstr" == *"$proto" ]]; then
              if ! $had_alpn_proto; then
                  out "$proto"
                  alpn_finding+="$proto"
                  had_alpn_proto=true
              else
                  out ", $proto"
                  alpn_finding+=", $proto"
              fi
          fi
     done
     if $had_alpn_proto; then
          outln " (offered)"
          fileout "https_alpn" "INFO" "HTTP2/ALPN : offered; Protocols: $alpn_finding"
          ret=0
     else
          outln "not offered"
          fileout "https_alpn" "INFO" "HTTP2/ALPN : not offered"
          ret=1
     fi
     tmpfile_handle $FUNCNAME.txt
     return $ret
}

# arg1: string to send
# arg2: possible success strings a egrep pattern, needed!
starttls_line() {
     debugme echo -e "\n=== sending \"$1\" ..."
     echo -e "$1" >&5

     # we don't know how much to read and it's blocking! So we just put a cat into the
     # background and read until $STARTTLS_SLEEP and: cross our fingers
     cat <&5 >$TMPFILE &
     wait_kill $! $STARTTLS_SLEEP
     debugme echo "... received result: "
     debugme cat $TMPFILE
     if [[ -n "$2" ]]; then
          if egrep -q "$2" $TMPFILE; then
               debugme echo "---> reply matched \"$2\""
          else
               # slow down for exim and friends who need a proper handshake:, see
               # https://github.com/drwetter/testssl.sh/issues/218
               FAST_STARTTLS=false
               debugme echo -e "\n=== sending with automated FAST_STARTTLS=false \"$1\" ..."
               echo -e "$1" >&5
               cat <&5 >$TMPFILE &
               debugme echo "... received result: "
               debugme cat $TMPFILE
               if [[ -n "$2" ]]; then
                    debugme echo "---> reply with automated FAST_STARTTLS=false matched \"$2\""
               else
                    debugme echo "---> reply didn't match \"$2\", see $TMPFILE"
                    pr_magenta "STARTTLS handshake problem. "
                    outln "Either switch to native openssl (--ssl-native), "
                    outln "   give the server more time to reply (STARTTLS_SLEEP=<seconds> ./testssh.sh ..) -- "
                    outln "   or debug what happened (add --debug=2)"
                    return 3
               fi
          fi
     fi

     return 0
}

starttls_just_send(){
     debugme echo -e "C: $1"
     echo -ne "$1\r\n" >&5
}

starttls_just_read(){
     debugme echo "=== just read banner ==="
     if [[ "$DEBUG" -ge 2 ]]; then
          cat <&5 &
          wait_kill $! $STARTTLS_SLEEP
     else
          dd of=/dev/null count=8 <&5 2>/dev/null &
          wait_kill $! $STARTTLS_SLEEP
     fi

     return 0
}

starttls_full_read(){
     starttls_read_data=()
     local one_line=""
     local ret=0
     local cont_pattern="$1"
     local end_pattern="$2"
     local ret_found=0
     if [[ $# -ge 3 ]]; then
          debugme echo "=== we have to search for $3 pattern ==="
          ret_found=3
     fi
     debugme echo "=== full read banner ==="

     local oldIFS="$IFS"
     IFS=''
     while read -r -t $STARTTLS_SLEEP one_line; do
          debugme echo "S: ${one_line}"
          if [[ $# -ge 3 ]]; then
               if [[ ${one_line} =~ $3 ]]; then
                    ret_found=0
                    debugme echo "^^^^^^^ that's what we were looking for ==="
               fi
          fi
          starttls_read_data+=("${one_line}")
          if [[ ${one_line} =~ ${end_pattern} ]]; then
               debugme echo "=== full read finished ==="
               IFS="${oldIFS}"
               return ${ret_found}
          fi
          if [[ ! ${one_line} =~ ${cont_pattern} ]]; then
               debugme echo "=== full read syntax error, expected regex pattern ${cont_pattern} (cont) or ${end_pattern} (end) ==="
               IFS="${oldIFS}"
               return 2
          fi
     done <&5
     ret=$?
     debugme echo "=== full read error/timeout ==="
     IFS="${oldIFS}"
     return $ret
}

starttls_ftp_dialog(){
     debugme echo "=== starting ftp STARTTLS dialog ==="
     local reAUTHTLS='^ AUTH TLS'
     starttls_full_read '^220-' '^220 '                    && debugme echo "received server greeting" &&
     starttls_just_send 'FEAT'                             && debugme echo "sent FEAT" &&
     starttls_full_read '^(211-| )' '^211 ' "${reAUTHTLS}" && debugme echo "received server features and checked STARTTLS availability" &&
     starttls_just_send 'AUTH TLS'                         && debugme echo "initiated STARTTLS" &&
     starttls_full_read '^234-' '^234 '                    && debugme echo "received ack for STARTTLS"
     local ret=$?
     debugme echo "=== finished ftp STARTTLS dialog with ${ret} ==="
     return $ret
}

starttls_smtp_dialog(){
     debugme echo "=== starting smtp STARTTLS dialog ==="
     local re250STARTTLS='^250[ -]STARTTLS'
     starttls_full_read '^220-' '^220 '                    && debugme echo "received server greeting" &&
     starttls_just_send 'EHLO testssl.sh'                  && debugme echo "sent EHLO" &&
     starttls_full_read '^250-' '^250 ' "${re250STARTTLS}" && debugme echo "received server capabilities and checked STARTTLS availability" &&
     starttls_just_send 'STARTTLS'                         && debugme echo "initiated STARTTLS" &&
     starttls_full_read '^220-' '^220 '                    && debugme echo "received ack for STARTTLS"
     local ret=$?
     debugme echo "=== finished smtp STARTTLS dialog with ${ret} ==="
     return $ret
}

starttls_pop3_dialog() {
     debugme echo "=== starting pop3 STARTTLS dialog ==="
     starttls_full_read '$^' '^+OK'                        && debugme echo "received server greeting" &&
     starttls_just_send 'STLS'                             && debugme echo "initiated STARTTLS" &&
     starttls_full_read '$^' '^+OK'                        && debugme echo "received ack for STARTTLS"
     local ret=$?
     debugme echo "=== finished pop3 STARTTLS dialog with ${ret} ==="
     return $ret
}

starttls_imap_dialog() {
     debugme echo "=== starting imap STARTTLS dialog ==="
     local reSTARTTLS='^\* CAPABILITY(( .*)? IMAP4rev1( .*)? STARTTLS( .*)?|( .*)? STARTTLS( .*)? IMAP4rev1( .*)?)$'
     starttls_full_read '^\* ' '^\* OK '                   && debugme echo "received server greeting" &&
     starttls_just_send 'a001 CAPABILITY'                  && debugme echo "sent CAPABILITY" &&
     starttls_full_read '^\* ' '^a001 OK ' "${reSTARTTLS}" && debugme echo "received server capabilities and checked STARTTLS availability" &&
     starttls_just_send 'a002 STARTTLS'                    && debugme echo "initiated STARTTLS" &&
     starttls_full_read '^\* ' '^a002 OK '                 && debugme echo "received ack for STARTTLS"
     local ret=$?
     debugme echo "=== finished imap STARTTLS dialog with ${ret} ==="
     return $ret
}

starttls_nntp_dialog() {
     debugme echo "=== starting nntp STARTTLS dialog ==="
     starttls_full_read '$^' '^20[01] '                    && debugme echo "received server greeting" &&
     starttls_just_send 'CAPABILITIES'                     && debugme echo "sent CAPABILITIES" &&
     starttls_full_read '$^' '^101 '                       &&
     starttls_full_read '' '^\.$' "^STARTTLS$"             && debugme echo "received server capabilities and checked STARTTLS availability" &&
     starttls_just_send 'STARTTLS'                         && debugme echo "initiated STARTTLS" &&
     starttls_full_read '$^' '^382 '                       && debugme echo "received ack for STARTTLS"
     local ret=$?
     debugme echo "=== finished nntp STARTTLS dialog with ${ret} ==="
     return $ret
}

starttls_postgres_dialog() {
     debugme echo "=== starting postgres STARTTLS dialog ==="
     local reINITTLS="\x00\x00\x00\x08\x04\xD2\x16\x2F"
     starttls_just_send "${reINITTLS}"                     && debugme echo "initiated STARTTLS" &&
     starttls_full_read '' '' 'S'                          && debugme echo "received ack for STARTTLS"
     local ret=$?
     debugme echo "=== finished postgres STARTTLS dialog with ${ret} ==="
     return $ret
}

# arg for a fd doesn't work here
fd_socket() {
     local jabber=""
     local proyxline=""
     local nodeip="$(tr -d '[]' <<< $NODEIP)"          # sockets do not need the square brackets we have of IPv6 addresses
                                                       # we just need do it here, that's all!
     if [[ -n "$PROXY" ]]; then
          if ! exec 5<> /dev/tcp/${PROXYIP}/${PROXYPORT}; then
               outln
               pr_magenta "$PROG_NAME: unable to open a socket to proxy $PROXYIP:$PROXYPORT"
               return 6
          fi
          echo "CONNECT $nodeip:$PORT" >&5
          while true ; do
               read proyxline <&5
               if [[ "${proyxline%/*}" == "HTTP" ]]; then
                    proyxline=${proyxline#* }
                    if [[ "${proyxline%% *}" != "200" ]]; then
                         pr_magenta "Unable to CONNECT via proxy. "
                         [[ "$PORT" != 443 ]] && pr_magentaln "Check whether your proxy supports port $PORT and the underlying protocol."
                         return 6
                    fi
               fi
               if [[ "$proyxline" == $'\r' ]]; then
                    break
               fi
          done
     elif ! exec 5<>/dev/tcp/$nodeip/$PORT; then  #  2>/dev/null would remove an error message, but disables debugging
          outln
          pr_magenta "Unable to open a socket to $NODEIP:$PORT. "
          # It can last ~2 minutes but for for those rare occasions we don't do a timeout handler here, KISS
          return 6
     fi

     if [[ -n "$STARTTLS" ]]; then
          case "$STARTTLS_PROTOCOL" in # port
               ftp|ftps)  # https://tools.ietf.org/html/rfc4217, https://tools.ietf.org/html/rfc959
                    starttls_ftp_dialog
                    ;;
               smtp|smtps)  # SMTP, see https://tools.ietf.org/html/rfc5321, https://tools.ietf.org/html/rfc3207
                    starttls_smtp_dialog
                    ;;
               pop3|pop3s) # POP, see https://tools.ietf.org/html/rfc2595
                    starttls_pop3_dialog
                    ;;
               nntp|nntps) # NNTP, see https://tools.ietf.org/html/rfc4642
                    starttls_nntp_dialog
                    ;;
               imap|imaps) # IMAP, https://tools.ietf.org/html/rfc2595, https://tools.ietf.org/html/rfc3501
                    starttls_imap_dialog
                    ;;
               ldap|ldaps) # LDAP, https://tools.ietf.org/html/rfc2830, https://tools.ietf.org/html/rfc4511
                    fatal "FIXME: LDAP+STARTTLS over sockets not yet supported (try \"--ssl-native\")" -4
                    ;;
               acap|acaps) # ACAP = Application Configuration Access Protocol, see https://tools.ietf.org/html/rfc2595
                    fatal "ACAP Easteregg: not implemented -- probably never will" -4
                    ;;
               xmpp|xmpps) # XMPP, see https://tools.ietf.org/html/rfc6120
                    starttls_just_read
                    [[ -z $XMPP_HOST ]] && XMPP_HOST="$NODE"
                    jabber=$(cat <<EOF
<?xml version='1.0' ?>
<stream:stream
xmlns:stream='http://etherx.jabber.org/streams'
xmlns='jabber:client'
to='$XMPP_HOST'
xml:lang='en'
version='1.0'>
EOF
)
                    starttls_line "$jabber"
                    starttls_line "<starttls xmlns='urn:ietf:params:xml:ns:xmpp-tls'/>" "proceed"
                    # BTW: https://xmpp.net !
                    ;;
               postgres|postgress) # Postgres SQL, see http://www.postgresql.org/docs/devel/static/protocol-message-formats.html
                    starttls_postgres_dialog
                    ;;
               *) # we need to throw an error here -- otherwise testssl.sh treats the STARTTLS protocol as plain SSL/TLS which leads to FP
                    fatal "FIXME: STARTTLS protocol $STARTTLS_PROTOCOL is not yet supported" -4
          esac
     fi

     return 0
}


close_socket(){
     exec 5<&-
     exec 5>&-
     return 0
}


# first: helper function for protocol checks
code2network() {
     # arg1: formatted string here in the code
     NW_STR=$(echo "$1" | sed -e 's/,/\\\x/g' | sed -e 's/# .*$//g' -e 's/ //g' -e '/^$/d' | tr -d '\n' | tr -d '\t')
     #TODO: just echo, no additional global var
}

len2twobytes() {
     local len_arg1=${#1}
     [[ $len_arg1 -le 2 ]] && LEN_STR=$(printf "00, %02s \n" "$1")
     [[ $len_arg1 -eq 3 ]] && LEN_STR=$(printf "%02s, %02s \n" "${1:0:1}" "${1:1:2}")
     [[ $len_arg1 -eq 4 ]] && LEN_STR=$(printf "%02s, %02s \n" "${1:0:2}" "${1:2:2}")
}

socksend_sslv2_clienthello() {
     local data=""

     code2network "$1"
     data="$NW_STR"
     [[ "$DEBUG" -ge 4 ]] && echo "\"$data\""
     printf -- "$data" >&5 2>/dev/null &
     sleep $USLEEP_SND
}

# for SSLv2 to TLS 1.2:
sockread_serverhello() {
     [[ -z "$2" ]] && maxsleep=$MAX_WAITSOCK || maxsleep=$2

     SOCK_REPLY_FILE=$(mktemp $TEMPDIR/ddreply.XXXXXX) || return 7
     dd bs=$1 of=$SOCK_REPLY_FILE count=1 <&5 2>/dev/null &
     wait_kill $! $maxsleep

     return $?
}

get_pub_key_size() {
     local pubkey pubkeybits
     local -i i len1 len
     local tmppubkeyfile

     # OpenSSL displays the number of bits for RSA and ECC
     pubkeybits=$($OPENSSL x509 -noout -pubkey -in $HOSTCERT | $OPENSSL pkey -pubin -text 2> $ERRFILE | grep -aw "Public-Key:" | sed -e 's/.*(//' -e 's/)//')
     if [[ -n $pubkeybits ]]; then
          echo "Server public key is $pubkeybits" >> $TMPFILE
     else
          # This extracts the public key for DSA, DH, and GOST
          tmppubkeyfile=$(mktemp $TEMPDIR/pubkey.XXXXXX) || return 7
          $OPENSSL x509 -noout -pubkey -in $HOSTCERT | $OPENSSL pkey -pubin -outform DER -out "$tmppubkeyfile" 2> $ERRFILE
          pubkey=$(hexdump -v -e '16/1 "%02X"' "$tmppubkeyfile")
          rm $tmppubkeyfile
          [[ -z "$pubkey" ]] && return 1
          # Skip over tag and length of subjectPublicKeyInfo
          i=2
          len1="0x${pubkey:i:2}"
          if [[ $len1 -lt 0x80 ]]; then
               i=$i+2
          else
               len1=$len1-0x80
               i=$i+2*$len1+2
          fi

          # Skip over algorithm field
          i=$i+2
          len1="0x${pubkey:i:2}"
          i=$i+2
          if [[ $len1 -lt 0x80 ]]; then
               i=$i+2*$len1
          else
               case $len1 in
                    129) len="0x${pubkey:i:2}" ;;
                    130) len="0x${pubkey:i:2}"
                        i=$i+2
                        len=256*$len+"0x${pubkey:i:2}"
                        ;;
                    131) len="0x${pubkey:i:2}"
                        i=$i+2
                        len=256*$len+"0x${pubkey:i:2}"
                        i=$i+2
                        len=256*$len+"0x${pubkey:i:2}"
                        ;;
                    132) len="0x${pubkey:i:2}"
                        i=$i+2
                        len=256*$len+"0x${pubkey:i:2}"
                        i=$i+2
                        len=256*$len+"0x${pubkey:i:2}"
                        i=$i+2
                        len=256*$len+"0x${pubkey:i:2}"
                        ;;
               esac
               i=$i+2+2*$len
          fi

          # Next is the public key BIT STRING. Skip over tag, length, and number of unused bits.
          i=$i+2
          len1="0x${pubkey:i:2}"
          if [[ $len1 -lt 0x80 ]]; then
               i=$i+4
          else
               len1=$len1-0x80
               i=$i+2*$len1+4
          fi

          # Now get the length of the public key
          i=$i+2
          len1="0x${pubkey:i:2}"
          i=$i+2
          if [[ $len1 -lt 0x80 ]]; then
               len=$len1
          else
               case $len1 in
                    129) len="0x${pubkey:i:2}" ;;
                    130) len="0x${pubkey:i:2}"
                        i=$i+2
                        len=256*$len+"0x${pubkey:i:2}"
                        ;;
                    131) len="0x${pubkey:i:2}"
                        i=$i+2
                        len=256*$len+"0x${pubkey:i:2}"
                        i=$i+2
                        len=256*$len+"0x${pubkey:i:2}"
                        ;;
                    132) len="0x${pubkey:i:2}"
                        i=$i+2
                        len=256*"0x${pubkey:i:2}"
                        i=$i+2
                        len=256*"0x${pubkey:i:2}"
                        i=$i+2
                        len=256*"0x${pubkey:i:2}"
                        ;;
               esac
          fi
          len=8*$len # convert from bytes to bits
          pubkeybits="$(printf "%d" $len)"
          echo "Server public key is $pubkeybits bit" >> $TMPFILE
     fi
     return 0
}

# Extract the DH ephemeral key from the ServerKeyExchange message
get_dh_ephemeralkey() {
     local tls_serverkeyexchange_ascii="$1"
     local -i tls_serverkeyexchange_ascii_len offset
     local dh_p dh_g dh_y dh_param len1 key_bitstring tmp_der_key_file
     local -i i dh_p_len dh_g_len dh_y_len dh_param_len

     tls_serverkeyexchange_ascii_len=${#tls_serverkeyexchange_ascii}
     dh_p_len=2*$(hex2dec "${tls_serverkeyexchange_ascii:0:4}")
     offset=4+$dh_p_len
     if [[ $tls_serverkeyexchange_ascii_len -lt $offset ]]; then
          debugme echo "Malformed ServerKeyExchange Handshake message in ServerHello."
          return 1
     fi

     # Subtract any leading 0 bytes
     for (( i=4; i < offset; i=i+2 )); do
          [[ "${tls_serverkeyexchange_ascii:i:2}" != "00" ]] && break
          dh_p_len=$dh_p_len-2
     done
     if [[ $i -ge $offset ]]; then
          debugme echo "Malformed ServerKeyExchange Handshake message in ServerHello."
          return 1
     fi
     dh_p="${tls_serverkeyexchange_ascii:i:dh_p_len}"

     dh_g_len=2*$(hex2dec "${tls_serverkeyexchange_ascii:offset:4}")
     i=4+$offset
     offset+=4+$dh_g_len
     if [[ $tls_serverkeyexchange_ascii_len -lt $offset ]]; then
          debugme echo "Malformed ServerKeyExchange Handshake message in ServerHello."
          return 1
     fi
     # Subtract any leading 0 bytes
     for (( 1; i < offset; i=i+2 )); do
          [[ "${tls_serverkeyexchange_ascii:i:2}" != "00" ]] && break
          dh_g_len=$dh_g_len-2
     done
     if [[ $i -ge $offset ]]; then
          debugme echo "Malformed ServerKeyExchange Handshake message in ServerHello."
          return 1
     fi
     dh_g="${tls_serverkeyexchange_ascii:i:dh_g_len}"

     dh_y_len=2*$(hex2dec "${tls_serverkeyexchange_ascii:offset:4}")
     i=4+$offset
     offset+=4+$dh_y_len
     if [[ $tls_serverkeyexchange_ascii_len -lt $offset ]]; then
          debugme echo "Malformed ServerKeyExchange Handshake message in ServerHello."
          return 1
     fi
     # Subtract any leading 0 bytes
     for (( 1; i < offset; i=i+2 )); do
          [[ "${tls_serverkeyexchange_ascii:i:2}" != "00" ]] && break
          dh_y_len=$dh_y_len-2
     done
     if [[ $i -ge $offset ]]; then
          debugme echo "Malformed ServerKeyExchange Handshake message in ServerHello."
          return 1
     fi
     dh_y="${tls_serverkeyexchange_ascii:i:dh_y_len}"

     # The following code assumes that all lengths can be encoded using at most 2 bytes,
     # which just means that the encoded length of the public key must be less than
     # 65,536 bytes. If the length is anywhere close to that, it is almost certainly an
     # encoding error.
     if [[ $dh_p_len+$dh_g_len+$dh_y_len -ge 131000 ]]; then
          debugme echo "Malformed ServerKeyExchange Handshake message in ServerHello."
          return 1
     fi
     # make ASN.1 INTEGER of p, g, and Y
     [[ "0x${dh_p:0:1}" -ge 8 ]] && dh_p_len+=2 && dh_p="00$dh_p"
     if [[ $dh_p_len -lt 256 ]]; then
          len1="$(printf "%02x" $((dh_p_len/2)))"
     elif [[ $dh_p_len -lt 512 ]]; then
          len1="81$(printf "%02x" $((dh_p_len/2)))"
     else
          len1="82$(printf "%04x" $((dh_p_len/2)))"
     fi
     dh_p="02${len1}$dh_p"

     [[ "0x${dh_g:0:1}" -ge 8 ]] && dh_g_len+=2 && dh_g="00$dh_g"
     if [[ $dh_g_len -lt 256 ]]; then
          len1="$(printf "%02x" $((dh_g_len/2)))"
     elif [[ $dh_g_len -lt 512 ]]; then
          len1="81$(printf "%02x" $((dh_g_len/2)))"
     else
          len1="82$(printf "%04x" $((dh_g_len/2)))"
     fi
     dh_g="02${len1}$dh_g"

     [[ "0x${dh_y:0:1}" -ge 8 ]] && dh_y_len+=2 && dh_y="00$dh_y"
     if [[ $dh_y_len -lt 256 ]]; then
          len1="$(printf "%02x" $((dh_y_len/2)))"
     elif [[ $dh_y_len -lt 512 ]]; then
          len1="81$(printf "%02x" $((dh_y_len/2)))"
     else
          len1="82$(printf "%04x" $((dh_y_len/2)))"
     fi
     dh_y="02${len1}$dh_y"

     # Make a SEQUENCE of p and g
     dh_param_len=${#dh_p}+${#dh_g}
     if [[ $dh_param_len -lt 256 ]]; then
          len1="$(printf "%02x" $((dh_param_len/2)))"
     elif [[ $dh_param_len -lt 512 ]]; then
          len1="81$(printf "%02x" $((dh_param_len/2)))"
     else
          len1="82$(printf "%04x" $((dh_param_len/2)))"
     fi
     dh_param="30${len1}${dh_p}${dh_g}"

     # Make a SEQUENCE of the paramters SEQUENCE and the OID
     dh_param_len=22+${#dh_param}
     if [[ $dh_param_len -lt 256 ]]; then
          len1="$(printf "%02x" $((dh_param_len/2)))"
     elif [[ $dh_param_len -lt 512 ]]; then
          len1="81$(printf "%02x" $((dh_param_len/2)))"
     else
          len1="82$(printf "%04x" $((dh_param_len/2)))"
     fi
     dh_param="30${len1}06092A864886F70D010301${dh_param}"

     # Encapsulate public key, y, in a BIT STRING
     dh_y_len=${#dh_y}+2
     if [[ $dh_y_len -lt 256 ]]; then
          len1="$(printf "%02x" $((dh_y_len/2)))"
     elif [[ $dh_y_len -lt 512 ]]; then
          len1="81$(printf "%02x" $((dh_y_len/2)))"
     else
          len1="82$(printf "%04x" $((dh_y_len/2)))"
     fi
     dh_y="03${len1}00$dh_y"

     # Create the public key SEQUENCE
     i=${#dh_param}+${#dh_y}
     if [[ $i -lt 256 ]]; then
          len1="$(printf "%02x" $((i/2)))"
     elif [[ $i -lt 512 ]]; then
          len1="81$(printf "%02x" $((i/2)))"
     else
          len1="82$(printf "%04x" $((i/2)))"
     fi
     key_bitstring="30${len1}${dh_param}${dh_y}"
     tmp_der_key_file=$(mktemp $TEMPDIR/pub_key_der.XXXXXX) || return 1
     asciihex_to_binary_file "$key_bitstring" "$tmp_der_key_file"
     key_bitstring="$($OPENSSL pkey -pubin -in $tmp_der_key_file -inform DER 2> $ERRFILE)"
     rm $tmp_der_key_file
     [[ -z "$key_bitstring" ]] && return 1
     out "$key_bitstring"
     return 0
}

# arg1: name of file with socket reply
# arg2: true if entire server hello should be parsed
parse_sslv2_serverhello() {
     local ret v2_hello_ascii v2_hello_initbyte v2_hello_length
     local v2_hello_handshake v2_cert_type v2_hello_cert_length
     local v2_hello_cipherspec_length tmp_der_certfile
     local -i certificate_len nr_ciphers_detected offset i
     # server hello:                                             in hex representation, see below
     # byte 1+2: length of server hello                          0123
     # 3:        04=Handshake message, server hello              45
     # 4:        session id hit or not (boolean: 00=false, this  67
     #           is the normal case)
     # 5:        certificate type, 01 = x509                     89
     # 6+7       version (00 02 = SSLv2)                         10-13
     # 8+9       certificate length                              14-17
     # 10+11     cipher spec length                              17-20
     # 12+13     connection id length
     # [certificate length] ==> certificate
     # [cipher spec length] ==> ciphers GOOD: HERE ARE ALL CIPHERS ALREADY!

     local ret=3
     local parse_complete="false"

     if [[ "$2" == "true" ]]; then
          parse_complete=true
     fi
     "$parse_complete" && echo "======================================" > $TMPFILE

     v2_hello_ascii=$(hexdump -v -e '16/1 "%02X"' $1)
     v2_hello_ascii="${v2_hello_ascii%%[!0-9A-F]*}"
     [[ "$DEBUG" -ge 5 ]] && echo "$v2_hello_ascii"
     if [[ -z "$v2_hello_ascii" ]]; then
          ret=0                                      # 1 line without any blanks: no server hello received
          debugme echo "server hello empty"
     else
          # now scrape two bytes out of the reply per byte
          v2_hello_initbyte="${v2_hello_ascii:0:1}"  # normally this belongs to the next, should be 8!
          v2_hello_length="${v2_hello_ascii:1:3}"    # + 0x8000 see above
          v2_hello_handshake="${v2_hello_ascii:4:2}"
          v2_cert_type="${v2_hello_ascii:8:2}"
          v2_hello_cert_length="${v2_hello_ascii:14:4}"
          v2_hello_cipherspec_length="${v2_hello_ascii:18:4}"

          V2_HELLO_CIPHERSPEC_LENGTH=$(printf "%d\n" "0x$v2_hello_cipherspec_length" 2>/dev/null)
          [[ $? -ne 0 ]] && ret=7

          if [[ $v2_hello_initbyte != "8" ]] || [[ $v2_hello_handshake != "04" ]]; then
               ret=1
               if [[ $DEBUG -ge 2 ]]; then
                    echo "no correct server hello"
                    echo "SSLv2 server init byte:    0x0$v2_hello_initbyte"
                    echo "SSLv2 hello handshake :    0x$v2_hello_handshake"
               fi
          fi

          if [[ $DEBUG -ge 3 ]]; then
               echo "SSLv2 server hello length: 0x0$v2_hello_length"
               echo "SSLv2 certificate type:    0x$v2_cert_type"
               echo "SSLv2 certificate length:  0x$v2_hello_cert_length"
               echo "SSLv2 cipher spec length:  0x$v2_hello_cipherspec_length"
          fi

          if "$parse_complete" && [[ 2*$(hex2dec "$v2_hello_length") -ne ${#v2_hello_ascii}-4 ]]; then
               ret=7
          fi
     fi

     "$parse_complete" || return $ret

     rm -f $HOSTCERT $TEMPDIR/intermediatecerts.pem
     if [[ $ret -eq 3 ]]; then
          certificate_len=2*$(hex2dec "$v2_hello_cert_length")

          if [[ "$v2_cert_type" == "01" ]] && [[ "$v2_hello_cert_length" != "00" ]]; then
               tmp_der_certfile=$(mktemp $TEMPDIR/der_cert.XXXXXX) || return $ret
               asciihex_to_binary_file "${v2_hello_ascii:26:certificate_len}" "$tmp_der_certfile"
               $OPENSSL x509 -inform DER -in $tmp_der_certfile -outform PEM -out $HOSTCERT 2>$ERRFILE
               if [[ $? -ne 0 ]]; then
                    debugme echo "Malformed certificate in ServerHello."
                    return 1
               fi
               rm $tmp_der_certfile
               get_pub_key_size
               echo "======================================" >> $TMPFILE
          fi

          # Output list of supported ciphers
          let offset=26+$certificate_len
          nr_ciphers_detected=$((V2_HELLO_CIPHERSPEC_LENGTH / 3))
          for (( i=0 ; i<nr_ciphers_detected; i++ )); do
               echo "Supported cipher: x$(echo ${v2_hello_ascii:offset:6} |  tr 'A-Z' 'a-z')" >> $TMPFILE
               let offset=$offset+6
          done
          echo "======================================" >> $TMPFILE

          tmpfile_handle $FUNCNAME.txt
     fi
     return $ret
}

# Return 0 if arg1 contains the entire server response, 1 if it does not, and 2 if the response is malformed.
# Return 3 if the response version is TLS 1.3 and the entire ServerHello has been received, since any remaining
# portion of the response will be encrypted.
# arg1: ASCII-HEX encoded reply
check_tls_serverhellodone() {
     local tls_hello_ascii="$1"
     local tls_handshake_ascii="" tls_alert_ascii=""
     local -i i tls_hello_ascii_len tls_handshake_ascii_len tls_alert_ascii_len
     local -i msg_len remaining
     local tls_content_type tls_protocol tls_handshake_type tls_msg_type
     local tls_err_level

     DETECTED_TLS_VERSION=""

     if [[ -z "$tls_hello_ascii" ]]; then
          return 0              # no server hello received
     fi

     tls_hello_ascii_len=${#tls_hello_ascii}
     for (( i=0; i<tls_hello_ascii_len; i=i+msg_len )); do
          remaining=$tls_hello_ascii_len-$i
          [[ $remaining -lt 10 ]] && return 1

          tls_content_type="${tls_hello_ascii:i:2}"
          [[ "$tls_content_type" != "15" ]] && [[ "$tls_content_type" != "16" ]] && \
               [[ "$tls_content_type" != "17" ]] && return 2
          i=$i+2
          tls_protocol="${tls_hello_ascii:i:4}"
          [[ -z "$DETECTED_TLS_VERSION" ]] && DETECTED_TLS_VERSION=$tls_protocol
          [[ "${tls_protocol:0:2}" != "03" ]] && return 2
          i=$i+4
          msg_len=2*$(hex2dec "${tls_hello_ascii:i:4}")
          i=$i+4
          remaining=$tls_hello_ascii_len-$i
          [[ $msg_len -gt $remaining ]] && return 1

          if [[ "$tls_content_type" == "16" ]]; then
               tls_handshake_ascii+="${tls_hello_ascii:i:msg_len}"
               tls_handshake_ascii_len=${#tls_handshake_ascii}
               # the ServerHello MUST be the first handshake message
               [[ $tls_handshake_ascii_len -ge 2 ]] && [[ "${tls_handshake_ascii:0:2}" != "02" ]] && return 2
               if [[ $tls_handshake_ascii_len -ge 12 ]]; then
                    DETECTED_TLS_VERSION="${tls_handshake_ascii:8:4}"
                    if [[ 0x"$DETECTED_TLS_VERSION" -ge "0x0304" ]]; then
                         tls_handshake_ascii_len=2*$(hex2dec "${tls_handshake_ascii:2:6}")
                         if [[ $tls_handshake_ascii_len+8 -gt $remaining ]]; then
                              return 1 # Not all of the ServerHello message has been received
                         else
                              return 3
                         fi
                    fi
               fi
          elif [[ "$tls_content_type" == "15" ]]; then   # TLS ALERT
               tls_alert_ascii+="${tls_hello_ascii:i:msg_len}"
          fi
     done

     # If there is a fatal alert, then we are done.
     tls_alert_ascii_len=${#tls_alert_ascii}
     for (( i=0; i<tls_alert_ascii_len; i=i+4 )); do
          remaining=$tls_alert_ascii_len-$i
          [[ $remaining -lt 4 ]] && return 1
          tls_err_level=${tls_alert_ascii:i:2}    # 1: warning, 2: fatal
          [[ $tls_err_level == "02" ]] && DETECTED_TLS_VERSION="" && return 0
     done

     # If there is a serverHelloDone or Finished, then we are done.
     tls_handshake_ascii_len=${#tls_handshake_ascii}
     for (( i=0; i<tls_handshake_ascii_len; i=i+msg_len )); do
          remaining=$tls_handshake_ascii_len-$i
          [[ $remaining -lt 8 ]] && return 1
          tls_msg_type="${tls_handshake_ascii:i:2}"
          i=$i+2
          msg_len=2*$(hex2dec "${tls_handshake_ascii:i:6}")
          i=$i+6
          remaining=$tls_handshake_ascii_len-$i
          [[ $msg_len -gt $remaining ]] && return 1

          # For SSLv3 - TLS1.2 look for a ServerHelloDone message.
          # For TLS 1.3 look for a Finished message.
          [[ $tls_msg_type == "0E" ]] && return 0
          [[ $tls_msg_type == "14" ]] && return 0
     done

     # If we haven't encoountered a fatal alert or a server hello done,
     # then there must be more data to retrieve.
     return 1
}

# arg1: ASCII-HEX encoded reply
# arg2: (optional): "all" -  process full response (including Certificate and certificate_status handshake messages)
#                   "ephemeralkey" - extract the server's ephemeral key (if any)
parse_tls_serverhello() {
     local tls_hello_ascii="$1"
     local process_full="$2"
     local tls_handshake_ascii="" tls_alert_ascii=""
     local -i tls_hello_ascii_len tls_handshake_ascii_len tls_alert_ascii_len msg_len
     local tls_serverhello_ascii="" tls_certificate_ascii=""
     local tls_serverkeyexchange_ascii="" tls_certificate_status_ascii=""
     local -i tls_serverhello_ascii_len=0 tls_certificate_ascii_len=0
     local -i tls_serverkeyexchange_ascii_len=0 tls_certificate_status_ascii_len=0
     local tls_alert_descrip tls_sid_len_hex issuerDN subjectDN CAissuerDN CAsubjectDN
     local -i tls_sid_len offset extns_offset nr_certs=0
     local tls_msg_type tls_content_type tls_protocol tls_protocol2 tls_hello_time
     local tls_err_level tls_err_descr tls_cipher_suite rfc_cipher_suite tls_compression_method
     local tls_extensions="" extension_type named_curve_str=""
     local -i i j extension_len tls_extensions_len ocsp_response_len ocsp_response_list_len
     local -i certificate_list_len certificate_len
     local -i curve_type named_curve
     local -i dh_bits=0 msb mask
     local tmp_der_certfile tmp_pem_certfile hostcert_issuer="" ocsp_response=""
     local key_bitstring=""
     local dh_p ephemeral_param rfc7919_param
     local -i dh_p_len

     TLS_TIME=""
     DETECTED_TLS_VERSION=""
     [[ -n "$tls_hello_ascii" ]] && echo "CONNECTED(00000003)" > $TMPFILE

     [[ "$DEBUG" -eq 5 ]] && echo $tls_hello_ascii      # one line without any blanks

     # Client messages, including handshake messages, are carried by the record layer.
     # First, extract the handshake and alert messages.
     # see http://en.wikipedia.org/wiki/Transport_Layer_Security-SSL#TLS_record
     # byte 0:      content type:                 0x14=CCS,    0x15=TLS alert  x16=Handshake,  0x17 Aplication, 0x18=HB
     # byte 1+2:    TLS version word, major is 03, minor 00=SSL3, 01=TLS1 02=TLS1.1 03=TLS 1.2
     # byte 3+4:    fragment length
     # bytes 5...:  message fragment
     tls_hello_ascii_len=${#tls_hello_ascii}
     if [[ $DEBUG -ge 2 ]] && [[ $tls_hello_ascii_len -gt 0 ]]; then
          echo "TLS message fragments:"
     fi
     for (( i=0; i<tls_hello_ascii_len; i=i+msg_len )); do
          if [[ $tls_hello_ascii_len-$i -lt 10 ]]; then
               if [[ "$process_full" == "all" ]]; then
                    # The entire server response should have been retrieved.
                    debugme pr_warningln "Malformed message."
                    return 1
               else
                    # This could just be a result of the server's response being
                    # split across two or more packets.
                    continue
               fi
          fi
          tls_content_type="${tls_hello_ascii:i:2}"
          i=$i+2
          tls_protocol="${tls_hello_ascii:i:4}"
          i=$i+4
          msg_len=2*$(hex2dec "${tls_hello_ascii:i:4}")
          i=$i+4

          if [[ $DEBUG -ge 2 ]]; then
               echo "     tls_protocol (reclyr):  0x$tls_protocol"
               out  "     tls_content_type:       0x$tls_content_type"
               case $tls_content_type in
                    15) outln " (alert)" ;;
                    16) outln " (handshake)" ;;
                    17) outln " (application data)" ;;
                     *) outln ;;
               esac
               echo "     msg_len:                $((msg_len/2))"
               outln
          fi
          if [[ $tls_content_type != "15" ]] && [[ $tls_content_type != "16" ]] && [[ $tls_content_type != "17" ]]; then
               debugme pr_warningln "Content type other than alert, handshake, or application data detected."
               return 1
          elif [[ "${tls_protocol:0:2}" != "03" ]]; then
               debugme pr_warningln "Protocol record_version.major is not 03."
               return 1
          fi
          DETECTED_TLS_VERSION=$tls_protocol

          if [[ $msg_len -gt $tls_hello_ascii_len-$i ]]; then
               if [[ "$process_full" == "all" ]]; then
                    debugme pr_warningln "Malformed message."
                    return 1
               else
                    # This could just be a result of the server's response being
                    # split across two or more packets. Just grab the part that
                    # is available.
                    msg_len=$tls_hello_ascii_len-$i
               fi
          fi

          if [[ $tls_content_type == "16" ]]; then
               tls_handshake_ascii="$tls_handshake_ascii${tls_hello_ascii:i:msg_len}"
          elif [[ $tls_content_type == "15" ]]; then   # TLS ALERT
               tls_alert_ascii="$tls_alert_ascii${tls_hello_ascii:i:msg_len}"
          fi
     done

     # Now check the alert messages.
     tls_alert_ascii_len=${#tls_alert_ascii}
     if [[ "$process_full" == "all" ]] && [[ $tls_alert_ascii_len%4 -ne 0 ]]; then
          debugme pr_warningln "Malformed message."
          return 1
     fi
     if [[ $tls_alert_ascii_len -gt 0 ]]; then
          debugme echo "TLS alert messages:"
          for (( i=0; i+3 < tls_alert_ascii_len; i=i+4 )); do
               tls_err_level=${tls_alert_ascii:i:2}    # 1: warning, 2: fatal
               j=$i+2
               tls_err_descr=${tls_alert_ascii:j:2}    # 112/0x70: Unrecognized name, 111/0x6F: certificate_unobtainable,
                                                       # 113/0x71: bad_certificate_status_response, #114/0x72: bad_certificate_hash_value

               debugme out  "     tls_err_descr:          0x${tls_err_descr} / = $(hex2dec ${tls_err_descr})"
               case $tls_err_descr in
                    00) tls_alert_descrip="close notify" ;;
                    01) tls_alert_descrip="end of early data" ;;
                    0A) tls_alert_descrip="unexpected message" ;;
                    14) tls_alert_descrip="bad record mac" ;;
                    15) tls_alert_descrip="decryption failed" ;;
                    16) tls_alert_descrip="record overflow" ;;
                    1E) tls_alert_descrip="decompression failure" ;;
                    28) tls_alert_descrip="handshake failure" ;;
                    29) tls_alert_descrip="no certificate RESERVED" ;;
                    2A) tls_alert_descrip="bad certificate" ;;
                    2B) tls_alert_descrip="unsupported certificate" ;;
                    2C) tls_alert_descrip="certificate revoked" ;;
                    2D) tls_alert_descrip="certificate expired" ;;
                    2E) tls_alert_descrip="certificate unknown" ;;
                    2F) tls_alert_descrip="illegal parameter" ;;
                    30) tls_alert_descrip="unknown ca" ;;
                    31) tls_alert_descrip="access denied" ;;
                    32) tls_alert_descrip="decode error" ;;
                    33) tls_alert_descrip="decrypt error" ;;
                    3C) tls_alert_descrip="export restriction RESERVED" ;;
                    46) tls_alert_descrip="protocol version" ;;
                    47) tls_alert_descrip="insufficient security" ;;
                    50) tls_alert_descrip="internal error" ;;
                    56) tls_alert_descrip="inappropriate fallback" ;;
                    5A) tls_alert_descrip="user canceled" ;;
                    64) tls_alert_descrip="no renegotiation" ;;
                    6D) tls_alert_descrip="missing extension" ;;
                    6E) tls_alert_descrip="unsupported extension" ;;
                    6F) tls_alert_descrip="certificate unobtainable" ;;
                    70) tls_alert_descrip="unrecognized name" ;;
                    71) tls_alert_descrip="bad certificate status response" ;;
                    72) tls_alert_descrip="bad certificate hash value" ;;
                    73) tls_alert_descrip="unknown psk identity" ;;
                    74) tls_alert_descrip="certificate required" ;;
                    78) tls_alert_descrip="no application protocol" ;;
                     *) tls_alert_descrip="$(hex2dec "$tls_err_descr")";;
               esac
               case $tls_err_level in
                    01) echo -n "warning " >> $TMPFILE ;;
                    02) echo -n "fatal " >> $TMPFILE ;;
               esac
               echo "alert $tls_alert_descrip" >> $TMPFILE
               echo "===============================================================================" >> $TMPFILE
               if [[ $DEBUG -ge 2 ]]; then
                    outln " ($tls_alert_descrip)"
                    out  "     tls_err_level:          ${tls_err_level}"
                    case $tls_err_level in
                         01) outln " (warning)" ;;
                         02) outln " (fatal)" ;;
                          *) outln ;;
                    esac
                    outln
               fi
               if [[ "$tls_err_level" != "01" ]] && [[ "$tls_err_level" != "02" ]]; then
                    debugme pr_warningln "Unexpected AlertLevel (0x$tls_err_level)."
                    return 1
               elif [[ "$tls_err_level" == "02" ]]; then
                    # Fatal alert
                    tmpfile_handle $FUNCNAME.txt
                    return 1
               fi
          done
     fi

     # Now extract just the server hello, certificate, certificate status,
     # and server key exchange handshake messages.
     tls_handshake_ascii_len=${#tls_handshake_ascii}
     if [[ $DEBUG -ge 2 ]] && [[ $tls_handshake_ascii_len -gt 0 ]]; then
          echo "TLS handshake messages:"
     fi
     for (( i=0; i<tls_handshake_ascii_len; i=i+msg_len )); do
          if [[ $tls_handshake_ascii_len-$i -lt 8 ]]; then
               if [[ "$process_full" == "all" ]]; then
                    # The entire server response should have been retrieved.
                    debugme pr_warningln "Malformed message."
                    return 1
               else
                    # This could just be a result of the server's response being
                    # split across two or more packets.
                    continue
               fi
          fi
          tls_msg_type="${tls_handshake_ascii:i:2}"
          i=$i+2
          msg_len=2*$(hex2dec "${tls_handshake_ascii:i:6}")
          i=$i+6

          if [[ $DEBUG -ge 2 ]]; then
               out  "     handshake type:         0x${tls_msg_type}"
               case $tls_msg_type in
                    00) outln " (hello_request)" ;;
                    01) outln " (client_hello)" ;;
                    02) outln " (server_hello)" ;;
                    03) outln " (hello_verify_request)" ;;
                    04) outln " (NewSessionTicket)" ;;
                    06) outln " (hello_retry_request)" ;;
                    08) outln " (encrypted_extensions)" ;;
                    0B) outln " (certificate)" ;;
                    0C) outln " (server_key_exchange)" ;;
                    0D) outln " (certificate_request)" ;;
                    0E) outln " (server_hello_done)" ;;
                    0F) outln " (certificate_verify)" ;;
                    10) outln " (client_key_exchange)" ;;
                    14) outln " (finished)" ;;
                    15) outln " (certificate_url)" ;;
                    16) outln " (certificate_status)" ;;
                    17) outln " (supplemental_data)" ;;
                    18) outln " (key_update)" ;;
                    *) outln ;;
               esac
               echo "     msg_len:                $((msg_len/2))"
               outln
          fi
          if [[ $msg_len -gt $tls_handshake_ascii_len-$i ]]; then
               if [[ "$process_full" == "all" ]]; then
                    debugme pr_warningln "Malformed message."
                    return 1
               else
                    # This could just be a result of the server's response being
                    # split across two or more packets. Just grab the part that
                    # is available.
                    msg_len=$tls_handshake_ascii_len-$i
               fi
          fi

          if [[ "$tls_msg_type" == "02" ]]; then
               if [[ -n "$tls_serverhello_ascii" ]]; then
                    debugme pr_warningln "Response contained more than one ServerHello handshake message."
                    return 1
               fi
               tls_serverhello_ascii="${tls_handshake_ascii:i:msg_len}"
               tls_serverhello_ascii_len=$msg_len
          elif [[ "$process_full" == "all" ]] && [[ "$tls_msg_type" == "0B" ]]; then
               if [[ -n "$tls_certificate_ascii" ]]; then
                    debugme pr_warningln "Response contained more than one Certificate handshake message."
                    return 1
               fi
               tls_certificate_ascii="${tls_handshake_ascii:i:msg_len}"
               tls_certificate_ascii_len=$msg_len
          elif ( [[ "$process_full" == "all" ]] || [[ "$process_full" == "ephemeralkey" ]] ) && [[ "$tls_msg_type" == "0C" ]]; then
               if [[ -n "$tls_serverkeyexchange_ascii" ]]; then
                    debugme pr_warningln "Response contained more than one ServerKeyExchange handshake message."
                    return 1
               fi
               tls_serverkeyexchange_ascii="${tls_handshake_ascii:i:msg_len}"
               tls_serverkeyexchange_ascii_len=$msg_len
          elif [[ "$process_full" == "all" ]] && [[ "$tls_msg_type" == "16" ]]; then
               if [[ -n "$tls_certificate_status_ascii" ]]; then
                    debugme pr_warningln "Response contained more than one certificate_status handshake message."
                    return 1
               fi
               tls_certificate_status_ascii="${tls_handshake_ascii:i:msg_len}"
               tls_certificate_status_ascii_len=$msg_len
          fi
     done

     if [[ $tls_serverhello_ascii_len -eq 0 ]]; then
          debugme echo "server hello empty, TCP connection closed"
          tmpfile_handle $FUNCNAME.txt
          return 1              # no server hello received
     elif [[ $tls_serverhello_ascii_len -lt 76 ]]; then
          debugme echo "Malformed response"
          return 1
     elif [[ "${tls_handshake_ascii:0:2}" != "02" ]]; then
          # the ServerHello MUST be the first handshake message
          debugme pr_warningln "The first handshake protocol message is not a ServerHello."
          return 1
     fi

     # First parse the server hello handshake message
     # byte 0+1:    03, TLS version word          see byte 1+2
     # byte 2-5:    TLS timestamp                 for OpenSSL <1.01f
     # byte 6-33:  random, 28 bytes
     # byte 34:     session id length
     # byte 35+36+sid-len:  cipher suite!
     # byte 37+sid-len:     compression method:  00: none, 01: deflate, 64: LZS
     # byte 38+39+sid-len:  extension length
     tls_protocol2="${tls_serverhello_ascii:0:4}"
     if [[ "${tls_protocol2:0:2}" != "03" ]]; then
          debugme pr_warningln "server_version.major in ServerHello is not 03."
          return 1
     fi
     DETECTED_TLS_VERSION="$tls_protocol2"

     if [[ "0x${tls_protocol2:2:2}" -le "0x03" ]]; then
          tls_hello_time="${tls_serverhello_ascii:4:8}"
          TLS_TIME=$(hex2dec "$tls_hello_time")
          tls_sid_len_hex="${tls_serverhello_ascii:68:2}"
          tls_sid_len=2*$(hex2dec "$tls_sid_len_hex")
          let offset=70+$tls_sid_len
          if [[ $tls_serverhello_ascii_len -lt 76+$tls_sid_len ]]; then
               debugme echo "Malformed response"
               return 1
          fi
     else
          let offset=68
     fi

     tls_cipher_suite="${tls_serverhello_ascii:offset:4}"

     if [[ "0x${tls_protocol2:2:2}" -le "0x03" ]]; then
          let offset=74+$tls_sid_len
          tls_compression_method="${tls_serverhello_ascii:offset:2}"
          let extns_offset=76+$tls_sid_len
     else
          let extns_offset=72
     fi

     if [[ $tls_serverhello_ascii_len -gt $extns_offset ]] && \
        ( [[ "$process_full" == "all" ]] || ( [[ "$process_full" == "ephemeralkey" ]] && [[ "0x${tls_protocol2:2:2}" -gt "0x03" ]] ) ); then
          if [[ $tls_serverhello_ascii_len -lt $extns_offset+4 ]]; then
               debugme echo "Malformed response"
               return 1
          fi
          tls_extensions_len=$(hex2dec "${tls_serverhello_ascii:extns_offset:4}")*2
          if [[ $tls_extensions_len -ne $tls_serverhello_ascii_len-$extns_offset-4 ]]; then
               debugme pr_warningln "Malformed message."
               return 1
          fi
          for (( i=0; i<tls_extensions_len; i=i+8+extension_len )); do
               if [[  $tls_extensions_len-$i -lt 8 ]]; then
                    debugme echo "Malformed response"
                    return 1
               fi
               let offset=$extns_offset+4+$i
               extension_type="${tls_serverhello_ascii:offset:4}"
               let offset=$extns_offset+8+$i
               extension_len=2*$(hex2dec "${tls_serverhello_ascii:offset:4}")
               if [[  $extension_len -gt $tls_extensions_len-$i-8 ]]; then
                    debugme echo "Malformed response"
                    return 1
               fi
               case $extension_type in
                    0000) tls_extensions+=" \"server name/#0\"" ;;
                    0001) tls_extensions+=" \"max fragment length/#1\"" ;;
                    0002) tls_extensions+=" \"client certificate URL/#2\"" ;;
                    0003) tls_extensions+=" \"trusted CA keys/#3\"" ;;
                    0004) tls_extensions+=" \"truncated HMAC/#4\"" ;;
                    0005) tls_extensions+=" \"status request/#5\"" ;;
                    0006) tls_extensions+=" \"user mapping/#6\"" ;;
                    0007) tls_extensions+=" \"client authz/#7\"" ;;
                    0008) tls_extensions+=" \"server authz/#8\"" ;;
                    0009) tls_extensions+=" \"cert type/#9\"" ;;
                    000A) tls_extensions+=" \"supported_groups/#10\"" ;;
                    000B) tls_extensions+=" \"EC point formats/#11\"" ;;
                    000C) tls_extensions+=" \"SRP/#12\"" ;;
                    000D) tls_extensions+=" \"signature algorithms/#13\"" ;;
                    000E) tls_extensions+=" \"use SRTP/#14\"" ;;
                    000F) tls_extensions+=" \"heartbeat/#15\"" ;;
                    0010) tls_extensions+=" \"application layer protocol negotiation/#16\""
                          if [[ $extension_len -lt 4 ]]; then
                               debugme echo "Malformed application layer protocol negotiation extension."
                               return 1
                          fi
                          echo -n "ALPN protocol:  " >> $TMPFILE
                          let offset=$extns_offset+12+$i
                          j=2*$(hex2dec "${tls_serverhello_ascii:offset:4}")
                          if [[ $extension_len -ne $j+4 ]] || [[ $j -lt 2 ]]; then
                               debugme echo "Malformed application layer protocol negotiation extension."
                               return 1
                          fi
                          let offset=$offset+4
                          j=2*$(hex2dec "${tls_serverhello_ascii:offset:2}")
                          if [[ $extension_len -ne $j+6 ]]; then
                               debugme echo "Malformed application layer protocol negotiation extension."
                               return 1
                          fi
                          let offset=$offset+2
                          asciihex_to_binary_file "${tls_serverhello_ascii:offset:j}" "$TMPFILE"
                          echo "" >> $TMPFILE
                          echo "===============================================================================" >> $TMPFILE
                          ;;
                    0011) tls_extensions+=" \"certificate status version 2/#17\"" ;;
                    0012) tls_extensions+=" \"signed certificate timestamps/#18\"" ;;
                    0013) tls_extensions+=" \"client certificate type/#19\"" ;;
                    0014) tls_extensions+=" \"server certificate type/#20\"" ;;
                    0015) tls_extensions+=" \"TLS padding/#21\"" ;;
                    0016) tls_extensions+=" \"encrypt-then-mac/#22\"" ;;
                    0017) tls_extensions+=" \"extended master secret/#23\"" ;;
                    0018) tls_extensions+=" \"token binding/#24\"" ;;
                    0019) tls_extensions+=" \"cached info/#25\"" ;;
                    0023) tls_extensions+=" \"session ticket/#35\"" ;;
                    0028) tls_extensions+=" \"key share/#40\"" ;;
                    0029) tls_extensions+=" \"pre-shared key/#41\"" ;;
                    002A) tls_extensions+=" \"early data/#42\"" ;;
                    002B) tls_extensions+=" \"supported versions/#43\"" ;;
                    002C) tls_extensions+=" \"cookie/#44\"" ;;
                    002D) tls_extensions+=" \"psk key exchange modes/#45\"" ;;
                    002E) tls_extensions+=" \"ticket early data info/#46\"" ;;
                    3374) tls_extensions+=" \"next protocol/#13172\""
                          local -i protocol_len
                          echo -n "Protocols advertised by server: " >> $TMPFILE
                          let offset=$extns_offset+12+$i
                          for (( j=0; j<extension_len; j=j+protocol_len+2 )); do
                               if [[ $extension_len -lt $j+2 ]]; then
                                    debugme echo "Malformed next protocol extension."
                                    return 1
                               fi
                               protocol_len=2*$(hex2dec "${tls_serverhello_ascii:offset:2}")
                               if [[ $extension_len -lt $j+$protocol_len+2 ]]; then
                                    debugme echo "Malformed next protocol extension."
                                    return 1
                               fi
                               let offset=$offset+2
                               asciihex_to_binary_file "${tls_serverhello_ascii:offset:protocol_len}" "$TMPFILE"
                               let offset=$offset+$protocol_len
                               [[ $j+$protocol_len+2 -lt $extension_len ]] && echo -n ", " >> $TMPFILE
                          done
                          echo "" >> $TMPFILE
                          echo "===============================================================================" >> $TMPFILE
                          ;;
                    FF01) tls_extensions+=" \"renegotiation info/#65281\"" ;;
                       *) tls_extensions+=" \"unrecognized extension/#$(printf "%d\n\n" "0x$extension_type")\"" ;;
               esac
          done
     fi

     if [[ "$tls_protocol2" == "0300" ]]; then
          echo "Protocol  : SSLv3" >> $TMPFILE
     else
          echo "Protocol  : TLSv1.$((0x$tls_protocol2-0x0301))" >> $TMPFILE
     fi
     echo "===============================================================================" >> $TMPFILE
     if [[ $TLS_NR_CIPHERS -ne 0 ]]; then
          if [[ "${tls_cipher_suite:0:2}" == "00" ]]; then
               rfc_cipher_suite="$(show_rfc_style "x${tls_cipher_suite:2:2}")"
          else
               rfc_cipher_suite="$(show_rfc_style "x${tls_cipher_suite:0:4}")"
          fi
     else
          rfc_cipher_suite="$($OPENSSL ciphers -V 'ALL:COMPLEMENTOFALL' | grep -i " 0x${tls_cipher_suite:0:2},0x${tls_cipher_suite:2:2} " | awk '{ print $3 }')"
     fi
     echo "Cipher    : $rfc_cipher_suite" >> $TMPFILE
     if [[ "0x${tls_protocol2:2:2}" -le "0x03" ]]; then
          case $tls_compression_method in
               00) echo "Compression: NONE" >> $TMPFILE ;;
               01) echo "Compression: zlib compression" >> $TMPFILE ;;
               40) echo "Compression: LZS compression" >> $TMPFILE ;;
                *) echo "Compression: unrecognized compression method" >> $TMPFILE ;;
          esac
          echo "===============================================================================" >> $TMPFILE
     fi
     [[ -n "$tls_extensions" ]] && echo "TLS Extensions: ${tls_extensions:1}" >> $TMPFILE

     if [[ $DEBUG -ge 2 ]]; then
          echo "TLS server hello message:"
          if [[ $DEBUG -ge 4 ]]; then
               echo "     tls_protocol:           0x$tls_protocol2"
               [[ "0x${tls_protocol2:2:2}" -le "0x03" ]] && echo "     tls_sid_len:            0x$tls_sid_len_hex / = $((tls_sid_len/2))"
          fi
          if [[ "0x${tls_protocol2:2:2}" -le "0x03" ]]; then
               echo -n "     tls_hello_time:         0x$tls_hello_time "
               parse_date "$TLS_TIME" "+%Y-%m-%d %r" "%s"
          fi
          echo "     tls_cipher_suite:       0x$tls_cipher_suite"
          if [[ "0x${tls_protocol2:2:2}" -le "0x03" ]]; then
               echo -n "     tls_compression_method: 0x$tls_compression_method "
               case $tls_compression_method in
                    00) echo "(NONE)" ;;
                    01) echo "(zlib compression)" ;;
                    40) echo "(LZS compression)" ;;
                     *) echo "(unrecognized compression method)" ;;
               esac
          fi
          if [[ -n "$tls_extensions" ]]; then
               echo "     tls_extensions:         ${tls_extensions:1}"
               if [[ "$tls_extensions" =~ "application layer protocol negotiation" ]]; then
                    echo "     ALPN protocol:          $(grep "ALPN protocol:" "$TMPFILE" | sed 's/ALPN protocol:  //')"
               fi
               if [[ "$tls_extensions" =~ "next protocol" ]]; then
                    echo "     NPN protocols:          $(grep "Protocols advertised by server:" "$TMPFILE" | sed 's/Protocols advertised by server: //')"
               fi
          fi
          outln
     fi

     # Now parse the Certificate message.
     if [[ "$process_full" == "all" ]]; then
          [[ -e "$HOSTCERT" ]] && rm "$HOSTCERT"
          [[ -e "$TEMPDIR/intermediatecerts.pem" ]] && rm "$TEMPDIR/intermediatecerts.pem"
     fi
     if [[ $tls_certificate_ascii_len -ne 0 ]]; then
          # The first certificate is the server's certificate. If there are anything
          # subsequent certificates, they are intermediate certificates.
          if [[ $tls_certificate_ascii_len -lt 12 ]]; then
               debugme echo "Malformed Certificate Handshake message in ServerHello."
               tmpfile_handle $FUNCNAME.txt
               return 1
          fi
          certificate_list_len=2*$(hex2dec "${tls_certificate_ascii:0:6}")
          if [[ $certificate_list_len -ne $tls_certificate_ascii_len-6 ]]; then
               debugme echo "Malformed Certificate Handshake message in ServerHello."
               tmpfile_handle $FUNCNAME.txt
               return 1
          fi

          # Place server's certificate in $HOSTCERT
          certificate_len=2*$(hex2dec "${tls_certificate_ascii:6:6}")
          if [[ $certificate_len -gt $tls_certificate_ascii_len-12 ]]; then
               debugme echo "Malformed Certificate Handshake message in ServerHello."
               tmpfile_handle $FUNCNAME.txt
               return 1
          fi
          tmp_der_certfile=$(mktemp $TEMPDIR/der_cert.XXXXXX) || return 1
          asciihex_to_binary_file "${tls_certificate_ascii:12:certificate_len}" "$tmp_der_certfile"
          $OPENSSL x509 -inform DER -in "$tmp_der_certfile" -outform PEM -out "$HOSTCERT" 2>$ERRFILE
          if [[ $? -ne 0 ]]; then
               debugme echo "Malformed certificate in Certificate Handshake message in ServerHello."
               rm "$tmp_der_certfile"
               tmpfile_handle $FUNCNAME.txt
               return 1
          fi
          rm "$tmp_der_certfile"
          get_pub_key_size
          echo "===============================================================================" >> $TMPFILE
          echo "---" >> $TMPFILE
          echo "Certificate chain" >> $TMPFILE
          subjectDN="$($OPENSSL x509 -in $HOSTCERT -noout -subject)"
          issuerDN="$($OPENSSL x509 -in $HOSTCERT -noout -issuer)"
          echo " $nr_certs s:${subjectDN:9}" >> $TMPFILE
          echo "   i:${issuerDN:8}" >> $TMPFILE
          cat "$HOSTCERT" >> $TMPFILE

          echo "" > "$TEMPDIR/intermediatecerts.pem"
          # Place any additional certificates in $TEMPDIR/intermediatecerts.pem
          for (( i=12+certificate_len; i<tls_certificate_ascii_len; i=i+certificate_len )); do
               if [[ $tls_certificate_ascii_len-$i -lt 6 ]]; then
                    debugme echo "Malformed Certificate Handshake message in ServerHello."
                    tmpfile_handle $FUNCNAME.txt
                    return 1
               fi
               certificate_len=2*$(hex2dec "${tls_certificate_ascii:i:6}")
               i+=6
               if [[ $certificate_len -gt $tls_certificate_ascii_len-$i ]]; then
                    debugme echo "Malformed certificate in Certificate Handshake message in ServerHello."
                    tmpfile_handle $FUNCNAME.txt
                    return 1
               fi
               tmp_der_certfile=$(mktemp $TEMPDIR/der_cert.XXXXXX) || return 1
               asciihex_to_binary_file "${tls_certificate_ascii:i:certificate_len}" "$tmp_der_certfile"
               tmp_pem_certfile=$(mktemp $TEMPDIR/pem_cert.XXXXXX) || return 1
               $OPENSSL x509 -inform DER -in "$tmp_der_certfile" -outform PEM -out "$tmp_pem_certfile" 2>$ERRFILE
               if [[ $? -ne 0 ]]; then
                    debugme echo "Malformed certificate in Certificate Handshake message in ServerHello."
                    rm "$tmp_der_certfile" "$tmp_pem_certfile"
                    tmpfile_handle $FUNCNAME.txt
                    return 1
               fi
               nr_certs+=1
               CAsubjectDN="$($OPENSSL x509 -in $tmp_pem_certfile -noout -subject)"
               CAissuerDN="$($OPENSSL x509 -in $tmp_pem_certfile -noout -issuer)"
               echo " $nr_certs s:${CAsubjectDN:9}" >> $TMPFILE
               echo "   i:${CAissuerDN:8}" >> $TMPFILE
               cat "$tmp_pem_certfile"  >> $TMPFILE
               cat "$tmp_pem_certfile" >> "$TEMPDIR/intermediatecerts.pem"
               rm "$tmp_der_certfile"
               if [[ -n "$hostcert_issuer" ]] || [[ $tls_certificate_status_ascii_len -eq 0 ]]; then
                    rm "$tmp_pem_certfile"
               else
                    hostcert_issuer="$tmp_pem_certfile"
               fi
          done
          echo "---" >> $TMPFILE
          echo "Server certificate" >> $TMPFILE
          echo "subject=${subjectDN:9}" >> $TMPFILE
          echo "issuer=${issuerDN:8}" >> $TMPFILE
          echo "---" >> $TMPFILE
     fi

     # Now parse the certificate status message
     if [[ $tls_certificate_status_ascii_len -ne 0 ]] && [[ $tls_certificate_status_ascii_len -lt 8 ]]; then
          debugme echo "Malformed certificate status Handshake message in ServerHello."
          tmpfile_handle $FUNCNAME.txt
          return 1
     elif [[ $tls_certificate_status_ascii_len -ne 0 ]] && [[ "${tls_certificate_status_ascii:0:2}" == "01" ]]; then
          # This is a certificate status message of type "ocsp"
          ocsp_response_len=2*$(hex2dec "${tls_certificate_status_ascii:2:6}")
          if [[ $ocsp_response_len -ne $tls_certificate_status_ascii_len-8 ]]; then
               debugme echo "Malformed certificate status Handshake message in ServerHello."
               tmpfile_handle $FUNCNAME.txt
               return 1
          fi
          ocsp_response=$(mktemp $TEMPDIR/ocsp_response.XXXXXX) || return 1
          asciihex_to_binary_file "${tls_certificate_status_ascii:8:ocsp_response_len}" "$ocsp_response"
     elif [[ $tls_certificate_status_ascii_len -ne 0 ]] && [[ "${tls_certificate_status_ascii:0:2}" == "02" ]]; then
          # This is a list of OCSP responses, but only the first one is needed
          # since the first one corresponds to the server's certificate.
          ocsp_response_list_len=2*$(hex2dec "${tls_certificate_status_ascii:2:6}")
          if [[ $ocsp_response_list_len -ne $tls_certificate_status_ascii_len-8 ]] || [[ $ocsp_response_list_len -lt 6 ]]; then
               debugme echo "Malformed certificate status Handshake message in ServerHello."
               tmpfile_handle $FUNCNAME.txt
               return 1
          fi
          ocsp_response_len=2*$(hex2dec "${tls_certificate_status_ascii:8:6}")
          if [[ $ocsp_response_len -gt $ocsp_response_list_len-6 ]]; then
               debugme echo "Malformed certificate status Handshake message in ServerHello."
               tmpfile_handle $FUNCNAME.txt
               return 1
          fi
          ocsp_response=$(mktemp $TEMPDIR/ocsp_response.XXXXXX) || return 1
          asciihex_to_binary_file "${tls_certificate_status_ascii:14:ocsp_response_len}" "$ocsp_response"
     fi
     if [[ -n "$ocsp_response" ]]; then
          echo "OCSP response:" >> $TMPFILE
          echo "===============================================================================" >> $TMPFILE
          if [[ -n "$hostcert_issuer" ]]; then
               $OPENSSL ocsp -no_nonce -CAfile $TEMPDIR/intermediatecerts.pem -issuer $hostcert_issuer -cert $HOSTCERT -respin $ocsp_response -resp_text >> $TMPFILE 2>$ERRFILE
               rm "$hostcert_issuer"
          else
               $OPENSSL ocsp -respin $ocsp_response -resp_text >> $TMPFILE 2>$ERRFILE
          fi
          echo "===============================================================================" >> $TMPFILE
     elif [[ "$process_full" == "all" ]]; then
          echo "OCSP response: no response sent" >> $TMPFILE
          echo "===============================================================================" >> $TMPFILE
     fi

     # Now parse the server key exchange message
     if [[ $tls_serverkeyexchange_ascii_len -ne 0 ]]; then
          if [[ $rfc_cipher_suite =~ "TLS_ECDHE_" ]] || [[ $rfc_cipher_suite =~ "TLS_ECDH_anon" ]] || \
             [[ $rfc_cipher_suite == ECDHE* ]] || [[ $rfc_cipher_suite == AECDH* ]]; then
               if [[ $tls_serverkeyexchange_ascii_len -lt 6 ]]; then
                    debugme echo "Malformed ServerKeyExchange Handshake message in ServerHello."
                    tmpfile_handle $FUNCNAME.txt
                    return 1
               fi
               curve_type=$(hex2dec "${tls_serverkeyexchange_ascii:0:2}")
               if [[ $curve_type -eq 3 ]]; then
                    # named_curve - the curve is identified by a 2-byte number
                    named_curve=$(hex2dec "${tls_serverkeyexchange_ascii:2:4}")
                    # http://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml#tls-parameters-8
                    case $named_curve in
                         1) dh_bits=163 ; named_curve_str="K-163" ;;
                         2) dh_bits=162 ; named_curve_str="sect163r1" ;;
                         3) dh_bits=163 ; named_curve_str="B-163" ;;
                         4) dh_bits=193 ; named_curve_str="sect193r1" ;;
                         5) dh_bits=193 ; named_curve_str="sect193r2" ;;
                         6) dh_bits=232 ; named_curve_str="K-233" ;;
                         7) dh_bits=233 ; named_curve_str="B-233" ;;
                         8) dh_bits=238 ; named_curve_str="sect239k1" ;;
                         9) dh_bits=281 ; named_curve_str="K-283" ;;
                         10) dh_bits=282 ; named_curve_str="B-283" ;;
                         11) dh_bits=407 ; named_curve_str="K-409" ;;
                         12) dh_bits=409 ; named_curve_str="B-409" ;;
                         13) dh_bits=570 ; named_curve_str="K-571" ;;
                         14) dh_bits=570 ; named_curve_str="B-571" ;;
                         15) dh_bits=161 ; named_curve_str="secp160k1" ;;
                         16) dh_bits=161 ; named_curve_str="secp160r1" ;;
                         17) dh_bits=161 ; named_curve_str="secp160r2" ;;
                         18) dh_bits=192 ; named_curve_str="secp192k1" ;;
                         19) dh_bits=192 ; named_curve_str="P-192" ;;
                         20) dh_bits=225 ; named_curve_str="secp224k1" ;;
                         21) dh_bits=224 ; named_curve_str="P-224" ;;
                         22) dh_bits=256 ; named_curve_str="secp256k1" ;;
                         23) dh_bits=256 ; named_curve_str="P-256" ;;
                         24) dh_bits=384 ; named_curve_str="P-384" ;;
                         25) dh_bits=521 ; named_curve_str="P-521" ;;
                         26) dh_bits=256 ; named_curve_str="brainpoolP256r1" ;;
                         27) dh_bits=384 ; named_curve_str="brainpoolP384r1" ;;
                         28) dh_bits=512 ; named_curve_str="brainpoolP512r1" ;;
                         29) dh_bits=253 ; named_curve_str="X25519" ;;
                         30) dh_bits=448 ; named_curve_str="X448" ;;
                    esac
               fi
               if [[ $dh_bits -ne 0 ]] && [[ $named_curve -ne 29 ]] && [[ $named_curve -ne 30 ]]; then
                    debugme echo "dh_bits:                ECDH, $named_curve_str, $dh_bits bits"
                    echo "Server Temp Key: ECDH, $named_curve_str, $dh_bits bits" >> $TMPFILE
               elif [[ $dh_bits -ne 0 ]]; then
                    debugme echo "dh_bits:                $named_curve_str, $dh_bits bits"
                    echo "Server Temp Key: $named_curve_str, $dh_bits bits" >> $TMPFILE
               fi
          elif [[ $rfc_cipher_suite =~ "TLS_DHE_" ]] || [[ $rfc_cipher_suite =~ "TLS_DH_anon" ]] || \
               [[ $rfc_cipher_suite == "DHE-"* ]] || [[ $rfc_cipher_suite == "EDH-"* ]] || \
               [[ $rfc_cipher_suite == "EXP1024-DHE-"* ]]; then
               # For DH ephemeral keys the first field is p, and the length of
               # p is the same as the length of the public key.
               if [[ $tls_serverkeyexchange_ascii_len -lt 4 ]]; then
                    debugme echo "Malformed ServerKeyExchange Handshake message in ServerHello."
                    tmpfile_handle $FUNCNAME.txt
                    return 1
               fi
               dh_p_len=2*$(hex2dec "${tls_serverkeyexchange_ascii:0:4}")
               offset=4+$dh_p_len
               if [[ $tls_serverkeyexchange_ascii_len -lt $offset ]]; then
                    debugme echo "Malformed ServerKeyExchange Handshake message in ServerHello."
                    tmpfile_handle $FUNCNAME.txt
                    return 1
               fi

               # Subtract any leading 0 bytes
               for (( i=4; i < offset; i=i+2 )); do
                    [[ "${tls_serverkeyexchange_ascii:i:2}" != "00" ]] && break
                    dh_p_len=$dh_p_len-2
               done
               if [[ $i -ge $offset ]]; then
                    debugme echo "Malformed ServerKeyExchange Handshake message in ServerHello."
                    tmpfile_handle $FUNCNAME.txt
                    return 1
               fi
               dh_p="${tls_serverkeyexchange_ascii:i:dh_p_len}"

               dh_bits=4*$dh_p_len
               msb=$(hex2dec "${tls_serverkeyexchange_ascii:i:2}")
               for (( mask=128; msb < mask; mask/=2 )); do
                    dh_bits=$dh_bits-1
               done

               key_bitstring="$(get_dh_ephemeralkey "$tls_serverkeyexchange_ascii")"
               [[ $? -eq 0 ]] && echo "$key_bitstring" >> $TMPFILE

               # Check to see whether the ephemeral public key uses one of the groups from
               # RFC 7919 for parameters
               case $dh_bits in
                    2048) named_curve=256; named_curve_str=" ffdhe2048," ;;
                    3072) named_curve=257; named_curve_str=" ffdhe3072," ;;
                    4096) named_curve=258; named_curve_str=" ffdhe4096," ;;
                    6144) named_curve=259; named_curve_str=" ffdhe6144," ;;
                    8192) named_curve=260; named_curve_str=" ffdhe8192," ;;
                       *) named_curve=0;   named_curve_str="" ;;
               esac
               [[ -z "$key_bitstring" ]] && named_curve=0 && named_curve_str=""
               if [[ $named_curve -ne 0 ]] && [[ "${TLS13_KEY_SHARES[named_curve]}" =~ "BEGIN" ]]; then
                    ephemeral_param="$($OPENSSL pkey -pubin -text -noout <<< "$key_bitstring" | grep -A 1000 "prime:")"
                    rfc7919_param="$($OPENSSL pkey -text -noout <<< "${TLS13_KEY_SHARES[named_curve]}" | grep -A 1000 "prime:")"
                    [[ "$ephemeral_param" != "$rfc7919_param" ]] && named_curve_str=""
               fi

               [[ $DEBUG -ge 2 ]] && [[ $dh_bits -ne 0 ]] && echo "dh_bits:                DH,$named_curve_str $dh_bits bits"
               [[ $dh_bits -ne 0 ]] && echo "Server Temp Key: DH,$named_curve_str $dh_bits bits" >> $TMPFILE
          fi
     fi
     tmpfile_handle $FUNCNAME.txt
     return 0
}


#arg1: list of ciphers suites or empty
#arg2: "true" if full server response should be parsed.
sslv2_sockets() {
     local ret
     local client_hello cipher_suites len_client_hello
     local len_ciph_suites_byte len_ciph_suites
     local server_hello sock_reply_file2
     local -i response_len server_hello_len
     local parse_complete=false

     if [[ "$2" == "true" ]]; then
          parse_complete=true
     fi

     if [[ -n "$1" ]]; then
          cipher_suites="$1"
     else
          cipher_suites="
          05,00,80, # 1st cipher   9 cipher specs, only classical V2 ciphers are used here, see  FIXME below
          03,00,80, # 2nd          there are v3 in v2!!! : https://tools.ietf.org/html/rfc6101#appendix-E
          01,00,80, # 3rd          Cipher specifications introduced in version 3.0 can be included in version 2.0 client hello messages using
          07,00,c0, # 4th          the syntax below. [..] # V2CipherSpec (see Version 3.0 name) = { 0x00, CipherSuite }; !!!!
          08,00,80, # 5th
          06,00,40, # 6th
          04,00,80, # 7th
          02,00,80, # 8th
          00,00,00" # 9th
          # FIXME: http://max.euston.net/d/tip_sslciphers.html
     fi

     code2network "$cipher_suites" # convert CIPHER_SUITES
     cipher_suites="$NW_STR"       # we don't have the leading \x here so string length is two byte less, see next
     len_ciph_suites_byte=$(echo ${#cipher_suites})
     let "len_ciph_suites_byte += 2"
     len_ciph_suites=$(printf "%02x\n" $(($len_ciph_suites_byte / 4 )))
     len_client_hello=$(printf "%02x\n" $((0x$len_ciph_suites + 0x19)))

     client_hello="
     ,80,$len_client_hello         # length
     ,01                           # Client Hello
     ,00,02                        # SSLv2
     ,00,$len_ciph_suites          # cipher spec length
     ,00,00                        # session ID length
     ,00,10                        # challenge length
     ,$cipher_suites
     ,29,22,be,b3,5a,01,8b,04,fe,5f,80,03,a0,13,eb,c4" # Challenge
     # https://idea.popcount.org/2012-06-16-dissecting-ssl-handshake/ (client)

     fd_socket 5 || return 6
     debugme outln "sending client hello... "
     socksend_sslv2_clienthello "$client_hello"

     sockread_serverhello 32768
     if "$parse_complete"; then
          server_hello=$(hexdump -v -e '16/1 "%02X"' "$SOCK_REPLY_FILE")
          server_hello_len=2+$(hex2dec "${server_hello:1:3}")
          response_len=$(wc -c "$SOCK_REPLY_FILE" | awk '{ print $1 }')
          for (( 1; response_len < server_hello_len; 1 )); do
               sock_reply_file2=$(mktemp $TEMPDIR/ddreply.XXXXXX) || return 7
               mv "$SOCK_REPLY_FILE" "$sock_reply_file2"

               debugme echo "requesting more server hello data..."
               socksend "" $USLEEP_SND
               sockread_serverhello 32768

               [[ ! -s "$SOCK_REPLY_FILE" ]] && break
               cat "$SOCK_REPLY_FILE" >> "$sock_reply_file2"
               mv "$sock_reply_file2" "$SOCK_REPLY_FILE"
               response_len=$(wc -c "$SOCK_REPLY_FILE" | awk '{ print $1 }')
          done
     fi
     debugme outln "reading server hello... "
     if [[ "$DEBUG" -ge 4 ]]; then
          hexdump -C "$SOCK_REPLY_FILE" | head -6
          outln
     fi

     parse_sslv2_serverhello "$SOCK_REPLY_FILE" "$parse_complete"
     ret=$?

     close_socket
     TMPFILE=$SOCK_REPLY_FILE
     tmpfile_handle $FUNCNAME.dd
     return $ret
}


# ARG1: TLS version low byte (00: SSLv3,  01: TLS 1.0,  02: TLS 1.1,  03: TLS 1.2)
# ARG2: CIPHER_SUITES string
# ARG3: (optional) additional request extensions
# ARG4: (optional): "true" if ClientHello should advertise compression methods other than "NULL"
socksend_tls_clienthello() {
     local tls_low_byte="$1"
     local tls_word_reclayer="03, 01"      # the first TLS version number is the record layer and always 0301 -- except: SSLv3
     local servername_hexstr len_servername len_servername_hex
     local hexdump_format_str part1 part2
     local all_extensions=""
     local -i i j len_extension len_padding_extension len_all
     local len_sni_listlen len_sni_ext len_extension_hex len_padding_extension_hex
     local cipher_suites len_ciph_suites len_ciph_suites_byte len_ciph_suites_word
     local len_client_hello_word len_all_word
     local ecc_cipher_suite_found=false
     local extension_signature_algorithms extension_heartbeat
     local extension_session_ticket extension_next_protocol extension_padding
     local extension_supported_groups="" extension_supported_point_formats=""
     local extra_extensions extra_extensions_list=""
     local offer_compression=false compression_metods

     # TLSv1.3 ClientHello messages MUST specify only the NULL compression method.
     [[ "$4" == "true" ]] && [[ "0x$tls_low_byte" -le "0x03" ]] && offer_compression=true

     code2network "$(tolower "$2")"               # convert CIPHER_SUITES
     cipher_suites="$NW_STR"                      # we don't have the leading \x here so string length is two byte less, see next

     len_ciph_suites_byte=$(echo ${#cipher_suites})
     let "len_ciph_suites_byte += 2"

     # we have additional 2 chars \x in each 2 byte string and 2 byte ciphers, so we need to divide by 4:
     len_ciph_suites=$(printf "%02x\n" $(($len_ciph_suites_byte / 4 )))
     len2twobytes "$len_ciph_suites"
     len_ciph_suites_word="$LEN_STR"
     #[[ $DEBUG -ge 3 ]] && echo $len_ciph_suites_word

     if [[ "$tls_low_byte" != "00" ]]; then
          # Add extensions

          # Check to see if any ECC cipher suites are included in cipher_suites
          for (( i=0; i<len_ciph_suites_byte; i=i+8 )); do
               j=$i+4
               part1="0x${cipher_suites:$i:2}"
               part2="0x${cipher_suites:$j:2}"
               if [[ "$part1" == "0xc0" ]]; then
                    if [[ "$part2" -ge "0x01" ]] && [[ "$part2" -le "0x19" ]]; then
                         ecc_cipher_suite_found=true && break
                    elif [[ "$part2" -ge "0x23" ]] && [[ "$part2" -le "0x3b" ]]; then
                         ecc_cipher_suite_found=true && break
                    elif [[ "$part2" -ge "0x48" ]] && [[ "$part2" -le "0x4f" ]]; then
                         ecc_cipher_suite_found=true && break
                    elif [[ "$part2" -ge "0x5c" ]] && [[ "$part2" -le "0x63" ]]; then
                         ecc_cipher_suite_found=true && break
                    elif [[ "$part2" -ge "0x70" ]] && [[ "$part2" -le "0x79" ]]; then
                         ecc_cipher_suite_found=true && break
                    elif [[ "$part2" -ge "0x86" ]] && [[ "$part2" -le "0x8d" ]]; then
                         ecc_cipher_suite_found=true && break
                    elif [[ "$part2" -ge "0x9a" ]] && [[ "$part2" -le "0x9b" ]]; then
                         ecc_cipher_suite_found=true && break
                    elif [[ "$part2" -ge "0xac" ]] && [[ "$part2" -le "0xaf" ]]; then
                         ecc_cipher_suite_found=true && break
                    fi
               elif [[ "$part1" == "0xcc" ]]; then
                    if [[ "$part2" == "0xa8" ]] || [[ "$part2" == "0xa9" ]] || [[ "$part2" == "0xac" ]] || [[ "$part2" == "0x13" ]] || [[ "$part2" == "0x14" ]]; then
                         ecc_cipher_suite_found=true && break
                    fi
               fi
          done

          if [[ -n "$SNI" ]]; then
               #formatted example for SNI
               #00 00    # extension server_name
               #00 1a    # length                      = the following +2 = server_name length + 5
               #00 18    # server_name list_length     = server_name length +3
               #00       # server_name type (hostname)
               #00 15    # server_name length
               #66 66 66 66 66 66 2e 66 66 66 66 66 66 66 66 66 66 2e 66 66 66  target.mydomain1.tld # server_name target
               len_servername=${#NODE}
               hexdump_format_str="$len_servername/1 \"%02x,\""
               servername_hexstr=$(printf $NODE | hexdump -v -e "${hexdump_format_str}" | sed 's/,$//')
               # convert lengths we need to fill in from dec to hex:
               len_servername_hex=$(printf "%02x\n" $len_servername)
               len_sni_listlen=$(printf "%02x\n" $((len_servername+3)))
               len_sni_ext=$(printf "%02x\n" $((len_servername+5)))
          fi

          extension_signature_algorithms="
          00, 0d,                    # Type: signature_algorithms , see RFC 5246
          00, 20,                    # len
          00,1e, 06,01, 06,02, 06,03, 05,01, 05,02, 05,03,
          04,01, 04,02, 04,03, 03,01, 03,02, 03,03, 02,01, 02,02, 02,03"

          extension_heartbeat="
          00, 0f, 00, 01, 01"

          extension_session_ticket="
          00, 23, 00, 00"

          extension_next_protocol="
          33, 74, 00, 00"

          if "$ecc_cipher_suite_found"; then
               # Supported Groups Extension
               extension_supported_groups="
               00, 0a,                    # Type: Supported Elliptic Curves , see RFC 4492
               00, 3e, 00, 3c,            # lengths
               00, 0e, 00, 0d, 00, 19, 00, 1c, 00, 1e, 00, 0b, 00, 0c, 00, 1b,
               00, 18, 00, 09, 00, 0a, 00, 1a, 00, 16, 00, 17, 00, 1d, 00, 08,
               00, 06, 00, 07, 00, 14, 00, 15, 00, 04, 00, 05, 00, 12, 00, 13,
               00, 01, 00, 02, 00, 03, 00, 0f, 00, 10, 00, 11"
               # Supported Point Formats Extension
               extension_supported_point_formats="
               00, 0b,                    # Type: Supported Point Formats , see RFC 4492
               00, 02,                    # len
               01, 00"
          fi

          # Each extension should appear in the ClientHello at most once. So,
          # find out what extensions were provided as an argument and only use
          # the provided values for those extensions.
          extra_extensions="$(echo "$3" | tr 'A-Z' 'a-z')"
          code2network "$extra_extensions"
          len_all=${#extra_extensions}
          for (( i=0; i < len_all; i=i+16+4*0x$len_extension_hex )); do
               part2=$i+4
               extra_extensions_list+=" ${NW_STR:i:2}${NW_STR:part2:2} "
               j=$i+8
               part2=$j+4
               len_extension_hex="${NW_STR:j:2}${NW_STR:part2:2}"
          done

          if [[ -n "$SNI" ]] && [[ ! "$extra_extensions_list" =~ " 0000 " ]]; then
               all_extensions="
                00, 00                  # extension server_name
               ,00, $len_sni_ext        # length SNI EXT
               ,00, $len_sni_listlen    # server_name list_length
               ,00                      # server_name type (hostname)
               ,00, $len_servername_hex # server_name length. We assume len(hostname) < FF - 9
               ,$servername_hexstr"     # server_name target
          fi
          if [[ ! "$extra_extensions_list" =~ " 000f " ]]; then
               [[ -n "$all_extensions" ]] && all_extensions+=","
               all_extensions+="$extension_heartbeat"
          fi
          if [[ ! "$extra_extensions_list" =~ " 0023 " ]]; then
               [[ -n "$all_extensions" ]] && all_extensions+=","
               all_extensions+="$extension_session_ticket"
          fi

          # If the ClientHello will include the ALPN extension, then don't include the NPN extension.
          if [[ ! "$extra_extensions_list" =~ " 3374 " ]] && [[ ! "$extra_extensions_list" =~ " 0010 " ]]; then
               [[ -n "$all_extensions" ]] && all_extensions+=","
               all_extensions+="$extension_next_protocol"
          fi

          # RFC 5246 says that clients MUST NOT offer the signature algorithms
          # extension if they are offering TLS versions prior to 1.2.
          if [[ "0x$tls_low_byte" -ge "0x03" ]] && [[ ! "$extra_extensions_list" =~ " 000d " ]]; then
               [[ -n "$all_extensions" ]] && all_extensions+=","
               all_extensions+="$extension_signature_algorithms"
          fi

          if [[ -n "$extension_supported_groups" ]] && [[ ! "$extra_extensions_list" =~ " 000a " ]]; then
               [[ -n "$all_extensions" ]] && all_extensions+=","
               all_extensions+="$extension_supported_groups"
          fi
          if [[ -n "$extension_supported_point_formats" ]] && [[ ! "$extra_extensions_list" =~ " 000b " ]]; then
               [[ -n "$all_extensions" ]] && all_extensions+=","
               all_extensions+="$extension_supported_point_formats"
          fi

          if [[ -n "$extra_extensions" ]]; then
               [[ -n "$all_extensions" ]] && all_extensions+=","
               all_extensions+="$extra_extensions"
          fi

          code2network "$all_extensions" # convert extensions
          all_extensions="$NW_STR"       # we don't have the leading \x here so string length is two byte less, see next
          len_extension=${#all_extensions}
          len_extension+=2
          len_extension=$len_extension/4
          len_extension_hex=$(printf "%02x\n" $len_extension)

          # If the length of the Client Hello would be between 256 and 511 bytes,
          # then add a padding extension (see RFC 7685)
          len_all=$((0x$len_ciph_suites + 0x2b + 0x$len_extension_hex + 0x2))
          "$offer_compression" && len_all+=2
          if [[ $len_all -ge 256 ]] && [[ $len_all -le 511 ]] && [[ ! "$extra_extensions_list" =~ " 0015 " ]]; then
               if [[ $len_all -gt 508 ]]; then
                    len_padding_extension=0
               else
                    len_padding_extension=$((508 - 0x$len_ciph_suites - 0x2b - 0x$len_extension_hex - 0x2))
               fi
               len_padding_extension_hex=$(printf "%02x\n" $len_padding_extension)
               len2twobytes "$len_padding_extension_hex"
               all_extensions="$all_extensions\\x00\\x15\\x${LEN_STR:0:2}\\x${LEN_STR:4:2}"
               for (( i=0; i<len_padding_extension; i++ )); do
                    all_extensions="$all_extensions\\x00"
               done
               len_extension=$len_extension+$len_padding_extension+0x4
               len_extension_hex=$(printf "%02x\n" $len_extension)
          fi
          len2twobytes "$len_extension_hex"
          all_extensions="
          ,$LEN_STR  # first the len of all extentions.
          ,$all_extensions"

     fi

     # RFC 3546 doesn't specify SSLv3 to have SNI, openssl just ignores the switch if supplied
     if [[ "$tls_low_byte" == "00" ]]; then
          len_all=$((0x$len_ciph_suites + 0x27))
     else
          len_all=$((0x$len_ciph_suites + 0x27 + 0x$len_extension_hex + 0x2))
     fi
     "$offer_compression" && len_all+=2
     len2twobytes $(printf "%02x\n" $len_all)
     len_client_hello_word="$LEN_STR"
     #[[ $DEBUG -ge 3 ]] && echo $len_client_hello_word

     if [[ "$tls_low_byte" == "00" ]]; then
          len_all=$((0x$len_ciph_suites + 0x2b))
     else
          len_all=$((0x$len_ciph_suites + 0x2b + 0x$len_extension_hex + 0x2))
     fi
     "$offer_compression" && len_all+=2
     len2twobytes $(printf "%02x\n" $len_all)
     len_all_word="$LEN_STR"
     #[[ $DEBUG -ge 3 ]] && echo $len_all_word

     # if we have SSLv3, the first occurence of TLS protocol -- record layer -- is SSLv3, otherwise TLS 1.0
     [[ $tls_low_byte == "00" ]] && tls_word_reclayer="03, 00"

     if "$offer_compression"; then
          # See http://www.iana.org/assignments/comp-meth-ids/comp-meth-ids.xhtml#comp-meth-ids-2
          compression_metods="03,01,40,00" # Offer NULL, DEFLATE, and LZS compression
     else
          compression_metods="01,00" # Only offer NULL compression (0x00)
     fi

     TLS_CLIENT_HELLO="
     # TLS header ( 5 bytes)
     ,16, $tls_word_reclayer  # TLS Version: in wireshark this is always 01 for TLS 1.0-1.2
     ,$len_all_word           # Length  <---
     # Handshake header:
     ,01                      # Type (x01 for ClientHello)
     ,00, $len_client_hello_word   # Length ClientHello
     ,03, $tls_low_byte       # TLS version ClientHello
     ,54, 51, 1e, 7a          # Unix time since  see www.moserware.com/2009/06/first-few-milliseconds-of-https.html
     ,de, ad, be, ef          # Random 28 bytes
     ,31, 33, 07, 00, 00, 00, 00, 00
     ,cf, bd, 39, 04, cc, 16, 0a, 85
     ,03, 90, 9f, 77, 04, 33, d4, de
     ,00                      # Session ID length
     ,$len_ciph_suites_word   # Cipher suites length
     ,$cipher_suites
     ,$compression_metods"

     fd_socket 5 || return 6

     code2network "$TLS_CLIENT_HELLO$all_extensions"
     data=$(echo $NW_STR)
     [[ "$DEBUG" -ge 4 ]] && echo "\"$data\""
     printf -- "$data" >&5 2>/dev/null &
     sleep $USLEEP_SND

     return 0
}

# arg1: TLS version low byte
#       (00: SSLv3,  01: TLS 1.0,  02: TLS 1.1,  03: TLS 1.2)
# arg2: (optional) list of cipher suites
# arg3: (optional): "all" - process full response (including Certificate and certificate_status handshake messages)
#                   "ephemeralkey" - extract the server's ephemeral key (if any)
# arg4: (optional) additional request extensions
# arg5: (optional) "true" if ClientHello should advertise compression methods other than "NULL"
tls_sockets() {
     local -i ret=0
     local -i save=0
     local lines
     local tls_low_byte
     local cipher_list_2send
     local sock_reply_file2 sock_reply_file3
     local tls_hello_ascii next_packet hello_done=0
     local process_full="$3" offer_compression=false

     [[ "$5" == "true" ]] && offer_compression=true
     tls_low_byte="$1"
     if [[ -n "$2" ]]; then             # use supplied string in arg2 if there is one
          cipher_list_2send="$2"
     else                               # otherwise use std ciphers then
          if [[ "$tls_low_byte" == "03" ]]; then
               cipher_list_2send="$TLS12_CIPHER"
          else
               cipher_list_2send="$TLS_CIPHER"
          fi
     fi

     debugme echo "sending client hello..."
     socksend_tls_clienthello "$tls_low_byte" "$cipher_list_2send" "$4" "$offer_compression"
     ret=$?                             # 6 means opening socket didn't succeed, e.g. timeout

     # if sending didn't succeed we don't bother
     if [[ $ret -eq 0 ]]; then
          sockread_serverhello 32768
          TLS_NOW=$(LC_ALL=C date "+%s")

          tls_hello_ascii=$(hexdump -v -e '16/1 "%02X"' "$SOCK_REPLY_FILE")
          tls_hello_ascii="${tls_hello_ascii%%[!0-9A-F]*}"

          # The server's response may span more than one packet. So,
          # check if response appears to be complete, and if it isn't
          # then try to get another packet from the server.
          if [[ "$process_full" == "all" ]] || [[ "$process_full" == "ephemeralkey" ]]; then
               check_tls_serverhellodone "$tls_hello_ascii"
               hello_done=$?
               [[ "$hello_done" -eq 3 ]] && process_full="ephemeralkey"
          fi
          for (( 1 ; hello_done==1; 1 )); do
               sock_reply_file2=$(mktemp $TEMPDIR/ddreply.XXXXXX) || return 7
               mv "$SOCK_REPLY_FILE" "$sock_reply_file2"

               debugme echo "requesting more server hello data..."
               socksend "" $USLEEP_SND
               sockread_serverhello 32768

               next_packet=$(hexdump -v -e '16/1 "%02X"' "$SOCK_REPLY_FILE")
               next_packet="${next_packet%%[!0-9A-F]*}"
               if [[ ${#next_packet} -eq 0 ]]; then
                    # This shouldn't be necessary. However, it protects against
                    # getting into an infinite loop if the server has nothing
                    # left to send and check_tls_serverhellodone doesn't
                    # correctly catch it.
                    mv "$sock_reply_file2" "$SOCK_REPLY_FILE"
                    hello_done=0
               else
                    tls_hello_ascii+="$next_packet"

                    sock_reply_file3=$(mktemp $TEMPDIR/ddreply.XXXXXX) || return 7
                    mv "$SOCK_REPLY_FILE" "$sock_reply_file3"
                    mv "$sock_reply_file2" "$SOCK_REPLY_FILE"
                    cat "$sock_reply_file3" >> "$SOCK_REPLY_FILE"
                    rm "$sock_reply_file3"

                    check_tls_serverhellodone "$tls_hello_ascii"
                    hello_done=$?
                    [[ "$hello_done" -eq 3 ]] && process_full="ephemeralkey"
               fi
          done

          debugme outln "reading server hello..."
          if [[ "$DEBUG" -ge 4 ]]; then
               hexdump -C $SOCK_REPLY_FILE | head -6
               echo
          fi

          parse_tls_serverhello "$tls_hello_ascii" "$process_full"
          save=$?

          if [[ $save == 0 ]]; then
               debugme echo "sending close_notify..."
               if [[ "$DETECTED_TLS_VERSION" == "0300" ]]; then
                    socksend ",x15, x03, x00, x00, x02, x02, x00" 0
               else
                    socksend ",x15, x03, x01, x00, x02, x02, x00" 0
               fi
          fi

          # see https://secure.wand.net.nz/trac/libprotoident/wiki/SSL
          lines=$(count_lines "$(hexdump -C "$SOCK_REPLY_FILE" 2>$ERRFILE)")
          debugme out "  (returned $lines lines)  "

          # determine the return value for higher level, so that they can tell what the result is
          if [[ $save -eq 1 ]] || [[ $lines -eq 1 ]]; then
               ret=1          # NOT available
          else
               if [[ 03$tls_low_byte -eq $DETECTED_TLS_VERSION ]]; then
                    ret=0     # protocol available, TLS version returned equal to the one send
               else
                    [[ $DEBUG -ge 2 ]] && echo -n "protocol send: 0x03$tls_low_byte, returned: 0x$DETECTED_TLS_VERSION"
                    ret=2     # protocol NOT available, server downgraded to $DETECTED_TLS_VERSION
               fi
          fi
          debugme outln
     else
          debugme echo "stuck on sending: $ret"
     fi

     close_socket
     TMPFILE=$SOCK_REPLY_FILE
     tmpfile_handle $FUNCNAME.dd
     return $ret
}


####### vulnerabilities follow #######

# general overview which browser "supports" which vulnerability:
# http://en.wikipedia.org/wiki/Transport_Layer_Security-SSL#Web_browsers


# mainly adapted from https://gist.github.com/takeshixx/10107280
run_heartbleed(){
     local tls_proto_offered tls_hexcode
     local heartbleed_payload client_hello
     local -i n ret lines_returned
     local -i hb_rounds=3
     local append=""
     local tls_hello_ascii=""
     local cve="CVE-2014-0160"
     local cwe="CWE-119"
     local hint=""

     [[ $VULN_COUNT -le $VULN_THRESHLD ]] && outln && pr_headlineln " Testing for heartbleed vulnerability " && outln
     pr_bold " Heartbleed"; out " ($cve)                "

     [[ -z "$TLS_EXTENSIONS" ]] && determine_tls_extensions
     if ! grep -q heartbeat <<< "$TLS_EXTENSIONS"; then
          pr_done_best "not vulnerable (OK)"
          outln ", no heartbeat extension"
          fileout "heartbleed" "OK" "Heartbleed: not vulnerable, no heartbeat extension" "$cve" "$cwe"
          return 0
     fi

     # determine TLS versions offered <-- needs to come from another place
     $OPENSSL s_client $STARTTLS $BUGS -connect $NODEIP:$PORT $PROXY -tlsextdebug >$TMPFILE 2>$ERRFILE </dev/null

     if "$HAS_SED_E"; then
          tls_proto_offered=$(grep -aw Protocol $TMPFILE | sed -E 's/[^[:digit:]]//g')
     else
          tls_proto_offered=$(grep -aw Protocol $TMPFILE | sed -r 's/[^[:digit:]]//g')
     fi
#FIXME: for SSLv3 only we need to set tls_hexcode and the record layer TLS version correctly
     case $tls_proto_offered in
          12)  tls_hexcode="x03, x03" ;;
          11)  tls_hexcode="x03, x02" ;;
          *) tls_hexcode="x03, x01" ;;
     esac
     heartbleed_payload=", x18, $tls_hexcode, x00, x03, x01, x40, x00"

     client_hello="
     # TLS header ( 5 bytes)
     ,x16,                      # content type (x16 for handshake)
     x03, x01,                  # TLS record layer version
     x00, xdc,                  # length
     # Handshake header
     x01,                       # type (x01 for ClientHello)
     x00, x00, xd8,             # length
     $tls_hexcode,              # TLS version
     # Random (32 byte)
     x53, x43, x5b, x90, x9d, x9b, x72, x0b,
     xbc, x0c, xbc, x2b, x92, xa8, x48, x97,
     xcf, xbd, x39, x04, xcc, x16, x0a, x85,
     x03, x90, x9f, x77, x04, x33, xd4, xde,
     x00,                       # session ID length
     x00, x66,                  # cipher suites length
                                # cipher suites (51 suites)
     xc0, x14, xc0, x0a, xc0, x22, xc0, x21,
     x00, x39, x00, x38, x00, x88, x00, x87,
     xc0, x0f, xc0, x05, x00, x35, x00, x84,
     xc0, x12, xc0, x08, xc0, x1c, xc0, x1b,
     x00, x16, x00, x13, xc0, x0d, xc0, x03,
     x00, x0a, xc0, x13, xc0, x09, xc0, x1f,
     xc0, x1e, x00, x33, x00, x32, x00, x9a,
     x00, x99, x00, x45, x00, x44, xc0, x0e,
     xc0, x04, x00, x2f, x00, x96, x00, x41,
     xc0, x11, xc0, x07, xc0, x0c, xc0, x02,
     x00, x05, x00, x04, x00, x15, x00, x12,
     x00, x09, x00, x14, x00, x11, x00, x08,
     x00, x06, x00, x03, x00, xff,
     x01,                       # compression methods length
     x00,                       # compression method (x00 for NULL)
     x00, x49,                  # extensions length
     # extension: ec_point_formats
     x00, x0b, x00, x04, x03, x00, x01, x02,
     # extension: elliptic_curves
     x00, x0a, x00, x34, x00, x32, x00, x0e,
     x00, x0d, x00, x19, x00, x0b, x00, x0c,
     x00, x18, x00, x09, x00, x0a, x00, x16,
     x00, x17, x00, x08, x00, x06, x00, x07,
     x00, x14, x00, x15, x00, x04, x00, x05,
     x00, x12, x00, x13, x00, x01, x00, x02,
     x00, x03, x00, x0f, x00, x10, x00, x11,
     # extension: session ticket TLS
     x00, x23, x00, x00,
     # extension: heartbeat
     x00, x0f, x00, x01, x01"

     fd_socket 5 || return 6
     debugme out "\nsending client hello (TLS version $tls_hexcode)"
     debugme outln " ($n of $hb_rounds)"
     socksend "$client_hello" 1

     debugme outln "\nreading server hello"
     sockread_serverhello 32768
     if [[ $DEBUG -ge 4 ]]; then
          hexdump -C "$SOCK_REPLY_FILE" | head -20
          outln "[...]"
          outln "\nsending payload with TLS version $tls_hexcode:"
     fi
     rm "$SOCK_REPLY_FILE"

     socksend "$heartbleed_payload" 1
     sockread_serverhello 16384 $HEARTBLEED_MAX_WAITSOCK
     if [[ $? -eq 3 ]]; then
          append=", timed out"
          pr_done_best "not vulnerable (OK)"; out "$append"
          fileout "heartbleed" "OK" "Heartbleed: not vulnerable $append" "$cve" "$cwe"
          ret=0
     else

          # server reply should be (>=SSLv3): 18030x in case of a heartBEAT reply -- which we take as a positive result
          tls_hello_ascii=$(hexdump -v -e '16/1 "%02X"' "$SOCK_REPLY_FILE")
          debugme echo "tls_content_type: ${tls_hello_ascii:0:2}"
          debugme echo "tls_protocol: ${tls_hello_ascii:2:4}"

          lines_returned=$(count_lines "$(hexdump -ve '16/1 "%02x " " \n"' "$SOCK_REPLY_FILE")")
          debugme echo "lines HB reply: $lines_returned"

          if [[ $DEBUG -ge 3 ]]; then
               outln "\nheartbleed reply: "
               hexdump -C "$SOCK_REPLY_FILE" | head -20
               [[ $lines_returned -gt 20 ]] && outln "[...]"
               outln
          fi

          if [[ $lines_returned -gt 1 ]] && [[ "${tls_hello_ascii:0:4}" == "1803" ]]; then
               if [[ "$STARTTLS_PROTOCOL" == "ftp" ]] || [[ "$STARTTLS_PROTOCOL" == "ftps" ]]; then
                    # check possibility of weird vsftpd reply, see #426, despite "1803" seems very unlikely...
                    if grep -q '500 OOPS' "$SOCK_REPLY_FILE" ; then
                         append=", successful weeded out vsftpd false positive"
                         pr_done_best "not vulnerable (OK)"; out "$append"
                         fileout "heartbleed" "OK" "Heartbleed: not vulnerable $append" "$cve" "$cwe"
                         ret=0
                    else
                         out "likely "
                         pr_svrty_critical "VULNERABLE (NOT ok)"
                         [[ $DEBUG -lt 3 ]] && out ", use debug >=3 to confirm"
                         fileout "heartbleed" "CRITICAL" "Heartbleed: VULNERABLE $cve" "$cwe" "$hint"
                         ret=1
                    fi
               else
                    pr_svrty_critical "VULNERABLE (NOT ok)"
                    fileout "heartbleed" "CRITICAL" "Heartbleed: VULNERABLE $cve" "$cwe" "$hint"
                    ret=1
               fi
          else
               pr_done_best "not vulnerable (OK)"
               fileout "heartbleed" "OK" "Heartbleed: not vulnerable $cve" "$cwe"
               ret=0
          fi
     fi
     outln

     TMPFILE="$SOCK_REPLY_FILE"
     close_socket
     tmpfile_handle $FUNCNAME.dd
     return $ret
}

# helper function
ok_ids(){
     pr_done_bestln "\n ok -- something resetted our ccs packets"
     return 0
}

#FIXME: At a certain point heartbleed and ccs needs to be changed and make use of code2network using a file, then tls_sockets
run_ccs_injection(){
     local tls_proto_offered tls_hexcode ccs_message client_hello byte6 sockreply
     local -i retval ret
     local tls_hello_ascii=""
     local cve="CVE-2014-0224"
     local cwe="CWE-310"
     local hint=""

     # see https://www.openssl.org/news/secadv_20140605.txt
     # mainly adapted from Ramon de C Valle's C code from https://gist.github.com/rcvalle/71f4b027d61a78c42607
     [[ $VULN_COUNT -le $VULN_THRESHLD ]] && outln && pr_headlineln " Testing for CCS injection vulnerability " && outln
     pr_bold " CCS"; out " ($cve)                       "

     # determine TLS versions offered <-- needs to come from another place
     $OPENSSL s_client $STARTTLS $BUGS -connect $NODEIP:$PORT $PROXY >$TMPFILE 2>$ERRFILE </dev/null

     if "$HAS_SED_E"; then
          tls_proto_offered=$(grep -aw Protocol $TMPFILE | sed -E 's/[^[:digit:]]//g')
     else
          tls_proto_offered=$(grep -aw Protocol $TMPFILE | sed -r 's/[^[:digit:]]//g')
     fi
     case "$tls_proto_offered" in
          12)  tls_hexcode="x03, x03" ;;
          11)  tls_hexcode="x03, x02" ;;
          *) tls_hexcode="x03, x01" ;;
#FIXME: for SSLv3 only we need to set tls_hexcode and the record layer TLS version correctly
     esac
     ccs_message=", x14, $tls_hexcode ,x00, x01, x01"

     client_hello="
     # TLS header (5 bytes)
     ,x16,                         # content type (x16 for handshake)
     x03, x01,                     # TLS version in record layer is always TLS 1.0 (except SSLv3)
     x00, x93,                     # length
     # Handshake header
     x01,                          # type (x01 for ClientHello)
     x00, x00, x8f,                # length
     $tls_hexcode,                 # TLS version
     # Random (32 byte)
     x53, x43, x5b, x90, x9d, x9b, x72, x0b,
     xbc, x0c, xbc, x2b, x92, xa8, x48, x97,
     xcf, xbd, x39, x04, xcc, x16, x0a, x85,
     x03, x90, x9f, x77, x04, x33, xd4, xde,
     x00,                # session ID length
     x00, x68,           # cipher suites length
     # Cipher suites (51 suites)
     xc0, x13, xc0, x12, xc0, x11, xc0, x10,
     xc0, x0f, xc0, x0e, xc0, x0d, xc0, x0c,
     xc0, x0b, xc0, x0a, xc0, x09, xc0, x08,
     xc0, x07, xc0, x06, xc0, x05, xc0, x04,
     xc0, x03, xc0, x02, xc0, x01, x00, x39,
     x00, x38, x00, x37, x00, x36, x00, x35, x00, x34,
     x00, x33, x00, x32, x00, x31, x00, x30,
     x00, x2f, x00, x16, x00, x15, x00, x14,
     x00, x13, x00, x12, x00, x11, x00, x10,
     x00, x0f, x00, x0e, x00, x0d, x00, x0c,
     x00, x0b, x00, x0a, x00, x09, x00, x08,
     x00, x07, x00, x06, x00, x05, x00, x04,
     x00, x03, x00, x02, x00, x01, x01, x00"

     fd_socket 5 || return 6

# we now make a standard handshake ...
     debugme out "\nsending client hello, "
     socksend "$client_hello" 1

     debugme outln "\nreading server hello"
     sockread_serverhello 32768
     if [[ $DEBUG -ge 4 ]]; then
          hexdump -C "$SOCK_REPLY_FILE" | head -20
          outln "[...]"
          out "\nsending payload #1 with TLS version $tls_hexcode:  "
     fi
     rm "$SOCK_REPLY_FILE"
# ... and then send the a change cipher spec message
     socksend "$ccs_message" 1 || ok_ids
     sockread_serverhello 4096 $CCS_MAX_WAITSOCK
     if [[ $DEBUG -ge 3 ]]; then
          outln "\n1st reply: "
          hexdump -C "$SOCK_REPLY_FILE" | head -20
# ok:      15 | 0301    |  02 | 02 | 0a
#       ALERT | TLS 1.0 | Length=2 | Unexpected Message (0a)
#    or just timed out
          outln
          out "sending payload #2 with TLS version $tls_hexcode:  "
     fi
     rm "$SOCK_REPLY_FILE"

     socksend "$ccs_message" 2 || ok_ids
     sockread_serverhello 4096 $CCS_MAX_WAITSOCK
     retval=$?

     tls_hello_ascii=$(hexdump -v -e '16/1 "%02X"' "$SOCK_REPLY_FILE")
     byte6="${tls_hello_ascii:12:2}"
     debugme echo "tls_content_type: ${tls_hello_ascii:0:2} | tls_protocol: ${tls_hello_ascii:2:4} | byte6: $byte6"

     if [[ $DEBUG -ge 3 ]]; then
          outln "\n2nd reply: "
          hexdump -C "$SOCK_REPLY_FILE"
          outln
     fi

# not ok:  15 | 0301    | 02 | 02  | 15
#       ALERT | TLS 1.0 | Length=2 | Decryption failed (21)
#
# ok:  0a or nothing: ==> RST

     if [[ -z "${tls_hello_ascii:0:12}" ]]; then
          # empty reply
          pr_done_best "not vulnerable (OK)"
          if [[ $retval -eq 3 ]]; then
### what?
               fileout "ccs" "OK" "CCS: not vulnerable (timed out)" "$cve" "$cwe"
          else
               fileout "ccs" "OK" "CCS: not vulnerable" "$cve" "$cwe"
          fi
          ret=0
     elif [[ "$byte6" == "15" ]] && [[ "${tls_hello_ascii:0:4}" == "1503" ]]; then
          pr_svrty_critical "VULNERABLE (NOT ok)"
          if [[ $retval -eq 3 ]]; then
               fileout "ccs" "CRITICAL" "CCS: VULNERABLE (timed out)" "$cve" "$cwe" "$hint"
          else
               fileout "ccs" "CRITICAL" "CCS: VULNERABLE" "$cve" "$cwe" "$hint"
          fi
          ret=1
     elif [[ "$byte6" == [0-9a-f][0-9a-f] ]] && [[ "${tls_hello_ascii:2:2}" != "03" ]]; then
          pr_warning "test failed"
          out ", probably read buffer too small (${tls_hello_ascii:0:14})"
          fileout "ccs" "WARN" "CCS: test failed, probably read buffer too small (${tls_hello_ascii:0:14})" "$cve" "$cwe" "$hint"
          ret=7
     else
          pr_warning "test failed "
          out "around line $LINENO (debug info: ${tls_hello_ascii:0:14})"
          fileout "ccs" "WARN" "CCS: test failed, around line $LINENO, debug info (${tls_hello_ascii:0:14})" "$cve" "$cwe" "$hint"
          ret=7
     fi
     outln

     TMPFILE="$SOCK_REPLY_FILE"
     close_socket
     tmpfile_handle $FUNCNAME.dd
     return $ret
}

run_renego() {
# no SNI here. Not needed as there won't be two different SSL stacks for one IP
     local legacycmd=""
     local insecure_renogo_str="Secure Renegotiation IS NOT"
     local sec_renego sec_client_renego addcmd=""
     local cve="CVE-2009-3555"
     local cwe="CWE-310"
     local hint=""

     [[ $VULN_COUNT -le $VULN_THRESHLD ]] && outln && pr_headlineln " Testing for Renegotiation vulnerabilities " && outln

     pr_bold " Secure Renegotiation "; out "($cve)      "    # and RFC5746, OSVDB 59968-59974
                                                                      # community.qualys.com/blogs/securitylabs/2009/11/05/ssl-and-tls-authentication-gap-vulnerability-discovered
     [[ ! "$OPTIMAL_PROTO" =~ ssl ]] && addcmd="$SNI"
     $OPENSSL s_client $OPTIMAL_PROTO $STARTTLS $BUGS -connect $NODEIP:$PORT $addcmd $PROXY 2>&1 </dev/null >$TMPFILE 2>$ERRFILE
     if sclient_connect_successful $? $TMPFILE; then
          grep -iaq "$insecure_renogo_str" $TMPFILE
          sec_renego=$?                                                    # 0= Secure Renegotiation IS NOT supported
#FIXME: didn't occur to me yet but why not also to check on "Secure Renegotiation IS supported"
          case $sec_renego in
               0)
                    pr_svrty_criticalln "VULNERABLE (NOT ok)"
                    fileout "secure_renego" "CRITICAL" "Secure Renegotiation: VULNERABLE" "$cve" "$cwe" "$hint"
                    ;;
               1)
                    pr_done_bestln "not vulnerable (OK)"
                    fileout "secure_renego" "OK" "Secure Renegotiation: not vulnerable" "$cve" "$cwe"
                    ;;
               *)
                    pr_warningln "FIXME (bug): $sec_renego"
                    fileout "secure_renego" "WARN" "Secure Renegotiation: FIXME (bug) $sec_renego" "$cve" "$cwe"
                    ;;
          esac
     else
          pr_warningln "handshake didn't succeed"
          fileout "secure_renego" "WARN" "Secure Renegotiation: handshake didn't succeed" "$cve" "$cwe"
     fi

     pr_bold " Secure Client-Initiated Renegotiation     "  # RFC 5746
     # see: https://community.qualys.com/blogs/securitylabs/2011/10/31/tls-renegotiation-and-denial-of-service-attacks
     #      http://blog.ivanristic.com/2009/12/testing-for-ssl-renegotiation.html -- head/get doesn't seem to be needed though
     case "$OSSL_VER" in
          0.9.8*)             # we need this for Mac OSX unfortunately
               case "$OSSL_VER_APPENDIX" in
                    [a-l])
                         local_problem_ln "$OPENSSL cannot test this secure renegotiation vulnerability"
                         fileout "sec_client_renego" "WARN" "Secure Client-Initiated Renegotiation : $OPENSSL cannot test this secure renegotiation vulnerability" "$cve" "$cwe"
                         return 3
                         ;;
                    [m-z])
                         ;; # all ok
               esac
               ;;
          1.0.1*|1.0.2*)
               legacycmd="-legacy_renegotiation"
               ;;
          0.9.9*|1.0*)
               ;;   # all ok
     esac

     if "$CLIENT_AUTH"; then
          pr_warningln "client authentication prevents this from being tested"
          fileout "sec_client_renego" "WARN" "Secure Client-Initiated Renegotiation : client authentication prevents this from being tested"
          sec_client_renego=1
     else
          # We need up to two tries here, as some LiteSpeed servers don't answer on "R" and block. Thus first try in the background
          # msg enables us to look deeper into it while debugging
          echo R | $OPENSSL s_client $OPTIMAL_PROTO $BUGS $legacycmd $STARTTLS -msg -connect $NODEIP:$PORT $addcmd $PROXY >$TMPFILE 2>>$ERRFILE &
          wait_kill $! $HEADER_MAXSLEEP
          if [[ $? -eq 3 ]]; then
               pr_done_good "likely not vulnerable (OK)"; outln ", timed out"        # it hung
               fileout "sec_client_renego" "OK" "Secure Client-Initiated Renegotiation : likely not vulnerable (timed out)" "$cve" "$cwe"
               sec_client_renego=1
          else
               # second try in the foreground as we are sure now it won't hang
               echo R | $OPENSSL s_client $legacycmd $STARTTLS $BUGS -msg -connect $NODEIP:$PORT $addcmd $PROXY >$TMPFILE 2>>$ERRFILE
               sec_client_renego=$?                                                  # 0=client is renegotiating & doesn't return an error --> vuln!
               case "$sec_client_renego" in
                    0)   if [[ $SERVICE == "HTTP" ]]; then
                              pr_svrty_high "VULNERABLE (NOT ok)"; outln ", DoS threat"
                              fileout "sec_client_renego" "HIGH" "Secure Client-Initiated Renegotiation : VULNERABLE, DoS threat" "$cve" "$cwe" "$hint"
                         else
                              pr_svrty_medium "VULNERABLE (NOT ok)"; outln ", potential DoS threat"
                              fileout "sec_client_renego" "MEDIUM" "Secure Client-Initiated Renegotiation : VULNERABLE, potential DoS threat" "$cve" "$cwe" "$hint"
                         fi
                         ;;
                    1)
                         pr_done_goodln "not vulnerable (OK)"
                         fileout "sec_client_renego" "OK" "Secure Client-Initiated Renegotiation : not vulnerable" "$cve" "$cwe"
                         ;;
                    *)
                         pr_warningln "FIXME (bug): $sec_client_renego"
                         fileout "sec_client_renego" "DEBUG" "Secure Client-Initiated Renegotiation : FIXME (bug) $sec_client_renego - Please report" "$cve" "$cwe"
                         ;;
               esac
          fi
     fi

     #FIXME Insecure Client-Initiated Renegotiation is missing

     tmpfile_handle $FUNCNAME.txt
     return $(($sec_renego + $sec_client_renego))
#FIXME: the return value is wrong, should be 0 if all ok. But as the caller doesn't care we don't care either ... yet ;-)
}

run_crime() {
     local -i ret=0 sclient_success
     local addcmd=""
     local cve="CVE-2012-4929"
     local cwe="CWE-310"
     local hint=""

     # in a nutshell: don't offer TLS/SPDY compression on the server side
     # This tests for CRIME Vulnerability (www.ekoparty.org/2012/juliano-rizzo.php) on HTTPS, not SPDY (yet)
     # Please note that it is an attack where you need client side control, so in regular situations this
     # means anyway "game over", w/wo CRIME
     # www.h-online.com/security/news/item/Vulnerability-in-SSL-encryption-is-barely-exploitable-1708604.html

     [[ $VULN_COUNT -le $VULN_THRESHLD ]] && outln && pr_headlineln " Testing for CRIME vulnerability " && outln
     pr_bold " CRIME, TLS " ; out "($cve)                "

     # first we need to test whether OpenSSL binary has zlib support
     $OPENSSL zlib -e -a -in /dev/stdin &>/dev/stdout </dev/null | grep -q zlib
     if [[ $? -eq 0 ]]; then
          if "$SSL_NATIVE"; then
               local_problem_ln "$OPENSSL lacks zlib support"
               fileout "crime" "WARN" "CRIME, TLS: Not tested. $OPENSSL lacks zlib support" "$cve" "$cwe"
               return 7
          else
               tls_sockets "03" "$TLS12_CIPHER" "" "" "true"
               sclient_success=$?
               [[ $sclient_success -eq 2 ]] && sclient_success=0
               [[ $sclient_success -eq 0 ]] && cp "$TEMPDIR/$NODEIP.parse_tls_serverhello.txt" $TMPFILE
          fi
     else
          [[ "$OSSL_VER" == "0.9.8"* ]] && addcmd="-no_ssl2"
          if [[ $OSSL_VER_MAJOR.$OSSL_VER_MINOR == "1.1.0"* ]] || [[ $OSSL_VER_MAJOR.$OSSL_VER_MINOR == "1.1.1"* ]]; then
               addcmd="-comp"
          fi
          $OPENSSL s_client $OPTIMAL_PROTO $BUGS $addcmd $STARTTLS -connect $NODEIP:$PORT $PROXY $SNI </dev/null &>$TMPFILE
          sclient_connect_successful $? $TMPFILE
          sclient_success=$?
     fi
     if [[ $sclient_success -ne 0 ]]; then
          pr_warning "test failed (couldn't connect)"
          fileout "crime" "WARN" "CRIME, TLS: Check failed. (couldn't connect)" "$cve" "$cwe"
          ret=7
     elif grep -a Compression $TMPFILE | grep -aq NONE >/dev/null; then
          pr_done_good "not vulnerable (OK)"
          if [[ $SERVICE != "HTTP" ]] && ! $CLIENT_AUTH;  then
               out " (not using HTTP anyway)"
               fileout "crime" "OK" "CRIME, TLS: Not vulnerable (not using HTTP anyway)" "$cve" "$cwe"
          else
               fileout "crime" "OK" "CRIME, TLS: Not vulnerable" "$cve" "$cwe"
          fi
          ret=0
     else
          if [[ $SERVICE == "HTTP" ]]; then
               pr_svrty_high "VULNERABLE (NOT ok)"
               fileout "crime" "HIGH" "CRIME, TLS: VULNERABLE" "$cve" "$cwe" "$hint"
          else
               pr_svrty_medium "VULNERABLE but not using HTTP: probably no exploit known"
               fileout "crime" "MEDIUM" "CRIME, TLS: VULNERABLE, but not using HTTP: probably no exploit known" "$cve" "$cwe" "$hint"
          fi
          ret=1
     fi
     # not clear whether this is a protocol != HTTP as one needs to have the ability to repeatedly modify the input
     # which is done e.g. via javascript in the context of HTTP
     outln

# this needs to be re-done i order to remove the redundant check for spdy

     # weed out starttls, spdy-crime is a web thingy
#    if [[ "x$STARTTLS" != "x" ]]; then
#         echo
#         return $ret
#    fi

     # weed out non-webports, spdy-crime is a web thingy. there's a catch thoug, you see it?
#    case $PORT in
#         25|465|587|80|110|143|993|995|21)
#         echo
#         return $ret
#    esac

#    if "$HAS_NPN"; then
#         $OPENSSL s_client -host $NODE -port $PORT -nextprotoneg $NPN_PROTOs  $SNI </dev/null 2>/dev/null >$TMPFILE
#         if [[ $? -eq 0 ]]; then
#              echo
#              pr_bold "CRIME Vulnerability, SPDY " ; outln "($cve): "

#              STR=$(grep Compression $TMPFILE )
#              if echo $STR | grep -q NONE >/dev/null; then
#                   pr_done_best "not vulnerable (OK)"
#                   ret=$((ret + 0))
#              else
#                   pr_svrty_critical "VULNERABLE (NOT ok)"
#                   ret=$((ret + 1))
#              fi
#         fi
#    fi
#    [[ $DEBUG -eq 2 ]] outln "$STR"
     tmpfile_handle $FUNCNAME.txt
     return $ret
}

# BREACH is a HTTP-level compression & an attack which works against any cipher suite and is agnostic
# to the version of TLS/SSL, more: http://www.breachattack.com/ . Foreign referrers are the important thing here!
# Mitigation: see https://community.qualys.com/message/20360
run_breach() {
     local header addcmd=""
     local -i ret=0
     local -i was_killed=0
     local referer useragent
     local url
     local spaces="                                          "
     local disclaimer=""
     local when_makesense=" Can be ignored for static pages or if no secrets in the page"
     local cve="CVE-2013-3587"
     local cwe="CWE-310"
     local hint=""

     [[ $SERVICE != "HTTP" ]] && return 7

     [[ $VULN_COUNT -le $VULN_THRESHLD ]] && outln && pr_headlineln " Testing for BREACH (HTTP compression) vulnerability " && outln
     pr_bold " BREACH"; out " ($cve)                    "

     url="$1"
     [[ -z "$url" ]] && url="/"
     disclaimer=" - only supplied \"$url\" tested"

     referer="https://google.com/"
     [[ "$NODE" =~ google ]] && referer="https://yandex.ru/" # otherwise we have a false positive for google.com

     useragent="$UA_STD"
     $SNEAKY && useragent="$UA_SNEAKY"

     [[ ! "$OPTIMAL_PROTO" =~ ssl ]] && addcmd="$SNI"
     printf "GET $url HTTP/1.1\r\nHost: $NODE\r\nUser-Agent: $useragent\r\nReferer: $referer\r\nConnection: Close\r\nAccept-encoding: gzip,deflate,compress\r\nAccept: text/*\r\n\r\n" | $OPENSSL s_client $OPTIMAL_PROTO $BUGS -quiet -ign_eof -connect $NODEIP:$PORT $PROXY $addcmd 1>$TMPFILE 2>$ERRFILE &
     wait_kill $! $HEADER_MAXSLEEP
     was_killed=$?                           # !=0 was killed
     result=$(awk '/^Content-Encoding/ { print $2 }' $TMPFILE)
     result=$(strip_lf "$result")
     debugme grep '^Content-Encoding' $TMPFILE
     if [[ ! -s $TMPFILE ]]; then
          pr_warning "failed (HTTP header request stalled"
          if [[ $was_killed -ne 0 ]]; then
               pr_warning " and was terminated"
               fileout "breach" "WARN" "BREACH: Test failed (HTTP request stalled and was terminated)" "$cve" "$cwe"
          else
               fileout "breach" "WARN" "BREACH: Test failed (HTTP request stalled)" "$cve" "$cwe"
          fi
          pr_warningln ") "
          ret=3
     elif [[ -z $result ]]; then
          pr_done_best "no HTTP compression (OK) "
          outln "$disclaimer"
          fileout "breach" "OK" "BREACH: no HTTP compression $disclaimer" "$cve" "$cwe"
          ret=0
     else
          pr_svrty_high "potentially NOT ok, uses $result HTTP compression."
          outln "$disclaimer"
          outln "$spaces$when_makesense"
          fileout "breach" "HIGH" "BREACH: potentially VULNERABLE, uses $result HTTP compression. $disclaimer ($when_makesense)" "$cve" "$cwe" "$hint"
          ret=1
     fi
     # Any URL can be vulnerable. I am testing now only the given URL!

     tmpfile_handle $FUNCNAME.txt
     return $ret
}

# SWEET32 (https://sweet32.info/). Birthday attacks on 64-bit block ciphers. In a nutshell: don't use 3DES ciphers anymore (DES, RC2 and IDEA too)
run_sweet32() {
     local -i sclient_success=0
     # DES, RC2 and IDEA are missing
     local sweet32_ciphers="ECDHE-RSA-DES-CBC3-SHA:ECDHE-ECDSA-DES-CBC3-SHA:SRP-DSS-3DES-EDE-CBC-SHA:SRP-RSA-3DES-EDE-CBC-SHA:SRP-3DES-EDE-CBC-SHA:EDH-RSA-DES-CBC3-SHA:EDH-DSS-DES-CBC3-SHA:DH-RSA-DES-CBC3-SHA:DH-DSS-DES-CBC3-SHA:AECDH-DES-CBC3-SHA:ADH-DES-CBC3-SHA:ECDH-RSA-DES-CBC3-SHA:ECDH-ECDSA-DES-CBC3-SHA:DES-CBC3-SHA:DES-CBC3-MD5:RSA-PSK-3DES-EDE-CBC-SHA:PSK-3DES-EDE-CBC-SHA:KRB5-DES-CBC3-SHA:KRB5-DES-CBC3-MD5:ECDHE-PSK-3DES-EDE-CBC-SHA:DHE-PSK-3DES-EDE-CBC-SHA"
     local sweet32_ciphers_hex="c0,12, c0,08, c0,1c, c0,1b, c0,1a, 00,16, 00,13, 00,10, 00,0d, c0,17, 00,1b, c0,0d, c0,03, 00,0a, 00,93, 00,8b, 00,1f, 00,23, c0,34, 00,8f, fe,ff, ff,e0"
# proper parsing to be clarified: 07,00,c0

     local cve="CVE-2016-2183, CVE-2016-6329"
     local cwe="CWE-327"
     local hint=""
     local -i nr_sweet32_ciphers=0
     local using_sockets=true

     [[ $VULN_COUNT -le $VULN_THRESHLD ]] && outln && pr_headlineln " Testing for SWEET32 (Birthday Attacks on 64-bit Block Ciphers)       " && outln
     pr_bold " SWEET32"; out " ($cve)    "

     "$SSL_NATIVE" && using_sockets=false
     # The openssl binary distributed has almost everything we need (PSK, KRB5 ciphers and feff, ffe0 are typically missing).
     # Measurements show that there's little impact whether we use sockets or TLS here, so the default is sockets here
     if "$using_sockets"; then
          tls_sockets "03" "${sweet32_ciphers_hex}"
          sclient_success=$?
     else
          nr_sweet32_ciphers=$(count_ciphers $sweet32_ciphers)
          nr_supported_ciphers=$(count_ciphers $(actually_supported_ciphers $sweet32_ciphers))
          $OPENSSL s_client $STARTTLS $BUGS -cipher $sweet32_ciphers -connect $NODEIP:$PORT $PROXY >$TMPFILE $SNI 2>$ERRFILE </dev/null
          sclient_connect_successful $? $TMPFILE
          sclient_success=$?
          [[ "$DEBUG" -eq 2 ]] && egrep -q "error|failure" $ERRFILE | egrep -av "unable to get local|verify error"
     fi
     if [[ $sclient_success -eq 0 ]]; then
          pr_svrty_low "VULNERABLE"; out ", uses 64 bit block ciphers"
          fileout "sweet32" "LOW" "SWEET32, uses 64 bit block ciphers" "$cve" "$cwe" "$hint"
     else
          pr_done_best "not vulnerable (OK)";
          if "$using_sockets"; then
               fileout "sweet32" "OK" "SWEET32: not vulnerable" "$cve" "$cwe"
          else
               if [[ "$nr_supported_ciphers" -ge 17 ]]; then
                    # Likely only PSK/KRB5 ciphers are missing: display discrepancy but no warning
                    out ", $nr_supported_ciphers/$nr_sweet32_ciphers local ciphers"
               else
                    pr_warning ", $nr_supported_ciphers/$nr_sweet32_ciphers local ciphers"
               fi
               fileout "sweet32" "OK" "SWEET32: not vulnerable ($nr_supported_ciphers of $nr_sweet32_ciphers local ciphers" "$cve" "$cwe"
          fi
     fi
     outln
     tmpfile_handle $FUNCNAME.txt
     return $sclient_success
}


# Padding Oracle On Downgraded Legacy Encryption, in a nutshell: don't use CBC Ciphers in SSLv3
run_ssl_poodle() {
     local -i sclient_success=0
     local cbc_ciphers="ECDHE-RSA-AES256-SHA:ECDHE-ECDSA-AES256-SHA:SRP-DSS-AES-256-CBC-SHA:SRP-RSA-AES-256-CBC-SHA:SRP-AES-256-CBC-SHA:DHE-PSK-AES256-CBC-SHA:DHE-RSA-AES256-SHA:DHE-DSS-AES256-SHA:DH-RSA-AES256-SHA:DH-DSS-AES256-SHA:DHE-RSA-CAMELLIA256-SHA:DHE-DSS-CAMELLIA256-SHA:DH-RSA-CAMELLIA256-SHA:DH-DSS-CAMELLIA256-SHA:AECDH-AES256-SHA:ADH-AES256-SHA:ADH-CAMELLIA256-SHA:ECDH-RSA-AES256-SHA:ECDH-ECDSA-AES256-SHA:AES256-SHA:ECDHE-PSK-AES256-CBC-SHA:CAMELLIA256-SHA:RSA-PSK-AES256-CBC-SHA:PSK-AES256-CBC-SHA:ECDHE-RSA-AES128-SHA:ECDHE-ECDSA-AES128-SHA:SRP-DSS-AES-128-CBC-SHA:SRP-RSA-AES-128-CBC-SHA:SRP-AES-128-CBC-SHA:DHE-RSA-AES128-SHA:DHE-DSS-AES128-SHA:DH-RSA-AES128-SHA:DH-DSS-AES128-SHA:DHE-RSA-SEED-SHA:DHE-DSS-SEED-SHA:DH-RSA-SEED-SHA:DH-DSS-SEED-SHA:DHE-RSA-CAMELLIA128-SHA:DHE-DSS-CAMELLIA128-SHA:DH-RSA-CAMELLIA128-SHA:DH-DSS-CAMELLIA128-SHA:AECDH-AES128-SHA:ADH-AES128-SHA:ADH-SEED-SHA:ADH-CAMELLIA128-SHA:ECDH-RSA-AES128-SHA:ECDH-ECDSA-AES128-SHA:AES128-SHA:ECDHE-PSK-AES128-CBC-SHA:DHE-PSK-AES128-CBC-SHA:SEED-SHA:CAMELLIA128-SHA:IDEA-CBC-SHA:RSA-PSK-AES128-CBC-SHA:PSK-AES128-CBC-SHA:KRB5-IDEA-CBC-SHA:KRB5-IDEA-CBC-MD5:ECDHE-RSA-DES-CBC3-SHA:ECDHE-ECDSA-DES-CBC3-SHA:SRP-DSS-3DES-EDE-CBC-SHA:SRP-RSA-3DES-EDE-CBC-SHA:SRP-3DES-EDE-CBC-SHA:EDH-RSA-DES-CBC3-SHA:EDH-DSS-DES-CBC3-SHA:DH-RSA-DES-CBC3-SHA:DH-DSS-DES-CBC3-SHA:AECDH-DES-CBC3-SHA:ADH-DES-CBC3-SHA:ECDH-RSA-DES-CBC3-SHA:ECDH-ECDSA-DES-CBC3-SHA:DES-CBC3-SHA:RSA-PSK-3DES-EDE-CBC-SHA:PSK-3DES-EDE-CBC-SHA:KRB5-DES-CBC3-SHA:KRB5-DES-CBC3-MD5:ECDHE-PSK-3DES-EDE-CBC-SHA:DHE-PSK-3DES-EDE-CBC-SHA:EXP1024-DHE-DSS-DES-CBC-SHA:EDH-RSA-DES-CBC-SHA:EDH-DSS-DES-CBC-SHA:DH-RSA-DES-CBC-SHA:DH-DSS-DES-CBC-SHA:ADH-DES-CBC-SHA:EXP1024-DES-CBC-SHA:DES-CBC-SHA:KRB5-DES-CBC-SHA:KRB5-DES-CBC-MD5:EXP-EDH-RSA-DES-CBC-SHA:EXP-EDH-DSS-DES-CBC-SHA:EXP-ADH-DES-CBC-SHA:EXP-DES-CBC-SHA:EXP-RC2-CBC-MD5:EXP-KRB5-RC2-CBC-SHA:EXP-KRB5-DES-CBC-SHA:EXP-KRB5-RC2-CBC-MD5:EXP-KRB5-DES-CBC-MD5:EXP-DH-DSS-DES-CBC-SHA:EXP-DH-RSA-DES-CBC-SHA"
     local cbc_ciphers_hex="c0,14, c0,0a, c0,22, c0,21, c0,20, 00,91, 00,39, 00,38, 00,37, 00,36, 00,88, 00,87, 00,86, 00,85, c0,19, 00,3a, 00,89, c0,0f, c0,05, 00,35, c0,36, 00,84, 00,95, 00,8d, c0,13, c0,09, c0,1f, c0,1e, c0,1d, 00,33, 00,32, 00,31, 00,30, 00,9a, 00,99, 00,98, 00,97, 00,45, 00,44, 00,43, 00,42, c0,18, 00,34, 00,9b, 00,46, c0,0e, c0,04, 00,2f, c0,35, 00,90, 00,96, 00,41, 00,07, 00,94, 00,8c, 00,21, 00,25, c0,12, c0,08, c0,1c, c0,1b, c0,1a, 00,16, 00,13, 00,10, 00,0d, c0,17, 00,1b, c0,0d, c0,03, 00,0a, 00,93, 00,8b, 00,1f, 00,23, c0,34, 00,8f, 00,63, 00,15, 00,12, 00,0f, 00,0c, 00,1a, 00,62, 00,09, 00,1e, 00,22, 00,14, 00,11, 00,19, 00,08, 00,06, 00,27, 00,26, 00,2a, 00,29, 00,0b, 00,0e"
     local cve="CVE-2014-3566"
     local cwe="CWE-310"
     local hint=""
     local -i nr_cbc_ciphers=0
     local using_sockets=true

     [[ $VULN_COUNT -le $VULN_THRESHLD ]] && outln && pr_headlineln " Testing for SSLv3 POODLE (Padding Oracle On Downgraded Legacy Encryption) " && outln
     pr_bold " POODLE, SSL"; out " ($cve)               "

     "$SSL_NATIVE" && using_sockets=false
     # The openssl binary distributed has almost everything we need (PSK and KRB5 ciphers are typically missing).
     # Measurements show that there's little impact whether we use sockets or TLS here, so the default is sockets here
     if "$using_sockets"; then
          tls_sockets "00" "$cbc_ciphers_hex"
          sclient_success=$?
     else
          if ! "$HAS_SSL3"; then
               local_problem_ln "Your $OPENSSL doesn't support SSLv3"
               return 1
          fi
          nr_cbc_ciphers=$(count_ciphers $cbc_ciphers)
          nr_supported_ciphers=$(count_ciphers $(actually_supported_ciphers $cbc_ciphers))
          # SNI not needed as SSLv3 has none:
          $OPENSSL s_client -ssl3 $STARTTLS $BUGS -cipher $cbc_ciphers -connect $NODEIP:$PORT $PROXY >$TMPFILE 2>$ERRFILE </dev/null
          sclient_connect_successful $? $TMPFILE
          sclient_success=$?
          [[ "$DEBUG" -eq 2 ]] && egrep -q "error|failure" $ERRFILE | egrep -av "unable to get local|verify error"
     fi
     if [[ $sclient_success -eq 0 ]]; then
          pr_svrty_high "VULNERABLE (NOT ok)"; out ", uses SSLv3+CBC (check TLS_FALLBACK_SCSV mitigation below)"
          fileout "poodle_ssl" "HIGH" "POODLE, SSL: VULNERABLE, uses SSLv3+CBC" "$cve" "$cwe" "$hint"
     else
          pr_done_best "not vulnerable (OK)";
          if "$using_sockets"; then
               fileout "poodle_ssl" "OK" "POODLE, SSL: not vulnerable" "$cve" "$cwe"
          else
               if [[ "$nr_supported_ciphers" -ge 83 ]]; then
                    # Likely only KRB and PSK cipher are missing: display discrepancy but no warning
                    out ", $nr_supported_ciphers/$nr_cbc_ciphers local ciphers"
               else
                    pr_warning ", $nr_supported_ciphers/$nr_cbc_ciphers local ciphers"
               fi
               fileout "poodle_ssl" "OK" "POODLE, SSL: not vulnerable ($nr_supported_ciphers of $nr_cbc_ciphers local ciphers" "$cve" "$cwe"
          fi
     fi
     outln
     tmpfile_handle $FUNCNAME.txt
     return $sclient_success
}

# for appliance which use padding, no fallback needed
run_tls_poodle() {
     local cve="CVE-2014-8730"
     local cwe="CWE-310"

     pr_bold " POODLE, TLS"; out " ($cve), experimental "
     #FIXME
     echo "#FIXME"
     fileout "poodle_tls" "WARN" "POODLE, TLS: Not tested. Not yet implemented #FIXME" "$cve" "$cwe"
     return 7
}

run_tls_fallback_scsv() {
     local -i ret=0

     [[ $VULN_COUNT -le $VULN_THRESHLD ]] && outln && pr_headlineln " Testing for TLS_FALLBACK_SCSV Protection " && outln
     pr_bold " TLS_FALLBACK_SCSV"; out " (RFC 7507)              "
     # This isn't a vulnerability check per se, but checks for the existence of
     # the countermeasure to protect against protocol downgrade attacks.

     # First check we have support for TLS_FALLBACK_SCSV in our local OpenSSL
     if ! "$HAS_FALLBACK_SCSV"; then
          local_problem_ln "$OPENSSL lacks TLS_FALLBACK_SCSV support"
          return 4
     fi
     #TODO: this need some tuning: a) if one protocol is supported only it has practcally no value (theoretical it's interesting though)
     # b) for IIS6 + openssl 1.0.2 this won't work
     # c) best to make sure that we hit a specific protocol, see https://alpacapowered.wordpress.com/2014/10/20/ssl-poodle-attack-what-is-this-scsv-thingy/
     # d) minor: we should do "-state" here

     # first: make sure SSLv3 or some TLS protocol is supported
     if [[ "$OPTIMAL_PROTO" == "-ssl2" ]]; then
          pr_svrty_criticalln "No fallback possible, SSLv2 is the only protocol"
          return 7
     fi
     # second: make sure we have tls1_2:
     $OPENSSL s_client $STARTTLS $BUGS -connect $NODEIP:$PORT $PROXY $SNI -no_tls1_2 >$TMPFILE 2>$ERRFILE </dev/null
     if ! sclient_connect_successful $? $TMPFILE; then
          pr_done_good "No fallback possible, TLS 1.2 is the only protocol (OK)"
          ret=7
     else
          # ...and do the test (we need to parse the error here!)
          $OPENSSL s_client $STARTTLS $BUGS -connect $NODEIP:$PORT $PROXY $SNI -no_tls1_2 -fallback_scsv &>$TMPFILE </dev/null
          if grep -q "CONNECTED(00" "$TMPFILE"; then
               if grep -qa "BEGIN CERTIFICATE" "$TMPFILE"; then
                    pr_svrty_medium "Downgrade attack prevention NOT supported"
                    fileout "fallback_scsv" "MEDIUM" "TLS_FALLBACK_SCSV (RFC 7507) (experimental) : Downgrade attack prevention NOT supported"
                    ret=1
               elif grep -qa "alert inappropriate fallback" "$TMPFILE"; then
                    pr_done_good "Downgrade attack prevention supported (OK)"
                    fileout "fallback_scsv" "OK" "TLS_FALLBACK_SCSV (RFC 7507) (experimental) : Downgrade attack prevention supported"
                    ret=0
               elif grep -qa "alert handshake failure" "$TMPFILE"; then
                    pr_done_good "Probably OK. "
                    fileout "fallback_scsv" "OK" "TLS_FALLBACK_SCSV (RFC 7507) (experimental) : Probably oK"
                    # see RFC 7507, https://github.com/drwetter/testssl.sh/issues/121
                    # other case reported by Nicolas was F5 and at costumer of mine: the same
                    pr_svrty_medium "But received non-RFC-compliant \"handshake failure\" instead of \"inappropriate fallback\""
                    fileout "fallback_scsv" "MEDIUM" "TLS_FALLBACK_SCSV (RFC 7507) (experimental) : But received non-RFC-compliant \"handshake failure\" instead of \"inappropriate fallback\""
                    ret=2
               elif grep -qa "ssl handshake failure" "$TMPFILE"; then
                    pr_svrty_medium "some unexpected \"handshake failure\" instead of \"inappropriate fallback\""
                    fileout "fallback_scsv" "MEDIUM" "TLS_FALLBACK_SCSV (RFC 7507) (experimental) : some unexpected \"handshake failure\" instead of \"inappropriate fallback\" (likely: warning)"
                    ret=3
               else
                    pr_warning "Check failed, unexpected result "
                    out ", run $PROG_NAME -Z --debug=1 and look at $TEMPDIR/*tls_fallback_scsv.txt"
                    fileout "fallback_scsv" "WARN" "TLS_FALLBACK_SCSV (RFC 7507) (experimental) : Check failed, unexpected result, run $PROG_NAME -Z --debug=1 and look at $TEMPDIR/*tls_fallback_scsv.txt"
               fi
          else
               pr_warning "test failed (couldn't connect)"
               fileout "fallback_scsv" "WARN" "TLS_FALLBACK_SCSV (RFC 7507) (experimental) : Check failed. (couldn't connect)"
               ret=7
          fi
     fi

     outln
     tmpfile_handle $FUNCNAME.txt
     return $ret
}


# Factoring RSA Export Keys: don't use EXPORT RSA ciphers, see https://freakattack.com/
run_freak() {
     local -i sclient_success=0
     local -i i nr_supported_ciphers=0 len
     # with correct build it should list these 9 ciphers (plus the two latter as SSLv2 ciphers):
     local exportrsa_cipher_list="EXP1024-DES-CBC-SHA:EXP1024-RC2-CBC-MD5:EXP1024-RC4-SHA:EXP1024-RC4-MD5:EXP-EDH-RSA-DES-CBC-SHA:EXP-DH-RSA-DES-CBC-SHA:EXP-DES-CBC-SHA:EXP-RC2-CBC-MD5:EXP-RC4-MD5"
     local exportrsa_tls_cipher_list_hex="00,62, 00,61, 00,64, 00,60, 00,14, 00,0E, 00,08, 00,06, 00,03"
     local exportrsa_ssl2_cipher_list_hex="04,00,80, 02,00,80"
     local detected_ssl2_ciphers
     local addcmd="" addtl_warning="" hexc
     local cve="CVE-2015-0204"
     local cwe="CWE-310"
     local hint=""
     local using_sockets=true

     [[ $VULN_COUNT -le $VULN_THRESHLD ]] && outln && pr_headlineln " Testing for FREAK attack " && outln
     pr_bold " FREAK"; out " ($cve)                     "

     "$SSL_NATIVE" && using_sockets=false
     if "$using_sockets"; then
          nr_supported_ciphers=$(count_words "$exportrsa_tls_cipher_list_hex")+$(count_words "$exportrsa_ssl2_cipher_list_hex")
     else
          nr_supported_ciphers=$(count_ciphers $(actually_supported_ciphers $exportrsa_cipher_list))
     fi
     #echo "========= ${PIPESTATUS[*]}

     case $nr_supported_ciphers in
          0)   local_problem_ln "$OPENSSL doesn't have any EXPORT RSA ciphers configured"
               fileout "freak" "WARN" "FREAK: Not tested. $OPENSSL doesn't have any EXPORT RSA ciphers configured" "$cve" "$cwe"
               return 7
               ;;
          1|2|3)
               addtl_warning=" ($magenta""tested only with $nr_supported_ciphers out of 9 ciphers only!$off)" ;;
          4|5|6|7)
               addtl_warning=" (tested with $nr_supported_ciphers/9 ciphers)" ;;
          8|9|10|11)
               addtl_warning="" ;;
     esac
     if "$using_sockets"; then
          tls_sockets "03" "$exportrsa_tls_cipher_list_hex"
          sclient_success=$?
          [[ $sclient_success -eq 2 ]] && sclient_success=0
          if [[ $sclient_success -ne 0 ]]; then
               sslv2_sockets "$exportrsa_ssl2_cipher_list_hex" "true"
               if [[ $? -eq 3 ]] && [[ "$V2_HELLO_CIPHERSPEC_LENGTH" -ne 0 ]]; then
                    exportrsa_ssl2_cipher_list_hex="$(strip_spaces "${exportrsa_ssl2_cipher_list_hex//,/}")"
                    len=${#exportrsa_ssl2_cipher_list_hex}
                    detected_ssl2_ciphers="$(grep "Supported cipher: " "$TEMPDIR/$NODEIP.parse_sslv2_serverhello.txt")"
                    for (( i=0; i<len; i=i+6 )); do
                         [[ "$detected_ssl2_ciphers" =~ "x${exportrsa_ssl2_cipher_list_hex:i:6}" ]] && sclient_success=0 && break
                    done
               fi
          fi
     else
          "$HAS_NO_SSL2" && addcmd="-no_ssl2" || addcmd=""
          $OPENSSL s_client $STARTTLS $BUGS -cipher $exportrsa_cipher_list -connect $NODEIP:$PORT $PROXY $SNI $addcmd >$TMPFILE 2>$ERRFILE </dev/null
          sclient_connect_successful $? $TMPFILE
          sclient_success=$?
          [[ $DEBUG -eq 2 ]] && egrep -a "error|failure" $ERRFILE | egrep -av "unable to get local|verify error"
          if [[ $sclient_success -ne 0 ]] && "$HAS_SSL2"; then
               $OPENSSL s_client $STARTTLS $BUGS -cipher $exportrsa_cipher_list -connect $NODEIP:$PORT $PROXY -ssl2 >$TMPFILE 2>$ERRFILE </dev/null
               sclient_connect_successful $? $TMPFILE
               sclient_success=$?
          fi
     fi
     if [[ $sclient_success -eq 0 ]]; then
          pr_svrty_critical "VULNERABLE (NOT ok)"; out ", uses EXPORT RSA ciphers"
          fileout "freak" "CRITICAL" "FREAK: VULNERABLE, uses EXPORT RSA ciphers" "$cve" "$cwe" "$hint"
     else
          pr_done_best "not vulnerable (OK)"; out "$addtl_warning"
          fileout "freak" "OK" "FREAK: not vulnerable $addtl_warning" "$cve" "$cwe"
     fi
     outln

     if [[ $DEBUG -ge 2 ]]; then
          if "$using_sockets"; then
               for hexc in $(sed 's/, / /g' <<< "$exportrsa_tls_cipher_list_hex, $exportrsa_ssl2_cipher_list_hex"); do
                    if [[ ${#hexc} -eq 5 ]]; then
                         hexc="0x${hexc:0:2},0x${hexc:3:2}"
                    else
                         hexc="0x${hexc:0:2},0x${hexc:3:2},0x${hexc:6:2}"
                    fi
                    for (( i=0; i < TLS_NR_CIPHERS; i++ )); do
                         [[ "$hexc" == "${TLS_CIPHER_HEXCODE[i]}" ]] && break
                    done
                    [[ $i -eq $TLS_NR_CIPHERS ]] && out "$hexc " || out "${TLS_CIPHER_OSSL_NAME[i]} "
               done
               outln
          else
               echo $(actually_supported_ciphers $exportrsa_cipher_list)
          fi
     fi
     debugme echo $nr_supported_ciphers

     tmpfile_handle $FUNCNAME.txt
     return $ret
}


# see https://weakdh.org/upported_ciphers/ogjam.html
run_logjam() {
     local -i sclient_success=0
     local exportdh_cipher_list="EXP1024-DHE-DSS-DES-CBC-SHA:EXP1024-DHE-DSS-RC4-SHA:EXP-EDH-RSA-DES-CBC-SHA:EXP-EDH-DSS-DES-CBC-SHA"
     local exportdh_cipher_list_hex="00,63, 00,65, 00,14, 00,11"
     local all_dh_ciphers="cc,15, 00,b3, 00,91, c0,97, 00,a3, 00,9f, cc,aa, c0,a3, c0,9f, 00,6b, 00,6a, 00,39, 00,38, 00,c4, 00,c3, 00,88, 00,87, 00,a7, 00,6d, 00,3a, 00,c5, 00,89, 00,ab, cc,ad, c0,a7, c0,43, c0,45, c0,47, c0,53, c0,57, c0,5b, c0,67, c0,6d, c0,7d, c0,81, c0,85, c0,91, 00,a2, 00,9e, c0,a2, c0,9e, 00,aa, c0,a6, 00,67, 00,40, 00,33, 00,32, 00,be, 00,bd, 00,9a, 00,99, 00,45, 00,44, 00,a6, 00,6c, 00,34, 00,bf, 00,9b, 00,46, 00,b2, 00,90, c0,96, c0,42, c0,44, c0,46, c0,52, c0,56, c0,5a, c0,66, c0,6c, c0,7c, c0,80, c0,84, c0,90, 00,66, 00,18, 00,8e, 00,16, 00,13, 00,1b, 00,8f, 00,63, 00,15, 00,12, 00,1a, 00,65, 00,14, 00,11, 00,19, 00,17, 00,b5, 00,b4, 00,2d" # 93 ciphers
     local -i i nr_supported_ciphers=0 server_key_exchange_len=0 ephemeral_pub_len=0 len_dh_p=0
     local addtl_warning="" hexc
     local cve="CVE-2015-4000"
     local cwe="CWE-310"
     local hint=""
     local server_key_exchange ephemeral_pub key_bitstring=""
     local dh_p=""
     local spaces="                                           "
     local vuln_exportdh_ciphers=false
     local common_primes_file="$TESTSSL_INSTALL_DIR/etc/common-primes.txt"
     local comment="" str=""
     local -i lineno_matched=0
     local -i ret
     local using_sockets=true

     [[ $VULN_COUNT -le $VULN_THRESHLD ]] && outln && pr_headlineln " Testing for LOGJAM vulnerability " && outln
     pr_bold " LOGJAM"; out " ($cve), experimental      "

     "$SSL_NATIVE" && using_sockets=false
     # Also as the openssl binary distributed has everything we need measurements show that
     # there's no impact whether we use sockets or TLS here, so the default is sockets here
     if ! "$using_sockets"; then
          nr_supported_ciphers=$(count_ciphers $(actually_supported_ciphers $exportdh_cipher_list))
          debugme echo $nr_supported_ciphers
          case $nr_supported_ciphers in
               0)   local_problem_ln "$OPENSSL doesn't have any DH EXPORT ciphers configured"
                    fileout "logjam" "WARN" "LOGJAM: Not tested. $OPENSSL doesn't have any DH EXPORT ciphers configured" "$cve" "$cwe"
                    return 1            # we could continue here testing common primes but the logjam test would be not complete and it's misleading/hard to code+display
                    ;;
               1|2|3) addtl_warning=" ($magenta""tested w/ $nr_supported_ciphers/4 ciphers only!$off)" ;;
               4)   ;;
          esac
     fi

     # test for DH export ciphers first
     if "$using_sockets"; then
          tls_sockets "03" "$exportdh_cipher_list_hex"
          sclient_success=$?
          [[ $sclient_success -eq 2 ]] && sclient_success=0
     else
          $OPENSSL s_client $STARTTLS $BUGS -cipher $exportdh_cipher_list -connect $NODEIP:$PORT $PROXY $SNI >$TMPFILE 2>$ERRFILE </dev/null
          sclient_connect_successful $? $TMPFILE
          sclient_success=$?
          debugme egrep -a "error|failure" $ERRFILE | egrep -av "unable to get local|verify error"
     fi
     [[ $sclient_success -eq 0 ]] && \
          vuln_exportdh_ciphers=true || \
          vuln_exportdh_ciphers=false

     if [[ $DEBUG -ge 2 ]]; then
          if "$using_sockets"; then
               for hexc in $(sed 's/, / /g' <<< "$exportdh_cipher_list_hex"); do
                    hexc="0x${hexc:0:2},0x${hexc:3:2}"
                    for (( i=0; i < TLS_NR_CIPHERS; i++ )); do
                         [[ "$hexc" == "${TLS_CIPHER_HEXCODE[i]}" ]] && break
                    done
                    [[ $i -eq $TLS_NR_CIPHERS ]] && out "$hexc " || out "${TLS_CIPHER_OSSL_NAME[i]} "
               done
               outln
          else
               echo $(actually_supported_ciphers $exportdh_cipher_list)
          fi
     fi

     # Try all ciphers that use an ephemeral DH key. If successful, check whether the key uses a weak prime.
     if "$using_sockets"; then
          tls_sockets "03" "$all_dh_ciphers" "ephemeralkey"
          sclient_success=$?
          if [[ $sclient_success -eq 0 ]] || [[ $sclient_success -eq 2 ]]; then
               cp "$TEMPDIR/$NODEIP.parse_tls_serverhello.txt" $TMPFILE
               key_bitstring="$(awk '/-----BEGIN PUBLIC KEY/,/-----END PUBLIC KEY/ { print $0 }' $TMPFILE)"
          fi
     else
          # FIXME: determine # of ciphers supported, 48 only are the shipped binaries
          $OPENSSL s_client $STARTTLS $BUGS -cipher kEDH -msg -connect $NODEIP:$PORT $PROXY $SNI >$TMPFILE 2>$ERRFILE </dev/null
          sclient_connect_successful $? $TMPFILE
          if [[ $? -eq 0 ]] && grep -q ServerKeyExchange $TMPFILE; then
               # Example: '<<< TLS 1.0 Handshake [length 010b], ServerKeyExchange'
               # get line with ServerKeyExchange, cut from the beginning to "length ". cut from the end to ']'
               str="$(awk '/<<< TLS 1.[0-2].*ServerKeyExchange$/' $TMPFILE)"
               str="${str#<*length }"
               str="${str%]*}"
               server_key_exchange_len=$(hex2dec "$str")
               server_key_exchange_len=2+$server_key_exchange_len/16
               server_key_exchange="$(grep -A $server_key_exchange_len ServerKeyExchange $TMPFILE | tail -n +2)"
               server_key_exchange="$(toupper "$(strip_spaces "$(newline_to_spaces "$server_key_exchange")")")"
               server_key_exchange="${server_key_exchange%%[!0-9A-F]*}"
               server_key_exchange_len=${#server_key_exchange}
               [[ $server_key_exchange_len -gt 8 ]] && [[ "${server_key_exchange:0:2}" == "0C" ]] && ephemeral_pub_len=$(hex2dec "${server_key_exchange:2:6}")
               [[ $ephemeral_pub_len -ne 0 ]] && [[ $ephemeral_pub_len -le $server_key_exchange_len ]] && key_bitstring="$(get_dh_ephemeralkey "${server_key_exchange:8}")"
          fi
     fi

     # now the final test for common primes
     if [[ -n "$key_bitstring" ]]; then
          dh_p="$($OPENSSL pkey -pubin -text -noout <<< "$key_bitstring" | awk '/prime:/,/generator:/' | tail -n +2 | head -n -1)"
          dh_p="$(strip_spaces "$(colon_to_spaces "$(newline_to_spaces "$dh_p")")")"
          [[ "${dh_p:0:2}" == "00" ]] && dh_p="${dh_p:2}"
          len_dh_p="$((4*${#dh_p}))"
          debugme outln "len(dh_p): $len_dh_p  |  dh_p: $dh_p"
          echo "$dh_p" > $TEMPDIR/dh_p.txt
          if [[ ! -s "$common_primes_file" ]]; then
               local_problem_ln "couldn't read common primes file $common_primes_file"
               out "${spaces}"
               fileout "LOGJAM_common primes" "WARN" "couldn't read common primes file $common_primes_file"
               ret=7
          else
               dh_p="$(toupper "$dh_p")"
               # In the previous line of the match is bascially the hint we want to echo
               # the most elegant thing to get the previous line [ awk '/regex/ { print x }; { x=$0 }' ] doesn't work with GNU grep
               lineno_matched=$(grep -n "$dh_p" "$common_primes_file" 2>/dev/null | awk -F':' '{ print $1 }')
               if [[ "$lineno_matched" -ne 0 ]]; then
                    comment="$(awk "NR == $lineno_matched-1" "$common_primes_file" | awk -F'"' '{ print $2 }')"
                    ret=1     # vulnerable: common prime
               else
                    ret=0     # not vulnerable: no known common prime
               fi
          fi
     else
          ret=3               # no DH key detected
     fi

     # now the final verdict
     # we only use once the color here on the screen, so screen and fileout SEEM to be inconsistent
     if "$vuln_exportdh_ciphers"; then
          pr_svrty_high "VULNERABLE (NOT ok):"; out " uses DH EXPORT ciphers"
          fileout "logjam" "HIGH" "LOGJAM: VULNERABLE, uses DH EXPORT ciphers" "$cve" "$cwe" "$hint"
          if [[ $ret -eq 3 ]]; then
               out ", no DH key detected"
               fileout "LOGJAM_common primes" "OK" "no DH key detected"
          elif [[ $ret -eq 1 ]]; then
               out "\n${spaces}"
               # now size matters -- i.e. the bit size ;-)
               if [[ $len_dh_p -le 512 ]]; then
                    pr_svrty_critical "VULNERABLE (NOT ok):"; out " common prime "; pr_italic "$comment"; out " detected ($len_dh_p bits)"
                    fileout "LOGJAM_common primes" "CRITICAL" "common prime \"$comment\" detected"
               elif [[ $len_dh_p -le 1024 ]]; then
                    pr_svrty_high "VULNERABLE (NOT ok):"; out " common prime "; pr_italic "$comment"; out " detected ($len_dh_p bits)"
                    fileout "LOGJAM_common primes" "HIGH" "common prime \"$comment\" detected"
               elif [[ $len_dh_p -le 1536 ]]; then
                    pr_svrty_medium "common prime with $len_dh_p bits detected: "; pr_italic "$comment"
                    fileout "LOGJAM_common primes" "MEDIUM" "common prime \"$comment\" detected"
               elif [[ $len_dh_p -le 2048 ]]; then
                    pr_svrty_low "common prime with $len_dh_p bits detected: "; pr_italic "$comment"
                    fileout "LOGJAM_common primes" "LOW" "common prime \"$comment\" detected"
               else
                    out "common prime with $len_dh_p bits detected: "; pr_italic "$comment"
                    fileout "LOGJAM_common primes" "INFO" "common prime \"$comment\" detected"
               fi
          elif [[ $ret -eq 0 ]]; then
               out " no common primes detected"
               fileout "LOGJAM_common primes" "INFO" "no common primes detected"
          elif [[ $ret -eq 7 ]]; then
               out "FIXME 1"
          fi
     else
          if [[ $ret -eq 1 ]]; then
               # now size matters -- i.e. the bit size ;-)
               if [[ $len_dh_p  -le 512 ]]; then
                    pr_svrty_critical "VULNERABLE (NOT ok):" ; out " uses common prime "; pr_italic "$comment"; out " ($len_dh_p bits)"
                    fileout "LOGJAM_common primes" "CRITICAL" "common prime \"$comment\" detected"
               elif [[ $len_dh_p -le 1024 ]]; then
                    pr_svrty_high "VULNERABLE (NOT ok):"; out " common prime "; pr_italic "$comment"; out " detected ($len_dh_p bits)"
                    fileout "LOGJAM_common primes" "HIGH" "common prime \"$comment\" detected"
               elif [[ $len_dh_p -le 1536 ]]; then
                    pr_svrty_medium "Common prime with $len_dh_p bits detected: "; pr_italic "$comment"
                    fileout "LOGJAM_common primes" "MEDIUM" "common prime \"$comment\" detected"
               elif [[ $len_dh_p -le 2048 ]]; then
                    pr_svrty_low "Common prime with $len_dh_p bits detected: "; pr_italic "$comment"
                    fileout "LOGJAM_common primes" "LOW" "common prime \"$comment\" detected"
               else
                    out "Common prime with $len_dh_p bits detected: "; pr_italic "$comment"
                    fileout "LOGJAM_common primes" "INFO" "common prime \"$comment\" detected"
               fi
               outln ","
               out "${spaces}but no DH EXPORT ciphers${addtl_warning}"
               fileout "logjam" "OK" "LOGJAM: not vulnerable, no DH EXPORT ciphers, $addtl_warning" "$cve" "$cwe"
          elif [[ $ret -eq 3 ]]; then
               pr_done_good "not vulnerable (OK):"; out " no DH EXPORT ciphers${addtl_warning}"
               fileout "logjam" "OK" "LOGJAM: not vulnerable, no DH EXPORT ciphers, $addtl_warning" "$cve" "$cwe"
               out ", no DH key detected"
               fileout "LOGJAM_common primes" "OK" "no DH key detected"
          elif [[ $ret -eq 0 ]]; then
               pr_done_good "not vulnerable (OK):"; out " no DH EXPORT ciphers${ddtl_warning}"
               fileout "logjam" "OK" "LOGJAM: not vulnerable, no DH EXPORT ciphers, $addtl_warning" "$cve" "$cwe"
               out ", no common primes detected"
               fileout "LOGJAM_common primes" "OK" "no common primes detected"
          elif [[ $ret -eq 7 ]]; then
               pr_done_good "partly not vulnerable:"; out " no DH EXPORT ciphers${ddtl_warning}"
               fileout "logjam" "OK" "LOGJAM: not vulnerable, no DH EXPORT ciphers, $addtl_warning" "$cve" "$cwe"
          fi
     fi
     outln
     tmpfile_handle $FUNCNAME.txt
     return 0
}


run_drown() {
     local nr_ciphers_detected ret
     local spaces="                                          "
     local cert_fingerprint_sha2=""
     local cve="CVE-2016-0800, CVE-2016-0703"
     local cwe="CWE-310"
     local hint=""

     if [[ $VULN_COUNT -le $VULN_THRESHLD ]]; then
          outln
          pr_headlineln " Testing for DROWN vulnerability "
          outln
     fi
# if we want to use OPENSSL: check for < openssl 1.0.2g, openssl 1.0.1s if native openssl
     pr_bold " DROWN"; out " ($cve)      "
     sslv2_sockets

     case $? in
          7) # strange reply, couldn't convert the cipher spec length to a hex number
               fixme "strange v2 reply "
               outln " (rerun with DEBUG >=2)"
               [[ $DEBUG -ge 3 ]] && hexdump -C "$TEMPDIR/$NODEIP.sslv2_sockets.dd" | head -1
               ret=7
               fileout "drown" "WARN" "SSLv2: received a strange SSLv2 reply (rerun with DEBUG>=2)" "$cve" "$cwe"
               ;;
          3)   # vulnerable
               lines=$(count_lines "$(hexdump -C "$TEMPDIR/$NODEIP.sslv2_sockets.dd" 2>/dev/null)")
               debugme out "  ($lines lines)  "
               if [[ "$lines" -gt 1 ]]; then
                    nr_ciphers_detected=$((V2_HELLO_CIPHERSPEC_LENGTH / 3))
                    if [[ 0 -eq "$nr_ciphers_detected" ]]; then
                         pr_svrty_highln "SSLv2 is supported but couldn't detect a cipher (NOT ok)";
                         fileout "drown" "HIGH" "SSLv2 is offered, but could not detect a cipher" "$cve" "$cwe" "$hint"
                    else
                         pr_svrty_criticalln  "VULNERABLE (NOT ok), SSLv2 offered with $nr_ciphers_detected ciphers";
                         fileout "drown" "CRITICAL" "VULNERABLE, SSLv2 offered with $nr_ciphers_detected ciphers" "$cve" "$cwe" "$hint"
                    fi
               fi
               ret=1
               ;;
          *)   pr_done_bestln "not vulnerable on this port (OK)"
               fileout "drown" "OK" "not vulnerable to DROWN" "$cve" "$cwe"
               # Any fingerprint that is placed in $RSA_CERT_FINGERPRINT_SHA2 is
               # also added to $CERT_FINGERPRINT_SHA2, so if $CERT_FINGERPRINT_SHA2
               # is not empty, but $RSA_CERT_FINGERPRINT_SHA2 is empty, then the server
               # doesn't have an RSA certificate.
               if [[ -z "$CERT_FINGERPRINT_SHA2" ]]; then
                    get_host_cert "-cipher aRSA"
                    [[ $? -eq 0 ]] && cert_fingerprint_sha2="$($OPENSSL x509 -noout -in $HOSTCERT -fingerprint -sha256 2>>$ERRFILE | sed -e 's/^.*Fingerprint=//' -e 's/://g' )"
               else
                    cert_fingerprint_sha2="$RSA_CERT_FINGERPRINT_SHA2"
               fi
               if [[ -n "$cert_fingerprint_sha2" ]]; then
                    outln "$spaces make sure you don't use this certificate elsewhere with SSLv2 enabled services"
                    if [[ "$DEBUG" -ge 1 ]] || "$SHOW_CENSYS_LINK"; then
# not advertising it as it after 5 tries and account is needed
                         cert_fingerprint_sha2=${cert_fingerprint_sha2/SHA256 /}
                         outln "$spaces https://censys.io/ipv4?q=$cert_fingerprint_sha2 could help you to find out"
                         fileout "drown" "INFO" "make sure you don't use this certificate elsewhere with SSLv2 enabled services, see https://censys.io/ipv4?q=$cert_fingerprint_sha2"
                    fi
               else
                    outln "$spaces no RSA certificate, thus certificate can't be used with SSLv2 elsewhere"
                    fileout "drown" "INFO" "no RSA certificate, thus certificate can't be used with SSLv2 elsewhere"
               fi
               ret=0
               ;;
     esac

     return $ret
}



# Browser Exploit Against SSL/TLS: don't use CBC Ciphers in SSLv3 TLSv1.0
run_beast(){
     local hexc dash cbc_cipher sslvers auth mac export sni
     local -a ciph hexcode normalized_hexcode kx enc export2
     local proto proto_hex
     local -i i nr_ciphers=0 sclient_success=0
     local detected_cbc_ciphers="" ciphers_to_test
     local higher_proto_supported=""
     local vuln_beast=false
     local spaces="                                           "
     local cr=$'\n'
     local first=true
     local continued=false
     local cbc_cipher_list="ECDHE-RSA-AES256-SHA:ECDHE-ECDSA-AES256-SHA:SRP-DSS-AES-256-CBC-SHA:SRP-RSA-AES-256-CBC-SHA:SRP-AES-256-CBC-SHA:DHE-PSK-AES256-CBC-SHA:DHE-RSA-AES256-SHA:DHE-DSS-AES256-SHA:DH-RSA-AES256-SHA:DH-DSS-AES256-SHA:DHE-RSA-CAMELLIA256-SHA:DHE-DSS-CAMELLIA256-SHA:DH-RSA-CAMELLIA256-SHA:DH-DSS-CAMELLIA256-SHA:AECDH-AES256-SHA:ADH-AES256-SHA:ADH-CAMELLIA256-SHA:ECDH-RSA-AES256-SHA:ECDH-ECDSA-AES256-SHA:AES256-SHA:ECDHE-PSK-AES256-CBC-SHA:CAMELLIA256-SHA:RSA-PSK-AES256-CBC-SHA:PSK-AES256-CBC-SHA:ECDHE-RSA-AES128-SHA:ECDHE-ECDSA-AES128-SHA:SRP-DSS-AES-128-CBC-SHA:SRP-RSA-AES-128-CBC-SHA:SRP-AES-128-CBC-SHA:DHE-RSA-AES128-SHA:DHE-DSS-AES128-SHA:DH-RSA-AES128-SHA:DH-DSS-AES128-SHA:DHE-RSA-SEED-SHA:DHE-DSS-SEED-SHA:DH-RSA-SEED-SHA:DH-DSS-SEED-SHA:DHE-RSA-CAMELLIA128-SHA:DHE-DSS-CAMELLIA128-SHA:DH-RSA-CAMELLIA128-SHA:DH-DSS-CAMELLIA128-SHA:AECDH-AES128-SHA:ADH-AES128-SHA:ADH-SEED-SHA:ADH-CAMELLIA128-SHA:ECDH-RSA-AES128-SHA:ECDH-ECDSA-AES128-SHA:AES128-SHA:ECDHE-PSK-AES128-CBC-SHA:DHE-PSK-AES128-CBC-SHA:SEED-SHA:CAMELLIA128-SHA:IDEA-CBC-SHA:RSA-PSK-AES128-CBC-SHA:PSK-AES128-CBC-SHA:KRB5-IDEA-CBC-SHA:KRB5-IDEA-CBC-MD5:ECDHE-RSA-DES-CBC3-SHA:ECDHE-ECDSA-DES-CBC3-SHA:SRP-DSS-3DES-EDE-CBC-SHA:SRP-RSA-3DES-EDE-CBC-SHA:SRP-3DES-EDE-CBC-SHA:EDH-RSA-DES-CBC3-SHA:EDH-DSS-DES-CBC3-SHA:DH-RSA-DES-CBC3-SHA:DH-DSS-DES-CBC3-SHA:AECDH-DES-CBC3-SHA:ADH-DES-CBC3-SHA:ECDH-RSA-DES-CBC3-SHA:ECDH-ECDSA-DES-CBC3-SHA:DES-CBC3-SHA:RSA-PSK-3DES-EDE-CBC-SHA:PSK-3DES-EDE-CBC-SHA:KRB5-DES-CBC3-SHA:KRB5-DES-CBC3-MD5:ECDHE-PSK-3DES-EDE-CBC-SHA:DHE-PSK-3DES-EDE-CBC-SHA:EXP1024-DHE-DSS-DES-CBC-SHA:EDH-RSA-DES-CBC-SHA:EDH-DSS-DES-CBC-SHA:DH-RSA-DES-CBC-SHA:DH-DSS-DES-CBC-SHA:ADH-DES-CBC-SHA:EXP1024-DES-CBC-SHA:DES-CBC-SHA:KRB5-DES-CBC-SHA:KRB5-DES-CBC-MD5:EXP-EDH-RSA-DES-CBC-SHA:EXP-EDH-DSS-DES-CBC-SHA:EXP-ADH-DES-CBC-SHA:EXP-DES-CBC-SHA:EXP-RC2-CBC-MD5:EXP-KRB5-RC2-CBC-SHA:EXP-KRB5-DES-CBC-SHA:EXP-KRB5-RC2-CBC-MD5:EXP-KRB5-DES-CBC-MD5:EXP-DH-DSS-DES-CBC-SHA:EXP-DH-RSA-DES-CBC-SHA"
     local cbc_ciphers_hex="c0,14, c0,0a, c0,22, c0,21, c0,20, 00,91, 00,39, 00,38, 00,37, 00,36, 00,88, 00,87, 00,86, 00,85, c0,19, 00,3a, 00,89, c0,0f, c0,05, 00,35, c0,36, 00,84, 00,95, 00,8d, c0,13, c0,09, c0,1f, c0,1e, c0,1d, 00,33, 00,32, 00,31, 00,30, 00,9a, 00,99, 00,98, 00,97, 00,45, 00,44, 00,43, 00,42, c0,18, 00,34, 00,9b, 00,46, c0,0e, c0,04, 00,2f, c0,35, 00,90, 00,96, 00,41, 00,07, 00,94, 00,8c, 00,21, 00,25, c0,12, c0,08, c0,1c, c0,1b, c0,1a, 00,16, 00,13, 00,10, 00,0d, c0,17, 00,1b, c0,0d, c0,03, 00,0a, 00,93, 00,8b, 00,1f, 00,23, c0,34, 00,8f, 00,63, 00,15, 00,12, 00,0f, 00,0c, 00,1a, 00,62, 00,09, 00,1e, 00,22, 00,14, 00,11, 00,19, 00,08, 00,06, 00,27, 00,26, 00,2a, 00,29, 00,0b, 00,0e"
     local has_dh_bits="$HAS_DH_BITS"
     local using_sockets=true
     local cve="CVE-2011-3389"
     local cwe="CWE-20"
     local hint=""

     if [[ $VULN_COUNT -le $VULN_THRESHLD ]]; then
          outln
          pr_headlineln " Testing for BEAST vulnerability "
     fi
     if [[ $VULN_COUNT -le $VULN_THRESHLD ]] || "$WIDE"; then
          outln
     fi
     pr_bold " BEAST"; out " ($cve)                     "

     "$SSL_NATIVE" && using_sockets=false
     [[ $TLS_NR_CIPHERS == 0 ]] && using_sockets=false
     if "$using_sockets" || [[ $OSSL_VER_MAJOR -lt 1 ]]; then
          for (( i=0; i < TLS_NR_CIPHERS; i++ )); do
               hexc="${TLS_CIPHER_HEXCODE[i]}"
               if [[ ${#hexc} -eq 9 ]] && [[ "${TLS_CIPHER_RFC_NAME[i]}" =~ CBC ]] && \
                  [[ ! "${TLS_CIPHER_RFC_NAME[i]}" =~ "SHA256" ]] && [[ ! "${TLS_CIPHER_RFC_NAME[i]}" =~ "SHA384" ]]; then
                    cbc_cipher_list_hex+=", ${hexc:2:2},${hexc:7:2}"
                    ciph[nr_ciphers]="${TLS_CIPHER_OSSL_NAME[i]}"
                    hexcode[nr_ciphers]="${hexc:2:2},${hexc:7:2}"
                    rfc_ciph[nr_ciphers]="${TLS_CIPHER_RFC_NAME[i]}"
                    kx[nr_ciphers]="${TLS_CIPHER_KX[i]}"
                    enc[nr_ciphers]="${TLS_CIPHER_ENC[i]}"
                    export2[nr_ciphers]="${TLS_CIPHER_EXPORT[i]}"
                    ossl_supported[nr_ciphers]=${TLS_CIPHER_OSSL_SUPPORTED[i]}
                    if "$using_sockets" && "$WIDE" && ! "$has_dh_bits" && \
                       ( [[ ${kx[nr_ciphers]} == "Kx=ECDH" ]] || [[ ${kx[nr_ciphers]} == "Kx=DH" ]] || [[ ${kx[nr_ciphers]} == "Kx=EDH" ]] ); then
                         ossl_supported[nr_ciphers]=false
                    fi
                    if [[ "${hexc:2:2}" == "00" ]]; then
                         normalized_hexcode[nr_ciphers]="x${hexc:7:2}"
                    else
                         normalized_hexcode[nr_ciphers]="x${hexc:2:2}${hexc:7:2}"
                    fi
                    nr_ciphers+=1
               fi
          done
          cbc_cipher_list_hex="${cbc_cipher_list_hex:2}"
     else
          while read hexc dash ciph[nr_ciphers] sslvers kx[nr_ciphers] auth enc[nr_ciphers] mac export2[nr_ciphers]; do
               if [[ ":${cbc_cipher_list}:" =~ ":${ciph[nr_ciphers]}:" ]]; then
                    ossl_supported[nr_ciphers]=true
                    if [[ "${hexc:2:2}" == "00" ]]; then
                         normalized_hexcode[nr_ciphers]="x${hexc:7:2}"
                    else
                         normalized_hexcode[nr_ciphers]="x${hexc:2:2}${hexc:7:2}"
                    fi
                    nr_ciphers+=1
               fi
          done  < <($OPENSSL ciphers -tls1 -V 'ALL:COMPLEMENTOFALL:@STRENGTH' 2>>$ERRFILE)
     fi

     # first determine whether it's mitigated by higher protocols
     for proto in tls1_1 tls1_2; do
          $OPENSSL s_client -state -"$proto" $STARTTLS $BUGS -connect $NODEIP:$PORT $PROXY $SNI 2>>$ERRFILE >$TMPFILE </dev/null
          if sclient_connect_successful $? $TMPFILE; then
               higher_proto_supported="$higher_proto_supported ""$(grep -aw "Protocol" $TMPFILE | sed -e 's/^.*Protocol .*://' -e 's/ //g')"
          fi
     done

     for proto in ssl3 tls1; do
          if [[ "$proto" == "ssl3" ]] && ! "$using_sockets" && ! locally_supported "-$proto"; then
               continued=true
               out "                                           "
               continue
          fi
          if [[ "$proto" != "ssl3" ]] || "$HAS_SSL3"; then
               [[ ! "$proto" =~ ssl ]] && sni="$SNI" || sni=""
               $OPENSSL s_client -"$proto" $STARTTLS $BUGS -connect $NODEIP:$PORT $PROXY $sni >$TMPFILE 2>>$ERRFILE </dev/null
               sclient_connect_successful $? $TMPFILE
          else
               tls_sockets "00" "$TLS_CIPHER"
          fi
          if [[ $? -ne 0 ]]; then                                # protocol supported?
               if "$continued"; then                             # second round: we hit TLS1
                    if "$HAS_SSL3" || "$using_sockets"; then
                         pr_done_goodln "no SSL3 or TLS1 (OK)"
                         fileout "beast" "OK" "BEAST: not vulnerable, no SSL3 or TLS1" "$cve" "$cwe"
                    else
                         pr_done_goodln "no TLS1 (OK)"
                         fileout "beast" "OK" "BEAST: not vulnerable, no TLS1" "$cve" "$cwe"
                    fi
                    return 0
               else                # protocol not succeeded but it's the first time
                    continued=true
                    continue       # protocol not supported, so we do not need to check each cipher with that protocol
               fi
          fi # protocol succeeded

          # now we test in one shot with the precompiled ciphers
          if "$using_sockets"; then
               case "$proto" in
                    "ssl3") proto_hex="00" ;;
                    "tls1") proto_hex="01" ;;
               esac
               tls_sockets "$proto_hex" "$cbc_cipher_list_hex"
               [[ $? -eq 0 ]] || continue
          else
               $OPENSSL s_client -"$proto" -cipher "$cbc_cipher_list" $STARTTLS $BUGS -connect $NODEIP:$PORT $PROXY $sni >$TMPFILE 2>>$ERRFILE </dev/null
               sclient_connect_successful $? $TMPFILE || continue
          fi

          detected_cbc_ciphers=""
          for ((i=0; i<nr_ciphers; i++)); do
               ciphers_found[i]=false
               sigalg[nr_ciphers]=""
          done
          while true; do
               ciphers_to_test=""
               for (( i=0; i < nr_ciphers; i++ )); do
                    ! "${ciphers_found[i]}" && "${ossl_supported[i]}" && ciphers_to_test+=":${ciph[i]}"
               done
               [[ -z "$ciphers_to_test" ]] && break
               $OPENSSL s_client -cipher "${ciphers_to_test:1}" -"$proto" $STARTTLS $BUGS -connect $NODEIP:$PORT $PROXY $sni >$TMPFILE 2>>$ERRFILE </dev/null
               sclient_connect_successful $? $TMPFILE || break
               cbc_cipher=$(awk '/Cipher *:/ { print $3 }' $TMPFILE)
               [[ -z "$cbc_cipher" ]] && break
               for (( i=0; i < nr_ciphers; i++ )); do
                    [[ "$cbc_cipher" == "${ciph[i]}" ]] && break
               done
               ciphers_found[i]=true
               if [[ -z "$SHOW_RFC" ]] || [[ "${rfc_ciph[i]}" == "-" ]]; then
                    detected_cbc_ciphers+="${ciph[i]} "
               else
                    detected_cbc_ciphers+="${rfc_ciph[i]} "
               fi
               vuln_beast=true
               if "$WIDE" && ( [[ ${kx[i]} == "Kx=ECDH" ]] || [[ ${kx[i]} == "Kx=DH" ]] || [[ ${kx[i]} == "Kx=EDH" ]] ); then
                    dhlen=$(read_dhbits_from_file "$TMPFILE" quiet)
                    kx[i]="${kx[i]} $dhlen"
               fi
               "$WIDE" && "$SHOW_SIGALGO" && grep -q "\-\-\-\-\-BEGIN CERTIFICATE\-\-\-\-\-" $TMPFILE && \
                    sigalg[i]="$($OPENSSL x509 -noout -text -in $TMPFILE | awk -F':' '/Signature Algorithm/ { print $2 }' | head -1)"
          done
          if "$using_sockets"; then
               while true; do
                    ciphers_to_test=""
                    for (( i=0; i < nr_ciphers; i++ )); do
                         ! "${ciphers_found[i]}" && ciphers_to_test+=", ${hexcode[i]}"
                    done
                    [[ -z "$ciphers_to_test" ]] && break
                    if "$SHOW_SIGALGO"; then
                         tls_sockets "$proto_hex" "${ciphers_to_test:2}, 00,ff" "all"
                    else
                         tls_sockets "$proto_hex" "${ciphers_to_test:2}, 00,ff" "ephemeralkey"
                    fi
                    [[ $? -ne 0 ]] && break
                    cbc_cipher=$(awk '/Cipher *:/ { print $3 }' "$TEMPDIR/$NODEIP.parse_tls_serverhello.txt")
                    for (( i=0; i < nr_ciphers; i++ )); do
                         [[ "$cbc_cipher" == "${rfc_ciph[i]}" ]] && break
                    done
                    ciphers_found[i]=true
                    if ( [[ -z "$SHOW_RFC" ]] && [[ "${ciph[i]}" != "-" ]] ) || [[ "${rfc_ciph[i]}" == "-" ]]; then
                         detected_cbc_ciphers+=" ${ciph[i]}"
                    else
                         detected_cbc_ciphers+=" ${rfc_ciph[i]}"
                    fi
                    vuln_beast=true
                    if "$WIDE" && ( [[ ${kx[i]} == "Kx=ECDH" ]] || [[ ${kx[i]} == "Kx=DH" ]] || [[ ${kx[i]} == "Kx=EDH" ]] ); then
                         dhlen=$(read_dhbits_from_file "$TEMPDIR/$NODEIP.parse_tls_serverhello.txt" quiet)
                         kx[i]="${kx[i]} $dhlen"
                    fi
                    "$WIDE" && "$SHOW_SIGALGO" && [[ -r "$HOSTCERT" ]] && \
                         sigalg[i]="$($OPENSSL x509 -noout -text -in "$HOSTCERT" | awk -F':' '/Signature Algorithm/ { print $2 }' | head -1)"
               done
          fi

          if "$WIDE" && [[ -n "$detected_cbc_ciphers" ]]; then
               out "\n "; pr_underline "$(toupper $proto):\n";
               if "$first"; then
                    neat_header
               fi
               first=false
               for (( i=0; i < nr_ciphers; i++ )); do
                    if "${ciphers_found[i]}" || "$SHOW_EACH_C"; then
                         export="${export2[i]}"
                         neat_list "$(tolower "${normalized_hexcode[i]}")" "${ciph[i]}" "${kx[i]}" "${enc[i]}" "${ciphers_found[i]}"
                         if "$SHOW_EACH_C"; then
                              if "${ciphers_found[i]}"; then
                                   if [[ -n "$higher_proto_supported" ]]; then
                                        pr_svrty_low "available"
                                   else
                                        pr_svrty_medium "available"
                                   fi
                              else
                                   pr_deemphasize "not a/v"
                              fi
                         fi
                         outln "${sigalg[i]}"
                    fi
               done
          fi

          if ! "$WIDE"; then
               if [[ -n "$detected_cbc_ciphers" ]]; then
                    fileout "cbc_$proto" "MEDIUM" "BEAST: CBC ciphers for $(toupper $proto): $detected_cbc_ciphers" "$cve" "$cwe" "$hint"
                    ! "$first" && out "$spaces"
                    out "$(toupper $proto): "
                    [[ -n "$higher_proto_supported" ]] && \
                         out_row_aligned_max_width "$detected_cbc_ciphers" "                                                 " $TERM_WIDTH pr_svrty_low || \
                         out_row_aligned_max_width "$detected_cbc_ciphers" "                                                 " $TERM_WIDTH pr_svrty_medium
                    outln
                    detected_cbc_ciphers=""  # empty for next round
                    first=false
               else
                    [[ $proto == "tls1" ]] && ! $first && echo -n "$spaces "
                    pr_done_goodln "no CBC ciphers for $(toupper $proto) (OK)"
                    first=false
               fi
          else
               if ! "$vuln_beast" ; then
                    pr_done_goodln " no CBC ciphers for $(toupper $proto) (OK)"
                    fileout "cbc_$proto" "OK" "BEAST: No CBC ciphers for $(toupper $proto)" "$cve" "$cwe"
               fi
          fi
     done  # for proto in ssl3 tls1

     if "$vuln_beast"; then
          if [[ -n "$higher_proto_supported" ]]; then
               if "$WIDE"; then
                    outln
                    # NOT ok seems too harsh for me if we have TLS >1.0
                    pr_svrty_low "VULNERABLE"
                    outln " -- but also supports higher protocols (possible mitigation):$higher_proto_supported"
               else
                    out "$spaces"
                    pr_svrty_low "VULNERABLE"
                    outln " -- but also supports higher protocols (possible mitigation):$higher_proto_supported"
               fi
               fileout "beast" "LOW" "BEAST: VULNERABLE -- but also supports higher protocols (possible mitigation):$higher_proto_supported" "$cve" "$cwe" "$hint"
          else
               if "$WIDE"; then
                    outln
               else
                    out "$spaces"
               fi
               pr_svrty_medium "VULNERABLE"
               outln " -- and no higher protocols as mitigation supported"
               fileout "beast" "MEDIUM" "BEAST: VULNERABLE -- and no higher protocols as mitigation supported" "$cve" "$cwe" "$hint"
          fi
     fi
     "$first" && ! "$vuln_beast" && pr_done_goodln "no CBC ciphers found for any protocol (OK)"

     "$using_sockets" && HAS_DH_BITS="$has_dh_bits"
     tmpfile_handle $FUNCNAME.txt
     return 0
}


# http://www.isg.rhul.ac.uk/tls/Lucky13.html
# in a nutshell: don't offer CBC suites (again). MAC as a fix for padding oracles is not enough. Best: TLS v1.2+ AES GCM
run_lucky13() {
     local spaces="                                           "
     local cbc_ciphers="ECDHE-RSA-AES256-SHA384:ECDHE-ECDSA-AES256-SHA384:ECDHE-RSA-AES256-SHA:ECDHE-ECDSA-AES256-SHA:SRP-DSS-AES-256-CBC-SHA:SRP-RSA-AES-256-CBC-SHA:SRP-AES-256-CBC-SHA:RSA-PSK-AES256-CBC-SHA384:DHE-PSK-AES256-CBC-SHA384:DHE-PSK-AES256-CBC-SHA:ECDHE-PSK-CAMELLIA256-SHA384:RSA-PSK-CAMELLIA256-SHA384:DHE-PSK-CAMELLIA256-SHA384:PSK-AES256-CBC-SHA384:PSK-CAMELLIA256-SHA384:DHE-RSA-AES256-SHA256:DHE-DSS-AES256-SHA256:DH-RSA-AES256-SHA256:DH-DSS-AES256-SHA256:DHE-RSA-AES256-SHA:DHE-DSS-AES256-SHA:DH-RSA-AES256-SHA:DH-DSS-AES256-SHA:ECDHE-RSA-CAMELLIA256-SHA384:ECDHE-ECDSA-CAMELLIA256-SHA384:DHE-RSA-CAMELLIA256-SHA256:DHE-DSS-CAMELLIA256-SHA256:DH-RSA-CAMELLIA256-SHA256:DH-DSS-CAMELLIA256-SHA256:DHE-RSA-CAMELLIA256-SHA:DHE-DSS-CAMELLIA256-SHA:DH-RSA-CAMELLIA256-SHA:DH-DSS-CAMELLIA256-SHA:AECDH-AES256-SHA:ADH-AES256-SHA256:ADH-AES256-SHA:ADH-CAMELLIA256-SHA256:ADH-CAMELLIA256-SHA:ECDH-RSA-AES256-SHA384:ECDH-ECDSA-AES256-SHA384:ECDH-RSA-AES256-SHA:ECDH-ECDSA-AES256-SHA:ECDH-RSA-CAMELLIA256-SHA384:ECDH-ECDSA-CAMELLIA256-SHA384:AES256-SHA256:AES256-SHA:CAMELLIA256-SHA256:ECDHE-PSK-AES256-CBC-SHA384:ECDHE-PSK-AES256-CBC-SHA:CAMELLIA256-SHA:RSA-PSK-AES256-CBC-SHA:PSK-AES256-CBC-SHA:ECDHE-RSA-AES128-SHA256:ECDHE-ECDSA-AES128-SHA256:ECDHE-RSA-AES128-SHA:ECDHE-ECDSA-AES128-SHA:SRP-DSS-AES-128-CBC-SHA:SRP-RSA-AES-128-CBC-SHA:SRP-AES-128-CBC-SHA:DHE-RSA-AES128-SHA256:DHE-DSS-AES128-SHA256:DH-RSA-AES128-SHA256:DH-DSS-AES128-SHA256:DHE-RSA-AES128-SHA:DHE-DSS-AES128-SHA:DH-RSA-AES128-SHA:DH-DSS-AES128-SHA:ECDHE-RSA-CAMELLIA128-SHA256:ECDHE-ECDSA-CAMELLIA128-SHA256:DHE-RSA-CAMELLIA128-SHA256:DHE-DSS-CAMELLIA128-SHA256:DH-RSA-CAMELLIA128-SHA256:DH-DSS-CAMELLIA128-SHA256:DHE-RSA-SEED-SHA:DHE-DSS-SEED-SHA:DH-RSA-SEED-SHA:DH-DSS-SEED-SHA:DHE-RSA-CAMELLIA128-SHA:DHE-DSS-CAMELLIA128-SHA:DH-RSA-CAMELLIA128-SHA:DH-DSS-CAMELLIA128-SHA:AECDH-AES128-SHA:ADH-AES128-SHA256:ADH-AES128-SHA:ADH-CAMELLIA128-SHA256:ADH-SEED-SHA:ADH-CAMELLIA128-SHA:ECDH-RSA-AES128-SHA256:ECDH-ECDSA-AES128-SHA256:ECDH-RSA-AES128-SHA:ECDH-ECDSA-AES128-SHA:ECDH-RSA-CAMELLIA128-SHA256:ECDH-ECDSA-CAMELLIA128-SHA256:AES128-SHA256:AES128-SHA:CAMELLIA128-SHA256:ECDHE-PSK-AES128-CBC-SHA256:ECDHE-PSK-AES128-CBC-SHA:RSA-PSK-AES128-CBC-SHA256:DHE-PSK-AES128-CBC-SHA256:DHE-PSK-AES128-CBC-SHA:SEED-SHA:CAMELLIA128-SHA:ECDHE-PSK-CAMELLIA128-SHA256:RSA-PSK-CAMELLIA128-SHA256:DHE-PSK-CAMELLIA128-SHA256:PSK-AES128-CBC-SHA256:PSK-CAMELLIA128-SHA256:IDEA-CBC-SHA:RSA-PSK-AES128-CBC-SHA:PSK-AES128-CBC-SHA:KRB5-IDEA-CBC-SHA:KRB5-IDEA-CBC-MD5:ECDHE-RSA-DES-CBC3-SHA:ECDHE-ECDSA-DES-CBC3-SHA:SRP-DSS-3DES-EDE-CBC-SHA:SRP-RSA-3DES-EDE-CBC-SHA:SRP-3DES-EDE-CBC-SHA:EDH-RSA-DES-CBC3-SHA:EDH-DSS-DES-CBC3-SHA:DH-RSA-DES-CBC3-SHA:DH-DSS-DES-CBC3-SHA:AECDH-DES-CBC3-SHA:ADH-DES-CBC3-SHA:ECDH-RSA-DES-CBC3-SHA:ECDH-ECDSA-DES-CBC3-SHA:DES-CBC3-SHA:RSA-PSK-3DES-EDE-CBC-SHA:PSK-3DES-EDE-CBC-SHA:KRB5-DES-CBC3-SHA:KRB5-DES-CBC3-MD5:ECDHE-PSK-3DES-EDE-CBC-SHA:DHE-PSK-3DES-EDE-CBC-SHA:EXP1024-DHE-DSS-DES-CBC-SHA:EDH-RSA-DES-CBC-SHA:EDH-DSS-DES-CBC-SHA:DH-RSA-DES-CBC-SHA:DH-DSS-DES-CBC-SHA:ADH-DES-CBC-SHA:EXP1024-DES-CBC-SHA:DES-CBC-SHA:KRB5-DES-CBC-SHA:KRB5-DES-CBC-MD5:EXP-EDH-RSA-DES-CBC-SHA:EXP-EDH-DSS-DES-CBC-SHA:EXP-ADH-DES-CBC-SHA:EXP-DES-CBC-SHA:EXP-RC2-CBC-MD5:EXP-KRB5-RC2-CBC-SHA:EXP-KRB5-DES-CBC-SHA:EXP-KRB5-RC2-CBC-MD5:EXP-KRB5-DES-CBC-MD5:EXP-DH-DSS-DES-CBC-SHA:EXP-DH-RSA-DES-CBC-SHA"
     cbc_ciphers_hex="c0,28, c0,24, c0,14, c0,0a, c0,22, c0,21, c0,20, 00,b7, 00,b3, 00,91, c0,9b, c0,99, c0,97, 00,af, c0,95, 00,6b, 00,6a, 00,69, 00,68, 00,39, 00,38, 00,37, 00,36, c0,77, c0,73, 00,c4, 00,c3, 00,c2, 00,c1, 00,88, 00,87, 00,86, 00,85, c0,19, 00,6d, 00,3a, 00,c5, 00,89, c0,2a, c0,26, c0,0f, c0,05, c0,79, c0,75, 00,3d, 00,35, 00,c0, c0,38, c0,36, 00,84, 00,95, 00,8d, c0,3d, c0,3f, c0,41, c0,43, c0,45, c0,47, c0,49, c0,4b, c0,4d, c0,4f, c0,65, c0,67, c0,69, c0,71, c0,27, c0,23, c0,13, c0,09, c0,1f, c0,1e, c0,1d, 00,67, 00,40, 00,3f, 00,3e, 00,33, 00,32, 00,31, 00,30, c0,76, c0,72, 00,be, 00,bd, 00,bc, 00,bb, 00,9a, 00,99, 00,98, 00,97, 00,45, 00,44, 00,43, 00,42, c0,18, 00,6c, 00,34, 00,bf, 00,9b, 00,46, c0,29, c0,25, c0,0e, c0,04, c0,78, c0,74, 00,3c, 00,2f, 00,ba, c0,37, c0,35, 00,b6, 00,b2, 00,90, 00,96, 00,41, c0,9a, c0,98, c0,96, 00,ae, c0,94, 00,07, 00,94, 00,8c, 00,21, 00,25, c0,3c, c0,3e, c0,40, c0,42, c0,44, c0,46, c0,48, c0,4a, c0,4c, c0,4e, c0,64, c0,66, c0,68, c0,70, c0,12, c0,08, c0,1c, c0,1b, c0,1a, 00,16, 00,13, 00,10, 00,0d, c0,17, 00,1b, c0,0d, c0,03, 00,0a, 00,93, 00,8b, 00,1f, 00,23, c0,34, 00,8f, fe,ff, ff,e0, 00,63, 00,15, 00,12, 00,0f, 00,0c, 00,1a, 00,62, 00,09, 00,1e, 00,22, fe,fe, ff,e1, 00,14, 00,11, 00,19, 00,08, 00,06, 00,27, 00,26, 00,2a, 00,29, 00,0b, 00,0e"
#FIXME: we have 154 ciphers here, some devices can only take 128 ciphers!!
     local has_dh_bits="$HAS_DH_BITS"
     local -i nr_supported_ciphers=0
     local using_sockets=true
     local cve="CVE-2013-0169"
     local cwe="CWE-310"
     local hint=""

     [[ $VULN_COUNT -le $VULN_THRESHLD ]] && outln && pr_headlineln " Testing for LUCKY13 vulnerability " && outln
     pr_bold " LUCKY13"; out " ($cve)                   "

     "$SSL_NATIVE" && using_sockets=false
     # The openssl binary distributed has almost everything we need (PSK, KRB5 ciphers and feff, ffe0 are typically missing).
     # Measurements show that there's little impact whether we use sockets or TLS here, so the default is sockets here

     if "$using_sockets"; then
          tls_sockets "03" "${cbc_ciphers_hex}"
          sclient_success=$?
     else
          nr_cbc_ciphers=$(count_ciphers $cbc_ciphers)
          nr_supported_ciphers=$(count_ciphers $(actually_supported_ciphers $cbc_ciphers))
          $OPENSSL s_client $STARTTLS $BUGS -cipher $cbc_ciphers -connect $NODEIP:$PORT $PROXY >$TMPFILE $SNI 2>$ERRFILE </dev/null
          sclient_connect_successful $? $TMPFILE
          sclient_success=$?
          [[ "$DEBUG" -eq 2 ]] && egrep -q "error|failure" $ERRFILE | egrep -av "unable to get local|verify error"
     fi
     if [[ $sclient_success -eq 0 ]]; then
          pr_svrty_low "VULNERABLE"; out ", uses cipher block chaining (CBC) ciphers"
          fileout "lucky13" "LOW" "LUCKY13, uses cipher block chaining (CBC) ciphers" "$cve" "$cwe" "$hint"
     else
          pr_done_best "not vulnerable (OK)";
          if "$using_sockets"; then
               fileout "lucky13" "OK" "LUCKY13: not vulnerable" "$cve" "$cwe"
          else
               if [[ "$nr_supported_ciphers" -ge 133 ]]; then
                    # Likely only PSK/KRB5 ciphers are missing: display discrepancy but no warning
                    out ", $nr_supported_ciphers/$nr_cbc_ciphers local ciphers"
               else
                    pr_warning ", $nr_supported_ciphers/$nr_cbc_ciphers local ciphers"
               fi
               fileout "lucky13" "OK" "LUCKY13: not vulnerable ($nr_supported_ciphers of $nr_cbc_ciphers local ciphers" "$cve" "$cwe"
          fi
     fi
     outln
     tmpfile_handle $FUNCNAME.txt
     return $sclient_success
}


# https://tools.ietf.org/html/rfc7465    REQUIRES that TLS clients and servers NEVER negotiate the use of RC4 cipher suites!
# https://en.wikipedia.org/wiki/Transport_Layer_Security#RC4_attacks
# http://blog.cryptographyengineering.com/2013/03/attack-of-week-rc4-is-kind-of-broken-in.html
run_rc4() {
     local -i rc4_offered=0
     local -i nr_ciphers=0 nr_ossl_ciphers=0 nr_nonossl_ciphers=0 ret
     local n auth mac export hexc sslv2_ciphers_hex="" sslv2_ciphers_ossl="" s
     local -a normalized_hexcode hexcode ciph sslvers kx enc export2 sigalg ossl_supported
     local -i i
     local -a ciphers_found ciphers_found2 hexcode2 ciph2 sslvers2 rfc_ciph2
     local -i -a index
     local dhlen available="" ciphers_to_test supported_sslv2_ciphers addcmd=""
     local has_dh_bits="$HAS_DH_BITS" rc4_detected=""
     local using_sockets=true
     local cve="CVE-2013-2566, CVE-2015-2808"
     local cwe="CWE-310"
     local hint=""

     "$SSL_NATIVE" && using_sockets=false
     "$FAST" && using_sockets=false
     [[ $TLS_NR_CIPHERS == 0 ]] && using_sockets=false

     if [[ $VULN_COUNT -le $VULN_THRESHLD ]]; then
          outln
          pr_headlineln " Checking for vulnerable RC4 Ciphers "
     fi
     if [[ $VULN_COUNT -le $VULN_THRESHLD ]] || "$WIDE"; then
          outln
     fi
     pr_bold " RC4"; out " ($cve)        "

     # get a list of all the cipher suites to test
     if "$using_sockets" || [[ $OSSL_VER_MAJOR -lt 1 ]]; then
          for (( i=0; i < TLS_NR_CIPHERS; i++ )); do
               if [[ "${TLS_CIPHER_RFC_NAME[i]}" =~ "RC4" ]] && ( "$using_sockets" || "${TLS_CIPHER_OSSL_SUPPORTED[i]}" ); then
                    hexc="$(tolower "${TLS_CIPHER_HEXCODE[i]}")"
                    ciph[nr_ciphers]="${TLS_CIPHER_OSSL_NAME[i]}"
                    rfc_ciph[nr_ciphers]="${TLS_CIPHER_RFC_NAME[i]}"
                    sslvers[nr_ciphers]="${TLS_CIPHER_SSLVERS[i]}"
                    kx[nr_ciphers]="${TLS_CIPHER_KX[i]}"
                    enc[nr_ciphers]="${TLS_CIPHER_ENC[i]}"
                    export2[nr_ciphers]="${TLS_CIPHER_EXPORT[i]}"
                    ciphers_found[nr_ciphers]=false
                    sigalg[nr_ciphers]=""
                    ossl_supported[nr_ciphers]="${TLS_CIPHER_OSSL_SUPPORTED[i]}"
                    if "$using_sockets" && "$WIDE" && ! "$HAS_DH_BITS" &&
                       ( [[ ${kx[nr_ciphers]} == "Kx=ECDH" ]] || [[ ${kx[nr_ciphers]} == "Kx=DH" ]] || [[ ${kx[nr_ciphers]} == "Kx=EDH" ]] ); then
                         ossl_supported[nr_ciphers]=false
                    fi
                    if [[ ${#hexc} -eq 9 ]]; then
                         hexcode[nr_ciphers]="${hexc:2:2},${hexc:7:2}"
                         if [[ "${hexc:2:2}" == "00" ]]; then
                              normalized_hexcode[nr_ciphers]="x${hexc:7:2}"
                         else
                              normalized_hexcode[nr_ciphers]="x${hexc:2:2}${hexc:7:2}"
                         fi
                    else
                         hexcode[nr_ciphers]="${hexc:2:2},${hexc:7:2},${hexc:12:2}"
                         normalized_hexcode[nr_ciphers]="x${hexc:2:2}${hexc:7:2}${hexc:12:2}"
                         sslv2_ciphers_hex+=", ${hexcode[nr_ciphers]}"
                         sslv2_ciphers_ossl+=":${ciph[nr_ciphers]}"
                    fi
                    nr_ciphers+=1
               fi
          done
     else
          while read hexc n ciph[nr_ciphers] sslvers[nr_ciphers] kx[nr_ciphers] auth enc[nr_ciphers] mac export2[nr_ciphers]; do
               if [[ "${ciph[nr_ciphers]}" =~ "RC4" ]]; then
                    ciphers_found[nr_ciphers]=false
                    if [[ ${#hexc} -eq 9 ]]; then
                         if [[ "${hexc:2:2}" == "00" ]]; then
                              normalized_hexcode[nr_ciphers]="$(tolower "x${hexc:7:2}")"
                         else
                              normalized_hexcode[nr_ciphers]="$(tolower "x${hexc:2:2}${hexc:7:2}")"
                         fi
                    else
                         normalized_hexcode[nr_ciphers]="$(tolower "x${hexc:2:2}${hexc:7:2}${hexc:12:2}")"
                         sslv2_ciphers_ossl+=":${ciph[nr_ciphers]}"
                    fi
                    sigalg[nr_ciphers]=""
                    ossl_supported[nr_ciphers]=true
                    nr_ciphers+=1
               fi
          done < <($OPENSSL ciphers -V 'ALL:COMPLEMENTOFALL:@STRENGTH' 2>>$ERRFILE)
     fi

     if "$using_sockets" && [[ -n "$sslv2_ciphers_hex" ]]; then
          sslv2_sockets "${sslv2_ciphers_hex:2}" "true"
          if [[ $? -eq 3 ]] && [[ "$V2_HELLO_CIPHERSPEC_LENGTH" -ne 0 ]]; then
               supported_sslv2_ciphers="$(grep "Supported cipher: " "$TEMPDIR/$NODEIP.parse_sslv2_serverhello.txt")"
               "$WIDE" && "$SHOW_SIGALGO" && s="$($OPENSSL x509 -noout -text -in "$HOSTCERT" | awk -F':' '/Signature Algorithm/ { print $2 }' | head -1)"
               for (( i=0 ; i<nr_ciphers; i++ )); do
                    if [[ "${sslvers[i]}" == "SSLv2" ]] && [[ "$supported_sslv2_ciphers" =~ "${normalized_hexcode[i]}" ]]; then
                         ciphers_found[i]=true
                         "$WIDE" && "$SHOW_SIGALGO" && sigalg[i]="$s"
                         rc4_offered=1
                    fi
               done
          fi
     elif "$HAS_SSL2" && [[ -n "$sslv2_ciphers_ossl" ]]; then
          $OPENSSL s_client -cipher "${sslv2_ciphers_ossl:1}" $STARTTLS $BUGS -connect $NODEIP:$PORT $PROXY -ssl2 >$TMPFILE 2>$ERRFILE </dev/null
          sclient_connect_successful "$?" "$TMPFILE"
          if [[ "$?" -eq 0 ]]; then
               supported_sslv2_ciphers="$(grep -A 4 "Ciphers common between both SSL endpoints:" $TMPFILE)"
               "$WIDE" && "$SHOW_SIGALGO" && s="$($OPENSSL x509 -noout -text -in $TMPFILE | awk -F':' '/Signature Algorithm/ { print $2 }' | head -1)"
               for (( i=0 ; i<nr_ciphers; i++ )); do
                    if [[ "${sslvers[i]}" == "SSLv2" ]] && [[ "$supported_sslv2_ciphers" =~ "${ciph[i]}" ]]; then
                         ciphers_found[i]=true
                         "$WIDE" && "$SHOW_SIGALGO" && sigalg[i]="$s"
                         rc4_offered=1
                    fi
               done
          fi
     fi

     for (( i=0; i < nr_ciphers; i++ )); do
          if "${ossl_supported[i]}" && [[ "${sslvers[i]}" != "SSLv2" ]]; then
               ciphers_found2[nr_ossl_ciphers]=false
               sslvers2[nr_ossl_ciphers]="${sslvers[i]}"
               ciph2[nr_ossl_ciphers]="${ciph[i]}"
               index[nr_ossl_ciphers]=$i
               nr_ossl_ciphers+=1
          fi
     done

     "$HAS_NO_SSL2" && addcmd="-no_ssl2"
     for (( success=0; success==0 ; 1 )); do
          ciphers_to_test=""
          for (( i=0; i < nr_ossl_ciphers; i++ )); do
               ! "${ciphers_found2[i]}" && ciphers_to_test+=":${ciph2[i]}"
          done
          success=1
          if [[ -n "$ciphers_to_test" ]]; then
               $OPENSSL s_client $addcmd -cipher "${ciphers_to_test:1}" $STARTTLS $BUGS -connect $NODEIP:$PORT $PROXY $SNI >$TMPFILE 2>$ERRFILE </dev/null
               sclient_connect_successful "$?" "$TMPFILE"
               if [[ "$?" -eq 0 ]]; then
                    cipher=$(awk '/Cipher *:/ { print $3 }' $TMPFILE)
                    if [[ -n "$cipher" ]]; then
                         success=0
                         rc4_offered=1
                         for (( i=0; i < nr_ossl_ciphers; i++ )); do
                              [[ "$cipher" == "${ciph2[i]}" ]] && ciphers_found2[i]=true && break
                         done
                         i=${index[i]}
                         ciphers_found[i]=true
                         if "$WIDE" && ( [[ ${kx[i]} == "Kx=ECDH" ]] || [[ ${kx[i]} == "Kx=DH" ]] || [[ ${kx[i]} == "Kx=EDH" ]] ); then
                              dhlen=$(read_dhbits_from_file "$TMPFILE" quiet)
                              kx[i]="${kx[i]} $dhlen"
                         fi
                         "$WIDE" && "$SHOW_SIGALGO" && grep -q "\-\-\-\-\-BEGIN CERTIFICATE\-\-\-\-\-" $TMPFILE && \
                              sigalg[i]="$($OPENSSL x509 -noout -text -in $TMPFILE | awk -F':' '/Signature Algorithm/ { print $2 }' | head -1)"
                    fi
               fi
          fi
     done

     if "$using_sockets"; then
          for (( i=0; i < nr_ciphers; i++ )); do
               if ! "${ciphers_found[i]}" && [[ "${sslvers[i]}" != "SSLv2" ]]; then
                    ciphers_found2[nr_nonossl_ciphers]=false
                    sslvers2[nr_nonossl_ciphers]="${sslvers[i]}"
                    hexcode2[nr_nonossl_ciphers]="${hexcode[i]}"
                    rfc_ciph2[nr_nonossl_ciphers]="${rfc_ciph[i]}"
                    index[nr_nonossl_ciphers]=$i
                    nr_nonossl_ciphers+=1
               fi
          done
     fi

     for (( success=0; success==0 ; 1 )); do
          ciphers_to_test=""
          for (( i=0; i < nr_nonossl_ciphers; i++ )); do
               ! "${ciphers_found2[i]}" && ciphers_to_test+=", ${hexcode2[i]}"
          done
          success=1
          if [[ -n "$ciphers_to_test" ]]; then
               if "$WIDE" && "$SHOW_SIGALGO"; then
                    tls_sockets "03" "${ciphers_to_test:2}, 00,ff" "all"
               else
                    tls_sockets "03" "${ciphers_to_test:2}, 00,ff" "ephemeralkey"
               fi
               ret=$?
               if [[ $ret -eq 0 ]] || [[ $ret -eq 2 ]]; then
                    success=0
                    rc4_offered=1
                    cipher=$(awk '/Cipher *:/ { print $3 }' "$TEMPDIR/$NODEIP.parse_tls_serverhello.txt")
                    for (( i=0; i < nr_nonossl_ciphers; i++ )); do
                         [[ "$cipher" == "${rfc_ciph2[i]}" ]] && ciphers_found2[i]=true && break
                    done
                    i=${index[i]}
                    ciphers_found[i]=true
                    if "$WIDE" && ( [[ ${kx[i]} == "Kx=ECDH" ]] || [[ ${kx[i]} == "Kx=DH" ]] || [[ ${kx[i]} == "Kx=EDH" ]] ); then
                         dhlen=$(read_dhbits_from_file "$TEMPDIR/$NODEIP.parse_tls_serverhello.txt" quiet)
                         kx[i]="${kx[i]} $dhlen"
                    fi
                    "$WIDE" && "$SHOW_SIGALGO" && [[ -r "$HOSTCERT" ]] && \
                         sigalg[i]="$($OPENSSL x509 -noout -text -in "$HOSTCERT" | awk -F':' '/Signature Algorithm/ { print $2 }' | head -1)"
               fi
          fi
     done

     if [[ $rc4_offered -eq 1 ]]; then
          "$WIDE" || pr_svrty_high "VULNERABLE (NOT ok): "
          if "$WIDE"; then
               outln "\n"
               neat_header
          fi
          for (( i=0 ; i<nr_ciphers; i++ )); do
               if ! "${ciphers_found[i]}" && ! "$SHOW_EACH_C"; then
                    continue                 # no successful connect AND not verbose displaying each cipher
               fi
               if "$WIDE"; then
                    #FIXME: JSON+CSV in wide mode is missing
                    export="${export2[i]}"
                    neat_list "${normalized_hexcode[i]}" "${ciph[i]}" "${kx[i]}" "${enc[i]}" "${ciphers_found[i]}"
                    if "$SHOW_EACH_C"; then
                         if "${ciphers_found[i]}"; then
                              pr_svrty_high "available"
                         else
                              pr_deemphasize "not a/v"
                         fi
                    fi
                    outln "${sigalg[i]}"
               fi
               if "${ciphers_found[i]}"; then
                    if ( [[ -z "$SHOW_RFC" ]] && [[ "${ciph[i]}" != "-" ]] ) || [[ "${rfc_ciph[i]}" == "-" ]]; then
                         rc4_detected+="${ciph[i]} "
                    else
                         rc4_detected+="${rfc_ciph[i]} "
                    fi
               fi
          done
          ! "$WIDE" && out_row_aligned_max_width "$rc4_detected" "                                                                " $TERM_WIDTH pr_svrty_high
          outln
          "$WIDE" && pr_svrty_high "VULNERABLE (NOT ok)"
          fileout "rc4" "HIGH" "RC4: VULNERABLE, Detected ciphers: $rc4_detected" "$cve" "$cwe" "$hint"
     elif [[ $nr_ciphers -eq 0 ]]; then
          local_problem_ln "No RC4 Ciphers configured in $OPENSSL"
          fileout "rc4" "WARN" "RC4 ciphers not supported by local OpenSSL ($OPENSSL)"
     else
          pr_done_goodln "no RC4 ciphers detected (OK)"
          fileout "rc4" "OK" "RC4: not vulnerable" "$cve" "$cwe"
     fi
     outln

     "$using_sockets" && HAS_DH_BITS="$has_dh_bits"
     tmpfile_handle $FUNCNAME.txt
     return $rc4_offered
}


run_youknowwho() {
    local cve="CVE-2013-2566"
    # CVE-2013-2566,
    # NOT FIXME as there's no code: http://www.isg.rhul.ac.uk/tls/
    # http://blog.cryptographyengineering.com/2013/03/attack-of-week-rc4-is-kind-of-broken-in.html
    return 0
    # in a nutshell: don't use RC4, really not!
    }

    # https://www.usenix.org/conference/woot13/workshop-program/presentation/smyth
    # https://secure-resumption.com/tlsauth.pdf
    run_tls_truncation() {
    #FIXME: difficult to test, is there any test available: pls let me know
        :
}


old_fart() {
     outln "Get precompiled bins or compile https://github.com/PeterMosmans/openssl ."
     fileout "old_fart" "WARN" "Your $OPENSSL $OSSL_VER version is an old fart... . It doesn\'t make much sense to proceed. Get precompiled bins or compile https://github.com/PeterMosmans/openssl ."
     fatal "Your $OPENSSL $OSSL_VER version is an old fart... . It doesn\'t make much sense to proceed." -5
}

# try very hard to determine the install path to get ahold of the mapping file and the CA bundles
# TESTSSL_INSTALL_DIR can be supplied via environment so that the cipher mapping and CA bundles can be found
# www.carbonwind.net/TLS_Cipher_Suites_Project/tls_ssl_cipher_suites_simple_table_all.htm
get_install_dir() {
     [[ -z "$TESTSSL_INSTALL_DIR" ]] && TESTSSL_INSTALL_DIR="$(dirname ${BASH_SOURCE[0]})"

     [[ -r "$RUN_DIR/etc/cipher-mapping.txt" ]] && CIPHERS_BY_STRENGTH_FILE="$RUN_DIR/etc/cipher-mapping.txt"
     [[ -r "$TESTSSL_INSTALL_DIR/etc/cipher-mapping.txt" ]] && CIPHERS_BY_STRENGTH_FILE="$TESTSSL_INSTALL_DIR/etc/cipher-mapping.txt"
     if [[ ! -r "$CIPHERS_BY_STRENGTH_FILE" ]]; then
          [[ -r "$RUN_DIR/cipher-mapping.txt" ]] && CIPHERS_BY_STRENGTH_FILE="$RUN_DIR/cipher-mapping.txt"
          [[ -r "$TESTSSL_INSTALL_DIR/cipher-mapping.txt" ]] && CIPHERS_BY_STRENGTH_FILE="$TESTSSL_INSTALL_DIR/cipher-mapping.txt"
     fi

     # we haven't found the cipher file yet...
     if [[ ! -r "$mapping_file_rfc" ]] && which readlink &>/dev/null ; then
          readlink -f ls &>/dev/null && \
               TESTSSL_INSTALL_DIR=$(readlink -f $(basename ${BASH_SOURCE[0]})) || \
               TESTSSL_INSTALL_DIR=$(readlink $(basename ${BASH_SOURCE[0]}))
               # not sure whether Darwin has -f
          TESTSSL_INSTALL_DIR=$(dirname $TESTSSL_INSTALL_DIR 2>/dev/null)
          [[ -r "$TESTSSL_INSTALL_DIR/cipher-mapping.txt" ]] && CIPHERS_BY_STRENGTH_FILE="$TESTSSL_INSTALL_DIR/cipher-mapping.txt"
          [[ -r "$TESTSSL_INSTALL_DIR/etc/cipher-mapping.txt" ]] && CIPHERS_BY_STRENGTH_FILE="$TESTSSL_INSTALL_DIR/etc/cipher-mapping.txt"
     fi

     # still no cipher mapping file:
     if [[ ! -r "$CIPHERS_BY_STRENGTH_FILE" ]] && which realpath &>/dev/null ; then
          TESTSSL_INSTALL_DIR=$(dirname $(realpath ${BASH_SOURCE[0]}))
          CIPHERS_BY_STRENGTH_FILE="$TESTSSL_INSTALL_DIR/etc/cipher-mapping.txt"
          [[ -r "$TESTSSL_INSTALL_DIR/cipher-mapping.txt" ]] && CIPHERS_BY_STRENGTH_FILE="$TESTSSL_INSTALL_DIR/cipher-mapping.txt"
     fi

     # still no cipher mapping file (and realpath is not present):
     if [[ ! -r "$CIPHERS_BY_STRENGTH_FILE" ]] && which readlink &>/dev/null ; then
         readlink -f ls &>/dev/null && \
              TESTSSL_INSTALL_DIR=$(dirname $(readlink -f ${BASH_SOURCE[0]})) || \
              TESTSSL_INSTALL_DIR=$(dirname $(readlink ${BASH_SOURCE[0]}))
              # not sure whether Darwin has -f
          CIPHERS_BY_STRENGTH_FILE="$TESTSSL_INSTALL_DIR/etc/cipher-mapping.txt"
          [[ -r "$TESTSSL_INSTALL_DIR/cipher-mapping.txt" ]] && CIPHERS_BY_STRENGTH_FILE="$TESTSSL_INSTALL_DIR/cipher-mapping.txt"
     fi

     if [[ ! -r "$CIPHERS_BY_STRENGTH_FILE" ]] ; then
          unset ADD_RFC_STR
          unset SHOW_RFC
          debugme echo "$CIPHERS_BY_STRENGTH_FILE"
          pr_warningln "\nATTENTION: No cipher mapping file found!"
          outln "Please note from 2.9dev on $PROG_NAME needs files in \"\$TESTSSL_INSTALL_DIR/etc/\" to function correctly."
          outln
          ignore_no_or_lame "Type \"yes\" to ignore this warning and proceed at your own risk" "yes"
          [[ $? -ne 0 ]] && exit -2
     fi
}


test_openssl_suffix() {
     local naming_ext="$(uname).$(uname -m)"
     local uname_arch="$(uname -m)"
     local myarch_suffix=""

     [[ $uname_arch =~ 64 ]] && myarch_suffix=64 || myarch_suffix=32
     if [[ -f "$1/openssl" ]] && [[ -x "$1/openssl" ]]; then
          OPENSSL="$1/openssl"
          return 0
     elif [[ -f "$1/openssl.$naming_ext" ]] && [[ -x "$1/openssl.$naming_ext" ]]; then
          OPENSSL="$1/openssl.$naming_ext"
          return 0
     elif [[ -f "$1/openssl.$uname_arch" ]] && [[ -x "$1/openssl.$uname_arch" ]]; then
          OPENSSL="$1/openssl.$uname_arch"
          return 0
     elif [[ -f "$1/openssl$myarch_suffix" ]] && [[ -x "$1/openssl$myarch_suffix" ]]; then
          OPENSSL="$1/openssl$myarch_suffix"
          return 0
     fi
     return 1
}


find_openssl_binary() {
     local s_client_has=$TEMPDIR/s_client_has.txt
     local s_client_starttls_has=$TEMPDIR/s_client_starttls_has.txt

     # 0. check environment variable whether it's executable
     if [[ -n "$OPENSSL" ]] && [[ ! -x "$OPENSSL" ]]; then
          pr_warningln "\ncannot find specified (\$OPENSSL=$OPENSSL) binary."
          outln " Looking some place else ..."
     elif [[ -x "$OPENSSL" ]]; then
          :    # 1. all ok supplied $OPENSSL was found and has excutable bit set -- testrun comes below
     elif [[ -e "/mnt/c/Windows/System32/bash.exe" ]] && test_openssl_suffix "$(dirname "$(which openssl)")"; then
          # 2. otherwise, only if on Bash on Windows, use system binaries only.
          SYSTEM2="WSL"
     elif test_openssl_suffix $RUN_DIR; then
          :    # 3. otherwise try openssl in path of testssl.sh
     elif test_openssl_suffix $RUN_DIR/bin; then
          :    # 4. otherwise here, this is supposed to be the standard --platform independed path in the future!!!
     elif test_openssl_suffix "$(dirname "$(which openssl)")"; then
          :    # 5. we tried hard and failed, so now we use the system binaries
     fi

     # no ERRFILE initialized yet, thus we use /dev/null for stderr directly
     $OPENSSL version -a 2>/dev/null >/dev/null
     if [[ $? -ne 0 ]] || [[ ! -x "$OPENSSL" ]]; then
          fatal "\ncannot exec or find any openssl binary" -5
     fi

     # http://www.openssl.org/news/openssl-notes.html
     OSSL_VER=$($OPENSSL version 2>/dev/null | awk -F' ' '{ print $2 }')
     OSSL_VER_MAJOR=$(echo "$OSSL_VER" | sed 's/\..*$//')
     OSSL_VER_MINOR=$(echo "$OSSL_VER" | sed -e 's/^.\.//' | tr -d '[a-zA-Z]-')
     OSSL_VER_APPENDIX=$(echo "$OSSL_VER" | tr -d '0-9.')
     OSSL_VER_PLATFORM=$($OPENSSL version -p 2>/dev/null | sed 's/^platform: //')
     OSSL_BUILD_DATE=$($OPENSSL version -a  2>/dev/null | grep '^built' | sed -e 's/built on//' -e 's/: ... //' -e 's/: //' -e 's/ UTC//' -e 's/ +0000//' -e 's/.000000000//')
     echo $OSSL_BUILD_DATE | grep -q "not available" && OSSL_BUILD_DATE=""

     # see #190, reverting logic: unless otherwise proved openssl has no dh bits
     case "$OSSL_VER_MAJOR.$OSSL_VER_MINOR" in
          1.0.2|1.1.0|1.1.1) HAS_DH_BITS=true ;;
     esac
     # libressl does not have "Server Temp Key" (SSL_get_server_tmp_key)

     if $OPENSSL version 2>/dev/null | grep -qi LibreSSL; then
          outln
          pr_warning "Please note: LibreSSL is not a good choice for testing INSECURE features!"
     fi

     initialize_engine

     OPENSSL_NR_CIPHERS=$(count_ciphers "$($OPENSSL ciphers 'ALL:COMPLEMENTOFALL:@STRENGTH' 2>/dev/null)")

     $OPENSSL s_client -ssl2 -connect x 2>&1 | grep -aq "unknown option" || \
          HAS_SSL2=true

     $OPENSSL s_client -ssl3 -connect x 2>&1 | grep -aq "unknown option" || \
          HAS_SSL3=true

     $OPENSSL s_client -no_ssl2 -connect x 2>&1 | grep -aq "unknown option" || \
          HAS_NO_SSL2=true

     $OPENSSL s_client -help 2>$s_client_has

     $OPENSSL s_client -starttls foo 2>$s_client_starttls_has

     grep -qw '\-alpn' $s_client_has && \
          HAS_ALPN=true

     grep -qw '\-nextprotoneg' $s_client_has && \
          HAS_SPDY=true

     grep -qw '\-fallback_scsv' $s_client_has && \
          HAS_FALLBACK_SCSV=true

     grep -q '\-proxy' $s_client_has && \
          HAS_PROXY=true

     grep -q '\-xmpp' $s_client_has && \
          HAS_XMPP=true

     grep -q 'postgres' $s_client_starttls_has && \
          HAS_POSTGRES=true

     if [[ "$OPENSSL_TIMEOUT" != "" ]]; then
          if which timeout >&2 2>/dev/null ; then
               # there are different "timeout". Check whether --preserve-status is supported
               if timeout --help 2>/dev/null | grep -q 'preserve-status'; then
                    OPENSSL="timeout --preserve-status $OPENSSL_TIMEOUT $OPENSSL"
               else
                    OPENSSL="timeout $OPENSSL_TIMEOUT $OPENSSL"
               fi
          else
               outln
               ignore_no_or_lame " Neccessary binary \"timeout\" not found. Continue without timeout? " "y"
               [[ $? -ne 0 ]] && exit -2
               unset OPENSSL_TIMEOUT
          fi
     fi

     return 0
}

check4openssl_oldfarts() {
     case "$OSSL_VER" in
          0.9.7*|0.9.6*|0.9.5*)
               # 0.9.5a was latest in 0.9.5 an released 2000/4/1, that'll NOT suffice for this test
               old_fart ;;
          0.9.8)
               case $OSSL_VER_APPENDIX in
                    a|b|c|d|e) old_fart;; # no SNI!
                    # other than that we leave this for MacOSX and FreeBSD but it's a pain and likely gives false negatives/positives
               esac
               ;;
     esac
     if [[ $OSSL_VER_MAJOR -lt 1 ]]; then ## mm: Patch for libressl
          pr_warningln " Your \"$OPENSSL\" is way too old (<version 1.0) !"
          case $SYSTEM in
               *BSD|Darwin)
                    outln " Please use binary provided in \$INSTALLDIR/bin/ or from ports/brew or compile from github.com/PeterMosmans/openssl"
                    fileout "too_old_openssl" "WARN" "Your $OPENSSL $OSSL_VER version is way too old. Please use binary provided in \$INSTALLDIR/bin/ or from ports/brew or compile from github.com/PeterMosmans/openssl ." ;;
               *)   outln " Update openssl binaries or compile from github.com/PeterMosmans/openssl"
                    fileout "too_old_openssl" "WARN" "Update openssl binaries or compile from github.com/PeterMosmans/openssl .";;
          esac
          ignore_no_or_lame " Type \"yes\" to accept false negatives or positives" "yes"
          [[ $? -ne 0 ]] && exit -2
     fi
     outln
}

# FreeBSD needs to have /dev/fd mounted. This is a friendly hint, see #258
check_bsd_mount() {
     if [[ "$(uname)" == FreeBSD ]]; then
          if ! mount | grep -q "^devfs"; then
               outln "you seem to run $PROG_NAME= in a jail. Hopefully you're did \"mount -t fdescfs fdesc /dev/fd\""
          elif mount | grep '/dev/fd' | grep -q fdescfs; then
               :
          else
               fatal "You need to mount fdescfs on FreeBSD: \"mount -t fdescfs fdesc /dev/fd\"" -3
          fi
     fi
}

help() {
     cat << EOF

     "$PROG_NAME URI"    or    "$PROG_NAME <options>"    or    "$PROG_NAME <options> URI"


"$PROG_NAME URI", where URI is:

     URI                           host|host:port|URL|URL:port   port 443 is default, URL can only contain HTTPS protocol)

"$PROG_NAME <options>", where <options> is:

     -h, --help                    what you're looking at
     -b, --banner                  displays banner + version of $PROG_NAME
     -v, --version                 same as previous
     -V, --local                   pretty print all local ciphers
     -V, --local <pattern>         which local ciphers with <pattern> are available? If pattern is not a number: word match

     pattern                       is always an ignore case word pattern of cipher hexcode or any other string in the name, kx or bits


"$PROG_NAME <options> URI", where <options> is:

     -t, --starttls <protocol>     does a default run against a STARTTLS enabled <protocol,
                                   protocol is <ftp|smtp|pop3|imap|xmpp|telnet|ldap|postgres> (latter three require supplied openssl)
     --xmpphost <to_domain>        for STARTTLS enabled XMPP it supplies the XML stream to-'' domain -- sometimes needed
     --mx <domain/host>            tests MX records from high to low priority (STARTTLS, port 25)
     --file <fname>                mass testing option: Reads command lines from <fname>, one line per instance.
                                   Comments via # allowed, EOF signals end of <fname>. Implicitly turns on "--warnings batch"

single check as <options>  ("$PROG_NAME  URI" does everything except -E):
     -e, --each-cipher             checks each local cipher remotely
     -E, --cipher-per-proto        checks those per protocol
     -f, --ciphers                 checks common cipher suites
     -p, --protocols               checks TLS/SSL protocols (including SPDY/HTTP2)
     -y, --spdy, --npn             checks for SPDY/NPN
     -Y, --http2, --alpn           checks for HTTP2/ALPN
     -S, --server-defaults         displays the server's default picks and certificate info
     -P, --server-preference       displays the server's picks: protocol+cipher
     -x, --single-cipher <pattern> tests matched <pattern> of ciphers
                                   (if <pattern> not a number: word match)
     -c, --client-simulation       test client simulations, see which client negotiates with cipher and protocol
     -H, --header, --headers       tests HSTS, HPKP, server/app banner, security headers, cookie, reverse proxy, IPv4 address

     -U, --vulnerable              tests all (of the following) vulnerabilities (if applicable)
     -B, --heartbleed              tests for heartbleed vulnerability
     -I, --ccs, --ccs-injection    tests for CCS injection vulnerability
     -R, --renegotiation           tests for renegotiation vulnerabilities
     -C, --compression, --crime    tests for CRIME vulnerability (TLS compression issue)
     -T, --breach                  tests for BREACH vulnerability (HTTP compression issue)
     -O, --poodle                  tests for POODLE (SSL) vulnerability
     -Z, --tls-fallback            checks TLS_FALLBACK_SCSV mitigation
     -W, --sweet32                 tests 64 bit block ciphers (3DES, RC2 and IDEA): SWEET32 vulnerability
     -A, --beast                   tests for BEAST vulnerability
     -L, --lucky13                 tests for LUCKY13
     -F, --freak                   tests for FREAK vulnerability
     -J, --logjam                  tests for LOGJAM vulnerability
     -D, --drown                   tests for DROWN vulnerability
     -s, --pfs, --fs, --nsa        checks (perfect) forward secrecy settings
     -4, --rc4, --appelbaum        which RC4 ciphers are being offered?

tuning / connect options (most also can be preset via environment variables):
     --fast                        omits some checks: using openssl for all ciphers (-e), show only first
                                   preferred cipher
     --bugs                        enables the "-bugs" option of s_client, needed e.g. for some buggy F5s
     --assume-http                 if protocol check fails it assumes HTTP protocol and enforces HTTP checks
     --ssl-native                  fallback to checks with OpenSSL where sockets are normally used
     --openssl <PATH>              use this openssl binary (default: look in \$PATH, \$RUN_DIR of $PROG_NAME)
     --proxy <host:port|auto>      connect via the specified HTTP proxy, auto: autodetermination from \$env (\$http(s)_proxy)
     -6                            also use IPv6. Works only with supporting OpenSSL version and IPv6 connectivity
     --ip <ip>                     a) tests the supplied <ip> v4 or v6 address instead of resolving host(s) in URI
                                   b) arg "one" means: just test the first DNS returns (useful for multiple IPs)
     -n, --nodns                   do not try any DNS lookup
     --sneaky                      leave less traces in target logs: user agent, referer

output options (can also be preset via environment variables):
     --warnings <batch|off|false>  "batch" doesn't wait for keypress, "off" or "false" skips connection warning
     --openssl-timeout <seconds>   useful to avoid hangers. <seconds> to wait before openssl connect will be terminated
     --quiet                       don't output the banner. By doing this you acknowledge usage terms normally appearing in the banner
     --wide                        wide output for tests like RC4, BEAST. PFS also with hexcode, kx, strength, RFC name
     --show-each                   for wide outputs: display all ciphers tested -- not only succeeded ones
     --mapping <rfc|no-rfc>        (rfc: display the RFC Cipher Suite name instead of the OpenSSL name;
                                    no-rfc: don't display the RFC Cipher Suite Name)
     --color <0|1|2>               0: no escape or other codes,  1: b/w escape codes,  2: color (default)
     --colorblind                  swap green and blue in the output
     --debug <0-6>                 1: screen output normal but keeps debug output in /tmp/.  2-6: see "grep -A 5 '^DEBUG=' testssl.sh"

file output options (can also be preset via environment variables):
     --log, --logging              logs stdout to <NODE-YYYYMMDD-HHMM.log> in current working directory
     --logfile <logfile>           logs stdout to <file/NODE-YYYYMMDD-HHMM.log> if file is a dir or to specified log file
     --json                        additional output of findings to flat JSON file <NODE-YYYYMMDD-HHMM.json> in cwd
     --jsonfile <jsonfile>         additional output to the specified flat JSON file
     --json-pretty                 additional pretty structured output of findings to JSON file <NODE-YYYYMMDD-HHMM.json> in cwd
     --jsonfile-pretty <jsonfile>  additional pretty structured output as JSON to the specified file
     --csv                         additional output of findings to CSV file <NODE-YYYYMMDD-HHMM.csv> in cwd
     --csvfile <csvfile>           additional output as CSV to the specified file
     --hints                       additional hints to findings
     --severity <severity>         severities with lower level will be filtered for CSV+JSON, possible values <LOW|MEDIUM|HIGH|CRITICAL>
     --append                      if <csvfile> or <jsonfile> exists rather append then overwrite


Options requiring a value can also be called with '=' e.g. testssl.sh -t=smtp --wide --openssl=/usr/bin/openssl <URI>.
URI always needs to be the last parameter.

Need HTML output? Just pipe through "aha" (ANSI HTML Adapter: github.com/theZiz/aha) like

   "$PROG_NAME <options> <URI> | aha >output.html" or use -log* and convert later

EOF
     #' Fix syntax highlight on sublime
     exit $1
}

maketempf() {
     TEMPDIR=$(mktemp -d /tmp/ssltester.XXXXXX) || exit -6
     TMPFILE=$TEMPDIR/tempfile.txt || exit -6
     if [[ "$DEBUG" -eq 0 ]]; then
          ERRFILE="/dev/null"
     else
          ERRFILE=$TEMPDIR/errorfile.txt || exit -6
     fi
     HOSTCERT=$TEMPDIR/host_certificate.txt
}

prepare_debug() {
     local hexc mac ossl_ciph ossl_supported_tls="" ossl_supported_sslv2=""
     if [[ $DEBUG -ne 0 ]]; then
          cat >$TEMPDIR/environment.txt << EOF


CVS_REL: $CVS_REL
GIT_REL: $GIT_REL

PID: $$
commandline: "$CMDLINE"
bash version: ${BASH_VERSINFO[0]}.${BASH_VERSINFO[1]}.${BASH_VERSINFO[2]}
status: ${BASH_VERSINFO[4]}
machine: ${BASH_VERSINFO[5]}
operating system: $SYSTEM
os constraint: $SYSTEM2
shellopts: $SHELLOPTS

$($OPENSSL version -a)
OSSL_VER_MAJOR: $OSSL_VER_MAJOR
OSSL_VER_MINOR: $OSSL_VER_MINOR
OSSL_VER_APPENDIX: $OSSL_VER_APPENDIX
OSSL_BUILD_DATE: $OSSL_BUILD_DATE
OSSL_VER_PLATFORM: $OSSL_VER_PLATFORM

OPENSSL_NR_CIPHERS: $OPENSSL_NR_CIPHERS
OPENSSL_CONF: $OPENSSL_CONF

HAS_IPv6: $HAS_IPv6
HAS_SSL2: $HAS_SSL2
HAS_SSL3: $HAS_SSL3
HAS_NO_SSL2: $HAS_NO_SSL2
HAS_SPDY: $HAS_SPDY
HAS_ALPN: $HAS_ALPN
HAS_FALLBACK_SCSV: $HAS_FALLBACK_SCSV
HAS_PROXY: $HAS_PROXY
HAS_XMPP: $HAS_XMPP
HAS_POSTGRES: $HAS_POSTGRES

PATH: $PATH
PROG_NAME: $PROG_NAME
TESTSSL_INSTALL_DIR: $TESTSSL_INSTALL_DIR
RUN_DIR: $RUN_DIR

CAPATH: $CAPATH
COLOR: $COLOR
COLORBLIND: $COLORBLIND
TERM_WIDTH: $TERM_WIDTH
INTERACTIVE: $INTERACTIVE
HAS_GNUDATE: $HAS_GNUDATE
HAS_FREEBSDDATE: $HAS_FREEBSDDATE
HAS_SED_E: $HAS_SED_E

SHOW_EACH_C: $SHOW_EACH_C
SSL_NATIVE: $SSL_NATIVE
ASSUME_HTTP $ASSUME_HTTP
SNEAKY: $SNEAKY

DEBUG: $DEBUG

HSTS_MIN: $HSTS_MIN
HPKP_MIN: $HPKP_MIN
CLIENT_MIN_PFS: $CLIENT_MIN_PFS
DAYS2WARN1: $DAYS2WARN1
DAYS2WARN2: $DAYS2WARN2

HEADER_MAXSLEEP: $HEADER_MAXSLEEP
MAX_WAITSOCK: $MAX_WAITSOCK
HEARTBLEED_MAX_WAITSOCK: $HEARTBLEED_MAX_WAITSOCK
CCS_MAX_WAITSOCK: $CCS_MAX_WAITSOCK
USLEEP_SND $USLEEP_SND
USLEEP_REC $USLEEP_REC

EOF
          which locale &>/dev/null && locale >>$TEMPDIR/environment.txt || echo "locale doesn't exist" >>$TEMPDIR/environment.txt
          $OPENSSL ciphers -V 'ALL:COMPLEMENTOFALL'  &>$TEMPDIR/all_local_ciphers.txt
     fi
     # see also $TEMPDIR/s_client_has.txt from find_openssl_binary

     if [[ -e $CIPHERS_BY_STRENGTH_FILE ]]; then
          "$HAS_SSL2" && ossl_supported_sslv2="$($OPENSSL ciphers -ssl2 -V 'ALL:COMPLEMENTOFALL:@STRENGTH' 2>$ERRFILE)"
          ossl_supported_tls="$($OPENSSL ciphers -tls1 -V 'ALL:COMPLEMENTOFALL:@STRENGTH' 2>$ERRFILE)"
          while read hexc n TLS_CIPHER_OSSL_NAME[TLS_NR_CIPHERS] TLS_CIPHER_RFC_NAME[TLS_NR_CIPHERS] TLS_CIPHER_SSLVERS[TLS_NR_CIPHERS] TLS_CIPHER_KX[TLS_NR_CIPHERS] TLS_CIPHER_AUTH[TLS_NR_CIPHERS] TLS_CIPHER_ENC[TLS_NR_CIPHERS] mac TLS_CIPHER_EXPORT[TLS_NR_CIPHERS]; do
               TLS_CIPHER_HEXCODE[TLS_NR_CIPHERS]="$hexc"
               TLS_CIPHER_OSSL_SUPPORTED[TLS_NR_CIPHERS]=false
               if [[ ${#hexc} -eq 9 ]]; then
                    if [[ $OSSL_VER_MAJOR -lt 1 ]]; then
                         [[ ":${ossl_supported_tls}:" =~ ":${TLS_CIPHER_OSSL_NAME[TLS_NR_CIPHERS]}:" ]] && TLS_CIPHER_OSSL_SUPPORTED[TLS_NR_CIPHERS]=true
                    else
                         ossl_ciph="$(grep -w "$hexc" <<< "$ossl_supported_tls" | awk '{ print $3 }')"
                         if [[ -n "$ossl_ciph" ]]; then
                              TLS_CIPHER_OSSL_SUPPORTED[TLS_NR_CIPHERS]=true
                              [[ "$ossl_ciph" != "${TLS_CIPHER_OSSL_NAME[TLS_NR_CIPHERS]}" ]] && TLS_CIPHER_OSSL_NAME[TLS_NR_CIPHERS]="$ossl_ciph"
                         fi
                    fi
               elif [[ $OSSL_VER_MAJOR -lt 1 ]]; then
                    [[ ":${ossl_supported_sslv2}:" =~ ":${TLS_CIPHER_OSSL_NAME[TLS_NR_CIPHERS]}:" ]] && TLS_CIPHER_OSSL_SUPPORTED[TLS_NR_CIPHERS]=true
               else
                    grep -qw "$hexc" <<< "$ossl_supported_sslv2" && TLS_CIPHER_OSSL_SUPPORTED[TLS_NR_CIPHERS]=true
               fi
               TLS_NR_CIPHERS+=1
          done < $CIPHERS_BY_STRENGTH_FILE
     fi
}


mybanner() {
     local idtag
     local bb
     local openssl_location="$(which $OPENSSL)"
     local cwd=""

     $QUIET && return
     OPENSSL_NR_CIPHERS=$(count_ciphers "$($OPENSSL ciphers 'ALL:COMPLEMENTOFALL:@STRENGTH' 2>/dev/null)")
     [[ -z "$GIT_REL" ]] && \
          idtag="$CVS_REL" || \
          idtag="$GIT_REL -- $CVS_REL_SHORT"
     [[ "$COLOR" -ne 0 ]] && idtag="\033[1;30m$idtag\033[m\033[1m"
     bb=$(cat <<EOF

###########################################################
    $PROG_NAME       $VERSION from $SWURL
    ($idtag)

      This program is free software. Distribution and
             modification under GPLv2 permitted.
      USAGE w/o ANY WARRANTY. USE IT AT YOUR OWN RISK!

       Please file bugs @ https://testssl.sh/bugs/

###########################################################
EOF
)
     pr_bold "$bb"
     outln "\n"
     outln " Using \"$($OPENSSL version 2>/dev/null)\" [~$OPENSSL_NR_CIPHERS ciphers]"
     out " on $HNAME:"

     [[ -n "$GIT_REL" ]] && \
          cwd=$(/bin/pwd) || \
          cwd=$RUN_DIR
     if [[ "$openssl_location" =~ $(/bin/pwd)/bin ]]; then
          OPENSSL_LOCATION="\$PWD/bin/$(basename "$openssl_location")"
     elif [[ "$openssl_location" =~ $cwd ]] && [[ "$cwd" != '.' ]]; then
          OPENSSL_LOCATION="${openssl_location%%$cwd}"
     else
         OPENSSL_LOCATION="$openssl_location"
     fi
     echo "$OPENSSL_LOCATION"
     outln " (built: \"$OSSL_BUILD_DATE\", platform: \"$OSSL_VER_PLATFORM\")\n"
}


cleanup () {
     if [[ "$DEBUG" -ge 1 ]]; then
          outln
          pr_underline "DEBUG (level $DEBUG): see files in $TEMPDIR"
          outln
     else
          [[ -d "$TEMPDIR" ]] && rm -rf "$TEMPDIR";
     fi
     outln
     "$APPEND" || fileout_footer
}

fatal() {
     pr_magentaln "Fatal error: $1" >&2
     exit $2
     # 1:  cmd line error
     # 2:  secondary/other cmd line error
     # -1: other user error
     # -2: network problem
     # -3: s.th. fatal is not supported in the client
     # -4: s.th. is not supported yet
     # -5: openssl problem
}


# for now only GOST engine
initialize_engine(){
     grep -q '^# testssl config file' "$OPENSSL_CONF" 2>/dev/null && return 0        # have been here already

     if ! $OPENSSL engine gost -vvvv -t -c 2>/dev/null >/dev/null; then
          outln
          pr_warning "No engine or GOST support via engine with your $OPENSSL"; outln
          return 1
     elif $OPENSSL engine gost -vvvv -t -c 2>&1 | grep -iq "No such" ; then
          outln
          pr_warning "No engine or GOST support via engine with your $OPENSSL"; outln
          return 1
     else      # we have engine support
          if [[ -n "$OPENSSL_CONF" ]]; then
               pr_warningln "For now I am providing the config file to have GOST support"
          else
               OPENSSL_CONF=$TEMPDIR/gost.conf || exit -6
               # see https://www.mail-archive.com/openssl-users@openssl.org/msg65395.html
               cat >$OPENSSL_CONF << EOF
# testssl config file for openssl

openssl_conf            = openssl_def

[ openssl_def ]
engines                 = engine_section

[ engine_section ]
gost = gost_section

[ gost_section ]
engine_id = gost
default_algorithms = ALL
CRYPT_PARAMS = id-Gost28147-89-CryptoPro-A-ParamSet

EOF
               export OPENSSL_CONF
          fi
     fi
     return 0
}

# arg1: text to display before "-->"
# arg2: arg needed to accept to continue
ignore_no_or_lame() {
     local a

     [[ "$WARNINGS" == off ]] && return 0
     [[ "$WARNINGS" == false ]] && return 0
     [[ "$WARNINGS" == batch ]] && return 1
     pr_warning "$1 --> "
     read a
     if [[ "$a" == "$(tolower "$2")" ]]; then
          $ok_arg return 0
     else
          return 1
     fi
}

# arg1: URI
parse_hn_port() {
     local tmp_port

     NODE="$1"
     # strip "https" and trailing urlpath supposed it was supplied additionally
     echo "$NODE" | grep -q 'https://' && NODE=$(echo "$NODE" | sed -e 's/^https\:\/\///')

     # strip trailing urlpath
     NODE=$(echo "$NODE" | sed -e 's/\/.*$//')

     # if there's a trailing ':' probably a starttls/application protocol was specified
     if grep -q ':$' <<< $NODE ; then
          fatal "\"$1\" is not a valid URI" 1
     fi

     # was the address supplied like [AA:BB:CC::]:port ?
     if echo "$NODE" | grep -q ']' ; then
          tmp_port=$(printf "$NODE" | sed 's/\[.*\]//' | sed 's/://')
          # determine v6 port, supposed it was supplied additionally
          if [[ -n "$tmp_port" ]]; then
               PORT=$tmp_port
               NODE=$(sed "s/:$PORT//" <<< "$NODE")
          fi
          NODE=$(sed -e 's/\[//' -e 's/\]//' <<< "$NODE")
     else
          # determine v4 port, supposed it was supplied additionally
          echo "$NODE" | grep -q ':' && \
               PORT=$(echo "$NODE" | sed 's/^.*\://') && NODE=$(echo "$NODE" | sed 's/\:.*$//')
     fi
     debugme echo $NODE:$PORT
     SNI="-servername $NODE"

     URL_PATH=$(echo "$1" | sed 's/https:\/\///' | sed 's/'"${NODE}"'//' | sed 's/.*'"${PORT}"'//')      # remove protocol and node part and port
     URL_PATH=$(echo "$URL_PATH" | sed 's/\/\//\//g')       # we rather want // -> /
     [[ -z "$URL_PATH" ]] && URL_PATH="/"
     debugme echo $URL_PATH
     return 0       # NODE, URL_PATH, PORT is set now
}


# now do logging if instructed
# arg1: for testing mx records name we put a name of logfile in here, otherwise we get strange file names
prepare_logging() {
     local fname_prefix="$1"

     [[ -z "$fname_prefix" ]] && fname_prefix="$NODE"_"$PORT"

     if "$do_logging"; then
          if [[ -z "$LOGFILE" ]]; then
               LOGFILE=$fname_prefix-$(date +"%Y%m%d-%H%M".log)
          elif [[ -d "$LOGFILE" ]]; then
               # actually we were instructed to place all files in a DIR instead of the current working dir
               LOGFILE=$LOGFILE/$fname_prefix-$(date +"%Y%m%d-%H%M".log)
          else
               : # just for clarity: a log file was specified, no need to do anything else
          fi
          >$LOGFILE
          outln "## Scan started as: \"$PROG_NAME $CMDLINE\"" >>${LOGFILE}
          outln "## at $HNAME:$OPENSSL_LOCATION" >>${LOGFILE}
          outln "## version testssl: $VERSION ${GIT_REL_SHORT:-$CVS_REL_SHORT} from $REL_DATE" >>${LOGFILE}
          outln "## version openssl: \"$OSSL_VER\" from \"$OSSL_BUILD_DATE\")\n" >>${LOGFILE}
          exec > >(tee -a ${LOGFILE})
          # not decided yet. Maybe good to have a separate file or none at all
          #exec 2> >(tee -a ${LOGFILE} >&2)
     fi

     if "$do_json" || "$do_pretty_json"; then
          if [[ -z "$JSONFILE" ]]; then
               JSONFILE=$fname_prefix-$(date +"%Y%m%d-%H%M".json)
          elif [[ -d "$JSONFILE" ]]; then
               # actually we were instructed to place all files in a DIR instead of the current working dir
               JSONFILE=$JSONFILE/$fname_prefix-$(date +"%Y%m%d-%H%M".json)
          fi
     fi
     if "$do_csv"; then
          if [[ -z "$CSVFILE" ]]; then
               CSVFILE=$fname_prefix-$(date +"%Y%m%d-%H%M".csv)
          elif [[ -d "$CSVFILE" ]]; then
               # actually we were instructed to place all files in a DIR instead of the current working dir
               CSVFILE=$CSVFILE/$fname_prefix-$(date +"%Y%m%d-%H%M".csv)
          fi
     fi
     fileout_header           # write out any CSV/JSON header line

     return 0
}


# args: string containing ip addresses
filter_ip6_address() {
     local a

     for a in "$@"; do
          if ! is_ipv6addr "$a"; then
               continue
          fi
          if "$HAS_SED_E"; then
               echo "$a" | sed -E 's/^abcdeABCDEFf0123456789:]//g' | sed -e '/^$/d' -e '/^;;/d'
          else
               echo "$a" | sed -r 's/[^abcdefABCDEF0123456789:]//g' | sed -e '/^$/d' -e '/^;;/d'
          fi
     done
}

filter_ip4_address() {
     local a

     for a in "$@"; do
          if ! is_ipv4addr "$a"; then
               continue
          fi
          if "$HAS_SED_E"; then
               echo "$a" | sed -E 's/[^[:digit:].]//g' | sed -e '/^$/d'
          else
               echo "$a" | sed -r 's/[^[:digit:].]//g' | sed -e '/^$/d'
          fi
     done
}

get_local_aaaa() {
     local ip6=""
     local etchosts="/etc/hosts /c/Windows/System32/drivers/etc/hosts"

     # for security testing sometimes we have local entries. Getent is BS under Linux for localhost: No network, no resolution
     ip6=$(grep -wh "$1" $etchosts 2>/dev/null | grep ':' | egrep -v '^#|\.local' | egrep "[[:space:]]$1" | awk '{ print $1 }')
     if is_ipv6addr "$ip6"; then
          echo "$ip6"
     else
          echo ""
     fi
}

get_local_a() {
     local ip4=""
     local etchosts="/etc/hosts /c/Windows/System32/drivers/etc/hosts"

     # for security testing sometimes we have local entries. Getent is BS under Linux for localhost: No network, no resolution
     ip4=$(grep -wh "$1" $etchosts 2>/dev/null | egrep -v ':|^#|\.local' |  egrep "[[:space:]]$1" | awk '{ print $1 }')
     if is_ipv4addr "$ip4"; then
          echo "$ip4"
     else
          echo ""
     fi
}

check_resolver_bins() {
     if ! which dig &> /dev/null && ! which host &> /dev/null && ! which drill &> /dev/null && ! which nslookup &>/dev/null; then
          fatal "Neither \"dig\", \"host\", \"drill\" or \"nslookup\" is present" "-3"
     fi
     return 0
}

# arg1: a host name. Returned will be 0-n IPv4 addresses
# watch out: $1 can also be a cname! --> all checked
get_a_record() {
     local ip4=""
     local saved_openssl_conf="$OPENSSL_CONF"

     "$NODNS" && return 0                    # if no DNS lookup was instructed, leave here
     OPENSSL_CONF=""                         # see https://github.com/drwetter/testssl.sh/issues/134
     if [[ "$NODE" == *.local ]]; then
          if which avahi-resolve &>/dev/null; then
               ip4=$(filter_ip4_address $(avahi-resolve -4 -n "$1" 2>/dev/null | awk '{ print $2 }'))
          elif which dig &>/dev/null; then
               ip4=$(filter_ip4_address $(dig @224.0.0.251 -p 5353 +short -t a +notcp "$1" 2>/dev/null | sed '/^;;/d'))
          else
               fatal "Local hostname given but no 'avahi-resolve' or 'dig' avaliable." -3
          fi
     fi
     if [[ -z "$ip4" ]]; then
          if which dig &> /dev/null ; then
               ip4=$(filter_ip4_address $(dig +short -t a "$1" 2>/dev/null | awk '/^[0-9]/'))
          fi
     fi
     if [[ -z "$ip4" ]]; then
          which host &> /dev/null && \
               ip4=$(filter_ip4_address $(host -t a "$1" 2>/dev/null | awk '/address/ { print $NF }'))
     fi
     if [[ -z "$ip4" ]]; then
          which drill &> /dev/null && \
               ip4=$(filter_ip4_address $(drill a "$1" | awk '/ANSWER SECTION/,/AUTHORITY SECTION/ { print $NF }' | awk '/^[0-9]/'))
     fi
     if [[ -z "$ip4" ]]; then
          if which nslookup &>/dev/null; then
               ip4=$(filter_ip4_address $(nslookup -querytype=a "$1" 2>/dev/null | awk '/^Name/ { getline; print $NF }'))
          fi
     fi
     OPENSSL_CONF="$saved_openssl_conf"      # see https://github.com/drwetter/testssl.sh/issues/134
     echo "$ip4"
}

# arg1: a host name. Returned will be 0-n IPv6 addresses
# watch out: $1 can also be a cname! --> all checked
get_aaaa_record() {
     local ip6=""
     local saved_openssl_conf="$OPENSSL_CONF"

     "$NODNS" && return 0                    # if no DNS lookup was instructed, leave here
     OPENSSL_CONF=""                         # see https://github.com/drwetter/testssl.sh/issues/134
     if [[ -z "$ip6" ]]; then
          if [[ "$NODE" == *.local ]]; then
               if which avahi-resolve &>/dev/null; then
                    ip6=$(filter_ip6_address $(avahi-resolve -6 -n "$1" 2>/dev/null | awk '{ print $2 }'))
               elif which dig &>/dev/null; then
                    ip6=$(filter_ip6_address $(dig @ff02::fb -p 5353 -t aaaa +short +notcp "$NODE"))
               else
                    fatal "Local hostname given but no 'avahi-resolve' or 'dig' avaliable." -3
               fi
          elif which host &> /dev/null ; then
               ip6=$(filter_ip6_address $(host -t aaaa "$1" | awk '/address/ { print $NF }'))
          elif which dig &> /dev/null; then
               ip6=$(filter_ip6_address $(dig +short -t aaaa "$1" 2>/dev/null | awk '/^[0-9]/'))
          elif which drill &> /dev/null; then
               ip6=$(filter_ip6_address $(drill aaaa "$1" | awk '/ANSWER SECTION/,/AUTHORITY SECTION/ { print $NF }' | awk '/^[0-9]/'))
          elif which nslookup &>/dev/null; then
               ip6=$(filter_ip6_address $(nslookup -type=aaaa "$1" 2>/dev/null | awk '/'"^${a}"'.*AAAA/ { print $NF }'))
          fi
     fi
     OPENSSL_CONF="$saved_openssl_conf"      # see https://github.com/drwetter/testssl.sh/issues/134
     echo "$ip6"
}

# RFC6844: DNS Certification Authority Authorization (CAA) Resource Record
# arg1: domain to check for
get_caa_rr_record() {
     local raw_caa=""
     local caa_flag
     local -i len_caa_property
     local caa_property_name
     local caa_property_value
     local saved_openssl_conf="$OPENSSL_CONF"

     # if there's a type257 record there are two output formats here, mostly depending on age of distribution
     # rougly that's the difference between text and binary format
     # 1) 'google.com has CAA record 0 issue "symantec.com"'
     # 2) 'google.com has TYPE257 record \# 19 0005697373756573796D616E7465632E636F6D'
     # for dig +short the output always starts with '0 issue [..]' or '\# 19 [..]' so we normalize thereto to keep caa_flag, caa_property
     # caa_property then has key/value pairs, see https://tools.ietf.org/html/rfc6844#section-3
     OPENSSL_CONF=""
     if which dig &> /dev/null; then
          raw_caa="$(dig $1 type257 +short)"
          # empty if no CAA record
     elif which drill &> /dev/null; then
          raw_caa="$(drill $1 type257 | awk '/'"^${1}"'.*CAA/ { print $5,$6,$7 }')"
     elif which host &> /dev/null; then
          raw_caa="$(host -t type257 $1)"
          if egrep -wvq "has no CAA|has no TYPE257" <<< "$raw_caa"; then
               raw_caa="$(sed -e 's/^.*has CAA record //' -e 's/^.*has TYPE257 record //' <<< "$raw_caa")"
          fi
     elif which nslookup &> /dev/null; then
          raw_caa="$(nslookup -type=type257 $1 | grep -w rdata_257)"
          if [[ -n "$raw_caa" ]]; then
               raw_caa="$(sed 's/^.*rdata_257 = //' <<< "$raw_caa")"
          fi
     else
          return 1
          # No dig, drill, host, or nslookup --> complaint was elsewhere already
     fi
     OPENSSL_CONF="$saved_openssl_conf"      # see https://github.com/drwetter/testssl.sh/issues/134
     debugme echo $raw_caa

     # '# 19' for google.com is the tag length probably --> we use this also to identify the binary format
     if [[ "$raw_caa" =~ \#\ [0-9][0-9]\ [A-F0-9]+$ ]]; then
          raw_caa=$(awk '{ print $NF }' <<< $raw_caa)       # caa_length would be awk '{ print $(NF-1) }' but we don't need it
          if [[ "${raw_caa:0:2}" == "00" ]]; then           # probably the flag
               caa_flag="0"
               len_caa_property=${raw_caa:2:2}              # implicit type casting, for google we have 05 here as a string
               len_caa_property=$((len_caa_property*2))     # =>word! Now get name from 4th and value from 4th+len position...
               caa_property_name=$(hex2ascii ${raw_caa:4:$len_caa_property})
               caa_property_value=$(hex2ascii ${raw_caa:$((4+len_caa_property)):100})
          else
               outln "please report unknown CAA flag $caa_flag @ $NODE"
          fi
     elif grep -q '"' <<< $raw_caa; then
          raw_caa=${raw_caa//\"/}                           # strip " first. Now we should have flag, name, value
          caa_flag=$(awk '{ print $1 }' <<< $raw_caa)
          caa_property_name=$(awk '{ print $2 }' <<< $raw_caa)
          caa_property_value=$(awk '{ print $3 }' <<< $raw_caa)
     else
          # no caa record
          return 1
     fi
     echo "$caa_property_name: $caa_property_value"

# to do:
#    4: check whether $1 is a CNAME and take this
     return 0
}

# watch out: $1 can also be a cname! --> all checked
get_mx_record() {
     local mx=""
     local saved_openssl_conf="$OPENSSL_CONF"

     OPENSSL_CONF=""                         # see https://github.com/drwetter/testssl.sh/issues/134
     check_resolver_bins
     # we need tha last two columns here!
     if which host &> /dev/null; then
          mxs=$(host -t MX "$1" 2>/dev/null | awk '/is handled by/ { print $(NF-1), $NF }')
     elif which dig &> /dev/null; then
          mxs=$(dig +short -t MX "$1" 2>/dev/null | awk '/^[0-9]/')
     elif which drill &> /dev/null; then
          mxs=$(drill mx $1 | | awk '/IN[ \t]MX[ \t]+/ { print $(NF-1), $NF }')
     elif which nslookup &> /dev/null; then
          mxs=$(nslookup -type=MX "$1" 2>/dev/null | awk '/mail exchanger/ { print $(NF-1), $NF }')
     else
          fatal "No dig, host, drill or nslookup" -3
     fi
     OPENSSL_CONF="$saved_openssl_conf"
     echo "$mxs"
}


# set IPADDRs and IP46ADDRs
#
determine_ip_addresses() {
     local ip4=""
     local ip6=""

     if [[ -n "$CMDLINE_IP" ]]; then
          # command line has supplied an IP address
          [[ "$CMDLINE_IP" == "one" ]] && \
               CMDLINE_IP="$(get_a_record $NODE | head -1)"
               # use first IPv4 address
          NODEIP="$CMDLINE_IP"
          if is_ipv4addr "$NODEIP"; then
               ip4="$NODEIP"
          elif is_ipv6addr "$NODEIP"; then
               ip6="$NODEIP"
          else
               fatal "couldn't identify supplied \"CMDLINE_IP\"" 2
          fi
     elif is_ipv4addr "$NODE"; then
          ip4="$NODE"                        # only an IPv4 address was supplied as an argument, no hostname
          SNI=""                             # override Server Name Indication as we test the IP only
     else
          ip4=$(get_local_a $NODE)           # is there a local host entry?
          if [[ -z $ip4 ]]; then             # empty: no (LOCAL_A is predefined as false)
               check_resolver_bins
               ip4=$(get_a_record $NODE)
          else
               LOCAL_A=true                  # we have the ip4 from local host entry and need to signal this to testssl
          fi
          # same now for ipv6
          ip6=$(get_local_aaaa $NODE)
          if [[ -z $ip6 ]]; then
               check_resolver_bins
               ip6=$(get_aaaa_record $NODE)
          else
               LOCAL_AAAA=true               # we have a local ipv6 entry and need to signal this to testssl
          fi
     fi

     if [[ -z "$ip4" ]]; then                # IPv6  only address
          if "$HAS_IPv6"; then
               IPADDRs=$(newline_to_spaces "$ip6")
               IP46ADDRs="$IPADDRs"          # IP46ADDRs are the ones to display, IPADDRs the ones to test
          fi
     else
          if "$HAS_IPv6" && [[ -n "$ip6" ]]; then
               IPADDRs=$(newline_to_spaces "$ip4 $ip6")
               IP46ADDRs="$IPADDRs"
          else
               IPADDRs=$(newline_to_spaces "$ip4")
               IP46ADDRs=$(newline_to_spaces "$ip4 $ip6")
          fi
     fi
     if [[ -z "$IPADDRs" ]]; then
          fatal "No IPv4 address for \"$NODE\" available" -1
     fi
     return 0                                # IPADDR and IP46ADDR is set now
}

determine_rdns() {
     local saved_openssl_conf="$OPENSSL_CONF"
     local nodeip="$(tr -d '[]' <<< $NODEIP)"     # for DNS we do not need the square brackets of IPv6 addresses

     "$NODNS" && rDNS="--" && return 0
     OPENSSL_CONF=""                              # see https://github.com/drwetter/testssl.sh/issues/134
     if [[ "$NODE" == *.local ]]; then
          if which avahi-resolve &>/dev/null; then
               rDNS=$(avahi-resolve -a $nodeip 2>/dev/null | awk '{ print $2 }')
          elif which dig &>/dev/null; then
               rDNS=$(dig -x $nodeip @224.0.0.251 -p 5353 +notcp +noall +answer | awk '/PTR/ { print $NF }')
          fi
     elif which dig &> /dev/null; then
          rDNS=$(dig -x $nodeip +noall +answer | awk  '/PTR/ { print $NF }')    # +short returns also CNAME, e.g. openssl.org
     elif which host &> /dev/null; then
          rDNS=$(host -t PTR $nodeip 2>/dev/null | awk '/pointer/ { print $NF }')
     elif which drill &> /dev/null; then
          rDNS=$(drill -x ptr $nodeip 2>/dev/null | awk '/ANSWER SECTION/ { getline; print $NF }')
     elif which nslookup &> /dev/null; then
          rDNS=$(nslookup -type=PTR $nodeip 2>/dev/null | grep -v 'canonical name =' | grep 'name = ' | awk '{ print $NF }' | sed 's/\.$//')
     fi
     OPENSSL_CONF="$saved_openssl_conf"      # see https://github.com/drwetter/testssl.sh/issues/134
     rDNS="$(echo $rDNS)"
     [[ -z "$rDNS" ]] && rDNS="--"
     return 0
}

# We need to get the IP address of the proxy so we can use it in fd_socket
#
check_proxy() {
     if [[ -n "$PROXY" ]]; then
          if ! "$HAS_PROXY"; then
               fatal "Your $OPENSSL is too old to support the \"-proxy\" option" -5
          fi
          if [[ "$PROXY" == "auto" ]]; then
               # get $ENV 
               PROXY=${https_proxy#*\/\/}
               [[ -z "$PROXY" ]] && PROXY=${http_proxy#*\/\/}
               [[ -z "$PROXY" ]] && fatal "you specified \"--proxy=auto\" but \"\$http(s)_proxy\" is empty" 2
          fi
          PROXYNODE=${PROXY%:*}
          PROXYPORT=${PROXY#*:}
          is_number "$PROXYPORT" || fatal "Proxy port cannot be determined from \"$PROXY\"" 2

          #if is_ipv4addr "$PROXYNODE" || is_ipv6addr "$PROXYNODE" ; then
          # IPv6 via openssl -proxy: that doesn't work. Sockets does
#FIXME: finish this with LibreSSL which supports an IPv6 proxy
          if is_ipv4addr "$PROXYNODE"; then
               PROXYIP="$PROXYNODE"
          else
               PROXYIP=$(get_a_record "$PROXYNODE" 2>/dev/null | grep -v alias | sed 's/^.*address //')
               [[ -z "$PROXYIP" ]] && fatal "Proxy IP cannot be determined from \"$PROXYNODE\"" "2"
          fi
          PROXY="-proxy $PROXYIP:$PROXYPORT"
     fi
}


# this is only being called from determine_optimal_proto in order to check whether we have a server
# with client authentication, a server with no SSL session ID switched off
#
sclient_auth() {
     [[ $1 -eq 0 ]] && return 0                                            # no client auth (CLIENT_AUTH=false is preset globally)
     if [[ -n $(awk '/Master-Key: / { print $2 }' "$2") ]]; then           # connect succeeded
          if grep -q '^<<< .*CertificateRequest' "$2"; then                # CertificateRequest message in -msg
               CLIENT_AUTH=true
               return 0
          fi
          if [[ -z $(awk '/Session-ID: / { print $2 }' "$2") ]]; then      # probably no SSL session
               if [[ 2 -eq $(grep -c CERTIFICATE "$2") ]]; then            # do another sanity check to be sure
                    CLIENT_AUTH=false
                    NO_SSL_SESSIONID=true                                  # NO_SSL_SESSIONID is preset globally to false for all other cases
                    return 0
               fi
          fi
     fi
     # what's left now is: master key empty, handshake returned not successful, session ID empty --> not sucessful
     return 1
}


# this function determines OPTIMAL_PROTO. It is a workaround function as under certain circumstances
# (e.g. IIS6.0 and openssl 1.0.2 as opposed to 1.0.1) needs a protocol otherwise s_client -connect will fail!
# Circumstances observed so far: 1.) IIS 6  2.) starttls + dovecot imap
# The first try in the loop is empty as we prefer not to specify always a protocol if it works w/o.
#
determine_optimal_proto() {
     local all_failed
     local sni=""

     #TODO: maybe query known openssl version before this workaround. 1.0.1 doesn't need this

     >$ERRFILE
     if [[ -n "$1" ]]; then
          # starttls workaround needed see https://github.com/drwetter/testssl.sh/issues/188
          # kind of odd
          for STARTTLS_OPTIMAL_PROTO in -tls1_2 -tls1 -ssl3 -tls1_1 -ssl2; do
               $OPENSSL s_client $STARTTLS_OPTIMAL_PROTO $BUGS -connect "$NODEIP:$PORT" $PROXY -msg -starttls $1 </dev/null >$TMPFILE 2>>$ERRFILE
               if sclient_auth $? $TMPFILE; then
                    all_failed=1
                    break
               fi
               all_failed=0
          done
          [[ $all_failed -eq 0 ]] && STARTTLS_OPTIMAL_PROTO=""
          debugme echo "STARTTLS_OPTIMAL_PROTO: $STARTTLS_OPTIMAL_PROTO"
     else
          for OPTIMAL_PROTO in '' -tls1_2 -tls1 -ssl3 -tls1_1 -ssl2; do
               [[ "$OPTIMAL_PROTO" =~ ssl ]] && sni="" || sni=$SNI
               $OPENSSL s_client $OPTIMAL_PROTO $BUGS -connect "$NODEIP:$PORT" -msg $PROXY $sni </dev/null >$TMPFILE 2>>$ERRFILE
               if sclient_auth $? $TMPFILE; then
                    all_failed=1
                    break
               fi
               all_failed=0
          done
          [[ $all_failed -eq 0 ]] && OPTIMAL_PROTO=""
          debugme echo "OPTIMAL_PROTO: $OPTIMAL_PROTO"
          if [[ "$OPTIMAL_PROTO" == "-ssl2" ]]; then
               pr_magentaln "$NODEIP:$PORT appears to only support SSLv2."
               ignore_no_or_lame " Type \"yes\" to proceed and accept false negatives or positives" "yes"
               [[ $? -ne 0 ]] && exit -2
          fi
     fi
     grep -q '^Server Temp Key' $TMPFILE && HAS_DH_BITS=true     # FIX #190

     if [[ $all_failed -eq 0 ]]; then
          outln
          if "$HAS_IPv6"; then
               pr_bold " Your $OPENSSL is not IPv6 aware, or $NODEIP:$PORT "
          else
               pr_bold " $NODEIP:$PORT "
          fi
          tmpfile_handle $FUNCNAME.txt
          pr_boldln "doesn't seem to be a TLS/SSL enabled server";
          ignore_no_or_lame " The results might look ok but they could be nonsense. Really proceed ? (\"yes\" to continue)" "yes"
          [[ $? -ne 0 ]] && exit -2
     fi

     tmpfile_handle $FUNCNAME.txt
     return 0
}


# arg1: ftp smtp, pop3, imap, xmpp, telnet, ldap, postgres (maybe with trailing s)
determine_service() {
     local ua
     local protocol

     if ! fd_socket; then          # check if we can connect to $NODEIP:$PORT
          [[ -n "$PROXY" ]] && \
               fatal "You're sure $PROXYNODE:$PROXYPORT allows tunneling here? Can't connect to \"$NODEIP:$PORT\"" -2 || \
               fatal "Can't connect to \"$NODEIP:$PORT\"\nMake sure a firewall is not between you and your scanning target!" -2
     fi
     close_socket

     datebanner " Start"
     outln
     if [[ -z "$1" ]]; then
          # no STARTTLS.
          determine_optimal_proto "$1"
          $SNEAKY && \
               ua="$UA_SNEAKY" || \
               ua="$UA_STD"
          GET_REQ11="GET $URL_PATH HTTP/1.1\r\nHost: $NODE\r\nUser-Agent: $ua\r\nConnection: Close\r\nAccept: text/*\r\n\r\n"
          #HEAD_REQ11="HEAD $URL_PATH HTTP/1.1\r\nHost: $NODE\r\nUser-Agent: $ua\r\nAccept: text/*\r\n\r\n"
          #GET_REQ10="GET $URL_PATH HTTP/1.0\r\nUser-Agent: $ua\r\nConnection: Close\r\nAccept: text/*\r\n\r\n"
          #HEAD_REQ10="HEAD $URL_PATH HTTP/1.0\r\nUser-Agent: $ua\r\nAccept: text/*\r\n\r\n"
          service_detection $OPTIMAL_PROTO
     else
          # STARTTLS
          if [[ "$1" == postgres ]]; then
               protocol="postgres"
          else
               protocol=${1%s}    # strip trailing 's' in ftp(s), smtp(s), pop3(s), etc
          fi
          case "$protocol" in
               ftp|smtp|pop3|imap|xmpp|telnet|ldap|postgres)
                    STARTTLS="-starttls $protocol"
                    SNI=""
                    if [[ "$protocol" == xmpp ]]; then
                         # for XMPP, openssl has a problem using -connect $NODEIP:$PORT. thus we use -connect $NODE:$PORT instead!
                         NODEIP="$NODE"
                         if [[ -n "$XMPP_HOST" ]]; then
                              if ! "$HAS_XMPP"; then
                                   fatal "Your $OPENSSL does not support the \"-xmpphost\" option" -5
                              fi
                              STARTTLS="$STARTTLS -xmpphost $XMPP_HOST"         # it's a hack -- instead of changing calls all over the place
                              # see http://xmpp.org/rfcs/rfc3920.html
                         fi
                    fi
                    if [[ "$protocol" == postgres ]]; then
                         # Check if openssl version supports postgres.
                         if ! "$HAS_POSTGRES"; then
                              fatal "Your $OPENSSL does not support the \"-starttls postgres\" option" -5
                         fi
                    fi
                    $OPENSSL s_client -connect $NODEIP:$PORT $PROXY $BUGS $STARTTLS 2>$ERRFILE >$TMPFILE </dev/null
                    if [[ $? -ne 0 ]]; then
                         debugme cat $TMPFILE
                         outln
                         fatal " $OPENSSL couldn't establish STARTTLS via $protocol to $NODEIP:$PORT" -2
                    fi
                    grep -q '^Server Temp Key' $TMPFILE && HAS_DH_BITS=true     # FIX #190
                    out " Service set:$CORRECT_SPACES            STARTTLS via "
                    fileout "service" "INFO" "$protocol"
                    toupper "$protocol"
                    [[ -n "$XMPP_HOST" ]] && echo -n " (XMPP domain=\'$XMPP_HOST\')"
                    outln
                    ;;
               *)   outln
                    fatal "momentarily only ftp, smtp, pop3, imap, xmpp, telnet, ldap and postgres allowed" -4
                    ;;
          esac
     fi
     #outln

     tmpfile_handle $FUNCNAME.txt
     return 0       # OPTIMAL_PROTO, GET_REQ*/HEAD_REQ* is set now
}


display_rdns_etc() {
     local ip
     local nodeip="$(tr -d '[]' <<< $NODEIP)"     # for displaying IPv6 addresses we don't need []


     if [[ -n "$PROXY" ]]; then
          out " Via Proxy:              $CORRECT_SPACES"
          outln "$PROXYIP:$PROXYPORT "
     fi
     if [[ $(count_words "$IP46ADDRs") -gt 1 ]]; then
          out " further IP addresses:  $CORRECT_SPACES"
          for ip in $IP46ADDRs; do
               if [[ "$ip" == "$NODEIP" ]] || [[ "[$ip]" == "$NODEIP" ]]; then
                    continue
               else
                    out " $ip"
               fi
          done
          outln
     fi
     if "$LOCAL_A"; then
          outln " A record via           $CORRECT_SPACES /etc/hosts "
     elif  [[ -n "$CMDLINE_IP" ]]; then
          outln " A record via           $CORRECT_SPACES supplied IP \"$CMDLINE_IP\""
     fi
     if [[ -n "$rDNS" ]]; then
          printf " %-23s %s" "rDNS ($nodeip):" "$rDNS"
     fi
}

datebanner() {
     pr_reverse "$1 $(date +%F) $(date +%T)    -->> $NODEIP:$PORT ($NODE) <<--"
     outln "\n"
     [[ "$1" =~ Start ]] && display_rdns_etc
}

# one line with char $1 over screen width $2
draw_line() {
     printf -- "$1"'%.s' $(eval "echo {1.."$(($2))"}")
}


run_mx_all_ips() {
     local mxs mx
     local mxport
     local -i ret=0

     STARTTLS_PROTOCOL="smtp"

     # test first higher priority servers
     mxs=$(get_mx_record "$1" | sort -n | sed -e 's/^.* //' -e 's/\.$//' | tr '\n' ' ')
     mxport=${2:-25}
     if [[ -n "$LOGFILE" ]]; then
          prepare_logging
     else
          prepare_logging "mx-$1"
     fi
     if [[ -n "$mxs" ]] && [[ "$mxs" != ' ' ]]; then
          [[ $mxport == "465" ]] && \
               STARTTLS_PROTOCOL=""          # no starttls for Port 465, on all other ports we speak starttls
          pr_bold "Testing now all MX records (on port $mxport): "; outln "$mxs"
          for mx in $mxs; do
               draw_line "-" $((TERM_WIDTH * 2 / 3))
               outln
               parse_hn_port "$mx:$mxport"
               determine_ip_addresses || continue
               if [[ $(count_words "$(echo -n "$IPADDRs")") -gt 1 ]]; then           # we have more than one ipv4 address to check
                    pr_bold "Testing all IPv4 addresses (port $PORT): "; outln "$IPADDRs"
                    for ip in $IPADDRs; do
                         NODEIP="$ip"
                         lets_roll "${STARTTLS_PROTOCOL}"
                    done
               else
                    NODEIP="$IPADDRs"
                    lets_roll "${STARTTLS_PROTOCOL}"
               fi
               ret=$(($? + ret))
          done
          draw_line "-" $((TERM_WIDTH * 2 / 3))
          outln
          pr_bold "Done testing now all MX records (on port $mxport): "; outln "$mxs"
     else
          pr_boldln " $1 has no MX records(s)"
     fi
     return $ret
}


run_mass_testing_parallel() {
     local cmdline=""
     local global_cmdline=${CMDLINE%%--file*}

     if [[ ! -r "$FNAME" ]] && $IKNOW_FNAME; then
          fatal "Can't read file \"$FNAME\"" "2"
     fi
     pr_reverse "====== Running in parallel file batch mode with file=\"$FNAME\" ======"; outln
     outln "(output is in ....\n)"
#FIXME: once this function is being called we need a handler which does the right thing, i.e.  ==> not to overwrite
     while read cmdline; do
          cmdline=$(filter_input "$cmdline")
          [[ -z "$cmdline" ]] && continue
          [[ "$cmdline" == "EOF" ]] && break
          cmdline="$0 $global_cmdline --warnings=batch -q $cmdline"
          draw_line "=" $((TERM_WIDTH / 2)); outln;
          determine_logfile
          outln "$cmdline"
          $cmdline >$LOGFILE &
          sleep $PARALLEL_SLEEP
     done < "$FNAME"
     return $?
}


run_mass_testing() {
     local cmdline=""
     local global_cmdline=${CMDLINE%%--file*}

     if [[ ! -r "$FNAME" ]] && "$IKNOW_FNAME"; then
          fatal "Can't read file \"$FNAME\"" "2"
     fi

     pr_reverse "====== Running in file batch mode with file=\"$FNAME\" ======"; outln "\n"
     APPEND=false # Make sure we close out our files
     while read cmdline; do
          cmdline=$(filter_input "$cmdline")
          [[ -z "$cmdline" ]] && continue
          [[ "$cmdline" == "EOF" ]] && break
          cmdline="$0 $global_cmdline --warnings=batch -q --append $cmdline"
          draw_line "=" $((TERM_WIDTH / 2)); outln;
          outln "$cmdline"
          $cmdline
     done < "${FNAME}"
     fileout_footer
     return $?
}



# This initializes boolean global do_* variables. They keep track of what to do
# -- as the name insinuates
initialize_globals() {
     do_allciphers=false
     do_vulnerabilities=false
     do_beast=false
     do_lucky13=false
     do_breach=false
     do_ccs_injection=false
     do_cipher_per_proto=false
     do_crime=false
     do_freak=false
     do_logjam=false
     do_drown=false
     do_header=false
     do_heartbleed=false
     do_mx_all_ips=false
     do_mass_testing=false
     do_logging=false
     do_json=false
     do_pretty_json=false
     do_csv=false
     do_pfs=false
     do_protocols=false
     do_rc4=false
     do_renego=false
     do_std_cipherlists=false
     do_server_defaults=false
     do_server_preference=false
     do_spdy=false
     do_http2=false
     do_ssl_poodle=false
     do_sweet32=false
     do_tls_fallback_scsv=false
     do_test_just_one=false
     do_tls_sockets=false
     do_client_simulation=false
     do_display_only=false
}


# Set default scanning options for the boolean global do_* variables.
set_scanning_defaults() {
     do_allciphers=true
     do_vulnerabilities=true
     do_beast=true
     do_lucky13=true
     do_breach=true
     do_heartbleed=true
     do_ccs_injection=true
     do_crime=true
     do_freak=true
     do_logjam=true
     do_drown=true
     do_ssl_poodle=true
     do_sweet32=true
     do_header=true
     do_pfs=true
     do_rc4=true
     do_protocols=true
     do_renego=true
     do_std_cipherlists=true
     do_server_defaults=true
     do_server_preference=true
     do_spdy=true
     do_http2=true
     do_tls_fallback_scsv=true
     do_client_simulation=true
     VULN_COUNT=16
}

query_globals() {
     local gbl
     local true_nr=0

     for gbl in do_allciphers do_vulnerabilities do_beast do_lucky13 do_breach do_ccs_injection do_cipher_per_proto do_crime \
               do_freak do_logjam do_drown do_header do_heartbleed do_mx_all_ips do_pfs do_protocols do_rc4 do_renego \
               do_std_cipherlists do_server_defaults do_server_preference do_spdy do_http2 do_ssl_poodle do_tls_fallback_scsv \
               do_sweet32 do_client_simulation do_test_just_one do_tls_sockets do_mass_testing do_display_only; do
                    [[ "${!gbl}" == "true" ]] && let true_nr++
     done
     return $true_nr
}


debug_globals() {
     local gbl

     for gbl in do_allciphers do_vulnerabilities do_beast do_lucky13 do_breach do_ccs_injection do_cipher_per_proto do_crime \
               do_freak do_logjam do_drown do_header do_heartbleed do_mx_all_ips do_pfs do_protocols do_rc4 do_renego \
               do_std_cipherlists do_server_defaults do_server_preference do_spdy do_http2 do_ssl_poodle do_tls_fallback_scsv \
               do_sweet32 do_client_simulation do_test_just_one do_tls_sockets do_mass_testing do_display_only; do
          printf "%-22s = %s\n" $gbl "${!gbl}"
     done
     printf "%-22s : %s\n" URI: "$URI"
}


# arg1: either switch+value (=) or switch
# arg2: value (if no = provided)
parse_opt_equal_sign() {
     if [[ "$1" == *=* ]]; then
          echo ${1#*=}
          return 1  # = means we don't need to shift args!
     else
          echo $2
          return 0  # we need to shift
     fi
}


parse_cmd_line() {
     # Show usage if no options were specified
     [[ -z "$1" ]] && help 0
     # Set defaults if only an URI was specified, maybe ToDo: use "="-option, then: ${i#*=} i.e. substring removal
     [[ "$#" -eq 1 ]] && set_scanning_defaults

     while [[ $# -gt 0 ]]; do
          case $1 in
               -h|--help)
                    help 0
                    ;;
               -b|--banner|-v|--version)
                    maketempf
                    find_openssl_binary
                    prepare_debug
                    mybanner
                    exit 0
                    ;;
               --mx)
                    do_mx_all_ips=true
                    PORT=25
                    ;;
               --mx465)                      # doesn't work with major ISPs
                    do_mx_all_ips=true
                    PORT=465
                    ;;
               --mx587)                      # doesn't work with major ISPs
                    do_mx_all_ips=true
                    PORT=587
                    ;;
               --ip|--ip=*)
                    CMDLINE_IP=$(parse_opt_equal_sign "$1" "$2")
                    [[ $? -eq 0 ]] && shift
                    ;;
               -n|--nodns)
                    NODNS=true
                    ;;
               -V|-V=*|--local|--local=*)    # attention, this could have a value or not!
                    do_display_only=true
                    PATTERN2SHOW="$(parse_opt_equal_sign "$1" "$2")"
                    retval=$?
                    if [[ "$PATTERN2SHOW" == -* ]]; then
                         unset PATTERN2SHOW  # we hit the next command ==> not our value
                    else                     # it was ours, point to next arg
                         [[ $retval -eq 0 ]] && shift
                    fi
                    ;;
               -x|-x=*|--single[-_]cipher|--single[-_]cipher=*)
                    do_test_just_one=true
                    single_cipher=$(parse_opt_equal_sign "$1" "$2")
                    [[ $? -eq 0 ]] && shift
                    ;;
               -t|-t=*|--starttls|--starttls=*)
                    do_starttls=true
                    STARTTLS_PROTOCOL=$(parse_opt_equal_sign "$1" "$2")
                    [[ $? -eq 0 ]] && shift
                    case $STARTTLS_PROTOCOL in
                         ftp|smtp|pop3|imap|xmpp|telnet|ldap|nntp|postgres) ;;
                         ftps|smtps|pop3s|imaps|xmpps|telnets|ldaps|nntps|postgress) ;;
                         *)   pr_magentaln "\nunrecognized STARTTLS protocol \"$1\", see help" 1>&2
                              help 1 ;;
                    esac
                    ;;
               --xmpphost|--xmpphost=*)
                    XMPP_HOST=$(parse_opt_equal_sign "$1" "$2")
                    [[ $? -eq 0 ]] && shift
                    ;;
               -e|--each-cipher)
                    do_allciphers=true
                    ;;
               -E|--cipher-per-proto|--cipher_per_proto)
                    do_cipher_per_proto=true
                    ;;
               -p|--protocols)
                    do_protocols=true
                    do_spdy=true
                    do_http2=true
                    ;;
               -y|--spdy|--npn)
                    do_spdy=true
                    ;;
               -Y|--http2|--alpn)
                    do_http2=true
                    ;;
               -f|--ciphers)
                    do_std_cipherlists=true
                    ;;
               -S|--server[-_]defaults)
                    do_server_defaults=true
                    ;;
               -P|--server[_-]preference|--preference)
                    do_server_preference=true
                    ;;
               -H|--header|--headers)
                    do_header=true
                    ;;
               -c|--client-simulation)
                    do_client_simulation=true
                    ;;
               -U|--vulnerable)
                    do_vulnerabilities=true
                    do_heartbleed=true
                    do_ccs_injection=true
                    do_renego=true
                    do_crime=true
                    do_breach=true
                    do_ssl_poodle=true
                    do_tls_fallback_scsv=true
                    do_sweet32=true
                    do_freak=true
                    do_drown=true
                    do_logjam=true
                    do_beast=true
                    do_lucky13=true
                    do_rc4=true
                    VULN_COUNT=10
                    ;;
               -B|--heartbleed)
                    do_heartbleed=true
                    let "VULN_COUNT++"
                    ;;
               -I|--ccs|--ccs[-_]injection)
                    do_ccs_injection=true
                    let "VULN_COUNT++"
                    ;;
               -R|--renegotiation)
                    do_renego=true
                    let "VULN_COUNT++"
                    ;;
               -C|--compression|--crime)
                    do_crime=true
                    let "VULN_COUNT++"
                    ;;
               -T|--breach)
                    do_breach=true
                    let "VULN_COUNT++"
                    ;;
               -O|--poodle)
                    do_ssl_poodle=true
                    do_tls_fallback_scsv=true
                    let "VULN_COUNT++"
                    ;;
               -Z|--tls[_-]fallback|tls[_-]fallback[_-]scs)
                    do_tls_fallback_scsv=true
                    let "VULN_COUNT++"
                    ;;
               -W|--sweet32)
                    do_sweet32=true
                    let "VULN_COUNT++"
                    ;;
               -F|--freak)
                    do_freak=true
                    let "VULN_COUNT++"
                    ;;
               -D|--drown)
                    do_drown=true
                    let "VULN_COUNT++"
                    ;;
               -J|--logjam)
                    do_logjam=true
                    let "VULN_COUNT++"
                    ;;
               -A|--beast)
                    do_beast=true
                    let "VULN_COUNT++"
                    ;;
               -L|--lucky13)
                    do_lucky13=true
                    let "VULN_COUNT++"
                    ;;
               -4|--rc4|--appelbaum)
                    do_rc4=true
                    let "VULN_COUNT++"
                    ;;
               -s|--pfs|--fs|--nsa)
                    do_pfs=true
                    ;;
               --devel) ### this development feature will soon disappear
                    HEX_CIPHER="$TLS12_CIPHER"
                    # DEBUG=3  ./testssl.sh --devel 03 "cc, 13, c0, 13" google.de                              --> TLS 1.2, old CHACHA/POLY
                    # DEBUG=3  ./testssl.sh --devel 03 "cc,a8, cc,a9, cc,aa, cc,ab, cc,ac" blog.cloudflare.com -->          new CHACHA/POLY
                    # DEBUG=3  ./testssl.sh --devel 01 yandex.ru                     --> TLS 1.0
                    # DEBUG=3  ./testssl.sh --devel 00 <host which supports SSLv3>
                    # DEBUG=3  ./testssl.sh --devel 22 <host which still supports SSLv2>
                    TLS_LOW_BYTE="$2";
                    if [[ $# -eq 4 ]]; then  # protocol AND ciphers specified
                         HEX_CIPHER="$3"
                         shift
                    fi
                    shift
                    do_tls_sockets=true
                    outln "\nTLS_LOW_BYTE/HEX_CIPHER: ${TLS_LOW_BYTE}/${HEX_CIPHER}"
                    ;;
               --wide)
                    WIDE=true
                    ;;
               --assuming[_-]http|--assume[-_]http)
                    ASSUME_HTTP=true
                    ;;
               --sneaky)
                    SNEAKY=true
                    ;;
               -q|--quiet)
                    QUIET=true
                    ;;
               --file|--file=*)
                    # no shift here as otherwise URI is empty and it bails out
                    FNAME=$(parse_opt_equal_sign "$1" "$2")
                    [[ $? -eq 0 ]] && shift
                    IKNOW_FNAME=true
                    WARNINGS=batch           # set this implicitly!
                    do_mass_testing=true
                    ;;
               --warnings|--warnings=*)
                    WARNINGS=$(parse_opt_equal_sign "$1" "$2")
                    [[ $? -eq 0 ]] && shift
                    case "$WARNINGS" in
                         batch|off|false) ;;
                         *)   pr_magentaln "\nwarnings can be either \"batch\", \"off\" or \"false\""
                              help 1
                    esac
                    ;;
               --show[-_]each)
                    SHOW_EACH_C=true
                    ;;
               --fast)
                    FAST=true
                    ;;
               --bugs)
                    BUGS="-bugs"
                    ;;
               --debug|--debug=*)
                    DEBUG=$(parse_opt_equal_sign "$1" "$2")
                    [[ $? -eq 0 ]] && shift
                    case $DEBUG in
                         [0-6]) ;;
                         *)   pr_magentaln "\nunrecognized debug value \"$1\", must be between 0..6" 1>&2
                              help 1
                    esac
                    ;;
               --color|--color=*)
                    COLOR=$(parse_opt_equal_sign "$1" "$2")
                    [[ $? -eq 0 ]] && shift
                    case $COLOR in
                         [0-2]) ;;
                         *)   COLOR=2
                              pr_magentaln "\nunrecognized color: \"$1\", must be between 0..2" 1>&2
                              help 1
                    esac
                    ;;
               --colorblind)
                    COLORBLIND=true
                    ;;
               --log|--logging)
                    do_logging=true
                    ;;   # DEFINITION of LOGFILE if no arg specified: automagically in parse_hn_port()
                    # following does the same but we can specify a log location additionally
               --logfile|--logfile=*)
                    LOGFILE=$(parse_opt_equal_sign "$1" "$2")
                    [[ $? -eq 0 ]] && shift
                    do_logging=true
                    ;;
               --json)
                    do_json=true
                    ;;   # DEFINITION of JSONFILE is not arg specified: automagically in parse_hn_port()
                    # following does the same but we can specify a log location additionally
               --jsonfile|--jsonfile=*)
                    JSONFILE=$(parse_opt_equal_sign "$1" "$2")
                    [[ $? -eq 0 ]] && shift
                    do_json=true
                    ;;
               --json-pretty)
                    do_pretty_json=true
                    ;;
               --jsonfile-pretty|--jsonfile-pretty=*)
                    JSONFILE=$(parse_opt_equal_sign "$1" "$2")
                    [[ $? -eq 0 ]] && shift
                    do_pretty_json=true
                    ;;
               --severity|--severity=*)
                    set_severity_level "$(parse_opt_equal_sign "$1" "$2")"
                    [[ $? -eq 0 ]] && shift
                    ;;
               --hints)
                    GIVE_HINTS=true
                    ;;
               --csv)
                    do_csv=true
                    ;;   # DEFINITION of CSVFILE is not arg specified: automagically in parse_hn_port()
                    # following does the same but we can specify a log location additionally
               --csvfile|--csvfile=*)
                    CSVFILE=$(parse_opt_equal_sign "$1" "$2")
                    [[ $? -eq 0 ]] && shift
                    do_csv=true
                    ;;
               --append)
                    APPEND=true
                    ;;
               --openssl|--openssl=*)
                    OPENSSL=$(parse_opt_equal_sign "$1" "$2")
                    [[ $? -eq 0 ]] && shift
                    ;;
               --openssl-timeout|--openssl-timeout=*)
                    OPENSSL_TIMEOUT=$(parse_opt_equal_sign "$1" "$2")
                    [[ $? -eq 0 ]] && shift
                    ;;
               --mapping|--mapping=*)
                    local cipher_mapping
                    cipher_mapping=$(parse_opt_equal_sign "$1" "$2")
                    [[ $? -eq 0 ]] && shift
                    case "$cipher_mapping" in
                         no-rfc) unset ADD_RFC_STR; unset SHOW_RFC;;
                         rfc) SHOW_RFC="rfc" ;;
                         *)   pr_magentaln "\nmapping can only be \"rfc\" or \"no-rfc\""
                              help 1 ;;
                    esac
                    ;;
               --proxy|--proxy=*)
                    PROXY=$(parse_opt_equal_sign "$1" "$2")
                    [[ $? -eq 0 ]] && shift
                    ;;
               -6)  # doesn't work automagically. My versions have -DOPENSSL_USE_IPV6, CentOS/RHEL/FC do not
                    HAS_IPv6=true
                    ;;
               --has[-_]dhbits|--has[_-]dh[-_]bits)      # For CentOS, RHEL and FC with openssl server temp key backport on version 1.0.1, see #190. But should work automagically
                    HAS_DH_BITS=true
                    ;;
               --ssl_native|--ssl-native)
                    SSL_NATIVE=true
                    ;;
               (--) shift
                    break
                    ;;
               (-*) pr_warningln "0: unrecognized option \"$1\"" 1>&2;
                    help 1
                    ;;
               (*)  break
                    ;;
          esac
          shift
     done

     # Show usage if no further options were specified
     if [[ -z "$1" ]] && [[ -z "$FNAME" ]] && ! $do_display_only; then
          echo && fatal "URI missing" "1"
     else
     # left off here is the URI
          URI="$1"
          # parameter after URI supplied:
          [[ -n "$2" ]] && echo && fatal "URI comes last" "1"
     fi

     [[ "$DEBUG" -ge 5 ]] && debug_globals
     # if we have no "do_*" set here --> query_globals: we do a standard run -- otherwise just the one specified
     query_globals && set_scanning_defaults
}


# connect call from openssl needs ipv6 in square brackets
nodeip_to_proper_ip6() {
     local len_nodeip=0

     if is_ipv6addr $NODEIP; then
          ${UNBRACKTD_IPV6} || NODEIP="[$NODEIP]"
          len_nodeip=${#NODEIP}
          CORRECT_SPACES="$(draw_line " " "$((len_nodeip - 17))" )"
          # IPv6 addresses are longer, this varaible takes care that "further IP" and "Service" is properly aligned
     fi
}


reset_hostdepended_vars() {
     TLS_EXTENSIONS=""
     PROTOS_OFFERED=""
     OPTIMAL_PROTO=""
     SERVER_SIZE_LIMIT_BUG=false
}


lets_roll() {
     local ret
     local section_number=1

     [[ -z "$NODEIP" ]] && fatal "$NODE doesn't resolve to an IP address" 2
     nodeip_to_proper_ip6
     reset_hostdepended_vars
     determine_rdns

     START_TIME=$(date +%s)

     ((SERVER_COUNTER++))
     determine_service "$1"        # any starttls service goes here

     $do_tls_sockets && [[ $TLS_LOW_BYTE -eq 22 ]] && { sslv2_sockets "" "true"; echo "$?" ; exit 0; }
     $do_tls_sockets && [[ $TLS_LOW_BYTE -ne 22 ]] && { tls_sockets "$TLS_LOW_BYTE" "$HEX_CIPHER" "all"; echo "$?" ; exit 0; }
     $do_test_just_one && test_just_one ${single_cipher}

     # all top level functions  now following have the prefix "run_"
     fileout_section_header $section_number false && ((section_number++))
     $do_protocols && { run_protocols; ret=$(($? + ret)); }
     $do_spdy && { run_spdy; ret=$(($? + ret)); }
     $do_http2 && { run_http2; ret=$(($? + ret)); }

     fileout_section_header $section_number true && ((section_number++))
     $do_std_cipherlists && { run_std_cipherlists; ret=$(($? + ret)); }

     fileout_section_header $section_number true && ((section_number++))
     $do_pfs && { run_pfs; ret=$(($? + ret)); }

     fileout_section_header $section_number true && ((section_number++))
     $do_server_preference && { run_server_preference; ret=$(($? + ret)); }

     fileout_section_header $section_number true && ((section_number++))
     $do_server_defaults && { run_server_defaults; ret=$(($? + ret)); }

     if $do_header; then
          #TODO: refactor this into functions
          fileout_section_header $section_number true && ((section_number++))
          if [[ $SERVICE == "HTTP" ]]; then
               run_http_header "$URL_PATH"
               run_http_date "$URL_PATH"
               run_hsts "$URL_PATH"
               run_hpkp "$URL_PATH"
               run_server_banner "$URL_PATH"
               run_application_banner "$URL_PATH"
               run_cookie_flags "$URL_PATH"
               run_more_flags "$URL_PATH"
               run_rp_banner "$URL_PATH"
         fi
     else
         ((section_number++))
     fi

     # vulnerabilities
     if [[ $VULN_COUNT -gt $VULN_THRESHLD ]] || $do_vulnerabilities; then
          outln; pr_headlineln " Testing vulnerabilities "
          outln
     fi

     fileout_section_header $section_number true && ((section_number++))
     $do_heartbleed && { run_heartbleed; ret=$(($? + ret)); }
     $do_ccs_injection && { run_ccs_injection; ret=$(($? + ret)); }
     $do_renego && { run_renego; ret=$(($? + ret)); }
     $do_crime && { run_crime; ret=$(($? + ret)); }
     $do_breach && { run_breach "$URL_PATH" ; ret=$(($? + ret)); }
     $do_ssl_poodle && { run_ssl_poodle; ret=$(($? + ret)); }
     $do_tls_fallback_scsv && { run_tls_fallback_scsv; ret=$(($? + ret)); }
     $do_sweet32 && { run_sweet32; ret=$(($? + ret)); }
     $do_freak && { run_freak; ret=$(($? + ret)); }
     $do_drown && { run_drown ret=$(($? + ret)); }
     $do_logjam && { run_logjam; ret=$(($? + ret)); }
     $do_beast && { run_beast; ret=$(($? + ret)); }
     $do_lucky13 && { run_lucky13; ret=$(($? + ret)); }
     $do_rc4 && { run_rc4; ret=$(($? + ret)); }

     fileout_section_header $section_number true && ((section_number++))
     $do_allciphers && { run_allciphers; ret=$(($? + ret)); }
     $do_cipher_per_proto && { run_cipher_per_proto; ret=$(($? + ret)); }

     fileout_section_header $section_number true && ((section_number++))
     $do_client_simulation && { run_client_simulation; ret=$(($? + ret)); }

     fileout_section_footer true

     outln
     END_TIME=$(date +%s)
     datebanner " Done"

     return $ret
}



################# main #################


initialize_globals
parse_cmd_line "$@"
get_install_dir
set_color_functions
maketempf
find_openssl_binary
prepare_debug
mybanner
check_proxy
check4openssl_oldfarts
check_bsd_mount

# TODO: it is ugly to have those two vars here --> main()
ret=0
ip=""

if $do_display_only; then
     prettyprint_local "$PATTERN2SHOW"
     exit $?
fi

if $do_mass_testing; then
     run_mass_testing
     exit $?
fi

#TODO: there shouldn't be the need for a special case for --mx, only the ip adresses we would need upfront and the do-parser
if $do_mx_all_ips; then
     query_globals                 # if we have just 1x "do_*" --> we do a standard run -- otherwise just the one specified
     [[ $? -eq 1 ]] && set_scanning_defaults
     run_mx_all_ips "${URI}" $PORT # we should reduce run_mx_all_ips to the stuff neccessary as ~15 lines later we have sililar code
     ret=$?
else
     parse_hn_port "${URI}"                                                     # NODE, URL_PATH, PORT, IPADDR and IP46ADDR is set now
     prepare_logging
     if ! determine_ip_addresses; then
          fatal "No IP address could be determined" 2
     fi
     if [[ -n "$CMDLINE_IP" ]]; then
          #  we just test the one supplied
          lets_roll "${STARTTLS_PROTOCOL}"
          ret=$?
     else                                                                       # no --ip was supplied
          if [[ $(count_words "$(echo -n "$IPADDRs")") -gt 1 ]]; then           # we have more than one ipv4 address to check
               pr_bold "Testing all IPv4 addresses (port $PORT): "; outln "$IPADDRs"
               for ip in $IPADDRs; do
                    draw_line "-" $((TERM_WIDTH * 2 / 3))
                    outln
                    NODEIP="$ip"
                    lets_roll "${STARTTLS_PROTOCOL}"
                    ret=$(($? + ret))
               done
               draw_line "-" $((TERM_WIDTH * 2 / 3))
               outln
               pr_bold "Done testing now all IP addresses (on port $PORT): "; outln "$IPADDRs"
          else                                                                  # we need just one ip4v to check
               NODEIP="$IPADDRs"
               lets_roll "${STARTTLS_PROTOCOL}"
               ret=$?
          fi
     fi
fi

exit $?
