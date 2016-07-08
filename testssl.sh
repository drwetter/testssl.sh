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

readonly VERSION="2.8rc1"
readonly SWCONTACT="dirk aet testssl dot sh"
egrep -q "dev|rc" <<< "$VERSION" && \
     SWURL="https://testssl.sh/dev/" ||
     SWURL="https://testssl.sh/    "

readonly PROG_NAME=$(basename "$0")
readonly RUN_DIR=$(dirname "$0")
INSTALL_DIR=""
MAPPING_FILE_RFC=""
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

if ! tput cols &>/dev/null || ! $INTERACTIVE; then     # Prevent tput errors if running non interactive
     TERM_WIDTH=${COLUMNS:-80}
else
     TERM_WIDTH=${COLUMNS:-$(tput cols)}               # for custom line wrapping and dashes
fi
TERM_CURRPOS=0                                         # custom line wrapping needs alter the current horizontal cursor pos

# following variables make use of $ENV, e.g. OPENSSL=<myprivate_path_to_openssl> ./testssl.sh <host>
# 0 means (normally) true here. Some of the variables are also accessible with a command line switch, see --help

declare -x OPENSSL
COLOR=${COLOR:-2}                       # 2: Full color, 1: b/w+positioning, 0: no ESC at all
COLORBLIND=${COLORBLIND:-false}         # if true, swap blue and green in the output
SHOW_EACH_C=${SHOW_EACH_C:-false}       # where individual ciphers are tested show just the positively ones tested
SHOW_SIGALGO=${SHOW_SIGALGO:-false}     # "secret" switch whether testssl.sh shows the signature algorithm for -E / -e
SNEAKY=${SNEAKY:-false}                 # is the referer and useragent we leave behind just usual?
QUIET=${QUIET:-false}                   # don't output the banner. By doing this yiu acknowledge usage term appearing in the banner
SSL_NATIVE=${SSL_NATIVE:-false}         # we do per default bash sockets where possible "true": switch back to "openssl native"
ASSUMING_HTTP=${ASSUMING_HTTP:-false}   # in seldom cases (WAF, old servers, grumpy SSL) service detection fails. "True" enforces HTTP checks
BUGS=${BUGS:-""}                        # -bugs option from openssl, needed for some BIG IP F5
DEBUG=${DEBUG:-0}                       # 1: normal putput the files in /tmp/ are kept for further debugging purposes
                                        # 2: list more what's going on , also lists some errors of connections
                                        # 3: slight hexdumps + other info,
                                        # 4: display bytes sent via sockets 
                                        # 5: display bytes received via sockets
                                        # 6: whole 9 yards
WIDE=${WIDE:-false}                     # whether to display for some options just ciphers or a table w hexcode/KX,Enc,strength etc.
LOGFILE=${LOGFILE:-""}                  # logfile if used
JSONFILE=${JSONFILE:-""}                # jsonfile if used
CSVFILE=${CSVFILE:-""}                  # csvfile if used
APPEND=${APPEND:-false}                 # append to csv/json file instead of overwriting it
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
HPKP_MIN=${HPKP_MIN:-30}                # >=30 days should be ok for HPKP_MIN, practical hints?
DAYS2WARN1=${DAYS2WARN1:-60}            # days to warn before cert expires, threshold 1
DAYS2WARN2=${DAYS2WARN2:-30}            # days to warn before cert expires, threshold 2
VULN_THRESHLD=${VULN_THRESHLD:-1}       # if vulnerabilities to check >$VULN_THRESHLD we DON'T show a separate header line in the output each vuln. check
readonly CLIENT_MIN_PFS=5               # number of ciphers needed to run a test for PFS
                                        # generated from 'kEECDH:kEDH:!aNULL:!eNULL:!DES:!3DES:!RC4' with openssl 1.0.2i and openssl 1.1.0
readonly ROBUST_PFS_CIPHERS="DHE-DSS-AES128-GCM-SHA256:DHE-DSS-AES128-SHA256:DHE-DSS-AES128-SHA:DHE-DSS-AES256-GCM-SHA384:DHE-DSS-AES256-SHA256:DHE-DSS-AES256-SHA:DHE-DSS-CAMELLIA128-SHA256:DHE-DSS-CAMELLIA128-SHA:DHE-DSS-CAMELLIA256-SHA256:DHE-DSS-CAMELLIA256-SHA:DHE-DSS-SEED-SHA:DHE-RSA-AES128-CCM8:DHE-RSA-AES128-CCM:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES128-SHA256:DHE-RSA-AES128-SHA:DHE-RSA-AES256-CCM8:DHE-RSA-AES256-CCM:DHE-RSA-AES256-GCM-SHA384:DHE-RSA-AES256-SHA256:DHE-RSA-AES256-SHA:DHE-RSA-CAMELLIA128-SHA256:DHE-RSA-CAMELLIA128-SHA:DHE-RSA-CAMELLIA256-SHA256:DHE-RSA-CAMELLIA256-SHA:DHE-RSA-CHACHA20-POLY1305-OLD:DHE-RSA-CHACHA20-POLY1305:DHE-RSA-SEED-SHA:ECDHE-ECDSA-AES128-CCM8:ECDHE-ECDSA-AES128-CCM:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES128-SHA256:ECDHE-ECDSA-AES128-SHA:ECDHE-ECDSA-AES256-CCM8:ECDHE-ECDSA-AES256-CCM:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES256-SHA384:ECDHE-ECDSA-AES256-SHA:ECDHE-ECDSA-CAMELLIA128-SHA256:ECDHE-ECDSA-CAMELLIA256-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305-OLD:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-SHA256:ECDHE-RSA-AES128-SHA:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-SHA384:ECDHE-RSA-AES256-SHA:ECDHE-RSA-CAMELLIA128-SHA256:ECDHE-RSA-CAMELLIA256-SHA384:ECDHE-RSA-CHACHA20-POLY1305-OLD:ECDHE-RSA-CHACHA20-POLY1305"

HAD_SLEPT=0
CAPATH="${CAPATH:-/etc/ssl/certs/}"     # Does nothing yet (FC has only a CA bundle per default, ==> openssl version -d)
FNAME=${FNAME:-""}                      # file name to read commands from
IKNOW_FNAME=false

# further global vars just declared here
readonly NPN_PROTOs="spdy/4a2,spdy/3,spdy/3.1,spdy/2,spdy/1,http/1.1"
# alpn_protos needs to be space-separated, not comma-seperated
readonly ALPN_PROTOs="h2 h2-17 h2-16 h2-15 h2-14 spdy/3.1 http/1.1"
TEMPDIR=""
TMPFILE=""
ERRFILE=""
CLIENT_AUTH=false
NO_SSL_SESSIONID=false
HOSTCERT=""
HEADERFILE=""
PROTOS_OFFERED=""
TLS_EXTENSIONS=""
GOST_STATUS_PROBLEM=false
DETECTED_TLS_VERSION=""
PATTERN2SHOW=""
SOCKREPLY=""
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
HAS_ALPN=false
HAS_SPDY=false
ADD_RFC_STR="rfc"                       # display RFC ciphernames
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
HEAD_REQ10=""
readonly UA_STD="TLS tester from $SWURL"
readonly UA_SNEAKY="Mozilla/5.0 (X11; Linux x86_64; rv:41.0) Gecko/20100101 Firefox/41.0"
FIRST_FINDING=true                      # Is this the first finding we are outputting to file?

# Devel stuff, see -q below
TLS_LOW_BYTE=""
HEX_CIPHER=""

                                             # The various hexdump commands we need to replace xxd (BSD compatibility)
HEXDUMPVIEW=(hexdump -C)                     # This is used in verbose mode to see what's going on
HEXDUMP=(hexdump -ve '16/1 "%02x " " \n"')   # This is used to analyze the reply
HEXDUMPPLAIN=(hexdump -ve '1/1 "%.2x"')      # Replaces both xxd -p and tr -cd '[:print:]'



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

readonly SSLv2_CLIENT_HELLO="
,80,34    # length (here: 52)
,01       # Client Hello
,00,02    # SSLv2
,00,1b    # cipher spec length (here: 27 )
,00,00    # session ID length
,00,10    # challenge length
,05,00,80 # 1st cipher   9 cipher specs, only classical V2 ciphers are used here, see  FIXME below
,03,00,80 # 2nd          there are v3 in v2!!! : https://tools.ietf.org/html/rfc6101#appendix-E
,01,00,80 # 3rd          Cipher specifications introduced in version 3.0 can be included in version 2.0 client hello messages using
,07,00,c0 # 4th          the syntax below. [..] # V2CipherSpec (see Version 3.0 name) = { 0x00, CipherSuite }; !!!!
,08,00,80 # 5th
,06,00,40 # 6th
,04,00,80 # 7th
,02,00,80 # 8th
,00,00,00 # 9th
,29,22,be,b3,5a,01,8b,04,fe,5f,80,03,a0,13,eb,c4" # Challenge
# https://idea.popcount.org/2012-06-16-dissecting-ssl-handshake/ (client)
# FIXME: http://max.euston.net/d/tip_sslciphers.html


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
pr_warningln() { pr_warning "$1"; outln; }                                                                                   # litemagenya
pr_magenta()   { [[ "$COLOR" -eq 2 ]] && out "\033[1;35m$1" || pr_underline "$1"; pr_off; }                                  # fatal error: quitting because of this!
pr_magentaln() { pr_magenta "$1"; outln; }

pr_litecyan()   { [[ "$COLOR" -eq 2 ]] && out "\033[0;36m$1" || out "$1"; pr_off; }                                          # not yet used
pr_litecyanln() { pr_litecyan "$1"; outln; }
pr_cyan()       { [[ "$COLOR" -eq 2 ]] && out "\033[1;36m$1" || out "$1"; pr_off; }                                          # additional hint
pr_cyanln()     { pr_cyan "$1"; outln; }

pr_litegreyln() { pr_litegrey "$1"; outln; }
pr_litegrey()   { [[ "$COLOR" -eq 2 ]] && out "\033[0;37m$1" || out "$1"; pr_off; }
pr_grey()       { [[ "$COLOR" -eq 2 ]] && out "\033[1;30m$1" || out "$1"; pr_off; }
pr_greyln()     { pr_grey "$1"; outln; }


pr_done_good()       { [[ "$COLOR" -eq 2 ]] && ( "$COLORBLIND" && out "\033[0;34m$1" || out "\033[0;32m$1" ) || out "$1"; pr_off; }   # litegreen (liteblue), This is good
pr_done_goodln()     { pr_done_good "$1"; outln; }
pr_done_best()       { [[ "$COLOR" -eq 2 ]] && ( "$COLORBLIND" && out "\033[1;34m$1" || out "\033[1;32m$1" ) ||  out "$1"; pr_off; }  # green (blue), This is the best 
pr_done_bestln()     { pr_done_best "$1"; outln; }

pr_svrty_minor()     { [[ "$COLOR" -eq 2 ]] && out "\033[1;33m$1" || out "$1"; pr_off; }                   # yellow brown | academic or minor problem 
pr_svrty_minorln()   { pr_svrty_minor "$1"; outln; }
pr_svrty_medium()    { [[ "$COLOR" -eq 2 ]] && out "\033[0;33m$1" || out "$1"; pr_off; }                   # brown | it is not a bad problem but you shouldn't do this
pr_svrty_mediumln()  { pr_svrty_medium "$1"; outln; }

pr_svrty_high()      { [[ "$COLOR" -eq 2 ]] && out "\033[0;31m$1" || pr_bold "$1"; pr_off; }               # litered
pr_svrty_highln()    { pr_svrty_high "$1"; outln; }
pr_svrty_critical()  { [[ "$COLOR" -eq 2 ]] && out "\033[1;31m$1" || pr_bold "$1"; pr_off; }               # red
pr_svrty_criticalln(){ pr_svrty_critical "$1"; outln; }


# color=1 functions
pr_off()          { [[ "$COLOR" -ne 0 ]] && out "\033[m"; }
pr_bold()         { [[ "$COLOR" -ne 0 ]] && out "\033[1m$1" || out "$1"; pr_off; }
pr_boldln()       { pr_bold "$1" ; outln; }
pr_italic()       { [[ "$COLOR" -ne 0 ]] && out "\033[3m$1" || out "$1"; pr_off; }
pr_underline()    { [[ "$COLOR" -ne 0 ]] && out "\033[4m$1" || out "$1"; pr_off; }
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
fixme() { pr_warningln "fixme: $1"; }

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
     sed -e "s,\x1B\[[0-9;]*[a-zA-Z],,g" \
          -e "s/\"/\\'/g" \
          -e 's/^ *//g' \
          -e 's/ *$//g' <<< "$1"    
}

fileout_header() {
     if "$APPEND"; then
          if [[ -f "$JSONFILE" ]]; then
               FIRST_FINDING=false # We need to insert a comma, because there is file content already
          else
               "$do_json" && printf "[\n" > "$JSONFILE"
          fi
          "$do_csv" && [[ ! -f "CSVFILE" ]] && echo "\"id\",\"fqdn/ip\",\"port\",\"severity\",\"finding\"" > "$CSVFILE"
     else
          "$do_json" && printf "[\n" > "$JSONFILE"
          "$do_csv" && echo "\"id\",\"fqdn/ip\",\"port\",\"severity\",\"finding\"" > "$CSVFILE"
     fi
}

fileout_footer() {
     "$do_json" && [[ -f "$JSONFILE" ]] && printf "]\n" >> "$JSONFILE"
}

fileout() { # ID, SEVERITY, FINDING
     local finding=$(strip_lf "$(newline_to_spaces "$(strip_quote "$3")")")

     if "$do_json"; then
          "$FIRST_FINDING" || echo -n "," >> $JSONFILE
          echo -e "         {
               \"id\"           : \"$1\",
               \"ip\"           : \"$NODE/$NODEIP\",
               \"port\"         : \"$PORT\",
               \"severity\"     : \"$2\",
               \"finding\"      : \"$finding\"
          }" >> $JSONFILE
     fi
     # does the following do any sanitization? 
     if "$do_csv"; then
          echo -e \""$1\"",\"$NODE/$NODEIP\",\"$PORT"\",\""$2"\",\""$finding"\"" >>$CSVFILE
     fi
     "$FIRST_FINDING" && FIRST_FINDING=false
}

###### helper function definitions ######

debugme() {
     [[ "$DEBUG" -ge 2 ]] && "$@"
}

hex2dec() {
     #/usr/bin/printf -- "%d" 0x"$1"
     echo $((16#$1))
}

# trim spaces for BSD and old sed
count_lines() {
     wc -l <<<"$1" | sed 's/ //g'
}
count_words() {
     wc -w <<<"$1" | sed 's/ //g'
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
     echo "$1" | tr -d '\n' | tr -d '\r'
}

strip_spaces() {
     echo "${1// /}"
}

toupper() {
     echo -n "$1" | tr 'a-z' 'A-Z'
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



# prints out multiple lines in $1, left aligned by spaces in $2
out_row_aligned() {
     local first=true

     echo "$1" | while read line; do
          if $first; then
               first=false
          else
               out "$2"
          fi
          outln "$line"
     done
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

###### check code starts here ######

# determines whether the port has an HTTP service running or not (plain TLS, no STARTTLS)
# arg1 could be the protocol determined as "working". IIS6 needs that
runs_HTTP() {
     local -i ret=0
     local -i was_killed

     if ! $CLIENT_AUTH; then
          # SNI is nonsense for !HTTPS but fortunately for other protocols s_client doesn't seem to care
          printf "$GET_REQ11" | $OPENSSL s_client $1 -quiet $BUGS -connect $NODEIP:$PORT $PROXY $SNI >$TMPFILE 2>$ERRFILE &
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
                    if $ASSUMING_HTTP; then
                         SERVICE=HTTP
                         out " -- ASSUMING_HTTP set though"
                         fileout "service" "DEBUG" "Couldn't determine service, --ASSUMING_HTTP set"
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
     local header
     local -i ret
     local referer useragent
     local url redirect

     HEADERFILE=$TEMPDIR/$NODEIP.http_header.txt
     outln; pr_headlineln " Testing HTTP header response @ \"$URL_PATH\" "
     outln

     [[ -z "$1" ]] && url="/" || url="$1"
     printf "$GET_REQ11" | $OPENSSL s_client $OPTIMAL_PROTO $BUGS -quiet -ign_eof -connect $NODEIP:$PORT $PROXY $SNI >$HEADERFILE 2>$ERRFILE &
     wait_kill $! $HEADER_MAXSLEEP
     if [[ $? -eq 0 ]]; then
          # we do the get command again as it terminated within $HEADER_MAXSLEEP. Thus it didn't hang, we do it
          # again in the foreground ito get an ccurate header time!
          printf "$GET_REQ11" | $OPENSSL s_client $OPTIMAL_PROTO $BUGS -quiet -ign_eof -connect $NODEIP:$PORT $PROXY $SNI >$HEADERFILE 2>$ERRFILE
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

     status_code=$(awk '/^HTTP\// { print $2 }' $HEADERFILE 2>>$ERRFILE)
     msg_thereafter=$(awk -F"$status_code" '/^HTTP\// { print $2 }' $HEADERFILE 2>>$ERRFILE)   # dirty trick to use the status code as a
     msg_thereafter=$(strip_lf "$msg_thereafter")                                    # field separator, otherwise we need a loop with awk
     debugme echo "Status/MSG: $status_code $msg_thereafter"

     pr_bold " HTTP Status Code           "
     [[ -z "$status_code" ]] && pr_cyan "No status code" && return 3

     out "  $status_code$msg_thereafter"
     case $status_code in
          301|302|307|308)
               redirect=$(grep -a '^Location' $HEADERFILE | sed 's/Location: //' | tr -d '\r\n')
               out ", redirecting to \"$redirect\""
               if [[ $redirect == "http://"* ]]; then
                    pr_svrty_high " -- Redirect to insecure URL (NOT ok)"
                    fileout "status_code" "NOT ok" \, "Redirect to insecure URL (NOT ok). Url: \"$redirect\""
               fi
               fileout "status_code" "INFO" \
                    "Testing HTTP header response @ \"$URL_PATH\", $status_code$msg_thereafter, redirecting to \"$redirect\""
               ;;
          200)
               fileout "status_code" "INFO" \
                    "Testing HTTP header response @ \"$URL_PATH\", $status_code$msg_thereafter"
               ;;
          204)
               fileout "status_code" "INFO" \
                    "Testing HTTP header response @ \"$URL_PATH\", $status_code$msg_thereafter"
               ;;
          206)
               out " -- WTF?"
               fileout "status_code" "INFO" \
                    "Testing HTTP header response @ \"$URL_PATH\", $status_code$msg_thereafter -- WTF?"
               ;;
          400)
               pr_cyan " (Hint: better try another URL)"
               fileout "status_code" "INFO" \
                    "Testing HTTP header response @ \"$URL_PATH\", $status_code$msg_thereafter (Hint: better try another URL)"
               ;;
          401)
               grep -aq "^WWW-Authenticate" $HEADERFILE && out "  "; strip_lf "$(grep -a "^WWW-Authenticate" $HEADERFILE)"
               fileout "status_code" "INFO" \
                    "Testing HTTP header response @ \"$URL_PATH\", $status_code$msg_thereafter $(grep -a "^WWW-Authenticate" $HEADERFILE)"
               ;;
          403)
               fileout "status_code" "INFO" \
                    "Testing HTTP header response @ \"$URL_PATH\", $status_code$msg_thereafter"
               ;;
          404)
               out " (Hint: supply a path which doesn't give a \"$status_code$msg_thereafter\")"
               fileout "status_code" "INFO" \
                    "Testing HTTP header response @ \"$URL_PATH\", $status_code$msg_thereafter (Hint: supply a path which doesn't give a \"$status_code$msg_thereafter\")"
               ;;
          405)
               fileout "status_code" "INFO" \
                    "Testing HTTP header response @ \"$URL_PATH\", $status_code$msg_thereafter"
               ;;
          *)
               pr_warning ". Oh, didn't expect \"$status_code$msg_thereafter\""
               fileout "status_code" "DEBUG" \
                    "Testing HTTP header response @ \"$URL_PATH\", $status_code$msg_thereafter. Oh, didn't expect a $status_code$msg_thereafter"
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
                    fileout "ip_in_header_$count" "NOT ok" "IPv4 address in header  $result $your_ip_msg"
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

     if [[ ! -s $HEADERFILE ]]; then
          run_http_header "$1" || return 3
     fi
     #pr_bold " HSTS                         "
     pr_bold " Strict Transport Security    "
     grep -iaw '^Strict-Transport-Security' $HEADERFILE >$TMPFILE
     if [[ $? -eq 0 ]]; then
          grep -aciw '^Strict-Transport-Security' $HEADERFILE | egrep -waq "1" || out "(two HSTS header, using 1st one) "
          hsts_age_sec=$(sed -e 's/[^0-9]*//g' $TMPFILE | head -1)
          if [[ -n $hsts_age_sec ]]; then
               hsts_age_days=$(( hsts_age_sec / 86400))
          else
               hsts_age_days=-1
          fi
          if [[ $hsts_age_days -eq -1 ]]; then
               pr_svrty_medium "HSTS max-age is required but missing. Setting 15552000 s (180 days) or more is recommended"
               fileout "hsts_time" "MEDIUM" "HSTS max-age missing. 15552000 s (180 days) or more recommnded"
          elif [[ $hsts_age_days -eq 0 ]]; then
               pr_svrty_medium "HSTS max-age is set to 0. HSTS is disabled"
               fileout "hsts_time" "MEDIUM" "HSTS max-age set to 0. HSTS is disabled"
          elif [[ $hsts_age_days -gt $HSTS_MIN ]]; then
               pr_done_good "$hsts_age_days days" ; out "=$hsts_age_sec s"
               fileout "hsts_time" "OK" "HSTS timeout $hsts_age_days days (=$hsts_age_sec seconds) > $HSTS_MIN days"
          else
               out "$hsts_age_sec s = "
               pr_svrty_medium "$hsts_age_days days, <$HSTS_MIN days is too short"
               fileout "hsts_time" "MEDIUM" "HSTS timeout too short. $hsts_age_days days (=$hsts_age_sec seconds) < $HSTS_MIN days"
          fi
          if includeSubDomains "$TMPFILE"; then
               fileout "hsts_subdomains" "OK" "HSTS includes subdomains"
          else
               fileout "hsts_subdomains" "WARN" "HSTS only for this domain, consider to include subdomains as well"
          fi
          if preload "$TMPFILE"; then
               fileout "hsts_preload" "OK" "HSTS domain is marked for preloading"
          else
               fileout "hsts_preload" "INFO" "HSTS domain is NOT marked for preloading"
          fi
          #FIXME: To be checked against e.g. https://dxr.mozilla.org/mozilla-central/source/security/manager/boot/src/nsSTSPreloadList.inc
          #                              and https://chromium.googlesource.com/chromium/src/+/master/net/http/transport_security_state_static.json
     else
          out "--"
          fileout "hsts" "NOT ok" "No support for HTTP Strict Transport Security"
     fi
     outln

     tmpfile_handle $FUNCNAME.txt
     return $?
}


run_hpkp() {
     local -i hpkp_age_sec
     local -i hpkp_age_days
     local -i hpkp_nr_keys
     local hpkp_key hpkp_key_hostcert
     local spaces="                             "
     local key_found=false
     local i
     local hpkp_headers
     local first_hpkp_header

     if [[ ! -s $HEADERFILE ]]; then
          run_http_header "$1" || return 3
     fi
     #pr_bold " HPKP                         "
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
               fileout "hpkp_multiple" "WARN" "Multiple HPKP headershpkp_headers. Using first header: $first_hpkp_header"
          fi

          # remove leading Public-Key-Pins*, any colons, double quotes and trailing spaces and taking the first -- whatever that is
          sed -e 's/Public-Key-Pins://g' -e s'/Public-Key-Pins-Report-Only://' $TMPFILE | \
               sed -e 's/;//g' -e 's/\"//g' -e 's/^ //' | head -1 > $TMPFILE.2
          # BSD lacks -i, otherwise we would have done it inline
          # now separate key value and other stuff per line:
          tr ' ' '\n' < $TMPFILE.2 >$TMPFILE

          hpkp_nr_keys=$(grep -ac pin-sha $TMPFILE)
          out "# of keys: "
          if [[ $hpkp_nr_keys -eq 1 ]]; then
               pr_svrty_high "1 (NOT ok), "
               fileout "hpkp_keys" "NOT ok" "Only one key pinned in HPKP header, this means the site may become unavailable if the key is revoked"
          else
               out "$hpkp_nr_keys, "
               fileout "hpkp_keys" "OK" "$hpkp_nr_keys keys pinned in HPKP header, additional keys are available if the current key is revoked"
          fi

          # print key=value pair with awk, then strip non-numbers, to be improved with proper parsing of key-value with awk
          hpkp_age_sec=$(awk -F= '/max-age/{max_age=$2; print max_age}' $TMPFILE | sed -E 's/[^[:digit:]]//g')
          hpkp_age_days=$((hpkp_age_sec / 86400))
          if [[ $hpkp_age_days -ge $HPKP_MIN ]]; then
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

          if [[ ! -s "$HOSTCERT" ]]; then
               get_host_cert || return 1
          fi
          # get the key fingerprint from the host certificate
          hpkp_key_hostcert="$($OPENSSL x509 -in $HOSTCERT -pubkey -noout | grep -v PUBLIC | \
               $OPENSSL base64 -d | $OPENSSL dgst -sha256 -binary | $OPENSSL base64)"
          # compare it with the ones provided in the header
          while read hpkp_key; do
               if [[ "$hpkp_key_hostcert" == "$hpkp_key" ]] || [[ "$hpkp_key_hostcert" == "$hpkp_key=" ]]; then
                    out "\n$spaces matching host key: "
                    pr_done_good "$hpkp_key"
                    fileout "hpkp_keymatch" "OK" "Key matches a key pinned in the HPKP header"
                    key_found=true
               fi
               debugme out "\n  $hpkp_key | $hpkp_key_hostcert"
          done < <(tr ';' '\n' < $TMPFILE | tr -d ' ' | tr -d '\"' | awk -F'=' '/pin.*=/ { print $2 }')
          if ! $key_found ; then
               out "\n$spaces"
               pr_svrty_high " No matching key for pins found "
               out "(CAs pinned? -- not checked for yet)"
               fileout "hpkp_keymatch" "DEBUG" "The TLS key does not match any key pinned in the HPKP header. If you pinned a CA key you can ignore this"
          fi
     else
          out "--"
          fileout "hpkp" "INFO" "No support for HTTP Public Key Pinning"
     fi
     outln

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
               rp_banners="$rp_bannersline"
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
          cat $TMPFILE | while read line; do
               line=$(strip_lf "$line")
               if ! $first; then
                    out "$spaces"
               else
                    first=false
               fi
               emphasize_stuff_in_headers "$line"
               app_banners="$app_bannersline"
          done
          fileout "app_banner" "WARN" "Application Banners found: $app_banners"
     fi
     tmpfile_handle $FUNCNAME.txt
     return 0
}

run_cookie_flags() {     # ARG1: Path, ARG2: path
     local -i nr_cookies
     local nr_httponly nr_secure
     local negative_word

     if [[ ! -s $HEADERFILE ]]; then
          run_http_header "$1" || return 3
     fi
     pr_bold " Cookie(s)                    "
     grep -ai '^Set-Cookie' $HEADERFILE >$TMPFILE
     if [[ $? -eq 0 ]]; then
          nr_cookies=$(count_lines "$TMPFILE")
          out "$nr_cookies issued: "
          fileout "cookie_count" "INFO" "$nr_cookies cookie(s) issued at \"$1\""
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
               fileout "cookie_httponly" "OK" "All $nr_cookies cookie(s) issued at \"$1\" marked as HttpOnly"
          else
               fileout "cookie_httponly" "WARN" "$nr_secure/$nr_cookies cookie(s) issued at \"$1\" marked as HttpOnly"
          fi
     else
          out "(none issued at \"$1\")"
          fileout "cookie_count" "INFO" "No cookies issued at \"$1\""
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
     # convert spaces to | (for egrep)
     egrep_pattern=$(echo "$good_flags2test $other_flags2test"| sed -e 's/ /|\^/g' -e 's/^/\^/g')
     egrep -ai "$egrep_pattern" $HEADERFILE >$TMPFILE
     if [[ $? -ne 0 ]]; then
          outln "--"
          fileout "sec_headers" "WARN" "No security (or other interesting) headers detected"
          ret=1
     else
          ret=0
          for f2t in $good_flags2test; do
               debugme echo "---> $f2t"
               result_str=$(grep -wi "^$f2t" $TMPFILE | grep -vi "$f2t"-)
               result_str=$(strip_lf "$result_str")
               [[ -z "$result_str" ]] && continue
               if ! "$first"; then
                    out "$spaces"  # output leading spaces if the first header
               else
                    first=false
               fi
               # extract and print key(=flag) in green:
               pr_done_good "${result_str%%:*}:"
               #pr_done_good "$(sed 's/:.*$/:/' <<< "$result_str")"
               # print value in plain text:
               outln "${result_str#*:}"
               fileout "${result_str%%:*}" "OK" "${result_str%%:*}: ${result_str#*:}"
          done
          # now the same with other flags
          for f2t in $other_flags2test; do
               result_str=$(grep -i "^$f2t" $TMPFILE)
               [[ -z "$result_str" ]] && continue
               if ! $first; then
                    out "$spaces"  # output leading spaces if the first header
               else
                    first=false
               fi
               # extract and print key(=flag) underlined
               pr_litecyan "${result_str%%:*}:"
               # print value in plain text:
               outln "${result_str#*:}"
               fileout "${result_str%%:*}" "WARN" "${result_str%%:*}: ${result_str#*:}"
          done
     fi
#TODO: I am not testing for the correctness or anything stupid yet, e.g. "X-Frame-Options: allowall"

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
     HEXC=$(echo $HEXC | tr 'A-Z' 'a-z' | sed 's/0x/x/') #tolower + strip leading 0
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
listciphers() {
     local -i ret
     local debugname="$(sed -e s'/\!/not/g' -e 's/\:/_/g' <<< "$1")"

     $OPENSSL ciphers "$1" &>$TMPFILE
     ret=$?
     debugme cat $TMPFILE

     tmpfile_handle $FUNCNAME.$debugname.txt
     return $ret
}


# argv[1]: cipher list to test
# argv[2]: string on console
# argv[3]: ok to offer? 0: yes, 1: no
std_cipherlists() {
     local -i sclient_success
     local singlespaces
     local debugname="$(sed -e s'/\!/not/g' -e 's/\:/_/g' <<< "$1")"

     pr_bold "$2    "         # indent in order to be in the same row as server preferences
     if listciphers "$1"; then  # is that locally available??
          $OPENSSL s_client -cipher "$1" $BUGS $STARTTLS -connect $NODEIP:$PORT $PROXY $SNI 2>$ERRFILE >$TMPFILE </dev/null
          sclient_connect_successful $? $TMPFILE
          sclient_success=$?
          debugme cat $ERRFILE
          case $3 in
               0)   # ok to offer
                    if [[ $sclient_success -eq 0 ]]; then
                         pr_done_bestln "offered (OK)"
                         fileout "std_$4" "OK" "$2 offered (OK)"
                    else
                         pr_svrty_mediumln "not offered"
                         fileout "std_$4" "MEDIUM" "$2 not offered (WARN)"
                    fi
                    ;;
               1) # the ugly ones
                    if [[ $sclient_success -eq 0 ]]; then
                         pr_svrty_criticalln "offered (NOT ok)"
                         fileout "std_$4" "NOT ok" "$2 offered (NOT ok) - ugly"
                    else
                         pr_done_bestln "not offered (OK)"
                         fileout "std_$4" "OK" "$2 not offered (OK)"
                    fi
                    ;;
               2)   # bad but not worst
                    if [[ $sclient_success -eq 0 ]]; then
                         pr_svrty_highln "offered (NOT ok)"
                         fileout "std_$4" "NOT ok" "$2 offered (NOT ok) - bad"
                    else
                         pr_done_goodln "not offered (OK)"
                         fileout "std_$4" "OK" "$2 not offered (OK)"
                    fi
                    ;;
               3) # not totally bad
                    if [[ $sclient_success -eq 0 ]]; then
                         pr_svrty_mediumln "offered"
                         fileout "std_$4" "MEDIUM" "$2 offered - not too bad"
                    else
                         outln "not offered (OK)"
                         fileout "std_$4" "OK" "$2 not offered (OK)"
                    fi
                    ;;
               *) # we shouldn't reach this
                    pr_warning "?: $3 (please report this)" 
                    fileout "std_$4" "WARN" "return condition $3 unclear"
                    ;;
          esac
          tmpfile_handle $FUNCNAME.$debugname.txt
     else
          singlespaces=$(echo "$2" | sed -e 's/ \+/ /g' -e 's/^ //' -e 's/ $//g' -e 's/  //g')
          local_problem_ln "No $singlespaces configured in $OPENSSL"
          fileout "std_$4" "WARN" "Cipher $2 ($1) not supported by local OpenSSL ($OPENSSL)"
     fi
     # we need 1xlf in those cases:
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


#FIXME: This is only for HB and CCS, others use still sockread_serverhello()
sockread() {
     local -i ret=0
     local ddreply

     [[ "x$2" == "x" ]] && maxsleep=$MAX_WAITSOCK || maxsleep=$2

     ddreply=$(mktemp $TEMPDIR/ddreply.XXXXXX) || return 7
     dd bs=$1 of=$ddreply count=1 <&5 2>/dev/null &
     wait_kill $! $maxsleep
     ret=$?
     SOCKREPLY=$(cat $ddreply 2>/dev/null)
     rm $ddreply
     return $ret
}

#FIXME: fill the following two:
openssl2rfc() {
     :
}

rfc2openssl() {
     local hexcode ossl_hexcode ossl_name
     local -i len

     hexcode=$(grep -iw "$1" "$MAPPING_FILE_RFC" 2>>$ERRFILE | head -1 | awk '{ print $1 }')
     [[ -z "$hexcode" ]] && return 0
     len=${#hexcode}
     case $len in
          3) ossl_hexcode="0x00,0x${hexcode:1:2}" ;;
          5) ossl_hexcode="0x${hexcode:1:2},0x${hexcode:3:2}" ;;
          7) ossl_hexcode="0x${hexcode:1:2},0x${hexcode:3:2},0x${hexcode:5:2}" ;;
          *) return 0 ;;
     esac
    ossl_name="$($OPENSSL ciphers -V 'ALL:COMPLEMENTOFALL' | grep -i " $ossl_hexcode " | awk '{ print $3 }')"
     [[ -z "$ossl_name" ]] && ossl_name="-"
     out "$ossl_name"
     return 0
}


show_rfc_style(){
     [[ -z "$ADD_RFC_STR" ]] && return 1
     #[[ -z "$1" ]] && return 0

     local rfcname
     rfcname="$(grep -iw "$1" "$MAPPING_FILE_RFC" | awk '{ print $2 }')"
     [[ -n "$rfcname" ]] && out "$rfcname"
     return 0
}

neat_header(){
     printf -- "Hexcode  Cipher Suite Name (OpenSSL)       KeyExch.  Encryption Bits${ADD_RFC_STR:+     Cipher Suite Name (RFC)}\n"
     printf -- "%s------------------------------------------------------------------------${ADD_RFC_STR:+---------------------------------------------------}\n"
}


# arg1: hexcode
# arg2: cipher in openssl notation
# arg3: keyexchange
# arg4: encryption (maybe included "export")
neat_list(){
     local hexcode="$1"
     local ossl_cipher="$2"
     local kx enc strength

     kx="${3//Kx=/}"
     enc="${4//Enc=/}"
     strength="${enc//\)/}"             # retrieve (). first remove traling ")"
     strength="${strength#*\(}"         # exfiltrate (VAL
     enc="${enc%%\(*}"

     enc="${enc//POLY1305/}"            # remove POLY1305
     enc="${enc//\//}"                  # remove "/"

     echo "$export" | grep -iq export && strength="$strength,exp"

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
     printf -- " %-7s %-33s %-10s %-10s%-8s${ADD_RFC_STR:+ %-49s}${SHOW_EACH_C:+  %-0s}" "$hexcode" "$ossl_cipher" "$kx" "$enc" "$strength" "$(show_rfc_style "$hexcode")"
}

test_just_one(){
     local hexcode n ciph sslvers kx auth enc mac export
     local dhlen
     local sclient_success
     local re='^[0-9A-Fa-f]+$'

     pr_headline " Testing single cipher with "
     if [[ $1 =~ $re ]]; then
          pr_headline "matching number pattern \"$1\" "
          tjolines="$tjolines matching number pattern \"$1\"\n\n"
     else
          pr_headline "word pattern "\"$1\"" (ignore case) "
          tjolines="$tjolines word pattern \"$1\" (ignore case)\n\n"
     fi
     outln
     ! "$HAS_DH_BITS" && pr_warningln "    (Your $OPENSSL cannot show DH/ECDH bits)"
     outln
     neat_header
     #for arg in $(echo $@ | sed 's/,/ /g'); do
     for arg in ${*//, /}; do
          # 1st check whether openssl has cipher or not
          $OPENSSL ciphers -V 'ALL:COMPLEMENTOFALL:@STRENGTH' 2>$ERRFILE | while read hexcode dash ciph sslvers kx auth enc mac export ; do
          # FIXME: e.g. OpenSSL < 1.0 doesn't understand "-V" --> we can't do anything about it!
               normalize_ciphercode $hexcode
               # is argument a number?
               if [[ $arg =~ $re ]]; then
                    neat_list $HEXC $ciph $kx $enc | grep -qai "$arg"
               else
                    neat_list $HEXC $ciph $kx $enc | grep -qwai "$arg"
               fi
               if [[ $? -eq 0 ]]; then    # string matches, so we can ssl to it:
                    $OPENSSL s_client -cipher $ciph $STARTTLS $BUGS -connect $NODEIP:$PORT $PROXY $SNI 2>$ERRFILE >$TMPFILE </dev/null
                    sclient_connect_successful $? $TMPFILE
                    sclient_success=$?
                    if [[ $kx == "Kx=ECDH" ]] || [[ $kx == "Kx=DH" ]] || [[ $kx == "Kx=EDH" ]]; then
                         if [[ $sclient_success -eq 0 ]]; then
                              dhlen=$(read_dhbits_from_file $TMPFILE quiet)
                              kx="$kx $dhlen"
                         else
                              kx="$kx$grey TBD $off "
                         fi
                    fi
                    neat_list $HEXC $ciph "$kx" $enc
                    if [[ $sclient_success -eq 0 ]]; then
                         pr_cyan "  available"
                         fileout "cipher_$HEXC" "INFO" "$(neat_header)(neat_list $HEXC $ciph "$kx" $enc) available"
                    else
                         out "  not a/v"
                         fileout "cipher_$HEXC" "INFO" "$(neat_header)(neat_list $HEXC $ciph "$kx" $enc) not a/v"
                    fi
                    outln
               fi
          done
          exit
     done
     outln

     tmpfile_handle $FUNCNAME.txt
     return 0       # this is a single test for a cipher
}


# test for all ciphers locally configured (w/o distinguishing whether they are good or bad)
run_allciphers() {
     local tmpfile
     local -i nr_ciphers=0
     local n sslvers auth mac export
     local -a hexcode ciph kx enc export2
     local -i i j parent child end_of_bundle round_num bundle_size num_bundles mod_check
     local -a ciphers_found
     local dhlen
     local available
     local ciphers_to_test

     # get a list of all the cipher suites to test (only need the hexcode, ciph, kx, enc, and export values)
     while read hexcode[nr_ciphers] n ciph[nr_ciphers] sslvers kx[nr_ciphers] auth enc[nr_ciphers] mac export2[nr_ciphers]; do
          nr_ciphers=$nr_ciphers+1
     done < <($OPENSSL ciphers -V 'ALL:COMPLEMENTOFALL:@STRENGTH' 2>>$ERRFILE)

     outln
     pr_headlineln " Testing all $OPENSSL_NR_CIPHERS locally available ciphers against the server, ordered by encryption strength "
     "$HAS_DH_BITS" || pr_warningln "    (Your $OPENSSL cannot show DH/ECDH bits)"
     outln
     neat_header

     # Split ciphers into bundles of size 4**n, starting with an "n" that
     # splits the ciphers into 4 bundles, and then reducing "n" by one in each
     # round. Only test a bundle of 4**n ciphers against the server if it was
     # part of a bundle of 4**(n+1) ciphers that included a cipher supported by
     # the server. Continue until n=0.

     # Determine bundle size that will result in their being exactly four bundles.
     for (( bundle_size=1; bundle_size < nr_ciphers; bundle_size*=4 )); do
          :
     done

     # set ciphers_found[1] so that all bundles will be tested in round 0.
     ciphers_found[1]=true
     # Some servers can't handle a handshake with >= 128 ciphers.
     for (( round_num=0; bundle_size/4 >= 128; bundle_size/=4 )); do
          round_num=$round_num+1
          for (( i=4**$round_num; i<2*4**$round_num; i++ )); do
               ciphers_found[i]=true
          done
     done

     for (( bundle_size/=4; bundle_size>=1; bundle_size/=4 )); do
         # Note that since the number of ciphers isn't a power of 4, the number
         # of bundles may be may be less than 4**(round_num+1), and the final
         # bundle may have fewer than bundle_size ciphers.
         num_bundles=$nr_ciphers/$bundle_size
         mod_check=$nr_ciphers%$bundle_size
         [[ $mod_check -ne 0 ]] && num_bundles=$num_bundles+1
         for ((i=0;i<num_bundles;i++)); do
             # parent=index of bundle from previous round that includes this bundle of ciphers
             parent=4**$round_num+$i/4
             # child=index for this bundle of ciphers
             child=4*4**$round_num+$i
             if ${ciphers_found[parent]}; then
                 ciphers_to_test=""
                 end_of_bundle=$i*$bundle_size+$bundle_size
                 [[ $end_of_bundle -gt $nr_ciphers ]] && end_of_bundle=$nr_ciphers
                 for ((j=i*bundle_size;j<end_of_bundle;j++)); do
                     ciphers_to_test="${ciphers_to_test}:${ciph[j]}"
                 done
                 ciphers_found[child]=false
                 $OPENSSL s_client -cipher "${ciphers_to_test:1}" $STARTTLS $BUGS -connect $NODEIP:$PORT $PROXY $SNI >$TMPFILE 2>$ERRFILE </dev/null
                 sclient_connect_successful "$?" "$TMPFILE"
                 [[ "$?" -eq 0 ]] && ciphers_found[child]=true
             else
                 # No need to test, since test of parent demonstrated none of these ciphers work.
                 ciphers_found[child]=false
             fi

             # If this is a "leaf" of the test tree, then print out the results.
             if [[ $bundle_size -eq 1 ]] && ( ${ciphers_found[child]} || "$SHOW_EACH_C"); then
                 export=${export2[i]}
                 normalize_ciphercode "${hexcode[i]}"
                 if [[ ${kx[i]} == "Kx=ECDH" ]] || [[ ${kx[i]} == "Kx=DH" ]] || [[ ${kx[i]} == "Kx=EDH" ]]; then
                     if ${ciphers_found[child]}; then
                         dhlen=$(read_dhbits_from_file "$TMPFILE" quiet)
                         kx[i]="${kx[i]} $dhlen"
                     fi
                 fi
                 neat_list "$HEXC" "${ciph[i]}" "${kx[i]}" "${enc[i]}"
                 available=""
                 if "$SHOW_EACH_C"; then
                     if ${ciphers_found[child]}; then
                         available="available"
                         pr_cyan "$available"
                     else
                         available="not a/v"
                         out "$available"
                     fi
                 fi
                 if "$SHOW_SIGALGO" && ${ciphers_found[child]}; then
                     $OPENSSL x509 -noout -text -in $TMPFILE | awk -F':' '/Signature Algorithm/ { print $2 }' | head -1
                 else
                     outln
                 fi
                 fileout "cipher_$HEXC" "INFO" "$(neat_list "$HEXC" "${ciph[i]}" "${kx[i]}" "${enc[i]}") $available"
             fi
         done
         round_num=round_num+1
     done

     outln
     tmpfile_handle $FUNCNAME.txt
     return 0
}

# test for all ciphers per protocol locally configured (w/o distinguishing whether they are good or bad)
run_cipher_per_proto() {
     local proto proto_text
     local -i nr_ciphers
     local n sslvers auth mac export
     local -a hexcode ciph kx enc export2
     local -i i j parent child end_of_bundle round_num bundle_size num_bundles mod_check
     local -a ciphers_found
     local dhlen
     local available
     local id

     pr_headlineln " Testing all locally available ciphers per protocol against the server, ordered by encryption strength "
     ! "$HAS_DH_BITS" && pr_warningln "    (Your $OPENSSL cannot show DH/ECDH bits)"
     outln
     neat_header
     outln " -ssl2 SSLv2\n -ssl3 SSLv3\n -tls1 TLS 1\n -tls1_1 TLS 1.1\n -tls1_2 TLS 1.2"| while read proto proto_text; do
          locally_supported "$proto" "$proto_text" || continue
          outln
          has_server_protocol "${proto:1}" || continue
          
          # get a list of all the cipher suites to test (only need the hexcode, ciph, kx, enc, and export values)
          nr_ciphers=0
          while read hexcode[nr_ciphers] n ciph[nr_ciphers] sslvers kx[nr_ciphers] auth enc[nr_ciphers] mac export2[nr_ciphers]; do
               nr_ciphers=$nr_ciphers+1
          done < <($OPENSSL ciphers $proto -V 'ALL:COMPLEMENTOFALL:@STRENGTH' 2>$ERRFILE)

          # Split ciphers into bundles of size 4**n, starting with the smallest
          # "n" that leaves the ciphers in one bundle, and then reducing "n" by
          # one in each round. Only test a bundle of 4**n ciphers against the
          # server if it was part of a bundle of 4**(n+1) ciphers that included
          # a cipher supported by the server. Continue until n=0.

          # Determine the smallest bundle size that will result in their being one bundle.
          for(( bundle_size=1; bundle_size < nr_ciphers; bundle_size*=4 )); do
               :
          done

          # set ciphers_found[1] so that the complete bundle will be tested in round 0.
          ciphers_found[1]=true
          # Some servers can't handle a handshake with >= 128 ciphers.
          for (( round_num=0; bundle_size>=128; bundle_size/=4 )); do
               round_num=$round_num+1
               for (( i=4**$round_num; i<2*4**$round_num; i++ )); do
                    ciphers_found[i]=true
               done
          done
          for (( 1; bundle_size>=1; bundle_size/=4 )); do
              # Note that since the number of ciphers isn't a power of 4, the number
              # of bundles may be may be less than 4**(round_num+1), and the final
              # bundle may have fewer than bundle_size ciphers.
              num_bundles=$nr_ciphers/$bundle_size
              mod_check=$nr_ciphers%$bundle_size
              [[ $mod_check -ne 0 ]] && num_bundles=$num_bundles+1
              for (( i=0; i<num_bundles; i++ )); do
                  # parent=index of bundle from previous round that includes this bundle of ciphers
                  parent=4**$round_num+$i/4
                  # child=index for this bundle of ciphers
                  child=4*4**$round_num+$i
                  if ${ciphers_found[parent]}; then
                      ciphers_to_test=""
                      end_of_bundle=$i*$bundle_size+$bundle_size
                      [[ $end_of_bundle -gt $nr_ciphers ]] && end_of_bundle=$nr_ciphers
                      for (( j=i*bundle_size; j<end_of_bundle; j++ )); do
                          ciphers_to_test="${ciphers_to_test}:${ciph[j]}"
                      done
                      ciphers_found[child]=false
                      $OPENSSL s_client -cipher "${ciphers_to_test:1}" $proto $STARTTLS $BUGS -connect $NODEIP:$PORT $PROXY $SNI >$TMPFILE 2>$ERRFILE  </dev/null
                      sclient_connect_successful "$?" "$TMPFILE"
                      [[ "$?" -eq 0 ]] && ciphers_found[child]=true
                  else
                      # No need to test, since test of parent demonstrated none of these ciphers work.
                      ciphers_found[child]=false
                  fi

                  # If this is a "leaf" of the test tree, then print out the results.
                  if [[ $bundle_size -eq 1 ]] && ( ${ciphers_found[child]} || "$SHOW_EACH_C"); then
                      export=${export2[i]}
                      normalize_ciphercode "${hexcode[i]}"
                      if [[ ${kx[i]} == "Kx=ECDH" ]] || [[ ${kx[i]} == "Kx=DH" ]] || [[ ${kx[i]} == "Kx=EDH" ]]; then
                          if ${ciphers_found[child]}; then
                              dhlen=$(read_dhbits_from_file "$TMPFILE" quiet)
                              kx[i]="${kx[i]} $dhlen"
                          fi
                      fi
                      neat_list "$HEXC" "${ciph[i]}" "${kx[i]}" "${enc[i]}"
                      if "$SHOW_EACH_C"; then
                          if ${ciphers_found[child]}; then
                              available="available"
                              pr_cyan "$available"
                          else
                              available="not a/v"
                              out "$available"
                          fi
                      fi
                      if "$SHOW_SIGALGO" && ${ciphers_found[child]}; then
                          $OPENSSL x509 -noout -text -in $TMPFILE | awk -F':' '/Signature Algorithm/ { print $2 }' | head -1
                      else
                          outln
                      fi
                      id="cipher$proto"
                      id+="_$HEXC"
                      fileout "$id" "INFO" "$proto_text  $(neat_list "$HEXC" "${ciph[i]}" "${kx[i]}" "${enc[i]}") $available"
                  fi
               done
               round_num=round_num+1
          done
     done
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
     debugme outln "reading server hello..."
     if [[ "$DEBUG" -ge 4 ]]; then
          hexdump -C $SOCK_REPLY_FILE | head -6
          echo
     fi

     parse_tls_serverhello "$SOCK_REPLY_FILE"
     save=$?

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
     local name tls proto cipher
     local using_sockets=true

     if $SSL_NATIVE || [[ -n "$STARTTLS" ]]; then
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

     outln
     if "$using_sockets"; then
          pr_headlineln " Running browser simulations via sockets (experimental) "
     else
          pr_headlineln " Running browser simulations (experimental) "
     fi
     outln

     debugme outln
     for name in "${short[@]}"; do
          #FIXME: printf formatting would look better, especially if we want a wide option here
          out " ${names[i]}   "
          if $using_sockets && [[ -n "${handshakebytes[i]}" ]]; then
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
               $OPENSSL s_client -cipher ${ciphers[i]} ${protos[i]} $STARTTLS $BUGS $PROXY -connect $NODEIP:$PORT ${sni[i]}  </dev/null >$TMPFILE 2>$ERRFILE
               debugme echo "$OPENSSL s_client -cipher ${ciphers[i]} ${protos[i]} $STARTTLS $BUGS $PROXY -connect $NODEIP:$PORT ${sni[i]}  </dev/null"
               sclient_connect_successful $? $TMPFILE
               sclient_success=$?
          fi
          if [[ $sclient_success -ne 0 ]]; then
               outln "No connection"
               fileout "client_${short[i]}" "INFO" "$(strip_spaces "${names[i]}") client simulation: No connection"
          else
               #FIXME: awk
               proto=$(grep -aw "Protocol" $TMPFILE | sed -e 's/^.*Protocol.*://' -e 's/ //g')
               [[ "$proto" == TLSv1 ]] && proto="TLSv1.0"
               if [[ "$proto" == TLSv1.2 ]] && ( ! $using_sockets || [[ -z "${handshakebytes[i]}" ]] ); then
                    # OpenSSL reports TLS1.2 even if the connection is TLS1.1 or TLS1.0. Need to figure out which one it is...
                    for tls in ${tlsvers[i]}; do
                         $OPENSSL s_client $tls -cipher ${ciphers[i]} ${protos[i]} $STARTTLS $BUGS $PROXY -connect $NODEIP:$PORT ${sni[i]}  </dev/null >$TMPFILE 2>$ERRFILE
                         debugme echo "$OPENSSL s_client $tls -cipher ${ciphers[i]} ${protos[i]} $STARTTLS $BUGS $PROXY -connect $NODEIP:$PORT ${sni[i]}  </dev/null"
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
               $using_sockets && [[ -n "${handshakebytes[i]}" ]] && [[ -n "$MAPPING_FILE_RFC" ]] && cipher="$(rfc2openssl "$cipher")"
               outln "$proto $cipher"
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
     if $OPENSSL s_client "$1" 2>&1 | grep -aq "unknown option"; then
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
     local via=""

     outln; pr_headline " Testing protocols "
     via="Protocol tested "

     if $SSL_NATIVE; then
          using_sockets=false
          pr_headlineln "(via native openssl)"
          via+="via native openssl"
     else
          if [[ -n "$STARTTLS" ]]; then
               pr_headlineln "(via openssl, SSLv2 via sockets) "
               via+="via openssl, SSLv2 via sockets"
               using_sockets=false
          else
               using_sockets=true
               pr_headlineln "(via sockets except TLS 1.2, SPDY+HTTP2) "
               via+="via sockets except for TLS1.2, SPDY+HTTP2"
          fi
     fi
     outln

     pr_bold " SSLv2      ";
     if ! $SSL_NATIVE; then
          sslv2_sockets                                                    #FIXME: messages/output need to be moved to this (higher) level
     else
          run_prototest_openssl "-ssl2"
          case $? in
               0)
                    pr_svrty_criticalln   "offered (NOT ok)"
                    fileout "sslv2" "NOT ok" "SSLv2 is offered (NOT ok)"
                    add_tls_offered "ssl2"
                    ;;
               1)
                    pr_done_bestln "not offered (OK)"
                    fileout "sslv2" "OK" "SSLv2 is not offered (OK)"
                    ;;
               5)
                    pr_svrty_high "CVE-2015-3197: $supported_no_ciph2";
                    fileout "sslv2" "WARN" "CVE-2015-3197: SSLv2 is $supported_no_ciph2"
                    add_tls_offered "ssl2"
                    ;;
               7)
                    fileout "sslv2" "INFO" "SSLv2 is not tested due to lack of local support"
                    ;;                                                     # no local support
          esac
     fi

     pr_bold " SSLv3      ";
     if $using_sockets; then
          tls_sockets "00" "$TLS_CIPHER"
     else
          run_prototest_openssl "-ssl3"
     fi
     case $? in
          0)
               pr_svrty_highln "offered (NOT ok)"
               fileout "sslv3" "NOT ok" "SSLv3 is offered (NOT ok)"
               add_tls_offered "ssl3"
               ;;
          1)
               pr_done_bestln "not offered (OK)"
               fileout "sslv3" "OK" "SSLv3 is not offered (OK)"
               ;;
          2)
               pr_warningln "#FIXME: downgraded. still missing a test case here"
               fileout "sslv3" "WARN" "SSLv3: #FIXME: downgraded. still missing a test case here"
               ;;
          5)
               fileout "sslv3" "WARN" "SSLv3 is $supported_no_ciph1"
               pr_svrty_high "$supported_no_ciph2"
               outln "(may need debugging)"
               add_tls_offered "ssl3"
               ;;       
          7)
               fileout "sslv3" "INFO" "SSLv3 is not tested due to lack of local support"
               ;;                                                            # no local support
     esac

     pr_bold " TLS 1      ";
     if $using_sockets; then
          tls_sockets "01" "$TLS_CIPHER"
     else
          run_prototest_openssl "-tls1"
     fi
     case $? in
          0)
               outln "offered"
               fileout "tls1" "INFO" "TLSv1.0 is offered"
               add_tls_offered "tls1"
               ;;                                           # nothing wrong with it -- per se
          1)
               outln "not offered"
               fileout "tls1" "INFO" "TLSv1.0 is not offered"
               ;;                                           # neither good or bad
          2)
               pr_svrty_medium "not offered"
               [[ $DEBUG -eq 1 ]] && out " -- downgraded"
               outln
               fileout "tls1" "MEDIUM" "TLSv1.0 is not offered, and downgraded to SSL"
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
     if $using_sockets; then
          tls_sockets "02" "$TLS_CIPHER"
     else
          run_prototest_openssl "-tls1_1"
     fi
     case $? in
          0)
               outln "offered"
               fileout "tls1_1" "INFO" "TLSv1.1 is offered"
               add_tls_offered "tls1_1"
               ;;                                            # nothing wrong with it
          1)
               outln "not offered"
               fileout "tls1_1" "INFO" "TLSv1.1 is not offered"
               ;;                                        # neither good or bad
          2)
               out "not offered"
               [[ $DEBUG -eq 1 ]] && out " -- downgraded"
               outln
               fileout "tls1_1" "NOT ok" "TLSv1.1 is not offered, and downgraded to a weaker protocol (NOT ok)"
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
     if $using_sockets && $EXPERIMENTAL; then               #TODO: IIS servers do have a problem here with our handshake
          tls_sockets "03" "$TLS12_CIPHER"
     else
          run_prototest_openssl "-tls1_2"
     fi
     case $? in
          0)
               pr_done_bestln "offered (OK)"
               fileout "tls1_2" "OK" "TLSv1.2 is offered (OK)"
               add_tls_offered "tls1_2"
               ;;                                  # GCM cipher in TLS 1.2: very good!
          1)
               pr_svrty_mediumln "not offered"
               fileout "tls1_2" "MEDIUM" "TLSv1.2 is not offered"
               ;;                          # no GCM, penalty
          2)
               pr_svrty_medium "not offered"
               [[ $DEBUG -eq 1 ]] && out " -- downgraded"
               outln
               fileout "tls1_2" "MEDIUM" "TLSv1.2 is not offered and downgraded to a weaker protocol"
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
     outln
     pr_headlineln " Testing ~standard cipher lists "
     outln
# see ciphers(1ssl)
     std_cipherlists 'NULL:eNULL'                       " Null Ciphers             " 1 "NULL"
     std_cipherlists 'aNULL'                            " Anonymous NULL Ciphers   " 1 "aNULL"
     std_cipherlists 'ADH'                              " Anonymous DH Ciphers     " 1 "ADH"
     std_cipherlists 'EXPORT40'                         " 40 Bit encryption        " 1 "EXPORT40"
     std_cipherlists 'EXPORT56'                         " 56 Bit encryption        " 1 "EXPORT56"
     std_cipherlists 'EXPORT'                           " Export Ciphers (general) " 1 "EXPORT"
     std_cipherlists 'LOW:!ADH'                         " Low (<=64 Bit)           " 1 "LOW"
     std_cipherlists 'DES:!ADH:!EXPORT:!aNULL'          " DES Ciphers              " 1 "DES"
     std_cipherlists 'MEDIUM:!NULL:!aNULL:!SSLv2'       " Medium grade encryption  " 2 "MEDIUM"
     std_cipherlists '3DES:!ADH:!aNULL'                 " Triple DES Ciphers       " 3 "3DES"
     std_cipherlists 'HIGH:!NULL:!aNULL:!DES:!3DES'     " High grade encryption    " 0 "HIGH"
     outln
     return 0
}


# arg1: file with input for grepping the bit length for ECDH/DHE
# arg2: whether to print warning "old fart" or not (empty: no)
read_dhbits_from_file() {
     local bits what_dh temp
     local add=""
     local old_fart=" (openssl cannot show DH bits)"

     temp=$(awk -F': ' '/^Server Temp Key/ { print $2 }' "$1")        # extract line
     what_dh=$(awk -F',' '{ print $1 }' <<< $temp)
     bits=$(awk -F',' '{ print $3 }' <<< $temp)
     # RH's backport has the DH bits in second arg after comma
     grep -q bits <<< $bits || bits=$(awk -F',' '{ print $2 }' <<< $temp)
     bits=$(tr -d ' bits' <<< $bits)

     debugme echo ">$HAS_DH_BITS|$what_dh|$bits<"

     [[ -n "$what_dh" ]] && HAS_DH_BITS=true                            # FIX 190
     if [[ -z "$what_dh" ]] && ! "$HAS_DH_BITS"; then
          if [[ -z "$2" ]]; then
               pr_warning "$old_fart"
          fi
          return 0
     fi

     [[ -n "$bits" ]] && [[ -z "$2" ]] && out ", "
     if [[ $what_dh == "DH" ]] || [[ $what_dh == "EDH" ]]; then
          [[ -z "$2" ]] && add="bit DH"
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
          [[ -z "$2" ]] && add="bit ECDH"
          if [[ "$bits" -le 80 ]]; then      # has that ever existed?
               pr_svrty_critical "$bits $add"
          elif [[ "$bits" -le 108 ]]; then   # has that ever existed?
               pr_svrty_high "$bits $add"
          elif [[ "$bits" -le 163 ]]; then
               pr_svrty_medium "$bits $add"
          elif [[ "$bits" -le 193 ]]; then   # hmm, according to https://wiki.openssl.org/index.php/Elliptic_Curve_Cryptography it should ok
               pr_svrty_minor "$bits $add"   # but openssl removed it https://github.com/drwetter/testssl.sh/issues/299#issuecomment-220905416
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
     local default_cipher default_proto
     local remark4default_cipher
     local -a cipher proto
     local p i
     local -i ret=0
     local list_fwd="DES-CBC3-SHA:RC4-MD5:DES-CBC-SHA:RC4-SHA:AES128-SHA:AES128-SHA256:AES256-SHA:ECDHE-RSA-AES128-SHA:DHE-RSA-AES128-SHA:DHE-RSA-AES256-SHA:ECDH-RSA-DES-CBC3-SHA:ECDH-RSA-AES128-SHA:ECDH-RSA-AES256-SHA:ECDHE-RSA-AES256-GCM-SHA384:DHE-RSA-AES128-SHA256:DHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES128-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-SHA384:ECDHE-RSA-AES256-SHA:DHE-DSS-AES256-GCM-SHA384:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES128-GCM-SHA256:AES256-SHA256"
     # now reversed offline via tac, see https://github.com/thomassa/testssl.sh/commit/7a4106e839b8c3033259d66697893765fc468393 :
     local list_reverse="AES256-SHA256:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:DHE-DSS-AES256-GCM-SHA384:ECDHE-RSA-AES256-SHA:ECDHE-RSA-AES256-SHA384:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES128-SHA256:DHE-RSA-AES256-GCM-SHA384:DHE-RSA-AES128-SHA256:ECDHE-RSA-AES256-GCM-SHA384:ECDH-RSA-AES256-SHA:ECDH-RSA-AES128-SHA:ECDH-RSA-DES-CBC3-SHA:DHE-RSA-AES256-SHA:DHE-RSA-AES128-SHA:ECDHE-RSA-AES128-SHA:AES256-SHA:AES128-SHA256:AES128-SHA:RC4-SHA:DES-CBC-SHA:RC4-MD5:DES-CBC3-SHA"
     local has_cipher_order=true
     local isok

     outln
     pr_headlineln " Testing server preferences "
     outln

     pr_bold " Has server cipher order?     "
     $OPENSSL s_client $STARTTLS -cipher $list_fwd $BUGS -connect $NODEIP:$PORT $PROXY $SNI </dev/null 2>$ERRFILE >$TMPFILE
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
          $OPENSSL s_client $STARTTLS $STARTTLS_OPTIMAL_PROTO -cipher $list_fwd $BUGS -connect $NODEIP:$PORT $PROXY $SNI </dev/null 2>$ERRFILE >$TMPFILE
          if ! sclient_connect_successful $? $TMPFILE; then
               pr_warning "no matching cipher in this list found (pls report this): "
               outln "$list_fwd  . "
               has_cipher_order=false
               ret=6
               fileout "order_bug" "WARN" "Could not determine server cipher order, no matching cipher in this list found (pls report this): $list_fwd"
          fi
     fi

     if $has_cipher_order; then
          cipher1=$(grep -wa Cipher $TMPFILE | egrep -avw "New|is" | sed -e 's/^ \+Cipher \+://' -e 's/ //g')
          $OPENSSL s_client $STARTTLS $STARTTLS_OPTIMAL_PROTO -cipher $list_reverse $BUGS -connect $NODEIP:$PORT $PROXY $SNI </dev/null 2>>$ERRFILE >$TMPFILE
          # that worked above so no error handling here
          cipher2=$(grep -wa Cipher $TMPFILE | egrep -avw "New|is" | sed -e 's/^ \+Cipher \+://' -e 's/ //g')

          if [[ "$cipher1" != "$cipher2" ]]; then
               pr_svrty_high "nope (NOT ok)"
               remark4default_cipher=" (limited sense as client will pick)"
               fileout "order" "NOT ok" "Server does NOT set a cipher order (NOT ok)"
          else
               pr_done_best "yes (OK)"
               remark4default_cipher=""
               fileout "order" "OK" "Server sets a cipher order (OK)"
          fi
          debugme out "  $cipher1 | $cipher2"
          outln

          pr_bold " Negotiated protocol          "
          $OPENSSL s_client $STARTTLS $BUGS -connect $NODEIP:$PORT $PROXY $SNI </dev/null 2>>$ERRFILE >$TMPFILE
          if ! sclient_connect_successful $? $TMPFILE; then
               # 2 second try with $OPTIMAL_PROTO especially for intolerant IIS6 servers:
               $OPENSSL s_client $STARTTLS $OPTIMAL_PROTO $BUGS -connect $NODEIP:$PORT $PROXY $SNI </dev/null 2>>$ERRFILE >$TMPFILE
               sclient_connect_successful $? $TMPFILE || pr_warning "Handshake error!"
          fi
          default_proto=$(grep -aw "Protocol" $TMPFILE | sed -e 's/^.*Protocol.*://' -e 's/ //g')
          case "$default_proto" in
               *TLSv1.2)
                    pr_done_bestln $default_proto
                    fileout "order_proto" "OK" "Default protocol TLS1.2 (OK)"
                    ;;
               *TLSv1.1)
                    pr_done_goodln $default_proto
                    fileout "order_proto" "OK" "Default protocol TLS1.1 (OK)"
                    ;;
               *TLSv1)
                    outln $default_proto
                    fileout "order_proto" "INFO" "Default protocol TLS1.0"
                    ;;
               *SSLv2)
                    pr_svrty_criticalln $default_proto
                    fileout "order_proto" "NOT ok" "Default protocol SSLv2"
                    ;;
               *SSLv3)
                    pr_svrty_criticalln $default_proto
                    fileout "order_proto" "NOT ok" "Default protocol SSLv3"
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
          default_cipher=$(grep -aw "Cipher" $TMPFILE | egrep -avw "New|is" | sed -e 's/^.*Cipher.*://' -e 's/ //g')
          case "$default_cipher" in
               *NULL*|*EXP*)
                    pr_svrty_critical "$default_cipher"
                    fileout "order_cipher" "NOT ok" "Default cipher: $default_cipher$(read_dhbits_from_file "$TMPFILE") (NOT ok)  $remark4default_cipher"
                    ;;
               *RC4*)
                    pr_svrty_high "$default_cipher"
                    fileout "order_cipher" "NOT ok" "Default cipher: $default_cipher$(read_dhbits_from_file "$TMPFILE") (NOT ok)  remark4default_cipher"
                    ;;
               *CBC*)
                    pr_svrty_medium "$default_cipher"
                    fileout "order_cipher" "MEDIUM" "Default cipher: $default_cipher$(read_dhbits_from_file "$TMPFILE") $remark4default_cipher"
                    ;;   # FIXME BEAST: We miss some CBC ciphers here, need to work w/ a list
               *GCM*|*CHACHA20*)
                    pr_done_best "$default_cipher"
                    fileout "order_cipher" "OK" "Default cipher: $default_cipher$(read_dhbits_from_file "$TMPFILE") (OK)  $remark4default_cipher"
                    ;;   # best ones
               ECDHE*AES*)
                    pr_svrty_minor "$default_cipher"
                    fileout "order_cipher" "WARN" "Default cipher: $default_cipher$(read_dhbits_from_file "$TMPFILE") (cbc)  $remark4default_cipher"
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
                         out "     (SSLv2: "; local_problem "$OPENSSL doesn't support \"s_client -ssl2\""; outln ")";
                         continue
                    fi
                    if [[ $p == ssl3 ]] && ! "$HAS_SSL3"; then
                         out "     (SSLv3: "; local_problem "$OPENSSL doesn't support \"s_client -ssl3\"" ; outln ")";
                         continue
                    fi
                    $OPENSSL s_client $STARTTLS -"$p" $BUGS -connect $NODEIP:$PORT $PROXY $SNI </dev/null 2>>$ERRFILE >$TMPFILE
                    if sclient_connect_successful $? $TMPFILE; then
                         proto[i]=$(grep -aw "Protocol" $TMPFILE | sed -e 's/^.*Protocol.*://' -e 's/ //g')
                         cipher[i]=$(grep -aw "Cipher" $TMPFILE | egrep -avw "New|is" | sed -e 's/^.*Cipher.*://' -e 's/ //g')
                         [[ ${cipher[i]} == "0000" ]] && cipher[i]=""                     # Hack!
                         [[ $DEBUG -ge 2 ]] && outln "Default cipher for ${proto[i]}: ${cipher[i]}"
                    else
                          proto[i]=""
                          cipher[i]=""
                    fi
                    i=$(($i + 1))
               done

               [[ -n "$PROXY" ]] && arg="   SPDY/NPN is"
               [[ -n "$STARTTLS" ]] && arg="    "
               if spdy_pre " $arg" ; then                                       # is NPN/SPDY supported and is this no STARTTLS? / no PROXY
                    $OPENSSL s_client -connect $NODEIP:$PORT $BUGS -nextprotoneg "$NPN_PROTOs" </dev/null 2>>$ERRFILE >$TMPFILE
                    if sclient_connect_successful $? $TMPFILE; then
                         proto[i]=$(grep -aw "Next protocol" $TMPFILE | sed -e 's/^Next protocol://' -e 's/(.)//' -e 's/ //g')
                         if [[ -z "${proto[i]}" ]]; then
                              cipher[i]=""
                         else
                              cipher[i]=$(grep -aw "Cipher" $TMPFILE | egrep -avw "New|is" | sed -e 's/^.*Cipher.*://' -e 's/ //g')
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
                              printf -- "     %-30s %s" "${cipher[i]}:" "${proto[i]}"     # print out both
                          else                                                            # previous NOT empty
                              if [[ "${cipher[i-1]}" == "${cipher[i]}" ]]; then           # and previous protocol same cipher
                                   out ", ${proto[i]}"                                    # same cipher --> only print out protocol behind it
                              else
                                   outln
                                   printf -- "     %-30s %s" "${cipher[i]}:" "${proto[i]}"     # print out both
                             fi
                          fi
                    fi
                    fileout "order_${proto[i]}_cipher" "INFO" "Default cipher on ${proto[i]}: ${cipher[i]}remark4default_cipher"
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
     local tested_cipher="-$1"
     local order="$1"

     while true; do
          $OPENSSL s_client $STARTTLS -tls1_2 $BUGS -cipher "ALL:$tested_cipher:$batchremoved" -connect $NODEIP:$PORT $PROXY $SNI </dev/null 2>>$ERRFILE >$TMPFILE
          if sclient_connect_successful $? $TMPFILE ; then
               cipher=$(awk '/Cipher.*:/ { print $3 }' $TMPFILE)
               order+=" $cipher"
               tested_cipher="$tested_cipher:-$cipher"
          else
               debugme outln "A: $tested_cipher"
               break
          fi
     done
     batchremoved="${batchremoved//-/}"
     while true; do
          # no ciphers from "ALL:$tested_cipher:$batchremoved" left
          # now we check $batchremoved, and remove the minus signs first:
          $OPENSSL s_client $STARTTLS -tls1_2 $BUGS -cipher "$batchremoved" -connect $NODEIP:$PORT $PROXY $SNI </dev/null 2>>$ERRFILE >$TMPFILE
          if sclient_connect_successful $? $TMPFILE ; then
               batchremoved_success=true               # signals that we have some of those ciphers and need to put everything together later on
               cipher=$(awk '/Cipher.*:/ { print $3 }' $TMPFILE)
               order+=" $cipher"
               batchremoved="$batchremoved:-$cipher"
               debugme outln "B1: $batchremoved"
          else
               debugme outln "B2: $batchremoved"
               break
               # nothing left with batchremoved ciphers, we need to put everything together
          fi
     done

     if "$batchremoved_success"; then
          # now we combine the two cipher sets from both while loops
          combined_ciphers="${order// /:}"
          $OPENSSL s_client $STARTTLS -tls1_2 $BUGS -cipher "$combined_ciphers" -connect $NODEIP:$PORT $PROXY $SNI </dev/null 2>>$ERRFILE >$TMPFILE
          if sclient_connect_successful $? $TMPFILE ; then
               # first cipher
               cipher=$(awk '/Cipher.*:/ { print $3 }' $TMPFILE)
               order="$cipher"
               tested_cipher="-$cipher"
          else
               fixmeln "something weird happened around line $((LINENO - 6))"
               return 1
          fi
          while true; do
               $OPENSSL s_client $STARTTLS -tls1_2 $BUGS -cipher "$combined_ciphers:$tested_cipher" -connect $NODEIP:$PORT $PROXY $SNI </dev/null 2>>$ERRFILE >$TMPFILE
               if sclient_connect_successful $? $TMPFILE ; then
                    cipher=$(awk '/Cipher.*:/ { print $3 }' $TMPFILE)
                    order+=" $cipher"
                    tested_cipher="$tested_cipher:-$cipher"
               else
                    # nothing left, we're done
                    out " $order"
                    break
               fi
          done

     else
          # second cipher set didn't succeed: we can just output everything
          out " $order"
     fi

     tmpfile_handle $FUNCNAME.txt
     return 0
}


cipher_pref_check() {
     local p proto protos npn_protos
     local tested_cipher cipher order
     local overflow_probe_cipherlist="ALL:-ECDHE-RSA-AES256-GCM-SHA384:-AES128-SHA:-DES-CBC3-SHA"

     pr_bold " Cipher order"

     for p in ssl2 ssl3 tls1 tls1_1 tls1_2; do
          order=""
          if [[ $p == ssl2 ]] && ! "$HAS_SSL2"; then
               out "\n    SSLv2:     "; local_problem "$OPENSSL doesn't support \"s_client -ssl2\"";
               continue
          fi
          if [[ $p == ssl3 ]] && ! "$HAS_SSL3"; then
               out "\n    SSLv3:     "; local_problem "$OPENSSL doesn't support \"s_client -ssl3\"";
               continue
          fi
          # with the supplied binaries SNI works also for SSLv2 (+ SSLv3)
          $OPENSSL s_client $STARTTLS -"$p" $BUGS -connect $NODEIP:$PORT $PROXY $SNI </dev/null 2>$ERRFILE >$TMPFILE
          if sclient_connect_successful $? $TMPFILE; then
               tested_cipher=""
               proto=$(awk '/Protocol/ { print $3 }' $TMPFILE)
               cipher=$(awk '/Cipher.*:/ { print $3 }' $TMPFILE)
               [[ -z "$proto" ]] && continue                # for early openssl versions sometimes needed
               outln
               printf "    %-10s" "$proto: "
               tested_cipher="-"$cipher
               order="$cipher"
               if [[ $p == tls1_2 ]]; then
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
                    order=$(check_tls12_pref "$cipher")
                    out "$order"
               else
                    out " $cipher"  # this is the first cipher for protocol
                    while true; do
                         $OPENSSL s_client $STARTTLS -"$p" $BUGS -cipher "ALL:$tested_cipher" -connect $NODEIP:$PORT $PROXY $SNI </dev/null 2>>$ERRFILE >$TMPFILE
                         sclient_connect_successful $? $TMPFILE || break
                         cipher=$(awk '/Cipher.*:/ { print $3 }' $TMPFILE)
                         out " $cipher"
                         order+=" $cipher"
                         tested_cipher="$tested_cipher:-$cipher"
                    done
               fi
          fi
          [[ -z "$order" ]] || fileout "order_$p" "INFO" "Default cipher order for protocol $p: $order"
     done
     outln

     if ! spdy_pre "     SPDY/NPN: "; then       # is NPN/SPDY supported and is this no STARTTLS?
          outln
     else
          npn_protos=$($OPENSSL s_client -host $NODE -port $PORT $BUGS -nextprotoneg \"\" </dev/null 2>>$ERRFILE | grep -a "^Protocols " | sed -e 's/^Protocols.*server: //' -e 's/,//g')
          for p in $npn_protos; do
               order=""
               $OPENSSL s_client -host $NODE -port $PORT $BUGS -nextprotoneg "$p" $PROXY </dev/null 2>>$ERRFILE >$TMPFILE
               cipher=$(awk '/Cipher.*:/ { print $3 }' $TMPFILE)
               printf "    %-10s %s " "$p:" "$cipher"
               tested_cipher="-"$cipher
               order="$cipher"
               while true; do
                    $OPENSSL s_client -cipher "ALL:$tested_cipher" -host $NODE -port $PORT $BUGS -nextprotoneg "$p" $PROXY </dev/null 2>>$ERRFILE >$TMPFILE
                    sclient_connect_successful $? $TMPFILE || break
                    cipher=$(awk '/Cipher.*:/ { print $3 }' $TMPFILE)
                    out "$cipher "
                    tested_cipher="$tested_cipher:-$cipher"
                    order+=" $cipher"
               done
               outln
               [[ -n $order ]] && fileout "order_spdy_$p" "INFO" "Default cipher order for SPDY protocol $p: $order"
          done
     fi

     outln
     tmpfile_handle $FUNCNAME.txt
     return 0
}


# arg1 is proto or empty
get_host_cert() {
     local tmpvar=$TEMPDIR/$FUNCNAME.txt     # change later to $TMPFILE

     $OPENSSL s_client $STARTTLS $BUGS -connect $NODEIP:$PORT $PROXY $SNI $1 2>/dev/null </dev/null >$tmpvar
     if sclient_connect_successful $? $tmpvar; then
          awk '/-----BEGIN/,/-----END/ { print $0 }' $tmpvar >$HOSTCERT
          return 0
     else
          pr_warningln "could not retrieve host certificate!"
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
     local ca_bundles="$INSTALL_DIR/etc/*.pem"
     local spaces="                              "
     local -i certificates_provided=1+$(grep -c "\-\-\-\-\-BEGIN CERTIFICATE\-\-\-\-\-" $TEMPDIR/intermediatecerts.pem)
     local addtl_warning
     
     # If $json_prefix is not empty, then there is more than one certificate 
     # and the output should should be indented by two more spaces.
     [[ -n $json_prefix ]] && spaces="                                "

     if [[ $OSSL_VER_MAJOR.$OSSL_VER_MINOR != "1.0.2" ]] && [[ $OSSL_VER_MAJOR.$OSSL_VER_MINOR != "1.1.0" ]]; then
          addtl_warning="(Your openssl <= 1.0.2 might be too unreliable to determine trust)"
          fileout "${json_prefix}trust_warn" "WARN" "$addtl_warning"
     fi
     debugme outln
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
          fileout "${json_prefix}trust" "OK" "All certificate trust checks passed. $addtl_warning"
	else
	     # at least one failed
		pr_svrty_critical "NOT ok"
		if ! $some_ok; then
		     # all failed (we assume with the same issue), we're displaying the reason
               out " "
			verify_retcode_helper "${verify_retcode[2]}"
               fileout "${json_prefix}trust" "NOT ok" "All certificate trust checks failed: $(verify_retcode_helper "${verify_retcode[2]}"). $addtl_warning"
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
               fileout "${json_prefix}trust" "NOT ok" "Some certificate trust checks failed : OK : $ok_was  NOT ok: $notok_was $addtl_warning"
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
          pr_warning "SSLv3 through TLS 1.2 didn't return a timestamp"
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

# arg1 is "-cipher <OpenSSL cipher>" or empty
# arg2 is a list of protocols to try (tls1_2, tls1_1, tls1, ssl3) or empty (if all should be tried)
determine_tls_extensions() {
     local proto
     local success
     local alpn=""
     local savedir
     local nrsaved

     "$HAS_ALPN" && alpn="h2-14,h2-15,h2"

     if [[ -n "$2" ]]; then
         protocols_to_try="$2"
     else
         protocols_to_try="tls1_2 tls1_1 tls1 ssl3"
     fi

     # throwing 1st every cipher/protocol at the server to know what works
     success=7
     for proto in $protocols_to_try; do
# alpn: echo | openssl s_client -connect google.com:443 -tlsextdebug -alpn h2-14 -servername google.com  <-- suport needs to be checked b4 -- see also: ssl/t1_trce.c
          $OPENSSL s_client $STARTTLS $BUGS $1 -showcerts -connect $NODEIP:$PORT $PROXY $SNI -$proto -tlsextdebug -nextprotoneg $alpn -status </dev/null 2>$ERRFILE >$TMPFILE
          sclient_connect_successful $? $TMPFILE && success=0 && break
     done                          # this loop is needed for IIS6 and others which have a handshake size limitations
     if [[ $success -eq 7 ]]; then
          # "-status" above doesn't work for GOST only servers, so we do another test without it and see whether that works then:
          $OPENSSL s_client $STARTTLS $BUGS $1 -showcerts -connect $NODEIP:$PORT $PROXY $SNI -$proto -tlsextdebug </dev/null 2>>$ERRFILE >$TMPFILE
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
     #TLS_EXTENSIONS=$(awk -F'"' '/TLS server extension / { printf "\""$2"\" " }' $TMPFILE)
     #
     # this is not beautiful (grep+sed)
     # but maybe we should just get the ids and do a private matching, according to
     # https://www.iana.org/assignments/tls-extensiontype-values/tls-extensiontype-values.xhtml <-- ALPN is missing
     TLS_EXTENSIONS=$(grep -a 'TLS server extension ' $TMPFILE | sed -e 's/TLS server extension //g' -e 's/\" (id=/\/#/g' -e 's/,.*$/,/g' -e 's/),$/\"/g')
     TLS_EXTENSIONS=$(echo $TLS_EXTENSIONS)       # into one line

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

# Return 0 if the server name provided in arg1 matches the CN or SAN in arg2, otherwise return 1.
compare_server_name_to_cert()
{
     local servername=$1
     local cert=$2
     local cn dns_sans ip_sans san basename

     cn="$(get_cn_from_cert $cert)"
     if [[ -n "$cn" ]]; then
          [[ "$cn" == "$servername" ]] && return 0
          # If the CN contains a wildcard name, then do a wildcard match
          if echo -n "$cn" | grep -q '^*.'; then
               basename="$(echo -n "$cn" | sed 's/^\*.//')"
               [[ "$cn" == "*.$basename" ]] && [[ "$servername" == *".$basename" ]] && return 0
          fi
     fi

     # Check whether any of the DNS names in the certificate match the servername
     dns_sans=$($OPENSSL x509 -in $cert -noout -text 2>>$ERRFILE | grep -A2 "Subject Alternative Name" | \
              sed -e 's/,/\n/g' | grep "DNS:" | sed -e 's/DNS://g' -e 's/ //g')
     for san in $dns_sans; do
          [[ "$san" == "$servername" ]] && return 0
          # If $san is a wildcard name, then do a wildcard match
          if echo -n "$san" | grep -q '^*.'; then
               basename="$(echo -n "$san" | sed 's/^\*.//')"
               [[ "$san" == "*.$basename" ]] && [[ "$servername" == *".$basename" ]] && return 0
          fi
     done

     # Check whether any of the IP addresses in the certificate match the serername
     ip_sans=$($OPENSSL x509 -in $cert -noout -text 2>>$ERRFILE | grep -A2 "Subject Alternative Name" | \
             sed -e 's/,/\n/g' | grep "IP Address:" | sed -e 's/IP Address://g' -e 's/ //g')
     for san in $ip_sans; do
          [[ "$san" == "$servername" ]] && return 0
     done
     return 1
}

certificate_info() {
     local proto
     local -i certificate_number=$1
     local -i number_of_certificates=$2
     local cipher=$3
     local cert_keysize=$4
     local ocsp_response=$5
     local ocsp_response_status=$6
     local cert_sig_algo cert_sig_hash_algo cert_key_algo
     local expire days2expire secs2warn ocsp_uri crl startdate enddate issuer_C issuer_O issuer sans san cn cn_nosni
     local cert_fingerprint_sha1 cert_fingerprint_sha2 cert_fingerprint_serial
     local policy_oid
     local spaces=""
     local wildcard=false
     local -i certificates_provided
     local cnfinding
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
          pr_headlineln "Server Certificate #$certificate_number"
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
               pr_svrty_mediumln "SHA1 with RSA"
               fileout "${json_prefix}algorithm" "MEDIUM" "Signature Algorithm: SHA1 with RSA (warning)"
               ;;
          sha224WithRSAEncryption)
               outln "SHA224 with RSA"
               fileout "${json_prefix}algorithm" "INFO" "Signature Algorithm: SHA224 with RSA"
               ;;
          sha256WithRSAEncryption)
               pr_done_goodln "SHA256 with RSA"
               fileout "${json_prefix}algorithm" "OK" "Signature Algorithm: SHA256 with RSA (OK)"
               ;;
          sha384WithRSAEncryption)
               pr_done_goodln "SHA384 with RSA"
               fileout "${json_prefix}algorithm" "OK" "Signature Algorithm: SHA384 with RSA (OK)"
               ;;
          sha512WithRSAEncryption)
               pr_done_goodln "SHA512 with RSA"
               fileout "${json_prefix}algorithm" "OK" "Signature Algorithm: SHA512 with RSA (OK)"
               ;;
          ecdsa-with-SHA1)
               pr_svrty_mediumln "ECDSA with SHA1"
               fileout "${json_prefix}algorithm" "MEDIUM" "Signature Algorithm: ECDSA with SHA1 (warning)"
               ;;
          ecdsa-with-SHA224)
               outln "ECDSA with SHA224"
               fileout "${json_prefix}algorithm" "INFO" "Signature Algorithm: ECDSA with SHA224"
               ;;
          ecdsa-with-SHA256)
               pr_done_goodln "ECDSA with SHA256"
               fileout "${json_prefix}algorithm" "OK" "Signature Algorithm: ECDSA with SHA256 (OK)"
               ;;
          ecdsa-with-SHA384)
               pr_done_goodln "ECDSA with SHA384"
               fileout "${json_prefix}algorithm" "OK" "Signature Algorithm: ECDSA with SHA384 (OK)"
               ;;
          ecdsa-with-SHA512)
               pr_done_goodln "ECDSA with SHA512"
               fileout "${json_prefix}algorithm" "OK" "Signature Algorithm: ECDSA with SHA512 (OK)"
               ;;
          dsaWithSHA1)
               pr_svrty_mediumln "DSA with SHA1"
               fileout "${json_prefix}algorithm" "MEDIUM" "Signature Algorithm: DSA with SHA1 (warning)"
               ;;
          dsa_with_SHA224)
               outln "DSA with SHA224"
               fileout "${json_prefix}algorithm" "INFO" "Signature Algorithm: DSA with SHA224"
               ;;
          dsa_with_SHA256)
               pr_done_goodln "DSA with SHA256"
               fileout "${json_prefix}algorithm" "OK" "Signature Algorithm: DSA with SHA256 (OK)"
               ;;
          rsassaPss)
               cert_sig_hash_algo="$($OPENSSL x509 -in $HOSTCERT -noout -text 2>>$ERRFILE | grep -A 1 "Signature Algorithm" | head -2 | tail -1 | sed 's/^.*Hash Algorithm: //')"
               case $cert_sig_hash_algo in
                    sha1)
                         pr_svrty_mediumln "RSASSA-PSS with SHA1"
                         fileout "${json_prefix}algorithm" "MEDIUM" "Signature Algorithm: RSASSA-PSS with SHA1 (warning)"
                         ;;
                    sha224)
                         outln "RSASSA-PSS with SHA224"
                         fileout "${json_prefix}algorithm" "INFO" "Signature Algorithm: RSASSA-PSS with SHA224"
                         ;;
                    sha256)
                         pr_done_goodln "RSASSA-PSS with SHA256"
                         fileout "${json_prefix}algorithm" "OK" "Signature Algorithm: RSASSA-PSS with SHA256 (OK)"
                         ;;
                    sha384)
                         pr_done_goodln "RSASSA-PSS with SHA384"
                         fileout "${json_prefix}algorithm" "OK" "Signature Algorithm: RSASSA-PSS with SHA384 (OK)"
                         ;;
                    sha512)
                         pr_done_goodln "RSASSA-PSS with SHA512"
                         fileout "${json_prefix}algorithm" "OK" "Signature Algorithm: RSASSA-PSS with SHA512 (OK)"
                         ;;
                    *)
                         out "RSASSA-PSS with $cert_sig_hash_algo"
                         pr_warningln " (Unknown hash algorithm)"
                         fileout "${json_prefix}algorithm" "DEBUG" "Signature Algorithm: RSASSA-PSS with $cert_sig_hash_algo"
                    esac
                    ;;
          md2*)
               pr_svrty_criticalln "MD2"
               fileout "${json_prefix}algorithm" "NOT ok" "Signature Algorithm: MD2 (NOT ok)"
               ;;
          md4*)
               pr_svrty_criticalln "MD4"
               fileout "${json_prefix}algorithm" "NOT ok" "Signature Algorithm: MD4 (NOT ok)"
               ;;
          md5*)
               pr_svrty_criticalln "MD5"
               fileout "${json_prefix}algorithm" "NOT ok" "Signature Algorithm: MD5 (NOT ok)"
               ;;
          *)
               out "$cert_sig_algo ("
               pr_warning "FIXME: can't tell whether this is good or not"
               outln ")"
               fileout "${json_prefix}algorithm" "DEBUG" "Signature Algorithm: $sign_algo"
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
               *)                       pr_warning "fixme: $cert_key_algo " ;;
          esac
          # https://tools.ietf.org/html/rfc4492,  http://www.keylength.com/en/compare/
          # http://infoscience.epfl.ch/record/164526/files/NPDF-22.pdf
          # see http://csrc.nist.gov/publications/nistpubs/800-57/sp800-57_part1_rev3_general.pdf
          # Table 2 @ chapter 5.6.1 (~ p64)
          if [[ $cert_key_algo =~ ecdsa ]] || [[ $cert_key_algo =~ ecPublicKey  ]]; then
               if [[ "$cert_keysize" -le 110 ]]; then       # a guess 
                    pr_svrty_critical "$cert_keysize"
                    fileout "${json_prefix}key_size" "NOT ok" "Server keys $cert_keysize EC bits (NOT ok)"
               elif [[ "$cert_keysize" -le 123 ]]; then    # a guess
                    pr_svrty_high "$cert_keysize"
                    fileout "${json_prefix}key_size" "NOT ok" "Server keys $cert_keysize EC bits (NOT ok)"
               elif [[ "$cert_keysize" -le 163 ]]; then
                    pr_svrty_medium "$cert_keysize"
                    fileout "${json_prefix}key_size" "MEDIUM" "Server keys $cert_keysize EC bits"
               elif [[ "$cert_keysize" -le 224 ]]; then
                    out "$cert_keysize"
                    fileout "${json_prefix}key_size" "INFO" "Server keys $cert_keysize EC bits"
               elif [[ "$cert_keysize" -le 533 ]]; then
                    pr_done_good "$cert_keysize"
                    fileout "${json_prefix}key_size" "OK" "Server keys $cert_keysize EC bits (OK)"
               else
                    out "keysize: $cert_keysize (not expected, FIXME)"
                    fileout "${json_prefix}key_size" "DEBUG" "Server keys $cert_keysize bits (not expected)"
               fi
               outln " bits"
          elif [[ $cert_key_algo = *RSA* ]] || [[ $cert_key_algo = *rsa* ]] || [[ $cert_key_algo = *dsa* ]]; then
               if [[ "$cert_keysize" -le 512 ]]; then
                    pr_svrty_critical "$cert_keysize"
                    outln " bits"
                    fileout "${json_prefix}key_size" "NOT ok" "Server keys $cert_keysize bits (NOT ok)"
               elif [[ "$cert_keysize" -le 768 ]]; then
                    pr_svrty_high "$cert_keysize"
                    outln " bits"
                    fileout "${json_prefix}key_size" "NOT ok" "Server keys $cert_keysize bits (NOT ok)"
               elif [[ "$cert_keysize" -le 1024 ]]; then
                    pr_svrty_medium "$cert_keysize"
                    outln " bits"
                    fileout "${json_prefix}key_size" "MEDIUM" "Server keys $cert_keysize bits"
               elif [[ "$cert_keysize" -le 2048 ]]; then
                    outln "$cert_keysize bits"
                    fileout "${json_prefix}key_size" "INFO" "Server keys $cert_keysize bits"
               elif [[ "$cert_keysize" -le 4096 ]]; then
                    pr_done_good "$cert_keysize"
                    fileout "${json_prefix}key_size" "OK" "Server keys $cert_keysize bits (OK)"
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

     out "$indent"; pr_bold " Common Name (CN)             "
     cnfinding="Common Name (CN) : "
     cn="$(get_cn_from_cert $HOSTCERT)"
     if [[ -n "$cn" ]]; then
          pr_dquoted "$cn"
          cnfinding="$cn"
          if echo -n "$cn" | grep -q '^*.' ; then
               out " (wildcard certificate"
               cnfinding+="(wildcard certificate "
               if [[ "$cn" == "*.$(echo -n "$cn" | sed 's/^\*.//')" ]]; then
                    out " match)"
                    cnfinding+=" match)"
                    wildcard=true
               else
                    cnfinding+=" NO match)"
                    cnok="INFO"
                    #FIXME: we need to test also the SANs as they can contain a wild card (google.de .e.g) ==> 2.7dev
               fi
          fi
     else
          cn="no CN field in subject"
          out "($cn)"
          cnfinding="$cn"
          cnok="INFO"
     fi

     # no cipher suites specified here. We just want the default vhost subject
     $OPENSSL s_client $STARTTLS $BUGS -connect $NODEIP:$PORT $PROXY $OPTIMAL_PROTO 2>>$ERRFILE </dev/null | awk '/-----BEGIN/,/-----END/ { print $0 }'  >$HOSTCERT.nosni
     cn_nosni="$(get_cn_from_cert "$HOSTCERT.nosni")"
     [[ -z "$cn_nosni" ]] && cn_nosni="no CN field in subject"

#FIXME: check for SSLv3/v2 and look whether it goes to a different CN (probably not polite)

     debugme out "\"$NODE\" | \"$cn\" | \"$cn_nosni\""
     if [[ "$cn_nosni" == "$cn" ]]; then
          outln " (works w/o SNI)"
          cnfinding+=" (works w/o SNI)"
     elif [[ $NODE == "$cn_nosni" ]]; then
          if [[ $SERVICE == "HTTP" ]] || $CLIENT_AUTH ; then
               outln " (works w/o SNI)"
               cnfinding+=" (works w/o SNI)"
          else
               outln " (matches certificate directly)"
               cnfinding+=" (matches certificate directly)"
               # for services != HTTP it depends on the protocol, server and client but it is not named "SNI"
          fi
     else
          if [[ $SERVICE != "HTTP" ]]; then
               outln
               cnfinding+="\n"
               #pr_svrty_mediumln " (non-SNI clients don't match CN but for non-HTTP services it might be ok)"
               #FIXME: this is irritating and needs to be redone. Then also the wildcard match needs to be tested against  "$cn_nosni"
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
               out " (CN in response to request w/o SNI: "; pr_dquoted "$cn_nosni"; outln ")"
               cnfinding+=" (CN in response to request w/o SNI: \"$cn_nosni\")"
          fi
     fi
     fileout "${json_prefix}cn" "$cnok" "$cnfinding"

     sans=$($OPENSSL x509 -in $HOSTCERT -noout -text 2>>$ERRFILE | grep -A2 "Subject Alternative Name" | \
          egrep "DNS:|IP Address:|email:|URI:|DirName:|Registered ID:" | \
          sed -e 's/ *DNS://g' -e 's/ *IP Address://g' -e 's/ *email://g' -e 's/ *URI://g' -e 's/ *DirName://g' \
              -e 's/ *Registered ID://g' -e 's/,/\n/g' \
              -e 's/ *othername:<unsupported>//g' -e 's/ *X400Name:<unsupported>//g' -e 's/ *EdiPartyName:<unsupported>//g')
#                   ^^^ CACert
     out "$indent"; pr_bold " subjectAltName (SAN)         "
     if [[ -n "$sans" ]]; then
          while read san; do
               [[ -n "$san" ]] && pr_dquoted "$san"
               out " "
          done <<< "$sans"
          fileout "${json_prefix}san" "INFO" "subjectAltName (SAN) : $sans"
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
     issuer_C="$(awk -F'=' '/C=/ { print $2 }' <<< "$issuer")"

     if [[ "$issuer_O" == "issuer=" ]] || [[ "$issuer_O" == "issuer= " ]] || [[ "$issuer_CN" == "$CN" ]]; then
          pr_svrty_criticalln "self-signed (NOT ok)"
          fileout "${json_prefix}issuer" "NOT ok" "Issuer: selfsigned (NOT ok)"
     else
          pr_dquoted "$issuer_CN"
          out " ("
          pr_dquoted "$issuer_O"
          if [[ -n "$issuer_C" ]]; then
               out " from "
               pr_dquoted "$issuer_C"
               fileout "${json_prefix}issuer" "INFO" "Issuer: \"$issuer\" ( \"$issuer_O\" from \"$issuer_C\")"
          else
               fileout "${json_prefix}issuer" "INFO" "Issuer: \"$issuer\" ( \"$issuer_O\" )"
          fi
          outln ")"
     fi

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
          expok="NOT ok"
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
                    expok="WARN"
               fi
          else
               pr_svrty_high "expires < $days2warn2 days ($days2expire) !"
               expfinding+="expires < $days2warn2 days ($days2expire) !"
               expok="NOT ok"
          fi
     fi
     outln " ($startdate --> $enddate)"
     fileout "${json_prefix}expiration" "$expok" "Certificate Expiration : $expfinding ($startdate --> $enddate)"

     certificates_provided=1+$(grep -c "\-\-\-\-\-BEGIN CERTIFICATE\-\-\-\-\-" $TEMPDIR/intermediatecerts.pem)
     out "$indent"; pr_bold " # of certificates provided"; outln "   $certificates_provided"
     fileout "${json_prefix}certcount" "INFO" "# of certificates provided :  $certificates_provided"


     out "$indent"; pr_bold " Chain of trust"; out " (experim.)    "
     determine_trust "$json_prefix" # Also handles fileout

     out "$indent"; pr_bold " Certificate Revocation List  "
     crl="$($OPENSSL x509 -in $HOSTCERT -noout -text 2>>$ERRFILE | grep -A 4 "CRL Distribution" | grep URI | sed 's/^.*URI://')"
     if [[ -z "$crl" ]]; then
          pr_svrty_highln "--"
          fileout "${json_prefix}crl" "NOT ok" "No CRL provided (NOT ok)"
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
     ocsp_uri=$($OPENSSL x509 -in $HOSTCERT -noout -ocsp_uri 2>>$ERRFILE)
     if [[ -z "$ocsp_uri" ]]; then
          pr_svrty_highln "--"
          fileout "${json_prefix}ocsp_uri" "NOT ok" "OCSP URI : -- (NOT ok)"
     else
          outln "$ocsp_uri"
          fileout "${json_prefix}ocsp_uri" "INFO" "OCSP URI : $ocsp_uri"
     fi

     out "$indent"; pr_bold " OCSP stapling                "
     if grep -a "OCSP response" <<<"$ocsp_response" | grep -q "no response sent" ; then
          pr_svrty_minor "--"
          fileout "${json_prefix}ocsp_stapling" "INFO" "OCSP stapling : not offered"
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
     local all_tls_extensions=""
     local -i certs_found=0
     local -a previous_hostcert previous_intermediates keysize cipher ocsp_response ocsp_response_status
     local -a ciphers_to_test success
     local cn_nosni cn_sni sans_nosni sans_sni san

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
                  determine_tls_extensions "-cipher ${ciphers_to_test[n]}" "tls1_1"
                  success[n]=$?
                  SNI="$sni"
             else
                  determine_tls_extensions "-cipher ${ciphers_to_test[n]}"
                  success[n]=$?
             fi
             if [[ ${success[n]} -eq 0 ]]; then
                 # check to see if any new TLS extensions were returned and add any new ones to all_tls_extensions
                 while read -d "\"" -r line; do
                     if [[ $line != "" ]] && ! grep -q "$line" <<< "$all_tls_extensions"; then
                         all_tls_extensions="${all_tls_extensions} \"${line}\""
                     fi
                 done <<<$TLS_EXTENSIONS
             
                 cp "$TEMPDIR/$NODEIP.determine_tls_extensions.txt" $TMPFILE
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
                     success[n]=$?

                     if [[ ${success[n]} -ne 0 ]]; then
                         cn_nosni="$(get_cn_from_cert $HOSTCERT)"
                         sans_nosni=$($OPENSSL x509 -in $HOSTCERT -noout -text 2>>$ERRFILE | grep -A2 "Subject Alternative Name" | grep "DNS:" | \
                              sed -e 's/DNS://g' -e 's/ //g' -e 's/,/ /g' -e 's/othername:<unsupported>//g')

                         echo "${previous_hostcert[1]}" > $HOSTCERT
                         cn_sni="$(get_cn_from_cert $HOSTCERT)"
                         
                         # FIXME: Not sure what the matching rule should be. At
                         # the moment, the no SNI certificate is considered a
                         # match if the CNs are the same and the SANs (if
                         # present) contain at least one DNS name in common.
                         if [[ "$cn_nosni" == "$cn_sni" ]]; then
                              sans_sni=$($OPENSSL x509 -in $HOSTCERT -noout -text 2>>$ERRFILE | grep -A2 "Subject Alternative Name" | grep "DNS:" | \
                                       sed -e 's/DNS://g' -e 's/ //g' -e 's/,/ /g' -e 's/othername:<unsupported>//g')
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
                 fi
             fi
         fi
     done
     
     if [[ $certs_found -eq 0 ]]; then
         [[ -z "$TLS_EXTENSIONS" ]] && determine_tls_extensions
         [[ -n "$TLS_EXTENSIONS" ]] && all_tls_extensions=" $TLS_EXTENSIONS"

         cp "$TEMPDIR/$NODEIP.determine_tls_extensions.txt" $TMPFILE
         >$ERRFILE

         sessticket_str=$(grep -aw "session ticket" $TMPFILE | grep -a lifetime)
     fi

     outln
     pr_headlineln " Testing server defaults (Server Hello) "
     outln

     pr_bold " TLS extensions (standard)    "
     if [[ -z "$all_tls_extensions" ]]; then
         outln "(none)"
         fileout "tls_extensions" "INFO" "TLS server extensions (std): (none)"
     else
         all_tls_extensions="${all_tls_extensions:1}"
         outln "$all_tls_extensions"
         fileout "tls_extensions" "INFO" "TLS server extensions (std): $all_tls_extensions"
     fi
     TLS_EXTENSIONS="$all_tls_extensions"

     pr_bold " Session Tickets RFC 5077     "
     if [[ -z "$sessticket_str" ]]; then
          outln "(none)"
          fileout "session_ticket" "INFO" "TLS session tickes RFC 5077 not supported"
     else
          lifetime=$(echo $sessticket_str | grep -a lifetime | sed 's/[A-Za-z:() ]//g')
          unit=$(echo $sessticket_str | grep -a lifetime | sed -e 's/^.*'"$lifetime"'//' -e 's/[ ()]//g')
          out "$lifetime $unit "
          pr_svrty_minorln "(PFS requires session ticket keys to be rotated <= daily)"
          fileout "session_ticket" "INFO" "TLS session tickes RFC 5077 valid for $lifetime $unit (PFS requires session ticket keys to be rotated at least daily)"
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
         certificate_info "$i" "$certs_found" "${cipher[i]}" "${keysize[i]}" "${ocsp_response[i]}" "${ocsp_response_status[i]}"
         i=$((i + 1))
     done
}

run_pfs() {
     local -i sclient_success
     local pfs_offered=false
     local tmpfile
     local dhlen
     local hexcode dash pfs_cipher sslvers kx auth enc mac
     local pfs_cipher_list="$ROBUST_PFS_CIPHERS"
     local -i nr_supported_ciphers=0
     local pfs_ciphers

     outln
     pr_headlineln " Testing robust (perfect) forward secrecy, (P)FS -- omitting Null Authentication/Encryption as well as 3DES and RC4 here "
     if ! "$HAS_DH_BITS" && "$WIDE"; then
          pr_warningln "    (Your $OPENSSL cannot show DH/ECDH bits)"
     fi

     nr_supported_ciphers=$(count_ciphers $(actually_supported_ciphers $pfs_cipher_list))
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
     if [[ $? -ne 0 ]] || [[ $(grep -ac "BEGIN CERTIFICATE" $TMPFILE) -eq 0 ]]; then
          outln
          pr_svrty_mediumln "No ciphers supporting Forward Secrecy offered"
          fileout "pfs" "MEDIUM" "(Perfect) Forward Secrecy : No ciphers supporting Forward Secrecy offered"
     else
          outln
          pfs_offered=true
          pfs_ciphers=""
          pr_done_good " PFS is offered (OK)"
          fileout "pfs" "OK" "(Perfect) Forward Secrecy : PFS is offered (OK)"
          if "$WIDE"; then
               outln ", ciphers follow (client/browser support is important here) \n"
               neat_header
          else
               out "  "
          fi
          while read hexcode dash pfs_cipher sslvers kx auth enc mac; do
               tmpfile=$TMPFILE.$hexcode
               $OPENSSL s_client -cipher $pfs_cipher $STARTTLS $BUGS -connect $NODEIP:$PORT $PROXY $SNI &>$tmpfile </dev/null
               sclient_connect_successful $? $tmpfile
               sclient_success=$?
               if [[ "$sclient_success" -ne 0 ]] && ! "$SHOW_EACH_C"; then
                    continue                 # no successful connect AND not verbose displaying each cipher
               fi

               if "$WIDE"; then
                    normalize_ciphercode $hexcode
                    if [[ $kx == "Kx=ECDH" ]] || [[ $kx == "Kx=DH" ]] || [[ $kx == "Kx=EDH" ]]; then
                         dhlen=$(read_dhbits_from_file "$tmpfile" quiet)
                         kx="$kx $dhlen"
                    fi
                    neat_list $HEXC $pfs_cipher "$kx" $enc $strength
                    if "$SHOW_EACH_C"; then
                         if [[ $sclient_success -eq 0 ]]; then
                              pr_done_best "available"
                         else
                              out "not a/v"
                         fi
                    else
                         pfs_offered=true
                    fi
                    outln
               else
                    if [[ $sclient_success -eq 0 ]]; then
                         out "$pfs_cipher "
                    fi
               fi
               [[ $sclient_success -eq 0 ]] && pfs_ciphers+="$pfs_cipher "
               debugme rm $tmpfile
          done < <($OPENSSL ciphers -V "$pfs_cipher_list" 2>$ERRFILE)      # -V doesn't work with openssl < 1.0
          debugme echo $pfs_offered
          "$WIDE" || outln

          if ! "$pfs_offered"; then
               pr_svrty_medium "WARN: no PFS ciphers found"
               fileout "pfs_ciphers" "NOT ok" "(Perfect) Forward Secrecy Ciphers: no PFS ciphers found (NOT ok)"
          else
               fileout "pfs_ciphers" "INFO" "(Perfect) Forward Secrecy Ciphers: $pfs_ciphers"
          fi
     fi
     outln

     tmpfile_handle $FUNCNAME.txt
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
     if [[ -n "$STARTTLS" ]]; then
          [[ -n "$1" ]] && out "$1"
          out "(SPDY is an HTTP protocol and thus not tested here)"
          fileout "spdy_npn" "INFO" "SPDY/NPN : (SPY is an HTTP protocol and thus not tested here)"
          return 1
     fi
     if [[ -n "$PROXY" ]]; then
          [[ -n "$1" ]] && pr_warning " $1 "
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
     if [[ -n "$STARTTLS" ]]; then
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
     if ! "$HAS_ALPN"; then
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
     if ! spdy_pre ; then
          outln
          return 0
     fi
     $OPENSSL s_client -connect $NODEIP:$PORT $BUGS $SNI -nextprotoneg $NPN_PROTOs </dev/null 2>$ERRFILE >$TMPFILE
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
     local tmpstr
     local -i ret=0
     local had_alpn_proto=false
     local alpn_finding=""

     pr_bold " HTTP2/ALPN "
     if ! http2_pre ; then
          outln
          return 0
     fi
     for proto in $ALPN_PROTOs; do
          # for some reason OpenSSL doesn't list the advertised protocols, so instead try common protocols
          $OPENSSL s_client -connect $NODEIP:$PORT $BUGS $SNI -alpn $proto </dev/null 2>$ERRFILE >$TMPFILE
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
     debugme echo -e "\n=== sending \"$1\" ..."
     echo -e "$1" >&5
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
               ftp|ftps)  # https://tools.ietf.org/html/rfc4217
                    $FAST_STARTTLS || starttls_just_read
                    $FAST_STARTTLS || starttls_line "FEAT" "211" && starttls_just_send "FEAT"
                    starttls_line "AUTH TLS" "successful|234"
                    ;;
               smtp|smtps)  # SMTP, see https://tools.ietf.org/html/rfc4217
                    $FAST_STARTTLS || starttls_just_read
                    $FAST_STARTTLS || starttls_line "EHLO testssl.sh" "220|250" && starttls_just_send "EHLO testssl.sh"
                    starttls_line "STARTTLS" "220"
                    ;;
               pop3|pop3s) # POP, see https://tools.ietf.org/html/rfc2595
                    $FAST_STARTTLS || starttls_just_read
                    starttls_line "STLS" "OK"
                    ;;
               nntp|nntps) # NNTP, see https://tools.ietf.org/html/rfc4642
                    $FAST_STARTTLS || starttls_just_read
                    $FAST_STARTTLS || starttls_line "CAPABILITIES" "101|200" && starttls_just_send "CAPABILITIES"
                    starttls_line "STARTTLS" "382"
                    ;;
               imap|imaps) # IMAP, https://tools.ietf.org/html/rfc2595
                    $FAST_STARTTLS || starttls_just_read
                    $FAST_STARTTLS || starttls_line "a001 CAPABILITY" "OK" && starttls_just_send "a001 CAPABILITY"
                    starttls_line "a002 STARTTLS" "OK"
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

# arg1: name of file with socket reply
parse_sslv2_serverhello() {
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

     v2_hello_ascii=$(hexdump -v -e '16/1 "%02X"' $1)
     [[ "$DEBUG" -ge 5 ]] && echo "$v2_hello_ascii"
     if [[ -z "$v2_hello_ascii" ]]; then
          ret=0                                        # 1 line without any blanks: no server hello received
          debugme echo "server hello empty"
     else
          # now scrape two bytes out of the reply per byte
          v2_hello_initbyte="${v2_hello_ascii:0:1}"  # normally this belongs to the next, should be 8!
          v2_hello_length="${v2_hello_ascii:1:3}"    # + 0x8000 see above
          v2_hello_handshake="${v2_hello_ascii:4:2}"
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
               echo "SSLv2 certificate length:  0x$v2_hello_cert_length"
               echo "SSLv2 cipher spec length:  0x$v2_hello_cipherspec_length"
          fi
     fi
     return $ret
}


# arg1: name of file with socket reply
parse_tls_serverhello() {
     local tls_hello_ascii=$(hexdump -v -e '16/1 "%02X"' "$1")
     local tls_handshake_ascii="" tls_alert_ascii=""
     local -i tls_hello_ascii_len tls_handshake_ascii_len tls_alert_ascii_len msg_len
     local tls_serverhello_ascii=""
     local -i tls_serverhello_ascii_len=0
     local tls_alert_descrip tls_sid_len_hex
     local -i tls_sid_len offset
     local tls_msg_type tls_content_type tls_protocol tls_protocol2 tls_hello_time
     local tls_err_level tls_err_descr tls_cipher_suite tls_compression_method
     local -i i

     TLS_TIME=""
     DETECTED_TLS_VERSION=""
     [[ -n "$tls_hello_ascii" ]] && echo "CONNECTED(00000003)" > $TMPFILE

     # $tls_hello_ascii may contain trailing whitespace. Remove it:
     tls_hello_ascii="${tls_hello_ascii%%[!0-9A-F]*}"
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
               # This could just be a result of the server's response being
               # split across two or more packets.
               continue
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
                     *) outln ;;
               esac
               echo "     msg_len:                $((msg_len/2))"
               outln
          fi
          if [[ $tls_content_type != "15" ]] && [[ $tls_content_type != "16" ]]; then
               debugme pr_warningln "Content type other than alert or handshake detected."
               return 1
          elif [[ "${tls_protocol:0:2}" != "03" ]]; then
               debugme pr_warningln "Protocol record_version.major is not 03."
               return 1
          fi
          DETECTED_TLS_VERSION=$tls_protocol

          if [[ $msg_len -gt $tls_hello_ascii_len-$i ]]; then
               # This could just be a result of the server's response being
               # split across two or more packets. Just grab the part that
               # is available.
               msg_len=$tls_hello_ascii_len-$i
          fi

          if [[ $tls_content_type == "16" ]]; then
               tls_handshake_ascii="$tls_handshake_ascii${tls_hello_ascii:i:msg_len}"
          elif [[ $tls_content_type == "15" ]]; then   # TLS ALERT
               tls_alert_ascii="$tls_alert_ascii${tls_hello_ascii:i:msg_len}"
          fi
     done

     # Now check the alert messages.
     tls_alert_ascii_len=${#tls_alert_ascii}
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
                    6E) tls_alert_descrip="unsupported extension" ;;
                    6F) tls_alert_descrip="certificate unobtainable" ;;
                    70) tls_alert_descrip="unrecognized name" ;;
                    71) tls_alert_descrip="bad certificate status response" ;;
                    72) tls_alert_descrip="bad certificate hash value" ;;
                    73) tls_alert_descrip="unknown psk identity" ;;
                    78) tls_alert_descrip="no application protocol" ;;
                     *) tls_alert_descrip="$(hex2dec "$tls_err_descr")";;
               esac

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
                    return 1
               fi
          done
     fi

     # Now extract just the server hello handshake message.
     tls_handshake_ascii_len=${#tls_handshake_ascii}
     if [[ $DEBUG -ge 2 ]] && [[ $tls_handshake_ascii_len -gt 0 ]]; then
         echo "TLS handshake messages:"
     fi
     for (( i=0; i<tls_handshake_ascii_len; i=i+msg_len )); do
          if [[ $tls_handshake_ascii_len-$i -lt 8 ]]; then
               # This could just be a result of the server's response being
               # split across two or more packets.
               continue
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
                    *) outln ;;
               esac
               echo "     msg_len:                $((msg_len/2))"
               outln
          fi
          if [[ $msg_len -gt $tls_handshake_ascii_len-$i ]]; then
               # This could just be a result of the server's response being
               # split across two or more packets. Just grab the part that
               # is available.
               msg_len=$tls_handshake_ascii_len-$i
          fi

          if [[ "$tls_msg_type" == "02" ]]; then
               if [[ -n "$tls_serverhello_ascii" ]]; then
                    debugme pr_warningln "Response contained more than one ServerHello handshake message."
                    return 1
               fi
               tls_serverhello_ascii="${tls_handshake_ascii:i:msg_len}"
               tls_serverhello_ascii_len=$msg_len
          fi
     done

     if [[ $tls_serverhello_ascii_len -eq 0 ]]; then
          debugme echo "server hello empty, TCP connection closed"
          return 1              # no server hello received
     elif [[ $tls_serverhello_ascii_len -lt 76 ]]; then
          debugme echo "Malformed response"
          return 1
     elif [[ "${tls_handshake_ascii:0:2}" != "02" ]]; then
          # the ServerHello MUST be the first handshake message
          debugme pr_warningln "The first handshake protocol message is not a ServerHello."
          return 1
     fi

     # Parse the server hello handshake message
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

     tls_hello_time="${tls_serverhello_ascii:4:8}"
     TLS_TIME=$(hex2dec "$tls_hello_time")

     tls_sid_len_hex="${tls_serverhello_ascii:68:2}"
     tls_sid_len=2*$(hex2dec "$tls_sid_len_hex")
     let offset=70+$tls_sid_len

     if [[ $tls_serverhello_ascii_len -lt 76+$tls_sid_len ]]; then
          debugme echo "Malformed response"
          return 1
     fi

     tls_cipher_suite="${tls_serverhello_ascii:$offset:4}"

     let offset=74+$tls_sid_len
     tls_compression_method="${tls_serverhello_ascii:$offset:2}"

     if [[ "$tls_protocol2" == "0300" ]]; then
          echo "Protocol  : SSLv3" >> $TMPFILE
     else
          echo "Protocol  : TLSv1.$((0x$tls_protocol2-0x0301))" >> $TMPFILE
     fi
     echo "===============================================================================" >> $TMPFILE
     if [[ -n "$MAPPING_FILE_RFC" ]]; then
          if [[ "${tls_cipher_suite:0:2}" == "00" ]]; then
               echo "Cipher    : $(strip_spaces $(show_rfc_style "x${tls_cipher_suite:2:2}"))" >> $TMPFILE
          else
               echo "Cipher    : $(strip_spaces $(show_rfc_style "x${tls_cipher_suite:0:4}"))" >> $TMPFILE
          fi
     else
          echo "Cipher    : $($OPENSSL ciphers -V 'ALL:COMPLEMENTOFALL' | grep -i " 0x${tls_cipher_suite:0:2},0x${tls_cipher_suite:2:2} " | awk '{ print $3 }')" >> $TMPFILE
     fi
     echo "===============================================================================" >> $TMPFILE

     if [[ $DEBUG -ge 2 ]]; then
          echo "TLS server hello message:"
          if [[ $DEBUG -ge 4 ]]; then
               echo "     tls_protocol:           0x$tls_protocol2"
               echo "     tls_sid_len:            0x$tls_sid_len_hex / = $((tls_sid_len/2))"
          fi
          echo -n "     tls_hello_time:         0x$tls_hello_time "
          parse_date "$TLS_TIME" "+%Y-%m-%d %r" "%s"
          echo "     tls_cipher_suite:       0x$tls_cipher_suite"
          echo -n "     tls_compression_method: 0x$tls_compression_method "
          case $tls_compression_method in
               00) echo "(NONE)" ;;
               01) echo "(zlib compression)" ;;
               40) echo "(LZS compression)" ;;
                *) echo "(unrecognized compression method)" ;;
          esac
          outln
     fi
     tmpfile_handle $FUNCNAME.txt
     return 0
}


sslv2_sockets() {
     local nr_ciphers_detected

     fd_socket 5 || return 6
     debugme outln "sending client hello... "
     socksend_sslv2_clienthello "$SSLv2_CLIENT_HELLO"

     sockread_serverhello 32768
     debugme outln "reading server hello... "
     if [[ "$DEBUG" -ge 4 ]]; then
          hexdump -C "$SOCK_REPLY_FILE" | head -6
          outln
     fi

     parse_sslv2_serverhello "$SOCK_REPLY_FILE"
     case $? in
          7) # strange reply, couldn't convert the cipher spec length to a hex number
               pr_cyan "strange v2 reply "
               outln " (rerun with DEBUG >=2)"
               [[ $DEBUG -ge 3 ]] && hexdump -C "$SOCK_REPLY_FILE" | head -1
               ret=7
               fileout "sslv2" "WARN" "SSLv2: received a strange SSLv2 reply (rerun with DEBUG>=2)"
               ;;
          1) # no sslv2 server hello returned, like in openlitespeed which returns HTTP!
               pr_done_bestln "not offered (OK)"
               ret=0
               fileout "sslv2" "OK" "SSLv2 not offered (OK)"
               ;;
          0) # reset
               pr_done_bestln "not offered (OK)"
               ret=0
               fileout "sslv2" "OK" "SSLv2 not offered (OK)"
               ;;
          3) # everything else
               lines=$(count_lines "$(hexdump -C "$SOCK_REPLY_FILE" 2>/dev/null)")
               [[ "$DEBUG" -ge 2 ]] && out "  ($lines lines)  "
               if [[ "$lines" -gt 1 ]]; then
                    nr_ciphers_detected=$((V2_HELLO_CIPHERSPEC_LENGTH / 3))
                    add_tls_offered "ssl2"
                    if [[ 0 -eq "$nr_ciphers_detected" ]]; then
                         pr_svrty_highln "supported but couldn't detect a cipher and vulnerable to CVE-2015-3197 ";
                         fileout "sslv2" "NOT ok" "SSLv2 offered (NOT ok), vulnerable to CVE-2015-3197"
                    else
                         pr_svrty_critical "offered (NOT ok), also VULNERABLE to DROWN attack";
                         outln " -- $nr_ciphers_detected ciphers"
                         fileout "sslv2" "NOT ok" "SSLv2 offered (NOT ok), vulnerable to DROWN attack.  Detected ciphers: $nr_ciphers_detected"
                    fi
                    ret=1
               fi ;;
     esac
     pr_off
     debugme outln

     close_socket
     TMPFILE=$SOCK_REPLY_FILE
     tmpfile_handle $FUNCNAME.dd
     return $ret
}


# ARG1: TLS version low byte (00: SSLv3,  01: TLS 1.0,  02: TLS 1.1,  03: TLS 1.2)
# ARG2: CIPHER_SUITES string
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
     local extension_session_ticket extension_next_protocol extensions_ecc extension_padding

     code2network "$2"             # convert CIPHER_SUITES
     cipher_suites="$NW_STR"       # we don't have the leading \x here so string length is two byte less, see next

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

          # Supported Elliptic Curves Extension and Supported Point Formats Extension.
          extensions_ecc="
          00, 0a,                    # Type: Supported Elliptic Curves , see RFC 4492
          00, 3e, 00, 3c,            # lengths
          00, 01, 00, 02, 00, 03, 00, 04, 00, 05, 00, 06, 00, 07, 00, 08,
          00, 09, 00, 0a, 00, 0b, 00, 0c, 00, 0d, 00, 0e, 00, 0f, 00, 10,
          00, 11, 00, 12, 00, 13, 00, 14, 00, 15, 00, 16, 00, 17, 00, 18,
          00, 19, 00, 1a, 00, 1b, 00, 1c, 00, 1d, 00, 1e,
          00, 0b,                    # Type: Supported Point Formats , see RFC 4492 
          00, 02,                    # len
          01, 00"
          
          all_extensions="
           00, 00                  # extension server_name
          ,00, $len_sni_ext        # length SNI EXT
          ,00, $len_sni_listlen    # server_name list_length
          ,00                      # server_name type (hostname)
          ,00, $len_servername_hex # server_name length. We assume len(hostname) < FF - 9
          ,$servername_hexstr      # server_name target
          ,$extension_heartbeat
          ,$extension_session_ticket
          ,$extension_next_protocol"

          # RFC 5246 says that clients MUST NOT offer the signature algorithms
          # extension if they are offering TLS versions prior to 1.2.
          if [[ "0x$tls_low_byte" -ge "0x03" ]]; then
               all_extensions="$all_extensions
               ,$extension_signature_algorithms"
          fi

          if $ecc_cipher_suite_found; then
               all_extensions="$all_extensions
               ,$extensions_ecc"
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
          if [[ $len_all -ge 256 ]] && [[ $len_all -le 511 ]]; then
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
          len2twobytes $(printf "%02x\n" $((0x$len_ciph_suites + 0x27)))
     else
          len2twobytes $(printf "%02x\n" $((0x$len_ciph_suites + 0x27 + 0x$len_extension_hex + 0x2)))
     fi
     len_client_hello_word="$LEN_STR"
     #[[ $DEBUG -ge 3 ]] && echo $len_client_hello_word

     if [[ "$tls_low_byte" == "00" ]]; then
          len2twobytes $(printf "%02x\n" $((0x$len_ciph_suites + 0x2b)))
     else
          len2twobytes $(printf "%02x\n" $((0x$len_ciph_suites + 0x2b + 0x$len_extension_hex + 0x2)))
     fi
     len_all_word="$LEN_STR"
     #[[ $DEBUG -ge 3 ]] && echo $len_all_word

     # if we have SSLv3, the first occurence of TLS protocol -- record layer -- is SSLv3, otherwise TLS 1.0
     [[ $tls_low_byte == "00" ]] && tls_word_reclayer="03, 00"

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
     ,01                      # Compression methods length
     ,00"                     # Compression method (x00 for NULL)

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
tls_sockets() {
     local -i ret=0
     local -i save=0
     local lines
     local tls_low_byte
     local cipher_list_2send

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
     socksend_tls_clienthello "$tls_low_byte" "$cipher_list_2send"
     ret=$?                             # 6 means opening socket didn't succeed, e.g. timeout

     # if sending didn't succeed we don't bother
     if [[ $ret -eq 0 ]]; then
          sockread_serverhello 32768
          TLS_NOW=$(LC_ALL=C date "+%s")
          debugme outln "reading server hello..."
          if [[ "$DEBUG" -ge 4 ]]; then
               hexdump -C $SOCK_REPLY_FILE | head -6
               echo
          fi

          parse_tls_serverhello "$SOCK_REPLY_FILE"
          save=$?

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
          debugme "stuck on sending: $ret"
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
     [[ $VULN_COUNT -le $VULN_THRESHLD ]] && outln && pr_headlineln " Testing for heartbleed vulnerability " && outln
     pr_bold " Heartbleed"; out " (CVE-2014-0160)                "

     [[ -z "$TLS_EXTENSIONS" ]] && determine_tls_extensions
     if ! grep -q heartbeat <<< "$TLS_EXTENSIONS"; then
          pr_done_best "not vulnerable (OK)"
          outln " (no heartbeat extension)"
          fileout "heartbleed" "OK" "Heartbleed (CVE-2014-0160): not vulnerable (OK) (no heartbeat extension)"
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

     debugme outln "\nsending client hello (TLS version $tls_hexcode)"
     socksend "$client_hello" 1

     debugme outln "\nreading server hello"
     sockread 32768
     if [[ $DEBUG -ge 4 ]]; then
          echo "$SOCKREPLY" | "${HEXDUMPVIEW[@]}" | head -20
          outln "[...]"
          outln "\nsending payload with TLS version $tls_hexcode:"
     fi

     socksend "$heartbleed_payload" 1
     sockread 16384 $HEARTBLEED_MAX_WAITSOCK
     retval=$?

     if [[ $DEBUG -ge 3 ]]; then
          outln "\nheartbleed reply: "
          echo "$SOCKREPLY" | "${HEXDUMPVIEW[@]}"
          outln
     fi

     lines_returned=$(echo "$SOCKREPLY" | "${HEXDUMP[@]}" | wc -l | sed 's/ //g')
     if [[ $lines_returned -gt 1 ]]; then
          pr_svrty_critical "VULNERABLE (NOT ok)"
          if [[ $retval -eq 3 ]]; then
               fileout "heartbleed" "NOT ok" "Heartbleed (CVE-2014-0160): VULNERABLE (NOT ok) (timed out)"
          else
               fileout "heartbleed" "NOT ok" "Heartbleed (CVE-2014-0160): VULNERABLE (NOT ok)"
          fi
          ret=1
     else
          pr_done_best "not vulnerable (OK)"
          if [[ $retval -eq 3 ]]; then
               fileout "heartbleed" "OK" "Heartbleed (CVE-2014-0160): not vulnerable (OK) (timed out)"
          else
               fileout "heartbleed" "OK" "Heartbleed (CVE-2014-0160): not vulnerable (OK)"
          fi
          ret=0
     fi
     [[ $retval -eq 3 ]] && out " (timed out)"
     outln

     close_socket
     tmpfile_handle $FUNCNAME.txt
     return $ret
}

# helper function
ok_ids(){
     pr_done_bestln "\n ok -- something resetted our ccs packets"
     return 0
}

#FIXME: At a certain point heartbleed and ccs needs to be changed and make use of code2network using a file, then tls_sockets
run_ccs_injection(){
     # see https://www.openssl.org/news/secadv_20140605.txt
     # mainly adapted from Ramon de C Valle's C code from https://gist.github.com/rcvalle/71f4b027d61a78c42607
     [[ $VULN_COUNT -le $VULN_THRESHLD ]] && outln && pr_headlineln " Testing for CCS injection vulnerability " && outln
     pr_bold " CCS"; out " (CVE-2014-0224)                       "

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
     sockread 32768
     if [[ $DEBUG -ge 4 ]]; then
          echo "$SOCKREPLY" | "${HEXDUMPVIEW[@]}" | head -20
          outln "[...]"
          outln "\npayload #1 with TLS version $tls_hexcode:"
     fi

# ... and then send the a change cipher spec message
     socksend "$ccs_message" 1 || ok_ids
     sockread 2048 $CCS_MAX_WAITSOCK
     if [[ $DEBUG -ge 3 ]]; then
          outln "\n1st reply: "
          out "$SOCKREPLY" | "${HEXDUMPVIEW[@]}" | head -20
# ok:      15 | 0301    |  02 | 02 | 0a
#       ALERT | TLS 1.0 | Length=2 | Unexpected Message (0a)
#    or just timed out
          outln
          outln "payload #2 with TLS version $tls_hexcode:"
     fi

     socksend "$ccs_message" 2 || ok_ids
     sockread 2048 $CCS_MAX_WAITSOCK
     retval=$?

     if [[ $DEBUG -ge 3 ]]; then
          outln "\n2nd reply: "
          printf -- "$SOCKREPLY" | "${HEXDUMPVIEW[@]}"
# not ok:  15 | 0301    | 02 | 02  | 15
#       ALERT | TLS 1.0 | Length=2 | Decryption failed (21)
# ok:  0a or nothing: ==> RST
          outln
     fi

     byte6=$(echo "$SOCKREPLY" | "${HEXDUMPPLAIN[@]}" | sed 's/^..........//')
     lines=$(echo "$SOCKREPLY" | "${HEXDUMP[@]}" | count_lines )
     debugme echo "lines: $lines, byte6: $byte6"

     if [[ "$byte6" == "0a" ]] || [[ "$lines" -gt 1 ]]; then
          pr_done_best "not vulnerable (OK)"
          if [[ $retval -eq 3 ]]; then
               fileout "ccs" "OK" "CCS (CVE-2014-0224): not vulnerable (OK) (timed out)"
          else
               fileout "ccs" "OK" "CCS (CVE-2014-0224): not vulnerable (OK)"
          fi
          ret=0
     else
          pr_svrty_critical "VULNERABLE (NOT ok)"
          if [[ $retval -eq 3 ]]; then
               fileout "ccs" "NOT ok" "CCS (CVE-2014-0224): VULNERABLE (NOT ok) (timed out)"
          else
               fileout "ccs" "NOT ok" "CCS (CVE-2014-0224): VULNERABLE (NOT ok)"
          fi
          ret=1
     fi
     [[ $retval -eq 3 ]] && out " (timed out)"
     outln

     close_socket
     tmpfile_handle $FUNCNAME.txt
     return $ret
}

run_renego() {
# no SNI here. Not needed as there won't be two different SSL stacks for one IP
     local legacycmd=""
     local insecure_renogo_str="Secure Renegotiation IS NOT"
     local sec_renego sec_client_renego

     [[ $VULN_COUNT -le $VULN_THRESHLD ]] && outln && pr_headlineln " Testing for Renegotiation vulnerabilities " && outln

     pr_bold " Secure Renegotiation "; out "(CVE-2009-3555)      "    # and RFC5746, OSVDB 59968-59974
                                                                      # community.qualys.com/blogs/securitylabs/2009/11/05/ssl-and-tls-authentication-gap-vulnerability-discovered
     $OPENSSL s_client $OPTIMAL_PROTO $STARTTLS $BUGS -connect $NODEIP:$PORT $SNI $PROXY 2>&1 </dev/null >$TMPFILE 2>$ERRFILE
     if sclient_connect_successful $? $TMPFILE; then
          grep -iaq "$insecure_renogo_str" $TMPFILE
          sec_renego=$?                                                    # 0= Secure Renegotiation IS NOT supported
#FIXME: didn't occur to me yet but why not also to check on "Secure Renegotiation IS supported"
          case $sec_renego in
               0)
                    pr_svrty_criticalln "VULNERABLE (NOT ok)"
                    fileout "secure_renego" "NOT ok" "Secure Renegotiation (CVE-2009-3555) : VULNERABLE (NOT ok)"
                    ;;
               1)
                    pr_done_bestln "not vulnerable (OK)"
                    fileout "secure_renego" "OK" "Secure Renegotiation (CVE-2009-3555) : not vulnerable (OK)"
                    ;;
               *)
                    pr_warningln "FIXME (bug): $sec_renego"
                    fileout "secure_renego" "WARN" "Secure Renegotiation (CVE-2009-3555) : FIXME (bug) $sec_renego"
                    ;;
          esac
     else
          pr_warningln "handshake didn't succeed"
          fileout "secure_renego" "WARN" "Secure Renegotiation (CVE-2009-3555) : handshake didn't succeed"
     fi

     pr_bold " Secure Client-Initiated Renegotiation     "  # RFC 5746
     # see: https://community.qualys.com/blogs/securitylabs/2011/10/31/tls-renegotiation-and-denial-of-service-attacks
     #      http://blog.ivanristic.com/2009/12/testing-for-ssl-renegotiation.html -- head/get doesn't seem to be needed though
     case "$OSSL_VER" in
          0.9.8*)             # we need this for Mac OSX unfortunately
               case "$OSSL_VER_APPENDIX" in
                    [a-l])
                         local_problem_ln "$OPENSSL cannot test this secure renegotiation vulnerability"
                         fileout "sec_client_renego" "WARN" "Secure Client-Initiated Renegotiation : $OPENSSL cannot test this secure renegotiation vulnerability"
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
          echo R | $OPENSSL s_client $OPTIMAL_PROTO $BUGS $legacycmd $STARTTLS -msg -connect $NODEIP:$PORT $SNI $PROXY >$TMPFILE 2>>$ERRFILE &
          wait_kill $! $HEADER_MAXSLEEP
          if [[ $? -eq 3 ]]; then
               pr_done_good "likely not vulnerable (OK)"; outln " (timed out)"       # it hung
               fileout "sec_client_renego" "OK" "Secure Client-Initiated Renegotiation : likely not vulnerable (OK) (timed out)"
               sec_client_renego=1
          else
               # second try in the foreground as we are sure now it won't hang
               echo R | $OPENSSL s_client $legacycmd $STARTTLS $BUGS -msg -connect $NODEIP:$PORT $SNI $PROXY >$TMPFILE 2>>$ERRFILE
               sec_client_renego=$?                                                  # 0=client is renegotiating & doesn't return an error --> vuln!
               case "$sec_client_renego" in
                    0)
                         pr_svrty_high "VULNERABLE (NOT ok)"; outln ", DoS threat"
                         fileout "sec_client_renego" "NOT ok" "Secure Client-Initiated Renegotiation : VULNERABLE (NOT ok), DoS threat"
                         ;;
                    1)
                         pr_done_goodln "not vulnerable (OK)"
                         fileout "sec_client_renego" "OK" "Secure Client-Initiated Renegotiation : not vulnerable (OK)"
                         ;;
                    *)
                         pr_warningln "FIXME (bug): $sec_client_renego"
                         fileout "sec_client_renego" "WARN" "Secure Client-Initiated Renegotiation : FIXME (bug) $sec_client_renego - Please report"
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
     local -i ret=0
     local addcmd=""
     # in a nutshell: don't offer TLS/SPDY compression on the server side
     # This tests for CRIME Vulnerability (www.ekoparty.org/2012/juliano-rizzo.php) on HTTPS, not SPDY (yet)
     # Please note that it is an attack where you need client side control, so in regular situations this
     # means anyway "game over", w/wo CRIME
     # www.h-online.com/security/news/item/Vulnerability-in-SSL-encryption-is-barely-exploitable-1708604.html

     [[ $VULN_COUNT -le $VULN_THRESHLD ]] && outln && pr_headlineln " Testing for CRIME vulnerability " && outln
     pr_bold " CRIME, TLS " ; out "(CVE-2012-4929)                "

     # first we need to test whether OpenSSL binary has zlib support
     $OPENSSL zlib -e -a -in /dev/stdin &>/dev/stdout </dev/null | grep -q zlib
     if [[ $? -eq 0 ]]; then
          local_problem_ln "$OPENSSL lacks zlib support"
          fileout "crime" "WARN" "CRIME, TLS (CVE-2012-4929) : Not tested. $OPENSSL lacks zlib support"
          return 7
     fi

     [[ "$OSSL_VER" == "0.9.8"* ]] && addcmd="-no_ssl2"
     $OPENSSL s_client $OPTIMAL_PROTO $BUGS $addcmd $STARTTLS -connect $NODEIP:$PORT $PROXY $SNI </dev/null &>$TMPFILE
     if grep -a Compression $TMPFILE | grep -aq NONE >/dev/null; then
          pr_done_good "not vulnerable (OK)"
          if [[ $SERVICE != "HTTP" ]] && ! $CLIENT_AUTH;  then
               out " (not using HTTP anyway)"
               fileout "crime" "OK" "CRIME, TLS (CVE-2012-4929) : Not vulnerable (OK) (not using HTTP anyway)"
          else
               fileout "crime" "OK" "CRIME, TLS (CVE-2012-4929) : Not vulnerable (OK)"
          fi
          ret=0
     else
          if [[ $SERVICE == "HTTP" ]]; then
               pr_svrty_high "VULNERABLE (NOT ok)"
               fileout "crime" "NOT ok" "CRIME, TLS (CVE-2012-4929) : VULNERABLE (NOT ok)"
          else
               pr_svrty_medium "VULNERABLE but not using HTTP: probably no exploit known"
               fileout "crime" "MEDIUM" "CRIME, TLS (CVE-2012-4929) : VULNERABLE (WARN), but not using HTTP: probably no exploit known"
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

#    $OPENSSL s_client -help 2>&1 | grep -qw nextprotoneg
#    if [[ $? -eq 0 ]]; then
#         $OPENSSL s_client -host $NODE -port $PORT -nextprotoneg $NPN_PROTOs  $SNI </dev/null 2>/dev/null >$TMPFILE
#         if [[ $? -eq 0 ]]; then
#              echo
#              pr_bold "CRIME Vulnerability, SPDY " ; outln "(CVE-2012-4929): "

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
     local header
     local -i ret=0
     local -i was_killed=0
     local referer useragent
     local url
     local spaces="                                          "
     local disclaimer=""
     local when_makesense=" Can be ignored for static pages or if no secrets in the page"

     [[ $SERVICE != "HTTP" ]] && return 7

     [[ $VULN_COUNT -le $VULN_THRESHLD ]] && outln && pr_headlineln " Testing for BREACH (HTTP compression) vulnerability " && outln
     pr_bold " BREACH"; out " (CVE-2013-3587)                    "

     url="$1"
     [[ -z "$url" ]] && url="/"
     disclaimer=" - only supplied \"$url\" tested"

     referer="https://google.com/"
     [[ "$NODE" =~ google ]] && referer="https://yandex.ru/" # otherwise we have a false positive for google.com

     useragent="$UA_STD"
     $SNEAKY && useragent="$UA_SNEAKY"

     printf "GET $url HTTP/1.1\r\nHost: $NODE\r\nUser-Agent: $useragent\r\nReferer: $referer\r\nConnection: Close\r\nAccept-encoding: gzip,deflate,compress\r\nAccept: text/*\r\n\r\n" | $OPENSSL s_client $OPTIMAL_PROTO $BUGS -quiet -ign_eof -connect $NODEIP:$PORT $PROXY $SNI 1>$TMPFILE 2>$ERRFILE &
     wait_kill $! $HEADER_MAXSLEEP
     was_killed=$?                           # !=0 was killed
     result=$(awk '/^Content-Encoding/ { print $2 }' $TMPFILE)
     result=$(strip_lf "$result")
     debugme grep '^Content-Encoding' $TMPFILE
     if [[ ! -s $TMPFILE ]]; then
          pr_warning "failed (HTTP header request stalled"
          if [[ $was_killed -ne 0 ]]; then
               pr_warning " and was terminated"
               fileout "breach" "WARN" "BREACH (CVE-2013-3587) : Test failed (HTTP request stalled and was terminated)"
          else
               fileout "breach" "WARN" "BREACH (CVE-2013-3587) : Test failed (HTTP request stalled)"
          fi
          pr_warningln ") "
          ret=3
     elif [[ -z $result ]]; then
          pr_done_best "no HTTP compression (OK) "
          outln "$disclaimer"
          fileout "breach" "OK" "BREACH (CVE-2013-3587) : no HTTP compression (OK) $disclaimer"
          ret=0
     else
          pr_svrty_high "potentially NOT ok, uses $result HTTP compression."
          outln "$disclaimer"
          outln "$spaces$when_makesense"
          fileout "breach" "NOT ok" "BREACH (CVE-2013-3587) : potentially VULNERABLE, uses $result HTTP compression. $disclaimer ($when_makesense)"
          ret=1
     fi
     # Any URL can be vulnerable. I am testing now only the given URL!

     tmpfile_handle $FUNCNAME.txt
     return $ret
}

# Padding Oracle On Downgraded Legacy Encryption, in a nutshell: don't use CBC Ciphers in SSLv3
run_ssl_poodle() {
     local -i sclient_success=0
     local cbc_ciphers="ECDHE-RSA-AES256-SHA:ECDHE-ECDSA-AES256-SHA:SRP-DSS-AES-256-CBC-SHA:SRP-RSA-AES-256-CBC-SHA:SRP-AES-256-CBC-SHA:DHE-PSK-AES256-CBC-SHA:DHE-RSA-AES256-SHA:DHE-DSS-AES256-SHA:DH-RSA-AES256-SHA:DH-DSS-AES256-SHA:DHE-RSA-CAMELLIA256-SHA:DHE-DSS-CAMELLIA256-SHA:DH-RSA-CAMELLIA256-SHA:DH-DSS-CAMELLIA256-SHA:AECDH-AES256-SHA:ADH-AES256-SHA:ADH-CAMELLIA256-SHA:ECDH-RSA-AES256-SHA:ECDH-ECDSA-AES256-SHA:AES256-SHA:ECDHE-PSK-AES256-CBC-SHA:CAMELLIA256-SHA:RSA-PSK-AES256-CBC-SHA:PSK-AES256-CBC-SHA:ECDHE-RSA-AES128-SHA:ECDHE-ECDSA-AES128-SHA:SRP-DSS-AES-128-CBC-SHA:SRP-RSA-AES-128-CBC-SHA:SRP-AES-128-CBC-SHA:DHE-RSA-AES128-SHA:DHE-DSS-AES128-SHA:DH-RSA-AES128-SHA:DH-DSS-AES128-SHA:DHE-RSA-SEED-SHA:DHE-DSS-SEED-SHA:DH-RSA-SEED-SHA:DH-DSS-SEED-SHA:DHE-RSA-CAMELLIA128-SHA:DHE-DSS-CAMELLIA128-SHA:DH-RSA-CAMELLIA128-SHA:DH-DSS-CAMELLIA128-SHA:AECDH-AES128-SHA:ADH-AES128-SHA:ADH-SEED-SHA:ADH-CAMELLIA128-SHA:ECDH-RSA-AES128-SHA:ECDH-ECDSA-AES128-SHA:AES128-SHA:ECDHE-PSK-AES128-CBC-SHA:DHE-PSK-AES128-CBC-SHA:SEED-SHA:CAMELLIA128-SHA:IDEA-CBC-SHA:IDEA-CBC-MD5:RC2-CBC-MD5:RSA-PSK-AES128-CBC-SHA:PSK-AES128-CBC-SHA:KRB5-IDEA-CBC-SHA:KRB5-IDEA-CBC-MD5:ECDHE-RSA-DES-CBC3-SHA:ECDHE-ECDSA-DES-CBC3-SHA:SRP-DSS-3DES-EDE-CBC-SHA:SRP-RSA-3DES-EDE-CBC-SHA:SRP-3DES-EDE-CBC-SHA:EDH-RSA-DES-CBC3-SHA:EDH-DSS-DES-CBC3-SHA:DH-RSA-DES-CBC3-SHA:DH-DSS-DES-CBC3-SHA:AECDH-DES-CBC3-SHA:ADH-DES-CBC3-SHA:ECDH-RSA-DES-CBC3-SHA:ECDH-ECDSA-DES-CBC3-SHA:DES-CBC3-SHA:DES-CBC3-MD5:RSA-PSK-3DES-EDE-CBC-SHA:PSK-3DES-EDE-CBC-SHA:KRB5-DES-CBC3-SHA:KRB5-DES-CBC3-MD5:ECDHE-PSK-3DES-EDE-CBC-SHA:DHE-PSK-3DES-EDE-CBC-SHA:EXP1024-DHE-DSS-DES-CBC-SHA:EDH-RSA-DES-CBC-SHA:EDH-DSS-DES-CBC-SHA:DH-RSA-DES-CBC-SHA:DH-DSS-DES-CBC-SHA:ADH-DES-CBC-SHA:EXP1024-DES-CBC-SHA:DES-CBC-SHA:DES-CBC-MD5:KRB5-DES-CBC-SHA:KRB5-DES-CBC-MD5:EXP-EDH-RSA-DES-CBC-SHA:EXP-EDH-DSS-DES-CBC-SHA:EXP-ADH-DES-CBC-SHA:EXP-DES-CBC-SHA:EXP-RC2-CBC-MD5:EXP-RC2-CBC-MD5:EXP-KRB5-RC2-CBC-SHA:EXP-KRB5-DES-CBC-SHA:EXP-KRB5-RC2-CBC-MD5:EXP-KRB5-DES-CBC-MD5"

     [[ $VULN_COUNT -le $VULN_THRESHLD ]] && outln && pr_headlineln " Testing for SSLv3 POODLE (Padding Oracle On Downgraded Legacy Encryption) " && outln
     pr_bold " POODLE, SSL"; out " (CVE-2014-3566)               "
     cbc_ciphers=$(actually_supported_ciphers $cbc_ciphers)

     debugme echo $cbc_ciphers
     $OPENSSL s_client -ssl3 $STARTTLS $BUGS -cipher $cbc_ciphers -connect $NODEIP:$PORT $PROXY $SNI >$TMPFILE 2>$ERRFILE </dev/null
     sclient_connect_successful $? $TMPFILE
     sclient_success=$?
     [[ "$DEBUG" -eq 2 ]] && egrep -q "error|failure" $ERRFILE | egrep -av "unable to get local|verify error"
     if [[ $sclient_success -eq 0 ]]; then
          pr_svrty_high "VULNERABLE (NOT ok)"; out ", uses SSLv3+CBC (check TLS_FALLBACK_SCSV mitigation below)"
          fileout "poodle_ssl" "NOT ok" "POODLE, SSL (CVE-2014-3566) : VULNERABLE (NOT ok), uses SSLv3+CBC (check if TLS_FALLBACK_SCSV mitigation is used)"
     else
          pr_done_best "not vulnerable (OK)"
          fileout "poodle_ssl" "OK" "POODLE, SSL (CVE-2014-3566) : not vulnerable (OK)"
     fi
     outln
     tmpfile_handle $FUNCNAME.txt
     return $sclient_success
}

# for appliance which use padding, no fallback needed
run_tls_poodle() {
     pr_bold " POODLE, TLS"; out " (CVE-2014-8730), experimental "
     #FIXME
     echo "#FIXME"
     fileout "poodle_tls" "WARN" "POODLE, TLS (CVE-2014-8730) : Not tested. Not yet implemented #FIXME"
     return 7
}

run_tls_fallback_scsv() {
     local -i ret=0

     [[ $VULN_COUNT -le $VULN_THRESHLD ]] && outln && pr_headlineln " Testing for TLS_FALLBACK_SCSV Protection " && outln
     pr_bold " TLS_FALLBACK_SCSV"; out " (RFC 7507), experim.    "
     # This isn't a vulnerability check per se, but checks for the existence of
     # the countermeasure to protect against protocol downgrade attacks.

     # First check we have support for TLS_FALLBACK_SCSV in our local OpenSSL
     if ! $OPENSSL s_client -help 2>&1 | grep -q "\-fallback_scsv"; then
          local_problem_ln "$OPENSSL lacks TLS_FALLBACK_SCSV support"
          return 4
     fi
     #TODO: this need some tuning: a) if one protocol is supported only it has practcally no value (theoretical it's interesting though)
     # b) for IIS6 + openssl 1.0.2 this won't work
     # c) best to make sure that we hit a specific protocol, see https://alpacapowered.wordpress.com/2014/10/20/ssl-poodle-attack-what-is-this-scsv-thingy/
     # d) minor: we should do "-state" here

     # first: make sure we have tls1_2:
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
                    fileout "fallback_scsv" "OK" "TLS_FALLBACK_SCSV (RFC 7507) (experimental) : Downgrade attack prevention supported (OK)"
                    ret=0
               elif grep -qa "alert handshake failure" "$TMPFILE"; then
                    # see RFC 7507, https://github.com/drwetter/testssl.sh/issues/121
                    pr_svrty_medium "\"handshake failure\" instead of \"inappropriate fallback\""
                    fileout "fallback_scsv" "MEDIUM" "TLS_FALLBACK_SCSV (RFC 7507) (experimental) : \"handshake failure\" instead of \"inappropriate fallback\" (likely: warning)"
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
     local -i nr_supported_ciphers=0
     # with correct build it should list these 7 ciphers (plus the two latter as SSLv2 ciphers):
     local exportrsa_cipher_list="EXP1024-DES-CBC-SHA:EXP1024-RC4-SHA:EXP-EDH-RSA-DES-CBC-SHA:EXP-DH-RSA-DES-CBC-SHA:EXP-DES-CBC-SHA:EXP-RC2-CBC-MD5:EXP-RC2-CBC-MD5:EXP-RC4-MD5:EXP-RC4-MD5"
     local addtl_warning=""

     [[ $VULN_COUNT -le $VULN_THRESHLD ]] && outln && pr_headlineln " Testing for FREAK attack " && outln
     pr_bold " FREAK"; out " (CVE-2015-0204)                     "

     nr_supported_ciphers=$(count_ciphers $(actually_supported_ciphers $exportrsa_cipher_list))
     #echo "========= ${PIPESTATUS[*]}

     case $nr_supported_ciphers in
          0)
               local_problem_ln "$OPENSSL doesn't have any EXPORT RSA ciphers configured"
               fileout "freak" "WARN" "FREAK (CVE-2015-0204) : Not tested. $OPENSSL doesn't have any EXPORT RSA ciphers configured"
               return 7
               ;;
          1|2|3)
               addtl_warning=" ($magenta""tested only with $nr_supported_ciphers out of 9 ciphers only!$off)" ;;
          8|9|10|11)
               addtl_warning="" ;;
          4|5|6|7)
               addtl_warning=" (tested with $nr_supported_ciphers/9 ciphers)" ;;
     esac
     $OPENSSL s_client $STARTTLS $BUGS -cipher $exportrsa_cipher_list -connect $NODEIP:$PORT $PROXY $SNI >$TMPFILE 2>$ERRFILE </dev/null
     sclient_connect_successful $? $TMPFILE
     sclient_success=$?
     [[ $DEBUG -eq 2 ]] && egrep -a "error|failure" $ERRFILE | egrep -av "unable to get local|verify error"
     if [[ $sclient_success -eq 0 ]]; then
          pr_svrty_critical "VULNERABLE (NOT ok)"; out ", uses EXPORT RSA ciphers"
          fileout "freak" "NOT ok" "FREAK (CVE-2015-0204) : VULNERABLE (NOT ok), uses EXPORT RSA ciphers"
     else
          pr_done_best "not vulnerable (OK)"; out "$addtl_warning"
          fileout "freak" "OK" "FREAK (CVE-2015-0204) : not vulnerable (OK) $addtl_warning"
     fi
     outln

     debugme echo $(actually_supported_ciphers $exportrsa_cipher_list)
     debugme echo $nr_supported_ciphers

     tmpfile_handle $FUNCNAME.txt
     return $ret
}


# see https://weakdh.org/logjam.html
run_logjam() {
     local -i sclient_success=0
     local exportdhe_cipher_list="EXP1024-DHE-DSS-DES-CBC-SHA:EXP1024-DHE-DSS-RC4-SHA:EXP-EDH-RSA-DES-CBC-SHA:EXP-EDH-DSS-DES-CBC-SHA"
     local -i nr_supported_ciphers=0
     local addtl_warning=""

     [[ $VULN_COUNT -le $VULN_THRESHLD ]] && outln && pr_headlineln " Testing for LOGJAM vulnerability " && outln
     pr_bold " LOGJAM"; out " (CVE-2015-4000), experimental      "

     nr_supported_ciphers=$(count_ciphers $(actually_supported_ciphers $exportdhe_cipher_list))

     case $nr_supported_ciphers in
          0)
               local_problem_ln "$OPENSSL doesn't have any DHE EXPORT ciphers configured"
               fileout "logjam" "WARN" "LOGJAM (CVE-2015-4000) : Not tested. $OPENSSL doesn't have any DHE EXPORT ciphers configured"
               return 3
               ;;
          1|2) addtl_warning=" ($magenta""tested w/ $nr_supported_ciphers/4 ciphers only!$off)" ;;
          3)   addtl_warning=" (tested w/ $nr_supported_ciphers/4 ciphers)" ;;
          4)   ;;
     esac
     $OPENSSL s_client $STARTTLS $BUGS -cipher $exportdhe_cipher_list -connect $NODEIP:$PORT $PROXY $SNI >$TMPFILE 2>$ERRFILE </dev/null
     sclient_connect_successful $? $TMPFILE
     sclient_success=$?
     debugme egrep -a "error|failure" $ERRFILE | egrep -av "unable to get local|verify error"
     addtl_warning="$addtl_warning, common primes not checked."
     if "$HAS_DH_BITS"; then
          if ! "$do_allciphers" && ! "$do_cipher_per_proto" && "$HAS_DH_BITS"; then
               addtl_warning="$addtl_warning \"$PROG_NAME -E/-e\" spots candidates"
          else
               "$HAS_DH_BITS" && addtl_warning="$addtl_warning See below for any DH ciphers + bit size"
          fi
     fi

     if [[ $sclient_success -eq 0 ]]; then
          pr_svrty_critical "VULNERABLE (NOT ok)"; out ", uses DHE EXPORT ciphers, common primes not checked."
          fileout "logjam" "NOT ok" "LOGJAM (CVE-2015-4000) : VULNERABLE (NOT ok), uses DHE EXPORT ciphers, common primes not checked."
     else
          pr_done_best "not vulnerable (OK)"; out "$addtl_warning"
          fileout "logjam" "OK" "LOGJAM (CVE-2015-4000) : not vulnerable (OK) $addtl_warning"
     fi
     outln

     debugme echo $(actually_supported_ciphers $exportdhe_cipher_list)
     debugme echo $nr_supported_ciphers

     tmpfile_handle $FUNCNAME.txt
     return $sclient_success
}
# TODO: perfect candidate for replacement by sockets, so is freak


run_drown() {
     local nr_ciphers_detected
     local spaces="                                          "
     local cert_fingerprint_sha2=""

#FIXME: test for iexistence of RSA key exchange
     if [[ $VULN_COUNT -le $VULN_THRESHLD ]]; then
          outln
          pr_headlineln " Testing for DROWN vulnerability "
          outln
     fi
# if we want to use OPENSSL: check for < openssl 1.0.2g, openssl 1.0.1s if native openssl
     pr_bold " DROWN"; out " (2016-0800, CVE-2016-0703), exper.  "
     fd_socket 5 || return 6
     debugme outln "sending client hello... "
     socksend_sslv2_clienthello "$SSLv2_CLIENT_HELLO"
     sockread_serverhello 32768
     debugme outln "reading server hello... "
     if [[ "$DEBUG" -ge 4 ]]; then
          hexdump -C "$SOCK_REPLY_FILE" | head -6
          outln
     fi
     parse_sslv2_serverhello "$SOCK_REPLY_FILE"
     case $? in
          7) # strange reply, couldn't convert the cipher spec length to a hex number
               fixme "strange v2 reply "
               outln " (rerun with DEBUG >=2)"
               [[ $DEBUG -ge 3 ]] && hexdump -C "$SOCK_REPLY_FILE" | head -1
               ret=7
               fileout "drown" "MINOR_ERROR" "SSLv2: received a strange SSLv2 reply (rerun with DEBUG>=2)"
               ;;
          3)   # vulnerable
               lines=$(count_lines "$(hexdump -C "$SOCK_REPLY_FILE" 2>/dev/null)")
               debugme out "  ($lines lines)  "
               if [[ "$lines" -gt 1 ]]; then
                    nr_ciphers_detected=$((V2_HELLO_CIPHERSPEC_LENGTH / 3))
                    if [[ 0 -eq "$nr_ciphers_detected" ]]; then
                         pr_svrty_highln "CVE-2015-3197: SSLv2 supported but couldn't detect a cipher (NOT ok)";
                         fileout "drown" "NOT ok" "SSLv2 offered (NOT ok), CVE-2015-3197: but could not detect a cipher"
                    else
                         pr_svrty_criticalln  "vulnerable (NOT ok), SSLv2 offered with $nr_ciphers_detected ciphers";
                         fileout "drown" "NOT ok" "vulnerable (NOT ok), SSLv2 offered with $nr_ciphers_detected ciphers"
                    fi
               fi
               ret=1
               ;;
          *)   pr_done_bestln "not vulnerable on this port (OK)"
               fileout "drown" "OK" "not vulnerable to DROWN"
               outln "$spaces make sure you don't use this certificate elsewhere with SSLv2 enabled services"
               if [[ "$DEBUG" -ge 1 ]] || "$SHOW_CENSYS_LINK"; then
# not advertising it as it after 5 tries and account is needed
                    if [[ -z "$CERT_FINGERPRINT_SHA2" ]]; then
                         get_host_cert || return 7
                         cert_fingerprint_sha2="$($OPENSSL x509 -noout -in $HOSTCERT -fingerprint -sha256 2>>$ERRFILE | sed -e 's/^.*Fingerprint=//' -e 's/://g' )"
                    else
                         cert_fingerprint_sha2="$CERT_FINGERPRINT_SHA2"
                    fi
                    cert_fingerprint_sha2=${cert_fingerprint_sha2/SHA256 /}
                    outln "$spaces https://censys.io/ipv4?q=$cert_fingerprint_sha2 could help you to find out"
               fi
               ;;
     esac

     return $?
}



# Browser Exploit Against SSL/TLS: don't use CBC Ciphers in SSLv3 TLSv1.0
run_beast(){
     local hexcode dash cbc_cipher sslvers kx auth enc mac export
     local detected_proto
     local -i sclient_success=0
     local detected_cbc_ciphers=""
     local higher_proto_supported=""
     local -i sclient_success=0
     local vuln_beast=false
     local spaces="                                           "
     local cr=$'\n'
     local first=true
     local continued=false
     local cbc_cipher_list="EXP-RC2-CBC-MD5:IDEA-CBC-SHA:EXP-DES-CBC-SHA:DES-CBC-SHA:DES-CBC3-SHA:EXP-DH-DSS-DES-CBC-SHA:DH-DSS-DES-CBC-SHA:DH-DSS-DES-CBC3-SHA:EXP-DH-RSA-DES-CBC-SHA:DH-RSA-DES-CBC-SHA:DH-RSA-DES-CBC3-SHA:EXP-EDH-DSS-DES-CBC-SHA:EDH-DSS-DES-CBC-SHA:EDH-DSS-DES-CBC3-SHA:EXP-EDH-RSA-DES-CBC-SHA:EDH-RSA-DES-CBC-SHA:EDH-RSA-DES-CBC3-SHA:EXP-ADH-DES-CBC-SHA:ADH-DES-CBC-SHA:ADH-DES-CBC3-SHA:KRB5-DES-CBC-SHA:KRB5-DES-CBC3-SHA:KRB5-IDEA-CBC-SHA:KRB5-DES-CBC-MD5:KRB5-DES-CBC3-MD5:KRB5-IDEA-CBC-MD5:EXP-KRB5-DES-CBC-SHA:EXP-KRB5-RC2-CBC-SHA:EXP-KRB5-DES-CBC-MD5:EXP-KRB5-RC2-CBC-MD5:AES128-SHA:DH-DSS-AES128-SHA:DH-RSA-AES128-SHA:DHE-DSS-AES128-SHA:DHE-RSA-AES128-SHA:ADH-AES128-SHA:AES256-SHA:DH-DSS-AES256-SHA:DH-RSA-AES256-SHA:DHE-DSS-AES256-SHA:DHE-RSA-AES256-SHA:ADH-AES256-SHA:AES128-SHA256:AES256-SHA256:DH-DSS-AES128-SHA256:DH-RSA-AES128-SHA256:DHE-DSS-AES128-SHA256:CAMELLIA128-SHA:DH-DSS-CAMELLIA128-SHA:DH-RSA-CAMELLIA128-SHA:DHE-DSS-CAMELLIA128-SHA:DHE-RSA-CAMELLIA128-SHA:ADH-CAMELLIA128-SHA:EXP1024-DES-CBC-SHA:EXP1024-DHE-DSS-DES-CBC-SHA:DHE-RSA-AES128-SHA256:DH-DSS-AES256-SHA256:DH-RSA-AES256-SHA256:DHE-DSS-AES256-SHA256:DHE-RSA-AES256-SHA256:ADH-AES128-SHA256:ADH-AES256-SHA256:CAMELLIA256-SHA:DH-DSS-CAMELLIA256-SHA:DH-RSA-CAMELLIA256-SHA:DHE-DSS-CAMELLIA256-SHA:DHE-RSA-CAMELLIA256-SHA:ADH-CAMELLIA256-SHA:PSK-3DES-EDE-CBC-SHA:PSK-AES128-CBC-SHA:PSK-AES256-CBC-SHA:SEED-SHA:DH-DSS-SEED-SHA:DH-RSA-SEED-SHA:DHE-DSS-SEED-SHA:DHE-RSA-SEED-SHA:ADH-SEED-SHA:ECDH-ECDSA-DES-CBC3-SHA:ECDH-ECDSA-AES128-SHA:ECDH-ECDSA-AES256-SHA:ECDHE-ECDSA-DES-CBC3-SHA:ECDHE-ECDSA-AES128-SHA:ECDHE-ECDSA-AES256-SHA:ECDH-RSA-DES-CBC3-SHA:ECDH-RSA-AES128-SHA:ECDH-RSA-AES256-SHA:ECDHE-RSA-DES-CBC3-SHA:ECDHE-RSA-AES128-SHA:ECDHE-RSA-AES256-SHA:AECDH-DES-CBC3-SHA:AECDH-AES128-SHA:AECDH-AES256-SHA:SRP-3DES-EDE-CBC-SHA:SRP-RSA-3DES-EDE-CBC-SHA:SRP-DSS-3DES-EDE-CBC-SHA:SRP-AES-128-CBC-SHA:SRP-RSA-AES-128-CBC-SHA:SRP-DSS-AES-128-CBC-SHA:SRP-AES-256-CBC-SHA:SRP-RSA-AES-256-CBC-SHA:SRP-DSS-AES-256-CBC-SHA:ECDHE-ECDSA-AES128-SHA256:ECDHE-ECDSA-AES256-SHA384:ECDH-ECDSA-AES128-SHA256:ECDH-ECDSA-AES256-SHA384:ECDHE-RSA-AES128-SHA256:ECDHE-RSA-AES256-SHA384:ECDH-RSA-AES128-SHA256:ECDH-RSA-AES256-SHA384:RC2-CBC-MD5:EXP-RC2-CBC-MD5:IDEA-CBC-MD5:DES-CBC-MD5:DES-CBC3-MD5"

     if [[ $VULN_COUNT -le $VULN_THRESHLD ]]; then
          outln
          pr_headlineln " Testing for BEAST vulnerability "
     fi
     if [[ $VULN_COUNT -le $VULN_THRESHLD ]] || "$WIDE"; then
          outln
     fi
     pr_bold " BEAST"; out " (CVE-2011-3389)                     "
# output in wide mode if cipher doesn't exist is not ok

     >$ERRFILE

     # first determine whether it's mitigated by higher protocols
     for proto in tls1_1 tls1_2; do
          $OPENSSL s_client -state -"$proto" $STARTTLS $BUGS -connect $NODEIP:$PORT $PROXY $SNI 2>>$ERRFILE >$TMPFILE </dev/null
          if sclient_connect_successful $? $TMPFILE; then
               higher_proto_supported="$higher_proto_supported ""$(grep -aw "Protocol" $TMPFILE | sed -e 's/^.*Protocol .*://' -e 's/ //g')"
          fi
     done

     for proto in ssl3 tls1; do
          $OPENSSL s_client -"$proto" $STARTTLS $BUGS -connect $NODEIP:$PORT $PROXY $SNI >$TMPFILE 2>>$ERRFILE </dev/null
          if ! sclient_connect_successful $? $TMPFILE; then      # protocol supported?
               if "$continued"; then                             # second round: we hit TLS1
                    pr_done_goodln "no SSL3 or TLS1 (OK)"
                    fileout "beast" "OK" "BEAST (CVE-2011-3389) : not vulnerable (OK) no SSL3 or TLS1"
                    return 0
               else                # protocol not succeeded but it's the first time
                    continued=true
                    continue       # protocol not supported, so we do not need to check each cipher with that protocol
                    "$WIDE" && outln
               fi
          fi # protocol succeeded


          # now we test in one shot with the precompiled ciphers
          $OPENSSL s_client -"$proto" -cipher "$cbc_cipher_list" $STARTTLS $BUGS -connect $NODEIP:$PORT $PROXY $SNI >$TMPFILE 2>>$ERRFILE </dev/null
          sclient_connect_successful $? $TMPFILE || continue

          if "$WIDE"; then
               out "\n "; pr_underline "$(toupper $proto):\n";
               if "$first"; then
                    neat_header         # NOT_THAT_NICE: we display the header also if in the end no cbc cipher is available on the client side
               fi
          fi
          for ciph in $(colon_to_spaces "$cbc_cipher_list"); do
               read hexcode dash cbc_cipher sslvers kx auth enc mac < <($OPENSSL ciphers -V "$ciph" 2>>$ERRFILE)        # -V doesn't work with openssl < 1.0
               #                                                    ^^^^^ process substitution as shopt will either segfault or doesn't work with old bash versions
               $OPENSSL s_client -cipher "$cbc_cipher" -"$proto" $STARTTLS $BUGS -connect $NODEIP:$PORT $PROXY $SNI >$TMPFILE 2>>$ERRFILE </dev/null
               sclient_connect_successful $? $TMPFILE
               sclient_success=$?
               if [[ $sclient_success -eq 0 ]]; then
                    vuln_beast=true 
                    "$WIDE" && first=false
               fi
               if "$WIDE"; then
                    normalize_ciphercode "$hexcode"
                    if "$SHOW_EACH_C"; then
                         [[ -z "$hexcode" ]] && continue
                         neat_list "$HEXC" "$cbc_cipher" "$kx" "$enc"      #why this is needed?
                         if [[ $sclient_success -eq 0 ]]; then
                              if [[ -n "$higher_proto_supported" ]]; then
                                   pr_svrty_minorln "available" 
                              else
                                   pr_svrty_mediumln "available"
                              fi

                         else
                              outln "not a/v"
                         fi
                    else
                         if [[ $sclient_success -eq 0 ]]; then
                              neat_list "$HEXC" "$cbc_cipher" "$kx" "$enc"
                              outln
                         fi
                    fi
               else # short display:
                    if [[ $sclient_success -eq 0 ]]; then
                         detected_cbc_ciphers="$detected_cbc_ciphers ""$(grep -aw "Cipher" $TMPFILE | egrep -avw "New|is" | sed -e 's/^.*Cipher.*://' -e 's/ //g')"
                         vuln_beast=true
                    fi
               fi
          done

          if ! "$WIDE"; then
               if [[ -n "$detected_cbc_ciphers" ]]; then
                    detected_cbc_ciphers=$(echo "$detected_cbc_ciphers" | \
                         sed -e "s/ /\\${cr}      ${spaces}/12" \
                             -e "s/ /\\${cr}      ${spaces}/9" \
                             -e "s/ /\\${cr}      ${spaces}/6" \
                             -e "s/ /\\${cr}      ${spaces}/3")
                    fileout "cbc_$proto" "MEDIUM" "BEAST (CVE-2011-3389) : CBC ciphers for $(toupper $proto): $detected_cbc_ciphers"
                    ! "$first" && out "$spaces"
                    out "$(toupper $proto):"
                    [[ -n "$higher_proto_supported" ]] && \
                         pr_svrty_minorln "$detected_cbc_ciphers" || \
                         pr_svrty_mediumln "$detected_cbc_ciphers"
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
                    fileout "cbc_$proto" "OK" "BEAST (CVE-2011-3389) : No CBC ciphers for $(toupper $proto) (OK)"
               fi
          fi
     done  # for proto in ssl3 tls1

     if "$vuln_beast"; then
          if [[ -n "$higher_proto_supported" ]]; then
               if "$WIDE"; then
                    outln
                    # NOT ok seems too harsh for me if we have TLS >1.0
                    pr_svrty_minor "VULNERABLE"
                    outln " -- but also supports higher protocols (possible mitigation):$higher_proto_supported"
               else
                    out "$spaces"
                    pr_svrty_minor "VULNERABLE"
                    outln " -- but also supports higher protocols (possible mitigation):$higher_proto_supported"
               fi
               fileout "beast" "MINOR" "BEAST (CVE-2011-3389) : VULNERABLE -- but also supports higher protocols (possible mitigation):$higher_proto_supported"
          else
               if "$WIDE"; then
                    outln
               else
                    out "$spaces"
               fi
               pr_svrty_medium "VULNERABLE"
               outln " -- and no higher protocols as mitigation supported"
               fileout "beast" "MEDIUM" "BEAST (CVE-2011-3389) : VULNERABLE -- and no higher protocols as mitigation supported"
          fi
     fi
     "$first" && ! "$vuln_beast" && pr_done_goodln "no CBC ciphers found for any protocol (OK)"

     tmpfile_handle $FUNCNAME.txt
     return 0
}

run_lucky13() {
#FIXME: to do . CVE-2013-0169
# in a nutshell: don't offer CBC suites (again). MAC as a fix for padding oracles is not enough. Best: TLS v1.2+ AES GCM
     echo "FIXME"
     fileout "lucky13" "WARN" "LUCKY13 (CVE-2013-0169) : No tested. Not implemented. #FIXME"
     return 1
}


# https://tools.ietf.org/html/rfc7465    REQUIRES that TLS clients and servers NEVER negotiate the use of RC4 cipher suites!
# https://en.wikipedia.org/wiki/Transport_Layer_Security#RC4_attacks
# http://blog.cryptographyengineering.com/2013/03/attack-of-week-rc4-is-kind-of-broken-in.html
run_rc4() {
     local -i rc4_offered=0
     local -i sclient_success
     local hexcode dash rc4_cipher sslvers kx auth enc mac export
     local rc4_ciphers_list="ECDHE-RSA-RC4-SHA:ECDHE-ECDSA-RC4-SHA:DHE-DSS-RC4-SHA:AECDH-RC4-SHA:ADH-RC4-MD5:ECDH-RSA-RC4-SHA:ECDH-ECDSA-RC4-SHA:RC4-SHA:RC4-MD5:RC4-MD5:RSA-PSK-RC4-SHA:PSK-RC4-SHA:KRB5-RC4-SHA:KRB5-RC4-MD5:RC4-64-MD5:EXP1024-DHE-DSS-RC4-SHA:EXP1024-RC4-SHA:EXP-ADH-RC4-MD5:EXP-RC4-MD5:EXP-RC4-MD5:EXP-KRB5-RC4-SHA:EXP-KRB5-RC4-MD5"
     local rc4_detected=""
     local available=""

     if [[ $VULN_COUNT -le $VULN_THRESHLD ]]; then
          outln
          pr_headlineln " Checking for vulnerable RC4 Ciphers "
     fi
     if [[ $VULN_COUNT -le $VULN_THRESHLD ]] || "$WIDE"; then
          outln
     fi
     pr_bold " RC4"; out " (CVE-2013-2566, CVE-2015-2808)        "

     $OPENSSL s_client -cipher $rc4_ciphers_list $STARTTLS $BUGS -connect $NODEIP:$PORT $PROXY $SNI >$TMPFILE 2>$ERRFILE </dev/null
     if sclient_connect_successful $? $TMPFILE; then
          "$WIDE" || pr_svrty_high "VULNERABLE (NOT ok): "
          rc4_offered=1
          if "$WIDE"; then
               outln "\n"
               neat_header
          fi
          while read hexcode dash rc4_cipher sslvers kx auth enc mac; do
               $OPENSSL s_client -cipher $rc4_cipher $STARTTLS $BUGS -connect $NODEIP:$PORT $PROXY $SNI </dev/null >$TMPFILE 2>$ERRFILE
               sclient_connect_successful $? $TMPFILE
               sclient_success=$?            # here we may have a fp with openssl < 1.0, TBC
               if [[ $sclient_success -ne 0 ]] && ! "$SHOW_EACH_C"; then
                    continue                 # no successful connect AND not verbose displaying each cipher
               fi
               if "$WIDE"; then
                    #FIXME: JSON+CSV in wide mode is missing
                    normalize_ciphercode "$hexcode"
                    neat_list "$HEXC" "$rc4_cipher" "$kx" "$enc"
                    if "$SHOW_EACH_C"; then
                         if [[ $sclient_success -eq 0 ]]; then
                              pr_svrty_high "available"
                         else
                              out "not a/v"
                         fi
                    else
                         rc4_offered=1
                         out
                    fi
                    outln
               else
                    [[ $sclient_success -eq 0 ]] && pr_svrty_high "$rc4_cipher "
               fi
               [[ $sclient_success -eq 0 ]] && rc4_detected+="$rc4_cipher "
          done < <($OPENSSL ciphers -V $rc4_ciphers_list:@STRENGTH)
          outln
          "$WIDE" && pr_svrty_high "VULNERABLE (NOT ok)"
          fileout "rc4" "NOT ok" "RC4 (CVE-2013-2566, CVE-2015-2808) : VULNERABLE (NOT ok) Detected ciphers: $rc4_detected"
     else
          pr_done_goodln "no RC4 ciphers detected (OK)"
          fileout "rc4" "OK" "RC4 (CVE-2013-2566, CVE-2015-2808) : not vulnerable (OK)"
          rc4_offered=0
     fi
     outln

     tmpfile_handle $FUNCNAME.txt
     return $rc4_offered
}


run_youknowwho() {
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
     fileout "old_fart" "ERROR" "Your $OPENSSL $OSSL_VER version is an old fart... . It doesn\'t make much sense to proceed. Get precompiled bins or compile https://github.com/PeterMosmans/openssl ."
     fatal "Your $OPENSSL $OSSL_VER version is an old fart... . It doesn\'t make much sense to proceed." -5
}

# try very hard to determine the install path to get ahold of the mapping file
# it provides "keycode/ RFC style name", see RFCs, cipher(1), www.carbonwind.net/TLS_Cipher_Suites_Project/tls_ssl_cipher_suites_simple_table_all.htm
get_install_dir() {
     #INSTALL_DIR=$(cd "$(dirname "$0")" && pwd)/$(basename "$0")
     INSTALL_DIR=$(dirname ${BASH_SOURCE[0]})

     [[ -r "$RUN_DIR/etc/mapping-rfc.txt" ]] && MAPPING_FILE_RFC="$RUN_DIR/etc/mapping-rfc.txt"
     [[ -r "$INSTALL_DIR/etc/mapping-rfc.txt" ]] && MAPPING_FILE_RFC="$INSTALL_DIR/etc/mapping-rfc.txt"
     if [[ ! -r "$MAPPING_FILE_RFC" ]]; then
# those will disapper:
          [[ -r "$RUN_DIR/mapping-rfc.txt" ]] && MAPPING_FILE_RFC="$RUN_DIR/mapping-rfc.txt"
          [[ -r "$INSTALL_DIR/mapping-rfc.txt" ]] && MAPPING_FILE_RFC="$INSTALL_DIR/mapping-rfc.txt"
     fi

     # we haven't found the mapping file yet...
     if [[ ! -r "$MAPPING_FILE_RFC" ]] && which readlink &>/dev/null ; then
          readlink -f ls &>/dev/null && \
               INSTALL_DIR=$(readlink -f $(basename ${BASH_SOURCE[0]})) || \
               INSTALL_DIR=$(readlink $(basename ${BASH_SOURCE[0]}))
               # not sure whether Darwin has -f
          INSTALL_DIR=$(dirname $INSTALL_DIR 2>/dev/null)
          [[ -r "$INSTALL_DIR/mapping-rfc.txt" ]] && MAPPING_FILE_RFC="$INSTALL_DIR/mapping-rfc.txt"
          [[ -r "$INSTALL_DIR/etc/mapping-rfc.txt" ]] && MAPPING_FILE_RFC="$INSTALL_DIR/etc/mapping-rfc.txt"
# will disappear:
     fi

     # still no mapping file:
     if [[ ! -r "$MAPPING_FILE_RFC" ]] && which realpath &>/dev/null ; then
          INSTALL_DIR=$(dirname $(realpath ${BASH_SOURCE[0]}))
          MAPPING_FILE_RFC="$INSTALL_DIR/etc/mapping-rfc.txt"
# will disappear
          [[ -r "$INSTALL_DIR/mapping-rfc.txt" ]] && MAPPING_FILE_RFC="$INSTALL_DIR/mapping-rfc.txt"
     fi

     [[ ! -r "$MAPPING_FILE_RFC" ]] && unset MAPPING_FILE_RFC && unset ADD_RFC_STR && pr_warningln "\nNo mapping file found"
     debugme echo "$MAPPING_FILE_RFC"
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
     # 0. check environment variable whether it's executable
     if [[ -n "$OPENSSL" ]] && [[ ! -x "$OPENSSL" ]]; then
          pr_warningln "\ncannot find specified (\$OPENSSL=$OPENSSL) binary."
          outln " Looking some place else ..."
     elif [[ -x "$OPENSSL" ]]; then
          :    # 1. all ok supplied $OPENSSL was found and has excutable bit set -- testrun comes below
     elif test_openssl_suffix $RUN_DIR; then
          :    # 2. otherwise try openssl in path of testssl.sh
     elif test_openssl_suffix $RUN_DIR/bin; then
          :    # 3. otherwise here, this is supposed to be the standard --platform independed path in the future!!!
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
          1.0.2|1.1.0) HAS_DH_BITS=true ;;
     esac
     # libressl does not have "Server Temp Key" (SSL_get_server_tmp_key)

     if $OPENSSL version 2>/dev/null | grep -qi LibreSSL; then
          outln
          pr_warning "Please note: LibreSSL is not a good choice for testing INSECURE features!"
     fi

     OPENSSL_NR_CIPHERS=$(count_ciphers "$($OPENSSL ciphers 'ALL:COMPLEMENTOFALL:@STRENGTH' 2>/dev/null)")

     $OPENSSL s_client -ssl2 2>&1 | grep -aq "unknown option" || \
          HAS_SSL2=true

     $OPENSSL s_client -ssl3 2>&1 | grep -aq "unknown option" || \
          HAS_SSL3=true

     $OPENSSL s_client -help 2>&1 | grep -qw '\-alpn' && \
          HAS_ALPN=true

     $OPENSSL s_client -help 2>&1 | grep -qw '\-nextprotoneg' && \
          HAS_SPDY=true

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
          pr_magentaln " Your \"$OPENSSL\" is way too old (<version 1.0) !"
          case $SYSTEM in
               *BSD|Darwin)
                    outln " Please use binary provided in \$INSTALLDIR/bin/ or from ports/brew or compile from github.com/PeterMosmans/openssl" ;;
               *)   outln " Update openssl binaries or compile from github.com/PeterMosmans/openssl" ;;
          esac
          ignore_no_or_lame " Type \"yes\" to accept some false negatives or positives "
     fi
     outln
}


# FreeBSD needs to have /dev/fd mounted. This is a friendly hint, see #258
check_bsd_mount() {
     if [[ "$(uname)" == FreeBSD ]]; then 
          if ! mount | grep '/dev/fd' | grep -q fdescfs; then
               fatal "You need to mount fdescfs on FreeBSD: \"mount -t fdescfs fdesc /dev/fd\"" -3
          fi
     fi
}


help() {
     cat << EOF

$PROG_NAME <options>

     -h, --help                    what you're looking at
     -b, --banner                  displays banner + version of $PROG_NAME
     -v, --version                 same as previous
     -V, --local                   pretty print all local ciphers
     -V, --local <pattern>         which local ciphers with <pattern> are available?
                                   (if pattern not a number: word match)

$PROG_NAME <options> URI    ("$PROG_NAME URI" does everything except -E)

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

     -U, --vulnerable              tests all vulnerabilities
     -B, --heartbleed              tests for heartbleed vulnerability
     -I, --ccs, --ccs-injection    tests for CCS injection vulnerability
     -R, --renegotiation           tests for renegotiation vulnerabilities
     -C, --compression, --crime    tests for CRIME vulnerability
     -T, --breach                  tests for BREACH vulnerability
     -O, --poodle                  tests for POODLE (SSL) vulnerability
     -Z, --tls-fallback            checks TLS_FALLBACK_SCSV mitigation
     -F, --freak                   tests for FREAK vulnerability
     -A, --beast                   tests for BEAST vulnerability
     -J, --logjam                  tests for LOGJAM vulnerability
     -D, --drown                   tests for DROWN vulnerability
     -s, --pfs, --fs, --nsa        checks (perfect) forward secrecy settings
     -4, --rc4, --appelbaum        which RC4 ciphers are being offered?

special invocations:
     -t, --starttls <protocol>     does a default run against a STARTTLS enabled <protocol>
     --xmpphost <to_domain>        for STARTTLS enabled XMPP it supplies the XML stream to-'' domain -- sometimes needed
     --mx <domain/host>            tests MX records from high to low priority (STARTTLS, port 25)
     --ip <ip>                     a) tests the supplied <ip> v4 or v6 address instead of resolving host(s) in URI
                                   b) arg "one" means: just test the first DNS returns (useful for multiple IPs)
     --file <fname>                mass testing option: Reads command lines from <fname>, one line per instance.
                                   Comments via # allowed, EOF signals end of <fname>. Implicitly turns on "--warnings batch"

partly mandatory parameters:
     URI                           host|host:port|URL|URL:port   (port 443 is assumed unless otherwise specified)
     pattern                       an ignore case word pattern of cipher hexcode or any other string in the name, kx or bits
     protocol                      is one of the STARTTLS protocols ftp,smtp,pop3,imap,xmpp,telnet,ldap 
                                   (for the latter two you need e.g. the supplied openssl)

tuning options (can also be preset via environment variables):
     --bugs                        enables the "-bugs" option of s_client, needed e.g. for some buggy F5s
     --assuming-http               if protocol check fails it assumes HTTP protocol and enforces HTTP checks
     --ssl-native                  fallback to checks with OpenSSL where sockets are normally used
     --openssl <PATH>              use this openssl binary (default: look in \$PATH, \$RUN_DIR of $PROG_NAME)
     --proxy <host>:<port>         connect via the specified HTTP proxy
     -6                            use also IPv6. Works only with supporting OpenSSL version and IPv6 connectivity
     --sneaky                      leave less traces in target logs: user agent, referer

output options (can also be preset via environment variables):
     --warnings <batch|off|false>  "batch" doesn't wait for keypress, "off" or "false" skips connection warning
     --quiet                       don't output the banner. By doing this you acknowledge usage terms normally appearing in the banner
     --wide                        wide output for tests like RC4, BEAST. PFS also with hexcode, kx, strength, RFC name
     --show-each                   for wide outputs: display all ciphers tested -- not only succeeded ones
     --mapping <no-rfc>            don't display the RFC Cipher Suite Name
     --color <0|1|2>               0: no escape or other codes,  1: b/w escape codes,  2: color (default)
     --colorblind                  swap green and blue in the output
     --debug <0-6>                 1: screen output normal but keeps debug output in /tmp/.  2-6: see "grep -A 5 '^DEBUG=' testssl.sh"

file output options (can also be preset via environment variables):
     --log, --logging              logs stdout to <NODE-YYYYMMDD-HHMM.log> in current working directory
     --logfile <logfile>           logs stdout to <file/NODE-YYYYMMDD-HHMM.log> if file is a dir or to specified log file
     --json                        additional output of findings to JSON file <NODE-YYYYMMDD-HHMM.json> in cwd
     --jsonfile <jsonfile>         additional output to JSON and output JSON to the specified file
     --csv                         additional output of findings to CSV file  <NODE-YYYYMMDD-HHMM.csv> in cwd
     --csvfile <csvfile>           set output to CSV and output CSV to the specified file
     --append                      if <csvfile> or <jsonfile> exists rather append then overwrite

All options requiring a value can also be called with '=' e.g. testssl.sh -t=smtp --wide --openssl=/usr/bin/openssl <URI>.

<URI> is always the last parameter.

Need HTML output? Just pipe through "aha" (ANSI HTML Adapter: github.com/theZiz/aha) like

   "$PROG_NAME <options> <URI> | aha >output.html"
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
     initialize_engine
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
HAS_SPDY: $HAS_SPDY
HAS_ALPN: $HAS_ALPN

PATH: $PATH
PROG_NAME: $PROG_NAME
INSTALL_DIR: $INSTALL_DIR
RUN_DIR: $RUN_DIR
MAPPING_FILE_RFC: $MAPPING_FILE_RFC

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
ASSUMING_HTTP $ASSUMING_HTTP
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


ignore_no_or_lame() {
     local a

     [[ "$WARNINGS" == off ]] && return 0
     [[ "$WARNINGS" == false ]] && return 0
     [[ "$WARNINGS" == batch ]] && return 1
     pr_magenta "$1 "
     read a
     case $a in
          Y|y|Yes|YES|yes) return 0;;
          default)         ;;
     esac
     return 1
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

     [[ -z "$fname_prefix" ]] && fname_prefix="$NODE"

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

     if "$do_json"; then
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
     ip6=$(grep -wh "$NODE" $etchosts 2>/dev/null | grep ':' | grep -v '^#' |  egrep  "[[:space:]]$NODE" | awk '{ print $1 }')
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
     ip4=$(grep -wh "$1" $etchosts 2>/dev/null | egrep -v ':|^#' |  egrep  "[[:space:]]$1" | awk '{ print $1 }')
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
get_a_record() {
     local ip4=""
     local saved_openssl_conf="$OPENSSL_CONF"

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
          which dig &> /dev/null && \
               ip4=$(filter_ip4_address $(dig +short -t a "$1" 2>/dev/null | sed '/^;;/d'))
     fi
     if [[ -z "$ip4" ]]; then
          which host &> /dev/null && \
               ip4=$(filter_ip4_address $(host -t a "$1" 2>/dev/null | grep -v alias | sed 's/^.*address //'))
     fi
     if [[ -z "$ip4" ]]; then
          which drill &> /dev/null && \
               ip4=$(filter_ip4_address $(drill a "$1" 2>/dev/null | awk '/^\;\;\sANSWER\sSECTION\:$/,/\;\;\sAUTHORITY\sSECTION\:$/ { print $5,$6 }' | sed '/^\s$/d'))
     fi
     if [[ -z "$ip4" ]]; then
          if which nslookup &>/dev/null; then
               ip4=$(filter_ip4_address $(nslookup -querytype=a "$1" 2>/dev/null | awk '/^Name/,/EOF/ { print $0 }' | grep -v Name))
          fi
     fi
     OPENSSL_CONF="$saved_openssl_conf"      # see https://github.com/drwetter/testssl.sh/issues/134
     echo "$ip4"
}

# arg1: a host name. Returned will be 0-n IPv6 addresses
get_aaaa_record() {
     local ip6=""
     local saved_openssl_conf="$OPENSSL_CONF"

     OPENSSL_CONF=""                         # see https://github.com/drwetter/testssl.sh/issues/134
     if [[ -z "$ip6" ]]; then
          if [[ "$NODE" == *.local ]]; then
               if which avahi-resolve &>/dev/null; then
                    ip6=$(filter_ip6_address $(avahi-resolve -6 -n "$NODE" 2>/dev/null | awk '{ print $2 }'))
               elif which dig &>/dev/null; then
                    ip6=$(filter_ip6_address $(dig @ff02::fb -p 5353 -t aaaa +short +notcp "$NODE"))
               else
                    fatal "Local hostname given but no 'avahi-resolve' or 'dig' avaliable." -3
               fi
          elif which host &> /dev/null ; then
               ip6=$(filter_ip6_address $(host -t aaaa "$NODE" | grep -v alias | grep -v "no AAAA record" | sed 's/^.*address //'))
          elif which dig &> /dev/null; then
               ip6=$(filter_ip6_address $(dig +short -t aaaa "$NODE" 2>/dev/null))
          elif which drill &> /dev/null; then
               ip6=$(filter_ip6_address $(drill aaaa "$NODE" 2>/dev/null | awk '/^\;\;\sANSWER\sSECTION\:$/,/^\;\;\sAUTHORITY\sSECTION\:$/ { print $5,$6 }' | sed '/^\s$/d'))
          elif which nslookup &>/dev/null; then
               ip6=$(filter_ip6_address $(nslookup -type=aaaa "$NODE" 2>/dev/null | grep -A10 Name | grep -v Name))
          fi
     fi
     OPENSSL_CONF="$saved_openssl_conf"      # see https://github.com/drwetter/testssl.sh/issues/134
     echo "$ip6"
}


# now get all IP addresses
determine_ip_addresses() {
     local ip4=""
     local ip6=""

     if is_ipv4addr "$NODE"; then
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
     if [[ -z "$IPADDRs" ]] && [[ -z "$CMDLINE_IP" ]]; then
          fatal "No IPv4 address for \"$NODE\" available" -1
     fi
     return 0                                # IPADDR and IP46ADDR is set now
}

determine_rdns() {
     local saved_openssl_conf="$OPENSSL_CONF"
     OPENSSL_CONF=""                              # see https://github.com/drwetter/testssl.sh/issues/134
     local nodeip="$(tr -d '[]' <<< $NODEIP)"     # for DNS we do not need the square brackets of IPv6 addresses

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
          rDNS=$(drill -x ptr $nodeip 2>/dev/null | awk '/^\;\;\sANSWER\sSECTION\:$/,/\;\;\sAUTHORITY\sSECTION\:$/ { print $5,$6 }' | sed '/^\s$/d')
     elif which nslookup &> /dev/null; then
          rDNS=$(nslookup -type=PTR $nodeip 2>/dev/null | grep -v 'canonical name =' | grep 'name = ' | awk '{ print $NF }' | sed 's/\.$//')
     fi
     OPENSSL_CONF="$saved_openssl_conf"      # see https://github.com/drwetter/testssl.sh/issues/134
     rDNS="$(echo $rDNS)"
     [[ -z "$rDNS" ]] && rDNS="--"
     return 0
}

get_mx_record() {
     local mx=""
     local saved_openssl_conf="$OPENSSL_CONF"

     OPENSSL_CONF=""                         # see https://github.com/drwetter/testssl.sh/issues/134
     check_resolver_bins
     if which host &> /dev/null; then
          mxs=$(host -t MX "$1" 2>/dev/null | grep 'handled by' | sed -e 's/^.*by //g' -e 's/\.$//')
     elif which dig &> /dev/null; then
          mxs=$(dig +short -t MX "$1" 2>/dev/null)
     elif which drill &> /dev/null; then
          mxs=$(drill mx "$1" 2>/dev/null | awk '/^\;\;\sANSWER\sSECTION\:$/,/\;\;\sAUTHORITY\sSECTION\:$/ { print $5,$6 }' | sed '/^\s$/d')
     elif which nslookup &> /dev/null; then
          mxs=$(nslookup -type=MX "$1" 2>/dev/null | grep 'mail exchanger = ' | sed 's/^.*mail exchanger = //g')
     else
          fatal "No dig, host, drill or nslookup" -3
     fi
     OPENSSL_CONF="$saved_openssl_conf"
     echo "$mxs"
}

# We need to get the IP address of the proxy so we can use it in fd_socket
#
check_proxy() {
     if [[ -n "$PROXY" ]]; then
          if ! $OPENSSL s_client -help 2>&1 | grep -qw proxy; then
               fatal "Your $OPENSSL is too old to support the \"--proxy\" option" -5
          fi
          PROXYNODE=${PROXY%:*}
          PROXYPORT=${PROXY#*:}
          is_number "$PROXYPORT" || fatal "Proxy port cannot be determined from \"$PROXY\"" "2"

          #if is_ipv4addr "$PROXYNODE" || is_ipv6addr "$PROXYNODE" ; then
          # IPv6 via openssl -proxy: that doesn't work. Sockets does
#FIXME: to finish this with LibreSSL which supports an IPv6 proxy
          if is_ipv4addr "$PROXYNODE"; then
               PROXYIP="$PROXYNODE"
          else
               check_resolver_bins
               PROXYIP=$(get_a_record $PROXYNODE 2>/dev/null | grep -v alias | sed 's/^.*address //')
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
     local addcmd=""

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
          debugme echo "STARTTLS_OPTIMAL_PROTO: $STARTTLS_OPTIMAL_PROTO"
     else
          for OPTIMAL_PROTO in '' -tls1_2 -tls1 -ssl3 -tls1_1 -ssl2 ''; do
               $OPENSSL s_client $OPTIMAL_PROTO $BUGS -connect "$NODEIP:$PORT" -msg $PROXY $SNI </dev/null >$TMPFILE 2>>$ERRFILE
               if sclient_auth $? $TMPFILE; then
                    all_failed=1
                    break
               fi
               all_failed=0
          done
          debugme echo "OPTIMAL_PROTO: $OPTIMAL_PROTO"
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
          ignore_no_or_lame " Note that the results might look ok but they are nonsense. Proceed ? "
          [[ $? -ne 0 ]] && exit -2
     fi

     tmpfile_handle $FUNCNAME.txt
     return 0
}


# arg1: ftp smtp, pop3, imap, xmpp, telnet, ldap (maybe with trailing s)
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
          HEAD_REQ11="HEAD $URL_PATH HTTP/1.1\r\nHost: $NODE\r\nUser-Agent: $ua\r\nAccept: text/*\r\n\r\n"
          GET_REQ10="GET $URL_PATH HTTP/1.0\r\nUser-Agent: $ua\r\nConnection: Close\r\nAccept: text/*\r\n\r\n"
          HEAD_REQ10="HEAD $URL_PATH HTTP/1.0\r\nUser-Agent: $ua\r\nAccept: text/*\r\n\r\n"
          runs_HTTP $OPTIMAL_PROTO
     else
          # STARTTLS
          protocol=${1%s}    # strip trailing 's' in ftp(s), smtp(s), pop3(s), etc
          case "$protocol" in
               ftp|smtp|pop3|imap|xmpp|telnet|ldap)
                    STARTTLS="-starttls $protocol"
                    SNI=""
                    if [[ "$protocol" == xmpp ]]; then
                         # for XMPP, openssl has a problem using -connect $NODEIP:$PORT. thus we use -connect $NODE:$PORT instead!
                         NODEIP="$NODE"
                         if [[ -n "$XMPP_HOST" ]]; then
                              if ! $OPENSSL s_client --help 2>&1 | grep -q xmpphost; then
                                   fatal "Your $OPENSSL does not support the \"-xmpphost\" option" -5
                              fi
                              STARTTLS="$STARTTLS -xmpphost $XMPP_HOST"         # it's a hack -- instead of changing calls all over the place
                              # see http://xmpp.org/rfcs/rfc3920.html
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
                    toupper "$protocol"
                    [[ -n "$XMPP_HOST" ]] && echo -n " (XMPP domain=\'$XMPP_HOST\')"
                    outln
                    ;;
               *)   outln
                    fatal "momentarily only ftp, smtp, pop3, imap, xmpp, telnet and ldap allowed" -4
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
#FIXME: once this function is being called we need a handler which does the right thing 
# ==> not overwrite
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
     do_breach=true
     do_ccs_injection=true
     do_crime=true
     do_freak=true
     do_logjam=true
     do_drown=true
     do_header=true
     do_heartbleed=true
     do_pfs=true
     do_protocols=true
     do_rc4=true
     do_renego=true
     do_std_cipherlists=true
     do_server_defaults=true
     do_server_preference=true
     do_spdy=true
     do_http2=true
     do_ssl_poodle=true
     do_tls_fallback_scsv=true
     do_client_simulation=true
     VULN_COUNT=10
}

query_globals() {
     local gbl
     local true_nr=0

     for gbl in do_allciphers do_vulnerabilities do_beast do_breach do_ccs_injection do_cipher_per_proto do_crime \
               do_freak do_logjam do_drown do_header do_heartbleed do_mx_all_ips do_pfs do_protocols do_rc4 do_renego \
               do_std_cipherlists do_server_defaults do_server_preference do_spdy do_http2 do_ssl_poodle do_tls_fallback_scsv \
               do_client_simulation do_test_just_one do_tls_sockets do_mass_testing do_display_only; do
                    [[ "${!gbl}" == "true" ]] && let true_nr++
     done
     return $true_nr
}


debug_globals() {
     local gbl

     for gbl in do_allciphers do_vulnerabilities do_beast do_breach do_ccs_injection do_cipher_per_proto do_crime \
               do_freak do_logjam do_drown do_header do_heartbleed do_rc4 do_mx_all_ips do_pfs do_protocols do_rc4 do_renego \
               do_std_cipherlists do_server_defaults do_server_preference do_spdy do_http2 do_ssl_poodle do_tls_fallback_scsv \
               do_client_simulation do_test_just_one do_tls_sockets do_mass_testing do_display_only; do
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
     # Set defaults if only an URI was specified, maybe ToDo: use "="-option, then: ${i#*=} i.e. substring removal
     [[ "$#" -eq 1 ]] && set_scanning_defaults

     while [[ $# -gt 0 ]]; do
          case $1 in
               -h|--help)
                    help 0
                    ;;
               -b|--banner|-v|--version)
                    find_openssl_binary
                    maketempf
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
                         ftp|smtp|pop3|imap|xmpp|telnet|ldap|nntp) ;;
                         ftps|smtps|pop3s|imaps|xmpps|telnets|ldaps|nntps) ;;
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
                    do_freak=true
                    do_drown=true
                    do_logjam=true
                    do_beast=true
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
               -4|--rc4|--appelbaum)
                    do_rc4=true
                    let "VULN_COUNT++"
                    ;;
               -s|--pfs|--fs|--nsa)
                    do_pfs=true
                    ;;
               --devel) ### this development feature will soon disappear
                    HEX_CIPHER=""
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
                    ASSUMING_HTTP=true
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
               --mapping|--mapping=*)
                    local cipher_mapping
                    cipher_mapping=$(parse_opt_equal_sign "$1" "$2")
                    [[ $? -eq 0 ]] && shift
                    case "$cipher_mapping" in
                         no-rfc) unset ADD_RFC_STR;;
                         *)   pr_magentaln "\nmapping can only be \"no-rfc\""
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
               (-*) pr_magentaln "0: unrecognized option \"$1\"" 1>&2;
                    help 1
                    ;;
               (*)  break
                    ;;
          esac
          shift
     done

     # Show usage if no options were specified
     if [[ -z "$1" ]] && [[ -z "$FNAME" ]] && ! $do_display_only; then
          help 0
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

     [[ -z "$NODEIP" ]] && fatal "$NODE doesn't resolve to an IP address" 2
     nodeip_to_proper_ip6
     reset_hostdepended_vars
     determine_rdns
     determine_service "$1"        # any starttls service goes here

     $do_tls_sockets && { [[ $TLS_LOW_BYTE -eq 22 ]] && \
          sslv2_sockets || \
          tls_sockets "$TLS_LOW_BYTE" "$HEX_CIPHER"; echo "$?" ; exit 0; }
     $do_test_just_one && test_just_one ${single_cipher}

     # all top level functions  now following have the prefix "run_"
     $do_protocols && { run_protocols; ret=$(($? + ret)); }
     $do_spdy && { run_spdy; ret=$(($? + ret)); }
     $do_http2 && { run_http2; ret=$(($? + ret)); }
     $do_std_cipherlists && { run_std_cipherlists; ret=$(($? + ret)); }
     $do_pfs && { run_pfs; ret=$(($? + ret)); }
     $do_server_preference && { run_server_preference; ret=$(($? + ret)); }
     $do_server_defaults && { run_server_defaults; ret=$(($? + ret)); }

     if $do_header; then
          #TODO: refactor this into functions
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
     fi

     # vulnerabilities
     if [[ $VULN_COUNT -gt $VULN_THRESHLD ]] || $do_vulnerabilities; then
          outln; pr_headlineln " Testing vulnerabilities "
          outln
     fi
     $do_heartbleed && { run_heartbleed; ret=$(($? + ret)); }
     $do_ccs_injection && { run_ccs_injection; ret=$(($? + ret)); }
     $do_renego && { run_renego; ret=$(($? + ret)); }
     $do_crime && { run_crime; ret=$(($? + ret)); }
     $do_breach && { run_breach "$URL_PATH" ; ret=$(($? + ret)); }
     $do_ssl_poodle && { run_ssl_poodle; ret=$(($? + ret)); }
     $do_tls_fallback_scsv && { run_tls_fallback_scsv; ret=$(($? + ret)); }
     $do_freak && { run_freak; ret=$(($? + ret)); }
     $do_drown && { run_drown ret=$(($? + ret)); }
     $do_logjam && { run_logjam; ret=$(($? + ret)); }
     $do_beast && { run_beast; ret=$(($? + ret)); }
     $do_rc4 && { run_rc4; ret=$(($? + ret)); }

     $do_allciphers && { run_allciphers; ret=$(($? + ret)); }
     $do_cipher_per_proto && { run_cipher_per_proto; ret=$(($? + ret)); }
     $do_client_simulation && { run_client_simulation; ret=$(($? + ret)); }

     outln
     datebanner " Done"

     return $ret
}



################# main #################

get_install_dir

initialize_globals
parse_cmd_line "$@"
set_color_functions
find_openssl_binary
maketempf
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
     if ! determine_ip_addresses && [[ -z "$CMDLINE_IP" ]]; then
          fatal "No IP address could be determined" 2
     fi
     if [[ -n "$CMDLINE_IP" ]]; then
          [[ "$CMDLINE_IP" == "one" ]] && \
               CMDLINE_IP=$(echo -n "$IPADDRs" | awk '{ print $1 }')
          NODEIP="$CMDLINE_IP"                                                  # specific ip address for NODE was supplied
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


#  $Id: testssl.sh,v 1.522 2016/07/08 09:25:39 dirkw Exp $
