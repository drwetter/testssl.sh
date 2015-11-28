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
# the recent version of this program. Do not violate the license!
#
# USAGE WITHOUT ANY WARRANTY, THE SOFTWARE IS PROVIDED "AS IS". USE IT AT
# your OWN RISK!

# HISTORY: 
# Back in 2006 it all started with a few openssl commands...
# That's because openssl is a such a good swiss army knife (see e.g.  
# wiki.openssl.org/index.php/Command_Line_Utilities) that it was difficult to resist 
# wrapping some shell commands around it, which I used for my pen tests. This is how 
# everything started.
# Now it has grown up, it has bash socket support for some features which basically replacing
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

readonly VERSION="2.7dev"
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
if which git &>/dev/null ; then
     readonly GIT_REL=$(git log --format='%h %ci' -1 2>/dev/null | awk '{ print $1" "$2" "$3 }')
     readonly GIT_REL_SHORT=$(git log --format='%h %ci' -1 2>/dev/null | awk '{ print $1 }')
     readonly REL_DATE=$(git log --format='%h %ci' -1 2>/dev/null | awk '{ print $2 }')
else
     readonly REL_DATE=$(tail -5 "$0" | awk '/dirkw Exp/ { print $5 }')
fi
readonly SYSTEM=$(uname -s)             
date --help >/dev/null 2>&1 && \
     readonly HAS_GNUDATE=true || \
     readonly HAS_GNUDATE=false
echo A | sed -E 's/A//' >/dev/null 2>&1 && \
     readonly HAS_SED_E=true || \
     readonly HAS_SED_E=false

tty -s && \
     readonly INTERACTIVE=true || \
     readonly INTERACTIVE=false

if ! tput cols &>/dev/null || ! $INTERACTIVE; then     # Prevent tput errors if running non interactive
     TERM_DWITH=${COLUMNS:-80}
else
     TERM_DWITH=${COLUMNS:-$(tput cols)}               # for custom line wrapping and dashes
fi
TERM_CURRPOS=0                                         # custom line wrapping needs alter the current horizontal cursor pos

# following variables make use of $ENV, e.g. OPENSSL=<myprivate_path_to_openssl> ./testssl.sh <host>
# 0 means (normally) true here. Some of the variables are also accessible with a command line switch
# most of them can be set also by a cmd line switch

declare -x OPENSSL
COLOR=${COLOR:-2}                       # 2: Full color, 1: b/w+positioning, 0: no ESC at all
SHOW_EACH_C=${SHOW_EACH_C:-0}           # where individual ciphers are tested show just the positively ones tested #FIXME: upside down value
SNEAKY=${SNEAKY:-false}                 # is the referer and useragent we leave behind just usual? 
QUIET=${QUIET:-false}                   # don't output the banner. By doing this yiu acknowledge usage term appearing in the banner
SSL_NATIVE=${SSL_NATIVE:-false}         # we do per default bash sockets where possible "true": switch back to "openssl native"
ASSUMING_HTTP=${ASSUMING_HTTP:-false}   # in seldom cases (WAF, old servers, grumpy SSL) service detection fails. "True" enforces HTTP checks
BUGS=${BUGS:-""}                        # -bugs option from openssl, needed for some BIG IP F5
DEBUG=${DEBUG:-0}                       # 1.: the temp files won't be erased. 
                                        # 2: list more what's going on (formerly: eq VERBOSE=1, VERBERR=true), lists some errors of connections
                                        # 3: slight hexdumps + other info, 
                                        # 4: display bytes sent via sockets, 5: display bytes received via sockets, 6: whole 9 yards
WIDE=${WIDE:-false}                     # whether to display for some options the cipher or the table with hexcode/KX,Enc,strength etc.
LOGFILE=${LOGILE-""}                    # logfile if used
HAS_IPv6=${HAS_IPv6:-false}             # if you have OPENSSL with IPv6 support AND IPv6 networking set it to yes and testssl.sh works!

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
readonly CLIENT_MIN_PFS=5               # number of ciphers needed to run a test for PFS
DAYS2WARN1=${DAYS2WARN1:-60}            # days to warn before cert expires, threshold 1
DAYS2WARN2=${DAYS2WARN2:-30}            # days to warn before cert expires, threshold 2
VULN_THRESHLD=${VULN_THRESHLD:-1}       # if vulnerabilities to check >$VULN_THRESHLD we DON'T show a separate header line in the output each vuln. check

HAD_SLEPT=0
CAPATH="${CAPATH:-/etc/ssl/certs/}"     # Does nothing yet (FC has only a CA bundle per default, ==> openssl version -d)
FNAME=${FNAME:-""}                      # file name to read commands from
IKNOW_FNAME=false

# further global vars just declared here
readonly NPN_PROTOs="spdy/4a2,spdy/3,spdy/3.1,spdy/2,spdy/1,http/1.1"
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
HAS_DH_BITS=${HAS_DH_BITS:-false}
HAS_SSL2=true                           #TODO: in the future we'll do the fastest possible test (openssl s_client -ssl2 is currently faster than sockets)
HAS_SSL3=true
HAS_ALPN=false
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
STARTTLS_PROTOCOL=""
OPTIMAL_PROTO=""                        # we need this for IIS6 (sigh) and OpenSSL 1.02, otherwise some handshakes
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

# Devel stuff, see -q below
TLS_LOW_BYTE=""
HEX_CIPHER=""

                                             # The various hexdump commands we need to replace xxd (BSD compatibility))
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
out()   { /usr/bin/printf -- "${1//%/%%}"; }
outln() { out "$1\n"; }
#TODO: Still no shell injection safe but if just run it from the cmd line: that's fine

# color print functions, see also http://www.tldp.org/HOWTO/Bash-Prompt-HOWTO/x329.html
pr_liteblue()   { [[ "$COLOR" -eq 2 ]] && out "\033[0;34m$1" || out "$1"; pr_off; }                 # not yet used
pr_liteblueln() { pr_liteblue "$1"; outln; }
pr_blue()       { [[ "$COLOR" -eq 2 ]] && out "\033[1;34m$1" || out "$1"; pr_off; }                 # used for head lines of single tests
pr_blueln()     { pr_blue "$1"; outln; }

pr_litered()   { [[ "$COLOR" -eq 2 ]] && out "\033[0;31m$1" || pr_bold "$1"; pr_off; }              # this is bad
pr_literedln() { pr_litered "$1"; outln; }
pr_red()       { [[ "$COLOR" -eq 2 ]] && out "\033[1;31m$1" || pr_bold "$1"; pr_off; }              # oh, this is really bad
pr_redln()     { pr_red "$1"; outln; }

pr_litemagenta()   { [[ "$COLOR" -eq 2 ]] && out "\033[0;35m$1" || pr_underline "$1"; pr_off; }     # local problem: one test cannot be done
pr_litemagentaln() { pr_litemagenta "$1"; outln; }
pr_magenta()       { [[ "$COLOR" -eq 2 ]] && out "\033[1;35m$1" || pr_underline "$1"; pr_off; }     # Fatal error: quitting because of this!
pr_magentaln()     { pr_magenta "$1"; outln; }

pr_litecyan()   { [[ "$COLOR" -eq 2 ]] && out "\033[0;36m$1" || out "$1"; pr_off; }                 # not yet used
pr_litecyanln() { pr_litecyan "$1"; outln; }
pr_cyan()       { [[ "$COLOR" -eq 2 ]] && out "\033[1;36m$1" || out "$1"; pr_off; }                 # additional hint
pr_cyanln()     { pr_cyan "$1"; outln; }

pr_litegreyln() { pr_litegrey "$1"; outln; }
pr_litegrey()   { [[ "$COLOR" -eq 2 ]] && out "\033[0;37m$1" || out "$1"; pr_off; }
pr_grey()       { [[ "$COLOR" -eq 2 ]] && out "\033[1;30m$1" || out "$1"; pr_off; }
pr_greyln()     { pr_grey "$1"; outln; }

pr_litegreen()   { [[ "$COLOR" -eq 2 ]] && out "\033[0;32m$1" || out "$1"; pr_off; }                # This is good
pr_litegreenln() { pr_litegreen "$1"; outln; }
pr_green()       { [[ "$COLOR" -eq 2 ]] && out "\033[1;32m$1" || out "$1"; pr_off; }                # This is the best 
pr_greenln()     { pr_green "$1"; outln; }

pr_yellow()   { [[ "$COLOR" -eq 2 ]] && out "\033[1;33m$1" || out "$1"; pr_off; }                   # academic or minor problem 
pr_yellowln() { pr_yellow "$1"; outln; }
pr_brown()    { [[ "$COLOR" -eq 2 ]] && out "\033[0;33m$1" || out "$1"; pr_off; }                   # it is not a bad problem but you shouldn't do this
pr_brownln()  { pr_brown "$1"; outln; }


# color=1 functions
pr_off()          { [[ "$COLOR" -ne 0 ]] && out "\033[m\c"; }
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


###### helper function definitions ######

debugme() {
     [[ $DEBUG -ge 2 ]] && "$@"
}

hex2dec() {
     #/usr/bin/printf -- "%d" 0x"$1"
     echo $((16#$1))
}

dec2hex() {
     /usr/bin/printf -- "%x" "$1"
     #echo $((0x$1))
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

     out " Service detected:      $CORRECT_SPACES"
     case $SERVICE in
          HTTP)
               out " $SERVICE"
               ret=0 ;;
          IMAP|POP|SMTP|NNTP)
               out " $SERVICE, thus skipping HTTP specific checks"
               ret=0 ;;
          *)   if $CLIENT_AUTH; then
                    out "certificate based authentication => skipping all HTTP checks"
                    echo "certificate based authentication => skipping all HTTP checks" >$TMPFILE
               else
                    out " Couldn't determine what's running on port $PORT"
                    if $ASSUMING_HTTP; then
                         SERVICE=HTTP
                         out " -- ASSUMING_HTTP set though"
                         ret=0
                    else
                         out ", assuming no HTTP service => skipping all HTTP checks"
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
     local url

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
               pr_litemagenta " likely HTTP header requests failed (#lines: $(wc -l < $HEADERFILE | sed 's/ //g'))."
               outln "Rerun with DEBUG=1 and inspect \"run_http_header.txt\"\n"
               debugme cat $HEADERFILE
               return 7
          fi
     fi
     # populate vars for HTTP time

     debugme echo "$NOW_TIME: $HTTP_TIME"

     sed  -e '/^<HTML/,$d' -e '/^<html/,$d' -e '/^<XML /,$d' -e '/<?XML /,$d' \
          -e '/^<xml /,$d' -e '/<?xml /,$d'  -e '/^<\!DOCTYPE/,$d' -e '/^<\!doctype/,$d' $HEADERFILE >$HEADERFILE.2
#### ^^^ Attention: the filtering for the html body only as of now, doesn't work for other content yet
     mv $HEADERFILE.2  $HEADERFILE  # sed'ing in place doesn't work with BSD and Linux simultaneously
     ret=0

     status_code=$(awk '/^HTTP\// { print $2 }' $HEADERFILE 2>>$ERRFILE)
     msg_thereafter=$(awk -F"$status_code" '/^HTTP\// { print $2 }' $HEADERFILE 2>>$ERRFILE)   # dirty trick to use the status code as a
     msg_thereafter=$(strip_lf "$msg_thereafter")                                    # field separator, otherwise we need a loop with awk
     debugme echo "Status/MSG: $status_code $msg_thereafter"

     pr_bold " HTTP Status Code           "
     [[ -z "$status_code" ]] && pr_litemagentaln "No status code" && return 3

     out "  $status_code$msg_thereafter" 
     case $status_code in
          301|302|307|308)    out ", redirecting to \"$(grep -a '^Location' $HEADERFILE | sed 's/Location: //' | tr -d '\r\n')\"" ;;
          200) ;;
          206) out " -- WTF?" ;;
          400) pr_litemagenta " (Hint: better try another URL)" ;;
          401) grep -aq "^WWW-Authenticate" $HEADERFILE && out "  "; strip_lf "$(grep -a "^WWW-Authenticate" $HEADERFILE)"
               ;;
          403)  ;;
          404) out " (Hint: supply a path which doesn't give a \"$status_code$msg_thereafter\")" ;; 
          405) ;;
          *) pr_litemagenta ". Oh, didn't expect a $status_code$msg_thereafter";;
     esac
     outln

     # we don't call "tmpfile_handle $FUNCNAME.txt" as we need the header file in other functions!
     return $ret
}

# Borrowed from Glenn Jackman, see https://unix.stackexchange.com/users/4667/glenn-jackman
detect_ipv4() {
     local octet="(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])"
     local ipv4address="$octet\\.$octet\\.$octet\\.$octet"
     local your_ip_msg="(check if it's your IP address or e.g. a cluster IP)"
     local result
     local first=true
     local spaces="                              "
     
     if [[ ! -s $HEADERFILE ]]; then
          run_http_header "$1" || return 3
     fi

     # remove pagespeed header as it is mistakenly identified as ipv4 address https://github.com/drwetter/testssl.sh/issues/158
     # also facebook has a CSP rule for 127.0.0.1
     if egrep -vi "pagespeed|page-speed|Content-Security-Policy" $HEADERFILE | grep -iqE "$ipv4address"; then
          pr_bold " IPv4 address in header       " 
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
                    pr_litered "$result"
                    outln "\n$spaces$your_ip_msg"
               fi
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
               if $HAS_GNUDATE ; then
                    HTTP_TIME=$(date --date="$HTTP_TIME" "+%s")
               else
                    HTTP_TIME=$(LC_ALL=C date -j -f "%a, %d %b %Y %T %Z" "$HTTP_TIME" "+%s" 2>>$ERRFILE) # the trailing \r confuses BSD flavors otherwise
               fi

               difftime=$((HTTP_TIME - $NOW_TIME))
               [[ $difftime != "-"* ]] && [[ $difftime != "0" ]] && difftime="+$difftime"
               # process was killed, so we need to add an error:
               [[ $HAD_SLEPT -ne 0 ]] && difftime="$difftime (± 1.5)"
               out "$difftime sec from localtime";
          else
               out "Got no HTTP time, maybe try different URL?";
          fi
          debugme out ", epoch: $HTTP_TIME"
     fi
     outln
     detect_ipv4
}

includeSubDomains() {
     if grep -aiqw includeSubDomains "$1"; then
          pr_litegreen ", includeSubDomains"
     else
          pr_litecyan ", just this domain"
     fi
}

preload() {
     grep -aiqw preload "$1" && pr_litegreen ", preload"
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
#FIXME: test for number!
          hsts_age_days=$(( hsts_age_sec / 86400))
          if [[ $hsts_age_days -gt $HSTS_MIN ]]; then
               pr_litegreen "$hsts_age_days days" ; out "=$hsts_age_sec s"
          else
               out "$hsts_age_sec s = "
               pr_brown "$hsts_age_days days, <$HSTS_MIN days is too short"
          fi
          includeSubDomains "$TMPFILE"
          preload "$TMPFILE"
          #FIXME: To be checked against e.g. https://dxr.mozilla.org/mozilla-central/source/security/manager/boot/src/nsSTSPreloadList.inc
          #                              and https://chromium.googlesource.com/chromium/src/+/master/net/http/transport_security_state_static.json
     else
          out "--"
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
               pr_brown "two HPKP headers: "
               for i in $(newline_to_spaces "$(egrep -ai '^Public-Key-Pins' $HEADERFILE | awk -F':' '/Public-Key-Pins/ { print $1 }')"); do
                    pr_italic $i
                    out " "
               done
               out "\n$spaces using first "
               pr_italic "$(awk -F':' '/Public-Key-Pins/ { print $1 }' $HEADERFILE | head -1), "
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
               pr_litered "1 (NOT ok), "
          else
               out "$hpkp_nr_keys, "
          fi

          # print key=value pair with awk, then strip non-numbers, to be improved with proper parsing of key-value with awk
          hpkp_age_sec=$(awk -F= '/max-age/{max_age=$2; print max_age}' $TMPFILE | sed -E 's/[^[:digit:]]//g')
          hpkp_age_days=$((hpkp_age_sec / 86400))
          if [[ $hpkp_age_days -ge $HPKP_MIN ]]; then
               pr_litegreen "$hpkp_age_days days" ; out "=$hpkp_age_sec s"
          else
               out "$hpkp_age_sec s = "
               pr_brown "$hpkp_age_days days (<$HPKP_MIN days is not good enough)"
          fi

          includeSubDomains "$TMPFILE"
          preload "$TMPFILE"

          [[ -s "$HOSTCERT" ]] || get_host_cert
          # get the key fingerprints
          hpkp_key_hostcert="$($OPENSSL x509 -in $HOSTCERT -pubkey -noout | grep -v PUBLIC | \
               $OPENSSL base64 -d | $OPENSSL dgst -sha256 -binary | $OPENSSL base64)"
          while read hpkp_key; do
               if [[ "$hpkp_key_hostcert" == "$hpkp_key" ]] || [[ "$hpkp_key_hostcert" == "$hpkp_key=" ]]; then
                    out "\n$spaces matching host key: "
                    pr_litegreen "$hpkp_key"
                    key_found=true
               fi
               debugme out "\n  $hpkp_key | $hpkp_key_hostcert"
          done < <(tr ';' '\n' < $TMPFILE | tr -d ' ' | tr -d '\"' | awk -F'=' '/pin.*=/ { print $2 }')
          if ! $key_found ; then
               out "\n$spaces"
               pr_litered " No matching key for pins found "
               out "(CAs pinned? -- not yet checked)"
          fi
     else
          out "--"
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
          if [[ x"$serverbanner" == "x\n" ]] || [[ x"$serverbanner" == "x\n\r" ]] || [[ x"$serverbanner" == "x" ]]; then
               outln "banner exists but empty string"
          else
               emphasize_stuff_in_headers "$serverbanner"
               [[ "$serverbanner" = *Microsoft-IIS/6.* ]] && [[ $OSSL_VER == 1.0.2* ]] && \
                    pr_litemagentaln "                              It's recommended to run another test w/ OpenSSL 1.01 !"
                    # see https://github.com/PeterMosmans/openssl/issues/19#issuecomment-100897892
          fi
          # mozilla.github.io/server-side-tls/ssl-config-generator/
          # https://support.microsoft.com/en-us/kb/245030
     else
          outln "(no \"Server\" line in header, interesting!)"
     fi

     tmpfile_handle $FUNCNAME.txt
     return 0
}

run_rp_banner() {
     local line
     local first=true
     local spaces="                              "

     if [[ ! -s $HEADERFILE ]]; then
          run_http_header "$1" || return 3
     fi
     pr_bold " Reverse Proxy banner         "
     egrep -ai '^Via:|^X-Cache|^X-Squid|^X-Varnish:|^X-Server-Name:|^X-Server-Port:|^x-forwarded' $HEADERFILE >$TMPFILE 
     if [[ $? -ne 0 ]]; then
          outln "--"
     else
          while read line; do
               line=$(strip_lf "$line")
               if ! $first; then
                    out "$spaces"
               else
                    first=false
               fi
               emphasize_stuff_in_headers "$line"
          done < $TMPFILE
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

     if [[ ! -s $HEADERFILE ]]; then
          run_http_header "$1" || return 3
     fi
     pr_bold " Application banner           "
     egrep -ai '^X-Powered-By|^X-AspNet-Version|^X-Version|^Liferay-Portal|^X-OWA-Version' $HEADERFILE >$TMPFILE
     if [[ $? -ne 0 ]]; then
          outln "--"
     else
          cat $TMPFILE | while read line; do
               line=$(strip_lf "$line")
               if ! $first; then
                    out "$spaces"
               else
                    first=false
               fi
               emphasize_stuff_in_headers "$line"
          done
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
          nr_cookies=$(wc -l < $TMPFILE | sed 's/ //g')
          out "$nr_cookies issued: "
          if [[ $nr_cookies -gt 1 ]]; then
               negative_word="NONE"
          else
               negative_word="NOT"
          fi
          nr_secure=$(grep -iac secure $TMPFILE)
          case $nr_secure in
               0) pr_brown "$negative_word" ;;
               [123456789]) pr_litegreen "$nr_secure/$nr_cookies";;
          esac
          out " secure, "
          nr_httponly=$(grep -cai httponly $TMPFILE)
          case $nr_httponly in
               0) pr_brown "$negative_word" ;;
               [123456789]) pr_litegreen "$nr_httponly/$nr_cookies";;
          esac
          out " HttpOnly"
     else
          out "(none issued at \"$1\")"
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
          ret=1
     else
          ret=0
          for f2t in $good_flags2test; do
               debugme echo "---> $f2t"
               result_str=$(grep -wi "^$f2t" $TMPFILE | grep -vi "$f2t"-)
               result_str=$(strip_lf "$result_str")
               [[ -z "$result_str" ]] && continue
               if ! $first; then
                    out "$spaces"  # output leading spaces if the first header
               else
                    first=false
               fi
               # extract and print key(=flag) in green:
               pr_litegreen "${result_str%%:*}:"
               #pr_litegreen "$(sed 's/:.*$/:/' <<< "$result_str")"
               # print value in plain text:
               outln "${result_str#*:}"

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

     pr_headline " Displaying all local ciphers ";
     if [[ -n "$1" ]]; then
          [[ $1 =~ $re ]] && \
               pr_headline "matching number pattern \"$1\" " || \
               pr_headline "matching word pattern "\"$1\"" (ignore case) "
     fi
     outln "\n"
     neat_header

     if [[ -z "$1" ]]; then
          $OPENSSL ciphers -V 'ALL:COMPLEMENTOFALL:@STRENGTH' 2>$ERRFILE | while read hexcode dash ciph sslvers kx auth enc mac export ; do       # -V doesn't work with openssl < 1.0
               normalize_ciphercode $hexcode
               neat_list $HEXC $ciph $kx $enc
               outln
          done
     else
          #for arg in $(echo $@ | sed 's/,/ /g'); do
          for arg in ${*//,/ /}; do
               $OPENSSL ciphers -V 'ALL:COMPLEMENTOFALL:@STRENGTH' 2>$ERRFILE | while read hexcode dash ciph sslvers kx auth enc mac export ; do # -V doesn't work with openssl < 1.0
                    normalize_ciphercode $hexcode
                    # for numbers we don't do word matching:
                    [[ $arg =~ $re ]] && \
                         neat_list $HEXC $ciph $kx $enc | grep -ai "$arg" || \
                         neat_list $HEXC $ciph $kx $enc | grep -wai "$arg"
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
                    [[ $sclient_success -eq 0 ]] && \
                         pr_greenln "offered (OK)" || \
                         pr_brownln "not offered (NOT ok)" ;;
               1) # the ugly ones
                    [[ $sclient_success -eq 0 ]] && \
                         pr_redln "offered (NOT ok)" || \
                         pr_greenln "not offered (OK)" ;;
               2)   # bad but not worst
                    [[ $sclient_success -eq 0 ]] && \
                         pr_literedln "offered (NOT ok)" || \
                         pr_litegreenln "not offered (OK)" ;;
               3) # not totally bad 
                    [[ $sclient_success -eq 0 ]] && \
                         pr_brownln "offered (NOT ok)" || \
                         outln "not offered (OK)" ;;
               *) # we shouldn't reach this
                    pr_litemagenta "? (please report this)" ;;
          esac
          tmpfile_handle $FUNCNAME.$debugname.txt
     else
          singlespaces=$(echo "$2" | sed -e 's/ \+/ /g' -e 's/^ //' -e 's/ $//g' -e 's/  //g')
          local_problem "No $singlespaces configured in $OPENSSL"
     fi
     # we need 1xlf in those cases:
     debugme echo
}


# sockets inspired by http://blog.chris007.de/?p=238
# ARG1: hexbyte with a leading comma (!!), separated by commas
# ARG2: sleep
socksend() {
     # the following works under BSD and Linux, which is quite tricky. So don't mess with it unless you're really sure what you do
     if $HAS_SED_E; then
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
     SOCKREPLY=$(cat $ddreply)
     rm $ddreply
     return $ret
}


show_rfc_style(){
     local rfcname

     [[ -z "$MAPPING_FILE_RFC" ]] && return 1
     rfcname=$(grep -iw "$1" "$MAPPING_FILE_RFC" | sed -e 's/^.*TLS/TLS/' -e 's/^.*SSL/SSL/')
     [[ -n "$rfcname" ]] && out "$rfcname"
     return 0
}

neat_header(){
     printf -- "Hexcode  Cipher Suite Name (OpenSSL)    KeyExch.   Encryption Bits${MAPPING_FILE_RFC:+        Cipher Suite Name (RFC)}\n"
     printf -- "%s-------------------------------------------------------------------------${MAPPING_FILE_RFC:+----------------------------------------------}\n"
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
     strength=$(sed -e 's/.*(//' -e 's/)//' <<< "$enc")                              # strength = encryption bits

     strength="${strength//ChaCha20-Poly1305/ly1305}"
     enc=$(sed -e 's/(.*)//g' -e 's/ChaCha20-Poly1305/ChaCha20-Po/g' <<< "$enc")     # workaround for empty bits ChaCha20-Poly1305
     echo "$export" | grep -iq export && strength="$strength,export"
     # workaround for color escape codes:
     if printf -- "$kx" | "${HEXDUMPVIEW[@]}" | grep -q 33 ; then         # here's a color code
          kx="$kx "                               # one for color code if ECDH and three digits
          [[ "${#kx}" -eq 18 ]] && kx="$kx  "     # 18 means DH, colored < 1000. Add another space
          [[ "${#kx}" -eq 19 ]] && kx="$kx "      # 19 means DH, colored >=1000. Add another space
          #echo ${#kx}                            # should be always 20
     fi
     #if [[ -r "$MAPPING_FILE_RFC" ]]; then
          printf -- " %-7s %-30s %-10s %-11s%-11s${MAPPING_FILE_RFC:+ %-48s}${SHOW_EACH_C:+  }" "$hexcode" "$ossl_cipher" "$kx" "$enc" "$strength" "$(show_rfc_style $HEXC)"
     #else
     #    printf -- " %-7s %-30s %-10s %-11s%-11s${SHOW_EACH_C:+  }" "$1" "$2" "$kx" "$enc" "$strength"
     #fi
}

test_just_one(){
     local hexcode n ciph sslvers kx auth enc mac export
     local dhlen
     local sclient_success
     local re='^[0-9A-Fa-f]+$'

     pr_headline " Testing single cipher with "
     [[ $1 =~ $re ]] && \
          pr_headline "matching number pattern \"$1\" " || \
          pr_headline "word pattern "\"$1\"" (ignore case) "
     outln
     ! $HAS_DH_BITS && pr_litemagentaln "    (Your $OPENSSL cannot show DH/ECDH bits)"
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
                    else
                         out "  not a/v"
                    fi
                    outln
               fi
          done
     done
     outln

     tmpfile_handle $FUNCNAME.txt
     return 0       # this is a single test for a cipher
}


# test for all ciphers locally configured (w/o distinguishing whether they are good or bad
run_allciphers(){
     local tmpfile
     local nr_ciphers
     local -i sclient_success=0
     local hexcode n ciph sslvers kx auth enc mac export
     local dhlen

     nr_ciphers=$(count_ciphers "$($OPENSSL ciphers 'ALL:COMPLEMENTOFALL:@STRENGTH' 2>$ERRFILE)")
     outln
     pr_headlineln " Testing all $nr_ciphers locally available ciphers against the server, ordered by encryption strength "
     ! $HAS_DH_BITS && pr_litemagentaln "    (Your $OPENSSL cannot show DH/ECDH bits)"
     outln
     neat_header

     $OPENSSL ciphers -V 'ALL:COMPLEMENTOFALL:@STRENGTH' 2>>$ERRFILE | while read hexcode n ciph sslvers kx auth enc mac export; do
     # FIXME: e.g. OpenSSL < 1.0 doesn't understand "-V" --> we can't do anything about it!
          $OPENSSL s_client -cipher $ciph $STARTTLS $BUGS -connect $NODEIP:$PORT $PROXY $SNI >$TMPFILE 2>$ERRFILE </dev/null
          sclient_connect_successful $? $TMPFILE
          sclient_success=$?
          if [[ $sclient_success -ne 0 ]] && [[ "$SHOW_EACH_C" -eq 0 ]]; then
               continue       # no successful connect AND not verbose displaying each cipher
          fi
          normalize_ciphercode $hexcode
          if [[ $kx == "Kx=ECDH" ]] || [[ $kx == "Kx=DH" ]] || [[ $kx == "Kx=EDH" ]]; then
               dhlen=$(read_dhbits_from_file $TMPFILE quiet)
               kx="$kx $dhlen"
          fi
          neat_list $HEXC $ciph "$kx" $enc
          if [[ "$SHOW_EACH_C" -ne 0 ]]; then
               if [[ $sclient_success -eq 0 ]]; then
                    pr_cyan "  available"
               else
                    out "  not a/v"
               fi
          fi
          outln
          tmpfile_handle $FUNCNAME.txt
     done
     outln
     return 0
}

# test for all ciphers per protocol locally configured (w/o distinguishing whether they are good or bad
run_cipher_per_proto(){
     local proto proto_text
     local hexcode n ciph sslvers kx auth enc mac export
     local -i sclient_success=0
     local dhlen

     pr_headlineln " Testing all locally available ciphers per protocol against the server, ordered by encryption strength "
     ! $HAS_DH_BITS && pr_litemagentaln "    (Your $OPENSSL cannot show DH/ECDH bits)"
     outln
     neat_header
     outln " -ssl2 SSLv2\n -ssl3 SSLv3\n -tls1 TLS 1\n -tls1_1 TLS 1.1\n -tls1_2 TLS 1.2"| while read proto proto_text; do
          locally_supported "$proto" "$proto_text" || continue
          outln
          $OPENSSL ciphers $proto -V 'ALL:COMPLEMENTOFALL:@STRENGTH' 2>$ERRFILE | while read hexcode n ciph sslvers kx auth enc mac export; do   # -V doesn't work with openssl < 1.0
               $OPENSSL s_client -cipher $ciph $proto $STARTTLS $BUGS -connect $NODEIP:$PORT $PROXY $SNI >$TMPFILE 2>$ERRFILE  </dev/null
               sclient_connect_successful $? $TMPFILE
               sclient_success=$?
               if [[ $sclient_success -ne 0 ]] && [[ "$SHOW_EACH_C" -eq 0 ]]; then
                    continue       # no successful connect AND not verbose displaying each cipher
               fi
               normalize_ciphercode $hexcode
               if [[ $kx == "Kx=ECDH" ]] || [[ $kx == "Kx=DH" ]] || [[ $kx == "Kx=EDH" ]]; then
                    dhlen=$(read_dhbits_from_file $TMPFILE quiet)
                    kx="$kx $dhlen"
               fi
               neat_list $HEXC $ciph "$kx" $enc
               if [[ "$SHOW_EACH_C" -ne 0 ]]; then
                    if [[ $sclient_success -eq 0 ]]; then
                         pr_cyan "  available"
                    else
                         out "  not a/v"
                    fi
               fi
               outln
               tmpfile_handle $FUNCNAME.txt
          done
     done
     return 0
}

# generic function whether $1 is supported by s_client ($2: string to display)
locally_supported() {
     [[ -n "$2" ]] && out "$2 "
     if $OPENSSL s_client "$1" 2>&1 | grep -aq "unknown option"; then
          local_problem "$OPENSSL doesn't support \"s_client $1\""
          return 7
     fi
     return 0
}


# the protocol check needs to be revamped. It sucks. 
# 1) we need to have a variable where the resulta are being stored so that every other test doesn't have to do this again.
# 2) the code is too old and one can do that way better
# 3) HAS_SSL3/2 does already exist
# we should do what's availabe and faster (opensssl vs. sockets) . Keep in mind tat the socket reply for SSLv2 returns the number # of ciphers!
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


# the protocol check needs to be revamped. It sucks, see above
run_protocols() {
     local using_sockets=true
     local supported_no_ciph1="supported but couldn't detect a cipher (may need debugging)" 
     local supported_no_ciph2="supported but couldn't detect a cipher" 

     outln; pr_headline " Testing protocols "

     #FIXME: use PROTOS_OFFERED here

     if $SSL_NATIVE; then
          using_sockets=false
          pr_headlineln "(via native openssl)"
     else
          if [[ -n "$STARTTLS" ]]; then
               pr_headlineln "(via openssl, SSLv2 via sockets) "
               using_sockets=false
          else
               using_sockets=true
               pr_headlineln "(via sockets except TLS 1.2 and SPDY/NPN) "
          fi
     fi
     outln

     pr_bold " SSLv2      ";
     if ! $SSL_NATIVE; then
          sslv2_sockets                                                    #FIXME: messages need to be moved to this higher level
     else
          run_prototest_openssl "-ssl2"
          case $? in
               0) pr_redln   "offered (NOT ok)" ;;
               1) pr_greenln "not offered (OK)" ;;
               5) pr_litered "$supported_no_ciph2"; 
                    outln " (may need further attention)"  ;;              # protocol ok, but no cipher
               7) ;;                                                       # no local support
          esac
     fi

     pr_bold " SSLv3      ";
     if $using_sockets; then
          tls_sockets "00" "$TLS_CIPHER"
     else
          run_prototest_openssl "-ssl3"
     fi
     case $? in
          0) pr_literedln "offered (NOT ok)" ;;
          1) pr_greenln "not offered (OK)"   ;;
          2) pr_litemagentaln "#FIXME: downgraded. still missing a test case here" ;;
          5) pr_litered "$supported_no_ciph2"; 
                    outln "(may need debugging)"  ;;                       # protocol ok, but no cipher
          7) ;;                                                            # no local support
     esac

     pr_bold " TLS 1      ";
     if $using_sockets; then
          tls_sockets "01" "$TLS_CIPHER"
     else
          run_prototest_openssl "-tls1"
     fi
     case $? in
          0) outln "offered" ;;                                            # nothing wrong with it -- per se
          1) outln "not offered" ;;                                        # neither good or bad
          2) pr_brown "not offered (NOT ok)"
               [[ $DEBUG -eq 1 ]] && out " -- downgraded"
               outln ;;
          5) outln "$supported_no_ciph1"  ;;                               # protocol ok, but no cipher
          7) ;;                                                            # no local support
     esac

     pr_bold " TLS 1.1    ";
     if $using_sockets; then
          tls_sockets "02" "$TLS_CIPHER"
     else
          run_prototest_openssl "-tls1_1"
     fi   
     case $? in
          0) outln "offered" ;;                                            # nothing wrong with it
          1) outln "not offered" ;;                                        # neither good or bad
          2) out "not offered" 
               [[ $DEBUG -eq 1 ]] && out " -- downgraded" 
               outln ;;
          5) outln "$supported_no_ciph1" ;;                                # protocol ok, but no cipher
          7) ;;                                                            # no local support
     esac

     pr_bold " TLS 1.2    ";
     if $using_sockets && $EXPERIMENTAL; then               #TODO: IIS servers do have a problem here with our handshake
          tls_sockets "03" "$TLS12_CIPHER"
     else
          run_prototest_openssl "-tls1_2"
     fi   
     case $? in
          0) pr_greenln "offered (OK)" ;;                                  # GCM cipher in TLS 1.2: very good!
          1) pr_brownln "not offered (NOT ok)" ;;                          # no GCM, penalty
          2) pr_brown "not offered (NOT ok)"
               [[ $DEBUG -eq 1 ]] && out " -- downgraded"
               outln ;;
          5) outln "$supported_no_ciph1" ;;                                # protocol ok, but no cipher
          7) ;;                                                            # no local support
     esac
     return 0
}

#TODO: work with fixed lists here
run_std_cipherlists() {
     outln
     pr_headlineln " Testing ~standard cipher lists "
     outln
# see ciphers(1ssl)
     std_cipherlists 'NULL:eNULL'                       " Null Ciphers             " 1
     std_cipherlists 'aNULL'                            " Anonymous NULL Ciphers   " 1
     std_cipherlists 'ADH'                              " Anonymous DH Ciphers     " 1
     std_cipherlists 'EXPORT40'                         " 40 Bit encryption        " 1
     std_cipherlists 'EXPORT56'                         " 56 Bit encryption        " 1
     std_cipherlists 'EXPORT'                           " Export Ciphers (general) " 1
     std_cipherlists 'LOW:!ADH'                         " Low (<=64 Bit)           " 1
     std_cipherlists 'DES:!ADH:!EXPORT:!aNULL'          " DES Ciphers              " 1
     std_cipherlists 'MEDIUM:!NULL:!aNULL:!SSLv2'       " Medium grade encryption  " 2
     std_cipherlists '3DES:!ADH:!aNULL'                 " Triple DES Ciphers       " 3
     std_cipherlists 'HIGH:!NULL:!aNULL:!DES:!3DES'     " High grade encryption    " 0
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
     if [[ -z "$what_dh" ]] && ! $HAS_DH_BITS; then
          if [[ -z "$2" ]]; then
               pr_litemagenta "$old_fart"
          fi
          return 0
     fi

     [[ -n "$bits" ]] && [[ -z "$2" ]] && out ", "
     if [[ $what_dh == "DH" ]] || [[ $what_dh == "EDH" ]]; then
          [[ -z "$2" ]] && add="bit DH"
          if [[ "$bits" -le 600 ]]; then
               pr_red "$bits $add"
          elif [[ "$bits" -le 800 ]]; then
               pr_litered "$bits $add"
          elif [[ "$bits" -le 1280 ]]; then
               pr_brown "$bits $add"
          elif [[ "$bits" -ge 2048 ]]; then
               pr_litegreen "$bits $add"
          else
               out "$bits $add"
          fi
     # https://wiki.openssl.org/index.php/Elliptic_Curve_Cryptography, http://www.keylength.com/en/compare/
     elif [[ $what_dh == "ECDH" ]]; then
          [[ -z "$2" ]] && add="bit ECDH"
          if [[ "$bits" -le 128 ]]; then     # has that ever existed?
               pr_red "$bits $add"
          elif [[ "$bits" -le 163 ]]; then
               pr_litered "$bits $add"
          elif [[ "$bits" -ge 224 ]]; then
               pr_litegreen "$bits $add"
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
     
     outln
     pr_headlineln " Testing server preferences "
     outln

     pr_bold " Has server cipher order?     "
     $OPENSSL s_client $STARTTLS -cipher $list_fwd $BUGS -connect $NODEIP:$PORT $PROXY $SNI </dev/null 2>$ERRFILE >$TMPFILE
     if ! sclient_connect_successful $? $TMPFILE && [[ -z "$STARTTLS_PROTOCOL" ]]; then
          pr_litemagenta "no matching cipher in this list found (pls report this): "
          outln "$list_fwd  . "
          has_cipher_order=false
          ret=6
     elif [[ -n "$STARTTLS_PROTOCOL" ]]; then
          # now it still could be that we hit this bug: https://github.com/drwetter/testssl.sh/issues/188
          # workaround is to connect with a protocol
          debugme out "(workaround #188) "
          determine_optimal_proto $STARTTLS_PROTOCOL             
          $OPENSSL s_client $STARTTLS $STARTTLS_OPTIMAL_PROTO -cipher $list_fwd $BUGS -connect $NODEIP:$PORT $PROXY $SNI </dev/null 2>$ERRFILE >$TMPFILE
          if ! sclient_connect_successful $? $TMPFILE; then
               pr_litemagenta "no matching cipher in this list found (pls report this): "
               outln "$list_fwd  . "
               has_cipher_order=false
               ret=6
          fi
     fi

     if $has_cipher_order; then
          cipher1=$(grep -wa Cipher $TMPFILE | egrep -avw "New|is" | sed -e 's/^ \+Cipher \+://' -e 's/ //g')
          $OPENSSL s_client $STARTTLS $STARTTLS_OPTIMAL_PROTO -cipher $list_reverse $BUGS -connect $NODEIP:$PORT $PROXY $SNI </dev/null 2>>$ERRFILE >$TMPFILE
          # that worked above so no error handling here
          cipher2=$(grep -wa Cipher $TMPFILE | egrep -avw "New|is" | sed -e 's/^ \+Cipher \+://' -e 's/ //g')

          if [[ "$cipher1" != "$cipher2" ]]; then
               pr_litered "nope (NOT ok)"
               remark4default_cipher=" (limited sense as client will pick)"
          else
               pr_green "yes (OK)"
               remark4default_cipher=""
          fi
          [[ $DEBUG -ge 2 ]] && out "  $cipher1 | $cipher2"
          outln

          pr_bold " Negotiated protocol          "
          $OPENSSL s_client $STARTTLS $BUGS -connect $NODEIP:$PORT $PROXY $SNI </dev/null 2>>$ERRFILE >$TMPFILE
          if ! sclient_connect_successful $? $TMPFILE; then
               # 2 second try with $OPTIMAL_PROTO especially for intolerant IIS6 servers:
               $OPENSSL s_client $STARTTLS $OPTIMAL_PROTO $BUGS -connect $NODEIP:$PORT $PROXY $SNI </dev/null 2>>$ERRFILE >$TMPFILE
               sclient_connect_successful $? $TMPFILE || pr_litemagenta "Handshake error!"
          fi
          default_proto=$(grep -aw "Protocol" $TMPFILE | sed -e 's/^.*Protocol.*://' -e 's/ //g')
          case "$default_proto" in
               *TLSv1.2)      pr_greenln $default_proto ;;
               *TLSv1.1)      pr_litegreenln $default_proto ;;
               *TLSv1)        outln $default_proto ;;
               *SSLv2)        pr_redln $default_proto ;;
               *SSLv3)        pr_redln $default_proto ;;
               "")            pr_litemagenta "default proto empty";  [[ $OSSL_VER == 1.0.2* ]] && outln " (Hint: if IIS6 give OpenSSL 1.01 a try)" ;; 
               *)             pr_litemagenta "FIXME line $LINENO: $default_proto" ;;
          esac

          pr_bold " Negotiated cipher            "
          default_cipher=$(grep -aw "Cipher" $TMPFILE | egrep -avw "New|is" | sed -e 's/^.*Cipher.*://' -e 's/ //g')
          case "$default_cipher" in
               *NULL*|*EXP*)  pr_red "$default_cipher" ;;
               *RC4*)         pr_litered "$default_cipher" ;;
               *CBC*)         pr_brown "$default_cipher" ;;   # FIXME BEAST: We miss some CBC ciphers here, need to work w/ a list
               *GCM*)         pr_green "$default_cipher" ;;   # best ones
               *CHACHA20*)    pr_green "$default_cipher" ;;   # best ones
               ECDHE*AES*)    pr_yellow "$default_cipher" ;;  # it's CBC. --> lucky13
               "")            pr_litemagenta "default cipher empty" ;  [[ $OSSL_VER == 1.0.2* ]] && out " (Hint: if IIS6 give OpenSSL 1.01 a try)" ;;
               *)             out "$default_cipher" ;;
          esac
          read_dhbits_from_file "$TMPFILE"
          outln "$remark4default_cipher"

          if [[ ! -z "$remark4default_cipher" ]]; then
               pr_bold " Negotiated cipher per proto"; outln " $remark4default_cipher"
               i=1
               for p in ssl2 ssl3 tls1 tls1_1 tls1_2; do
               #locally_supported -"$p" "    " || continue
               locally_supported -"$p" || continue
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
               if spdy_pre " $arg"; then                                                  # is NPN/SPDY supported and is this no STARTTLS? / no PROXY
                    $OPENSSL s_client -host $NODE -port $PORT $BUGS -nextprotoneg "$NPN_PROTOs" </dev/null 2>>$ERRFILE >$TMPFILE
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

cipher_pref_check() {
     local p proto protos
     local tested_cipher cipher

     pr_bold " Cipher order"

     for p in ssl2 ssl3 tls1 tls1_1 tls1_2; do
          $OPENSSL s_client $STARTTLS -"$p" $BUGS -connect $NODEIP:$PORT $PROXY $SNI </dev/null 2>$ERRFILE >$TMPFILE
          if sclient_connect_successful $? $TMPFILE; then
               tested_cipher=""
               proto=$(grep -aw "Protocol" $TMPFILE | sed -e 's/^.*Protocol.*://' -e 's/ //g')
               cipher=$(grep -aw "Cipher" $TMPFILE | egrep -avw "New|is" | sed -e 's/^.*Cipher.*://' -e 's/ //g')
               [[ -z "$proto" ]] && continue      # for early openssl versions sometimes needed
               outln
               printf "     %-10s %s " "$proto:" "$cipher"
               tested_cipher="-"$cipher
               while true; do
                    $OPENSSL s_client $STARTTLS -"$p" $BUGS -cipher "ALL:$tested_cipher" -connect $NODEIP:$PORT $PROXY $SNI </dev/null 2>>$ERRFILE >$TMPFILE
                    sclient_connect_successful $? $TMPFILE || break
                    cipher=$(grep -aw "Cipher" $TMPFILE | egrep -avw "New|is" | sed -e 's/^.*Cipher.*://' -e 's/ //g')
                    out "$cipher "
                    tested_cipher="$tested_cipher:-$cipher"
               done
          fi
     done
     outln

     if ! spdy_pre "     SPDY/NPN: "; then       # is NPN/SPDY supported and is this no STARTTLS?
          outln
     else
          protos=$($OPENSSL s_client -host $NODE -port $PORT $BUGS -nextprotoneg \"\" </dev/null 2>>$ERRFILE | grep -a "^Protocols " | sed -e 's/^Protocols.*server: //' -e 's/,//g')
          for p in $protos; do
               $OPENSSL s_client -host $NODE -port $PORT $BUGS -nextprotoneg "$p" $PROXY </dev/null 2>>$ERRFILE >$TMPFILE
               cipher=$(grep -aw "Cipher" $TMPFILE | egrep -avw "New|is" | sed -e 's/^.*Cipher.*://' -e 's/ //g')
               printf "     %-10s %s " "$p:" "$cipher"
               tested_cipher="-"$cipher
               while true; do
                    $OPENSSL s_client -cipher "ALL:$tested_cipher" -host $NODE -port $PORT $BUGS -nextprotoneg "$p" $PROXY </dev/null 2>>$ERRFILE >$TMPFILE
                    sclient_connect_successful $? $TMPFILE || break
                    cipher=$(grep -aw "Cipher" $TMPFILE | egrep -avw "New|is" | sed -e 's/^.*Cipher.*://' -e 's/ //g')
                    out "$cipher "
                    tested_cipher="$tested_cipher:-$cipher"
               done
          outln
          done
     fi

     outln
     tmpfile_handle $FUNCNAME.txt
     return 0
}


# arg1 is proto or empty
get_host_cert() {
     local tmpvar=$TEMPDIR/$FUNCNAME.txt     # change later to $TMPFILE

     $OPENSSL s_client $STARTTLS $BUGS -connect $NODEIP:$PORT $PROXY $SNI $1 2>/dev/null </dev/null >$TEMPDIR/$FUNCNAME.txt
     if sclient_connect_successful $? $tmpvar; then
          awk '/-----BEGIN/,/-----END/ { print $0 }' $tmpvar >$HOSTCERT
     else
          return 1
     fi
    #      return $((${PIPESTATUS[0]} + ${PIPESTATUS[1]}))
}

get_all_certs() {
     local savedir
     local nrsaved

     $OPENSSL s_client -showcerts $STARTTLS $BUGS -connect $NODEIP:$PORT $PROXY $SNI 2>$ERRFILE </dev/null >$TEMPDIR/allcerts.txt
     sclient_connect_successful $? $TMPFILE || \
          pr_litemagenta "problem getting all certs"
     savedir=$(pwd); cd $TEMPDIR
     # http://backreference.org/2010/05/09/ocsp-verification-with-openssl/
     awk -v n=-1 '/-----BEGIN CERTIFICATE-----/{ inc=1; n++ } 
             inc { print > ("level" n ".crt") }
             /---END CERTIFICATE-----/{ inc=0 }' $TEMPDIR/allcerts.txt
     nrsaved=$(count_words "$(echo level?.crt 2>/dev/null)")
     cd "$savedir"
     echo $nrsaved
}


verify_retcode_helper() {
     local ret=0

	case "$1" in
		# codes from ./doc/apps/verify.pod | verify(1ssl)
		*"24 "*      ) out " (certificate unreadable)" ;; 	# X509_V_ERR_INVALID_CA
		*23*revoked* ) out " (certificate revoked)" ;; 		# X509_V_ERR_CERT_REVOKED
		*21*unable*  ) out " (chain incomplete, only 1 cert provided)" ;; 	# X509_V_ERR_UNABLE_TO_VERIFY_LEAF_SIGNATURE
		*20*unable*  ) out " (chain incomplete)" ;;			# X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY
		*19*self*    ) out " (self signed CA in chain)" ;;	# X509_V_ERR_SELF_SIGNED_CERT_IN_CHAIN
		*18*self*    ) out " (self signed)" ;;				# X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT
		*10*expired* ) out " (expired)" ;;				     # X509_V_ERR_CERT_HAS_EXPIRED
		*"9 "*       ) out " (not yet valid)" ;;		     # X509_V_ERR_CERT_NOT_YET_VALID
		*"2 "*       ) out " (issuer cert missing)" ;;         # X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT
		*) ret=1 ; pr_litemagenta " (unknown, pls report) $1" ;;
	esac
     return $ret
}

determine_trust() {
	local i=1
	local bundle_fname
	local -a certificate_file verify_retcode trust 
	local ok_was=""
	local notok_was=""
     local code
     local ca_bundles="$INSTALL_DIR/etc/*.pem"
     local spaces="                              "

     if [[ $OSSL_VER_MAJOR.$OSSL_VER_MINOR == "1.1.0" ]]; then
          pr_litemagentaln "Your $OPENSSL is too new, needed is version 1.0.2"
          return 7
     elif [[ $OSSL_VER_MAJOR.$OSSL_VER_MINOR != "1.0.2" ]]; then
          pr_litemagentaln "Your $OPENSSL is too old, needed is version >=1.0.2"
     fi
     debugme outln
	for bundle_fname in $ca_bundles; do
		certificate_file[i]=$(basename $bundle_fname | sed 's/\.pem//')
          if [[ ! -r $bundle_fname ]]; then
               pr_litemagentaln "\"$bundle_fname\" cannot be found / not readable" 
               return 7
          fi
		debugme printf -- " %-12s" "${certificate_file[i]}"
		$OPENSSL s_client -purpose sslserver -CAfile $bundle_fname $STARTTLS $BUGS $PROXY -connect $NODEIP:$PORT $SNI </dev/null  >$TEMPDIR/${certificate_file[i]}.1 2>$TEMPDIR/${certificate_file[i]}.2
		verify_retcode[i]=$(awk -F':' '/Verify return code: / { print $2 }' $TEMPDIR//${certificate_file[i]}.1)
		if egrep -wq "ok|0" <<< ${verify_retcode[i]}; then
			trust[i]=true
			debugme pr_litegreen "Ok   "
			debugme outln "${verify_retcode[i]}"
		else
			trust[i]=false
			debugme pr_litered "not trusted"
			debugme outln "${verify_retcode[i]}"
		fi
		i=$(($i + 1))
	done
     debugme out " "
	# all stores ok
	if ${trust[1]} && ${trust[2]} && ${trust[3]} && ${trust[4]}; then
		pr_litegreen "Ok   "			
	# at least one failed
	else
		pr_litered "NOT ok"	
		# all failed (we assume with the same issue)
		if ! ${trust[1]} && ! ${trust[2]} && ! ${trust[3]} && ! ${trust[4]}; then
			verify_retcode_helper "${verify_retcode[2]}"
		else
			# is one ok and the others not?
			if ${trust[1]} || ${trust[2]} || ${trust[3]} || ${trust[4]}; then
				pr_litered ":"
				for i in 1 2 3 4; do
					if ${trust[i]}; then
						ok_was="${certificate_file[i]} $ok_was"
					else
                              #code="$(verify_retcode_helper ${verify_retcode[i]})"
                              #notok_was="${certificate_file[i]} $notok_was"
                              pr_litered "  ${certificate_file[i]}:"
                              verify_retcode_helper "${verify_retcode[i]}"
					fi
				done
				#pr_litered "$notok_was "
                    #outln "$code"
                    outln
				#lf + green ones
                    [[ $DEBUG -eq 0 ]] && out "$spaces"
				pr_litegreen "OK: $ok_was"
               fi
		fi
	fi
	outln
     return 0
}

# not handled: Root CA supplied (contains anchor)
# attention: 1.0.1 fails on mozilla


tls_time() {
     local now difftime

     tls_sockets "01" "$TLS_CIPHER"                              # try first TLS 1.0 (mostfrequently used protocol)
     [[ -z "$TLS_TIME" ]] && tls_sockets "03" "$TLS12_CIPHER"    #           TLS 1.2
     [[ -z "$TLS_TIME" ]] && tls_sockets "02" "$TLS_CIPHER"      #           TLS 1.1
     [[ -z "$TLS_TIME" ]] && tls_sockets "00" "$TLS_CIPHER"      #           SSL 3

     if [[ -n "$TLS_TIME" ]]; then                               # nothing returned a time!
          difftime=$(($TLS_TIME - $TLS_NOW))                     # TLS_NOW is being set in tls_sockets()
          if [[ "${#difftime}" -gt 5 ]]; then
               # openssl >= 1.0.1f fills this field with random values! --> good for possible fingerprint
               pr_bold " TLS timestamp" ; outln "                random values, no fingerprinting possible "
          else
               [[ $difftime != "-"* ]] && [[ $difftime != "0" ]] && difftime="+$difftime"
               pr_bold " TLS clock skew" ; outln "               $difftime sec from localtime";
          fi
          debugme out "$TLS_TIME"
          outln
     else
          pr_bold " TLS timestamp" ; out "                "; pr_litemagentaln "SSLv3 through TLS 1.2 didn't return a timestamp"
     fi
     return 0
}

# core function determining whether handshake succeded or not
#
sclient_connect_successful() {
     [[ $1 -eq 0 ]] && return 0
     [[ -n $(awk '/Master-Key: / { print $2 }' "$2") ]] && return 0
     # second check saved like 
     # fgrep 'Cipher is (NONE)' "$2" &> /dev/null && return 1
     # what's left now is: master key empty and Session-ID not empty ==> probably client based auth with x509 certificate
     return 1
}


determine_tls_extensions() {
     local proto
     local success
     local alpn=""

     $HAS_ALPN && alpn="h2-14,h2-15,h2"

     # throwing 1st every cipher/protocol at the server to know what works
     success=7
     for proto in tls1_2 tls1_1 tls1 ssl3; do
# alpn: echo | openssl s_client -connect google.com:443 -tlsextdebug -alpn h2-14 -servername google.com  <-- suport needs to be checked b4 -- see also: ssl/t1_trce.c
          $OPENSSL s_client $STARTTLS $BUGS -connect $NODEIP:$PORT $PROXY $SNI -$proto -tlsextdebug -nextprotoneg $alpn -status </dev/null 2>$ERRFILE >$TMPFILE
          sclient_connect_successful $? $TMPFILE && success=0 && break
     done                          # this loop is needed for IIS/6
     if [[ $success -eq 7 ]]; then
          # "-status" above doesn't work for GOST only servers, so we do another test without it and see whether that works then:
          $OPENSSL s_client $STARTTLS $BUGS -connect $NODEIP:$PORT $PROXY $SNI -$proto -tlsextdebug </dev/null 2>>$ERRFILE >$TMPFILE
          if ! sclient_connect_successful $? $TMPFILE; then
               pr_litemagentaln "Strange, no SSL/TLS protocol seems to be supported (error around line $((LINENO - 6)))"
               tmpfile_handle $FUNCNAME.txt
               return 7  # this is ugly, I know
          else
               GOST_STATUS_PROBLEM=true
          fi
     fi
     TLS_EXTENSIONS=$(awk -F'"' '/TLS server extension / { printf "\""$2"\" " }' $TMPFILE)
     get_host_cert "-$proto"
     success=$?

     tmpfile_handle $FUNCNAME.txt
     return $success
}


run_server_defaults() {
     local proto
     local sessticket_str lifetime unit keysize sig_algo key_algo
     local expire secs2warn ocsp_uri crl startdate enddate issuer_C issuer_O issuer sans san cn cn_nosni
     local policy_oid
     local spaces="                              "
     local wildcard=false

     outln
     pr_headlineln " Testing server defaults (Server Hello) "
     outln

     pr_bold " TLS server extensions (std)  "
     [[ -z "$TLS_EXTENSIONS" ]] && determine_tls_extensions

     #extensions=$(grep -aw "^TLS server extension" $TMPFILE | sed -e 's/^TLS server extension \"//' -e 's/\".*$/,/g')
     if [[ -z "$TLS_EXTENSIONS" ]]; then
          outln "(none)"
     else
          #echo $extensions | sed 's/ /,/g' 
          outln "$TLS_EXTENSIONS"
     fi

     cp "$TEMPDIR/$NODEIP.determine_tls_extensions.txt" $TMPFILE
     >$ERRFILE

     pr_bold " Session Tickets RFC 5077     "
     sessticket_str=$(grep -aw "session ticket" $TMPFILE | grep -a lifetime)
     if [[ -z "$sessticket_str" ]]; then
          outln "(none)"
     else
          lifetime=$(echo $sessticket_str | grep -a lifetime | sed 's/[A-Za-z:() ]//g')
          unit=$(echo $sessticket_str | grep -a lifetime | sed -e 's/^.*'"$lifetime"'//' -e 's/[ ()]//g')
          out "$lifetime $unit "
          pr_yellowln "(PFS requires session ticket keys to be rotated <= daily)"
     fi
 
     pr_bold " SSL Session ID support       "
     if $NO_SSL_SESSIONID; then
          outln "no"
     else
          outln "yes"
     fi

     pr_bold " Server key size              "
     keysize=$(grep -aw "^Server public key is" $TMPFILE | sed -e 's/^Server public key is //' -e 's/bit//' -e 's/ //')
     sig_algo=$($OPENSSL x509 -in $HOSTCERT -noout -text 2>>$ERRFILE | grep "Signature Algorithm" | sed 's/^.*Signature Algorithm: //' | sort -u )
     key_algo=$($OPENSSL x509 -in $HOSTCERT -noout -text 2>>$ERRFILE | awk -F':' '/Public Key Algorithm:/ { print $2 }' | sort -u )

     if [[ -z "$keysize" ]]; then
          outln "(couldn't determine)"
     else
          if [[ "$keysize" -le 768 ]]; then
               if [[ $sig_algo =~ ecdsa ]] || [[ $key_algo =~ ecPublicKey  ]]; then
                    pr_litegreen "EC $keysize"
               else
                    pr_red "$keysize"
               fi
          elif [[ "$keysize" -le 1024 ]]; then
               pr_brown "$keysize"
          elif [[ "$keysize" -le 2048 ]]; then
               out "$keysize"
          elif [[ "$keysize" -le 4096 ]]; then
               pr_litegreen "$keysize"
          else
               out "weird keysize: $keysize"
          fi
     fi
     outln " bit"

     pr_bold " Signature Algorithm          "
     case $sig_algo in
          sha1WithRSAEncryption)   pr_brownln "SHA1 with RSA" ;;
          sha256WithRSAEncryption) pr_litegreenln "SHA256 with RSA" ;;
          sha384WithRSAEncryption) pr_litegreenln "SHA384 with RSA" ;;
          sha512WithRSAEncryption) pr_litegreenln "SHA512 with RSA" ;;
          ecdsa-with-SHA256)       pr_litegreenln "ECDSA with SHA256" ;;
          md5*)                    pr_redln "MD5" ;;
          *)                       outln "$sig_algo" ;;
     esac
     # old, but interesting: https://blog.hboeck.de/archives/754-Playing-with-the-EFF-SSL-Observatory.html

     pr_bold " Fingerprint / Serial         "
     outln "$($OPENSSL x509 -noout -in $HOSTCERT -fingerprint -sha1 2>>$ERRFILE | sed 's/Fingerprint=//' | sed 's/://g' ) / $($OPENSSL x509 -noout -in $HOSTCERT -serial 2>>$ERRFILE | sed 's/serial=//')"
     outln "$spaces$($OPENSSL x509 -noout -in $HOSTCERT -fingerprint -sha256 2>>$ERRFILE | sed 's/Fingerprint=//' | sed 's/://g' )"

     pr_bold " Common Name (CN)             "
     if $OPENSSL x509 -in $HOSTCERT -noout -subject 2>>$ERRFILE | grep -wq CN; then
          cn=$($OPENSSL x509 -in $HOSTCERT -noout -subject 2>>$ERRFILE | sed 's/subject= //' | sed -e 's/^.*CN=//' -e 's/\/emailAdd.*//')
          pr_dquoted "$cn"
          if echo -n "$cn" | grep -q '^*.' ; then
               out " (wildcard certificate"
               if [[ "$cn" == "*.$(echo -n "$cn" | sed 's/^\*.//')" ]]; then
                    out " match)"
                    wildcard=true
               else
                    :
                    #FIXME: we need to test also the SANs as they can contain a wild card (google.de .e.g) ==> 2.7dev
               fi
          fi
     else
          cn="(no CN field in subject)"
          out "$cn"
     fi

     $OPENSSL s_client $STARTTLS $BUGS -connect $NODEIP:$PORT $PROXY $OPTIMAL_PROTO 2>>$ERRFILE </dev/null | awk '/-----BEGIN/,/-----END/ { print $0 }'  >$HOSTCERT.nosni
     cn_nosni=""
     if [[ -s $HOSTCERT.nosni ]]; then
          if $OPENSSL x509 -in $HOSTCERT.nosni -noout -subject 2>>$ERRFILE | grep -wq CN; then
               cn_nosni=$($OPENSSL x509 -in $HOSTCERT.nosni -noout -subject 2>>$ERRFILE | sed 's/subject= //' | sed -e 's/^.*CN=//' -e 's/\/emailAdd.*//')
          else
               cn_nosni="no CN field in subject"
          fi
     fi
#FIXME: check for SSLv3/v2 and look wheher it goes to a different CN

     debugme out "\"$NODE\" | \"$cn\" | \"$cn_nosni\""
     if [[ $NODE == "$cn_nosni" ]]; then
          if [[ $SERVICE == "HTTP" ]] || $CLIENT_AUTH; then
               outln " (works w/o SNI)"
          else
               outln " (matches certificate directly)"
               # for services != HTTP it depends on the protocol, server and client but it is not named "SNI"
          fi
     else
          if [[ $SERVICE != "HTTP" ]]; then
               outln
               #pr_brownln " (non-SNI clients don't match CN but for non-HTTP services it might be ok)"
               #FIXME: this is irritating and needs to be redone. Then also the wildcard match needs to be tested against  "$cn_nosni"
          elif [[ -z "$cn_nosni" ]]; then
               out " (request w/o SNI didn't succeed";
               [[ $sig_algo =~ ecdsa ]] && out ", usual for EC certificates"
               outln ")"
          elif [[ "$cn_nosni" == "*no CN field*" ]]; then
               outln ", (request w/o SNI: $cn_nosni)"
          else
               out " (CN in response to request w/o SNI: "; pr_dquoted "$cn_nosni"; outln ")"
          fi
     fi

     sans=$($OPENSSL x509 -in $HOSTCERT -noout -text 2>>$ERRFILE | grep -A3 "Subject Alternative Name" | grep "DNS:" | \
          sed -e 's/DNS://g' -e 's/ //g' -e 's/,/ /g' -e 's/othername:<unsupported>//g')
#                                                       ^^^ CACert

     pr_bold " subjectAltName (SAN)         "
     if [[ -n "$sans" ]]; then
          for san in $sans; do
               pr_dquoted "$san"
               out " "
          done
     else
          out "-- "
     fi
     outln
     pr_bold " Issuer                       "
     issuer=$($OPENSSL x509 -in $HOSTCERT -noout -issuer 2>>$ERRFILE| sed -e 's/^.*CN=//g' -e 's/\/.*$//g')
     issuer_O=$($OPENSSL x509 -in $HOSTCERT -noout -issuer 2>>$ERRFILE | sed 's/^.*O=//g' | sed 's/\/.*$//g')
     if $OPENSSL x509 -in $HOSTCERT -noout -issuer 2>>$ERRFILE | grep -q 'C=' ; then
          issuer_C=$($OPENSSL x509 -in $HOSTCERT -noout -issuer 2>>$ERRFILE | sed 's/^.*C=//g' | sed 's/\/.*$//g')
     else
          issuer_C=""         # CACert would have 'issuer= ' here otherwise
     fi
     if [[ "$issuer_O" == "issuer=" ]] || [[ "$issuer_O" == "issuer= " ]] || [[ "$issuer" == "$CN" ]]; then
          pr_redln "selfsigned (NOT ok)"
     else
          pr_dquoted "$issuer"
          out " ("
          pr_dquoted "$issuer_O"
          if [[ -n "$issuer_C" ]]; then
               out " from " 
               pr_dquoted "$issuer_C"
          fi
          outln ")"
     fi

     # http://events.ccc.de/congress/2010/Fahrplan/attachments/1777_is-the-SSLiverse-a-safe-place.pdf, see page 40pp
     pr_bold " EV cert"; out " (experimental)       "
     policy_oid=$($OPENSSL x509 -in $HOSTCERT -text 2>>$ERRFILE | awk '/ .Policy: / { print $2 }')
     if echo "$issuer" | egrep -q 'Extended Validation|Extended Validated|EV SSL|EV CA' || \
          [[ 2.16.840.1.114028.10.1.2 == "$policy_oid" ]] || \
          [[ 2.16.840.1.114412.1.3.0.2 == "$policy_oid" ]] || \
          [[ 2.16.840.1.114412.2.1 == "$policy_oid" ]] || \
          [[ 2.16.578.1.26.1.3.3 == "$policy_oid" ]] || \
          [[ 1.3.6.1.4.1.17326.10.14.2.1.2 == "$policy_oid" ]] || \
          [[ 1.3.6.1.4.1.17326.10.8.12.1.2 == "$policy_oid" ]] || \
          [[ 1.3.6.1.4.1.13177.10.1.3.10 == "$policy_oid" ]] ; then     
          out "yes "
     else
          out "no "
     fi
     debugme echo "($(newline_to_spaces "$policy_oid"))"
     outln
#TODO: use browser OIDs: 
#         https://mxr.mozilla.org/mozilla-central/source/security/certverifier/ExtendedValidation.cpp
#         http://src.chromium.org/chrome/trunk/src/net/cert/ev_root_ca_metadata.cc
#         https://certs.opera.com/03/ev-oids.xml

     pr_bold " Certificate Expiration       "
     expire=$($OPENSSL x509 -in $HOSTCERT -checkend 0 2>>$ERRFILE)
     if ! echo $expire | grep -qw not; then
     pr_red "expired!"
     else
          secs2warn=$((24 * 60 * 60 * DAYS2WARN2))  # low threshold first
          expire=$($OPENSSL x509 -in $HOSTCERT -checkend $secs2warn 2>>$ERRFILE)
          if echo "$expire" | grep -qw not; then
               secs2warn=$((24 * 60 * 60 * DAYS2WARN1))
               expire=$($OPENSSL x509 -in $HOSTCERT -checkend $secs2warn 2>>$ERRFILE)
               if echo "$expire" | grep -qw not; then
                    pr_litegreen ">= $DAYS2WARN1 days"
               else
               pr_brown "expires < $DAYS2WARN1 days"
               fi
          else
               pr_litered "expires < $DAYS2WARN2 days!"
          fi
     fi
     if $HAS_GNUDATE ; then
          enddate=$(date --date="$($OPENSSL x509 -in $HOSTCERT -noout -enddate 2>>$ERRFILE | cut -d= -f 2)" +"%F %H:%M %z")
          startdate=$(date --date="$($OPENSSL x509 -in $HOSTCERT -noout -startdate 2>>$ERRFILE | cut -d= -f 2)" +"%F %H:%M")
     else
          enddate=$(LC_ALL=C date -j -f "%b %d %T %Y %Z" "$($OPENSSL x509 -in $HOSTCERT -noout -enddate 2>>$ERRFILE | cut -d= -f 2)" +"%F %H:%M %z")
          startdate=$(LC_ALL=C date -j -f "%b %d %T %Y %Z" "$($OPENSSL x509 -in $HOSTCERT -noout -startdate 2>>$ERRFILE | cut -d= -f 2)" +"%F %H:%M")
     fi
     outln " ($startdate --> $enddate)"


     pr_bold " # of certificates provided"; outln "   $(get_all_certs)"

     pr_bold " Chain of trust"; out " (experim.)    "
     determine_trust

     pr_bold " Certificate Revocation List  "
     crl="$($OPENSSL x509 -in $HOSTCERT -noout -text 2>>$ERRFILE | grep -A 4 "CRL Distribution" | grep URI | sed 's/^.*URI://')"
     if [[ -z "$crl" ]]; then
          pr_literedln "--"
     elif grep -q http <<< "$crl"; then
          if [[ $(count_lines "$crl") -eq 1 ]]; then
               outln "$crl"
          else # more than one CRL
               out_row_aligned "$crl" "$spaces" 
          fi
     else
          pr_litemagentaln "no parsable output \"$url\", pls report"
     fi

     pr_bold " OCSP URI                     "
     ocsp_uri=$($OPENSSL x509 -in $HOSTCERT -noout -ocsp_uri 2>>$ERRFILE)
     [[ x"$ocsp_uri" == "x" ]] && pr_literedln "--" || echo "$ocsp_uri"

     pr_bold " OCSP stapling               "
     if grep -a "OCSP response" $TMPFILE | grep -q "no response sent" ; then
          out " not offered"
     else
          if grep -a "OCSP Response Status" $TMPFILE | grep -q successful; then
               pr_litegreen " offered"
          else
               if $GOST_STATUS_PROBLEM; then
                    out " (GOST servers make problems here, sorry)"
                    ret=0
               else
                    outln " not sure what's going on here, debug:"
                    grep -aA 20 "OCSP response"  $TMPFILE
                    ret=2
               fi
          fi
     fi
     outln

     # if we call tls_time before tmpfile_handle it throws an error because the function tls_sockets removed $TMPFILE 
     # already -- and that was a different one -- means that would get overwritten anyway
     tmpfile_handle $FUNCNAME.txt

     tls_time
     return $ret
}
# FIXME: revoked, see checkcert.sh
# FIXME: Trust (only CN)

# http://www.heise.de/security/artikel/Forward-Secrecy-testen-und-einrichten-1932806.html
run_pfs() {
     local -i sclient_success
     local -i pfs_offered=1
     local tmpfile
     local dhlen
     local hexcode dash pfs_cipher sslvers kx auth enc mac
     # https://community.qualys.com/blogs/securitylabs/2013/08/05/configuring-apache-nginx-and-openssl-for-forward-secrecy -- but with RC4:
     #local pfs_ciphers='EECDH+ECDSA+AESGCM EECDH+aRSA+AESGCM EECDH+ECDSA+SHA256 EECDH+aRSA+SHA256 EECDH+aRSA+RC4 EDH+aRSA EECDH RC4 !RC4-SHA !aNULL !eNULL !LOW !3DES !MD5 !EXP !PSK !SRP !DSS:@STRENGTH'
     #w/o RC4:
     #local pfs_ciphers='EECDH+ECDSA+AESGCM EECDH+aRSA+AESGCM EECDH+ECDSA+SHA256 EECDH+aRSA+SHA256 EDH+aRSA EECDH !RC4-SHA !aNULL !eNULL !LOW !3DES !MD5 !EXP !PSK !SRP !DSS:@STRENGTH'
     local pfs_cipher_list="ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:DHE-RSA-CHACHA20-POLY1305:DHE-RSA-AES256-GCM-SHA384:DHE-RSA-AES256-SHA256:DHE-RSA-AES256-SHA:DHE-RSA-CAMELLIA256-SHA256:DHE-RSA-CAMELLIA256-SHA:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:ECDHE-RSA-AES256-SHA384:ECDHE-ECDSA-AES256-SHA384:ECDHE-RSA-AES256-SHA:ECDHE-ECDSA-AES256-SHA:ECDHE-RSA-CAMELLIA256-SHA384:ECDHE-ECDSA-CAMELLIA256-SHA384:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES128-SHA256:ECDHE-ECDSA-CAMELLIA128-SHA256:ECDHE-RSA-AES128-SHA256:ECDHE-RSA-CAMELLIA128-SHA256:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES128-SHA256:DHE-RSA-AES128-SHA:DHE-RSA-CAMELLIA128-SHA256:DHE-RSA-SEED-SHA:DHE-RSA-CAMELLIA128-SHA:ECDHE-RSA-AES128-SHA:ECDHE-ECDSA-AES128-SHA:ECDHE-RSA-RC4-SHA:ECDHE-ECDSA-RC4-SHA"
     local -i nr_supported_ciphers=0

     outln
     pr_headlineln " Testing (perfect) forward secrecy, (P)FS -- omitting 3DES, RC4 and Null Encryption here "
     ! $HAS_DH_BITS && $WIDE && pr_litemagentaln "    (Your $OPENSSL cannot show DH/ECDH bits)"

     nr_supported_ciphers=$(count_ciphers $(actually_supported_ciphers $pfs_cipher_list))
     if [[ "$nr_supported_ciphers" -le "$CLIENT_MIN_PFS" ]]; then
          outln
          local_problem "You only have $nr_supported_ciphers PFS ciphers on the client side "
          return 1
     fi

     $OPENSSL s_client -cipher 'ECDH:DH' $STARTTLS $BUGS -connect $NODEIP:$PORT $PROXY $SNI >$TMPFILE 2>$ERRFILE </dev/null
     sclient_connect_successful $? $TMPFILE
     sclient_success=$?
     outln
     if [[ $sclient_success -ne 0 ]] || [[ $(grep -ac "BEGIN CERTIFICATE" $TMPFILE) -eq 0 ]]; then
          pr_brownln "Not OK: No ciphers supporting Forward Secrecy offered"
     else
          pfs_offered=0
          pr_litegreen " PFS is offered (OK)"
          if $WIDE; then
               outln ", ciphers follow (client/browser support is here specially important) \n"
               neat_header
          else
               out "  "
          fi
          while read hexcode dash pfs_cipher sslvers kx auth enc mac; do
               tmpfile=$TMPFILE.$hexcode
               $OPENSSL s_client -cipher $pfs_cipher $STARTTLS $BUGS -connect $NODEIP:$PORT $PROXY $SNI &>$tmpfile </dev/null
               sclient_connect_successful $? $tmpfile
               sclient_success=$?
               if [[ $sclient_success -ne 0 ]] && [[ "$SHOW_EACH_C" -eq 0 ]]; then
                    continue # no successful connect AND not verbose displaying each cipher
               fi
               if $WIDE; then
                    normalize_ciphercode $hexcode
                    if [[ $kx == "Kx=ECDH" ]] || [[ $kx == "Kx=DH" ]] || [[ $kx == "Kx=EDH" ]]; then
                         dhlen=$(read_dhbits_from_file "$tmpfile" quiet)
                         kx="$kx $dhlen"
                    fi
                    neat_list $HEXC $pfs_cipher "$kx" $enc $strength
                    let "pfs_offered++"
                    if [[ "$SHOW_EACH_C" -ne 0 ]]; then
                         if [[ $sclient_success -eq 0 ]]; then
                              pr_green "works"
                         else
                              out "not a/v"
                         fi
                    fi
                    outln
               else
                    out "$pfs_cipher "
               fi
          done < <($OPENSSL ciphers -V "$pfs_cipher_list" 2>$ERRFILE)      # -V doesn't work with openssl < 1.0
          #    ^^^^^ posix redirect as shopt will either segfault or doesn't work with old bash versions
          debugme echo $pfs_offered
          $WIDE || outln

          if [[ "$pfs_offered" -eq 1 ]]; then
                pr_brown "no PFS ciphers found"
          fi
     fi
     outln

     debugme echo $(actually_supported_ciphers $pfs_cipher_list)
     debugme echo $nr_supported_ciphers

     tmpfile_handle $FUNCNAME.txt
#     sub1_curves
     return $pfs_offered
}


# good source for configuration and bugs: https://wiki.mozilla.org/Security/Server_Side_TLS
# good start to read: http://en.wikipedia.org/wiki/Transport_Layer_Security#Attacks_against_TLS.2FSSL


spdy_pre(){
     if [[ -n "$STARTTLS" ]]; then
          [[ -n "$1" ]] && out "$1"
          out "(SPDY is a HTTP protocol and thus not tested here)"
          return 1
     fi
     if [[ -n "$PROXY" ]]; then
          [[ -n "$1" ]] && pr_litemagenta " $1 "
          pr_litemagenta "not tested as proxies do not support proxying it"
          return 1
     fi
     if ! $HAS_SPDY; then
          local_problem "$OPENSSL doesn't support SPDY/NPN";
          return 7
     fi
     return 0
}

run_spdy() {
     local tmpstr
     local -i ret=0

     pr_bold " SPDY/NPN   "
     if ! spdy_pre ; then
          outln "\n"
          return 0
     fi
     $OPENSSL s_client -host $NODE -port $PORT $BUGS -nextprotoneg $NPN_PROTOs </dev/null 2>$ERRFILE >$TMPFILE
     tmpstr=$(grep -a '^Protocols' $TMPFILE | sed 's/Protocols.*: //')
     if [[ -z "$tmpstr" ]] || [[ "$tmpstr" == " " ]]; then
          outln "not offered"
          ret=1
     else
          # now comes a strange thing: "Protocols advertised by server:" is empty but connection succeeded
          if echo $tmpstr | egrep -aq "spdy|http" ; then
               out "$tmpstr" 
               outln " (advertised)"
               ret=0
          else
               pr_litemagentaln "please check manually, server response was ambigious ..."
               ret=10
          fi
     fi
     outln
     # btw: nmap can do that too http://nmap.org/nsedoc/scripts/tls-nextprotoneg.html
     # nmap --script=tls-nextprotoneg #NODE -p $PORT is your friend if your openssl doesn't want to test this
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
     local tls_content_type tls_protocol tls_len_all
#TODO: all vars here

     TLS_TIME=""
     DETECTED_TLS_VERSION=""

     # server hello, handshake details see http://en.wikipedia.org/wiki/Transport_Layer_Security-SSL#TLS_record
     # byte 0:      content type:                 0x14=CCS,    0x15=TLS alert  x16=Handshake,  0x17 Aplication, 0x18=HB
     # byte 1+2:    TLS version word, major is 03, minor 00=SSL3, 01=TLS1 02=TLS1.1 03=TLS 1.2
     # byte 3+4:    length all
     # byte 5:      handshake type (2=hello)      TLS alert: level (2=fatal), descr (0x28=handshake failure)
     # byte 6+7+8:  length server hello
     # byte 9+10:   03, TLS version word          see byte 1+2
     # byte 11-14:  TLS timestamp                 for OpenSSL <1.01f
     # byte 15-42:  random, 28 bytes
     # byte 43:     session id length
     # byte 44+45+sid-len:  cipher suite!
     # byte 46+sid-len:     compression method:  00: none, 01: deflate
     # byte 47+48+sid-len:  extension length

     [[ "$DEBUG" -eq 5 ]] && echo $tls_hello_ascii      # one line without any blanks
     if [[ -z "$tls_hello_ascii" ]]; then
          debugme echo "server hello empty, TCP connection closed" 
          return 1              # no server hello received
     fi

     # now scrape two bytes out of the reply per byte
     tls_content_type="${tls_hello_ascii:0:2}"         # normally this is x16 (Handshake) here
     tls_protocol="${tls_hello_ascii:2:4}"
     DETECTED_TLS_VERSION=$tls_protocol

     tls_len_all=${tls_hello_ascii:6:4}

     sid_len_offset=86
     tls_hello="${tls_hello_ascii:10:2}"               # normally this is x02
     tls_protocol2="${tls_hello_ascii:18:4}"
     tls_hello_time="${tls_hello_ascii:22:8}"

     if [[ $tls_content_type == "15" ]]; then          # TLS ALERT
          tls_err_level=${tls_hello_ascii:10:2}        # 1: warning, 2: fatal
          tls_err_descr=${tls_hello_ascii:12:2}        # 112/0x70: Unrecognized name, 111/0x6F: certificate_unobtainable, 
                                                       # 113/0x71: bad_certificate_status_response, #114/0x72: bad_certificate_hash_value
          if [[ $DEBUG -ge 2 ]]; then
               echo "tls_protocol (reclyr):  0x$tls_protocol"
               echo "tls_content_type:       0x$tls_content_type"
               echo "tls_len_all:            $tls_len_all"
               echo "tls_err_descr:          0x${tls_err_descr} / = $(hex2dec ${tls_err_descr})"
               echo "tls_err_level:          ${tls_err_level} (warning:1, fatal:2)"  
          fi
          # now, here comes a strange thing... -- on the first glance
          # IF an apache 2.2/2.4 server e.g. has a default servername configured but we send SNI <myhostname>
          # we get a TLS ALERT saying "unrecognized_name" (0x70) and a warning (0x1), see RFC https://tools.ietf.org/html/rfc6066#page-17
          # note that RFC recommended to fail instead: https://tools.ietf.org/html/rfc6066#section-3
          # we need to handle this properly -- otherwise we always return that the protocol or cipher is not available!
          if [[ "$tls_err_descr" == 70 ]] && [[ "${tls_err_level}" == "01" ]]; then
               sid_len_offset=100                      # we are 2x7 bytes off (formerly: 86 instead of 100)
               tls_hello="${tls_hello_ascii:24:2}"     # here, too       (normally this is (02)
               tls_protocol2="${tls_hello_ascii:32:4}" # here, too
               tls_hello_time="${tls_hello_ascii:36:8}"     # and here, too
          else
               return 1
          fi
     fi

     TLS_TIME=$(hex2dec "$tls_hello_time")
     tls_sid_len=$(hex2dec "${tls_hello_ascii:$sid_len_offset:2}")
     let sid_offset=$sid_len_offset+2+$tls_sid_len*2
     tls_cipher_suite="${tls_hello_ascii:$sid_offset:4}"
     let sid_offset=$sid_len_offset+6++$tls_sid_len*2
     tls_compression_method="${tls_hello_ascii:$sid_offset:2}"

     if [[ $DEBUG -ge 2 ]]; then
          echo "tls_protocol (reclyr):  0x$tls_protocol"
          echo "tls_hello:              0x$tls_hello"
          if [[ $DEBUG -ge 4 ]]; then
               echo "tls_protocol:           0x$tls_protocol2"
               echo "tls_sid_len:            0x$(dec2hex $tls_sid_len) / = $tls_sid_len"
          fi
          echo -n "tls_hello_time:         0x$tls_hello_time "
          if $HAS_GNUDATE ; then
               date --date="@$TLS_TIME" "+%Y-%m-%d %r"
          else
               LC_ALL=C date -j -f %s "$TLS_TIME" "+%Y-%m-%d %r"
          fi
          echo "tls_cipher_suite:       0x$tls_cipher_suite"
          echo "tls_compression_method: 0x$tls_compression_method"
          outln
     fi
     return 0
}


sslv2_sockets() {
     local ciphers_detected

     fd_socket 5 || return 6
     [[ "$DEBUG" -ge 2 ]] && outln "sending client hello... "
     socksend_sslv2_clienthello "$SSLv2_CLIENT_HELLO"

     sockread_serverhello 32768
     [[ "$DEBUG" -ge 2 ]] && outln "reading server hello... "
     if [[ "$DEBUG" -ge 4 ]]; then
          hexdump -C "$SOCK_REPLY_FILE" | head -6
          outln
     fi

     parse_sslv2_serverhello "$SOCK_REPLY_FILE"
     case $? in
          7) # strange reply, couldn't convert the cipher spec length to a hex number
               pr_litemagenta "strange v2 reply "
               outln " (rerun with DEBUG >=2)"
               [[ $DEBUG -ge 3 ]] && hexdump -C "$SOCK_REPLY_FILE" | head -1
               ret=7 ;;
          1) # no sslv2 server hello returned, like in openlitespeed which returns HTTP!
               pr_greenln "not offered (OK)"
               ret=0 ;;
          0) # reset
               pr_greenln "not offered (OK)"
               ret=0 ;;
          3) # everything else
               lines=$(hexdump -C "$SOCK_REPLY_FILE" 2>/dev/null | wc -l | sed 's/ //g')
               [[ "$DEBUG" -ge 2 ]] && out "  ($lines lines)  "
               if [[ "$lines" -gt 1 ]]; then
                    ciphers_detected=$((V2_HELLO_CIPHERSPEC_LENGTH / 3))
                    if [[ 0 -eq "$ciphers_detected" ]]; then
                         pr_litered "supported but couldn't detect a cipher"; outln " (may need further attention)"
                    else
                         pr_red "offered (NOT ok)"; outln " -- $ciphers_detected ciphers"
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
#FIXME: redo this with all extensions!
     local tls_low_byte="$1"
     local tls_word_reclayer="03, 01"      # the first TLS version number is the record layer and always 0301 -- except: SSLv3
     local servername_hexstr len_servername len_servername_hex
     local hexdump_format_str
     local all_extensions
     local len_sni_listlen len_sni_ext len_extension_hex
     local cipher_suites len_ciph_suites len_ciph_suites_word
     local len_client_hello_word len_all_word
     
     #len_servername=$(echo ${#NODE})
     len_servername=${#NODE}
     hexdump_format_str="$len_servername/1 \"%02x,\""
     servername_hexstr=$(printf $NODE | hexdump -v -e "${hexdump_format_str}" | sed 's/,$//')

     code2network "$2"             # convert CIPHER_SUITES
     cipher_suites="$NW_STR"       # we don't have the leading \x here so string length is two byte less, see next

#formatted example for SNI
#00 00    # extension server_name
#00 1a    # length                      = the following +2 = server_name length + 5
#00 18    # server_name list_length     = server_name length +3
#00       # server_name type (hostname)
#00 15    # server_name length
#66 66 66 66 66 66 2e 66 66 66 66 66 66 66 66 66 66 2e 66 66 66  target.mydomain1.tld # server_name target

     # convert lengths we need to fill in from dec to hex:
     len_servername_hex=$(printf "%02x\n" $len_servername)
     len_sni_listlen=$(printf "%02x\n" $((len_servername+3)))
     len_sni_ext=$(printf "%02x\n" $((len_servername+5)))
     len_extension_hex=$(printf "%02x\n" $((len_servername+9)))  #FIXME: for TLS 1.2 and IIS servers we need extension_signature_algorithms!!

     len_ciph_suites_byte=$(echo ${#cipher_suites})
     let "len_ciph_suites_byte += 2"

     # we have additional 2 chars \x in each 2 byte string and 2 byte ciphers, so we need to divide by 4:
     len_ciph_suites=$(printf "%02x\n" $(($len_ciph_suites_byte / 4 )))
     len2twobytes "$len_ciph_suites"
     len_ciph_suites_word="$LEN_STR"
     #[[ $DEBUG -ge 3 ]] && echo $len_ciph_suites_word

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

#TODO,add (see heartbleed)
# extension lenghth (word)
# extension ec_point_formats (4 words) 1st: 00 0b
#len                              00 04
# ec prot formats len:            03
# uncompressed                    00
# EC point format: ansiX962_compressed_prime  01
# EC point format: ansiX962_compressed_char2  02

# ec, 1st:                 00 0a
#     2nd length: (word)         e.g. 0x34
#     3rd: ec curve len    ln-2  e.g. 0x32
#     4.-n.  curves              e.g. 25 words

# Extension: Session Ticket        00 23

     extension_signature_algorithms="
     00, 0d,                    # Type: signature_algorithms , see RFC 5246
     00, 20,                    # len
     00,1e, 06,01, 06,02, 06,03, 05,01, 05,02, 05,03, 
     04,01, 04,02, 04,03, 03,01, 03,02, 03,03, 02,01, 02,02, 02,03"

# Extension: Haertbeat             00 0f 
# len                              00 01
# peer allowed to send requests       01

     if [[ "$tls_low_byte" == "00" ]]; then
          all_extensions=""
     else                          #FIXME: we (probably) need extension_signature_algorithms here. TLS 1.2 fails on IIS otherwise
          all_extensions="
          ,00, $len_extension_hex  # first the len of all (here: 1) extentions. We assume len(hostname) < FF - 9
          ,00, 00                  # extension server_name
          ,00, $len_sni_ext        # length SNI EXT
          ,00, $len_sni_listlen    # server_name list_length
          ,00                      # server_name type (hostname)
          ,00, $len_servername_hex # server_name length
          ,$servername_hexstr"     # server_name target
     fi

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

     [[ "$DEBUG" -ge 2 ]] && echo "sending client hello..."
     socksend_tls_clienthello "$tls_low_byte" "$cipher_list_2send"
     ret=$?                             # 6 means opening socket didn't succeed, e.g. timeout

     # if sending didn't succeed we don't bother
     if [[ $ret -eq 0 ]]; then
          sockread_serverhello 32768
          TLS_NOW=$(LC_ALL=C date "+%s")
          [[ "$DEBUG" -ge 2 ]] && outln "reading server hello..."
          if [[ "$DEBUG" -ge 3 ]]; then
               hexdump -C $SOCK_REPLY_FILE | head -6
               echo
          fi

          parse_tls_serverhello "$SOCK_REPLY_FILE"
          save=$?

          # see https://secure.wand.net.nz/trac/libprotoident/wiki/SSL
          lines=$(count_lines "$(hexdump -C "$SOCK_REPLY_FILE" 2>$ERRFILE)")
          [[ "$DEBUG" -ge 2 ]] && out "  (returned $lines lines)  "

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
     [ $VULN_COUNT -le $VULN_THRESHLD ]  && outln && pr_headlineln " Testing for heartbleed vulnerability " && outln
     pr_bold " Heartbleed\c"; out " (CVE-2014-0160)                "

     [[ -z "$TLS_EXTENSIONS" ]] && determine_tls_extensions
     if ! grep -q heartbeat <<< "$TLS_EXTENSIONS"; then
          pr_green "not vulnerable (OK)"
          outln " (no heartbeat extension)"
          return 0
     fi

     # determine TLS versions offered <-- needs to come from another place
     $OPENSSL s_client $STARTTLS $BUGS -connect $NODEIP:$PORT $PROXY -tlsextdebug >$TMPFILE 2>$ERRFILE </dev/null

     if $HAS_SED_E; then
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

     [[ $DEBUG -ge 2 ]] && outln "\nsending client hello (TLS version $tls_hexcode)"
     socksend "$client_hello" 1
     sockread 16384

     [[ $DEBUG -ge 2 ]] && outln "\nreading server hello"
     if [[ $DEBUG -ge 3 ]]; then
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
          pr_red "VULNERABLE (NOT ok)"
          ret=1
     else
          pr_green "not vulnerable (OK)"
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
     pr_greenln "\n ok -- something resetted our ccs packets"
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

     if $HAS_SED_E; then
          tls_proto_offered=$(grep -aw Protocol $TMPFILE | sed -E 's/[^[:digit:]]//g')
     else
          tls_proto_offered=$(grep -aw Protocol $TMPFILE | sed -r 's/[^[:digit:]]//g')
     fi
     case $tls_proto_offered in
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
     sockread 16384

     debugme outln "\nreading server hello"
     if [[ $DEBUG -ge 3 ]]; then
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
          pr_green "not vulnerable (OK)"
          ret=0
     else
          pr_red "VULNERABLE (NOT ok)"
          ret=1
     fi
     [[ $retval -eq 3 ]] && out " (timed out)"
     outln

     close_socket
     tmpfile_handle $FUNCNAME.txt
     return $ret
}

local_problem() {
     pr_litemagentaln "Local problem: $1"
}

run_renego() {
# no SNI here. Not needed as there won't be two different SSL stacks for one IP
     local legacycmd=""
     local insecure_renogo_str="Secure Renegotiation IS NOT"
     local sec_renego sec_client_renego

     [ $VULN_COUNT -le $VULN_THRESHLD ]  && outln && pr_headlineln " Testing for Renegotiation vulnerabilities " && outln

     pr_bold " Secure Renegotiation "; out "(CVE-2009-3555)      "    # and RFC5746, OSVDB 59968-59974
                                                                      # community.qualys.com/blogs/securitylabs/2009/11/05/ssl-and-tls-authentication-gap-vulnerability-discovered
     $OPENSSL s_client $OPTIMAL_PROTO $STARTTLS $BUGS -connect $NODEIP:$PORT $SNI $PROXY 2>&1 </dev/null >$TMPFILE 2>$ERRFILE
     if sclient_connect_successful $? $TMPFILE; then
          grep -iaq "$insecure_renogo_str" $TMPFILE
          sec_renego=$?                                                    # 0= Secure Renegotiation IS NOT supported
#FIXME: didn't occur to me yet but why not also to check on "Secure Renegotiation IS supported"
          case $sec_renego in
               0) pr_redln "VULNERABLE (NOT ok)" ;;
               1) pr_greenln "not vulnerable (OK)" ;;
               *) pr_litemagentaln "FIXME (bug): $sec_renego" ;;
          esac
     else
          pr_litemagentaln "handshake didn't succeed" 
     fi

     pr_bold " Secure Client-Initiated Renegotiation     "  # RFC 5746
     # see: https://community.qualys.com/blogs/securitylabs/2011/10/31/tls-renegotiation-and-denial-of-service-attacks
     #      http://blog.ivanristic.com/2009/12/testing-for-ssl-renegotiation.html -- head/get doesn't seem to be needed though
     case "$OSSL_VER" in
          0.9.8*)             # we need this for Mac OSX unfortunately
               case "$OSSL_VER_APPENDIX" in
                    [a-l]) local_problem "$OPENSSL cannot test this secure renegotiation vulnerability"
                           return 3 ;;
                    [m-z]) ;; # all ok
               esac ;;
          1.0.1*|1.0.2*) legacycmd="-legacy_renegotiation" ;;
          0.9.9*|1.0*) ;;   # all ok
     esac

     if $CLIENT_AUTH; then
          pr_litemagentaln "client authentication prevents this from being tested"
          sec_client_renego=1
     else
          # We need up to two tries here, as some LiteSpeed servers don't answer on "R" and block. Thus first try in the background
          # msg enables us to look deeper into it while debugging
          echo R | $OPENSSL s_client $OPTIMAL_PROTO $BUGS $legacycmd $STARTTLS -msg -connect $NODEIP:$PORT $SNI $PROXY >$TMPFILE 2>>$ERRFILE &     
          wait_kill $! $HEADER_MAXSLEEP
          if [[ $? -eq 3 ]]; then
               pr_litegreen "likely not vulnerable (OK)"; outln " (timed out)"       # it hung
               sec_client_renego=1
          else
               # second try in the foreground as we are sure now it won't hang
               echo R | $OPENSSL s_client $legacycmd $STARTTLS $BUGS -msg -connect $NODEIP:$PORT $SNI $PROXY >$TMPFILE 2>>$ERRFILE
               sec_client_renego=$?                                                  # 0=client is renegotiating & doesn't return an error --> vuln!
               case $sec_client_renego in
                    0) pr_litered "VULNERABLE (NOT ok)"; outln ", DoS threat" ;;
                    1) pr_litegreenln "not vulnerable (OK)" ;;
                    *) "FIXME (bug): $sec_client_renego" ;;
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

     [ $VULN_COUNT -le $VULN_THRESHLD ]  && outln && pr_headlineln " Testing for CRIME vulnerability " && outln 
     pr_bold " CRIME, TLS " ; out "(CVE-2012-4929)                "

     # first we need to test whether OpenSSL binary has zlib support
     $OPENSSL zlib -e -a -in /dev/stdin &>/dev/stdout </dev/null | grep -q zlib
     if [[ $? -eq 0 ]]; then
          local_problem "$OPENSSL lacks zlib support"
          return 7
     fi

     [[ "$OSSL_VER" == "*0.9.8*" ]] && addcmd="-no_ssl2" 
     $OPENSSL s_client $OPTIMAL_PROTO $BUGS $addcmd $STARTTLS -connect $NODEIP:$PORT $PROXY $SNI </dev/null &>$TMPFILE
     if grep -a Compression $TMPFILE | grep -aq NONE >/dev/null; then
          pr_litegreen "not vulnerable (OK)"
          if [[ $SERVICE != "HTTP" ]] && ! $CLIENT_AUTH;  then 
               out " (not using HTTP anyway)"
          fi
          ret=0
     else
          if [[ $SERVICE == "HTTP" ]]; then
               pr_litered "VULNERABLE (NOT ok)"
          else
               pr_brown "VULNERABLE (NOT ok), but not using HTTP: probably no exploit known"
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

#    $OPENSSL s_client help 2>&1 | grep -qw nextprotoneg
#    if [[ $? -eq 0 ]]; then
#         $OPENSSL s_client -host $NODE -port $PORT -nextprotoneg $NPN_PROTOs  $SNI </dev/null 2>/dev/null >$TMPFILE
#         if [[ $? -eq 0 ]]; then
#              echo
#              pr_bold "CRIME Vulnerability, SPDY \c" ; outln "(CVE-2012-4929): \c"

#              STR=$(grep Compression $TMPFILE )
#              if echo $STR | grep -q NONE >/dev/null; then
#                   pr_green "not vulnerable (OK)"
#                   ret=$((ret + 0))
#              else
#                   pr_red "VULNERABLE (NOT ok)"
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
          pr_litemagenta "failed (HTTP header request stalled"
          [[ $was_killed -ne 0 ]] && pr_litemagenta " and was terminated"
          pr_litemagenta ") "
          ret=3
     elif [[ -z $result ]]; then
          pr_green "no HTTP compression (OK) "
          outln "$disclaimer"
          ret=0
     else
          pr_litered "potentially NOT ok, uses $result HTTP compression."
          outln "$disclaimer"
          outln "$spaces Can be ignored for static pages or if no secrets in the page"
           ret=1
     fi
     # Any URL can be vulnerable. I am testing now only the given URL!

     tmpfile_handle $FUNCNAME.txt
     return $ret
}

# Padding Oracle On Downgraded Legacy Encryption, in a nutshell: don't use CBC Ciphers in SSLv3
run_ssl_poodle() {
     local -i sclient_success=0
     local cbc_ciphers
     local cbc_ciphers="SRP-DSS-AES-256-CBC-SHA:SRP-RSA-AES-256-CBC-SHA:SRP-AES-256-CBC-SHA:RSA-PSK-AES256-CBC-SHA:PSK-AES256-CBC-SHA:SRP-DSS-AES-128-CBC-SHA:SRP-RSA-AES-128-CBC-SHA:SRP-AES-128-CBC-SHA:IDEA-CBC-SHA:IDEA-CBC-MD5:RC2-CBC-MD5:RSA-PSK-AES128-CBC-SHA:PSK-AES128-CBC-SHA:ECDHE-RSA-DES-CBC3-SHA:ECDHE-ECDSA-DES-CBC3-SHA:SRP-DSS-3DES-EDE-CBC-SHA:SRP-RSA-3DES-EDE-CBC-SHA:SRP-3DES-EDE-CBC-SHA:EDH-RSA-DES-CBC3-SHA:EDH-DSS-DES-CBC3-SHA:DH-RSA-DES-CBC3-SHA:DH-DSS-DES-CBC3-SHA:AECDH-DES-CBC3-SHA:ADH-DES-CBC3-SHA:ECDH-RSA-DES-CBC3-SHA:ECDH-ECDSA-DES-CBC3-SHA:DES-CBC3-SHA:DES-CBC3-MD5:RSA-PSK-3DES-EDE-CBC-SHA:PSK-3DES-EDE-CBC-SHA:EXP1024-DHE-DSS-DES-CBC-SHA:EDH-RSA-DES-CBC-SHA:EDH-DSS-DES-CBC-SHA:DH-RSA-DES-CBC-SHA:DH-DSS-DES-CBC-SHA:ADH-DES-CBC-SHA:EXP1024-DES-CBC-SHA:DES-CBC-SHA:EXP1024-RC2-CBC-MD5:DES-CBC-MD5:EXP-EDH-RSA-DES-CBC-SHA:EXP-EDH-DSS-DES-CBC-SHA:EXP-ADH-DES-CBC-SHA:EXP-DES-CBC-SHA:EXP-RC2-CBC-MD5:EXP-RC2-CBC-MD5"
     local cbc_ciphers_krb="KRB5-IDEA-CBC-SHA:KRB5-IDEA-CBC-MD5:KRB5-DES-CBC3-SHA:KRB5-DES-CBC3-MD5:KRB5-DES-CBC-SHA:KRB5-DES-CBC-MD5:EXP-KRB5-RC2-CBC-SHA:EXP-KRB5-DES-CBC-SHA:EXP-KRB5-RC2-CBC-MD5:EXP-KRB5-DES-CBC-MD5"

     [ $VULN_COUNT -le $VULN_THRESHLD ]  && outln && pr_headlineln " Testing for SSLv3 POODLE (Padding Oracle On Downgraded Legacy Encryption) " && outln
     pr_bold " POODLE, SSL"; out " (CVE-2014-3566)               "
     #nr_supported_ciphers=$(count_ciphers $(actually_supported_ciphers $cbc_ciphers:cbc_ciphers_krb))
     cbc_ciphers=$($OPENSSL ciphers -v 'ALL:eNULL' 2>$ERRFILE | awk '/CBC/ { print $1 }' | tr '\n' ':')

     debugme echo $cbc_ciphers
     $OPENSSL s_client -ssl3 $STARTTLS $BUGS -cipher $cbc_ciphers -connect $NODEIP:$PORT $PROXY $SNI >$TMPFILE 2>$ERRFILE </dev/null
     sclient_connect_successful $? $TMPFILE
     sclient_success=$?
     [[ $DEBUG -eq 2 ]] && egrep -q "error|failure" $ERRFILE | egrep -av "unable to get local|verify error"
     if [[ $sclient_success -eq 0 ]]; then
          pr_litered "VULNERABLE (NOT ok)"; out ", uses SSLv3+CBC (check TLS_FALLBACK_SCSV mitigation below)"
     else
          pr_green "not vulnerable (OK)"
     fi
     outln
     tmpfile_handle $FUNCNAME.txt
     return $sclient_success
}

# for appliance which use padding, no fallback needed
run_tls_poodle() {
     pr_bold " POODLE, SSL"; out " CVE-2014-8730), experimental "
     #FIXME
     echo "#FIXME"
     return 7
}

run_tls_fallback_scsv() {
     local -i ret=0

     [ $VULN_COUNT -le $VULN_THRESHLD ]  && outln && pr_headlineln " Testing for TLS_FALLBACK_SCSV Protection " && outln
     pr_bold " TLS_FALLBACK_SCSV"; out " (RFC 7507), experim.    "
     # This isn't a vulnerability check per se, but checks for the existence of
     # the countermeasure to protect against protocol downgrade attacks.

     # First check we have support for TLS_FALLBACK_SCSV in our local OpenSSL
     if ! $OPENSSL s_client -h 2>&1 | grep -q "\-fallback_scsv"; then
          local_problem "$OPENSSL lacks TLS_FALLBACK_SCSV support"
          return 4
     fi
     #TODO: this need some tuning: a) if one protocol is supported only it has practcally no value (theoretical it's interesting though)
     # b) for IIS6 + openssl 1.0.2 this won't work
     # c) best to make sure that we hit a specific protocol, see https://alpacapowered.wordpress.com/2014/10/20/ssl-poodle-attack-what-is-this-scsv-thingy/
     # d) minor: we should do "-state" here

     # first: make sure we have tls1_2:
     $OPENSSL s_client $STARTTLS $BUGS -connect $NODEIP:$PORT $PROXY $SNI -no_tls1_2 >$TMPFILE 2>$ERRFILE </dev/null
     if ! sclient_connect_successful $? $TMPFILE; then
          pr_litegreen "No fallback possible, TLS 1.2 is the only protocol (OK)"
          ret=7
     else
          # ...and do the test (we need to parse the error here!)
          $OPENSSL s_client $STARTTLS $BUGS -connect $NODEIP:$PORT $PROXY $SNI -no_tls1_2 -fallback_scsv &>$TMPFILE </dev/null
          if grep -q "CONNECTED(00" "$TMPFILE"; then
               if grep -qa "BEGIN CERTIFICATE" "$TMPFILE"; then
                    pr_brown "Downgrade attack prevention NOT supported"
                    ret=1
               elif grep -qa "alert inappropriate fallback" "$TMPFILE"; then
                    pr_litegreen "Downgrade attack prevention supported (OK)"
                    ret=0
               elif grep -qa "alert handshake failure" "$TMPFILE"; then
                    # see RFC 7507, https://github.com/drwetter/testssl.sh/issues/121
                    pr_brown "\"handshake failure\" instead of \"inappropriate fallback\" (likely NOT ok)"
                    ret=2
               elif grep -qa "ssl handshake failure" "$TMPFILE"; then
                    pr_brown "some unexpected \"handshake failure\" instead of \"inappropriate fallback\" (likely NOT ok)"
                    ret=3
               else
                    pr_litemagenta "Check failed, unexpected result "
                    out ", run $PROG_NAME -Z --debug=1 and look at $TEMPDIR/*tls_fallback_scsv.txt"
               fi
          else
               pr_litemagenta "test failed (couldn't connect)"
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

     [ $VULN_COUNT -le $VULN_THRESHLD ]  && outln && pr_headlineln " Testing for FREAK attack " && outln 
     pr_bold " FREAK"; out " (CVE-2015-0204)                     "

     nr_supported_ciphers=$(count_ciphers $(actually_supported_ciphers $exportrsa_cipher_list))
     #echo "========= ${PIPESTATUS[*]}

     case $nr_supported_ciphers in
          0)   local_problem "$OPENSSL doesn't have any EXPORT RSA ciphers configured"
               return 7 ;;
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
          pr_red "VULNERABLE (NOT ok)"; out ", uses EXPORT RSA ciphers"
     else
          pr_green "not vulnerable (OK)"; out "$addtl_warning"
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

     [ $VULN_COUNT -le $VULN_THRESHLD ]  && outln && pr_headlineln " Testing for LOGJAM vulnerability " && outln 
     pr_bold " LOGJAM"; out " (CVE-2015-4000), experimental      "

     nr_supported_ciphers=$(count_ciphers $(actually_supported_ciphers $exportdhe_cipher_list))

     case $nr_supported_ciphers in
          0)   local_problem "$OPENSSL doesn't have any DHE EXPORT ciphers configured"
               return 3 ;;
          1|2) addtl_warning=" ($magenta""tested w/ $nr_supported_ciphers/4 ciphers only!$off)" ;;
          3) addtl_warning=" (tested w/ $nr_supported_ciphers/4 ciphers)" ;;
          4)   ;;
     esac
     $OPENSSL s_client $STARTTLS $BUGS -cipher $exportdhe_cipher_list -connect $NODEIP:$PORT $PROXY $SNI >$TMPFILE 2>$ERRFILE </dev/null
     sclient_connect_successful $? $TMPFILE
     sclient_success=$?
     [[ $DEBUG -eq 2 ]] && egrep -a "error|failure" $ERRFILE | egrep -av "unable to get local|verify error"
     addtl_warning="$addtl_warning, common primes not checked."
     if $HAS_DH_BITS; then
          if ! $do_allciphers && ! $do_cipher_per_proto && $HAS_DH_BITS; then
               addtl_warning="$addtl_warning \"$PROG_NAME -E/-e\" spots candidates"
          else
               $HAS_DH_BITS && addtl_warning="$addtl_warning See below for any DH ciphers + bit size"
          fi
     fi
          
     if [[ $sclient_success -eq 0 ]]; then
          pr_red "VULNERABLE (NOT ok)"; out ", uses DHE EXPORT ciphers, common primes not checked."
     else
          pr_green "not vulnerable (OK)"; out "$addtl_warning"
     fi
     outln

     debugme echo $(actually_supported_ciphers $exportdhe_cipher_list)
     debugme echo $nr_supported_ciphers

     tmpfile_handle $FUNCNAME.txt
     return $sclient_success
}
# TODO: perfect candidate for replacement by sockets, so is freak



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

     if [[ $VULN_COUNT -le $VULN_THRESHLD ]] || $WIDE; then
          outln
          pr_headlineln " Testing for BEAST vulnerability "
          outln
     fi
     pr_bold " BEAST"; out " (CVE-2011-3389)                     "
     $WIDE && outln
# output in wide mode if cipher doesn't exist is not ok

     >$ERRFILE

     # first determine whether it's mitogated by higher protocols
     for proto in tls1_1 tls1_2; do
          $OPENSSL s_client -state -"$proto" $STARTTLS $BUGS -connect $NODEIP:$PORT $PROXY $SNI 2>>$ERRFILE >$TMPFILE </dev/null
          if sclient_connect_successful $? $TMPFILE; then
               higher_proto_supported="$higher_proto_supported ""$(grep -aw "Protocol" $TMPFILE | sed -e 's/^.*Protocol .*://' -e 's/ //g')"
          fi
     done

     for proto in ssl3 tls1; do
          $OPENSSL s_client -"$proto" $STARTTLS $BUGS -connect $NODEIP:$PORT $PROXY $SNI >$TMPFILE 2>>$ERRFILE </dev/null
          if ! sclient_connect_successful $? $TMPFILE; then # protocol supported?
               if $continued; then                          # second round: we hit TLS1:
                    pr_litegreenln "no SSL3 or TLS1"
                    return 0
               else                # protocol not succeeded but it';s the first time
                    continued=true
                    continue       # protocol not supported, so we do not need to check each cipher with that protocol
               fi
          fi # protocol succeeded

          # now we test in one shot with the precompiled ciphers
          $OPENSSL s_client -"$proto" -cipher "$cbc_cipher_list" $STARTTLS $BUGS -connect $NODEIP:$PORT $PROXY $SNI >$TMPFILE 2>>$ERRFILE </dev/null
          sclient_connect_successful $? $TMPFILE || continue

          if $WIDE; then
               outln "\n $(toupper $proto):";
               neat_header # NOT_THAT_NICE: we display the header also if in the end no cbc cipher is available on the client side
          fi
          for ciph in $(colon_to_spaces "$cbc_cipher_list"); do
               read hexcode dash cbc_cipher sslvers kx auth enc mac < <($OPENSSL ciphers -V "$ciph" 2>>$ERRFILE)        # -V doesn't work with openssl < 1.0
               #                                                    ^^^^^ process substitution as shopt will either segfault or doesn't work with old bash versions
               $OPENSSL s_client -cipher "$cbc_cipher" -"$proto" $STARTTLS $BUGS -connect $NODEIP:$PORT $PROXY $SNI >$TMPFILE 2>>$ERRFILE </dev/null
               sclient_connect_successful $? $TMPFILE
               sclient_success=$?
               [[ $sclient_success -eq 0 ]] && vuln_beast=true
               if $WIDE; then
                    normalize_ciphercode $hexcode
                    if [[ "$SHOW_EACH_C" -ne 0 ]]; then
                         neat_list $HEXC $cbc_cipher $kx $enc
                         if [[ $sclient_success -eq 0 ]]; then
                              [[ -n "$higher_proto_supported" ]] && \
                                   pr_yellowln "available" || \
                                   pr_brownln "available" 

                         else
                              outln "not a/v"
                         fi
                    else
                         [[ $sclient_success -eq 0 ]] && neat_list $HEXC $cbc_cipher $kx $enc && outln
                    fi
               else # short display:
                    if [[ $sclient_success -eq 0 ]]; then
                         detected_cbc_ciphers="$detected_cbc_ciphers ""$(grep -aw "Cipher" $TMPFILE | egrep -avw "New|is" | sed -e 's/^.*Cipher.*://' -e 's/ //g')"
                         vuln_beast=true
                    fi
               fi
          done

          if ! $WIDE; then
               if [[ -n "$detected_cbc_ciphers" ]]; then
                    detected_cbc_ciphers=$(echo "$detected_cbc_ciphers" | sed -e "s/ /\\${cr}      ${spaces}/9" -e "s/ /\\${cr}      ${spaces}/6" -e "s/ /\\${cr}      ${spaces}/3")
                    ! $first && out "$spaces"
                    out "$(toupper $proto):"
                    [[ -n "$higher_proto_supported" ]] && \
                         pr_yellowln "$detected_cbc_ciphers" || \
                         pr_brownln "$detected_cbc_ciphers"
                    detected_cbc_ciphers="" # empty for next round
                    first=false
               else
                    [[ $proto == "tls1" ]] && ! $first && echo -n "$spaces"
                    pr_litegreenln "no CBC ciphers for $(toupper $proto) (OK)"
                    first=false
               fi
          else
               $vuln_beast || pr_litegreenln " no CBC ciphers for $(toupper $proto) (OK)"
          fi
     done  # for proto in ssl3 tls1

     if $vuln_beast ; then
          if [[ -n "$higher_proto_supported" ]]; then
               if $WIDE; then
                    outln
                    # BOT ok seems too harsh for me if we have TLS >1.0
                    pr_yellow "VULNERABLE"
                    outln " -- but also supports higher protocols (possible mitigation):$higher_proto_supported"
               else
                    out "${spaces}"
                    pr_yellow "VULNERABLE"
                    outln " -- but also supports higher protocols (possible mitigation):$higher_proto_supported"
               fi
          else
               if $WIDE; then
                    outln
               else
                    out "${spaces}"
               fi
               pr_brown "VULNERABLE (NOT ok)"
               outln " -- and no higher protocols as mitigation supported"
          fi
     fi

     tmpfile_handle $FUNCNAME.txt
     return 0
}

run_lucky13() {
#FIXME: to do . CVE-2013-0169
# in a nutshell: don't offer CBC suites (again). MAC as a fix for padding oracles is not enough. Best: TLS v1.2+ AES GCM
     echo "FIXME"
     return -1
}


# https://tools.ietf.org/html/rfc7465    REQUIRES that TLS clients and servers NEVER negotiate the use of RC4 cipher suites!
# https://en.wikipedia.org/wiki/Transport_Layer_Security#RC4_attacks
# http://blog.cryptographyengineering.com/2013/03/attack-of-week-rc4-is-kind-of-broken-in.html
run_rc4() {
     local -i rc4_offered=0
     local -i sclient_success
     local hexcode dash rc4_cipher sslvers kx auth enc mac export
     local rc4_ciphers_list="ECDHE-RSA-RC4-SHA:ECDHE-ECDSA-RC4-SHA:DHE-DSS-RC4-SHA:AECDH-RC4-SHA:ADH-RC4-MD5:ECDH-RSA-RC4-SHA:ECDH-ECDSA-RC4-SHA:RC4-SHA:RC4-MD5:RC4-MD5:RSA-PSK-RC4-SHA:PSK-RC4-SHA:KRB5-RC4-SHA:KRB5-RC4-MD5:RC4-64-MD5:EXP1024-DHE-DSS-RC4-SHA:EXP1024-RC4-SHA:EXP-ADH-RC4-MD5:EXP-RC4-MD5:EXP-RC4-MD5:EXP-KRB5-RC4-SHA:EXP-KRB5-RC4-MD5"

     if [[ $VULN_COUNT -le $VULN_THRESHLD ]] || $WIDE; then
          outln
          pr_headlineln " Checking for vulnerable RC4 Ciphers "
          outln
     fi
     pr_bold " RC4"; out " (CVE-2013-2566, CVE-2015-2808)        "

     $OPENSSL s_client -cipher $rc4_ciphers_list $STARTTLS $BUGS -connect $NODEIP:$PORT $PROXY $SNI >$TMPFILE 2>$ERRFILE </dev/null
     if sclient_connect_successful $? $TMPFILE; then
          pr_litered "VULNERABLE (NOT ok): "
          $WIDE && outln "\n"
          rc4_offered=1
          $WIDE && neat_header
          while read hexcode dash rc4_cipher sslvers kx auth enc mac; do
               $OPENSSL s_client -cipher $rc4_cipher $STARTTLS $BUGS -connect $NODEIP:$PORT $PROXY $SNI </dev/null >$TMPFILE 2>$ERRFILE
               sclient_connect_successful $? $TMPFILE
               sclient_success=$?            # here we may have a fp with openssl < 1.0, TBC
               if [[ $sclient_success -ne 0 ]] && [[ "$SHOW_EACH_C" -eq 0 ]]; then
                    continue                 # no successful connect AND not verbose displaying each cipher
               fi
               if $WIDE; then
                    normalize_ciphercode $hexcode
                    neat_list $HEXC $rc4_cipher $kx $enc
                    if [[ "$SHOW_EACH_C" -ne 0 ]]; then
                         if [[ $sclient_success -eq 0 ]]; then
                              pr_litered "available"
                         else
                              out "not a/v"
                         fi
                    else
                         rc4_offered=1
                         out
                    fi
                    outln
               else
                    pr_litered "$rc4_cipher "
               fi
          done < <($OPENSSL ciphers -V $rc4_ciphers_list:@STRENGTH)
          outln
     else
          pr_litegreenln "no RC4 ciphers detected (OK)"
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
     fatal "Your $OPENSSL $OSSL_VER version is an old fart... . It doesn\'t make much sense to proceed." -2
}

# try very hard to determine th install path to get ahold of the mapping file
# it provides "keycode/ RFC style name", see RFCs, cipher(1), www.carbonwind.net/TLS_Cipher_Suites_Project/tls_ssl_cipher_suites_simple_table_all.htm
get_install_dir() {
     #INSTALL_DIR=$(cd "$(dirname "$0")" && pwd)/$(basename "$0")
     INSTALL_DIR=$(dirname ${BASH_SOURCE[0]})

     [[ -r "$RUN_DIR/etc/mapping-rfc.txt" ]] && MAPPING_FILE_RFC="$RUN_DIR/etc/mapping-rfc.txt" 
     [[ -r "$INSTALL_DIR/etc/mapping-rfc.txt" ]] && MAPPING_FILE_RFC="$INSTALL_DIR/etc/mapping-rfc.txt"
# those will disapper:
     [[ -r "$RUN_DIR/mapping-rfc.txt" ]] && MAPPING_FILE_RFC="$RUN_DIR/mapping-rfc.txt" 
     [[ -r "$INSTALL_DIR/mapping-rfc.txt" ]] && MAPPING_FILE_RFC="$INSTALL_DIR/mapping-rfc.txt"

     # we haven't found the mapping file yet...
     if [[ ! -r "$MAPPING_FILE_RFC" ]] && which readlink &>/dev/null ; then
          readlink -f ls &>/dev/null && \
               INSTALL_DIR=$(readlink -f $(basename ${BASH_SOURCE[0]})) || \
               INSTALL_DIR=$(readlink $(basename ${BASH_SOURCE[0]}))
               # not sure whether Darwin has -f
          INSTALL_DIR=$(dirname $INSTALL_DIR 2>/dev/null)
          [[ -r "$INSTALL_DIR/etc/mapping-rfc.txt" ]] && MAPPING_FILE_RFC="$INSTALL_DIR/etc/mapping-rfc.txt"
# will disappear:
          [[ -r "$INSTALL_DIR/mapping-rfc.txt" ]] && MAPPING_FILE_RFC="$INSTALL_DIR/mapping-rfc.txt"
     fi

     # still no mapping file:
     if [[ ! -r "$MAPPING_FILE_RFC" ]] && which realpath &>/dev/null ; then
          INSTALL_DIR=$(dirname $(realpath ${BASH_SOURCE[0]}))
          MAPPING_FILE_RFC="$INSTALL_DIR/etc/mapping-rfc.txt"
# will disappear
          MAPPING_FILE_RFC="$INSTALL_DIR/mapping-rfc.txt"
     fi

     [[ ! -r "$MAPPING_FILE_RFC" ]] && unset MAPPING_FILE_RFC && pr_litemagentaln "\nNo mapping file found"
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
          pr_litemagentaln "\ncannot find specified (\$OPENSSL=$OPENSSL) binary."
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
          fatal "\ncannot exec or find any openssl binary" -1
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
          pr_litemagenta "Please note: LibreSSL is not a good choice for testing INSECURE features!"
     fi

     $OPENSSL s_client -ssl2 2>&1 | grep -aq "unknown option" || \
          HAS_SSL2=true && \
          HAS_SSL2=false
     $OPENSSL s_client -ssl3 2>&1 | grep -aq "unknown option" || \
          HAS_SSL3=true && \
          HAS_SSL3=false
     $OPENSSL s_client help 2>&1 | grep -qw '\-alpn' && \
          HAS_ALPN=true || \
          HAS_ALPN=false
     $OPENSSL s_client help 2>&1 | grep -qw '\-nextprotoneg' && \
          HAS_SPDY=true || \
          HAS_SPDY=false

     return 0
}

openssl_age() {
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
     if [[ $OSSL_VER_MAJOR.$OSSL_VER_MINOR == "1.1.0" ]]; then
          pr_magentaln "$PROG_NAME doesn't work yet with OpenSSL 1.1.0!"
          ignore_no_or_lame "Type \"yes\" to accept weird output, false negatives and positives "
     fi
     outln
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
     -p, --protocols               checks TLS/SSL protocols
     -S, --server_defaults         displays the servers default picks and certificate info
     -P, --preference              displays the servers picks: protocol+cipher
     -y, --spdy, --npn             checks for SPDY/NPN
     -x, --single-cipher <pattern> tests matched <pattern> of ciphers
                                   (if <pattern> not a number: word match)
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
     -s, --pfs, --fs,--nsa         checks (perfect) forward secrecy settings
     -4, --rc4, --appelbaum        which RC4 ciphers are being offered?
     -H, --header, --headers       tests HSTS, HPKP, server/app banner, security headers, cookie, reverse proxy, IPv4 address

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
     protocol                      is one of ftp,smtp,pop3,imap,xmpp,telnet,ldap (for the latter two you need e.g. the supplied openssl)

tuning options (can also be preset via environment variables):

     --bugs                        enables the "-bugs" option of s_client, needed e.g. for some buggy F5s
     --assuming-http               if protocol check fails it assumes HTTP protocol and enforces HTTP checks
     --ssl-native                  fallback to checks with OpenSSL where sockets are normally used
     --openssl <PATH>              use this openssl binary (default: look in \$PATH, \$RUN_DIR of $PROG_NAME
     --proxy <host>:<port>         connect via the specified HTTP proxy
     -6                            use also IPv6 checks, works only with supporting OpenSSL version and IPv6 connectivity
     --sneaky                      leave less traces in target logs: user agent, referer
     --quiet                       don't output the banner. By doing this you acknowledge usage terms normally appearing in the banner
     --log, --logging              logs stdout to <NODE-YYYYMMDD-HHMM.log> in current working directory
     --logfile <file>              logs stdout to <file/NODE-YYYYMMDD-HHMM.log> if file is a dir or to specified file
     --wide                        wide output for tests like RC4, BEAST. PFS also with hexcode, kx, strength, RFC name
     --show-each                   for wide outputs: display all ciphers tested -- not only succeeded ones
     --warnings <batch|off|false>  "batch" doesn't wait for keypress, "off" or "false" skips connection warning
     --color <0|1|2>               0: no escape or other codes,  1: b/w escape codes,  2: color (default)
     --debug <0-6>                 1: screen output normal but debug output in temp files.  2-6: see line ~120

All options requiring a value can also be called with '=' (e.g. testssl.sh -t=smtp --wide --openssl=/usr/bin/openssl <URI>.
<URI> is always the last parameter.

Need HTML output? Just pipe through "aha" (Ansi HTML Adapter: github.com/theZiz/aha) like

   "$PROG_NAME <options> <URI> | aha >output.html"
EOF
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
     HEADERFILE=$TEMPDIR/http_header.txt
     initialize_engine
     if [[ $DEBUG -ne 0 ]]; then
          cat >$TEMPDIR/environment.txt << EOF

CVS_REL: $CVS_REL
GIT_REL: $GIT_REL

PID: $$
bash version: ${BASH_VERSINFO[0]}.${BASH_VERSINFO[1]}.${BASH_VERSINFO[2]}
status: ${BASH_VERSINFO[4]}
machine: ${BASH_VERSINFO[5]}
operating system: $SYSTEM
shellopts: $SHELLOPTS

$OPENSSL version -a:
$($OPENSSL version -a)
OSSL_VER_MAJOR: $OSSL_VER_MAJOR
OSSL_VER_MINOR: $OSSL_VER_MINOR
OSSL_VER_APPENDIX: $OSSL_VER_APPENDIX
OSSL_BUILD_DATE: "$OSSL_BUILD_DATE"
OSSL_VER_PLATFORM: "$OSSL_VER_PLATFORM"

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
ECHO: $ECHO
COLOR: $COLOR
TERM_DWITH: $TERM_DWITH
INTERACTIVE: $INTERACTIVE
HAS_GNUDATE: $HAS_GNUDATE
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
     local nr_ciphers
     local idtag
     local bb
     local openssl_location="$(which $OPENSSL)"
     local cwd=""

     $QUIET && return
     nr_ciphers=$(count_ciphers "$($OPENSSL ciphers 'ALL:COMPLEMENTOFALL:@STRENGTH' 2>/dev/null)")
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
     outln " Using \"$($OPENSSL version 2>/dev/null)\" [~$nr_ciphers ciphers]"
     out "on $HNAME:"

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
}

fatal() {
     pr_magentaln "Fatal error: $1" >&2
     exit $2
}


# for now only GOST engine
initialize_engine(){
     grep -q '^# testssl config file' "$OPENSSL_CONF" 2>/dev/null && return 0        # have been here already

     if ! $OPENSSL engine gost -vvvv -t -c 2>/dev/null >/dev/null; then
          outln
          pr_litemagenta "No engine or GOST support via engine with your $OPENSSL"; outln
          return 1
     elif $OPENSSL engine gost -vvvv -t -c 2>&1 | grep -iq "No such" ; then
          outln
          pr_litemagenta "No engine or GOST support via engine with your $OPENSSL"; outln
          return 1
     else      # we have engine support
          if [[ -n "$OPENSSL_CONF" ]]; then
               pr_litemagentaln "For now I am providing the config file in to have GOST support"
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

     [[ "$WARNINGS" == "off" ]] && return 0
     [[ "$WARNINGS" == "false" ]] && return 0
     [[ "$WARNINGS" == "batch" ]] && return 1
     pr_magenta "$1 "
     read a
     case $a in
          Y|y|Yes|YES|yes) return 0;;
          default)         ;;
     esac
     return 1
}

# arg1: URI
# arg2: protocol
parse_hn_port() {
     local tmp_port

     NODE="$1"
     # strip "https" and trailing urlpath supposed it was supplied additionally
     echo "$NODE" | grep -q 'https://' && NODE=$(echo "$NODE" | sed -e 's/^https\:\/\///')

     # strip trailing urlpath
     NODE=$(echo "$NODE" | sed -e 's/\/.*$//')

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

     # now do logging if instructed
     if $do_logging; then
          if [[ -z "$LOGFILE" ]]; then
               LOGFILE=$NODE-$(date +"%Y%m%d-%H%M".log)
          elif [[ -d "$LOGFILE" ]]; then
               # actually we were instructed to place all files in a DIR instead of the current working dir
               LOGFILE=$LOGFILE/$NODE-$(date +"%Y%m%d-%H%M".log)
          else
               : # just for clarity: a log file was specified, no need to do anything else
          fi
          >$LOGFILE
          outln "## Scan started as: \"$PROG_NAME $CMDLINE\"" >>${LOGFILE}
          outln "## ($VERSION ${GIT_REL_SHORT:-CVS_REL_SHORT} from $REL_DATE, at $HNAME:$OPENSSL_LOCATION)\n" >>${LOGFILE}
          exec > >(tee -a ${LOGFILE})
          # not decided yet. Maybe good to have a separate file or none at all
          #exec 2> >(tee -a ${LOGFILE} >&2)
     fi

     URL_PATH=$(echo "$1" | sed 's/https:\/\///' | sed 's/'"${NODE}"'//' | sed 's/.*'"${PORT}"'//')      # remove protocol and node part and port
     URL_PATH=$(echo "$URL_PATH" | sed 's/\/\//\//g')       # we rather want // -> /
     [[ -z "$URL_PATH" ]] && URL_PATH="/"
     debugme echo $URL_PATH
     return 0       # NODE, URL_PATH, PORT is set now
}


# args: string containing ip addresses
filter_ip6_address() {
     local a

     for a in "$@"; do
          if ! is_ipv6addr "$a"; then
               continue
          fi
          if $HAS_SED_E; then
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
          if $HAS_SED_E; then
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
               fatal "Local hostname given but no 'avahi-resolve' or 'dig' avaliable."
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
                    fatal "Local hostname given but no 'avahi-resolve' or 'dig' avaliable."
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
          if $HAS_IPv6; then
               IPADDRs=$(newline_to_spaces "$ip6")
               IP46ADDRs="$IPADDRs"          # IP46ADDRs are the ones to display, IPADDRs the ones to test
          fi
     else
          if $HAS_IPv6 && [[ -n "$ip6" ]]; then
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
     OPENSSL_CONF=""                         # see https://github.com/drwetter/testssl.sh/issues/134

     if [[ "$NODE" == *.local ]]; then
          if which avahi-resolve &>/dev/null; then
               rDNS=$(avahi-resolve -a $NODEIP 2>/dev/null | awk '{ print $2 }')
          elif which dig &>/dev/null; then
               rDNS=$(dig -x $NODEIP @224.0.0.251 -p 5353 +notcp +noall +answer | awk '/PTR/ { print $NF }')
          fi
     elif which dig &> /dev/null; then
          rDNS=$(dig -x $NODEIP +noall +answer | awk  '/PTR/ { print $NF }')    # +short returns also CNAME, e.g. openssl.org
     elif which host &> /dev/null; then
          rDNS=$(host -t PTR $NODEIP 2>/dev/null | awk '/pointer/ { print $NF }')
     elif which drill &> /dev/null; then
          rDNS=$(drill -x ptr $NODEIP 2>/dev/null | awk '/^\;\;\sANSWER\sSECTION\:$/,/\;\;\sAUTHORITY\sSECTION\:$/ { print $5,$6 }' | sed '/^\s$/d')
     elif which nslookup &> /dev/null; then
          rDNS=$(nslookup -type=PTR $NODEIP 2>/dev/null | grep -v 'canonical name =' | grep 'name = ' | awk '{ print $NF }' | sed 's/\.$//')
     fi
     OPENSSL_CONF="$saved_openssl_conf"      # see https://github.com/drwetter/testssl.sh/issues/134
     rDNS="$(echo $rDNS)"
     [[ -z "$rDNS" ]] && rDNS=" --"
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
          if ! $OPENSSL s_client help 2>&1 | grep -qw proxy; then
               fatal "Your $OPENSSL is too old to support the \"--proxy\" option" -1
          fi
          PROXYNODE=${PROXY%:*}
          PROXYPORT=${PROXY#*:}
          is_number "$PROXYPORT" || fatal "Proxy port cannot be determined from \"$PROXY\"" "-3"

          #if is_ipv4addr "$PROXYNODE" || is_ipv6addr "$PROXYNODE" ; then
          # IPv6 via openssl -proxy: that doesn't work. Sockets does
#FIXME: to finish this with LibreSSL which supports an IPv6 proxy
          if is_ipv4addr "$PROXYNODE"; then
               PROXYIP="$PROXYNODE"
          else
               check_resolver_bins
               PROXYIP=$(get_a_record $PROXYNODE 2>/dev/null | grep -v alias | sed 's/^.*address //')
               [[ -z "$PROXYIP" ]] && fatal "Proxy IP cannot be determined from \"$PROXYNODE\"" "-3"
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
                    NO_SSL_SESSIONID=true                                  # NO_SSL_SESSIONI is preset globally to false for all other cases
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
          if $HAS_IPv6; then
               pr_bold " Your $OPENSSL is not IPv6 aware, or $NODEIP:$PORT "
          else
               pr_bold " $NODEIP:$PORT "
          fi
          tmpfile_handle $FUNCNAME.txt
          pr_boldln "doesn't seem a TLS/SSL enabled server";
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
                    if [[ $protocol == "xmpp" ]]; then
                         # for XMPP, openssl has a problem using -connect $NODEIP:$PORT. thus we use -connect $NODE:$PORT instead!
                         NODEIP="$NODE"
                         if [[ -n "$XMPP_HOST" ]]; then
                              if ! $OPENSSL s_client --help 2>&1 | grep -q xmpphost; then
                                   fatal "Your $OPENSSL does not support the \"-xmpphost\" option" -3
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
                    fatal "momentarily only ftp, smtp, pop3, imap, xmpp, telnet and ldap allowed" -1
                    ;;
          esac
     fi
     #outln

     tmpfile_handle $FUNCNAME.txt
     return 0       # OPTIMAL_PROTO, GET_REQ*/HEAD_REQ* is set now
}


display_rdns_etc() {
     local ip

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
          outln " A record via            /etc/hosts "
     fi
     if [[ -n "$rDNS" ]]; then
          if $HAS_IPv6; then
               printf " %-23s %s" "rDNS $NODEIP:" "$rDNS"
          else
               printf " %-23s %s" "rDNS ($NODEIP):" "$rDNS"
          fi
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


mx_all_ips() {
     local mxs mx
     local mxport 
     local -i ret=0

     STARTTLS_PROTOCOL="smtp"

     # test first higher priority servers
     mxs=$(get_mx_record "$1" | sort -n | sed -e 's/^.* //' -e 's/\.$//' | tr '\n' ' ')
     mxport=${2:-25}
     if [[ -n "$mxs" ]] && [[ "$mxs" != ' ' ]]; then
          [[ $mxport == "465" ]] && \
               STARTTLS_PROTOCOL=""          # no starttls for Port 465, on all other ports we speak starttls
          pr_bold "Testing now all MX records (on port $mxport): "; outln "$mxs"
          for mx in $mxs; do
               draw_line "-" $((TERM_DWITH * 2 / 3))
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
          draw_line "-" $((TERM_DWITH * 2 / 3))
          outln
          pr_bold "Done testing now all MX records (on port $mxport): "; outln "$mxs"
     else
          pr_boldln " $1 has no MX records(s)"
     fi
     return $ret
}

run_mass_testing() {
     local cmdline=""

     if [[ ! -r "$FNAME" ]] && $IKNOW_FNAME; then
          fatal "Can't read file \"$FNAME\"" "-1"
     fi
     pr_reverse "====== Running in file batch mode with file=\"$FNAME\" ======"; outln "\n"
     while read cmdline; do
          cmdline=$(filter_input "$cmdline")
          [[ -z "$cmdline" ]] && continue
          [[ "$cmdline" == "EOF" ]] && break
          echo "$0 -q $cmdline"
          draw_line "=" $((TERM_DWITH / 2)); outln;
          $0 -q $cmdline
     done < "$FNAME"
     exit $?
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
     do_header=false
     do_heartbleed=false
     do_mx_all_ips=false
     do_mass_testing=false
     do_logging=false
     do_pfs=false
     do_protocols=false
     do_rc4=false
     do_renego=false
     do_std_cipherlists=false
     do_server_defaults=false
     do_server_preference=false
     do_spdy=false
     do_ssl_poodle=false
     do_tls_fallback_scsv=false
     do_test_just_one=false
     do_tls_sockets=false
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
     do_ssl_poodle=true
     do_tls_fallback_scsv=true
     VULN_COUNT=10
}

query_globals() {
     local gbl
     local true_nr=0

     for gbl in do_allciphers do_vulnerabilities do_beast do_breach do_ccs_injection do_cipher_per_proto do_crime \
               do_freak do_logjam do_header do_heartbleed do_mx_all_ips do_pfs do_protocols do_rc4 do_renego \
               do_std_cipherlists do_server_defaults do_server_preference do_spdy do_ssl_poodle do_tls_fallback_scsv \
               do_test_just_one do_tls_sockets do_mass_testing; do
                    [[ "${!gbl}" == "true" ]] && let true_nr++
     done
     return $true_nr
}


debug_globals() {
     local gbl

     for gbl in do_allciphers do_vulnerabilities do_beast do_breach do_ccs_injection do_cipher_per_proto do_crime \
               do_freak do_logjam do_header do_heartbleed do_rc4 do_mx_all_ips do_pfs do_protocols do_rc4 do_renego \
               do_std_cipherlists do_server_defaults do_server_preference do_spdy do_ssl_poodle do_tls_fallback_scsv \
               do_test_just_one do_tls_sockets do_mass_testing; do
          printf "%-22s = %s\n" $gbl "${!gbl}"
     done
     printf "%-22s : %s\n" URI: "$URI"
}


# arg1+2 are just the options
parse_opt_equal_sign() {
     if [[ "$1" == *=* ]]; then
          echo "$1" | awk -F'=' '{ print $2 }' 
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
               -V|-V=*|--local|--local=*)    # this is only displaying local ciphers, thus we don't put it in the loop
                    find_openssl_binary
                    maketempf                # for GOST support
                    mybanner
                    openssl_age
                    prettyprint_local $(parse_opt_equal_sign "$1" "$2")
                    exit $? 
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
                    ;;
               -y|--spdy|--npn)
                    do_spdy=true
                    ;;
               -f|--ciphers)
                    do_std_cipherlists=true
                    ;;
               -S|--server[-_]defaults)
                    do_server_defaults=true
                    ;;
               -P|--server[_-]preference)
                    do_server_preference=true
                    ;;
               -H|--header|--headers)
                    do_header=true
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
                    # DEBUG=3  ./testssl.sh --devel 03 "cc, 13, c0, 13" google.de    --> TLS 1.2
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
                    SHOW_EACH_C=1            #FIXME: sense is vice versa
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
               --log|--logging)
                    do_logging=true 
                    ;;   # DEFINITION of LOGFILE if no arg specified via ENV or automagically in parse_hn_ports()
                    # following does the same but we can specify a log location additionally
               --logfile=*)
                    LOGFILE=$(parse_opt_equal_sign "$1" "$2")
                    [[ $? -eq 0 ]] && shift
                    do_logging=true 
                    ;;   
               --openssl|--openssl=*)
                    OPENSSL=$(parse_opt_equal_sign "$1" "$2")
                    [[ $? -eq 0 ]] && shift
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
               (-*) pr_magentaln "\n$0: unrecognized option \"$1\"" 1>&2;
                    help 1 
                    ;;
               (*)  break 
                    ;;
          esac
          shift
     done

     # Show usage if no options were specified
     if [[ -z "$1" ]] && [[ -z "$FNAME" ]] ; then
          help 0
     else
     # left off here is the URI
          URI="$1"
     fi

     [[ "$DEBUG" -ge 5 ]] && debug_globals
     # if we have no "do_*" set here --> query_globals: we do a standard run -- otherwise just the one specified
     query_globals && set_scanning_defaults
}


# connect call from openssl needs ipv6 in square brackets
nodeip_to_proper_ip6() {
     local len_nodeip=0

     if is_ipv6addr $NODEIP; then
          NODEIP="[$NODEIP]"
          len_nodeip=${#NODEIP}
          CORRECT_SPACES="$(draw_line " " "$((len_nodeip - 16))" )"
          # IPv6 addresses are longer, this varaible takes care that "further IP" and "Service" is properly aligned
     fi
}


reset_hostdepended_vars() {
     TLS_EXTENSIONS=""
     PROTOS_OFFERED=""
     OPTIMAL_PROTO=""
}

lets_roll() {
     local ret

     [[ -z "$NODEIP" ]] && fatal "$NODE doesn't resolve to an IP address" -1
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
     $do_logjam && { run_logjam; ret=$(($? + ret)); }
     $do_beast && { run_beast; ret=$(($? + ret)); }
     $do_rc4 && { run_rc4; ret=$(($? + ret)); }

     $do_allciphers && { run_allciphers; ret=$(($? + ret)); }
     $do_cipher_per_proto && { run_cipher_per_proto; ret=$(($? + ret)); }

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
openssl_age

# TODO: it's ugly to have those two vars here --> main()
ret=0
ip=""

$do_mass_testing && run_mass_testing

#TODO: there shouldn't be the need for a special case for --mx, only the ip adresses we would need upfront and the do-parser
if $do_mx_all_ips; then
     query_globals                 # if we have just 1x "do_*" --> we do a standard run -- otherwise just the one specified
     [[ $? -eq 1 ]] && set_scanning_defaults
     mx_all_ips "${URI}" $PORT
     ret=$?
else 
     parse_hn_port "${URI}"                                                     # NODE, URL_PATH, PORT, IPADDR and IP46ADDR is set now
     if ! determine_ip_addresses && [[ -z "$CMDLINE_IP" ]]; then
          fatal "No IP address could be determined"
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
                    draw_line "-" $((TERM_DWITH * 2 / 3))
                    outln
                    NODEIP="$ip"
                    lets_roll "${STARTTLS_PROTOCOL}"
                    ret=$(($? + ret))
               done
               draw_line "-" $((TERM_DWITH * 2 / 3))
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


#  $Id: testssl.sh,v 1.423 2015/11/28 16:33:09 dirkw Exp $
