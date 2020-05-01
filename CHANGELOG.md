
## Change Log

### Features implemented / improvements in 3.1dev

* Extend Server (cipher) preference: always now in wide mode instead of running all ciphers in the end (per default)
* Improved compatibility with OpenSSL 3.0
* Renamed PFS/perfect forward secrecy --> FS/forward secrecy
* Improved mass testing
* Align better colors of ciphers with standard cipherlists
* Added several ciphers to colored ciphers
* Percent output char problem fixed
* Several display/output fixes
* Security fix: DNS input
* Don't use external pwd anymore
* STARTTLS: XMPP server support
* Rating (SSL Labs, not complete)

### Features implemented / improvements in 3.0

* Full support of TLS 1.3, shows also drafts supported
* Extended protocol downgrade checks
* ROBOT check
* Better TLS extension support
* Better OpenSSL 1.1.1 and higher versions support as well as LibreSSL >3
* More robustness for OpenBSD
* DNS over Proxy and other proxy improvements
* Decoding of unencrypted BIG IP cookies
* Initial client certificate support
* Warning of 825 day limit for certificates issued after 2018/3/1
* Socket timeouts (``--connect-timeout``)
* IDN/IDN2 servername/URI + emoji support, supposed libidn/idn2 is installed and DNS resolver is recent) support
* Initial support for certificate compression
* Better JSON output: renamed IDs and findings shorter/better parsable, also includes certficate
* JSON output now valid also for non-responding servers
* Testing now per default 370 ciphers
* Further improving the robustness of TLS sockets (sending and parsing)
* Support of supplying timeout value for `openssl connect` -- useful for batch/mass scanning
* File input for serial or parallel mass testing can be also in nmap grep(p)able (-oG) format
* LOGJAM: now checking also for DH  and FFDHE groups (TLS 1.2)
* PFS: Display of elliptical curves supported, DH and FFDHE groups (TLS 1.2 + TLS 1.3)
* Check for session resumption (Ticket, ID)
* TLS Robustness check GREASE and more
* Server preference distinguishes between TLS 1.3 and lower protocols
* Mark TLS 1.0 and TLS 1.1 as deprecated
* Does a few startup checks which make later tests easier and faster (``determine_optimal_\*()``)
* Expect-CT Header Detection
* `--phone-out` does certificate revocation checks via OCSP (LDAP+HTTP) and with CRL
* `--phone-out` checks whether the private key has been compromised via https://pwnedkeys.com/
* Missing SAN warning
* Added support for private CAs
* Way better handling of connectivity problems (counting those, if threshold exceeded -> bye)
* Fixed TCP fragmentation
* Added `--ids-friendly` switch
* Exit codes better: 0 for running without error, 1+n for small errors, >240 for major errors.
* Better error msg suppression (not fully installed OpenSSL)
* Better parsing of HTTP headers & better output of longer HTTP headers
* Display more HTTP security headers
* HTTP Basic Auth support for HTTP header
* experimental "eTLS" detection
* Dockerfile and repo @ docker hub with that file (see above)
* Java Root CA store added
* Better support for XMPP via STARTTLS & faster
* Certificate check for to-name in stream of XMPP
* Support for NNTP and LMTP via STARTTLS, fixes for MySQL and PostgresQL
* Support for SNI and STARTTLS
* More robustness for any STARTTLS protocol (fall back to plaintext while in TLS caused problems)
* Renegotiation checks improved, also no false potive for Node.js anymore
* Major update of client simulations with self-collected up-to-date data
* Update of CA certificate stores
* Lots of bug fixes
* More travis/CI checks -- still place for improvements
* Man page reviewed

### Features implemented / improvements in 2.9.5

* Way better coverage of ciphers as most checks are done via bash sockets where ever possible
* Further tests via TLS sockets and improvements (handshake parsing, completeness, robustness)
* Testing 359 default ciphers (``testssl.sh -e/-E``) with a mixture of sockets and openssl. Same speed as with openssl only but addtional ciphers such as post-quantum ciphers, new CHAHA20/POLY1305, CamelliaGCM etc.
* TLS 1.2 protocol check via sockets in production
* Finding more TLS extensions via sockets
* TLS Supported Groups Registry (RFC 7919), key shares extension
* Non-flat JSON output support
* File output (CSV, JSON flat, JSON non-flat) supports a minimum severity level (only above supplied level there will be output)
* Native HTML support instead going through 'aha'
* LUCKY13 and SWEET32 checks
* Ticketbleed check
* LOGJAM: now checking also for known DH parameters
* Support of supplying timeout value for ``openssl connect`` -- useful for batch/mass scanning
* Parallel mass testing
* Check for CAA RR
* Check for OCSP must staple
* Check for Certificate Transparency
* Check for session resumption (Ticket, ID)
* Better formatting of output (indentation)
* Choice showing the RFC naming scheme only
* File input for mass testing can be also in nmap grep(p)able (-oG) format
* Postgres und MySQL STARTTLS support
* Man page


### New in 2.8

* Trust chain check against certificate stores from Apple (OS), Linux (OS),
  Microsoft (OS), Mozilla (Firefox Browser), works for openssl >=1.0.1
* IPv6 (status: 80% working, details see
  https://github.com/drwetter/testssl.sh/issues/11
* works now on servers requiring a x509 certificate for authentication
* extensive CN <--> hostname check
* SSL Session ID check
* Avahi/mDNS based name resolution
* HTTP2/ALPN protocol check
* Logging to a file / dir
* Logging to (flat) JSON + CSV
* HPKP checks now also for Root, intermediate SPKIs
* Check for multiple server certificates
* Browser cipher simulation: what client will connect with which cipher + protocol
* GOST cipher+certificate improvements
* Assistance for color-blind users
* Even more compatibility improvements for FreeBSD, NetBSD, Gentoo, RH-ish, F5 and Cisco systems
* Considerable speed improvements for each cipher runs (-e/-E)
* More robust SSLv2 + TLS socket interface
* seperate check for curves
* OpenSSL 1.1.0 compliant
* check for DROWN
* Whole number of bugs squashed

### New in 2.6

  * Display matching host key (HPKP)
  * LOGJAM 1: check DHE_EXPORT cipher
  * LOGJAM 2: displays DH(/ECDH) bits in wide mode on negotiated ciphers
  * "wide mode" option for checks like RC4, BEAST. PFS. Displays hexcode, kx, strength, DH bits, RFC name
  * binary directory provides out of the box better binaries (Linux 32+64 Bit, Darwin 64 bit, FreeBSD 64 bit)
  * OS X binaries (@jvehent, new builds: @jpluimers)
  * ARM binary (@f-s)
  * FreeBSD binary
  * TLS_FALLBACK_SCSV check -- thx @JonnyHightower
  * (HTTP) proxy support! Also with sockets -- thx @jnewbigin
  * Extended validation certificate detection
  * Run in default mode through all ciphers at the end of a default run
  * will test multiple IP adresses of one supplied server name in one shot, --ip= restricts it accordingly
  * new mass testing file option --file option where testssl.sh commands are being read from, see https://twitter.com/drwetter/status/627619848344989696
  * TLS time and HTTP time stamps
  * TLS time displayed also for STARTTLS protocols
  * support of sockets for STARTTLS protocols
  * TLS 1.0-1.1 as socket checks per default in production
  * further detection of security relevant headers (reverse proxy, IPv4 addresses), proprietary banners (OWA, Liferay etc.)
  * can scan STARTTLS+XMPP by also supplying the XMPP domain (to-option in XML streams).
  * quite some LibreSSL fixes, still not recommended to use though (see https://testssl.sh/)
  * lots of fixes, code improvements, even more robust

Full log @ https://github.com/drwetter/testssl.sh/commits/2.6/testssl.sh


### New in 2.4
  * "only one cmd line option at a time" is completely gone
  * several tuning parameters on the cmd line (only available through environment variables b4): --assuming-http, --ssl-native, --sneaky, --warnings, --color, -- debug, --long
  * certificate information
  * more HTTP header infos (cookies+security headers)
  * protocol check via bash sockets for SSLv2+v3
  * debug handling significantly improved (verbosity/each function leaves files in $TEMPDIR)
  * BEAST check
  * FREAK check
  * check for Secure Client-Initiated Renegotiation
  * lots of cosmetic and maintainability code cleanups
  * bugfixing

Full changelog: https://github.com/drwetter/testssl.sh/commits/2.4/testssl.sh

### 2.2. new features:
  * Works fully under FreeBSD (openssl >=1.0)
  * single cipher check (-x) with pattern of hexcode/cipher
  * check for POODLE SSL
  * HPKP check
  * OCSP stapling
  * GOST and CHACHA20 POLY1305 cipher support
  * service detection (HTTP, IMAP, POP, SMTP)
  * runs now with all colors, b/w screen, no escape codes at all
  * protocol check better
  * job control removes stalling
  * RFC <---> OpenSSL name space mapping of ciphers everywhere
  * includes a lot of fixes

Full changelog @  https://github.com/drwetter/testssl.sh/commits/2.2/testssl.sh

### 2.0 major release, new features:
  * SNI
  * STARTTLS fully supported
  * RC4 check
  * (P)FS check
  * SPDY check
  * color codes make more sense now
  * cipher hexcodes are shown
  * tests ciphers per protocol
  * HSTS
  * web and application server banner
  * server prefereences
  * TLS server extensions
  * server key size
  * cipher suite mapping from openssl to RFC
  * heartbleed check
  * CCS injection check

### Historical releases

1.112
- IPv6 display fix

1.111
- NEW: tested unter FreeBSD (works with exception of xxd in CCS)
- getent now works under Linux and FreeBSD
- sed -i in hsts sacrificed for compatibility
- reomved query for IP for finishing banner, is now called once in parse_hn_port
- GOST warning after banner
- empty build date is not displayed anymore
- long build date strings minimized
- FIXED: IPv6 address are displayed again

1.110
- NEW: adding Russian GOST cipher support by providing a config file on the fly
- adding the compile date of openssl in the banner

1.109
- minor IPv6 fixes

1.108
- NEW: Major rewrite of output functions. Now using printf instead of "echo -e" for BSD and MacOSX compatibility

1.107
- improved IP address stuff

1.106
- minor fixes

1.105
- NEW: working prototype for CCS injection

1.104
- NEW: everywhere *also* RFC style ciphers -- if the mapping file is found
- unitary calls to display cipher suites

1.103
- NEW: telnet support for STARTTLS (works only with a patched openssl version)
  --> not tested (lack of server)

1.102
- NEW: test for BREACH (experimental)

.101
- BUGFIX: muted too verbose output of which on CentOS/RHEL
- BUGFIX: muted too verbose output of netcat/nc on CentOS/RHEL+Debian

1.100
- further cleanup
  - starttls now tests allciphers() instead of cipher_per_proto
      (normal use case makes most sense here)
  - ENV J_POSITIV --> SHOW_EACH_C
- finding mapping-rfc.txt is now a bit smarter
- preparations for ChaCha20-Poly1305 (would have provided binaries but
  "openssl s_client -connect" with that ciphersuite fails currently with
  a handshake error though client and server hello succeeded!)

1.99
- BUGFIX: now really really everywhere testing the IP with supplied name
- locking out openssl < 0.9.8f, new function called "old_fart" ;-)
- FEATURE: displaying PTR record of IP
- FEATURE: displaying further IPv4/IPv6 addresses
- bit of a cleanup

1.98
- http_header is in total only called once
- better parsing of default protocol (FIXME shouldn't appear anymore)

1.97
- reduced sleep time for server hello and payload reply (heartbleed)

1.96
- NEW: (experimental) heartbleed support with bash sockets (shell only SSL handshake!)
  see also https://testssl.sh/bash-heartbleed.sh

1.95 (2.0rc3)
- changed cmdline options for CRIME and renego vuln to uppercase
- NEW: displays server key size now
- NEW: displays TLS server extensions (might kill old openssl versions)
- brown warning if HSTS < 180 days
- brown warning if SSLv3 is offered as default protocol

1.94
- NEW: prototype of mapping to RFC cipher suite names, needed file mapping-rfc.txt in same dir
  as of now only used for 'testssl.sh -V'
- internal renaming: it was supposed to be "cipherlists" instead of "ciphersuites"
- additional tests for cipherlists DES, 3DES, ADH

1.93
- BUGFIX: removed space in Server banner fixed (at the expense of showing just nothing if Server string is empty)

1.92
- BUGFIX: fixed error of faulty detected empty server string

1.91
- replaced most lcyan to brown (=not really bad but somehow)
- empty server string better displayed
- prefered CBC TLS 1.2 cipher is now brown (lucky13)

1.90
- fix for netweaver banner (server is lowercase)
- no server banner is no disadvantage (color code)


1.89
- reordered! : protocols + cipher come first
- colorized prefered server preference (e.g. CBC+RC4 is light red now, TLSv1.2 green)
- SSLv3 is now light cyan
- NEW: -P|--preference now in help menu
- light cyan is more appropriate than red for HSTS

1.88
- NEW: prototype for protocol and cipher preference
- prototype for session ticket

1.87
- changed just the version string to rc1

1.86
 - NEW: App banner now production, except 2 liners
 - DEBUG: 1 is now true as everywhere else
 - CRIME+Renego prettier
 - last optical polish for RC4, PFS

1.85
 - NEW: appbanner (also 2 lines like asp.net)
 - OSSL_VER_MAJOR/MINOR/APPENDIX
 - less bold because bold headlines as bold should be reserved for emphasize findings
 - tabbed output also for protocols and cipher classes
 - unify neat printing

1.84
 - NEW: deprecating openssl version <0.98
 - displaying a warning >= 0.98 < 1.0
 - NEW: neat print also for all ciphers (-E,-e)

1.83
- BUGFIX: results from unit test: logical error in PFS+RC4 fixed
- headline of -V / PFS+RC4 ciphers unified

1.82
- NEW: output for -V now better (bits seperate, spacing improved)

1.81
- output for RC4+PFS now better (with headline, bits seperate, spacing improved)
- both also sorted by encr. strength .. umm ..err bits!

1.80
- order of finding supplied binary extended (first one wins):
  1. use supplied variable $OPENSSL
  2. use "openssl" in same path as testssl.sh
  3. use "openssl.`uname -m`" in same path as testssl.sh
  4. use anything in system $PATH (return value of "which"

1.79
- STARTTLS options w/o trailing 's' now (easier)
- commented code for CRIME SPDY
- issue a warning for openssl < 0.9.7 ( that version won't work anyway probably)

1.78
- -E, -e now sorted by encryption strength (note: it's only encr key length)
- -V now pretty prints all local ciphers
- -V <pattern> now pretty prints all local ciphers matching pattern (plain string, no regex)
- bugfix: SSLv2 cipher hex codes has 3 bytes!

1.77
- removed legacy code (PROD_REL var)

1.76
- bash was gone!! desaster for Ubuntu, fixed
- starttls+rc4 check: bottom line was wrong
- starttls had too much output (certificate) at first a/v check

1.75
- location is now https://testssl.sh
- be nice: banner, version, help also works for BSD folks (on dash)
- bug in server banner fixed
- sneaky referer and user agent possible

1.74
- Debian 7 fix
- ident obsoleted

1.72
- removed obsolete GREP
- SWURL/SWCONTACT
- output for positive RC4 better

1.71
- workaround for buggy bash (RC4)
- colors improved
  - blue is now reserved for headline
  - magenta for local probs
  - in RC4 removal of SSL protocol provided by openssl

1.70
- DEBUG in http_headers now as expected
- <?xml marker as HTML body understood

1.69
- HTTP 1.1 header
- removed in each cipher the proto openssl is returning
+ NEW: cipher_per_proto

1.68
- header parser for openssl
- HSTS

[..]

1.36
* fixed issue while connecting to non-webservers

1.35
* fixed portability issue on Ubuntu

1.34
* ip(v4) address in output, helps to tell different systems apart later on
* local hostname in output

1.31 (Halloween Release)
* bugfix: SSLv2 was kind of borken
* now it works for sure but ssl protocol are kind of ugly

1.30b (25.10.2012)
* bugfix: TLS 1.1/1.2 may lead to false negatives
* bugfix: CMDLINE -a/-e was misleading, now similar to help menu

1.3 (10/13/2012)
* can test now for cipher suites only
* can test now for protocols suites only
* tests for tls v1.1/v1.2 of local openssl supports it
* commandline "all "is rename to "each-cipher"
* banner when it's done

1.21a (10/4/2012)
* tests whether openssl has support for zlib compiled so that it avoids a false negative

1.21 (10/4/2012)
* CRIME support

1.20b
* bugfixed release

1.20a
* code cleanup
* showciphers variable introduced: only show ciphers if this is set (it is by
  default now and there's a comment
* openssl version + path to it in the banner


1.20
* bugfix (ssl in ssl handshake failure is sometimes too much)
* date in output
* autodetection of CVS version removed

1.19
* bugfix
1.18
* Rearragement of arguments: URL comes now always last!
* small code cleanups for readability
* individual cipher test is now with bold headline, not blue
* NOPARANOID flag tells whether medium grade ciphers are ok. NOW they are (=<1.17 was paranoid)

1.17
* SSL tests now for renegotiation vulnerabilty!
* version detection of testssl.sh
* program has a banner
* fixed bug leading to a file named "1"
* comment for 128Bit ciphers

1.16
* major code cleanups
* cmd line options: port is now in first argument!!
* help is more verbose
* check whether on other server side is ssl server listening
* https:// can be now supplied also on the command line
* test all ciphers now
* new cleanup routine
* -a does not do standard test afterward, you need to run testssl a second
  time w/o -a if you want this

1.12
* tests also medium grade ciphers (which you should NOT use)
* tests now also high grade ciphers which you SHOULD ONLY use
* switch for more verbose output of cipher for those cryptographically interested .
  in rows: SSL version, Key eXchange, Authentication, Encryption and Message Authentication Code
* this is per default enabled (provide otherwise "" as VERB_CLIST)
* as a courtesy I am providing 64+32 Linux binaries for testing 56 Bit ciphers

1.11
* Hint for howto enable 56 Bit ciphers fpr testing
* possible to specify where openssl is (hardcoded, $ENV, last resort: auto)
* warns if netcat is not there

1.10
* somewhat first released version
