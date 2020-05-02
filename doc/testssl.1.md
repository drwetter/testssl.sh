
## NAME
   testssl.sh -- check encryption of SSL/TLS servers

## SYNOPSIS


`testssl.sh [OPTIONS] <URI>`,   `testssl.sh [OPTIONS] --file <FILE>`

  or

`testssl.sh [BANNER OPTIONS]`

## DESCRIPTION

testssl.sh is a free command line tool which checks a server's service on any port for the support of TLS/SSL ciphers, protocols as well as cryptographic flaws and much more.

The output rates findings by color (screen) or severity (file output) so that you are able to tell whether something is good or bad. The (screen) output has several sections in which classes of checks are being performed. To ease readability on the screen it aligns and indents the output properly.

Only you see the result. You also can use it internally on your LAN. Except DNS lookups or unless you instruct testssl.sh to check for revocation of certificates it doesn't use any other hosts or even third parties for any test.

## REQUIREMENTS

Testssl.sh is out of the box portable: it runs under any Unix-like
stack: Linux, \*BSD, MacOS X, WSL=Windows Subsystem for Linux, Cygwin and MSYS2.
`bash` is a prerequisite, also version 3 is still supported.
Standard utilities like awk, sed, tr and head are also needed. This can be of a BSD,
System 5 or GNU flavor whereas grep from System V is not yet supported.

Any OpenSSL or LibreSSL version is needed as a helper. Unlike previous versions
of testssl.sh almost every check is done via (TCP) sockets. In addition statically
linked OpenSSL binaries for major operating systems are supplied in `./bin/`.


## GENERAL

`testssl.sh URI` as the default invocation does the so-called default run which does a number of checks and puts out the results colorized (ANSI and termcap) on the screen. It does every check listed below except `-E` which are (order of appearance):

0) displays a banner (see below), does a DNS lookup also for further IP addresses and does for the returned IP address a reverse lookup. Last but not least a service check is being done.

1) SSL/TLS protocol check

2) standard cipher categories

3) server's cipher preferences (server order?)

4) forward secrecy: ciphers and elliptical curves

5) server defaults (certificate info, TLS extensions, session information)

6) HTTP header (if HTTP detected or being forced via `--assume-http`)

7) vulnerabilities

8) testing each of 370 preconfigured ciphers

8) client simulation

9) rating



## OPTIONS AND PARAMETERS

Options are either short or long options. Any long or short option requiring a value can be called with or without an equal sign. E.g. `testssl.sh -t=smtp --wide --openssl=/usr/bin/openssl <URI>` (short options with equal sign) is equivalent to `testssl.sh --starttls smtp --wide --openssl /usr/bin/openssl <URI>` (long option without equal sign). Some command line options can also be preset via ENV variables. `WIDE=true OPENSSL=/usr/bin/openssl testssl.sh --starttls=smtp <URI>` would be the equivalent to the aforementioned examples. Preference has the command line over any environment variables.

`<URI>` or `--file <FILE>` always needs to be the last parameter.

### BANNER OPTIONS

`--help` (or no arg) display command line help

`-b, --banner`        displays testssl.sh banner, including license, usage conditions, version of testssl.sh, detected openssl version, its path to it, # of ciphers of openssl, its build date and the architecture

`-v, --version`     same as before

`-V [pattern] , --local [pattern]`  pretty print all local ciphers supported by openssl version. If a pattern is supplied it performs a match (ignore case) on any of the strings supplied in the wide output, see below. The pattern will be searched in the any of the columns: hexcode, cipher suite name (OpenSSL or IANA), key exchange, encryption, bits. It does a word pattern match for non-numbers, for number just a normal match applies. Numbers here are defined as [0-9,A-F]. This means (attention: catch) that the pattern CBC is matched as non-word, but AES as word.

### INPUT PARAMETERS

`URI` can be a hostname, an IPv4 or IPv6 address (restriction see below) or an URL. IPv6 addresses need to be in square brackets. For any given parameter port 443 is assumed unless specified by appending a colon and a port number. The only preceding protocol specifier allowed is `https`. You need to be aware that checks for an IP address might not hit the vhost you want. DNS resolution (A/AAAA record) is being performed unless you have an `/etc/hosts` entry for the hostname.

`--file <fname>` or the equivalent `-iL <fname>` are mass testing options. Per default it implicitly turns on `--warnings batch`. In its first incarnation the mass testing option reads command lines from `fname`. `fname` consists of command lines of testssl, one line per instance. Comments after `#` are ignored, `EOF` signals the end of fname any subsequent lines will be ignored too. You can also supply additional options which will be inherited to each child, e.g.  When invoking `testssl.sh --wide --log --file <fname>` . Each single line in `fname` is parsed upon execution. If there's a conflicting option and serial mass testing option is being performed the check will be aborted at the time it occurs and depending on the output option potentially leaving you with an output file without footer. In parallel mode the mileage varies, likely a line won't be scanned.

Alternatively `fname` can be in `nmap`'s grep(p)able output format (`-oG`). Only open ports will be considered. Multiple ports per line are allowed. The ports can be different and will be tested by testssl.sh according to common practice in the internet, i.e. if nmap shows in its output an open port 25, automatically `-t smtp` will be added before the URI whereas port 465 will be treated as a plain TLS/SSL port, not requiring an STARTTLS SMTP handshake upfront. This is done by an internal table which correlates nmap's open port detected to the STARTTLS/plain text decision from testssl.sh.

Nmap's output always returns IP addresses and only if there's a PTR DNS record available a hostname. As it is not checked by nmap whether the hostname matches the IP (A or AAAA record), testssl.sh does this automatically for you. If the A record of the hostname matches the IP address, the hostname is used and not the IP address. Please keep in mind that checks against an IP address might not hit the vhost you maybe were aiming at and thus it may lead to different results.

A typical internal conversion to testssl.sh file format from nmap's grep(p)able format could look like:

```
10.10.12.16:443
10.10.12.16:1443
-t smtp host.example.com:25
host.example.com:443
host.example.com:631
-t ftp 10.10.12.11:21
10.10.12.11:8443
```
Please note that `fname` has to be in Unix format. DOS carriage returns won't be accepted. Instead of the command line switch the environment variable FNAME will be honored too.

`--mode <serial|parallel>`. Mass testing to be done serial (default) or parallel (`--parallel` is shortcut for the latter, `--serial` is the opposite option). Per default mass testing is being run in serial mode, i.e. one line after the other is processed and invoked. The variable `MASS_TESTING_MODE` can be defined to be either equal `serial` or `parallel`.

`--warnings <batch|off>`.  The warnings parameter determines how testssl.sh will deal with situations where user input normally will be necessary. There are two options. `batch` doesn't wait for a confirming keypress when a client- or server-side probem is encountered. As of 3.0 it just then terminates the particular scan.  This is automatically chosen for mass testing (`--file`). `off` just skips the warning, the confirmation but continues the scan, independent whether it makes sense or not. Please note that there are conflicts where testssl.sh will still ask for confirmation which are the ones which otherwise would have a drastic impact on the results. Almost any other decision will be made in the future as a best guess by testssl.sh.
The same can be achieved by setting the environment variable `WARNINGS`.

`--connect-timeout <seconds>`  This is useful for socket TCP connections to a node. If the node does not complete a TCP handshake (e.g. because it is down or behind a firewall or there's an IDS or a tarpit) testssl.sh may ususally hang for around 2 minutes or even much more. This parameter instructs testssl.sh to wait at most `seconds` for the handshake to complete before giving up. This option only works if your OS has a timeout binary installed. CONNECT_TIMEOUT is the corresponding enviroment variable.

`--openssl-timeout <seconds>` This is especially useful for all connects using openssl and practically useful for mass testing. It avoids the openssl connect to hang for ~2 minutes. The expected parameter `seconds` instructs testssl.sh to wait before the openssl connect will be terminated. The option is only available if your OS has a timeout binary installed. As there are different implementations of `timeout`: It automatically calls the binary with the right parameters. OPENSSL_TIMEOUT is the equivalent environment variable.

`--basicauth <user:pass>` This can be set to provide HTTP basic auth credentials which are used during checks for security headers. BASICAUTH is the ENV variable you can use instead.


### SPECIAL INVOCATIONS

`-t <protocol>, --starttls <protocol>`    does a default run against a STARTTLS enabled `protocol`. `protocol` must be one of `ftp`, `smtp`,  `pop3`, `imap`, `xmpp`, `xmpp-server`, `telnet`, `ldap`, `irc`, `lmtp`, `nntp`, `postgres`, `mysql`. For the latter four you need e.g. the supplied OpenSSL or OpenSSL version 1.1.1. Please note: MongoDB doesn't offer a STARTTLS connection, LDAP currently only works with `--ssl-native`. `telnet` and `irc` is WIP.

`--xmpphost <jabber_domain>` is an additional option for STARTTLS enabled XMPP: It expects the jabber domain as a parameter. This is only needed if the domain is different from the URI supplied.

`--mx <domain|host>` tests all MX records (STARTTLS on port 25) from high to low priority, one after the other.

`--ip <ip>` tests either the supplied IPv4 or IPv6 address instead of resolving host(s) in `<URI>`. IPv6 addresses need to be supplied in square brackets. `--ip=one` means: just test the first A record DNS returns (useful for multiple IPs). If `-6` and  `--ip=one` was supplied an AAAA record will be picked if available. The ``--ip`` option might be also useful if you want to resolve the supplied hostname to a different IP, similar as if you would edit `/etc/hosts` or `/c/Windows/System32/drivers/etc/hosts`. `--ip=proxy` tries a DNS resolution via proxy.

`--proxy <host>:<port>`  does ANY check via the specified proxy. `--proxy=auto` inherits the proxy setting from the environment. The hostname supplied will be resolved to the first A record. In addition if you want lookups via proxy you can specify `DNS_VIA_PROXY=true`. OCSP revocation checking (`-S --phone-out`) is not supported by OpenSSL via proxy. As supplying a proxy is an indicator for port 80 and 443 outgoing being blocked in your network an OCSP revocation check won't be performed. However if `IGN_OCSP_PROXY=true` has been supplied it will be tried directly. Authentication to the proxy is not supported. Proxying via IPv6 addresses is not possible, no HTTPS or SOCKS proxy is supported.

`-6` does (also) IPv6 checks. Please note that testssl.sh doesn't perform checks on an IPv6 address automatically, because of two reasons: testssl.sh does no connectivity checks for IPv6 and it cannot determine reliably whether the OpenSSL binary you're using has IPv6 s_client support. `-6` assumes both is the case. If both conditions are met and you in general prefer to test for IPv6 branches as well you can add `HAS_IPv6` to your shell environment. Besides the OpenSSL binary supplied IPv6 is known to work with vanilla OpenSSL >= 1.1.0 and older versions >=1.0.2 in RHEL/CentOS/FC and Gentoo.

`--ssl-native`  Instead of using a mixture of bash sockets and a few openssl s_client connects, testssl.sh uses the latter (almost) only. This is faster at the moment but provides less accurate results, especially for the client simulation and for cipher support. For all checks you will see a warning if testssl.sh cannot tell if a particular check cannot be performed. For some checks however you might end up getting false negatives without a warning. This option is only recommended if you prefer speed over accuracy or you know that your target has sufficient overlap with the protocols and cipher provided by your openssl binary.

`--openssl <path_to_openssl>`           testssl.sh tries very hard to find automagically the binary supplied (where the tree of testssl.sh resides, from the directory where testssl.sh has been started from, etc.). If all that doesn't work it falls back to openssl supplied from the OS (`$PATH`). With this option you can point testssl.sh to your binary of choice and override any internal magic to find the openssl binary. (Environment preset via `OPENSSL=<path_to_openssl>`).


### TUNING OPTIONS

`--bugs`  does some workarounds for buggy servers like padding for old F5 devices. The option is passed as `-bug` to openssl when needed, see `s_client(1)`, environment preset via `BUGS="-bugs"` (1x dash). For the socket part testssl.sh has always workarounds in place to cope with broken server implementations.

`--assuming-http`  testssl.sh normally does upfront an application protocol detection. In cases where HTTP cannot be automatically detected you may want to use this option. It enforces testssl.sh not to skip HTTP specific tests (HTTP header) and to run a browser based client simulation. Please note that sometimes also the severity depends on the application protocol, e.g. SHA1 signed certificates, the lack of any SAN matches and some vulnerabilities will be punished harder when checking a web server as opposed to a mail server.

`-n, --nodns <min|none>` tells testssl.sh which DNS lookups should be performed. `min` uses only forward DNS resolution (A and AAAA record or MX record) and skips CAA lookups and PTR records from the IP address back to a DNS name.  `none` performs no DNS lookups at all. For the latter you either have to supply the IP address as a target, to use `--ip` or have the IP address
in `/etc/hosts`.  The use of the switch is only useful if you either can't or are not willing to perform DNS lookups. The latter can apply e.g. to some pentests. In general this option could e.g. help you to avoid timeouts by DNS lookups. `NODNS` is the enviroment variable for this.

`--sneaky` For HTTP header checks testssl.sh uses normally the server friendly HTTP user agent `TLS tester from ${URL}`. With this option your traces are less verbose and a Firefox user agent is being used. Be aware that it doesn't hide your activities. That is just not possible (environment preset via `SNEAKY=true`).

`--ids-friendly` is a switch which may help to get a scan finished which otherwise would be blocked by a server side IDS. This switch skips tests for the following vulnerabilities: Heartbleed, CCS Injection, Ticketbleed and ROBOT. The environment variable OFFENSIVE set to false will achieve the same result. Please be advised that as an alternative or as a general approach you can try to apply evasion techniques by changing the variables USLEEP_SND and / or USLEEP_REC and maybe MAX_WAITSOCK.

`--phone-out` Checking for revoked certificates via CRL and OCSP is not done per default. This switch instructs testssl.sh to query external -- in a sense of the current run -- URIs. By using this switch you acknowledge that the check might have privacy issues, a download of several megabytes (CRL file) may happen and there may be network connectivity problems while contacting the endpoint which testssl.sh doesn't handle. PHONE_OUT is the environment variable for this which needs to be set to true if you want this.

`--add-ca <cafile>` enables you to add your own CA(s) for trust chain checks. `cafile` can be a single path or multiple paths as a comma separated list of root CA files. Internally they will be added during runtime to all CA stores. This is (only) useful for internal hosts whose certificates is issued by internal CAs. Alternatively 
ADDTL_CA_FILES is the environment variable for this.


### SINGLE CHECK OPTIONS

Any single check switch supplied as an argument prevents testssl.sh from doing a default run. It just takes this and if supplied other options and runs them - in the order they would also appear in the default run.

`-e, --each-cipher` checks each of the (currently configured) 370 ciphers via openssl + sockets remotely on the server and reports back the result in wide mode. If you want to display each cipher tested you need to add `--show-each`. Per default it lists the following parameters: `hexcode`, `OpenSSL cipher suite name`, `key exchange`, `encryption bits`, `IANA/RFC cipher suite name`. Please note the `--mapping` parameter changes what cipher suite names you will see here and at which position. Also please note that the __bit__ length for the encryption is shown and not the __security__ length, albeit it'll be sorted by the latter. For 3DES due to the Meet-in-the-Middle problem the bit size of 168 bits is equivalent to the security size of 112 bits.

`-E, --cipher-per-proto`  is similar to `-e, --each-cipher`. It checks each of the possible ciphers, here: per protocol. If you want to display each cipher tested you need to add `--show-each`. The output is sorted by security strength, it lists the encryption bits though.

`-s, --std, --standard`   tests certain lists of cipher suites by strength. Those lists are (`openssl ciphers $LIST`, $LIST from below:)

* `NULL encryption ciphers`: 'NULL:eNULL'
* `Anonymous NULL ciphers`: 'aNULL:ADH'
* `Export ciphers` (w/o the preceding ones): 'EXPORT:!ADH:!NULL'
* `LOW` (64 Bit + DES ciphers, without EXPORT ciphers): 'LOW:DES:RC2:RC4:!ADH:!EXP:!NULL:!eNULL'
* `3DES + IDEA Ciphers`: '3DES:IDEA:!aNULL:!ADH'
* `Average grade Ciphers`: 'HIGH:MEDIUM:AES:CAMELLIA:ARIA:!IDEA:!CHACHA20:!3DES:!RC2:!RC4:!AESCCM8:!AESCCM:!AESGCM:!ARIAGCM:!aNULL'
* `Strong grade Ciphers` (AEAD): 'AESGCM:CHACHA20:CamelliaGCM:AESCCM8:AESCCM'

`-f, --fs, --nsa, --forward-secrecy` Checks robust forward secrecy key exchange. "Robust" means that ciphers having intrinsic severe weaknesses like Null Authentication or Encryption, 3DES and RC4 won't be considered here. There shouldn't be the wrong impression that a secure key exchange has been taking place and everything is fine when in reality the encryption sucks. Also this section lists the available elliptical curves and Diffie Hellman groups, as well as FFDHE groups (TLS 1.2 and TLS 1.3).

`-p, --protocols`  checks TLS/SSL protocols SSLv2, SSLv3, TLS 1.0 through TLS 1.3 and for HTTP: SPDY (NPN) and ALPN, a.k.a. HTTP/2. For TLS 1.3 several drafts (from 18 on) and final are supported and being tested for.

`-P, --preference`  displays the servers preferences: cipher order, with used openssl client: negotiated protocol and cipher. If there's a cipher order enforced by the server it displays it for each protocol (openssl+sockets). If there's not, it displays instead which ciphers from the server were picked with each protocol.

`-S, --server_defaults`  displays information from the server hello(s):

* Available TLS extensions,
* TLS ticket + session ID information/capabilities,
* session resumption capabilities,
* Time skew relative to localhost (most server implementations return random values).
* Several certificate information
    - signature algorithm,
    - key size,
    - key usage and extended key usage,
    - fingerprints and serial
    - Common Name (CN), Subject Alternative Name (SAN), Issuer,
    - Trust via hostname + chain of trust against supplied certificates
    - EV certificate detection
    - experimental "eTLS" detection
    - validity: start + end time, how many days to go (warning for certificate lifetime >=5 years)
    - revocation info (CRL, OCSP, OCSP stapling + must staple). When `--phone-out` supplied it checks against the certificate issuer whether the host certificate has been revoked (plain OCSP, CRL).
    - displaying DNS Certification Authority Authorization resource record
    - Certificate Transparency info (if provided by server).

For the trust chain check 5 certificate stores are provided. If the test against one of the trust stores failed, the one is being identified and the reason for the failure is displayed - in addition the ones which succeeded are displayed too.
You can configure your own CA via ADDTL_CA_FILES, see section `FILES` below.  If the server provides no matching record in Subject Alternative Name (SAN) but in Common Name (CN), it will be indicated as this is deprecated.
Also for multiple server certificates are being checked for as well as for the certificate reply to a non-SNI (Server Name Indication) client hello to the IP address. Regarding the TLS clock skew: it displays the time difference to the client. Only a few TLS stacks nowadays still support this and return the local clock `gmt_unix_time`, e.g. IIS, openssl < 1.0.1f. In addition to the HTTP date you could e.g. derive that there are different hosts where your TLS and your HTTP request ended -- if the time deltas differ significantly.

`-x <pattern>, --single-cipher <pattern>` tests matched `pattern` of ciphers against a server. Patterns are similar to `-V pattern , --local pattern`, see above about matching.

`-h, --header, --headers`       if the service is HTTP (either by detection or by enforcing via `--assume-http`. It tests several HTTP headers like

* HTTP Strict Transport Security (HSTS)
* HTTP Public Key Pinning (HPKP)
* Server banner
* HTTP date+time
* Server banner like Linux or other Unix vendor headers
* Application banner (PHP, RoR, OWA, SharePoint, Wordpress, etc)
* Reverse proxy headers
* Web server modules
* IPv4 address in header
* Cookie (including Secure/HTTPOnly flags)
* Decodes BIG IP F5 non-encrypted cookies
* Security headers (X-Frame-Options, X-XSS-Protection, Expect-CT,... , CSP headers). Nonsense is not yet detected here.

`--c, --client-simulation`     This simulates a handshake with a number of standard clients so that you can figure out which client cannot or can connect to your site. For the latter case the protocol, cipher and curve is displayed, also if there's Forward Secrecy. testssl.sh uses a handselected set of clients which are retrieved by the SSLlabs API. The output is aligned in columns when combined with the `--wide` option. If you want the full nine yards of clients displayed use the environment variable ALL_CLIENTS.

`-g, --grease` checks several server implementation bugs like tolerance to size limitations and GREASE, see https://www.ietf.org/archive/id/draft-ietf-tls-grease-01.txt . This checks doesn't run per default.



### VULNERABILITIES

`-U, --vulnerable, --vulnerabilities` Just tests all (of the following) vulnerabilities. The environment variable `VULN_THRESHLD` determines after which value a separate headline for each vulnerability is being displayed. Default is `1` which means if you check for two vulnerabilities, only the general headline for vulnerabilities section is displayed -- in addition to the vulnerability and the result. Otherwise each vulnerability or vulnerability section gets its own headline in addition to the output of the name of the vulnerabilty and test result. A vulnerability section is comprised of more than one check, e.g. the renegotiation vulnerability check has two checks, so has Logjam.

`-H, --heartbleed`              Checks for Heartbleed, a memory leakage in openssl. Unless the server side doesn't support the heartbeat extension it is likely that this check runs into a timeout. The seconds to wait for a reply can be adjusted with `HEARTBLEED_MAX_WAITSOCK`. 8 is the default.

`-I, --ccs, --ccs-injection`    Checks for CCS Injection which is an openssl vulnerability. Sometimes also here the check needs to wait for a reply. The predefined timeout of 5 seconds can be changed with the environment variable `CCS_MAX_WAITSOCK`.

`-T, --ticketbleed`             Checks for Ticketbleed memory leakage in BigIP loadbalancers.

`-BB, --robot`          Checks for vulnerability to ROBOT / (*Return Of Bleichenbacher's Oracle Threat*) attack.

`-R, --renegotiation`           Tests renegotiation vulnerabilities. Currently there's a check for *Secure Renegotiation* and for *Secure Client-Initiated Renegotiation*. Please be aware that vulnerable servers to the latter can likely be DoSed very easily (HTTP). A check for *Insecure Client-Initiated Renegotiation* is not yet implemented.

`-C, --compression, --crime`    Checks for CRIME (*Compression Ratio Info-leak Made Easy*) vulnerability in TLS. CRIME in SPDY is not yet being checked for.

`-B, --breach`                  Checks for BREACH (*Browser Reconnaissance and Exfiltration via Adaptive Compression of Hypertext*) vulnerability. As for this vulnerability HTTP level compression is a prerequisite it'll be not tested if HTTP cannot be detected or the detection is not enforced via ``--assume-http`. Please note that only the URL supplied (normally "/" ) is being tested.

`-O, --poodle`                  Tests for SSL POODLE (*Padding Oracle On Downgraded Legacy Encryption*) vulnerability. It basically checks for the existence of CBC ciphers in SSLv3.

`-Z, --tls-fallback`            Checks TLS_FALLBACK_SCSV mitigation. TLS_FALLBACK_SCSV is basically a ciphersuite appended to the Client Hello trying to prevent protocol downgrade attacks by a Man in the Middle.

`-W, --sweet32`                 Checks for vulnerability to SWEET32 by testing 64 bit block ciphers (3DES, RC2 and IDEA).

`-F, --freak`                   Checks for FREAK vulnerability (*Factoring RSA Export Keys*) by testing for EXPORT RSA ciphers

`-D, --drown`                   Checks for DROWN vulnerability (*Decrypting RSA with Obsolete and Weakened eNcryption*) by checking whether the SSL 2 protocol is available at the target. Please note that if you use the same RSA certificate elsewhere you might be vulnerable too. testssl.sh doesn't check for this but provides a helpful link @ censys.io which provides this service.

`-J, --logjam`                  Checks for LOGJAM vulnerability by checking for DH EXPORT ciphers. It also checks for "common primes" which are preconfigured DH keys. DH keys =< 1024 Bit will be penalized. Also FFDHE groups (TLS 1.2) will be displayed here.

`-A, --beast`                   Checks BEAST vulnerabilities in SSL 3 and TLS 1.0 by testing the usage of CBC ciphers.

`-L, --lucky13`                 Checks for LUCKY13 vulnerability. It checks for the presence of CBC ciphers in TLS versions 1.0 - 1.2.

`-4, --rc4, --appelbaum`        Checks which RC4 stream ciphers are being offered.


### OUTPUT OPTIONS

`-q, --quiet`  Normally testssl.sh displays a banner on stdout with several version information, usage rights and a warning. This option suppresses it. Please note that by choosing this option you acknowledge usage terms and the warning normally appearing in the banner.

`--wide` Except the "each cipher output" all tests displays the single cipher name (scheme see below). This option enables testssl.sh to display also for the following sections the same output as for testing each ciphers: BEAST, FS, RC4. The client simulation has also a wide mode. The difference here is restricted to a column aligned output and a proper headline. The environment variable `WIDE` can be used instead.

`--mapping <openssl|iana|no-openssl|no-iana>`

* `openssl`: use the OpenSSL cipher suite name as the primary name cipher suite name form (default),
* `iana`: use the IANA cipher suite name as the primary name cipher suite name form.
* `no-openssl`: don't display the OpenSSL cipher suite name, display IANA names only.
* `no-iana`: don't display the IANA cipher suite name, display OpenSSL names only.

Please note that in testssl.sh 3.0 you can still use `rfc` instead of `iana` and `no-rfc` instead of `no-iana` but it'll disappear after 3.0.

`--show-each` This is an option for all wide modes only: it displays all ciphers tested -- not only succeeded ones.  `SHOW_EACH_C` is your friend if you prefer to set this via the shell environment.


`--color <0|1|2|3>` determines the use of colors on the screen and in the log file: `2` is the default and makes use of ANSI and termcap escape codes on your terminal. `1` just uses non-colored mark-up like bold, italics, underline, reverse.  `0` means no mark-up at all = no escape codes. This is also what you want when you want a log file without any escape codes. `3` will color ciphers and EC according to an internal (not yet perfect) rating. Setting the environment variable `COLOR` to the value achieves the same result. Please not that OpenBSD and early FreeBSD do not support italics.


`--colorblind`                  Swaps green and blue colors in the output, so that this percentage of folks (up to 8% of males, see https://en.wikipedia.org/wiki/Color_blindness) can distinguish those findings better. `COLORBLIND` is the according variable if you want to set this in the environment.

`--debug <0-6>`                 This gives you additional output on the screen (2-6), only useful for debugging. `DEBUG` is the according environment variable which you can use. There are six levels (0 is the default, thus it has no effect):

1. screen output normal but leaves useful debug output in __/tmp/testssl.XXXXXX/__ . The info about the exact directory is included in the screen output in the end of the run.
2. lists more what's going on, status (high level) and connection errors, a few general debug output
3. even slightly more info: hexdumps + other info
4. display bytes sent via sockets
5. display bytes received via sockets
6. whole 9 yards

`--disable-rating` disables rating.
Rating automatically gets disabled, to not give a wrong or misleading grade, when not all required functions are executed (e.g when checking for a single vulnerabilities).


### FILE OUTPUT OPTIONS

`--log, --logging`      Logs stdout also to `${NODE}-p${port}${YYYYMMDD-HHMM}.log` in current working directory of the shell. Depending on the color output option (see above) the output file will contain color and other markup escape codes, unless you specify `--color 0` too. `cat` and -- if properly configured `less` -- will show the output properly formatted on your terminal. The output shows a banner with the almost the same information as on the screen. In addition it shows the command line of the testssl.sh instance. Please note that the resulting log file is formatted according to the width of your screen while running testssl.sh. You can override the width with the environment variable TERM_WIDTH.

`--logfile <logfile>` or `-oL <logfile>`  Instead of the previous option you may want to use this one if you want to log into a directory or if you rather want to specify the log file name yourself. If `logfile` is a directory the output will put into `logfile/${NODE}-p${port}${YYYYMMDD-HHMM}.log`. If `logfile` is a file it will use that file name, an absolute path is also permitted here. LOGFILE is the variable you need to set if you prefer to work environment variables instead. Please note that the resulting log file is formatted according to the width of your screen while running testssl.sh. You can override the width with the environment variable TERM_WIDTH.

`--json`                Logs additionally to JSON file `${NODE}-p${port}${YYYYMMDD-HHMM}.json` in the current working directory of the shell. The resulting JSON file is opposed to `--json-pretty` flat -- which means each section is self contained and has an identifier for each single check, the hostname/IP address, the port, severity and the finding. For vulnerabilities it may contain a CVE and CWE entry too. The output doesn't contain a banner or a footer.

`--jsonfile <jsonfile>` or `-oj <jsonfile>` Instead of the previous option you may want to use this one if you want to log the JSON out put into a directory or if you rather want to specify the log file name yourself. If `jsonfile` is a directory the output will put into `logfile/${NODE}-p${port}${YYYYMMDD-HHMM}.json. If `jsonfile` is a file it will use that file name, an absolute path is also permitted here.

`--json-pretty` Logs additionally to JSON file `${NODE}-p${port}${YYYYMMDD-HHMM}.json in the current working directory of the shell. The resulting JSON file is opposed to `--json` non-flat -- which means it is structured. The structure contains a header similar to the banner on the screen, including the command line, scan host, openssl binary used, testssl version and epoch of the start time. Then for every test section of testssl.sh it contains a separate JSON object/section. Each finding has a key/value pair identifier with the identifier for each single check, the severity and the finding. For vulnerabilities it may contain a CVE and CWE entry too.  The footer lists the scan time in seconds.

`--jsonfile-pretty <jsonfile>` or `-oJ <jsonfile>`  Similar to the aforementioned `--jsonfile` or `--logfile` it logs the output in pretty JSON format (see `--json-pretty`) into a file or a directory. For further explanation see `--jsonfile` or `--logfile`.

`--csv`  Logs additionally to a CSV file `${NODE}-p${port}${YYYYMMDD-HHMM}.csv` in the current working directory of the shell. The output contains a header with the keys, the values are the same as in the flat JSON format (identifier for each single check, the hostname/IP address, the port, severity, the finding and for vulnerabilities a CVE and CWE number).

`--csvfile <csvfile>` or `-oC <csvfile>` Similar to  the aforementioned `--jsonfile` or `--logfile` it logs the output in CSV format (see `--cvs`) additionally into a file or a directory. For further explanation see `--jsonfile` or `--logfile`.

`--html` Logs additionally to an HTML file `${NODE}-p${port}${YYYYMMDD-HHMM}.html` in the current working directory of the shell. It contains a 1:1 output of the console. In former versions there was a non-native option to use "aha" (Ansi HTML Adapter: github.com/theZiz/aha) like `testssl.sh [options] <URI> | aha >output.html`. This is not necessary anymore.

`--htmlfile <htmlfile>` or `-oH <htmlfile>`         Similar to  the aforementioned `--jsonfile` or `--logfile` it logs the output in HTML format (see `--html`) additionally into a file or a directory. For further explanation see `--jsonfile` or `--logfile`.

`-oA <filename>` / `--outFile <filename>`    Similar to nmap it does a file output to all available file formats: LOG, JSON pretty, CSV, HTML. If the filename supplied is equal `auto` the filename is automatically generated using '${NODE}-p${port}${YYYYMMDD-HHMM}.${EXT}' with the according extension. If a directory is provided all output files will put into `<filename>/${NODE}-p${port}${YYYYMMDD-HHMM}.{log,json,csv,html}`.

`-oa <filename>` / `--outfile <filename>` Does the same as the previous option but uses flat JSON instead.

`--hints`  This option is not in use yet. This option is meant to give hints how to fix a finding or at least a help to improve something. GIVE_HINTS is the environment variable for this.

`--severity <severity>` For CSV and both JSON outputs this will only add findings to the output file if a severity is equal or higher than the `severity` value specified. Allowed are `<LOW|MEDIUM|HIGH|CRITICAL>`. WARN is another level which translates to a client-side scanning error or problem. Thus you will always see them in a file if they occur.

`--append` Normally, if an output file already exists and it has a file size greater zero, testssl.sh will prompt you to manually remove the file exit with an error. `--append` however will append to this file, without a header. The environment variable APPEND does the same. Be careful using this switch/variable. A complementary option which overwrites an existing file doesn't exist per design.

`--outprefix <fname_prefix>` Prepend output filename prefix <fname_prefix> before '${NODE}-'. You can use as well the environment variable FNAME_PREFIX. Using this any output files will be named `<fname_prefix>-${NODE}-p${port}${YYYYMMDD-HHMM}.<format>` when no file name of the respective output option was specified. If you do not like the separator '-' you can as well supply a `<fname_prefix>` ending in '.',  '_' or ','. In this case or if you already supplied '-' no additional '-' will be appended to `<fname_prefix>`.

A few file output options can also be preset via environment variables.

### COLOR RATINGS

Testssl.sh makes use of (the eight) standard terminal colors. The color scheme is as follows:

* light red: a critical finding
* red: a high finding
* brown: a medium finding
* yellow: a low finding
* green (blue if COLORBLIND is set): something which is either in general a good thing or a negative result of a check which otherwise results in a high finding
* light green (light blue if COLORBLIND is set) : something which is either in general a very good thing or a negative result of a check which otherwise results in a critical finding
* no color at places where also a finding can be expected: a finding on an info level
* cyan: currently only used for `--show-each` or an additional hint
* magenta: signals a warning condition, e.g. either a local lack of capabilities on the client side or another problem
* light magenta: a fatal error which either requires strict consent from the user to continue or a condition which leaves no other choice for testssl.sh to quit

What is labeled as "light" above appears as such on the screen but is technically speaking "bold". Besides `--color=3` will color ciphers according to an internal and rough rating.

Markup (without any color) is used in the following manner:

* bold: for the name of the test
* underline + bold: for the headline of each test section
* underline: for a sub-headline
* italics: for strings just reflecting a value read from the server


### TUNING via ENV variables and more options

Except the environment variables mentioned above which can replace command line options here a some which cannot be set otherwise. Variables used for tuning are preset with reasonable values. *There should be no reason to change them* unless you use testssl.sh under special conditions.

* TERM_WIDTH is a variable which overrides the auto-determined terminal width size. Setting this variable normally only makes sense if you log the output to a file using the `--log`, `--logfile` or `-oL` option.
* DEBUG_ALLINONE / SETX: when setting one of those to true testssl.sh falls back to the standard bash behavior, i.e. calling ``bash -x testssl.sh`` it displays the bash debugging output not in an external file `/tmp/testssl-<XX>.log`
* DEBUGTIME: Profiling option. When using bash's debug mode and when this is set to true, it generates a separate text file with epoch times in `/tmp/testssl-<XX>.time`. They need to be concatenated by `paste /tmp/testssl-<XX>.{time,log}`
[comment]: # * FAST_SOCKET
[comment]: # * SHOW_SIGALGO
[comment]: # * FAST
* EXPERIMENTAL=true is an option which is sometimes used in the development process to make testing easier. In released versions this has no effect.
* ALL_CLIENTS=true runs a client simulation with *all* (currently 126) clients when testing HTTP.
* UNBRACKTD_IPV6: needs to be set to true for some old versions of OpenSSL (like from Gentoo) which don't support [bracketed] IPv6 addresses
* NO_ENGINE: if you have problems with garbled output containing the word 'engine' you might want to set this to true. It forces testssl.sh not try to configure openssl's engine or a non existing one from libressl
* HEADER_MAXSLEEP: To wait how long before killing the process to retrieve a service banner / HTTP header
* MAX_WAITSOCK: It instructs testssl.sh to wait until the specified time before declaring a socket connection dead. Don't change this unless you're absolutely sure what you're doing. Value is in seconds.
* CCS_MAX_WAITSOCK Is the similar to above but applies only to the CCS handshakes, for both of the two the two CCS payload. Don't change this unless you're absolutely sure what you're doing. Value is in seconds.
* HEARTBLEED_MAX_WAITSOCK  Is the similar to MAX_WAITSOCK but applies only to the ServerHello after sending the Heartbleed payload. Don't change this unless you're absolutely sure what you're doing. Value is in seconds.
* MEASURE_TIME_FILE For seldom cases when you don't want the scan time to be included in the output you can set this to false.
* STARTTLS_SLEEP is per default set to 10 (seconds). That's the value testssl.sh waits for a string in the STARTTLS handshake before giving up.
* MAX_PARALLEL is the maximum number of tests to run in parallel in parallel mass testing mode. The default value of 20 may be made larger on systems with faster processors.
* MAX_WAIT_TEST is the maximum time (in seconds) to wait for a single test in parallel mass testing mode to complete. The default is 1200.
[comment]: # USLEEP_SND
[comment]: # USLEEP_REC
* HSTS_MIN is preset to 179 (days). If you want warnings sooner or later for HTTP Strict Transport Security you can change this.
* HPKP_MIN is preset to 30 (days). If you want warnings sooner or later for HTTP Public Key Pinning you can change this
* DAYS2WARN1 is the first threshold when you'll be warning of a certificate expiration of a host, preset to 60 (days). For Let's Encrypt this value will be divided internally by 2.
* DAYS2WARN2 is the second threshold when you'll be warning of a certificate expiration of a host, preset to 30 (days). For Let's Encrypt this value will be divided internally by 2.
* TESTSSL_INSTALL_DIR is the derived installation directory of testssl.sh. Relatively to that the `bin` and mandatory `etc` directory will be looked for.
* CA_BUNDLES_PATH: If you have an own set of CA bundles or you want to point testssl.sh to a specific location of a CA bundle, you can use this variable to set the directory which testssl.sh will use. Please note that it overrides completely the builtin path of testssl.sh which means that you will only test against the bundles you point to. Also you might want to use `~/utils/create_ca_hashes.sh` to create the hashes for HPKP.
* MAX_SOCKET_FAIL: A number which tells testssl.sh how often a TCP socket connection may fail before the program gives up and terminates. The default is 2. You can increase it to a higher value if you frequently see a message like *Fatal error: repeated openssl s_client connect problem, doesn't make sense to continue*.
* MAX_OSSL_FAIL: A number which tells testssl.sh how often an OpenSSL s_client connect may fail before the program gives up and terminates. The default is 2. You can increase it to a higher value if you frequently see a message like *Fatal error: repeated TCP connect problems, giving up*.
* MAX_HEADER_FAIL: A number which tells testssl.sh how often a HTTP GET request over OpenSSL may return an empty file before the program gives up and terminates. The default is 3. Also here you can incerase the threshold when you spot messages like *Fatal error: repeated HTTP header connect problems, doesn't make sense to continue*.

### RATING
This program has a near-complete implementation of SSL Labs's '[SSL Server Rating Guide](https://github.com/ssllabs/research/wiki/SSL-Server-Rating-Guide)'.

This is *not* a 100% reimplementation of the [SSL Lab's SSL Server Test](https://www.ssllabs.com/ssltest/analyze.html), but an implementation of the above rating specification, slight discrepancies may occur. Please note that for now we stick to the SSL Labs rating as good as possible. We are not responsible for their rating. Before filing issues please inspect their Rating Guide.

Disclaimer: Having a good grade is **NOT** necessarily equal to having good security! Don't start a competition for the best grade, at least not without monitoring the client handshakes and not without adding a portion of good sense to it.

As of writing, these checks are missing:
* GOLDENDOODLE - should be graded **F** if vulnerable
* Insecure renegotiation - should be graded **F** if vulnerable
* Padding oracle in AES-NI CBC MAC check (CVE-2016-2107) - should be graded **F** if vulnerable
* Sleeping POODLE - should be graded **F** if vulnerable
* Zero Length Padding Oracle (CVE-2019-1559) - should be graded **F** if vulnerable
* Zombie POODLE - should be graded **F** if vulnerable
* All remaining old Symantec PKI certificates are distrusted - should be graded **T**
* Symantec certificates issued before June 2016 are distrusted - should be graded **T**
* ! A reading of DH params - should give correct points in `set_key_str_score()`
* Anonymous key exchange - should give **0** points in `set_key_str_score()`
* Exportable key exchange - should give **40** points in `set_key_str_score()`
* Weak key (Debian OpenSSL Flaw) - should give **0** points in `set_key_str_score()`

#### Implementing new grades caps or -warnings
To implement a new grading cap, simply call the `set_grade_cap()` function, with the grade and a reason:
```bash
set_grade_cap "D" "Vulnerable to documentation"
```
To implement a new grade warning, simply call the `set_grade_warning()` function, with a message:
```bash
set_grade_warning "Documentation is always right"
```
#### Implementing a new check which contains grade caps
When implementing a new check (be it vulnerability or not) that sets grade caps, the `set_rating_state()` has to be updated (i.e. the `$do_mycheck` variable-name has to be added to the loop, and `$nr_enabled` if-statement has to be incremented)

The `set_rating_state()` automatically disables ratinng, if all the required checks are *not* enabled.
This is to prevent giving out a misleading or wrong grade.

#### Implementing a new revision
When a new revision of the rating specification comes around, the following has to be done:
* New grade caps has to be either:
  1. Added to the script wherever relevant, or
  2. Added to the above list of missing checks (if *i.* is not possible)
* New grade warnings has to be added wherever relevant
* The revision output in `run_rating()` function has to updated

## EXAMPLES

      testssl.sh testssl.sh

does a default run on https://testssl.sh (protocols, standard cipher lists, server's cipher preferences, forward secrecy, server defaults, vulnerabilities, client simulation, and rating.

      testssl.sh testssl.net:443

does the same default run as above with the subtle difference that testssl.net has two IPv4 addresses. Both are tested.

      testssl.sh --ip=one --wide https://testssl.net:443

does the same checks as above, with the difference that one IP address is being picked randomly. Displayed is everything where possible in wide format.

      testssl.sh -6 https://testssl.net

As opposed to the first example it also tests the IPv6 part -- supposed you have an IPv6 network and your openssl supports IPv6 (see above).

      testssl.sh -t smtp smtp.gmail.com:25

Checks are done via a STARTTLS handshake on the plain text port 25. It checks every IP on smtp.gmail.com.

        testssl.sh --starttls=imap imap.gmx.net:143

does the same on the plain text IMAP port.

Please note that for plain TLS-encrypted ports you must not specify the protocol option when no STARTTLS handshake is offered: `testssl.sh smtp.gmail.com:465` just checks the encryption on the SMTPS port, `testssl.sh imap.gmx.net:993` on the IMAPS port. Also MongoDB which provides TLS support without STARTTLS can be tested directly.


## RFCs and other standards

* RFC 2246: The TLS Protocol Version 1.0
* RFC 2818: HTTP Over TLS
* RFC 2595: Using TLS with IMAP, POP3 and ACAP
* RFC 3207: SMTP Service Extension for Secure SMTP over Transport Layer Security
* RFC 3501: INTERNET MESSAGE ACCESS PROTOCOL - VERSION 4rev1
* RFC 4346: The Transport Layer Security (TLS) Protocol Version 1.1
* RFC 4366: Transport Layer Security (TLS) Extensions
* RFC 4492: Elliptic Curve Cryptography (ECC) Cipher Suites for Transport Layer Security (TLS)
* RFC 5077: Transport Layer Security (TLS) Session Resumption
* RFC 5246: The Transport Layer Security (TLS) Protocol Version 1.2
* RFC 5280: Internet X.509 Public Key Infrastructure Certificate and Certificate Revocation List (CRL) Profile
* RFC 5321: Simple Mail Transfer Protocol
* RFC 5746: Transport Layer Security (TLS) Renegotiation Indication Extension
* RFC 6066: Transport Layer Security (TLS) Extensions: Extension Definitions
* RFC 6101: The Secure Sockets Layer (SSL) Protocol Version 3.0
* RFC 6120: Extensible Messaging and Presence Protocol (XMPP): Core
* RFC 6125: Domain-Based Application Service Identity [..]
* RFC 6797: HTTP Strict Transport Security (HSTS)
* RFC 6961: The Transport Layer Security (TLS) Multiple Certificate Status Request Extension
* RFC 7469: Public Key Pinning Extension for HTTP (HPKP)
* RFC 7507: TLS Fallback Signaling Cipher Suite Value (SCSV) for Preventing Protocol Downgrade Attacks
* RFC 7627: Transport Layer Security (TLS) Session Hash and Extended Master Secret Extension
* RFC 7633: X.509v3 Transport Layer Security (TLS) Feature Extension
* RFC 7465: Prohibiting RC4 Cipher Suites
* RFC 7685: A Transport Layer Security (TLS) ClientHello Padding Extension
* RFC 7905: ChaCha20-Poly1305 Cipher Suites for Transport Layer Security (TLS)
* RFC 7919: Negotiated Finite Field Diffie-Hellman Ephemeral Parameters for Transport Layer Security
* RFC 8143: Using Transport Layer Security (TLS) with Network News Transfer Protocol (NNTP)
* RFC 8446: The Transport Layer Security (TLS) Protocol Version 1.3
* W3C CSP: Content Security Policy Level 1-3
* TLSWG Draft: The Transport Layer Security (TLS) Protocol Version 1.3


## EXIT STATUS

* 0    testssl.sh finished successfully without errors and without ambiguous results
* 1    testssl.sh has encountered exactly one ambiguous situation or an error during run
* 1+n  same as previous. The errors or ambiguous results are added, also per IP.
* 50-200 reserved for returning a vulnerability scoring for system monitoring or a CI tools
* 242 (ERR_CHILD)       Child received a signal from master
* 244 (ERR_RESOURCE)    Resources testssl.sh needs couldn't be read
* 245 (ERR_CLUELESS)    Weird state, either though user options or testssl.sh
* 246 (ERR_CONNECT)     Connectivity problem
* 247 (ERR_DNSLOOKUP)   Problem with resolving IP addresses or names
* 248 (ERR_OTHERCLIENT) Other client problem
* 249 (ERR_DNSBIN)      Problem with DNS lookup binaries
* 250 (ERR_OSSLBIN)     Problem with OpenSSL binary
* 251 (ERR_NOSUPPORT)   Feature requested is not supported
* 252 (ERR_FNAMEPARSE)  Input file couldn't be parsed
* 253 (ERR_FCREATE)     Output file couldn't be created
* 254 (ERR_CMDLINE)     Cmd line couldn't be parsed
* 255 (ERR_BASH)       Bash version incorrect

## FILES

**etc/\*pem**               are the certificate stores from Apple, Linux, Mozilla Firefox, Windows and Java.

**etc/client-simulation.txt**  contains client simulation data.


**etc/cipher-mapping.txt**  provides a mandatory file with mapping from OpenSSL cipher suites names to the ones from IANA / used in the RFCs.

**etc/tls_data.txt**        provides a mandatory file for ciphers (bash sockets) and key material.


## AUTHORS

Developed by Dirk Wetter, David Cooper and many others, see CREDITS.md .


## COPYRIGHT

Copyright © 2012 Dirk Wetter. License GPLv2: Free Software Foundation, Inc.
       This is free software: you are free to change and redistribute it under the terms of the license. Usage WITHOUT ANY WARRANTY. USE at your OWN RISK!

If you're offering testssl.sh as a public and / or paid service in the internet you need to mention to your audience that you're using this program and
where to get this program from.


## LIMITATION

All native Windows platforms emulating Linux are known to be slow.


## BUGS

Probably. Current known ones and interface for filing new ones: https://testssl.sh/bugs/ .


## SEE ALSO

`ciphers`(1), `openssl`(1), `s_client`(1), `x509`(1), `verify`(1), `ocsp`(1), `crl`(1), `bash`(1) and the websites https://testssl.sh/ and https://github.com/drwetter/testssl.sh/ .
