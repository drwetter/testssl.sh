
## NAME
   testssl.sh -- check encryption of SSL/TLS servers

## SYNOPSIS


`testssl.sh [OPTIONS] <URI>`,   `testssl.sh [OPTIONS] --file <FILE>`

  or

`testssl.sh [BANNER OPTIONS]`

## DESCRIPTION

testssl.sh is a free command line tool which checks a server's service on any port for the support of TLS/SSL ciphers, protocols as well as cryptographic flaws and much more.

The output rates findings by color (screen) or severity (file output) so that you are able to tell whether something is good or bad. The (screen) output has several sections in which classes of checks are being performed. To ease readability on the screen it aligns and indents the output properly.

Only you see the result. You also can use it internally on your LAN. Except DNS lookups it doesn't use any other hosts or even third parties for checks.

It is out of the box pretty much portable: testssl.sh runs under any Unix-like
stack (Linux, *BSD, MacOS X, WSL=bash on Windows, Cygwin and MSYS2). `bash`
(also version 3 is still supported) is a prerequisite as well as standard
utilities like awk, sed, tr and head. This can be of BSD, System 5 or GNU
flavor whereas grep from System V is not yet supported.


## GENERAL

`testssl.sh URI` as the default invocation does the so-called default run which does a number of checks and puts out the results colorized (ANSI and termcap) on the screen. It does every check listed below except `-E` which are (order of appearance):

0) displays a banner (see below), does a DNS lookup also for further IP addresses and does for the returned IP address a reverse lookup. Last but not least a service check is being done.

1) SSL/TLS protocol check

2) standard cipher categories to give you upfront an idea for the ciphers supported

3) checks (perfect) forward secrecy: ciphers and elliptical curves

4) server preferences (server order)

5) server defaults (certificate info, TLS extensions, session information)

6) HTTP header (if HTTP detected or being forced via `--assume-http`)

7) vulnerabilities

8) testing each of 359 ciphers

9) client simulation


## OPTIONS AND PARAMETERS

Options are either short or long options. Any option requiring a value can be called with or without an equal sign '=' e.g. `testssl.sh -t=smtp --wide --openssl=/usr/bin/openssl <URI>` (short option with equal sign) is equivalent to `testssl.sh --starttls smtp --wide --openssl /usr/bin/openssl <URI>` (long option without equal sign). Some command line options can also be preset via ENV variables. `WIDE=true OPENSSL=/usr/bin/openssl testssl.sh --starttls=smtp <URI>` would be the equivalent to the aforementioned examples. Preference has the command line over any environment variables.

`<URI>` or `--file <FILE>` always needs to be the last parameter.

### BANNER OPTIONS

`--help` (or no arg) display command line help

`-b, --banner`        displays testssl.sh banner, including license, usage conditions, version of testssl.sh, detected openssl version, its path to it, # of ciphers of openssl, its build date and the architecture

`-v, --version`     same as before

`-V [pattern] , --local [pattern]`  pretty print all local ciphers supported by openssl version. If a pattern is supplied it performs a match (ignore case) on any of the strings supplied in the wide output, see below. The pattern will be searched in the any of the columns: hexcode, cipher suite name (OpenSSL or RFC), key exchange, encryption, bits. It does a word pattern match for non-numbers, for number just a normal match applies. Numbers here are defined as [0-9,A-F]. This means (attention: catch) that the pattern CBC is matched as non-word, but AES as word.

### INPUT PARAMETERS

`URI`     can be a hostname, an IPv4 or IPv6 address (restriction see below) or an URL. IPv6 addresses need to be in square brackets. For any given parameter port 443 is assumed unless specified by appending a colon and a port number. The only preceding protocol specifier allowed is `https`. You need to be aware that checks for an IP address might not hit the vhost you want. DNS resolution (A/AAAA record) is being performed unless you have an `/etc/hosts` entry for the hostname.

`--file <fname>` is the mass testing option. Per default it implicitly turns on `--warnings batch`.
In its first incarnation the mass testing option reads command lines from `fname`. `fname` consists of command lines of testssl, one line per instance. Comments after `#` are ignored, `EOF` signals the end of fname any subsequent lines will be ignored too. You can also supply additional options which will be inherited to each child, e.g.  When invoking `testssl.sh --wide --log --file <fname>` . Each single line in `fname` is parsed upon execution. If there's a conflicting option and serial mass testing option is being performed the check will be aborted at the time it occurs and depending on the output option potentially leaving you with an output file without footer. In parallel mode the mileage varies.

Alternatively `fname` can be in `nmap`'s grep(p)able output format (`-oG`). Only open ports will be considered. Multiple ports per line are allowed. The ports can be different and will be tested by testssl.sh according to common practice in the internet, .i.e. if nmap shows in its output an open port 25, automatically `-t smtp` will be added before the URI whereas port 465 will be treated as a plain TLS/SSL port, not requiring an STARTTLS SMTP handshake upfront. This is done by an internal table which correlates nmap's open port to the STARTTLS/plain text decision from testssl.sh.

The nmap output always returns IP addresses and -- only if there's a PTR DNS record available -- a hostname. As it is not checked by nmap whether the hostname matches the IP (A or AAAA record), testssl.sh does this for you. If the A record of the hostname matches the IP address, the hostname is used and not the IP address. Watch out as stated above checks against an IP address might not hit the vhost you maybe were aiming at.

A typical internal conversion from nmap's grep(p)able format could look like:

```
10.10.12.16:443
10.10.12.16:1443
-t smtp host.example.com:25
host.example.com:443
host.example.com:631
-t ftp 10.10.12.11:21
10.10.12.11:8443
```
Please note that the content of `fname` has to be in Unix format. DOS carriage returns won't be accepted. Instead of the command line switch the environment variable FNAME will be honored too.


`--mode <serial|parallel>`. Mass testing to be done serial (default) or parallel (`--parallel` is shortcut for the latter, `--serial` is the opposite option). Per default mass testing is being run in serial mode, i.e. one line after the other is processed and invoked. The variable `MASS_TESTING_MODE` can be defined to be either equal `serial` or `parallel`.


### SPECIAL INVOCATIONS

`-t <protocol>, --starttls <protocol>`    does a default run against a STARTTLS enabled `protocol`. `protocol` must be one of `ftp`, `smtp`, `pop3`, `imap`, `xmpp`, `telnet`, `ldap`, `postgres`, `mysql`. For the latter four you need e.g. the supplied openssl. MongoDB doesn't need a STARTTLS handshake.

`--xmpphost <jabber_domain>`   is an additional option for STARTTLS enabled XMPP: It expects as a parameter the jabber domain. This is only needed if the domain is different from the URI supplied.

`--mx <domain|host>`     tests all MX records (STARTTLS, port 25) from high to low priority one after the other.

`--ip <ip>`              tests either the supplied IPv4 or IPv6 address instead of resolving host(s) in `<URI>`. IPv6 addresses needs to be in square brackets.
                   `--ip=one` means: just test the first DNS returns (useful for multiple IPs). It's also useful if you want to resolve the supplied hostname to  a different IP, similar as if you would edit `/etc/hosts` or `/c/Windows/System32/drivers/etc/hosts`. `--ip=proxy` tries a DNS resolution via proxy.

`--proxy <host>:<port>`    does the whole check via the specified HTTP proxy. `--proxy=auto` inherits the proxy setting from the environment. Proxying via IPv6 addresses is not possible. The hostname supplied will only be resolved to the first A record. Authentication to the proxy is not supported. In addition if you want lookups via proxy you can specify `DNS_VIA_PROXY=true`.

`-6`       does (also) IPv6 checks. Please note if a supplied URI resolves (also) to an IPv6 address that testssl.sh doesn't do checks on an IPv6 address automatically. This is because testssl.sh does no connectivity checks for IPv6. It also cannot determine reliably whether the OpenSSL binary you are using has IPv6 support. `-6` assumes both is the case. If both conditions are met and you want in general enable IPv6 tests you might as well add `HAS_IPv6` to your shell environment.

`--ssl-native`               instead of using a mixture of bash sockets and openssl s_client connects testssl.sh uses the latter only. This is at the moment faster but provides less accurate results, especially in the client
 simulation and if the openssl binary lacks cipher support. For TLS protocol checks and standard cipher lists and certain other checks you will see a warning if testssl.sh internally can tell if one check cannot be performed or will give you inaccurate results. For e.g. single cipher checks (`--each-cipher` and `--cipher-per-proto`) you might end up getting false negatives without a warning.

`--openssl <path_to_openssl>`           testssl.sh tries very hard to find automagically the binary supplied (where the tree of testssl.sh resides, from the directory where testssl.sh has been started from, etc.). If all that doesn't work it falls back to openssl supplied from the OS (`$PATH`). With this option you can point testssl.sh to your binary of choice and override any internal magic to find the openssl binary. (environment preset via `OPENSSL=<path_to_openssl>`)

`--bugs`                    does some workarounds for buggy servers like padding for old F5 devices. The option is passed as `-bug` to openssl when needed, see `s_client(1)`. For the socket part testssl.sh tries its best also without that option to cope with broken server implementations (environment preset via `BUGS="-bugs"`)

`--assuming-http`           testssl.sh does upfront an application protocol detection. In cases where for some reasons the usage of HTTP cannot be automatically detected you may want to use this option. It tells testssl.sh not to skip HTTP specific tests and to run the client simulation with browsers. Sometimes also the severity depends on the application protocol, e.g. SHA1 signed certificates, the lack of any SAN matches and some vulnerabilities will be punished harder when checking a web server as opposed to a mail server.

`-n, --nodns <min|none>` tells testssl.sh which DNS lookups should be performed. `min` uses only forward DNS resolution (A and AAAA record or MX record) and skips CAA lookups and PTR records from the IP address back to a DNS name.  `none` performs no
DNS lookups at all. For the latter you either have to supply the IP address as a target, to use `--ip` or have the IP address
in /etc/hosts.  The use of the switch is only useful if you either can't or are not willing to perform DNS lookups. The latter can apply e.g. to some pentestsi. In general this option could e.g. help you to avoid timeouts by DNS lookups. `NODNS` is the enviroment variable for this.

`--sneaky` as a friendly feature for the server side testssl.sh uses a HTTP user agent `TLS tester from ${URL}`. With this option your traces are less verbose and a Firefox user agent is being used. Be aware that it doesn't hide your activities. That is just not possible (environment preset via `SNEAKY=true`).

`--phone-out`    instructs testssl.sh to query external -- in a sense of the current run -- URLs or URIs. This is needed for checking revoked certificates via CRL and OCSP. By using this switch you acknowledge that the check might could have privacy issues, a download of several megabytes (CRL file) may happen and there may be network connectivity problems while contacting CA which testssl.sh doesn't handle. PHONE_OUT is the environment variable for this which needs to be set to true if you want this.


### SINGLE CHECK OPTIONS

Any single check switch supplied as an argument prevents testssl.sh from doing a default run. It just takes this and if supplied other options and runs them - in the order they would also appear in the default run.

`-e, --each-cipher` checks each of the local 364 ciphers (openssl + sockets) remotely on the server and reports back the result in wide mode. If you want to display each cipher tested you need to add `--show-each`. Per default it lists the following parameter: `hexcode`, `OpenSSL cipher suite name`,i `key exchange`, `encryption bits`, `RFC cipher suite name (RFC)`. Please note the `--mapping` parameter changes what cipher suite names you will see here and at which position. Also please note that the __bit__ length for the encryption is shown and not the __security__ length. For 3DES due to the Meet-in-the-Middle problem the bit size of 168 bits is equivalent to the security size of 112 bits. The output is sorted by security strength, it lists the encryption bits though.


`-E, --cipher-per-proto`  similar to `-e, --each-cipher` it checks each of the possible ciphers, here: per protocol. If you want to display each cipher tested you need to add `--show-each`. The output is sorted by security strength, it lists the encryption bits though.

`-s, --std, --standard`   tests certain lists of cipher suites by strength. Those lists are (`openssl ciphers $LIST`, $LIST from below:)

* `NULL encryption ciphers`: 'NULL:eNULL'
* `Anonymous NULL ciphers`: 'aNULL:ADH'
* `Export ciphers` (w/o the preceding ones): 'EXPORT:!ADH:!NULL' * `LOW` (64 Bit + DES ciphers, without EXPORT ciphers): 'LOW:DES:!ADH:!EXP:!NULL'
* `Weak 128 Bit ciphers`: 'MEDIUM:!aNULL:!AES:!CAMELLIA:!ARIA:!CHACHA20:!3DES'
* `3DES Ciphers`: '3DES:!aNULL:!ADH'
* `High grade Ciphers`: 'HIGH:!NULL:!aNULL:!DES:!3DES:!AESGCM:!CHACHA20:!AESGCM:!CamelliaGCM:!AESCCM8:!AESCCM'
* `Strong grade Ciphers` (AEAD): 'AESGCM:CHACHA20:AESGCM:CamelliaGCM:AESCCM8:AESCCM'


`-p, --protocols`               checks TLS/SSL protocols SSLv2, SSLv3, TLS 1.0 - TLS 1.3 and for HTTP: SPDY (NPN) and ALPN, a.k.a. HTTP/2. For TLS 1.3 several drafts (18-23) and TLS 1.3 final are supported.

`-P, --preference`              displays the servers preferences: cipher order, with used openssl client: negotiated protocol and cipher. If there's a cipher order enforced by the server it displays it for each protocol (openssl+sockets). If there's not, it displays instead which ciphers from the server were picked with each protocol (by using openssl only)

`-S, --server_defaults`         displays information from the server hello(s):
available TLS extensions, TLS ticket + session information/capabilities, session resumption
capabilities, time skew relative to localhost (most server implementations
return random values) and several certificate info: certificate signature algorithm,
certificate key size, X509v3 key usage and extended key usage, certificate
fingerprints and serial, revocation info (CRL, OCSP, OCSP
stapling/must staple), certificate transparency info (if provided by
server).  When `--phone-out` supplied it checks against the certificate issuer
whether the host certificate has been revoked (only URI scheme supported
currently is HTTP).  `-S, --server_defaults` also displays certificate start and expiration time in GMT.
In addition testssl.sh checks the trust (CN, SAN, Chain of trust). For the trust chain
check there are 4 certificate stores provided (see section `FILES` below). If
the trust is confirmed or not confirmed and the same in all four certificate
stores there will be only one line of output with the appropriate result. If
there are different results, each store is listed and for the one where there's
no trust there's an indication what the failure is. Additional certificate
stores for e.g. an intranet CA an be put into __etc/__ with the extension
__pem__. In that case there will be a complaint about a missing trust with the
other stores, in the opposite case -- i.e. if trust will be checked against
hosts having a certificate issued by a different CA -- there will be a
complaint by a missing trust in this additional store.  If the server provides
no matching record in Subject Alternative Name (SAN) but in Common Name (CN),
it will be clearly indicated as this is deprecated. Possible fingerprinting is
possible by the results in TLS clock skew: Only a few servers nowadays still
have and TLS/SSL implementation which returns the local clock `gmt_unix_time`
(e.g. IIS, openssl < 1.0.1f). In addition to the HTTP date you could derive
that there are different hosts where your TLS and your HTTP request ended -- if
the time deltas differ significantly. Also multiple server certificates are
being checked for as well as the certificate reply to a non-SNI (Server Name
Indication) client hello to the IP address.
Also the Certification Authority Authorization (CAA) record is displayed.

`-x <pattern>, --single-cipher <pattern>` tests matched `pattern` of ciphers against a server. Patterns are similar to `-V pattern , --local pattern`

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
* Security headers (X-Frame-Options, X-XSS-Protection, ..., CSP headers)


### VULNERABILITIES

`-U, --vulnerable`              Just tests all (following) vulnerabilities. The environment variable `VULN_THRESHLD` determines after which value a separate headline for each vulnerability is being displayed. Default is `1` which means if you check for two vulnerabilities, only the general headline for vulnerabilities section is displayed -- in addition to the vulnerability and the result. Otherwise each vulnerability or vulnerability section gets its own headline in addition to the output of the name of the vulnerabilty and test result. A vulnerability section is comprised of more than one check, e.g. the renegotiation vulnerability check has two checks, so has Logjam.

`-H, --heartbleed`              Checks for Heartbleed, a memory leakage in openssl. Unless the server side doesn't support the heartbeat extension it is likely that this check runs into a timeout. The seconds to wait for a reply can be adjusted with `HEARTBLEED_MAX_WAITSOCK`. 8 is the default (unit: seconds)

`-I, --ccs, --ccs-injection`    Checks for CCS injection which is an openssl vulnerability. Sometimes also here the check needs to wait for a reply. The predefined timeout of 5 seconds can be changed with the environment variable `CCS_MAX_WAITSOCK`.

`-T, --ticketbleed`             Checks for Ticketbleed memory leakage in BigIP loadbalancers.

`-BB, --robot`          Checks for vulnerability to Bleichenbacher attacks.

`-R, --renegotiation`           Tests renegotiation vulnerabilities. Currently there's a check for "Secure Renegotiation" and for "Secure Client-Initiated Renegotiation". Please be aware that vulnerable servers to the latter can likely be DoSed very easily (HTTP). A check for "Insecure Client-Initiated Renegotiation" is not yet implemented.

`-C, --compression, --crime`    Checks for CRIME ("Compression Ratio Info-leak Made Easy") vulnerability in TLS. CRIME in SPDY is not yet being checked for.

`-B, --breach`                  Checks for BREACH ("Browser Reconnaissance and Exfiltration via Adaptive Compression of Hypertext") vulnerability. As for this vulnerability HTTP level compression is a prerequisite it'll be not tested if HTTP cannot be detected or the detection is not enforced via ``--assume-http`. Please note that only the URL supplied (normally "/" ) is being tested.

`-O, --poodle`                  Tests for SSL POODLE ("Padding Oracle On Downgraded Legacy Encryption") vulnerability. It basically checks for the existence of CBC ciphers in SSLv3.

`-Z, --tls-fallback`            Checks TLS_FALLBACK_SCSV mitigation. TLS_FALLBACK_SCSV is basically a ciphersuite appended to the Client Hello trying to prevent protocol downgrade attacks by a Man in the Middle.

`-W, --sweet32`                 Checks for vulnerability to SWEET32 by testing 64 bit block ciphers (3DES, RC2 and IDEA).

`-A, --beast`                   Checks BEAST vulnerabilities in SSL 3 and TLS 1.0 by testing the usage of CBC ciphers.

`-L, --lucky13`                 Checks for LUCKY13 vulnerability. It checks for the presence of CBC ciphers in all TLS versions.

`-F, --freak`                   Checks for FREAK vulnerability by testing for EXPORT RSA ciphers

`-J, --logjam`                  Checks for LOGJAM vulnerability by checking for DH EXPORT ciphers. It also checks for "common primes" which are preconfigured DH keys. DH keys =< 1024 Bit will be penalized

`-D, --drown`                   Checks for DROWN vulnerability by checking whether the SSL 2 protocol is available at the target. Please note that if you use the same RSA certificate elsewhere you might be vulnerable too. testssl.sh doesn't check for this but provides a helpful link @ censys.io which provides this service.

`-f, --pfs, --fs,--nsa `        Checks robust (perfect) forward secrecy settings. "Robust" means -- as the headline says -- that ciphers having intrinsic severe weaknesses like "Null Authentication/Encryption, 3DES, RC4" won't be considered here. There shouldn't be the wrong impression that a secure key exchange has been taking place and everything is fine when in reality the encryption sucks. Also this section lists the available elliptical curves.

`-4, --rc4, --appelbaum`        Checks which RC4 stream ciphers are being offered.

`-g, --grease`                  Checks several server implementation bugs like GREASE and size limitations,see https://www.ietf.org/archive/id/draft-ietf-tls-grease-00.txt


### OUTPUT OPTIONS

`--warnings <batch|off>`     The warnings parameter determines how testssl.sh will deal with situations where user input normally will be necessary. There are a couple of options here.  `batch` doesn't wait for a confirming keypress. This is automatically being chosen for mass testing (`--file`). `-false` just skips the warning AND the confirmation. Please note that there are conflicts where testssl.sh will still ask for confirmation which are the ones which otherwise would have a drastic impact on the results. Almost any other decision will be made as a best guess by testssl.sh.
The same can be achieved by setting the environment variable `WARNINGS`.

`--openssl-timeout <seconds>` This is especially useful for all connects using openssl and practically useful for mass testing. It avoids the openssl connect to hang for ~2 minutes. The expected parameter `seconds` instructs testssl.sh to wait before the openssl connect will be terminated. The option is only available if your OS has a timeout binary installed. As there are different implementations of `timeout`: It automatically calls the binary with the right parameters.

`-q, --quiet`                      Normally testssl.sh displays a banner on stdout with several version information, usage rights and a warning. This option suppresses it. Please note that by choosing this option you acknowledge usage terms and the warning normally appearing in the banner.

`--wide`                        Except the "each cipher output" all tests displays the single cipher name (scheme see below). This option enables testssl.sh to display also for the following sections the same output as for testing each ciphers: BEAST, PFS, RC4. The client simulation has also a wide mode. The difference here is restricted to a column aligned output and a proper headline. The environment variable `WIDE` can be used instead.


`--mapping <openssl|rfc|no-openssl|no-rfc>`

* `openssl`: use the OpenSSL cipher suite name as the primary name cipher suite name form (default),
* `rfc`: use the RFC cipher suite name as the primary name cipher suite name form.
* `no-openssl`: don't display the OpenSSL cipher suite name, display RFC names only.
* `no-rfc`: don't display the RFC cipher suite name, display OpenSSL names only.


`--show-each`                   This is an option for all wide modes only: it displays all ciphers tested -- not only succeeded ones.  `SHOW_EACH_C` is your friend if you prefer to set this via the shell environment.


`--color <0|1|2|3>`               It determines the use of colors on the screen: `2` is the default and makes use of ANSI and termcap escape codes on your terminal. `1` just uses non-colored mark-up like bold, italics, underline, reverse.  `0` means no mark-up at all = no escape codes. `3` will color ciphers and EC according to an internal (not yet perfect) rating. Setting the environment variable `COLOR` achieves the same result.


`--colorblind`                  Swaps green and blue colors in the output, so that this percentage of folks (up to 8% of males, see https://en.wikipedia.org/wiki/Color_blindness) can distinguish those findings better. `COLORBLIND` is the according variable if you want to set this in the environment.

`--debug <0-6>`                 This gives you additional output on the screen (2-6), only useful for debugging. `DEBUG` is the according environment variable which you can use. There are six levels (0 is the default, thus it has no effect):

1. screen output normal but leaves useful debug output in __/tmp/testssl.XXXXXX/__ . The info about the exact directory is included in the screen output.
2. list more what's going on, status (high level) and connection errors, a few general debug output
3. even slightly more info: hexdumps + other info
4. display bytes sent via sockets
5. display bytes received via sockets
6. whole 9 yards



### FILE OUTPUT OPTIONS

`--log, --logging`      Logs stdout also to `${NODE}-p${port}${YYYYMMDD-HHMM}.log` in current working directory of the shell. Depending on the color output option (see above) the output file will contain color and other markup escape codes. `cat` and -- if properly configured `less` -- will show the output properly formatted on your terminal. The output shows a banner with the almost the same information as on the screen. In addition it shows the command line of the testssl.sh instance. Please note that the resulting log file is formatted according to the width of your screen while running testssl.sh.

`--logfile <logfile>` or `-oL <logfile>`  Instead of the previous option you may want to use this one if you want to log into a directory or if you rather want to specify the log file name yourself. If `logfile` is a directory the output will put into `logfile/${NODE}-p${port}${YYYYMMDD-HHMM}.log`. If `logfile`is a file it will use that file name, an absolute path is also permitted here. LOGFILE is the variable you need to set if you prefer to work environment variables instead. Please note that the resulting log file is formatted according to the width of your screen while running testssl.sh. You can override the width with the environment variable TERM_WIDTH.

`--json`                Logs additionally to JSON file `${NODE}-p${port}${YYYYMMDD-HHMM}.json` in the current working directory of the shell. The resulting JSON file is opposed to `--json-pretty` flat -- which means each section is self contained and has an identifier for each single check, the hostname/IP address, the port, severity and the finding. For vulnerabilities it may contain a cve and cwe entry too. The output doesn't contain a banner or a footer.

`--jsonfile <jsonfile>` or `-oj <jsonfile>` Instead of the previous option you may want to use this one if you want to log the JSON out put into a directory or if you rather want to specify the log file name yourself. If `jsonfile` is a directory the output will put into `logfile/${NODE}-p${port}${YYYYMMDD-HHMM}.json. If `jsonfile` is a file it will use that file name, an absolute path is also permitted here. JSONFILE is the variable you need to set if you prefer to work environment variables instead.

`--json-pretty`         Logs additionally to JSON file `${NODE}-p${port}${YYYYMMDD-HHMM}.json in the current working directory of the shell. The resulting JSON file is opposed to `--json` non-flat -- which means it is structured. The structure contains a header similar to the banner on the screen (with the epoch of the start time) and then for every test section of testssl.sh it contains a separate JSON object/section. Each finding has a key/value pair identifier with the identifier for each single check, the severity and the finding. For vulnerabilities it may contain a cve and cwe entry too.  The footer lists the scan time in seconds.

`--jsonfile-pretty <jsonfile>` or `-oJ <jsonfile>`  Similar to the aforementioned `--jsonfile` or `--logfile` it logs the output in pretty JSON format (see `--json-pretty`) additionally into a file or a directory. For further explanation see `--jsonfile` or ``--logfile`. `JSONFILE` is the variable you need to set if you prefer to work environment with variables instead.

`--csv`                         Logs additionally to a CSV file `${NODE}-p${port}${YYYYMMDD-HHMM}.csv` in the current working directory of the shell. The output contains a header with the keys, the values are the same as in the flat JSON format (identifier for each single check, the hostname/IP address, the port, severity,the finding and for vulnerabilities a cve and cwe too).

`--csvfile <csvfile>` or `-oC <csvfile>`          Similar to  the aforementioned `--jsonfile` or `--logfile` it logs the output in CSV format (see `--cvs`) additionally into a file or a directory. For further explanation see `--jsonfile` or ``--logfile`. `CSVFILE` is the variable you need to set if you prefer to work environment with variables instead.

--html                          Logs additionally to an HTML file `${NODE}-p${port}${YYYYMMDD-HHMM}.html` in the current working directory of the shell. It contains a 1:1 output of the console. In former versions there was a non-native option to use "aha" (Ansi HTML Adapter: github.com/theZiz/aha) like `testssl.sh [options] <URI> | aha >output.html`. This is not necessary anymore.

`--htmlfile <htmlfile>` or `-oH <htmlfile>`         Similar to  the aforementioned `--jsonfile` or `--logfile` it logs the output in HTML format (see `--html`) additionally into a file or a directory. For further explanation see `--jsonfile` or `--logfile`. `HTMLFILE` is the variable you need to set if you prefer to work with environment variables instead.

`-oA <filename>` / `--outFile <filename>`    Similar to nmap it does a file output to all available file formats: LOG,JSON pretty,CSV,HTML. If the filename supplied is equal `auto` the filename is automatically generated using '\${NODE}-p${port}\${YYYYMMDD-HHMM}.\${EXT}' with the according extension.

`-oa <filename>` / `--outfile <filename>`     Does the same as the previous option but uses flat JSON instead.

`--hints`                       This option is not in use yet. This option is meant to give hints how to fix a finding or at least a help to improve something. GIVE_HINTS is the environment variable for this.

`--severity <severity>`         For JSON and CSV output this will only add findings to the output file if a severity is equal or higher than the `severity` value specified. Allowed are `<LOW|MEDIUM|HIGH|CRITICAL>`. WARN is another severity level which translates to a client-side scanning error or problem. Implicitly you will see all WARN severities in a file.

`--append`                      Normally, if an output file already exists and it has a file size greater zero, testssl.sh will prompt you to manually remove the file exit with an error. `--append` however will append to this file, without a header. The environment variable APPEND does the same. Be careful using this switch/variable. A complementary option which overwrites an existing file doesn't exist per design.

`--outprefix <fname_prefix>`   Prepend output filename prefix <fname_prefix> before '\${NODE}.'. You can use as well the environment variable FNAME_PREFIX. Using this any output files will be named `<fname_prefix>.${NODE}-p${port}${YYYYMMDD-HHMM}.<format>` when no file name of the respective output option was specified.

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
* cyan: currently used for `--show-each` or an additional hint
* magenta: signals a warning condition, e.g. either a local lack of capabilities on the client side or another problem
* light magenta: a fatal error which either requires strict consent from the user to continue or a condition which leaves no other choice for testssl.sh to quit

Besides `--color=3` will color ciphers and EC according to an internal and rough rating.

What is labeled as "light" above appears as such on the screen but is technically speaking "bold".  Markup (without any color) is used in the following manner:

* bold: for the name of the test
* underline + bold: for the headline of each test section
* underline: for a sub-headline
* italics: for strings just reflecting a value read from the server


### TUNING via ENV variables and more options

Except the environment variables mentioned above which replace command line options here a some which cannot be set otherwise. Variables used for tuning are preset with reasonable values. There should be no reason to change them unless you use testssl.sh under special conditions.

* TERM_WIDTH is a variable which overrides the autodetermined terminal width size. Setting this variable normally only makes sense if you log the output to a file using the `--log`, `--logfile` or `-oL` option.
[comment]: # * DEBUGTIME
[comment]: # * DEBUG_ALLINONE
[comment]: # * FAST_SOCKET
[comment]: # * SHOW_SIGALGO
[comment]: # * FAST
[comment]: # * EXPERIMENTAL
* ALL_CLIENTS runs a client simulation with all (currently) 117 clients
* UNBRACKTD_IPV6: needs to be set to true for some versions of OpenSSL (like from Gentoo) which don't support [bracketed] IPv6 addresses
* NO_ENGINE: if you have problems with garbled output containing the word 'engine' you might want to set this to true. It forces testssl.sh not try to configure openssl's engine or a non existing one from libressl
* HEADER_MAXSLEEP: To wait how long before killing the process to retrieve a service banner / HTTP header
* MAX_WAITSOCK:    It instructs testssl.sh to wait until the specified time before declaring a socket connection dead. Don't change this unless you're absolutely sure what you're doing. Value is in seconds.
* CCS_MAX_WAITSOCK Is the similar to above but applies only to the CCS handshakes, for both of the two the two CCS payload. Don't change this unless you're absolutely sure what you're doing. Value is in seconds.
* HEARTBLEED_MAX_WAITSOCK  Is the similar to MAX_WAITSOCK but applies only to the ServerHello after sending the Heartbleed payload. Don't change this unless you're absolutely sure what you're doing. Value is in seconds.
* MEASURE_TIME_FILE For seldom cases when you don't want the scan time to be included in the output you can set this to false.

[comment]: # STARTTLS_SLEEP
[comment]: # FAST_STARTTLS
* MAX_PARALLEL  is the maximum number of tests to run in parallel in parallel mass testing mode. The default value of 20 may be made larger on systems with faster processors.
* MAX_WAIT_TEST is the maximum time (in seconds) to wait for a single test in parallel mass testing mode to complete. The default is 1200.
[comment]: # USLEEP_SND
[comment]: # USLEEP_REC
[comment]: # HSTS_MIN
[comment]: # HPKP_MIN
[comment]: # DAYS2WARN1
[comment]: # DAYS2WARN2
[comment]: # TESTSSL_INSTALL_DIR
* CA_BUNDLES_PATH: If you have an own set of CA bundles or you want to point testssl.sh to a specific location of a CA bundle, you can use this variable to set the directory which testssl.sh will
use. Please note that it overrides completely the builtin path of testssl.sh which means that you will only test against the bundles you point to. Also you might want to use ~/utils/create_ca_hashes.sh
to create the hashes for HPKP.
* MAX_SOCKET_FAIL: A number which tells testssl.sh how often a TCP socket connection may fail before the program gives up and terminates. The default is 2.
* MAX_OSSL_FAIL: A number which tells testssl.sh how often an OpenSSL s_client connect may fail before the program gives up and terminates. The default is 2.
* MAX_HEADER_FAIL: A number which tells testssl.sh how often a HTTP GET request over OpenSSL may return an empty file before the program gives up and terminates. The default is 3.


[comment]: # CAPATH


## EXAMPLES

      testssl.sh testssl.sh

does a default run on https://testssl.sh (protocols, standard cipher lists, PFS, server preferences, server defaults, vulnerabilities, testing all (359 possible) ciphers, client simulation.

      testssl.sh testssl.net:443

does the same default run as above with the subtle difference that testssl.net has two IPv4 addresses. Both are tested.

      testssl.sh --ip=one --wide https://testssl.net:443

does the same checks as above, with the difference that one IP address is being picked randomly. Displayed is everything where possible in wide format.

      testssl.sh -t smtp smtp.gmail.com:25

implicitly does a STARTTLS handshake on the plain text port, then check the IPs @ smtp.gmail.com.

        testssl.sh --starttls=imap imap.gmx.net:143

does the same on the plain text IMAP port. Please note that for plain TLS-encrypted ports you must not specify the protocol option: `testssl.sh smtp.gmail.com:465` tests the encryption on the SMTPS port, `testssl.sh imap.gmx.net:993` on the IMAPS port. Also MongoDB which provides TLS support can be tested.


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
* W3C CSP: Content Security Policy Level 1-3
* TLSWG Draft: The Transport Layer Security (TLS) Protocol Version 1.3


## EXIT STATUS

* 0    testssl.sh finished successfully without errors and without unambiguous results
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
* 255 (ERR_BASH )       Bash version incorrect

## FILES

**etc/\*pem**             Here are the certificate stores from Apple, Linux, Mozilla Firefox, Windows.

**etc/mapping-rfc.txt**   Provides a mandatory file with mapping from OpenSSL cipher suites names to the ones from IANA / used in the RFCs.

**etc/tls_data.txt**      Provides a mandatory file for ciphers (bash sockets) and key material.


## AUTHORS

Developed by Dirk Wetter, David Cooper and many others, see https://github.com/drwetter/testssl.sh/blob/master/CREDITS.md


## COPYRIGHT

Copyright © 2012 Dirk Wetter. License GPLv2: Free Software Foundation, Inc.
       This is free software: you are free to change and redistribute it under the terms of the license. Usage WITHOUT ANY WARRANTY. USE at your OWN RISK!

## LIMITATION

All native Windows platforms emulating Linux are known to be slow.


## BUGS

Probably. Current known ones and interface for filing new ones: https://testssl.sh/bugs/ .


## SEE ALSO

`ciphers`(1), `openssl`(1), `s_client`(1), `x509`(1), `verify`(1), `ocsp`(1), `crl`(1), `bash`(1) and the websites __https://testssl.sh/__ and __https://github.com/drwetter/testssl.sh/__ .

