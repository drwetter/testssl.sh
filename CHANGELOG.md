
#### Features implemented in 2.9dev:

* Full support of TLS 1.3, shows also drafts supported
* ROBOT check
* Better TLS extension support
* Better OpenSSL 1.1.1 support
* DNS over Proxy and other proxy improvements
* Decoding of unencrypted BIG IP cookies
* Better JSON output: renamed IDs and findings shorter/better parsable
* JSON output now valid also for non-responding servers
* Testing now per default 370 ciphers
* Further improving the robustness of TLS sockets (sending and parsing)
* Support of supplying timeout value for `openssl connect` -- useful for batch/mass scanning
* File input for serial or parallel mass testing can be also in nmap grep(p)able (-oG) format
* LOGJAM: now checking also for DH  and FFDHE groups (TLS 1.2)
* PFS: Display of elliptical curves supported, DH and FFDHE groups (TLS 1.2 + TLS 1.3)
* Check for session resumption (Ticket, ID)
* TLS Robustness check (GREASE)
* Expect-CT Header Detection
* `--phone-out` does certificate revocation checks via OCSP (LDAP+HTTP) and with CRL
* Fully OpenBSD and LibreSSL support
* Missing SAN warning
* Added support for private CAs
* Man page reviewed
* Better error msg suppression (not fully installed OpenSSL)
* Way better handling of connectivity problems
* Exit codes better: 0 for running without error, 1+n for small errors, >240 for major errors.
* Dockerfile and repo @ docker hub with that file (see above)
* Java Root CA store added
* Better support for XMPP via STARTTLS & faster
* Certificate check for to-name in stream of XMPP
* Support for NNTP via STARTTLS
* More robustness for any STARTTLS protocol (fall back to plaintext while in TLS)
* Fixed TCP fragmentation
* Added `--ids-friendly` switch
* Major update of client simulations with self-collected data

