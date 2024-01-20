
Full contribution, see git log.

* Dirk Wetter (creator, maintainer and main contributor)
  - Everything what's not mentioned below and is included in testssl.sh's git log
    minus what I probably forgot to mention
  (too much other things to do at the moment and to list it would be a tough job)

* David Cooper (main contributor)
  - Major extensions to socket support for all protocols
  - extended parsing of TLS ServerHello messages
  - TLS 1.3 support (final and pre-final) with needed en/decryption
  - add several TLS extensions
  - Detection + output of multiple certificates
  - several cleanups of server certificate related stuff
  - testssl.sh -e/-E: testing with a mixture of openssl + sockets
  - add more ciphers
  - coloring of ciphers
  - extensive CN+SAN <--> hostname check
  - separate check for curves
  - RFC 7919, key shares extension
  - keyUsage extension in certificate
  - experimental "eTLS" detection
  - parallel mass testing!
  - RFC <--> OpenSSL cipher name space switches for the command line
  - better error msg suppression (not fully installed openssl)
  - GREASE support
  - Bleichenbacher / ROBOT vulnerability test
  - several protocol preferences improvements
  - pwnedkeys.com support
  - CT support
  - Extract CA list CertificateRequest message is encountered
  - RFC 8879, certificate compression
  - 128 cipher limit, padding
  - compatibility for LibreSSL and different OpenSSL versions
  - Check for ffdhe groups
  - TLS 1.2 and TLS 1.3 sig algs added
  - Show server supported signature algorithms
  - Show supported certification authorities sent by the server when client auth is requested
  - Provide a better verdict wrt to server order: Now per protocol and ciphers are weighted for each protocol
 -  Provide compatibility to every LibreSSL/OpenSSL versions
  - Lots of fixes and improvements

##### Further credits (in alphabetical order)

* a666
  - Bugfix

* Christoph Badura
  - NetBSD fixes

* Jim Blankendaal
  - maximum certificate lifespan of 398 days
  - ssl renegotiation amount variable
  - custom http request headers

* Frank Breedijk
  - Detection of insecure redirects
  - JSON and CSV output
  - CA pinning
  - Client simulations
  - CI integration, some test cases for it

* Steven Danneman
  - Postgres and MySQL STARTTLS support
  - MongoDB support

* Christian Dresen
   - Dockerfile

* csett86
   - some MacOSX and Java client handshake data

* Mark Felder
  - lots of cleanups
  - Shellcheck static analysis

* Laine Gholson
  - avahi/mDNS support
  - HTTP2/ALPN
  - bugfixes
  - former ARM binary support

* Maciej Grela
  - colorless handling

* Jac2NL
  - initial support for skipping offensive vulnerability tests

* Scott Johnson
  - Bugfix F5

* Hubert Kario
  - helped with avoiding accidental TCP fragmentation

* Brennan Kinney
  - refactored multistage Dockerfiles: performance gain+address bugs/inconsistencies

* Magnus Larsen
  - SSL Labs Rating

* Jacco de Leeuw
  - skip checks which might trigger an IDS ($OFFENSIVE / --ids-friendly)

* Manuel
  - HTTP basic auth

* Markus Manzke
  - Fix for HSTS + subdomains
  - LibreSSL patch

* Jean Marsault
  - client auth: ideas, code snippets

* Thomas Martens
  - adding colorblind option
  - no-rfc mapping

* Peter Mosmans
  - started way better cmd line parsing
  - cleanups, fixes
  - openssl sources support with the "missing" features

* John Newbigin
  - Proxy support (sockets and openssl)

* Oleksandr Nosenko
  - non-flat JSON support (--json-pretty)
  - in file output (CSV, JSON flat, JSON non-flat) support of a minimum severity level

* Jonathan Roach
  - TLS_FALLBACK_SCSV checks

* Jonathon Rossi
  - fix for bash3 (Darwin)
  - and other Darwin fixes

* Дилян Палаузов
  - bug fix for 3des report
  - reported a tricky STARTTLS bug

* Thomas Patzke:
  - Support of supplying timeout value for openssl connect

* Olivier Paroz
  - conversion xxd --> hexdump stuff

* Jeroen Wiert Pluimers
  - Darwin binaries support

* Joao Poupino
  - Minimize false positive detection for Renegotiation checks against Node.js etc.

* Rechi
  - initial MX stuff
  - fixes

* Gonçalo Ribeiro
  - --connect-timeout

* Dmitri S
  - inspiration & help for Darwin port

* Jonas Schäfer
  - XMPP server patch

* Maurizio Siddu
  - added --mTLS feature

* Marcin Szychowski
  - Quick'n'dirty client certificate support

* Viktor Szépe
  - color function maker

* Julien Vehent
  - supplied 1st Darwin binary

* Thomas Ward
  - add initial IDN support

* @typingArtist
  - improved BEAST detection

* @f-s
  - ARM binary support

* @nvsofts (NV)
  - LibreSSL patch for GOST

* @w4ntun
  - fixed DNS via proxy

Probably more I forgot to mention which did give me feedback, bug reports and helped one way or another.


##### Last but not least:

* OpenSSL team for providing openssl.

* Ivan Ristic/Qualys for the liberal license which made it possible to make partly use of the client data

* My family for supporting me doing this work
