
* David Cooper (main contributor)

  - Detection + output of multiple certificates
  - several cleanups of server certificate related stuff
  - extended parsing of TLS ServerHello messages
  - testssl.sh -e/-E: testing with a mixture of openssl + sockets
  - more ciphers
  - finding more TLS extensions via sockets
  - extensive CN+SAN <--> hostname check
  - separate check for curves
  - RFC 7919, key shares extension
  - parallel mass testing!
  - RFC <--> OpenSSL cipher name space switches for the command line
  - numerous fixes
  - better error msg suppression (not fully installed openssl
  - GREASE support
  - Bleichenbacher vulnerability test
  - TLS 1.3 support

##### Credits also to

* Christoph Badura
  - NetBSD fixes

* Frank Breedijk
  - Detection of insecure redirects
  - JSON and CSV output
  - CA pinning
  - Client simulations
  - CI integration, some test cases for it

 * Steven Danneman
   - Postgres and MySQL STARTTLS support
   * MongoDB support

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

* Markus Manzke
  - Fix for HSTS + subdomains
  - LibreSSL patch

* Jean Marsault
  - client auth: ideas, code snipplets

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

* Rechi
  - initial MX stuff
  - fixes

* Dmitri S
  - inspiration & help for Darwin port

* Viktor Szépe
  - color function maker

* Julien Vehent
  - supplied 1st Darwin binary

* @typingArtist
  - improved BEAST detection

* @f-s
  - ARM binary support

* @nvsofts (NV)
  - LibreSSL patch for GOST

Others I forgot to mention which did give me feedback, bug reports and helped one way or another.


##### Last but not least:

* OpenSSL team for providing openssl.

* Ivan Ristic/Qualys for the liberal license which made it possible to use the client data

* My family for supporting me doing this work

