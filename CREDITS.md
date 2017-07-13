
##### Credits to

* Peter Mosmans
  - started way better cmd line parsing
  - cleanups, fixes
  - openssl sources support with the "missing" features

* John Newbigin
  - Proxy support (sockets and openssl)

* Jonathan Roach
  - TLS_FALLBACK_SCSV checks

* Mark Felder
  - lots of cleanups
  - Shellcheck static analysis

* Frank Breedijk
  - Detection of insecure redirects
  - JSON and CSV output
  - CA pinning
  - Client simulations
  - CI integration, some test cases for it

* David Cooper
  - Detection + output of multiple certificates
  - several cleanups of server certificate related stuff
  - extended parsing of TLS ServerHello messages
  - testssl.sh -e/-E: testing with a mixture of openssl + sockets
  - finding more TLS extensions via sockets
  - extensive CN+SAN <--> hostname check
  - seperate check for curves
  - RFC 7919, key shares extension
  - parallel mass testing!
  - RFC <--> OpenSSL cipher name space switches for the command line 
  - numerous fixes
 
 * Steven Danneman
   - Postgres and MySQL STARTTLS support

* Thomas Patzke:
  - Support of supplying timeout value for openssl connect

* Oleksandr Nosenko
  - non-flat JSON support (--json-pretty)
  - in file output (CSV, JSON flat, JSON non-flat) support of a minimum severity level

* Christoph Badura
  - NetBSD fixes

* Jean Marsault
  - client auth: ideas, code snipplets

* Maciej Grela
  - colorless handling

* Olivier Paroz
  - conversion xxd --> hexdump stuff

* @typingArtist
  - improved BEAST detection

* @f-s
  - ARM binary support

* Jeroen Wiert Pluimers
  - Darwin binaries support

* Julien Vehent
  - supplied 1st Darwin binary

* Rechi
  - initial MX stuff
  - fixes

* Laine Gholson
  - avahi/mDNS support
  - HTTP2/ALPN
  - bugfixes
  - former ARM binary support

* Дилян Палаузов
  - bug fix for 3des report
  - reported a tricky STARTTLS bug

* Viktor Szépe
  - color function maker

* Thomas Martens
  - adding colorblind option
  - no-rfc mapping

* Jonathon Rossi
  - fix for bash3 (Darwin)
  - and other Darwin fixes

* @nvsofts (NV)
  - LibreSSL patch for GOST

* Markus Manzke
  - Fix for HSTS + subdomains
  - LibreSSL patch

* Dmitri S
  - inspiration & help for Darwin port


Others I forgot to mention which did give me feedback, bug reports and helped one way or another.


##### Last but not least:

* OpenSSL team for providing openssl.

* Ivan Ristic/Qualys for the liberal license which made it possible to use the client data

* My family for supporting me doing this work

