
## Intro

[![Gitter](https://badges.gitter.im/Join%20Chat.svg)](https://gitter.im/drwetter/testssl.sh?utm_source=badge&utm_medium=badge&utm_campaign=pr-badge&utm_content=badge)

`testssl.sh` is a free command line tool which checks a server's service on any port for the support of TLS/SSL ciphers, protocols as well as some cryptographic flaws. It's designed to provide clear output in any case.

It is working on every Linux distribution out of the box with some limitations of disabled features from the openssl client -- some workarounds are done with bash-socket-based checks. It also works on BSD and other Unices out of the box, supposed they have `/bin/bash` and standard tools like sed and awk installed. MacOS X and Windows (using MSYS2 or cygwin) work too. OpenSSL version >= 1 is a must.  OpenSSL version >= 1.0.2 is needed for better LOGJAM checks and to display bit strengths for key exchanges.

On github you will find in the master branch the development version of the software -- with new features and maybe some bugs. For the stable version and a more thorough description of the software please see [testssl.sh](https://testssl.sh/ "Go to the site with the stable version and more documentation"). 

New features in the stable release 2.6 are: 

* display matching host key (HPKP)
* LOGJAM 1: check DHE_EXPORT cipher 
* LOGJAM 2: displays DH(/ECDH) bits in wide mode on negotiated ciphers
* "wide mode" option for checks like RC4, BEAST. PFS. Displays hexcode, kx, strength, DH bits, RFC name
* binary directory provides out of the box better binaries (Linux 32+64 Bit, Darwin 64 bit, FreeBSD 64 bit)
* OS X binaries (@jvehent, new builds: @jpluimers)
* ARM binary (@f-s)
* (HTTP) proxy support, via openssl and sockets! -- Thx @jnewbigin
* TLS_FALLBACK_SCSV check -- Thx @JonnyHightower
* Extended validation certificate detection
* Run in default mode through all ciphers at the end of a default run
* will test multiple IP adresses in one shot, --ip=<adress|"one"> restricts it accordingly
* new mass testing file option ``--file`` option where testssl.sh commands are being read from, see https://twitter.com/drwetter/status/627619848344989696 
* TLS time and HTTP time stamps
* TLS time displayed also for STARTTLS protocols
* support of sockets for STARTTLS protocols 
* TLS 1.0-1.1 as socket checks per default in production
* further detection of security relevant headers (reverse proxy, IPv4 addresses), proprietary banners (OWA, Liferay etc.)
* can scan STARTTLS+XMPP by also supplying the XMPP domain (to-option in XML streams).
* quite some LibreSSL fixes, still not recommended to use though (see https://testssl.sh/) 
* lots of fixes, code improvements, even more robust


Contributions, feedback, also bug reports are welcome! For contributions please note: One patch per feature -- bug fix/improvement. Please test your changes thouroughly as reliability is important for this project. 

Please file bug reports @ https://github.com/drwetter/testssl.sh/issues .

Update notification here or @ [twitter](https://twitter.com/drwetter). 


