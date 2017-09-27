
## Intro

[![Build Status](https://travis-ci.org/drwetter/testssl.sh.svg?branch=master)](https://travis-ci.org/drwetter/testssl.sh)
[![Gitter](https://badges.gitter.im/Join%20Chat.svg)](https://gitter.im/drwetter/testssl.sh?utm_source=badge&utm_medium=badge&utm_campaign=pr-badge&utm_content=badge)

`testssl.sh` is a free command line tool which checks a server's service on
any port for the support of TLS/SSL ciphers, protocols as well as some
cryptographic flaws.

#### Key features

* Clear output: you can tell easily whether anything is good or bad
* Ease of installation: It works for Linux, Darwin, FreeBSD, NetBSD and
  MSYS2/Cygwin out of the box: no need to install or configure something,
  no gems, CPAN, pip or the like.
* Flexibility: You can test any SSL/TLS enabled and STARTTLS service, not
  only webservers at port 443
* Toolbox: Several command line options help you to run YOUR test and
  configure YOUR output
* Reliability: features are tested thoroughly
* Verbosity: If a particular check cannot be performed because of a missing
  capability on your client side, you'll get a warning
* Privacy: It's only you who sees the result, not a third party
* Freedom: It's 100% open source. You can look at the code, see what's
  going on and you can change it.
* Heck, even the development is open (github)

#### Installation

You can download testssl.sh by cloning this git repository:

    git clone --depth 1 --branch 2.9.5 https://github.com/drwetter/testssl.sh.git

Or help yourself downloading the ZIP archive https://github.com/drwetter/testssl.sh/archive/v2.9.5-1.zip.
Then ``testssl.sh --help`` will give you some help upfront. More help: see doc directory. Older
sample runs are at https://testssl.sh/.

#### Compatibility

testssl.sh is working on every Linux/BSD distribution out of the box. In 2.9.5 most
of the limitations of disabled features from the openssl client are gone due to bash-socket-based
checks. testssl.sh also works on other unixoid system out of the box, supposed they have
`/bin/bash` and standard tools like sed and awk installed. System V needs to have GNU versions
of grep installed. MacOS X and Windows (using MSYS2 or cygwin) work too. OpenSSL
version >= 1.0.2 is recommended, you will get further with earlier openssl versions in
this interim release though as most of the checks in 2.9 are done via sockets.

Update notification here or @ [twitter](https://twitter.com/drwetter).

#### Status

2.9.5 is an interim release snapshot from the current 2.9dev version. It
has reached a point which is considered to be mature enough for day-to-day
usage before taking the next step in the development of this project.

2.9.5 has less bugs and has evolved considerably since 2.8.


#### Features implemented in 2.9.5
* Way better coverage of ciphers as most checks are done via sockets, using bash sockets where ever possible
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

#### Contributions

Contributions, feedback,  bug reports are welcome! For contributions please
note: One patch per feature -- bug fix/improvement. Please test your
changes thouroughly as reliability is important for this project.

There's a [coding guideline](https://github.com/drwetter/testssl.sh/wiki/Coding-Style).

Please file bug reports @ https://github.com/drwetter/testssl.sh/issues.

#### Bug reports

Please file bugs in the issue tracker. Do not forget to provide detailed information,
see https://github.com/drwetter/testssl.sh/wiki/Bug-reporting. Nobody can read your
thoughts -- yet. And only agencies your screen ;-)

----

## External/related projects

Please address questions not specifically to the code of testssl.sh to the
respective projects

#### Cool web frontend
* https://github.com/TKCERT/testssl.sh-webfrontend

#### Mass scanner w parallel scans and elastic searching the results
* https://github.com/TKCERT/testssl.sh-masscan

#### Ready-to-go docker images are available at:
* https://quay.io/repository/jumanjiman/testssl
* https://hub.docker.com/r/mvance/testssl/

#### Brew package

* see [#233](https://github.com/drwetter/testssl.sh/issues/233) and
  [https://github.com/Homebrew/homebrew](https://github.com/Homebrew/homebrew)
