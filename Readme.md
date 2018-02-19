
## Intro

[![Build Status](https://travis-ci.org/drwetter/testssl.sh.svg?branch=master)](https://travis-ci.org/drwetter/testssl.sh)
[![Gitter](https://badges.gitter.im/Join%20Chat.svg)](https://gitter.im/drwetter/testssl.sh?utm_source=badge&utm_medium=badge&utm_campaign=pr-badge&utm_content=badge)

`testssl.sh` is a free command line tool which checks a server's service on
any port for the support of TLS/SSL ciphers, protocols as well as some
cryptographic flaws.

#### Key features

* Clear output: you can tell easily whether anything is good or bad
* Ease of installation: It works for Linux, OSX/Darwin, FreeBSD, NetBSD,
  OpenBSD (needs bash) and MSYS2/Cygwin out of the box: no need to install
  or to configure something.  No gems, CPAN, pip or the like/
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

    git clone --depth 1 https://github.com/drwetter/testssl.sh.git

Or help yourself downloading the ZIP archive
https://github.com/drwetter/testssl.sh/archive/2.9dev.zip.  ``testssl.sh --help``
will give you some help upfront.  More help: see doc directory with
man pages. Older sample runs are at https://testssl.sh/.


#### Status

Here in the _2.9dev branch you find the development version_ of the software
-- with new features and maybe some bugs -- albeit we try our best before
committing to test changes. Be aware that we also change the output or command
line.

For the previous stable version please see [testssl.sh](https://testssl.sh/
"Go to the site with the stable version") or
download  the interim release 2.9.5 from here [2.9.5](https://github.com/drwetter/testssl.sh/tree/2.9.5) which is is the
successor of 2.8 and stable for day-to-day work.

#### Compatibility

testssl.sh is working on every Linux/BSD distribution out of the box. Since 2.9dev
most of the limitations of disabled features from the openssl client are gone
due to bash-socket-based checks. As a result you can also use e.g. LibreSSL.
testssl.sh also works on other unixoid system out of the box, supposed they have
`/bin/bash` >= version 3.2 and standard tools like sed and awk installed.
System V needs to have GNU grep installed. MacOS X and Windows (using MSYS2 or
cygwin) work too. OpenSSL version  version >= 1.0.2 is recommended for better
LOGJAM checks and to display bit strengths for key exchanges.

Update notification here or @ [twitter](https://twitter.com/drwetter).

#### Features implemented in [2.9dev](Readme.md#devel)
* Using bash sockets where ever possible --> better detection of ciphers, independent on the openssl version used.
* Testing 364 default ciphers (``testssl.sh -e/-E``) with a mixture of sockets and openssl. Same speed as with openssl only but additional ciphers such as post-quantum ciphers, new CHAHA20/POLY1305, CamelliaGCM etc.
* Further tests via TLS sockets and improvements (handshake parsing, completeness, robustness),
* TLS 1.2 protocol check via socket in production
* Finding more TLS extensions via sockets
* TLS Supported Groups Registry (RFC 7919), key shares extension
* Non-flat JSON support
* File output (CSV, JSON flat, JSON non-flat) supports a minimum severity level (only above supplied level there will be output)
* Support of supplying timeout value for ``openssl connect`` -- useful for batch/mass scanning
* Parallel mass testing (!)
* File input for serial or parallel mass testing can be also in nmap grep(p)able (-oG) format
* Native HTML support instead going through 'aha'
* Better formatting of output (indentation)
* Choice showing the RFC naming scheme only
* LUCKY13 and SWEET32 checks
* Check for vulnerability to Bleichenbacher attacks
* Ticketbleed check
* Decoding of unencrypted BIG IP cookies
* LOGJAM: now checking also for known DH parameters
* Check for CAA RR
* Check for OCSP must staple
* Check for Certificate Transparency
* Expect-CT Header Detection
* Check for session resumption (Ticket, ID)
* TLS Robustness check (GREASE)
* Postgres und MySQL STARTTLS support, MongoDB support
* Decodes BIG IP F5 Cookie
* Fully OpenBSD and LibreSSL support
* Missing SAN warning
* Man page
* Better error msg suppression (not fully installed OpenSSL)
* DNS over Proxy and other proxy improvements
* Better JSON output: renamed IDs and findings shorter/better parsable
* JSON output now valid also for non-responsing servers
* Added support for private CAs
* Exit code now 0 for running without error
* ROBOT check
* Better extension support
* Better OpenSSL 1.1.1 support
* Supports latest and greatest version of TLS 1.3, shows drafts supported

#### Further features planned in 2.9dev

https://github.com/drwetter/testssl.sh/issues?q=is%3Aopen+is%3Aissue+milestone%3A2.9dev

#### Contributions

Contributions, feedback,  bug reports are welcome! For contributions please
note: One patch per feature -- bug fix/improvement. Please test your
changes thouroughly as reliability is important for this project.

There's a [coding guideline](https://github.com/drwetter/testssl.sh/wiki/Coding-Style).

Please file bug reports @ https://github.com/drwetter/testssl.sh/issues.

#### Documentation

For a start see the
[wiki](https://github.com/drwetter/testssl.sh/wiki/Man-Page).
Help is needed here. Will Hunt provides a good [description](https://www.4armed.com/blog/doing-your-own-ssl-tls-testing/) for version 2.8, including useful background info.

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

#### A ready-to-go docker image is at:
* https://quay.io/repository/jumanjiman/testssl

#### Privacy checker using testssl.sh
* https://privacyscore.org

#### Brew package

* see [#233](https://github.com/drwetter/testssl.sh/issues/233) and
  [https://github.com/Homebrew/homebrew](https://github.com/Homebrew/homebrew)
