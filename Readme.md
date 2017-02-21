
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

#### Status

Here in the _2.9dev branch you find the development version_ of the software
-- with new features and maybe some bugs. For the stable version and **a
more thorough description of the command line options** please see
[testssl.sh](https://testssl.sh/ "Go to the site with the stable version
and more documentation") or https://github.com/drwetter/testssl.sh/wiki/Usage-Documentation. 

#### Compatibility

testssl.sh is working on every Linux/BSD distribution out of the box. In 2.9dev most
of the limitations of disabled features from the openssl client are gone due to bash-socket-based 
checks. testssl.sh also works on otherunixoid system out of the box, supposed they have 
`/bin/bash` and standard tools like sed and awk installed. System V needs to have GNU versions 
of grep and sed installed. MacOS X and Windows (using MSYS2 or cygwin) work too. OpenSSL 
version  >= 1 is a must.  OpenSSL version >= 1.0.2 is needed for better LOGJAM checks and to 
display bit strengths for key exchanges.

Update notification here or @ [twitter](https://twitter.com/drwetter).

#### Features implemented in [2.9dev](Readme.md#devel)
* Support of supplying timeout value for ``openssl connect`` -- useful for batch/mass scanning
* TLS 1.2 protocol check via socket
* Further TLS socket improvements (handshake parsing, completeness, robustness)
* non-flat JSON support
* in file output (CSV, JSON flat, JSON non-flat) support of a minimum severity level (only above supplied level there will be output)
* testing 359 default ciphers (``testssl.sh -e``) with a mixture of sockets and openssl. Same speed as with openssl only but addtional ciphers such as post-quantum ciphers, new CHAHA20/POLY1305, CamelliaGCM etc.
* finding more TLS extensions via sockets
* TLS Supported Groups Registry (RFC 7919), key shares extension
* using bash sockets where ever possible
* LUCKY13 and SWEET32 checks
* LOGJAM: now checking also for known DH parameters
* Check for CAA RR
* better formatting of output
* choice showing the RFC naming scheme only


#### Features planned in 2.9dev

https://github.com/drwetter/testssl.sh/issues?q=is%3Aopen+is%3Aissue+milestone%3A2.9dev

#### Contributions

Contributions, feedback,  bug reports are welcome! For contributions please
note: One patch per feature -- bug fix/improvement. Please test your
changes thouroughly as reliability is important for this project.

There's [coding guideline](https://github.com/drwetter/testssl.sh/wiki/Coding-Style).

Please file bug reports @ https://github.com/drwetter/testssl.sh/issues.

#### Documentation

For a start see the
[wiki](https://github.com/drwetter/testssl.sh/wiki/Usage-Documentation).
Help is needed here.

#### Bug reports

Please file bugs in the issue tracker. Do not forget to provide detailed information, see https://github.com/drwetter/testssl.sh/wiki/Bug-reporting. (Nobody can read your thoughts 
-- yet. And only agencies your screen) ;-)

----

## External/related projects

Please address questions not specifically to the code of testssl.sh to the
respective projects

#### Cool web frontend
* https://github.com/TKCERT/testssl.sh-webfrontend

#### mass scanner w parallel scans and elastic searching the results
* https://github.com/TKCERT/testssl.sh-masscan

#### Ready-to-go docker images are available at:
* https://quay.io/repository/jumanjiman/testssl
* https://hub.docker.com/r/mvance/testssl/

#### Brew package

* see [#233](https://github.com/drwetter/testssl.sh/issues/233) and
  [https://github.com/Homebrew/homebrew](https://github.com/Homebrew/homebrew)
